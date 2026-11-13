#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "unity/unity.h"
#include "dns.h"
#include "subdomain.h"
#include "validate.h"

#define SUBDOMAIN_TEST_PROBE_1 "azavbjrzhpxfqg.example.com"
#define SUBDOMAIN_TEST_PROBE_2 "xfumewogyqpeti.example.com"

#define SUBDOMAIN_TEST_QUESTION_COUNT (2 + 3 + SUBDOMAIN_WORDLIST_COUNT)

#define SUBDOMAIN_TEST_MAX_CALL_COUNT     8
#define SUBDOMAIN_TEST_MAX_QUESTION_COUNT 128

typedef struct {
  const char*        mp_name;
  DnsRecordType_t    m_type;
  DnsAnswerStatus_t  m_status;
  const char* const* mp_records;
} SubdomainTestAnswer_t;

typedef struct {
  char            ma_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsRecordType_t m_type;
} SubdomainTestQuestion_t;

static const SubdomainTestAnswer_t* g_answers;
static int                          g_answerCount;
static SubdomainTestQuestion_t      g_questions[SUBDOMAIN_TEST_MAX_QUESTION_COUNT];
static int                          g_questionCount;
static int                          g_callCount;
static int                          g_callQuestionCounts[SUBDOMAIN_TEST_MAX_CALL_COUNT];
static int                          g_callDeadlinesMs[SUBDOMAIN_TEST_MAX_CALL_COUNT];
static int                          g_callSleepsMs[SUBDOMAIN_TEST_MAX_CALL_COUNT];
static int                          g_answerFreeCount;
static int                          g_getrandomCallCount;
static size_t                       g_getrandomLastLength;
static int                          g_getrandomShortCall;

static SubdomainNameSet_t* g_nameSet;

void __real_dns_answerFree(DnsAnswer_t* answer);

void __wrap_dns_answerFree(DnsAnswer_t* answer)
{
  g_answerFreeCount++;
  __real_dns_answerFree(answer);
}

ssize_t __wrap_getrandom(void* buffer, size_t length, unsigned int flags)
{
  static const unsigned char CALL_BYTES[2][14] = {
    { 0x00, 0x19, 0x1a, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20 },
    { 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c },
  };
  (void)flags;
  int call = g_getrandomCallCount++;
  g_getrandomLastLength = length;
  unsigned char* bytes = buffer;
  for (size_t i = 0; i < length; i++)
    bytes[i] = i < 14 && call < 2 ? CALL_BYTES[call][i] : 0x77;
  return call == g_getrandomShortCall ? (ssize_t)length - 1 : (ssize_t)length;
}

static const SubdomainTestAnswer_t* static_findAnswer(const DnsQuestion_t* question)
{
  for (int i = 0; i < g_answerCount; i++)
    if (g_answers[i].m_type == question->m_type && strcmp(g_answers[i].mp_name, question->mp_domainName) == 0)
      return &g_answers[i];
  return NULL;
}

static void static_fillAnswer(const DnsQuestion_t* question, DnsAnswer_t* answer_out)
{
  memset(answer_out, 0, sizeof(*answer_out));
  const SubdomainTestAnswer_t* scripted = static_findAnswer(question);
  if (scripted == NULL)
  {
    answer_out->m_status = DNS_ANSWER_NXDOMAIN;
    return;
  }

  answer_out->m_status = scripted->m_status;
  int record_count = 0;
  while (scripted->mp_records != NULL && scripted->mp_records[record_count] != NULL)
    record_count++;
  if (record_count == 0)
    return;

  answer_out->m_recordCount = record_count;
  if (question->m_type == DNS_RECORD_TYPE_MX)
  {
    answer_out->mp_mxRecords = calloc((size_t)record_count, sizeof(DnsMxRecord_t));
    for (int i = 0; i < record_count; i++)
    {
      answer_out->mp_mxRecords[i].m_priority  = (uint16_t)(10 * (i + 1));
      answer_out->mp_mxRecords[i].mp_hostname = strdup(scripted->mp_records[i]);
    }
    return;
  }

  answer_out->mp_texts = calloc((size_t)record_count, sizeof(DnsRecordText_t));
  for (int i = 0; i < record_count; i++)
  {
    answer_out->mp_texts[i].mp_bytes    = strdup(scripted->mp_records[i]);
    answer_out->mp_texts[i].m_byteCount = strlen(scripted->mp_records[i]);
  }
}

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  int call = g_callCount++;
  TEST_ASSERT_TRUE(call < SUBDOMAIN_TEST_MAX_CALL_COUNT);
  TEST_ASSERT_TRUE(question_count > 0 && question_count <= DNS_MAX_QUESTION_COUNT);
  g_callQuestionCounts[call] = question_count;
  g_callDeadlinesMs[call]    = deadline_ms;

  for (int i = 0; i < question_count; i++)
  {
    TEST_ASSERT_TRUE(g_questionCount < SUBDOMAIN_TEST_MAX_QUESTION_COUNT);
    TEST_ASSERT_TRUE(strlen(questions[i].mp_domainName) <= VALIDATE_DOMAIN_NAME_MAX_LEN);
    snprintf(g_questions[g_questionCount].ma_name, sizeof(g_questions[0].ma_name), "%s", questions[i].mp_domainName);
    g_questions[g_questionCount].m_type = questions[i].m_type;
    g_questionCount++;
  }

  if (g_callSleepsMs[call] > 0)
  {
    struct timespec pause = { .tv_sec = g_callSleepsMs[call] / 1000, .tv_nsec = (long)(g_callSleepsMs[call] % 1000) * 1000000L };
    nanosleep(&pause, NULL);
  }

  for (int i = 0; i < question_count; i++)
    static_fillAnswer(&questions[i], &answers_out[i]);
}

static void static_forgetCalls(void)
{
  g_questionCount       = 0;
  g_callCount           = 0;
  g_answerFreeCount     = 0;
  g_getrandomCallCount  = 0;
  g_getrandomLastLength = 0;
  memset(g_questions, 0, sizeof(g_questions));
  memset(g_callQuestionCounts, 0, sizeof(g_callQuestionCounts));
  memset(g_callDeadlinesMs, 0, sizeof(g_callDeadlinesMs));
}

void setUp(void)
{
  g_answers            = NULL;
  g_answerCount        = 0;
  g_getrandomShortCall = -1;
  memset(g_callSleepsMs, 0, sizeof(g_callSleepsMs));
  static_forgetCalls();
  g_nameSet = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(g_nameSet);
}

void tearDown(void)
{
  subdomain_destroyNameSet(g_nameSet);
  g_nameSet = NULL;
}

static int static_findName(const char* name)
{
  for (int i = 0; i < g_nameSet->m_count; i++)
    if (strcmp(g_nameSet->mp_names[i], name) == 0)
      return i;
  return -1;
}

static void static_assertNameSources(const char* name, unsigned int sources)
{
  int index = static_findName(name);
  TEST_ASSERT_TRUE_MESSAGE(index >= 0, name);
  TEST_ASSERT_EQUAL_HEX32_MESSAGE(sources, g_nameSet->mp_sources[index], name);
}

static SubdomainWildcard_t static_lookupExample(void)
{
  SubdomainWildcard_t wildcard = (SubdomainWildcard_t)77;
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard);
  return wildcard;
}

static void static_makeDomain(size_t length, char* domain)
{
  for (size_t i = 0; i < length; i++)
    domain[i] = i % 63 == 62 ? '.' : (char)('a' + i / 63);
  domain[length] = '\0';
  TEST_ASSERT_TRUE(domain[length - 1] != '.');
  TEST_ASSERT_TRUE(validate_publicDnsName(domain));
}

void test_createNameSet_starts_empty(void)
{
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
  TEST_ASSERT_NOT_NULL(g_nameSet->mp_names);
  TEST_ASSERT_NOT_NULL(g_nameSet->mp_sources);
  subdomain_destroyNameSet(NULL);
}

void test_addName_drops_a_leading_wildcard_label(void)
{
  subdomain_addName(g_nameSet, "*.www.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_nameSet->mp_names[0]);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_CERTIFICATE_LOGS, g_nameSet->mp_sources[0]);
  subdomain_addName(g_nameSet, "*api.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
}

void test_addName_lowers_upper_case(void)
{
  subdomain_addName(g_nameSet, "WwW.Example.COM", "example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_nameSet->mp_names[0]);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_DNS_WORDLIST, g_nameSet->mp_sources[0]);
  subdomain_addName(g_nameSet, "M.EXAMPLE.com", "example.com", SUBDOMAIN_SOURCE_DNS_RECORDS);
  TEST_ASSERT_EQUAL_INT(2, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("m.example.com", g_nameSet->mp_names[1]);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_DNS_RECORDS, g_nameSet->mp_sources[1]);
}

void test_addName_refuses_a_name_outside_the_domain(void)
{
  subdomain_addName(g_nameSet, "www.example.org", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "example.com.evil.net", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_addName_refuses_the_domain_itself(void)
{
  subdomain_addName(g_nameSet, "example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "EXAMPLE.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "*.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_addName_refuses_a_lookalike_suffix(void)
{
  subdomain_addName(g_nameSet, "badexample.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "www.badexample.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "www-example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_addName_refuses_a_name_validate_refuses(void)
{
  subdomain_addName(g_nameSet, "_spf.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_RECORDS);
  subdomain_addName(g_nameSet, "a b.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, ".example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "www.corp.local", "corp.local", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_addName_keeps_the_longest_name_and_refuses_a_longer_one(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(VALIDATE_DOMAIN_NAME_MAX_LEN - 4, domain);
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 8];
  snprintf(name, sizeof(name), "www.%s", domain);
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(name));
  subdomain_addName(g_nameSet, name, domain, SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING(name, g_nameSet->mp_names[0]);

  snprintf(name, sizeof(name), "wwww.%s", domain);
  subdomain_addName(g_nameSet, name, domain, SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
}

void test_addName_repeat_adds_the_source(void)
{
  subdomain_addName(g_nameSet, "api.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "mail.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  subdomain_addName(g_nameSet, "API.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_RECORDS);
  TEST_ASSERT_EQUAL_INT(2, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_CERTIFICATE_LOGS | SUBDOMAIN_SOURCE_DNS_RECORDS, g_nameSet->mp_sources[0]);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_DNS_WORDLIST, g_nameSet->mp_sources[1]);
}

void test_addName_full_set_refuses_a_new_name(void)
{
  char name[64];
  for (int i = 0; i < SUBDOMAIN_MAX_NAME_COUNT; i++)
  {
    snprintf(name, sizeof(name), "h%d.example.com", i);
    subdomain_addName(g_nameSet, name, "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  }
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_MAX_NAME_COUNT, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("h999.example.com", g_nameSet->mp_names[SUBDOMAIN_MAX_NAME_COUNT - 1]);

  subdomain_addName(g_nameSet, "new.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_MAX_NAME_COUNT, g_nameSet->m_count);
  for (int i = 0; i < SUBDOMAIN_MAX_NAME_COUNT; i++)
    TEST_ASSERT_NOT_EQUAL_INT(0, strcmp("new.example.com", g_nameSet->mp_names[i]));

  subdomain_addName(g_nameSet, "h7.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_CERTIFICATE_LOGS | SUBDOMAIN_SOURCE_DNS_WORDLIST, g_nameSet->mp_sources[7]);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_MAX_NAME_COUNT, g_nameSet->m_count);
}

void test_lookupDnsNames_asks_the_questions_in_order(void)
{
  static_lookupExample();
  TEST_ASSERT_EQUAL_INT(2, g_getrandomCallCount);
  TEST_ASSERT_EQUAL_size_t(14, g_getrandomLastLength);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_questionCount);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_answerFreeCount);

  TEST_ASSERT_EQUAL_STRING(SUBDOMAIN_TEST_PROBE_1, g_questions[0].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[0].m_type);
  TEST_ASSERT_EQUAL_STRING(SUBDOMAIN_TEST_PROBE_2, g_questions[1].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[1].m_type);
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[2].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_MX, g_questions[2].m_type);
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[3].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_NS, g_questions[3].m_type);
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[4].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_TXT, g_questions[4].m_type);
  for (int i = 0; i < SUBDOMAIN_WORDLIST_COUNT; i++)
  {
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    snprintf(name, sizeof(name), "%s.example.com", subdomain_wordlist[i]);
    TEST_ASSERT_EQUAL_STRING(name, g_questions[5 + i].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[5 + i].m_type);
  }
}

void test_wordlist_holds_the_labels_in_order(void)
{
  TEST_ASSERT_EQUAL_STRING("www", subdomain_wordlist[0]);
  TEST_ASSERT_EQUAL_STRING("mail", subdomain_wordlist[1]);
  TEST_ASSERT_EQUAL_STRING("m", subdomain_wordlist[2]);
  TEST_ASSERT_EQUAL_STRING("enterpriseregistration", subdomain_wordlist[59]);
  TEST_ASSERT_EQUAL_STRING("mx", subdomain_wordlist[SUBDOMAIN_WORDLIST_COUNT - 1]);
}

void test_wordlist_is_the_measured_list(void)
{
  static const char EXPECTED[] = "www,mail,m,ns2,blog,ns1,forum,ftp,shop,smtp,support,webmail,my,autodiscover,help,pop,app,ns3,store,imap,portal,test,secure,vpn,jobs,sip,news,api,careers,ns,es,dev,mobile,pop3,www2,cdn,en,ns4,fr,online,login,lyncdiscover,forums,speedtest,cloud,wiki,de,cpanel,community,it,admin,docs,dns2,web,git,info,ru,enterpriseenrollment,library,enterpriseregistration,search,dns1,moodle,autoconfig,bbs,ntp,us,mail2,pt,apps,dns,blogs,email,catalog,zabbix,go,account,new,www1,images,uk,old,members,nl,demo,id,msoid,sso,amp,proxy,home,monitor,live,mx";
  char joined[2048] = "";
  size_t len = 0;
  for (int i = 0; i < SUBDOMAIN_WORDLIST_COUNT; i++)
    len += (size_t)snprintf(joined + len, sizeof(joined) - len, "%s%s", i > 0 ? "," : "", subdomain_wordlist[i]);
  TEST_ASSERT_EQUAL_STRING(EXPECTED, joined);
}

void test_lookupDnsNames_asks_in_rounds_of_the_most_questions(void)
{
  static_lookupExample();
  TEST_ASSERT_EQUAL_INT(4, g_callCount);
  TEST_ASSERT_EQUAL_INT(DNS_MAX_QUESTION_COUNT, g_callQuestionCounts[0]);
  TEST_ASSERT_EQUAL_INT(DNS_MAX_QUESTION_COUNT, g_callQuestionCounts[1]);
  TEST_ASSERT_EQUAL_INT(DNS_MAX_QUESTION_COUNT, g_callQuestionCounts[2]);
  TEST_ASSERT_EQUAL_INT(3, g_callQuestionCounts[3]);
}

void test_lookupDnsNames_ninety_six_questions_take_three_rounds(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(231, domain);
  g_getrandomShortCall = 0;
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_INT(96, g_questionCount);
  TEST_ASSERT_EQUAL_INT(3, g_callCount);
}

void test_lookupDnsNames_rounds_share_one_deadline(void)
{
  g_callSleepsMs[0] = 30;
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_INT(4, g_callCount);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] <= 2000);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] > 1000);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[1] <= g_callDeadlinesMs[0] - 30);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[2] <= g_callDeadlinesMs[1]);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[3] <= g_callDeadlinesMs[2]);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[3] > 0);
}

void test_lookupDnsNames_first_round_gets_nearly_the_whole_deadline(void)
{
  static_lookupExample();
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] <= SUBDOMAIN_DNS_DEADLINE_MS);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] > SUBDOMAIN_DNS_DEADLINE_MS - 100);
}

void test_lookupDnsNames_sends_no_round_after_the_deadline(void)
{
  static const char* const address[] = { "192.0.2.44", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "mx.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address },
  };
  g_answers         = answers;
  g_answerCount     = 1;
  g_callSleepsMs[0] = SUBDOMAIN_DNS_DEADLINE_MS + 20;
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, wildcard);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_answerFreeCount);
}

void test_lookupDnsNames_asks_a_name_of_the_longest_length(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(230, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_questionCount);
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(g_questions[5 + 59].ma_name));
}

void test_lookupDnsNames_skips_a_name_too_long(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(231, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT - 1, g_questionCount);
  TEST_ASSERT_EQUAL_INT(2, g_callQuestionCounts[3]);
  for (int i = 0; i < g_questionCount; i++)
    TEST_ASSERT_TRUE(strncmp(g_questions[i].ma_name, "enterpriseregistration.", 23) != 0);
  TEST_ASSERT_EQUAL_STRING_LEN("enterpriseenrollment.", g_questions[5 + 57].ma_name, 21);
  TEST_ASSERT_EQUAL_STRING_LEN("library.", g_questions[5 + 58].ma_name, 8);
  TEST_ASSERT_EQUAL_STRING_LEN("search.", g_questions[5 + 59].ma_name, 7);
}

void test_lookupDnsNames_asks_probes_of_the_longest_length(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(238, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_STRING_LEN("azavbjrzhpxfqg.", g_questions[0].ma_name, 15);
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(g_questions[1].ma_name));
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, wildcard);
}

void test_lookupDnsNames_without_room_for_a_probe_is_undetermined(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(239, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_ABSENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard);
  TEST_ASSERT_EQUAL_STRING(domain, g_questions[0].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_MX, g_questions[0].m_type);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, wildcard);
}

void test_lookupDnsNames_short_random_bytes_send_no_probe(void)
{
  static const char* const address[] = { "192.0.2.80", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 1;

  for (int short_call = 0; short_call < 2; short_call++)
  {
    g_getrandomShortCall = short_call;
    static_forgetCalls();
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, static_lookupExample());
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT - 2, g_questionCount);
    TEST_ASSERT_EQUAL_STRING("example.com", g_questions[0].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_MX, g_questions[0].m_type);
    TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
  }
}

void test_lookupDnsNames_first_probe_with_an_address_means_present(void)
{
  static const char* const address[] = { "192.0.2.10", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A, DNS_ANSWER_OK,      address },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A, DNS_ANSWER_TIMEOUT, NULL },
    { "www.example.com",      DNS_RECORD_TYPE_A, DNS_ANSWER_OK,      address },
  };
  g_answers     = answers;
  g_answerCount = 3;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_lookupDnsNames_second_probe_with_an_address_means_present(void)
{
  static const char* const address[] = { "192.0.2.20", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 1;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
}

void test_lookupDnsNames_two_nxdomain_probes_mean_absent_and_keep_hits(void)
{
  static const char* const address[] = { "10.0.0.5", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK,           address },
    { "vpn.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK,           address },
    { "api.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK,           NULL },
    { "dev.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_SERVER_ERROR, NULL },
    { "mx.example.com",  DNS_RECORD_TYPE_A, DNS_ANSWER_OK,           address },
  };
  g_answers     = answers;
  g_answerCount = 5;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(3, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_nameSet->mp_names[0]);
  TEST_ASSERT_EQUAL_STRING("vpn.example.com", g_nameSet->mp_names[1]);
  TEST_ASSERT_EQUAL_STRING("mx.example.com", g_nameSet->mp_names[2]);
  for (int i = 0; i < g_nameSet->m_count; i++)
    TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_DNS_WORDLIST, g_nameSet->mp_sources[i]);
}

void test_lookupDnsNames_probes_without_a_record_mean_absent(void)
{
  static const SubdomainTestAnswer_t both_empty[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A, DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A, DNS_ANSWER_OK, NULL },
  };
  g_answers     = both_empty;
  g_answerCount = 2;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());

  static_forgetCalls();
  g_answerCount = 1;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());
}

void test_lookupDnsNames_unmeasured_probe_means_undetermined(void)
{
  static const char* const address[] = { "192.0.2.30", NULL };
  static const SubdomainTestAnswer_t answers[4][2] = {
    { { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A, DNS_ANSWER_TIMEOUT,      NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
    { { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A, DNS_ANSWER_TIMEOUT,      NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
    { { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A, DNS_ANSWER_SERVER_ERROR, NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
    { { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A, DNS_ANSWER_SERVER_ERROR, NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
  };
  for (int i = 0; i < 4; i++)
  {
    g_answers     = answers[i];
    g_answerCount = 2;
    static_forgetCalls();
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, static_lookupExample());
    TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
  }
}

void test_lookupDnsNames_reads_names_from_mx_ns_and_spf(void)
{
  static const char* const address[]  = { "192.0.2.10", NULL };
  static const char* const mx_hosts[] = { "mx.mailhost.net", "mx1.example.com", "MX2.Example.com", NULL };
  static const char* const ns_names[] = { "ns.provider.net", "ns-a.example.com", NULL };
  static const char* const texts[]    = {
    "google-site-verification=a.example.com",
    "v=spf1 a:web.example.com/24 mx:relay.example.com//64 include:_spf.example.com include:spf.out.example.com "
    "exists:%{i}.x.example.com exists:check.example.com ptr:ptr.example.com ip4:192.0.2.0/24 "
    "exp=exp.example.com a:other.net -all redirect=red.example.com",
    NULL,
  };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A,   DNS_ANSWER_OK, address },
    { "example.com",          DNS_RECORD_TYPE_MX,  DNS_ANSWER_OK, mx_hosts },
    { "example.com",          DNS_RECORD_TYPE_NS,  DNS_ANSWER_OK, ns_names },
    { "example.com",          DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, texts },
  };
  g_answers     = answers;
  g_answerCount = 4;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());

  const unsigned int records = SUBDOMAIN_SOURCE_DNS_RECORDS;
  TEST_ASSERT_EQUAL_INT(8, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING("mx1.example.com", g_nameSet->mp_names[0]);
  TEST_ASSERT_EQUAL_STRING("mx2.example.com", g_nameSet->mp_names[1]);
  TEST_ASSERT_EQUAL_STRING("ns-a.example.com", g_nameSet->mp_names[2]);
  TEST_ASSERT_EQUAL_STRING("web.example.com", g_nameSet->mp_names[3]);
  TEST_ASSERT_EQUAL_STRING("relay.example.com", g_nameSet->mp_names[4]);
  TEST_ASSERT_EQUAL_STRING("spf.out.example.com", g_nameSet->mp_names[5]);
  TEST_ASSERT_EQUAL_STRING("check.example.com", g_nameSet->mp_names[6]);
  TEST_ASSERT_EQUAL_STRING("red.example.com", g_nameSet->mp_names[7]);
  for (int i = 0; i < g_nameSet->m_count; i++)
    TEST_ASSERT_EQUAL_HEX32(records, g_nameSet->mp_sources[i]);
}

void test_lookupDnsNames_reads_no_spf_from_two_records(void)
{
  static const char* const texts[] = {
    "v=spf1 a:one.example.com -all",
    "v=spf1 include:two.example.com -all",
    NULL,
  };
  static const SubdomainTestAnswer_t answers[] = {
    { "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, texts },
  };
  g_answers     = answers;
  g_answerCount = 1;
  static_lookupExample();
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_lookupDnsNames_merges_the_sources_of_one_name(void)
{
  static const char* const address[]  = { "192.0.2.25", NULL };
  static const char* const mx_hosts[] = { "smtp.example.com", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "example.com",      DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, mx_hosts },
    { "smtp.example.com", DNS_RECORD_TYPE_A,  DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 2;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  static_assertNameSources("smtp.example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST | SUBDOMAIN_SOURCE_DNS_RECORDS);
}

void test_lookupDnsNames_reads_an_spf_host_of_the_longest_length(void)
{
  char host[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  memset(host, 'a', sizeof(host));
  host[63]  = '.';
  host[127] = '.';
  host[191] = '.';
  snprintf(host + 241, sizeof(host) - 241, ".example.com");
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(host));

  static char spf_text[1024];
  snprintf(spf_text, sizeof(spf_text), "v=spf1 a:%s/24 a:b%s -all", host, host);
  static const char* texts[] = { spf_text, NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, texts },
  };
  g_answers     = answers;
  g_answerCount = 1;
  static_lookupExample();
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_STRING(host, g_nameSet->mp_names[0]);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_createNameSet_starts_empty);
  RUN_TEST(test_addName_drops_a_leading_wildcard_label);
  RUN_TEST(test_addName_lowers_upper_case);
  RUN_TEST(test_addName_refuses_a_name_outside_the_domain);
  RUN_TEST(test_addName_refuses_the_domain_itself);
  RUN_TEST(test_addName_refuses_a_lookalike_suffix);
  RUN_TEST(test_addName_refuses_a_name_validate_refuses);
  RUN_TEST(test_addName_keeps_the_longest_name_and_refuses_a_longer_one);
  RUN_TEST(test_addName_repeat_adds_the_source);
  RUN_TEST(test_addName_full_set_refuses_a_new_name);
  RUN_TEST(test_wordlist_holds_the_labels_in_order);
  RUN_TEST(test_wordlist_is_the_measured_list);
  RUN_TEST(test_lookupDnsNames_asks_the_questions_in_order);
  RUN_TEST(test_lookupDnsNames_asks_in_rounds_of_the_most_questions);
  RUN_TEST(test_lookupDnsNames_ninety_six_questions_take_three_rounds);
  RUN_TEST(test_lookupDnsNames_rounds_share_one_deadline);
  RUN_TEST(test_lookupDnsNames_first_round_gets_nearly_the_whole_deadline);
  RUN_TEST(test_lookupDnsNames_sends_no_round_after_the_deadline);
  RUN_TEST(test_lookupDnsNames_asks_a_name_of_the_longest_length);
  RUN_TEST(test_lookupDnsNames_skips_a_name_too_long);
  RUN_TEST(test_lookupDnsNames_asks_probes_of_the_longest_length);
  RUN_TEST(test_lookupDnsNames_without_room_for_a_probe_is_undetermined);
  RUN_TEST(test_lookupDnsNames_short_random_bytes_send_no_probe);
  RUN_TEST(test_lookupDnsNames_first_probe_with_an_address_means_present);
  RUN_TEST(test_lookupDnsNames_second_probe_with_an_address_means_present);
  RUN_TEST(test_lookupDnsNames_two_nxdomain_probes_mean_absent_and_keep_hits);
  RUN_TEST(test_lookupDnsNames_probes_without_a_record_mean_absent);
  RUN_TEST(test_lookupDnsNames_unmeasured_probe_means_undetermined);
  RUN_TEST(test_lookupDnsNames_reads_names_from_mx_ns_and_spf);
  RUN_TEST(test_lookupDnsNames_reads_an_spf_host_of_the_longest_length);
  RUN_TEST(test_lookupDnsNames_reads_no_spf_from_two_records);
  RUN_TEST(test_lookupDnsNames_merges_the_sources_of_one_name);
  return UNITY_END();
}
