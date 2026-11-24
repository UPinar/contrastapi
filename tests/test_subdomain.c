#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "unity/unity.h"
#include "dns.h"
#include "subdomain.h"
#include "validate.h"

#define SUBDOMAIN_TEST_PROBE_COUNT 6

#define SUBDOMAIN_TEST_PROBE_1 "azavbjrzhpxfqg.example.com"
#define SUBDOMAIN_TEST_PROBE_2 "xfumewogyqpeti.example.com"
#define SUBDOMAIN_TEST_PROBE_3 "rizqhypgxofwne.example.com"
#define SUBDOMAIN_TEST_PROBE_4 "cegikmoqsuwyac.example.com"
#define SUBDOMAIN_TEST_PROBE_5 "grcnyjufqbmxit.example.com"
#define SUBDOMAIN_TEST_PROBE_6 "xnlmfkvrjcuwzb.example.com"

#define SUBDOMAIN_TEST_QUESTION_COUNT (2 * SUBDOMAIN_TEST_PROBE_COUNT + 3 + SUBDOMAIN_WORDLIST_COUNT)

#define SUBDOMAIN_TEST_GUESS_INDEX (2 * SUBDOMAIN_TEST_PROBE_COUNT + 3)

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

static const char* const g_probeNames[SUBDOMAIN_TEST_PROBE_COUNT] = {
  SUBDOMAIN_TEST_PROBE_1, SUBDOMAIN_TEST_PROBE_2, SUBDOMAIN_TEST_PROBE_3,
  SUBDOMAIN_TEST_PROBE_4, SUBDOMAIN_TEST_PROBE_5, SUBDOMAIN_TEST_PROBE_6,
};

static SubdomainNameSet_t*            g_nameSet;
static SubdomainWildcardIpAddresses_t g_wildcardIpAddresses;

void __real_dns_answerFree(DnsAnswer_t* answer);

void __wrap_dns_answerFree(DnsAnswer_t* answer)
{
  g_answerFreeCount++;
  __real_dns_answerFree(answer);
}

ssize_t __wrap_getrandom(void* buffer, size_t length, unsigned int flags)
{
  static const unsigned char CALL_BYTES[SUBDOMAIN_TEST_PROBE_COUNT][14] = {
    { 0x00, 0x19, 0x1a, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20 },
    { 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c },
    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee },
    { 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c },
    { 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d },
    { 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83 },
  };
  (void)flags;
  int call = g_getrandomCallCount++;
  g_getrandomLastLength = length;
  unsigned char* bytes = buffer;
  for (size_t i = 0; i < length; i++)
    bytes[i] = i < 14 && call < SUBDOMAIN_TEST_PROBE_COUNT ? CALL_BYTES[call][i] : 0x77;
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
  memset(&g_wildcardIpAddresses, 0, sizeof(g_wildcardIpAddresses));
  g_wildcardIpAddresses.m_count = 77;
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
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard, &g_wildcardIpAddresses);
  return wildcard;
}

static void static_assertAddressState(const char* name, SubdomainAddressState_t state)
{
  int index = static_findName(name);
  TEST_ASSERT_TRUE_MESSAGE(index >= 0, name);
  TEST_ASSERT_EQUAL_INT_MESSAGE(state, g_nameSet->mp_addressStates[index], name);
}

static int static_addNameWithState(const char* name, SubdomainAddressState_t state)
{
  subdomain_addName(g_nameSet, name, "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  int index = static_findName(name);
  TEST_ASSERT_TRUE_MESSAGE(index >= 0, name);
  g_nameSet->mp_addressStates[index] = state;
  return index;
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
  TEST_ASSERT_EQUAL_INT(6, g_getrandomCallCount);
  TEST_ASSERT_EQUAL_size_t(14, g_getrandomLastLength);
  TEST_ASSERT_EQUAL_INT(109, g_questionCount);
  TEST_ASSERT_EQUAL_INT(109, g_answerFreeCount);

  for (int i = 0; i < SUBDOMAIN_TEST_PROBE_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_STRING(g_probeNames[i], g_questions[i].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[i].m_type);
    TEST_ASSERT_EQUAL_STRING(g_probeNames[i], g_questions[SUBDOMAIN_TEST_PROBE_COUNT + i].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_CNAME, g_questions[SUBDOMAIN_TEST_PROBE_COUNT + i].m_type);
  }
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[12].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_MX, g_questions[12].m_type);
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[13].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_NS, g_questions[13].m_type);
  TEST_ASSERT_EQUAL_STRING("example.com", g_questions[14].ma_name);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_TXT, g_questions[14].m_type);
  for (int i = 0; i < SUBDOMAIN_WORDLIST_COUNT; i++)
  {
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    snprintf(name, sizeof(name), "%s.example.com", subdomain_wordlist[i]);
    TEST_ASSERT_EQUAL_STRING(name, g_questions[SUBDOMAIN_TEST_GUESS_INDEX + i].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[SUBDOMAIN_TEST_GUESS_INDEX + i].m_type);
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
  TEST_ASSERT_EQUAL_INT(13, g_callQuestionCounts[3]);
}

void test_lookupDnsNames_ninety_six_questions_take_three_rounds(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(231, domain);
  g_getrandomShortCall = 0;
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard, &g_wildcardIpAddresses);
  TEST_ASSERT_EQUAL_INT(96, g_questionCount);
  TEST_ASSERT_EQUAL_INT(3, g_callCount);
}

void test_lookupDnsNames_rounds_share_one_deadline(void)
{
  g_callSleepsMs[0] = 30;
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard, &g_wildcardIpAddresses);
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
  subdomain_lookupDnsNames("example.com", g_nameSet, &wildcard, &g_wildcardIpAddresses);
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
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard, &g_wildcardIpAddresses);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_questionCount);
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(g_questions[SUBDOMAIN_TEST_GUESS_INDEX + 59].ma_name));
}

void test_lookupDnsNames_skips_a_name_too_long(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(231, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard, &g_wildcardIpAddresses);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT - 1, g_questionCount);
  TEST_ASSERT_EQUAL_INT(12, g_callQuestionCounts[3]);
  for (int i = 0; i < g_questionCount; i++)
    TEST_ASSERT_TRUE(strncmp(g_questions[i].ma_name, "enterpriseregistration.", 23) != 0);
  TEST_ASSERT_EQUAL_STRING_LEN("enterpriseenrollment.", g_questions[SUBDOMAIN_TEST_GUESS_INDEX + 57].ma_name, 21);
  TEST_ASSERT_EQUAL_STRING_LEN("library.", g_questions[SUBDOMAIN_TEST_GUESS_INDEX + 58].ma_name, 8);
  TEST_ASSERT_EQUAL_STRING_LEN("search.", g_questions[SUBDOMAIN_TEST_GUESS_INDEX + 59].ma_name, 7);
}

void test_lookupDnsNames_asks_probes_of_the_longest_length(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(238, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_PRESENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard, &g_wildcardIpAddresses);
  TEST_ASSERT_EQUAL_STRING_LEN("azavbjrzhpxfqg.", g_questions[0].ma_name, 15);
  for (int i = 0; i < 2 * SUBDOMAIN_TEST_PROBE_COUNT; i++)
    TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(g_questions[i].ma_name));
  TEST_ASSERT_EQUAL_STRING_LEN("xnlmfkvrjcuwzb.", g_questions[SUBDOMAIN_TEST_PROBE_COUNT - 1].ma_name, 15);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, wildcard);
}

void test_lookupDnsNames_without_room_for_a_probe_is_undetermined(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_makeDomain(239, domain);
  SubdomainWildcard_t wildcard = SUBDOMAIN_WILDCARD_ABSENT;
  subdomain_lookupDnsNames(domain, g_nameSet, &wildcard, &g_wildcardIpAddresses);
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

  for (int short_call = 0; short_call < SUBDOMAIN_TEST_PROBE_COUNT; short_call++)
  {
    g_getrandomShortCall = short_call;
    static_forgetCalls();
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, static_lookupExample());
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT - 2 * SUBDOMAIN_TEST_PROBE_COUNT, g_questionCount);
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

void test_lookupDnsNames_nxdomain_probes_mean_absent_and_keep_hits(void)
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

void test_createNameSet_starts_with_every_address_unmeasured(void)
{
  TEST_ASSERT_NOT_NULL(g_nameSet->mp_addressStates);
  for (int i = 0; i < SUBDOMAIN_MAX_NAME_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_ADDRESS_UNMEASURED, g_nameSet->mp_addressStates[i]);
  subdomain_addName(g_nameSet, "ftp.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_RECORDS);
  static_assertAddressState("ftp.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
}

void test_lookupDnsNames_dangling_wildcard_cname_means_present(void)
{
  static const char* const target[]  = { "gone.cloudapp.example.net", NULL };
  static const char* const address[] = { "192.0.2.61", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A,     DNS_ANSWER_NXDOMAIN, NULL },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A,     DNS_ANSWER_NXDOMAIN, NULL },
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK,       target },
    { "www.example.com",      DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,       address },
  };
  g_answers     = answers;
  g_answerCount = 4;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
}

void test_lookupDnsNames_first_cname_probe_with_a_record_means_present(void)
{
  static const char* const target[]  = { "edge.cdn.example.net", NULL };
  static const char* const address[] = { "192.0.2.62", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK, target },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK, NULL },
    { "www.example.com",      DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 5;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_lookupDnsNames_second_cname_probe_with_a_record_means_present(void)
{
  static const char* const target[]  = { "park.host.example.org", NULL };
  static const char* const address[] = { "192.0.2.63", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK, NULL },
    { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK, target },
    { "www.example.com",      DNS_RECORD_TYPE_A,     DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 5;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
}

void test_lookupDnsNames_cname_probe_timeout_means_undetermined(void)
{
  static const char* const address[] = { "192.0.2.64", NULL };
  static const SubdomainTestAnswer_t answers[2][2] = {
    { { SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_TIMEOUT, NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
    { { SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_TIMEOUT, NULL }, { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address } },
  };
  for (int i = 0; i < 2; i++)
  {
    g_answers     = answers[i];
    g_answerCount = 2;
    static_forgetCalls();
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, static_lookupExample());
    TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
    TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
  }
}

static int static_writeProbeAnswers(SubdomainTestAnswer_t* answers_out, const char* const* common_addresses, int odd_index, const char* const* odd_addresses)
{
  for (int i = 0; i < SUBDOMAIN_TEST_PROBE_COUNT; i++)
    answers_out[i] = (SubdomainTestAnswer_t){ g_probeNames[i], DNS_RECORD_TYPE_A, DNS_ANSWER_OK, i == odd_index ? odd_addresses : common_addresses };
  return SUBDOMAIN_TEST_PROBE_COUNT;
}

void test_lookupDnsNames_bypass_keeps_a_guess_outside_the_wildcard_ip_addresses(void)
{
  static const char* const probe_1_addresses[] = { "192.0.2.1", "192.0.2.2", NULL };
  static const char* const other_addresses[]   = { "192.0.2.2", "192.0.2.1", NULL };
  static const char* const www_address[]       = { "198.51.100.7", NULL };
  static const char* const mail_addresses[]    = { "198.51.100.8", "192.0.2.2", NULL };
  static const char* const shop_address[]      = { "192.0.2.1", NULL };
  SubdomainTestAnswer_t answers[SUBDOMAIN_TEST_PROBE_COUNT + 6];
  int count = static_writeProbeAnswers(answers, other_addresses, 0, probe_1_addresses);
  answers[count++] = (SubdomainTestAnswer_t){ SUBDOMAIN_TEST_PROBE_1, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_NXDOMAIN, NULL };
  answers[count++] = (SubdomainTestAnswer_t){ SUBDOMAIN_TEST_PROBE_2, DNS_RECORD_TYPE_CNAME, DNS_ANSWER_OK,       NULL };
  answers[count++] = (SubdomainTestAnswer_t){ "www.example.com",      DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,       www_address };
  answers[count++] = (SubdomainTestAnswer_t){ "mail.example.com",     DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,       mail_addresses };
  answers[count++] = (SubdomainTestAnswer_t){ "shop.example.com",     DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,       shop_address };
  answers[count++] = (SubdomainTestAnswer_t){ "vpn.example.com",      DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,       NULL };
  g_answers     = answers;
  g_answerCount = count;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  static_assertNameSources("www.example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  static_assertAddressState("www.example.com", SUBDOMAIN_ADDRESS_FOUND);
  TEST_ASSERT_EQUAL_INT(2, g_wildcardIpAddresses.m_count);
  TEST_ASSERT_EQUAL_STRING("192.0.2.1", g_wildcardIpAddresses.ma_ipAddresses[0]);
  TEST_ASSERT_EQUAL_STRING("192.0.2.2", g_wildcardIpAddresses.ma_ipAddresses[1]);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_TEST_QUESTION_COUNT, g_answerFreeCount);
}

static void static_assertNoBypass(const char* const* odd_addresses, const char* const* common_addresses)
{
  static const char* const www_address[] = { "198.51.100.40", NULL };
  for (int odd_index = 0; odd_index < SUBDOMAIN_TEST_PROBE_COUNT; odd_index++)
  {
    SubdomainTestAnswer_t answers[SUBDOMAIN_TEST_PROBE_COUNT + 1];
    int count = static_writeProbeAnswers(answers, common_addresses, odd_index, odd_addresses);
    answers[count++] = (SubdomainTestAnswer_t){ "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, www_address };
    g_answers     = answers;
    g_answerCount = count;
    static_forgetCalls();
    g_wildcardIpAddresses.m_count = 77;
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
    TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
    TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
    g_answers = NULL;
  }
}

void test_lookupDnsNames_no_bypass_when_a_probe_has_an_extra_address(void)
{
  static const char* const probe_1_addresses[] = { "192.0.2.11", "192.0.2.12", NULL };
  static const char* const probe_2_addresses[] = { "192.0.2.11", "192.0.2.12", "192.0.2.13", NULL };
  static_assertNoBypass(probe_1_addresses, probe_2_addresses);
  static_assertNoBypass(probe_2_addresses, probe_1_addresses);
}

void test_lookupDnsNames_no_bypass_when_the_probe_addresses_differ(void)
{
  static const char* const probe_1_addresses[] = { "192.0.2.21", "192.0.2.22", NULL };
  static const char* const probe_2_addresses[] = { "192.0.2.21", "192.0.2.23", NULL };
  static_assertNoBypass(probe_1_addresses, probe_2_addresses);
}

void test_lookupDnsNames_no_bypass_when_a_probe_repeats_an_address(void)
{
  static const char* const repeated[] = { "192.0.2.31", "192.0.2.31", NULL };
  static const char* const distinct[] = { "192.0.2.31", "192.0.2.32", NULL };
  static const char* const single[]   = { "192.0.2.31", NULL };
  static_assertNoBypass(repeated, distinct);
  static_assertNoBypass(distinct, repeated);
  static_assertNoBypass(repeated, single);
}

void test_lookupDnsNames_no_bypass_when_a_wildcard_ip_address_does_not_fit(void)
{
  static const char* const too_long[]    = { "192.0.2.255.abcd", NULL };
  static const char* const longest[]     = { "255.255.255.255", NULL };
  static const char* const www_address[] = { "198.51.100.41", NULL };
  TEST_ASSERT_EQUAL_INT(INET_ADDRSTRLEN, (int)strlen(too_long[0]));
  TEST_ASSERT_EQUAL_INT(INET_ADDRSTRLEN - 1, (int)strlen(longest[0]));
  static_assertNoBypass(too_long, too_long);

  SubdomainTestAnswer_t answers[SUBDOMAIN_TEST_PROBE_COUNT + 1];
  int count = static_writeProbeAnswers(answers, longest, 0, longest);
  answers[count++] = (SubdomainTestAnswer_t){ "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, www_address };
  g_answers     = answers;
  g_answerCount = count;
  static_forgetCalls();
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(1, g_nameSet->m_count);
  static_assertAddressState("www.example.com", SUBDOMAIN_ADDRESS_FOUND);
  TEST_ASSERT_EQUAL_INT(1, g_wildcardIpAddresses.m_count);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", g_wildcardIpAddresses.ma_ipAddresses[0]);
  g_answers = NULL;
}

void test_lookupDnsNames_no_bypass_when_one_a_probe_is_nxdomain(void)
{
  static const char* const address[] = { "192.0.2.41", NULL };
  static_assertNoBypass(address, NULL);
  static_assertNoBypass(NULL, address);
}

void test_lookupDnsNames_no_bypass_when_a_cname_probe_is_not_empty(void)
{
  static const char* const address[]     = { "192.0.2.51", NULL };
  static const char* const www_address[] = { "198.51.100.51", NULL };
  static const char* const target[]      = { "lb.example.net", NULL };
  DnsAnswerStatus_t cname_statuses[2] = { DNS_ANSWER_OK, DNS_ANSWER_TIMEOUT };
  for (int probe = 0; probe < SUBDOMAIN_TEST_PROBE_COUNT; probe++)
  {
    for (int kind = 0; kind < 2; kind++)
    {
      SubdomainTestAnswer_t answers[SUBDOMAIN_TEST_PROBE_COUNT + 2];
      int count = static_writeProbeAnswers(answers, address, 0, address);
      answers[count++] = (SubdomainTestAnswer_t){ g_probeNames[probe],  DNS_RECORD_TYPE_CNAME, cname_statuses[kind], kind == 0 ? target : NULL };
      answers[count++] = (SubdomainTestAnswer_t){ "www.example.com",    DNS_RECORD_TYPE_A,     DNS_ANSWER_OK,        www_address };
      g_answers     = answers;
      g_answerCount = count;
      static_forgetCalls();
      g_wildcardIpAddresses.m_count = 77;
      TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_PRESENT, static_lookupExample());
      TEST_ASSERT_EQUAL_INT(0, g_nameSet->m_count);
      TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
      g_answers = NULL;
    }
  }
}

void test_lookupDnsNames_without_probes_reads_no_bypass(void)
{
  static const char* const mx_hosts[] = { "mx7.example.com", NULL };
  static const char* const ns_names[] = { "ns9.example.com", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, mx_hosts },
    { "example.com", DNS_RECORD_TYPE_NS, DNS_ANSWER_OK, ns_names },
  };
  g_answers            = answers;
  g_answerCount        = 2;
  g_getrandomShortCall = 0;
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_UNDETERMINED, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
  TEST_ASSERT_EQUAL_INT(2, g_nameSet->m_count);
  static_assertAddressState("mx7.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("ns9.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
}

void test_lookupDnsNames_absent_marks_kept_guesses_found(void)
{
  static const char* const www_address[] = { "203.0.113.70", NULL };
  static const char* const vpn_address[] = { "203.0.113.71", NULL };
  static const char* const mx_hosts[]    = { "relay.example.com", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "example.com",     DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, mx_hosts },
    { "www.example.com", DNS_RECORD_TYPE_A,  DNS_ANSWER_OK, www_address },
    { "vpn.example.com", DNS_RECORD_TYPE_A,  DNS_ANSWER_OK, vpn_address },
  };
  g_answers     = answers;
  g_answerCount = 3;
  subdomain_addName(g_nameSet, "vpn.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  subdomain_addName(g_nameSet, "portal.example.com", "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(0, g_wildcardIpAddresses.m_count);
  TEST_ASSERT_EQUAL_INT(4, g_nameSet->m_count);
  static_assertAddressState("www.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertAddressState("vpn.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertNameSources("vpn.example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS | SUBDOMAIN_SOURCE_DNS_WORDLIST);
  static_assertAddressState("portal.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("relay.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
}

void test_lookupDnsNames_full_set_refuses_a_guess_and_writes_no_state(void)
{
  static const char* const www_address[] = { "203.0.113.70", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "www.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, www_address },
  };
  g_answers     = answers;
  g_answerCount = 1;
  for (int i = 0; i < SUBDOMAIN_MAX_NAME_COUNT; i++)
  {
    char name[64];
    snprintf(name, sizeof(name), "n%d.example.com", i);
    subdomain_addName(g_nameSet, name, "example.com", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  }
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_MAX_NAME_COUNT, g_nameSet->m_count);
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_WILDCARD_ABSENT, static_lookupExample());
  TEST_ASSERT_EQUAL_INT(SUBDOMAIN_MAX_NAME_COUNT, g_nameSet->m_count);
  for (int i = 0; i < SUBDOMAIN_MAX_NAME_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_ADDRESS_UNMEASURED, g_nameSet->mp_addressStates[i]);
}

void test_lookupAddressStates_absent_reads_each_answer(void)
{
  static const char* const alpha_address[] = { "203.0.113.81", NULL };
  static const char* const hotel_address[] = { "203.0.113.82", NULL };
  static const char* const india_address[] = { "203.0.113.83", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "alpha.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_OK,              alpha_address },
    { "bravo.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_NXDOMAIN,        NULL },
    { "charlie.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK,              NULL },
    { "delta.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_TIMEOUT,         NULL },
    { "echo.example.com",    DNS_RECORD_TYPE_A, DNS_ANSWER_SERVER_ERROR,    NULL },
    { "foxtrot.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_NOT_PUBLIC_NAME, NULL },
    { "golf.example.com",    DNS_RECORD_TYPE_A, DNS_ANSWER_NXDOMAIN,        NULL },
    { "hotel.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_OK,              hotel_address },
    { "india.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_OK,              india_address },
  };
  g_answers     = answers;
  g_answerCount = 9;
  int india   = static_addNameWithState("india.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int golf    = static_addNameWithState("golf.example.com", SUBDOMAIN_ADDRESS_FOUND);
  int alpha   = static_addNameWithState("alpha.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int bravo   = static_addNameWithState("bravo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int hotel   = static_addNameWithState("hotel.example.com", SUBDOMAIN_ADDRESS_NONE);
  int charlie = static_addNameWithState("charlie.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int delta   = static_addNameWithState("delta.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int echo    = static_addNameWithState("echo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  int foxtrot = static_addNameWithState("foxtrot.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  (void)india;
  const int indexes[] = { golf, alpha, bravo, hotel, charlie, delta, echo, foxtrot };
  SubdomainWildcardIpAddresses_t no_addresses = { .m_count = 0 };

  subdomain_lookupAddressStates(g_nameSet, indexes, 8, SUBDOMAIN_WILDCARD_ABSENT, &no_addresses);

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] <= 1000);
  TEST_ASSERT_TRUE(g_callDeadlinesMs[0] > 900);
  static const char* const asked[] = {
    "alpha.example.com", "bravo.example.com", "charlie.example.com",
    "delta.example.com", "echo.example.com", "foxtrot.example.com",
  };
  TEST_ASSERT_EQUAL_INT(6, g_questionCount);
  for (int i = 0; i < 6; i++)
  {
    TEST_ASSERT_EQUAL_STRING(asked[i], g_questions[i].ma_name);
    TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_questions[i].m_type);
  }
  TEST_ASSERT_EQUAL_INT(6, g_answerFreeCount);
  static_assertAddressState("alpha.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertAddressState("bravo.example.com", SUBDOMAIN_ADDRESS_NONE);
  static_assertAddressState("charlie.example.com", SUBDOMAIN_ADDRESS_NONE);
  static_assertAddressState("delta.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("echo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("foxtrot.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("golf.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertAddressState("hotel.example.com", SUBDOMAIN_ADDRESS_NONE);
  static_assertAddressState("india.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
}

void test_lookupAddressStates_thirty_three_names_take_two_rounds(void)
{
  int indexes[33];
  for (int i = 0; i < 33; i++)
  {
    char name[64];
    snprintf(name, sizeof(name), "host%d.example.com", i + 3);
    indexes[i] = static_addNameWithState(name, SUBDOMAIN_ADDRESS_UNMEASURED);
  }
  SubdomainWildcardIpAddresses_t no_addresses = { .m_count = 0 };

  subdomain_lookupAddressStates(g_nameSet, indexes, 33, SUBDOMAIN_WILDCARD_ABSENT, &no_addresses);

  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_INT(32, g_callQuestionCounts[0]);
  TEST_ASSERT_EQUAL_INT(1, g_callQuestionCounts[1]);
  TEST_ASSERT_EQUAL_INT(33, g_answerFreeCount);
  for (int i = 0; i < 33; i++)
    TEST_ASSERT_EQUAL_INT(SUBDOMAIN_ADDRESS_NONE, g_nameSet->mp_addressStates[indexes[i]]);
}

void test_lookupAddressStates_asks_nothing_when_every_name_is_measured(void)
{
  int found = static_addNameWithState("kilo.example.com", SUBDOMAIN_ADDRESS_FOUND);
  int none  = static_addNameWithState("lima.example.com", SUBDOMAIN_ADDRESS_NONE);
  const int indexes[] = { found, none };
  SubdomainWildcardIpAddresses_t no_addresses = { .m_count = 0 };

  subdomain_lookupAddressStates(g_nameSet, indexes, 2, SUBDOMAIN_WILDCARD_ABSENT, &no_addresses);

  TEST_ASSERT_EQUAL_INT(0, g_callCount);
  TEST_ASSERT_EQUAL_INT(0, g_answerFreeCount);
  static_assertAddressState("kilo.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertAddressState("lima.example.com", SUBDOMAIN_ADDRESS_NONE);
}

void test_lookupAddressStates_bypass_keeps_only_disjoint_addresses(void)
{
  static const char* const alpha_address[]   = { "198.51.100.20", NULL };
  static const char* const bravo_addresses[] = { "198.51.100.21", "192.0.2.9", NULL };
  static const char* const charlie_address[] = { "192.0.2.1", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "alpha.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_OK,       alpha_address },
    { "bravo.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_OK,       bravo_addresses },
    { "charlie.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK,       charlie_address },
    { "delta.example.com",   DNS_RECORD_TYPE_A, DNS_ANSWER_NXDOMAIN, NULL },
    { "echo.example.com",    DNS_RECORD_TYPE_A, DNS_ANSWER_OK,       NULL },
  };
  g_answers     = answers;
  g_answerCount = 5;
  const int indexes[] = {
    static_addNameWithState("alpha.example.com", SUBDOMAIN_ADDRESS_UNMEASURED),
    static_addNameWithState("bravo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED),
    static_addNameWithState("charlie.example.com", SUBDOMAIN_ADDRESS_UNMEASURED),
    static_addNameWithState("delta.example.com", SUBDOMAIN_ADDRESS_UNMEASURED),
    static_addNameWithState("echo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED),
  };
  SubdomainWildcardIpAddresses_t wildcard_ip_addresses = { .m_count = 2, .ma_ipAddresses = { "192.0.2.1", "192.0.2.9" } };

  subdomain_lookupAddressStates(g_nameSet, indexes, 5, SUBDOMAIN_WILDCARD_PRESENT, &wildcard_ip_addresses);

  TEST_ASSERT_EQUAL_INT(5, g_questionCount);
  TEST_ASSERT_EQUAL_INT(5, g_answerFreeCount);
  static_assertAddressState("alpha.example.com", SUBDOMAIN_ADDRESS_FOUND);
  static_assertAddressState("bravo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("charlie.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("delta.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
  static_assertAddressState("echo.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
}

void test_lookupAddressStates_asks_nothing_without_a_usable_verdict(void)
{
  static const char* const address[] = { "198.51.100.90", NULL };
  static const SubdomainTestAnswer_t answers[] = {
    { "mike.example.com", DNS_RECORD_TYPE_A, DNS_ANSWER_OK, address },
  };
  g_answers     = answers;
  g_answerCount = 1;
  const int indexes[] = { static_addNameWithState("mike.example.com", SUBDOMAIN_ADDRESS_UNMEASURED) };
  SubdomainWildcardIpAddresses_t no_addresses = { .m_count = 0 };
  SubdomainWildcardIpAddresses_t one_address  = { .m_count = 1, .ma_ipAddresses = { "192.0.2.95" } };

  subdomain_lookupAddressStates(g_nameSet, indexes, 1, SUBDOMAIN_WILDCARD_UNDETERMINED, &no_addresses);
  subdomain_lookupAddressStates(g_nameSet, indexes, 1, SUBDOMAIN_WILDCARD_UNDETERMINED, &one_address);
  subdomain_lookupAddressStates(g_nameSet, indexes, 1, SUBDOMAIN_WILDCARD_PRESENT, &no_addresses);

  TEST_ASSERT_EQUAL_INT(0, g_callCount);
  static_assertAddressState("mike.example.com", SUBDOMAIN_ADDRESS_UNMEASURED);
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
  RUN_TEST(test_lookupDnsNames_nxdomain_probes_mean_absent_and_keep_hits);
  RUN_TEST(test_lookupDnsNames_probes_without_a_record_mean_absent);
  RUN_TEST(test_lookupDnsNames_unmeasured_probe_means_undetermined);
  RUN_TEST(test_lookupDnsNames_reads_names_from_mx_ns_and_spf);
  RUN_TEST(test_lookupDnsNames_reads_an_spf_host_of_the_longest_length);
  RUN_TEST(test_lookupDnsNames_reads_no_spf_from_two_records);
  RUN_TEST(test_lookupDnsNames_merges_the_sources_of_one_name);
  RUN_TEST(test_createNameSet_starts_with_every_address_unmeasured);
  RUN_TEST(test_lookupDnsNames_dangling_wildcard_cname_means_present);
  RUN_TEST(test_lookupDnsNames_first_cname_probe_with_a_record_means_present);
  RUN_TEST(test_lookupDnsNames_second_cname_probe_with_a_record_means_present);
  RUN_TEST(test_lookupDnsNames_cname_probe_timeout_means_undetermined);
  RUN_TEST(test_lookupDnsNames_bypass_keeps_a_guess_outside_the_wildcard_ip_addresses);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_a_probe_has_an_extra_address);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_the_probe_addresses_differ);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_a_probe_repeats_an_address);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_a_wildcard_ip_address_does_not_fit);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_one_a_probe_is_nxdomain);
  RUN_TEST(test_lookupDnsNames_no_bypass_when_a_cname_probe_is_not_empty);
  RUN_TEST(test_lookupDnsNames_without_probes_reads_no_bypass);
  RUN_TEST(test_lookupDnsNames_absent_marks_kept_guesses_found);
  RUN_TEST(test_lookupDnsNames_full_set_refuses_a_guess_and_writes_no_state);
  RUN_TEST(test_lookupAddressStates_absent_reads_each_answer);
  RUN_TEST(test_lookupAddressStates_thirty_three_names_take_two_rounds);
  RUN_TEST(test_lookupAddressStates_asks_nothing_when_every_name_is_measured);
  RUN_TEST(test_lookupAddressStates_bypass_keeps_only_disjoint_addresses);
  RUN_TEST(test_lookupAddressStates_asks_nothing_without_a_usable_verdict);
  return UNITY_END();
}
