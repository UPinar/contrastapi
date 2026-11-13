#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "unity/unity.h"
#include "emailcheck.h"

#define FAKE_MAX_TEXT_COUNT 4

#define FAKE_MAX_ANSWER_COUNT 40

typedef struct {
  const char*       mp_name;
  DnsRecordType_t   m_type;
  DnsAnswerStatus_t m_status;
  const char*       ma_texts[FAKE_MAX_TEXT_COUNT];
  bool              m_hasNullMx;
} FakeAnswer_t;

typedef struct {
  int             m_questionCount;
  int             m_deadlineMs;
  char            ma_names[DNS_MAX_QUESTION_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsRecordType_t ma_types[DNS_MAX_QUESTION_COUNT];
} AskCall_t;

static FakeAnswer_t g_fakes[FAKE_MAX_ANSWER_COUNT];
static int          g_fakeCount;
static AskCall_t    g_calls[2];
static int          g_callCount;
static int64_t      g_nowMs;
static int64_t      g_askAdvanceMs;
static int          g_parseDkimCount;

void __real_emailauth_parseDkim(const DnsRecordText_t* record, EmailAuthDkim_t* dkim_out);

void __wrap_emailauth_parseDkim(const DnsRecordText_t* record, EmailAuthDkim_t* dkim_out)
{
  g_parseDkimCount++;
  __real_emailauth_parseDkim(record, dkim_out);
}

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  AskCall_t* call = &g_calls[g_callCount < 2 ? g_callCount : 1];
  g_callCount++;
  g_nowMs += g_askAdvanceMs;
  call->m_questionCount = question_count;
  call->m_deadlineMs    = deadline_ms;
  for (int i = 0; i < question_count; i++)
  {
    snprintf(call->ma_names[i], sizeof(call->ma_names[i]), "%s", questions[i].mp_domainName);
    call->ma_types[i] = questions[i].m_type;

    DnsAnswer_t* answer = &answers_out[i];
    memset(answer, 0, sizeof(*answer));
    answer->m_status = DNS_ANSWER_NXDOMAIN;
    const FakeAnswer_t* fake = NULL;
    for (int j = 0; j < g_fakeCount && fake == NULL; j++)
      if (strcmp(g_fakes[j].mp_name, questions[i].mp_domainName) == 0 && g_fakes[j].m_type == questions[i].m_type)
        fake = &g_fakes[j];
    if (fake == NULL)
      continue;

    answer->m_status    = fake->m_status;
    answer->m_hasNullMx = fake->m_hasNullMx;
    int text_count = 0;
    while (text_count < FAKE_MAX_TEXT_COUNT && fake->ma_texts[text_count] != NULL)
      text_count++;
    if (fake->m_status != DNS_ANSWER_OK || text_count == 0)
      continue;
    if (fake->m_type == DNS_RECORD_TYPE_MX)
    {
      answer->mp_mxRecords = calloc((size_t)text_count, sizeof(DnsMxRecord_t));
      for (int j = 0; j < text_count; j++)
      {
        answer->mp_mxRecords[j].m_priority  = (uint16_t)(10 * (j + 1));
        answer->mp_mxRecords[j].mp_hostname = strdup(fake->ma_texts[j]);
      }
    }
    else
    {
      answer->mp_texts = calloc((size_t)text_count, sizeof(DnsRecordText_t));
      for (int j = 0; j < text_count; j++)
      {
        answer->mp_texts[j].mp_bytes    = strdup(fake->ma_texts[j]);
        answer->mp_texts[j].m_byteCount = strlen(fake->ma_texts[j]);
      }
    }
    answer->m_recordCount = text_count;
  }
}

static EMAILAUTHCHECKRecord_t    g_record;
static EMAILADDRESSCHECKRecord_t g_addressRecord;

void setUp(void)
{
  memset(g_fakes, 0, sizeof(g_fakes));
  memset(g_calls, 0, sizeof(g_calls));
  g_fakeCount    = 0;
  g_callCount    = 0;
  g_nowMs          = 1000000;
  g_askAdvanceMs   = 0;
  g_parseDkimCount = 0;
}

void tearDown(void)
{
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  emailcheck_EMAILADDRESSCHECKRecordFree(&g_addressRecord);
}

static void static_addFake(FakeAnswer_t fake)
{
  TEST_ASSERT_TRUE(g_fakeCount < FAKE_MAX_ANSWER_COUNT);
  g_fakes[g_fakeCount++] = fake;
}

#define KEY_DER_SIZE 700

#define KEY_RECORD_SIZE 1100

static const unsigned char RSA_ALGORITHM_DER[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

static int static_writeDerLength(int length, unsigned char* out)
{
  if (length < 0x80)
  {
    out[0] = (unsigned char)length;
    return 1;
  }
  if (length < 0x100)
  {
    out[0] = 0x81;
    out[1] = (unsigned char)length;
    return 2;
  }
  out[0] = 0x82;
  out[1] = (unsigned char)(length >> 8);
  out[2] = (unsigned char)length;
  return 3;
}

static int static_writeDerElement(unsigned char tag, const unsigned char* content, int length, unsigned char* out)
{
  out[0] = tag;
  int header_len = 1 + static_writeDerLength(length, out + 1);
  memcpy(out + header_len, content, (size_t)length);
  return header_len + length;
}

static void static_writeRsaKeyBase64(int key_bits, bool is_bare_rsa, bool is_modulus_negative, char* base64_out)
{
  unsigned char modulus[KEY_DER_SIZE] = { 0 };
  int           byte_count = (key_bits + 7) / 8;
  int           lead       = (key_bits % 8 == 0 && !is_modulus_negative) ? 1 : 0;
  for (int i = 0; i < byte_count; i++)
    modulus[lead + i] = 0xa5;
  modulus[lead]                  = (unsigned char)(1u << ((key_bits - 1) % 8));
  modulus[lead + byte_count - 1] |= 1;

  static const unsigned char exponent[] = { 0x01, 0x00, 0x01 };
  unsigned char integers[KEY_DER_SIZE];
  int           integers_len = static_writeDerElement(0x02, modulus, lead + byte_count, integers);
  integers_len += static_writeDerElement(0x02, exponent, sizeof(exponent), integers + integers_len);
  unsigned char rsa_key[KEY_DER_SIZE];
  int           rsa_key_len = static_writeDerElement(0x30, integers, integers_len, rsa_key);

  unsigned char der[KEY_DER_SIZE];
  int           der_len = rsa_key_len;
  if (is_bare_rsa)
    memcpy(der, rsa_key, (size_t)rsa_key_len);
  else
  {
    unsigned char bit_string[KEY_DER_SIZE] = { 0 };
    memcpy(bit_string + 1, rsa_key, (size_t)rsa_key_len);
    unsigned char info[KEY_DER_SIZE];
    memcpy(info, RSA_ALGORITHM_DER, sizeof(RSA_ALGORITHM_DER));
    int info_len = (int)sizeof(RSA_ALGORITHM_DER);
    info_len += static_writeDerElement(0x03, bit_string, rsa_key_len + 1, info + info_len);
    der_len = static_writeDerElement(0x30, info, info_len, der);
  }
  EVP_EncodeBlock((unsigned char*)base64_out, der, der_len);
}

static const char* static_rsaKeyRecord(int slot, const char* before, int key_bits, bool is_bare_rsa, bool is_modulus_negative)
{
  static char records[4][KEY_RECORD_SIZE];
  char        base64[KEY_RECORD_SIZE];
  static_writeRsaKeyBase64(key_bits, is_bare_rsa, is_modulus_negative, base64);
  int record_len = snprintf(records[slot], sizeof(records[slot]), "%sp=%s", before, base64);
  TEST_ASSERT_TRUE(record_len > 0 && (size_t)record_len < sizeof(records[slot]));
  return records[slot];
}

#define GOOD_SPF     "v=spf1 include:_spf.google.com -all"
#define GOOD_DMARC   "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
#define GOOD_MTA_STS "v=STSv1; id=20261023"

static void static_fakeGoodDomain(const char* except_name, DnsRecordType_t except_type)
{
  const FakeAnswer_t fakes[] = {
    { "example.com",                    DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_SPF },             false },
    { "example.com",                    DNS_RECORD_TYPE_MX,  DNS_ANSWER_OK, { "aspmx.l.google.com" }, false },
    { "_dmarc.example.com",             DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_DMARC },           false },
    { "_mta-sts.example.com",           DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_MTA_STS },         false },
    { "google._domainkey.example.com",  DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL },                 false },
  };
  for (size_t i = 0; i < sizeof(fakes) / sizeof(fakes[0]); i++)
  {
    if (except_name != NULL && strcmp(fakes[i].mp_name, except_name) == 0 && fakes[i].m_type == except_type)
      continue;
    static_addFake(fakes[i]);
    if (strcmp(fakes[i].mp_name, "google._domainkey.example.com") == 0)
      g_fakes[g_fakeCount - 1].ma_texts[0] = static_rsaKeyRecord(3, "v=DKIM1; k=rsa; ", 2048, false, false);
  }
}

static int static_resultOf(EmailCheckKind_t kind)
{
  for (int i = 0; i < g_record.m_checkCount; i++)
    if (g_record.ma_checks[i].m_kind == kind)
      return (int)g_record.ma_checks[i].m_result;
  return -1;
}

static void static_assertQuestions(const AskCall_t* call, const char* const* names, const DnsRecordType_t* types, int count)
{
  TEST_ASSERT_EQUAL_INT(count, call->m_questionCount);
  for (int i = 0; i < count; i++)
  {
    TEST_ASSERT_EQUAL_STRING(names[i], call->ma_names[i]);
    TEST_ASSERT_EQUAL_INT(types[i], call->ma_types[i]);
  }
}

static void static_writeLongDomain(int length, char* out)
{
  int cursor = 0;
  int left   = length - (int)strlen(".example.com");
  while (left > 0)
  {
    int label_len = left > 51 ? 50 : left;
    if (left > 51 && left - 51 < 2)
      label_len = left - 3;
    for (int i = 0; i < label_len; i++)
      out[cursor++] = 'a';
    left -= label_len;
    if (left > 0)
    {
      out[cursor++] = '.';
      left--;
    }
  }
  snprintf(out + cursor, (size_t)(VALIDATE_DOMAIN_NAME_MAX_LEN + 1 - cursor), ".example.com");
  TEST_ASSERT_EQUAL_INT(length, (int)strlen(out));
}

void test_checkDomain_asks_two_rounds_and_passes_every_check(void)
{
  static_fakeGoodDomain(NULL, DNS_RECORD_TYPE_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("Example.COM", NULL, &g_record));

  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  const char* const     first_names[] = { "example.com", "example.com", "_dmarc.example.com", "_mta-sts.example.com" };
  const DnsRecordType_t first_types[] = { DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_MX, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT };
  static_assertQuestions(&g_calls[0], first_names, first_types, 4);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS, g_calls[0].m_deadlineMs);
  const char* const     second_names[] = { "google._domainkey.example.com" };
  const DnsRecordType_t second_types[] = { DNS_RECORD_TYPE_TXT };
  static_assertQuestions(&g_calls[1], second_names, second_types, 1);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS, g_calls[1].m_deadlineMs);

  TEST_ASSERT_EQUAL_STRING("example.com", g_record.ma_domain);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_spfRecordCount);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_mailProviderCount);
  TEST_ASSERT_EQUAL_STRING("Google Workspace", g_record.ma_mailProviders[0]->mp_name);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER, g_record.m_dkimSelectorSource);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dkimSelectorCount);
  TEST_ASSERT_EQUAL_STRING("google", g_record.ma_dkimSelectors[0].ma_selector);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dkimStatus);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_KEY_FOUND, g_record.m_dkimKeyStatus);
  TEST_ASSERT_EQUAL_INT(2048, g_record.ma_dkimSelectors[0].m_firstKeyRecord.m_keyBits);
  TEST_ASSERT_FALSE(g_record.ma_dkimSelectors[0].m_hasSecondKeyRecord);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dmarcStatus);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcNameCount);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_DOMAIN, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(0, g_record.m_dmarcNameIndex);
  TEST_ASSERT_TRUE(g_record.m_isDmarcApplied);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, g_record.m_appliedDmarcPolicy);
  TEST_ASSERT_TRUE(g_record.m_hasMtaStsRecord);

  TEST_ASSERT_EQUAL_INT(EMAILCHECK_KIND_COUNT, g_record.m_checkCount);
  for (int i = 0; i < EMAILCHECK_KIND_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_INT(i, g_record.ma_checks[i].m_kind);
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, g_record.ma_checks[i].m_result);
  }
}

void test_checkDomain_asks_a_given_selector_in_the_first_round(void)
{
  static_fakeGoodDomain(NULL, DNS_RECORD_TYPE_TXT);
  static_addFake((FakeAnswer_t){ "Sel1._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  g_fakes[g_fakeCount - 1].ma_texts[0] = static_rsaKeyRecord(0, "", 2048, false, false);

  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("Example.COM", "Sel1", &g_record));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const char* const     names[] = { "example.com", "example.com", "_dmarc.example.com", "_mta-sts.example.com", "Sel1._domainkey.example.com" };
  const DnsRecordType_t types[] = { DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_MX, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT };
  static_assertQuestions(&g_calls[0], names, types, 5);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_SELECTOR_SOURCE_CALLER_GIVEN, g_record.m_dkimSelectorSource);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dkimSelectorCount);
  TEST_ASSERT_EQUAL_STRING("Sel1", g_record.ma_dkimSelectors[0].ma_selector);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_KEY_FOUND, g_record.m_dkimKeyStatus);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
}

void test_checkDomain_refuses_a_selector_whose_name_is_too_long(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_writeLongDomain(200, domain);
  char selector[64];
  memset(selector, 's', 41);
  selector[41] = '\0';

  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NOT_FOUND, emailcheck_checkDomain(domain, selector, &g_record));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_INT(5, g_calls[0].m_questionCount);
  TEST_ASSERT_EQUAL_INT(VALIDATE_DOMAIN_NAME_MAX_LEN, (int)strlen(g_calls[0].ma_names[4]));
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  selector[41] = 's';
  selector[42] = '\0';
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_INVALID_NAME, emailcheck_checkDomain(domain, selector, &g_record));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
}

void test_checkDomain_refuses_an_invalid_domain_or_selector(void)
{
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_INVALID_NAME, emailcheck_checkDomain("printer.local", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_INVALID_NAME, emailcheck_checkDomain("example.com", "a_b", &g_record));
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_INVALID_NAME, emailcheck_checkDomain("example.com", "_sel", &g_record));
  TEST_ASSERT_EQUAL_INT(0, g_callCount);

  static_fakeGoodDomain(NULL, DNS_RECORD_TYPE_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", "", &g_record));
  TEST_ASSERT_EQUAL_INT(4, g_calls[0].m_questionCount);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER, g_record.m_dkimSelectorSource);
}

void test_checkDomain_not_found_when_the_domain_does_not_exist(void)
{
  const struct {
    DnsAnswerStatus_t m_txtStatus;
    DnsAnswerStatus_t m_mxStatus;
    DnsLookupStatus_t m_expected;
  } cases[] = {
    { DNS_ANSWER_NXDOMAIN, DNS_ANSWER_NXDOMAIN, DNS_LOOKUP_NOT_FOUND },
    { DNS_ANSWER_NXDOMAIN, DNS_ANSWER_TIMEOUT,  DNS_LOOKUP_NOT_FOUND },
    { DNS_ANSWER_TIMEOUT,  DNS_ANSWER_NXDOMAIN, DNS_LOOKUP_NOT_FOUND },
    { DNS_ANSWER_NXDOMAIN, DNS_ANSWER_OK,       DNS_LOOKUP_OK },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, cases[i].m_txtStatus, { NULL }, false });
    static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX,  cases[i].m_mxStatus,  { "mx.example.net" }, false });
    TEST_ASSERT_EQUAL_INT(cases[i].m_expected, emailcheck_checkDomain("example.com", NULL, &g_record));
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_no_answer_when_no_first_round_question_is_answered(void)
{
  const char* const timed_out[] = { "example.com", "_dmarc.example.com", "_mta-sts.example.com" };
  for (int i = 0; i < 3; i++)
    static_addFake((FakeAnswer_t){ timed_out[i], DNS_RECORD_TYPE_TXT, DNS_ANSWER_TIMEOUT, { NULL }, false });
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_SERVER_ERROR, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  g_fakes[2] = (FakeAnswer_t){ "_mta-sts.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_MTA_STS }, false };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_MTA_STS));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_SPF_RECORD));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_MX));
}

void test_checkDomain_no_memory_when_an_answer_could_not_be_allocated(void)
{
  static_fakeGoodDomain("example.com", DNS_RECORD_TYPE_MX);
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_NO_MEMORY, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_MEMORY, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_fakeGoodDomain("google._domainkey.example.com", DNS_RECORD_TYPE_TXT);
  static_addFake((FakeAnswer_t){ "google._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_NO_MEMORY, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_MEMORY, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
}

void test_EMAILAUTHCHECKRecordFree_ignores_null(void)
{
  emailcheck_EMAILAUTHCHECKRecordFree(NULL);
}

void test_checkDomain_leaves_out_the_checks_of_a_failed_section(void)
{
  static_fakeGoodDomain("_dmarc.example.com", DNS_RECORD_TYPE_TXT);
  static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_SERVER_ERROR, { NULL }, false });
  g_fakes[1].m_status = DNS_ANSWER_TIMEOUT;

  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_SERVER_ERROR, g_record.m_dmarcStatus);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcNameCount);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_mailProviderCount);
  TEST_ASSERT_EQUAL_STRING("google._domainkey.example.com", g_calls[1].ma_names[0]);
  TEST_ASSERT_EQUAL_INT(1, g_calls[1].m_questionCount);
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_POLICY));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_MX));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_KIND_COUNT - 5, g_record.m_checkCount);
}

static DnsLookupStatus_t static_checkWithDmarcRecords(const char* domain, const char* const* records)
{
  static_addFake((FakeAnswer_t){ domain, DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  for (int i = 0; records[i] != NULL; i += 2)
    static_addFake((FakeAnswer_t){ records[i], DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { records[i + 1] }, false });
  return emailcheck_checkDomain(domain, NULL, &g_record);
}

void test_checkDomain_walk_picks_the_record_with_the_fewest_labels(void)
{
  const char* const records[] = {
    "_dmarc.mail.example.com", "v=DMARC1; p=none",
    "_dmarc.example.com",      "v=DMARC1; p=reject; sp=quarantine",
    NULL,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", records));

  TEST_ASSERT_EQUAL_INT(4, g_record.m_dmarcNameCount);
  TEST_ASSERT_EQUAL_STRING("_dmarc.mail.example.com", g_calls[1].ma_names[0]);
  TEST_ASSERT_EQUAL_STRING("_dmarc.example.com",      g_calls[1].ma_names[1]);
  TEST_ASSERT_EQUAL_STRING("_dmarc.com",              g_calls[1].ma_names[2]);
  TEST_ASSERT_EQUAL_STRING("default._domainkey.a.mail.example.com", g_calls[1].ma_names[3]);
  TEST_ASSERT_EQUAL_INT(3 + EMAILDATA_COMMON_DKIM_SELECTOR_COUNT, g_calls[1].m_questionCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_NONE, g_record.m_ownDmarcRecordCount);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(2, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, g_record.m_dmarcRecord.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, g_record.m_appliedDmarcPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
}

void test_checkDomain_walk_stops_at_psd_n(void)
{
  const char* const records[] = {
    "_dmarc.mail.example.com", "v=DMARC1; p=quarantine; psd=n",
    "_dmarc.example.com",      "v=DMARC1; p=reject",
    NULL,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", records));

  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, g_record.m_appliedDmarcPolicy);
}

void test_checkDomain_walk_applies_the_public_suffix_record(void)
{
  const char* const records[] = {
    "_dmarc.com", "v=DMARC1; p=reject; sp=none; psd=y",
    NULL,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", records));

  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(3, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, g_record.m_appliedDmarcPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_DMARC_POLICY));
}

void test_checkDomain_walk_applies_the_record_under_the_public_suffix(void)
{
  const char* const records[] = {
    "_dmarc.mail.example.com", "v=DMARC1; p=none",
    "_dmarc.example.com",      "v=DMARC1; p=quarantine",
    "_dmarc.com",              "v=DMARC1; p=reject; psd=y",
    NULL,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", records));

  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(2, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, g_record.m_appliedDmarcPolicy);
}

void test_checkDomain_walk_stops_at_psd_y(void)
{
  const char* const stopped[] = {
    "_dmarc.example.com", "v=DMARC1; p=reject; psd=y",
    "_dmarc.com",         "v=DMARC1; p=none",
    NULL,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", stopped));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(2, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, g_record.m_appliedDmarcPolicy);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "google-site-verification=x", "v=DMARC1; p=quarantine" }, false });
  const char* const first[] = { "_dmarc.com", "v=DMARC1; p=none; psd=y", NULL };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("mail.example.com", first));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcRecordIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, g_record.m_appliedDmarcPolicy);
}

void test_checkDomain_walk_skips_a_name_with_two_records(void)
{
  static_addFake((FakeAnswer_t){ "_dmarc.mail.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=DMARC1; p=none; psd=n", "v=DMARC1; p=quarantine" }, false });
  const char* const records[] = { "_dmarc.example.com", "v=DMARC1; p=reject", NULL };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", records));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(2, g_record.m_dmarcNameIndex);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, g_record.m_appliedDmarcPolicy);
}

void test_checkDomain_walk_fails_only_before_it_stops(void)
{
  static_addFake((FakeAnswer_t){ "_dmarc.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_TIMEOUT, { NULL }, false });
  const char* const stopped[] = { "_dmarc.mail.example.com", "v=DMARC1; p=reject; psd=n", NULL };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", stopped));
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dmarcStatus);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "_dmarc.mail.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_TIMEOUT, { NULL }, false });
  const char* const failed[] = { "_dmarc.example.com", "v=DMARC1; p=reject", NULL };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("a.mail.example.com", failed));
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.m_dmarcStatus);
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
}

void test_checkDomain_walk_shortens_a_long_domain_to_seven_labels(void)
{
  const struct {
    const char* mp_domain;
    int         m_walkNameCount;
    const char* mp_firstWalkName;
  } cases[] = {
    { "a.b.c.d.e.f.g.h.i.example.com", 7, "_dmarc.e.f.g.h.i.example.com" },
    { "a.b.c.d.e.f.g.example.com",     7, "_dmarc.c.d.e.f.g.example.com" },
    { "a.b.c.d.e.f.example.com",       7, "_dmarc.b.c.d.e.f.example.com" },
    { "example.com",                   1, "_dmarc.com" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    const char* const none[] = { NULL };
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords(cases[i].mp_domain, none));
    TEST_ASSERT_EQUAL_INT(1 + cases[i].m_walkNameCount, g_record.m_dmarcNameCount);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_firstWalkName, g_calls[1].ma_names[0]);
    TEST_ASSERT_EQUAL_STRING("_dmarc.com", g_calls[1].ma_names[cases[i].m_walkNameCount - 1]);
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_NONE, g_record.m_dmarcSource);
    TEST_ASSERT_FALSE(g_record.m_isDmarcApplied);
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_FAIL, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
    TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_POLICY));
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_walks_past_two_own_records(void)
{
  static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=DMARC1; p=reject", "v=DMARC1; p=none" }, false });
  const char* const records[] = { "_dmarc.com", "v=DMARC1; p=quarantine; psd=y; rua=mailto:a@example.net", NULL };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("example.com", records));

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_MANY, g_record.m_ownDmarcRecordCount);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX, g_record.m_dmarcSource);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_FAIL, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DMARC_POLICY));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DMARC_REPORTING));
}

void test_checkDomain_applies_the_rfc_9989_policy_rules(void)
{
  const struct {
    const char*            mp_name;
    const char*            mp_record;
    bool                   m_isApplied;
    EmailAuthDmarcPolicy_t m_policy;
    EmailCheckResult_t     m_result;
  } cases[] = {
    { "_dmarc.mail.example.com", "v=DMARC1; sp=reject",                              true,  EMAILAUTH_DMARC_POLICY_NONE,       EMAILCHECK_RESULT_WARN },
    { "_dmarc.mail.example.com", "v=DMARC1; p=quarantine; sp=reject",                true,  EMAILAUTH_DMARC_POLICY_QUARANTINE, EMAILCHECK_RESULT_PASS },
    { "_dmarc.example.com",      "v=DMARC1; p=quarantine; sp=reject",                true,  EMAILAUTH_DMARC_POLICY_REJECT,     EMAILCHECK_RESULT_PASS },
    { "_dmarc.example.com",      "v=DMARC1; p=quarantine",                           true,  EMAILAUTH_DMARC_POLICY_QUARANTINE, EMAILCHECK_RESULT_PASS },
    { "_dmarc.mail.example.com", "v=DMARC1; p=bogus; rua=mailto:a@example.com",      true,  EMAILAUTH_DMARC_POLICY_NONE,       EMAILCHECK_RESULT_WARN },
    { "_dmarc.mail.example.com", "v=DMARC1; p=bogus",                                false, EMAILAUTH_DMARC_POLICY_NONE,       EMAILCHECK_RESULT_FAIL },
    { "_dmarc.mail.example.com", "v=DMARC1; p=reject; sp=bogus; rua=mailto:a@x.com", true,  EMAILAUTH_DMARC_POLICY_NONE,       EMAILCHECK_RESULT_WARN },
    { "_dmarc.mail.example.com", "v=DMARC1; p=reject; np=bogus; rua=bogus",          false, EMAILAUTH_DMARC_POLICY_NONE,       EMAILCHECK_RESULT_FAIL },
    { "_dmarc.example.com",      "v=DMARC1; p=quarantine; np=reject",                true,  EMAILAUTH_DMARC_POLICY_QUARANTINE, EMAILCHECK_RESULT_PASS },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    const char* const records[] = { cases[i].mp_name, cases[i].mp_record, NULL };
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("mail.example.com", records));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isApplied, g_record.m_isDmarcApplied, cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_policy, g_record.m_appliedDmarcPolicy, cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_result, static_resultOf(EMAILCHECK_KIND_DMARC_POLICY), cases[i].mp_record);
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }

  const struct {
    DnsAnswerStatus_t m_txtStatus;
    DnsAnswerStatus_t m_mxStatus;
  } statuses[] = {
    { DNS_ANSWER_TIMEOUT,  DNS_ANSWER_TIMEOUT },
    { DNS_ANSWER_NXDOMAIN, DNS_ANSWER_OK },
  };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    setUp();
    static_addFake((FakeAnswer_t){ "mail.example.com", DNS_RECORD_TYPE_TXT, statuses[i].m_txtStatus, { NULL }, false });
    static_addFake((FakeAnswer_t){ "mail.example.com", DNS_RECORD_TYPE_MX,  statuses[i].m_mxStatus,  { "mx.example.net" }, false });
    static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=DMARC1; p=quarantine; np=reject" }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("mail.example.com", NULL, &g_record));
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
    TEST_ASSERT_TRUE(g_record.m_isDmarcApplied);
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, g_record.m_appliedDmarcPolicy);
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_tries_the_selectors_of_the_mx_and_spf_providers(void)
{
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=spf1 include:sendgrid.net include:_spf.google.com -all" }, false });
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK,
                                 { "example-com.mail.protection.outlook.com", "EXAMPLE-COM.mail.protection.outlook.com." }, false });
  static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_DMARC }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));

  TEST_ASSERT_EQUAL_INT(3, g_record.m_mailProviderCount);
  TEST_ASSERT_EQUAL_STRING("Microsoft 365",    g_record.ma_mailProviders[0]->mp_name);
  TEST_ASSERT_EQUAL_STRING("SendGrid",         g_record.ma_mailProviders[1]->mp_name);
  TEST_ASSERT_EQUAL_STRING("Google Workspace", g_record.ma_mailProviders[2]->mp_name);
  const char* const names[] = {
    "selector1._domainkey.example.com", "selector2._domainkey.example.com",
    "s1._domainkey.example.com", "s2._domainkey.example.com", "google._domainkey.example.com",
  };
  const DnsRecordType_t types[] = { DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_TXT };
  static_assertQuestions(&g_calls[1], names, types, 5);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER, g_record.m_dkimSelectorSource);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { "in1-smtp.messagingengine.com" }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_STRING("Fastmail", g_record.ma_mailProviders[0]->mp_name);
  TEST_ASSERT_EQUAL_INT(EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT, g_record.m_dkimSelectorCount);
  TEST_ASSERT_EQUAL_STRING("mesmtp", g_record.ma_dkimSelectors[EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT - 1].ma_selector);
}

void test_checkDomain_tries_the_common_selectors_when_no_provider_names_one(void)
{
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=spf1 redirect=zoho.com" }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));

  TEST_ASSERT_EQUAL_INT(1, g_record.m_mailProviderCount);
  TEST_ASSERT_EQUAL_STRING("Zoho Mail", g_record.ma_mailProviders[0]->mp_name);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_SELECTOR_SOURCE_COMMON, g_record.m_dkimSelectorSource);
  TEST_ASSERT_EQUAL_INT(EMAILDATA_COMMON_DKIM_SELECTOR_COUNT, g_record.m_dkimSelectorCount);
  TEST_ASSERT_EQUAL_INT(1 + EMAILDATA_COMMON_DKIM_SELECTOR_COUNT, g_calls[1].m_questionCount);
  for (int i = 0; i < EMAILDATA_COMMON_DKIM_SELECTOR_COUNT; i++)
  {
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    snprintf(name, sizeof(name), "%s._domainkey.example.com", emaildata_commonDkimSelectors[i]);
    TEST_ASSERT_EQUAL_STRING(name, g_calls[1].ma_names[1 + i]);
  }
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_KEY_UNKNOWN, g_record.m_dkimKeyStatus);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_USABLE));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS));
}

void test_checkDomain_skips_the_names_that_do_not_fit(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_writeLongDomain(229, domain);
  static_addFake((FakeAnswer_t){ domain, DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain(domain, NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILDATA_COMMON_DKIM_SELECTOR_COUNT - 1, g_record.m_dkimSelectorCount);
  for (int i = 0; i < g_record.m_dkimSelectorCount; i++)
    TEST_ASSERT_TRUE(strcmp("everlytickey1", g_record.ma_dkimSelectors[i].ma_selector) != 0);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_writeLongDomain(247, domain);
  static_addFake((FakeAnswer_t){ domain, DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain(domain, NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(2, g_calls[0].m_questionCount);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_BAD_QUESTION, g_record.m_dmarcStatus);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_BAD_QUESTION, g_record.m_mtaStsAnswer.m_status);
  TEST_ASSERT_EQUAL_INT(0, g_record.m_dkimSelectorCount);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_BAD_QUESTION, g_record.m_dkimStatus);
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DMARC_RECORD));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_MTA_STS));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
}

void test_checkDomain_second_round_gets_the_time_left(void)
{
  const struct {
    int64_t m_firstRoundMs;
    int     m_callCount;
    int     m_secondDeadlineMs;
  } cases[] = {
    { 4000, 2, 1000 },
    { 4999, 2, 1 },
    { 5000, 1, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_askAdvanceMs = cases[i].m_firstRoundMs;
    static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { GOOD_SPF }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
    TEST_ASSERT_EQUAL_INT(cases[i].m_callCount, g_callCount);
    if (cases[i].m_callCount == 2)
    {
      TEST_ASSERT_EQUAL_INT(cases[i].m_secondDeadlineMs, g_calls[1].m_deadlineMs);
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dkimStatus);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.m_dkimStatus);
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.m_dmarcStatus);
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.ma_dkimSelectors[0].m_answer.m_status);
    }
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_reads_two_key_records_of_a_selector(void)
{
  static_fakeGoodDomain("google._domainkey.example.com", DNS_RECORD_TYPE_TXT);
  static_addFake((FakeAnswer_t){ "google._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "v=spf1 -all", NULL }, false });
  g_fakes[g_fakeCount - 1].ma_texts[1] = static_rsaKeyRecord(0, "v=DKIM1; ", 2048, false, false);
  g_fakes[g_fakeCount - 1].ma_texts[2] = static_rsaKeyRecord(1, "v=DKIM1; ", 1024, false, false);
  g_fakes[g_fakeCount - 1].ma_texts[3] = static_rsaKeyRecord(2, "v=DKIM1; ", 512, false, false);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));

  const EmailCheckDkimSelector_t* selector = &g_record.ma_dkimSelectors[0];
  TEST_ASSERT_TRUE(selector->m_hasKeyRecord);
  TEST_ASSERT_EQUAL_INT(2048, selector->m_firstKeyRecord.m_keyBits);
  TEST_ASSERT_TRUE(selector->m_hasSecondKeyRecord);
  TEST_ASSERT_EQUAL_INT(3, g_parseDkimCount);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_SIZE));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS));
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { "example-com.mail.protection.outlook.com" }, false });
  static_addFake((FakeAnswer_t){ "selector1._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  g_fakes[g_fakeCount - 1].ma_texts[0] = static_rsaKeyRecord(0, "v=DKIM1; ", 2048, false, false);
  g_fakes[g_fakeCount - 1].ma_texts[1] = static_rsaKeyRecord(1, "v=DKIM1; ", 2048, false, false);
  static_addFake((FakeAnswer_t){ "selector2._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  g_fakes[g_fakeCount - 1].ma_texts[0] = static_rsaKeyRecord(2, "v=DKIM1; ", 2048, false, false);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_TRUE(g_record.ma_dkimSelectors[0].m_hasSecondKeyRecord);
  TEST_ASSERT_FALSE(g_record.ma_dkimSelectors[1].m_hasSecondKeyRecord);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS));
}

void test_checkDomain_rates_a_given_selector_without_a_key(void)
{
  const struct {
    DnsAnswerStatus_t m_status;
    const char*       mp_text;
  } cases[] = {
    { DNS_ANSWER_NXDOMAIN, NULL },
    { DNS_ANSWER_OK,       "v=spf1 -all" },
    { DNS_ANSWER_TIMEOUT,  NULL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_fakeGoodDomain(NULL, DNS_RECORD_TYPE_TXT);
    static_addFake((FakeAnswer_t){ "sel._domainkey.example.com", DNS_RECORD_TYPE_TXT, cases[i].m_status, { cases[i].mp_text }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", "sel", &g_record));
    if (cases[i].m_status == DNS_ANSWER_TIMEOUT)
    {
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.m_dkimStatus);
      TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dkimStatus);
      TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_KEY_NOT_FOUND, g_record.m_dkimKeyStatus);
      TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_FAIL, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
      TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_USABLE));
    }
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_fails_the_dkim_section_when_every_selector_fails(void)
{
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  static_addFake((FakeAnswer_t){ "default._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_TIMEOUT, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_record.m_dkimStatus);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_DKIM_KEY_UNKNOWN, g_record.m_dkimKeyStatus);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  for (int i = 0; i < EMAILDATA_COMMON_DKIM_SELECTOR_COUNT; i++)
  {
    static char names[EMAILDATA_COMMON_DKIM_SELECTOR_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    snprintf(names[i], sizeof(names[i]), "%s._domainkey.example.com", emaildata_commonDkimSelectors[i]);
    static_addFake((FakeAnswer_t){ names[i], DNS_RECORD_TYPE_TXT, i == 0 ? DNS_ANSWER_TIMEOUT : DNS_ANSWER_SERVER_ERROR, { NULL }, false });
  }
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_TIMEOUT, g_record.m_dkimStatus);
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
}

void test_checkDomain_reads_one_mta_sts_record(void)
{
  const struct {
    const char* ma_texts[2];
    bool        m_hasRecord;
  } cases[] = {
    { { "v=STSv1; id=1", NULL },                 true },
    { { "v=STSv1;id=1", NULL },                  true },
    { { "v=STSv1 \t; id=1", NULL },              true },
    { { "v=STSv1;", NULL },                      true },
    { { "v=spf1 -all", "v=STSv1; id=1" },        true },
    { { "v=STSv1", NULL },                       false },
    { { "v=STSv1 id=1", NULL },                  false },
    { { "V=STSV1; id=1", NULL },                 false },
    { { "v=STSv2; id=1", NULL },                 false },
    { { "v=STSv1; id=1", "v=STSv1; id=2" },      false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_fakeGoodDomain("_mta-sts.example.com", DNS_RECORD_TYPE_TXT);
    static_addFake((FakeAnswer_t){ "_mta-sts.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { cases[i].ma_texts[0], cases[i].ma_texts[1] }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_hasRecord, g_record.m_hasMtaStsRecord, cases[i].ma_texts[0]);
    TEST_ASSERT_EQUAL_INT(cases[i].m_hasRecord ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_MTA_STS));
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }

  setUp();
  static_fakeGoodDomain("_mta-sts.example.com", DNS_RECORD_TYPE_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_MTA_STS));
}

void test_checkDomain_rates_the_mx_hosts(void)
{
  static_fakeGoodDomain("example.com", DNS_RECORD_TYPE_MX);
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { NULL }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_WARN, static_resultOf(EMAILCHECK_KIND_MX));
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  g_fakes[g_fakeCount - 1].m_hasNullMx = true;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_MX));
}

#define SPF_LONG_RECORD_SIZE 600

static void static_assertSpfResults(const char* const* texts, const int* expected)
{
  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { texts[0], texts[1] }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  for (int kind = EMAILCHECK_KIND_SPF_RECORD; kind <= EMAILCHECK_KIND_SPF_RECORD_SIZE; kind++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[kind], static_resultOf((EmailCheckKind_t)kind), texts[0]);
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
}

void test_checkDomain_rates_the_spf_record(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, W = EMAILCHECK_RESULT_WARN, F = EMAILCHECK_RESULT_FAIL, X = -1 };
  const struct {
    const char* ma_texts[2];
    int         ma_results[8];
  } cases[] = {
    { { "v=spf1 -all", NULL },                       { P, P, P, P, P, P, P, P } },
    { { "v=spf1 ~all", NULL },                       { P, P, P, P, P, P, P, P } },
    { { "v=spf1 ?all", NULL },                       { P, P, P, W, P, P, P, P } },
    { { "v=spf1 +all", NULL },                       { P, P, P, F, P, P, P, P } },
    { { "v=spf1 all", NULL },                        { P, P, P, F, P, P, P, P } },
    { { "v=spf1 a", NULL },                          { P, P, P, W, P, P, P, P } },
    { { "v=spf1 redirect=_spf.example.net", NULL },  { P, P, P, P, P, P, P, P } },
    { { "v=spf1 -all a", NULL },                     { P, P, P, P, W, P, P, P } },
    { { "v=spf1 -all exists:x.example.net", NULL },  { P, P, P, P, W, P, P, P } },
    { { "v=spf1 -all +all", NULL },                  { P, P, P, P, W, P, P, P } },
    { { "v=spf1 -all exp=x.example.net", NULL },     { P, P, P, P, P, P, P, P } },
    { { "v=spf1 -all redirect=x.example.net", NULL },{ P, P, P, P, W, P, P, P } },
    { { "v=spf1 ptr -all", NULL },                   { P, P, P, P, P, W, P, P } },
    { { "v=spf1 ip4:0.0.0.0/0 -all", NULL },         { P, P, P, P, P, P, F, P } },
    { { "v=spf1 -ip4:0.0.0.0/0 -all", NULL },        { P, P, P, P, P, P, P, P } },
    { { "v=spf1 ip6:::/0 -all", NULL },              { P, P, P, P, P, P, F, P } },
    { { "v=spf1 a/0 -all", NULL },                   { P, P, P, P, P, P, F, P } },
    { { "v=spf1 mx//0 -all", NULL },                 { P, P, P, P, P, P, F, P } },
    { { "v=spf1 ip4:10.0.0.0/15 -all", NULL },       { P, P, P, P, P, P, W, P } },
    { { "v=spf1 ip4:10.0.0.0/16 -all", NULL },       { P, P, P, P, P, P, P, P } },
    { { "v=spf1 ip6:2001:db8::/31 -all", NULL },     { P, P, P, P, P, P, W, P } },
    { { "v=spf1 ip6:2001:db8::/32 -all", NULL },     { P, P, P, P, P, P, P, P } },
    { { "v=spf1 ip4:10.0.0.0/15 ip4:0.0.0.0/0 -all", NULL }, { P, P, P, P, P, P, F, P } },
    { { "v=spf1 ip4:0.0.0.0/0 ip4:10.0.0.0/15 -all", NULL }, { P, P, P, P, P, P, F, P } },
    { { "v=spf1 foo -all", NULL },                   { P, F, P, P, P, P, P, P } },
    { { "v=spf1 -all", "v=spf1 ~all" },              { F, X, X, X, X, X, X, X } },
    { { "google-site-verification=x", NULL },        { F, X, X, X, X, X, X, X } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    static_assertSpfResults(cases[i].ma_texts, cases[i].ma_results);

  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { NULL }, false });
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { "mx.example.net" }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_FAIL, static_resultOf(EMAILCHECK_KIND_SPF_RECORD));
  TEST_ASSERT_EQUAL_INT(-1, static_resultOf(EMAILCHECK_KIND_SPF_SYNTAX));
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  setUp();
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK,
                                 { "google-site-verification=x", "v=spf1 include:sendgrid.net -all", "v=spf1 include:_spf.google.com ~all" }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(2, g_record.m_spfRecordCount);
  TEST_ASSERT_EQUAL_INT(1, g_record.m_spfRecordIndex);
  TEST_ASSERT_EQUAL_INT(0, g_record.m_spfRecord.m_termCount);
  TEST_ASSERT_EQUAL_INT(0, g_record.m_mailProviderCount);
}

void test_checkDomain_rates_the_spf_size_and_lookups(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, W = EMAILCHECK_RESULT_WARN, F = EMAILCHECK_RESULT_FAIL };
  static char record_450[SPF_LONG_RECORD_SIZE];
  static char record_451[SPF_LONG_RECORD_SIZE];
  snprintf(record_450, sizeof(record_450), "v=spf1 -all x=%0*d", 436, 0);
  snprintf(record_451, sizeof(record_451), "v=spf1 -all x=%0*d", 437, 0);
  TEST_ASSERT_EQUAL_INT(450, (int)strlen(record_450));
  static char other_451[SPF_LONG_RECORD_SIZE];
  snprintf(other_451, sizeof(other_451), "google-site-verification=%0*d", 426, 0);
  TEST_ASSERT_EQUAL_INT(451, (int)strlen(other_451));

  const struct {
    const char* ma_texts[2];
    int         ma_results[8];
  } cases[] = {
    { { record_450, NULL },                              { P, P, P, P, P, P, P, P } },
    { { record_451, NULL },                              { P, P, P, P, P, P, P, W } },
    { { other_451, "v=spf1 -all" },                      { P, P, P, P, P, P, P, P } },
    { { "v=spf1 a mx a mx a mx a mx a mx -all", NULL },   { P, P, P, P, P, P, P, P } },
    { { "v=spf1 a mx a mx a mx a mx a mx a -all", NULL }, { P, P, F, P, P, P, P, P } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    static_assertSpfResults(cases[i].ma_texts, cases[i].ma_results);
}

void test_checkDomain_rates_an_spf_record_past_the_term_cap(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, F = EMAILCHECK_RESULT_FAIL, X = -1 };
  const struct {
    const char* mp_head;
    int         m_fillerCount;
    const char* mp_tail;
    int         ma_results[8];
  } cases[] = {
    { "v=spf1",                       EMAILAUTH_SPF_MAX_TERM_COUNT - 1,  " -all", { P, P, P, P, P, P, P, P } },
    { "v=spf1",                       EMAILAUTH_SPF_MAX_TERM_COUNT,      " -all", { P, P, P, X, X, X, X, P } },
    { "v=spf1 foo",                   EMAILAUTH_SPF_MAX_TERM_COUNT - 1,  " -all", { P, F, P, X, X, X, X, P } },
    { "v=spf1 a a a a a a a a a a a", EMAILAUTH_SPF_MAX_TERM_COUNT - 11, " -all", { P, P, F, X, X, X, X, P } },
    { "v=spf1",                       EMAILAUTH_SPF_MAX_TERM_COUNT,      " foo",  { P, F, P, X, X, X, X, P } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static char record[SPF_LONG_RECORD_SIZE];
    snprintf(record, sizeof(record), "%s", cases[i].mp_head);
    for (int j = 0; j < cases[i].m_fillerCount; j++)
      strcat(record, " x=y");
    strcat(record, cases[i].mp_tail);
    DnsRecordText_t text = { record, strlen(record) };
    EmailAuthSpf_t  spf;
    emailauth_parseSpf(&text, &spf);
    TEST_ASSERT_EQUAL_INT_MESSAGE(i == 0 ? 0 : 1, spf.m_unreadTermCount, record);
    const char* const texts[2] = { record, NULL };
    static_assertSpfResults(texts, cases[i].ma_results);
  }
}

void test_checkDomain_rates_the_dmarc_record(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, W = EMAILCHECK_RESULT_WARN };
  const struct {
    const char* mp_record;
    int         m_testModeResult;
    int         m_reportingResult;
  } cases[] = {
    { "v=DMARC1; p=reject; rua=mailto:a@example.com",       P, P },
    { "v=DMARC1; p=reject; t=y; rua=mailto:a@example.com",  W, P },
    { "v=DMARC1; p=reject; t=n; rua=mailto:a@example.com",  P, P },
    { "v=DMARC1; p=reject",                                 P, W },
    { "v=DMARC1; p=reject; rua=bogus",                      P, W },
    { "v=DMARC1; p=quarantine; t=y",                        W, W },
    { "v=DMARC1; p=none; t=y; rua=mailto:a@example.com",    P, P },
    { "v=DMARC1; t=y",                                      P, W },
    { "v=DMARC1; p=bogus; t=y",                             P, W },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_fakeGoodDomain("_dmarc.example.com", DNS_RECORD_TYPE_TXT);
    static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { cases[i].mp_record }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_testModeResult, static_resultOf(EMAILCHECK_KIND_DMARC_TEST_MODE), cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_reportingResult, static_resultOf(EMAILCHECK_KIND_DMARC_REPORTING), cases[i].mp_record);
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }

  setUp();
  static_fakeGoodDomain("_dmarc.example.com", DNS_RECORD_TYPE_TXT);
  static_addFake((FakeAnswer_t){ "_dmarc.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { "google-site-verification=x", "v=DMARC1; p=reject; t=y" }, false });
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
  TEST_ASSERT_EQUAL_INT(1, g_record.m_dmarcRecordIndex);
  TEST_ASSERT_EQUAL_INT(W, static_resultOf(EMAILCHECK_KIND_DMARC_TEST_MODE));
  emailcheck_EMAILAUTHCHECKRecordFree(&g_record);

  const struct {
    const char* mp_record;
    int         m_testModeResult;
  } parent_cases[] = {
    { "v=DMARC1; p=reject; sp=none; t=y",       P },
    { "v=DMARC1; p=none; sp=quarantine; t=y",   W },
  };
  for (size_t i = 0; i < sizeof(parent_cases) / sizeof(parent_cases[0]); i++)
  {
    setUp();
    const char* const records[] = { "_dmarc.example.com", parent_cases[i].mp_record, NULL };
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, static_checkWithDmarcRecords("mail.example.com", records));
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL, g_record.m_dmarcSource);
    TEST_ASSERT_EQUAL_INT_MESSAGE(parent_cases[i].m_testModeResult, static_resultOf(EMAILCHECK_KIND_DMARC_TEST_MODE), parent_cases[i].mp_record);
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_rates_the_dkim_keys(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, W = EMAILCHECK_RESULT_WARN, F = EMAILCHECK_RESULT_FAIL, X = -1 };
  const struct {
    const char* mp_before;
    int         m_keyBits;
    bool        m_isBareRsa;
    bool        m_isModulusNegative;
    int         ma_results[5];
  } cases[] = {
    { "v=DKIM1; ",               1023, false, false, { P, F, P, P, P } },
    { "v=DKIM1; ",               1024, false, false, { P, W, P, P, P } },
    { "v=DKIM1; ",               2047, false, false, { P, W, P, P, P } },
    { "v=DKIM1; ",               2048, false, false, { P, P, P, P, P } },
    { "v=DKIM1; ",               4096, false, false, { P, P, P, P, P } },
    { "v=DKIM1; ",               4097, false, false, { P, W, P, P, P } },
    { "v=DKIM1; ",               2048, true,  false, { P, P, W, P, P } },
    { "v=DKIM1; ",               2048, false, true,  { P, P, W, P, P } },
    { "k=rsa; v=DKIM1; ",        2048, false, false, { P, P, W, P, P } },
    { "v=DKIM1; t=y; ",          2048, false, false, { P, P, P, W, P } },
    { "v=DKIM1; t=s; ",          2048, false, false, { P, P, P, P, P } },
    { "v=DKIM1; h=sha1; ",       2048, false, false, { P, P, P, P, F } },
    { "v=DKIM1; s=other; ",      2048, false, false, { P, P, P, P, F } },
    { "v=DKIM1; h=sha1:sha256; s=email; ", 2048, false, false, { P, P, P, P, P } },
    { "v=DKIM1; k=ed25519; ",    0,    false, false, { P, P, P, P, P } },
    { NULL,                      0,    false, false, { F, X, X, X, X } },
    { "v=DKIM1; k=foo; ",        2048, false, false, { W, X, X, X, X } },
    { "v=DKIM1; h=; ",           2048, false, false, { F, X, X, X, X } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_fakeGoodDomain("google._domainkey.example.com", DNS_RECORD_TYPE_TXT);
    const char* key_record = "v=DKIM1; p=";
    if (cases[i].mp_before != NULL && cases[i].m_keyBits == 0)
      key_record = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    else if (cases[i].mp_before != NULL)
      key_record = static_rsaKeyRecord(0, cases[i].mp_before, cases[i].m_keyBits, cases[i].m_isBareRsa, cases[i].m_isModulusNegative);
    static_addFake((FakeAnswer_t){ "google._domainkey.example.com", DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { key_record }, false });
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
    TEST_ASSERT_EQUAL_INT(EMAILCHECK_RESULT_PASS, static_resultOf(EMAILCHECK_KIND_DKIM_KEY_FOUND));
    const EmailCheckKind_t kinds[] = {
      EMAILCHECK_KIND_DKIM_KEY_USABLE, EMAILCHECK_KIND_DKIM_KEY_SIZE, EMAILCHECK_KIND_DKIM_KEY_FORMAT,
      EMAILCHECK_KIND_DKIM_TEST_MODE, EMAILCHECK_KIND_DKIM_KEY_RESTRICTED,
    };
    for (int j = 0; j < 5; j++)
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].ma_results[j], static_resultOf(kinds[j]), key_record);
    TEST_ASSERT_EQUAL_INT(P, static_resultOf(EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS));
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkDomain_rates_the_keys_of_two_selectors(void)
{
  enum { P = EMAILCHECK_RESULT_PASS, W = EMAILCHECK_RESULT_WARN, F = EMAILCHECK_RESULT_FAIL, X = -1 };
  const char* const revoked = "v=DKIM1; p=";
  const char* const unknown = "v=DKIM1; k=foo; p=AAAA";
  const struct {
    int         ma_slots[2];
    const char* ma_fixed[2];
    int         ma_bits[2];
    const char* ma_before[2];
    int         ma_results[5];
  } cases[] = {
    { { -1, 1 }, { revoked, NULL }, { 0, 2048 },    { NULL, "v=DKIM1; " },    { P, P, P, P, P } },
    { { -1, -1 }, { unknown, revoked }, { 0, 0 },   { NULL, NULL },           { W, X, X, X, X } },
    { { 0, 1 }, { NULL, NULL }, { 2048, 1023 },     { "v=DKIM1; ", "v=DKIM1; t=y; " }, { P, F, P, W, P } },
    { { 1, -1 }, { NULL, NULL }, { 2048, 0 },       { "v=DKIM1; ", NULL },    { P, P, P, P, P } },
    { { 1, -1 }, { NULL, unknown }, { 2048, 0 },    { "v=DKIM1; ", NULL },    { P, P, P, P, P } },
    { { 0, 1 }, { NULL, NULL }, { 1023, 1024 },     { "v=DKIM1; ", "v=DKIM1; " }, { P, F, P, P, P } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { "example-com.mail.protection.outlook.com" }, false });
    const char* const names[2] = { "selector1._domainkey.example.com", "selector2._domainkey.example.com" };
    for (int j = 0; j < 2; j++)
    {
      const char* text = cases[i].ma_slots[j] < 0 ? cases[i].ma_fixed[j] : static_rsaKeyRecord(cases[i].ma_slots[j], cases[i].ma_before[j], cases[i].ma_bits[j], false, false);
      static_addFake((FakeAnswer_t){ names[j], DNS_RECORD_TYPE_TXT, DNS_ANSWER_OK, { text }, false });
    }
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkDomain("example.com", NULL, &g_record));
    const EmailCheckKind_t kinds[] = {
      EMAILCHECK_KIND_DKIM_KEY_USABLE, EMAILCHECK_KIND_DKIM_KEY_SIZE, EMAILCHECK_KIND_DKIM_KEY_FORMAT,
      EMAILCHECK_KIND_DKIM_TEST_MODE, EMAILCHECK_KIND_DKIM_KEY_RESTRICTED,
    };
    for (int j = 0; j < 5; j++)
      TEST_ASSERT_EQUAL_INT(cases[i].ma_results[j], static_resultOf(kinds[j]));
    emailcheck_EMAILAUTHCHECKRecordFree(&g_record);
  }
}

void test_checkAddressDomain_asks_mx_a_and_aaaa_in_one_round(void)
{
  static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, DNS_ANSWER_OK, { "mx1.example.net", "mx2.example.net" }, false });
  snprintf(g_addressRecord.ma_email, sizeof(g_addressRecord.ma_email), "%s", "Kept+ci@example.com");
  snprintf(g_addressRecord.ma_domain, sizeof(g_addressRecord.ma_domain), "%s", "example.com");
  snprintf(g_addressRecord.ma_disposableListedDomain, sizeof(g_addressRecord.ma_disposableListedDomain), "%s", "kept.example");
  g_addressRecord.m_isDisposableFeedLoaded = true;

  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, emailcheck_checkAddressDomain("example.com", &g_addressRecord));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_INT(3, g_calls[0].m_questionCount);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS, g_calls[0].m_deadlineMs);
  static const DnsRecordType_t types[] = { DNS_RECORD_TYPE_MX, DNS_RECORD_TYPE_A, DNS_RECORD_TYPE_AAAA };
  for (int i = 0; i < 3; i++)
  {
    TEST_ASSERT_EQUAL_STRING("example.com", g_calls[0].ma_names[i]);
    TEST_ASSERT_EQUAL_INT(types[i], g_calls[0].ma_types[i]);
  }
  TEST_ASSERT_TRUE(g_addressRecord.m_isDomainFound);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_MAIL_ROUTE_MX, g_addressRecord.m_mailRoute);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, g_addressRecord.m_mxAnswer.m_status);
  TEST_ASSERT_EQUAL_INT(2, g_addressRecord.m_mxAnswer.m_recordCount);
  TEST_ASSERT_EQUAL_STRING("mx2.example.net", g_addressRecord.m_mxAnswer.mp_mxRecords[1].mp_hostname);
  TEST_ASSERT_EQUAL_STRING("Kept+ci@example.com", g_addressRecord.ma_email);
  TEST_ASSERT_EQUAL_STRING("example.com", g_addressRecord.ma_domain);
  TEST_ASSERT_EQUAL_STRING("kept.example", g_addressRecord.ma_disposableListedDomain);
  TEST_ASSERT_TRUE(g_addressRecord.m_isDisposableFeedLoaded);
}

#define ADDRESS_NO_FAKE  ((DnsAnswerStatus_t)-1)

typedef struct {
  const char*           mp_label;
  DnsAnswerStatus_t     m_mxStatus;
  const char*           mp_mxHost;
  bool                  m_hasNullMx;
  DnsAnswerStatus_t     m_aStatus;
  const char*           mp_aAddress;
  DnsAnswerStatus_t     m_aaaaStatus;
  const char*           mp_aaaaAddress;
  DnsLookupStatus_t     m_status;
  bool                  m_isDomainFound;
  EmailCheckMailRoute_t m_mailRoute;
} AddressRouteCase_t;

void test_checkAddressDomain_route_of_each_answer(void)
{
  static const AddressRouteCase_t cases[] = {
    { "mx host",                  DNS_ANSWER_OK,           "mx.example.net", false, DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_MX },
    { "null mx",                  DNS_ANSWER_OK,           NULL,             true,  DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_NULL_MX },
    { "null mx and a host",       DNS_ANSWER_OK,           "mx.example.net", true,  DNS_ANSWER_OK,           NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_NULL_MX },
    { "a record",                 DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX },
    { "aaaa record",              DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_OK,           "2001:db8::1", DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX },
    { "aaaa record, a timeout",   DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_TIMEOUT,      NULL,         DNS_ANSWER_OK,           "2001:db8::1", DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX },
    { "a record, aaaa failed",    DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_SERVER_ERROR, NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX },
    { "no record anywhere",       DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_NONE },
    { "no record, aaaa nxdomain", DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           NULL,         ADDRESS_NO_FAKE,         NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_NONE },
    { "no record, a nxdomain",    DNS_ANSWER_OK,           NULL,             false, ADDRESS_NO_FAKE,         NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_OK,         true,  EMAILCHECK_MAIL_ROUTE_NONE },
    { "no record, a failed",      DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_SERVER_ERROR, NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NO_ANSWER,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "no record, aaaa timeout",  DNS_ANSWER_OK,           NULL,             false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_TIMEOUT,      NULL,          DNS_LOOKUP_NO_ANSWER,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "mx nxdomain",              ADDRESS_NO_FAKE,         NULL,             false, DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NOT_FOUND,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "mx failed, a record",      DNS_ANSWER_SERVER_ERROR, NULL,             false, DNS_ANSWER_OK,           "192.0.2.1",  DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NO_ANSWER,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "mx timeout",               DNS_ANSWER_TIMEOUT,      NULL,             false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NO_ANSWER,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "mx no memory",             DNS_ANSWER_NO_MEMORY,    NULL,             false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NO_MEMORY,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "a no memory",              DNS_ANSWER_OK,           "mx.example.net", false, DNS_ANSWER_NO_MEMORY,    NULL,         DNS_ANSWER_OK,           NULL,          DNS_LOOKUP_NO_MEMORY,  false, EMAILCHECK_MAIL_ROUTE_NONE },
    { "aaaa no memory",           DNS_ANSWER_OK,           "mx.example.net", false, DNS_ANSWER_OK,           NULL,         DNS_ANSWER_NO_MEMORY,    NULL,          DNS_LOOKUP_NO_MEMORY,  false, EMAILCHECK_MAIL_ROUTE_NONE },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const AddressRouteCase_t* row = &cases[i];
    setUp();
    if (row->m_mxStatus != ADDRESS_NO_FAKE)
      static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_MX, row->m_mxStatus, { row->mp_mxHost }, row->m_hasNullMx });
    if (row->m_aStatus != ADDRESS_NO_FAKE)
      static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_A, row->m_aStatus, { row->mp_aAddress }, false });
    if (row->m_aaaaStatus != ADDRESS_NO_FAKE)
      static_addFake((FakeAnswer_t){ "example.com", DNS_RECORD_TYPE_AAAA, row->m_aaaaStatus, { row->mp_aaaaAddress }, false });
    emailcheck_EMAILADDRESSCHECKRecordFree(&g_addressRecord);
    g_addressRecord.m_isDomainFound = !row->m_isDomainFound;
    g_addressRecord.m_mailRoute     = EMAILCHECK_MAIL_ROUTE_NULL_MX;

    TEST_ASSERT_EQUAL_INT_MESSAGE(row->m_status, emailcheck_checkAddressDomain("example.com", &g_addressRecord), row->mp_label);

    TEST_ASSERT_EQUAL_MESSAGE(row->m_isDomainFound, g_addressRecord.m_isDomainFound, row->mp_label);
    if (row->m_status == DNS_LOOKUP_OK)
      TEST_ASSERT_EQUAL_INT_MESSAGE(row->m_mailRoute, g_addressRecord.m_mailRoute, row->mp_label);
  }
}

void test_checkAddressDomain_refuses_a_name_that_is_not_public(void)
{
  g_addressRecord.m_isDomainFound = true;
  g_addressRecord.m_mailRoute     = EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX;
  g_addressRecord.m_mxAnswer.m_recordCount = 3;

  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_INVALID_NAME, emailcheck_checkAddressDomain("printer.local", &g_addressRecord));

  TEST_ASSERT_EQUAL_INT(0, g_callCount);
  TEST_ASSERT_FALSE(g_addressRecord.m_isDomainFound);
  TEST_ASSERT_EQUAL_INT(EMAILCHECK_MAIL_ROUTE_NONE, g_addressRecord.m_mailRoute);
  TEST_ASSERT_EQUAL_INT(0, g_addressRecord.m_mxAnswer.m_recordCount);
}

void test_EMAILADDRESSCHECKRecordFree_accepts_null(void)
{
  emailcheck_EMAILADDRESSCHECKRecordFree(NULL);
}

void test_kindId_names_each_kind_and_no_other_value(void)
{
  static const char* const expected_ids[EMAILCHECK_KIND_COUNT] = {
    "spf_record", "spf_syntax", "spf_lookup_limit", "spf_all", "spf_ignored_terms", "spf_ptr",
    "spf_wide_range", "spf_record_size", "dmarc_record", "dmarc_policy", "dmarc_test_mode",
    "dmarc_reporting", "dkim_key_found", "dkim_key_usable", "dkim_key_size", "dkim_key_format",
    "dkim_test_mode", "dkim_key_restricted", "dkim_multiple_keys", "mx", "mta_sts",
  };
  size_t longest_len = 0;
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
  {
    const char* id = emailcheck_kindId((EmailCheckKind_t)kind);
    TEST_ASSERT_NOT_NULL(id);
    TEST_ASSERT_EQUAL_STRING(expected_ids[kind], id);
    TEST_ASSERT_LESS_OR_EQUAL_size_t(EMAILCHECK_KIND_ID_MAX_LEN, strlen(id));
    if (strlen(id) > longest_len)
      longest_len = strlen(id);
  }
  TEST_ASSERT_EQUAL_size_t(EMAILCHECK_KIND_ID_MAX_LEN, longest_len);

  TEST_ASSERT_NULL(emailcheck_kindId((EmailCheckKind_t)-1));
  TEST_ASSERT_NULL(emailcheck_kindId((EmailCheckKind_t)EMAILCHECK_KIND_COUNT));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_checkDomain_asks_two_rounds_and_passes_every_check);
  RUN_TEST(test_checkDomain_asks_a_given_selector_in_the_first_round);
  RUN_TEST(test_checkDomain_refuses_a_selector_whose_name_is_too_long);
  RUN_TEST(test_checkDomain_refuses_an_invalid_domain_or_selector);
  RUN_TEST(test_checkDomain_not_found_when_the_domain_does_not_exist);
  RUN_TEST(test_checkDomain_no_answer_when_no_first_round_question_is_answered);
  RUN_TEST(test_checkDomain_no_memory_when_an_answer_could_not_be_allocated);
  RUN_TEST(test_EMAILAUTHCHECKRecordFree_ignores_null);
  RUN_TEST(test_checkDomain_leaves_out_the_checks_of_a_failed_section);
  RUN_TEST(test_checkDomain_walk_picks_the_record_with_the_fewest_labels);
  RUN_TEST(test_checkDomain_walk_stops_at_psd_n);
  RUN_TEST(test_checkDomain_walk_applies_the_public_suffix_record);
  RUN_TEST(test_checkDomain_walk_applies_the_record_under_the_public_suffix);
  RUN_TEST(test_checkDomain_walk_stops_at_psd_y);
  RUN_TEST(test_checkDomain_walk_skips_a_name_with_two_records);
  RUN_TEST(test_checkDomain_walk_fails_only_before_it_stops);
  RUN_TEST(test_checkDomain_walk_shortens_a_long_domain_to_seven_labels);
  RUN_TEST(test_checkDomain_walks_past_two_own_records);
  RUN_TEST(test_checkDomain_applies_the_rfc_9989_policy_rules);
  RUN_TEST(test_checkDomain_tries_the_selectors_of_the_mx_and_spf_providers);
  RUN_TEST(test_checkDomain_tries_the_common_selectors_when_no_provider_names_one);
  RUN_TEST(test_checkDomain_skips_the_names_that_do_not_fit);
  RUN_TEST(test_checkDomain_second_round_gets_the_time_left);
  RUN_TEST(test_checkDomain_reads_two_key_records_of_a_selector);
  RUN_TEST(test_checkDomain_rates_a_given_selector_without_a_key);
  RUN_TEST(test_checkDomain_fails_the_dkim_section_when_every_selector_fails);
  RUN_TEST(test_checkDomain_reads_one_mta_sts_record);
  RUN_TEST(test_checkDomain_rates_the_mx_hosts);
  RUN_TEST(test_checkDomain_rates_the_spf_record);
  RUN_TEST(test_checkDomain_rates_the_spf_size_and_lookups);
  RUN_TEST(test_checkDomain_rates_an_spf_record_past_the_term_cap);
  RUN_TEST(test_checkDomain_rates_the_dmarc_record);
  RUN_TEST(test_checkDomain_rates_the_dkim_keys);
  RUN_TEST(test_checkDomain_rates_the_keys_of_two_selectors);
  RUN_TEST(test_checkAddressDomain_asks_mx_a_and_aaaa_in_one_round);
  RUN_TEST(test_checkAddressDomain_route_of_each_answer);
  RUN_TEST(test_checkAddressDomain_refuses_a_name_that_is_not_public);
  RUN_TEST(test_EMAILADDRESSCHECKRecordFree_accepts_null);
  RUN_TEST(test_kindId_names_each_kind_and_no_other_value);
  return UNITY_END();
}
