#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "unity/unity.h"
#include "watchlist/endpoint/watchlist_cert_search.h"
#include "watchlist/endpoint/watchlist_dns_lookup.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/endpoint/watchlist_headers_check.h"
#include "watchlist/endpoint/watchlist_ssl_check.h"
#include "watchlist/endpoint/watchlist_whois_lookup.h"
#include "external/rdap.h"
#include "tlsprobe.h"
#include "header_check.h"
#include "external/certspotter.h"

typedef enum {
  TEST_DIGEST_PASS = 0,
  TEST_DIGEST_NO_CONTEXT,
  TEST_DIGEST_INIT_FAILS,
  TEST_DIGEST_UPDATE_FAILS,
  TEST_DIGEST_FINAL_FAILS,
  TEST_DIGEST_SHORT_LENGTH,
} WatchlistDomainTestDigestFault_t;

static WatchlistDomainTestDigestFault_t g_digestFault = TEST_DIGEST_PASS;

static int g_liveContextCount = 0;

EVP_MD_CTX* __real_EVP_MD_CTX_new(void);
void        __real_EVP_MD_CTX_free(EVP_MD_CTX* ctx);
int         __real_EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl);
int         __real_EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data, size_t count);
int         __real_EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* size);

EVP_MD_CTX* __wrap_EVP_MD_CTX_new(void);
void        __wrap_EVP_MD_CTX_free(EVP_MD_CTX* ctx);
int         __wrap_EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl);
int         __wrap_EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data, size_t count);
int         __wrap_EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* size);

EVP_MD_CTX* __wrap_EVP_MD_CTX_new(void)
{
  if (g_digestFault == TEST_DIGEST_NO_CONTEXT)
  {
    g_digestFault = TEST_DIGEST_PASS;
    return NULL;
  }
  EVP_MD_CTX* ctx = __real_EVP_MD_CTX_new();
  if (ctx != NULL)
    g_liveContextCount++;
  return ctx;
}

void __wrap_EVP_MD_CTX_free(EVP_MD_CTX* ctx)
{
  if (ctx != NULL)
    g_liveContextCount--;
  __real_EVP_MD_CTX_free(ctx);
}

int __wrap_EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl)
{
  if (g_digestFault == TEST_DIGEST_INIT_FAILS)
  {
    g_digestFault = TEST_DIGEST_PASS;
    return 0;
  }
  return __real_EVP_DigestInit_ex(ctx, type, impl);
}

int __wrap_EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data, size_t count)
{
  if (g_digestFault == TEST_DIGEST_UPDATE_FAILS)
  {
    g_digestFault = TEST_DIGEST_PASS;
    return 0;
  }
  return __real_EVP_DigestUpdate(ctx, data, count);
}

int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* size)
{
  WatchlistDomainTestDigestFault_t fault = g_digestFault;
  if (fault == TEST_DIGEST_FINAL_FAILS)
  {
    g_digestFault = TEST_DIGEST_PASS;
    *size = 32;
    return 0;
  }
  int result = __real_EVP_DigestFinal_ex(ctx, md, size);
  if (fault == TEST_DIGEST_SHORT_LENGTH)
  {
    g_digestFault = TEST_DIGEST_PASS;
    *size = 20;
  }
  return result;
}

#define SHA256_OF_EMPTY       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA256_OF_A_LF_B      "7e18f737311b2dc3b2f269dd78396b0351f14fb66efa879f768cb23181883c78"
#define SHA256_OF_FOUND       "bcc649cfdb8cc557053da67df7e7fcb740dcf7f721cebe1f2082597ad0d5e7d8"
#define SHA256_OF_NOT_FOUND   "8bf1172df581a12c2c602a62dd15e76b3096035a2d65c910c29838f277eafa0d"
#define SHA256_OF_EMPTY_STATE "2e1cfa82b035c26cbbbdae632cea070514eb8b773f616aaeaf668e2f0be8f10d"
#define SHA256_OF_PUBLIC      "efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7"
#define SHA256_OF_NOT_PUBLIC  "0e6d97b1a32aa9a5716fae8c16882ad1cde596b456e0c516ec63514cd704f32c"
#define SHA256_OF_NONE        "140bedbf9c3f6d56a9846d2ba7088798683f4da0c248231336e6a05679e4fdfe"
#define SHA256_OF_VULNERABLE  "f2b826b18b9de86628dd9b798f3cb6cfd582fb7cee4ea68489387c0b19dc09c1"
#define SHA256_OF_VULNERABLE_DISCOURSE "529fe49b7437de044e34c9bd3418ea9c1fdf855f942a5ba4c3c0c57e8fc45db5"
#define SHA256_OF_NULL        "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
#define SHA256_OF_MX_AND_NULL "15c1d5e3cf6801e7e73d7bd99cb2b93812ce2dfa532087def2164958bacec6ee"
#define SHA256_OF_MX_PAIR     "ad762775cfd7799105f78e59f2978eb70aa7c46b373a86523c77863ab0674fb3"
#define SHA256_OF_NS_PAIR     "554f60e29fe650012fb81826a449443b45f2f55eb4aca83467e8bdca1576dfb2"
#define SHA256_OF_CHECK_RESULTS "8e889f2d563ac950725cfa5d1c45f57ae6e4177743a8a229eae53b16a8f5fdcb"
#define SHA256_OF_NO_CHECK    "fc0e1c1c3e9991d9af86ba58ff1744171469bda051b1268aa127a088fb18ff82"

#define SHA256_OF_CAP_BELOW   "27a5830aa619057e503fb09137975f9ea72a49c469c8da0e556ed296116a34cc"
#define SHA256_OF_CAP_AT      "bb1fca743eaee1784c8fad322735802d12e05e42d955820d8790d169bf3a7b5d"
#define SHA256_OF_CAP_PAST    "7459b574530797ed2fed8ce574f782b6f8846af59793a58e94d90488fc3f40fe"

#define TEST_FILL_BYTE 0x5A

#define TEST_LONG_NAME_SIZE 300

void setUp(void)
{
  g_digestFault      = TEST_DIGEST_PASS;
  g_liveContextCount = 0;
}

void tearDown(void) {}

static void static_fillValue(WatchlistDomainValue_t* value)
{
  memset(value, TEST_FILL_BYTE, sizeof(*value));
}

static void static_assertUntouched(const WatchlistDomainValue_t* value)
{
  WatchlistDomainValue_t filled;
  static_fillValue(&filled);
  TEST_ASSERT_EQUAL_MEMORY(&filled, value, sizeof(filled));
}

static void static_assertValue(const WatchlistDomainValue_t* value, const char* text, int item_count, int kept_item_count, const char* sha256_hex)
{
  TEST_ASSERT_EQUAL_STRING(text, value->ma_text);
  TEST_ASSERT_EQUAL_INT(item_count, value->m_itemCount);
  TEST_ASSERT_EQUAL_INT(kept_item_count, value->m_keptItemCount);
  TEST_ASSERT_EQUAL_STRING(sha256_hex, value->ma_sha256Hex);
}

static void static_setTexts(DnsRecordText_t* texts, const char* const* names, int name_count)
{
  for (int i = 0; i < name_count; i++)
  {
    texts[i].mp_bytes    = (char*)names[i];
    texts[i].m_byteCount = strlen(names[i]);
  }
}

static DnsAnswer_t static_textAnswer(DnsAnswerStatus_t status, DnsRecordText_t* texts, int record_count)
{
  DnsAnswer_t answer = { 0 };
  answer.m_status      = status;
  answer.m_recordCount = record_count;
  answer.mp_texts      = texts;
  return answer;
}

static DnsAnswer_t static_mxAnswer(DnsAnswerStatus_t status, DnsMxRecord_t* records, int record_count, bool has_null_mx)
{
  DnsAnswer_t answer = { 0 };
  answer.m_status       = status;
  answer.m_recordCount  = record_count;
  answer.mp_mxRecords   = records;
  answer.m_hasNullMx    = has_null_mx;
  return answer;
}

static const DnsAnswerStatus_t NOT_OK_STATUSES[] = {
  DNS_ANSWER_SERVER_ERROR, DNS_ANSWER_TRUNCATED, DNS_ANSWER_MALFORMED, DNS_ANSWER_NO_MEMORY,
  DNS_ANSWER_TIMEOUT, DNS_ANSWER_NO_RESOLVER, DNS_ANSWER_BAD_QUESTION, DNS_ANSWER_NOT_PUBLIC_NAME,
};
#define NOT_OK_STATUS_COUNT ((int)(sizeof(NOT_OK_STATUSES) / sizeof(NOT_OK_STATUSES[0])))

void test_constants_hold_their_values(void)
{
  TEST_ASSERT_EQUAL_INT(2048, WATCHLIST_DOMAIN_VALUE_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(64, WATCHLIST_DOMAIN_SHA256_HEX_LEN);
  TEST_ASSERT_EQUAL_INT(4, WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT);
}

void test_dns_presence_all_nxdomain_is_not_found(void)
{
  DnsAnswer_t answers[5] = { { 0 } };
  for (int i = 0; i < 4; i++)
    answers[i].m_status = DNS_ANSWER_NXDOMAIN;
  answers[4].m_status = DNS_ANSWER_OK;

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteDnsPresence(answers, &value));
  static_assertValue(&value, "not_found", 1, 1, SHA256_OF_NOT_FOUND);
}

void test_dns_presence_one_ok_answer_is_found(void)
{
  for (int ok_index = 0; ok_index < 4; ok_index++)
  {
    DnsAnswer_t answers[4] = { { 0 } };
    answers[0].m_status = DNS_ANSWER_NXDOMAIN;
    answers[1].m_status = DNS_ANSWER_SERVER_ERROR;
    answers[2].m_status = DNS_ANSWER_TIMEOUT;
    answers[3].m_status = DNS_ANSWER_NXDOMAIN;
    answers[ok_index].m_status = DNS_ANSWER_OK;

    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteDnsPresence(answers, &value));
    static_assertValue(&value, "found", 1, 1, SHA256_OF_FOUND);
  }
}

void test_dns_presence_not_public_name_answer_is_found(void)
{
  for (int not_public_index = 0; not_public_index < 4; not_public_index += 3)
  {
    DnsAnswer_t answers[4] = { { 0 } };
    for (int j = 0; j < 4; j++)
      answers[j].m_status = DNS_ANSWER_NXDOMAIN;
    answers[not_public_index].m_status = DNS_ANSWER_NOT_PUBLIC_NAME;

    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteDnsPresence(answers, &value));
    static_assertValue(&value, "found", 1, 1, SHA256_OF_FOUND);
  }
}

void test_dns_presence_error_without_ok_answer_has_no_value(void)
{
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    if (NOT_OK_STATUSES[i] == DNS_ANSWER_NOT_PUBLIC_NAME)
      continue;
    for (int error_index = 0; error_index < 4; error_index += 3)
    {
      DnsAnswer_t answers[4] = { { 0 } };
      for (int j = 0; j < 4; j++)
        answers[j].m_status = DNS_ANSWER_NXDOMAIN;
      answers[error_index].m_status = NOT_OK_STATUSES[i];

      WatchlistDomainValue_t value;
      static_fillValue(&value);
      TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteDnsPresence(answers, &value));
      static_assertUntouched(&value);
    }
  }
}

void test_ns_names_are_lowercase_sorted_unique_without_trailing_dot(void)
{
  static const char* const names[] = { "NS2.Example.COM.", "ns1.example.com", "ns2.example.com" };
  DnsRecordText_t texts[3];
  static_setTexts(texts, names, 3);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 3);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  static_assertValue(&value, "ns1.example.com\nns2.example.com", 2, 2, SHA256_OF_NS_PAIR);
}

void test_ns_names_sha256_is_taken_of_the_text(void)
{
  static const char* const names[] = { "b", "a" };
  DnsRecordText_t texts[2];
  static_setTexts(texts, names, 2);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 2);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  static_assertValue(&value, "a\nb", 2, 2, SHA256_OF_A_LF_B);
}

void test_ns_names_sort_in_strcmp_byte_order_of_lowercase_names(void)
{
  static const char* const names[] = { "Zeta", "ab", "[y", "alpha", "a.b", "@x", "a" };
  DnsRecordText_t texts[7];
  static_setTexts(texts, names, 7);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 7);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_STRING("@x\n[y\na\na.b\nab\nalpha\nzeta", value.ma_text);
  TEST_ASSERT_EQUAL_INT(7, value.m_itemCount);
}

void test_ns_names_keep_a_repeated_name_once(void)
{
  static const char* const names[] = { "B.example", "a.example", "b.example.", "A.EXAMPLE.", "b.example" };
  DnsRecordText_t texts[5];
  static_setTexts(texts, names, 5);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 5);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_STRING("a.example\nb.example", value.ma_text);
  TEST_ASSERT_EQUAL_INT(2, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(2, value.m_keptItemCount);
}

void test_ns_names_nxdomain_and_empty_ok_are_the_empty_text(void)
{
  DnsAnswer_t answers[2] = { static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0), static_textAnswer(DNS_ANSWER_OK, NULL, 0) };
  for (int i = 0; i < 2; i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answers[i], &value));
    static_assertValue(&value, "", 0, 0, SHA256_OF_EMPTY);
  }
}

void test_ns_names_other_status_has_no_value(void)
{
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    DnsAnswer_t answer = static_textAnswer(NOT_OK_STATUSES[i], NULL, 0);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
    static_assertUntouched(&value);
  }
}

static char g_countedNames[DNS_ANSWER_MAX_RECORD_COUNT + 1][16];

void test_ns_names_record_count_at_and_past_the_cap(void)
{
  DnsRecordText_t texts[DNS_ANSWER_MAX_RECORD_COUNT + 1];
  for (int i = 0; i <= DNS_ANSWER_MAX_RECORD_COUNT; i++)
  {
    snprintf(g_countedNames[i], sizeof(g_countedNames[i]), "n%03d", i);
    texts[i].mp_bytes    = g_countedNames[i];
    texts[i].m_byteCount = strlen(g_countedNames[i]);
  }

  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, DNS_ANSWER_MAX_RECORD_COUNT);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_INT(256, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(256, value.m_keptItemCount);
  TEST_ASSERT_EQUAL_size_t(256 * 5 - 1, strlen(value.ma_text));

  answer.m_recordCount = DNS_ANSWER_MAX_RECORD_COUNT + 1;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  static_assertUntouched(&value);

  answer.m_recordCount = -1;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  static_assertUntouched(&value);
}

static char g_longNames[8][TEST_LONG_NAME_SIZE];

static DnsAnswer_t static_capAnswer(DnsRecordText_t* texts, size_t last_len)
{
  for (int i = 0; i < 8; i++)
  {
    size_t name_len = i < 7 ? 255 : last_len;
    memset(g_longNames[i], 'a' + i, name_len);
    g_longNames[i][name_len] = '\0';
    texts[i].mp_bytes    = g_longNames[i];
    texts[i].m_byteCount = name_len;
  }
  return static_textAnswer(DNS_ANSWER_OK, texts, 8);
}

void test_ns_names_text_one_below_and_at_the_cap_is_whole(void)
{
  static const struct {
    size_t      m_lastLen;
    const char* mp_sha256Hex;
  } cases[] = { { 255, SHA256_OF_CAP_BELOW }, { 256, SHA256_OF_CAP_AT } };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    DnsRecordText_t texts[8];
    DnsAnswer_t answer = static_capAnswer(texts, cases[i].m_lastLen);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
    TEST_ASSERT_EQUAL_size_t(7 * 256 + cases[i].m_lastLen, strlen(value.ma_text));
    TEST_ASSERT_EQUAL_INT(8, value.m_itemCount);
    TEST_ASSERT_EQUAL_INT(8, value.m_keptItemCount);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_sha256Hex, value.ma_sha256Hex);
    TEST_ASSERT_EQUAL_MEMORY(g_longNames[7], value.ma_text + 7 * 256, cases[i].m_lastLen);
  }
}

void test_ns_names_text_past_the_cap_keeps_whole_lines(void)
{
  DnsRecordText_t texts[8];
  DnsAnswer_t answer = static_capAnswer(texts, 257);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_size_t(7 * 256 - 1, strlen(value.ma_text));
  TEST_ASSERT_EQUAL_MEMORY(g_longNames[6], value.ma_text + 6 * 256, 255);
  TEST_ASSERT_EQUAL_INT(8, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(7, value.m_keptItemCount);
  TEST_ASSERT_EQUAL_STRING(SHA256_OF_CAP_PAST, value.ma_sha256Hex);
}

void test_ns_names_line_past_the_cap_still_changes_the_sha256(void)
{
  DnsRecordText_t texts[8];
  DnsAnswer_t answer = static_capAnswer(texts, 257);
  WatchlistDomainValue_t first;
  static_fillValue(&first);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &first));

  g_longNames[7][100] = 'i';
  WatchlistDomainValue_t second;
  static_fillValue(&second);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &second));

  TEST_ASSERT_EQUAL_STRING(first.ma_text, second.ma_text);
  TEST_ASSERT_EQUAL_INT(7, second.m_keptItemCount);
  TEST_ASSERT_FALSE(strcmp(first.ma_sha256Hex, second.ma_sha256Hex) == 0);
}

void test_ns_names_keep_no_line_after_a_dropped_line(void)
{
  static char first[1501];
  static char second[601];
  static char third[11];
  memset(first, 'a', 1500);
  first[1500] = '\0';
  memset(second, 'b', 600);
  second[600] = '\0';
  memset(third, 'c', 10);
  third[10] = '\0';
  const char* const names[] = { third, second, first };
  DnsRecordText_t texts[3];
  static_setTexts(texts, names, 3);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 3);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_STRING(first, value.ma_text);
  TEST_ASSERT_EQUAL_INT(3, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(1, value.m_keptItemCount);
}

void test_ns_names_root_name_is_one_empty_line(void)
{
  static const char* const names[] = { "." };
  DnsRecordText_t texts[1];
  static_setTexts(texts, names, 1);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 1);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  static_assertValue(&value, "", 1, 1, SHA256_OF_EMPTY);
}

void test_mx_records_lines_hold_priority_and_lowercase_host(void)
{
  DnsMxRecord_t records[] = {
    { 10, (char*)"MX2.Example.com." },
    { 5,  (char*)"mx1.example.com"  },
    { 10, (char*)"mx2.example.com"  },
  };
  DnsAnswer_t answer = static_mxAnswer(DNS_ANSWER_OK, records, 3, false);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  static_assertValue(&value, "10 mx2.example.com\n5 mx1.example.com", 2, 2, SHA256_OF_MX_PAIR);
}

void test_mx_records_priority_is_part_of_the_line(void)
{
  DnsMxRecord_t records[] = {
    { 65535, (char*)"a.example" },
    { 0,     (char*)"a.example" },
  };
  DnsAnswer_t answer = static_mxAnswer(DNS_ANSWER_OK, records, 2, false);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  TEST_ASSERT_EQUAL_STRING("0 a.example\n65535 a.example", value.ma_text);
  TEST_ASSERT_EQUAL_INT(2, value.m_itemCount);
}

void test_mx_records_null_mx_is_a_null_line(void)
{
  WatchlistDomainValue_t value;
  DnsAnswer_t alone = static_mxAnswer(DNS_ANSWER_OK, NULL, 0, true);
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&alone, &value));
  static_assertValue(&value, "null", 1, 1, SHA256_OF_NULL);

  DnsMxRecord_t records[] = { { 0, (char*)"A.B" } };
  DnsAnswer_t beside = static_mxAnswer(DNS_ANSWER_OK, records, 1, true);
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&beside, &value));
  static_assertValue(&value, "0 a.b\nnull", 2, 2, SHA256_OF_MX_AND_NULL);
}

void test_mx_records_nxdomain_and_empty_ok_are_the_empty_text(void)
{
  DnsAnswer_t answers[2] = { static_mxAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0, true), static_mxAnswer(DNS_ANSWER_OK, NULL, 0, false) };
  for (int i = 0; i < 2; i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&answers[i], &value));
    static_assertValue(&value, "", 0, 0, SHA256_OF_EMPTY);
  }
}

void test_mx_records_other_status_has_no_value(void)
{
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    DnsAnswer_t answer = static_mxAnswer(NOT_OK_STATUSES[i], NULL, 0, true);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
    static_assertUntouched(&value);
  }
}

static char g_mxHosts[DNS_ANSWER_MAX_RECORD_COUNT + 1][16];

void test_mx_records_record_count_at_and_past_the_cap(void)
{
  DnsMxRecord_t records[DNS_ANSWER_MAX_RECORD_COUNT + 1];
  for (int i = 0; i <= DNS_ANSWER_MAX_RECORD_COUNT; i++)
  {
    snprintf(g_mxHosts[i], sizeof(g_mxHosts[i]), "h%03d", i);
    records[i].m_priority  = 1;
    records[i].mp_hostname = g_mxHosts[i];
  }

  DnsAnswer_t answer = static_mxAnswer(DNS_ANSWER_OK, records, DNS_ANSWER_MAX_RECORD_COUNT, true);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  TEST_ASSERT_EQUAL_INT(257, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(257, value.m_keptItemCount);
  TEST_ASSERT_EQUAL_size_t(256 * 7 + 4, strlen(value.ma_text));

  answer.m_recordCount = DNS_ANSWER_MAX_RECORD_COUNT + 1;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  static_assertUntouched(&value);

  answer.m_recordCount = -1;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  static_assertUntouched(&value);
}

void test_mx_records_text_past_the_cap_keeps_whole_lines(void)
{
  static char first_host[1499];
  static char second_host[599];
  memset(first_host, 'a', sizeof(first_host) - 1);
  first_host[sizeof(first_host) - 1] = '\0';
  memset(second_host, 'b', sizeof(second_host) - 1);
  second_host[sizeof(second_host) - 1] = '\0';
  DnsMxRecord_t records[] = { { 2, second_host }, { 1, first_host } };
  DnsAnswer_t answer = static_mxAnswer(DNS_ANSWER_OK, records, 2, false);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteMxRecords(&answer, &value));
  TEST_ASSERT_EQUAL_size_t(1500, strlen(value.ma_text));
  TEST_ASSERT_EQUAL_MEMORY("1 aaa", value.ma_text, 5);
  TEST_ASSERT_EQUAL_INT(2, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(1, value.m_keptItemCount);
}

static const char* const PUBLIC_V4[]  = { "93.184.216.34" };
static const char* const PUBLIC_V6[]  = { "2606:2800:220:1:248:1893:25c8:1946" };
static const char* const PRIVATE_V4[] = { "93.184.216.34", "10.0.0.1" };
static const char* const PRIVATE_V6[] = { "2606:2800:220:1:248:1893:25c8:1946", "fd00::1" };

void test_ip_address_reachability_text_follows_the_addresses(void)
{
  DnsRecordText_t v4[2];
  DnsRecordText_t v6[2];
  DnsRecordText_t private_v4[2];
  DnsRecordText_t private_v6[2];
  static_setTexts(v4, PUBLIC_V4, 1);
  static_setTexts(v6, PUBLIC_V6, 1);
  static_setTexts(private_v4, PRIVATE_V4, 2);
  static_setTexts(private_v6, PRIVATE_V6, 2);

  const struct {
    DnsAnswer_t m_a;
    DnsAnswer_t m_aaaa;
    const char* mp_text;
    const char* mp_sha256Hex;
  } cases[] = {
    { static_textAnswer(DNS_ANSWER_OK,       v4,         1), static_textAnswer(DNS_ANSWER_OK,       v6,         1), "public",     SHA256_OF_PUBLIC      },
    { static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL,       0), static_textAnswer(DNS_ANSWER_OK,       v6,         1), "public",     SHA256_OF_PUBLIC      },
    { static_textAnswer(DNS_ANSWER_OK,       v4,         1), static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL,       0), "public",     SHA256_OF_PUBLIC      },
    { static_textAnswer(DNS_ANSWER_OK,       private_v4, 2), static_textAnswer(DNS_ANSWER_OK,       v6,         1), "not_public", SHA256_OF_NOT_PUBLIC  },
    { static_textAnswer(DNS_ANSWER_OK,       v4,         1), static_textAnswer(DNS_ANSWER_OK,       private_v6, 2), "not_public", SHA256_OF_NOT_PUBLIC  },
    { static_textAnswer(DNS_ANSWER_OK,       NULL,       0), static_textAnswer(DNS_ANSWER_OK,       NULL,       0), "empty",      SHA256_OF_EMPTY_STATE },
    { static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL,       0), static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL,       0), "empty",      SHA256_OF_EMPTY_STATE },
    { static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL,       0), static_textAnswer(DNS_ANSWER_OK,       NULL,       0), "empty",      SHA256_OF_EMPTY_STATE },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_tryWriteIpAddressReachability(&cases[i].m_a, &cases[i].m_aaaa, &value), cases[i].mp_text);
    static_assertValue(&value, cases[i].mp_text, 1, 1, cases[i].mp_sha256Hex);
  }
}

void test_ip_address_reachability_not_public_name_on_either_side_is_not_public(void)
{
  DnsRecordText_t v4[1];
  static_setTexts(v4, PUBLIC_V4, 1);
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    DnsAnswer_t not_public = static_textAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, NULL, 0);
    DnsAnswer_t other      = static_textAnswer(NOT_OK_STATUSES[i], NULL, 0);
    DnsAnswer_t ok         = static_textAnswer(DNS_ANSWER_OK, v4, 1);

    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteIpAddressReachability(&not_public, &other, &value));
    static_assertValue(&value, "not_public", 1, 1, SHA256_OF_NOT_PUBLIC);

    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteIpAddressReachability(&other, &not_public, &value));
    static_assertValue(&value, "not_public", 1, 1, SHA256_OF_NOT_PUBLIC);

    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteIpAddressReachability(&ok, &not_public, &value));
    static_assertValue(&value, "not_public", 1, 1, SHA256_OF_NOT_PUBLIC);
  }
}

void test_ip_address_reachability_error_on_either_side_has_no_value(void)
{
  DnsRecordText_t v4[1];
  static_setTexts(v4, PUBLIC_V4, 1);
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    if (NOT_OK_STATUSES[i] == DNS_ANSWER_NOT_PUBLIC_NAME)
      continue;
    DnsAnswer_t error = static_textAnswer(NOT_OK_STATUSES[i], NULL, 0);
    DnsAnswer_t ok    = static_textAnswer(DNS_ANSWER_OK, v4, 1);

    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteIpAddressReachability(&error, &ok, &value));
    static_assertUntouched(&value);

    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteIpAddressReachability(&ok, &error, &value));
    static_assertUntouched(&value);
  }
}

static const char* const HOSTING_V4[] = { "93.184.216.34", "8.8.8.8" };
static const char* const HOSTING_V6[] = { "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888" };
#define HOSTING_JOINED     "93.184.216.34,8.8.8.8,2606:2800:220:1:248:1893:25c8:1946,2001:4860:4860::8888"
#define HOSTING_JOINED_LEN 77

#define HOSTING_FILL 'x'

static void static_fillAddresses(char* addresses, size_t size)
{
  memset(addresses, HOSTING_FILL, size - 1);
  addresses[size - 1] = '\0';
}

void test_hosting_ip_addresses_join_a_then_aaaa_in_answer_order(void)
{
  DnsRecordText_t v4[2];
  DnsRecordText_t v6[2];
  static_setTexts(v4, HOSTING_V4, 2);
  static_setTexts(v6, HOSTING_V6, 2);
  DnsAnswer_t a    = static_textAnswer(DNS_ANSWER_OK, v4, 2);
  DnsAnswer_t aaaa = static_textAnswer(DNS_ANSWER_OK, v6, 2);

  char addresses[128];
  static_fillAddresses(addresses, sizeof(addresses));
  watchlist_dns_lookup_writeHostingIpAddresses(&a, &aaaa, addresses, sizeof(addresses));
  TEST_ASSERT_EQUAL_STRING(HOSTING_JOINED, addresses);
  TEST_ASSERT_EQUAL_size_t(HOSTING_JOINED_LEN, strlen(addresses));
}

void test_hosting_ip_addresses_ok_and_nxdomain_answers_are_read(void)
{
  DnsRecordText_t v4[2];
  DnsRecordText_t v6[2];
  static_setTexts(v4, HOSTING_V4, 2);
  static_setTexts(v6, HOSTING_V6, 2);
  DnsAnswer_t ok_a     = static_textAnswer(DNS_ANSWER_OK,       v4,   2);
  DnsAnswer_t ok_aaaa  = static_textAnswer(DNS_ANSWER_OK,       v6,   2);
  DnsAnswer_t nxdomain = static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0);

  char addresses[128];
  static_fillAddresses(addresses, sizeof(addresses));
  watchlist_dns_lookup_writeHostingIpAddresses(&ok_a, &nxdomain, addresses, sizeof(addresses));
  TEST_ASSERT_EQUAL_STRING("93.184.216.34,8.8.8.8", addresses);

  static_fillAddresses(addresses, sizeof(addresses));
  watchlist_dns_lookup_writeHostingIpAddresses(&nxdomain, &ok_aaaa, addresses, sizeof(addresses));
  TEST_ASSERT_EQUAL_STRING("2606:2800:220:1:248:1893:25c8:1946,2001:4860:4860::8888", addresses);
}

void test_hosting_ip_addresses_other_status_on_either_side_writes_nothing(void)
{
  DnsRecordText_t v4[1];
  DnsRecordText_t v6[1];
  static_setTexts(v4, HOSTING_V4, 1);
  static_setTexts(v6, HOSTING_V6, 1);
  for (int i = 0; i < NOT_OK_STATUS_COUNT; i++)
  {
    char message[32] = "";
    snprintf(message, sizeof(message), "status %d", (int)NOT_OK_STATUSES[i]);
    DnsAnswer_t other   = static_textAnswer(NOT_OK_STATUSES[i], NULL, 0);
    DnsAnswer_t ok_a    = static_textAnswer(DNS_ANSWER_OK, v4, 1);
    DnsAnswer_t ok_aaaa = static_textAnswer(DNS_ANSWER_OK, v6, 1);

    char addresses[128];
    static_fillAddresses(addresses, sizeof(addresses));
    watchlist_dns_lookup_writeHostingIpAddresses(&other, &ok_aaaa, addresses, sizeof(addresses));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", addresses, message);

    static_fillAddresses(addresses, sizeof(addresses));
    watchlist_dns_lookup_writeHostingIpAddresses(&ok_a, &other, addresses, sizeof(addresses));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", addresses, message);
  }
}

void test_hosting_ip_addresses_without_an_address_write_nothing(void)
{
  DnsAnswer_t nxdomain = static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0);
  DnsAnswer_t empty_ok = static_textAnswer(DNS_ANSWER_OK,       NULL, 0);
  const DnsAnswer_t* pairs[][2] = {
    { &nxdomain, &nxdomain }, { &empty_ok, &empty_ok }, { &nxdomain, &empty_ok }, { &empty_ok, &nxdomain },
  };
  for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++)
  {
    char addresses[128];
    static_fillAddresses(addresses, sizeof(addresses));
    watchlist_dns_lookup_writeHostingIpAddresses(pairs[i][0], pairs[i][1], addresses, sizeof(addresses));
    TEST_ASSERT_EQUAL_STRING("", addresses);
  }
}

void test_hosting_ip_addresses_not_public_address_on_either_side_writes_nothing(void)
{
  DnsRecordText_t v4[1];
  DnsRecordText_t v6[1];
  DnsRecordText_t private_v4[2];
  DnsRecordText_t private_v6[2];
  static_setTexts(v4, HOSTING_V4, 1);
  static_setTexts(v6, HOSTING_V6, 1);
  static_setTexts(private_v4, PRIVATE_V4, 2);
  static_setTexts(private_v6, PRIVATE_V6, 2);

  DnsAnswer_t a            = static_textAnswer(DNS_ANSWER_OK, v4,         1);
  DnsAnswer_t aaaa         = static_textAnswer(DNS_ANSWER_OK, v6,         1);
  DnsAnswer_t private_a    = static_textAnswer(DNS_ANSWER_OK, private_v4, 2);
  DnsAnswer_t private_aaaa = static_textAnswer(DNS_ANSWER_OK, private_v6, 2);

  char addresses[128];
  static_fillAddresses(addresses, sizeof(addresses));
  watchlist_dns_lookup_writeHostingIpAddresses(&private_a, &aaaa, addresses, sizeof(addresses));
  TEST_ASSERT_EQUAL_STRING("", addresses);

  static_fillAddresses(addresses, sizeof(addresses));
  watchlist_dns_lookup_writeHostingIpAddresses(&a, &private_aaaa, addresses, sizeof(addresses));
  TEST_ASSERT_EQUAL_STRING("", addresses);
}

void test_hosting_ip_addresses_fit_with_their_nul(void)
{
  DnsRecordText_t v4[2];
  DnsRecordText_t v6[2];
  static_setTexts(v4, HOSTING_V4, 2);
  static_setTexts(v6, HOSTING_V6, 2);
  DnsAnswer_t a    = static_textAnswer(DNS_ANSWER_OK, v4, 2);
  DnsAnswer_t aaaa = static_textAnswer(DNS_ANSWER_OK, v6, 2);
  TEST_ASSERT_EQUAL_size_t(HOSTING_JOINED_LEN, strlen(HOSTING_JOINED));

  static const struct {
    size_t m_size;
    bool   m_isWritten;
  } cases[] = {
    { 5,                      false },
    { HOSTING_JOINED_LEN,     false },
    { HOSTING_JOINED_LEN + 1, true  },
    { HOSTING_JOINED_LEN + 2, true  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char message[32] = "";
    snprintf(message, sizeof(message), "size %zu", cases[i].m_size);
    char addresses[128];
    static_fillAddresses(addresses, sizeof(addresses));

    watchlist_dns_lookup_writeHostingIpAddresses(&a, &aaaa, addresses, cases[i].m_size);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].m_isWritten ? HOSTING_JOINED : "", addresses, message);
    for (size_t j = cases[i].m_size; j < sizeof(addresses) - 1; j++)
      TEST_ASSERT_EQUAL_CHAR_MESSAGE(HOSTING_FILL, addresses[j], message);
  }
}

static const DnsTakeoverSuffix_t DISCOURSE = { "Discourse", "trydiscourse.com" };

static DNSTAKEOVERCHECKRecord_t static_takeoverRecord(int chain_length, bool is_target_found, const DnsTakeoverSuffix_t* matched_suffix)
{
  DNSTAKEOVERCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  memcpy(record.ma_hostname, "www.example.com", sizeof("www.example.com"));
  for (int i = 0; i < chain_length; i++)
    snprintf(record.ma_hostnameChain[i], sizeof(record.ma_hostnameChain[i]), "c%d.trydiscourse.com", i);
  record.m_hostnameChainLength = chain_length;
  record.m_isTargetFound       = is_target_found;
  record.mp_matchedSuffix      = matched_suffix;
  return record;
}

void test_cname_takeover_lookup_status_other_than_ok_has_no_value(void)
{
  static const DnsLookupStatus_t statuses[] = { DNS_LOOKUP_NOT_FOUND, DNS_LOOKUP_NO_ANSWER, DNS_LOOKUP_INVALID_NAME, DNS_LOOKUP_NO_MEMORY };
  DNSTAKEOVERCHECKRecord_t record = static_takeoverRecord(1, false, &DISCOURSE);
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteCnameTakeover(statuses[i], &record, &value));
    static_assertUntouched(&value);
  }
}

void test_cname_takeover_text_follows_the_record(void)
{
  const struct {
    DNSTAKEOVERCHECKRecord_t m_record;
    const char*              mp_text;
    const char*              mp_sha256Hex;
  } cases[] = {
    { static_takeoverRecord(0, false, NULL),       "none",                 SHA256_OF_NONE                 },
    { static_takeoverRecord(0, false, &DISCOURSE), "none",                 SHA256_OF_NONE                 },
    { static_takeoverRecord(1, false, NULL),       "vulnerable",           SHA256_OF_VULNERABLE           },
    { static_takeoverRecord(1, false, &DISCOURSE), "vulnerable Discourse", SHA256_OF_VULNERABLE_DISCOURSE },
    { static_takeoverRecord(2, false, &DISCOURSE), "vulnerable Discourse", SHA256_OF_VULNERABLE_DISCOURSE },
    { static_takeoverRecord(1, true,  &DISCOURSE), "none",                 SHA256_OF_NONE                 },
    { static_takeoverRecord(2, true,  NULL),       "none",                 SHA256_OF_NONE                 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteCnameTakeover(DNS_LOOKUP_OK, &cases[i].m_record, &value));
    static_assertValue(&value, cases[i].mp_text, 1, 1, cases[i].mp_sha256Hex);
  }
}

static char g_longServiceName[WATCHLIST_DOMAIN_VALUE_MAX_LEN];

void test_cname_takeover_text_at_and_past_the_cap(void)
{
  DnsTakeoverSuffix_t long_service = { g_longServiceName, "example.net" };
  DNSTAKEOVERCHECKRecord_t record = static_takeoverRecord(1, false, &long_service);
  size_t service_len = WATCHLIST_DOMAIN_VALUE_MAX_LEN - strlen("vulnerable ");
  memset(g_longServiceName, 'S', service_len);
  g_longServiceName[service_len] = '\0';

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteCnameTakeover(DNS_LOOKUP_OK, &record, &value));
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_VALUE_MAX_LEN, strlen(value.ma_text));
  TEST_ASSERT_EQUAL_MEMORY("vulnerable SS", value.ma_text, 13);
  TEST_ASSERT_EQUAL_INT(1, value.m_keptItemCount);

  g_longServiceName[service_len]     = 'S';
  g_longServiceName[service_len + 1] = '\0';
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteCnameTakeover(DNS_LOOKUP_OK, &record, &value));
  static_assertUntouched(&value);
}

void test_email_check_results_without_checks_are_all_dashes(void)
{
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteEmailCheckResults(NULL, 0, &value));
  static_assertValue(&value, "---------------------", 1, 1, SHA256_OF_NO_CHECK);
}

void test_email_check_results_put_each_result_at_its_kind(void)
{
  const EmailCheckItem_t checks[] = {
    { EMAILCHECK_KIND_MTA_STS,      EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_DMARC_RECORD, EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_SPF_RECORD,   EMAILCHECK_RESULT_PASS },
    { EMAILCHECK_KIND_MX,           EMAILCHECK_RESULT_WARN },
  };
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteEmailCheckResults(checks, 4, &value));
  static_assertValue(&value, "p-------f----------wf", 1, 1, SHA256_OF_CHECK_RESULTS);
  TEST_ASSERT_EQUAL_size_t(EMAILCHECK_KIND_COUNT, strlen(value.ma_text));
}

void test_dns_values_failed_sha256_leaves_the_value_untouched(void)
{
  static const WatchlistDomainTestDigestFault_t faults[] = {
    TEST_DIGEST_NO_CONTEXT, TEST_DIGEST_INIT_FAILS, TEST_DIGEST_UPDATE_FAILS, TEST_DIGEST_FINAL_FAILS, TEST_DIGEST_SHORT_LENGTH,
  };
  static const char* const names[] = { "b", "a" };
  DnsRecordText_t texts[2];
  static_setTexts(texts, names, 2);
  DnsAnswer_t ns_answer  = static_textAnswer(DNS_ANSWER_OK, texts, 2);
  DnsMxRecord_t mx[]     = { { 1, (char*)"a" } };
  DnsAnswer_t mx_answer  = static_mxAnswer(DNS_ANSWER_OK, mx, 1, false);
  DnsAnswer_t nxdomain   = static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0);
  DnsAnswer_t presence_answers[4] = { static_textAnswer(DNS_ANSWER_OK, NULL, 0) };
  DNSTAKEOVERCHECKRecord_t record = static_takeoverRecord(0, false, NULL);
  const EmailCheckItem_t checks[] = { { EMAILCHECK_KIND_MX, EMAILCHECK_RESULT_PASS } };

  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    for (int call = 0; call < 6; call++)
    {
      WatchlistDomainValue_t value;
      static_fillValue(&value);
      g_digestFault = faults[i];
      bool is_written = true;
      if (call == 0)
        is_written = watchlist_dns_lookup_tryWriteNsNames(&ns_answer, &value);
      else if (call == 1)
        is_written = watchlist_dns_lookup_tryWriteMxRecords(&mx_answer, &value);
      else if (call == 2)
        is_written = watchlist_dns_lookup_tryWriteDnsPresence(presence_answers, &value);
      else if (call == 3)
        is_written = watchlist_dns_lookup_tryWriteIpAddressReachability(&nxdomain, &nxdomain, &value);
      else if (call == 4)
        is_written = watchlist_dns_lookup_tryWriteCnameTakeover(DNS_LOOKUP_OK, &record, &value);
      else
        is_written = watchlist_dns_lookup_tryWriteEmailCheckResults(checks, 1, &value);
      TEST_ASSERT_FALSE(is_written);
      static_assertUntouched(&value);
      TEST_ASSERT_EQUAL_INT(TEST_DIGEST_PASS, g_digestFault);
      TEST_ASSERT_EQUAL_INT(0, g_liveContextCount);
    }
  }
}

void test_dns_values_failed_sha256_of_the_empty_text_has_no_value(void)
{
  DnsAnswer_t nxdomain = static_textAnswer(DNS_ANSWER_NXDOMAIN, NULL, 0);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  g_digestFault = TEST_DIGEST_FINAL_FAILS;
  TEST_ASSERT_FALSE(watchlist_dns_lookup_tryWriteNsNames(&nxdomain, &value));
  static_assertUntouched(&value);
}

void test_written_value_leaves_no_sha256_context_open(void)
{
  static const char* const names[] = { "b", "a" };
  DnsRecordText_t texts[2];
  static_setTexts(texts, names, 2);
  DnsAnswer_t answer = static_textAnswer(DNS_ANSWER_OK, texts, 2);
  WatchlistDomainValue_t value;
  TEST_ASSERT_TRUE(watchlist_dns_lookup_tryWriteNsNames(&answer, &value));
  TEST_ASSERT_EQUAL_INT(0, g_liveContextCount);
}

static TlsProbeResult_t static_tlsResult(int days_remaining, const char* valid_until, unsigned int problems, const char* protocol)
{
  TlsProbeResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_daysRemaining = days_remaining;
  snprintf(result.m_serverCertificate.ma_validUntil, sizeof(result.m_serverCertificate.ma_validUntil), "%s", valid_until);
  result.m_problems = problems;
  snprintf(result.ma_protocol, sizeof(result.ma_protocol), "%s", protocol);
  return result;
}

void test_certificate_expiry_bucket_follows_the_days_left(void)
{
  static const struct {
    int         m_daysRemaining;
    const char* mp_validUntil;
    const char* mp_text;
  } cases[] = {
    {  8, "2026-11-08T10:00:00Z", "none\n2026-11-08T10:00:00Z" },
    {  7, "2026-11-07T10:00:00Z", "7\n2026-11-07T10:00:00Z"    },
    {  2, "2026-11-02T10:00:00Z", "7\n2026-11-02T10:00:00Z"    },
    {  1, "2026-11-01T10:00:00Z", "1\n2026-11-01T10:00:00Z"    },
    {  0, "2026-10-31T10:00:00Z", "1\n2026-10-31T10:00:00Z"    },
    { -1, "2026-10-30T10:00:00Z", "1\n2026-10-30T10:00:00Z"    },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    TlsProbeResult_t result = static_tlsResult(cases[c].m_daysRemaining, cases[c].mp_validUntil, TLSPROBE_PROBLEM_OTHER, "TLSv1.3");
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_tryWriteCertificateExpiry(&result, &value), cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, value.m_itemCount, cases[c].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, value.m_keptItemCount, cases[c].mp_text);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(WATCHLIST_DOMAIN_SHA256_HEX_LEN, strlen(value.ma_sha256Hex), cases[c].mp_text);
  }
}

void test_certificate_expiry_sha256_is_taken_of_the_text(void)
{
  static const struct {
    int         m_daysRemaining;
    const char* mp_validUntil;
    const char* mp_text;
    const char* mp_sha256;
  } cases[] = {
    {  5, "2026-11-06T12:00:00Z", "7\n2026-11-06T12:00:00Z",    "c0494eb85e88c8bb707a4d70dab584a5c24de4126b875f39c55bbe6fd02d675b" },
    { 30, "2026-12-31T23:59:59Z", "none\n2026-12-31T23:59:59Z", "331c161322ba5b906593d0ee7c6c4ac16a2713edd2ac3c111a73addb914800e0" },
    {  1, "2026-11-01T00:00:00Z", "1\n2026-11-01T00:00:00Z",    "ca075c6151f7bd96d75fc359afae76b3de5f7e4f18d88589a5f9790d1f0a4b6a" },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    TlsProbeResult_t result = static_tlsResult(cases[c].m_daysRemaining, cases[c].mp_validUntil, 0, "TLSv1.2");
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateExpiry(&result, &value));
    static_assertValue(&value, cases[c].mp_text, 2, 2, cases[c].mp_sha256);
  }
}

void test_certificate_expiry_without_its_end_has_no_value(void)
{
  TlsProbeResult_t result = static_tlsResult(3, "", 0, "TLSv1.2");
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_ssl_check_tryWriteCertificateExpiry(&result, &value));
  static_assertUntouched(&value);
}

void test_certificate_validity_without_a_problem_is_valid(void)
{
  static const unsigned int problem_sets[] = { 0, 1u << 8 };
  for (size_t c = 0; c < sizeof(problem_sets) / sizeof(problem_sets[0]); c++)
  {
    TlsProbeResult_t result = static_tlsResult(40, "2026-12-09T00:00:00Z", problem_sets[c], "TLSv1.3");
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateValidity(&result, &value));
    static_assertValue(&value, "valid", 1, 1, "ec654fac9599f62e79e2706abef23dfb7c07c08185aa86db4d8695f0b718d1b3");
  }
}

void test_certificate_validity_each_problem_has_its_name(void)
{
  static const struct {
    unsigned int m_bit;
    const char*  mp_name;
  } cases[] = {
    { TLSPROBE_PROBLEM_EXPIRED,           "expired"           },
    { TLSPROBE_PROBLEM_NOT_YET_VALID,     "not_yet_valid"     },
    { TLSPROBE_PROBLEM_SELF_SIGNED,       "self_signed"       },
    { TLSPROBE_PROBLEM_UNTRUSTED_ROOT,    "untrusted_root"    },
    { TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, "hostname_mismatch" },
    { TLSPROBE_PROBLEM_CHAIN_INCOMPLETE,  "chain_incomplete"  },
    { TLSPROBE_PROBLEM_OTHER,             "other"             },
    { TLSPROBE_PROBLEM_WEAK_CRYPTO,       "weak_crypto"       },
  };
  TEST_ASSERT_EQUAL_INT(8, TLSPROBE_PROBLEM_NAME_COUNT);
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    TlsProbeResult_t result = static_tlsResult(40, "2026-12-09T00:00:00Z", cases[c].m_bit, "TLSv1.3");
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_tryWriteCertificateValidity(&result, &value), cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_name, value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, value.m_itemCount, cases[c].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, value.m_keptItemCount, cases[c].mp_name);
  }
}

void test_certificate_validity_names_keep_the_order_of_their_bits(void)
{
  TlsProbeResult_t result = static_tlsResult(40, "2026-12-09T00:00:00Z",
                                             TLSPROBE_PROBLEM_WEAK_CRYPTO | TLSPROBE_PROBLEM_EXPIRED | TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, "TLSv1.3");
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateValidity(&result, &value));
  static_assertValue(&value, "expired\nhostname_mismatch\nweak_crypto", 3, 3, "08a897ba6b14ff08ad31976b17ffc1b091140c46323b05a8492d8e10b5860ff0");

  result = static_tlsResult(40, "2026-12-09T00:00:00Z", 0x1FFu, "TLSv1.3");
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateValidity(&result, &value));
  TEST_ASSERT_EQUAL_STRING("expired\nnot_yet_valid\nself_signed\nuntrusted_root\nhostname_mismatch\nchain_incomplete\nother\nweak_crypto", value.ma_text);
  TEST_ASSERT_EQUAL_INT(8, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(8, value.m_keptItemCount);
}

static SSLCHECKRecord_t static_listingRecord(bool is_unavailable, bool is_feed_loaded, const char* listing_reason)
{
  SSLCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  record.m_isBlacklistUnavailable = is_unavailable;
  record.m_isBlacklistFeedLoaded  = is_feed_loaded;
  snprintf(record.ma_blacklistListingReason, sizeof(record.ma_blacklistListingReason), "%s", listing_reason);
  snprintf(record.ma_blacklistListingTime, sizeof(record.ma_blacklistListingTime), "%s", "2026-09-01T08:00:00Z");
  return record;
}

void test_certificate_listing_text_follows_the_list(void)
{
  SSLCHECKRecord_t record = static_listingRecord(false, true, "");
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateListing(&record, &value));
  static_assertValue(&value, "not_listed", 1, 1, "339475c26e7b224f9973eb0ec39523172401c5628a4429b54804dbc6b6b83221");

  record = static_listingRecord(false, true, "Dridex C&C");
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_ssl_check_tryWriteCertificateListing(&record, &value));
  static_assertValue(&value, "listed\nDridex C&C", 2, 2, "a0689e61dc5bf203007765008c272ee0792cd75eacb726d1354d1ed7a2fcdb2a");
}

void test_certificate_listing_of_a_list_not_read_or_not_loaded_has_no_value(void)
{
  static const struct {
    bool        m_isUnavailable;
    bool        m_isFeedLoaded;
    const char* mp_reason;
  } cases[] = {
    { true,  true,  "Dridex C&C" },
    { true,  true,  ""           },
    { true,  false, ""           },
    { false, false, "Dridex C&C" },
    { false, false, ""           },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    SSLCHECKRecord_t record = static_listingRecord(cases[c].m_isUnavailable, cases[c].m_isFeedLoaded, cases[c].mp_reason);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);
    TEST_ASSERT_FALSE_MESSAGE(watchlist_ssl_check_tryWriteCertificateListing(&record, &value), message);
    static_assertUntouched(&value);
  }
}

void test_tls_protocol_text_is_the_protocol_name(void)
{
  static const char* const protocols[] = { "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };
  for (size_t c = 0; c < sizeof(protocols) / sizeof(protocols[0]); c++)
  {
    TlsProbeResult_t result = static_tlsResult(40, "2026-12-09T00:00:00Z", 0, protocols[c]);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_tryWriteTlsProtocol(&result, &value), protocols[c]);
    TEST_ASSERT_EQUAL_STRING(protocols[c], value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, value.m_itemCount, protocols[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, value.m_keptItemCount, protocols[c]);
    if (c == 0)
      TEST_ASSERT_EQUAL_STRING("ede892933f763d59c23a190c5047384b94f884f7fef23c8c2fe4b6ee3c5b2988", value.ma_sha256Hex);
    else if (c == 2)
      TEST_ASSERT_EQUAL_STRING("9ba51fafa79696331b1d48485cd6041070682b0ee815ff3065668603df4ec6df", value.ma_sha256Hex);
  }
}

void test_tls_protocol_without_a_name_has_no_value(void)
{
  TlsProbeResult_t result = static_tlsResult(40, "2026-12-09T00:00:00Z", 0, "");
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_ssl_check_tryWriteTlsProtocol(&result, &value));
  static_assertUntouched(&value);
}

void test_tls_values_failed_sha256_leaves_the_value_untouched(void)
{
  static const WatchlistDomainTestDigestFault_t faults[] = {
    TEST_DIGEST_NO_CONTEXT, TEST_DIGEST_INIT_FAILS, TEST_DIGEST_UPDATE_FAILS, TEST_DIGEST_FINAL_FAILS, TEST_DIGEST_SHORT_LENGTH,
  };
  TlsProbeResult_t result = static_tlsResult(5, "2026-11-04T00:00:00Z", TLSPROBE_PROBLEM_SELF_SIGNED, "TLSv1.1");
  SSLCHECKRecord_t record = static_listingRecord(false, true, "Dridex C&C");

  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    for (int call = 0; call < 4; call++)
    {
      WatchlistDomainValue_t value;
      static_fillValue(&value);
      g_digestFault = faults[i];
      bool is_written = true;
      if (call == 0)
        is_written = watchlist_ssl_check_tryWriteCertificateExpiry(&result, &value);
      else if (call == 1)
        is_written = watchlist_ssl_check_tryWriteCertificateValidity(&result, &value);
      else if (call == 2)
        is_written = watchlist_ssl_check_tryWriteCertificateListing(&record, &value);
      else
        is_written = watchlist_ssl_check_tryWriteTlsProtocol(&result, &value);
      TEST_ASSERT_FALSE(is_written);
      static_assertUntouched(&value);
      TEST_ASSERT_EQUAL_INT(TEST_DIGEST_PASS, g_digestFault);
      TEST_ASSERT_EQUAL_INT(0, g_liveContextCount);
    }
  }
}

#define TEST_EXPIRY_EPOCH 1796083200

static RdapRegistration_t static_registration(const char* expires_at, long registrar_iana_id, const char* registrar_name, RdapDelegationSigned_t delegation_signed)
{
  RdapRegistration_t registration;
  memset(&registration, 0, sizeof(registration));
  snprintf(registration.ma_expiresAt, sizeof(registration.ma_expiresAt), "%s", expires_at);
  registration.m_registrarIanaId = registrar_iana_id;
  snprintf(registration.ma_registrarName, sizeof(registration.ma_registrarName), "%s", registrar_name);
  registration.m_delegationSigned = delegation_signed;
  return registration;
}

static void static_setStatuses(RdapRegistration_t* registration, const char* const* statuses, int text_count, int status_count)
{
  for (int i = 0; i < text_count; i++)
    snprintf(registration->ma_statuses[i], sizeof(registration->ma_statuses[i]), "%s", statuses[i]);
  registration->m_statusCount = status_count;
}

void test_registration_expiry_bucket_follows_the_days_left(void)
{
  static const struct {
    int64_t     m_secondsLeft;
    const char* mp_text;
  } cases[] = {
    { 31 * 86400,         "none\n2026-12-01T00:00:00Z" },
    { 30 * 86400 + 86399, "30\n2026-12-01T00:00:00Z"   },
    { 30 * 86400,         "30\n2026-12-01T00:00:00Z"   },
    { 29 * 86400,         "30\n2026-12-01T00:00:00Z"   },
    {  8 * 86400,         "30\n2026-12-01T00:00:00Z"   },
    {  7 * 86400,         "7\n2026-12-01T00:00:00Z"    },
    {  2 * 86400,         "7\n2026-12-01T00:00:00Z"    },
    {  1 * 86400,         "1\n2026-12-01T00:00:00Z"    },
    {  0,                 "1\n2026-12-01T00:00:00Z"    },
    { -1 * 86400,         "1\n2026-12-01T00:00:00Z"    },
  };
  RdapRegistration_t registration = static_registration("2026-12-01T00:00:00Z", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH - cases[c].m_secondsLeft, &value), cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, value.m_itemCount, cases[c].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, value.m_keptItemCount, cases[c].mp_text);
  }
}

void test_registration_expiry_keeps_the_date_as_given(void)
{
  static const char* const forms[] = {
    "2026-12-01",
    "2026-12-01T00:00:00Z",
    "2026-12-01T02:00:00+02:00",
    "2026-12-01T00:00:00.123Z",
  };
  for (size_t c = 0; c < sizeof(forms) / sizeof(forms[0]); c++)
  {
    RdapRegistration_t registration = static_registration(forms[c], -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH - 30 * 86400, &value), forms[c]);
    char text[128];
    snprintf(text, sizeof(text), "30\n%s", forms[c]);
    TEST_ASSERT_EQUAL_STRING(text, value.ma_text);
  }

  RdapRegistration_t registration = static_registration("2026-12-01T00:00:00Z", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH - 30 * 86400, &value));
  static_assertValue(&value, "30\n2026-12-01T00:00:00Z", 2, 2, "cdc69cb9f5bd08192ffa171000947aba0104ea05ed14c600767349cb41ec8fc7");
}

void test_registration_expiry_without_a_readable_date_has_no_value(void)
{
  static const char* const texts[] = { "", "2026-02-30", "2026-1-01", "2026-12-01 ", "never" };
  for (size_t c = 0; c < sizeof(texts) / sizeof(texts[0]); c++)
  {
    RdapRegistration_t registration = static_registration(texts[c], 292, "MarkMonitor Inc.", RDAP_DELEGATION_SIGNED_YES);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE_MESSAGE(watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH, &value), texts[c]);
    static_assertUntouched(&value);
  }
}

void test_registrar_text_follows_the_id_and_the_name(void)
{
  static const struct {
    long        m_ianaId;
    const char* mp_name;
    const char* mp_text;
  } cases[] = {
    { 292, "MarkMonitor Inc.",      "292\nMarkMonitor Inc."      },
    {  -1, "Example Registrar",     "-\nExample Registrar"       },
    { 146, "",                      "146\n"                      },
    {   0, "",                      "0\n"                        },
    {   0, "Zero",                  "0\nZero"                    },
    {  -1, "Registrar \xc3\x9cml",  "-\nRegistrar \xc3\x9cml"    },
    {  -1, "a~b",                   "-\na~b"                     },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    RdapRegistration_t registration = static_registration("", cases[c].m_ianaId, cases[c].mp_name, RDAP_DELEGATION_SIGNED_UNKNOWN);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_tryWriteRegistrar(&registration, &value), cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, value.m_itemCount, cases[c].mp_text);
  }

  RdapRegistration_t registration = static_registration("", 292, "MarkMonitor Inc.", RDAP_DELEGATION_SIGNED_UNKNOWN);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteRegistrar(&registration, &value));
  static_assertValue(&value, "292\nMarkMonitor Inc.", 2, 2, "be9d2e4be462b31f8b5c6d67a101c90dab6d712a39c9c7c2ae810463070844e9");

  registration = static_registration("", 146, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteRegistrar(&registration, &value));
  static_assertValue(&value, "146\n", 2, 2, "4c005f84cfaf4ccea894c12b193c1fba0207ffd615da6f61f1f8c130d2a0c9f1");
}

void test_registrar_without_a_writable_name_has_no_value(void)
{
  static const struct {
    long        m_ianaId;
    const char* mp_name;
  } cases[] = {
    {  -1, ""           },
    { 292, "Mark\nMon"  },
    { 292, "Mark\tMon"  },
    { 292, "Mark\x1fMon" },
    { 292, "Mark\x7fMon" },
    { 292, "Mark\xc3\x28" },
    { 292, "Mark\x80"   },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    RdapRegistration_t registration = static_registration("2026-12-01", cases[c].m_ianaId, cases[c].mp_name, RDAP_DELEGATION_SIGNED_YES);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE_MESSAGE(watchlist_whois_lookup_tryWriteRegistrar(&registration, &value), cases[c].mp_name);
    static_assertUntouched(&value);
  }
}

void test_transfer_lock_lines_follow_the_statuses(void)
{
  static const struct {
    const char* ma_statuses[4];
    int         m_count;
    const char* mp_text;
    int         m_lineCount;
  } cases[] = {
    { { "client transfer prohibited", "server transfer prohibited" }, 2, "client transfer prohibited\nserver transfer prohibited", 2 },
    { { "serverTransferProhibited", "clientTransferProhibited" },     2, "client transfer prohibited\nserver transfer prohibited", 2 },
    { { "CLIENTTRANSFERPROHIBITED", "active" },                       2, "client transfer prohibited",                             1 },
    { { "Client Transfer Prohibited" },                               1, "client transfer prohibited",                             1 },
    { { "Server Transfer Prohibited", "server transfer prohibited", "servertransferprohibited" }, 3, "server transfer prohibited", 1 },
    { { "active", "client delete prohibited", "client transfer prohibited ", "transfer prohibited" }, 4, "", 0 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    RdapRegistration_t registration = static_registration("", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
    static_setStatuses(&registration, cases[c].ma_statuses, cases[c].m_count, cases[c].m_count);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_tryWriteTransferLock(&registration, &value), cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, value.ma_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_lineCount, value.m_itemCount, cases[c].mp_text);
  }

  RdapRegistration_t registration = static_registration("", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  static const char* const both[] = { "server transfer prohibited", "client transfer prohibited" };
  static_setStatuses(&registration, both, 2, 2);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteTransferLock(&registration, &value));
  static_assertValue(&value, "client transfer prohibited\nserver transfer prohibited", 2, 2, "427cac5f0e75217731a85b91474a7748b6b927e21222aea34434adcc0762fa91");

  static const char* const unlocked[] = { "active" };
  static_setStatuses(&registration, unlocked, 1, 1);
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteTransferLock(&registration, &value));
  static_assertValue(&value, "", 0, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void test_transfer_lock_of_an_empty_or_cut_status_list_has_no_value(void)
{
  static const char* const filler[RDAP_STATUS_MAX_COUNT] = {
    "client transfer prohibited", "active", "active", "active", "active", "active", "active", "active",
    "active", "active", "active", "active", "active", "active", "active", "active",
  };
  static const int counts[] = { 0, -1, RDAP_STATUS_MAX_COUNT + 1 };
  for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++)
  {
    RdapRegistration_t registration = static_registration("", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
    static_setStatuses(&registration, filler, RDAP_STATUS_MAX_COUNT, counts[c]);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_whois_lookup_tryWriteTransferLock(&registration, &value));
    static_assertUntouched(&value);
  }

  RdapRegistration_t registration = static_registration("", -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  static_setStatuses(&registration, filler, RDAP_STATUS_MAX_COUNT, RDAP_STATUS_MAX_COUNT);
  snprintf(registration.ma_statuses[0], sizeof(registration.ma_statuses[0]), "%s", "active");
  snprintf(registration.ma_statuses[RDAP_STATUS_MAX_COUNT - 1], sizeof(registration.ma_statuses[0]), "%s", "clientTransferProhibited");
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteTransferLock(&registration, &value));
  TEST_ASSERT_EQUAL_STRING("client transfer prohibited", value.ma_text);
}

void test_dnssec_delegation_text_follows_the_answer(void)
{
  RdapRegistration_t registration = static_registration("", -1, "", RDAP_DELEGATION_SIGNED_YES);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteDnssecDelegation(&registration, &value));
  static_assertValue(&value, "signed", 1, 1, "4a3cdfae6f291c8f544daea5b72905cf9e74c1ed427d831ad0d7ca00c73c794d");

  registration.m_delegationSigned = RDAP_DELEGATION_SIGNED_NO;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteDnssecDelegation(&registration, &value));
  static_assertValue(&value, "unsigned", 1, 1, "ceffe727ab2fa2c7c3322ee4a1aa0c2d2a4664836c2133df93dd15055bb617be");

  registration.m_delegationSigned = RDAP_DELEGATION_SIGNED_UNKNOWN;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_whois_lookup_tryWriteDnssecDelegation(&registration, &value));
  static_assertUntouched(&value);
}

void test_rdap_whois_values_failed_sha256_leaves_the_value_untouched(void)
{
  static const WatchlistDomainTestDigestFault_t faults[] = {
    TEST_DIGEST_NO_CONTEXT, TEST_DIGEST_INIT_FAILS, TEST_DIGEST_UPDATE_FAILS, TEST_DIGEST_FINAL_FAILS, TEST_DIGEST_SHORT_LENGTH,
  };
  RdapRegistration_t registration = static_registration("2026-12-01", 292, "MarkMonitor Inc.", RDAP_DELEGATION_SIGNED_YES);
  static const char* const locks[] = { "client transfer prohibited" };
  static_setStatuses(&registration, locks, 1, 1);

  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    for (int call = 0; call < 4; call++)
    {
      WatchlistDomainValue_t value;
      static_fillValue(&value);
      g_digestFault = faults[i];
      bool is_written = true;
      if (call == 0)
        is_written = watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH, &value);
      else if (call == 1)
        is_written = watchlist_whois_lookup_tryWriteRegistrar(&registration, &value);
      else if (call == 2)
        is_written = watchlist_whois_lookup_tryWriteTransferLock(&registration, &value);
      else
        is_written = watchlist_whois_lookup_tryWriteDnssecDelegation(&registration, &value);
      TEST_ASSERT_FALSE(is_written);
      static_assertUntouched(&value);
      TEST_ASSERT_EQUAL_INT(TEST_DIGEST_PASS, g_digestFault);
      TEST_ASSERT_EQUAL_INT(0, g_liveContextCount);
    }
  }
}

static HeaderCheckReport_t static_headersReport(const HeaderCheckHeader_t* missing_headers, int missing_count)
{
  HeaderCheckReport_t report;
  memset(&report, 0, sizeof(report));
  for (int rule = 0; rule < HEADER_CHECK_RULE_COUNT; rule++)
  {
    report.ma_findings[rule].m_header = (HeaderCheckHeader_t)rule;
    report.ma_findings[rule].m_result = HEADER_CHECK_RESULT_PASS;
  }
  for (int i = 0; i < missing_count; i++)
    report.ma_findings[missing_headers[i]].m_result = HEADER_CHECK_RESULT_MISSING;
  return report;
}

void test_security_headers_lists_each_present_header_in_rule_order(void)
{
  static const HeaderCheckHeader_t missing[] = { HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS, HEADER_CHECK_HEADER_REFERRER_POLICY };
  HeaderCheckReport_t report = static_headersReport(missing, 2);
  report.ma_findings[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY].m_result = HEADER_CHECK_RESULT_WARN;
  report.ma_findings[HEADER_CHECK_HEADER_X_FRAME_OPTIONS].m_result           = HEADER_CHECK_RESULT_FAIL;

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders("https://www.example.com/", &report, &value));
  static_assertValue(&value, "https://www.example.com/\ncontent-security-policy\nstrict-transport-security\nx-frame-options\npermissions-policy",
                     5, 5, "c3bafc79cf9fb5446b309d4146579cec57a08d9bf2f1e0e09c73bd8e4b412dbd");
}

void test_docs_list_the_rated_headers_in_rule_order(void)
{
  HeaderCheckReport_t report = static_headersReport(NULL, 0);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders("https://example.com/", &report, &value));
  TEST_ASSERT_EQUAL_INT(7, value.m_itemCount);

  char list[512];
  size_t list_len = (size_t)snprintf(list, sizeof(list), "%s", "which of six security headers it sent: ");
  const char* name = strchr(value.ma_text, '\n');
  for (int i = 0; name != NULL; i++)
  {
    name++;
    size_t name_len = strcspn(name, "\n");
    const char* separator = (i == 0) ? "" : (name[name_len] == '\0') ? " and " : ", ";
    list_len += (size_t)snprintf(list + list_len, sizeof(list) - list_len, "%s`%.*s`", separator, (int)name_len, name);
    TEST_ASSERT_TRUE(list_len < sizeof(list));
    name = strchr(name, '\n');
  }
  snprintf(list + list_len, sizeof(list) - list_len, "%s", ". The value");

  FILE* file = fopen("docs/API_Documentation.md", "rb");
  TEST_ASSERT_NOT_NULL(file);
  static char docs[1 << 21];
  size_t read_len = fread(docs, 1, sizeof(docs) - 1, file);
  fclose(file);
  TEST_ASSERT_TRUE(read_len > 0 && read_len < sizeof(docs) - 1);
  size_t out = 0;
  for (size_t k = 0; k < read_len; k++)
  {
    bool is_space = docs[k] == ' ' || docs[k] == '\t' || docs[k] == '\r' || docs[k] == '\n';
    if (!is_space)
      docs[out++] = docs[k];
    else if (out == 0 || docs[out - 1] != ' ')
      docs[out++] = ' ';
  }
  docs[out] = '\0';
  const char* hit = strstr(docs, list);
  TEST_ASSERT_NOT_NULL_MESSAGE(hit, list);
  TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, list), list);
}

void test_security_headers_with_no_present_header_is_the_url_alone(void)
{
  static const HeaderCheckHeader_t missing[] = {
    HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY, HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY, HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS,
    HEADER_CHECK_HEADER_X_FRAME_OPTIONS,         HEADER_CHECK_HEADER_REFERRER_POLICY,           HEADER_CHECK_HEADER_PERMISSIONS_POLICY,
  };
  HeaderCheckReport_t report = static_headersReport(missing, 6);

  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders("https://example.com/", &report, &value));
  static_assertValue(&value, "https://example.com/", 1, 1, "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7");
}

void test_security_headers_without_a_visible_ascii_url_has_no_value(void)
{
  HeaderCheckReport_t report = static_headersReport(NULL, 0);
  static const char* const urls[] = {
    NULL, "", "https://example.com/\ncontent-security-policy", "https://example.com/a b", "https://example.com/\x7f", "https://example.com/\x80",
  };
  for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE(watchlist_headers_check_tryWriteSecurityHeaders(urls[i], &report, &value));
    static_assertUntouched(&value);
  }

  WatchlistDomainValue_t value;
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders("https://example.com/!~", &report, &value));
  TEST_ASSERT_EQUAL_STRING_LEN("https://example.com/!~\n", value.ma_text, strlen("https://example.com/!~\n"));
}

void test_security_headers_text_that_does_not_fit_has_no_value(void)
{
  HeaderCheckReport_t report = static_headersReport(NULL, 0);
  static char url[2048];
  static const char prefix[] = "https://example.com/";
  memset(url, 'a', sizeof(url));
  memcpy(url, prefix, sizeof(prefix) - 1);

  url[1924] = '\0';
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders(url, &report, &value));
  TEST_ASSERT_EQUAL_size_t(2048, strlen(value.ma_text));
  TEST_ASSERT_EQUAL_INT(7, value.m_itemCount);
  TEST_ASSERT_EQUAL_INT(7, value.m_keptItemCount);
  static const char six_lines[] = "\ncontent-security-policy\nstrict-transport-security\nx-content-type-options\nx-frame-options"
                                  "\nreferrer-policy\npermissions-policy";
  TEST_ASSERT_EQUAL_STRING(six_lines, value.ma_text + 2048 - (sizeof(six_lines) - 1));

  url[1924] = 'a';
  url[1925] = '\0';
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_headers_check_tryWriteSecurityHeaders(url, &report, &value));
  static_assertUntouched(&value);

  static const HeaderCheckHeader_t missing[] = {
    HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY, HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY, HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS,
    HEADER_CHECK_HEADER_X_FRAME_OPTIONS,         HEADER_CHECK_HEADER_REFERRER_POLICY,           HEADER_CHECK_HEADER_PERMISSIONS_POLICY,
  };
  HeaderCheckReport_t bare_report = static_headersReport(missing, 6);
  static char long_url[2050];
  memset(long_url, 'a', sizeof(long_url));
  memcpy(long_url, prefix, sizeof(prefix) - 1);
  long_url[2048] = '\0';
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_headers_check_tryWriteSecurityHeaders(long_url, &bare_report, &value));
  TEST_ASSERT_EQUAL_size_t(2048, strlen(value.ma_text));
  TEST_ASSERT_EQUAL_INT(1, value.m_itemCount);
  long_url[2048] = 'a';
  long_url[2049] = '\0';
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_headers_check_tryWriteSecurityHeaders(long_url, &bare_report, &value));
  static_assertUntouched(&value);
}

void test_security_headers_failed_sha256_leaves_the_value_untouched(void)
{
  static const WatchlistDomainTestDigestFault_t faults[] = {
    TEST_DIGEST_NO_CONTEXT, TEST_DIGEST_INIT_FAILS, TEST_DIGEST_UPDATE_FAILS, TEST_DIGEST_FINAL_FAILS, TEST_DIGEST_SHORT_LENGTH,
  };
  HeaderCheckReport_t report = static_headersReport(NULL, 0);
  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    g_digestFault = faults[i];
    TEST_ASSERT_FALSE(watchlist_headers_check_tryWriteSecurityHeaders("https://example.com/", &report, &value));
    static_assertUntouched(&value);
    TEST_ASSERT_EQUAL_INT(TEST_DIGEST_PASS, g_digestFault);
    TEST_ASSERT_EQUAL_INT(0, g_liveContextCount);
  }
}

void test_hosting_classes_bound_equals_the_value_max_len(void)
{
  FILE* file = fopen("sql/fn_asn_lookup.sql", "rb");
  TEST_ASSERT_NOT_NULL(file);
  static char text[65536];
  size_t read_len = fread(text, 1, sizeof(text) - 1, file);
  fclose(file);
  TEST_ASSERT_TRUE(read_len > 0 && read_len < sizeof(text) - 1);
  text[read_len] = '\0';

  char bound[64];
  snprintf(bound, sizeof(bound), "octet_length(joined.hosting_classes) <= %d", WATCHLIST_DOMAIN_VALUE_MAX_LEN);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(text, bound), bound);
}

void test_registration_expiry_keeps_a_date_of_the_max_length(void)
{
  char date[RDAP_DATE_MAX_LEN + 1];
  memset(date, '0', sizeof(date));
  memcpy(date, "2026-12-01T00:00:00.", 20);
  date[RDAP_DATE_MAX_LEN - 1] = 'Z';
  date[RDAP_DATE_MAX_LEN]     = '\0';
  RdapRegistration_t registration = static_registration(date, -1, "", RDAP_DELEGATION_SIGNED_UNKNOWN);
  TEST_ASSERT_EQUAL_size_t(RDAP_DATE_MAX_LEN, strlen(registration.ma_expiresAt));
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_tryWriteRegistrationExpiry(&registration, TEST_EXPIRY_EPOCH - 30 * 86400, &value));
  char text[128];
  snprintf(text, sizeof(text), "30\n%s", date);
  TEST_ASSERT_EQUAL_STRING(text, value.ma_text);
}

static CertSpotterCertificateList_t g_issuerList;

static void static_resetIssuers(void)
{
  memset(&g_issuerList, 0, sizeof(g_issuerList));
  g_issuerList.m_isComplete = true;
}

static void static_addIssuer(const char* key, const char* const* caa_domains, int caa_domain_count, bool is_exact, bool is_wildcard)
{
  TEST_ASSERT_TRUE(g_issuerList.m_issuerCount < CERTSPOTTER_ISSUER_MAX_COUNT);
  CertSpotterIssuer_t* issuer = &g_issuerList.ma_issuers[g_issuerList.m_issuerCount++];
  snprintf(issuer->ma_key, sizeof(issuer->ma_key), "%s", key);
  issuer->m_isCaaDomainListKnown = caa_domains != NULL;
  for (int i = 0; caa_domains != NULL && i < caa_domain_count; i++)
    snprintf(issuer->ma_caaDomains[i], sizeof(issuer->ma_caaDomains[i]), "%s", caa_domains[i]);
  issuer->m_caaDomainCount       = caa_domains != NULL ? caa_domain_count : 0;
  issuer->m_isSeenOnExactName    = is_exact;
  issuer->m_isSeenOnWildcardName = is_wildcard;
}

static const char* const LETSENCRYPT_DOMAINS[] = { "letsencrypt.org" };
static const char* const PKI_GOOG_DOMAINS[]    = { "pki.goog" };
static const char* const DIGICERT_DOMAINS[]    = { "digicert.com", "symantec.com" };

static DnsCaaRecord_t static_caa(uint8_t flags, const char* tag, const char* value)
{
  DnsCaaRecord_t record;
  record.m_flags              = flags;
  record.m_tag.mp_bytes       = (char*)tag;
  record.m_tag.m_byteCount    = strlen(tag);
  record.m_value.mp_bytes     = (char*)value;
  record.m_value.m_byteCount  = strlen(value);
  return record;
}

static DnsAnswer_t static_caaSet(DnsCaaRecord_t* records, int record_count)
{
  DnsAnswer_t answer;
  memset(&answer, 0, sizeof(answer));
  answer.m_status        = DNS_ANSWER_OK;
  answer.m_recordCount   = record_count;
  answer.mp_caaRecords   = records;
  return answer;
}

static void static_writeIssuers(const DnsAnswer_t* caa_set, const char* text)
{
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE_MESSAGE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, caa_set, caa_set, &value), text);
  TEST_ASSERT_EQUAL_STRING(text, value.ma_text);
  int line_count = (text[0] != '\0') ? 1 : 0;
  for (const char* c = text; *c != '\0'; c++)
    line_count += (*c == '\n');
  TEST_ASSERT_EQUAL_INT_MESSAGE(line_count, value.m_itemCount, text);
  TEST_ASSERT_EQUAL_INT_MESSAGE(line_count, value.m_keptItemCount, text);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(WATCHLIST_DOMAIN_SHA256_HEX_LEN, strlen(value.ma_sha256Hex), text);
}

void test_cert_issuers_without_caa_lists_each_issuer_as_new_in_key_order(void)
{
  static_resetIssuers();
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, true, false);
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  static_addIssuer("Some CA", NULL, 0, false, true);

  static_writeIssuers(NULL, "new_issuer Some CA\nnew_issuer letsencrypt.org\nnew_issuer pki.goog");
  DnsAnswer_t empty = static_caaSet(NULL, 0);
  static_writeIssuers(&empty, "new_issuer Some CA\nnew_issuer letsencrypt.org\nnew_issuer pki.goog");
}

void test_cert_issuers_issue_tag_decides_an_exact_issuer(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, true, false);
  static_addIssuer("digicert.com,symantec.com", DIGICERT_DOMAINS, 2, false, false);
  DnsCaaRecord_t records[] = { static_caa(0, "issue", "letsencrypt.org") };
  DnsAnswer_t caa_set = static_caaSet(records, 1);

  static_writeIssuers(&caa_set, "caa_mismatch digicert.com,symantec.com\nnew_issuer letsencrypt.org\ncaa_mismatch pki.goog");
}

void test_cert_issuers_tag_value_parameters_space_and_case(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  static_addIssuer("digicert.com,symantec.com", DIGICERT_DOMAINS, 2, true, false);
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, true, false);
  DnsCaaRecord_t records[] = {
    static_caa(0, "issue", " LetsEncrypt.org ; validationmethods=dns-01"),
    static_caa(0, "ISSUE", "symantec.com;"),
    static_caa(0, "issue", "\tpki.goog\t;\taccounturi=x"),
  };
  DnsAnswer_t caa_set = static_caaSet(records, 3);

  static_writeIssuers(&caa_set, "new_issuer digicert.com,symantec.com\nnew_issuer letsencrypt.org\nnew_issuer pki.goog");
}

void test_cert_issuers_tag_domain_must_match_whole(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, true, false);
  DnsCaaRecord_t records[] = {
    static_caa(0, "issue", "letsencrypt.org.evil"), static_caa(0, "issue", "letsencrypt"), static_caa(0, "issue", "sub.pki.goog"),
  };
  DnsAnswer_t caa_set = static_caaSet(records, 3);

  static_writeIssuers(&caa_set, "caa_mismatch letsencrypt.org\ncaa_mismatch pki.goog");
}

void test_cert_issuers_empty_issue_value_permits_no_issuer(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  DnsCaaRecord_t semicolon[] = { static_caa(0, "issue", ";") };
  DnsAnswer_t semicolon_set = static_caaSet(semicolon, 1);
  static_writeIssuers(&semicolon_set, "caa_mismatch letsencrypt.org");
  DnsCaaRecord_t empty[] = { static_caa(0, "issue", "") };
  DnsAnswer_t empty_set = static_caaSet(empty, 1);
  static_writeIssuers(&empty_set, "caa_mismatch letsencrypt.org");
}

void test_cert_issuers_wildcard_issuer_reads_issuewild_then_issue(void)
{
  DnsCaaRecord_t set_a[] = { static_caa(0, "issue", "pki.goog"), static_caa(0, "issuewild", "letsencrypt.org") };
  DnsAnswer_t caa_a = static_caaSet(set_a, 2);
  DnsCaaRecord_t set_b[] = { static_caa(0, "issue", "pki.goog") };
  DnsAnswer_t caa_b = static_caaSet(set_b, 1);

  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, false, true);
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, false, true);
  static_writeIssuers(&caa_a, "new_issuer letsencrypt.org\ncaa_mismatch pki.goog");
  static_writeIssuers(&caa_b, "caa_mismatch letsencrypt.org\nnew_issuer pki.goog");

  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, true);
  static_writeIssuers(&caa_a, "caa_mismatch letsencrypt.org");
}

void test_cert_issuers_wildcard_issuer_reads_the_set_of_the_parent(void)
{
  DnsCaaRecord_t host_records[]   = { static_caa(0, "issue", "pki.goog") };
  DnsCaaRecord_t parent_records[] = { static_caa(0, "issue", "letsencrypt.org") };
  DnsAnswer_t host_set   = static_caaSet(host_records, 1);
  DnsAnswer_t parent_set = static_caaSet(parent_records, 1);
  static const struct {
    bool        m_isExact;
    bool        m_isWildcard;
    const char* mp_text;
  } cases[] = {
    { false, true,  "new_issuer letsencrypt.org\ncaa_mismatch pki.goog" },
    { true,  false, "caa_mismatch letsencrypt.org\nnew_issuer pki.goog" },
    { true,  true,  "caa_mismatch letsencrypt.org\ncaa_mismatch pki.goog" },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    static_resetIssuers();
    static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, cases[c].m_isExact, cases[c].m_isWildcard);
    static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, cases[c].m_isExact, cases[c].m_isWildcard);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_TRUE_MESSAGE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, &host_set, &parent_set, &value), cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, value.ma_text);
  }
}

void test_cert_issuers_needed_sets_follow_the_flags(void)
{
  static const struct {
    bool m_isExact;
    bool m_isWildcard;
    bool m_isHostSetNeeded;
    bool m_isWildcardSetNeeded;
  } cases[] = {
    { false, false, true,  false },
    { true,  false, true,  false },
    { false, true,  false, true  },
    { true,  true,  true,  true  },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    CertSpotterIssuer_t issuer = { .m_isSeenOnExactName = cases[c].m_isExact, .m_isSeenOnWildcardName = cases[c].m_isWildcard };
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_isHostSetNeeded, watchlist_cert_search_isHostCaaSetNeeded(&issuer), message);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_isWildcardSetNeeded, watchlist_cert_search_isWildcardCaaSetNeeded(&issuer), message);
  }
}

void test_cert_issuers_issuewild_alone_leaves_the_exact_name_open(void)
{
  DnsCaaRecord_t records[] = { static_caa(0, "issuewild", ";") };
  DnsAnswer_t caa_set = static_caaSet(records, 1);
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  static_writeIssuers(&caa_set, "new_issuer letsencrypt.org");
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, false, true);
  static_writeIssuers(&caa_set, "caa_mismatch letsencrypt.org");
}

void test_cert_issuers_critical_unknown_tag_permits_no_issuer(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  DnsCaaRecord_t critical[] = { static_caa(0, "issue", "letsencrypt.org"), static_caa(128, "futuretag", "x") };
  DnsAnswer_t critical_set = static_caaSet(critical, 2);
  static_writeIssuers(&critical_set, "caa_mismatch letsencrypt.org");
  DnsCaaRecord_t plain[] = { static_caa(0, "issue", "letsencrypt.org"), static_caa(1, "futuretag", "x") };
  DnsAnswer_t plain_set = static_caaSet(plain, 2);
  static_writeIssuers(&plain_set, "new_issuer letsencrypt.org");
  static const char* const known_tags[] = { "issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone", "IODEF" };
  for (size_t t = 0; t < sizeof(known_tags) / sizeof(known_tags[0]); t++)
  {
    DnsCaaRecord_t known[] = { static_caa(0, "issue", "letsencrypt.org"), static_caa(128, known_tags[t], "mailto:x@example.com") };
    DnsAnswer_t known_set = static_caaSet(known, 2);
    static_writeIssuers(&known_set, "new_issuer letsencrypt.org");
  }
}

void test_cert_issuers_issuer_without_caa_domains_matches_no_tag(void)
{
  static_resetIssuers();
  static_addIssuer("Some CA", NULL, 0, true, false);
  DnsCaaRecord_t iodef[] = { static_caa(0, "iodef", "mailto:x@example.com") };
  DnsAnswer_t iodef_set = static_caaSet(iodef, 1);
  static_writeIssuers(&iodef_set, "new_issuer Some CA");
  DnsCaaRecord_t issue[] = { static_caa(0, "issue", "letsencrypt.org") };
  DnsAnswer_t issue_set = static_caaSet(issue, 1);
  static_writeIssuers(&issue_set, "caa_mismatch Some CA");
}

void test_cert_issuers_record_past_the_count_permits_no_issuer(void)
{
  static_resetIssuers();
  static_addIssuer("pki.goog", PKI_GOOG_DOMAINS, 1, true, false);
  DnsCaaRecord_t records[] = { static_caa(0, "issue", "letsencrypt.org"), static_caa(0, "issue", "pki.goog") };
  DnsAnswer_t caa_set = static_caaSet(records, 1);
  static_writeIssuers(&caa_set, "caa_mismatch pki.goog");
}

void test_cert_issuers_tag_past_the_count_is_not_in_the_set(void)
{
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  DnsCaaRecord_t records[] = { static_caa(0, "issuewild", "pki.goog"), static_caa(0, "issue", "pki.goog") };
  DnsAnswer_t caa_set = static_caaSet(records, 1);
  static_writeIssuers(&caa_set, "new_issuer letsencrypt.org");
}

void test_cert_issuers_incomplete_or_dropped_list_gives_no_value(void)
{
  WatchlistDomainValue_t value;
  static_resetIssuers();
  static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
  g_issuerList.m_isComplete = false;
  static_fillValue(&value);
  TEST_ASSERT_FALSE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, NULL, NULL, &value));
  static_assertUntouched(&value);

  g_issuerList.m_isComplete      = true;
  g_issuerList.m_isIssuerDropped = true;
  TEST_ASSERT_FALSE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, NULL, NULL, &value));
  static_assertUntouched(&value);
}

void test_cert_issuers_key_outside_printable_ascii_or_all_spaces_gives_no_value(void)
{
  static_resetIssuers();
  static_addIssuer(" ~CA~", NULL, 0, true, false);
  static_writeIssuers(NULL, "new_issuer  ~CA~");

  static const char* const keys[] = { "Bad\nCA", "Bad\tCA", "Bad\x1f" "CA", "Bad\x7f" "CA", "Bad\x80" "CA", "", " ", "   " };
  for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
  {
    static_resetIssuers();
    static_addIssuer("letsencrypt.org", LETSENCRYPT_DOMAINS, 1, true, false);
    static_addIssuer(keys[k], NULL, 0, true, false);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    TEST_ASSERT_FALSE_MESSAGE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, NULL, NULL, &value), keys[k]);
    static_assertUntouched(&value);
  }
}

void test_cert_issuers_longest_key_on_caa_mismatch_is_whole(void)
{
  char long_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN + 1];
  memset(long_key, 'a', CERTSPOTTER_ISSUER_KEY_MAX_LEN);
  long_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN] = '\0';
  long_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN - 1] = 'z';
  static_resetIssuers();
  static_addIssuer(long_key, NULL, 0, true, false);
  DnsCaaRecord_t records[] = { static_caa(0, "issue", "letsencrypt.org") };
  DnsAnswer_t    host_set  = static_caaSet(records, 1);
  WatchlistDomainValue_t value;
  static_fillValue(&value);
  TEST_ASSERT_TRUE(watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, &host_set, NULL, &value));
  char expected[sizeof("caa_mismatch ") + CERTSPOTTER_ISSUER_KEY_MAX_LEN];
  snprintf(expected, sizeof(expected), "caa_mismatch %s", long_key);
  TEST_ASSERT_EQUAL_STRING(expected, value.ma_text);
}

void test_cert_issuers_text_past_the_limit_gives_no_value(void)
{
  char long_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN + 1];
  memset(long_key, 'a', CERTSPOTTER_ISSUER_KEY_MAX_LEN);
  long_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN] = '\0';
  char other_key[1004];

  for (int other_len = 1002; other_len <= 1003; other_len++)
  {
    memset(other_key, 'b', (size_t)other_len);
    other_key[other_len] = '\0';
    static_resetIssuers();
    static_addIssuer(long_key, NULL, 0, true, false);
    static_addIssuer(other_key, NULL, 0, true, false);
    WatchlistDomainValue_t value;
    static_fillValue(&value);
    bool is_written = watchlist_cert_search_tryWriteCertIssuers(&g_issuerList, NULL, NULL, &value);
    if (other_len == 1002)
    {
      TEST_ASSERT_TRUE(is_written);
      TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_VALUE_MAX_LEN, strlen(value.ma_text));
    }
    else
    {
      TEST_ASSERT_FALSE(is_written);
      static_assertUntouched(&value);
    }
  }
}

void test_cert_issuers_empty_set_is_an_empty_value(void)
{
  static_resetIssuers();
  static_writeIssuers(NULL, "");
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(88, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_constants_hold_their_values);
  RUN_TEST(test_dns_presence_all_nxdomain_is_not_found);
  RUN_TEST(test_dns_presence_one_ok_answer_is_found);
  RUN_TEST(test_dns_presence_not_public_name_answer_is_found);
  RUN_TEST(test_dns_presence_error_without_ok_answer_has_no_value);
  RUN_TEST(test_ns_names_are_lowercase_sorted_unique_without_trailing_dot);
  RUN_TEST(test_ns_names_sha256_is_taken_of_the_text);
  RUN_TEST(test_ns_names_sort_in_strcmp_byte_order_of_lowercase_names);
  RUN_TEST(test_ns_names_keep_a_repeated_name_once);
  RUN_TEST(test_ns_names_nxdomain_and_empty_ok_are_the_empty_text);
  RUN_TEST(test_ns_names_other_status_has_no_value);
  RUN_TEST(test_ns_names_record_count_at_and_past_the_cap);
  RUN_TEST(test_ns_names_text_one_below_and_at_the_cap_is_whole);
  RUN_TEST(test_ns_names_text_past_the_cap_keeps_whole_lines);
  RUN_TEST(test_ns_names_line_past_the_cap_still_changes_the_sha256);
  RUN_TEST(test_ns_names_keep_no_line_after_a_dropped_line);
  RUN_TEST(test_ns_names_root_name_is_one_empty_line);
  RUN_TEST(test_mx_records_lines_hold_priority_and_lowercase_host);
  RUN_TEST(test_mx_records_priority_is_part_of_the_line);
  RUN_TEST(test_mx_records_null_mx_is_a_null_line);
  RUN_TEST(test_mx_records_nxdomain_and_empty_ok_are_the_empty_text);
  RUN_TEST(test_mx_records_other_status_has_no_value);
  RUN_TEST(test_mx_records_record_count_at_and_past_the_cap);
  RUN_TEST(test_mx_records_text_past_the_cap_keeps_whole_lines);
  RUN_TEST(test_ip_address_reachability_text_follows_the_addresses);
  RUN_TEST(test_ip_address_reachability_not_public_name_on_either_side_is_not_public);
  RUN_TEST(test_ip_address_reachability_error_on_either_side_has_no_value);
  RUN_TEST(test_hosting_ip_addresses_join_a_then_aaaa_in_answer_order);
  RUN_TEST(test_hosting_ip_addresses_ok_and_nxdomain_answers_are_read);
  RUN_TEST(test_hosting_ip_addresses_other_status_on_either_side_writes_nothing);
  RUN_TEST(test_hosting_ip_addresses_without_an_address_write_nothing);
  RUN_TEST(test_hosting_ip_addresses_not_public_address_on_either_side_writes_nothing);
  RUN_TEST(test_hosting_ip_addresses_fit_with_their_nul);
  RUN_TEST(test_cname_takeover_lookup_status_other_than_ok_has_no_value);
  RUN_TEST(test_cname_takeover_text_follows_the_record);
  RUN_TEST(test_cname_takeover_text_at_and_past_the_cap);
  RUN_TEST(test_email_check_results_without_checks_are_all_dashes);
  RUN_TEST(test_email_check_results_put_each_result_at_its_kind);
  RUN_TEST(test_dns_values_failed_sha256_leaves_the_value_untouched);
  RUN_TEST(test_dns_values_failed_sha256_of_the_empty_text_has_no_value);
  RUN_TEST(test_written_value_leaves_no_sha256_context_open);
  RUN_TEST(test_certificate_expiry_bucket_follows_the_days_left);
  RUN_TEST(test_certificate_expiry_sha256_is_taken_of_the_text);
  RUN_TEST(test_certificate_expiry_without_its_end_has_no_value);
  RUN_TEST(test_certificate_validity_without_a_problem_is_valid);
  RUN_TEST(test_certificate_validity_each_problem_has_its_name);
  RUN_TEST(test_certificate_validity_names_keep_the_order_of_their_bits);
  RUN_TEST(test_certificate_listing_text_follows_the_list);
  RUN_TEST(test_certificate_listing_of_a_list_not_read_or_not_loaded_has_no_value);
  RUN_TEST(test_tls_protocol_text_is_the_protocol_name);
  RUN_TEST(test_tls_protocol_without_a_name_has_no_value);
  RUN_TEST(test_tls_values_failed_sha256_leaves_the_value_untouched);
  RUN_TEST(test_registration_expiry_bucket_follows_the_days_left);
  RUN_TEST(test_registration_expiry_keeps_the_date_as_given);
  RUN_TEST(test_registration_expiry_keeps_a_date_of_the_max_length);
  RUN_TEST(test_registration_expiry_without_a_readable_date_has_no_value);
  RUN_TEST(test_registrar_text_follows_the_id_and_the_name);
  RUN_TEST(test_registrar_without_a_writable_name_has_no_value);
  RUN_TEST(test_transfer_lock_lines_follow_the_statuses);
  RUN_TEST(test_transfer_lock_of_an_empty_or_cut_status_list_has_no_value);
  RUN_TEST(test_dnssec_delegation_text_follows_the_answer);
  RUN_TEST(test_rdap_whois_values_failed_sha256_leaves_the_value_untouched);
  RUN_TEST(test_security_headers_lists_each_present_header_in_rule_order);
  RUN_TEST(test_docs_list_the_rated_headers_in_rule_order);
  RUN_TEST(test_security_headers_with_no_present_header_is_the_url_alone);
  RUN_TEST(test_security_headers_without_a_visible_ascii_url_has_no_value);
  RUN_TEST(test_security_headers_text_that_does_not_fit_has_no_value);
  RUN_TEST(test_security_headers_failed_sha256_leaves_the_value_untouched);
  RUN_TEST(test_hosting_classes_bound_equals_the_value_max_len);
  RUN_TEST(test_cert_issuers_without_caa_lists_each_issuer_as_new_in_key_order);
  RUN_TEST(test_cert_issuers_issue_tag_decides_an_exact_issuer);
  RUN_TEST(test_cert_issuers_tag_value_parameters_space_and_case);
  RUN_TEST(test_cert_issuers_tag_domain_must_match_whole);
  RUN_TEST(test_cert_issuers_empty_issue_value_permits_no_issuer);
  RUN_TEST(test_cert_issuers_wildcard_issuer_reads_issuewild_then_issue);
  RUN_TEST(test_cert_issuers_wildcard_issuer_reads_the_set_of_the_parent);
  RUN_TEST(test_cert_issuers_needed_sets_follow_the_flags);
  RUN_TEST(test_cert_issuers_issuewild_alone_leaves_the_exact_name_open);
  RUN_TEST(test_cert_issuers_critical_unknown_tag_permits_no_issuer);
  RUN_TEST(test_cert_issuers_issuer_without_caa_domains_matches_no_tag);
  RUN_TEST(test_cert_issuers_record_past_the_count_permits_no_issuer);
  RUN_TEST(test_cert_issuers_tag_past_the_count_is_not_in_the_set);
  RUN_TEST(test_cert_issuers_incomplete_or_dropped_list_gives_no_value);
  RUN_TEST(test_cert_issuers_key_outside_printable_ascii_or_all_spaces_gives_no_value);
  RUN_TEST(test_cert_issuers_text_past_the_limit_gives_no_value);
  RUN_TEST(test_cert_issuers_longest_key_on_caa_mismatch_is_whole);
  RUN_TEST(test_cert_issuers_empty_set_is_an_empty_value);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
