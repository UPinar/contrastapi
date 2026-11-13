#include <string.h>

#include <openssl/rand.h>

#include "unity/unity.h"
#include "auth.h"
#include "request_text.h"
#include "validate.h"

#define KEY_PREFIX  "contrastapi_"
#define HEX47       "00000000000000000000000000000000000000000000000"
#define HEX48       "000000000000000000000000000000000000000000000000"
#define NON_HEX48   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
#define UPPER_HEX48 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define HEX49       "0000000000000000000000000000000000000000000000000"

_Static_assert(sizeof(HEX47)       - 1 == 47, "HEX47");
_Static_assert(sizeof(HEX48)       - 1 == 48, "HEX48");
_Static_assert(sizeof(NON_HEX48)   - 1 == 48, "NON_HEX48");
_Static_assert(sizeof(UPPER_HEX48) - 1 == 48, "UPPER_HEX48");
_Static_assert(sizeof(HEX49)       - 1 == 49, "HEX49");

#define HEX48_CRC       "0fa16679"
#define NON_HEX48_CRC   "4a1a9e4e"
#define UPPER_HEX48_CRC "09f6b21e"

#define VALID_KEY KEY_PREFIX HEX48 HEX48_CRC
_Static_assert(sizeof(VALID_KEY) - 1 == API_KEY_TOTAL_LEN, "VALID_KEY");

static AuthApiKeyParseResult_t static_parseApiKey(const char* text)
{
  ReceiveResult_t request;
  TEST_ASSERT_TRUE_MESSAGE(requestText_parse(text, &request), text);
  return auth_parseApiKey(request.ma_headers, request.m_headerCount);
}

#define VALID_KEY_HASH "fc6730db4f395fa509b7c72abd9c49b8ddd4691da46e5ae5a070033bf09eb5fe"

#define TEST_IP        "127.0.0.1"
#define TEST_IP_SECRET "contrast_ip_secret"
#define IP_SHA256      "12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0"
#define IP_HMAC_SHA256 "51444d1b74dbe3e87f76152c0119c34ca708ca995dfc49e0d5f376be9ae6fbd6"

typedef enum {
  AUTH_TEST_RAND_REAL,
  AUTH_TEST_RAND_SCRIPT,
  AUTH_TEST_RAND_FAIL,
} AuthTestRandMode_t;

static AuthTestRandMode_t g_randMode         = AUTH_TEST_RAND_REAL;
static unsigned char      g_randScript[24];
static int                g_randFailResult   = 0;
static int                g_randCallCount    = 0;
static int                g_randLastNum      = -1;

int __real_RAND_bytes(unsigned char* buf, int num);

int __wrap_RAND_bytes(unsigned char* buf, int num)
{
  g_randCallCount++;
  g_randLastNum = num;
  if (g_randMode == AUTH_TEST_RAND_REAL)
    return __real_RAND_bytes(buf, num);
  for (int i = 0; i < num; i++)
    buf[i] = (g_randMode == AUTH_TEST_RAND_SCRIPT && i < (int)sizeof(g_randScript)) ? g_randScript[i] : 0x5a;
  return g_randMode == AUTH_TEST_RAND_SCRIPT ? 1 : g_randFailResult;
}

void setUp(void)
{
  g_randMode       = AUTH_TEST_RAND_REAL;
  g_randFailResult = 0;
  g_randCallCount  = 0;
  g_randLastNum    = -1;
  memset(g_randScript, 0, sizeof(g_randScript));
}

void tearDown(void) {}

#define AUTH_TEST_KEY_BUF_SIZE (API_KEY_TOTAL_LEN + 1 + 8)

#define GEN_COUNTING_KEY "contrastapi_000102030405060708090a0b0c0d0e0f101112131415161770640eef"
#define GEN_ONES_KEY     "contrastapi_ffffffffffffffffffffffffffffffffffffffffffffffff21b7a791"

static void static_assertGeneratedKey(const unsigned char* script, const char* expected)
{
  char key[AUTH_TEST_KEY_BUF_SIZE];
  memset(key, 0xA5, sizeof(key));
  memcpy(g_randScript, script, sizeof(g_randScript));
  g_randMode = AUTH_TEST_RAND_SCRIPT;

  TEST_ASSERT_TRUE(auth_tryGenerateApiKey(key));

  TEST_ASSERT_EQUAL_STRING(expected, key);
  TEST_ASSERT_EQUAL_INT(1, g_randCallCount);
  TEST_ASSERT_EQUAL_INT(24, g_randLastNum);
  for (size_t i = API_KEY_TOTAL_LEN + 1; i < sizeof(key); i++)
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xA5, (unsigned char)key[i], "a byte after the key was written");
}

#define HEX48_ONES "111111111111111111111111111111111111111111111111"
_Static_assert(sizeof(HEX48_ONES) - 1 == 48, "HEX48_ONES");
#define HEX48_ONES_CRC "7c335323"
#define OTHER_KEY KEY_PREFIX HEX48_ONES HEX48_ONES_CRC

#define IP6_BUCKET_SHA256      "b22e912162f83195c2043c77ed6a9509b5d6eba568c75abff1d2e30a3beeb7d0"
#define IP6_BUCKET_HMAC_SHA256 "fd7ed035457e257fa7485b0682fc10530facb5accf93a5d4ba879e99b7103fa0"
#define NOT_AN_IP_SHA256       "e50f7840fcd02669893cddaf76a8d16e2908150aedda106664e92ec2422f56eb"
#define FULL_WIDTH_64_SHA256   "015bf05f4fedc09d5aec125f2d3b08905b2b09361f867842eeb921117f35278a"

void test_no_header(void)
{
  const char* req = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_header_whose_name_extends_a_key_header_is_not_read(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorizationx: Bearer " VALID_KEY "\r\n"
  "X-API-Keys: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_header_whose_name_is_a_prefix_of_a_key_header_is_not_read(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorizatio: Bearer " VALID_KEY "\r\n"
  "X-API-Ke: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_lowercase_authorization_header_recognized(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "authorization: Bearer " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_authorization_without_space_after_colon_recognized(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorization:Bearer " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_lowercase_x_api_key_header_recognized(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "x-api-key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_header_lookalike_in_body_is_ignored(void)
{
  const char* req =
    "POST /mcp HTTP/1.1\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    "X-API-Key: " VALID_KEY "\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_key_followed_by_space_is_malformed(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "X-API-Key: " VALID_KEY " trailing\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_with_empty_key_falls_through_to_x_api_key(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorization: Bearer \r\n"
  "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_bearer_key_trailing_ows_is_trimmed_valid(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorization: Bearer " VALID_KEY "  \r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_folded_authorization_classifies_first_fragment_only(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorization: Bearer contrastapi_0123\r\n"
  " 456789abcdef\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_too_short(void)
{
  const char* req =
  "GET /health HTTP/1.1\r\n"
  "Authorization: Bearer " KEY_PREFIX HEX47 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_too_long(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX HEX49 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_non_hex(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX NON_HEX48 NON_HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_uppercase_hex_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX UPPER_HEX48 UPPER_HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_wrong_prefix(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer sk_" HEX48 "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_wrong_prefix_bearer_falls_through_to_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer sk_" HEX48 "\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_non_bearer_authorization_falls_through_to_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Basic dXNlcjpwYXNz\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_malformed_bearer_falls_through_to_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX HEX47 HEX48_CRC "\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_uppercase_hex_bearer_falls_through_to_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX UPPER_HEX48 UPPER_HEX48_CRC "\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_valid_bearer_wins_over_valid_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " VALID_KEY "\r\n"
    "X-API-Key: " OTHER_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_first_x_api_key_header_wins(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " VALID_KEY "\r\n"
    "X-API-Key: " OTHER_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_first_authorization_header_wins(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " VALID_KEY "\r\n"
    "Authorization: Bearer " OTHER_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_valid_bearer_wins_over_malformed_x_api_key(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " VALID_KEY "\r\n"
    "X-API-Key: " KEY_PREFIX HEX47 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_malformed_bearer_and_malformed_x_api_key_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX HEX47 HEX48_CRC "\r\n"
    "X-API-Key: " KEY_PREFIX HEX49 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_non_bearer_authorization_with_malformed_x_api_key_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Basic dXNlcjpwYXNz\r\n"
    "X-API-Key: " KEY_PREFIX HEX47 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_valid(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_x_api_key_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " KEY_PREFIX HEX47 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_x_api_key_too_long(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " KEY_PREFIX HEX49 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_x_api_key_uppercase_hex_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " KEY_PREFIX UPPER_HEX48 UPPER_HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_x_api_key_wrong_prefix(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: sk_" HEX48 "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_x_api_key_valid(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_hash_known_output(void)
{
  char hex[SHA256_HEX_LEN + 1];
  auth_hashApiKey(VALID_KEY, hex);
  TEST_ASSERT_EQUAL_INT(SHA256_HEX_LEN, (int)strlen(hex));
  TEST_ASSERT_EQUAL_STRING(VALID_KEY_HASH, hex);
}

void test_hash_ip_null_secret_falls_back_to_sha256(void)
{
  char hex[SHA256_HEX_LEN + 1];
  auth_hashIp(TEST_IP, NULL, hex);
  TEST_ASSERT_EQUAL_INT(SHA256_HEX_LEN, (int)strlen(hex));
  TEST_ASSERT_EQUAL_STRING(IP_SHA256, hex);
}

void test_hash_ip_with_secret_uses_hmac(void)
{
  char hex[SHA256_HEX_LEN + 1];
  auth_hashIp(TEST_IP, TEST_IP_SECRET, hex);
  TEST_ASSERT_EQUAL_INT(SHA256_HEX_LEN, (int)strlen(hex));
  TEST_ASSERT_EQUAL_STRING(IP_HMAC_SHA256, hex);
}

void test_hash_ip_same_ipv6_64_shares_bucket(void)
{
  char first[SHA256_HEX_LEN + 1], second[SHA256_HEX_LEN + 1];
  auth_hashIp("2001:db8:1:2::1",      NULL, first);
  auth_hashIp("2001:db8:1:2:ffff::9", NULL, second);
  TEST_ASSERT_EQUAL_STRING(first, second);

  auth_hashIp("2001:db8:1:2::1",      TEST_IP_SECRET, first);
  auth_hashIp("2001:db8:1:2:ffff::9", TEST_IP_SECRET, second);
  TEST_ASSERT_EQUAL_STRING(first, second);
}

void test_hash_ip_next_ipv6_64_gets_own_bucket(void)
{
  char first[SHA256_HEX_LEN + 1], second[SHA256_HEX_LEN + 1];
  auth_hashIp("2001:db8:1:2::1", TEST_IP_SECRET, first);
  auth_hashIp("2001:db8:1:3::1", TEST_IP_SECRET, second);
  TEST_ASSERT_FALSE(strcmp(first, second) == 0);
}

void test_hash_ip_v4_mapped_ipv6_is_its_ipv4(void)
{
  char mapped[SHA256_HEX_LEN + 1], plain[SHA256_HEX_LEN + 1];
  auth_hashIp("::ffff:8.8.8.8", TEST_IP_SECRET, mapped);
  auth_hashIp("8.8.8.8",        TEST_IP_SECRET, plain);
  TEST_ASSERT_EQUAL_STRING(plain, mapped);
}

void test_hash_ip_ipv4_is_not_masked(void)
{
  char first[SHA256_HEX_LEN + 1], second[SHA256_HEX_LEN + 1];
  auth_hashIp("192.0.2.1", TEST_IP_SECRET, first);
  auth_hashIp("192.0.2.2", TEST_IP_SECRET, second);
  TEST_ASSERT_FALSE(strcmp(first, second) == 0);
}

void test_hash_ip_ipv6_bucket_known_answer(void)
{
  char hex[SHA256_HEX_LEN + 1];
  auth_hashIp("2001:db8::abcd", NULL, hex);
  TEST_ASSERT_EQUAL_STRING(IP6_BUCKET_SHA256, hex);

  auth_hashIp("2001:0db8:0000:0000:0000:0000:0000:0001", NULL, hex);
  TEST_ASSERT_EQUAL_STRING(IP6_BUCKET_SHA256, hex);

  auth_hashIp("2001:db8::abcd", TEST_IP_SECRET, hex);
  TEST_ASSERT_EQUAL_STRING(IP6_BUCKET_HMAC_SHA256, hex);
}

void test_hash_ip_unparseable_hashes_raw_text(void)
{
  char hex[SHA256_HEX_LEN + 1];
  auth_hashIp("not-an-address", NULL, hex);
  TEST_ASSERT_EQUAL_STRING(NOT_AN_IP_SHA256, hex);
}

void test_hash_ip_full_width_ipv6_64_known_answer(void)
{
  char first[SHA256_HEX_LEN + 1], second[SHA256_HEX_LEN + 1];
  auth_hashIp("ffff:ffff:ffff:ffff::1",                  NULL, first);
  auth_hashIp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", NULL, second);
  TEST_ASSERT_EQUAL_STRING(FULL_WIDTH_64_SHA256, first);
  TEST_ASSERT_EQUAL_STRING(first, second);
}

void test_bearer_scheme_lowercase_valid(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: bearer " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_bearer_scheme_uppercase_valid(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: BEARER " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_bearer_scheme_mixed_case_valid(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: BeArEr " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(VALID_KEY, r.ma_apiKey);
}

void test_bearer_scheme_lowercase_malformed_key_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: bearer " KEY_PREFIX HEX47 HEX48_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_bearer_scheme_lowercase_wrong_prefix_is_none(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: bearer sk_" HEX48 "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_bearer_scheme_tab_separator_is_none(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer\t" VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_bearer_scheme_double_space_is_none(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer  " VALID_KEY "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_bearer_checksum_of_another_body_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " KEY_PREFIX HEX48 HEX48_ONES_CRC "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_x_api_key_checksum_with_one_character_changed_is_malformed(void)
{
  static const char* const reqs[] = {
    "GET /health HTTP/1.1\r\nX-API-Key: " KEY_PREFIX HEX48 "1fa16679" "\r\n\r\n",
    "GET /health HTTP/1.1\r\nX-API-Key: " KEY_PREFIX HEX48 "0fa1667a" "\r\n\r\n",
  };
  for (size_t i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++)
  {
    AuthApiKeyParseResult_t r = static_parseApiKey(reqs[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus, reqs[i]);
  }
}

void test_x_api_key_uppercase_checksum_is_malformed(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " KEY_PREFIX HEX48 "0FA16679" "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);
}

void test_x_api_key_prefix_alone_is_malformed(void)
{
  AuthApiKeyParseResult_t r = static_parseApiKey("GET /health HTTP/1.1\r\nX-API-Key: contrastapi_\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus);

  r = static_parseApiKey("GET /health HTTP/1.1\r\nX-API-Key: contrastapi\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

void test_x_api_key_cc_prefix_is_none(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: cc_" HEX48 "\r\n\r\n";
  AuthApiKeyParseResult_t r = static_parseApiKey(req);
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_NONE, r.m_apiKeyStatus);
}

#define HEX48_ALL_DIGITS     "0123456789abcdef0123456789abcdef0123456789abcdef"
#define HEX48_ALL_DIGITS_CRC "b73ba778"
void test_body_of_every_lowercase_hex_digit_is_valid(void)
{
  AuthApiKeyParseResult_t r = static_parseApiKey("GET /health HTTP/1.1\r\nX-API-Key: " KEY_PREFIX HEX48_ALL_DIGITS HEX48_ALL_DIGITS_CRC "\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
  TEST_ASSERT_EQUAL_STRING(KEY_PREFIX HEX48_ALL_DIGITS HEX48_ALL_DIGITS_CRC, r.ma_apiKey);

  r = static_parseApiKey("GET /health HTTP/1.1\r\nAuthorization: Bearer " KEY_PREFIX HEX48_ALL_DIGITS HEX48_ALL_DIGITS_CRC "\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus);
}

void test_body_byte_beside_the_hex_ranges_is_malformed(void)
{
  static const char* const keys[] = {
    KEY_PREFIX "/00000000000000000000000000000000000000000000000" "e4b6418e",
    KEY_PREFIX "00000000000000000000000000000000000000000000000/" "82a96b8c",
    KEY_PREFIX ":00000000000000000000000000000000000000000000000" "423cdf60",
    KEY_PREFIX "00000000000000000000000000000000000000000000000:" "ef748f67",
    KEY_PREFIX "`00000000000000000000000000000000000000000000000" "0edfa472",
    KEY_PREFIX "00000000000000000000000000000000000000000000000`" "64ca378d",
    KEY_PREFIX "g00000000000000000000000000000000000000000000000" "beca2266",
    KEY_PREFIX "00000000000000000000000000000000000000000000000g" "faaea22e",
  };
  char req[256];
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    snprintf(req, sizeof(req), "GET /health HTTP/1.1\r\nX-API-Key: %s\r\n\r\n", keys[i]);
    AuthApiKeyParseResult_t r = static_parseApiKey(req);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AUTH_API_KEY_MALFORMED, r.m_apiKeyStatus, keys[i]);
  }
}

void test_prefix_in_another_case_or_separator_is_none(void)
{
  static const char* const keys[] = {
    "Contrastapi_" HEX48 HEX48_CRC,
    "CONTRASTAPI_" HEX48 HEX48_CRC,
    "contrastapi-" HEX48 HEX48_CRC,
  };
  char req[256];
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    snprintf(req, sizeof(req), "GET /health HTTP/1.1\r\nX-API-Key: %s\r\n\r\n", keys[i]);
    AuthApiKeyParseResult_t r = static_parseApiKey(req);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AUTH_API_KEY_NONE, r.m_apiKeyStatus, keys[i]);
  }
}


void test_generated_key_from_zero_bytes_is_valid_key(void)
{
  static const unsigned char zeros[24] = { 0 };
  static_assertGeneratedKey(zeros, VALID_KEY);
}

void test_generated_key_from_counting_bytes_matches_mint_script(void)
{
  unsigned char counting[24];
  for (int i = 0; i < 24; i++)
    counting[i] = (unsigned char)i;
  static_assertGeneratedKey(counting, GEN_COUNTING_KEY);
}

void test_generated_key_from_all_ones_bytes_matches_mint_script(void)
{
  unsigned char ones[24];
  memset(ones, 0xff, sizeof(ones));
  static_assertGeneratedKey(ones, GEN_ONES_KEY);
}

void test_generated_key_failure_leaves_empty_text(void)
{
  static const int fail_results[] = { 0, -1 };
  for (size_t f = 0; f < sizeof(fail_results) / sizeof(fail_results[0]); f++)
  {
    setUp();
    g_randMode       = AUTH_TEST_RAND_FAIL;
    g_randFailResult = fail_results[f];
    char key[AUTH_TEST_KEY_BUF_SIZE];
    memset(key, 0xA5, sizeof(key));

    TEST_ASSERT_FALSE(auth_tryGenerateApiKey(key));

    TEST_ASSERT_EQUAL_CHAR('\0', key[0]);
    for (size_t i = 1; i < sizeof(key); i++)
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xA5, (unsigned char)key[i], "a failed generator wrote a byte");
    TEST_ASSERT_EQUAL_INT(1, g_randCallCount);
  }
}

void test_generated_keys_from_real_source_parse_valid_and_differ(void)
{
  char first[AUTH_TEST_KEY_BUF_SIZE];
  char second[AUTH_TEST_KEY_BUF_SIZE];
  TEST_ASSERT_TRUE(auth_tryGenerateApiKey(first));
  TEST_ASSERT_TRUE(auth_tryGenerateApiKey(second));
  TEST_ASSERT_EQUAL_INT(2, g_randCallCount);
  TEST_ASSERT_EQUAL_size_t(API_KEY_TOTAL_LEN, strlen(first));
  TEST_ASSERT_NOT_EQUAL(0, strcmp(first, second));

  const char* keys[] = { first, second };
  char req[256];
  for (size_t i = 0; i < 2; i++)
  {
    snprintf(req, sizeof(req), "GET /health HTTP/1.1\r\nX-API-Key: %s\r\n\r\n", keys[i]);
    AuthApiKeyParseResult_t r = static_parseApiKey(req);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AUTH_API_KEY_VALID_FORMAT, r.m_apiKeyStatus, keys[i]);
    TEST_ASSERT_EQUAL_STRING(keys[i], r.ma_apiKey);
  }
}


void test_generated_uuid_sets_the_version_and_variant_bits(void)
{
  static const struct { unsigned char m_seed; bool m_isCounting; const char* mp_expected; } cases[] = {
    { 0x00, false, "00000000-0000-4000-8000-000000000000" },
    { 0xFF, false, "ffffffff-ffff-4fff-bfff-ffffffffffff" },
    { 0x00, true,  "00010203-0405-4607-8809-0a0b0c0d0e0f" },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_randMode = AUTH_TEST_RAND_SCRIPT;
    for (int i = 0; i < 16; i++)
      g_randScript[i] = cases[c].m_isCounting ? (unsigned char)i : cases[c].m_seed;
    char uuid[37];
    TEST_ASSERT_TRUE(auth_tryGenerateUuid(uuid, sizeof(uuid)));
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_expected, uuid);
    TEST_ASSERT_EQUAL_INT(16, g_randLastNum);
    TEST_ASSERT_TRUE(validate_uuid(uuid));
  }
}

void test_generated_uuid_failure_leaves_empty_text(void)
{
  static const int fail_results[] = { 0, -1 };
  for (size_t f = 0; f < sizeof(fail_results) / sizeof(fail_results[0]); f++)
  {
    setUp();
    g_randMode       = AUTH_TEST_RAND_FAIL;
    g_randFailResult = fail_results[f];
    char uuid[37];
    memset(uuid, 0xA5, sizeof(uuid));
    TEST_ASSERT_FALSE(auth_tryGenerateUuid(uuid, sizeof(uuid)));
    TEST_ASSERT_EQUAL_STRING("", uuid);
    TEST_ASSERT_EQUAL_HEX8(0xA5, (unsigned char)uuid[1]);
  }
}

void test_generated_uuid_buffer_limit_is_37_bytes(void)
{
  char uuid[37];
  memset(uuid, 0xA5, sizeof(uuid));
  TEST_ASSERT_FALSE(auth_tryGenerateUuid(uuid, 36));
  TEST_ASSERT_EQUAL_STRING("", uuid);
  TEST_ASSERT_EQUAL_INT(0, g_randCallCount);

  TEST_ASSERT_TRUE(auth_tryGenerateUuid(uuid, 37));
  TEST_ASSERT_EQUAL_size_t(36, strlen(uuid));
}

void test_generated_uuids_from_real_source_are_valid_and_differ(void)
{
  char first[37];
  char second[37];
  TEST_ASSERT_TRUE(auth_tryGenerateUuid(first, sizeof(first)));
  TEST_ASSERT_TRUE(auth_tryGenerateUuid(second, sizeof(second)));
  TEST_ASSERT_TRUE(validate_uuid(first));
  TEST_ASSERT_TRUE(validate_uuid(second));
  TEST_ASSERT_TRUE(strcmp(first, second) != 0);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_no_header);
  RUN_TEST(test_header_whose_name_extends_a_key_header_is_not_read);
  RUN_TEST(test_header_whose_name_is_a_prefix_of_a_key_header_is_not_read);
  RUN_TEST(test_bearer_valid);
  RUN_TEST(test_bearer_too_short);
  RUN_TEST(test_bearer_too_long);
  RUN_TEST(test_bearer_non_hex);
  RUN_TEST(test_bearer_uppercase_hex_is_malformed);
  RUN_TEST(test_bearer_wrong_prefix);
  RUN_TEST(test_x_api_key_valid);
  RUN_TEST(test_x_api_key_malformed);
  RUN_TEST(test_x_api_key_too_long);
  RUN_TEST(test_x_api_key_uppercase_hex_is_malformed);
  RUN_TEST(test_x_api_key_wrong_prefix);
  RUN_TEST(test_wrong_prefix_bearer_falls_through_to_x_api_key);
  RUN_TEST(test_non_bearer_authorization_falls_through_to_x_api_key);
  RUN_TEST(test_malformed_bearer_falls_through_to_x_api_key);
  RUN_TEST(test_uppercase_hex_bearer_falls_through_to_x_api_key);
  RUN_TEST(test_valid_bearer_wins_over_valid_x_api_key);
  RUN_TEST(test_first_x_api_key_header_wins);
  RUN_TEST(test_first_authorization_header_wins);
  RUN_TEST(test_valid_bearer_wins_over_malformed_x_api_key);
  RUN_TEST(test_malformed_bearer_and_malformed_x_api_key_is_malformed);
  RUN_TEST(test_non_bearer_authorization_with_malformed_x_api_key_is_malformed);
  RUN_TEST(test_hash_known_output);
  RUN_TEST(test_hash_ip_null_secret_falls_back_to_sha256);
  RUN_TEST(test_hash_ip_with_secret_uses_hmac);
  RUN_TEST(test_hash_ip_same_ipv6_64_shares_bucket);
  RUN_TEST(test_hash_ip_next_ipv6_64_gets_own_bucket);
  RUN_TEST(test_hash_ip_v4_mapped_ipv6_is_its_ipv4);
  RUN_TEST(test_hash_ip_ipv4_is_not_masked);
  RUN_TEST(test_hash_ip_ipv6_bucket_known_answer);
  RUN_TEST(test_hash_ip_unparseable_hashes_raw_text);
  RUN_TEST(test_hash_ip_full_width_ipv6_64_known_answer);
  RUN_TEST(test_lowercase_authorization_header_recognized);
  RUN_TEST(test_authorization_without_space_after_colon_recognized);
  RUN_TEST(test_lowercase_x_api_key_header_recognized);
  RUN_TEST(test_header_lookalike_in_body_is_ignored);
  RUN_TEST(test_key_followed_by_space_is_malformed);
  RUN_TEST(test_bearer_with_empty_key_falls_through_to_x_api_key);
  RUN_TEST(test_bearer_key_trailing_ows_is_trimmed_valid);
  RUN_TEST(test_folded_authorization_classifies_first_fragment_only);
  RUN_TEST(test_bearer_scheme_lowercase_valid);
  RUN_TEST(test_bearer_scheme_uppercase_valid);
  RUN_TEST(test_bearer_scheme_mixed_case_valid);
  RUN_TEST(test_bearer_scheme_lowercase_malformed_key_is_malformed);
  RUN_TEST(test_bearer_scheme_lowercase_wrong_prefix_is_none);
  RUN_TEST(test_bearer_scheme_tab_separator_is_none);
  RUN_TEST(test_bearer_scheme_double_space_is_none);
  RUN_TEST(test_bearer_checksum_of_another_body_is_malformed);
  RUN_TEST(test_x_api_key_checksum_with_one_character_changed_is_malformed);
  RUN_TEST(test_x_api_key_uppercase_checksum_is_malformed);
  RUN_TEST(test_x_api_key_prefix_alone_is_malformed);
  RUN_TEST(test_x_api_key_cc_prefix_is_none);
  RUN_TEST(test_body_of_every_lowercase_hex_digit_is_valid);
  RUN_TEST(test_body_byte_beside_the_hex_ranges_is_malformed);
  RUN_TEST(test_prefix_in_another_case_or_separator_is_none);
  RUN_TEST(test_generated_key_from_zero_bytes_is_valid_key);
  RUN_TEST(test_generated_key_from_counting_bytes_matches_mint_script);
  RUN_TEST(test_generated_key_from_all_ones_bytes_matches_mint_script);
  RUN_TEST(test_generated_key_failure_leaves_empty_text);
  RUN_TEST(test_generated_keys_from_real_source_parse_valid_and_differ);
  RUN_TEST(test_generated_uuid_sets_the_version_and_variant_bits);
  RUN_TEST(test_generated_uuid_failure_leaves_empty_text);
  RUN_TEST(test_generated_uuid_buffer_limit_is_37_bytes);
  RUN_TEST(test_generated_uuids_from_real_source_are_valid_and_differ);
  return UNITY_END();
}
