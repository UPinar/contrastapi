#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "config.h"
#include "external/certspotter.h"
#include "http_stub.h"
#include "quota.h"
#include "subdomain.h"
#include "validate.h"

#define CERTSPOTTER_TEST_SHA_A "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
#define CERTSPOTTER_TEST_SHA_B "5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a"
#define CERTSPOTTER_TEST_SHA_C "c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc"

static const char CERTSPOTTER_TEST_ANSWER[] = R"([
{"id":"11","tbs_sha256":"ff","cert_sha256":")" CERTSPOTTER_TEST_SHA_C R"(","dns_names":["old.example.com"],"pubkey_sha256":"ee",
 "issuer":{"friendly_name":"Old CA","name":"CN=Old","pubkey_sha256":"dd","caa_domains":["old-ca.example"]},
 "not_before":"2025-01-02T03:04:05Z","not_after":"2026-12-31T23:59:59Z","revoked":null},
{"id":"12","tbs_sha256":"fe","cert_sha256":")" CERTSPOTTER_TEST_SHA_B R"(","dns_names":["example.com","www.example.com","*.example.com"],"pubkey_sha256":"ed",
 "issuer":{"friendly_name":"Sectigo","name":"CN=Sectigo RSA","pubkey_sha256":"dc","caa_domains":["sectigo.com","comodoca.com"]},
 "not_before":"2026-08-01T10:20:30Z","not_after":"2027-08-31T11:21:31Z","revoked":true},
{"id":"13","tbs_sha256":"fd","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","dns_names":["mail.example.com"],"pubkey_sha256":"ec",
 "issuer":{"friendly_name":"Let's Encrypt","name":"CN=R10","pubkey_sha256":"db","caa_domains":[]},
 "not_before":"2026-02-03T04:05:06Z","not_after":"2026-05-04T05:06:07Z","revoked":false}
])";

#define CERTSPOTTER_TEST_CERTIFICATE_FORMAT R"({"cert_sha256":"%s","not_before":"%s","not_after":"2027-01-01T00:00:00Z","dns_names":%s%s})"
#define CERTSPOTTER_TEST_DNS_NAMES          R"(["example.com"])"

#define CERTSPOTTER_TEST_PAGE_SIZE 8192
#define CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT R"({"id":"%d","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"%s","not_after":"2027-01-01T00:00:00Z","dns_names":%s%s})"

typedef struct {
  CertSpotterCertificateList_t  m_list;
  unsigned char                 ma_spare[CERTSPOTTER_CERTIFICATE_MAX_COUNT * sizeof(CertSpotterCertificate_t)];
} CertSpotterTestRoom_t;

#define CERTSPOTTER_TEST_SPARE_BYTE 0xa5

extern QuotaStatus_t g_stub_QUOTA_reserve_status;
extern QuotaStatus_t g_stub_QUOTA_reserve_statuses[];
extern int           g_stub_QUOTA_reserve_status_count;
extern int           g_stub_QUOTA_reserve_count;
extern PGconn*       g_stub_QUOTA_last_reserve_conn;
extern QuotaRule_t   g_stub_QUOTA_last_reserve_rule;

#define CERTSPOTTER_TEST_CONN ((PGconn*)20)
static const QuotaRule_t CERTSPOTTER_TEST_RULE = { "certspotter_test", 60, 7 };

#define CERTSPOTTER_TEST_HOST "example.com"
#define CERTSPOTTER_TEST_URL  "https://api.certspotter.com/v1/issuances?domain=example.com&match_wildcards=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains"

static unsigned int g_retryAfterSeconds;

void setUp(void)
{
  g_retryAfterSeconds             = 7;
  g_stub_answers                  = NULL;
  g_stub_answer_count             = 0;
  g_stub_http_call_count          = 0;
  g_stub_last_url[0]              = '\0';
  g_stub_last_header[0]           = '\0';
  g_stub_next_status              = 200;
  g_stub_next_body                = NULL;
  g_stub_next_body_null           = false;
  g_stub_next_error               = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms          = -1;
  g_stub_last_max_body_byte_count = 0;
  g_stub_last_is_target_trusted   = false;
  g_stub_QUOTA_reserve_status       = QUOTA_GRANTED;
  g_stub_QUOTA_reserve_status_count = 0;
  g_stub_QUOTA_reserve_count        = 0;
  g_stub_QUOTA_last_reserve_conn    = NULL;
  g_stub_QUOTA_last_reserve_rule    = (QuotaRule_t){ NULL, 0, 0 };
  certspotter_setApiKey("123_testkey");
}

void tearDown(void) {}

static CertSpotterStatus_t static_walkOnePage(const char* host_name, const char* body, CertSpotterCertificateList_t* list_out)
{
  static HttpStubAnswer_t answers[2];
  answers[0] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = body };
  answers[1] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = "[]" };
  g_stub_answers         = answers;
  g_stub_answer_count    = 2;
  g_stub_http_call_count = 0;
  return certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, host_name, list_out, &g_retryAfterSeconds);
}

static void static_prepareRoom(CertSpotterTestRoom_t* room)
{
  memset(room, CERTSPOTTER_TEST_SPARE_BYTE, sizeof(*room));
}

static void static_assertSpareUntouched(const CertSpotterTestRoom_t* room)
{
  for (size_t i = 0; i < sizeof(room->ma_spare); i++)
    TEST_ASSERT_EQUAL_HEX8(CERTSPOTTER_TEST_SPARE_BYTE, room->ma_spare[i]);
}

static void static_writeDayAnswer(const int* days, int day_count, char* body, size_t body_size)
{
  size_t used = (size_t)snprintf(body, body_size, "[");
  for (int i = 0; i < day_count; i++)
  {
    char not_before[32];
    snprintf(not_before, sizeof(not_before), "2026-01-%02dT00:00:00Z", days[i]);
    used += (size_t)snprintf(body + used, body_size - used, "%s" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT, i > 0 ? "," : "", i + 1, not_before, CERTSPOTTER_TEST_DNS_NAMES, "");
    TEST_ASSERT_TRUE(used < body_size);
  }
  snprintf(body + used, body_size - used, "]");
}

static int static_readOneCertificate(const char* dns_names, const char* extra_fields, CertSpotterCertificate_t* certificate_out)
{
  static char body[16384];
  snprintf(body, sizeof(body), "[" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT "]", 1, "2026-01-01T00:00:00Z", dns_names, extra_fields);
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list));
  TEST_ASSERT_EQUAL_INT(list.m_readCount, list.m_keptCount);
  *certificate_out = list.ma_certificates[0];
  return list.m_readCount;
}

void test_lookupCertificates_page_reads_each_field_of_each_certificate(void)
{
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, CERTSPOTTER_TEST_ANSWER, &list));
  TEST_ASSERT_EQUAL_INT(3, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(3, list.m_readCount);

  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_B, list.ma_certificates[0].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING("Sectigo", list.ma_certificates[0].ma_issuer);
  TEST_ASSERT_TRUE(list.ma_certificates[0].m_isCaaDomainListKnown);
  TEST_ASSERT_EQUAL_INT(2, list.ma_certificates[0].m_caaDomainCount);
  TEST_ASSERT_EQUAL_STRING("sectigo.com", list.ma_certificates[0].ma_caaDomains[0]);
  TEST_ASSERT_EQUAL_STRING("comodoca.com", list.ma_certificates[0].ma_caaDomains[1]);
  TEST_ASSERT_EQUAL_STRING("2026-08-01T10:20:30Z", list.ma_certificates[0].ma_validFrom);
  TEST_ASSERT_EQUAL_STRING("2027-08-31T11:21:31Z", list.ma_certificates[0].ma_validUntil);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_REVOKED, list.ma_certificates[0].m_revocation);
  TEST_ASSERT_EQUAL_INT(3, list.ma_certificates[0].m_dnsNameCount);
  TEST_ASSERT_EQUAL_STRING("example.com", list.ma_certificates[0].ma_dnsNames[0]);
  TEST_ASSERT_EQUAL_STRING("www.example.com", list.ma_certificates[0].ma_dnsNames[1]);
  TEST_ASSERT_EQUAL_STRING("*.example.com", list.ma_certificates[0].ma_dnsNames[2]);

  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_A, list.ma_certificates[1].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING("Let's Encrypt", list.ma_certificates[1].ma_issuer);
  TEST_ASSERT_TRUE(list.ma_certificates[1].m_isCaaDomainListKnown);
  TEST_ASSERT_EQUAL_INT(0, list.ma_certificates[1].m_caaDomainCount);
  TEST_ASSERT_EQUAL_STRING("2026-02-03T04:05:06Z", list.ma_certificates[1].ma_validFrom);
  TEST_ASSERT_EQUAL_STRING("2026-05-04T05:06:07Z", list.ma_certificates[1].ma_validUntil);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_NOT_REVOKED, list.ma_certificates[1].m_revocation);
  TEST_ASSERT_EQUAL_INT(1, list.ma_certificates[1].m_dnsNameCount);
  TEST_ASSERT_EQUAL_STRING("mail.example.com", list.ma_certificates[1].ma_dnsNames[0]);

  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_C, list.ma_certificates[2].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING("Old CA", list.ma_certificates[2].ma_issuer);
  TEST_ASSERT_EQUAL_STRING("old-ca.example", list.ma_certificates[2].ma_caaDomains[0]);
  TEST_ASSERT_EQUAL_STRING("2025-01-02T03:04:05Z", list.ma_certificates[2].ma_validFrom);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_UNKNOWN, list.ma_certificates[2].m_revocation);
  TEST_ASSERT_EQUAL_STRING("old.example.com", list.ma_certificates[2].ma_dnsNames[0]);
}

void test_lookupCertificates_page_keeps_the_latest_certificates_that_fit(void)
{
  int days[CERTSPOTTER_CERTIFICATE_MAX_COUNT + 1];
  days[0] = 2;
  days[1] = 1;
  for (int i = 2; i <= CERTSPOTTER_CERTIFICATE_MAX_COUNT; i++)
    days[i] = i + 1;
  static char body[16384];
  static_writeDayAnswer(days, CERTSPOTTER_CERTIFICATE_MAX_COUNT + 1, body, sizeof(body));

  static CertSpotterTestRoom_t room;
  static_prepareRoom(&room);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &room.m_list));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT, room.m_list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT + 1, room.m_list.m_readCount);
  for (int i = 0; i < CERTSPOTTER_CERTIFICATE_MAX_COUNT; i++)
  {
    char not_before[32];
    snprintf(not_before, sizeof(not_before), "2026-01-%02dT00:00:00Z", CERTSPOTTER_CERTIFICATE_MAX_COUNT + 1 - i);
    TEST_ASSERT_EQUAL_STRING(not_before, room.m_list.ma_certificates[i].ma_validFrom);
  }
  static_assertSpareUntouched(&room);
}

void test_lookupCertificates_page_orders_a_tie_by_digest(void)
{
  static char body[4096];
  snprintf(body, sizeof(body), "[" CERTSPOTTER_TEST_CERTIFICATE_FORMAT "," CERTSPOTTER_TEST_CERTIFICATE_FORMAT "," CERTSPOTTER_TEST_CERTIFICATE_FORMAT "," CERTSPOTTER_TEST_CERTIFICATE_FORMAT "]",
           CERTSPOTTER_TEST_SHA_C, "2026-03-03T03:03:03Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"1")",
           CERTSPOTTER_TEST_SHA_A, "2026-03-03T03:03:03Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"2")",
           CERTSPOTTER_TEST_SHA_B, "2026-03-03T03:03:03Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"3")",
           CERTSPOTTER_TEST_SHA_C, "2026-03-03T03:03:04Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"4")");
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list));
  TEST_ASSERT_EQUAL_INT(4, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(4, list.m_readCount);
  TEST_ASSERT_EQUAL_STRING("2026-03-03T03:03:04Z", list.ma_certificates[0].ma_validFrom);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_A, list.ma_certificates[1].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_B, list.ma_certificates[2].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_C, list.ma_certificates[3].ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING("2026-03-03T03:03:03Z", list.ma_certificates[3].ma_validFrom);
}

void test_lookupCertificates_page_drops_the_earliest_past_a_full_list(void)
{
  int days[CERTSPOTTER_CERTIFICATE_MAX_COUNT + 3];
  for (int i = 0; i < CERTSPOTTER_CERTIFICATE_MAX_COUNT + 2; i++)
    days[i] = i + 2;
  days[CERTSPOTTER_CERTIFICATE_MAX_COUNT + 2] = 1;
  static char body[16384];
  static_writeDayAnswer(days, CERTSPOTTER_CERTIFICATE_MAX_COUNT + 3, body, sizeof(body));

  static CertSpotterTestRoom_t room;
  static_prepareRoom(&room);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &room.m_list));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT, room.m_list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT + 3, room.m_list.m_readCount);
  for (int i = 0; i < CERTSPOTTER_CERTIFICATE_MAX_COUNT; i++)
  {
    char not_before[32];
    snprintf(not_before, sizeof(not_before), "2026-01-%02dT00:00:00Z", CERTSPOTTER_CERTIFICATE_MAX_COUNT + 3 - i);
    TEST_ASSERT_EQUAL_STRING(not_before, room.m_list.ma_certificates[i].ma_validFrom);
  }
  static_assertSpareUntouched(&room);
}

void test_lookupCertificates_page_inserts_into_the_middle_of_a_list(void)
{
  static const int days[]      = { 20, 2, 18, 4, 16, 6, 14, 8, 12, 10, 11, 5 };
  static const int kept_days[] = { 20, 18, 16, 14, 12, 11, 10, 8, 6, 5 };
  static char body[16384];
  static_writeDayAnswer(days, (int)(sizeof(days) / sizeof(days[0])), body, sizeof(body));

  static CertSpotterTestRoom_t room;
  static_prepareRoom(&room);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &room.m_list));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT, room.m_list.m_keptCount);
  TEST_ASSERT_EQUAL_INT((int)(sizeof(days) / sizeof(days[0])), room.m_list.m_readCount);
  for (int i = 0; i < CERTSPOTTER_CERTIFICATE_MAX_COUNT; i++)
  {
    char not_before[32];
    snprintf(not_before, sizeof(not_before), "2026-01-%02dT00:00:00Z", kept_days[i]);
    TEST_ASSERT_EQUAL_STRING(not_before, room.m_list.ma_certificates[i].ma_validFrom);
  }
  static_assertSpareUntouched(&room);
}

void test_lookupCertificates_page_empty_list_holds_no_certificate(void)
{
  CertSpotterCertificateList_t list;
  memset(&list, 'x', sizeof(list));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, "[ ]", &list));
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
  TEST_ASSERT_TRUE(list.m_isComplete);
  TEST_ASSERT_EQUAL_STRING("", list.ma_certificates[0].ma_sha256Hex);
  TEST_ASSERT_EQUAL_INT(0, list.ma_certificates[CERTSPOTTER_CERTIFICATE_MAX_COUNT - 1].m_dnsNameCount);
}

void test_lookupCertificates_page_refuses_a_body_that_is_not_a_list(void)
{
  static const char* const refused[] = {
    R"({"code":"not_found","message":"Not found"})",
    "[",
    "[" R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"("},])",
    R"("[]")",
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_UPSTREAM_ERROR, static_walkOnePage(CERTSPOTTER_TEST_HOST, refused[i], &list));
    TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
    TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
    TEST_ASSERT_FALSE(list.m_isComplete);
  }
}

void test_lookupCertificates_page_leaves_out_a_certificate_it_cannot_read(void)
{
  static const char* const broken[] = {
    R"({"not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":"0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":"0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":"0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":"0g1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01 00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00.5Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-0xT00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":"yes","dns_names":["example.com"]})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":"example.com"})",
    R"({"cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com",7]})",
    R"(["not","an","object"])",
  };
  for (size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); i++)
  {
    static char body[4096];
    snprintf(body, sizeof(body), "[" CERTSPOTTER_TEST_CERTIFICATE_FORMAT ",%s," CERTSPOTTER_TEST_CERTIFICATE_FORMAT "]",
             CERTSPOTTER_TEST_SHA_B, "2026-02-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"1")", broken[i], CERTSPOTTER_TEST_SHA_C, "2026-03-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, R"(,"id":"3")");
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
    TEST_ASSERT_EQUAL_INT_MESSAGE(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list), broken[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, list.m_readCount, broken[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, list.m_keptCount, broken[i]);
    TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_C, list.ma_certificates[0].ma_sha256Hex);
    TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_B, list.ma_certificates[1].ma_sha256Hex);
  }
}

void test_lookupCertificates_page_list_of_refused_certificates_is_not_empty(void)
{
  static const char body[] = R"([{"id":"7","not_before":"2026-04-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]}])";
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=7", g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
  TEST_ASSERT_TRUE(list.m_isComplete);
}

void test_lookupCertificates_page_reads_the_revocation(void)
{
  CertSpotterCertificate_t certificate;
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, R"(,"revoked":true)", &certificate));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_REVOKED, certificate.m_revocation);
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, R"(,"revoked":false)", &certificate));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_NOT_REVOKED, certificate.m_revocation);
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, R"(,"revoked":null)", &certificate));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_UNKNOWN, certificate.m_revocation);
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, "", &certificate));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_REVOCATION_UNKNOWN, certificate.m_revocation);
}

void test_lookupCertificates_page_keeps_the_first_dns_names_and_counts_all(void)
{
  static char dns_names[4096];
  size_t      used = (size_t)snprintf(dns_names, sizeof(dns_names), "[");
  for (int i = 0; i < CERTSPOTTER_DNS_NAME_MAX_COUNT + 2; i++)
    used += (size_t)snprintf(dns_names + used, sizeof(dns_names) - used, R"(%s"n%d.example.com")", i > 0 ? "," : "", i);
  snprintf(dns_names + used, sizeof(dns_names) - used, "]");

  CertSpotterCertificate_t certificate;
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(dns_names, "", &certificate));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_DNS_NAME_MAX_COUNT + 2, certificate.m_dnsNameCount);
  TEST_ASSERT_EQUAL_STRING("n0.example.com", certificate.ma_dnsNames[0]);
  TEST_ASSERT_EQUAL_STRING("n19.example.com", certificate.ma_dnsNames[CERTSPOTTER_DNS_NAME_MAX_COUNT - 1]);
}

void test_lookupCertificates_page_leaves_out_a_dns_name_that_does_not_fit(void)
{
  char name_253[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char name_254[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  memset(name_253, 'a', sizeof(name_253) - 1);
  name_253[sizeof(name_253) - 1] = '\0';
  memset(name_254, 'b', sizeof(name_254) - 1);
  name_254[sizeof(name_254) - 1] = '\0';

  static char dns_names[1024];
  snprintf(dns_names, sizeof(dns_names), R"(["%s","","bad\u0000name","%s"])", name_254, name_253);
  CertSpotterCertificate_t certificate;
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(dns_names, "", &certificate));
  TEST_ASSERT_EQUAL_INT(1, certificate.m_dnsNameCount);
  TEST_ASSERT_EQUAL_STRING(name_253, certificate.ma_dnsNames[0]);
}

void test_lookupCertificates_page_keeps_a_full_caa_list(void)
{
  char long_domain[CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1];
  memset(long_domain, 'c', sizeof(long_domain) - 1);
  long_domain[sizeof(long_domain) - 1] = '\0';

  static char extra[2048];
  size_t used = (size_t)snprintf(extra, sizeof(extra), R"(,"issuer":{"friendly_name":"Full CA","caa_domains":[)");
  for (int i = 0; i < CERTSPOTTER_CAA_DOMAIN_MAX_COUNT - 1; i++)
    used += (size_t)snprintf(extra + used, sizeof(extra) - used, R"("ca%d.example",)", i);
  snprintf(extra + used, sizeof(extra) - used, R"("%s"]})", long_domain);

  CertSpotterCertificate_t certificate;
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, extra, &certificate));
  TEST_ASSERT_EQUAL_STRING("Full CA", certificate.ma_issuer);
  TEST_ASSERT_TRUE(certificate.m_isCaaDomainListKnown);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CAA_DOMAIN_MAX_COUNT, certificate.m_caaDomainCount);
  TEST_ASSERT_EQUAL_STRING("ca0.example", certificate.ma_caaDomains[0]);
  TEST_ASSERT_EQUAL_STRING(long_domain, certificate.ma_caaDomains[CERTSPOTTER_CAA_DOMAIN_MAX_COUNT - 1]);
}

void test_lookupCertificates_page_leaves_a_caa_list_unknown_when_it_does_not_fit(void)
{
  char too_long[CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 2];
  memset(too_long, 'c', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';

  static char too_many[2048];
  size_t used = (size_t)snprintf(too_many, sizeof(too_many), R"(,"issuer":{"caa_domains":[)");
  for (int i = 0; i < CERTSPOTTER_CAA_DOMAIN_MAX_COUNT + 1; i++)
    used += (size_t)snprintf(too_many + used, sizeof(too_many) - used, R"(%s"ca%d.example")", i > 0 ? "," : "", i);
  snprintf(too_many + used, sizeof(too_many) - used, "]}");

  static char too_long_list[256];
  snprintf(too_long_list, sizeof(too_long_list), R"(,"issuer":{"caa_domains":["ok.example","%s"]})", too_long);

  const char* const unknown[] = {
    too_many,
    too_long_list,
    R"(,"issuer":{"caa_domains":["ok.example",""]})",
    R"(,"issuer":{"caa_domains":["ok.example",5]})",
    R"(,"issuer":{"caa_domains":null})",
    R"(,"issuer":{"caa_domains":"ok.example"})",
    R"(,"issuer":{"friendly_name":"No List CA"})",
  };
  for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++)
  {
    CertSpotterCertificate_t certificate;
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, unknown[i], &certificate), unknown[i]);
    TEST_ASSERT_FALSE_MESSAGE(certificate.m_isCaaDomainListKnown, unknown[i]);
    TEST_ASSERT_EQUAL_INT(0, certificate.m_caaDomainCount);
  }
}

void test_lookupCertificates_page_leaves_out_an_issuer_name_that_does_not_fit(void)
{
  char name_max[CERTSPOTTER_ISSUER_MAX_LEN + 1];
  char name_over[CERTSPOTTER_ISSUER_MAX_LEN + 2];
  memset(name_max, 'i', sizeof(name_max) - 1);
  name_max[sizeof(name_max) - 1] = '\0';
  memset(name_over, 'j', sizeof(name_over) - 1);
  name_over[sizeof(name_over) - 1] = '\0';

  static char extra[512];
  CertSpotterCertificate_t certificate;
  snprintf(extra, sizeof(extra), R"(,"issuer":{"friendly_name":"%s"})", name_max);
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, extra, &certificate));
  TEST_ASSERT_EQUAL_STRING(name_max, certificate.ma_issuer);

  snprintf(extra, sizeof(extra), R"(,"issuer":{"friendly_name":"%s"})", name_over);
  const char* const nameless[] = { extra, R"(,"issuer":{"friendly_name":12})", R"(,"issuer":{"name":"CN=Only DN"})", "" };
  for (size_t i = 0; i < sizeof(nameless) / sizeof(nameless[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, nameless[i], &certificate));
    TEST_ASSERT_EQUAL_STRING("", certificate.ma_issuer);
    TEST_ASSERT_FALSE(certificate.m_isCaaDomainListKnown);
  }
}

void test_lookupCertificates_page_reads_a_caa_list_without_an_issuer_name(void)
{
  CertSpotterCertificate_t certificate;
  TEST_ASSERT_EQUAL_INT(1, static_readOneCertificate(CERTSPOTTER_TEST_DNS_NAMES, R"(,"issuer":{"name":"CN=Only DN","caa_domains":["ca.example"]})", &certificate));
  TEST_ASSERT_EQUAL_STRING("", certificate.ma_issuer);
  TEST_ASSERT_TRUE(certificate.m_isCaaDomainListKnown);
  TEST_ASSERT_EQUAL_INT(1, certificate.m_caaDomainCount);
  TEST_ASSERT_EQUAL_STRING("ca.example", certificate.ma_caaDomains[0]);
}

void test_lookupCertificates_sends_each_request_with_the_key_and_reads_the_answer(void)
{
  const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = CERTSPOTTER_TEST_ANSWER },
    { .m_status = 200, .mp_body = "[]" },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 2;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_TRUE(list.m_isComplete);
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=13", g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_STRING("Authorization: Bearer 123_testkey", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(10000, CERTSPOTTER_LOOKUP_TIMEOUT_MS);
  for (int i = 0; i < 2; i++)
  {
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_LOOKUP_TIMEOUT_MS, g_stub_requests[i].m_timeoutMs);
    TEST_ASSERT_EQUAL_UINT64(2 * 1024 * 1024, g_stub_requests[i].m_maxBodyByteCount);
    TEST_ASSERT_TRUE(g_stub_requests[i].m_isTargetTrusted);
    TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[i].ma_headerNamesToCapture);
  }
  TEST_ASSERT_EQUAL_INT(2, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == CERTSPOTTER_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("certspotter_test", g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(60, g_stub_QUOTA_last_reserve_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(7, g_stub_QUOTA_last_reserve_rule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(3, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(3, list.m_readCount);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_SHA_B, list.ma_certificates[0].ma_sha256Hex);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupCertificates_sends_the_longest_name_whole(void)
{
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(name, 'a', 63);
  name[63] = '.';
  memset(name + 64, 'b', 63);
  name[127] = '.';
  memset(name + 128, 'c', 63);
  name[191] = '.';
  memset(name + 192, 'd', 61);
  name[253] = '\0';
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(name));
  g_stub_next_body = "[]";
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, name, &list, &g_retryAfterSeconds));
  TEST_ASSERT_TRUE(list.m_isComplete);
  char url[512];
  snprintf(url, sizeof(url), "https://api.certspotter.com/v1/issuances?domain=%s&match_wildcards=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains", name);
  TEST_ASSERT_EQUAL_STRING(url, g_stub_last_url);
}

void test_lookupCertificates_sends_the_longest_key_whole(void)
{
  char key[CONFIG_CERTSPOTTER_API_KEY_MAX_LEN + 1];
  memset(key, 'k', sizeof(key) - 1);
  key[sizeof(key) - 1] = '\0';
  certspotter_setApiKey(key);
  g_stub_next_body = "[]";
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  char header[256];
  snprintf(header, sizeof(header), "Authorization: Bearer %s", key);
  TEST_ASSERT_EQUAL_STRING(header, g_stub_last_header);
}

void test_hasApiKey_follows_the_last_key_set(void)
{
  TEST_ASSERT_TRUE(certspotter_hasApiKey());
  certspotter_setApiKey(NULL);
  TEST_ASSERT_FALSE(certspotter_hasApiKey());
}

void test_lookupCertificates_without_a_key_sends_no_request(void)
{
  certspotter_setApiKey(NULL);
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_NO_API_KEY, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
  TEST_ASSERT_FALSE(list.m_isComplete);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupCertificates_refuses_an_invalid_name_without_a_request(void)
{
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_INVALID_NAME, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "bad name.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
  TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
  TEST_ASSERT_FALSE(list.m_isComplete);
  certspotter_setApiKey(NULL);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_INVALID_NAME, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com&x=1", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
}

void test_lookupCertificates_429_names_the_wait(void)
{
  static const char* const header_lines[] = { "Retry-After: 120", NULL };
  const HttpStubAnswer_t answers[] = {
    { .m_status = 429, .mp_body = R"({"code":"rate_limited"})", .mp_headerLines = header_lines },
    { .m_status = 429, .mp_body = R"({"code":"rate_limited"})" },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 2;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_RATE_LIMITED, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(120, g_retryAfterSeconds);
  TEST_ASSERT_FALSE(list.m_isComplete);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_RATE_LIMITED, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
}

void test_lookupCertificates_answer_it_cannot_read_is_an_upstream_error(void)
{
  const HttpStubAnswer_t answers[] = {
    { .m_status = 500, .mp_body = CERTSPOTTER_TEST_ANSWER },
    { .m_status = 404, .mp_body = "[]" },
    { .m_status = 200, .mp_body = R"({"code":"unexpected"})" },
    { .m_status = 200, .mp_body = NULL },
    { .m_error  = HTTP_ERROR_TIMEOUT },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = (int)(sizeof(answers) / sizeof(answers[0]));
  for (int i = 0; i < g_stub_answer_count; i++)
  {
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_UPSTREAM_ERROR, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
    TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
    TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
    TEST_ASSERT_FALSE(list.m_isComplete);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
  TEST_ASSERT_EQUAL_INT(g_stub_answer_count, g_stub_http_call_count);
}

static void static_writePage(char* body, int first_id, int count, int first_serial, const char* extra_fields)
{
  size_t used = (size_t)snprintf(body, CERTSPOTTER_TEST_PAGE_SIZE, "[");
  for (int i = 0; i < count; i++)
  {
    int  serial = first_serial + i;
    char not_before[32];
    snprintf(not_before, sizeof(not_before), "2026-%02d-%02dT00:00:00Z", serial / 28 + 1, serial % 28 + 1);
    used += (size_t)snprintf(body + used, CERTSPOTTER_TEST_PAGE_SIZE - used, "%s" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT,
                             i > 0 ? "," : "", first_id + i, not_before, CERTSPOTTER_TEST_DNS_NAMES, extra_fields);
    TEST_ASSERT_TRUE(used < CERTSPOTTER_TEST_PAGE_SIZE);
  }
  snprintf(body + used, CERTSPOTTER_TEST_PAGE_SIZE - used, "]");
}

void test_lookupCertificates_follows_a_short_page_until_an_empty_one(void)
{
  static char first_page[CERTSPOTTER_TEST_PAGE_SIZE];
  static char short_page[CERTSPOTTER_TEST_PAGE_SIZE];
  static_writePage(first_page, 11, 3, 0, "");
  static_writePage(short_page, 14, 1, 3, "");
  const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = first_page },
    { .m_status = 200, .mp_body = short_page },
    { .m_status = 200, .mp_body = "[ ]" },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 3;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=13", g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=14", g_stub_requests[2].ma_url);
  TEST_ASSERT_EQUAL_INT(3, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(4, list.m_readCount);
  TEST_ASSERT_EQUAL_INT(4, list.m_keptCount);
  TEST_ASSERT_EQUAL_STRING("2026-01-04T00:00:00Z", list.ma_certificates[0].ma_validFrom);
  TEST_ASSERT_TRUE(list.m_isComplete);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupCertificates_reads_at_most_the_page_cap(void)
{
  TEST_ASSERT_EQUAL_INT(5, CERTSPOTTER_MAX_PAGE_COUNT);
  static char pages[CERTSPOTTER_MAX_PAGE_COUNT + 1][CERTSPOTTER_TEST_PAGE_SIZE];
  for (int page = 0; page <= CERTSPOTTER_MAX_PAGE_COUNT; page++)
  {
    char extra_fields[64];
    snprintf(extra_fields, sizeof(extra_fields), R"(,"issuer":{"friendly_name":"Page %d CA"})", page + 1);
    static_writePage(pages[page], 100 * (page + 1), 2, 2 * page, extra_fields);
  }
  for (int is_last_page_empty = 0; is_last_page_empty <= 1; is_last_page_empty++)
  {
    HttpStubAnswer_t answers[CERTSPOTTER_MAX_PAGE_COUNT + 2];
    for (int page = 0; page <= CERTSPOTTER_MAX_PAGE_COUNT; page++)
      answers[page] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = pages[page] };
    if (is_last_page_empty)
      answers[CERTSPOTTER_MAX_PAGE_COUNT].mp_body = "[]";
    answers[CERTSPOTTER_MAX_PAGE_COUNT + 1] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = "[]" };
    g_stub_answers         = answers;
    g_stub_answer_count    = CERTSPOTTER_MAX_PAGE_COUNT + 2;
    g_stub_http_call_count = 0;
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_MAX_PAGE_COUNT + 1, g_stub_http_call_count);
    TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=501", g_stub_requests[CERTSPOTTER_MAX_PAGE_COUNT].ma_url);
    TEST_ASSERT_EQUAL_INT(2 * CERTSPOTTER_MAX_PAGE_COUNT, list.m_readCount);
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_MAX_PAGE_COUNT, list.m_issuerCount);
    TEST_ASSERT_EQUAL_STRING("Page 5 CA", list.ma_issuers[CERTSPOTTER_MAX_PAGE_COUNT - 1].ma_key);
    TEST_ASSERT_FALSE(list.m_isIssuerDropped);
    TEST_ASSERT_EQUAL_INT(is_last_page_empty, list.m_isComplete);
  }
}

void test_lookupCertificates_failed_check_past_the_cap_cuts_the_walk(void)
{
  static char pages[CERTSPOTTER_MAX_PAGE_COUNT][CERTSPOTTER_TEST_PAGE_SIZE];
  static const char* const header_lines[] = { "Retry-After: 45", NULL };
  HttpStubAnswer_t answers[CERTSPOTTER_MAX_PAGE_COUNT + 1];
  for (int page = 0; page < CERTSPOTTER_MAX_PAGE_COUNT; page++)
  {
    static_writePage(pages[page], 100 * (page + 1), 2, 2 * page, "");
    answers[page] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = pages[page] };
  }
  answers[CERTSPOTTER_MAX_PAGE_COUNT] = (HttpStubAnswer_t){ .m_status = 429, .mp_body = "{}", .mp_headerLines = header_lines };
  g_stub_answers      = answers;
  g_stub_answer_count = CERTSPOTTER_MAX_PAGE_COUNT + 1;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_RATE_LIMITED, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_MAX_PAGE_COUNT + 1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_UINT(45, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(0, list.m_readCount);
  TEST_ASSERT_EQUAL_INT(0, list.m_keptCount);
}

void test_lookupCertificates_reserves_each_request_and_a_refusal_ends_the_walk(void)
{
  static char page[CERTSPOTTER_TEST_PAGE_SIZE];
  static_writePage(page, 31, 2, 0, "");
  static const struct {
    QuotaStatus_t       m_refusal;
    int                 m_grantedCount;
    CertSpotterStatus_t m_status;
    int                 m_requestCount;
    int                 m_readCount;
  } cases[] = {
    { QUOTA_EXHAUSTED, 0, CERTSPOTTER_QUOTA_EXHAUSTED, 0, 0 },
    { QUOTA_ERROR,     0, CERTSPOTTER_DB_ERROR,        0, 0 },
    { QUOTA_EXHAUSTED, 1, CERTSPOTTER_QUOTA_EXHAUSTED, 1, 0 },
    { QUOTA_ERROR,     1, CERTSPOTTER_DB_ERROR,        1, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    const HttpStubAnswer_t answers[] = {
      { .m_status = 200, .mp_body = page },
      { .m_status = 200, .mp_body = "[]" },
    };
    g_stub_answers                    = answers;
    g_stub_answer_count               = 2;
    g_stub_http_call_count            = 0;
    g_stub_QUOTA_reserve_count        = 0;
    g_stub_QUOTA_reserve_statuses[0]  = QUOTA_GRANTED;
    g_stub_QUOTA_reserve_statuses[cases[i].m_grantedCount] = cases[i].m_refusal;
    g_stub_QUOTA_reserve_status_count = cases[i].m_grantedCount + 1;
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds), label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requestCount, g_stub_http_call_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_grantedCount + 1, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_readCount, list.m_readCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_readCount, list.m_keptCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, list.m_issuerCount, label);
    TEST_ASSERT_FALSE_MESSAGE(list.m_isComplete, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_retryAfterSeconds, label);
  }
}

void test_lookupCertificates_failed_request_after_a_page_cuts_the_walk(void)
{
  static char page[CERTSPOTTER_TEST_PAGE_SIZE];
  static_writePage(page, 41, 2, 0, R"(,"issuer":{"friendly_name":"Cut CA"})");
  static const char* const header_lines[] = { "Retry-After: 90", NULL };
  const HttpStubAnswer_t failures[] = {
    { .m_status = 429, .mp_body = R"({"code":"rate_limited"})", .mp_headerLines = header_lines },
    { .m_status = 500, .mp_body = "[]" },
    { .m_status = 200, .mp_body = R"({"code":"unexpected"})" },
    { .m_error  = HTTP_ERROR_TIMEOUT },
  };
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    const HttpStubAnswer_t answers[] = { { .m_status = 200, .mp_body = page }, failures[i] };
    g_stub_answers         = answers;
    g_stub_answer_count    = 2;
    g_stub_http_call_count = 0;
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
    TEST_ASSERT_EQUAL_INT_MESSAGE(i == 0 ? CERTSPOTTER_RATE_LIMITED : CERTSPOTTER_UPSTREAM_ERROR,
                                  certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds), label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_stub_http_call_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, list.m_readCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, list.m_keptCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, list.m_issuerCount, label);
    TEST_ASSERT_FALSE_MESSAGE(list.m_isComplete, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(i == 0 ? 90 : 0, g_retryAfterSeconds, label);
  }
}

void test_lookupCertificates_page_without_a_last_id_cuts_the_walk(void)
{
  static const char* const last_ids[] = {
    "",
    R"("id":52,)",
    R"("id":"",)",
    R"("id":"5a",)",
    R"("id":"123456789012345678901",)",
  };
  for (size_t i = 0; i < sizeof(last_ids) / sizeof(last_ids[0]); i++)
  {
    static char page[CERTSPOTTER_TEST_PAGE_SIZE];
    snprintf(page, sizeof(page), "[" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT ",{%s" R"("cert_sha256":")" CERTSPOTTER_TEST_SHA_B R"(","not_before":"2026-02-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["example.com"]}])",
             51, "2026-01-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, "", last_ids[i]);
    const HttpStubAnswer_t answers[] = {
      { .m_status = 200, .mp_body = page },
      { .m_status = 200, .mp_body = "[]" },
    };
    g_stub_answers         = answers;
    g_stub_answer_count    = 2;
    g_stub_http_call_count = 0;
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1, .m_isComplete = true };
    TEST_ASSERT_EQUAL_INT_MESSAGE(CERTSPOTTER_UPSTREAM_ERROR, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds), last_ids[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, last_ids[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, list.m_readCount, last_ids[i]);
    TEST_ASSERT_FALSE_MESSAGE(list.m_isComplete, last_ids[i]);
  }
}

void test_lookupCertificates_follows_the_longest_id_after_the_longest_name(void)
{
  TEST_ASSERT_EQUAL_INT(20, CERTSPOTTER_CERTIFICATE_ID_MAX_LEN);
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (int i = 0; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    name[i] = (i % 64 == 63) ? '.' : 'a';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  static char page[CERTSPOTTER_TEST_PAGE_SIZE];
  snprintf(page, sizeof(page), "[" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT R"(,{"id":"12345678901234567890","not_before":"2026-02-01T00:00:00Z"}])",
           61, "2026-01-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, "");
  const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = page },
    { .m_status = 200, .mp_body = "[]" },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 2;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, name, &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  char url[1024];
  snprintf(url, sizeof(url), "https://api.certspotter.com/v1/issuances?domain=%s&match_wildcards=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains&after=12345678901234567890", name);
  TEST_ASSERT_EQUAL_STRING(url, g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_INT(1, list.m_readCount);
  TEST_ASSERT_TRUE(list.m_isComplete);
}

void test_lookupCertificates_keeps_the_latest_over_every_page(void)
{
  static char first_page[CERTSPOTTER_TEST_PAGE_SIZE];
  static char second_page[CERTSPOTTER_TEST_PAGE_SIZE];
  static char second_tail[CERTSPOTTER_TEST_PAGE_SIZE];
  static_writePage(first_page, 71, 6, 0, R"(,"issuer":{"friendly_name":"CA A"})");
  static_writePage(second_page, 77, 1, 11, R"(,"issuer":{"friendly_name":"CA B"})");
  static_writePage(second_tail, 78, 5, 6, R"(,"issuer":{"friendly_name":"CA B"})");
  size_t head_len = strlen(second_page);
  snprintf(second_page + head_len - 1, sizeof(second_page) - head_len + 1, ",%s", second_tail + 1);
  const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = first_page },
    { .m_status = 200, .mp_body = second_page },
    { .m_status = 200, .mp_body = "[]" },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 3;
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupCertificates(CERTSPOTTER_TEST_CONN, &CERTSPOTTER_TEST_RULE, "example.com", &list, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING(CERTSPOTTER_TEST_URL "&after=82", g_stub_requests[2].ma_url);
  TEST_ASSERT_EQUAL_INT(12, list.m_readCount);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CERTIFICATE_MAX_COUNT, list.m_keptCount);
  for (int i = 0; i < CERTSPOTTER_CERTIFICATE_MAX_COUNT; i++)
  {
    int  serial = 11 - i;
    char expected[32];
    snprintf(expected, sizeof(expected), "2026-01-%02dT00:00:00Z", serial + 1);
    TEST_ASSERT_EQUAL_STRING(expected, list.ma_certificates[i].ma_validFrom);
  }
  TEST_ASSERT_EQUAL_INT(2, list.m_issuerCount);
  TEST_ASSERT_EQUAL_STRING("CA A", list.ma_issuers[0].ma_key);
  TEST_ASSERT_EQUAL_STRING("CA B", list.ma_issuers[1].ma_key);
  TEST_ASSERT_TRUE(list.m_isComplete);
}

static const char CERTSPOTTER_TEST_ISSUER_ANSWER[] = "["
  R"({"id":"1","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"],"issuer":{"friendly_name":"Sectigo","caa_domains":["sectigo.com","comodoca.com"]}},)"
  R"({"id":"2","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-02T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.example.com"],"issuer":{"friendly_name":"Sectigo RSA","caa_domains":["comodoca.com","sectigo.com"]}},)"
  R"({"id":"3","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-03T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.example.com","WWW.EXAMPLE.COM"],"issuer":{"friendly_name":"Let's Encrypt","caa_domains":[]}},)"
  R"({"id":"4","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-04T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.Example.COM"],"issuer":{"friendly_name":"Wild Only CA"}},)"
  R"({"id":"5","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-05T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.example.com"],"issuer":{"friendly_name":"Wild First CA"}},)"
  R"({"id":"6","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-06T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["mail.example.com","a.example.com"],"issuer":{"friendly_name":"Other CA","caa_domains":["zeta.example","alpha.example","mid.example"]}},)"
  R"({"id":"7","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-07T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.www.example.com","*.com","*xexample.com"],"issuer":{"friendly_name":"Deep Wild CA","caa_domains":["deep-wild.example"]}},)"
  R"({"id":"8","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-08T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"]},)"
  R"({"id":"9","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-09T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"],"issuer":{"friendly_name":"Wild First CA"}})"
  "]";

void test_lookupCertificates_page_fills_the_issuer_set(void)
{
  CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage("www.example.com", CERTSPOTTER_TEST_ISSUER_ANSWER, &list));
  TEST_ASSERT_EQUAL_INT(9, list.m_readCount);
  TEST_ASSERT_EQUAL_INT(6, list.m_issuerCount);
  TEST_ASSERT_TRUE(list.m_isIssuerDropped);

  static const struct {
    const char* mp_key;
    int         m_caaDomainCount;
    bool        m_isCaaDomainListKnown;
    const char* mp_firstCaaDomain;
    const char* mp_lastCaaDomain;
    bool        m_isSeenOnExactName;
    bool        m_isSeenOnWildcardName;
  } expected[] = {
    { "comodoca.com,sectigo.com",                 2, true,  "comodoca.com",  "sectigo.com",  true,  true  },
    { "Let's Encrypt",                            0, true,  NULL,            NULL,           true,  true  },
    { "Wild Only CA",                             0, false, NULL,            NULL,           false, true  },
    { "Wild First CA",                            0, false, NULL,            NULL,           true,  true  },
    { "alpha.example,mid.example,zeta.example",   3, true,  "alpha.example", "zeta.example", false, false },
    { "deep-wild.example",                        1, true,  "deep-wild.example", "deep-wild.example", false, false },
  };
  for (int i = 0; i < 6; i++)
  {
    const CertSpotterIssuer_t* issuer = &list.ma_issuers[i];
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[i].mp_key, issuer->ma_key, expected[i].mp_key);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_caaDomainCount, issuer->m_caaDomainCount, expected[i].mp_key);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_isCaaDomainListKnown, issuer->m_isCaaDomainListKnown, expected[i].mp_key);
    if (expected[i].mp_firstCaaDomain != NULL)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[i].mp_firstCaaDomain, issuer->ma_caaDomains[0], expected[i].mp_key);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[i].mp_lastCaaDomain, issuer->ma_caaDomains[issuer->m_caaDomainCount - 1], expected[i].mp_key);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_isSeenOnExactName, issuer->m_isSeenOnExactName, expected[i].mp_key);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_isSeenOnWildcardName, issuer->m_isSeenOnWildcardName, expected[i].mp_key);
  }
  TEST_ASSERT_EQUAL_STRING("mid.example", list.ma_issuers[4].ma_caaDomains[1]);
}

void test_lookupCertificates_page_repeated_issuer_keeps_the_kind_of_its_certificates(void)
{
  static const char body[] = "["
    R"({"id":"1","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"],"issuer":{"friendly_name":"Twice Exact CA"}},)"
    R"({"id":"2","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-02T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"],"issuer":{"friendly_name":"Twice Exact CA"}},)"
    R"({"id":"3","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-03T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.example.com"],"issuer":{"friendly_name":"Twice Wild CA"}},)"
    R"({"id":"4","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-04T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["*.example.com"],"issuer":{"friendly_name":"Twice Wild CA"}},)"
    R"({"id":"5","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-05T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com"],"issuer":{"friendly_name":"Later Both CA"}},)"
    R"({"id":"6","cert_sha256":")" CERTSPOTTER_TEST_SHA_A R"(","not_before":"2026-01-06T00:00:00Z","not_after":"2027-01-01T00:00:00Z","dns_names":["www.example.com","*.example.com"],"issuer":{"friendly_name":"Later Both CA"}})"
    "]";
  CertSpotterCertificateList_t list = { .m_keptCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage("www.example.com", body, &list));
  TEST_ASSERT_EQUAL_INT(3, list.m_issuerCount);
  TEST_ASSERT_EQUAL_STRING("Twice Exact CA", list.ma_issuers[0].ma_key);
  TEST_ASSERT_TRUE(list.ma_issuers[0].m_isSeenOnExactName);
  TEST_ASSERT_FALSE(list.ma_issuers[0].m_isSeenOnWildcardName);
  TEST_ASSERT_EQUAL_STRING("Twice Wild CA", list.ma_issuers[1].ma_key);
  TEST_ASSERT_FALSE(list.ma_issuers[1].m_isSeenOnExactName);
  TEST_ASSERT_TRUE(list.ma_issuers[1].m_isSeenOnWildcardName);
  TEST_ASSERT_EQUAL_STRING("Later Both CA", list.ma_issuers[2].ma_key);
  TEST_ASSERT_TRUE(list.ma_issuers[2].m_isSeenOnExactName);
  TEST_ASSERT_TRUE(list.ma_issuers[2].m_isSeenOnWildcardName);
}

void test_lookupCertificates_page_name_past_the_kept_ones_still_matches(void)
{
  TEST_ASSERT_EQUAL_INT(20, CERTSPOTTER_DNS_NAME_MAX_COUNT);
  char names[2048];
  size_t used = (size_t)snprintf(names, sizeof(names), "[");
  for (int i = 0; i < CERTSPOTTER_DNS_NAME_MAX_COUNT; i++)
    used += (size_t)snprintf(names + used, sizeof(names) - used, "\"n%02d.example.com\",", i);
  snprintf(names + used, sizeof(names) - used, "\"www.example.com\"]");
  static char body[CERTSPOTTER_TEST_PAGE_SIZE];
  snprintf(body, sizeof(body), "[" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT "]", 1, "2026-01-01T00:00:00Z", names, R"(,"issuer":{"friendly_name":"Many Names CA"})");
  CertSpotterCertificateList_t list = { .m_keptCount = -1 };
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage("www.example.com", body, &list));
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_DNS_NAME_MAX_COUNT + 1, list.ma_certificates[0].m_dnsNameCount);
  TEST_ASSERT_EQUAL_INT(1, list.m_issuerCount);
  TEST_ASSERT_TRUE(list.ma_issuers[0].m_isSeenOnExactName);
}

void test_lookupCertificates_page_issuer_set_keeps_the_first_16(void)
{
  TEST_ASSERT_EQUAL_INT(16, CERTSPOTTER_ISSUER_MAX_COUNT);
  for (int extra = 0; extra <= 1; extra++)
  {
    static char body[CERTSPOTTER_TEST_PAGE_SIZE * 2];
    size_t used = (size_t)snprintf(body, sizeof(body), "[");
    int    count = CERTSPOTTER_ISSUER_MAX_COUNT + 1;
    for (int i = 0; i < count; i++)
    {
      int  number = (i == CERTSPOTTER_ISSUER_MAX_COUNT && extra == 0) ? 1 : i + 1;
      char extra_fields[64];
      snprintf(extra_fields, sizeof(extra_fields), R"(,"issuer":{"friendly_name":"CA %02d"})", number);
      used += (size_t)snprintf(body + used, sizeof(body) - used, "%s" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT, i > 0 ? "," : "", i + 1, "2026-01-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, extra_fields);
      TEST_ASSERT_TRUE(used < sizeof(body));
    }
    snprintf(body + used, sizeof(body) - used, "]");
    CertSpotterCertificateList_t list = { .m_keptCount = -1, .m_readCount = -1 };
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list));
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_ISSUER_MAX_COUNT, list.m_issuerCount);
    TEST_ASSERT_EQUAL_STRING("CA 01", list.ma_issuers[0].ma_key);
    TEST_ASSERT_EQUAL_STRING("CA 16", list.ma_issuers[CERTSPOTTER_ISSUER_MAX_COUNT - 1].ma_key);
    TEST_ASSERT_EQUAL_INT(extra, list.m_isIssuerDropped);
  }
}

void test_lookupCertificates_page_longest_issuer_key_fits_whole(void)
{
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_CAA_DOMAIN_MAX_COUNT * (CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1) - 1, CERTSPOTTER_ISSUER_KEY_MAX_LEN);
  char caa_list[CERTSPOTTER_CAA_DOMAIN_MAX_COUNT * (CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 3) + 64];
  char expected_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN + 1];
  size_t used     = (size_t)snprintf(caa_list, sizeof(caa_list), R"(,"issuer":{"caa_domains":[)");
  size_t key_used = 0;
  for (int i = 0; i < CERTSPOTTER_CAA_DOMAIN_MAX_COUNT; i++)
  {
    char domain[CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1];
    memset(domain, 'p' - i, CERTSPOTTER_CAA_DOMAIN_MAX_LEN);
    domain[CERTSPOTTER_CAA_DOMAIN_MAX_LEN] = '\0';
    used += (size_t)snprintf(caa_list + used, sizeof(caa_list) - used, "%s\"%s\"", i > 0 ? "," : "", domain);
    memset(domain, 'a' + i, CERTSPOTTER_CAA_DOMAIN_MAX_LEN);
    key_used += (size_t)snprintf(expected_key + key_used, sizeof(expected_key) - key_used, "%s%s", i > 0 ? "," : "", domain);
  }
  snprintf(caa_list + used, sizeof(caa_list) - used, "]}");
  TEST_ASSERT_EQUAL_size_t(CERTSPOTTER_ISSUER_KEY_MAX_LEN, strlen(expected_key));
  CertSpotterCertificateList_t list = { .m_keptCount = -1 };
  static char body[CERTSPOTTER_TEST_PAGE_SIZE];
  snprintf(body, sizeof(body), "[" CERTSPOTTER_TEST_CERTIFICATE_WITH_ID_FORMAT "]", 1, "2026-01-01T00:00:00Z", CERTSPOTTER_TEST_DNS_NAMES, caa_list);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, static_walkOnePage(CERTSPOTTER_TEST_HOST, body, &list));
  TEST_ASSERT_EQUAL_INT(1, list.m_issuerCount);
  TEST_ASSERT_FALSE(list.m_isIssuerDropped);
  TEST_ASSERT_EQUAL_STRING(expected_key, list.ma_issuers[0].ma_key);
}

static const char CERTSPOTTER_TEST_SUBTREE_ANSWER[] = R"([
{"id":"21","dns_names":["example.com","*.example.com","www.example.com"]},
{"id":"22","dns_names":["API.example.com","www.example.com","example.org","*.dev.example.com"]},
{"id":"23","tbs_sha256":"ab"},
"not a certificate",
{"id":"25","dns_names":[17,null,{"name":"x.example.com"},"mail.example.com"]},
{"id":"26","dns_names":"shop.example.com"}
])";

void test_tryReadSubdomainNames_adds_each_name_under_the_domain(void)
{
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = true;
  TEST_ASSERT_TRUE(certspotter_tryReadSubdomainNames(CERTSPOTTER_TEST_SUBTREE_ANSWER, strlen(CERTSPOTTER_TEST_SUBTREE_ANSWER), "example.com", name_set, &is_answer_empty));
  TEST_ASSERT_FALSE(is_answer_empty);
  TEST_ASSERT_EQUAL_INT(4, name_set->m_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", name_set->mp_names[0]);
  TEST_ASSERT_EQUAL_STRING("api.example.com", name_set->mp_names[1]);
  TEST_ASSERT_EQUAL_STRING("dev.example.com", name_set->mp_names[2]);
  TEST_ASSERT_EQUAL_STRING("mail.example.com", name_set->mp_names[3]);
  for (int i = 0; i < name_set->m_count; i++)
    TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_CERTIFICATE_LOGS, name_set->mp_sources[i]);
  subdomain_destroyNameSet(name_set);
}

void test_tryReadSubdomainNames_adds_the_source_to_a_known_name(void)
{
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  subdomain_addName(name_set, "vpn.example.com", "example.com", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  TEST_ASSERT_EQUAL_INT(1, name_set->m_count);
  static const char body[] = R"([{"dns_names":["vpn.example.com"]}])";
  bool is_answer_empty = true;
  TEST_ASSERT_TRUE(certspotter_tryReadSubdomainNames(body, strlen(body), "example.com", name_set, &is_answer_empty));
  TEST_ASSERT_EQUAL_INT(1, name_set->m_count);
  TEST_ASSERT_EQUAL_HEX32(SUBDOMAIN_SOURCE_DNS_WORDLIST | SUBDOMAIN_SOURCE_CERTIFICATE_LOGS, name_set->mp_sources[0]);
  subdomain_destroyNameSet(name_set);
}

void test_tryReadSubdomainNames_refuses_a_body_that_is_not_a_list(void)
{
  static const char* const bodies[] = {
    R"({"dns_names":["www.example.com"]})",
    R"("www.example.com")",
    R"([{"dns_names":["www.example.com"]})",
  };
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    bool is_answer_empty = true;
    TEST_ASSERT_FALSE(certspotter_tryReadSubdomainNames(bodies[i], strlen(bodies[i]), "example.com", name_set, &is_answer_empty));
    TEST_ASSERT_FALSE(is_answer_empty);
  }
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  subdomain_destroyNameSet(name_set);
}

void test_tryReadSubdomainNames_keeps_a_name_of_the_longest_length(void)
{
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(name, 'a', 63);
  name[63] = '.';
  memset(name + 64, 'b', 63);
  name[127] = '.';
  memset(name + 128, 'c', 63);
  name[191] = '.';
  memset(name + 192, 'd', 49);
  snprintf(name + 241, sizeof(name) - 241, ".example.com");
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(name));
  char body[512];
  snprintf(body, sizeof(body), "[{\"dns_names\":[\"%s\"]}]", name);
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = true;
  TEST_ASSERT_TRUE(certspotter_tryReadSubdomainNames(body, strlen(body), "example.com", name_set, &is_answer_empty));
  TEST_ASSERT_EQUAL_INT(1, name_set->m_count);
  TEST_ASSERT_EQUAL_STRING(name, name_set->mp_names[0]);
  subdomain_destroyNameSet(name_set);
}

void test_tryReadSubdomainNames_empty_list_is_an_empty_answer(void)
{
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = false;
  TEST_ASSERT_TRUE(certspotter_tryReadSubdomainNames("[ ]", 3, "example.com", name_set, &is_answer_empty));
  TEST_ASSERT_TRUE(is_answer_empty);
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  subdomain_destroyNameSet(name_set);
}

void test_tryReadSubdomainNames_list_without_a_name_is_not_empty(void)
{
  static const char* const bodies[] = {
    R"([{"id":"23","tbs_sha256":"ab"},{"id":"24","dns_names":["example.org"]}])",
    R"([{"id":"23","tbs_sha256":"ab"},7])",
  };
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    bool is_answer_empty = true;
    TEST_ASSERT_TRUE(certspotter_tryReadSubdomainNames(bodies[i], strlen(bodies[i]), "example.com", name_set, &is_answer_empty));
    TEST_ASSERT_FALSE_MESSAGE(is_answer_empty, bodies[i]);
  }
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  subdomain_destroyNameSet(name_set);
}

void test_lookupSubdomainNames_sends_one_request_for_the_subtree(void)
{
  g_stub_next_body = CERTSPOTTER_TEST_SUBTREE_ANSWER;
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = true;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupSubdomainNames("example.com", name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_FALSE(is_answer_empty);
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&match_wildcards=true&expand=dns_names", g_stub_last_url);
  TEST_ASSERT_EQUAL_STRING("Authorization: Bearer 123_testkey", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(3000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_SUBTREE_TIMEOUT_MS, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_UINT64(2 * 1024 * 1024, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_INT(4, name_set->m_count);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  subdomain_destroyNameSet(name_set);
}

void test_lookupSubdomainNames_sends_the_longest_domain_whole(void)
{
  char domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(domain, 'a', 63);
  domain[63] = '.';
  memset(domain + 64, 'b', 63);
  domain[127] = '.';
  memset(domain + 128, 'c', 63);
  domain[191] = '.';
  memset(domain + 192, 'd', 61);
  domain[253] = '\0';
  g_stub_next_body = "[]";
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = false;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_OK, certspotter_lookupSubdomainNames(domain, name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_TRUE(is_answer_empty);
  char url[512];
  snprintf(url, sizeof(url), "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&match_wildcards=true&expand=dns_names", domain);
  TEST_ASSERT_EQUAL_STRING(url, g_stub_last_url);
  subdomain_destroyNameSet(name_set);
}

void test_lookupSubdomainNames_429_names_the_wait(void)
{
  static const char* const header_lines[] = { "Retry-After: 240", NULL };
  const HttpStubAnswer_t answers[] = {
    { .m_status = 429, .mp_body = CERTSPOTTER_TEST_SUBTREE_ANSWER, .mp_headerLines = header_lines },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = 1;
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  bool is_answer_empty = true;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_RATE_LIMITED, certspotter_lookupSubdomainNames("example.com", name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(240, g_retryAfterSeconds);
  TEST_ASSERT_FALSE(is_answer_empty);
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  subdomain_destroyNameSet(name_set);
}

void test_lookupSubdomainNames_without_a_key_or_a_valid_name_sends_no_request(void)
{
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  certspotter_setApiKey(NULL);
  bool is_answer_empty = true;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_NO_API_KEY, certspotter_lookupSubdomainNames("example.com", name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_FALSE(is_answer_empty);
  is_answer_empty = true;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_INVALID_NAME, certspotter_lookupSubdomainNames("example.com&x=1", name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_FALSE(is_answer_empty);
  certspotter_setApiKey("123_testkey");
  g_retryAfterSeconds = 7;
  is_answer_empty     = true;
  TEST_ASSERT_EQUAL_INT(CERTSPOTTER_INVALID_NAME, certspotter_lookupSubdomainNames("bad name.com", name_set, &is_answer_empty, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_FALSE(is_answer_empty);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  subdomain_destroyNameSet(name_set);
}

void test_lookupSubdomainNames_answer_it_cannot_read_is_an_upstream_error(void)
{
  const HttpStubAnswer_t answers[] = {
    { .m_status = 500, .mp_body = CERTSPOTTER_TEST_SUBTREE_ANSWER },
    { .m_status = 404, .mp_body = CERTSPOTTER_TEST_SUBTREE_ANSWER },
    { .m_status = 200, .mp_body = R"({"code":"unexpected"})" },
    { .m_status = 200, .mp_body = NULL },
    { .m_error  = HTTP_ERROR_TIMEOUT },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = (int)(sizeof(answers) / sizeof(answers[0]));
  SubdomainNameSet_t* name_set = subdomain_createNameSet();
  TEST_ASSERT_NOT_NULL(name_set);
  for (int i = 0; i < g_stub_answer_count; i++)
  {
    bool is_answer_empty = true;
    TEST_ASSERT_EQUAL_INT(CERTSPOTTER_UPSTREAM_ERROR, certspotter_lookupSubdomainNames("example.com", name_set, &is_answer_empty, &g_retryAfterSeconds));
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
    TEST_ASSERT_FALSE(is_answer_empty);
  }
  TEST_ASSERT_EQUAL_INT(0, name_set->m_count);
  TEST_ASSERT_EQUAL_INT(g_stub_answer_count, g_stub_http_call_count);
  subdomain_destroyNameSet(name_set);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_lookupCertificates_page_reads_each_field_of_each_certificate);
  RUN_TEST(test_lookupCertificates_page_keeps_the_latest_certificates_that_fit);
  RUN_TEST(test_lookupCertificates_page_orders_a_tie_by_digest);
  RUN_TEST(test_lookupCertificates_page_drops_the_earliest_past_a_full_list);
  RUN_TEST(test_lookupCertificates_page_inserts_into_the_middle_of_a_list);
  RUN_TEST(test_lookupCertificates_page_empty_list_holds_no_certificate);
  RUN_TEST(test_lookupCertificates_page_refuses_a_body_that_is_not_a_list);
  RUN_TEST(test_lookupCertificates_page_leaves_out_a_certificate_it_cannot_read);
  RUN_TEST(test_lookupCertificates_page_list_of_refused_certificates_is_not_empty);
  RUN_TEST(test_lookupCertificates_page_reads_the_revocation);
  RUN_TEST(test_lookupCertificates_page_keeps_the_first_dns_names_and_counts_all);
  RUN_TEST(test_lookupCertificates_page_leaves_out_a_dns_name_that_does_not_fit);
  RUN_TEST(test_lookupCertificates_page_keeps_a_full_caa_list);
  RUN_TEST(test_lookupCertificates_page_leaves_a_caa_list_unknown_when_it_does_not_fit);
  RUN_TEST(test_lookupCertificates_page_leaves_out_an_issuer_name_that_does_not_fit);
  RUN_TEST(test_lookupCertificates_page_reads_a_caa_list_without_an_issuer_name);
  RUN_TEST(test_lookupCertificates_sends_the_longest_name_whole);
  RUN_TEST(test_lookupCertificates_sends_the_longest_key_whole);
  RUN_TEST(test_hasApiKey_follows_the_last_key_set);
  RUN_TEST(test_lookupCertificates_sends_each_request_with_the_key_and_reads_the_answer);
  RUN_TEST(test_lookupCertificates_without_a_key_sends_no_request);
  RUN_TEST(test_lookupCertificates_refuses_an_invalid_name_without_a_request);
  RUN_TEST(test_lookupCertificates_429_names_the_wait);
  RUN_TEST(test_lookupCertificates_answer_it_cannot_read_is_an_upstream_error);
  RUN_TEST(test_lookupCertificates_follows_a_short_page_until_an_empty_one);
  RUN_TEST(test_lookupCertificates_reads_at_most_the_page_cap);
  RUN_TEST(test_lookupCertificates_reserves_each_request_and_a_refusal_ends_the_walk);
  RUN_TEST(test_lookupCertificates_failed_request_after_a_page_cuts_the_walk);
  RUN_TEST(test_lookupCertificates_page_without_a_last_id_cuts_the_walk);
  RUN_TEST(test_lookupCertificates_failed_check_past_the_cap_cuts_the_walk);
  RUN_TEST(test_lookupCertificates_follows_the_longest_id_after_the_longest_name);
  RUN_TEST(test_lookupCertificates_keeps_the_latest_over_every_page);
  RUN_TEST(test_lookupCertificates_page_fills_the_issuer_set);
  RUN_TEST(test_lookupCertificates_page_issuer_set_keeps_the_first_16);
  RUN_TEST(test_lookupCertificates_page_longest_issuer_key_fits_whole);
  RUN_TEST(test_lookupCertificates_page_repeated_issuer_keeps_the_kind_of_its_certificates);
  RUN_TEST(test_lookupCertificates_page_name_past_the_kept_ones_still_matches);
  RUN_TEST(test_tryReadSubdomainNames_adds_each_name_under_the_domain);
  RUN_TEST(test_tryReadSubdomainNames_adds_the_source_to_a_known_name);
  RUN_TEST(test_tryReadSubdomainNames_refuses_a_body_that_is_not_a_list);
  RUN_TEST(test_tryReadSubdomainNames_keeps_a_name_of_the_longest_length);
  RUN_TEST(test_tryReadSubdomainNames_empty_list_is_an_empty_answer);
  RUN_TEST(test_tryReadSubdomainNames_list_without_a_name_is_not_empty);
  RUN_TEST(test_lookupSubdomainNames_sends_one_request_for_the_subtree);
  RUN_TEST(test_lookupSubdomainNames_sends_the_longest_domain_whole);
  RUN_TEST(test_lookupSubdomainNames_429_names_the_wait);
  RUN_TEST(test_lookupSubdomainNames_without_a_key_or_a_valid_name_sends_no_request);
  RUN_TEST(test_lookupSubdomainNames_answer_it_cannot_read_is_an_upstream_error);
  return UNITY_END();
}
