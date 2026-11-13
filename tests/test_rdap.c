#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "external/rdap.h"
#include "http_stub.h"

static const char RDAP_TEST_ANSWER[] = R"({
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "server transfer prohibited"],
  "entities": [
    {"objectClassName": "entity", "roles": ["registrant"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrant Person"]]]},
    {"objectClassName": "entity", "roles": ["technical", "registrar"],
     "publicIds": [{"type": "Other ID", "identifier": "555"}, {"type": "IANA Registrar ID", "identifier": "376"}],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Test Registrar, Inc."]]]}
  ],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "last update of RDAP database", "eventDate": "2026-10-24T08:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:31Z"}
  ],
  "nameservers": [
    {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
    {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"}
  ],
  "secureDNS": {"delegationSigned": true}
})";

#define VERISIGN_COM_BASE_URL "https://rdap.verisign.com/com/v1/"

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
}

void tearDown(void) {}

static bool static_tryReadAnswer(const char* body, RdapRegistration_t* registration_out)
{
  return rdap_tryReadDomain(body, strlen(body), registration_out);
}

void test_servers_are_sorted_lower_case_https_base_urls(void)
{
  TEST_ASSERT_GREATER_THAN_INT(1000, rdap_serverCount);
  for (int i = 0; i < rdap_serverCount; i++)
  {
    TEST_ASSERT_EQUAL_INT(0, strncmp(rdap_servers[i].mp_baseUrl, "https://", strlen("https://")));
    TEST_ASSERT_EQUAL_CHAR('/', rdap_servers[i].mp_baseUrl[strlen(rdap_servers[i].mp_baseUrl) - 1]);
    for (const char* byte = rdap_servers[i].mp_tld; *byte != '\0'; byte++)
      TEST_ASSERT_FALSE(*byte >= 'A' && *byte <= 'Z');
    if (i > 0)
      TEST_ASSERT_LESS_THAN_INT(0, strcmp(rdap_servers[i - 1].mp_tld, rdap_servers[i].mp_tld));
  }
}

void test_findServerBaseUrl_reads_the_last_label(void)
{
  TEST_ASSERT_EQUAL_STRING(VERISIGN_COM_BASE_URL, rdap_findServerBaseUrl("example.com"));
  TEST_ASSERT_EQUAL_STRING("https://rdap.nominet.uk/uk/", rdap_findServerBaseUrl("www.example.co.uk"));
  TEST_ASSERT_EQUAL_STRING(VERISIGN_COM_BASE_URL, rdap_findServerBaseUrl("com"));
}

void test_findServerBaseUrl_ignores_case(void)
{
  TEST_ASSERT_EQUAL_STRING(VERISIGN_COM_BASE_URL, rdap_findServerBaseUrl("Example.COM"));
}

void test_findServerBaseUrl_finds_the_first_and_the_last_entry(void)
{
  TEST_ASSERT_EQUAL_STRING(rdap_servers[0].mp_baseUrl, rdap_findServerBaseUrl(rdap_servers[0].mp_tld));
  TEST_ASSERT_EQUAL_STRING(rdap_servers[rdap_serverCount - 1].mp_baseUrl,
                           rdap_findServerBaseUrl(rdap_servers[rdap_serverCount - 1].mp_tld));
}

void test_findServerBaseUrl_tld_without_server_is_null(void)
{
  TEST_ASSERT_NULL(rdap_findServerBaseUrl("example.de"));
  TEST_ASSERT_NULL(rdap_findServerBaseUrl("example.tr"));
  TEST_ASSERT_NULL(rdap_findServerBaseUrl("example.kg"));
}

void test_tryReadDomain_reads_every_field(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(RDAP_TEST_ANSWER, &registration));
  TEST_ASSERT_EQUAL_STRING("Test Registrar, Inc.", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(376, registration.m_registrarIanaId);
  TEST_ASSERT_EQUAL_STRING("1995-08-14T04:00:00Z", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2026-08-14T07:01:31Z", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("2027-08-13T04:00:00Z", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(2, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("client delete prohibited", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_STRING("server transfer prohibited", registration.ma_statuses[1]);
  TEST_ASSERT_EQUAL_INT(2, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("a.iana-servers.net", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("b.iana-servers.net", registration.ma_nameServers[1]);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_YES, registration.m_delegationSigned);
}

void test_tryReadDomain_needs_a_domain_object(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"({"objectClassName": "nameserver", "status": ["active"]})", &registration));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"({"status": ["active"]})", &registration));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"(["domain"])", &registration));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"({"objectClassName": "domain", "status": [)", &registration));
}

void test_tryReadDomain_lacking_fields_read_as_empty(void)
{
  RdapRegistration_t registration;
  memset(&registration, 'x', sizeof(registration));
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain"})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_updatedAt);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(0, registration.m_statusCount);
  TEST_ASSERT_EQUAL_INT(0, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_UNKNOWN, registration.m_delegationSigned);
}

void test_tryReadDomain_first_event_of_a_kind_wins(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "events": [
    {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"},
    {"eventAction": "registration", "eventDate": "2002-02-02T00:00:00Z"}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("2001-01-01T00:00:00Z", registration.ma_createdAt);
}

void test_tryReadDomain_unreadable_date_stays_empty(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "events": [
    {"eventAction": "registration", "eventDate": "123456789012345678901234567890123456789012345678901234567890123"},
    {"eventAction": "expiration", "eventDate": "1234567890123456789012345678901234567890123456789012345678901234"},
    {"eventAction": "last changed", "eventDate": 20260814}]})", &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_DATE_MAX_LEN, (int)strlen(registration.ma_createdAt));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_STRING("", registration.ma_updatedAt);
}

void test_tryReadDomain_skips_an_unreadable_event_and_reads_the_next(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "events": [
    {"eventAction": "registration"},
    {"eventAction": "expiration", "eventDate": 7},
    {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
    {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("2001-01-01T00:00:00Z", registration.ma_createdAt);
  TEST_ASSERT_EQUAL_STRING("2027-01-01T00:00:00Z", registration.ma_expiresAt);
}

void test_tryReadDomain_skips_an_entity_without_the_registrar_role(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrant"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "111"}],
     "vcardArray": ["vcard", [["fn", {}, "text", "Registrant Person"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);
}

void test_tryReadDomain_skips_an_entity_without_roles(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"publicIds": [{"type": "IANA Registrar ID", "identifier": "111"}],
     "vcardArray": ["vcard", [["fn", {}, "text", "No Roles"]]]},
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "82"}],
     "vcardArray": ["vcard", [["fn", {}, "text", "Second Registrar"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("Second Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(82, registration.m_registrarIanaId);
}

void test_tryReadDomain_first_registrar_wins(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "81"}],
     "vcardArray": ["vcard", [["fn", {}, "text", "First Registrar"]]]},
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "82"}],
     "vcardArray": ["vcard", [["fn", {}, "text", "Second Registrar"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("First Registrar", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(81, registration.m_registrarIanaId);
}

void test_tryReadDomain_registrar_name_decodes_escapes(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Caf\u00e9 Registrar"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("Caf\xc3\xa9 Registrar", registration.ma_registrarName);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Bad\u0000Name"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
}

void test_tryReadDomain_registrar_name_needs_a_vcard_tag_and_four_parts(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["card", [["fn", {}, "text", "Wrong Tag"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["org", {}, "text", "Org Name"], ["fn", {}, "text", "Second Property"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("Second Property", registration.ma_registrarName);
}

void test_tryReadDomain_only_the_first_fn_counts(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", 5], ["fn", {}, "text", "Second"]]]}]})", &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
}

void test_tryReadDomain_registrar_name_of_the_longest_length_fits(void)
{
  char name[RDAP_REGISTRAR_NAME_MAX_LEN + 2];
  memset(name, 'n', sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';

  char body[1024];
  RdapRegistration_t registration;
  name[RDAP_REGISTRAR_NAME_MAX_LEN] = '\0';
  snprintf(body, sizeof(body), R"({"objectClassName": "domain", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "%s"]]]}]})", name);
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_REGISTRAR_NAME_MAX_LEN, (int)strlen(registration.ma_registrarName));

  name[RDAP_REGISTRAR_NAME_MAX_LEN] = 'n';
  snprintf(body, sizeof(body), R"({"objectClassName": "domain", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "%s"]]]}]})", name);
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, &registration));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
}

void test_tryReadDomain_iana_registrar_id_must_be_one_to_nine_digits(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "123456789"}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(123456789, registration.m_registrarIanaId);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "1234567890"}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "12a"}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": ""}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": 376}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);
}

void test_tryReadDomain_iana_registrar_id_skips_an_unreadable_one_and_reads_decimal(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "entities": [
    {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "12a"},
                                           {"type": "IANA Registrar ID", "identifier": "0376"}]}]})", &registration));
  TEST_ASSERT_EQUAL_INT64(376, registration.m_registrarIanaId);
}

void test_tryReadDomain_lists_the_first_statuses_and_counts_them_all(void)
{
  char body[2048];
  size_t used = (size_t)snprintf(body, sizeof(body), R"({"objectClassName": "domain", "status": [)");
  for (int i = 0; i <= RDAP_STATUS_MAX_COUNT; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, "%s\"status %d\"", i > 0 ? ", " : "", i);
  snprintf(body + used, sizeof(body) - used, "]}");

  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_STATUS_MAX_COUNT + 1, registration.m_statusCount);
  TEST_ASSERT_EQUAL_STRING("status 0", registration.ma_statuses[0]);
  TEST_ASSERT_EQUAL_STRING("status 15", registration.ma_statuses[RDAP_STATUS_MAX_COUNT - 1]);
}

void test_tryReadDomain_skips_an_unreadable_status(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "status": [
    "", 7, "123456789012345678901234567890123456789012345678901234567890123",
    "1234567890123456789012345678901234567890123456789012345678901234", "active"]})", &registration));
  TEST_ASSERT_EQUAL_INT(2, registration.m_statusCount);
  TEST_ASSERT_EQUAL_INT(RDAP_STATUS_MAX_LEN, (int)strlen(registration.ma_statuses[0]));
  TEST_ASSERT_EQUAL_STRING("active", registration.ma_statuses[1]);
}

void test_tryReadDomain_lists_the_first_name_servers_and_counts_them_all(void)
{
  char body[2048];
  size_t used = (size_t)snprintf(body, sizeof(body), R"({"objectClassName": "domain", "nameservers": [)");
  for (int i = 0; i <= RDAP_NAME_SERVER_MAX_COUNT; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, R"(%s{"ldhName": "NS%d.EXAMPLE.NET"})", i > 0 ? ", " : "", i);
  snprintf(body + used, sizeof(body) - used, "]}");

  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_NAME_SERVER_MAX_COUNT + 1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns0.example.net", registration.ma_nameServers[0]);
  TEST_ASSERT_EQUAL_STRING("ns15.example.net", registration.ma_nameServers[RDAP_NAME_SERVER_MAX_COUNT - 1]);
}

void test_tryReadDomain_skips_a_name_server_that_is_not_a_domain_name(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "nameservers": [
    {"ldhName": "bad name.example.net"}, {"ldhName": 5}, {"handle": "NS1"}, "ns.example.net",
    {"ldhName": "ns2.example.net"}]})", &registration));
  TEST_ASSERT_EQUAL_INT(1, registration.m_nameServerCount);
  TEST_ASSERT_EQUAL_STRING("ns2.example.net", registration.ma_nameServers[0]);
}

void test_tryReadDomain_delegation_signed_false_and_unreadable(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "secureDNS": {"delegationSigned": false}})", &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_NO, registration.m_delegationSigned);

  TEST_ASSERT_TRUE(static_tryReadAnswer(R"({"objectClassName": "domain", "secureDNS": {"delegationSigned": "true"}})", &registration));
  TEST_ASSERT_EQUAL_INT(RDAP_DELEGATION_SIGNED_UNKNOWN, registration.m_delegationSigned);
}

void test_lookupDomain_sends_a_trusted_request_for_the_name(void)
{
  g_stub_next_body = RDAP_TEST_ANSWER;
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(RDAP_OK, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(VERISIGN_COM_BASE_URL "domain/example.com", g_stub_last_url);
  TEST_ASSERT_EQUAL_STRING("Accept: application/rdap+json", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_size_t(256 * 1024, g_stub_last_max_body_byte_count);
  TEST_ASSERT_TRUE(g_stub_last_is_target_trusted);
  TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_STRING("Test Registrar, Inc.", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupDomain_404_is_not_registered(void)
{
  g_stub_next_status = 404;
  g_stub_next_body   = RDAP_TEST_ANSWER;
  RdapRegistration_t registration;
  memset(&registration, 'x', sizeof(registration));
  TEST_ASSERT_EQUAL_INT(RDAP_NOT_REGISTERED, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("", registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT64(-1, registration.m_registrarIanaId);
}

void test_lookupDomain_other_answers_are_upstream_errors(void)
{
  RdapRegistration_t registration;

  g_stub_next_status = 500;
  g_stub_next_body   = RDAP_TEST_ANSWER;
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));

  g_stub_next_status = 203;
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));

  g_stub_next_status = 200;
  g_stub_next_body   = R"({"objectClassName": "entity"})";
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));

  g_stub_next_body      = RDAP_TEST_ANSWER;
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));

  g_stub_next_body_null = false;
  g_stub_next_error     = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(5, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupDomain_429_is_rate_limited_with_its_wait(void)
{
  static const char* const seconds_header[] = { "Retry-After: 120", NULL };
  static const char* const date_header[]    = { "Retry-After: Wed, 21 Oct 2026 07:28:00 GMT", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 429, .mp_headerLines = seconds_header },
    { .m_status = 429 },
    { .m_status = 429, .mp_headerLines = date_header },
    { .m_status = 503, .mp_headerLines = seconds_header },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = (int)(sizeof(answers) / sizeof(answers[0]));
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(RDAP_RATE_LIMITED, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(120, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(RDAP_RATE_LIMITED, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(RDAP_RATE_LIMITED, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(RDAP_UPSTREAM_ERROR, rdap_lookupDomain("example.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_lookupDomain_invalid_name_sends_no_request(void)
{
  RdapRegistration_t registration;
  TEST_ASSERT_EQUAL_INT(RDAP_INVALID_NAME, rdap_lookupDomain("bad name.com", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(RDAP_INVALID_NAME, rdap_lookupDomain("example.com/../x", VERISIGN_COM_BASE_URL, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_lookupDomain_url_of_the_longest_length_is_sent(void)
{
  const char* domain_name = "example.com";
  char base_url[512];
  size_t base_len = 512 - strlen("domain/") - strlen(domain_name);
  memset(base_url, 'b', base_len);
  base_url[base_len] = '\0';

  RdapRegistration_t registration;
  g_stub_next_body = RDAP_TEST_ANSWER;
  TEST_ASSERT_EQUAL_INT(RDAP_OK, rdap_lookupDomain(domain_name, base_url, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);

  base_url[base_len]     = 'b';
  base_url[base_len + 1] = '\0';
  TEST_ASSERT_EQUAL_INT(RDAP_INVALID_NAME, rdap_lookupDomain(domain_name, base_url, &registration, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_servers_are_sorted_lower_case_https_base_urls);
  RUN_TEST(test_findServerBaseUrl_reads_the_last_label);
  RUN_TEST(test_findServerBaseUrl_ignores_case);
  RUN_TEST(test_findServerBaseUrl_finds_the_first_and_the_last_entry);
  RUN_TEST(test_findServerBaseUrl_tld_without_server_is_null);
  RUN_TEST(test_tryReadDomain_reads_every_field);
  RUN_TEST(test_tryReadDomain_needs_a_domain_object);
  RUN_TEST(test_tryReadDomain_lacking_fields_read_as_empty);
  RUN_TEST(test_tryReadDomain_first_event_of_a_kind_wins);
  RUN_TEST(test_tryReadDomain_unreadable_date_stays_empty);
  RUN_TEST(test_tryReadDomain_skips_an_unreadable_event_and_reads_the_next);
  RUN_TEST(test_tryReadDomain_skips_an_entity_without_the_registrar_role);
  RUN_TEST(test_tryReadDomain_skips_an_entity_without_roles);
  RUN_TEST(test_tryReadDomain_first_registrar_wins);
  RUN_TEST(test_tryReadDomain_registrar_name_decodes_escapes);
  RUN_TEST(test_tryReadDomain_registrar_name_needs_a_vcard_tag_and_four_parts);
  RUN_TEST(test_tryReadDomain_only_the_first_fn_counts);
  RUN_TEST(test_tryReadDomain_registrar_name_of_the_longest_length_fits);
  RUN_TEST(test_tryReadDomain_iana_registrar_id_must_be_one_to_nine_digits);
  RUN_TEST(test_tryReadDomain_iana_registrar_id_skips_an_unreadable_one_and_reads_decimal);
  RUN_TEST(test_tryReadDomain_lists_the_first_statuses_and_counts_them_all);
  RUN_TEST(test_tryReadDomain_skips_an_unreadable_status);
  RUN_TEST(test_tryReadDomain_lists_the_first_name_servers_and_counts_them_all);
  RUN_TEST(test_tryReadDomain_skips_a_name_server_that_is_not_a_domain_name);
  RUN_TEST(test_tryReadDomain_delegation_signed_false_and_unreadable);
  RUN_TEST(test_lookupDomain_sends_a_trusted_request_for_the_name);
  RUN_TEST(test_lookupDomain_404_is_not_registered);
  RUN_TEST(test_lookupDomain_other_answers_are_upstream_errors);
  RUN_TEST(test_lookupDomain_429_is_rate_limited_with_its_wait);
  RUN_TEST(test_lookupDomain_invalid_name_sends_no_request);
  RUN_TEST(test_lookupDomain_url_of_the_longest_length_is_sent);
  return UNITY_END();
}
