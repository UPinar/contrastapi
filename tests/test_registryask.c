#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "registryask.h"

extern const char* const        g_stub_RDAP_default_server_base_url;
extern const RdapRegistration_t g_stub_RDAP_default_registration;
extern const char*              g_stub_RDAP_server_base_url;
extern RdapStatus_t             g_stub_RDAP_lookup_status;
extern RdapRegistration_t       g_stub_RDAP_registration;
extern unsigned int             g_stub_RDAP_retry_after_seconds;
extern int                      g_stub_RDAP_find_count;
extern int                      g_stub_RDAP_lookup_count;
extern char                     g_stub_RDAP_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                     g_stub_RDAP_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                     g_stub_RDAP_last_lookup_base_url[256];

extern const WhoisServer_t  g_stub_WHOIS_test_server;
extern const WhoisServer_t* g_stub_WHOIS_server;
extern WhoisStatus_t        g_stub_WHOIS_lookup_status;
extern RdapRegistration_t   g_stub_WHOIS_registration;
extern int                  g_stub_WHOIS_find_count;
extern int                  g_stub_WHOIS_lookup_count;
extern char                 g_stub_WHOIS_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                 g_stub_WHOIS_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern const WhoisServer_t* g_stub_WHOIS_last_lookup_server;

extern ThrottleStatus_t g_stub_THROTTLE_charge_status;
extern unsigned int     g_stub_THROTTLE_retry_after_seconds;
extern int              g_stub_THROTTLE_charge_count;
extern PGconn*          g_stub_THROTTLE_last_conn;
extern ThrottleRule_t   g_stub_THROTTLE_last_rule;
extern char             g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN + 1];
extern unsigned int     g_stub_THROTTLE_last_charged_count;

extern bool         g_stub_QUOTA_hold_read_result;
extern unsigned int g_stub_QUOTA_hold_seconds;
extern int          g_stub_QUOTA_hold_read_count;
extern PGconn*      g_stub_QUOTA_last_hold_read_conn;
extern char         g_stub_QUOTA_last_hold_read_name[];
extern int          g_stub_QUOTA_hold_set_count;
extern PGconn*      g_stub_QUOTA_last_hold_set_conn;
extern char         g_stub_QUOTA_last_hold_set_name[];
extern unsigned int g_stub_QUOTA_last_hold_set_seconds;

extern QuotaStatus_t g_stub_QUOTA_reserve_status;
extern int           g_stub_QUOTA_reserve_status_count;
extern int           g_stub_QUOTA_reserve_count;
extern PGconn*       g_stub_QUOTA_last_reserve_conn;
extern QuotaRule_t   g_stub_QUOTA_last_reserve_rule;

#define TEST_CONN       ((PGconn*)7)
#define TEST_DOMAIN     "example.test"
#define UNTOUCHED_RETRY 4242u

static const QuotaRule_t TEST_DAILY_QUOTA_RULE = { "test_daily_rule", 3600, 5 };

static RegistryAskServer_t g_rdapServer;
static RegistryAskServer_t g_whoisServer;

void setUp(void)
{
  g_stub_RDAP_server_base_url         = g_stub_RDAP_default_server_base_url;
  g_stub_RDAP_lookup_status           = RDAP_OK;
  g_stub_RDAP_registration            = g_stub_RDAP_default_registration;
  g_stub_RDAP_retry_after_seconds     = 0;
  g_stub_RDAP_find_count              = 0;
  g_stub_RDAP_lookup_count            = 0;
  g_stub_RDAP_last_find_name[0]       = '\0';
  g_stub_RDAP_last_lookup_name[0]     = '\0';
  g_stub_RDAP_last_lookup_base_url[0] = '\0';
  g_stub_WHOIS_server                 = NULL;
  g_stub_WHOIS_lookup_status          = WHOIS_OK;
  g_stub_WHOIS_registration           = g_stub_RDAP_default_registration;
  g_stub_WHOIS_find_count             = 0;
  g_stub_WHOIS_lookup_count           = 0;
  g_stub_WHOIS_last_find_name[0]      = '\0';
  g_stub_WHOIS_last_lookup_name[0]    = '\0';
  g_stub_WHOIS_last_lookup_server     = NULL;
  g_stub_THROTTLE_charge_status       = THROTTLE_CHARGED;
  g_stub_THROTTLE_retry_after_seconds = 0;
  g_stub_THROTTLE_charge_count        = 0;
  g_stub_THROTTLE_last_conn           = NULL;
  memset(&g_stub_THROTTLE_last_rule, 0, sizeof(g_stub_THROTTLE_last_rule));
  g_stub_THROTTLE_last_target_name[0] = '\0';
  g_stub_THROTTLE_last_charged_count  = 0;
  g_stub_QUOTA_hold_read_result       = true;
  g_stub_QUOTA_hold_seconds           = 0;
  g_stub_QUOTA_hold_read_count        = 0;
  g_stub_QUOTA_last_hold_read_conn    = NULL;
  g_stub_QUOTA_last_hold_read_name[0] = '\0';
  g_stub_QUOTA_hold_set_count         = 0;
  g_stub_QUOTA_last_hold_set_conn     = NULL;
  g_stub_QUOTA_last_hold_set_name[0]  = '\0';
  g_stub_QUOTA_last_hold_set_seconds  = 0;
  g_stub_QUOTA_reserve_status         = QUOTA_GRANTED;
  g_stub_QUOTA_reserve_status_count   = 0;
  g_stub_QUOTA_reserve_count          = 0;
  g_stub_QUOTA_last_reserve_conn      = NULL;
  memset(&g_stub_QUOTA_last_reserve_rule, 0, sizeof(g_stub_QUOTA_last_reserve_rule));

  g_rdapServer.mp_rdapServerBaseUrl  = g_stub_RDAP_default_server_base_url;
  g_rdapServer.mp_whoisServer        = NULL;
  g_whoisServer.mp_rdapServerBaseUrl = NULL;
  g_whoisServer.mp_whoisServer       = &g_stub_WHOIS_test_server;
}
void tearDown(void) {}

static RegistryAskStatus_t static_ask(const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const RegistryAskServer_t* server, RdapRegistration_t* registration_out, unsigned int* retry_out)
{
  memset(registration_out, 0, sizeof(*registration_out));
  snprintf(registration_out->ma_registrarName, sizeof(registration_out->ma_registrarName), "%s", "untouched");
  *retry_out = UNTOUCHED_RETRY;
  return registryask_askDomain(TEST_CONN, throttle_rules, daily_quota_rule, server, TEST_DOMAIN, registration_out, retry_out);
}

static void static_assertCharged(const char* rule_name, unsigned int charge_limit, const char* target_name)
{
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_TRUE(g_stub_THROTTLE_last_conn == TEST_CONN);
  TEST_ASSERT_NOT_NULL(g_stub_THROTTLE_last_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_STRING(rule_name, g_stub_THROTTLE_last_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60, g_stub_THROTTLE_last_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(charge_limit, g_stub_THROTTLE_last_rule.m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING(target_name, g_stub_THROTTLE_last_target_name);
  TEST_ASSERT_EQUAL_UINT(1, g_stub_THROTTLE_last_charged_count);
}

void test_askDomain_passes_the_rdap_rule_and_host_to_the_throttle(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(0, retry);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_read_name);
  static_assertCharged("rdap", 30, "rdap.example.test");
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_STRING(TEST_DOMAIN, g_stub_RDAP_last_lookup_name);
  TEST_ASSERT_EQUAL_STRING(g_stub_RDAP_default_server_base_url, g_stub_RDAP_last_lookup_base_url);
  TEST_ASSERT_EQUAL_STRING(g_stub_RDAP_default_registration.ma_registrarName, registration.ma_registrarName);
  TEST_ASSERT_EQUAL_STRING(g_stub_RDAP_default_registration.ma_expiresAt, registration.ma_expiresAt);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);

  setUp();
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, &g_rdapServer, &registration, &retry));
  static_assertCharged("rdap", 10, "rdap.example.test");
}

void test_askDomain_passes_the_whois_rule_and_server_host(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &g_whoisServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(0, retry);
  static_assertCharged("whois", 10, "whois.example.test");
  TEST_ASSERT_EQUAL_INT(1, g_stub_WHOIS_lookup_count);
  TEST_ASSERT_EQUAL_STRING(TEST_DOMAIN, g_stub_WHOIS_last_lookup_name);
  TEST_ASSERT_TRUE(g_stub_WHOIS_last_lookup_server == &g_stub_WHOIS_test_server);
  TEST_ASSERT_EQUAL_STRING(g_stub_RDAP_default_registration.ma_registrarName, registration.ma_registrarName);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);

  setUp();
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, &g_whoisServer, &registration, &retry));
  static_assertCharged("whois", 3, "whois.example.test");
}

void test_askDomain_held_rdap_server_sends_nothing(void)
{
  g_stub_QUOTA_hold_seconds = 120;
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(120, retry);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_STRING("untouched", registration.ma_registrarName);

  setUp();
  g_stub_QUOTA_hold_seconds = 1;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(1, retry);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
}

void test_askDomain_watchlist_scan_takes_a_daily_call_only_when_the_request_goes(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  g_stub_QUOTA_hold_seconds = 30;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);

  const RegistryAskServer_t* servers[2] = { &g_rdapServer, &g_whoisServer };
  for (int k = 0; k < 2; k++)
  {
    const char* message = k == 0 ? "rdap" : "whois";
    setUp();
    g_stub_THROTTLE_charge_status       = THROTTLE_REFUSED;
    g_stub_THROTTLE_retry_after_seconds = 17;
    TEST_ASSERT_EQUAL_INT_MESSAGE(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, servers[k], &registration, &retry), message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(17, retry, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_reserve_count, message);

    setUp();
    TEST_ASSERT_EQUAL_INT_MESSAGE(REGISTRYASK_OK, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, servers[k], &registration, &retry), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_THROTTLE_charge_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_reserve_count, message);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_QUOTA_last_reserve_conn == TEST_CONN, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("test_daily_rule", g_stub_QUOTA_last_reserve_rule.mp_sourceName, message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(3600, g_stub_QUOTA_last_reserve_rule.m_windowSeconds, message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(5,    g_stub_QUOTA_last_reserve_rule.m_callLimit, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_RDAP_lookup_count + g_stub_WHOIS_lookup_count, message);
  }

  setUp();
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
}

void test_askDomain_refused_or_unread_daily_call_sends_nothing(void)
{
  static const struct {
    QuotaStatus_t       m_quotaStatus;
    RegistryAskStatus_t m_askStatus;
  } cases[] = {
    { QUOTA_EXHAUSTED, REGISTRYASK_DAILY_QUOTA_EXHAUSTED },
    { QUOTA_ERROR,     REGISTRYASK_DB_ERROR              },
  };
  const RegistryAskServer_t* servers[2] = { &g_rdapServer, &g_whoisServer };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
    for (int k = 0; k < 2; k++)
    {
      char message[24] = "";
      snprintf(message, sizeof(message), "case %zu %s", c, k == 0 ? "rdap" : "whois");
      setUp();
      g_stub_QUOTA_reserve_status = cases[c].m_quotaStatus;
      RdapRegistration_t registration;
      unsigned int       retry = 0;
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_askStatus, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, servers[k], &registration, &retry), message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_THROTTLE_charge_count, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_reserve_count, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_RDAP_lookup_count, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_WHOIS_lookup_count, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", registration.ma_registrarName, message);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(0, retry, message);
    }
}

void test_askDomain_full_count_sends_nothing(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  g_stub_THROTTLE_charge_status       = THROTTLE_REFUSED;
  g_stub_THROTTLE_retry_after_seconds = 42;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(42, retry);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);

  setUp();
  g_stub_THROTTLE_charge_status       = THROTTLE_REFUSED;
  g_stub_THROTTLE_retry_after_seconds = 42;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_userRequestThrottleRules, NULL, &g_whoisServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(42, retry);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_lookup_count);
}

void test_askDomain_429_holds_the_server_for_its_retry_after(void)
{
  g_stub_RDAP_lookup_status       = RDAP_RATE_LIMITED;
  g_stub_RDAP_retry_after_seconds = 90;
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UNAVAILABLE, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_UINT(90, retry);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_set_conn == TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_set_name);
  TEST_ASSERT_EQUAL_UINT(90, g_stub_QUOTA_last_hold_set_seconds);
}

void test_askDomain_whois_reads_and_sets_no_hold(void)
{
  g_stub_QUOTA_hold_seconds = 120;
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &g_whoisServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WHOIS_lookup_count);
}

void test_askDomain_maps_each_lookup_status(void)
{
  static const struct {
    RdapStatus_t        m_rdapStatus;
    WhoisStatus_t       m_whoisStatus;
    RegistryAskStatus_t m_expected;
  } CASES[] = {
    { RDAP_OK,             WHOIS_OK,             REGISTRYASK_OK             },
    { RDAP_NOT_REGISTERED, WHOIS_NOT_REGISTERED, REGISTRYASK_NOT_REGISTERED },
    { RDAP_UPSTREAM_ERROR, WHOIS_UPSTREAM_ERROR, REGISTRYASK_UPSTREAM_ERROR },
    { RDAP_INVALID_NAME,   WHOIS_INVALID_NAME,   REGISTRYASK_INVALID_NAME   },
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    RdapRegistration_t registration;
    unsigned int       retry = 0;
    setUp();
    g_stub_RDAP_lookup_status = CASES[i].m_rdapStatus;
    TEST_ASSERT_EQUAL_INT(CASES[i].m_expected, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
    TEST_ASSERT_EQUAL_UINT(0, retry);
    TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
    setUp();
    g_stub_WHOIS_lookup_status = CASES[i].m_whoisStatus;
    TEST_ASSERT_EQUAL_INT(CASES[i].m_expected, static_ask(&registryask_userRequestThrottleRules, NULL, &g_whoisServer, &registration, &retry));
    TEST_ASSERT_EQUAL_UINT(0, retry);
  }
}

void test_askDomain_unreadable_hold_or_count_is_a_db_error(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  g_stub_QUOTA_hold_read_result = false;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_DB_ERROR, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);

  setUp();
  g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_DB_ERROR, static_ask(&registryask_userRequestThrottleRules, NULL, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);

  setUp();
  g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_DB_ERROR, static_ask(&registryask_userRequestThrottleRules, NULL, &g_whoisServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_lookup_count);
}

void test_askDomain_watchlist_scan_unread_hold_or_count_takes_no_daily_call(void)
{
  RdapRegistration_t registration;
  unsigned int       retry = 0;
  g_stub_QUOTA_hold_read_result = false;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_DB_ERROR, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, &g_rdapServer, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);

  const RegistryAskServer_t* servers[2] = { &g_rdapServer, &g_whoisServer };
  for (int k = 0; k < 2; k++)
  {
    const char* message = k == 0 ? "rdap" : "whois";
    setUp();
    g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
    TEST_ASSERT_EQUAL_INT_MESSAGE(REGISTRYASK_DB_ERROR, static_ask(&registryask_watchlistScanThrottleRules, &TEST_DAILY_QUOTA_RULE, servers[k], &registration, &retry), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_THROTTLE_charge_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_reserve_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_RDAP_lookup_count + g_stub_WHOIS_lookup_count, message);
  }
}

void test_askDomain_names_the_host_of_the_base_url(void)
{
  RdapRegistration_t  registration;
  unsigned int        retry = 0;
  RegistryAskServer_t server = { "https://rdap.example.test:8443/rdap/", NULL };
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &server, &registration, &retry));
  TEST_ASSERT_EQUAL_STRING("rdap.example.test", g_stub_THROTTLE_last_target_name);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_read_name);

  static const char* const NO_HOST[] = { "http://rdap.example.test/", "https:///", "https://:443/", "rdap.example.test/" };
  for (size_t i = 0; i < sizeof(NO_HOST) / sizeof(NO_HOST[0]); i++)
  {
    setUp();
    server.mp_rdapServerBaseUrl = NO_HOST[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(REGISTRYASK_UPSTREAM_ERROR, static_ask(&registryask_userRequestThrottleRules, NULL, &server, &registration, &retry), NO_HOST[i]);
    TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
    TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
    TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  }

  char url[400];
  char host[THROTTLE_TARGET_NAME_MAX_LEN + 2];
  memset(host, 'a', THROTTLE_TARGET_NAME_MAX_LEN);
  host[THROTTLE_TARGET_NAME_MAX_LEN] = '\0';
  snprintf(url, sizeof(url), "https://%s/", host);
  setUp();
  server.mp_rdapServerBaseUrl = url;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_OK, static_ask(&registryask_userRequestThrottleRules, NULL, &server, &registration, &retry));
  TEST_ASSERT_EQUAL_STRING(host, g_stub_THROTTLE_last_target_name);

  host[THROTTLE_TARGET_NAME_MAX_LEN]     = 'a';
  host[THROTTLE_TARGET_NAME_MAX_LEN + 1] = '\0';
  snprintf(url, sizeof(url), "https://%s/", host);
  setUp();
  server.mp_rdapServerBaseUrl = url;
  TEST_ASSERT_EQUAL_INT(REGISTRYASK_UPSTREAM_ERROR, static_ask(&registryask_userRequestThrottleRules, NULL, &server, &registration, &retry));
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
}

void test_tryFindServer_prefers_rdap_then_whois_then_none(void)
{
  RegistryAskServer_t server = { "stale", &g_stub_WHOIS_test_server };
  g_stub_WHOIS_server = &g_stub_WHOIS_test_server;
  TEST_ASSERT_TRUE(registryask_tryFindServer(TEST_DOMAIN, &server));
  TEST_ASSERT_EQUAL_PTR(g_stub_RDAP_default_server_base_url, server.mp_rdapServerBaseUrl);
  TEST_ASSERT_NULL(server.mp_whoisServer);
  TEST_ASSERT_EQUAL_STRING(TEST_DOMAIN, g_stub_RDAP_last_find_name);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_find_count);

  setUp();
  g_stub_RDAP_server_base_url = NULL;
  g_stub_WHOIS_server         = &g_stub_WHOIS_test_server;
  server.mp_rdapServerBaseUrl = "stale";
  TEST_ASSERT_TRUE(registryask_tryFindServer(TEST_DOMAIN, &server));
  TEST_ASSERT_NULL(server.mp_rdapServerBaseUrl);
  TEST_ASSERT_TRUE(server.mp_whoisServer == &g_stub_WHOIS_test_server);
  TEST_ASSERT_EQUAL_STRING(TEST_DOMAIN, g_stub_WHOIS_last_find_name);

  setUp();
  g_stub_RDAP_server_base_url = NULL;
  server.mp_rdapServerBaseUrl = "stale";
  server.mp_whoisServer       = &g_stub_WHOIS_test_server;
  TEST_ASSERT_FALSE(registryask_tryFindServer(TEST_DOMAIN, &server));
  TEST_ASSERT_NULL(server.mp_rdapServerBaseUrl);
  TEST_ASSERT_NULL(server.mp_whoisServer);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
}

void test_rules_share_names_and_windows_and_leave_users_the_larger_share(void)
{
  const RegistryAskThrottleRules_t* user_request = &registryask_userRequestThrottleRules;
  const RegistryAskThrottleRules_t* watchlist_scan   = &registryask_watchlistScanThrottleRules;
  TEST_ASSERT_EQUAL_STRING("rdap",  user_request->mp_rdapRule->mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60,        user_request->mp_rdapRule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(30,        user_request->mp_rdapRule->m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING("whois", user_request->mp_whoisRule->mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60,        user_request->mp_whoisRule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(10,        user_request->mp_whoisRule->m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING("rdap",  watchlist_scan->mp_rdapRule->mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60,        watchlist_scan->mp_rdapRule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(10,        watchlist_scan->mp_rdapRule->m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING("whois", watchlist_scan->mp_whoisRule->mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60,        watchlist_scan->mp_whoisRule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(3,         watchlist_scan->mp_whoisRule->m_chargeLimit);
  TEST_ASSERT_TRUE(watchlist_scan->mp_rdapRule->m_chargeLimit  < user_request->mp_rdapRule->m_chargeLimit);
  TEST_ASSERT_TRUE(watchlist_scan->mp_whoisRule->m_chargeLimit < user_request->mp_whoisRule->m_chargeLimit);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(15, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_askDomain_passes_the_rdap_rule_and_host_to_the_throttle);
  RUN_TEST(test_askDomain_passes_the_whois_rule_and_server_host);
  RUN_TEST(test_askDomain_held_rdap_server_sends_nothing);
  RUN_TEST(test_askDomain_full_count_sends_nothing);
  RUN_TEST(test_askDomain_watchlist_scan_takes_a_daily_call_only_when_the_request_goes);
  RUN_TEST(test_askDomain_refused_or_unread_daily_call_sends_nothing);
  RUN_TEST(test_askDomain_429_holds_the_server_for_its_retry_after);
  RUN_TEST(test_askDomain_whois_reads_and_sets_no_hold);
  RUN_TEST(test_askDomain_maps_each_lookup_status);
  RUN_TEST(test_askDomain_unreadable_hold_or_count_is_a_db_error);
  RUN_TEST(test_askDomain_watchlist_scan_unread_hold_or_count_takes_no_daily_call);
  RUN_TEST(test_askDomain_names_the_host_of_the_base_url);
  RUN_TEST(test_tryFindServer_prefers_rdap_then_whois_then_none);
  RUN_TEST(test_rules_share_names_and_windows_and_leave_users_the_larger_share);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
