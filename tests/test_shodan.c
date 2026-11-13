#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "unity/unity.h"
#include "external/shodan.h"
#include "http_stub.h"

#define TEST_KEY  "AbCdEfGhIjKlMnOpQrStUvWxYz012389"
#define TEST_IP   "192.0.2.7"

static const char SHODAN_FULL_BODY[] =
  "{\"area_code\":null,\"asn\":\"AS63949\",\"city\":\"Fremont\",\"country_code\":\"US\","
  "\"data\":[],\"domains\":[\"nmap.org\"],"
  "\"hostnames\":[\"scanme.nmap.org\",\"b.example\"],"
  "\"ip\":758194332,\"ip_str\":\"45.33.32.156\",\"isp\":\"Akamai\","
  "\"last_update\":\"2026-11-05T17:51:42.725642\",\"latitude\":37.5,\"longitude\":-121.9,"
  "\"org\":\"Akamai\",\"os\":null,\"ports\":[80,9929,123,22],\"region_code\":\"CA\","
  "\"tags\":[\"cloud\",\"vpn\"],"
  "\"vulns\":[\"CVE-2014-0160\",\"CVE-2021-44228\",\"CVE-2023-123456\"]}";

static unsigned int g_retryAfterSeconds;

static ShodanHost_t g_host;

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
  memset(g_stub_requests, 0, sizeof(g_stub_requests));
  memset(&g_host, 0, sizeof(g_host));
}

void tearDown(void)
{
  shodan_freeHost(&g_host);
}

static ShodanStatus_t static_lookupBody(const char* body)
{
  g_stub_next_body = body;
  return shodan_lookupHost(TEST_KEY, TEST_IP, &g_host, &g_retryAfterSeconds);
}

static ShodanStatus_t static_lookupStatus(int status)
{
  g_stub_next_status = status;
  return shodan_lookupHost(TEST_KEY, TEST_IP, &g_host, &g_retryAfterSeconds);
}

static void static_assertHostEmpty(void)
{
  TEST_ASSERT_NULL(g_host.mp_ports);
  TEST_ASSERT_NULL(g_host.m_vulns.mp_items);
  TEST_ASSERT_NULL(g_host.m_hostnames.mp_items);
  TEST_ASSERT_NULL(g_host.m_tags.mp_items);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_portCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_hostnames.m_count);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_skippedPortCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_hostnames.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_tags.m_skippedCount);
  TEST_ASSERT_EQUAL_STRING("", g_host.ma_lastUpdate);
}

static char* static_makeRun(char byte, size_t count)
{
  char* run = malloc(count + 1);
  TEST_ASSERT_NOT_NULL(run);
  memset(run, byte, count);
  run[count] = '\0';
  return run;
}

void test_lookupHost_sends_the_host_url_with_the_key_and_minify(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupStatus(200));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/shodan/host/" TEST_IP "?key=" TEST_KEY "&minify=true", g_stub_requests[0].ma_url);
}

void test_lookupHost_request_flags_timeout_and_cap(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupStatus(200));
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_EQUAL_INT(3000, SHODAN_TIMEOUT_MS);
  TEST_ASSERT_EQUAL_INT(3000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(262144, SHODAN_MAX_BODY_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(262144, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_header);
  TEST_ASSERT_EQUAL_STRING("", g_stub_requests[0].ma_headerNamesToCapture);
}

void test_checkKey_sends_the_api_info_url_with_the_key(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/api-info?key=" TEST_KEY, g_stub_requests[0].ma_url);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_EQUAL_INT(3000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(262144, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_header);
  TEST_ASSERT_EQUAL_STRING("", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupHost_maps_each_status(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupStatus(200));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  g_retryAfterSeconds = 7;
  TEST_ASSERT_EQUAL_INT(SHODAN_NOT_FOUND, static_lookupStatus(404));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  static_assertHostEmpty();
  g_retryAfterSeconds = 7;
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, static_lookupStatus(401));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, static_lookupStatus(403));
  g_retryAfterSeconds = 7;
  TEST_ASSERT_EQUAL_INT(SHODAN_RATE_LIMITED, static_lookupStatus(429));
  TEST_ASSERT_EQUAL_UINT(1, g_retryAfterSeconds);
}

void test_lookupHost_other_answers_are_unavailable(void)
{
  static const int statuses[] = { 500, 302, 400, 402, 201, 503 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    g_retryAfterSeconds = 7;
    TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, static_lookupStatus(statuses[i]));
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, static_lookupStatus(200));
}

void test_checkKey_maps_each_status(void)
{
  g_stub_next_status = 401;
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  g_stub_next_status = 403;
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
  g_stub_next_status = 429;
  TEST_ASSERT_EQUAL_INT(SHODAN_RATE_LIMITED, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(1, g_retryAfterSeconds);

  static const int statuses[] = { 404, 500, 302, 201 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    g_retryAfterSeconds = 7;
    g_stub_next_status  = statuses[i];
    TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
  g_stub_next_status = 200;
  g_stub_next_error  = HTTP_ERROR_CONNECT;
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
}

void test_checkKey_does_not_parse_the_body(void)
{
  g_stub_next_body = "not json";
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_checkKey(TEST_KEY, &g_retryAfterSeconds));
}

void test_refused_keys_send_no_request(void)
{
  static const char* const keys[] = {
    "ab-cd", "ab/cd", "ab&cd", "ab=cd", "ab?cd", "ab#cd", "ab%cd", "ab cd", "ab_cd", "ab.cd",
    "ab:cd", "ab@cd", "ab[cd", "ab`cd", "ab{cd", "ab\x80" "cd", "ab\xff", "-abcd", "abcd&", ""
  };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    g_retryAfterSeconds = 7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SHODAN_KEY_REJECTED, shodan_lookupHost(keys[i], TEST_IP, &g_host, &g_retryAfterSeconds), keys[i]);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
    g_retryAfterSeconds = 7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SHODAN_KEY_REJECTED, shodan_checkKey(keys[i], &g_retryAfterSeconds), keys[i]);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);

  char* too_long = static_makeRun('a', SHODAN_KEY_MAX_LEN + 1);
  ShodanStatus_t lookup_status = shodan_lookupHost(too_long, TEST_IP, &g_host, &g_retryAfterSeconds);
  ShodanStatus_t check_status  = shodan_checkKey(too_long, &g_retryAfterSeconds);
  free(too_long);
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, lookup_status);
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, check_status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_accepted_keys_are_sent_whole(void)
{
  TEST_ASSERT_EQUAL_INT(128, SHODAN_KEY_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_lookupHost("AZaz09", TEST_IP, &g_host, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/shodan/host/" TEST_IP "?key=AZaz09&minify=true", g_stub_last_url);
  shodan_freeHost(&g_host);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_checkKey("Q", &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/api-info?key=Q", g_stub_last_url);

  char* longest = static_makeRun('z', SHODAN_KEY_MAX_LEN);
  char  expected[512];
  snprintf(expected, sizeof(expected), "https://api.shodan.io/shodan/host/" TEST_IP "?key=%s&minify=true", longest);
  ShodanStatus_t lookup_status = shodan_lookupHost(longest, TEST_IP, &g_host, &g_retryAfterSeconds);
  char lookup_url[sizeof(g_stub_last_url)];
  memcpy(lookup_url, g_stub_last_url, sizeof(lookup_url));
  char expected_check[512];
  snprintf(expected_check, sizeof(expected_check), "https://api.shodan.io/api-info?key=%s", longest);
  ShodanStatus_t check_status = shodan_checkKey(longest, &g_retryAfterSeconds);
  free(longest);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, lookup_status);
  TEST_ASSERT_EQUAL_STRING(expected, lookup_url);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, check_status);
  TEST_ASSERT_EQUAL_STRING(expected_check, g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_refused_addresses_send_no_request(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, shodan_lookupHost(TEST_KEY, "", &g_host, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  char* too_long = static_makeRun('1', 46);
  ShodanStatus_t status = shodan_lookupHost(TEST_KEY, too_long, &g_host, &g_retryAfterSeconds);
  free(too_long);
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_longest_address_is_sent_whole(void)
{
  static const char longest[] = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
  TEST_ASSERT_EQUAL_size_t(45, strlen(longest));
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, shodan_lookupHost(TEST_KEY, longest, &g_host, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/shodan/host/ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255?key=" TEST_KEY "&minify=true", g_stub_last_url);
}

void test_lookupHost_reads_each_field(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody(SHODAN_FULL_BODY));
  TEST_ASSERT_EQUAL_size_t(4, g_host.m_portCount);
  TEST_ASSERT_EQUAL_INT(80,   g_host.mp_ports[0]);
  TEST_ASSERT_EQUAL_INT(9929, g_host.mp_ports[1]);
  TEST_ASSERT_EQUAL_INT(123,  g_host.mp_ports[2]);
  TEST_ASSERT_EQUAL_INT(22,   g_host.mp_ports[3]);
  TEST_ASSERT_EQUAL_size_t(3, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2014-0160",   g_host.m_vulns.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228",  g_host.m_vulns.mp_items[1]);
  TEST_ASSERT_EQUAL_STRING("CVE-2023-123456", g_host.m_vulns.mp_items[2]);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_hostnames.m_count);
  TEST_ASSERT_EQUAL_STRING("scanme.nmap.org", g_host.m_hostnames.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("b.example",       g_host.m_hostnames.mp_items[1]);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_STRING("cloud", g_host.m_tags.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("vpn",   g_host.m_tags.mp_items[1]);
  TEST_ASSERT_EQUAL_STRING("2026-11-05T17:51:42.725642", g_host.ma_lastUpdate);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_skippedPortCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_hostnames.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_tags.m_skippedCount);
}

void test_lookupHost_missing_or_empty_lists_are_empty(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"ip_str\":\"192.0.2.7\"}"));
  static_assertHostEmpty();
  shodan_freeHost(&g_host);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"ports\":[],\"vulns\":[ ],\"hostnames\":[],\"tags\":[]}"));
  static_assertHostEmpty();
}

void test_lookupHost_lists_of_one(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"ports\":[443],\"vulns\":[\"CVE-2020-0001\"],\"hostnames\":[\"h.example\"],\"tags\":[\"vpn\"]}"));
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_portCount);
  TEST_ASSERT_EQUAL_INT(443, g_host.mp_ports[0]);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2020-0001", g_host.m_vulns.mp_items[0]);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_hostnames.m_count);
  TEST_ASSERT_EQUAL_STRING("h.example", g_host.m_hostnames.mp_items[0]);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_STRING("vpn", g_host.m_tags.mp_items[0]);
}

void test_lookupHost_many_vulns(void)
{
  char* body = malloc(131 * 20 + 32);
  TEST_ASSERT_NOT_NULL(body);
  size_t used = (size_t)sprintf(body, "{\"vulns\":[");
  for (int i = 0; i < 131; i++)
    used += (size_t)sprintf(body + used, "%s\"CVE-2020-%04d\"", i > 0 ? "," : "", 1000 + i);
  sprintf(body + used, "]}");
  ShodanStatus_t status = static_lookupBody(body);
  free(body);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, status);
  TEST_ASSERT_EQUAL_size_t(131, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2020-1000", g_host.m_vulns.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2020-1130", g_host.m_vulns.mp_items[130]);
}

void test_lookupHost_malformed_cve_ids_are_skipped(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody(
    "{\"vulns\":[\"CVE-2021-44228\",\"CVE-21-1234\",\"cve-2021-44228\",\"CVE-2021-123\",\"\","
    "\"CVE-2021-1234567890123456\",\"CVE-2021-4\\u00004228\",\"CVE-2022-22965\"]}"));
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", g_host.m_vulns.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-22965", g_host.m_vulns.mp_items[1]);
  TEST_ASSERT_EQUAL_size_t(6, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_hostnames.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_tags.m_skippedCount);
}

void test_lookupHost_lists_that_keep_nothing_are_null(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"ports\":[-1,70000],\"vulns\":[\"x\"],\"hostnames\":[\"\"],\"tags\":[\"\"]}"));
  TEST_ASSERT_NULL(g_host.mp_ports);
  TEST_ASSERT_NULL(g_host.m_vulns.mp_items);
  TEST_ASSERT_NULL(g_host.m_hostnames.mp_items);
  TEST_ASSERT_NULL(g_host.m_tags.mp_items);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_skippedPortCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_hostnames.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_skippedCount);
}

void test_lookupHost_zeroes_the_host_first(void)
{
  g_host.m_skippedPortCount = 9;
  g_host.m_tags.m_skippedCount = 9;
  memcpy(g_host.ma_lastUpdate, "old", 4);
  TEST_ASSERT_EQUAL_INT(SHODAN_KEY_REJECTED, shodan_lookupHost("", TEST_IP, &g_host, &g_retryAfterSeconds));
  static_assertHostEmpty();
}

void test_lookupHost_ports_outside_the_range_are_skipped(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"ports\":[0,-1,65536,65535,99999999999999999999999]}"));
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_portCount);
  TEST_ASSERT_EQUAL_INT(0,     g_host.mp_ports[0]);
  TEST_ASSERT_EQUAL_INT(65535, g_host.mp_ports[1]);
  TEST_ASSERT_EQUAL_size_t(3, g_host.m_skippedPortCount);
}

void test_lookupHost_over_long_names_and_tags_are_skipped(void)
{
  char* host_253 = static_makeRun('h', 253);
  char* host_254 = static_makeRun('h', 254);
  char* tag_64   = static_makeRun('t', 64);
  char* tag_65   = static_makeRun('t', 65);
  char* body     = malloc(1024);
  TEST_ASSERT_NOT_NULL(body);
  snprintf(body, 1024, "{\"hostnames\":[\"%s\",\"%s\",\"\",\"x.example\"],\"tags\":[\"%s\",\"%s\",\"\",\"a\\u0000\"]}",
           host_254, host_253, tag_65, tag_64);
  ShodanStatus_t status = static_lookupBody(body);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, status);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_hostnames.m_count);
  TEST_ASSERT_EQUAL_STRING(host_253,    g_host.m_hostnames.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("x.example", g_host.m_hostnames.mp_items[1]);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_hostnames.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_STRING(tag_64, g_host.m_tags.mp_items[0]);
  TEST_ASSERT_EQUAL_size_t(3, g_host.m_tags.m_skippedCount);
  free(host_253);
  free(host_254);
  free(tag_64);
  free(tag_65);
  free(body);
}

void test_lookupHost_over_long_last_update_is_left_out(void)
{
  TEST_ASSERT_EQUAL_INT(32, SHODAN_LAST_UPDATE_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"last_update\":\"2026-11-05T17:51:42.725642+00:00\",\"ports\":[1]}"));
  TEST_ASSERT_EQUAL_STRING("2026-11-05T17:51:42.725642+00:00", g_host.ma_lastUpdate);
  shodan_freeHost(&g_host);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"last_update\":\"2026-11-05T17:51:42.725642+00:000\",\"ports\":[1]}"));
  TEST_ASSERT_EQUAL_STRING("", g_host.ma_lastUpdate);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_portCount);
}

void test_lookupHost_wrong_types_are_unavailable(void)
{
  static const char* const bodies[] = {
    "{\"ports\":\"80\"}", "{\"ports\":{}}", "{\"ports\":null}", "{\"ports\":[\"80\"]}", "{\"ports\":[1.5]}", "{\"ports\":[true]}",
    "{\"vulns\":\"CVE-2014-0160\"}", "{\"vulns\":{\"CVE-2014-0160\":{}}}", "{\"vulns\":null}", "{\"vulns\":[5]}",
    "{\"hostnames\":\"a.example\"}", "{\"hostnames\":null}", "{\"hostnames\":[null]}",
    "{\"tags\":\"cloud\"}", "{\"tags\":7}", "{\"tags\":[true]}",
    "{\"last_update\":5}", "{\"last_update\":null}", "{\"last_update\":[]}",
    "{\"vulns\":[\"CVE-2014-\\q160\"]}", "{\"hostnames\":[\"a\\qb\"]}", "{\"tags\":[\"a\\u12\"]}", "{\"last_update\":\"a\\qb\"}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(SHODAN_UNAVAILABLE, static_lookupBody(bodies[i]), bodies[i]);
    static_assertHostEmpty();
  }
}

void test_lookupHost_unreadable_bodies_are_unavailable(void)
{
  static const char* const bodies[] = { "[]", "\"x\"", "not json", "", "{\"ports\":[80", "{} x" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(SHODAN_UNAVAILABLE, static_lookupBody(bodies[i]), bodies[i]);
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, static_lookupBody(NULL));
}

void test_lookupHost_failure_after_lists_frees_them(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, static_lookupBody(
    "{\"ports\":[80,443],\"vulns\":[\"CVE-2014-0160\"],\"hostnames\":[\"a.example\"],\"last_update\":\"x\",\"tags\":{}}"));
  static_assertHostEmpty();
}

void test_lookupHost_body_at_the_cap_and_past_it(void)
{
  char* body = static_makeRun(' ', SHODAN_MAX_BODY_BYTE_COUNT);
  static const char head[] = "{\"ports\":[22]";
  memcpy(body, head, sizeof(head) - 1);
  body[SHODAN_MAX_BODY_BYTE_COUNT - 1] = '}';
  ShodanStatus_t status = static_lookupBody(body);
  free(body);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, status);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_portCount);
  TEST_ASSERT_EQUAL_size_t(SHODAN_MAX_BODY_BYTE_COUNT, g_stub_requests[0].m_maxBodyByteCount);
  shodan_freeHost(&g_host);

  g_stub_next_error = HTTP_ERROR_BODY_TOO_LARGE;
  TEST_ASSERT_EQUAL_INT(SHODAN_UNAVAILABLE, static_lookupBody(SHODAN_FULL_BODY));
  static_assertHostEmpty();
}

void test_freeHost_is_safe_on_zeroed_and_freed_hosts(void)
{
  ShodanHost_t zeroed;
  memset(&zeroed, 0, sizeof(zeroed));
  shodan_freeHost(&zeroed);
  static_assertHostEmpty();

  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody(SHODAN_FULL_BODY));
  g_host.m_skippedPortCount = 9;
  shodan_freeHost(&g_host);
  static_assertHostEmpty();
  shodan_freeHost(&g_host);
  static_assertHostEmpty();
}

void test_freeHost_frees_a_partial_record(void)
{
  g_host.m_tags.mp_items    = calloc(2, sizeof(char*));
  TEST_ASSERT_NOT_NULL(g_host.m_tags.mp_items);
  g_host.m_tags.mp_items[0] = malloc(4);
  TEST_ASSERT_NOT_NULL(g_host.m_tags.mp_items[0]);
  memcpy(g_host.m_tags.mp_items[0], "vpn", 4);
  g_host.m_tags.m_count = 1;
  shodan_freeHost(&g_host);
  static_assertHostEmpty();
}

void test_longest_address_with_longest_key_is_sent_whole(void)
{
  static const char longest_ip[] = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
  char* longest_key = static_makeRun('z', SHODAN_KEY_MAX_LEN);
  char  expected[512];
  snprintf(expected, sizeof(expected), "https://api.shodan.io/shodan/host/%s?key=%s&minify=true", longest_ip, longest_key);
  ShodanStatus_t status = shodan_lookupHost(longest_key, longest_ip, &g_host, &g_retryAfterSeconds);
  free(longest_key);
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, status);
  TEST_ASSERT_EQUAL_STRING(expected, g_stub_last_url);
}

void test_lookupHost_empty_last_update_is_kept_empty(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody("{\"last_update\":\"\",\"ports\":[1]}"));
  TEST_ASSERT_EQUAL_STRING("", g_host.ma_lastUpdate);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_portCount);
}

static const char SHODAN_FACETS_BODY[] =
  "{\"matches\":[],\"facets\":{"
  "\"vuln\":[{\"count\":1,\"value\":\"cve-2014-0160\"},{\"count\":1,\"value\":\"cve-2021-44228\"},{\"count\":1,\"value\":\"cve-x\"}],"
  "\"tag\":[{\"count\":1,\"value\":\"cloud\"}],"
  "\"port\":[{\"count\":1,\"value\":22},{\"count\":1,\"value\":9929},{\"count\":1,\"value\":70000}]},"
  "\"total\":4}";

static ShodanStatus_t static_lookupFacets(HttpStubAnswer_t answers[2], int status, const char* body)
{
  answers[0] = (HttpStubAnswer_t){ .m_status = 403, .mp_body = "{\"error\": \"Requires membership or higher to access\"}" };
  answers[1] = (HttpStubAnswer_t){ .m_status = status, .mp_body = body };
  g_stub_answers         = answers;
  g_stub_answer_count    = 2;
  g_stub_http_call_count = 0;
  return shodan_lookupHost(TEST_KEY, TEST_IP, &g_host, &g_retryAfterSeconds);
}

void test_lookupHost_403_reads_the_count_query(void)
{
  HttpStubAnswer_t answers[2];
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupFacets(answers, 200, SHODAN_FACETS_BODY));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(1000, SHODAN_FACET_SIZE);
  TEST_ASSERT_EQUAL_STRING("https://api.shodan.io/shodan/host/count?key=" TEST_KEY "&query=ip:" TEST_IP "&facets=port:1000,vuln:1000,tag:1000", g_stub_requests[1].ma_url);
  TEST_ASSERT_TRUE(g_stub_requests[1].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[1].m_isRedirectLeftToCaller);
  TEST_ASSERT_EQUAL_INT(SHODAN_TIMEOUT_MS, g_stub_requests[1].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(SHODAN_MAX_BODY_BYTE_COUNT, g_stub_requests[1].m_maxBodyByteCount);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_portCount);
  TEST_ASSERT_EQUAL_INT(22, g_host.mp_ports[0]);
  TEST_ASSERT_EQUAL_INT(9929, g_host.mp_ports[1]);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_skippedPortCount);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_vulns.m_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2014-0160", g_host.m_vulns.mp_items[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", g_host.m_vulns.mp_items[1]);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_STRING("cloud", g_host.m_tags.mp_items[0]);
  TEST_ASSERT_NULL(g_host.m_hostnames.mp_items);
  TEST_ASSERT_EQUAL_STRING("", g_host.ma_lastUpdate);
  TEST_ASSERT_TRUE(g_host.m_isFromFacets);
  TEST_ASSERT_FALSE(g_host.m_isVulnListCut);
}

void test_lookupHost_host_query_sets_no_count_flag(void)
{
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupBody(SHODAN_FULL_BODY));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_FALSE(g_host.m_isFromFacets);
  TEST_ASSERT_FALSE(g_host.m_isVulnListCut);
}

void test_lookupHost_count_query_maps_each_answer(void)
{
  const struct { int m_status; const char* mp_body; ShodanStatus_t m_expected; unsigned int m_wait; } cases[] = {
    { 200, "{\"matches\":[],\"facets\":{\"port\":[],\"vuln\":[],\"tag\":[]},\"total\":0}", SHODAN_NOT_FOUND,    0 },
    { 200, "{\"total\":0}",                                                            SHODAN_NOT_FOUND,    0 },
    { 401, "{}",                                                                       SHODAN_KEY_REJECTED, 0 },
    { 403, "{}",                                                                       SHODAN_KEY_REJECTED, 0 },
    { 429, "{}",                                                                       SHODAN_RATE_LIMITED, 1 },
    { 500, "{}",                                                                       SHODAN_UNAVAILABLE,  0 },
    { 400, "{\"error\":\"Facet size too big for current subscription (limit: 1000)\"}", SHODAN_UNAVAILABLE,  0 },
    { 200, NULL,                                                                       SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"facets\":{}}",                                                          SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":\"4\",\"facets\":{}}",                                          SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":[]}",                                              SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"port\":{}}}",                                   SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"port\":[22]}}",                                 SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"port\":[{\"count\":1}]}}",                      SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"port\":[{\"value\":\"22\"}]}}",                 SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"vuln\":[{\"value\":5}]}}",                      SHODAN_UNAVAILABLE,  0 },
    { 200, "{\"total\":4,\"facets\":{\"tag\":[{\"value\":null}]}}",                    SHODAN_UNAVAILABLE,  0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[2];
    g_retryAfterSeconds = 7;
    shodan_freeHost(&g_host);
    char message[64];
    snprintf(message, sizeof(message), "case %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_expected, static_lookupFacets(answers, cases[i].m_status, cases[i].mp_body), message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_wait, g_retryAfterSeconds, message);
    TEST_ASSERT_TRUE_MESSAGE(g_host.m_isFromFacets, message);
    TEST_ASSERT_NULL_MESSAGE(g_host.mp_ports, message);
    TEST_ASSERT_NULL_MESSAGE(g_host.m_vulns.mp_items, message);
    TEST_ASSERT_NULL_MESSAGE(g_host.m_tags.mp_items, message);
  }
}

void test_lookupHost_count_query_flags_a_full_vuln_list(void)
{
  static char body[96 * SHODAN_FACET_SIZE];
  const struct { size_t m_count; bool m_hasMalformed; bool m_isCut; size_t m_kept; } cases[] = {
    { SHODAN_FACET_SIZE - 1, false, false, SHODAN_FACET_SIZE - 1 },
    { SHODAN_FACET_SIZE,     false, true,  SHODAN_FACET_SIZE     },
    { SHODAN_FACET_SIZE,     true,  true,  SHODAN_FACET_SIZE - 1 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    size_t len = (size_t)snprintf(body, sizeof(body), "{\"total\":1,\"facets\":{\"vuln\":[");
    for (size_t i = 0; i < cases[c].m_count; i++)
    {
      if (cases[c].m_hasMalformed && i == 0)
        len += (size_t)snprintf(body + len, sizeof(body) - len, "{\"count\":1,\"value\":\"cve-x\"}");
      else
        len += (size_t)snprintf(body + len, sizeof(body) - len, "%s{\"count\":1,\"value\":\"cve-2020-%05zu\"}", i > 0 ? "," : "", 10000 + i);
    }
    snprintf(body + len, sizeof(body) - len, "]}}");
    HttpStubAnswer_t answers[2];
    shodan_freeHost(&g_host);
    TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupFacets(answers, 200, body));
    TEST_ASSERT_EQUAL(cases[c].m_isCut, g_host.m_isVulnListCut);
    TEST_ASSERT_EQUAL_size_t(cases[c].m_kept, g_host.m_vulns.m_count);
  }
}


void test_lookupHost_count_query_port_and_tag_bounds(void)
{
  static char body[1024];
  char tag64[SHODAN_TAG_MAX_LEN + 1];
  char tag65[SHODAN_TAG_MAX_LEN + 2];
  memset(tag64, 't', SHODAN_TAG_MAX_LEN);     tag64[SHODAN_TAG_MAX_LEN]     = '\0';
  memset(tag65, 'u', SHODAN_TAG_MAX_LEN + 1); tag65[SHODAN_TAG_MAX_LEN + 1] = '\0';
  snprintf(body, sizeof(body), "{\"total\":1,\"facets\":{"
           "\"port\":[{\"value\":-1},{\"value\":0},{\"value\":65535},{\"value\":65536},{\"value\":99999999999999999999}],"
           "\"tag\":[{\"value\":\"\"},{\"value\":\"%s\"},{\"value\":\"%s\"}]}}", tag65, tag64);
  HttpStubAnswer_t answers[2];
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupFacets(answers, 200, body));
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_portCount);
  TEST_ASSERT_EQUAL_INT(0, g_host.mp_ports[0]);
  TEST_ASSERT_EQUAL_INT(65535, g_host.mp_ports[1]);
  TEST_ASSERT_EQUAL_size_t(3, g_host.m_skippedPortCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_count);
  TEST_ASSERT_EQUAL_STRING(tag64, g_host.m_tags.mp_items[0]);
  TEST_ASSERT_EQUAL_size_t(2, g_host.m_tags.m_skippedCount);
}

void test_lookupHost_count_query_all_skipped_ends_with_null_arrays(void)
{
  HttpStubAnswer_t answers[2];
  TEST_ASSERT_EQUAL_INT(SHODAN_OK, static_lookupFacets(answers, 200,
    "{\"total\":1,\"facets\":{\"port\":[{\"value\":70000}],\"vuln\":[{\"value\":\"cve-x\"}],\"tag\":[{\"value\":\"\"}]}}"));
  TEST_ASSERT_NULL(g_host.mp_ports);
  TEST_ASSERT_EQUAL_size_t(0, g_host.m_portCount);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_skippedPortCount);
  TEST_ASSERT_NULL(g_host.m_vulns.mp_items);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_vulns.m_skippedCount);
  TEST_ASSERT_NULL(g_host.m_tags.mp_items);
  TEST_ASSERT_EQUAL_size_t(1, g_host.m_tags.m_skippedCount);
}

void test_lookupHost_count_query_refuses_more_shapes(void)
{
  const struct { int m_status; const char* mp_body; ShodanStatus_t m_expected; } cases[] = {
    { 200, "{\"total\":4,\"facets\":{\"tag\":[{\"count\":1}]}}",              SHODAN_UNAVAILABLE },
    { 200, "{\"total\":4,\"facets\":{\"vuln\":[\"cve-2014-0160\"]}}",          SHODAN_UNAVAILABLE },
    { 201, "{\"total\":4,\"facets\":{\"tag\":[{\"value\":\"cloud\"}]}}",      SHODAN_UNAVAILABLE },
    { 200, "{\"total\":-1}",                                                  SHODAN_NOT_FOUND   },
    { 200, "{\"total\":4,\"facets\":{\"tag\":[{\"value\":\"a\x01" "b\"}]}}",  SHODAN_UNAVAILABLE },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[2];
    shodan_freeHost(&g_host);
    char message[32];
    snprintf(message, sizeof(message), "case %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_expected, static_lookupFacets(answers, cases[i].m_status, cases[i].mp_body), message);
    TEST_ASSERT_NULL_MESSAGE(g_host.m_tags.mp_items, message);
  }
}

void test_lookupHost_count_query_sends_longest_key_and_address_whole(void)
{
  static const char ip[] = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
  char* key = static_makeRun('z', SHODAN_KEY_MAX_LEN);
  HttpStubAnswer_t answers[2];
  answers[0] = (HttpStubAnswer_t){ .m_status = 403, .mp_body = "{}" };
  answers[1] = (HttpStubAnswer_t){ .m_status = 200, .mp_body = "{\"total\":0}" };
  g_stub_answers = answers; g_stub_answer_count = 2; g_stub_http_call_count = 0;
  ShodanStatus_t status = shodan_lookupHost(key, ip, &g_host, &g_retryAfterSeconds);
  char expected[512];
  snprintf(expected, sizeof(expected), "https://api.shodan.io/shodan/host/count?key=%s&query=ip:%s&facets=port:1000,vuln:1000,tag:1000", key, ip);
  free(key);
  TEST_ASSERT_EQUAL_INT(SHODAN_NOT_FOUND, status);
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(expected, g_stub_requests[1].ma_url);
}

void test_page_key_pattern_matches_isKeyAccepted(void)
{
  FILE* file = fopen("web/static/js/vendor_keys.js", "rb");
  TEST_ASSERT_NOT_NULL(file);
  static char script[65536];
  size_t script_len = fread(script, 1, sizeof(script) - 1, file);
  fclose(file);
  script[script_len] = '\0';
  const char* head = strstr(script, "    shodan: /");
  TEST_ASSERT_NOT_NULL(head);
  head += strlen("    shodan: /");
  const char* tail = strchr(head, '\n');
  TEST_ASSERT_NOT_NULL(tail);
  while (tail > head && tail[-1] != '/')
    tail--;
  TEST_ASSERT_TRUE(tail > head);
  tail--;
  char pattern[128];
  TEST_ASSERT_TRUE((size_t)(tail - head) < sizeof(pattern));
  snprintf(pattern, sizeof(pattern), "%.*s", (int)(tail - head), head);
  regex_t regex;
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB), pattern);

  char key[SHODAN_KEY_MAX_LEN + 2];
  for (int byte = 1; byte < 256; byte++)
  {
    key[0] = (char)byte;
    key[1] = '\0';
    TEST_ASSERT_EQUAL_INT_MESSAGE(shodan_isKeyAccepted(key), regexec(&regex, key, 0, NULL, 0) == 0, pattern);
  }
  const size_t lengths[] = { 1, SHODAN_KEY_MAX_LEN, SHODAN_KEY_MAX_LEN + 1 };
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
  {
    memset(key, 'A', lengths[i]);
    key[lengths[i]] = '\0';
    TEST_ASSERT_EQUAL_INT_MESSAGE(shodan_isKeyAccepted(key), regexec(&regex, key, 0, NULL, 0) == 0, pattern);
  }
  regfree(&regex);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(39, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_lookupHost_sends_the_host_url_with_the_key_and_minify);
  RUN_TEST(test_lookupHost_request_flags_timeout_and_cap);
  RUN_TEST(test_checkKey_sends_the_api_info_url_with_the_key);
  RUN_TEST(test_lookupHost_maps_each_status);
  RUN_TEST(test_lookupHost_other_answers_are_unavailable);
  RUN_TEST(test_checkKey_maps_each_status);
  RUN_TEST(test_checkKey_does_not_parse_the_body);
  RUN_TEST(test_refused_keys_send_no_request);
  RUN_TEST(test_accepted_keys_are_sent_whole);
  RUN_TEST(test_refused_addresses_send_no_request);
  RUN_TEST(test_longest_address_is_sent_whole);
  RUN_TEST(test_lookupHost_reads_each_field);
  RUN_TEST(test_lookupHost_missing_or_empty_lists_are_empty);
  RUN_TEST(test_lookupHost_lists_of_one);
  RUN_TEST(test_lookupHost_many_vulns);
  RUN_TEST(test_lookupHost_malformed_cve_ids_are_skipped);
  RUN_TEST(test_lookupHost_lists_that_keep_nothing_are_null);
  RUN_TEST(test_lookupHost_zeroes_the_host_first);
  RUN_TEST(test_lookupHost_ports_outside_the_range_are_skipped);
  RUN_TEST(test_lookupHost_over_long_names_and_tags_are_skipped);
  RUN_TEST(test_lookupHost_over_long_last_update_is_left_out);
  RUN_TEST(test_lookupHost_wrong_types_are_unavailable);
  RUN_TEST(test_lookupHost_unreadable_bodies_are_unavailable);
  RUN_TEST(test_lookupHost_failure_after_lists_frees_them);
  RUN_TEST(test_lookupHost_body_at_the_cap_and_past_it);
  RUN_TEST(test_freeHost_is_safe_on_zeroed_and_freed_hosts);
  RUN_TEST(test_freeHost_frees_a_partial_record);
  RUN_TEST(test_longest_address_with_longest_key_is_sent_whole);
  RUN_TEST(test_lookupHost_empty_last_update_is_kept_empty);
  RUN_TEST(test_lookupHost_403_reads_the_count_query);
  RUN_TEST(test_lookupHost_host_query_sets_no_count_flag);
  RUN_TEST(test_lookupHost_count_query_maps_each_answer);
  RUN_TEST(test_lookupHost_count_query_flags_a_full_vuln_list);
  RUN_TEST(test_lookupHost_count_query_port_and_tag_bounds);
  RUN_TEST(test_lookupHost_count_query_all_skipped_ends_with_null_arrays);
  RUN_TEST(test_lookupHost_count_query_refuses_more_shapes);
  RUN_TEST(test_lookupHost_count_query_sends_longest_key_and_address_whole);
  RUN_TEST(test_page_key_pattern_matches_isKeyAccepted);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
