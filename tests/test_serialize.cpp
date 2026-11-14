#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include "unity/unity.h"

extern "C" {
#include "serialize.h"
#include "tlsprobe.h"
#include "header_fetch.h"
#include "header_check.h"
#include "external/rdap.h"
#include "external/wayback.h"
#include "external/certspotter.h"
#include "subdomain.h"
#include "watchlist/watchlist.h"
#include "watchlist/watchlist_domain.h"
#include "jsonbuf.h"
#include "pricing.h"
}

void setUp(void)    {}
void tearDown(void) {}

static JsonBuf_t* static_newJsonBuf(size_t initial_cap, size_t ceiling)
{
  JsonBuf_t* json_buf = jsonbuf_create(initial_cap, ceiling);
  TEST_ASSERT_NOT_NULL(json_buf);
  return json_buf;
}

static char* static_finishJsonBuf(JsonBuf_t* json_buf)
{
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

static int static_countOccurrences(const char* text, const char* needle)
{
  int count = 0;
  for (const char* at = strstr(text, needle); at; at = strstr(at + 1, needle))
    count++;
  return count;
}

void test_CVELOOKUP_metasploit_fields_in_json(void)
{
  CVELOOKUPRecord_t r;
  memset(&r, 0, sizeof(r));
  strncpy(r.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  r.m_metasploitModuleCount  = 5;
  r.m_isMetasploitFeedLoaded = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&r, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("has_metasploit_module":true)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("metasploit_module_count":5)"));
  free(body);
}

static void test_CVEEXPLOIT_no_results_serializes(void)
{
  CVEEXPLOITRecord_t rec;
  memset(&rec, 0, sizeof(rec));
  strncpy(rec.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  rec.ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
  rec.m_githubAvailable     = true;
  rec.m_metasploitAvailable = true;
  rec.m_nvdAvailable        = true;
  rec.m_exploitdbAvailable  = true;
  rec.m_githubPocRepoTotal = 0;
  rec.m_githubTopStarredRepoCount = 0;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&rec, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("cve_id")"));
  TEST_ASSERT_NOT_NULL(strstr(body, "CVE-2021-44228"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("exploits_found":0)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("has_public_exploit":null)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("in_kev":false)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("sources":[)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"github")"));
  TEST_ASSERT_NULL(strstr(body, "shodan"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"metasploit")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("has_module":false)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"nvd")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"exploitdb")"));
  free(body);
}

static void test_CVEEXPLOIT_with_github_results_serializes(void)
{
  CVEEXPLOITRecord_t rec;
  memset(&rec, 0, sizeof(rec));
  strncpy(rec.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  rec.ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
  rec.m_githubAvailable   = true;
  rec.m_githubPocRepoTotal = 127;
  rec.m_githubTopStarredRepoCount = 1;
  strncpy(rec.ma_githubTopStarredRepos[0].ma_url,  "https://github.com/user/poc", CVEEXPLOIT_REPO_URL_LEN);
  rec.ma_githubTopStarredRepos[0].ma_url[CVEEXPLOIT_REPO_URL_LEN] = '\0';
  strncpy(rec.ma_githubTopStarredRepos[0].ma_name, "user/poc", CVEEXPLOIT_REPO_NAME_LEN);
  rec.ma_githubTopStarredRepos[0].ma_name[CVEEXPLOIT_REPO_NAME_LEN] = '\0';
  rec.ma_githubTopStarredRepos[0].m_starCount = 500;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&rec, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("exploits_found":127)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("has_public_exploit":null)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"github")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("count":127)"));
  TEST_ASSERT_NOT_NULL(strstr(body, "user/poc"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("stars":500)"));
  free(body);
}

static void test_CVEEXPLOIT_with_metasploit_serializes(void)
{
  CVEEXPLOITRecord_t rec;
  memset(&rec, 0, sizeof(rec));
  strncpy(rec.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  rec.ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
  rec.m_metasploitAvailable   = true;
  rec.m_metasploitModuleTotal = 5;
  rec.m_metasploitModuleCount = 1;
  strncpy(rec.ma_metasploitModules[0].ma_name, "exploit_multi/handler/log4shell",
          CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  rec.ma_metasploitModules[0].ma_name[CVEEXPLOIT_METASPLOIT_MODULE_LEN] = '\0';
  strncpy(rec.ma_metasploitModules[0].ma_type, "exploit", CVEEXPLOIT_METASPLOIT_TYPE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&rec, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"metasploit")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("has_module":true)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("count":5)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"({"name":"exploit_multi/handler/log4shell","type":"exploit"})"));
  free(body);
}

static void static_fillTriageItem(CVETRIAGEItem_t* it)
{
  memset(it, 0, sizeof(*it));
  strncpy(it->ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  it->m_riskScore = 96.5;
  strncpy(it->ma_label, "CRITICAL", CVERISKSCORE_LABEL_LEN);
}

void test_CVETRIAGE_json_shape(void)
{
  CVETRIAGEItem_t item;
  static_fillTriageItem(&item);
  CVETRIAGEResult_t r = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVETRIAGEParams_t p;
  memset(&p, 0, sizeof(p));
  p.m_limit  = 20; 
  p.m_offset = 0;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&r, &p, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("total":1)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("limit":20)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("offset":0)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("next_offset":1)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("results":[)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("cve_id":"CVE-2021-44228")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("risk_score":96.5)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("label":"CRITICAL")"));
  TEST_ASSERT_NULL(strstr(body, "in_kev"));
  TEST_ASSERT_NULL(strstr(body, "has_public_poc"));
  TEST_ASSERT_NULL(strstr(body, "components"));
  TEST_ASSERT_NULL(strstr(body, R"("summary")"));
  TEST_ASSERT_NULL(strstr(body, R"("cvss_v3")"));
  TEST_ASSERT_NULL(strstr(body, R"("epss_score")"));
  free(body);
}

void test_CVETRIAGEBULK_json_envelope(void)
{
  CVETRIAGEItem_t item;
  static_fillTriageItem(&item);
  CVETRIAGEBULKResult_t r;
  memset(&r, 0, sizeof(r));
  r.m_total       = 3; 
  r.m_processed   = 2; 
  r.m_successful  = 1; 
  r.m_skipped     = 1; 
  r.m_failed      = 1;
  r.mp_items      = &item;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGEBULK_response(&r, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("total":3)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("processed":2)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("successful":1)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("skipped":1)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("failed":1)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("cve_id":"CVE-2021-44228")"));
  free(body);
}

void test_PRODUCTEXPOSURE_json_shape(void)
{
  PRODUCTEXPOSURERecord_t r;
  memset(&r, 0, sizeof(r));
  strncpy(r.ma_vendor,  "cisco", CVESEARCH_VENDOR_LEN);
  strncpy(r.ma_product, "ios",   CVESEARCH_PRODUCT_LEN);
  r.m_totalCveCount  = 42;
  r.m_criticalCount  = 10;
  r.m_highCount      = 20;
  r.m_mediumCount    = 8;
  r.m_lowCount       = 4;
  r.m_kevCount       = 7;
  r.m_maxCvss        = 9.8;
  r.m_avgCvss        = 6.42;
  r.m_maxEpss        = 0.97531;
  r.m_pocBackedCount = 12;
  r.m_worstRiskScore = 96.5;
  strncpy(r.ma_mostRecentPublished, "2024-01-15T00:00:00Z", CVELOOKUP_PUBLISHED_LEN);
  strncpy(r.ma_topCves[0].ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  r.ma_topCves[0].m_riskScore = 96.5;
  strncpy(r.ma_topCves[0].ma_label, "CRITICAL", CVERISKSCORE_LABEL_LEN);
  r.m_topCveCount = 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&r, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("vendor":"cisco")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("product":"ios")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("exposure":{)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("total_cves":42)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("critical":10)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("high":20)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("kev_count":7)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("max_cvss":9.8)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("avg_cvss":6.42)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("max_epss":0.9753)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("poc_backed_count":12)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("worst_risk_score":96.5)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("most_recent_published":"2024-01-15T00:00:00Z")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("top_cves":[)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("cve_id":"CVE-2021-44228")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("risk_score":96.5)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("label":"CRITICAL")"));
  free(body);
}

static void static_fillGoldenHealth(HEALTHData_t* health)
{
  memset(health, 0, sizeof(*health));
  health->m_cveCount = 312000;
  strcpy(health->ma_nvdLastCveId,          "CVE-2026-1234");
  strcpy(health->ma_nvdLastPublishedTime,  "2026-08-29T10:00:00Z");
  health->m_kevCount = 1300;
  strcpy(health->ma_kevLastCveId,          "CVE-2026-9999");
  strcpy(health->ma_kevLastDateAdded,      "2026-08-28");
  health->m_cweCount = 940;
  strcpy(health->ma_cweLastId,             "CWE-79");
  strcpy(health->ma_cweLastUpdatedAt,      "2026-08-27T09:00:00Z");
  health->m_feedCount = 2;
  strcpy(health->ma_feeds[0].ma_name,       "nvd");
  strcpy(health->ma_feeds[0].ma_lastSynced, "2026-10-08T01:22:39Z");
  strcpy(health->ma_feeds[0].ma_lastStatus, "ok");
  health->ma_feeds[0].m_recordsUpdated = 21874;
  strcpy(health->ma_feeds[1].ma_name,       "cwe");
  strcpy(health->ma_feeds[1].ma_lastStatus, "in_progress");
}

void test_HEALTH_serializes_every_section(void)
{
  HEALTHData_t health;
  static_fillGoldenHealth(&health);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(&health, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"status":"ok","version":"2.0.1","db":{)"
      R"("nvd":{"cve_count":312000,"last_added":{"cve_id":"CVE-2026-1234",)"
        R"("published_time":"2026-08-29T10:00:00Z"}},)"
      R"("kev":{"entry_count":1300,"last_added":{"cve_id":"CVE-2026-9999",)"
        R"("date_added":"2026-08-28"}},)"
      R"("cwe":{"entry_count":940,"last_updated":{"cwe_id":"CWE-79",)"
        R"("updated_at":"2026-08-27T09:00:00Z"}},)"
      R"("feeds":[)"
        R"({"name":"nvd","last_synced":"2026-10-08T01:22:39Z","last_status":"ok","records_updated":21874},)"
        R"({"name":"cwe","last_synced":null,"last_status":"in_progress","records_updated":0}])"
    R"(}})" "\n", body);
  free(body);
}

void test_HEALTH_null_db_serializes_unavailable_and_null_db(void)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(NULL, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"status":"unavailable","version":"2.0.1","db":null})" "\n", body);
  free(body);
}

void test_HEALTH_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  HEALTHData_t health;
  static_fillGoldenHealth(&health);

  JsonBuf_t* roomy = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(&health, roomy);
  char* roomy_body = static_finishJsonBuf(roomy);

  for (size_t start = 1; start <= strlen(roomy_body); start++)
  {
    JsonBuf_t* tight = static_newJsonBuf(start, JSONBUF_DEFAULT_CEILING);
    serialize_HEALTH_response(&health, tight);
    char* tight_body = static_finishJsonBuf(tight);
    TEST_ASSERT_EQUAL_STRING(roomy_body, tight_body);
    free(tight_body);
  }

  free(roomy_body);
}

void test_HEALTH_over_ceiling_hands_back_no_body(void)
{
  HEALTHData_t health;
  static_fillGoldenHealth(&health);

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_HEALTH_response(&health, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

void test_HEALTH_every_string_is_escaped_through_its_own_class(void)
{
  HEALTHData_t health;
  memset(&health, 0, sizeof(health));
  health.m_cveCount = 1;
  strcpy(health.ma_nvdLastCveId,         "CVE-\"1");
  strcpy(health.ma_nvdLastPublishedTime, "2026\\08");
  health.m_kevCount = 2;
  strcpy(health.ma_kevLastCveId,         "CVE\n9");
  strcpy(health.ma_kevLastDateAdded,     "2026\t28");
  health.m_cweCount = 3;
  strcpy(health.ma_cweLastId,            "CWE\b79");
  strcpy(health.ma_cweLastUpdatedAt,     "2026\00127");
  health.m_feedCount = 1;
  strcpy(health.ma_feeds[0].ma_name,       "nv\rd");
  strcpy(health.ma_feeds[0].ma_lastSynced, "2026\f10");
  strcpy(health.ma_feeds[0].ma_lastStatus, "o\002k");
  health.ma_feeds[0].m_recordsUpdated = 4;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(&health, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"status":"ok","version":"2.0.1","db":{)"
      R"("nvd":{"cve_count":1,"last_added":{"cve_id":"CVE-\"1","published_time":"2026\\08"}},)"
      R"("kev":{"entry_count":2,"last_added":{"cve_id":"CVE\n9","date_added":"2026\t28"}},)"
      R"("cwe":{"entry_count":3,"last_updated":{"cwe_id":"CWE\b79","updated_at":"2026)" "\\u0001" R"(27"}},)"
      R"("feeds":[{"name":"nv\rd","last_synced":"2026\f10","last_status":"o)" "\\u0002" R"(k","records_updated":4}])"
    R"(}})" "\n", body);
  free(body);
}

void test_HEALTH_no_feed_writes_an_empty_list(void)
{
  HEALTHData_t health;
  static_fillGoldenHealth(&health);
  health.m_feedCount = 0;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(&health, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("updated_at":"2026-08-27T09:00:00Z"}},"feeds":[]}})" "\n"));
  free(body);
}

void test_HEALTH_feed_count_past_its_array_is_clamped(void)
{
  struct {
    HEALTHData_t m_health;
    HEALTHFeed_t m_spare;
  } fixture;
  memset(&fixture, 0, sizeof(fixture));
  static_fillGoldenHealth(&fixture.m_health);
  fixture.m_health.m_feedCount = HEALTH_MAX_FEEDS + 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEALTH_response(&fixture.m_health, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_INT(HEALTH_MAX_FEEDS, static_countOccurrences(body, R"("records_updated":)"));
  free(body);
}

typedef struct {
  const char* mp_cveId;
  const char* mp_severity;
  double      m_cvssV3;
  double      m_epssScore;
  double      m_epssPercentile;
  bool        m_inKev;
  const char* mp_publishedTime;
  const char* mp_cweId;
} GoldenCveListItem_t;

static void static_fillGoldenCveListItem(CveListItem_t* item, GoldenCveListItem_t spec)
{
  memset(item, 0, sizeof(*item));
  strncpy(item->ma_cveId, spec.mp_cveId, CVELOOKUP_ID_MAX_LEN);
  strncpy(item->ma_severity, spec.mp_severity, CVELOOKUP_SEVERITY_LEN);
  item->m_cvssV3          = spec.m_cvssV3;
  item->m_hasCvssV3       = true;
  item->m_epssScore       = spec.m_epssScore;
  item->m_epssPercentile  = spec.m_epssPercentile;
  item->m_inKev           = spec.m_inKev;
  strncpy(item->ma_publishedTime, spec.mp_publishedTime, CVELOOKUP_PUBLISHED_LEN);
  strncpy(item->ma_cweId, spec.mp_cweId, CVELOOKUP_CWE_ID_LEN);
}

static void static_fillGoldenListPair(CveListItem_t* items)
{
  static_fillGoldenCveListItem(&items[0], (GoldenCveListItem_t){
    .mp_cveId = "CVE-2021-44228", .mp_severity = "CRITICAL", .m_cvssV3 = 10.0,
    .m_epssScore = 0.97564, .m_epssPercentile = 0.99977, .m_inKev = true,
    .mp_publishedTime = "2021-12-10", .mp_cweId = "CWE-917" });
  static_fillGoldenCveListItem(&items[1], (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = 8.5,
    .m_epssScore = 0.5, .m_epssPercentile = 0.9, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
}

void test_error_golden(void)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_error_response("bad_request", "limit must be \"1-100\"\nnot 0", json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"error":{"code":"bad_request",)"
      R"("message":"limit must be \"1-100\"\nnot 0"}})" "\n", body);
  free(body);
}

void test_error_code_is_escaped(void)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_error_response("a\"b", "m", json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(R"({"error":{"code":"a\"b","message":"m"}})" "\n", body);
  free(body);
}

static void static_fillGoldenRiskScore(CVERISKSCORERecord_t* record)
{
  memset(record, 0, sizeof(*record));
  record->m_score = 94.5;
  strncpy(record->ma_label, "CRITICAL", CVERISKSCORE_LABEL_LEN);
  record->m_hasPublicPoc            = true;
  record->m_exploitabilityComponent = 57.25;
  record->m_impactComponent         = 30.0;
  record->m_evidenceComponent       = 7.25;
}

void test_CVERISKSCORE_golden(void)
{
  CVERISKSCORERecord_t record;
  static_fillGoldenRiskScore(&record);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVERISKSCORE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"score":94.5,"label":"CRITICAL","has_public_poc":true,"components":{)"
      R"("exploitability":{"score":57.25,"max":60.00},)"
      R"("impact":{"score":30.00,"max":30.00},)"
      R"("evidence":{"score":7.25,"max":10.00})"
    R"(}})" "\n", body);
  free(body);
}

void test_CVERISKSCORE_golden_no_poc_whole_numbers(void)
{
  CVERISKSCORERecord_t record;
  memset(&record, 0, sizeof(record));
  record.m_score = 40.0;
  strncpy(record.ma_label, "MEDIUM", CVERISKSCORE_LABEL_LEN);
  record.m_hasPublicPoc            = false;
  record.m_exploitabilityComponent = 10.0;
  record.m_impactComponent         = 30.0;
  record.m_evidenceComponent       = 0.0;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVERISKSCORE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"score":40.0,"label":"MEDIUM","has_public_poc":null,"components":{)"
      R"("exploitability":{"score":10.00,"max":60.00},)"
      R"("impact":{"score":30.00,"max":30.00},)"
      R"("evidence":{"score":0.00,"max":10.00})"
    R"(}})" "\n", body);
  free(body);
}

void test_CVERISKSCORE_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  CVERISKSCORERecord_t record;
  static_fillGoldenRiskScore(&record);

  JsonBuf_t* roomy = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVERISKSCORE_response(&record, roomy);
  char* roomy_body = static_finishJsonBuf(roomy);

  for (size_t start = 1; start <= strlen(roomy_body); start++)
  {
    JsonBuf_t* tight = static_newJsonBuf(start, JSONBUF_DEFAULT_CEILING);
    serialize_CVERISKSCORE_response(&record, tight);
    char* tight_body = static_finishJsonBuf(tight);
    TEST_ASSERT_EQUAL_STRING(roomy_body, tight_body);
    free(tight_body);
  }

  free(roomy_body);
}

void test_CVERISKSCORE_over_ceiling_hands_back_no_body(void)
{
  CVERISKSCORERecord_t record;
  static_fillGoldenRiskScore(&record);

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_CVERISKSCORE_response(&record, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

void test_CVERISKSCORE_label_is_escaped(void)
{
  CVERISKSCORERecord_t record;
  static_fillGoldenRiskScore(&record);
  strcpy(record.ma_label, "\"CRIT\001");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVERISKSCORE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("label":"\"CRIT)" "\\u0001" R"(",)"), body);
  free(body);
}

void test_CVESEARCH_golden_empty(void)
{
  CveListResult_t results = { .m_total = 0, .m_count = 0, .mp_items = NULL };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(R"({"total":0,"limit":20,"offset":0,"next_offset":0,"results":[]})" "\n", body);
  free(body);
}

void test_CVESEARCH_golden_two_items(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,"results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.97564,"epss_percentile":0.99977,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null},)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVESEARCH_golden_escapes_every_class(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2021-44228", .mp_severity = "CRITICAL", .m_cvssV3 = 10.0,
    .m_epssScore = 0.9, .m_epssPercentile = 0.99, .m_inKev = true,
    .mp_publishedTime = "\" \\ \n \t \b \f \r \x07 \x1f", .mp_cweId = "CWE-917" });
  CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"limit":20,"offset":0,"next_offset":1,"results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.90000,"epss_percentile":0.99000,"in_kev":true,)"
        R"("published_time":"\" \\ \n \t \b \f \r \u0007 \u001f",)"
        R"("cwe_id":"CWE-917","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVESEARCH_golden_next_offset_clamped_at_int_max(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2021-44228", .mp_severity = "LOW", .m_cvssV3 = 0.0,
    .m_epssScore = 0.0, .m_epssPercentile = 0.0, .m_inKev = false,
    .mp_publishedTime = "", .mp_cweId = "" });
  CveListResult_t results = { .m_total = 2147483647, .m_count = 1, .mp_items = &item };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 1;
  params.m_offset = 2147483647;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2147483647,"limit":1,"offset":2147483647,"next_offset":2147483647,"results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"LOW","cvss_v3":0.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.00000,"epss_percentile":0.00000,"in_kev":false,)"
        R"("published_time":"","cwe_id":"","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_critical_verdict(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 12, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":2,"total":12,"limit":20,"verdict":"critical",)"
      R"("summary":"2 CVEs ranked by exploitation probability; CVE-2021-44228 leads at 97.6% (EPSS, next 30 days). 1 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.97564,"epss_percentile":0.99977,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null},)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_high_verdict(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = 8.5,
    .m_epssScore = 0.2, .m_epssPercentile = 0.85, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"high",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 20.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.20000,"epss_percentile":0.85000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_moderate_verdict(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "MEDIUM", .m_cvssV3 = 5.5,
    .m_epssScore = 0.05, .m_epssPercentile = 0.6, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"moderate",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 5.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"MEDIUM","cvss_v3":5.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.05000,"epss_percentile":0.60000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_empty_none_verdict(void)
{
  CveListResult_t results = { .m_total = 0, .m_count = 0, .mp_items = NULL };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":0,"total":0,"limit":20,"verdict":"none",)"
      R"("summary":"No CVEs matched this filter.",)"
      R"("results":[]})" "\n", body);
  free(body);
}

void test_KEVLOOKUP_golden_full(void)
{
  KEVLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  strncpy(record.ma_dateAdded, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_vendorProject, "Apache", KEVLOOKUP_VENDOR_LEN);
  strncpy(record.ma_product, "Log4j", KEVLOOKUP_PRODUCT_LEN);
  strncpy(record.ma_patchDeadline, "2021-12-24", CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_requiredAction, "Apply updates", KEVLOOKUP_REQUIRED_ACTION_LEN);
  record.m_knownRansomwareUse = true;
  strncpy(record.ma_vulnerabilityName, "Log4Shell", KEVLOOKUP_VULN_NAME_LEN);
  strncpy(record.ma_shortDescription, "JNDI RCE", KEVLOOKUP_SHORT_DESC_LEN);
  strncpy(record.ma_dateRemoved, "2026-01-02", KEVLOOKUP_DATE_REMOVED_LEN);
  record.m_inKev = false;
  record.mp_cwes = strdup(R"(["CWE-917"])");
  record.mp_notes = strdup("https://logging.apache.org/log4j/2.x/security.html");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_KEVLOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_cwes);
  free(record.mp_notes);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","in_kev":false,"date_added":"2021-12-10",)"
      R"("vendor_project":"Apache","product":"Log4j","patch_deadline":"2021-12-24",)"
      R"("required_action":"Apply updates","known_ransomware_use":true,)"
      R"("vulnerability_name":"Log4Shell","short_description":"JNDI RCE",)"
      R"("notes":"https://logging.apache.org/log4j/2.x/security.html",)"
      R"("cwes":["CWE-917"],"date_removed":"2026-01-02"})" "\n", body);
  free(body);
}

void test_KEVLOOKUP_golden_null_cwes(void)
{
  KEVLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2024-3400", CVELOOKUP_ID_MAX_LEN);
  strncpy(record.ma_dateAdded, "2024-04-12", CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_vendorProject, "Palo Alto", KEVLOOKUP_VENDOR_LEN);
  strncpy(record.ma_product, "PAN-OS", KEVLOOKUP_PRODUCT_LEN);
  strncpy(record.ma_patchDeadline, "2024-04-19", CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_requiredAction, "Apply mitigations", KEVLOOKUP_REQUIRED_ACTION_LEN);
  record.m_knownRansomwareUse = false;
  strncpy(record.ma_vulnerabilityName, "PAN-OS Command Injection", KEVLOOKUP_VULN_NAME_LEN);
  strncpy(record.ma_shortDescription, "Command injection", KEVLOOKUP_SHORT_DESC_LEN);
  record.m_inKev = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_KEVLOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2024-3400","in_kev":true,"date_added":"2024-04-12",)"
      R"("vendor_project":"Palo Alto","product":"PAN-OS","patch_deadline":"2024-04-19",)"
      R"("required_action":"Apply mitigations","known_ransomware_use":false,)"
      R"("vulnerability_name":"PAN-OS Command Injection","short_description":"Command injection",)"
      R"("notes":"","cwes":null,"date_removed":""})" "\n", body);
  free(body);
}

void test_KEVLOOKUP_writes_a_stored_byte_that_is_not_valid_utf8_as_u_fffd(void)
{
  KEVLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  strncpy(record.ma_shortDescription, "a\xff" "b\xe2\x80\xae" "c", KEVLOOKUP_SHORT_DESC_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_KEVLOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_NOT_NULL(strstr(body, "\"short_description\":\"a\xef\xbf\xbd" "b\\u202e" "c\""));
  free(body);
}

void test_json_members_follow_the_text_rules(void)
{
  static char document[] = "[\"a\xe2\x80\xae" "b\xff\"]";
  const char* written = "[\"a\\u202eb\xef\xbf\xbd\"]";

  CVELOOKUPRecord_t lookup;
  memset(&lookup, 0, sizeof(lookup));
  strncpy(lookup.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  lookup.mp_cwes                 = document;
  lookup.mp_affectedProducts     = document;
  lookup.mp_refs                 = document;
  lookup.mp_epssTrend            = document;
  lookup.mp_cveTags              = document;
  lookup.mp_productCountByVendor = document;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&lookup, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(6, static_countOccurrences(body, written), "CVELOOKUP");
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "\xe2\x80\xae"), "CVELOOKUP");
  TEST_ASSERT_NULL_MESSAGE(strchr(body, '\xff'), "CVELOOKUP");
  free(body);

  KEVLOOKUPRecord_t kev;
  memset(&kev, 0, sizeof(kev));
  kev.mp_cwes = document;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_KEVLOOKUP_response(&kev, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(body, written), "KEVLOOKUP");
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "\xe2\x80\xae"), "KEVLOOKUP");
  free(body);

  CWELOOKUPRecord_t cwe;
  memset(&cwe, 0, sizeof(cwe));
  cwe.mp_mitigations = document;
  cwe.mp_examples    = document;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&cwe, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, static_countOccurrences(body, written), "CWELOOKUP");
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "\xe2\x80\xae"), "CWELOOKUP");
  free(body);

  CVEPRODUCTSResult_t products = { .m_affectedProductCount = 1, .m_listedProductCount = 1, .mp_affectedProducts = document };
  CVEPRODUCTSParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  params.m_limit = 20;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEPRODUCTS_response(&products, &params, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(body, written), "CVEPRODUCTS");
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "\xe2\x80\xae"), "CVEPRODUCTS");
  TEST_ASSERT_NULL_MESSAGE(strchr(body, '\xff'), "CVEPRODUCTS");
  free(body);
}

static void static_fillGoldenCwe(CWELOOKUPRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  strncpy(record->ma_cweId, "CWE-79", CWELOOKUP_ID_MAX_LEN);
  strncpy(record->ma_name, "Improper Neutralization", CWELOOKUP_NAME_LEN);
  strncpy(record->ma_abstraction, "Base", CWELOOKUP_ABSTRACTION_LEN);
  strncpy(record->ma_status, "Stable", CWELOOKUP_STATUS_LEN);
  strncpy(record->ma_description, "XSS description", CWELOOKUP_DESC_MAX_LEN);
  strncpy(record->ma_likelihood, "High", CWELOOKUP_LIKELIHOOD_LEN);
  strncpy(record->ma_parentCwe, "CWE-74", CWELOOKUP_PARENT_CWE_LEN);
  strncpy(record->ma_updatedAt, "2026-05-21T00:00:00+00:00", CWELOOKUP_UPDATED_AT_LEN);
  record->m_cveCount = 42;
  record->m_kevCount = 3;
  record->m_avgCvss  = 6.5;
  record->m_avgEpss  = 0.0287;
}

void test_CWELOOKUP_golden_filled_heap(void)
{
  CWELOOKUPRecord_t record;
  static_fillGoldenCwe(&record);
  record.mp_extendedDescription = strdup(R"(Extended "desc")");
  record.mp_mitigations         = strdup(R"(["escape output"])");
  record.mp_examples            = strdup(R"(["CVE-2024-1234"])");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_extendedDescription);
  free(record.mp_mitigations);
  free(record.mp_examples);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cwe_id":"CWE-79","name":"Improper Neutralization","abstraction":"Base","status":"Stable",)"
      R"("description":"XSS description","extended_description":"Extended \"desc\"",)"
      R"("likelihood_of_exploit":"High","mitigations":["escape output"],)"
      R"("examples":["CVE-2024-1234"],"parent_cwe":"CWE-74","cve_count":42,)"
      R"("kev_count":3,"avg_cvss":6.50,"avg_epss":0.0287,)"
      R"("updated_at":"2026-05-21T00:00:00+00:00"})" "\n", body);
  free(body);
}

void test_CWELOOKUP_golden_null_heap(void)
{
  CWELOOKUPRecord_t record;
  static_fillGoldenCwe(&record);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cwe_id":"CWE-79","name":"Improper Neutralization","abstraction":"Base","status":"Stable",)"
      R"("description":"XSS description","extended_description":null,)"
      R"("likelihood_of_exploit":"High","mitigations":null,)"
      R"("examples":null,"parent_cwe":"CWE-74","cve_count":42,)"
      R"("kev_count":3,"avg_cvss":6.50,"avg_epss":0.0287,)"
      R"("updated_at":"2026-05-21T00:00:00+00:00"})" "\n", body);
  free(body);
}

void test_CWELOOKUP_golden_empty_heap_matches_null_heap(void)
{
  CWELOOKUPRecord_t record;
  static_fillGoldenCwe(&record);
  record.mp_extendedDescription = strdup("");
  record.mp_mitigations         = strdup("");
  record.mp_examples            = strdup("");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_extendedDescription);
  free(record.mp_mitigations);
  free(record.mp_examples);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cwe_id":"CWE-79","name":"Improper Neutralization","abstraction":"Base","status":"Stable",)"
      R"("description":"XSS description","extended_description":null,)"
      R"("likelihood_of_exploit":"High","mitigations":null,)"
      R"("examples":null,"parent_cwe":"CWE-74","cve_count":42,)"
      R"("kev_count":3,"avg_cvss":6.50,"avg_epss":0.0287,)"
      R"("updated_at":"2026-05-21T00:00:00+00:00"})" "\n", body);
  free(body);
}

static char GOLDEN_CWES_DOCUMENT[] = R"(["CWE-917"])";
static char GOLDEN_NUCLEI_TEMPLATES_DOCUMENT[] =
  R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
  R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
  R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}])";

static void static_fillGoldenLookup(CVELOOKUPRecord_t* record, const char* cve_id)
{
  memset(record, 0, sizeof(*record));
  strncpy(record->ma_cveId, cve_id, CVELOOKUP_ID_MAX_LEN);
  strncpy(record->ma_description, "Log4Shell RCE", CVELOOKUP_DESC_MAX_LEN);
  strncpy(record->ma_severity, "CRITICAL", CVELOOKUP_SEVERITY_LEN);
  record->m_cvssV3 = 10.0;
  strncpy(record->ma_cvssV3Vector, "AV:N/AC:L/PR:N", CVELOOKUP_V3_VECTOR_LEN);
  strncpy(record->ma_publishedTime, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
  record->m_epssScore     = 0.97564;
  record->m_epssPercentile = 0.99977;
  strncpy(record->ma_cweId, "CWE-917", CVELOOKUP_CWE_ID_LEN);
  record->mp_cwes = GOLDEN_CWES_DOCUMENT;
  record->m_inKev = true;
  strncpy(record->ma_kevDateAdded, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
  strncpy(record->ma_vulnerabilityStatus, "Analyzed", CVELOOKUP_STATUS_LEN);
  strncpy(record->ma_ransomwareCampaign, "Known", CVELOOKUP_RANSOMWARE_LEN);
  record->m_pocCount             = 22;
  record->m_vendorAdvisoryCount  = 3;
  record->m_metasploitModuleCount = 2;
  record->m_isMetasploitFeedLoaded = true;
  record->m_nucleiTemplateCount        = 1;
  record->m_isNucleiTemplateFeedLoaded = true;
  record->mp_nucleiTemplates           = GOLDEN_NUCLEI_TEMPLATES_DOCUMENT;
  record->m_affectedProductCount       = 356;
  record->m_refCount                   = 52;
}

void test_CVELOOKUP_golden_sources(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_cvssV4 = 9.3;
  strncpy(record.ma_cvssV4Vector, "AV:N/AC:L", CVELOOKUP_V4_VECTOR_LEN);
  strncpy(record.ma_cvssV3Source, "nvd", CVELOOKUP_SOURCE_LEN);
  strncpy(record.ma_cvssV4Source, "cna", CVELOOKUP_SOURCE_LEN);
  strncpy(record.ma_cweSource,    "adp", CVELOOKUP_SOURCE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":"nvd","cvss_v4":9.3,"cvss_v4_vector":"AV:N/AC:L","cvss_v4_source":"cna",)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":"adp",)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVESEARCH_golden_sources(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  strncpy(items[0].ma_cvssV3Source, "nvd",   CVELOOKUP_SOURCE_LEN);
  strncpy(items[0].ma_cvssV4Source, "cna",   CVELOOKUP_SOURCE_LEN);
  strncpy(items[0].ma_cweSource,    "adp",   CVELOOKUP_SOURCE_LEN);
  strncpy(items[1].ma_cvssV3Source, "other", CVELOOKUP_SOURCE_LEN);
  CveListResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,"results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":"nvd","cvss_v4":null,"cvss_v4_source":"cna","epss_score":0.97564,"epss_percentile":0.99977,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":"adp"},)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":"other","cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_ghsa_hint_url(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_metasploit_null_when_the_feed_is_not_loaded(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isMetasploitFeedLoaded = false;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":null,"metasploit_module_count":null,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_nuclei_templates_not_synced_when_the_feed_is_not_loaded(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isNucleiTemplateFeedLoaded = false;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body,
    R"("metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":false,"reason":"not_synced","count":0,"templates":[]},)"
    R"("description":"Log4Shell RCE",)"), body);
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "template_id"), body);
  free(body);
}

void test_CVELOOKUP_nuclei_templates_count_is_written_apart_from_the_list(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_nucleiTemplateCount = 7;
  record.mp_nucleiTemplates    = NULL;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body,
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":7,"templates":[]},)"), body);
  free(body);
}

void test_CVELOOKUP_golden_ghsa_null_when_enriched_without_advisory(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isGhsaAsked      = true;
  record.m_isGhsaFeedLoaded = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":null})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_ghsa_advisory_is_written_as_it_is(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isGhsaAsked      = true;
  record.m_isGhsaFeedLoaded = true;
  record.mp_ghsa = strdup(R"({"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "affected": [{"package": "org.apache.logging.log4j:log4j-core", )"
                          R"("ecosystem": "Maven", "patched_versions": "2.15.0", "vulnerable_version_range": ">= 2.13.0, < 2.15.0"}], )"
                          R"("attribution": {"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}, )"
                          R"("affected_total": 10})");
  TEST_ASSERT_NOT_NULL(record.mp_ghsa);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":{"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "affected": [{"package": "org.apache.logging.log4j:log4j-core", )"
    R"("ecosystem": "Maven", "patched_versions": "2.15.0", "vulnerable_version_range": ">= 2.13.0, < 2.15.0"}], )"
    R"("attribution": {"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}, )"
    R"("affected_total": 10}})" "\n", body);
  free(body);
  free(record.mp_ghsa);
}

void test_CVELOOKUP_golden_ghsa_not_synced(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isGhsaAsked = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":{"available":false,"reason":"not_synced"}})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_ghsa_database_error(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_isGhsaAsked     = true;
  record.m_ghsaUnavailable = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":{"available":false,"reason":"database_error"}})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_ransomware_null_outside_kev(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_inKev                  = false;
  record.ma_kevDateAdded[0]       = '\0';
  record.ma_ransomwareCampaign[0] = '\0';

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":false,"kev_date_added":"",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":null,)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

#define CVSS_V4_GOLDEN_VECTOR "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

void test_CVELOOKUP_cvss_v4_follows_its_vector_and_range(void)
{
  static const struct { double m_score; bool m_hasVector; const char* mp_json; } cases[] = {
    { 9.3,  false, R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,"published_time")" },
    { 9.3,  true,  R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":9.3,"cvss_v4_vector":")" CVSS_V4_GOLDEN_VECTOR R"(","cvss_v4_source":null,"published_time")" },
    { 11.0, true,  R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":10.0,"cvss_v4_vector":")" CVSS_V4_GOLDEN_VECTOR R"(","cvss_v4_source":null,"published_time")" },
    { -1.0, true,  R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":0.0,"cvss_v4_vector":")" CVSS_V4_GOLDEN_VECTOR R"(","cvss_v4_source":null,"published_time")" },
    { NAN,  true,  R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":0.0,"cvss_v4_vector":")" CVSS_V4_GOLDEN_VECTOR R"(","cvss_v4_source":null,"published_time")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVELOOKUPRecord_t record;
    static_fillGoldenLookup(&record, "CVE-2021-44228");
    record.m_cvssV4 = cases[i].m_score;
    if (cases[i].m_hasVector)
      strncpy(record.ma_cvssV4Vector, CVSS_V4_GOLDEN_VECTOR, CVELOOKUP_V4_VECTOR_LEN);

    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVELOOKUP_response(&record, json_buf);
    char* body = static_finishJsonBuf(json_buf);

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_json), cases[i].mp_json);
    free(body);
  }
}

void test_CVELOOKUP_cvss_v3_follows_its_vector_and_range(void)
{
  static const struct { double m_score; bool m_hasVector; const char* mp_json; } cases[] = {
    { 10.0, false, R"("severity":"CRITICAL","cvss_v3":null,"cvss_v3_vector":null,"cvss_v3_source":null,"cvss_v4")" },
    { 10.0, true,  R"("severity":"CRITICAL","cvss_v3":10.0,"cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4")" },
    { 11.0, true,  R"("severity":"CRITICAL","cvss_v3":10.0,"cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4")" },
    { -1.0, true,  R"("severity":"CRITICAL","cvss_v3":0.0,"cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4")" },
    { NAN,  true,  R"("severity":"CRITICAL","cvss_v3":0.0,"cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVELOOKUPRecord_t record;
    static_fillGoldenLookup(&record, "CVE-2021-44228");
    record.m_cvssV3 = cases[i].m_score;
    if (!cases[i].m_hasVector)
      record.ma_cvssV3Vector[0] = '\0';

    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVELOOKUP_response(&record, json_buf);
    char* body = static_finishJsonBuf(json_buf);

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_json), cases[i].mp_json);
    free(body);
  }
}

void test_CVELOOKUP_booleans_follow_their_own_fields(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.m_inKev = false;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("in_kev":false,)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("has_metasploit_module":true,)"), body);
  free(body);

  record.m_inKev = true;
  record.m_metasploitModuleCount = 0;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("in_kev":true,)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("has_metasploit_module":false,)"), body);
  free(body);
}

void test_CVELOOKUP_one_metasploit_module_is_a_module(void)
{
  CVELOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_metasploitModuleCount  = 1;
  record.m_isMetasploitFeedLoaded = true;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("has_metasploit_module":true,"metasploit_module_count":1,)"), body);
  free(body);
}

void test_CVELOOKUP_golden_raw_json_fields_passed_through(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_affectedProducts = strdup(R"([{"vendor":"apache","product":"log4j"}])");
  record.mp_productCountByVendor = strdup(R"({"apache":4,"cisco":258})");
  record.mp_refs             = strdup(R"([{"url":"https://example.test/a"}])");
  record.mp_epssTrend        = strdup(R"([{"epss_date":"2026-09-01","score":0.97}])");
  record.mp_cveTags          = strdup(R"(["exclusively-hosted-service"])");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_affectedProducts);
  free(record.mp_productCountByVendor);
  free(record.mp_refs);
  free(record.mp_epssTrend);
  free(record.mp_cveTags);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[{"vendor":"apache","product":"log4j"}],)"
    R"("affected_product_count":356,"product_count_by_vendor":{"apache":4,"cisco":258},)"
    R"("refs":[{"url":"https://example.test/a"}],"ref_count":52,)"
    R"("poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[{"epss_date":"2026-09-01","score":0.97}],)"
    R"("cve_tags":["exclusively-hosted-service"],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_description_escaped(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  strncpy(record.ma_description, "quote \" backslash \\ newline \n tab \t unit \x1f", CVELOOKUP_DESC_MAX_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"quote \" backslash \\ newline \n tab \t unit \u001f",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUPBULK_golden_zero_successful(void)
{
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total     = 2;
  results.m_processed = 2;
  results.m_skipped   = 1;
  results.m_failed    = 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2,"processed":2,"successful":0,"skipped":1,"failed":1,"not_processed":[],"results":[]})",
    body);
  free(body);
}

void test_CVELOOKUPBULK_golden_not_processed_ids(void)
{
  char not_processed_ids[2][BULK_ID_MAX_LEN + 1] = { "CVE-2023-0001", "CVE-2023-\"2" };
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total              = 4;
  results.m_processed          = 2;
  results.m_failed             = 2;
  results.mp_notProcessedIds   = not_processed_ids;
  results.m_notProcessedCount  = 2;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":4,"processed":2,"successful":0,"skipped":0,"failed":2,"not_processed":["CVE-2023-0001","CVE-2023-\"2"],"results":[]})",
    body);
  free(body);
}

void test_CVELOOKUPBULK_golden_newline_between_elements(void)
{
  CVELOOKUPRecord_t items[2];
  static_fillGoldenLookup(&items[0], "CVE-2021-44228");
  static_fillGoldenLookup(&items[1], "CVE-2024-3400");
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 2;
  results.m_processed  = 2;
  results.m_successful = 2;
  results.mp_items     = items;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2,"processed":2,"successful":2,"skipped":0,"failed":0,"not_processed":[],"results":[)"
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n"
    ","
    R"({"cve_id":"CVE-2024-3400","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2024-3400?include_ghsa=true"})" "\n"
    "]}",
    body);
  free(body);
}

void test_CVEEXPLOIT_golden_all_sources_available_and_empty(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable     = true;
  record.m_metasploitAvailable = true;
  record.m_nvdAvailable        = true;
  record.m_exploitdbAvailable  = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_unavailable_sources_hide_their_other_fields(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubPocRepoTotal        = 9;
  record.m_githubTopStarredRepoCount = 1;
  strncpy(record.ma_githubTopStarredRepos[0].ma_url, "https://github.test/a/poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[0].ma_name, "a/poc", CVEEXPLOIT_REPO_NAME_LEN);
  record.m_metasploitModuleTotal = 4;
  record.m_metasploitModuleCount = 1;
  strncpy(record.ma_metasploitModules[0].ma_name, "exploit/multi/http/log4shell", CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  record.m_inKev              = true;
  record.m_nvdExploitRefTotal = 9;
  record.m_nvdExploitRefCount = 1;
  strncpy(record.ma_nvdExploitRefs[0].ma_url, "https://nvd.test/exploit/a", CVEEXPLOIT_NVD_REF_URL_LEN);
  record.m_exploitdbEntryTotal = 6;
  record.m_exploitdbEntryCount = 1;
  record.ma_exploitdbEntries[0].m_edbId = 50383;
  strncpy(record.ma_exploitdbEntries[0].ma_type, "webapps", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":null,"has_public_exploit":null,"in_kev":null,"sources":[)"
      R"({"source":"github","available":false,"reason":"database_error","count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":false,"reason":"database_error","has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":false,"reason":"database_error","count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":false,"reason":"database_error","license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_empty_metasploit_table_is_not_synced(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable        = true;
  record.m_isMetasploitTableEmpty = true;
  record.m_metasploitModuleTotal  = 4;
  record.m_nvdAvailable           = true;
  record.m_exploitdbAvailable     = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":false,"reason":"not_synced","has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_empty_github_table_is_not_synced(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_isGithubTableEmpty        = true;
  record.m_githubPocRepoTotal        = 4;
  record.m_githubTopStarredRepoCount = 1;
  strncpy(record.ma_githubTopStarredRepos[0].ma_url, "https://github.test/a/poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[0].ma_name, "a/poc", CVEEXPLOIT_REPO_NAME_LEN);
  record.m_metasploitAvailable       = true;
  record.m_nvdAvailable              = true;
  record.m_exploitdbAvailable        = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":null,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":false,"reason":"not_synced","count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_github_unavailable_metasploit_found(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubPocRepoTotal    = 9;
  record.m_metasploitAvailable   = true;
  record.m_metasploitModuleTotal = 2;
  record.m_metasploitModuleCount = 1;
  strncpy(record.ma_metasploitModules[0].ma_name, "exploit_multi/http/log4shell", CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  strncpy(record.ma_metasploitModules[0].ma_type, "exploit", CVEEXPLOIT_METASPLOIT_TYPE_LEN);
  record.m_nvdAvailable          = true;
  record.m_exploitdbAvailable    = true;
  record.m_inKev                 = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":null,"has_public_exploit":true,"in_kev":true,"sources":[)"
      R"({"source":"github","available":false,"reason":"database_error","count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":true,"count":2,"top_results":[)"
        R"({"name":"exploit_multi/http/log4shell","type":"exploit"}]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_all_sources_two_items(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable           = true;
  record.m_githubPocRepoTotal        = 127;
  record.m_githubTopStarredRepoCount = 2;
  strncpy(record.ma_githubTopStarredRepos[0].ma_url, "https://github.test/a/poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[0].ma_name, "a/poc", CVEEXPLOIT_REPO_NAME_LEN);
  record.ma_githubTopStarredRepos[0].m_starCount = 500;
  strncpy(record.ma_githubTopStarredRepos[1].ma_url, "https://github.test/b/poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[1].ma_name, "b/poc", CVEEXPLOIT_REPO_NAME_LEN);
  record.ma_githubTopStarredRepos[1].m_starCount = 12;
  record.m_metasploitAvailable   = true;
  record.m_metasploitModuleTotal = 5;
  record.m_metasploitModuleCount = 2;
  strncpy(record.ma_metasploitModules[0].ma_name, "exploit_multi/http/log4shell", CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  strncpy(record.ma_metasploitModules[0].ma_type, "exploit", CVEEXPLOIT_METASPLOIT_TYPE_LEN);
  strncpy(record.ma_metasploitModules[1].ma_name, "auxiliary_scanner/log4shell", CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  strncpy(record.ma_metasploitModules[1].ma_type, "auxiliary", CVEEXPLOIT_METASPLOIT_TYPE_LEN);
  record.m_nvdAvailable       = true;
  record.m_inKev              = true;
  record.m_nvdExploitRefTotal = 11;
  record.m_nvdExploitRefCount = 2;
  strncpy(record.ma_nvdExploitRefs[0].ma_url, "https://nvd.test/exploit/a", CVEEXPLOIT_NVD_REF_URL_LEN);
  strncpy(record.ma_nvdExploitRefs[1].ma_url, "https://nvd.test/exploit/b", CVEEXPLOIT_NVD_REF_URL_LEN);
  record.m_exploitdbAvailable  = true;
  record.m_exploitdbEntryTotal = 8;
  record.m_exploitdbEntryCount = 2;
  record.ma_exploitdbEntries[0].m_edbId      = 50592;
  record.ma_exploitdbEntries[0].m_isVerified = true;
  strncpy(record.ma_exploitdbEntries[0].ma_url, "https://edb.test/50592", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_type, "remote", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_platform, "java", CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN);
  snprintf(record.ma_exploitdbEntries[0].ma_datePublished, sizeof(record.ma_exploitdbEntries[0].ma_datePublished), "%s", "2021-12-14");
  record.ma_exploitdbEntries[1].m_edbId = 50590;
  strncpy(record.ma_exploitdbEntries[1].ma_url, "https://edb.test/50590", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[1].ma_type, "webapps", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);
  strncpy(record.ma_exploitdbEntries[1].ma_platform, "multiple", CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN);
  snprintf(record.ma_exploitdbEntries[1].ma_datePublished, sizeof(record.ma_exploitdbEntries[1].ma_datePublished), "%s", "2021-12-13");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":127,"has_public_exploit":true,"in_kev":true,"sources":[)"
      R"({"source":"github","available":true,"count":127,"top_results":[)"
        R"({"url":"https://github.test/a/poc","name":"a/poc","stars":500},)"
        R"({"url":"https://github.test/b/poc","name":"b/poc","stars":12}]},)"
      R"({"source":"metasploit","available":true,"has_module":true,"count":5,"top_results":[)"
        R"({"name":"exploit_multi/http/log4shell","type":"exploit"},)"
        R"({"name":"auxiliary_scanner/log4shell","type":"auxiliary"}]},)"
      R"({"source":"nvd","available":true,"count":11,"top_results":[)"
        R"({"url":"https://nvd.test/exploit/a"},)"
        R"({"url":"https://nvd.test/exploit/b"}]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":8,"top_results":[)"
        R"({"edb_id":50592,"url":"https://edb.test/50592","type":"remote","platform":"java","date_published":"2021-12-14","verified":true},)"
        R"({"edb_id":50590,"url":"https://edb.test/50590","type":"webapps","platform":"multiple","date_published":"2021-12-13","verified":false}]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_cve_not_in_local_database_is_unknown(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable       = true;
  record.m_metasploitAvailable   = true;
  record.m_cveNotInLocalDatabase = true;
  record.m_exploitdbAvailable    = true;
  record.m_inKev                 = true;
  record.m_nvdExploitRefTotal    = 3;
  record.m_nvdExploitRefCount    = 1;
  strncpy(record.ma_nvdExploitRefs[0].ma_url, "https://nvd.test/exploit/a", CVEEXPLOIT_NVD_REF_URL_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":null,"in_kev":null,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":false,"reason":"cve_not_in_database","count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_nvd_every_slot_is_written(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2006-4189", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable     = true;
  record.m_metasploitAvailable = true;
  record.m_nvdAvailable        = true;
  record.m_exploitdbAvailable  = true;
  record.m_nvdExploitRefTotal  = 41;
  record.m_nvdExploitRefCount  = CVEEXPLOIT_NVD_MAX_REFS;
  for (int i = 0; i < CVEEXPLOIT_NVD_MAX_REFS; i++)
    snprintf(record.ma_nvdExploitRefs[i].ma_url, sizeof(record.ma_nvdExploitRefs[i].ma_url), "https://nvd.test/%d", i + 1);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2006-4189","exploits_found":0,"has_public_exploit":true,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":41,"top_results":[)"
        R"({"url":"https://nvd.test/1"},{"url":"https://nvd.test/2"},{"url":"https://nvd.test/3"},)"
        R"({"url":"https://nvd.test/4"},{"url":"https://nvd.test/5"}]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_has_public_exploit_follows_every_source(void)
{
  typedef struct {
    bool        m_metasploitAvailable;
    int         m_metasploitTotal;
    bool        m_nvdAvailable;
    int         m_nvdTotal;
    bool        m_exploitdbAvailable;
    int         m_exploitdbTotal;
    const char* mp_expected;
  } HasPublicExploitRow_t;

  typedef struct {
    bool m_githubAvailable;
    int  m_githubTotal;
  } GithubState_t;

  static const HasPublicExploitRow_t rows[] = {
    { false, 3, false, 3, false, 3, R"("has_public_exploit":null,)"  },
    { false, 3, false, 3, true,  0, R"("has_public_exploit":null,)"  },
    { false, 3, false, 3, true,  3, R"("has_public_exploit":true,)"  },
    { false, 3, true,  0, false, 3, R"("has_public_exploit":null,)"  },
    { false, 3, true,  0, true,  0, R"("has_public_exploit":null,)"  },
    { false, 3, true,  0, true,  3, R"("has_public_exploit":true,)"  },
    { false, 3, true,  3, false, 3, R"("has_public_exploit":true,)"  },
    { false, 3, true,  3, true,  0, R"("has_public_exploit":true,)"  },
    { false, 3, true,  3, true,  3, R"("has_public_exploit":true,)"  },
    { true,  0, false, 3, false, 3, R"("has_public_exploit":null,)"  },
    { true,  0, false, 3, true,  0, R"("has_public_exploit":null,)"  },
    { true,  0, false, 3, true,  3, R"("has_public_exploit":true,)"  },
    { true,  0, true,  0, false, 3, R"("has_public_exploit":null,)"  },
    { true,  0, true,  0, true,  0, R"("has_public_exploit":null,)"  },
    { true,  0, true,  0, true,  3, R"("has_public_exploit":true,)"  },
    { true,  0, true,  3, false, 3, R"("has_public_exploit":true,)"  },
    { true,  0, true,  3, true,  0, R"("has_public_exploit":true,)"  },
    { true,  0, true,  3, true,  3, R"("has_public_exploit":true,)"  },
    { true,  3, false, 3, false, 3, R"("has_public_exploit":true,)"  },
    { true,  3, false, 3, true,  0, R"("has_public_exploit":true,)"  },
    { true,  3, false, 3, true,  3, R"("has_public_exploit":true,)"  },
    { true,  3, true,  0, false, 3, R"("has_public_exploit":true,)"  },
    { true,  3, true,  0, true,  0, R"("has_public_exploit":true,)"  },
    { true,  3, true,  0, true,  3, R"("has_public_exploit":true,)"  },
    { true,  3, true,  3, false, 3, R"("has_public_exploit":true,)"  },
    { true,  3, true,  3, true,  0, R"("has_public_exploit":true,)"  },
    { true,  3, true,  3, true,  3, R"("has_public_exploit":true,)"  },
    { true,  1, true,  0, true,  0, R"("has_public_exploit":true,)"  },
    { true,  0, true,  1, true,  0, R"("has_public_exploit":true,)"  },
    { true,  0, true,  0, true,  1, R"("has_public_exploit":true,)"  },
  };
  static const GithubState_t github_states[] = { { false, 3 }, { true, 0 }, { true, 3 } };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    for (size_t g = 0; g < sizeof(github_states) / sizeof(github_states[0]); g++)
    {
      CVEEXPLOITRecord_t record;
      memset(&record, 0, sizeof(record));
      strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
      record.m_githubAvailable       = github_states[g].m_githubAvailable;
      record.m_githubPocRepoTotal    = github_states[g].m_githubTotal;
      record.m_metasploitAvailable   = rows[i].m_metasploitAvailable;
      record.m_metasploitModuleTotal = rows[i].m_metasploitTotal;
      record.m_nvdAvailable          = rows[i].m_nvdAvailable;
      record.m_nvdExploitRefTotal    = rows[i].m_nvdTotal;
      record.m_exploitdbAvailable    = rows[i].m_exploitdbAvailable;
      record.m_exploitdbEntryTotal   = rows[i].m_exploitdbTotal;

      JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
      serialize_CVEEXPLOIT_response(&record, json_buf);
      char* body = static_finishJsonBuf(json_buf);

      char message[48];
      snprintf(message, sizeof(message), "row %zu, github state %zu", i, g);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, rows[i].mp_expected), message);
      free(body);
    }
  }
}

void test_CVEEXPLOIT_golden_github_only_is_not_proof(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable           = true;
  record.m_githubPocRepoTotal        = 3;
  record.m_githubTopStarredRepoCount = 1;
  strncpy(record.ma_githubTopStarredRepos[0].ma_url, "https://github.test/a/poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[0].ma_name, "a/poc", CVEEXPLOIT_REPO_NAME_LEN);
  record.ma_githubTopStarredRepos[0].m_starCount = 40;
  record.m_metasploitAvailable       = true;
  record.m_nvdAvailable              = true;
  record.m_exploitdbAvailable        = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":3,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":3,"top_results":[)"
        R"({"url":"https://github.test/a/poc","name":"a/poc","stars":40}]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_exploitdb_entries(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable     = true;
  record.m_metasploitAvailable = true;
  record.m_nvdAvailable        = true;
  record.m_exploitdbAvailable  = true;
  record.m_exploitdbEntryTotal = 12;
  record.m_exploitdbEntryCount = 3;
  record.ma_exploitdbEntries[0].m_edbId      = 50383;
  record.ma_exploitdbEntries[0].m_isVerified = true;
  strncpy(record.ma_exploitdbEntries[0].ma_url, "https://www.exploit-db.com/exploits/50383", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_type, "webapps", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_platform, "php", CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN);
  snprintf(record.ma_exploitdbEntries[0].ma_datePublished, sizeof(record.ma_exploitdbEntries[0].ma_datePublished), "%s", "2021-12-14");
  record.ma_exploitdbEntries[1].m_edbId = 49001;
  strncpy(record.ma_exploitdbEntries[1].ma_url, "https://www.exploit-db.com/exploits/49001", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[1].ma_type, "local", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);
  record.ma_exploitdbEntries[2].m_edbId      = 48002;
  record.ma_exploitdbEntries[2].m_isVerified = true;
  strncpy(record.ma_exploitdbEntries[2].ma_url, "https://www.exploit-db.com/exploits/48002", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[2].ma_platform, "a\"b", CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN);
  snprintf(record.ma_exploitdbEntries[2].ma_datePublished, sizeof(record.ma_exploitdbEntries[2].ma_datePublished), "%s", "2019-01-02");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":true,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":12,"top_results":[)"
        R"({"edb_id":50383,"url":"https://www.exploit-db.com/exploits/50383","type":"webapps","platform":"php","date_published":"2021-12-14","verified":true},)"
        R"({"edb_id":49001,"url":"https://www.exploit-db.com/exploits/49001","type":"local","platform":"","date_published":null,"verified":false},)"
        R"({"edb_id":48002,"url":"https://www.exploit-db.com/exploits/48002","type":"","platform":"a\"b","date_published":"2019-01-02","verified":true}]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_exploitdb_unavailable_hides_its_fields(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable     = true;
  record.m_metasploitAvailable = true;
  record.m_nvdAvailable        = true;
  record.m_exploitdbEntryTotal = 5;
  record.m_exploitdbEntryCount = 1;
  record.ma_exploitdbEntries[0].m_edbId = 50383;
  strncpy(record.ma_exploitdbEntries[0].ma_type, "webapps", CVEEXPLOIT_EXPLOITDB_TYPE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":false,"reason":"database_error","license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_golden_empty_exploitdb_table_is_not_synced(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable       = true;
  record.m_metasploitAvailable   = true;
  record.m_nvdAvailable          = true;
  record.m_isExploitdbTableEmpty = true;
  record.m_exploitdbEntryTotal   = 4;
  record.m_exploitdbEntryCount   = 1;
  record.ma_exploitdbEntries[0].m_edbId = 50383;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","exploits_found":0,"has_public_exploit":null,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":0,"top_results":[]},)"
      R"({"source":"metasploit","available":true,"has_module":false,"count":0,"top_results":[]},)"
      R"({"source":"nvd","available":true,"count":0,"top_results":[]},)"
      R"({"source":"exploitdb","available":false,"reason":"not_synced","license":"GPL-2.0-only","count":0,"top_results":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_has_module_follows_the_total_not_the_stored_names(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record.m_metasploitAvailable   = true;
  record.m_metasploitModuleTotal = 1;
  record.m_metasploitModuleCount = 0;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"({"source":"metasploit","available":true,"has_module":true,"count":1,"top_results":[]})"), body);
  free(body);
}

#define PRODUCT_FILTER_NOTE_GOLDEN \
  R"("product_filter_note":"This filter matches names exactly. It can miss a CVE whose CNA spelled the vendor or product another way. Use cpe_search to find other spellings.",)"

#define CVETRIAGE_GOLDEN_ITEM_PAIR \
  R"({"cve_id":"CVE-2021-44228","risk_score":96.5,"label":"CRITICAL"},)" \
  R"({"cve_id":"CVE-2024-3400","risk_score":71.0,"label":"HIGH"})"

static void static_fillGoldenTriagePair(CVETRIAGEItem_t* items)
{
  static_fillTriageItem(&items[0]);
  memset(&items[1], 0, sizeof(items[1]));
  strncpy(items[1].ma_cveId, "CVE-2024-3400", CVELOOKUP_ID_MAX_LEN);
  items[1].m_riskScore = 71.0;
  strncpy(items[1].ma_label, "HIGH", CVERISKSCORE_LABEL_LEN);
}

void test_CVETRIAGE_golden_empty(void)
{
  CVETRIAGEResult_t results = { .m_total = 0, .m_count = 0, .mp_items = NULL };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(R"({"total":0,"limit":20,"offset":0,"next_offset":0,"results":[]})" "\n", body);
  free(body);
}

void test_CVETRIAGE_golden_two_items(void)
{
  CVETRIAGEItem_t items[2];
  static_fillGoldenTriagePair(items);
  CVETRIAGEResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,"results":[)"
    CVETRIAGE_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_CVETRIAGE_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  CVETRIAGEItem_t items[2];
  static_fillGoldenTriagePair(items);
  CVETRIAGEResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(64, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,"results":[)"
    CVETRIAGE_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_CVETRIAGE_over_ceiling_hands_back_no_body(void)
{
  CVETRIAGEItem_t items[2];
  static_fillGoldenTriagePair(items);
  CVETRIAGEResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_CVETRIAGE_response(&results, &params, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

void test_CVETRIAGE_escape_heavy_item_is_escaped_and_complete(void)
{
  CVETRIAGEItem_t item;
  static_fillTriageItem(&item);
  memset(item.ma_cveId, '"', CVELOOKUP_ID_MAX_LEN);
  item.ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
  memset(item.ma_label, '\\', CVERISKSCORE_LABEL_LEN);
  item.ma_label[CVERISKSCORE_LABEL_LEN] = '\0';

  CVETRIAGEResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 20;
  params.m_offset = 0;

  char escaped_id[2 * CVELOOKUP_ID_MAX_LEN + 1];
  for (int i = 0; i < CVELOOKUP_ID_MAX_LEN; i++)
  {
    escaped_id[2 * i]     = '\\';
    escaped_id[2 * i + 1] = '"';
  }
  escaped_id[2 * CVELOOKUP_ID_MAX_LEN] = '\0';

  char escaped_label[2 * CVERISKSCORE_LABEL_LEN + 1];
  for (int i = 0; i < CVERISKSCORE_LABEL_LEN; i++)
  {
    escaped_label[2 * i]     = '\\';
    escaped_label[2 * i + 1] = '\\';
  }
  escaped_label[2 * CVERISKSCORE_LABEL_LEN] = '\0';

  char expected[512];
  snprintf(expected, sizeof(expected),
    R"({"total":1,"limit":20,"offset":0,"next_offset":1,"results":[)"
    R"({"cve_id":"%s","risk_score":96.5,"label":"%s"}]})" "\n", escaped_id, escaped_label);

  JsonBuf_t* json_buf = static_newJsonBuf(64, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(expected, body);
  free(body);
}

void test_CVETRIAGEBULK_golden_zero_successful(void)
{
  CVETRIAGEBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total     = 3;
  results.m_processed = 2;
  results.m_skipped   = 1;
  results.m_failed    = 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGEBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":3,"processed":2,"successful":0,"skipped":1,"failed":1,"not_processed":[],"results":[]})" "\n", body);
  free(body);
}

void test_CVETRIAGEBULK_golden_not_processed_ids(void)
{
  char not_processed_ids[2][BULK_ID_MAX_LEN + 1] = { "CVE-2023-0001", "CVE-2023-0002" };
  CVETRIAGEBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total              = 3;
  results.m_processed          = 1;
  results.m_failed             = 1;
  results.mp_notProcessedIds   = not_processed_ids;
  results.m_notProcessedCount  = 2;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGEBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":3,"processed":1,"successful":0,"skipped":0,"failed":1,"not_processed":["CVE-2023-0001","CVE-2023-0002"],"results":[]})" "\n", body);
  free(body);
}

void test_CVETRIAGEBULK_golden_two_items(void)
{
  CVETRIAGEItem_t items[3];
  static_fillGoldenTriagePair(items);
  memset(&items[2], 0, sizeof(items[2]));
  strncpy(items[2].ma_cveId, "CVE-2019-0708", CVELOOKUP_ID_MAX_LEN);
  items[2].m_riskScore = 55.0;
  strncpy(items[2].ma_label, "MEDIUM", CVERISKSCORE_LABEL_LEN);
  CVETRIAGEBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 3;
  results.m_processed  = 3;
  results.m_successful = 2;
  results.m_skipped    = 1;
  results.mp_items     = items;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGEBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":3,"processed":3,"successful":2,"skipped":1,"failed":0,"not_processed":[],"results":[)"
    CVETRIAGE_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_no_top_cves(void)
{
  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_vendor, "cisco", CVESEARCH_VENDOR_LEN);
  strncpy(record.ma_product, "ios", CVESEARCH_PRODUCT_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"vendor":"cisco","product":"ios","exposure":{)"
      R"("total_cves":0,"critical":0,"high":0,"medium":0,"low":0,"kev_count":0,)"
      R"("max_cvss":0.0,"avg_cvss":0.00,"max_epss":0.0000,"poc_backed_count":0,)"
      R"("worst_risk_score":0.0,"most_recent_published":""},)"
      PRODUCT_FILTER_NOTE_GOLDEN
      R"("top_cves":[],"eol":null})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_envelope_strings_are_escaped(void)
{
  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_vendor,  R"(ci"sco)", CVESEARCH_VENDOR_LEN);
  strncpy(record.ma_product, R"(i\os)",   CVESEARCH_PRODUCT_LEN);
  strncpy(record.ma_mostRecentPublished, R"(2024"01)", CVELOOKUP_PUBLISHED_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"vendor":"ci\"sco","product":"i\\os","exposure":{)"
      R"("total_cves":0,"critical":0,"high":0,"medium":0,"low":0,"kev_count":0,)"
      R"("max_cvss":0.0,"avg_cvss":0.00,"max_epss":0.0000,"poc_backed_count":0,)"
      R"("worst_risk_score":0.0,"most_recent_published":"2024\"01"},)"
      PRODUCT_FILTER_NOTE_GOLDEN
      R"("top_cves":[],"eol":null})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_two_top_cves(void)
{
  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_vendor, "cisco", CVESEARCH_VENDOR_LEN);
  strncpy(record.ma_product, "ios", CVESEARCH_PRODUCT_LEN);
  record.m_totalCveCount  = 613;
  record.m_criticalCount  = 10;
  record.m_highCount      = 20;
  record.m_mediumCount    = 8;
  record.m_lowCount       = 4;
  record.m_kevCount       = 38;
  record.m_maxCvss        = 10.0;
  record.m_avgCvss        = 6.42;
  record.m_maxEpss        = 0.97531;
  record.m_pocBackedCount = 12;
  record.m_worstRiskScore = 96.5;
  strncpy(record.ma_mostRecentPublished, "2024-01-15T00:00:00Z", CVELOOKUP_PUBLISHED_LEN);
  static_fillGoldenTriagePair(record.ma_topCves);
  record.m_topCveCount = 2;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"vendor":"cisco","product":"ios","exposure":{)"
      R"("total_cves":613,"critical":10,"high":20,"medium":8,"low":4,"kev_count":38,)"
      R"("max_cvss":10.0,"avg_cvss":6.42,"max_epss":0.9753,"poc_backed_count":12,)"
      R"("worst_risk_score":96.5,"most_recent_published":"2024-01-15T00:00:00Z"},)"
      PRODUCT_FILTER_NOTE_GOLDEN
      R"("top_cves":[)"
    CVETRIAGE_GOLDEN_ITEM_PAIR
    R"(],"eol":null})" "\n", body);
  free(body);
}

static void static_setEolCycle(PRODUCTEXPOSUREEolCycle_t* cycle, const char* name, const char* eol_date,
                               bool is_eol, bool is_maintained, bool is_lts, const char* latest_version)
{
  snprintf(cycle->ma_name,          sizeof(cycle->ma_name),          "%s", name);
  snprintf(cycle->ma_eolDate,       sizeof(cycle->ma_eolDate),       "%s", eol_date);
  snprintf(cycle->ma_latestVersion, sizeof(cycle->ma_latestVersion), "%s", latest_version);
  cycle->m_isEol        = is_eol;
  cycle->m_isMaintained = is_maintained;
  cycle->m_isLts        = is_lts;
}

static void static_newEolRecord(PRODUCTEXPOSURERecord_t* record)
{
  memset(record, 0, sizeof(*record));
  strncpy(record->ma_vendor, "cisco", CVESEARCH_VENDOR_LEN);
  strncpy(record->ma_product, "ios", CVESEARCH_PRODUCT_LEN);
  record->m_eol.m_hasEol = true;
  strncpy(record->m_eol.ma_eolProduct, "nodejs", PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  strncpy(record->m_eol.ma_eolUrl, "https://endoflife.date/nodejs", PRODUCTEXPOSURE_EOL_URL_MAX_LEN);
}

#define PRODUCTEXPOSURE_GOLDEN_HEAD \
  R"({"vendor":"cisco","product":"ios","exposure":{)" \
    R"("total_cves":0,"critical":0,"high":0,"medium":0,"low":0,"kev_count":0,)" \
    R"("max_cvss":0.0,"avg_cvss":0.00,"max_epss":0.0000,"poc_backed_count":0,)" \
    R"("worst_risk_score":0.0,"most_recent_published":""},)" \
    PRODUCT_FILTER_NOTE_GOLDEN \
    R"("top_cves":[],)"

void test_PRODUCTEXPOSURE_golden_eol_one_cycle(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[0], "2\"2", "2027-04-30", false, true, false, "22.21.1");
  record.m_eol.m_eolSeriesCycleCount = 1;
  static_setEolCycle(&record.m_eol.ma_eolMaintainedCycles[0], "26", "2029-04-30", false, true, false, "26.0.1");
  static_setEolCycle(&record.m_eol.ma_eolMaintainedCycles[1], "2\"4", "", false, true, true, "24.1.0");
  record.m_eol.m_eolMaintainedCycleCount = 2;
  record.m_eol.m_hasMoreEolMaintainedCycles = true;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"nodejs","url":"https://endoflife.date/nodejs",)"
      R"("cycle":{"name":"2\"2","eol_date":"2027-04-30","is_eol":false,"is_maintained":true,"is_lts":false,"latest_version":"22.21.1"},)"
      R"("cycle_variants":null,)"
      R"("maintained_cycles":[{"name":"26","eol_date":"2029-04-30","is_lts":false},{"name":"2\"4","eol_date":null,"is_lts":true}],)"
      R"("maintained_cycles_truncated":true}})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_eol_cycle_without_date(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[0], "2", "", true, false, false, "");
  record.m_eol.m_eolSeriesCycleCount = 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"nodejs","url":"https://endoflife.date/nodejs",)"
      R"("cycle":{"name":"2","eol_date":null,"is_eol":true,"is_maintained":false,"is_lts":false,"latest_version":null},)"
      R"("cycle_variants":null,"maintained_cycles":[],"maintained_cycles_truncated":false}})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_eol_lts_cycle(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[0], "20", "2026-04-30", false, true, true, "20.19.5");
  record.m_eol.m_eolSeriesCycleCount = 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"nodejs","url":"https://endoflife.date/nodejs",)"
      R"("cycle":{"name":"20","eol_date":"2026-04-30","is_eol":false,"is_maintained":true,"is_lts":true,"latest_version":"20.19.5"},)"
      R"("cycle_variants":null,"maintained_cycles":[],"maintained_cycles_truncated":false}})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_eol_variants(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);
  strncpy(record.m_eol.ma_eolProduct, R"(win"dows)", PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  strncpy(record.m_eol.ma_eolUrl, R"(https://endoflife.date/win"dows)", PRODUCTEXPOSURE_EOL_URL_MAX_LEN);
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[0], R"(11-24h2-"w)", "2026-10-13", true, false, false, "26100.1");
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[1], "11-24h2-e", "2027-10-12", false, true, true, "26100.2");
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[2], "11-24h2-e-lts", "", false, true, true, "");
  record.m_eol.m_eolSeriesCycleCount = 3;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"win\"dows","url":"https://endoflife.date/win\"dows",)"
      R"("cycle":null,"cycle_variants":[)"
        R"({"name":"11-24h2-\"w","eol_date":"2026-10-13","is_eol":true,"is_maintained":false},)"
        R"({"name":"11-24h2-e","eol_date":"2027-10-12","is_eol":false,"is_maintained":true},)"
        R"({"name":"11-24h2-e-lts","eol_date":null,"is_eol":false,"is_maintained":true}],)"
      R"("maintained_cycles":[],"maintained_cycles_truncated":false}})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_eol_two_variants(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[0], "11-24h2-w", "2026-10-13", true, false, false, "");
  static_setEolCycle(&record.m_eol.ma_eolSeriesCycles[1], "11-24h2-e", "2027-10-12", false, true, true, "");
  record.m_eol.m_eolSeriesCycleCount = 2;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"nodejs","url":"https://endoflife.date/nodejs",)"
      R"("cycle":null,"cycle_variants":[)"
        R"({"name":"11-24h2-w","eol_date":"2026-10-13","is_eol":true,"is_maintained":false},)"
        R"({"name":"11-24h2-e","eol_date":"2027-10-12","is_eol":false,"is_maintained":true}],)"
      R"("maintained_cycles":[],"maintained_cycles_truncated":false}})" "\n", body);
  free(body);
}

void test_PRODUCTEXPOSURE_golden_eol_no_series(void)
{
  PRODUCTEXPOSURERecord_t record;
  static_newEolRecord(&record);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    PRODUCTEXPOSURE_GOLDEN_HEAD
    R"("eol":{"source":"endoflife.date","product":"nodejs","url":"https://endoflife.date/nodejs",)"
      R"("cycle":null,"cycle_variants":null,"maintained_cycles":[],"maintained_cycles_truncated":false}})" "\n", body);
  free(body);
}

#define CVE_LIST_GOLDEN_ITEM_PAIR \
  R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)" \
    R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.97564,"epss_percentile":0.99977,"in_kev":true,)" \
    R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null},)" \
  R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)" \
    R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)" \
    R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"

void test_CVESEARCH_golden_product_filter_note(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_vendor, "apache", CVESEARCH_VENDOR_LEN);
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,)"
    PRODUCT_FILTER_NOTE_GOLDEN
    R"("results":[)"
    CVE_LIST_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_CVESEARCH_golden_product_filter_note_for_a_product(void)
{
  CveListResult_t results = { .m_total = 12, .m_count = 0, .mp_items = NULL };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_product, "tomcat", CVESEARCH_PRODUCT_LEN);
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":12,"limit":20,"offset":0,"next_offset":0,)"
    PRODUCT_FILTER_NOTE_GOLDEN
    R"("results":[]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_product_filter_note(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 12, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_vendor, "apache", CVESEARCH_VENDOR_LEN);
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":2,"total":12,"limit":20,"verdict":"critical",)"
      R"("summary":"2 CVEs ranked by exploitation probability; CVE-2021-44228 leads at 97.6% (EPSS, next 30 days). 1 in CISA KEV.",)"
      PRODUCT_FILTER_NOTE_GOLDEN
      R"("results":[)"
      CVE_LIST_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_CVETRIAGE_golden_product_filter_note(void)
{
  CVETRIAGEItem_t items[2];
  static_fillGoldenTriagePair(items);
  CVETRIAGEResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_vendor,  "apache", CVESEARCH_VENDOR_LEN);
  strncpy(params.ma_product, "tomcat", CVESEARCH_PRODUCT_LEN);
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,)"
    PRODUCT_FILTER_NOTE_GOLDEN
    R"("results":[)"
    CVETRIAGE_GOLDEN_ITEM_PAIR
    R"(]})" "\n", body);
  free(body);
}

void test_CVE_lists_with_one_product_filter_write_product_filter_note(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t list_results = { .m_total = 12, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  strncpy(leading_params.ma_product, "tomcat", CVESEARCH_PRODUCT_LEN);
  leading_params.m_limit = 20;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&list_results, &leading_params, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, PRODUCT_FILTER_NOTE_GOLDEN), body);
  free(body);

  CVETRIAGEItem_t triage_items[2];
  static_fillGoldenTriagePair(triage_items);
  CVETRIAGEResult_t triage_results = { .m_total = 57, .m_count = 2, .mp_items = triage_items };
  static const struct {
    const char* mp_vendor;
    const char* mp_product;
  } filters[] = { { "apache", "" }, { "", "tomcat" } };
  for (size_t i = 0; i < sizeof(filters) / sizeof(filters[0]); i++)
  {
    CVETRIAGEParams_t triage_params;
    memset(&triage_params, 0, sizeof(triage_params));
    strncpy(triage_params.ma_vendor,  filters[i].mp_vendor,  CVESEARCH_VENDOR_LEN);
    strncpy(triage_params.ma_product, filters[i].mp_product, CVESEARCH_PRODUCT_LEN);
    triage_params.m_limit = 20;
    json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVETRIAGE_response(&triage_results, &triage_params, json_buf);
    body = static_finishJsonBuf(json_buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, PRODUCT_FILTER_NOTE_GOLDEN), body);
    free(body);
  }
}

void test_CVE_lists_without_a_product_filter_write_no_product_filter_note(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t list_results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_limit = 20;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&list_results, &search_params, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "product_filter_note"), body);
  free(body);

  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  leading_params.m_limit = 20;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&list_results, &leading_params, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "product_filter_note"), body);
  free(body);

  CVETRIAGEItem_t triage_items[2];
  static_fillGoldenTriagePair(triage_items);
  CVETRIAGEResult_t triage_results = { .m_total = 57, .m_count = 2, .mp_items = triage_items };
  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  triage_params.m_limit = 20;
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&triage_results, &triage_params, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "product_filter_note"), body);
  free(body);

  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0, sizeof(record));
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(body, "product_filter_note"), body);
  free(body);
}

void test_CWELOOKUP_golden_mixed_heap_states(void)
{
  CWELOOKUPRecord_t record;
  static_fillGoldenCwe(&record);
  record.mp_extendedDescription = strdup(R"(Extended "desc")");
  record.mp_mitigations         = strdup("");
  record.mp_examples            = strdup(R"(["CVE-2024-1234"])");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_extendedDescription);
  free(record.mp_mitigations);
  free(record.mp_examples);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cwe_id":"CWE-79","name":"Improper Neutralization","abstraction":"Base","status":"Stable",)"
      R"("description":"XSS description","extended_description":"Extended \"desc\"",)"
      R"("likelihood_of_exploit":"High","mitigations":null,)"
      R"("examples":["CVE-2024-1234"],"parent_cwe":"CWE-74","cve_count":42,)"
      R"("kev_count":3,"avg_cvss":6.50,"avg_epss":0.0287,)"
      R"("updated_at":"2026-05-21T00:00:00+00:00"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_mixed_raw_json_fields(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_affectedProducts = strdup(R"([{"vendor":"apache","product":"log4j"}])");
  record.mp_productCountByVendor = strdup(R"({"apache":4})");
  record.mp_epssTrend        = strdup(R"([{"epss_date":"2026-09-01","score":0.97}])");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_affectedProducts);
  free(record.mp_productCountByVendor);
  free(record.mp_epssTrend);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[{"vendor":"apache","product":"log4j"}],)"
    R"("affected_product_count":356,"product_count_by_vendor":{"apache":4},)"
    R"("refs":[],"ref_count":52,)"
    R"("poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[{"epss_date":"2026-09-01","score":0.97}],)"
    R"("cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_golden_mixed_raw_json_fields_paired_the_other_way(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_affectedProducts = strdup(R"([{"vendor":"apache","product":"log4j"}])");
  record.mp_refs             = strdup(R"([{"url":"https://example.test/a"}])");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_affectedProducts);
  free(record.mp_refs);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[{"vendor":"apache","product":"log4j"}],)"
    R"("affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[{"url":"https://example.test/a"}],"ref_count":52,)"
    R"("poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],)"
    R"("cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_long_cwes_is_written_whole(void)
{
  char document[1024] = "[";
  for (int i = 0; i < 50; i++)
    strcat(document, i == 0 ? R"("CWE-1234")" : R"(, "CWE-1234")");
  strcat(document, "]");
  TEST_ASSERT_EQUAL_size_t(600, strlen(document));

  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_cwes = document;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  char expected[1100] = "";
  snprintf(expected, sizeof(expected), R"("cwes":%s,"in_kev":)", document);
  TEST_ASSERT_NOT_NULL(strstr(body, expected));
  free(body);
}

void test_CVELOOKUP_long_cve_tags_is_written_whole(void)
{
  char document[2048] = "[";
  for (int i = 0; i < 50; i++)
    strcat(document, i == 0 ? R"("exclusively-hosted-service")" : R"(, "exclusively-hosted-service")");
  strcat(document, "]");
  TEST_ASSERT_EQUAL_size_t(1500, strlen(document));

  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_cveTags = document;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  char expected[2048] = "";
  snprintf(expected, sizeof(expected), R"("cve_tags":%s,"has_metasploit_module":)", document);
  TEST_ASSERT_NOT_NULL(strstr(body, expected));
  free(body);
}

void test_CVELOOKUP_null_cwes_is_written_as_empty_array(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  record.mp_cwes = NULL;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("cwes":[],"in_kev":)"));
  free(body);
}

void test_CVETRIAGE_golden_next_offset_clamped_at_int_max(void)
{
  CVETRIAGEItem_t item;
  static_fillTriageItem(&item);
  CVETRIAGEResult_t results = { .m_total = 2147483647, .m_count = 1, .mp_items = &item };
  CVETRIAGEParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 1;
  params.m_offset = 2147483647;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVETRIAGE_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2147483647,"limit":1,"offset":2147483647,"next_offset":2147483647,"results":[)"
      R"({"cve_id":"CVE-2021-44228","risk_score":96.5,"label":"CRITICAL"})"
    R"(]})" "\n", body);
  free(body);
}

void test_CPESEARCH_golden_empty(void)
{
  CPESEARCHResult_t results = { .m_total = 0, .m_count = 0, .mp_items = NULL };
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CPESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(R"({"total":0,"limit":20,"offset":0,"next_offset":0,"results":[]})" "\n", body);
  free(body);
}

void test_CPESEARCH_golden_two_items(void)
{
  CPESEARCHItem_t items[2];
  memset(items, 0, sizeof(items));
  strncpy(items[0].ma_vendor,  "notepad-plus-plus", CVESEARCH_VENDOR_LEN);
  strncpy(items[0].ma_product, R"(notepad\+\+)",      CVESEARCH_PRODUCT_LEN);
  items[0].m_vulnerableCveCount = 7;
  char sources[] = R"(["cna", "nvd"])";
  items[0].mp_productNamedBy = sources;
  strncpy(items[1].ma_vendor,  "microsoft",         CVESEARCH_VENDOR_LEN);
  strncpy(items[1].ma_product, "windows_10",        CVESEARCH_PRODUCT_LEN);
  items[1].m_vulnerableCveCount = 0;
  CPESEARCHResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_search, "notepad", CPESEARCH_SEARCH_MAX_LEN);
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CPESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":57,"limit":20,"offset":40,"next_offset":42,"results":[)"
      R"({"vendor":"notepad-plus-plus","product":"notepad\\+\\+","vulnerable_cve_count":7,"product_named_by":["cna", "nvd"]},)"
      R"({"vendor":"microsoft","product":"windows_10","vulnerable_cve_count":0,"product_named_by":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CPESEARCH_golden_next_offset_clamped_at_int_max(void)
{
  CPESEARCHItem_t item;
  memset(&item, 0, sizeof(item));
  strncpy(item.ma_vendor,  "microsoft",  CVESEARCH_VENDOR_LEN);
  strncpy(item.ma_product, "windows_10", CVESEARCH_PRODUCT_LEN);
  item.m_vulnerableCveCount = 3;
  CPESEARCHResult_t results = { .m_total = 2147483647, .m_count = 1, .mp_items = &item };
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit  = 1;
  params.m_offset = 2147483647;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CPESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2147483647,"limit":1,"offset":2147483647,"next_offset":2147483647,"results":[)"
      R"({"vendor":"microsoft","product":"windows_10","vulnerable_cve_count":3,"product_named_by":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEPRODUCTS_golden_page(void)
{
  char page[] = R"([{"vendor": "acme", "product": "alpha"}, {"vendor": "acme", "product": "beta"}])";
  CVEPRODUCTSResult_t result = { .m_affectedProductCount = 41, .m_listedProductCount = 2, .mp_affectedProducts = page };
  CVEPRODUCTSParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_cveId, R"(CVE-"1")", CVELOOKUP_ID_MAX_LEN);
  strncpy(params.ma_vendor, "acme", CVESEARCH_VENDOR_LEN);
  params.m_limit  = 20;
  params.m_offset = 40;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEPRODUCTS_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-\"1\"","total":41,"limit":20,"offset":40,"next_offset":42,"results":)"
    R"([{"vendor": "acme", "product": "alpha"}, {"vendor": "acme", "product": "beta"}]})" "\n", body);
  free(body);
}

void test_CVEPRODUCTS_golden_no_page(void)
{
  CVEPRODUCTSResult_t result = { .m_affectedProductCount = 0, .m_listedProductCount = 0, .mp_affectedProducts = NULL };
  CVEPRODUCTSParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEPRODUCTS_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","total":0,"limit":20,"offset":0,"next_offset":0,"results":[]})" "\n", body);
  free(body);
}

void test_CVEPRODUCTS_golden_next_offset_clamped_at_int_max(void)
{
  char page[] = R"([{"vendor": "acme"}])";
  CVEPRODUCTSResult_t result = { .m_affectedProductCount = 3, .m_listedProductCount = 1, .mp_affectedProducts = page };
  CVEPRODUCTSParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  params.m_limit  = 1;
  params.m_offset = 2147483647;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEPRODUCTS_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","total":3,"limit":1,"offset":2147483647,"next_offset":2147483647,"results":[{"vendor": "acme"}]})" "\n", body);
  free(body);
}

static void static_setD3fendDefense(D3FENDFORATTACKItem_t* defense, const char* defense_id, const char* defense_label,
                                    const char* defense_tactic, const char* digital_artifact, const char* parents, const char* ids)
{
  memset(defense, 0, sizeof(*defense));
  snprintf(defense->ma_defenseId,       sizeof(defense->ma_defenseId),       "%s", defense_id);
  snprintf(defense->ma_defenseLabel,    sizeof(defense->ma_defenseLabel),    "%s", defense_label);
  snprintf(defense->ma_defenseTactic,   sizeof(defense->ma_defenseTactic),   "%s", defense_tactic);
  snprintf(defense->ma_digitalArtifact, sizeof(defense->ma_digitalArtifact), "%s", digital_artifact);
  defense->mp_parentDefenseLabels = parents != NULL ? strdup(parents) : NULL;
  defense->mp_attackTechniqueIds  = ids     != NULL ? strdup(ids)     : NULL;
}

void test_D3FENDFORATTACK_golden_empty(void)
{
  D3FENDFORATTACKResult_t result;
  memset(&result, 0, sizeof(result));
  D3FENDFORATTACKParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_attackTechniqueId, "T9999", ATTACK_TECHNIQUE_ID_MAX_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_D3FENDFORATTACK_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"attack_technique_id":"T9999","attack_techniques":[],)"
    R"("defense_count_by_defense_tactic":{"Model":0,"Harden":0,"Detect":0,"Isolate":0,"Deceive":0,"Evict":0,"Restore":0},)"
    R"("defenses":[]})" "\n", body);
  free(body);
}

void test_D3FENDFORATTACK_golden_two_defenses(void)
{
  D3FENDFORATTACKItem_t defenses[2];
  static_setD3fendDefense(&defenses[0], "Multi-factorAuthentication", "Multi-factor \"Auth\\entication\" Doppelg\xc3\xa4nging", "Harden", "",
                          R"(["Agent Authentication"])", R"(["T1055"])");
  static_setD3fendDefense(&defenses[1], "SystemCallAnalysis", "System Call Analysis", "Detect", "System Call",
                          R"(["Operating System Monitoring","Platform Monitoring"])", R"(["T1055.001","T1055.012"])");
  D3FENDFORATTACKResult_t result = {
    .mp_attackTechniques = strdup(R"([{"attack_technique_id":"T1055","subtechnique_of":null,"attack_label":null},{"attack_technique_id":"T1055.012","subtechnique_of":"T1055","attack_label":"Process Hollowing"}])"),
    .m_defenseCount      = 2,
    .mp_defenses         = defenses,
  };
  D3FENDFORATTACKParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_attackTechniqueId, "T1055", ATTACK_TECHNIQUE_ID_MAX_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_D3FENDFORATTACK_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"attack_technique_id":"T1055",)"
    R"("attack_techniques":[{"attack_technique_id":"T1055","subtechnique_of":null,"attack_label":null},{"attack_technique_id":"T1055.012","subtechnique_of":"T1055","attack_label":"Process Hollowing"}],)"
    R"("defense_count_by_defense_tactic":{"Model":0,"Harden":1,"Detect":1,"Isolate":0,"Deceive":0,"Evict":0,"Restore":0},)"
    R"("defenses":[)"
      R"({"defense_id":"Multi-factorAuthentication","defense_label":"Multi-factor \"Auth\\entication\" Doppelg)" "\xc3\xa4" R"(nging",)"
      R"("uri":"http://d3fend.mitre.org/ontologies/d3fend.owl#Multi-factorAuthentication","parent_defense_labels":["Agent Authentication"],)"
      R"("defense_tactic":"Harden","digital_artifact":null,"attack_technique_ids":["T1055"]},)"
      R"({"defense_id":"SystemCallAnalysis","defense_label":"System Call Analysis",)"
      R"("uri":"http://d3fend.mitre.org/ontologies/d3fend.owl#SystemCallAnalysis","parent_defense_labels":["Operating System Monitoring","Platform Monitoring"],)"
      R"("defense_tactic":"Detect","digital_artifact":"System Call","attack_technique_ids":["T1055.001","T1055.012"]})"
    R"(]})" "\n", body);
  free(body);
  free(result.mp_attackTechniques);
  for (int i = 0; i < 2; i++)
  {
    free(defenses[i].mp_parentDefenseLabels);
    free(defenses[i].mp_attackTechniqueIds);
  }
}

void test_D3FENDFORATTACK_counts_each_tactic_alone(void)
{
  static const char* const tactics[] = { "Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore" };
  D3FENDFORATTACKItem_t defenses[22];
  int defense_count = 0;
  for (int t = 0; t < 7; t++)
    for (int k = 0; k < t; k++)
      static_setD3fendDefense(&defenses[defense_count++], "D", "L", tactics[t], "", NULL, NULL);
  static_setD3fendDefense(&defenses[defense_count++], "D", "L", "detect", "", NULL, NULL);
  TEST_ASSERT_EQUAL_INT(22, defense_count);
  D3FENDFORATTACKResult_t result = { .mp_attackTechniques = NULL, .m_defenseCount = defense_count, .mp_defenses = defenses };
  D3FENDFORATTACKParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_attackTechniqueId, "T1059", ATTACK_TECHNIQUE_ID_MAX_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_D3FENDFORATTACK_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  const char* expected = R"(,"defense_count_by_defense_tactic":{"Model":0,"Harden":1,"Detect":2,"Isolate":3,"Deceive":4,"Evict":5,"Restore":6},"defenses":[)";
  const char* counts = strstr(body, R"(,"defense_count_by_defense_tactic":)");
  TEST_ASSERT_NOT_NULL(counts);
  TEST_ASSERT_EQUAL_STRING_LEN(expected, counts, strlen(expected));
  free(body);
}

static char* static_serializeDriverLookup(const DRIVERLOOKUPRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_DRIVERLOOKUP_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_DRIVERLOOKUP_golden_found(void)
{
  DRIVERLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_fileHash, sizeof(record.ma_fileHash), "%s", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
  record.m_matchCount         = 2;
  record.m_isDriverFeedLoaded = true;
  record.mp_matches           = strdup(R"([{"driver_id":"00000000-0000-0000-0000-00000000000a","matched_on":["sha256"]}])");

  char* body = static_serializeDriverLookup(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"hash":"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8","hash_type":"sha256",)"
    R"("data_source":{"source":"loldrivers","available":true,"license":"Apache-2.0"},)"
    R"("found":true,"match_count":2,"matches":[{"driver_id":"00000000-0000-0000-0000-00000000000a","matched_on":["sha256"]}]})" "\n", body);
  free(body);
  free(record.mp_matches);
}

void test_DRIVERLOOKUP_golden_not_found(void)
{
  DRIVERLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_fileHash, sizeof(record.ma_fileHash), "%s", "5f4dcc3b5aa765d61d8327deb882cf99");
  record.m_isDriverFeedLoaded = true;

  char* body = static_serializeDriverLookup(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"hash":"5f4dcc3b5aa765d61d8327deb882cf99","hash_type":"md5",)"
    R"("data_source":{"source":"loldrivers","available":true,"license":"Apache-2.0"},)"
    R"("found":false,"match_count":0,"matches":[]})" "\n", body);
  free(body);
}

void test_DRIVERLOOKUP_golden_catalog_not_loaded(void)
{
  DRIVERLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_fileHash, sizeof(record.ma_fileHash), "%s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
  record.m_matchCount         = 3;
  record.m_isDriverFeedLoaded = false;
  record.mp_matches           = strdup(R"([{"driver_id":"00000000-0000-0000-0000-00000000000a"}])");

  char* body = static_serializeDriverLookup(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"hash":"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8","hash_type":"sha1",)"
    R"("data_source":{"source":"loldrivers","available":false,"reason":"not_synced","license":"Apache-2.0"},)"
    R"("found":null,"match_count":null,"matches":[]})" "\n", body);
  free(body);
  free(record.mp_matches);
}

static DnsMxRecord_t g_emailAddressCheckMxRecords[2] = { { 5, (char*)"mx-a.example.net" }, { 15, (char*)"mx-b.example.net" } };

#define EMAILADDRESSCHECK_GOLDEN_MX_HOSTS \
  R"([{"priority":5,"host":"mx-a.example.net"},{"priority":15,"host":"mx-b.example.net"}])"

static void static_fillEMAILADDRESSCHECKRecord(EMAILADDRESSCHECKRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_email, sizeof(record->ma_email), "%s", "Info+x@example.com");
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "example.com");
  record->m_isDisposableFeedLoaded   = true;
  record->m_isDomainFound            = true;
  record->m_mailRoute                = EMAILCHECK_MAIL_ROUTE_MX;
  record->m_mxAnswer.m_status        = DNS_ANSWER_OK;
  record->m_mxAnswer.m_recordCount   = 2;
  record->m_mxAnswer.mp_mxRecords    = g_emailAddressCheckMxRecords;
}

static char* static_EMAILADDRESSCHECKBody(const EMAILADDRESSCHECKRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_EMAILADDRESSCHECK_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_EMAILADDRESSCHECK_golden_mx_route(void)
{
  EMAILADDRESSCHECKRecord_t record;
  static_fillEMAILADDRESSCHECKRecord(&record);

  char* body = static_EMAILADDRESSCHECKBody(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"email":"Info+x@example.com","domain":"example.com","domain_exists":true,"accepts_mail":true,"mail_route":"mx","mx_hosts":)"
    EMAILADDRESSCHECK_GOLDEN_MX_HOSTS
    R"(,"disposable":false,"disposable_listed_domain":null,"unavailable":{}})" "\n",
    body);
  free(body);
}

void test_EMAILADDRESSCHECK_echoed_address_is_escaped(void)
{
  EMAILADDRESSCHECKRecord_t record;
  static_fillEMAILADDRESSCHECKRecord(&record);
  snprintf(record.ma_email, sizeof(record.ma_email), "%s", "q\"b\\a\xE2\x80\xAEz\xE2\x80\x8B@example.com");
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "ex\"ample.com");

  char* body = static_EMAILADDRESSCHECKBody(&record);

  TEST_ASSERT_EQUAL_STRING_LEN(R"({"email":"q\"b\\a\u202ez\u200b@example.com","domain":"ex\"ample.com",)", body,
                               strlen(R"({"email":"q\"b\\a\u202ez\u200b@example.com","domain":"ex\"ample.com",)"));
  free(body);
}

void test_EMAILADDRESSCHECK_each_route(void)
{
  static const struct { bool m_isDomainFound; EmailCheckMailRoute_t m_mailRoute; DnsAnswerStatus_t m_mxStatus; int m_mxCount; const char* mp_part; } cases[] = {
    { true,  EMAILCHECK_MAIL_ROUTE_MX,          DNS_ANSWER_OK,       2,
      R"("domain_exists":true,"accepts_mail":true,"mail_route":"mx","mx_hosts":)" EMAILADDRESSCHECK_GOLDEN_MX_HOSTS "," },
    { true,  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX, DNS_ANSWER_OK,       0,
      R"("domain_exists":true,"accepts_mail":true,"mail_route":"implicit_mx","mx_hosts":[],)" },
    { true,  EMAILCHECK_MAIL_ROUTE_NULL_MX,     DNS_ANSWER_OK,       0,
      R"("domain_exists":true,"accepts_mail":false,"mail_route":"null_mx","mx_hosts":[],)" },
    { true,  EMAILCHECK_MAIL_ROUTE_NONE,        DNS_ANSWER_OK,       0,
      R"("domain_exists":true,"accepts_mail":false,"mail_route":"none","mx_hosts":[],)" },
    { false, EMAILCHECK_MAIL_ROUTE_MX,          DNS_ANSWER_NXDOMAIN, 2,
      R"("domain_exists":false,"accepts_mail":false,"mail_route":null,"mx_hosts":[],)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EMAILADDRESSCHECKRecord_t record;
    static_fillEMAILADDRESSCHECKRecord(&record);
    record.m_isDomainFound           = cases[i].m_isDomainFound;
    record.m_mailRoute               = cases[i].m_mailRoute;
    record.m_mxAnswer.m_status       = cases[i].m_mxStatus;
    record.m_mxAnswer.m_recordCount  = cases[i].m_mxCount;

    char* body = static_EMAILADDRESSCHECKBody(&record);

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("domain":"example.com",)"), cases[i].mp_part);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_part), cases[i].mp_part);
    free(body);
  }
}

void test_EMAILADDRESSCHECK_disposable_of_each_list_state(void)
{
  static const struct { const char* mp_listedDomain; bool m_isFeedLoaded; const char* mp_tail; } cases[] = {
    { "example.com", true,
      R"("disposable":true,"disposable_listed_domain":"example.com","unavailable":{}})" "\n" },
    { "",            true,
      R"("disposable":false,"disposable_listed_domain":null,"unavailable":{}})" "\n" },
    { "",            false,
      R"("disposable":null,"disposable_listed_domain":null,"unavailable":{"disposable_listed_domain":"not_synced"}})" "\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EMAILADDRESSCHECKRecord_t record;
    static_fillEMAILADDRESSCHECKRecord(&record);
    snprintf(record.ma_disposableListedDomain, sizeof(record.ma_disposableListedDomain), "%s", cases[i].mp_listedDomain);
    record.m_isDisposableFeedLoaded = cases[i].m_isFeedLoaded;

    char* body = static_EMAILADDRESSCHECKBody(&record);

    size_t body_len = strlen(body);
    size_t tail_len = strlen(cases[i].mp_tail);
    TEST_ASSERT_TRUE_MESSAGE(body_len > tail_len, cases[i].mp_tail);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_tail, body + body_len - tail_len, cases[i].mp_tail);
    free(body);
  }
}

#define IPLOOKUP_FIX_LISTED_ON \
  R"([{"prefix": "8.8.4.0/24", "source": "drop", "copyright": "(c) 2026 The Spamhaus Project SLU", "list_time": "2026-10-24T00:00:00Z", "listing_id": "SBL1"}, )" \
  R"({"prefix": "8.8.0.0/16", "source": "drop", "copyright": "(c) 2026 The Spamhaus Project SLU", "list_time": "2026-10-23T00:00:00Z", "listing_id": "SBL22"}])"

#define IPLOOKUP_GOLDEN_SLOTS \
  R"("reputation":{"available":false,"reason":"pro_key_required","action_url":"https://api.contrastcyber.com/pricing"},)" \
  R"("internet_exposure":{"available":false,"reason":"pro_key_required","action_url":"https://api.contrastcyber.com/pricing"},)"

#define IPLOOKUP_GOLDEN_LOADED_HEAD \
  R"({"ip_address":"8.8.4.4","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)" \
  R"("cloud_provider":"aws","cloud_service":"ec2","is_cdn":false,"is_datacenter":true,"is_tor_exit":true,)" \
  R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON ","

static DnsRecordText_t g_iplookupPtrTexts[2] = { { (char*)"ptr.example.net", 15 }, { (char*)"other.example.net", 17 } };

static void static_setIPLOOKUPPtr(IPLOOKUPRecord_t* record, DnsAnswerStatus_t status, int record_count, DnsRecordText_t* texts)
{
  memset(&record->m_ptrAnswer, 0, sizeof(record->m_ptrAnswer));
  record->m_ptrAnswer.m_status      = status;
  record->m_ptrAnswer.m_recordCount = record_count;
  record->m_ptrAnswer.mp_texts      = texts;
}

static void static_fillIPLOOKUPRecord(IPLOOKUPRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_ipAddress, sizeof(record->ma_ipAddress), "%s", "8.8.4.4");
  record->m_asn = 4200000000u;
  snprintf(record->ma_asnName, sizeof(record->ma_asnName), "%s", "EX\"AMPLE\\NET");
  snprintf(record->ma_asnCountry, sizeof(record->ma_asnCountry), "%s", "DE");
  snprintf(record->ma_geoCountry, sizeof(record->ma_geoCountry), "%s", "FR");
  snprintf(record->ma_cloudProvider, sizeof(record->ma_cloudProvider), "%s", "aws");
  snprintf(record->ma_cloudService, sizeof(record->ma_cloudService), "%s", "ec2");
  record->m_isCdn                = false;
  record->m_isDatacenter         = true;
  record->m_isTorExit            = true;
  record->mp_listedOn            = (char*)IPLOOKUP_FIX_LISTED_ON;
  record->m_isAsnFeedLoaded      = true;
  record->m_isGeoFeedLoaded      = true;
  record->m_isCloudFeedLoaded    = true;
  record->m_isTorFeedLoaded      = true;
  record->m_isDropListFeedLoaded = true;
  static_setIPLOOKUPPtr(record, DNS_ANSWER_OK, 2, g_iplookupPtrTexts);
}

static char* static_IPLOOKUPSlotsBody(const IPLOOKUPRecord_t* record, const IPLOOKUPVendorSlots_t* slots)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IPLOOKUP_response(record, slots, json_buf);
  return static_finishJsonBuf(json_buf);
}

static char* static_IPLOOKUPBody(const IPLOOKUPRecord_t* record)
{
  IPLOOKUPVendorSlots_t slots;
  memset(&slots, 0, sizeof(slots));
  slots.m_internetExposure.m_slotState = IPLOOKUP_SLOT_PRO_KEY_REQUIRED;
  slots.m_reputation.m_slotState       = IPLOOKUP_SLOT_PRO_KEY_REQUIRED;
  return static_IPLOOKUPSlotsBody(record, &slots);
}

void test_IPLOOKUP_golden_every_source_loaded_with_matches(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);

  char* body = static_IPLOOKUPBody(&record);

  TEST_ASSERT_EQUAL_STRING(IPLOOKUP_GOLDEN_LOADED_HEAD R"("ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{}})" "\n", body);
  free(body);
}

void test_IPLOOKUP_golden_ipv6_cdn_that_is_not_a_tor_exit(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  snprintf(record.ma_ipAddress, sizeof(record.ma_ipAddress), "%s", "2606:4700::1111");
  snprintf(record.ma_cloudProvider, sizeof(record.ma_cloudProvider), "%s", "cloudflare");
  snprintf(record.ma_cloudService, sizeof(record.ma_cloudService), "%s", "cdn");
  record.m_isCdn     = true;
  record.m_isTorExit = false;

  char* body = static_IPLOOKUPBody(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"ip_address":"2606:4700::1111","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)"
    R"("cloud_provider":"cloudflare","cloud_service":"cdn","is_cdn":true,"is_datacenter":true,"is_tor_exit":false,)"
    R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON R"(,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{}})" "\n", body);
  free(body);
}

void test_IPLOOKUP_golden_every_source_loaded_without_a_match(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  record.m_asn               = 0;
  record.ma_asnName[0]       = '\0';
  record.ma_asnCountry[0]    = '\0';
  record.ma_geoCountry[0]    = '\0';
  record.ma_cloudProvider[0] = '\0';
  record.ma_cloudService[0]  = '\0';
  record.m_isDatacenter      = false;
  record.m_isTorExit         = false;
  record.mp_listedOn         = (char*)"[]";
  static_setIPLOOKUPPtr(&record, DNS_ANSWER_OK, 0, NULL);

  char* body = static_IPLOOKUPBody(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"ip_address":"8.8.4.4","asn":null,"asn_name":null,"asn_country":null,"geo_country":null,)"
    R"("cloud_provider":null,"cloud_service":null,"is_cdn":null,"is_datacenter":false,"is_tor_exit":false,)"
    R"("listed_on":[],"ptr":null,)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{}})" "\n", body);
  free(body);
}

void test_IPLOOKUP_an_empty_as_text_is_null_alone(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  record.ma_asnName[0] = '\0';
  char* body = static_IPLOOKUPBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("asn":4200000000,"asn_name":null,"asn_country":"DE","geo_country":"FR",)"), body);
  free(body);

  static_fillIPLOOKUPRecord(&record);
  record.ma_asnCountry[0] = '\0';
  body = static_IPLOOKUPBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":null,"geo_country":"FR",)"), body);
  free(body);
}

void test_IPLOOKUP_as_1_is_a_number(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  record.m_asn = 1;
  char* body = static_IPLOOKUPBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("asn":1,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)"), body);
  free(body);
}

void test_IPLOOKUP_one_source_not_loaded_and_a_failed_ptr(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  record.m_isGeoFeedLoaded = false;
  static_setIPLOOKUPPtr(&record, DNS_ANSWER_TIMEOUT, 0, NULL);
  char* body = static_IPLOOKUPBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("unavailable":{"geo_country":"not_synced","ptr":"timeout"}})" "\n"), body);
  free(body);
}

void test_IPLOOKUP_golden_each_source_not_loaded(void)
{
  static const char* const goldens[] = {
    R"({"ip_address":"8.8.4.4","asn":null,"asn_name":null,"asn_country":null,"geo_country":"FR",)"
    R"("cloud_provider":"aws","cloud_service":"ec2","is_cdn":false,"is_datacenter":null,"is_tor_exit":true,)"
    R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON R"(,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{"asn":"not_synced"}})" "\n",

    R"({"ip_address":"8.8.4.4","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":null,)"
    R"("cloud_provider":"aws","cloud_service":"ec2","is_cdn":false,"is_datacenter":true,"is_tor_exit":true,)"
    R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON R"(,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{"geo_country":"not_synced"}})" "\n",

    R"({"ip_address":"8.8.4.4","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)"
    R"("cloud_provider":null,"cloud_service":null,"is_cdn":null,"is_datacenter":null,"is_tor_exit":true,)"
    R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON R"(,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{"cloud_provider":"not_synced"}})" "\n",

    R"({"ip_address":"8.8.4.4","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)"
    R"("cloud_provider":"aws","cloud_service":"ec2","is_cdn":false,"is_datacenter":true,"is_tor_exit":null,)"
    R"("listed_on":)" IPLOOKUP_FIX_LISTED_ON R"(,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{"is_tor_exit":"not_synced"}})" "\n",

    R"({"ip_address":"8.8.4.4","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","geo_country":"FR",)"
    R"("cloud_provider":"aws","cloud_service":"ec2","is_cdn":false,"is_datacenter":true,"is_tor_exit":true,)"
    R"("listed_on":null,"ptr":"ptr.example.net",)" IPLOOKUP_GOLDEN_SLOTS R"("unavailable":{"listed_on":"not_synced"}})" "\n",
  };
  for (int source = 0; source < 5; source++)
  {
    IPLOOKUPRecord_t record;
    static_fillIPLOOKUPRecord(&record);
    if (source == 0)
    {
      record.m_isAsnFeedLoaded = false;
      record.m_isDatacenter    = false;
    }
    else if (source == 1)
      record.m_isGeoFeedLoaded = false;
    else if (source == 2)
    {
      record.m_isCloudFeedLoaded = false;
      record.m_isDatacenter      = false;
    }
    else if (source == 3)
      record.m_isTorFeedLoaded = false;
    else
      record.m_isDropListFeedLoaded = false;

    char* body = static_IPLOOKUPBody(&record);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(goldens[source], body, goldens[source]);
    free(body);
  }
}

void test_IPLOOKUP_golden_nothing_loaded_and_ptr_timed_out(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  record.m_isAsnFeedLoaded      = false;
  record.m_isGeoFeedLoaded      = false;
  record.m_isCloudFeedLoaded    = false;
  record.m_isTorFeedLoaded      = false;
  record.m_isDropListFeedLoaded = false;
  record.m_isCdn                = false;
  record.m_isTorExit            = false;
  record.mp_listedOn            = NULL;
  static_setIPLOOKUPPtr(&record, DNS_ANSWER_TIMEOUT, 0, NULL);

  char* body = static_IPLOOKUPBody(&record);

  TEST_ASSERT_EQUAL_STRING(
    R"({"ip_address":"8.8.4.4","asn":null,"asn_name":null,"asn_country":null,"geo_country":null,)"
    R"("cloud_provider":null,"cloud_service":null,"is_cdn":null,"is_datacenter":true,"is_tor_exit":null,)"
    R"("listed_on":null,"ptr":null,)" IPLOOKUP_GOLDEN_SLOTS
    R"("unavailable":{"asn":"not_synced","geo_country":"not_synced","cloud_provider":"not_synced","is_tor_exit":"not_synced","listed_on":"not_synced","ptr":"timeout"}})" "\n", body);
  free(body);
}

void test_IPLOOKUP_golden_each_failed_ptr_answer(void)
{
  static const struct { DnsAnswerStatus_t m_status; const char* mp_unavailable; } cases[] = {
    { DNS_ANSWER_NXDOMAIN,        "{}" },
    { DNS_ANSWER_SERVER_ERROR,    R"({"ptr":"server_error"})" },
    { DNS_ANSWER_TIMEOUT,         R"({"ptr":"timeout"})" },
    { DNS_ANSWER_NO_RESOLVER,     R"({"ptr":"no_resolver"})" },
    { DNS_ANSWER_NOT_PUBLIC_NAME, R"({"ptr":"not_public_name"})" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    IPLOOKUPRecord_t record;
    static_fillIPLOOKUPRecord(&record);
    static_setIPLOOKUPPtr(&record, cases[i].m_status, 2, g_iplookupPtrTexts);
    char golden[8192];
    int written = snprintf(golden, sizeof(golden), "%s%s%s%s}\n", IPLOOKUP_GOLDEN_LOADED_HEAD, R"("ptr":null,)", IPLOOKUP_GOLDEN_SLOTS R"("unavailable":)", cases[i].mp_unavailable);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(golden));

    char* body = static_IPLOOKUPBody(&record);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(golden, body, cases[i].mp_unavailable);
    free(body);
  }
}

void test_IPLOOKUP_ptr_name_is_escaped_by_its_byte_count(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  static DnsRecordText_t nul_name[1] = { { (char*)"a\0b", 3 } };
  static_setIPLOOKUPPtr(&record, DNS_ANSWER_OK, 1, nul_name);

  char* body = static_IPLOOKUPBody(&record);

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"(,"ptr":"a\u0000b","reputation":)"), body);
  free(body);
}

static int   g_iplookupShodanPorts[3]     = { 0, 443, 65535 };
static char* g_iplookupShodanVulns[1]     = { (char*)"CVE-2019-0708" };
static char* g_iplookupShodanHostnames[2] = { (char*)"a.example.org", (char*)"b\"q.example.org" };
static char* g_iplookupShodanTags[2]      = { (char*)"self\\signed", (char*)"cloud" };

static void static_fillIPLOOKUPSlots(IPLOOKUPVendorSlots_t* slots)
{
  memset(slots, 0, sizeof(*slots));
  slots->m_internetExposure.m_slotState            = IPLOOKUP_SLOT_FILLED;
  slots->m_internetExposure.m_retryAfterSeconds    = 5;
  slots->m_shodanHost.mp_ports                     = g_iplookupShodanPorts;
  slots->m_shodanHost.m_portCount                  = 3;
  slots->m_shodanHost.m_vulns.mp_items             = g_iplookupShodanVulns;
  slots->m_shodanHost.m_vulns.m_count              = 1;
  slots->m_shodanHost.m_hostnames.mp_items         = g_iplookupShodanHostnames;
  slots->m_shodanHost.m_hostnames.m_count          = 2;
  slots->m_shodanHost.m_tags.mp_items              = g_iplookupShodanTags;
  slots->m_shodanHost.m_tags.m_count               = 2;
  snprintf(slots->m_shodanHost.ma_lastUpdate, sizeof(slots->m_shodanHost.ma_lastUpdate), "%s", "2026-09-01T00:00:01.000001");
  slots->m_reputation.m_slotState                  = IPLOOKUP_SLOT_FILLED;
  slots->m_reputation.m_retryAfterSeconds          = 6;
  slots->m_abuseIpDbReport.m_abuseConfidenceScore  = 100;
  slots->m_abuseIpDbReport.m_reportCount           = 2048;
  slots->m_abuseIpDbReport.m_distinctReporterCount = 77;
  snprintf(slots->m_abuseIpDbReport.ma_lastReportedAt, sizeof(slots->m_abuseIpDbReport.ma_lastReportedAt), "%s", "2026-10-31T23:59:59+00:00");
  slots->m_abuseIpDbReport.m_whitelist             = ABUSEIPDB_WHITELIST_YES;
  snprintf(slots->m_abuseIpDbReport.ma_usageType, sizeof(slots->m_abuseIpDbReport.ma_usageType), "%s", "Fixed \"Line\" ISP");
}

void test_IPLOOKUP_golden_both_vendor_slots_filled(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  IPLOOKUPVendorSlots_t slots;
  static_fillIPLOOKUPSlots(&slots);

  char* body = static_IPLOOKUPSlotsBody(&record, &slots);

  TEST_ASSERT_EQUAL_STRING(IPLOOKUP_GOLDEN_LOADED_HEAD R"("ptr":"ptr.example.net",)"
    R"("reputation":{"available":true,"source":"abuseipdb","abuse_confidence_score":100,"total_reports":2048,"distinct_reporter_count":77,)"
    R"("last_reported_at":"2026-10-31T23:59:59+00:00","is_whitelisted":true,"usage_type":"Fixed \"Line\" ISP"},)"
    R"("internet_exposure":{"available":true,"source":"shodan","ports":[0,443,65535],"vulns":["CVE-2019-0708"],"vulns_truncated":false,)"
    R"("hostnames":["a.example.org","b\"q.example.org"],"tags":["self\\signed","cloud"],"last_update":"2026-09-01T00:00:01.000001"},)"
    R"("unavailable":{}})" "\n", body);
  free(body);
}

void test_IPLOOKUP_internet_exposure_from_the_count_query(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  const struct { bool m_isCut; const char* mp_slot; } cases[] = {
    { false, R"("internet_exposure":{"available":true,"source":"shodan_facets","ports":[0,443,65535],"vulns":["CVE-2019-0708"],"vulns_truncated":false,"hostnames":[],"tags":["self\\signed","cloud"],"last_update":null},)" },
    { true,  R"("internet_exposure":{"available":true,"source":"shodan_facets","ports":[0,443,65535],"vulns":["CVE-2019-0708"],"vulns_truncated":true,"hostnames":[],"tags":["self\\signed","cloud"],"last_update":null},)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    IPLOOKUPVendorSlots_t slots;
    static_fillIPLOOKUPSlots(&slots);
    slots.m_shodanHost.m_hostnames.mp_items = NULL;
    slots.m_shodanHost.m_hostnames.m_count  = 0;
    slots.m_shodanHost.ma_lastUpdate[0]     = '\0';
    slots.m_shodanHost.m_isFromFacets       = true;
    slots.m_shodanHost.m_isVulnListCut      = cases[i].m_isCut;
    char* body = static_IPLOOKUPSlotsBody(&record, &slots);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_slot), body);
    free(body);
  }
}

void test_IPLOOKUP_reputation_empty_texts_and_whitelist_values(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  const struct { AbuseIpDbWhitelist_t m_whitelist; bool m_isEmpty; const char* mp_tail; } cases[] = {
    { ABUSEIPDB_WHITELIST_NO,      false, R"("last_reported_at":"2026-10-31T23:59:59+00:00","is_whitelisted":false,"usage_type":"Fixed \"Line\" ISP"},)" },
    { ABUSEIPDB_WHITELIST_UNKNOWN, true,  R"("last_reported_at":null,"is_whitelisted":null,"usage_type":null},)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    IPLOOKUPVendorSlots_t slots;
    static_fillIPLOOKUPSlots(&slots);
    slots.m_abuseIpDbReport.m_whitelist = cases[i].m_whitelist;
    if (cases[i].m_isEmpty)
    {
      slots.m_abuseIpDbReport.ma_lastReportedAt[0] = '\0';
      slots.m_abuseIpDbReport.ma_usageType[0]      = '\0';
    }
    char* body = static_IPLOOKUPSlotsBody(&record, &slots);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_tail), body);
    free(body);
  }
}

void test_IPLOOKUP_each_empty_vendor_slot(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  const struct {
    IPLOOKUPSlotState_t m_reputation;
    unsigned int        m_reputationRetry;
    IPLOOKUPSlotState_t m_internetExposure;
    unsigned int        m_internetExposureRetry;
    const char*         mp_slots;
  } cases[] = {
    { IPLOOKUP_SLOT_KEY_MISSING,        0, IPLOOKUP_SLOT_KEY_REJECTED,       0,
      R"("reputation":{"available":false,"reason":"vendor_key_missing","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)"
      R"("internet_exposure":{"available":false,"reason":"vendor_key_rejected","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)" },
    { IPLOOKUP_SLOT_KEY_REJECTED,       0, IPLOOKUP_SLOT_KEY_MISSING,        0,
      R"("reputation":{"available":false,"reason":"vendor_key_rejected","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)"
      R"("internet_exposure":{"available":false,"reason":"vendor_key_missing","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)" },
    { IPLOOKUP_SLOT_VENDOR_UNAVAILABLE, 1, IPLOOKUP_SLOT_VENDOR_UNAVAILABLE, 0,
      R"("reputation":{"available":false,"reason":"vendor_unavailable","retry_after_seconds":1},)"
      R"("internet_exposure":{"available":false,"reason":"vendor_unavailable"},)" },
    { IPLOOKUP_SLOT_VENDOR_UNAVAILABLE, 0, IPLOOKUP_SLOT_VENDOR_UNAVAILABLE, 4294967295u,
      R"("reputation":{"available":false,"reason":"vendor_unavailable"},)"
      R"("internet_exposure":{"available":false,"reason":"vendor_unavailable","retry_after_seconds":4294967295},)" },
    { IPLOOKUP_SLOT_DB_ERROR,           3, IPLOOKUP_SLOT_PRO_KEY_REQUIRED,   3,
      R"("reputation":{"available":false,"reason":"database_error"},)"
      R"("internet_exposure":{"available":false,"reason":"pro_key_required","action_url":"https://api.contrastcyber.com/pricing"},)" },
    { IPLOOKUP_SLOT_PRO_KEY_REQUIRED,   3, IPLOOKUP_SLOT_DB_ERROR,           3,
      R"("reputation":{"available":false,"reason":"pro_key_required","action_url":"https://api.contrastcyber.com/pricing"},)"
      R"("internet_exposure":{"available":false,"reason":"database_error"},)" },
    { IPLOOKUP_SLOT_FILLED,             3, IPLOOKUP_SLOT_KEY_MISSING,        3,
      R"("reputation":{"available":true,"source":"abuseipdb","abuse_confidence_score":100,"total_reports":2048,"distinct_reporter_count":77,)"
      R"("last_reported_at":"2026-10-31T23:59:59+00:00","is_whitelisted":true,"usage_type":"Fixed \"Line\" ISP"},)"
      R"("internet_exposure":{"available":false,"reason":"vendor_key_missing","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)" },
    { IPLOOKUP_SLOT_KEY_REJECTED,       3, IPLOOKUP_SLOT_FILLED,             3,
      R"("reputation":{"available":false,"reason":"vendor_key_rejected","action_url":"https://api.contrastcyber.com/privacy_my_data","action_tool":"privacy_my_data"},)"
      R"("internet_exposure":{"available":true,"source":"shodan","ports":[0,443,65535],"vulns":["CVE-2019-0708"],"vulns_truncated":false,)"
      R"("hostnames":["a.example.org","b\"q.example.org"],"tags":["self\\signed","cloud"],"last_update":"2026-09-01T00:00:01.000001"},)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    IPLOOKUPVendorSlots_t slots;
    static_fillIPLOOKUPSlots(&slots);
    slots.m_reputation.m_slotState               = cases[i].m_reputation;
    slots.m_reputation.m_retryAfterSeconds       = cases[i].m_reputationRetry;
    slots.m_internetExposure.m_slotState         = cases[i].m_internetExposure;
    slots.m_internetExposure.m_retryAfterSeconds = cases[i].m_internetExposureRetry;
    char* body = static_IPLOOKUPSlotsBody(&record, &slots);
    TEST_ASSERT_NULL_MESSAGE(strstr(body, "#l="), body);
    char golden[4096];
    int written = snprintf(golden, sizeof(golden), "%s%s%s", IPLOOKUP_GOLDEN_LOADED_HEAD R"("ptr":"ptr.example.net",)", cases[i].mp_slots, R"("unavailable":{}})" "\n");
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(golden));
    TEST_ASSERT_EQUAL_STRING(golden, body);
    free(body);
  }
}

static char* static_serializeDriverLookupBulk(const DRIVERLOOKUPBULKResult_t* results)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_DRIVERLOOKUPBULK_response(results, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_DRIVERLOOKUPBULK_golden_loaded(void)
{
  DRIVERLOOKUPRecord_t items[2];
  memset(items, 0, sizeof(items));
  snprintf(items[0].ma_fileHash, sizeof(items[0].ma_fileHash), "%s", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
  items[0].m_matchCount         = 4;
  items[0].m_isDriverFeedLoaded = true;
  items[0].mp_matches           = strdup(R"([{"driver_id":"00000000-0000-0000-0000-00000000000a"}])");
  snprintf(items[1].ma_fileHash, sizeof(items[1].ma_fileHash), "%s", "5f4dcc3b5aa765d61d8327deb882cf99");
  items[1].m_isDriverFeedLoaded = true;
  items[1].mp_matches           = strdup("[]");
  char not_processed_ids[1][BULK_ID_MAX_LEN + 1] = { "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" };
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total             = 6;
  results.m_processed         = 3;
  results.m_successful        = 2;
  results.m_skipped           = 2;
  results.m_failed            = 1;
  results.mp_items            = items;
  results.mp_notProcessedIds  = not_processed_ids;
  results.m_notProcessedCount = 1;

  char* body = static_serializeDriverLookupBulk(&results);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":6,"processed":3,"successful":2,"skipped":2,"failed":1,"not_processed":["5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"],)"
    R"("data_source":{"source":"loldrivers","available":true,"license":"Apache-2.0"},"results":[)"
    R"({"hash":"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8","hash_type":"sha256","found":true,"match_count":4,)"
    R"("matches":[{"driver_id":"00000000-0000-0000-0000-00000000000a"}]})" "\n"
    R"(,{"hash":"5f4dcc3b5aa765d61d8327deb882cf99","hash_type":"md5","found":false,"match_count":0,"matches":[]})" "\n"
    "]}", body);
  free(body);
  free(items[0].mp_matches);
  free(items[1].mp_matches);
}

void test_DRIVERLOOKUPBULK_golden_catalog_not_loaded_and_not_known(void)
{
  DRIVERLOOKUPRecord_t item;
  memset(&item, 0, sizeof(item));
  snprintf(item.ma_fileHash, sizeof(item.ma_fileHash), "%s", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
  item.m_matchCount = 2;
  item.mp_matches   = strdup(R"([{"driver_id":"00000000-0000-0000-0000-00000000000a"}])");
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 1;
  results.m_processed  = 1;
  results.m_successful = 1;
  results.mp_items     = &item;

  char* body = static_serializeDriverLookupBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"processed":1,"successful":1,"skipped":0,"failed":0,"not_processed":[],)"
    R"("data_source":{"source":"loldrivers","available":false,"reason":"not_synced","license":"Apache-2.0"},"results":[)"
    R"({"hash":"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8","hash_type":"sha1","found":null,"match_count":null,"matches":[]})" "\n"
    "]}", body);
  free(body);
  free(item.mp_matches);

  memset(&results, 0, sizeof(results));
  results.m_total   = 1;
  results.m_skipped = 1;
  body = static_serializeDriverLookupBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"processed":0,"successful":0,"skipped":1,"failed":0,"not_processed":[],)"
    R"("data_source":{"source":"loldrivers","available":null,"license":"Apache-2.0"},"results":[]})", body);
  free(body);
}

void test_DRIVERLOOKUPBULK_golden_no_record_read_is_unknown(void)
{
  DRIVERLOOKUPRecord_t item;
  memset(&item, 0, sizeof(item));
  item.m_isDriverFeedLoaded = true;
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total     = 2;
  results.m_processed = 2;
  results.m_failed    = 2;
  results.mp_items    = &item;

  char* body = static_serializeDriverLookupBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2,"processed":2,"successful":0,"skipped":0,"failed":2,"not_processed":[],)"
    R"("data_source":{"source":"loldrivers","available":null,"license":"Apache-2.0"},"results":[]})", body);
  free(body);
}

#define ASNLOOKUP_FIX_IPV4_PREFIXES R"(["8.8.4.0/24", "8.8.8.0/24", "34.0.0.0/15"])"
#define ASNLOOKUP_FIX_IPV6_PREFIXES R"(["2001:4860::/32"])"

#define ASNLOOKUP_GOLDEN_TAIL \
  R"(,"ipv4_prefix_count":120,"ipv6_prefix_count":7,"limit":50,"offset":0,"next_offset":50,"ipv4_prefixes":)" ASNLOOKUP_FIX_IPV4_PREFIXES \
  R"(,"ipv6_prefixes":)" ASNLOOKUP_FIX_IPV6_PREFIXES "}\n"

static void static_fillASNLOOKUPRecord(ASNLOOKUPRecord_t* record, ASNLOOKUPParams_t* params)
{
  memset(record, 0, sizeof(*record));
  record->m_asn = 4200000000u;
  snprintf(record->ma_asnName, sizeof(record->ma_asnName), "%s", "EX\"AMPLE\\NET");
  snprintf(record->ma_asnCountry, sizeof(record->ma_asnCountry), "%s", "DE");
  record->m_ipv4PrefixCount = 120;
  record->m_ipv6PrefixCount = 7;
  record->mp_ipv4Prefixes   = (char*)ASNLOOKUP_FIX_IPV4_PREFIXES;
  record->mp_ipv6Prefixes   = (char*)ASNLOOKUP_FIX_IPV6_PREFIXES;
  memset(params, 0, sizeof(*params));
  snprintf(params->ma_target, sizeof(params->ma_target), "%s", "AS4200000000");
  params->m_limit  = 50;
  params->m_offset = 0;
}

static char* static_ASNLOOKUPBody(const ASNLOOKUPRecord_t* record, const ASNLOOKUPParams_t* params)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_ASNLOOKUP_response(record, params, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_ASNLOOKUP_golden_as_target(void)
{
  ASNLOOKUPRecord_t record;
  ASNLOOKUPParams_t params;
  static_fillASNLOOKUPRecord(&record, &params);

  char* body = static_ASNLOOKUPBody(&record, &params);

  TEST_ASSERT_EQUAL_STRING(
    R"({"target":"AS4200000000","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","prefix":null)" ASNLOOKUP_GOLDEN_TAIL, body);
  free(body);
}

void test_ASNLOOKUP_golden_ip_target_with_its_prefix(void)
{
  ASNLOOKUPRecord_t record;
  ASNLOOKUPParams_t params;
  static_fillASNLOOKUPRecord(&record, &params);
  snprintf(params.ma_target, sizeof(params.ma_target), "%s", "2001:4860:4860::8888");
  snprintf(record.ma_prefix, sizeof(record.ma_prefix), "%s", "2001:4860::/32");
  record.m_asn = 1;

  char* body = static_ASNLOOKUPBody(&record, &params);

  TEST_ASSERT_EQUAL_STRING(
    R"({"target":"2001:4860:4860::8888","asn":1,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","prefix":"2001:4860::/32")" ASNLOOKUP_GOLDEN_TAIL, body);
  free(body);
}

void test_ASNLOOKUP_golden_empty_country_is_null_alone(void)
{
  ASNLOOKUPRecord_t record;
  ASNLOOKUPParams_t params;
  static_fillASNLOOKUPRecord(&record, &params);
  record.ma_asnCountry[0] = '\0';

  char* body = static_ASNLOOKUPBody(&record, &params);

  TEST_ASSERT_EQUAL_STRING(
    R"({"target":"AS4200000000","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":null,"prefix":null)" ASNLOOKUP_GOLDEN_TAIL, body);
  free(body);
}

void test_ASNLOOKUP_golden_empty_family_and_a_count_past_its_list(void)
{
  ASNLOOKUPRecord_t record;
  ASNLOOKUPParams_t params;
  static_fillASNLOOKUPRecord(&record, &params);
  record.m_ipv4PrefixCount = 0;
  record.mp_ipv4Prefixes   = (char*)"[]";
  record.m_ipv6PrefixCount = 4423;
  params.m_limit           = 7;
  params.m_offset          = 4420;

  char* body = static_ASNLOOKUPBody(&record, &params);

  TEST_ASSERT_EQUAL_STRING(
    R"({"target":"AS4200000000","asn":4200000000,"asn_name":"EX\"AMPLE\\NET","asn_country":"DE","prefix":null,)"
    R"("ipv4_prefix_count":0,"ipv6_prefix_count":4423,"limit":7,"offset":4420,"next_offset":4423,"ipv4_prefixes":[],"ipv6_prefixes":)" ASNLOOKUP_FIX_IPV6_PREFIXES "}\n", body);
  free(body);
}

void test_ASNLOOKUP_next_offset_follows_the_larger_family(void)
{
  static const struct { int m_ipv4Count; int m_ipv6Count; int m_limit; int m_offset; const char* mp_page; } rows[] = {
    { 120,      7,        50, 0,           R"("limit":50,"offset":0,"next_offset":50,)" },
    { 120,      7,        50, 100,         R"("limit":50,"offset":100,"next_offset":120,)" },
    { 7,        120,      50, 100,         R"("limit":50,"offset":100,"next_offset":120,)" },
    { 120,      7,        20, 100,         R"("limit":20,"offset":100,"next_offset":120,)" },
    { 121,      7,        20, 100,         R"("limit":20,"offset":100,"next_offset":120,)" },
    { 101,      7,        20, 100,         R"("limit":20,"offset":100,"next_offset":101,)" },
    { 100,      7,        20, 100,         R"("limit":20,"offset":100,"next_offset":100,)" },
    { 120,      7,        50, 5000,        R"("limit":50,"offset":5000,"next_offset":5000,)" },
    { INT_MAX,  0,        50, INT_MAX - 3, R"("limit":50,"offset":2147483644,"next_offset":2147483647,)" },
    { 0,        INT_MAX,  1,  INT_MAX,     R"("limit":1,"offset":2147483647,"next_offset":2147483647,)" },
  };
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    ASNLOOKUPRecord_t record;
    ASNLOOKUPParams_t params;
    static_fillASNLOOKUPRecord(&record, &params);
    record.m_ipv4PrefixCount = rows[i].m_ipv4Count;
    record.m_ipv6PrefixCount = rows[i].m_ipv6Count;
    params.m_limit           = rows[i].m_limit;
    params.m_offset          = rows[i].m_offset;

    char* body = static_ASNLOOKUPBody(&record, &params);

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, rows[i].mp_page), body);
    free(body);
  }
}

static char* static_serializePackageCheckBulk(const PACKAGECHECKBULKResult_t* results)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PACKAGECHECKBULK_response(results, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_PACKAGECHECKBULK_golden_loaded(void)
{
  PACKAGECHECKBULKItem_t not_processed_items[2];
  memset(not_processed_items, 0, sizeof(not_processed_items));
  snprintf(not_processed_items[0].ma_ecosystem,   sizeof(not_processed_items[0].ma_ecosystem),   "%s", "PyPI");
  snprintf(not_processed_items[0].ma_packageName, sizeof(not_processed_items[0].ma_packageName), "%s", "django");
  snprintf(not_processed_items[0].ma_version,     sizeof(not_processed_items[0].ma_version),     "%s", "3.2.0");
  snprintf(not_processed_items[1].ma_ecosystem,   sizeof(not_processed_items[1].ma_ecosystem),   "%s", "npm");
  snprintf(not_processed_items[1].ma_packageName, sizeof(not_processed_items[1].ma_packageName), "%s", "a\"b\\c");
  snprintf(not_processed_items[1].ma_version,     sizeof(not_processed_items[1].ma_version),     "%s", "1.0.0");
  PACKAGECHECKBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total                = 6;
  results.m_processed            = 3;
  results.m_successful           = 2;
  results.m_skipped              = 2;
  results.m_failed               = 1;
  results.m_isAdvisoryFeedLoaded = true;
  results.mp_results             = strdup(R"([{"name":"lodash"},{"name":"django"}])");
  results.mp_attribution         = strdup(R"([{"source":"ghsa","license":"CC-BY-4.0"}])");
  results.mp_notProcessedItems   = not_processed_items;
  results.m_notProcessedCount    = 2;

  char* body = static_serializePackageCheckBulk(&results);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":6,"processed":3,"successful":2,"skipped":2,"failed":1,"not_processed":[)"
    R"({"ecosystem":"PyPI","name":"django","version":"3.2.0"},{"ecosystem":"npm","name":"a\"b\\c","version":"1.0.0"}],)"
    R"("data_source":{"source":"osv","available":true},"results":[{"name":"lodash"},{"name":"django"}],)"
    R"("attribution":[{"source":"ghsa","license":"CC-BY-4.0"}]})" "\n", body);
  free(body);
  free(results.mp_results);
  free(results.mp_attribution);
}

void test_PACKAGECHECKBULK_golden_not_synced_and_not_known(void)
{
  PACKAGECHECKBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total        = 1;
  results.m_processed    = 1;
  results.m_successful   = 1;
  results.mp_results     = strdup(R"([{"name":"lodash"}])");
  results.mp_attribution = strdup("[]");

  char* body = static_serializePackageCheckBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"processed":1,"successful":1,"skipped":0,"failed":0,"not_processed":[],)"
    R"("data_source":{"source":"osv","available":false,"reason":"not_synced"},"results":[{"name":"lodash"}],"attribution":[]})" "\n", body);
  free(body);
  free(results.mp_results);
  free(results.mp_attribution);

  memset(&results, 0, sizeof(results));
  results.m_total                = 1;
  results.m_skipped              = 1;
  results.m_isAdvisoryFeedLoaded = true;
  body = static_serializePackageCheckBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"processed":0,"successful":0,"skipped":1,"failed":0,"not_processed":[],)"
    R"("data_source":{"source":"osv","available":null},"results":[],"attribution":[]})" "\n", body);
  free(body);
}

void test_PACKAGECHECKBULK_golden_no_package_read_is_unknown(void)
{
  PACKAGECHECKBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total                = 2;
  results.m_processed            = 2;
  results.m_failed               = 2;
  results.m_isAdvisoryFeedLoaded = true;

  char* body = static_serializePackageCheckBulk(&results);
  TEST_ASSERT_EQUAL_STRING(
    R"({"total":2,"processed":2,"successful":0,"skipped":0,"failed":2,"not_processed":[],)"
    R"("data_source":{"source":"osv","available":null},"results":[],"attribution":[]})" "\n", body);
  free(body);
}

static char* static_serializePackageCheck(const PACKAGECHECKResult_t* result, const char* version, int limit, int offset)
{
  PACKAGECHECKParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.ma_version, sizeof(params.ma_version), "%s", version);
  params.m_limit  = limit;
  params.m_offset = offset;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PACKAGECHECK_response(result, &params, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_PACKAGECHECK_golden_with_a_version(void)
{
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_isAdvisoryFeedLoaded = true;
  result.m_hasAdvisoryData      = true;
  result.m_resultCount          = 7;
  snprintf(result.ma_fixedVersion, sizeof(result.ma_fixedVersion), "%s", "4.17.21");
  result.mp_malicious   = strdup(R"({"id":"MAL-1"})");
  result.mp_results     = strdup(R"([{"id":"GHSA-a"}])");
  result.mp_attribution = strdup(R"([{"source":"ghsa"}])");

  char* body = static_serializePackageCheck(&result, "4.17.20", 3, 2);

  TEST_ASSERT_EQUAL_STRING(
    R"({"data_source":{"source":"osv","available":true},"has_advisory_data":true,"total":7,"limit":3,"offset":2,"next_offset":5,)"
    R"("fixed_version":"4.17.21","malicious":{"id":"MAL-1"},"results":[{"id":"GHSA-a"}],"eol":null,"attribution":[{"source":"ghsa"}]})" "\n", body);
  free(body);
  free(result.mp_malicious);
  free(result.mp_results);
  free(result.mp_attribution);
}

void test_PACKAGECHECK_golden_not_synced_and_no_fixed_version(void)
{
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));

  char* body = static_serializePackageCheck(&result, "1.0.0", 20, 0);

  TEST_ASSERT_EQUAL_STRING(
    R"({"data_source":{"source":"osv","available":false,"reason":"not_synced"},"has_advisory_data":false,"total":0,"limit":20,"offset":0,"next_offset":0,)"
    R"("fixed_version":null,"malicious":null,"results":[],"eol":null,"attribution":[]})" "\n", body);
  free(body);
}

void test_PACKAGECHECK_without_a_version_writes_no_fixed_version(void)
{
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_isAdvisoryFeedLoaded = true;
  result.m_resultCount          = 1;
  snprintf(result.ma_fixedVersion, sizeof(result.ma_fixedVersion), "%s", "4.17.21");

  char* body = static_serializePackageCheck(&result, "", 20, 0);

  TEST_ASSERT_EQUAL_STRING(
    R"({"data_source":{"source":"osv","available":true},"has_advisory_data":false,"total":1,"limit":20,"offset":0,"next_offset":1,)"
    R"("malicious":null,"results":[],"eol":null,"attribution":[]})" "\n", body);
  free(body);
}

void test_PACKAGECHECK_fixed_version_is_escaped(void)
{
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  snprintf(result.ma_fixedVersion, sizeof(result.ma_fixedVersion), "%s", "1.0\"x\\");

  char* body = static_serializePackageCheck(&result, "1.0", 20, 0);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("fixed_version":"1.0\"x\\",)"));
  free(body);
}

void test_PACKAGECHECK_next_offset_is_the_offset_after_the_page(void)
{
  static const struct { int m_total; int m_offset; int m_limit; const char* mp_next; } cases[] = {
    { 7,       0,           20, R"("next_offset":7,)" },
    { 60,      20,          20, R"("next_offset":40,)" },
    { 61,      40,          20, R"("next_offset":60,)" },
    { 59,      40,          20, R"("next_offset":59,)" },
    { 5,       10,          20, R"("next_offset":10,)" },
    { INT_MAX, INT_MAX - 10, 50, R"("next_offset":2147483647,)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    PACKAGECHECKResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_resultCount = cases[i].m_total;
    char* body = static_serializePackageCheck(&result, "", cases[i].m_limit, cases[i].m_offset);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_next), body);
    free(body);
  }
}

void test_PACKAGECHECK_golden_with_eol(void)
{
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_isAdvisoryFeedLoaded = true;
  result.m_eol.m_hasEol         = true;
  strncpy(result.m_eol.ma_eolProduct, "django", PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  strncpy(result.m_eol.ma_eolUrl, "https://endoflife.date/django", PRODUCTEXPOSURE_EOL_URL_MAX_LEN);
  result.m_eol.m_eolSeriesCycleCount = 1;
  static_setEolCycle(&result.m_eol.ma_eolSeriesCycles[0], "4.2", "2026-04-30", true, false, true, "4.2.7");

  char* body = static_serializePackageCheck(&result, "", 20, 0);

  TEST_ASSERT_EQUAL_STRING(
    R"({"data_source":{"source":"osv","available":true},"has_advisory_data":false,"total":0,"limit":20,"offset":0,"next_offset":0,)"
    R"("malicious":null,"results":[],"eol":{"source":"endoflife.date","product":"django","url":"https://endoflife.date/django",)"
      R"("cycle":{"name":"4.2","eol_date":"2026-04-30","is_eol":true,"is_maintained":false,"is_lts":true,"latest_version":"4.2.7"},)"
      R"("cycle_variants":null,"maintained_cycles":[],"maintained_cycles_truncated":false},"attribution":[]})" "\n", body);
  free(body);
}

static char* static_eolMember(const char* body, const char* end)
{
  const char* start = strstr(body, R"("eol":)");
  TEST_ASSERT_NOT_NULL(start);
  const char* stop = strstr(start, end);
  TEST_ASSERT_NOT_NULL(stop);
  return strndup(start, (size_t)(stop - start));
}

void test_PACKAGECHECK_eol_is_the_eol_of_product_exposure(void)
{
  PRODUCTEXPOSURERecord_t* record = (PRODUCTEXPOSURERecord_t*)calloc(1, sizeof(PRODUCTEXPOSURERecord_t));
  TEST_ASSERT_NOT_NULL(record);
  static_newEolRecord(record);
  record->m_eol.m_eolSeriesCycleCount = 3;
  static_setEolCycle(&record->m_eol.ma_eolSeriesCycles[0], R"(11-24h2-"w)", "2026-10-13", true, false, false, "26100.1");
  static_setEolCycle(&record->m_eol.ma_eolSeriesCycles[1], "11-24h2-e", "2027-10-12", false, true, true, "26100.2");
  static_setEolCycle(&record->m_eol.ma_eolSeriesCycles[2], "11-24h2-e-lts", "", false, true, true, "");
  record->m_eol.m_eolMaintainedCycleCount = 2;
  static_setEolCycle(&record->m_eol.ma_eolMaintainedCycles[0], "26", "2029-04-30", false, true, false, "26.0.1");
  static_setEolCycle(&record->m_eol.ma_eolMaintainedCycles[1], "24", "", false, true, true, "24.1.0");
  record->m_eol.m_hasMoreEolMaintainedCycles = true;
  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_eol = record->m_eol;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(record, json_buf);
  char* product_exposure_body = static_finishJsonBuf(json_buf);
  char* package_check_body    = static_serializePackageCheck(&result, "", 20, 0);
  char* product_exposure_eol  = static_eolMember(product_exposure_body, "}\n");
  char* package_check_eol     = static_eolMember(package_check_body, R"(,"attribution":)");

  TEST_ASSERT_NOT_NULL(strstr(product_exposure_eol, R"("cycle_variants":[)"));
  TEST_ASSERT_NOT_NULL(strstr(product_exposure_eol, R"("maintained_cycles_truncated":true})"));
  TEST_ASSERT_EQUAL_STRING(product_exposure_eol, package_check_eol);
  free(product_exposure_eol);
  free(package_check_eol);
  free(product_exposure_body);
  free(package_check_body);
  free(record);
}

void test_D3FENDFORATTACK_digital_artifact_is_escaped(void)
{
  D3FENDFORATTACKItem_t defense;
  static_setD3fendDefense(&defense, "D", "L", "Detect", "Say \"x\\y\"", "[]", "[]");
  D3FENDFORATTACKResult_t result = { .mp_attackTechniques = NULL, .m_defenseCount = 1, .mp_defenses = &defense };
  D3FENDFORATTACKParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_attackTechniqueId, "T1059", ATTACK_TECHNIQUE_ID_MAX_LEN);
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_D3FENDFORATTACK_response(&result, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("digital_artifact":"Say \"x\\y\"",)"));
  free(body);
  free(defense.mp_parentDefenseLabels);
  free(defense.mp_attackTechniqueIds);
}

void test_IMAGEINSPECT_golden_lists_the_matched_types_in_order(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format    = IMAGESCAN_FORMAT_PNG;
  result.m_byteCount = 4000;
  memset(result.ma_sha256Hex, 'a', IMAGESCAN_SHA256_HEX_LEN);
  result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_ZIP]          = { 3, { 1200, 2400, 3600 } };
  result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_SHELL_SCRIPT] = { 1, { 77 } };
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    R"({"format":"png","byte_count":4000,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",)"
    R"("embedded_file_signatures":[{"file_type":"zip","match_count":3,"match_offsets":[1200,2400,3600]},)"
    R"({"file_type":"shell_script","match_count":1,"match_offsets":[77]}],)"
    R"("embedded_file_signature_note":"A signature match is a sign, not proof: the compressed data of an image can hold the same bytes by chance.",)"
    R"("metadata":{"camera_make":null,"camera_model":null,"software":null,"creator_tool":null,"digital_source_type":null,)"
    R"("date_time_original":null,"offset_time_original":null,"modify_date":null,"gps_date_time":null,)"
    R"("gps_position":null,"jpeg_quality_estimate":null,"thumbnail_byte_count":0,"c2pa_manifest":false,"c2pa_claim_generator":null,)"
    R"("generator_parameters":false,"identifiers_present":{"serial_number":false,"owner_name":false,"unique_id":false,"host_computer":false,)"
    R"("author":false,"copyright":false,"person_in_image":false,"original_file_name":false},"edit_history":[],"edit_history_has_more":false},)"
    R"("indicators":[],)"
    R"("indicator_note":"An indicator is a sign, not proof. Metadata is easy to write, to edit and to strip, and absent metadata is not a sign of forgery."})" "\n",
    body);
  free(body);
}

void test_IMAGEINSPECT_golden_writes_each_metadata_field_and_indicator(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format    = IMAGESCAN_FORMAT_JPEG;
  result.m_byteCount = 24;
  memset(result.ma_sha256Hex, 'd', IMAGESCAN_SHA256_HEX_LEN);
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_cameraMake,          "Canon");
  strcpy(exif.ma_cameraModel,         "EOS R5");
  strcpy(exif.ma_software,            "Adobe Photoshop 25.0");
  strcpy(exif.ma_creatorTool,         "Adobe Photoshop");
  strcpy(exif.ma_digitalSourceType,   "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture");
  strcpy(exif.ma_c2paClaimGenerator,  "Adobe Firefly 2");
  strcpy(exif.ma_dateTimeOriginal,    "2024:05:01 10:00:00");
  strcpy(exif.ma_offsetTimeOriginal,  "+03:00");
  strcpy(exif.ma_modifyDate,          "2024:05:02 11:30:00");
  strcpy(exif.ma_gpsDateTime,         "2024:05:01 07:00:00Z");
  exif.m_hasGpsPosition         = true;
  exif.m_gpsLatitude            = 41.0082;
  exif.m_gpsLongitude           = 28.9784;
  exif.m_jpegQualityEstimate    = 92;
  exif.m_thumbnailByteCount     = 4500;
  exif.m_hasC2paManifest        = true;
  exif.m_hasGeneratorParameters = false;
  exif.ma_isIdentifierPresent[EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER] = true;
  exif.ma_isIdentifierPresent[EXIFCLIENT_IDENTIFIER_AUTHOR]        = true;
  strcpy(exif.ma_editHistoryEntries[0].ma_action,        "created");
  strcpy(exif.ma_editHistoryEntries[0].ma_when,          "2024:05:01 10:00:00+03:00");
  strcpy(exif.ma_editHistoryEntries[0].ma_softwareAgent, "Adobe Photoshop");
  strcpy(exif.ma_editHistoryEntries[1].ma_action,        "saved");
  strcpy(exif.ma_editHistoryEntries[1].ma_when,          "2024:05:02 11:30:00+03:00");
  strcpy(exif.ma_editHistoryEntries[1].ma_softwareAgent, "Adobe Photoshop");
  exif.m_editHistoryEntryCount    = 2;
  exif.m_hasMoreEditHistoryEntries = true;
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_C2PA_MANIFEST] = true;
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_GPS_POSITION]  = true;
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_IDENTIFIER]    = true;
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_EDIT_HISTORY]  = true;
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_THUMBNAIL]     = true;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    R"({"format":"jpeg","byte_count":24,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",)"
    R"("embedded_file_signatures":[],)"
    R"("embedded_file_signature_note":"A signature match is a sign, not proof: the compressed data of an image can hold the same bytes by chance.",)"
    R"("metadata":{"camera_make":"Canon","camera_model":"EOS R5","software":"Adobe Photoshop 25.0","creator_tool":"Adobe Photoshop",)"
    R"("digital_source_type":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",)"
    R"("date_time_original":"2024:05:01 10:00:00","offset_time_original":"+03:00","modify_date":"2024:05:02 11:30:00","gps_date_time":"2024:05:01 07:00:00Z",)"
    R"("gps_position":{"latitude":41.008200,"longitude":28.978400},"jpeg_quality_estimate":92,"thumbnail_byte_count":4500,)"
    R"("c2pa_manifest":true,"c2pa_claim_generator":"Adobe Firefly 2","generator_parameters":false,)"
    R"("identifiers_present":{"serial_number":true,"owner_name":false,"unique_id":false,"host_computer":false,"author":true,"copyright":false,"person_in_image":false,"original_file_name":false},)"
    R"("edit_history":[{"action":"created","when":"2024:05:01 10:00:00+03:00","software_agent":"Adobe Photoshop"},)"
    R"({"action":"saved","when":"2024:05:02 11:30:00+03:00","software_agent":"Adobe Photoshop"}],"edit_history_has_more":true},)"
    R"("indicators":[)"
    R"({"code":"c2pa_manifest","severity":"info","note":"The file carries a C2PA manifest. Its signature is not checked, so the manifest is a claim about who made the image, not proof."},)"
    R"({"code":"gps_position","severity":"info","note":"The file carries a GPS position: where the file says the image was taken."},)"
    R"({"code":"identifier_present","severity":"info","note":"A tag that can tie the image to a person or a device is present. Its value is not shown."},)"
    R"({"code":"edit_history","severity":"info","note":"The XMP history lists at least one edit."},)"
    R"({"code":"thumbnail","severity":"info","note":"The file carries an embedded thumbnail. A thumbnail can show an earlier version of the image."}],)"
    R"("indicator_note":"An indicator is a sign, not proof. Metadata is easy to write, to edit and to strip, and absent metadata is not a sign of forgery."})" "\n",
    body);
  free(body);
}

void test_IMAGEINSPECT_escapes_the_metadata_texts(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format = IMAGESCAN_FORMAT_PNG;
  memset(result.ma_sha256Hex, 'e', IMAGESCAN_SHA256_HEX_LEN);
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_software, "a\"b\\c\x01");
  strcpy(exif.ma_editHistoryEntries[0].ma_action, "sa\"ved");
  exif.m_editHistoryEntryCount = 1;
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("software":"a\"b\\c\u0001",)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("edit_history":[{"action":"sa\"ved","when":null,"software_agent":null}],)"), body);
  free(body);
}

void test_IMAGEINSPECT_lists_only_the_kept_offsets(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format    = IMAGESCAN_FORMAT_JPEG;
  result.m_byteCount = 5000;
  memset(result.ma_sha256Hex, 'c', IMAGESCAN_SHA256_HEX_LEN);
  result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_PHP].m_matchCount = 40;
  for (int k = 0; k < IMAGESCAN_MAX_MATCH_OFFSETS; k++)
    result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_PHP].ma_matchOffsets[k] = 10 * (size_t)(k + 1);
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("embedded_file_signatures":[{"file_type":"php","match_count":40,"match_offsets":[10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160]}],)"), body);
  free(body);
}

void test_IMAGEINSPECT_writes_the_severity_of_each_kind(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format = IMAGESCAN_FORMAT_PNG;
  memset(result.ma_sha256Hex, 'f', IMAGESCAN_SHA256_HEX_LEN);
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_AI_SOURCE_TYPE]  = true;
  indicators.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_GPS_NULL_ISLAND] = true;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"({"code":"ai_source_type","severity":"moderate",)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"({"code":"gps_null_island","severity":"weak",)"), body);
  free(body);
}

void test_IMAGEINSPECT_no_match_gives_an_empty_list(void)
{
  ImageScanResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_format    = IMAGESCAN_FORMAT_TIFF;
  result.m_byteCount = 9;
  memset(result.ma_sha256Hex, 'b', IMAGESCAN_SHA256_HEX_LEN);
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  ImageIndicatorResult_t indicators;
  memset(&indicators, 0, sizeof(indicators));
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_IMAGEINSPECT_response(&result, &exif, &indicators, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"({"format":"tiff","byte_count":9,"sha256":")"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("embedded_file_signatures":[],"embedded_file_signature_note":")"), body);
  free(body);
}

void test_CPESEARCH_golden_vendor_escaped(void)
{
  CPESEARCHItem_t item;
  memset(&item, 0, sizeof(item));
  strncpy(item.ma_vendor,  R"(at\&t)", CVESEARCH_VENDOR_LEN);
  strncpy(item.ma_product, "router",   CVESEARCH_PRODUCT_LEN);
  item.m_vulnerableCveCount = 1;
  CPESEARCHResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CPESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"limit":20,"offset":0,"next_offset":1,"results":[)"
      R"({"vendor":"at\\&t","product":"router","vulnerable_cve_count":1,"product_named_by":[]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELOOKUPBULK_golden_counters_all_distinct(void)
{
  CVELOOKUPRecord_t items[2];
  static_fillGoldenLookup(&items[0], "CVE-2021-44228");
  static_fillGoldenLookup(&items[1], "CVE-2024-3400");
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 9;
  results.m_processed  = 7;
  results.m_successful = 2;
  results.m_skipped    = 3;
  results.m_failed     = 1;
  results.mp_items     = items;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":9,"processed":7,"successful":2,"skipped":3,"failed":1,"not_processed":[],"results":[)"
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n"
    ","
    R"({"cve_id":"CVE-2024-3400","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-2024-3400?include_ghsa=true"})" "\n"
    "]}",
    body);
  free(body);
}

void test_CVELOOKUP_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");

  JsonBuf_t* roomy = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, roomy);
  char* roomy_body = static_finishJsonBuf(roomy);

  JsonBuf_t* tight = static_newJsonBuf(64, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, tight);
  char* tight_body = static_finishJsonBuf(tight);

  TEST_ASSERT_GREATER_THAN_MESSAGE(64, strlen(tight_body),
    "the fixture stopped outgrowing the 64-byte start, so this test no longer exercises growth");
  TEST_ASSERT_EQUAL_STRING(roomy_body, tight_body);

  free(roomy_body);
  free(tight_body);
}

void test_CVELOOKUP_over_ceiling_hands_back_no_body(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_CVELOOKUP_response(&record, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

void test_CVELOOKUPBULK_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  CVELOOKUPRecord_t items[2];
  static_fillGoldenLookup(&items[0], "CVE-2021-44228");
  static_fillGoldenLookup(&items[1], "CVE-2024-3400");
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 2;
  results.m_processed  = 2;
  results.m_successful = 2;
  results.mp_items     = items;

  JsonBuf_t* roomy = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, roomy);
  char* roomy_body = static_finishJsonBuf(roomy);

  JsonBuf_t* tight = static_newJsonBuf(64, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUPBULK_response(&results, tight);
  char* tight_body = static_finishJsonBuf(tight);

  TEST_ASSERT_GREATER_THAN_MESSAGE(64, strlen(tight_body),
    "the fixture stopped outgrowing the 64-byte start, so this test no longer exercises growth");
  TEST_ASSERT_EQUAL_STRING(roomy_body, tight_body);

  free(roomy_body);
  free(tight_body);
}

void test_CVELOOKUPBULK_over_ceiling_hands_back_no_body(void)
{
  CVELOOKUPRecord_t items[2];
  static_fillGoldenLookup(&items[0], "CVE-2021-44228");
  static_fillGoldenLookup(&items[1], "CVE-2024-3400");
  CVELOOKUPBULKResult_t results;
  memset(&results, 0, sizeof(results));
  results.m_total      = 2;
  results.m_processed  = 2;
  results.m_successful = 2;
  results.mp_items     = items;

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_CVELOOKUPBULK_response(&results, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

static void static_fillGoldenSsvc(CVELOOKUPRecord_t* record)
{
  snprintf(record->ma_ssvcExploitation,    sizeof(record->ma_ssvcExploitation),    "%s", "active");
  snprintf(record->ma_ssvcAutomatable,     sizeof(record->ma_ssvcAutomatable),     "%s", "no");
  snprintf(record->ma_ssvcTechnicalImpact, sizeof(record->ma_ssvcTechnicalImpact), "%s", "total");
  snprintf(record->ma_ssvcVersion,         sizeof(record->ma_ssvcVersion),         "%s", "2.0.3");
  snprintf(record->ma_ssvcScoredAt,        sizeof(record->ma_ssvcScoredAt),        "%s", "2024-04-17T04:00:13Z");
  SsvcResult_t* ssvc_result = &record->m_ssvcResult;
  snprintf(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_LOW],    SSVC_DECISION_NAME_LEN + 1, "%s", "Track");
  snprintf(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_MEDIUM], SSVC_DECISION_NAME_LEN + 1, "%s", "Attend");
  snprintf(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_HIGH],   SSVC_DECISION_NAME_LEN + 1, "%s", "Act");
  snprintf(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_LOW],    SSVC_REMEDIATION_ADVICE_LEN + 1, "%s", "within standard update timelines");
  snprintf(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_MEDIUM], SSVC_REMEDIATION_ADVICE_LEN + 1, "%s", "sooner than standard update timelines");
  snprintf(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_HIGH],   SSVC_REMEDIATION_ADVICE_LEN + 1, "%s", "as soon as possible");
}

void test_CVELOOKUP_golden_ssvc_object(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  static_fillGoldenSsvc(&record);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":{"exploitation":"active","automatable":"no","technical_impact":"total",)"
      R"("version":"2.0.3","scored_at":"2024-04-17T04:00:13Z","mission_wellbeing":{)"
        R"("low":{"decision":"Track","remediation_advice":"within standard update timelines"},)"
        R"("medium":{"decision":"Attend","remediation_advice":"sooner than standard update timelines"},)"
        R"("high":{"decision":"Act","remediation_advice":"as soon as possible"}}},)"
    R"("ghsa":"/cve_lookup/CVE-2021-44228?include_ghsa=true"})" "\n", body);
  free(body);
}

void test_CVELOOKUP_ssvc_without_a_time_writes_scored_at_null(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  static_fillGoldenSsvc(&record);
  record.ma_ssvcScoredAt[0] = '\0';

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body,
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":{"exploitation":"active","automatable":"no","technical_impact":"total",)"
      R"("version":"2.0.3","scored_at":null,"mission_wellbeing":{)"
        R"("low":{"decision":"Track","remediation_advice":"within standard update timelines"},)"
        R"("medium":{"decision":"Attend","remediation_advice":"sooner than standard update timelines"},)"
        R"("high":{"decision":"Act","remediation_advice":"as soon as possible"}}},)"
    R"("ghsa":)"));
  free(body);
}

void test_CVELOOKUP_ssvc_escapes_every_string_field(void)
{
  CVELOOKUPRecord_t record;
  static_fillGoldenLookup(&record, "CVE-2021-44228");
  strncpy(record.ma_ssvcExploitation,    "act\"ive", CVELOOKUP_SSVC_VALUE_LEN);
  strncpy(record.ma_ssvcAutomatable,     "y\\es",   CVELOOKUP_SSVC_VALUE_LEN);
  strncpy(record.ma_ssvcTechnicalImpact, "to\ttal",  CVELOOKUP_SSVC_VALUE_LEN);
  strncpy(record.ma_ssvcVersion,         "2.0\n3",   CVELOOKUP_SSVC_VALUE_LEN);
  strncpy(record.ma_ssvcScoredAt,        "2024\r04", CVELOOKUP_PUBLISHED_LEN);
  SsvcResult_t* ssvc_result = &record.m_ssvcResult;
  strncpy(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_LOW],       "Tr\bck",   SSVC_DECISION_NAME_LEN);
  strncpy(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_MEDIUM],    "At\fnd",   SSVC_DECISION_NAME_LEN);
  strncpy(ssvc_result->ma_decisions[SSVC_MISSION_WELLBEING_HIGH],      "A\001ct",  SSVC_DECISION_NAME_LEN);
  strncpy(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_LOW],    "with\002in", SSVC_REMEDIATION_ADVICE_LEN);
  strncpy(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_MEDIUM], "soon\"er",   SSVC_REMEDIATION_ADVICE_LEN);
  strncpy(ssvc_result->ma_remediationAdvice[SSVC_MISSION_WELLBEING_HIGH],   "as\\soon",  SSVC_REMEDIATION_ADVICE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body,
    R"("ssvc":{"exploitation":"act\"ive","automatable":"y\\es","technical_impact":"to\ttal",)"
      R"("version":"2.0\n3","scored_at":"2024\r04","mission_wellbeing":{)"
        R"("low":{"decision":"Tr\bck","remediation_advice":"with)" "\\u0002" R"(in"},)"
        R"("medium":{"decision":"At\fnd","remediation_advice":"soon\"er"},)"
        R"("high":{"decision":"A)" "\\u0001" R"(ct","remediation_advice":"as\\soon"}}},)"
    R"("ghsa":)"));
  free(body);
}

void test_CVELOOKUP_record_escapes_every_string_field(void)
{
  CVELOOKUPRecord_t inline_record;
  static_fillGoldenLookup(&inline_record, "CVE-\"1\"");
  strncpy(inline_record.ma_severity,            "HI\\GH",      CVELOOKUP_SEVERITY_LEN);
  strncpy(inline_record.ma_cvssV3Vector,        "AV:N\tAC:L",  CVELOOKUP_V3_VECTOR_LEN);
  strncpy(inline_record.ma_cvssV4Vector,        "CVSS:4.0\v/AV:N", CVELOOKUP_V4_VECTOR_LEN);
  inline_record.m_cvssV4 = 9.3;
  strncpy(inline_record.ma_publishedTime,       "2021\n12",    CVELOOKUP_PUBLISHED_LEN);
  strncpy(inline_record.ma_cweId,               "CWE\r917",    CVELOOKUP_CWE_ID_LEN);
  strncpy(inline_record.ma_kevDateAdded,        "2021\b10",    CVELOOKUP_PUBLISHED_LEN);
  strncpy(inline_record.ma_vulnerabilityStatus, "Ana\flyzed",  CVELOOKUP_STATUS_LEN);
  strncpy(inline_record.ma_description,         "one\001two",  CVELOOKUP_DESC_MAX_LEN);
  strncpy(inline_record.ma_ransomwareCampaign,  "Kn\"own",     CVELOOKUP_RANSOMWARE_LEN);

  JsonBuf_t* inline_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&inline_record, inline_buf);
  char* inline_body = static_finishJsonBuf(inline_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-\"1\"","severity":"HI\\GH","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N\tAC:L","cvss_v3_source":null,"cvss_v4":9.3,"cvss_v4_vector":"CVSS:4.0)" "\\u000b" R"(/AV:N","cvss_v4_source":null,)"
    R"("published_time":"2021\n12",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE\r917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021\b10",)"
    R"("vulnerability_status":"Ana\flyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"one)" "\\u0001" R"(two",)"
    R"("ransomware_campaign":"Kn\"own",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-\"1\"?include_ghsa=true"})" "\n", inline_body);
  free(inline_body);

  CVELOOKUPRecord_t hint_record;
  static_fillGoldenLookup(&hint_record, "CVE-\0372");

  JsonBuf_t* hint_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELOOKUP_response(&hint_record, hint_buf);
  char* hint_body = static_finishJsonBuf(hint_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":")" "CVE-\\u001f2" R"(","severity":"CRITICAL","cvss_v3":10.0,)"
    R"("cvss_v3_vector":"AV:N/AC:L/PR:N","cvss_v3_source":null,"cvss_v4":null,"cvss_v4_vector":null,"cvss_v4_source":null,)"
    R"("published_time":"2021-12-10",)"
    R"("epss_score":0.97564,"epss_percentile":0.99977,"cwe_id":"CWE-917","cwe_source":null,)"
    R"("cwes":["CWE-917"],"in_kev":true,"kev_date_added":"2021-12-10",)"
    R"("vulnerability_status":"Analyzed",)"
    R"("affected_products":[],"affected_product_count":356,"product_count_by_vendor":{},)"
    R"("refs":[],"ref_count":52,"poc_count":22,"vendor_advisory_count":3,)"
    R"("epss_trend":[],"cve_tags":[],)"
    R"("has_metasploit_module":true,"metasploit_module_count":2,)"
    R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":1,"templates":)"
    R"([{"template_id":"CVE-2021-44228","name":"Apache Log4j2 Remote Code Injection","severity":"critical",)"
    R"("template_path":"http/cves/2021/CVE-2021-44228.yaml",)"
    R"("url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"}]},)"
    R"("description":"Log4Shell RCE",)"
    R"("ransomware_campaign":"Known",)"
    R"("ssvc":null,)"
    R"("ghsa":"/cve_lookup/CVE-)" "\\u001f" R"(2?include_ghsa=true"})" "\n", hint_body);
  free(hint_body);
}

void test_CVELEADING_golden_kev_count_includes_last_item(void)
{
  CveListItem_t items[2];
  static_fillGoldenCveListItem(&items[0], (GoldenCveListItem_t){
    .mp_cveId = "CVE-2021-44228", .mp_severity = "CRITICAL", .m_cvssV3 = 10.0,
    .m_epssScore = 0.97564, .m_epssPercentile = 0.99977, .m_inKev = true,
    .mp_publishedTime = "2021-12-10", .mp_cweId = "CWE-917" });
  static_fillGoldenCveListItem(&items[1], (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = 8.5,
    .m_epssScore = 0.5, .m_epssPercentile = 0.9, .m_inKev = true,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 12, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":2,"total":12,"limit":20,"verdict":"critical",)"
      R"("summary":"2 CVEs ranked by exploitation probability; CVE-2021-44228 leads at 97.6% (EPSS, next 30 days). 2 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.97564,"epss_percentile":0.99977,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null},)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":true,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_golden_critical_band_lower_edge(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = 8.5,
    .m_epssScore = 0.5, .m_epssPercentile = 0.9, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"critical",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 50.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_clamps_nonfinite_top_epss(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = 8.5,
    .m_epssScore = NAN, .m_epssPercentile = 0.85, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"low",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 0.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.00000,"epss_percentile":0.85000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_clamps_out_of_range_item_fields(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2021-44228", .mp_severity = "CRITICAL", .m_cvssV3 = 99.0,
    .m_epssScore = 5.0, .m_epssPercentile = 3.0, .m_inKev = true,
    .mp_publishedTime = "2021-12-10", .mp_cweId = "CWE-917" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"critical",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2021-44228 leads at 100.0% (EPSS, next 30 days). 1 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":1.00000,"epss_percentile":1.00000,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_clamps_negative_and_infinite_item_fields(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = -3.0,
    .m_epssScore = -0.5, .m_epssPercentile = INFINITY, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"low",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 0.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":0.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.00000,"epss_percentile":0.00000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_clamps_infinite_top_epss_drives_verdict(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = INFINITY,
    .m_epssScore = INFINITY, .m_epssPercentile = 0.85, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"low",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 0.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":0.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.00000,"epss_percentile":0.85000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_clamps_negative_zero_to_positive_zero(void)
{
  CveListItem_t item;
  static_fillGoldenCveListItem(&item, (GoldenCveListItem_t){
    .mp_cveId = "CVE-2024-3400", .mp_severity = "HIGH", .m_cvssV3 = -0.0,
    .m_epssScore = -0.0, .m_epssPercentile = 0.42, .m_inKev = false,
    .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 5, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":5,"limit":10,"verdict":"low",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-2024-3400 leads at 0.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-2024-3400","severity":"HIGH","cvss_v3":0.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.00000,"epss_percentile":0.42000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_growth_produces_the_same_bytes_as_a_preallocated_buffer(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* roomy = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, roomy);
  char* roomy_body = static_finishJsonBuf(roomy);

  JsonBuf_t* tight = static_newJsonBuf(64, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, tight);
  char* tight_body = static_finishJsonBuf(tight);

  TEST_ASSERT_GREATER_THAN_MESSAGE(64, strlen(tight_body),
    "the fixture stopped outgrowing the 64-byte start, so this test no longer exercises growth");
  TEST_ASSERT_EQUAL_STRING(roomy_body, tight_body);

  free(roomy_body);
  free(tight_body);
}

void test_CVELEADING_over_ceiling_hands_back_no_body(void)
{
  CveListItem_t items[2];
  static_fillGoldenListPair(items);
  CveListResult_t results = { .m_total = 57, .m_count = 2, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(64, 128);
  serialize_CVELEADING_response(&results, &params, json_buf);

  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NULL(body);
}

void test_CVESEARCH_item_escapes_every_field_through_the_shared_writer(void)
{
  CveListItem_t item;
  memset(&item, 0, sizeof(item));
  strncpy(item.ma_cveId,         "CVE-\"1\"",  CVELOOKUP_ID_MAX_LEN);
  strncpy(item.ma_severity,      "HI\\GH",     CVELOOKUP_SEVERITY_LEN);
  strncpy(item.ma_publishedTime, "2024\t04",   CVELOOKUP_PUBLISHED_LEN);
  strncpy(item.ma_cweId,         "CWE\n77\001", CVELOOKUP_CWE_ID_LEN);
  item.m_cvssV3         = 8.5;
  item.m_hasCvssV3      = true;
  item.m_epssScore      = 0.5;
  item.m_epssPercentile = 0.9;
  item.m_inKev          = false;

  CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"limit":20,"offset":0,"next_offset":1,"results":[)"
      R"({"cve_id":"CVE-\"1\"","severity":"HI\\GH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024\t04","cwe_id":"CWE\n77\u0001","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVELEADING_envelope_summary_escapes_the_repeated_cve_id(void)
{
  CveListItem_t item;
  memset(&item, 0, sizeof(item));
  strncpy(item.ma_cveId,         "CVE-\"1\"",  CVELOOKUP_ID_MAX_LEN);
  strncpy(item.ma_severity,      "HIGH",       CVELOOKUP_SEVERITY_LEN);
  strncpy(item.ma_publishedTime, "2024-04-12", CVELOOKUP_PUBLISHED_LEN);
  strncpy(item.ma_cweId,         "CWE-77",     CVELOOKUP_CWE_ID_LEN);
  item.m_cvssV3         = 8.5;
  item.m_hasCvssV3      = true;
  item.m_epssScore      = 0.5;
  item.m_epssPercentile = 0.9;
  item.m_inKev          = false;

  CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"count":1,"total":1,"limit":20,"verdict":"critical",)"
      R"("summary":"1 CVE ranked by exploitation probability; CVE-\"1\" leads at 50.0% (EPSS, next 30 days). 0 in CISA KEV.",)"
      R"("results":[)"
      R"({"cve_id":"CVE-\"1\"","severity":"HIGH","cvss_v3":8.5,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":0.50000,"epss_percentile":0.90000,"in_kev":false,)"
        R"("published_time":"2024-04-12","cwe_id":"CWE-77","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVESEARCH_publishes_out_of_range_epss_unclamped(void)
{
  CveListItem_t item;
  memset(&item, 0, sizeof(item));
  strncpy(item.ma_cveId,         "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  strncpy(item.ma_severity,      "CRITICAL",       CVELOOKUP_SEVERITY_LEN);
  strncpy(item.ma_publishedTime, "2021-12-10",     CVELOOKUP_PUBLISHED_LEN);
  strncpy(item.ma_cweId,         "CWE-917",        CVELOOKUP_CWE_ID_LEN);
  item.m_cvssV3         = 99.0;
  item.m_hasCvssV3      = true;
  item.m_epssScore      = 1.5;
  item.m_epssPercentile = 1.25;
  item.m_inKev          = true;

  CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"total":1,"limit":20,"offset":0,"next_offset":1,"results":[)"
      R"({"cve_id":"CVE-2021-44228","severity":"CRITICAL","cvss_v3":10.0,)"
        R"("cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score":1.50000,"epss_percentile":1.25000,"in_kev":true,)"
        R"("published_time":"2021-12-10","cwe_id":"CWE-917","cwe_source":null})"
    R"(]})" "\n", body);
  free(body);
}

void test_list_widest_full_page_stays_under_the_default_ceiling(void)
{
  static CveListItem_t items[CVE_LIST_MAX_LIMIT];
  memset(items, 0, sizeof(items));
  for (int i = 0; i < CVE_LIST_MAX_LIMIT; i++)
  {
    memset(items[i].ma_cveId,         0x01, CVELOOKUP_ID_MAX_LEN);
    memset(items[i].ma_severity,      0x01, CVELOOKUP_SEVERITY_LEN);
    memset(items[i].ma_publishedTime, 0x01, CVELOOKUP_PUBLISHED_LEN);
    memset(items[i].ma_cweId,         0x01, CVELOOKUP_CWE_ID_LEN);
    items[i].m_cvssV3         = 10.0;
    items[i].m_hasCvssV3      = true;
    items[i].m_cvssV4         = 10.0;
    items[i].m_hasCvssV4      = true;
    items[i].m_epssScore      = -DBL_MAX;
    items[i].m_epssPercentile = -DBL_MAX;
  }
  CveListResult_t results = { .m_total = CVE_LIST_MAX_LIMIT, .m_count = CVE_LIST_MAX_LIMIT, .mp_items = items };
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_limit = CVE_LIST_MAX_LIMIT;
  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  leading_params.m_limit = CVE_LIST_MAX_LIMIT;

  JsonBuf_t* search_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &search_params, search_buf);
  char* search_body = static_finishJsonBuf(search_buf);
  JsonBuf_t* leading_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &leading_params, leading_buf);
  char* leading_body = static_finishJsonBuf(leading_buf);

  TEST_ASSERT_LESS_THAN_size_t(JSONBUF_DEFAULT_CEILING, strlen(search_body));
  TEST_ASSERT_LESS_THAN_size_t(JSONBUF_DEFAULT_CEILING, strlen(leading_body));
  free(search_body);
  free(leading_body);
}

void test_CVE_lists_write_cvss_v4_from_its_flag_and_range(void)
{
  static const struct { double m_score; bool m_hasCvssV4; const char* mp_json; } cases[] = {
    { 9.3,  false, R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
    { 9.3,  true,  R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":9.3,"cvss_v4_source":null,"epss_score")" },
    { 11.0, true,  R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":10.0,"cvss_v4_source":null,"epss_score")" },
    { -1.0, true,  R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":0.0,"cvss_v4_source":null,"epss_score")" },
    { NAN,  true,  R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":0.0,"cvss_v4_source":null,"epss_score")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CveListItem_t item;
    memset(&item, 0, sizeof(item));
    strncpy(item.ma_cveId, "CVE-2024-3400", CVELOOKUP_ID_MAX_LEN);
    item.m_cvssV3    = 8.5;
    item.m_hasCvssV3 = true;
    item.m_cvssV4    = cases[i].m_score;
    item.m_hasCvssV4 = cases[i].m_hasCvssV4;
    CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };

    CVESEARCHParams_t search_params;
    memset(&search_params, 0, sizeof(search_params));
    search_params.m_limit = 20;
    JsonBuf_t* search_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVESEARCH_response(&results, &search_params, search_buf);
    char* search_body = static_finishJsonBuf(search_buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(search_body, cases[i].mp_json), cases[i].mp_json);
    free(search_body);

    CVELEADINGParams_t leading_params;
    memset(&leading_params, 0, sizeof(leading_params));
    leading_params.m_limit = 20;
    JsonBuf_t* leading_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVELEADING_response(&results, &leading_params, leading_buf);
    char* leading_body = static_finishJsonBuf(leading_buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(leading_body, cases[i].mp_json), cases[i].mp_json);
    free(leading_body);
  }
}

void test_CVE_lists_write_cvss_v3_from_its_flag_and_range(void)
{
  static const struct { double m_score; bool m_hasCvssV3; const char* mp_json; } cases[] = {
    { 8.5,  false, R"("cvss_v3":null,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
    { 8.5,  true,  R"("cvss_v3":8.5,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
    { 11.0, true,  R"("cvss_v3":10.0,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
    { -1.0, true,  R"("cvss_v3":0.0,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
    { NAN,  true,  R"("cvss_v3":0.0,"cvss_v3_source":null,"cvss_v4":null,"cvss_v4_source":null,"epss_score")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CveListItem_t item;
    memset(&item, 0, sizeof(item));
    strncpy(item.ma_cveId, "CVE-2024-3400", CVELOOKUP_ID_MAX_LEN);
    item.m_cvssV3    = cases[i].m_score;
    item.m_hasCvssV3 = cases[i].m_hasCvssV3;
    CveListResult_t results = { .m_total = 1, .m_count = 1, .mp_items = &item };

    CVESEARCHParams_t search_params;
    memset(&search_params, 0, sizeof(search_params));
    search_params.m_limit = 20;
    JsonBuf_t* search_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVESEARCH_response(&results, &search_params, search_buf);
    char* search_body = static_finishJsonBuf(search_buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(search_body, cases[i].mp_json), cases[i].mp_json);
    free(search_body);

    CVELEADINGParams_t leading_params;
    memset(&leading_params, 0, sizeof(leading_params));
    leading_params.m_limit = 20;
    JsonBuf_t* leading_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVELEADING_response(&results, &leading_params, leading_buf);
    char* leading_body = static_finishJsonBuf(leading_buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(leading_body, cases[i].mp_json), cases[i].mp_json);
    free(leading_body);
  }
}

void test_CVELEADING_widest_summary_sentence_fits_its_buffer(void)
{
  CveListItem_t items[10];
  for (int i = 0; i < 10; i++)
    static_fillGoldenCveListItem(&items[i], (GoldenCveListItem_t){
      .mp_cveId = "CVE-2024-123456789012345", .mp_severity = "CRITICAL", .m_cvssV3 = 10.0,
      .m_epssScore = 1.0, .m_epssPercentile = 1.0, .m_inKev = true,
      .mp_publishedTime = "2024-04-12", .mp_cweId = "CWE-77" });
  CveListResult_t results = { .m_total = 10, .m_count = 10, .mp_items = items };
  CVELEADINGParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 50;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVELEADING_response(&results, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  const char* sentence = "10 CVEs ranked by exploitation probability; CVE-2024-123456789012345 leads at 100.0% (EPSS, next 30 days). 10 in CISA KEV.";
  TEST_ASSERT_EQUAL_UINT_MESSAGE(CVELOOKUP_ID_MAX_LEN, strlen(items[0].ma_cveId), "fixture id is no longer the widest id");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(122, strlen(sentence), "fixture no longer builds the widest sentence");
  char expected[256];
  snprintf(expected, sizeof(expected), "\"summary\":\"%s\",", sentence);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, expected), body);
  free(body);
}

void test_KEVLOOKUP_every_field_is_escaped_through_its_own_class(void)
{
  KEVLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId,             "CVE-\"1",        CVELOOKUP_ID_MAX_LEN);
  strncpy(record.ma_dateAdded,         "2021\\12",       CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_vendorProject,     "Apa\bche",       KEVLOOKUP_VENDOR_LEN);
  strncpy(record.ma_product,           "Log\f4j",        KEVLOOKUP_PRODUCT_LEN);
  strncpy(record.ma_patchDeadline, "2021\n24",       CVELOOKUP_PUBLISHED_LEN);
  strncpy(record.ma_requiredAction,    "Apply\rupdates", KEVLOOKUP_REQUIRED_ACTION_LEN);
  record.m_knownRansomwareUse = true;
  strncpy(record.ma_vulnerabilityName, "Log4\tShell",    KEVLOOKUP_VULN_NAME_LEN);
  strncpy(record.ma_shortDescription,  "JNDI\001RCE",    KEVLOOKUP_SHORT_DESC_LEN);
  strncpy(record.ma_dateRemoved,       "2026\03702",     KEVLOOKUP_DATE_REMOVED_LEN);
  record.m_inKev = true;
  record.mp_cwes = strdup(R"(["CWE-917"])");
  record.mp_notes = strdup("see\002notes");

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_KEVLOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_cwes);
  free(record.mp_notes);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-\"1","in_kev":true,"date_added":"2021\\12",)"
      R"("vendor_project":"Apa\bche","product":"Log\f4j","patch_deadline":"2021\n24",)"
      R"("required_action":"Apply\rupdates","known_ransomware_use":true,)"
      R"("vulnerability_name":"Log4\tShell","short_description":"JNDI)" "\\u0001" R"(RCE",)"
      R"("notes":"see)" "\\u0002" R"(notes",)"
      R"("cwes":["CWE-917"],"date_removed":"2026)" "\\u001f" R"(02"})" "\n", body);
  free(body);
}

void test_CWELOOKUP_every_field_is_escaped_through_its_own_class(void)
{
  CWELOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cweId,       "CWE-\"79",   CWELOOKUP_ID_MAX_LEN);
  strncpy(record.ma_name,        "Impro\\per", CWELOOKUP_NAME_LEN);
  strncpy(record.ma_abstraction, "Ba\001se",   CWELOOKUP_ABSTRACTION_LEN);
  strncpy(record.ma_status,      "Sta\002ble", CWELOOKUP_STATUS_LEN);
  strncpy(record.ma_description, "XSS\bdesc",  CWELOOKUP_DESC_MAX_LEN);
  strncpy(record.ma_likelihood,  "Hi\ngh",     CWELOOKUP_LIKELIHOOD_LEN);
  strncpy(record.ma_parentCwe,   "CWE\r74",    CWELOOKUP_PARENT_CWE_LEN);
  strncpy(record.ma_updatedAt,   "2026\t05",   CWELOOKUP_UPDATED_AT_LEN);
  record.mp_extendedDescription = strdup("Ext\fdesc");
  record.mp_mitigations         = strdup(R"(["allowlists"])");
  record.mp_examples            = strdup(R"(["CVE-2024-1234"])");
  record.m_cveCount = 42;
  record.m_kevCount = 3;
  record.m_avgCvss  = 6.5;
  record.m_avgEpss  = 0.0287;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CWELOOKUP_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  free(record.mp_extendedDescription);
  free(record.mp_mitigations);
  free(record.mp_examples);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cwe_id":"CWE-\"79","name":"Impro\\per",)"
      R"("abstraction":"Ba)" "\\u0001" R"(se","status":"Sta)" "\\u0002" R"(ble",)"
      R"("description":"XSS\bdesc","extended_description":"Ext\fdesc",)"
      R"("likelihood_of_exploit":"Hi\ngh","mitigations":["allowlists"],)"
      R"("examples":["CVE-2024-1234"],"parent_cwe":"CWE\r74","cve_count":42,)"
      R"("kev_count":3,"avg_cvss":6.50,"avg_epss":0.0287,)"
      R"("updated_at":"2026\t05"})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_every_string_is_escaped_through_its_own_class(void)
{
  CVEEXPLOITRecord_t record;
  memset(&record, 0, sizeof(record));
  strncpy(record.ma_cveId, "CVE-\"1", CVELOOKUP_ID_MAX_LEN);
  record.m_githubAvailable           = true;
  record.m_githubPocRepoTotal        = 7;
  record.m_githubTopStarredRepoCount = 1;
  strncpy(record.ma_githubTopStarredRepos[0].ma_url,  "https://g\\poc", CVEEXPLOIT_REPO_URL_LEN);
  strncpy(record.ma_githubTopStarredRepos[0].ma_name, "a\npoc",         CVEEXPLOIT_REPO_NAME_LEN);
  record.ma_githubTopStarredRepos[0].m_starCount = 9;
  record.m_metasploitAvailable   = true;
  record.m_metasploitModuleTotal = 5;
  record.m_metasploitModuleCount = 1;
  strncpy(record.ma_metasploitModules[0].ma_name, "mod\001x", CVEEXPLOIT_METASPLOIT_MODULE_LEN);
  strncpy(record.ma_metasploitModules[0].ma_type, "ex\003p", CVEEXPLOIT_METASPLOIT_TYPE_LEN);
  record.m_nvdAvailable       = true;
  record.m_nvdExploitRefTotal = 2;
  record.m_nvdExploitRefCount = 1;
  strncpy(record.ma_nvdExploitRefs[0].ma_url, "https://n\tx", CVEEXPLOIT_NVD_REF_URL_LEN);
  record.m_exploitdbAvailable  = true;
  record.m_exploitdbEntryTotal = 3;
  record.m_exploitdbEntryCount = 1;
  record.ma_exploitdbEntries[0].m_edbId = 7;
  strncpy(record.ma_exploitdbEntries[0].ma_url,           "https://e\bx", CVEEXPLOIT_EXPLOITDB_URL_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_type,          "re\fm",        CVEEXPLOIT_EXPLOITDB_TYPE_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_platform,      "li\rx",        CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN);
  strncpy(record.ma_exploitdbEntries[0].ma_datePublished, "20\0042",      CVEEXPLOIT_EXPLOITDB_DATE_LEN);

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"cve_id":"CVE-\"1","exploits_found":7,"has_public_exploit":true,"in_kev":false,"sources":[)"
      R"({"source":"github","available":true,"count":7,"top_results":[)"
        R"({"url":"https://g\\poc","name":"a\npoc","stars":9}]},)"
      R"({"source":"metasploit","available":true,"has_module":true,"count":5,"top_results":[)"
        R"({"name":"mod)" "\\u0001" R"(x","type":"ex)" "\\u0003" R"(p"}]},)"
      R"({"source":"nvd","available":true,"count":2,"top_results":[)"
        R"({"url":"https://n\tx"}]},)"
      R"({"source":"exploitdb","available":true,"license":"GPL-2.0-only","count":3,"top_results":[)"
        R"({"edb_id":7,"url":"https://e\bx","type":"re\fm","platform":"li\rx","date_published":"20)" "\\u0004" R"(2","verified":false}]})"
    R"(]})" "\n", body);
  free(body);
}

void test_CVEEXPLOIT_item_counts_past_their_arrays_are_clamped(void)
{
  struct {
    CVEEXPLOITRecord_t         m_record;
    CVEEXPLOITExploitdbEntry_t m_spare;
  } fixture;
  memset(&fixture, 0, sizeof(fixture));
  CVEEXPLOITRecord_t* record = &fixture.m_record;
  strncpy(record->ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  record->m_githubAvailable           = true;
  record->m_githubTopStarredRepoCount = CVEEXPLOIT_MAX_GITHUB_REPOS + 1;
  record->m_metasploitAvailable       = true;
  record->m_metasploitModuleCount     = CVEEXPLOIT_METASPLOIT_MAX_MODULES + 1;
  record->m_nvdAvailable              = true;
  record->m_nvdExploitRefCount        = CVEEXPLOIT_NVD_MAX_REFS + 1;
  record->m_exploitdbAvailable        = true;
  record->m_exploitdbEntryCount       = CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES + 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVEEXPLOIT_response(record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  const char* nvd_source = strstr(body, R"("source":"nvd")");
  TEST_ASSERT_NOT_NULL(nvd_source);
  TEST_ASSERT_EQUAL_INT(CVEEXPLOIT_MAX_GITHUB_REPOS, static_countOccurrences(body, R"("stars":)"));
  TEST_ASSERT_EQUAL_INT(CVEEXPLOIT_METASPLOIT_MAX_MODULES + CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES,
                        static_countOccurrences(body, R"("type":)"));
  TEST_ASSERT_EQUAL_INT(CVEEXPLOIT_NVD_MAX_REFS, static_countOccurrences(nvd_source, R"({"url":)"));
  TEST_ASSERT_EQUAL_INT(CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES, static_countOccurrences(body, R"("edb_id":)"));
  free(body);
}

void test_PRODUCTEXPOSURE_top_cve_count_past_its_array_is_clamped(void)
{
  struct {
    PRODUCTEXPOSURERecord_t m_record;
    CVETRIAGEItem_t         m_spare;
  } fixture;
  memset(&fixture, 0, sizeof(fixture));
  PRODUCTEXPOSURERecord_t* record = &fixture.m_record;
  strncpy(record->ma_vendor,  "cisco", CVESEARCH_VENDOR_LEN);
  strncpy(record->ma_product, "ios",   CVESEARCH_PRODUCT_LEN);
  record->m_topCveCount = PRODUCTEXPOSURE_TOP_N + 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_TOP_N, static_countOccurrences(body, R"("cve_id":)"));
  free(body);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(312, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}


static void static_setCveIdItem(WatchlistItem_t* item, const char* cve_id)
{
  char* field = NULL;
  size_t field_size = 0;
  if (item->m_itemKind == WATCHLIST_ITEM_CVE_LOOKUP)
  {
    field      = item->m_cveLookup.ma_cveId;
    field_size = sizeof(item->m_cveLookup.ma_cveId);
  }
  else if (item->m_itemKind == WATCHLIST_ITEM_KEV_LOOKUP)
  {
    field      = item->m_kevLookup.ma_cveId;
    field_size = sizeof(item->m_kevLookup.ma_cveId);
  }
  else if (item->m_itemKind == WATCHLIST_ITEM_CVE_EXPLOIT)
  {
    field      = item->m_cveExploit.ma_cveId;
    field_size = sizeof(item->m_cveExploit.ma_cveId);
  }
  TEST_ASSERT_NOT_NULL_MESSAGE(field, "no CVE id kind");
  snprintf(field, field_size, "%s", cve_id);
}

static void static_setDomainItem(WatchlistItem_t* item, WatchlistItemKind_t kind, const char* domain_name)
{
  memset(item, 0, sizeof(*item));
  item->m_itemKind = kind;
  char* field = NULL;
  size_t field_size = 0;
  switch (kind)
  {
    case WATCHLIST_ITEM_DNS_LOOKUP:    field = item->m_dnsLookup.ma_domainName;    field_size = sizeof(item->m_dnsLookup.ma_domainName);    break;
    case WATCHLIST_ITEM_SSL_CHECK:     field = item->m_sslCheck.ma_domainName;     field_size = sizeof(item->m_sslCheck.ma_domainName);     break;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:  field = item->m_whoisLookup.ma_domainName;  field_size = sizeof(item->m_whoisLookup.ma_domainName);  break;
    case WATCHLIST_ITEM_HEADERS_CHECK: field = item->m_headersCheck.ma_domainName; field_size = sizeof(item->m_headersCheck.ma_domainName); break;
    case WATCHLIST_ITEM_CERT_SEARCH:   field = item->m_certSearch.ma_domainName;   field_size = sizeof(item->m_certSearch.ma_domainName);   break;
    default: break;
  }
  TEST_ASSERT_NOT_NULL_MESSAGE(field, "no domain kind");
  snprintf(field, field_size, "%s", domain_name);
}

static void static_cveIdItem(WatchlistItem_t* item, const char* endpoint, const char* cve_id)
{
  memset(item, 0, sizeof(*item));
  TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(endpoint, &item->m_itemKind), endpoint);
  static_setCveIdItem(item, cve_id);
}

void test_PRODUCTEXPOSURE_eol_counts_past_their_arrays_are_clamped(void)
{
  PRODUCTEXPOSURERecord_t* record = (PRODUCTEXPOSURERecord_t*)calloc(1, sizeof(PRODUCTEXPOSURERecord_t));
  TEST_ASSERT_NOT_NULL(record);
  record->m_eol.m_hasEol = true;
  for (int i = 0; i < PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX; i++)
    snprintf(record->m_eol.ma_eolSeriesCycles[i].ma_name, sizeof(record->m_eol.ma_eolSeriesCycles[i].ma_name), "s%d", i);
  for (int i = 0; i < PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX; i++)
    snprintf(record->m_eol.ma_eolMaintainedCycles[i].ma_name, sizeof(record->m_eol.ma_eolMaintainedCycles[i].ma_name), "m%d", i);
  record->m_eol.m_eolSeriesCycleCount     = PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX + 1;
  record->m_eol.m_eolMaintainedCycleCount = PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX + 1;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRODUCTEXPOSURE_response(record, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX, static_countOccurrences(body, R"({"name":"s)"));
  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX, static_countOccurrences(body, R"({"name":"m)"));
  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX + PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX, static_countOccurrences(body, R"({"name":)"));
  free(body);
  free(record);
}

static void static_productExposureItem(WatchlistItem_t* item, const char* vendor, const char* product, const char* version, bool has_cves)
{
  memset(item, 0, sizeof(*item));
  item->m_itemKind = WATCHLIST_ITEM_PRODUCT_EXPOSURE;
  snprintf(item->m_productExposure.ma_vendor,  sizeof(item->m_productExposure.ma_vendor),  "%s", vendor);
  snprintf(item->m_productExposure.ma_product, sizeof(item->m_productExposure.ma_product), "%s", product);
  snprintf(item->m_productExposure.ma_version, sizeof(item->m_productExposure.ma_version), "%s", version);
  item->m_productExposure.m_hasCves = has_cves;
}

static void static_cveSearchItem(WatchlistItem_t* item, const char* vendor, const char* product, const char* severity, const char* cwe_id,
                                 double min_cvss, double min_epss, CveKevFilter_t kev_filter, bool known_ransomware,
                                 bool has_nuclei_template)
{
  memset(item, 0, sizeof(*item));
  item->m_itemKind = WATCHLIST_ITEM_CVE_SEARCH;
  WATCHLISTCVESEARCHItem_t* filter = &item->m_cveSearch;
  snprintf(filter->ma_vendor,   sizeof(filter->ma_vendor),   "%s", vendor);
  snprintf(filter->ma_product,  sizeof(filter->ma_product),  "%s", product);
  snprintf(filter->ma_severity, sizeof(filter->ma_severity), "%s", severity);
  snprintf(filter->ma_cweId,    sizeof(filter->ma_cweId),    "%s", cwe_id);
  filter->m_minCvss           = min_cvss;
  filter->m_minEpss           = min_epss;
  filter->m_kevFilter         = kev_filter;
  filter->m_knownRansomware   = known_ransomware;
  filter->m_hasNucleiTemplate = has_nuclei_template;
}

static void static_domainNameItem(WatchlistItem_t* item, const char* domain_name)
{
  static_setDomainItem(item, WATCHLIST_ITEM_DNS_LOOKUP, domain_name);
}

static void static_packageItem(WatchlistItem_t* item, const char* ecosystem, const char* name, const char* version)
{
  memset(item, 0, sizeof(*item));
  item->m_itemKind = WATCHLIST_ITEM_PACKAGE_CHECK;
  snprintf(item->m_packageCheck.ma_ecosystem, sizeof(item->m_packageCheck.ma_ecosystem), "%s", ecosystem);
  snprintf(item->m_packageCheck.ma_name,      sizeof(item->m_packageCheck.ma_name),      "%s", name);
  snprintf(item->m_packageCheck.ma_version,   sizeof(item->m_packageCheck.ma_version),   "%s", version);
}

static char* static_WATCHLISTEDITCountedBody(WatchlistItem_t* items, int item_count, int key_item_count, int key_package_item_count)
{
  WATCHLISTEDITItemsResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_status                           = WATCHLISTEDIT_OK;
  result.mp_items                           = items;
  result.m_itemCount                        = item_count;
  result.m_itemCountForCurrentApiKey        = key_item_count;
  result.m_packageItemCountForCurrentApiKey = key_package_item_count;
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  serialize_WATCHLISTEDITItems_response(&result, json_buf);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

static char* static_WATCHLISTEDITBody(WatchlistItem_t* items, int item_count)
{
  return static_WATCHLISTEDITCountedBody(items, item_count, item_count, 0);
}

void test_WATCHLISTEDIT_golden_each_kind(void)
{
  WatchlistItem_t items[10];
  static_cveIdItem(&items[0], "cve_lookup",  "CVE-2021-0001");
  static_cveIdItem(&items[1], "kev_lookup",  "CVE-2021-0002");
  static_cveIdItem(&items[2], "cve_exploit", "CVE-2021-0003");
  static_setDomainItem(&items[3], WATCHLIST_ITEM_DNS_LOOKUP,    "a.example");
  static_setDomainItem(&items[4], WATCHLIST_ITEM_SSL_CHECK,     "b.example");
  static_setDomainItem(&items[5], WATCHLIST_ITEM_WHOIS_LOOKUP,  "c.example");
  static_setDomainItem(&items[6], WATCHLIST_ITEM_HEADERS_CHECK, "d.example");
  static_setDomainItem(&items[7], WATCHLIST_ITEM_CERT_SEARCH,   "e.example");
  memset(&items[8], 0, sizeof(items[8]));
  items[8].m_itemKind = WATCHLIST_ITEM_IP_LOOKUP;
  snprintf(items[8].m_ipLookup.ma_ipAddress, sizeof(items[8].m_ipLookup.ma_ipAddress), "%s", "8.8.8.8");
  memset(&items[9], 0, sizeof(items[9]));
  items[9].m_itemKind = WATCHLIST_ITEM_IP_LOOKUP;
  snprintf(items[9].m_ipLookup.ma_ipAddress, sizeof(items[9].m_ipLookup.ma_ipAddress), "%s", "2606:4700::1111");
  char* body = static_WATCHLISTEDITBody(items, 10);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[)x"
      R"x({"endpoint":"cve_lookup","cve_id":"CVE-2021-0001"},)x"
      R"x({"endpoint":"kev_lookup","cve_id":"CVE-2021-0002"},)x"
      R"x({"endpoint":"cve_exploit","cve_id":"CVE-2021-0003"},)x"
      R"x({"endpoint":"dns_lookup","domain":"a.example"},)x"
      R"x({"endpoint":"ssl_check","domain":"b.example"},)x"
      R"x({"endpoint":"whois_lookup","domain":"c.example"},)x"
      R"x({"endpoint":"headers_check","domain":"d.example"},)x"
      R"x({"endpoint":"cert_search","domain":"e.example"},)x"
      R"x({"endpoint":"ip_lookup","ip_address":"8.8.8.8"},)x"
      R"x({"endpoint":"ip_lookup","ip_address":"2606:4700::1111"})x"
    R"x(],"item_count":10,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_golden(void)
{
  WatchlistItem_t items[6];
  static_cveIdItem(&items[0], "cve_lookup", "CVE-2021-44228");
  static_productExposureItem(&items[1], "apache", "log4j", "2.14\"1", true);
  static_productExposureItem(&items[2], "cisco",  "ios",   "",       false);
  static_cveSearchItem(&items[3], "",     "",       "HIGH", "CWE-79", 7.5,  0.25, CVE_KEV_FILTER_ONLY_IN_KEV, true, false);
  static_cveSearchItem(&items[4], "a\"b", "gadget", "",     "",       -1.0, -1.0, CVE_KEV_FILTER_NOT_IN_KEV,  false, true);
  static_cveSearchItem(&items[5], "",     "",       "",     "",       -1.0, -1.0, CVE_KEV_FILTER_ANY,         false, false);
  char* body = static_WATCHLISTEDITBody(items, 6);

  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[)x"
      R"x({"endpoint":"cve_lookup","cve_id":"CVE-2021-44228"},)x"
      R"x({"endpoint":"product_exposure","vendor":"apache","product":"log4j","version":"2.14\"1","product_has_cves":true},)x"
      R"x({"endpoint":"product_exposure","vendor":"cisco","product":"ios","version":null,"product_has_cves":false},)x"
      R"x({"endpoint":"cve_search","severity":"HIGH","cwe_id":"CWE-79","min_cvss":7.5,"min_epss":0.25000,"in_kev":true,"known_ransomware":true},)x"
      R"x({"endpoint":"cve_search","vendor":"a\"b","product":"gadget","in_kev":false,"has_nuclei_template":true},)x"
      R"x({"endpoint":"cve_search"})x"
    R"x(],"item_count":6,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_domain_items_golden(void)
{
  WatchlistItem_t items[3];
  static_domainNameItem(&items[0], "example.co.uk");
  static_domainNameItem(&items[1], "shop.example.com");
  static_domainNameItem(&items[2], "a\"b\\c");
  char* body = static_WATCHLISTEDITBody(items, 3);

  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[)x"
      R"x({"endpoint":"dns_lookup","domain":"example.co.uk"},)x"
      R"x({"endpoint":"dns_lookup","domain":"shop.example.com"},)x"
      R"x({"endpoint":"dns_lookup","domain":"a\"b\\c"})x"
    R"x(],"item_count":3,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_ssl_check_item_golden(void)
{
  WatchlistItem_t items[2];
  static_setDomainItem(&items[0], WATCHLIST_ITEM_SSL_CHECK, "example.org");
  static_cveIdItem(&items[1], "cve_lookup", "CVE-2021-44228");
  char* body = static_WATCHLISTEDITBody(items, 2);

  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[)x"
      R"x({"endpoint":"ssl_check","domain":"example.org"},)x"
      R"x({"endpoint":"cve_lookup","cve_id":"CVE-2021-44228"})x"
    R"x(],"item_count":2,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_empty_list_golden(void)
{
  char* body = static_WATCHLISTEDITBody(NULL, 0);
  TEST_ASSERT_EQUAL_STRING(R"x({"items":[],"item_count":0,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_package_items_golden(void)
{
  WatchlistItem_t items[3];
  static_packageItem(&items[0], "npm",  "@babel/core", "7.24.0");
  static_packageItem(&items[1], "PyPI", "Django_X",    "");
  static_packageItem(&items[2], "npm",  "a\"b",        "1.0.0-rc.1+x");
  char* body = static_WATCHLISTEDITCountedBody(items, 3, 0, 3);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[)x"
      R"x({"endpoint":"package_check","ecosystem":"npm","name":"@babel/core","version":"7.24.0"},)x"
      R"x({"endpoint":"package_check","ecosystem":"PyPI","name":"Django_X","version":null},)x"
      R"x({"endpoint":"package_check","ecosystem":"npm","name":"a\"b","version":"1.0.0-rc.1+x"})x"
    R"x(],"item_count":0,"item_limit":100,"package_item_count":3,"package_item_limit":500})x" "\n", body);
  free(body);

  body = static_WATCHLISTEDITCountedBody(items, 1, 3, 498);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"items":[{"endpoint":"package_check","ecosystem":"npm","name":"@babel/core","version":"7.24.0"}],)x"
    R"x("item_count":3,"item_limit":100,"package_item_count":498,"package_item_limit":500})x" "\n", body);
  free(body);

  body = static_WATCHLISTEDITCountedBody(NULL, 0, 41, 7);
  TEST_ASSERT_EQUAL_STRING(R"x({"items":[],"item_count":41,"item_limit":100,"package_item_count":7,"package_item_limit":500})x" "\n", body);
  free(body);
}

static char* static_WATCHLISTEDITPackageListBody(WATCHLISTEDITAction_t action, int added_count, int removed_count, int unchanged_count)
{
  WATCHLISTEDITPackageListResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_status                           = WATCHLISTEDIT_OK;
  result.m_action                           = action;
  result.m_addedCount                       = added_count;
  result.m_removedCount                     = removed_count;
  result.m_unchangedCount                   = unchanged_count;
  result.m_packageItemCountForCurrentApiKey = 9;
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  serialize_WATCHLISTEDITPackageList_response(&result, json_buf);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return body;
}

void test_WATCHLISTEDIT_package_list_golden(void)
{
  char* body = static_WATCHLISTEDITPackageListBody(WATCHLISTEDIT_ACTION_ADD, 4, 3, 5);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"added_count":4,"unchanged_count":5,"package_item_count":9,"package_item_limit":500})x" "\n", body);
  free(body);

  body = static_WATCHLISTEDITPackageListBody(WATCHLISTEDIT_ACTION_REMOVE, 4, 3, 5);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"removed_count":3,"unchanged_count":5,"package_item_count":9,"package_item_limit":500})x" "\n", body);
  free(body);
}

static void static_problemElement(WATCHLISTEDITPackageElement_t* element, const char* ecosystem, const char* name, const char* version,
                                  PackageElementProblem_t problem, int earlier_index)
{
  memset(element, 0, sizeof(*element));
  element->m_hasEcosystem = ecosystem != NULL;
  element->m_hasName      = name != NULL;
  element->m_hasVersion   = version != NULL;
  snprintf(element->m_package.ma_ecosystem,   sizeof(element->m_package.ma_ecosystem),   "%s", ecosystem != NULL ? ecosystem : "");
  snprintf(element->m_package.ma_packageName, sizeof(element->m_package.ma_packageName), "%s", name != NULL ? name : "");
  snprintf(element->m_package.ma_version,     sizeof(element->m_package.ma_version),     "%s", version != NULL ? version : "");
  element->m_problem      = problem;
  element->m_earlierIndex = earlier_index;
}

static char* static_WATCHLISTEDITProblemsBody(const char* message, const WATCHLISTEDITPackageElement_t* elements, int element_count, size_t ceiling)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, ceiling);
  TEST_ASSERT_NOT_NULL(json_buf);
  serialize_WATCHLISTEDITPackageList_problems_response(message, elements, element_count, json_buf);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return body;
}

void test_WATCHLISTEDIT_problems_golden(void)
{
  WATCHLISTEDITPackageElement_t elements[7];
  static_problemElement(&elements[0], "npm",  "lodash",   "4.17.20", PACKAGE_ELEMENT_PROBLEM_NONE,              -1);
  static_problemElement(&elements[1], NULL,   NULL,       NULL,      PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT,     -1);
  static_problemElement(&elements[2], "cpan", "a\"b",     NULL,      PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN, -1);
  static_problemElement(&elements[3], "NPM",  "lodash",   "4.17.20", PACKAGE_ELEMENT_PROBLEM_REPEATED,          0);
  static_problemElement(&elements[4], "PyPI", "Foo_Bar",  "1",       PACKAGE_ELEMENT_PROBLEM_NONE,              -1);
  static_problemElement(&elements[5], "pypi", "foo-bar",  "1",       PACKAGE_ELEMENT_PROBLEM_NORMALIZED_REPEAT, 4);
  static_problemElement(&elements[6], "npm",  "a\x01" "b", "",       PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR, -1);
  char* body = static_WATCHLISTEDITProblemsBody("nothing \"changed\"", elements, 7, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"error":{"code":"bad_request","message":"nothing \"changed\""},"problems":[)x"
      R"x({"index":1,"ecosystem":null,"name":null,"version":null,"reason":"the element is not a JSON object"},)x"
      R"x({"index":2,"ecosystem":"cpan","name":"a\"b","version":null,"reason":"ecosystem must be one of npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL"},)x"
      R"x({"index":3,"ecosystem":"NPM","name":"lodash","version":"4.17.20","reason":"repeats packages[0]"},)x"
      R"x({"index":5,"ecosystem":"pypi","name":"foo-bar","version":"1","reason":"names the package and version of packages[4] once the names are normalized"},)x"
      R"x({"index":6,"ecosystem":"npm","name":"a\u0001b","version":"","reason":"name must not contain a control character"})x"
    R"x(]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEDIT_problems_give_each_problem_its_reason(void)
{
  const struct { PackageElementProblem_t m_problem; const char* mp_reason; } cases[] = {
    { PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT,      "the element is not a JSON object" },
    { PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN,     "the element holds a member other than ecosystem, name and version" },
    { PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED,    "the element names one member twice" },
    { PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT, "ecosystem must be a string of at most 16 bytes, with no \\\\u0000 and no lone surrogate" },
    { PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      "name must be a string of at most 256 bytes, with no \\\\u0000 and no lone surrogate" },
    { PACKAGE_ELEMENT_PROBLEM_VERSION_NOT_TEXT,   "version must be a string of at most 128 bytes, with no \\\\u0000 and no lone surrogate" },
    { PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN,  "ecosystem must be one of npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL" },
    { PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY,         "name is missing or empty" },
    { PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR,  "name must not contain a control character" },
    { PACKAGE_ELEMENT_PROBLEM_NAME_SPACE,         "name must not contain a space" },
    { PACKAGE_ELEMENT_PROBLEM_VERSION_INVALID,    "version must hold only visible ASCII characters, with no space" },
    { PACKAGE_ELEMENT_PROBLEM_REPEATED,           "repeats packages[12]" },
    { PACKAGE_ELEMENT_PROBLEM_NORMALIZED_REPEAT,  "names the package and version of packages[12] once the names are normalized" },
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
  {
    WATCHLISTEDITPackageElement_t element;
    static_problemElement(&element, NULL, NULL, NULL, cases[k].m_problem, 12);
    char* body = static_WATCHLISTEDITProblemsBody("m", &element, 1, JSONBUF_DEFAULT_CEILING);
    TEST_ASSERT_NOT_NULL(body);
    char expected[512];
    snprintf(expected, sizeof(expected),
             R"x({"error":{"code":"bad_request","message":"m"},"problems":[{"index":0,"ecosystem":null,"name":null,"version":null,"reason":"%s"}]})x" "\n",
             cases[k].mp_reason);
    TEST_ASSERT_EQUAL_STRING(expected, body);
    free(body);
  }
}

void test_WATCHLISTEDIT_problems_of_most_elements_fit_the_ceiling(void)
{
  const int                      element_count = WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY;
  WATCHLISTEDITPackageElement_t* elements = (WATCHLISTEDITPackageElement_t*)calloc((size_t)element_count, sizeof(WATCHLISTEDITPackageElement_t));
  TEST_ASSERT_NOT_NULL(elements);
  for (int i = 0; i < element_count; i++)
  {
    PACKAGECHECKBULKItem_t* package = &elements[i].m_package;
    memset(package->ma_ecosystem, 0x01, sizeof(package->ma_ecosystem) - 1);
    memset(package->ma_packageName, 0x01, sizeof(package->ma_packageName) - 1);
    memset(package->ma_version, 0x01, sizeof(package->ma_version) - 1);
    elements[i].m_hasEcosystem = true;
    elements[i].m_hasName      = true;
    elements[i].m_hasVersion   = true;
    elements[i].m_problem      = PACKAGE_ELEMENT_PROBLEM_REPEATED;
    elements[i].m_earlierIndex = 0;
  }
  char* body = static_WATCHLISTEDITProblemsBody("m", elements, element_count, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(body);
  size_t body_len = strlen(body);
  TEST_ASSERT_TRUE(body_len < (size_t)JSONBUF_DEFAULT_CEILING);
  printf("refusal of %d longest problem rows: %zu bytes of %d\n", element_count, body_len, JSONBUF_DEFAULT_CEILING);
  free(body);
  free(elements);
}

void test_WATCHLISTEDIT_item_writes_only_its_set_fields(void)
{
  static const struct { const char* mp_field; const char* mp_expected; } cases[] = {
    { "vendor",           R"x({"endpoint":"cve_search","vendor":"v"})x" },
    { "product",          R"x({"endpoint":"cve_search","product":"p"})x" },
    { "severity",         R"x({"endpoint":"cve_search","severity":"LOW"})x" },
    { "cwe_id",           R"x({"endpoint":"cve_search","cwe_id":"CWE-20"})x" },
    { "min_cvss",         R"x({"endpoint":"cve_search","min_cvss":0.0})x" },
    { "min_epss",         R"x({"endpoint":"cve_search","min_epss":0.00000})x" },
    { "in_kev",           R"x({"endpoint":"cve_search","in_kev":false})x" },
    { "known_ransomware", R"x({"endpoint":"cve_search","known_ransomware":true})x" },
    { "has_nuclei_template", R"x({"endpoint":"cve_search","has_nuclei_template":true})x" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    WatchlistItem_t item;
    static_cveSearchItem(&item, "", "", "", "", -1.0, -1.0, CVE_KEV_FILTER_ANY, false, false);
    WATCHLISTCVESEARCHItem_t* filter = &item.m_cveSearch;
    const char* field = cases[i].mp_field;
    if (strcmp(field, "vendor") == 0)
      snprintf(filter->ma_vendor, sizeof(filter->ma_vendor), "%s", "v");
    else if (strcmp(field, "product") == 0)
      snprintf(filter->ma_product, sizeof(filter->ma_product), "%s", "p");
    else if (strcmp(field, "severity") == 0)
      snprintf(filter->ma_severity, sizeof(filter->ma_severity), "%s", "LOW");
    else if (strcmp(field, "cwe_id") == 0)
      snprintf(filter->ma_cweId, sizeof(filter->ma_cweId), "%s", "CWE-20");
    else if (strcmp(field, "min_cvss") == 0)
      filter->m_minCvss = 0.0;
    else if (strcmp(field, "min_epss") == 0)
      filter->m_minEpss = 0.0;
    else if (strcmp(field, "in_kev") == 0)
      filter->m_kevFilter = CVE_KEV_FILTER_NOT_IN_KEV;
    else if (strcmp(field, "known_ransomware") == 0)
      filter->m_knownRansomware = true;
    else
      filter->m_hasNucleiTemplate = true;

    char expected[256];
    int written = snprintf(expected, sizeof(expected), R"x({"items":[%s],"item_count":1,"item_limit":100,"package_item_count":0,"package_item_limit":500})x" "\n", cases[i].mp_expected);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected));
    char* body = static_WATCHLISTEDITBody(&item, 1);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, body, field);
    free(body);
  }
}

static void static_watchlistEvent(WATCHLISTEVENTSEvent_t* event, const char* event_type, const char* changed_at, const char* cve_id,
                                  bool has_previous, double previous, bool has_current, double current)
{
  memset(event, 0, sizeof(*event));
  snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", event_type);
  snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", changed_at);
  WATCHLISTEVENTSCveChange_t* change = &event->m_cveChange;
  snprintf(change->ma_cveId, sizeof(change->ma_cveId), "%s", cve_id);
  change->m_hasPreviousValue = has_previous;
  change->m_previousValue    = previous;
  change->m_hasCurrentValue  = has_current;
  change->m_currentValue     = current;
}

static WatchlistEventKind_t static_domainEventKind(const char* event_type)
{
  static const struct { const char* mp_type; WatchlistEventKind_t m_kind; } lanes[] = {
    { "domain_not_found",        WATCHLIST_EVENT_DNS_LOOKUP },
    { "domain_found",            WATCHLIST_EVENT_DNS_LOOKUP },
    { "ns_changed",              WATCHLIST_EVENT_DNS_LOOKUP },
    { "mx_changed",              WATCHLIST_EVENT_DNS_LOOKUP },
    { "ip_address_not_public",   WATCHLIST_EVENT_DNS_LOOKUP },
    { "ip_address_lost",         WATCHLIST_EVENT_DNS_LOOKUP },
    { "ip_address_restored",     WATCHLIST_EVENT_DNS_LOOKUP },
    { "cname_takeover_detected", WATCHLIST_EVENT_DNS_LOOKUP },
    { "cname_takeover_resolved", WATCHLIST_EVENT_DNS_LOOKUP },
    { "email_auth_degraded",     WATCHLIST_EVENT_DNS_LOOKUP },
    { "hosting_changed",         WATCHLIST_EVENT_DNS_LOOKUP },
    { "cert_expiring",           WATCHLIST_EVENT_SSL_CHECK },
    { "cert_invalid",            WATCHLIST_EVENT_SSL_CHECK },
    { "cert_listed",             WATCHLIST_EVENT_SSL_CHECK },
    { "tls_downgraded",          WATCHLIST_EVENT_SSL_CHECK },
    { "domain_expiring",         WATCHLIST_EVENT_WHOIS_LOOKUP },
    { "registrar_changed",       WATCHLIST_EVENT_WHOIS_LOOKUP },
    { "transfer_lock_removed",   WATCHLIST_EVENT_WHOIS_LOOKUP },
    { "dnssec_disabled",         WATCHLIST_EVENT_WHOIS_LOOKUP },
    { "security_header_removed", WATCHLIST_EVENT_HEADERS_CHECK },
    { "cert_unexpected",         WATCHLIST_EVENT_CERT_SEARCH },
  };
  for (size_t i = 0; i < sizeof(lanes) / sizeof(lanes[0]); i++)
  {
    if (strcmp(lanes[i].mp_type, event_type) == 0)
      return lanes[i].m_kind;
  }
  TEST_FAIL_MESSAGE(event_type);
  return WATCHLIST_EVENT_CVE;
}

static void static_domainEvent(WATCHLISTEVENTSEvent_t* event, const char* event_type, const char* changed_at, const char* check_id,
                               const char* previous, const char* current)
{
  memset(event, 0, sizeof(*event));
  snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", event_type);
  snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", changed_at);
  event->m_eventKind = static_domainEventKind(event_type);
  char** previous_field = NULL;
  char** current_field  = NULL;
  switch (event->m_eventKind)
  {
    case WATCHLIST_EVENT_DNS_LOOKUP:
      if (check_id != NULL)
        snprintf(event->m_dnsLookupChange.ma_degradedEmailCheckId, sizeof(event->m_dnsLookupChange.ma_degradedEmailCheckId), "%s", check_id);
      previous_field = &event->m_dnsLookupChange.mp_previousValue;
      current_field  = &event->m_dnsLookupChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_SSL_CHECK:
      previous_field = &event->m_sslCheckChange.mp_previousValue;
      current_field  = &event->m_sslCheckChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_WHOIS_LOOKUP:
      previous_field = &event->m_whoisLookupChange.mp_previousValue;
      current_field  = &event->m_whoisLookupChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_HEADERS_CHECK:
      previous_field = &event->m_headersCheckChange.mp_previousValue;
      current_field  = &event->m_headersCheckChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_CERT_SEARCH:
      previous_field = &event->m_certSearchChange.mp_previousValue;
      current_field  = &event->m_certSearchChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_CVE:
    case WATCHLIST_EVENT_PACKAGE_CHECK:
    case WATCHLIST_EVENT_IP_LOOKUP:
    case WATCHLIST_EVENT_PRODUCT_EXPOSURE:
      break;
  }
  TEST_ASSERT_NOT_NULL_MESSAGE(previous_field, event_type);
  TEST_ASSERT_TRUE_MESSAGE(check_id == NULL || event->m_eventKind == WATCHLIST_EVENT_DNS_LOOKUP, event_type);
  *previous_field = const_cast<char*>(previous);
  *current_field  = const_cast<char*>(current);
}

static void static_ipEvent(WATCHLISTEVENTSEvent_t* event, const char* event_type, const char* changed_at, const char* previous,
                           const char* current, const char* list_time, const char* copyright)
{
  memset(event, 0, sizeof(*event));
  snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", event_type);
  snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", changed_at);
  event->m_eventKind = WATCHLIST_EVENT_IP_LOOKUP;
  WATCHLISTIPLOOKUPChange_t* change = &event->m_ipLookupChange;
  change->mp_previousValue = const_cast<char*>(previous);
  change->mp_currentValue  = const_cast<char*>(current);
  snprintf(change->ma_dropListTime,  sizeof(change->ma_dropListTime),  "%s", list_time != NULL ? list_time : "");
  snprintf(change->ma_dropCopyright, sizeof(change->ma_dropCopyright), "%s", copyright != NULL ? copyright : "");
}

static void static_cveFacts(WATCHLISTEVENTSCveFacts_t* facts, const char* cve_id, double risk_score, const char* label, bool is_in_kev,
                            const char* kev_patch_deadline, bool kev_known_ransomware, bool has_metasploit, int poc_count)
{
  memset(facts, 0, sizeof(*facts));
  snprintf(facts->ma_cveId, sizeof(facts->ma_cveId), "%s", cve_id);
  facts->m_riskScore = risk_score;
  snprintf(facts->ma_riskLabel, sizeof(facts->ma_riskLabel), "%s", label);
  facts->m_isInKev = is_in_kev;
  facts->m_hasKev  = kev_patch_deadline != NULL;
  snprintf(facts->ma_kevPatchDeadline, sizeof(facts->ma_kevPatchDeadline), "%s", kev_patch_deadline != NULL ? kev_patch_deadline : "");
  facts->m_kevKnownRansomware = kev_known_ransomware;
  facts->m_hasMetasploit      = has_metasploit;
  facts->m_pocCount           = poc_count;
}

typedef struct {
  const char* mp_dnsPresence;
  const char* mp_ns;
  const char* mp_mx;
  const char* mp_address;
  const char* mp_takeover;
  const char* mp_emailAuth;
} WatchlistTestDomainValues_t;

static void static_domainFacts(WATCHLISTEVENTSDomainFacts_t* facts, const char* domain_name, const char* registered_domain,
                               const WatchlistTestDomainValues_t* values)
{
  memset(facts, 0, sizeof(*facts));
  snprintf(facts->ma_domainName, sizeof(facts->ma_domainName), "%s", domain_name);
  snprintf(facts->ma_registeredDomain, sizeof(facts->ma_registeredDomain), "%s", registered_domain);
  facts->m_dnsFacts.mp_dnsPresenceValue           = const_cast<char*>(values->mp_dnsPresence);
  facts->m_dnsFacts.mp_nsValue                    = const_cast<char*>(values->mp_ns);
  facts->m_dnsFacts.mp_mxValue                    = const_cast<char*>(values->mp_mx);
  facts->m_dnsFacts.mp_ipAddressReachabilityValue = const_cast<char*>(values->mp_address);
  facts->m_dnsFacts.mp_cnameTakeoverValue         = const_cast<char*>(values->mp_takeover);
  facts->m_dnsFacts.mp_emailAuthValue             = const_cast<char*>(values->mp_emailAuth);
}

static void static_answerItem(WATCHLISTEVENTSAnswerItem_t* answer_item, const char* endpoint, const char* value, int first_pair_index, int pair_count)
{
  memset(answer_item, 0, sizeof(*answer_item));
  WatchlistItem_t* item = &answer_item->m_item;
  WatchlistItemKind_t kind;
  TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(endpoint, &kind), endpoint);
  item->m_itemKind = kind;
  if (kind == WATCHLIST_ITEM_CVE_LOOKUP || kind == WATCHLIST_ITEM_KEV_LOOKUP || kind == WATCHLIST_ITEM_CVE_EXPLOIT)
    static_setCveIdItem(item, value);
  else if (watchlist_isDomainItemKind(kind))
    static_setDomainItem(item, kind, value);
  else if (kind == WATCHLIST_ITEM_IP_LOOKUP)
    snprintf(item->m_ipLookup.ma_ipAddress, sizeof(item->m_ipLookup.ma_ipAddress), "%s", value);
  else if (kind == WATCHLIST_ITEM_CVE_SEARCH)
  {
    item->m_cveSearch.m_minCvss   = -1.0;
    item->m_cveSearch.m_minEpss   = -1.0;
    item->m_cveSearch.m_kevFilter = CVE_KEV_FILTER_ANY;
  }
  answer_item->m_firstPairIndex = first_pair_index;
  answer_item->m_pairCount      = pair_count;
}

static char* static_WATCHLISTEVENTSBodyWithCeiling(const WATCHLISTEVENTSParams_t* params, const char* next_cursor, bool has_more,
                                                   WATCHLISTEVENTSResult_t* result, size_t ceiling)
{
  result->m_status = next_cursor != NULL ? WATCHLISTEVENTS_OK : WATCHLISTEVENTS_NO_POSITION;
  snprintf(result->ma_nextCursor, sizeof(result->ma_nextCursor), "%s", next_cursor != NULL ? next_cursor : "");
  result->m_hasMore = has_more;
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, ceiling);
  TEST_ASSERT_NOT_NULL(json_buf);
  serialize_WATCHLISTEVENTS_response(result, params, json_buf);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return body;
}

static char* static_WATCHLISTEVENTSBody(const WATCHLISTEVENTSParams_t* params, const char* next_cursor, bool has_more, WATCHLISTEVENTSResult_t* result)
{
  char* body = static_WATCHLISTEVENTSBodyWithCeiling(params, next_cursor, has_more, result, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

void test_WATCHLISTEVENTS_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 7;
  snprintf(params.ma_cursor, sizeof(params.ma_cursor), "%s", "41");
  params.m_isRepeat = false;
  WATCHLISTEVENTSEvent_t events[3];
  static_watchlistEvent(&events[0], "kev_added",              "2026-10-15T08:09:10Z", "CVE-2021-44228", false, 0.0, false, 0.0);
  static_watchlistEvent(&events[1], "epss_changed",           "2026-10-15T08:09:11Z", "CVE-2022-12345", true,  0.4, true,  0.52345);
  static_watchlistEvent(&events[2], "cvss_risk_band_changed", "2026-10-15T08:09:12Z", "CVE-2021-44228", true,  5.0, true,  7.5);
  WATCHLISTEVENTSAnswerItem_t items[2];
  static_answerItem(&items[0], "cve_lookup",     "CVE-2021-44228", 0, 1);
  static_answerItem(&items[1], "cve_search", NULL,             1, 3);
  snprintf(items[1].m_item.m_cveSearch.ma_severity, sizeof(items[1].m_item.m_cveSearch.ma_severity), "%s", "CRITICAL");
  int pairs[] = { 0, 0, 1, 2 };
  WATCHLISTEVENTSCveFacts_t cve_facts[2];
  static_cveFacts(&cve_facts[0], "CVE-2021-44228", 96.5, "CRITICAL", true,  "2021-12-24", true,  false, 3);
  static_cveFacts(&cve_facts[1], "CVE-2022-12345", 40.0, "MEDIUM",   false, NULL,         false, true,  12);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 3;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 2;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 4;
  result.mp_cveFacts         = cve_facts;
  result.m_cveFactCount      = 2;
  char* body = static_WATCHLISTEVENTSBody(&params, "58", true, &result);

  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":7,"cursor":"41","repeat":false,"next_cursor":"58","has_more":true,"items":[)x"
      R"x({"item":{"endpoint":"cve_lookup","cve_id":"CVE-2021-44228"},"events":[)x"
        R"x({"event":"kev_added","changed_at":"2026-10-15T08:09:10Z","cve_id":"CVE-2021-44228","previous":null,"current":null,"vendor":null,"product":null}]},)x"
      R"x({"item":{"endpoint":"cve_search","severity":"CRITICAL"},"events":[)x"
        R"x({"event":"kev_added","changed_at":"2026-10-15T08:09:10Z","cve_id":"CVE-2021-44228","previous":null,"current":null,"vendor":null,"product":null},)x"
        R"x({"event":"epss_changed","changed_at":"2026-10-15T08:09:11Z","cve_id":"CVE-2022-12345","previous":0.40000,"current":0.52345,"vendor":null,"product":null},)x"
        R"x({"event":"cvss_risk_band_changed","changed_at":"2026-10-15T08:09:12Z","cve_id":"CVE-2021-44228","previous":5.00000,"current":7.50000,"vendor":null,"product":null}]})x"
    R"x(],"cves":{)x"
      R"x("CVE-2021-44228":{"risk_score":96.5,"label":"CRITICAL","in_kev":true,"kev_patch_deadline":"2021-12-24","known_ransomware":true,"has_metasploit":false,"poc_count":3},)x"
      R"x("CVE-2022-12345":{"risk_score":40.0,"label":"MEDIUM","in_kev":false,"kev_patch_deadline":null,"known_ransomware":false,"has_metasploit":true,"poc_count":12})x"
    R"x(},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_no_position_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit    = 20;
  params.m_isRepeat = true;
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  char* body = static_WATCHLISTEVENTSBody(&params, NULL, false, &result);
  TEST_ASSERT_EQUAL_STRING(R"x({"limit":20,"cursor":null,"repeat":true,"next_cursor":null,"has_more":false,"items":[],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_cves_map_keeps_the_entry_order(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 4;
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  char* body = static_WATCHLISTEVENTSBody(&params, "3", false, &result);
  TEST_ASSERT_EQUAL_STRING(R"x({"limit":4,"cursor":null,"repeat":false,"next_cursor":"3","has_more":false,"items":[],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);

  WATCHLISTEVENTSEvent_t events[4];
  static_watchlistEvent(&events[0], "product_added", "2026-01-02T03:04:05Z", "CVE-2024-0002", false, 0.0, false, 0.0);
  events[0].m_cveChange.m_hasProductPair = true;
  snprintf(events[0].m_cveChange.ma_vendor, sizeof(events[0].m_cveChange.ma_vendor), "%s", "a\"cme");
  snprintf(events[0].m_cveChange.ma_product, sizeof(events[0].m_cveChange.ma_product), "%s", "wid\\get");
  static_watchlistEvent(&events[1], "cve_added",     "2026-01-02T03:04:06Z", "CVE-2024-0001", false, 0.0, false, 0.0);
  static_watchlistEvent(&events[2], "cvss_added",    "2026-01-02T03:04:07Z", "CVE-2024-0002", false, 0.0, true,  9.8);
  static_watchlistEvent(&events[3], "kev_removed",   "2026-01-02T03:04:08Z", "CVE-2024-0001", false, 0.0, false, 0.0);
  WATCHLISTEVENTSAnswerItem_t items[1];
  static_answerItem(&items[0], "cve_search", NULL, 0, 4);
  int pairs[] = { 0, 1, 2, 3 };
  WATCHLISTEVENTSCveFacts_t cve_facts[2];
  static_cveFacts(&cve_facts[0], "CVE-2024-0002", 71.0, "HIGH", false, "2026-01-15", true,  true,  7);
  static_cveFacts(&cve_facts[1], "CVE-2024-0001", 12.5, "LOW",  true,  NULL,         false, false, 2);
  result.mp_events           = events;
  result.m_eventCount        = 4;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 1;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 4;
  result.mp_cveFacts         = cve_facts;
  result.m_cveFactCount      = 2;
  body = static_WATCHLISTEVENTSBody(&params, "9", true, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":4,"cursor":null,"repeat":false,"next_cursor":"9","has_more":true,"items":[{"item":{"endpoint":"cve_search"},"events":[)x"
      R"x({"event":"product_added","changed_at":"2026-01-02T03:04:05Z","cve_id":"CVE-2024-0002","previous":null,"current":null,"vendor":"a\"cme","product":"wid\\get"},)x"
      R"x({"event":"cve_added","changed_at":"2026-01-02T03:04:06Z","cve_id":"CVE-2024-0001","previous":null,"current":null,"vendor":null,"product":null},)x"
      R"x({"event":"cvss_added","changed_at":"2026-01-02T03:04:07Z","cve_id":"CVE-2024-0002","previous":null,"current":9.80000,"vendor":null,"product":null},)x"
      R"x({"event":"kev_removed","changed_at":"2026-01-02T03:04:08Z","cve_id":"CVE-2024-0001","previous":null,"current":null,"vendor":null,"product":null})x"
    R"x(]}],"cves":{)x"
      R"x("CVE-2024-0002":{"risk_score":71.0,"label":"HIGH","in_kev":false,"kev_patch_deadline":"2026-01-15","known_ransomware":true,"has_metasploit":true,"poc_count":7},)x"
      R"x("CVE-2024-0001":{"risk_score":12.5,"label":"LOW","in_kev":true,"kev_patch_deadline":null,"known_ransomware":false,"has_metasploit":false,"poc_count":2})x"
    R"x(},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_dns_events_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;
  WATCHLISTEVENTSEvent_t events[8];
  static_domainEvent(&events[0], "ns_changed",              "2026-10-16T01:02:03Z", NULL, "ns1.example.net\nns2.example.net", "ns1.example.org");
  static_domainEvent(&events[1], "mx_changed",              "2026-10-16T01:02:04Z", NULL, "", "null");
  static_domainEvent(&events[2], "mx_changed",              "2026-10-16T01:02:05Z", NULL, "10 mx1.example.com\n20 mx2.example.com", "");
  static_domainEvent(&events[3], "domain_found",            "2026-10-16T01:02:06Z", NULL, "not_found", "found");
  static_domainEvent(&events[4], "ip_address_lost",         "2026-10-16T01:02:07Z", NULL, "public", "not_public");
  static_domainEvent(&events[5], "cname_takeover_resolved", "2026-10-16T01:02:08Z", NULL, NULL, "none");
  static_domainEvent(&events[6], "hosting_changed",         "2026-10-16T01:02:10Z", NULL, "akamai/akamai\naws/cloudfront", "cloudflare/cloudflare");
  static_domainEvent(&events[7], "cname_takeover_detected", "2026-10-16T01:02:09Z", NULL, "none", "vulnerable a\"b\\c");
  WATCHLISTEVENTSAnswerItem_t items[2];
  static_answerItem(&items[0], "dns_lookup", "example.com",     0, 7);
  static_answerItem(&items[1], "dns_lookup", "www.example.com", 7, 1);
  int pairs[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 8;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 2;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 8;
  char* body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
        R"x({"event":"ns_changed","changed_at":"2026-10-16T01:02:03Z","previous":["ns1.example.net","ns2.example.net"],"current":["ns1.example.org"]},)x"
        R"x({"event":"mx_changed","changed_at":"2026-10-16T01:02:04Z","previous":[],"current":["0 ."]},)x"
        R"x({"event":"mx_changed","changed_at":"2026-10-16T01:02:05Z","previous":["10 mx1.example.com","20 mx2.example.com"],"current":[]},)x"
        R"x({"event":"domain_found","changed_at":"2026-10-16T01:02:06Z","previous":"not_found","current":"found"},)x"
        R"x({"event":"ip_address_lost","changed_at":"2026-10-16T01:02:07Z","previous":"public","current":"not_public"},)x"
        R"x({"event":"cname_takeover_resolved","changed_at":"2026-10-16T01:02:08Z","previous":null,"current":"none"},)x"
        R"x({"event":"hosting_changed","changed_at":"2026-10-16T01:02:10Z","previous":["akamai/akamai","aws/cloudfront"],"current":["cloudflare/cloudflare"]}]},)x"
      R"x({"item":{"endpoint":"dns_lookup","domain":"www.example.com"},"events":[)x"
        R"x({"event":"cname_takeover_detected","changed_at":"2026-10-16T01:02:09Z","previous":"none","current":"vulnerable a\"b\\c"}]})x"
    R"x(],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);

  static_domainEvent(&events[0], "ns_changed", "2026-10-16T01:02:03Z", NULL, NULL, "a\\b");
  static_answerItem(&items[0], "dns_lookup", "example.com", 0, 1);
  result.m_eventCount      = 1;
  result.m_answerItemCount = 1;
  result.m_pairCount       = 1;
  body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[{"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
      R"x({"event":"ns_changed","changed_at":"2026-10-16T01:02:03Z","previous":null,"current":["a\\b"]}]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);

  static_domainEvent(&events[0], "hosting_changed", "2026-10-16T01:02:03Z", NULL, "null", NULL);
  body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[{"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
      R"x({"event":"hosting_changed","changed_at":"2026-10-16T01:02:03Z","previous":["null"],"current":null}]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_ip_events_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;
  WATCHLISTEVENTSEvent_t events[4];
  static_ipEvent(&events[0], "drop_listed",     "2026-11-02T01:00:00Z", NULL, "192.0.2.0/24 SBL1\n192.0.0.0/16 SBL22",
                 "2026-11-01T00:00:00Z", "(c) 2026 The Spamhaus Project SLM");
  static_ipEvent(&events[1], "drop_unlisted",   "2026-11-03T01:00:00Z", "192.0.2.0/24 SBL1", "",
                 "2026-11-02T00:00:00Z", "(c) \"2026\" a\\b");
  static_ipEvent(&events[2], "hosting_changed", "2026-11-04T01:00:00Z", "AS64510", "aws/ec2", NULL, NULL);
  static_ipEvent(&events[3], "drop_listed",     "2026-11-05T01:00:00Z", "", "2001:db8::/32 SBL3",
                 "2026-11-04T00:00:00Z", "(c) 2026 drop");
  WATCHLISTEVENTSAnswerItem_t items[2];
  static_answerItem(&items[0], "ip_lookup", "192.0.2.7",   0, 3);
  static_answerItem(&items[1], "ip_lookup", "2001:db8::7", 3, 1);
  int pairs[] = { 0, 1, 2, 3 };
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 4;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 2;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 4;
  char* body = static_WATCHLISTEVENTSBody(&params, "71", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"71","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"ip_lookup","ip_address":"192.0.2.7"},"events":[)x"
        R"x({"event":"drop_listed","changed_at":"2026-11-02T01:00:00Z","previous":null,)x"
          R"x("current":[{"prefix":"192.0.2.0/24","listing_id":"SBL1"},{"prefix":"192.0.0.0/16","listing_id":"SBL22"}],)x"
          R"x("list_time":"2026-11-01T00:00:00Z","copyright":"(c) 2026 The Spamhaus Project SLM"},)x"
        R"x({"event":"drop_unlisted","changed_at":"2026-11-03T01:00:00Z","previous":[{"prefix":"192.0.2.0/24","listing_id":"SBL1"}],)x"
          R"x("current":[],"list_time":"2026-11-02T00:00:00Z","copyright":"(c) \"2026\" a\\b"},)x"
        R"x({"event":"hosting_changed","changed_at":"2026-11-04T01:00:00Z","previous":["AS64510"],"current":["aws/ec2"]}]},)x"
      R"x({"item":{"endpoint":"ip_lookup","ip_address":"2001:db8::7"},"events":[)x"
        R"x({"event":"drop_listed","changed_at":"2026-11-05T01:00:00Z","previous":[],)x"
          R"x("current":[{"prefix":"2001:db8::/32","listing_id":"SBL3"}],"list_time":"2026-11-04T00:00:00Z","copyright":"(c) 2026 drop"}]})x"
    R"x(],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);

  static_ipEvent(&events[0], "drop_listed", "2026-11-02T01:00:00Z", NULL, "a\"b", "2026-11-01T00:00:00Z", "c");
  static_answerItem(&items[0], "ip_lookup", "192.0.2.7", 0, 1);
  result.m_eventCount      = 1;
  result.m_answerItemCount = 1;
  result.m_pairCount       = 1;
  body = static_WATCHLISTEVENTSBody(&params, "71", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"71","has_more":false,"items":[{"item":{"endpoint":"ip_lookup","ip_address":"192.0.2.7"},"events":[)x"
      R"x({"event":"drop_listed","changed_at":"2026-11-02T01:00:00Z","previous":null,"current":[{"prefix":"a\"b","listing_id":""}],)x"
      R"x("list_time":"2026-11-01T00:00:00Z","copyright":"c"}]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_tls_events_and_a_dns_first_value_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;
  WATCHLISTEVENTSEvent_t events[11];
  static_domainEvent(&events[0],  "cert_expiring",    "2026-10-30T01:00:00Z", NULL, "none\n2026-11-20T00:00:00Z", "7\n2026-11-06T00:00:00Z");
  static_domainEvent(&events[1],  "cert_expiring",    "2026-10-30T01:00:01Z", NULL, "7\n2026-11-06T00:00:00Z",    "1\n2026-11-05T00:00:00Z");
  static_domainEvent(&events[2],  "cert_expiring",    "2026-10-30T01:00:02Z", NULL, NULL,                         "1\n2026-10-31T12:00:00Z");
  static_domainEvent(&events[3],  "cert_expiring",    "2026-10-30T01:00:03Z", NULL, "1\n2026-10-31T12:00:00Z",    "none");
  static_domainEvent(&events[4],  "cert_invalid",     "2026-10-30T01:00:04Z", NULL, "valid",                      "expired\nself_signed");
  static_domainEvent(&events[5],  "cert_invalid",     "2026-10-30T01:00:05Z", NULL, NULL,                         "hostname_mismatch");
  static_domainEvent(&events[6],  "cert_listed",      "2026-10-30T01:00:06Z", NULL, "not_listed",                 "listed\nDridex \"C&C\"");
  static_domainEvent(&events[7],  "cert_listed",      "2026-10-30T01:00:07Z", NULL, NULL,                         "listed");
  static_domainEvent(&events[8],  "tls_downgraded",   "2026-10-30T01:00:08Z", NULL, "TLSv1.3",                    "TLSv1");
  static_domainEvent(&events[9],  "tls_downgraded",   "2026-10-30T01:00:09Z", NULL, NULL,                         "TLSv1.1");
  static_domainEvent(&events[10], "domain_not_found", "2026-10-30T01:00:10Z", NULL, NULL,                         "not_found");
  WATCHLISTEVENTSAnswerItem_t items[2];
  static_answerItem(&items[0], "ssl_check", "example.org", 0, 10);
  static_answerItem(&items[1], "dns_lookup", "gone.example.com", 10, 1);
  int pairs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 11;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 2;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 11;
  char* body = static_WATCHLISTEVENTSBody(&params, "90", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":20,"cursor":null,"repeat":false,"next_cursor":"90","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"ssl_check","domain":"example.org"},"events":[)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:00Z","previous":null,"current":7,"valid_until":"2026-11-06T00:00:00Z"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:01Z","previous":7,"current":1,"valid_until":"2026-11-05T00:00:00Z"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:02Z","previous":null,"current":1,"valid_until":"2026-10-31T12:00:00Z"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:03Z","previous":1,"current":null,"valid_until":null},)x"
        R"x({"event":"cert_invalid","changed_at":"2026-10-30T01:00:04Z","previous":[],"current":["expired","self_signed"]},)x"
        R"x({"event":"cert_invalid","changed_at":"2026-10-30T01:00:05Z","previous":null,"current":["hostname_mismatch"]},)x"
        R"x({"event":"cert_listed","changed_at":"2026-10-30T01:00:06Z","previous":null,"current":"Dridex \"C&C\""},)x"
        R"x({"event":"cert_listed","changed_at":"2026-10-30T01:00:07Z","previous":null,"current":null},)x"
        R"x({"event":"tls_downgraded","changed_at":"2026-10-30T01:00:08Z","previous":"TLSv1.3","current":"TLSv1"},)x"
        R"x({"event":"tls_downgraded","changed_at":"2026-10-30T01:00:09Z","previous":null,"current":"TLSv1.1"}]},)x"
      R"x({"item":{"endpoint":"dns_lookup","domain":"gone.example.com"},"events":[)x"
        R"x({"event":"domain_not_found","changed_at":"2026-10-30T01:00:10Z","previous":null,"current":"not_found"}]})x"
    R"x(],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_expiry_bucket_reads_one_or_two_digits(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;
  WATCHLISTEVENTSEvent_t events[7];
  static_domainEvent(&events[0], "cert_expiring", "2026-10-30T01:00:00Z", NULL, "30\n2026-11-20", "9\n2026-11-08");
  static_domainEvent(&events[1], "cert_expiring", "2026-10-30T01:00:01Z", NULL, "99\nx",          "1\nx");
  static_domainEvent(&events[2], "cert_expiring", "2026-10-30T01:00:02Z", NULL, "7\nx",           "0\nx");
  static_domainEvent(&events[3], "cert_expiring", "2026-10-30T01:00:03Z", NULL, "07\nx",          "100\nx");
  static_domainEvent(&events[4], "cert_expiring", "2026-10-30T01:00:04Z", NULL, "3a\nx",          "30");
  static_domainEvent(&events[5], "cert_expiring", "2026-10-30T01:00:05Z", NULL, "\nx",            "/\nx");
  static_domainEvent(&events[6], "cert_expiring", "2026-10-30T01:00:06Z", NULL, "1:\nx",          "1/\nx");
  WATCHLISTEVENTSAnswerItem_t items[1];
  static_answerItem(&items[0], "ssl_check", "example.org", 0, 7);
  int pairs[] = { 0, 1, 2, 3, 4, 5, 6 };
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 7;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 1;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 7;
  char* body = static_WATCHLISTEVENTSBody(&params, "90", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":20,"cursor":null,"repeat":false,"next_cursor":"90","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"ssl_check","domain":"example.org"},"events":[)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:00Z","previous":30,"current":9,"valid_until":"2026-11-08"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:01Z","previous":99,"current":1,"valid_until":"x"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:02Z","previous":7,"current":null,"valid_until":"x"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:03Z","previous":null,"current":null,"valid_until":"x"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:04Z","previous":null,"current":null,"valid_until":null},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:05Z","previous":null,"current":null,"valid_until":"x"},)x"
        R"x({"event":"cert_expiring","changed_at":"2026-10-30T01:00:06Z","previous":null,"current":null,"valid_until":"x"}]})x"
    R"x(],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

static char* static_whoisEventsBody(WATCHLISTEVENTSEvent_t* events, int event_count)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 20;
  WATCHLISTEVENTSAnswerItem_t items[1];
  static_answerItem(&items[0], "whois_lookup", "example.com", 0, event_count);
  int pairs[8];
  TEST_ASSERT_TRUE(event_count <= 8);
  for (int i = 0; i < event_count; i++)
    pairs[i] = i;
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = event_count;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 1;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = event_count;
  return static_WATCHLISTEVENTSBody(&params, "90", false, &result);
}

#define WHOIS_EVENTS_HEAD R"x({"limit":20,"cursor":null,"repeat":false,"next_cursor":"90","has_more":false,"items":[{"item":{"endpoint":"whois_lookup","domain":"example.com"},"events":[)x"
#define WHOIS_EVENTS_TAIL R"x(]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n"

void test_WATCHLISTEVENTS_domain_expiring_golden(void)
{
  WATCHLISTEVENTSEvent_t events[4];
  static_domainEvent(&events[0], "domain_expiring", "2026-10-31T01:00:00Z", NULL, NULL,                       "30\n2026-11-20T04:00:00Z");
  static_domainEvent(&events[1], "domain_expiring", "2026-10-31T01:00:01Z", NULL, "30\n2026-11-07",           "7\n2026-11-07");
  static_domainEvent(&events[2], "domain_expiring", "2026-10-31T01:00:02Z", NULL, "7\n2026-11-01",            "1\n2026-11-01");
  static_domainEvent(&events[3], "domain_expiring", "2026-10-31T01:00:03Z", NULL, "1\n2026-11-01",            "none\n2027-11-01");
  char* body = static_whoisEventsBody(events, 4);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"domain_expiring","changed_at":"2026-10-31T01:00:00Z","previous":null,"current":30,"expires_at":"2026-11-20T04:00:00Z"},)x"
      R"x({"event":"domain_expiring","changed_at":"2026-10-31T01:00:01Z","previous":30,"current":7,"expires_at":"2026-11-07"},)x"
      R"x({"event":"domain_expiring","changed_at":"2026-10-31T01:00:02Z","previous":7,"current":1,"expires_at":"2026-11-01"},)x"
      R"x({"event":"domain_expiring","changed_at":"2026-10-31T01:00:03Z","previous":1,"current":null,"expires_at":"2027-11-01"})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

void test_WATCHLISTEVENTS_registrar_changed_golden(void)
{
  WATCHLISTEVENTSEvent_t events[7];
  static_domainEvent(&events[0], "registrar_changed", "2026-10-31T01:00:00Z", NULL, "292\nMarkMonitor Inc.", "146\nGoDaddy.com, LLC");
  static_domainEvent(&events[1], "registrar_changed", "2026-10-31T01:00:01Z", NULL, "-\nExample Registrar", "146\n");
  static_domainEvent(&events[2], "registrar_changed", "2026-10-31T01:00:02Z", NULL, NULL,                   "-\nA \"B\" \xc3\x9c");
  static_domainEvent(&events[3], "registrar_changed", "2026-10-31T01:00:03Z", NULL, "1234567890123456789\nx", "12345678901234567890\ny");
  static_domainEvent(&events[4], "registrar_changed", "2026-10-31T01:00:04Z", NULL, "0\nz",                "012\nw");
  static_domainEvent(&events[5], "registrar_changed", "2026-10-31T01:00:05Z", NULL, "292",                  "2a\nv");
  static_domainEvent(&events[6], "registrar_changed", "2026-10-31T01:00:06Z", NULL, "\nu",                  "1:\nt");
  char* body = static_whoisEventsBody(events, 7);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:00Z","previous":[292,"MarkMonitor Inc."],"current":[146,"GoDaddy.com, LLC"]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:01Z","previous":[null,"Example Registrar"],"current":[146,null]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:02Z","previous":null,"current":[null,"A \"B\" )x" "\xc3\x9c" R"x("]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:03Z","previous":[1234567890123456789,"x"],"current":[null,"y"]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:04Z","previous":[0,"z"],"current":[null,"w"]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:05Z","previous":[292,null],"current":[null,"v"]},)x"
      R"x({"event":"registrar_changed","changed_at":"2026-10-31T01:00:06Z","previous":[null,"u"],"current":[null,"t"]})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

void test_WATCHLISTEVENTS_transfer_lock_removed_golden(void)
{
  WATCHLISTEVENTSEvent_t events[3];
  static_domainEvent(&events[0], "transfer_lock_removed", "2026-10-31T01:00:00Z", NULL, "client transfer prohibited\nserver transfer prohibited", "server transfer prohibited");
  static_domainEvent(&events[1], "transfer_lock_removed", "2026-10-31T01:00:01Z", NULL, "client transfer prohibited", "");
  static_domainEvent(&events[2], "transfer_lock_removed", "2026-10-31T01:00:02Z", NULL, NULL, "");
  char* body = static_whoisEventsBody(events, 3);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"transfer_lock_removed","changed_at":"2026-10-31T01:00:00Z","previous":["client transfer prohibited","server transfer prohibited"],"current":["server transfer prohibited"]},)x"
      R"x({"event":"transfer_lock_removed","changed_at":"2026-10-31T01:00:01Z","previous":["client transfer prohibited"],"current":[]},)x"
      R"x({"event":"transfer_lock_removed","changed_at":"2026-10-31T01:00:02Z","previous":null,"current":[]})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

void test_WATCHLISTEVENTS_cert_unexpected_golden(void)
{
  WATCHLISTEVENTSEvent_t events[3];
  static_domainEvent(&events[0], "cert_unexpected", "2026-11-01T02:00:00Z", NULL, "letsencrypt.org\npki.goog",
                     "caa_mismatch digicert.com\nknown letsencrypt.org\nknown pki.goog");
  static_domainEvent(&events[1], "cert_unexpected", "2026-11-01T02:00:01Z", NULL, "", "new_issuer Some X CA\ncaa_mismatch letsencrypt.org");
  static_domainEvent(&events[2], "cert_unexpected", "2026-11-01T02:00:02Z", NULL, NULL, NULL);
  char* body = static_whoisEventsBody(events, 3);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"cert_unexpected","changed_at":"2026-11-01T02:00:00Z","previous":["letsencrypt.org","pki.goog"],"current":["digicert.com","letsencrypt.org","pki.goog"],"new_issuers":[{"issuer":"digicert.com","reason":"caa_mismatch"}]},)x"
      R"x({"event":"cert_unexpected","changed_at":"2026-11-01T02:00:01Z","previous":[],"current":["Some X CA","letsencrypt.org"],"new_issuers":[{"issuer":"Some X CA","reason":"new_issuer"},{"issuer":"letsencrypt.org","reason":"caa_mismatch"}]},)x"
      R"x({"event":"cert_unexpected","changed_at":"2026-11-01T02:00:02Z","previous":null,"current":null,"new_issuers":[]})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

void test_WATCHLISTEVENTS_security_header_removed_golden(void)
{
  WATCHLISTEVENTSEvent_t events[4];
  static_domainEvent(&events[0], "security_header_removed", "2026-11-01T01:00:00Z", NULL,
                     "https://example.com/\ncontent-security-policy\nstrict-transport-security\nx-frame-options",
                     "https://example.com/\ncontent-security-policy");
  static_domainEvent(&events[1], "security_header_removed", "2026-11-01T01:00:01Z", NULL,
                     "https://www.example.com/Xa\ncontent-security-policy\nreferrer-policy",
                     "https://www.example.com/Xa\nreferrer-policy\npermissions-policy");
  static_domainEvent(&events[2], "security_header_removed", "2026-11-01T01:00:02Z", NULL,
                     "https://example.com/\nx-frame-options", "https://example.com/");
  static_domainEvent(&events[3], "security_header_removed", "2026-11-01T01:00:03Z", NULL, NULL, "https://example.com/\nreferrer-policy");
  char* body = static_whoisEventsBody(events, 4);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"security_header_removed","changed_at":"2026-11-01T01:00:00Z","previous":["content-security-policy","strict-transport-security","x-frame-options"],"current":["content-security-policy"],"url":"https://example.com/","removed":["strict-transport-security","x-frame-options"]},)x"
      R"x({"event":"security_header_removed","changed_at":"2026-11-01T01:00:01Z","previous":["content-security-policy","referrer-policy"],"current":["referrer-policy","permissions-policy"],"url":"https://www.example.com/Xa","removed":["content-security-policy"]},)x"
      R"x({"event":"security_header_removed","changed_at":"2026-11-01T01:00:02Z","previous":["x-frame-options"],"current":[],"url":"https://example.com/","removed":["x-frame-options"]},)x"
      R"x({"event":"security_header_removed","changed_at":"2026-11-01T01:00:03Z","previous":null,"current":["referrer-policy"],"url":"https://example.com/","removed":[]})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

void test_WATCHLISTEVENTS_dnssec_disabled_golden(void)
{
  WATCHLISTEVENTSEvent_t events[2];
  static_domainEvent(&events[0], "dnssec_disabled", "2026-10-31T01:00:00Z", NULL, "signed", "unsigned");
  static_domainEvent(&events[1], "dnssec_disabled", "2026-10-31T01:00:01Z", NULL, NULL,     "unsigned");
  char* body = static_whoisEventsBody(events, 2);
  TEST_ASSERT_EQUAL_STRING(
    WHOIS_EVENTS_HEAD
      R"x({"event":"dnssec_disabled","changed_at":"2026-10-31T01:00:00Z","previous":"signed","current":"unsigned"},)x"
      R"x({"event":"dnssec_disabled","changed_at":"2026-10-31T01:00:01Z","previous":null,"current":"unsigned"})x"
    WHOIS_EVENTS_TAIL, body);
  free(body);
}

#define EMAIL_VECTOR_ALL_PASS "ppppppppppppppppppppp"
#define EMAIL_VECTOR_DEGRADED "wpp-pppppfpppppppppp-"
#define EMAIL_VECTOR_LATER    "fppwppppppppppppppppw"

void test_WATCHLISTEVENTS_email_auth_degraded_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;
  TEST_ASSERT_EQUAL_size_t(EMAILCHECK_KIND_COUNT, strlen(EMAIL_VECTOR_ALL_PASS));
  TEST_ASSERT_EQUAL_size_t(EMAILCHECK_KIND_COUNT, strlen(EMAIL_VECTOR_DEGRADED));
  TEST_ASSERT_EQUAL_size_t(EMAILCHECK_KIND_COUNT, strlen(EMAIL_VECTOR_LATER));
  WATCHLISTEVENTSEvent_t events[8];
  static_domainEvent(&events[0], "email_auth_degraded", "2026-10-16T01:02:03Z", "dmarc_policy", EMAIL_VECTOR_ALL_PASS, EMAIL_VECTOR_DEGRADED);
  static_domainEvent(&events[1], "email_auth_degraded", "2026-10-16T01:02:04Z", "spf_all",      EMAIL_VECTOR_DEGRADED, EMAIL_VECTOR_LATER);
  static_domainEvent(&events[2], "email_auth_degraded", "2026-10-16T01:02:05Z", "mta_sts",      EMAIL_VECTOR_DEGRADED, EMAIL_VECTOR_LATER);
  static_domainEvent(&events[3], "email_auth_degraded", "2026-10-16T01:02:06Z", "spf_record",   EMAIL_VECTOR_DEGRADED, EMAIL_VECTOR_LATER);
  static_domainEvent(&events[4], "email_auth_degraded", "2026-10-16T01:02:07Z", "bimi_record",  EMAIL_VECTOR_ALL_PASS, EMAIL_VECTOR_LATER);
  static_domainEvent(&events[5], "email_auth_degraded", "2026-10-16T01:02:08Z", "spf_all",      "pppwpppppppppppppppp", EMAIL_VECTOR_LATER);
  static_domainEvent(&events[6], "email_auth_degraded", "2026-10-16T01:02:09Z", "spf_all",      EMAIL_VECTOR_ALL_PASS, "pppxppppppppppppppppp");
  static_domainEvent(&events[7], "email_auth_degraded", "2026-10-16T01:02:10Z", "spf_all",      "pppwpppppppppppppppppp", EMAIL_VECTOR_LATER);
  WATCHLISTEVENTSAnswerItem_t items[1];
  static_answerItem(&items[0], "dns_lookup", "example.com", 0, 8);
  int pairs[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 8;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 1;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 8;
  char* body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[{"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:03Z","check":"dmarc_policy","previous":"pass","current":"fail",)x"
        R"x("detail":"A policy tag of the DMARC record is not valid and its rua= tag holds no valid address, so receivers apply no DMARC."},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:04Z","check":"spf_all","previous":null,"current":"warn",)x"
        R"x("detail":"The SPF record's all is ?all, or it has neither all nor redirect, so it does not turn other senders away."},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:05Z","check":"mta_sts","previous":null,"current":"warn",)x"
        R"x("detail":"The domain publishes no MTA-STS record, or more than one, so senders may deliver its mail without TLS."},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:06Z","check":"spf_record","previous":"warn","current":"fail",)x"
        R"x("detail":"The domain has no SPF record, or more than one."},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:07Z","check":"bimi_record","previous":null,"current":null,"detail":null},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:08Z","check":"spf_all","previous":null,"current":"warn",)x"
        R"x("detail":"The SPF record's all is ?all, or it has neither all nor redirect, so it does not turn other senders away."},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:09Z","check":"spf_all","previous":"pass","current":null,"detail":null},)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:10Z","check":"spf_all","previous":null,"current":"warn",)x"
        R"x("detail":"The SPF record's all is ?all, or it has neither all nor redirect, so it does not turn other senders away."})x"
    R"x(]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);

  static_domainEvent(&events[0], "email_auth_degraded", "2026-10-16T01:02:03Z", "spf_record", NULL, EMAIL_VECTOR_DEGRADED);
  result.m_eventCount       = 1;
  result.m_pairCount        = 1;
  items[0].m_pairCount      = 1;
  body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[{"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
      R"x({"event":"email_auth_degraded","changed_at":"2026-10-16T01:02:03Z","check":"spf_record","previous":null,"current":"warn","detail":null}]}],"cves":{},"domains":{},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_domains_map_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;
  const WatchlistTestDomainValues_t full = { "found", "ns1.example.org\nns2.example.org", "10 mx.zeta.example\nnull", "public", "none",
                                             EMAIL_VECTOR_LATER };
  const WatchlistTestDomainValues_t only_takeover = { NULL, NULL, NULL, NULL, "vulnerable github", NULL };
  const WatchlistTestDomainValues_t all_pass = { "not_found", "a\\b", "", "not_public", "vulnerable \"x\"", EMAIL_VECTOR_ALL_PASS };
  const WatchlistTestDomainValues_t odd = { "maybe", "", NULL, "empty", NULL, "pppppppppppppppppppp" };
  const WatchlistTestDomainValues_t long_vector = { NULL, NULL, NULL, NULL, NULL, "fppppppppppppppppppppp" };
  WATCHLISTEVENTSDomainFacts_t domain_facts[5];
  static_domainFacts(&domain_facts[0], "zeta.example",    "zeta.example", &full);
  static_domainFacts(&domain_facts[1], "www.example.com", "example.com",  &only_takeover);
  static_domainFacts(&domain_facts[2], "alpha.example",   "alpha.example", &all_pass);
  static_domainFacts(&domain_facts[3], "beta.example",    "beta.example",  &odd);
  static_domainFacts(&domain_facts[4], "gamma.example",   "gamma.example", &long_vector);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_domainFacts    = domain_facts;
  result.m_domainFactCount = 5;
  char* body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[],"cves":{},"domains":{)x"
      R"x("zeta.example":{"registered_domain":"zeta.example","dns_presence":"found","ns":["ns1.example.org","ns2.example.org"],)x"
        R"x("mx":["10 mx.zeta.example","0 ."],"ip_address_reachability":"public","cname_takeover":"none",)x"
        R"x("email_auth_failing":{"spf_record":"fail","spf_all":"warn","mta_sts":"warn"}},)x"
      R"x("www.example.com":{"registered_domain":"example.com","dns_presence":null,"ns":null,"mx":null,"ip_address_reachability":null,)x"
        R"x("cname_takeover":"vulnerable github","email_auth_failing":null},)x"
      R"x("alpha.example":{"registered_domain":"alpha.example","dns_presence":"not_found","ns":["a\\b"],"mx":[],"ip_address_reachability":"not_public",)x"
        R"x("cname_takeover":"vulnerable \"x\"","email_auth_failing":{}},)x"
      R"x("beta.example":{"registered_domain":"beta.example","dns_presence":"maybe","ns":[],"mx":null,"ip_address_reachability":"empty",)x"
        R"x("cname_takeover":null,"email_auth_failing":null},)x"
      R"x("gamma.example":{"registered_domain":"gamma.example","dns_presence":null,"ns":null,"mx":null,"ip_address_reachability":null,)x"
        R"x("cname_takeover":null,"email_auth_failing":null})x"
    R"x(},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

void test_WATCHLISTEVENTS_only_the_whole_null_mx_line_becomes_0_dot(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;
  WATCHLISTEVENTSEvent_t events[2];
  static_domainEvent(&events[0], "mx_changed", "2026-10-16T01:02:03Z", NULL, "nul\nnulll\n10 null", "null");
  static_domainEvent(&events[1], "ns_changed", "2026-10-16T01:02:04Z", NULL, "null", "null");
  WATCHLISTEVENTSAnswerItem_t items[1];
  static_answerItem(&items[0], "dns_lookup", "example.com", 0, 2);
  int pairs[] = { 0, 1 };
  const WatchlistTestDomainValues_t values = { NULL, "null", "null\nnullx", NULL, NULL, NULL };
  WATCHLISTEVENTSDomainFacts_t domain_facts[1];
  static_domainFacts(&domain_facts[0], "example.com", "example.com", &values);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events           = events;
  result.m_eventCount        = 2;
  result.mp_answerItems      = items;
  result.m_answerItemCount   = 1;
  result.mp_pairEventIndexes = pairs;
  result.m_pairCount         = 2;
  result.mp_domainFacts      = domain_facts;
  result.m_domainFactCount   = 1;
  char* body = static_WATCHLISTEVENTSBody(&params, "70", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"70","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"dns_lookup","domain":"example.com"},"events":[)x"
        R"x({"event":"mx_changed","changed_at":"2026-10-16T01:02:03Z","previous":["nul","nulll","10 null"],"current":["0 ."]},)x"
        R"x({"event":"ns_changed","changed_at":"2026-10-16T01:02:04Z","previous":["null"],"current":["null"]}]}],)x"
    R"x("cves":{},"domains":{"example.com":{"registered_domain":"example.com","dns_presence":null,"ns":["null"],"mx":["0 .","nullx"],)x"
      R"x("ip_address_reachability":null,"cname_takeover":null,"email_auth_failing":null}},"advisories":{},"attribution":[]})x" "\n", body);
  free(body);
}

static void static_packageEvent(WATCHLISTEVENTSEvent_t* event, const char* event_type, const char* changed_at, const char* advisory_id,
                                const char* fixed_version)
{
  memset(event, 0, sizeof(*event));
  snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", event_type);
  snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", changed_at);
  event->m_eventKind = WATCHLIST_EVENT_PACKAGE_CHECK;
  snprintf(event->m_packageCheckChange.ma_advisoryId, sizeof(event->m_packageCheckChange.ma_advisoryId), "%s", advisory_id);
  snprintf(event->m_packageCheckChange.ma_fixedVersion, sizeof(event->m_packageCheckChange.ma_fixedVersion), "%s",
           fixed_version != NULL ? fixed_version : "");
}

static void static_packageItem(WATCHLISTEVENTSAnswerItem_t* answer_item, const char* ecosystem, const char* name, const char* version,
                               int first_pair_index, int pair_count)
{
  static_answerItem(answer_item, "package_check", NULL, first_pair_index, pair_count);
  WATCHLISTPACKAGECHECKItem_t* package = &answer_item->m_item.m_packageCheck;
  snprintf(package->ma_ecosystem, sizeof(package->ma_ecosystem), "%s", ecosystem);
  snprintf(package->ma_name, sizeof(package->ma_name), "%s", name);
  snprintf(package->ma_version, sizeof(package->ma_version), "%s", version != NULL ? version : "");
}

void test_WATCHLISTEVENTS_package_events_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  WATCHLISTEVENTSEvent_t events[3];
  static_packageEvent(&events[0], "fix_available", "2026-10-20T01:02:03Z", "GHSA-p6mc-m468-83gw", "4.17.21");
  static_watchlistEvent(&events[1], "kev_added", "2026-10-20T01:02:04Z", "CVE-2021-23337", false, 0.0, false, 0.0);
  static_packageEvent(&events[2], "malware_added", "2026-10-20T01:02:05Z", "MAL-2026-0001", NULL);
  WATCHLISTEVENTSAnswerItem_t items[2];
  static_packageItem(&items[0], "npm", "lodash", "4.17.20", 0, 2);
  static_packageItem(&items[1], "npm", "Lodash", NULL, 2, 2);
  int  pairs[4]                    = { 1, 0, 0, 2 };
  bool pair_is_version_affected[4] = { false, true, false, false };
  WATCHLISTEVENTSCveFacts_t cve_facts[3];
  static_cveFacts(&cve_facts[0], "CVE-2021-23337", 72.5, "HIGH", true, "2022-01-10", false, false, 4);
  static_cveFacts(&cve_facts[1], "CVE-2020-8203", 74.0, "HIGH", false, NULL, false, true, 9);
  static_cveFacts(&cve_facts[2], "CVE-2020-28500", 5.3, "MEDIUM", false, NULL, false, false, 0);
  WATCHLISTPACKAGECHECKAdvisory_t advisories[2];
  memset(advisories, 0, sizeof(advisories));
  snprintf(advisories[0].ma_advisoryId, sizeof(advisories[0].ma_advisoryId), "%s", "GHSA-p6mc-m468-83gw");
  snprintf(advisories[0].ma_source, sizeof(advisories[0].ma_source), "%s", "ghsa");
  char aliases[] = R"(["CVE-2020-8203", "CVE-2020-28500", "SNYK-JS-LODASH-590103"])";
  advisories[0].mp_aliases = aliases;
  snprintf(advisories[1].ma_advisoryId, sizeof(advisories[1].ma_advisoryId), "%s", "MAL-2026-0001");
  char attribution[] = R"([{"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}])";

  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events                = events;
  result.m_eventCount             = 3;
  result.mp_answerItems           = items;
  result.m_answerItemCount        = 2;
  result.mp_pairEventIndexes      = pairs;
  result.mp_pairIsVersionAffected = pair_is_version_affected;
  result.m_pairCount              = 4;
  result.mp_cveFacts              = cve_facts;
  result.m_cveFactCount           = 3;
  result.mp_advisories            = advisories;
  result.m_advisoryCount          = 2;
  result.mp_attribution           = attribution;
  char* body = static_WATCHLISTEVENTSBody(&params, "77", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"77","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"package_check","ecosystem":"npm","name":"lodash","version":"4.17.20"},"events":[)x"
        R"x({"event":"kev_added","changed_at":"2026-10-20T01:02:04Z","cve_id":"CVE-2021-23337","previous":null,"current":null,)x"
          R"x("vendor":null,"product":null},)x"
        R"x({"event":"fix_available","changed_at":"2026-10-20T01:02:03Z","cve_id":null,"advisory_id":"GHSA-p6mc-m468-83gw",)x"
          R"x("fixed_version":"4.17.21","affects_version":true}]},)x"
      R"x({"item":{"endpoint":"package_check","ecosystem":"npm","name":"Lodash","version":null},"events":[)x"
        R"x({"event":"fix_available","changed_at":"2026-10-20T01:02:03Z","cve_id":null,"advisory_id":"GHSA-p6mc-m468-83gw",)x"
          R"x("fixed_version":"4.17.21","affects_version":null},)x"
        R"x({"event":"malware_added","changed_at":"2026-10-20T01:02:05Z","cve_id":null,"advisory_id":"MAL-2026-0001",)x"
          R"x("fixed_version":null,"affects_version":null}]}],)x"
    R"x("cves":{"CVE-2021-23337":{"risk_score":72.5,"label":"HIGH","in_kev":true,"kev_patch_deadline":"2022-01-10","known_ransomware":false,)x"
      R"x("has_metasploit":false,"poc_count":4},)x"
      R"x("CVE-2020-8203":{"risk_score":74.0,"label":"HIGH","in_kev":false,"kev_patch_deadline":null,"known_ransomware":false,)x"
      R"x("has_metasploit":true,"poc_count":9},)x"
      R"x("CVE-2020-28500":{"risk_score":5.3,"label":"MEDIUM","in_kev":false,"kev_patch_deadline":null,"known_ransomware":false,)x"
      R"x("has_metasploit":false,"poc_count":0}},)x"
    R"x("domains":{},)x"
    R"x("advisories":{"GHSA-p6mc-m468-83gw":{"source":"ghsa","aliases":["CVE-2020-8203", "CVE-2020-28500", "SNYK-JS-LODASH-590103"]},)x"
      R"x("MAL-2026-0001":{"source":null,"aliases":[]}},)x"
    R"x("attribution":[{"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}]})x" "\n", body);
  free(body);
}

static void static_eolEvent(WATCHLISTEVENTSEvent_t* event, const char* event_type, const char* changed_at, const char* eol_product,
                            const char* cycle, const char* eol_date, const char* previous_eol_date)
{
  memset(event, 0, sizeof(*event));
  snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", event_type);
  snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", changed_at);
  event->m_eventKind = WATCHLIST_EVENT_PRODUCT_EXPOSURE;
  WATCHLISTPRODUCTEXPOSUREChange_t* change = &event->m_productExposureChange;
  snprintf(change->ma_eolProduct, sizeof(change->ma_eolProduct), "%s", eol_product);
  snprintf(change->ma_cycle, sizeof(change->ma_cycle), "%s", cycle);
  snprintf(change->ma_eolDate, sizeof(change->ma_eolDate), "%s", eol_date != NULL ? eol_date : "");
  snprintf(change->ma_previousEolDate, sizeof(change->ma_previousEolDate), "%s", previous_eol_date != NULL ? previous_eol_date : "");
}

void test_WATCHLISTEVENTS_eol_events_golden(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 10;

  WATCHLISTEVENTSEvent_t events[3];
  static_eolEvent(&events[0], "eol_approaching", "2026-11-01T01:02:03Z", "nginx", "1.24", "2026-11-30", NULL);
  static_eolEvent(&events[1], "eol_date_changed", "2026-11-02T01:02:03Z", "nginx", "1.24", "2027-05-31", "2026-11-30");
  static_eolEvent(&events[2], "eol_reached", "2026-11-03T01:02:03Z", "nginx\"plus", "r\"30", NULL, NULL);
  WATCHLISTEVENTSAnswerItem_t items[1];
  memset(items, 0, sizeof(items));
  static_productExposureItem(&items[0].m_item, "f5", "nginx", "1.24.0", true);
  items[0].m_firstPairIndex = 0;
  items[0].m_pairCount      = 3;
  int  pairs[3]                    = { 0, 1, 2 };
  bool pair_is_version_affected[3] = { false, false, false };
  char attribution[] = R"([{"url": "https://endoflife.date", "source": "endoflife.date", "license": "MIT"}, )"
                       R"({"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}])";

  WATCHLISTEVENTSResult_t result;
  memset(&result, 0, sizeof(result));
  result.mp_events                = events;
  result.m_eventCount             = 3;
  result.mp_answerItems           = items;
  result.m_answerItemCount        = 1;
  result.mp_pairEventIndexes      = pairs;
  result.mp_pairIsVersionAffected = pair_is_version_affected;
  result.m_pairCount              = 3;
  result.mp_attribution           = attribution;
  char* body = static_WATCHLISTEVENTSBody(&params, "77", false, &result);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"limit":10,"cursor":null,"repeat":false,"next_cursor":"77","has_more":false,"items":[)x"
      R"x({"item":{"endpoint":"product_exposure","vendor":"f5","product":"nginx","version":"1.24.0","product_has_cves":true},"events":[)x"
        R"x({"event":"eol_approaching","changed_at":"2026-11-01T01:02:03Z","cve_id":null,)x"
          R"x("eol":{"product":"nginx","cycle":"1.24","eol_date":"2026-11-30","previous_eol_date":null}},)x"
        R"x({"event":"eol_date_changed","changed_at":"2026-11-02T01:02:03Z","cve_id":null,)x"
          R"x("eol":{"product":"nginx","cycle":"1.24","eol_date":"2027-05-31","previous_eol_date":"2026-11-30"}},)x"
        R"x({"event":"eol_reached","changed_at":"2026-11-03T01:02:03Z","cve_id":null,)x"
          R"x("eol":{"product":"nginx\"plus","cycle":"r\"30","eol_date":null,"previous_eol_date":null}}]}],)x"
    R"x("cves":{},"domains":{},"advisories":{},)x"
    R"x("attribution":[{"url": "https://endoflife.date", "source": "endoflife.date", "license": "MIT"}, )x"
      R"x({"url": "https://github.com/github/advisory-database", "source": "ghsa", "license": "CC-BY-4.0"}]})x" "\n", body);
  free(body);
}

typedef struct {
  WATCHLISTEVENTSEvent_t*          mp_events;
  WATCHLISTEVENTSAnswerItem_t*     mp_items;
  int*                             mp_pairs;
  bool*                            mp_pairIsVersionAffected;
  WATCHLISTEVENTSCveFacts_t*       mp_cveFacts;
  WATCHLISTEVENTSDomainFacts_t*    mp_domainFacts;
  WATCHLISTPACKAGECHECKAdvisory_t* mp_advisories;
} WatchlistTestPage_t;

#define WATCHLIST_TEST_CVE_FACT_MAX_COUNT (CVE_LIST_MAX_LIMIT * (1 + WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT))

typedef struct {
  int m_cveEventCount;
  int m_cveItemCount;
  int m_cvePairCount;
  int m_domainItemCount;
  int m_domainEventCount;
  int m_packageEventCount;
  int m_packageItemCount;
  int m_packagePairCount;
} WatchlistTestShape_t;

static const char* static_WATCHLISTEVENTSTestAttribution(void)
{
  static char attribution[4096];
  if (attribution[0] != '\0')
    return attribution;
  static const char* const pairs[][2] = {
    { "go", "CC-BY-4.0" }, { "mal", "Apache-2.0" }, { "ghsa", "CC-BY-4.0" }, { "pysec", "CC-BY-4.0" },
    { "rustsec", "CC0-1.0" }, { "rustsec", "CC-BY-4.0" },
  };
  size_t length = (size_t)snprintf(attribution, sizeof(attribution), "%s",
                                   R"([{"url": "https://endoflife.date", "notice": "Retrieved from endoflife.date. ContrastAPI selected the)"
                                   R"( fields and matched the release cycles to the watched product. No warranty; the source does not)"
                                   R"( endorse ContrastAPI.", "source": "endoflife.date", "license": "MIT"})");
  for (size_t p = 0; p < sizeof(pairs) / sizeof(pairs[0]); p++)
  {
    int written = snprintf(attribution + length, sizeof(attribution) - length,
                           R"(, {"url": "https://github.com/ossf/malicious-packages", "notice": "Retrieved through OSV.dev. ContrastAPI)"
                           R"( selected and normalized the fields and computed affects_version and fixed_version. No warranty; the)"
                           R"( source does not endorse ContrastAPI.", "source": "%s", "license": "%s"})",
                           pairs[p][0], pairs[p][1]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(attribution) - length);
    length += (size_t)written;
  }
  TEST_ASSERT_TRUE(length + 2 <= sizeof(attribution));
  attribution[length++] = ']';
  attribution[length]   = '\0';
  return attribution;
}

static const char* static_WATCHLISTEVENTSTestAliases(void)
{
  static char aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN + 1];
  if (aliases[0] != '\0')
    return aliases;
  size_t length = 0;
  aliases[length++] = '[';
  for (int a = 0; a < WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT; a++)
  {
    if (a > 0)
    {
      aliases[length++] = ',';
      aliases[length++] = ' ';
    }
    aliases[length++] = '"';
    memset(aliases + length, 'a', WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_LEN);
    length += WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_LEN;
    aliases[length++] = '"';
  }
  aliases[length++] = ']';
  aliases[length]   = '\0';
  return aliases;
}

static void static_WATCHLISTEVENTSShapePage(WatchlistTestPage_t* page, const WatchlistTestShape_t* shape, WATCHLISTEVENTSResult_t* result)
{
  static char lines[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  for (int i = 0; i < WATCHLIST_DOMAIN_VALUE_MAX_LEN; i++)
    lines[i] = (i % 2 == 0) ? 'a' : '\n';
  lines[WATCHLIST_DOMAIN_VALUE_MAX_LEN - 1] = 'a';
  lines[WATCHLIST_DOMAIN_VALUE_MAX_LEN]     = '\0';
  static char long_value[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  memset(long_value, 'z', WATCHLIST_DOMAIN_VALUE_MAX_LEN);
  long_value[WATCHLIST_DOMAIN_VALUE_MAX_LEN] = '\0';
  const WatchlistTestDomainValues_t values = { long_value, lines, lines, long_value, long_value, EMAIL_VECTOR_LATER };

  for (int e = 0; e < shape->m_cveEventCount; e++)
  {
    char cve_id[CVELOOKUP_ID_MAX_LEN + 1];
    snprintf(cve_id, sizeof(cve_id), "CVE-2026-%07d", e);
    static_watchlistEvent(&page->mp_events[e], "vendor_advisory_published", "2026-10-16T01:02:03Z", cve_id, true, 0.12345, true, 0.98765);
    page->mp_events[e].m_cveChange.m_hasProductPair = true;
    memset(page->mp_events[e].m_cveChange.ma_vendor, 'v', CVESEARCH_VENDOR_LEN);
    memset(page->mp_events[e].m_cveChange.ma_product, 'p', CVESEARCH_PRODUCT_LEN);
    static_cveFacts(&page->mp_cveFacts[e], cve_id, 96.5, "CRITICAL", true, "2021-12-24", true, true, 999);
  }
  int pair_index = 0;
  for (int i = 0; i < shape->m_cveItemCount; i++)
  {
    int item_pair_count = shape->m_cvePairCount / shape->m_cveItemCount + (i < shape->m_cvePairCount % shape->m_cveItemCount ? 1 : 0);
    static_answerItem(&page->mp_items[i], "cve_search", NULL, pair_index, item_pair_count);
    WATCHLISTCVESEARCHItem_t* filter = &page->mp_items[i].m_item.m_cveSearch;
    memset(filter->ma_vendor, 'v', CVESEARCH_VENDOR_LEN);
    memset(filter->ma_product, 'p', CVESEARCH_PRODUCT_LEN);
    memset(filter->ma_severity, 's', CVELOOKUP_SEVERITY_LEN);
    memset(filter->ma_cweId, 'c', CVELOOKUP_CWE_ID_LEN);
    filter->m_minCvss           = 10.0;
    filter->m_minEpss           = 0.99999;
    filter->m_kevFilter         = CVE_KEV_FILTER_NOT_IN_KEV;
    filter->m_knownRansomware   = true;
    filter->m_hasNucleiTemplate = true;
    for (int p = 0; p < item_pair_count; p++, pair_index++)
    {
      page->mp_pairs[pair_index]                 = pair_index % shape->m_cveEventCount;
      page->mp_pairIsVersionAffected[pair_index] = false;
    }
  }

  int event_index = shape->m_cveEventCount;
  for (int d = 0; d < shape->m_domainItemCount; d++)
  {
    char number[16];
    snprintf(number, sizeof(number), "%07d", d);
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    memset(name, 'd', VALIDATE_DOMAIN_NAME_MAX_LEN);
    name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
    memcpy(name, number, 7);
    int item_pair_count = shape->m_domainEventCount / shape->m_domainItemCount + (d < shape->m_domainEventCount % shape->m_domainItemCount ? 1 : 0);
    static_answerItem(&page->mp_items[shape->m_cveItemCount + d], "dns_lookup", name, pair_index, item_pair_count);
    static_domainFacts(&page->mp_domainFacts[d], name, name, &values);
    for (int p = 0; p < item_pair_count; p++, pair_index++, event_index++)
    {
      static_domainEvent(&page->mp_events[event_index], "ns_changed", "2026-10-16T01:02:03Z", NULL, lines, lines);
      page->mp_pairs[pair_index]                 = event_index;
      page->mp_pairIsVersionAffected[pair_index] = false;
    }
  }

  const int first_package_event_index = event_index;
  int cve_fact_count = shape->m_cveEventCount;
  for (int e = 0; e < shape->m_packageEventCount; e++, event_index++)
  {
    WATCHLISTEVENTSEvent_t* event = &page->mp_events[event_index];
    memset(event, 0, sizeof(*event));
    snprintf(event->ma_eventType, sizeof(event->ma_eventType), "%s", "fix_available");
    snprintf(event->ma_changedAt, sizeof(event->ma_changedAt), "%s", "2026-10-16T01:02:03Z");
    event->m_eventKind = WATCHLIST_EVENT_PACKAGE_CHECK;
    char advisory_id[WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN + 1];
    memset(advisory_id, 'r', WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN);
    advisory_id[WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN] = '\0';
    char number[24];
    snprintf(number, sizeof(number), "RUSTSEC-%07d", e);
    memcpy(advisory_id, number, strlen(number));
    snprintf(event->m_packageCheckChange.ma_advisoryId, sizeof(event->m_packageCheckChange.ma_advisoryId), "%s", advisory_id);
    memset(event->m_packageCheckChange.ma_fixedVersion, 'f', PACKAGECHECK_VERSION_MAX_LEN);

    WATCHLISTPACKAGECHECKAdvisory_t* advisory = &page->mp_advisories[e];
    memset(advisory, 0, sizeof(*advisory));
    snprintf(advisory->ma_advisoryId, sizeof(advisory->ma_advisoryId), "%s", advisory_id);
    snprintf(advisory->ma_source, sizeof(advisory->ma_source), "%s", "rustsec");
    advisory->mp_aliases = const_cast<char*>(static_WATCHLISTEVENTSTestAliases());
    for (int a = 0; a < WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT; a++, cve_fact_count++)
    {
      char cve_id[CVELOOKUP_ID_MAX_LEN + 1];
      snprintf(cve_id, sizeof(cve_id), "CVE-2025-%07d", e * WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT + a);
      static_cveFacts(&page->mp_cveFacts[cve_fact_count], cve_id, 96.5, "CRITICAL", true, "2021-12-24", true, true, 999);
    }
  }
  const int package_item_offset = shape->m_cveItemCount + shape->m_domainItemCount;
  const int first_package_pair_index = pair_index;
  for (int i = 0; i < shape->m_packageItemCount; i++)
  {
    int item_pair_count = shape->m_packagePairCount / shape->m_packageItemCount + (i < shape->m_packagePairCount % shape->m_packageItemCount ? 1 : 0);
    static_answerItem(&page->mp_items[package_item_offset + i], "package_check", NULL, pair_index, item_pair_count);
    WATCHLISTPACKAGECHECKItem_t* package = &page->mp_items[package_item_offset + i].m_item.m_packageCheck;
    memset(package->ma_ecosystem, 'e', PACKAGECHECK_ECOSYSTEM_MAX_LEN);
    memset(package->ma_name, 'n', PACKAGECHECK_NAME_MAX_LEN);
    memset(package->ma_version, 'v', PACKAGECHECK_VERSION_MAX_LEN);
    char number[16];
    snprintf(number, sizeof(number), "%07d", i);
    memcpy(package->ma_version, number, 7);
    for (int p = 0; p < item_pair_count; p++, pair_index++)
    {
      page->mp_pairs[pair_index]                 = first_package_event_index + (pair_index - first_package_pair_index) % shape->m_packageEventCount;
      page->mp_pairIsVersionAffected[pair_index] = true;
    }
  }

  memset(result, 0, sizeof(*result));
  result->mp_events                = page->mp_events;
  result->m_eventCount             = event_index;
  result->mp_answerItems           = page->mp_items;
  result->m_answerItemCount        = package_item_offset + shape->m_packageItemCount;
  result->mp_pairEventIndexes      = page->mp_pairs;
  result->mp_pairIsVersionAffected = page->mp_pairIsVersionAffected;
  result->m_pairCount              = pair_index;
  result->mp_cveFacts              = page->mp_cveFacts;
  result->m_cveFactCount           = cve_fact_count;
  result->mp_domainFacts           = page->mp_domainFacts;
  result->m_domainFactCount        = shape->m_domainItemCount;
  result->mp_advisories            = page->mp_advisories;
  result->m_advisoryCount          = shape->m_packageEventCount;
  result->mp_attribution           = shape->m_packageEventCount > 0 ? const_cast<char*>(static_WATCHLISTEVENTSTestAttribution()) : NULL;
}

static size_t static_WATCHLISTEVENTSShapeSize(WatchlistTestPage_t* page, const WatchlistTestShape_t* shape, size_t ceiling)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = CVE_LIST_MAX_LIMIT;
  memset(params.ma_cursor, '9', WATCHLIST_CURSOR_MAX_LEN);
  WATCHLISTEVENTSResult_t result;
  static_WATCHLISTEVENTSShapePage(page, shape, &result);
  char* body = static_WATCHLISTEVENTSBodyWithCeiling(&params, "999999999999999999", true, &result, ceiling);
  size_t size = (body != NULL) ? strlen(body) : 0;
  free(body);
  return size;
}

typedef struct {
  long long m_noneSize;
  long long m_cveOneSize;
  long long m_cveEventLength;
  long long m_cveItemLength;
  long long m_cvePairLength;
  long long m_domainOneSize;
  long long m_domainPairLength;
  long long m_domainItemLength;
  long long m_packageOneSize;
  long long m_packageEventLength;
  long long m_packageItemLength;
  long long m_packagePairLength;
} WatchlistTestPartLengths_t;

static long long static_WATCHLISTEVENTSShapeSum(const WatchlistTestPartLengths_t* lengths, const WatchlistTestShape_t* shape)
{
  long long size = lengths->m_noneSize;
  int kind_count = 0;
  if (shape->m_cveEventCount > 0)
  {
    size += lengths->m_cveOneSize - lengths->m_noneSize + (shape->m_cveEventCount - 1) * lengths->m_cveEventLength
            + (shape->m_cveItemCount - 1) * lengths->m_cveItemLength + (shape->m_cvePairCount - 1) * lengths->m_cvePairLength;
    kind_count++;
  }
  if (shape->m_domainItemCount > 0)
  {
    size += lengths->m_domainOneSize - lengths->m_noneSize + (shape->m_domainEventCount - 1) * lengths->m_domainPairLength
            + (shape->m_domainItemCount - 1) * lengths->m_domainItemLength;
    kind_count++;
  }
  if (shape->m_packageEventCount > 0)
  {
    size += lengths->m_packageOneSize - lengths->m_noneSize + (shape->m_packageEventCount - 1) * lengths->m_packageEventLength
            + (shape->m_packageItemCount - 1) * lengths->m_packageItemLength
            + (shape->m_packagePairCount - 1) * lengths->m_packagePairLength;
    kind_count++;
  }
  if (kind_count > 1)
    size += kind_count - 1;
  if (shape->m_cveEventCount > 0 && shape->m_packageEventCount > 0)
    size += 1;
  return size;
}

static long long static_WATCHLISTEVENTSEolPairLength(void)
{
  WATCHLISTEVENTSParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = CVE_LIST_MAX_LIMIT;
  WATCHLISTEVENTSEvent_t event;
  static_eolEvent(&event, "eol_date_changed", "2026-11-02T01:02:03Z", "", "", "2027-05-31", "2026-11-30");
  memset(event.m_productExposureChange.ma_eolProduct, 'p', PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  memset(event.m_productExposureChange.ma_cycle, 'c', PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN);
  WATCHLISTEVENTSAnswerItem_t item;
  memset(&item, 0, sizeof(item));
  static_productExposureItem(&item.m_item, "f5", "nginx", "", false);
  int  pairs[2]                    = { 0, 0 };
  bool pair_is_version_affected[2] = { false, false };
  long long sizes[2] = { 0, 0 };
  for (int pair_count = 1; pair_count <= 2; pair_count++)
  {
    item.m_pairCount = pair_count;
    WATCHLISTEVENTSResult_t result;
    memset(&result, 0, sizeof(result));
    result.mp_events                = &event;
    result.m_eventCount             = 1;
    result.mp_answerItems           = &item;
    result.m_answerItemCount        = 1;
    result.mp_pairEventIndexes      = pairs;
    result.mp_pairIsVersionAffected = pair_is_version_affected;
    result.m_pairCount              = pair_count;
    char* body = static_WATCHLISTEVENTSBodyWithCeiling(&params, "58", false, &result, JSONBUF_MAX_CEILING);
    TEST_ASSERT_NOT_NULL(body);
    sizes[pair_count - 1] = (long long)strlen(body);
    free(body);
  }
  return sizes[1] - sizes[0];
}

void test_WATCHLISTEVENTS_worst_case_size(void)
{
  WatchlistTestPage_t page;
  const int item_max_count = WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY + WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY;
  page.mp_events                = static_cast<WATCHLISTEVENTSEvent_t*>(calloc(CVE_LIST_MAX_LIMIT, sizeof(WATCHLISTEVENTSEvent_t)));
  page.mp_items                 = static_cast<WATCHLISTEVENTSAnswerItem_t*>(calloc(item_max_count, sizeof(WATCHLISTEVENTSAnswerItem_t)));
  page.mp_pairs                 = static_cast<int*>(calloc(WATCHLIST_ANSWER_PAIR_MAX_COUNT, sizeof(int)));
  page.mp_pairIsVersionAffected = static_cast<bool*>(calloc(WATCHLIST_ANSWER_PAIR_MAX_COUNT, sizeof(bool)));
  page.mp_cveFacts              = static_cast<WATCHLISTEVENTSCveFacts_t*>(calloc(WATCHLIST_TEST_CVE_FACT_MAX_COUNT, sizeof(WATCHLISTEVENTSCveFacts_t)));
  page.mp_domainFacts           = static_cast<WATCHLISTEVENTSDomainFacts_t*>(calloc(WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY, sizeof(WATCHLISTEVENTSDomainFacts_t)));
  page.mp_advisories            = static_cast<WATCHLISTPACKAGECHECKAdvisory_t*>(calloc(CVE_LIST_MAX_LIMIT, sizeof(WATCHLISTPACKAGECHECKAdvisory_t)));
  TEST_ASSERT_TRUE(page.mp_events != NULL && page.mp_items != NULL && page.mp_pairs != NULL && page.mp_pairIsVersionAffected != NULL
                   && page.mp_cveFacts != NULL && page.mp_domainFacts != NULL && page.mp_advisories != NULL);

  const WatchlistTestShape_t no_part      = { 0, 0, 0, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t cve_one      = { 1, 1, 1, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t cve_event    = { 2, 1, 2, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t cve_item     = { 1, 2, 2, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t cve_both     = { 2, 2, 2, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t domain_one   = { 0, 0, 0, 1, 1, 0, 0, 0 };
  const WatchlistTestShape_t domain_pair  = { 0, 0, 0, 1, 2, 0, 0, 0 };
  const WatchlistTestShape_t domain_item  = { 0, 0, 0, 2, 2, 0, 0, 0 };
  const WatchlistTestShape_t package_one   = { 0, 0, 0, 0, 0, 1, 1, 1 };
  const WatchlistTestShape_t package_event = { 0, 0, 0, 0, 0, 2, 1, 2 };
  const WatchlistTestShape_t package_item  = { 0, 0, 0, 0, 0, 1, 2, 2 };
  const WatchlistTestShape_t package_both  = { 0, 0, 0, 0, 0, 2, 2, 2 };
  const long long size_cve_event     = (long long)static_WATCHLISTEVENTSShapeSize(&page, &cve_event, JSONBUF_MAX_CEILING);
  const long long size_cve_item      = (long long)static_WATCHLISTEVENTSShapeSize(&page, &cve_item, JSONBUF_MAX_CEILING);
  const long long size_cve_both      = (long long)static_WATCHLISTEVENTSShapeSize(&page, &cve_both, JSONBUF_MAX_CEILING);
  const long long size_domain_pair   = (long long)static_WATCHLISTEVENTSShapeSize(&page, &domain_pair, JSONBUF_MAX_CEILING);
  const long long size_domain_item   = (long long)static_WATCHLISTEVENTSShapeSize(&page, &domain_item, JSONBUF_MAX_CEILING);
  const long long size_package_event = (long long)static_WATCHLISTEVENTSShapeSize(&page, &package_event, JSONBUF_MAX_CEILING);
  const long long size_package_item  = (long long)static_WATCHLISTEVENTSShapeSize(&page, &package_item, JSONBUF_MAX_CEILING);
  const long long size_package_both  = (long long)static_WATCHLISTEVENTSShapeSize(&page, &package_both, JSONBUF_MAX_CEILING);
  WatchlistTestPartLengths_t lengths;
  lengths.m_noneSize           = (long long)static_WATCHLISTEVENTSShapeSize(&page, &no_part, JSONBUF_MAX_CEILING);
  lengths.m_cveOneSize         = (long long)static_WATCHLISTEVENTSShapeSize(&page, &cve_one, JSONBUF_MAX_CEILING);
  lengths.m_cveEventLength     = size_cve_both - size_cve_item;
  lengths.m_cveItemLength      = size_cve_both - size_cve_event;
  lengths.m_cvePairLength      = size_cve_event - lengths.m_cveOneSize - lengths.m_cveEventLength;
  lengths.m_domainOneSize      = (long long)static_WATCHLISTEVENTSShapeSize(&page, &domain_one, JSONBUF_MAX_CEILING);
  lengths.m_domainPairLength   = size_domain_pair - lengths.m_domainOneSize;
  lengths.m_domainItemLength   = size_domain_item - size_domain_pair;
  lengths.m_packageOneSize     = (long long)static_WATCHLISTEVENTSShapeSize(&page, &package_one, JSONBUF_MAX_CEILING);
  lengths.m_packageEventLength = size_package_both - size_package_item;
  lengths.m_packageItemLength  = size_package_both - size_package_event;
  lengths.m_packagePairLength  = size_package_event - lengths.m_packageOneSize - lengths.m_packageEventLength;
  TEST_ASSERT_TRUE(lengths.m_packageItemLength + lengths.m_packagePairLength > lengths.m_cvePairLength);
  TEST_ASSERT_TRUE(lengths.m_packageItemLength + lengths.m_packagePairLength > lengths.m_packagePairLength);
  const long long eol_pair_length = static_WATCHLISTEVENTSEolPairLength();
  TEST_ASSERT_TRUE(eol_pair_length < lengths.m_cvePairLength);

  WatchlistTestShape_t largest_shape = no_part;
  long long largest_size = lengths.m_noneSize;
  for (int domain_item_count = 0; domain_item_count <= WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY; domain_item_count++)
  {
    for (int domain_event_count = domain_item_count; domain_event_count <= CVE_LIST_MAX_LIMIT; domain_event_count++)
    {
      if (domain_item_count == 0 && domain_event_count > 0)
        break;
      for (int package_event_count = 0; package_event_count <= CVE_LIST_MAX_LIMIT - domain_event_count; package_event_count++)
      {
        WatchlistTestShape_t shape = { 0, 0, 0, domain_item_count, domain_event_count, package_event_count, 0, 0 };
        shape.m_cveItemCount  = WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY - domain_item_count;
        shape.m_cveEventCount = (shape.m_cveItemCount > 0) ? CVE_LIST_MAX_LIMIT - domain_event_count - package_event_count : 0;
        if (shape.m_cveEventCount == 0)
          shape.m_cveItemCount = 0;
        int pairs_left = WATCHLIST_ANSWER_PAIR_MAX_COUNT - domain_event_count;
        int cve_pair_min = (shape.m_cveEventCount > shape.m_cveItemCount) ? shape.m_cveEventCount : shape.m_cveItemCount;
        pairs_left -= cve_pair_min;
        if (package_event_count > 0)
        {
          shape.m_packageItemCount = (pairs_left < WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY) ? pairs_left : WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY;
          shape.m_packagePairCount = (package_event_count > shape.m_packageItemCount) ? package_event_count : shape.m_packageItemCount;
          pairs_left -= shape.m_packagePairCount;
        }
        if (pairs_left < 0 || (package_event_count > 0 && shape.m_packageItemCount == 0))
          continue;
        long long cve_pair_room     = (long long)shape.m_cveEventCount * shape.m_cveItemCount - cve_pair_min;
        long long package_pair_room = (long long)package_event_count * shape.m_packageItemCount - shape.m_packagePairCount;
        int cve_pair_extra = 0;
        int package_pair_extra = 0;
        if (lengths.m_cvePairLength >= lengths.m_packagePairLength)
        {
          cve_pair_extra     = (int)((pairs_left < cve_pair_room) ? pairs_left : cve_pair_room);
          package_pair_extra = (int)((pairs_left - cve_pair_extra < package_pair_room) ? pairs_left - cve_pair_extra : package_pair_room);
        }
        else
        {
          package_pair_extra = (int)((pairs_left < package_pair_room) ? pairs_left : package_pair_room);
          cve_pair_extra     = (int)((pairs_left - package_pair_extra < cve_pair_room) ? pairs_left - package_pair_extra : cve_pair_room);
        }
        shape.m_cvePairCount      = cve_pair_min + cve_pair_extra;
        shape.m_packagePairCount += package_pair_extra;
        long long size = static_WATCHLISTEVENTSShapeSum(&lengths, &shape);
        if (size > largest_size)
        {
          largest_size  = size;
          largest_shape = shape;
        }
      }
    }
  }

  const WatchlistTestShape_t cve_only     = { CVE_LIST_MAX_LIMIT, WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY, WATCHLIST_ANSWER_PAIR_MAX_COUNT, 0, 0, 0, 0, 0 };
  const WatchlistTestShape_t domain_only  = { 0, 0, 0, WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY, CVE_LIST_MAX_LIMIT, 0, 0, 0 };
  const WatchlistTestShape_t package_only = { 0, 0, 0, 0, 0, CVE_LIST_MAX_LIMIT, WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY, WATCHLIST_ANSWER_PAIR_MAX_COUNT };
  TEST_ASSERT_EQUAL_INT64(static_WATCHLISTEVENTSShapeSum(&lengths, &cve_only), (long long)static_WATCHLISTEVENTSShapeSize(&page, &cve_only, JSONBUF_MAX_CEILING));
  TEST_ASSERT_EQUAL_INT64(static_WATCHLISTEVENTSShapeSum(&lengths, &domain_only), (long long)static_WATCHLISTEVENTSShapeSize(&page, &domain_only, JSONBUF_MAX_CEILING));
  TEST_ASSERT_EQUAL_INT64(static_WATCHLISTEVENTSShapeSum(&lengths, &package_only), (long long)static_WATCHLISTEVENTSShapeSize(&page, &package_only, JSONBUF_MAX_CEILING));
  TEST_ASSERT_LESS_OR_EQUAL_INT(WATCHLIST_ANSWER_PAIR_MAX_COUNT, largest_shape.m_cvePairCount + largest_shape.m_domainEventCount + largest_shape.m_packagePairCount);
  TEST_ASSERT_LESS_OR_EQUAL_INT(CVE_LIST_MAX_LIMIT, largest_shape.m_cveEventCount + largest_shape.m_domainEventCount + largest_shape.m_packageEventCount);
  TEST_ASSERT_EQUAL_INT64(largest_size, (long long)static_WATCHLISTEVENTSShapeSize(&page, &largest_shape, JSONBUF_MAX_CEILING));

  printf("watchlist_events worst case: %lld bytes with %d CVE events, %d CVE items, %d CVE pairs, %d domain items, %d domain events,"
         " %d package events, %d package items and %d package pairs; JSONBUF_DEFAULT_CEILING %d bytes\n",
         largest_size, largest_shape.m_cveEventCount, largest_shape.m_cveItemCount, largest_shape.m_cvePairCount,
         largest_shape.m_domainItemCount, largest_shape.m_domainEventCount, largest_shape.m_packageEventCount,
         largest_shape.m_packageItemCount, largest_shape.m_packagePairCount, JSONBUF_DEFAULT_CEILING);
  printf("watchlist_events part lengths: none %lld; CVE one %lld, event %lld, item %lld, pair %lld; domain one %lld, pair %lld,"
         " item %lld; package one %lld, event %lld, item %lld, pair %lld\n",
         lengths.m_noneSize, lengths.m_cveOneSize, lengths.m_cveEventLength, lengths.m_cveItemLength, lengths.m_cvePairLength,
         lengths.m_domainOneSize, lengths.m_domainPairLength, lengths.m_domainItemLength, lengths.m_packageOneSize,
         lengths.m_packageEventLength, lengths.m_packageItemLength, lengths.m_packagePairLength);
  TEST_ASSERT_EQUAL_INT64(largest_size, (long long)static_WATCHLISTEVENTSShapeSize(&page, &largest_shape, JSONBUF_DEFAULT_CEILING));
  free(page.mp_events);
  free(page.mp_items);
  free(page.mp_pairs);
  free(page.mp_pairIsVersionAffected);
  free(page.mp_cveFacts);
  free(page.mp_domainFacts);
  free(page.mp_advisories);
}

void test_CVSSCALCULATOR_golden(void)
{
  CvssResult_t result;
  memset(&result, 0, sizeof(result));
  memcpy(result.ma_vector, "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L/E:P/CR:H", sizeof("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L/E:P/CR:H"));
  memcpy(result.ma_version, "3.1", sizeof("3.1"));
  memcpy(result.ma_baseSeverity, "MEDIUM", sizeof("MEDIUM"));
  memcpy(result.ma_attackVector, "ADJACENT_NETWORK", sizeof("ADJACENT_NETWORK"));
  memcpy(result.ma_attackComplexity, "HIGH", sizeof("HIGH"));
  memcpy(result.ma_privilegesRequired, "LOW", sizeof("LOW"));
  memcpy(result.ma_userInteraction, "REQUIRED", sizeof("REQUIRED"));
  memcpy(result.ma_scope, "CHANGED", sizeof("CHANGED"));
  memcpy(result.ma_confidentialityImpact, "HIGH", sizeof("HIGH"));
  memcpy(result.ma_integrityImpact, "NONE", sizeof("NONE"));
  memcpy(result.ma_availabilityImpact, "LOW", sizeof("LOW"));
  result.m_baseScore          = 6.2;
  result.m_temporalScore      = 5.9;
  result.m_environmentalScore = 7.2;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVSSCALCULATOR_response(&result, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"version":"3.1","vector":"CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:N/A:L/E:P/CR:H",)"
      R"("base_score":6.2,"base_severity":"MEDIUM",)"
      R"("metrics":{"attack_vector":"ADJACENT_NETWORK","attack_complexity":"HIGH","privileges_required":"LOW",)"
      R"("user_interaction":"REQUIRED","scope":"CHANGED","confidentiality_impact":"HIGH","integrity_impact":"NONE",)"
      R"("availability_impact":"LOW"},"temporal_score":5.9,"environmental_score":7.2,)"
      R"("summary":"CVSS v3.1 MEDIUM (6.2). AV=ADJACENT_NETWORK, AC=HIGH, PR=LOW, UI=REQUIRED, Scope=CHANGED."})" "\n", body);
  free(body);
}

void test_CVSSCALCULATOR_each_member_lands_under_its_own_key(void)
{
  CvssResult_t result;
  memset(&result, 0, sizeof(result));
  memcpy(result.ma_vector, "VECTOR", sizeof("VECTOR"));
  memcpy(result.ma_version, "3.0", sizeof("3.0"));
  memcpy(result.ma_baseSeverity, "SEVERITY", sizeof("SEVERITY"));
  memcpy(result.ma_attackVector, "AV-LABEL", sizeof("AV-LABEL"));
  memcpy(result.ma_attackComplexity, "AC-LABEL", sizeof("AC-LABEL"));
  memcpy(result.ma_privilegesRequired, "PR-LABEL", sizeof("PR-LABEL"));
  memcpy(result.ma_userInteraction, "UI-LABEL", sizeof("UI-LABEL"));
  memcpy(result.ma_scope, "S-LABEL", sizeof("S-LABEL"));
  memcpy(result.ma_confidentialityImpact, "C-LABEL", sizeof("C-LABEL"));
  memcpy(result.ma_integrityImpact, "I-LABEL", sizeof("I-LABEL"));
  memcpy(result.ma_availabilityImpact, "A-LABEL", sizeof("A-LABEL"));
  result.m_baseScore          = 1.1;
  result.m_temporalScore      = 2.2;
  result.m_environmentalScore = 3.3;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVSSCALCULATOR_response(&result, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_EQUAL_STRING(
    R"({"version":"3.0","vector":"VECTOR","base_score":1.1,"base_severity":"SEVERITY",)"
      R"("metrics":{"attack_vector":"AV-LABEL","attack_complexity":"AC-LABEL","privileges_required":"PR-LABEL",)"
      R"("user_interaction":"UI-LABEL","scope":"S-LABEL","confidentiality_impact":"C-LABEL","integrity_impact":"I-LABEL",)"
      R"("availability_impact":"A-LABEL"},"temporal_score":2.2,"environmental_score":3.3,)"
      R"("summary":"CVSS v3.0 SEVERITY (1.1). AV=AV-LABEL, AC=AC-LABEL, PR=PR-LABEL, UI=UI-LABEL, Scope=S-LABEL."})" "\n", body);
  free(body);
}

void test_CVSSCALCULATOR_vector_is_escaped(void)
{
  CvssResult_t result;
  memset(&result, 0, sizeof(result));
  memcpy(result.ma_vector, R"(a"b\c)", sizeof(R"(a"b\c)"));

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVSSCALCULATOR_response(&result, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL(strstr(body, R"("vector":"a\"b\\c",)"));
  free(body);
}

void test_CVSSCALCULATOR_whole_number_scores_keep_one_decimal(void)
{
  CvssResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_baseScore          = 10.0;
  result.m_temporalScore      = 0.0;
  result.m_environmentalScore = 5.0;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVSSCALCULATOR_response(&result, json_buf);
  char* body = static_finishJsonBuf(json_buf);

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("base_score":10.0,)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("temporal_score":0.0,"environmental_score":5.0,)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, " (10.0). "), body);
  free(body);
}

#define SSLCHECK_FIX_SHA256 "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
#define SSLCHECK_FIX_SHA1   "1f2e3d4c5b6a79880f1e2d3c4b5a69780f1e2d3c"

static void static_fillSSLCHECKRecord(SSLCHECKRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  TlsProbeResult_t*      result      = &record->m_result;
  TlsProbeCertificate_t* certificate = &result->m_serverCertificate;
  snprintf(record->ma_checkedAt, sizeof(record->ma_checkedAt), "%s", "2026-10-24T08:09:10Z");
  snprintf(result->ma_hostname, sizeof(result->ma_hostname), "%s", "shop.example.com");
  snprintf(result->ma_ipAddress, sizeof(result->ma_ipAddress), "%s", "2001:db8::7");
  snprintf(result->ma_protocol, sizeof(result->ma_protocol), "%s", "TLSv1.2");
  snprintf(result->ma_cipherName, sizeof(result->ma_cipherName), "%s", "ECDHE-ECDSA-AES256-GCM-SHA384");
  result->m_cipherBits = 256;
  snprintf(result->ma_keyExchangeGroup, sizeof(result->ma_keyExchangeGroup), "%s", "secp384r1");
  result->m_keyExchangeBits = 384;
  snprintf(result->ma_alpnProtocol, sizeof(result->ma_alpnProtocol), "%s", "http/1.1");

  snprintf(certificate->ma_sha256Hex, sizeof(certificate->ma_sha256Hex), "%s", SSLCHECK_FIX_SHA256);
  snprintf(certificate->ma_sha1Hex, sizeof(certificate->ma_sha1Hex), "%s", SSLCHECK_FIX_SHA1);
  snprintf(certificate->ma_validFrom, sizeof(certificate->ma_validFrom), "%s", "2025-01-01T00:00:00Z");
  snprintf(certificate->ma_validUntil, sizeof(certificate->ma_validUntil), "%s", "2026-10-21T12:00:00Z");
  certificate->m_validUntilUnixSeconds = 1792584000;
  snprintf(certificate->ma_issuer, sizeof(certificate->ma_issuer), "%s", "Example Issuer Org");
  snprintf(certificate->ma_subject, sizeof(certificate->ma_subject), "%s", "cn.example.com");
  snprintf(certificate->ma_serialHex, sizeof(certificate->ma_serialHex), "%s", "00FF10");
  snprintf(certificate->ma_signatureAlgorithm, sizeof(certificate->ma_signatureAlgorithm), "%s", "ecdsa-with-SHA384");
  snprintf(certificate->ma_keyType, sizeof(certificate->ma_keyType), "%s", "EC");
  certificate->m_keyBits = 521;
  snprintf(certificate->ma_dnsNames[0], sizeof(certificate->ma_dnsNames[0]), "%s", "alt-one.example.com");
  snprintf(certificate->ma_dnsNames[1], sizeof(certificate->ma_dnsNames[1]), "%s", "*.alt-two.example.net");
  snprintf(certificate->ma_dnsNames[2], sizeof(certificate->ma_dnsNames[2]), "%s", "stale.example.org");
  certificate->m_dnsNameCount = 2;

  snprintf(result->ma_chain[0].ma_subjectFullName, sizeof(result->ma_chain[0].ma_subjectFullName), "%s", "CN=cn.example.com");
  snprintf(result->ma_chain[0].ma_issuerFullName, sizeof(result->ma_chain[0].ma_issuerFullName), "%s", "CN=Example Issuing CA,O=Example Issuer Org,C=DE");
  snprintf(result->ma_chain[0].ma_validUntil, sizeof(result->ma_chain[0].ma_validUntil), "%s", "2026-10-21T12:00:01Z");
  snprintf(result->ma_chain[1].ma_subjectFullName, sizeof(result->ma_chain[1].ma_subjectFullName), "%s", "CN=Example Issuing CA,O=Example Issuer Org,C=DE");
  snprintf(result->ma_chain[1].ma_issuerFullName, sizeof(result->ma_chain[1].ma_issuerFullName), "%s", "CN=Example Root,O=Example Issuer Org,C=DE");
  snprintf(result->ma_chain[1].ma_validUntil, sizeof(result->ma_chain[1].ma_validUntil), "%s", "2031-05-06T07:08:09Z");
  snprintf(result->ma_chain[2].ma_subjectFullName, sizeof(result->ma_chain[2].ma_subjectFullName), "%s", "CN=stale");
  result->m_chainCount = 2;

  result->m_problems            = TLSPROBE_PROBLEM_EXPIRED | TLSPROBE_PROBLEM_HOSTNAME_MISMATCH;
  result->m_isTrusted           = false;
  result->m_revokeStatus        = TLSPROBE_REVOKE_REVOKED;
  result->m_daysRemaining       = -3;
  result->m_secureRenegotiation = TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED;

  record->m_isBlacklistFeedLoaded = true;
  snprintf(record->ma_blacklistListingReason, sizeof(record->ma_blacklistListingReason), "%s", "AsyncRAT C&C");
  snprintf(record->ma_blacklistListingTime, sizeof(record->ma_blacklistListingTime), "%s", "2025-11-12T13:14:15Z");
}

#define SSLCHECK_FIX_CHAIN_JSON \
  R"(},"chain":[{"subject":"CN=cn.example.com","issuer":"CN=Example Issuing CA,O=Example Issuer Org,C=DE","valid_until":"2026-10-21T12:00:01Z"},)" \
  R"({"subject":"CN=Example Issuing CA,O=Example Issuer Org,C=DE","issuer":"CN=Example Root,O=Example Issuer Org,C=DE","valid_until":"2031-05-06T07:08:09Z"}],)" \
  R"("chain_truncated":false,)"

static char* static_SSLCHECKBody(const SSLCHECKRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_SSLCHECK_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_SSLCHECK_full_result_golden(void)
{
  static SSLCHECKRecord_t record;
  static_fillSSLCHECKRecord(&record);
  char* body = static_SSLCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","ip_address":"2001:db8::7","checked_at":"2026-10-24T08:09:10Z","protocol":"TLSv1.2",)"
    R"("cipher":{"name":"ECDHE-ECDSA-AES256-GCM-SHA384","bits":256},"key_exchange":{"group":"secp384r1","bits":384},)"
    R"("alpn_protocol":"http/1.1","secure_renegotiation":true,"trusted":false,"problems":["expired","hostname_mismatch"],)"
    R"("revocation":"revoked","days_remaining":-3,)"
    R"("certificate":{"subject":"cn.example.com","issuer":"Example Issuer Org","serial_number":"00FF10",)"
    R"("sha256_fingerprint":")" SSLCHECK_FIX_SHA256 R"(","sha1_fingerprint":")" SSLCHECK_FIX_SHA1 R"(",)"
    R"("valid_from":"2025-01-01T00:00:00Z","valid_until":"2026-10-21T12:00:00Z",)"
    R"("signature_algorithm":"ecdsa-with-SHA384","key":{"type":"EC","bits":521},)"
    R"("dns_names":["alt-one.example.com","*.alt-two.example.net"],"dns_names_truncated":false,)"
    R"("listed_on":[{"source":"sslbl","listing_reason":"AsyncRAT C&C","listing_time":"2025-11-12T13:14:15Z"}]},)"
    R"("chain":[{"subject":"CN=cn.example.com","issuer":"CN=Example Issuing CA,O=Example Issuer Org,C=DE","valid_until":"2026-10-21T12:00:01Z"},)"
    R"({"subject":"CN=Example Issuing CA,O=Example Issuer Org,C=DE","issuer":"CN=Example Root,O=Example Issuer Org,C=DE","valid_until":"2031-05-06T07:08:09Z"}],)"
    R"("chain_truncated":false,"unavailable":{}})" "\n", body);
  free(body);
}

void test_SSLCHECK_every_problem_in_bit_order(void)
{
  static SSLCHECKRecord_t record;
  static_fillSSLCHECKRecord(&record);
  record.m_result.m_problems = TLSPROBE_PROBLEM_EXPIRED | TLSPROBE_PROBLEM_NOT_YET_VALID | TLSPROBE_PROBLEM_SELF_SIGNED |
                               TLSPROBE_PROBLEM_UNTRUSTED_ROOT | TLSPROBE_PROBLEM_HOSTNAME_MISMATCH |
                               TLSPROBE_PROBLEM_CHAIN_INCOMPLETE | TLSPROBE_PROBLEM_OTHER | TLSPROBE_PROBLEM_WEAK_CRYPTO;
  char* body = static_SSLCHECKBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body,
    R"("trusted":false,"problems":["expired","not_yet_valid","self_signed","untrusted_root","hostname_mismatch",)"
    R"("chain_incomplete","other","weak_crypto"],"revocation":"revoked",)"), body);
  free(body);
}

void test_SSLCHECK_each_problem_bit_writes_its_own_name(void)
{
  static const struct { unsigned int m_bit; const char* mp_problems; } cases[] = {
    { TLSPROBE_PROBLEM_EXPIRED,           R"("problems":["expired"],)"           },
    { TLSPROBE_PROBLEM_NOT_YET_VALID,     R"("problems":["not_yet_valid"],)"     },
    { TLSPROBE_PROBLEM_SELF_SIGNED,       R"("problems":["self_signed"],)"       },
    { TLSPROBE_PROBLEM_UNTRUSTED_ROOT,    R"("problems":["untrusted_root"],)"    },
    { TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, R"("problems":["hostname_mismatch"],)" },
    { TLSPROBE_PROBLEM_CHAIN_INCOMPLETE,  R"("problems":["chain_incomplete"],)"  },
    { TLSPROBE_PROBLEM_OTHER,             R"("problems":["other"],)"             },
    { TLSPROBE_PROBLEM_WEAK_CRYPTO,       R"("problems":["weak_crypto"],)"       },
  };
  static SSLCHECKRecord_t record;
  static_fillSSLCHECKRecord(&record);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    record.m_result.m_problems = cases[i].m_bit;
    char* body = static_SSLCHECKBody(&record);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_problems), cases[i].mp_problems);
    free(body);
  }
}

void test_SSLCHECK_empty_texts_are_null_golden(void)
{
  static SSLCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  TlsProbeResult_t* result = &record.m_result;
  snprintf(result->ma_hostname, sizeof(result->ma_hostname), "%s", "bare.example.com");
  snprintf(result->ma_ipAddress, sizeof(result->ma_ipAddress), "%s", "192.0.2.1");
  result->m_cipherBits                             = 128;
  result->m_keyExchangeBits                        = 253;
  result->m_serverCertificate.m_keyBits            = 2048;
  result->m_serverCertificate.m_isDnsNameListTruncated = true;
  result->m_chainCount                             = 1;
  result->m_isChainTruncated                       = true;
  result->m_isTrusted                              = true;
  result->m_revokeStatus                           = TLSPROBE_REVOKE_NOT_SENT;
  result->m_secureRenegotiation                    = TLSPROBE_SECURE_RENEGOTIATION_NOT_SUPPORTED;
  char* body = static_SSLCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"bare.example.com","ip_address":"192.0.2.1","checked_at":null,"protocol":null,"cipher":null,)"
    R"("key_exchange":null,"alpn_protocol":null,"secure_renegotiation":false,"trusted":true,"problems":[],)"
    R"("revocation":"not_sent","days_remaining":0,)"
    R"("certificate":{"subject":null,"issuer":null,"serial_number":null,"sha256_fingerprint":"","sha1_fingerprint":"",)"
    R"("valid_from":"","valid_until":"",)"
    R"("signature_algorithm":null,"key":null,"dns_names":[],"dns_names_truncated":true,"listed_on":null},)"
    R"("chain":[{"subject":null,"issuer":null,"valid_until":null}],"chain_truncated":true,)"
    R"("unavailable":{"listed_on":"not_synced"}})" "\n", body);
  free(body);
}

void test_SSLCHECK_renegotiation_null_and_each_revocation_name(void)
{
  static const struct { TlsProbeRevokeStatus_t m_status; const char* mp_revocation; } cases[] = {
    { TLSPROBE_REVOKE_NOT_SENT,    R"("revocation":"not_sent",)"    },
    { TLSPROBE_REVOKE_NOT_REVOKED, R"("revocation":"not_revoked",)" },
    { TLSPROBE_REVOKE_REVOKED,     R"("revocation":"revoked",)"     },
    { TLSPROBE_REVOKE_UNKNOWN,     R"("revocation":"unknown",)"     },
    { TLSPROBE_REVOKE_UNUSABLE,    R"("revocation":"unusable",)"    },
  };
  static SSLCHECKRecord_t record;
  static_fillSSLCHECKRecord(&record);
  snprintf(record.m_result.ma_protocol, sizeof(record.m_result.ma_protocol), "%s", "TLSv1.3");
  record.m_result.m_secureRenegotiation = TLSPROBE_SECURE_RENEGOTIATION_NOT_APPLICABLE;
  record.m_result.m_chainCount          = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    record.m_result.m_revokeStatus = cases[i].m_status;
    char* body = static_SSLCHECKBody(&record);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("protocol":"TLSv1.3",)"), body);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"(,"secure_renegotiation":null,"trusted":false,)"), body);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_revocation), cases[i].mp_revocation);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"(,"chain":[],"chain_truncated":false,"unavailable":{}})" "\n"), body);
    free(body);
  }
}

void test_SSLCHECK_certificate_names_are_escaped(void)
{
  static SSLCHECKRecord_t record;
  static_fillSSLCHECKRecord(&record);
  TlsProbeResult_t* result = &record.m_result;
  snprintf(result->m_serverCertificate.ma_subject, sizeof(result->m_serverCertificate.ma_subject), "%s", "a\xff" "b\xe2\x80\xae" "c");
  snprintf(result->m_serverCertificate.ma_issuer, sizeof(result->m_serverCertificate.ma_issuer), "%s", "Q\"uote\\");
  snprintf(result->m_serverCertificate.ma_dnsNames[0], sizeof(result->m_serverCertificate.ma_dnsNames[0]), "%s", "a\"b\xff");
  snprintf(result->ma_chain[0].ma_subjectFullName, sizeof(result->ma_chain[0].ma_subjectFullName), "%s", "CN=x\xe2\x80\x8b" "y");
  char* body = static_SSLCHECKBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, "\"certificate\":{\"subject\":\"a\xef\xbf\xbd" "b\\" "u202e" "c\","), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("issuer":"Q\"uote\\",)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("dns_names":["a\"b)" "\xef\xbf\xbd" R"(",)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, "\"chain\":[{\"subject\":\"CN=x\\" "u200b" "y\","), body);
  TEST_ASSERT_NULL(strstr(body, "\xe2\x80\xae"));
  TEST_ASSERT_NULL(strchr(body, '\xff'));
  free(body);
}

void test_SSLCHECK_listed_on_and_unavailable_follow_the_list_state(void)
{
  static const struct {
    bool        m_isUnavailable;
    bool        m_isFeedLoaded;
    const char* mp_reason;
    const char* mp_tail;
  } cases[] = {
    { false, true,  "AsyncRAT C&C",
      R"("listed_on":[{"source":"sslbl","listing_reason":"AsyncRAT C&C","listing_time":"2025-11-12T13:14:15Z"}])" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{}})" "\n" },
    { false, true,  "",
      R"("listed_on":[])" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{}})" "\n" },
    { false, false, "",
      R"("listed_on":null)" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{"listed_on":"not_synced"}})" "\n" },
    { true,  true,  "AsyncRAT C&C",
      R"("listed_on":null)" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{"listed_on":"database_error"}})" "\n" },
    { true,  false, "",
      R"("listed_on":null)" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{"listed_on":"database_error"}})" "\n" },
    { false, true,  "Q\"uote\\",
      R"("listed_on":[{"source":"sslbl","listing_reason":"Q\"uote\\","listing_time":"2025-11-12T13:14:15Z"}])" SSLCHECK_FIX_CHAIN_JSON R"("unavailable":{}})" "\n" },
  };
  static SSLCHECKRecord_t record;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_fillSSLCHECKRecord(&record);
    record.m_isBlacklistUnavailable = cases[i].m_isUnavailable;
    record.m_isBlacklistFeedLoaded  = cases[i].m_isFeedLoaded;
    snprintf(record.ma_blacklistListingReason, sizeof(record.ma_blacklistListingReason), "%s", cases[i].mp_reason);
    char* body = static_SSLCHECKBody(&record);
    const char* listed_on = strstr(body, R"("listed_on":)");
    TEST_ASSERT_NOT_NULL_MESSAGE(listed_on, body);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_tail, listed_on);
    free(body);
  }

  static_fillSSLCHECKRecord(&record);
  snprintf(record.ma_blacklistListingTime, sizeof(record.ma_blacklistListingTime), "%s", "T\"ime\\");
  char* time_body = static_SSLCHECKBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(time_body, R"("listing_time":"T\"ime\\"}])"), time_body);
  free(time_body);
}

#define HEADERSCHECK_FIX_CHECKED_AT "2026-10-25T09:08:07Z"

#define HEADERSCHECK_ALL_MISSING_FINDINGS \
  R"x([{"header":"Content-Security-Policy","severity":"high","result":"missing","issues":[],"value":null,"remediation":"Add a Content-Security-Policy header with a strict policy; start with default-src 'self'"})x" \
  R"x(,{"header":"Strict-Transport-Security","severity":"high","result":"missing","issues":[],"value":null,"remediation":"Add Strict-Transport-Security: max-age=63072000; includeSubDomains"})x" \
  R"x(,{"header":"X-Content-Type-Options","severity":"medium","result":"missing","issues":[],"value":null,"remediation":"Add X-Content-Type-Options: nosniff"})x" \
  R"x(,{"header":"X-Frame-Options","severity":"medium","result":"missing","issues":[],"value":null,"remediation":"Add X-Frame-Options: DENY or SAMEORIGIN"})x" \
  R"x(,{"header":"Referrer-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer"})x"

#define HEADERSCHECK_NO_COOKIE_NO_CORS_FINDINGS \
  R"x(,{"header":"Set-Cookie","severity":"medium","result":"pass","issues":[],"value":null,"cookie_count":0})x" \
  R"x(,{"header":"Access-Control-Allow-Origin","severity":"low","result":"pass","issues":[],"value":null})x"

static char* static_HEADERSCHECKBody(const char* url, int status, int redirect_count, const char* redirect_to, char* const captured_values[HEADER_CHECK_HEADER_COUNT], size_t set_cookie_copy_count, bool is_full_header_value_included)
{
  static HEADERSCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  record.m_fetchResult.m_httpStatus             = status;
  record.m_fetchResult.mp_url                   = (char*)url;
  record.m_fetchResult.m_followedRedirectCount  = redirect_count;
  record.m_fetchResult.mp_unfollowedRedirectUrl = (char*)redirect_to;
  record.m_fetchResult.m_setCookieCopyCount     = set_cookie_copy_count;
  snprintf(record.ma_checkedAt, sizeof(record.ma_checkedAt), "%s", HEADERSCHECK_FIX_CHECKED_AT);
  header_check_evaluate(captured_values, set_cookie_copy_count, &record.m_report);
  HEADERSCHECKParams_t params = { "example.com", is_full_header_value_included };
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEADERSCHECK_response(&record, &params, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_HEADERSCHECK_each_result_golden(void)
{
  char csp[]         = "script-src 'self' 'unsafe-inline'; object-src 'none'";
  char hsts[]        = "max-age=63072000; includeSubDomains";
  char xcto[]        = "sniff";
  char xfo[]         = "DENY";
  char permissions[] = "camera=()";
  char xxp[]         = "0";
  char set_cookie[]  = "id=1; Secure; HttpOnly; SameSite=Lax";
  char allow_origin[] = "*";
  char report_only[] = "default-src 'none'";
  char* values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]             = csp;
  values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY]           = hsts;
  values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS]              = xcto;
  values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]                     = xfo;
  values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY]                  = permissions;
  values[HEADER_CHECK_HEADER_X_XSS_PROTECTION]                    = xxp;
  values[HEADER_CHECK_HEADER_SET_COOKIE]                          = set_cookie;
  values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]         = allow_origin;
  values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY] = report_only;
  char* body = static_HEADERSCHECKBody("https://www.example.com/start", 200, 2, NULL, values, 1, false);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"url":"https://www.example.com/start","status_code":200,"redirect_count":2,"checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":[)x"
    R"x({"header":"Content-Security-Policy","severity":"high","result":"warn","issues":["Permissive CSP: 'script-src' allows 'unsafe-inline' (XSS risk)","Missing base-uri directive (recommended: base-uri 'none' or 'self')"],"value":"script-src 'self' 'unsafe-inline'; object-src 'none'","remediation":"Add a Content-Security-Policy header with a strict policy; start with default-src 'self'"})x"
    R"x(,{"header":"Strict-Transport-Security","severity":"high","result":"pass","issues":[],"value":"max-age=63072000; includeSubDomains"})x"
    R"x(,{"header":"X-Content-Type-Options","severity":"medium","result":"fail","issues":["Invalid value. Allowed: nosniff (case-insensitive)"],"value":"sniff","remediation":"Add X-Content-Type-Options: nosniff"})x"
    R"x(,{"header":"X-Frame-Options","severity":"medium","result":"pass","issues":[],"value":"DENY"})x"
    R"x(,{"header":"Referrer-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer"})x"
    R"x(,{"header":"Permissions-Policy","severity":"low","result":"pass","issues":[],"value":"camera=()"})x"
    R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":"0"})x"
    R"x(,{"header":"Set-Cookie","severity":"medium","result":"pass","issues":[],"value":null,"cookie_count":1})x"
    R"x(,{"header":"Access-Control-Allow-Origin","severity":"low","result":"pass","issues":[],"value":"*"}]})x" "\n", body);
  free(body);
}

void test_HEADERSCHECK_redirect_target_golden(void)
{
  char* const values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  char* body = static_HEADERSCHECKBody("https://example.com/", 301, 0, "https://other.example/next", values, 0, false);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"url":"https://example.com/","status_code":301,"redirect_count":0,"redirect_to":"https://other.example/next","checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":)x"
    HEADERSCHECK_ALL_MISSING_FINDINGS
    R"x(,{"header":"Permissions-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())"})x"
    R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":null})x" HEADERSCHECK_NO_COOKIE_NO_CORS_FINDINGS R"x(]})x" "\n", body);
  free(body);
}

void test_HEADERSCHECK_redirect_limit_golden(void)
{
  static HEADERSCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  record.m_fetchResult.m_httpStatus             = 307;
  record.m_fetchResult.mp_url                   = (char*)"https://example.com/5";
  record.m_fetchResult.m_followedRedirectCount  = 5;
  record.m_fetchResult.mp_unfollowedRedirectUrl = (char*)"https://example.com/6";
  record.m_fetchResult.m_isRedirectLimitReached = true;
  snprintf(record.ma_checkedAt, sizeof(record.ma_checkedAt), "%s", HEADERSCHECK_FIX_CHECKED_AT);
  char* const values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  header_check_evaluate(values, 0, &record.m_report);
  HEADERSCHECKParams_t params = { "example.com", false };
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_HEADERSCHECK_response(&record, &params, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    R"x({"url":"https://example.com/5","status_code":307,"redirect_count":5,"redirect_to":"https://example.com/6","redirect_limit_reached":true,"checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":)x"
    HEADERSCHECK_ALL_MISSING_FINDINGS
    R"x(,{"header":"Permissions-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())"})x"
    R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":null})x" HEADERSCHECK_NO_COOKIE_NO_CORS_FINDINGS R"x(]})x" "\n", body);
  free(body);
}

static char* static_HEADERSCHECKPermissionsBody(char* permissions_value, bool is_full_header_value_included)
{
  char* values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = permissions_value;
  return static_HEADERSCHECKBody("https://example.org/", 404, 3, NULL, values, 0, is_full_header_value_included);
}

static void static_HEADERSCHECKPermissionsGolden(const char* shown_value, const char* total_member, char* golden_out, size_t golden_size)
{
  int written = snprintf(golden_out, golden_size,
    R"x({"url":"https://example.org/","status_code":404,"redirect_count":3,"checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":)x"
    HEADERSCHECK_ALL_MISSING_FINDINGS
    R"x(,{"header":"Permissions-Policy","severity":"low","result":"fail","issues":["The value does not parse as a structured field dictionary (RFC 8941), so browsers ignore the whole header"],"value":"%s"%s,"remediation":"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())"})x"
    R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":null})x" HEADERSCHECK_NO_COOKIE_NO_CORS_FINDINGS R"x(]})x" "\n",
    shown_value, total_member);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < golden_size);
}

void test_HEADERSCHECK_long_value_is_cut_at_a_whole_character(void)
{
  char value[499 + 3 + 1 + 1];
  memset(value, 'a', 499);
  memcpy(value + 499, "\xe2\x82\xac", 3);
  value[502] = '\0';
  char shown_500[sizeof(value)];
  memcpy(shown_500, value, sizeof(value));
  static char golden[4096];

  char* body = static_HEADERSCHECKPermissionsBody(value, false);
  static_HEADERSCHECKPermissionsGolden(shown_500, "", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);

  value[502] = 'b';
  value[503] = '\0';
  body = static_HEADERSCHECKPermissionsBody(value, false);
  static_HEADERSCHECKPermissionsGolden(shown_500, R"x(,"total_value_length":501)x", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);

  body = static_HEADERSCHECKPermissionsBody(value, true);
  static_HEADERSCHECKPermissionsGolden(value, "", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);
}

static void static_HEADERSCHECKUrlGolden(const char* shown_url, const char* url_total_member, const char* shown_redirect_to, const char* redirect_to_total_member, char* golden_out, size_t golden_size)
{
  int written = snprintf(golden_out, golden_size,
    R"x({"url":"%s"%s,"status_code":301,"redirect_count":0,"redirect_to":"%s"%s,"checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":)x"
    HEADERSCHECK_ALL_MISSING_FINDINGS
    R"x(,{"header":"Permissions-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())"})x"
    R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":null})x" HEADERSCHECK_NO_COOKIE_NO_CORS_FINDINGS R"x(]})x" "\n",
    shown_url, url_total_member, shown_redirect_to, redirect_to_total_member);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < golden_size);
}

void test_HEADERSCHECK_long_url_and_redirect_target_are_cut_at_a_whole_character(void)
{
  char url[20 + 479 + 3 + 1 + 1];
  memcpy(url, "https://example.com/", 20);
  memset(url + 20, 'a', 479);
  memcpy(url + 499, "\xe2\x82\xac", 3);
  url[502] = 'c';
  url[503] = '\0';
  char shown_url[sizeof(url)];
  memcpy(shown_url, url, 502);
  shown_url[502] = '\0';

  char redirect_to[600 + 1];
  memcpy(redirect_to, "https://other.example/", 22);
  memset(redirect_to + 22, 'b', 600 - 22);
  redirect_to[600] = '\0';
  char shown_redirect_to[500 + 1];
  memcpy(shown_redirect_to, redirect_to, 500);
  shown_redirect_to[500] = '\0';

  char* const values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  static char golden[4096];

  char* body = static_HEADERSCHECKBody(url, 301, 0, redirect_to, values, 0, false);
  static_HEADERSCHECKUrlGolden(shown_url, R"x(,"total_url_length":501)x", shown_redirect_to, R"x(,"total_redirect_to_length":600)x", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);

  body = static_HEADERSCHECKBody(url, 301, 0, redirect_to, values, 0, true);
  static_HEADERSCHECKUrlGolden(url, "", redirect_to, "", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);

  url[502]         = '\0';
  redirect_to[500] = '\0';
  body = static_HEADERSCHECKBody(url, 301, 0, redirect_to, values, 0, false);
  static_HEADERSCHECKUrlGolden(url, "", redirect_to, "", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);
}

void test_HEADERSCHECK_value_is_escaped(void)
{
  char value[] = "a\"b\\c\x01" "d\xff" "e\xe2\x80\xae" "f";
  static char golden[4096];
  char* body = static_HEADERSCHECKPermissionsBody(value, false);
  static_HEADERSCHECKPermissionsGolden("a\\\"b\\\\c\\" "u0001d\xef\xbf\xbd" "e\\" "u202ef", "", golden, sizeof(golden));
  TEST_ASSERT_EQUAL_STRING(golden, body);
  free(body);
}

void test_HEADERSCHECK_set_cookie_value_is_never_written(void)
{
  char set_cookie[]        = "sid=SECRETTOKEN; Secure; SameSite=Lax\nlogin=SECRETTOKEN";
  char allow_origin[]      = "*";
  char allow_credentials[] = "true";
  char* values[HEADER_CHECK_HEADER_COUNT] = { NULL };
  values[HEADER_CHECK_HEADER_SET_COOKIE]                       = set_cookie;
  values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]      = allow_origin;
  values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = allow_credentials;
  const bool full_value_choices[] = { true, false };
  for (size_t i = 0; i < sizeof(full_value_choices) / sizeof(full_value_choices[0]); i++)
  {
    char* body = static_HEADERSCHECKBody("https://example.org/", 200, 0, NULL, values, 60, full_value_choices[i]);
    TEST_ASSERT_EQUAL_STRING(
      R"x({"url":"https://example.org/","status_code":200,"redirect_count":0,"checked_at":")x" HEADERSCHECK_FIX_CHECKED_AT R"x(","findings":)x"
      HEADERSCHECK_ALL_MISSING_FINDINGS
      R"x(,{"header":"Permissions-Policy","severity":"low","result":"missing","issues":[],"value":null,"remediation":"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())"})x"
      R"x(,{"header":"X-XSS-Protection","severity":"low","result":"pass","issues":[],"value":null})x"
      R"x(,{"header":"Set-Cookie","severity":"medium","result":"fail","issues":["Cookies with no Secure attribute: 1","Session or login cookies with no HttpOnly attribute: 1","Cookies not checked: 58"],"value":null,"cookie_count":60,"remediation":"Mark every cookie Secure with SameSite=Lax or Strict, and mark session cookies HttpOnly"})x"
      R"x(,{"header":"Access-Control-Allow-Origin","severity":"low","result":"warn","issues":["Allowing credentials with the origin * is an error; browsers refuse * for a request with credentials"],"value":"*","remediation":"Send Access-Control-Allow-Origin with one trusted origin; never null, and never * with credentials"}]})x" "\n", body);
    TEST_ASSERT_NULL(strstr(body, "SECRETTOKEN"));
    free(body);
  }
}

#define WHOISLOOKUP_FIX_SERVER "https://rdap.fixture.test/rdap/"

#define WHOISLOOKUP_FIX_HEAD R"({"domain":"example.org","available":true,"rdap_server":")" WHOISLOOKUP_FIX_SERVER R"(","whois_server":null,)"

static void static_fillWHOISLOOKUPRecord(WHOISLOOKUPRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  RdapRegistration_t* registration = &record->m_registration;
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "example.org");
  record->mp_rdapServerBaseUrl = WHOISLOOKUP_FIX_SERVER;
  record->m_unavailableReason  = WHOISLOOKUP_UNAVAILABLE_NONE;
  snprintf(registration->ma_registrarName, sizeof(registration->ma_registrarName), "%s", "Fixture Registrar GmbH");
  registration->m_registrarIanaId = 146;
  snprintf(registration->ma_createdAt, sizeof(registration->ma_createdAt), "%s", "1995-08-14T04:00:00Z");
  snprintf(registration->ma_updatedAt, sizeof(registration->ma_updatedAt), "%s", "2024-08-14T07:01:34Z");
  snprintf(registration->ma_expiresAt, sizeof(registration->ma_expiresAt), "%s", "2026-08-13T04:00:00Z");
  snprintf(registration->ma_statuses[0], sizeof(registration->ma_statuses[0]), "%s", "client delete prohibited");
  snprintf(registration->ma_statuses[1], sizeof(registration->ma_statuses[1]), "%s", "client transfer prohibited");
  snprintf(registration->ma_statuses[2], sizeof(registration->ma_statuses[2]), "%s", "client update prohibited");
  snprintf(registration->ma_statuses[3], sizeof(registration->ma_statuses[3]), "%s", "server hold");
  registration->m_statusCount = 3;
  snprintf(registration->ma_nameServers[0], sizeof(registration->ma_nameServers[0]), "%s", "a0.fixture-dns.test");
  snprintf(registration->ma_nameServers[1], sizeof(registration->ma_nameServers[1]), "%s", "b0.fixture-dns.test");
  snprintf(registration->ma_nameServers[2], sizeof(registration->ma_nameServers[2]), "%s", "c0.fixture-dns.test");
  registration->m_nameServerCount  = 2;
  registration->m_delegationSigned = RDAP_DELEGATION_SIGNED_NO;
}

static char* static_WHOISLOOKUPBody(const WHOISLOOKUPRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_WHOISLOOKUP_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_WHOISLOOKUP_full_registration_golden(void)
{
  static WHOISLOOKUPRecord_t record;
  static_fillWHOISLOOKUPRecord(&record);
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    WHOISLOOKUP_FIX_HEAD
    R"("registrar_name":"Fixture Registrar GmbH","registrar_iana_id":146,)"
    R"("created_at":"1995-08-14T04:00:00Z","updated_at":"2024-08-14T07:01:34Z","expires_at":"2026-08-13T04:00:00Z",)"
    R"("status":["client delete prohibited","client transfer prohibited","client update prohibited"],"status_count":3,)"
    R"("name_servers":["a0.fixture-dns.test","b0.fixture-dns.test"],"name_server_count":2,)"
    R"("dnssec_signed":false})" "\n", body);
  free(body);
}

void test_WHOISLOOKUP_empty_texts_and_missing_iana_id_are_null_golden(void)
{
  static WHOISLOOKUPRecord_t record;
  static_fillWHOISLOOKUPRecord(&record);
  RdapRegistration_t* registration = &record.m_registration;
  registration->ma_registrarName[0] = '\0';
  registration->ma_createdAt[0]     = '\0';
  registration->ma_updatedAt[0]     = '\0';
  registration->ma_expiresAt[0]     = '\0';
  registration->m_registrarIanaId   = -1;
  registration->m_statusCount       = 0;
  registration->m_nameServerCount   = 0;
  registration->m_delegationSigned  = RDAP_DELEGATION_SIGNED_UNKNOWN;
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    WHOISLOOKUP_FIX_HEAD
    R"("registrar_name":null,"registrar_iana_id":null,"created_at":null,"updated_at":null,"expires_at":null,)"
    R"("status":[],"status_count":0,"name_servers":[],"name_server_count":0,"dnssec_signed":null})" "\n", body);
  free(body);
}

void test_WHOISLOOKUP_dnssec_signed_true_false_null_and_iana_id_zero(void)
{
  static const struct { RdapDelegationSigned_t m_signed; const char* mp_text; } cases[] = {
    { RDAP_DELEGATION_SIGNED_YES,     "true"  },
    { RDAP_DELEGATION_SIGNED_NO,      "false" },
    { RDAP_DELEGATION_SIGNED_UNKNOWN, "null"  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static WHOISLOOKUPRecord_t record;
    static_fillWHOISLOOKUPRecord(&record);
    record.m_registration.m_registrarIanaId  = 0;
    record.m_registration.m_delegationSigned = cases[i].m_signed;
    char expected[1024];
    int written = snprintf(expected, sizeof(expected), "%s%s%s}\n",
      WHOISLOOKUP_FIX_HEAD
      R"("registrar_name":"Fixture Registrar GmbH","registrar_iana_id":0,)"
      R"("created_at":"1995-08-14T04:00:00Z","updated_at":"2024-08-14T07:01:34Z","expires_at":"2026-08-13T04:00:00Z",)"
      R"("status":["client delete prohibited","client transfer prohibited","client update prohibited"],"status_count":3,)"
      R"("name_servers":["a0.fixture-dns.test","b0.fixture-dns.test"],"name_server_count":2,)",
      R"("dnssec_signed":)", cases[i].mp_text);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected));
    char* body = static_WHOISLOOKUPBody(&record);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, body, cases[i].mp_text);
    free(body);
  }
}

void test_WHOISLOOKUP_lists_stop_at_their_max_and_count_all(void)
{
  TEST_ASSERT_EQUAL_INT(16, RDAP_STATUS_MAX_COUNT);
  TEST_ASSERT_EQUAL_INT(16, RDAP_NAME_SERVER_MAX_COUNT);
  static WHOISLOOKUPRecord_t record;
  static_fillWHOISLOOKUPRecord(&record);
  RdapRegistration_t* registration = &record.m_registration;
  static char expected[8192];
  size_t used = (size_t)snprintf(expected, sizeof(expected), "%s",
    WHOISLOOKUP_FIX_HEAD
    R"("registrar_name":"Fixture Registrar GmbH","registrar_iana_id":146,)"
    R"("created_at":"1995-08-14T04:00:00Z","updated_at":"2024-08-14T07:01:34Z","expires_at":"2026-08-13T04:00:00Z","status":[)");
  for (int i = 0; i < RDAP_STATUS_MAX_COUNT; i++)
  {
    snprintf(registration->ma_statuses[i], sizeof(registration->ma_statuses[i]), "status %02d", i + 1);
    used += (size_t)snprintf(expected + used, sizeof(expected) - used, "%s\"status %02d\"", i > 0 ? "," : "", i + 1);
  }
  used += (size_t)snprintf(expected + used, sizeof(expected) - used, "%s", R"(],"status_count":20,"name_servers":[)");
  for (int i = 0; i < RDAP_NAME_SERVER_MAX_COUNT; i++)
  {
    snprintf(registration->ma_nameServers[i], sizeof(registration->ma_nameServers[i]), "ns%02d.fixture-dns.test", i + 1);
    used += (size_t)snprintf(expected + used, sizeof(expected) - used, "%s\"ns%02d.fixture-dns.test\"", i > 0 ? "," : "", i + 1);
  }
  used += (size_t)snprintf(expected + used, sizeof(expected) - used, "%s", R"(],"name_server_count":17,"dnssec_signed":false})" "\n");
  TEST_ASSERT_TRUE(used < sizeof(expected));
  registration->m_statusCount     = RDAP_STATUS_MAX_COUNT + 4;
  registration->m_nameServerCount = RDAP_NAME_SERVER_MAX_COUNT + 1;
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(expected, body);
  free(body);
}

void test_WHOISLOOKUP_texts_from_the_server_are_escaped(void)
{
  static WHOISLOOKUPRecord_t record;
  static_fillWHOISLOOKUPRecord(&record);
  RdapRegistration_t* registration = &record.m_registration;
  snprintf(registration->ma_registrarName, sizeof(registration->ma_registrarName), "%s", "Q\"uote\\Back\tTab\x1f" "End");
  snprintf(registration->ma_statuses[0], sizeof(registration->ma_statuses[0]), "%s", "pending \"delete\"");
  snprintf(registration->ma_createdAt, sizeof(registration->ma_createdAt), "%s", "1995\xe2\x80\xae" "08");
  snprintf(registration->ma_nameServers[0], sizeof(registration->ma_nameServers[0]), "%s", "a0\\fixture-dns.test");
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    WHOISLOOKUP_FIX_HEAD
    "\"registrar_name\":\"Q\\\"uote\\\\Back\\tTab\\u001fEnd\",\"registrar_iana_id\":146,"
    "\"created_at\":\"1995\\u202e08\",\"updated_at\":\"2024-08-14T07:01:34Z\",\"expires_at\":\"2026-08-13T04:00:00Z\","
    "\"status\":[\"pending \\\"delete\\\"\",\"client transfer prohibited\",\"client update prohibited\"],\"status_count\":3,"
    "\"name_servers\":[\"a0\\\\fixture-dns.test\",\"b0.fixture-dns.test\"],\"name_server_count\":2,"
    "\"dnssec_signed\":false}\n", body);
  free(body);
}

void test_WHOISLOOKUP_each_unavailable_reason_golden(void)
{
  static WHOISLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "example.org");
  record.mp_rdapServerBaseUrl = NULL;
  record.m_unavailableReason  = WHOISLOOKUP_UNAVAILABLE_NO_REGISTRY_SERVER;
  record.m_retryAfterSeconds  = 23;
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"example.org","available":false,"reason":"no_registry_server","retry_after_seconds":null})" "\n", body);
  free(body);

  static_fillWHOISLOOKUPRecord(&record);
  record.m_unavailableReason = WHOISLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
  record.m_retryAfterSeconds = 17;
  body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"example.org","available":false,"reason":"quota_exhausted","retry_after_seconds":17})" "\n", body);
  free(body);
}

void test_WHOISLOOKUP_answer_from_a_whois_server_golden(void)
{
  static WHOISLOOKUPRecord_t record;
  static_fillWHOISLOOKUPRecord(&record);
  record.mp_rdapServerBaseUrl = NULL;
  record.mp_whoisServerHost   = "whois.fixture.test";
  char* body = static_WHOISLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","available":true,"rdap_server":null,"whois_server":"whois.fixture.test",)"
    R"("registrar_name":"Fixture Registrar GmbH","registrar_iana_id":146,)"
    R"("created_at":"1995-08-14T04:00:00Z","updated_at":"2024-08-14T07:01:34Z","expires_at":"2026-08-13T04:00:00Z",)"
    R"("status":["client delete prohibited","client transfer prohibited","client update prohibited"],"status_count":3,)"
    R"("name_servers":["a0.fixture-dns.test","b0.fixture-dns.test"],"name_server_count":2,)"
    R"("dnssec_signed":false})" "\n", body);
  free(body);
}

static void static_setWAYBACKLOOKUPCapture(WaybackCapture_t* capture, const char* timestamp, int http_status, const char* media_type)
{
  snprintf(capture->ma_timestamp, sizeof(capture->ma_timestamp), "%s", timestamp);
  capture->m_httpStatus = http_status;
  snprintf(capture->ma_mediaType, sizeof(capture->ma_mediaType), "%s", media_type);
}

static void static_fillWAYBACKLOOKUPRecord(WAYBACKLOOKUPRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "web.example.net");
  record->m_unavailableReason = WAYBACKLOOKUP_UNAVAILABLE_NONE;
  static_setWAYBACKLOOKUPCapture(&record->ma_latestCaptures[0], "20251107091523", 200, "text/html");
  static_setWAYBACKLOOKUPCapture(&record->ma_latestCaptures[1], "20230214234759", 0, "application/xhtml+xml");
  static_setWAYBACKLOOKUPCapture(&record->ma_latestCaptures[2], "20210630120001", 302, "");
  static_setWAYBACKLOOKUPCapture(&record->ma_latestCaptures[3], "20200101000000", 418, "image/webp");
  record->m_latestCaptureCount = 3;
  static_setWAYBACKLOOKUPCapture(&record->m_firstCapture, "19990418061210", 404, "text/plain");
}

static char* static_WAYBACKLOOKUPBody(const WAYBACKLOOKUPRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_WAYBACKLOOKUP_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_WAYBACKLOOKUP_three_captures_golden(void)
{
  static WAYBACKLOOKUPRecord_t record;
  static_fillWAYBACKLOOKUPRecord(&record);
  char* body = static_WAYBACKLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"web.example.net","available":true,"first_seen":"1999-04-18","last_seen":"2025-11-07","years_online":26,"latest_captures":[)"
    R"({"captured_at":"2025-11-07T09:15:23Z","http_status":200,"media_type":"text/html","url":"https://web.archive.org/web/20251107091523/web.example.net"})"
    R"(,{"captured_at":"2023-02-14T23:47:59Z","http_status":null,"media_type":"application/xhtml+xml","url":"https://web.archive.org/web/20230214234759/web.example.net"})"
    R"(,{"captured_at":"2021-06-30T12:00:01Z","http_status":302,"media_type":null,"url":"https://web.archive.org/web/20210630120001/web.example.net"})"
    R"(],"archive_url":"https://web.archive.org/web/*/web.example.net"})" "\n", body);
  free(body);
}

void test_WAYBACKLOOKUP_years_online_is_the_year_difference_at_least_one(void)
{
  static const struct { const char* mp_firstTimestamp; const char* mp_members; } cases[] = {
    { "20240101000000", R"("first_seen":"2024-01-01","last_seen":"2024-12-31","years_online":1,"latest_captures":[)" },
    { "20231130111111", R"("first_seen":"2023-11-30","last_seen":"2024-12-31","years_online":1,"latest_captures":[)" },
    { "20220228222222", R"("first_seen":"2022-02-28","last_seen":"2024-12-31","years_online":2,"latest_captures":[)" },
    { "20000315033333", R"("first_seen":"2000-03-15","last_seen":"2024-12-31","years_online":24,"latest_captures":[)" },
  };
  static WAYBACKLOOKUPRecord_t record;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_fillWAYBACKLOOKUPRecord(&record);
    static_setWAYBACKLOOKUPCapture(&record.ma_latestCaptures[0], "20241231235958", 200, "text/html");
    static_setWAYBACKLOOKUPCapture(&record.m_firstCapture, cases[i].mp_firstTimestamp, 404, "text/plain");
    char* body = static_WAYBACKLOOKUPBody(&record);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_members), cases[i].mp_members);
    free(body);
  }
}

void test_WAYBACKLOOKUP_one_capture_is_the_first_and_the_last_day(void)
{
  static WAYBACKLOOKUPRecord_t record;
  static_fillWAYBACKLOOKUPRecord(&record);
  record.m_latestCaptureCount = 1;
  static_setWAYBACKLOOKUPCapture(&record.m_firstCapture, "20251107091523", 200, "text/html");
  char* body = static_WAYBACKLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    "{\"domain\":\"web.example.net\",\"available\":true,\"first_seen\":\"2025-11-07\",\"last_seen\":\"2025-11-07\","
    "\"years_online\":1,\"latest_captures\":[{\"captured_at\":\"2025-11-07T09:15:23Z\",\"http_status\":200,"
    "\"media_type\":\"text/html\",\"url\":\"https://web.archive.org/web/20251107091523/web.example.net\"}],"
    "\"archive_url\":\"https://web.archive.org/web/*/web.example.net\"}\n", body);
  free(body);
}

void test_WAYBACKLOOKUP_host_without_a_capture_golden(void)
{
  static WAYBACKLOOKUPRecord_t record;
  static_fillWAYBACKLOOKUPRecord(&record);
  record.m_latestCaptureCount = 0;
  char* body = static_WAYBACKLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"web.example.net","available":true,"first_seen":null,"last_seen":null,"years_online":null,"latest_captures":[)"
    R"(],"archive_url":"https://web.archive.org/web/*/web.example.net"})" "\n", body);
  free(body);
}

void test_WAYBACKLOOKUP_quota_exhausted_golden(void)
{
  static WAYBACKLOOKUPRecord_t record;
  static_fillWAYBACKLOOKUPRecord(&record);
  record.m_unavailableReason = WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
  record.m_retryAfterSeconds = 45;
  char* body = static_WAYBACKLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"web.example.net","available":false,"reason":"quota_exhausted","retry_after_seconds":45})" "\n", body);
  free(body);
}

static void static_setCERTSEARCHCertificate(CertSpotterCertificate_t* certificate, const char* sha256_fingerprint, const char* issuer, const char* valid_from, const char* valid_until, CertSpotterRevocation_t revocation)
{
  memset(certificate, 0, sizeof(*certificate));
  snprintf(certificate->ma_sha256Hex, sizeof(certificate->ma_sha256Hex), "%s", sha256_fingerprint);
  snprintf(certificate->ma_issuer, sizeof(certificate->ma_issuer), "%s", issuer);
  snprintf(certificate->ma_validFrom, sizeof(certificate->ma_validFrom), "%s", valid_from);
  snprintf(certificate->ma_validUntil, sizeof(certificate->ma_validUntil), "%s", valid_until);
  certificate->m_revocation = revocation;
}

static void static_fillCERTSEARCHRecord(CERTSEARCHRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "certs.example.org");
  record->m_unavailableReason           = CERTSEARCH_UNAVAILABLE_NONE;
  record->m_certificateList.m_readCount = 41;

  CertSpotterCertificate_t* first = &record->m_certificateList.ma_certificates[0];
  static_setCERTSEARCHCertificate(first, "1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988", "Fixture Issuing CA 7",
                                  "2025-01-02T03:04:05Z", "2025-06-07T08:09:10Z", CERTSPOTTER_REVOCATION_NOT_REVOKED);
  first->m_isCaaDomainListKnown = true;
  snprintf(first->ma_caaDomains[0], sizeof(first->ma_caaDomains[0]), "%s", "caa-one.example");
  snprintf(first->ma_caaDomains[1], sizeof(first->ma_caaDomains[1]), "%s", "caa-two.example");
  snprintf(first->ma_caaDomains[2], sizeof(first->ma_caaDomains[2]), "%s", "caa-three.example");
  snprintf(first->ma_caaDomains[3], sizeof(first->ma_caaDomains[3]), "%s", "caa-four.example");
  first->m_caaDomainCount = 3;
  snprintf(first->ma_dnsNames[0], sizeof(first->ma_dnsNames[0]), "%s", "a.certs.example.org");
  snprintf(first->ma_dnsNames[1], sizeof(first->ma_dnsNames[1]), "%s", "b.certs.example.org");
  snprintf(first->ma_dnsNames[2], sizeof(first->ma_dnsNames[2]), "%s", "c.certs.example.org");
  snprintf(first->ma_dnsNames[3], sizeof(first->ma_dnsNames[3]), "%s", "d.certs.example.org");
  first->m_dnsNameCount = 3;

  CertSpotterCertificate_t* second = &record->m_certificateList.ma_certificates[1];
  static_setCERTSEARCHCertificate(second, "9a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f3021", "Second Root R9",
                                  "2024-11-12T13:14:15Z", "2026-02-17T18:19:20Z", CERTSPOTTER_REVOCATION_REVOKED);
  second->m_isCaaDomainListKnown = true;
  second->m_caaDomainCount       = 0;
  snprintf(second->ma_dnsNames[0], sizeof(second->ma_dnsNames[0]), "%s", "certs.example.org");
  second->m_dnsNameCount = 1;

  static_setCERTSEARCHCertificate(&record->m_certificateList.ma_certificates[2], "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "Past The Count CA",
                                  "2023-03-03T03:03:03Z", "2023-04-04T04:04:04Z", CERTSPOTTER_REVOCATION_REVOKED);
  record->m_certificateList.m_keptCount = 2;
}

static char* static_CERTSEARCHBody(const CERTSEARCHRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CERTSEARCH_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_CERTSEARCH_two_certificates_golden(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"certs.example.org","available":true,"complete":false,"certificate_count":41,"certificates":[)"
    R"({"sha256_fingerprint":"1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988","issuer":"Fixture Issuing CA 7",)"
    R"("issuer_caa_domains":["caa-one.example","caa-two.example","caa-three.example"],)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)"
    R"("dns_names":["a.certs.example.org","b.certs.example.org","c.certs.example.org"],"dns_name_count":3})"
    R"(,{"sha256_fingerprint":"9a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f3021","issuer":"Second Root R9",)"
    R"("issuer_caa_domains":[],"valid_from":"2024-11-12T13:14:15Z","valid_until":"2026-02-17T18:19:20Z","revoked":true,)"
    R"("dns_names":["certs.example.org"],"dns_name_count":1})"
    R"(]})" "\n", body);
  free(body);
}

void test_CERTSEARCH_complete_walk_of_many_pages_golden(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_certificateList.m_readCount   = 437;
  record.m_certificateList.m_isComplete  = true;
  record.m_certificateList.m_issuerCount = 1;
  snprintf(record.m_certificateList.ma_issuers[0].ma_key, sizeof(record.m_certificateList.ma_issuers[0].ma_key), "%s", "issuer-set.example");
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"certs.example.org","available":true,"complete":true,"certificate_count":437,"certificates":[)"
    R"({"sha256_fingerprint":"1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988","issuer":"Fixture Issuing CA 7",)"
    R"("issuer_caa_domains":["caa-one.example","caa-two.example","caa-three.example"],)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)"
    R"("dns_names":["a.certs.example.org","b.certs.example.org","c.certs.example.org"],"dns_name_count":3})"
    R"(,{"sha256_fingerprint":"9a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f3021","issuer":"Second Root R9",)"
    R"("issuer_caa_domains":[],"valid_from":"2024-11-12T13:14:15Z","valid_until":"2026-02-17T18:19:20Z","revoked":true,)"
    R"("dns_names":["certs.example.org"],"dns_name_count":1})"
    R"(]})" "\n", body);
  free(body);
}

void test_CERTSEARCH_each_unknown_value_is_null(void)
{
  static const char* const head = R"({"domain":"certs.example.org","available":true,"complete":false,"certificate_count":41,"certificates":[)"
                                  R"({"sha256_fingerprint":"1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988",)";
  static const char* const tail = R"("dns_names":["a.certs.example.org","b.certs.example.org","c.certs.example.org"],"dns_name_count":3}]})" "\n";
  static const char* const middles[] = {
    R"("issuer":null,"issuer_caa_domains":["caa-one.example","caa-two.example","caa-three.example"],)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)",
    R"("issuer":"Fixture Issuing CA 7","issuer_caa_domains":null,)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)",
    R"("issuer":"Fixture Issuing CA 7","issuer_caa_domains":["caa-one.example","caa-two.example","caa-three.example"],)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":null,)",
  };
  static CERTSEARCHRecord_t record;
  for (size_t i = 0; i < sizeof(middles) / sizeof(middles[0]); i++)
  {
    static_fillCERTSEARCHRecord(&record);
    record.m_certificateList.m_keptCount = 1;
    CertSpotterCertificate_t* first = &record.m_certificateList.ma_certificates[0];
    if (i == 0)
      first->ma_issuer[0] = '\0';
    if (i == 1)
      first->m_isCaaDomainListKnown = false;
    if (i == 2)
      first->m_revocation = CERTSPOTTER_REVOCATION_UNKNOWN;
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s%s%s", head, middles[i], tail);
    char* body = static_CERTSEARCHBody(&record);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, body, middles[i]);
    free(body);
  }
}

void test_CERTSEARCH_dns_names_stop_at_the_kept_count(void)
{
  static const int counts[] = { 19, 20, 21, 57 };
  static CERTSEARCHRecord_t record;
  for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++)
  {
    static_fillCERTSEARCHRecord(&record);
    record.m_certificateList.m_keptCount = 1;
    CertSpotterCertificate_t* first = &record.m_certificateList.ma_certificates[0];
    for (int k = 0; k < CERTSPOTTER_DNS_NAME_MAX_COUNT; k++)
      snprintf(first->ma_dnsNames[k], sizeof(first->ma_dnsNames[k]), "n%02d.certs.example.org", k + 1);
    first->m_dnsNameCount = counts[i];

    char names[CERTSPOTTER_DNS_NAME_MAX_COUNT * 32] = "";
    size_t used = 0;
    int listed_count = counts[i] < 20 ? counts[i] : 20;
    for (int k = 0; k < listed_count; k++)
      used += (size_t)snprintf(names + used, sizeof(names) - used, "%s\"n%02d.certs.example.org\"", k > 0 ? "," : "", k + 1);
    char expected[2048];
    snprintf(expected, sizeof(expected),
             R"({"domain":"certs.example.org","available":true,"complete":false,"certificate_count":41,"certificates":[)"
             R"({"sha256_fingerprint":"1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988","issuer":"Fixture Issuing CA 7",)"
             R"("issuer_caa_domains":["caa-one.example","caa-two.example","caa-three.example"],)"
             R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)"
             R"("dns_names":[%s],"dns_name_count":%d}]})" "\n", names, counts[i]);
    char label[16];
    snprintf(label, sizeof(label), "count %d", counts[i]);
    char* body = static_CERTSEARCHBody(&record);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, body, label);
    free(body);
  }
}

void test_CERTSEARCH_escapes_the_text_cert_spotter_sends(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_certificateList.m_keptCount = 1;
  CertSpotterCertificate_t* first = &record.m_certificateList.ma_certificates[0];
  snprintf(first->ma_issuer, sizeof(first->ma_issuer), "%s", "Evil \"CA\" \\\x01");
  snprintf(first->ma_caaDomains[0], sizeof(first->ma_caaDomains[0]), "%s", "c\"a\\a\x02");
  first->m_caaDomainCount = 1;
  snprintf(first->ma_dnsNames[0], sizeof(first->ma_dnsNames[0]), "%s", "d\"n\\s\x1f");
  first->m_dnsNameCount = 1;
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"certs.example.org","available":true,"complete":false,"certificate_count":41,"certificates":[)"
    R"({"sha256_fingerprint":"1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988","issuer":"Evil \"CA\" \\\u0001",)"
    R"("issuer_caa_domains":["c\"a\\a\u0002"],)"
    R"("valid_from":"2025-01-02T03:04:05Z","valid_until":"2025-06-07T08:09:10Z","revoked":false,)"
    R"("dns_names":["d\"n\\s\u001f"],"dns_name_count":1}]})" "\n", body);
  free(body);
}

void test_CERTSEARCH_host_without_a_certificate_golden(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_certificateList.m_keptCount     = 0;
  record.m_certificateList.m_readCount     = 0;
  record.m_certificateList.m_isComplete    = true;
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"certs.example.org","available":true,"complete":true,"certificate_count":0,"certificates":[]})" "\n", body);
  free(body);
}

void test_CERTSEARCH_page_of_refused_certificates_is_not_complete(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_certificateList.m_keptCount = 0;
  record.m_certificateList.m_readCount = 0;
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"certs.example.org","available":true,"complete":false,"certificate_count":0,"certificates":[]})" "\n", body);
  free(body);
}

void test_CERTSEARCH_quota_exhausted_golden(void)
{
  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_unavailableReason              = CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED;
  record.m_retryAfterSeconds              = 1234;
  record.m_certificateList.m_isComplete    = true;
  char* body = static_CERTSEARCHBody(&record);
  TEST_ASSERT_EQUAL_STRING(R"({"domain":"certs.example.org","available":false,"reason":"quota_exhausted","retry_after_seconds":1234})" "\n", body);
  free(body);
}

#define SUBDOMAINENUM_TEST_NAME_ROOM (SUBDOMAINENUM_MAX_LISTED_NAME_COUNT + 1)

static char               g_SUBDOMAINENUMNames[SUBDOMAINENUM_TEST_NAME_ROOM][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static unsigned int       g_SUBDOMAINENUMSources[SUBDOMAINENUM_TEST_NAME_ROOM];
static SubdomainNameSet_t g_SUBDOMAINENUMNameSet;

static void static_addSUBDOMAINENUMName(const char* name, unsigned int source)
{
  int index = g_SUBDOMAINENUMNameSet.m_count;
  TEST_ASSERT_TRUE(index < SUBDOMAINENUM_TEST_NAME_ROOM);
  snprintf(g_SUBDOMAINENUMNames[index], sizeof(g_SUBDOMAINENUMNames[index]), "%s", name);
  g_SUBDOMAINENUMSources[index] = source;
  g_SUBDOMAINENUMNameSet.m_count++;
}

static void static_fillSUBDOMAINENUMRecord(SUBDOMAINENUMRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  memset(g_SUBDOMAINENUMNames, 0, sizeof(g_SUBDOMAINENUMNames));
  memset(g_SUBDOMAINENUMSources, 0, sizeof(g_SUBDOMAINENUMSources));
  memset(&g_SUBDOMAINENUMNameSet, 0, sizeof(g_SUBDOMAINENUMNameSet));
  g_SUBDOMAINENUMNameSet.mp_names   = g_SUBDOMAINENUMNames;
  g_SUBDOMAINENUMNameSet.mp_sources = g_SUBDOMAINENUMSources;
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "example.org");
  record->mp_nameSet             = &g_SUBDOMAINENUMNameSet;
  record->m_wildcardDns          = SUBDOMAIN_WILDCARD_ABSENT;
  record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_AVAILABLE;
}

static char* static_SUBDOMAINENUMBody(const SUBDOMAINENUMRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_SUBDOMAINENUM_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_SUBDOMAINENUM_dns_confirmed_names_first_in_strcmp_order_golden(void)
{
  static SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  static_addSUBDOMAINENUMName("zeta.example.org",  SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  static_addSUBDOMAINENUMName("beta.example.org",  SUBDOMAIN_SOURCE_DNS_WORDLIST);
  static_addSUBDOMAINENUMName("alpha.example.org", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS | SUBDOMAIN_SOURCE_DNS_RECORDS);
  static_addSUBDOMAINENUMName("gamma.example.org", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS | SUBDOMAIN_SOURCE_DNS_WORDLIST | SUBDOMAIN_SOURCE_DNS_RECORDS);
  static_addSUBDOMAINENUMName("delta.example.org", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  static_addSUBDOMAINENUMName("mx.example.org",    SUBDOMAIN_SOURCE_DNS_RECORDS);
  char* body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","subdomain_count":6,"subdomains":[)"
    R"({"hostname":"alpha.example.org","sources":["certificate_logs","dns_records"]},)"
    R"({"hostname":"beta.example.org","sources":["dns_wordlist"]},)"
    R"({"hostname":"gamma.example.org","sources":["certificate_logs","dns_wordlist","dns_records"]},)"
    R"({"hostname":"mx.example.org","sources":["dns_records"]},)"
    R"({"hostname":"delta.example.org","sources":["certificate_logs"]},)"
    R"({"hostname":"zeta.example.org","sources":["certificate_logs"]}],)"
    R"("wildcard_dns":"absent","certificate_logs_available":true,"certificate_logs_complete":false})" "\n", body);
  free(body);
}

void test_SUBDOMAINENUM_lists_at_most_fifty_names_and_counts_them_all(void)
{
  static SUBDOMAINENUMRecord_t record;
  static char expected[16384];
  for (int name_count = SUBDOMAINENUM_MAX_LISTED_NAME_COUNT; name_count <= SUBDOMAINENUM_MAX_LISTED_NAME_COUNT + 1; name_count++)
  {
    static_fillSUBDOMAINENUMRecord(&record);
    char name[32];
    for (int i = 0; i < name_count - 1; i++)
    {
      snprintf(name, sizeof(name), "c%02d.example.org", i);
      static_addSUBDOMAINENUMName(name, SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
    }
    static_addSUBDOMAINENUMName("z.example.org", SUBDOMAIN_SOURCE_DNS_WORDLIST);

    int len = snprintf(expected, sizeof(expected),
                       R"({"domain":"example.org","subdomain_count":%d,"subdomains":[{"hostname":"z.example.org","sources":["dns_wordlist"]})", name_count);
    for (int i = 0; i < SUBDOMAINENUM_MAX_LISTED_NAME_COUNT - 1; i++)
      len += snprintf(expected + len, sizeof(expected) - (size_t)len, R"(,{"hostname":"c%02d.example.org","sources":["certificate_logs"]})", i);
    snprintf(expected + len, sizeof(expected) - (size_t)len, R"(],"wildcard_dns":"absent","certificate_logs_available":true,"certificate_logs_complete":false})" "\n");

    char* body = static_SUBDOMAINENUMBody(&record);
    TEST_ASSERT_EQUAL_STRING(expected, body);
    free(body);
  }
}

void test_SUBDOMAINENUM_quota_exhausted_golden(void)
{
  static SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  static_addSUBDOMAINENUMName("www.example.org", SUBDOMAIN_SOURCE_DNS_WORDLIST);
  record.m_certificateLogStatus        = SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED;
  record.m_retryAfterSeconds           = 3127;
  record.m_isCertificateLogAnswerEmpty = true;
  char* body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","subdomain_count":1,"subdomains":[{"hostname":"www.example.org","sources":["dns_wordlist"]}],)"
    R"("wildcard_dns":"absent","certificate_logs_available":false,"certificate_logs_reason":"quota_exhausted","retry_after_seconds":3127})" "\n", body);
  free(body);
}

void test_SUBDOMAINENUM_upstream_error_golden(void)
{
  static SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  static_addSUBDOMAINENUMName("mail.example.org", SUBDOMAIN_SOURCE_DNS_RECORDS);
  record.m_certificateLogStatus        = SUBDOMAINENUM_CERTIFICATE_LOGS_UPSTREAM_ERROR;
  record.m_retryAfterSeconds           = 99;
  record.m_isCertificateLogAnswerEmpty = true;
  char* body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","subdomain_count":1,"subdomains":[{"hostname":"mail.example.org","sources":["dns_records"]}],)"
    R"("wildcard_dns":"absent","certificate_logs_available":false,"certificate_logs_reason":"upstream_error"})" "\n", body);
  free(body);
}

void test_SUBDOMAINENUM_empty_list_golden(void)
{
  static SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  record.m_isCertificateLogAnswerEmpty = true;
  char* body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","subdomain_count":0,"subdomains":[],"wildcard_dns":"absent","certificate_logs_available":true,"certificate_logs_complete":true})" "\n", body);
  free(body);
}

void test_SUBDOMAINENUM_each_wildcard_value(void)
{
  static const struct { SubdomainWildcard_t m_wildcardDns; const char* mp_body; } cases[] = {
    { SUBDOMAIN_WILDCARD_ABSENT,       R"({"domain":"example.org","subdomain_count":0,"subdomains":[],"wildcard_dns":"absent","certificate_logs_available":true,"certificate_logs_complete":false})" "\n" },
    { SUBDOMAIN_WILDCARD_PRESENT,      R"({"domain":"example.org","subdomain_count":0,"subdomains":[],"wildcard_dns":"present","certificate_logs_available":true,"certificate_logs_complete":false})" "\n" },
    { SUBDOMAIN_WILDCARD_UNDETERMINED, R"({"domain":"example.org","subdomain_count":0,"subdomains":[],"wildcard_dns":"undetermined","certificate_logs_available":true,"certificate_logs_complete":false})" "\n" },
  };
  static SUBDOMAINENUMRecord_t record;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_fillSUBDOMAINENUMRecord(&record);
    record.m_wildcardDns = cases[i].m_wildcardDns;
    char* body = static_SUBDOMAINENUMBody(&record);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, body);
    free(body);
  }
}

void test_SUBDOMAINENUM_escapes_a_name(void)
{
  static SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  static_addSUBDOMAINENUMName("q\"x\\y.example.org", SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
  char* body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","subdomain_count":1,"subdomains":[{"hostname":"q\"x\\y.example.org","sources":["certificate_logs"]}],)"
    R"("wildcard_dns":"absent","certificate_logs_available":true,"certificate_logs_complete":false})" "\n", body);
  free(body);
}

#define PRIVACYMYDATA_TEST_HASH "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

#define PRIVACYMYDATA_TEST_MANAGE_URL "https://api.contrastcyber.com/vendor-keys#l=00ff"

#define PRIVACYMYDATA_VENDOR_KEYS_UNKNOWN R"("vendor_keys":{"shodan":{"configured":null},"abuseipdb":{"configured":null},"manage_url":null},)"

static char* static_PRIVACYMYDATAVendorKeysBody(RequestTier_t tier, DbApiKeyExpiry_t key_expiry, const PRIVACYMYDATAVendorKeys_t* vendor_keys, unsigned int limit, int remaining, time_t reset)
{
  RequestCreditBudget_t credit_budget;
  memset(&credit_budget, 0, sizeof(credit_budget));
  memcpy(credit_budget.ma_budgetHash, PRIVACYMYDATA_TEST_HASH, sizeof(PRIVACYMYDATA_TEST_HASH));
  credit_budget.m_tier                      = tier;
  credit_budget.m_keyExpiry                 = key_expiry;
  credit_budget.m_rateLimitInfo.m_limit     = limit;
  credit_budget.m_rateLimitInfo.m_remaining = remaining;
  credit_budget.m_rateLimitInfo.m_reset     = reset;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PRIVACYMYDATA_response(&credit_budget, "00:39:38", vendor_keys, json_buf);
  return static_finishJsonBuf(json_buf);
}

static char* static_PRIVACYMYDATAKeyBody(RequestTier_t tier, DbApiKeyExpiry_t key_expiry, unsigned int limit, int remaining, time_t reset)
{
  const PRIVACYMYDATAVendorKeys_t unknown = { false, false, "" };
  return static_PRIVACYMYDATAVendorKeysBody(tier, key_expiry, tier == REQUEST_TIER_PRO ? &unknown : NULL, limit, remaining, reset);
}

static char* static_PRIVACYMYDATABodyAt(RequestTier_t tier, unsigned int limit, int remaining, time_t reset)
{
  const DbApiKeyExpiry_t no_expiry = { false, 0 };
  return static_PRIVACYMYDATAKeyBody(tier, no_expiry, limit, remaining, reset);
}

static char* static_PRIVACYMYDATABody(RequestTier_t tier, unsigned int limit, int remaining)
{
  return static_PRIVACYMYDATABodyAt(tier, limit, remaining, 1760004000);
}

void test_PRIVACYMYDATA_golden(void)
{
  char* body = static_PRIVACYMYDATABody(REQUEST_TIER_FREE, 30, 29);

  TEST_ASSERT_EQUAL_STRING(
    R"x({"tier":"free",)x"
      R"x("upgrade_url":"https://api.contrastcyber.com/pricing",)x"
      R"x("key_expires_at":null,)x"
      R"x("key_expires_at_utc":null,)x"
      R"x("rate_limit":{"hourly_limit":30,)x"
      R"x("remaining_in_window":29,)x"
      R"x("resets_at":1760004000,)x"
      R"x("resets_at_utc":"2025-10-09T10:00:00Z",)x"
      R"x("resets_in":"00:39:38"},)x"
      R"x("stored":{"metered_by":"ip_hmac",)x"
      R"x("hash":")x" PRIVACYMYDATA_TEST_HASH R"x("},)x"
      R"x("vendor_keys":null,)x"
      R"x("policy":"https://api.contrastcyber.com/privacy"})x" "\n", body);
  free(body);
}

void test_PRIVACYMYDATA_key_credit_budget_is_metered_by_the_key(void)
{
  char* body = static_PRIVACYMYDATABody(REQUEST_TIER_PRO, 500, 499);

  TEST_ASSERT_EQUAL_STRING(
    R"({"tier":"pro","upgrade_url":null,"key_expires_at":null,"key_expires_at_utc":null,"rate_limit":{"hourly_limit":500,"remaining_in_window":499,"resets_at":1760004000,"resets_at_utc":"2025-10-09T10:00:00Z","resets_in":"00:39:38"},)"
    R"("stored":{"metered_by":"key_sha256","hash":")" PRIVACYMYDATA_TEST_HASH R"("},)"
    PRIVACYMYDATA_VENDOR_KEYS_UNKNOWN
    R"("policy":"https://api.contrastcyber.com/privacy"})" "\n", body);
  free(body);
}

static void static_PRIVACYMYDATAVendorKeysMember(const PRIVACYMYDATAVendorKeys_t* vendor_keys, char* member_out, size_t member_size)
{
  const DbApiKeyExpiry_t no_expiry = { false, 0 };
  char* body = static_PRIVACYMYDATAVendorKeysBody(REQUEST_TIER_PRO, no_expiry, vendor_keys, 500, 499, 1760004000);
  const char* start = strstr(body, R"("vendor_keys":)");
  const char* end   = strstr(body, R"(,"policy":)");
  TEST_ASSERT_NOT_NULL_MESSAGE(start, body);
  TEST_ASSERT_NOT_NULL_MESSAGE(end, body);
  TEST_ASSERT_EQUAL_STRING(R"(,"policy":"https://api.contrastcyber.com/privacy"})" "\n", end);
  TEST_ASSERT_TRUE(start < end);
  TEST_ASSERT_TRUE((size_t)(end - start) < member_size);
  memcpy(member_out, start, (size_t)(end - start));
  member_out[end - start] = '\0';
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("metered_by":"key_sha256","hash":")" PRIVACYMYDATA_TEST_HASH R"("},"vendor_keys":)"), body);
  free(body);
}

void test_PRIVACYMYDATA_vendor_keys_golden(void)
{
  char member[512];
  const PRIVACYMYDATAVendorKeys_t shodan_only = { true, false, PRIVACYMYDATA_TEST_MANAGE_URL };
  static_PRIVACYMYDATAVendorKeysMember(&shodan_only, member, sizeof(member));
  TEST_ASSERT_EQUAL_STRING(R"("vendor_keys":{"shodan":{"configured":true},"abuseipdb":{"configured":false},"manage_url":")" PRIVACYMYDATA_TEST_MANAGE_URL R"("})", member);

  const PRIVACYMYDATAVendorKeys_t abuseipdb_only = { false, true, PRIVACYMYDATA_TEST_MANAGE_URL };
  static_PRIVACYMYDATAVendorKeysMember(&abuseipdb_only, member, sizeof(member));
  TEST_ASSERT_EQUAL_STRING(R"("vendor_keys":{"shodan":{"configured":false},"abuseipdb":{"configured":true},"manage_url":")" PRIVACYMYDATA_TEST_MANAGE_URL R"("})", member);
}

void test_PRIVACYMYDATA_vendor_keys_without_a_link_are_null(void)
{
  char member[512];
  const PRIVACYMYDATAVendorKeys_t unknown = { true, true, "" };
  static_PRIVACYMYDATAVendorKeysMember(&unknown, member, sizeof(member));
  TEST_ASSERT_EQUAL_STRING(R"("vendor_keys":{"shodan":{"configured":null},"abuseipdb":{"configured":null},"manage_url":null})", member);
}

void test_PRIVACYMYDATA_no_vendor_keys_is_null(void)
{
  char member[512];
  static_PRIVACYMYDATAVendorKeysMember(NULL, member, sizeof(member));
  TEST_ASSERT_EQUAL_STRING(R"("vendor_keys":null)", member);
}

void test_PRIVACYMYDATA_resets_at_utc_is_the_reset_in_utc(void)
{
  const char* saved_tz = getenv("TZ");
  char saved_tz_copy[64] = "";
  if (saved_tz != NULL)
    snprintf(saved_tz_copy, sizeof(saved_tz_copy), "%s", saved_tz);
  TEST_ASSERT_EQUAL_INT(0, setenv("TZ", "JST-9", 1));
  tzset();

  char* year_end = static_PRIVACYMYDATABodyAt(REQUEST_TIER_FREE, 30, 29, 1767225599);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(year_end, R"("resets_at":1767225599,"resets_at_utc":"2025-12-31T23:59:59Z","resets_in":"00:39:38"},)"), year_end);
  free(year_end);

  char* epoch = static_PRIVACYMYDATABodyAt(REQUEST_TIER_FREE, 30, 29, 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(epoch, R"("resets_at":0,"resets_at_utc":"1970-01-01T00:00:00Z",)"), epoch);
  free(epoch);

  char* apart = static_PRIVACYMYDATABodyAt(REQUEST_TIER_FREE, 30, 29, 1760008496);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(apart, R"("resets_at":1760008496,"resets_at_utc":"2025-10-09T11:14:56Z",)"), apart);
  free(apart);

  if (saved_tz != NULL)
    setenv("TZ", saved_tz_copy, 1);
  else
    unsetenv("TZ");
  tzset();
}

void test_PRIVACYMYDATA_unrepresentable_reset_has_a_null_utc_time(void)
{
  char* body = static_PRIVACYMYDATABodyAt(REQUEST_TIER_FREE, 30, 29, (time_t)LLONG_MAX);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("resets_at_utc":null,"resets_in":"00:39:38"},)"), body);
  free(body);
}

void test_PRIVACYMYDATA_key_expiry_is_null_without_an_expiry(void)
{
  char* free_body = static_PRIVACYMYDATABody(REQUEST_TIER_FREE, 30, 29);
  const char* free_head = R"({"tier":"free","upgrade_url":"https://api.contrastcyber.com/pricing","key_expires_at":null,"key_expires_at_utc":null,"rate_limit":{)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(free_head, free_body, strlen(free_head), free_body);
  free(free_body);

  char* key_body = static_PRIVACYMYDATABody(REQUEST_TIER_PRO, 500, 499);
  const char* key_head = R"({"tier":"pro","upgrade_url":null,"key_expires_at":null,"key_expires_at_utc":null,"rate_limit":{)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(key_head, key_body, strlen(key_head), key_body);
  free(key_body);
}

void test_PRIVACYMYDATA_key_expires_at_names_the_expiry_in_utc(void)
{
  const DbApiKeyExpiry_t expiry_2027 = { true, 1798761600 };
  char* body_2027 = static_PRIVACYMYDATAKeyBody(REQUEST_TIER_PRO, expiry_2027, 500, 499, 1760004000);
  const char* head_2027 =
    R"({"tier":"pro","upgrade_url":null,"key_expires_at":1798761600,"key_expires_at_utc":"2027-01-01T00:00:00Z",)"
    R"("rate_limit":{"hourly_limit":500,"remaining_in_window":499,"resets_at":1760004000,"resets_at_utc":"2025-10-09T10:00:00Z","resets_in":"00:39:38"},)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(head_2027, body_2027, strlen(head_2027), body_2027);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body_2027, PRIVACYMYDATA_VENDOR_KEYS_UNKNOWN R"("policy":"https://api.contrastcyber.com/privacy"})" "\n"), body_2027);
  free(body_2027);

  const DbApiKeyExpiry_t expiry_2100 = { true, 4102444800 };
  char* body_2100 = static_PRIVACYMYDATAKeyBody(REQUEST_TIER_PRO, expiry_2100, 500, 499, 1760004000);
  const char* head_2100 =
    R"({"tier":"pro","upgrade_url":null,"key_expires_at":4102444800,"key_expires_at_utc":"2100-01-01T00:00:00Z",)"
    R"("rate_limit":{"hourly_limit":500,"remaining_in_window":499,"resets_at":1760004000,"resets_at_utc":"2025-10-09T10:00:00Z",)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(head_2100, body_2100, strlen(head_2100), body_2100);
  free(body_2100);
}

void test_PRIVACYMYDATA_unrepresentable_key_expiry_has_a_null_utc_time(void)
{
  const DbApiKeyExpiry_t far_expiry = { true, INT64_MAX };
  char* body = static_PRIVACYMYDATAKeyBody(REQUEST_TIER_PRO, far_expiry, 500, 499, 1760004000);
  const char* head = R"({"tier":"pro","upgrade_url":null,"key_expires_at":9223372036854775807,"key_expires_at_utc":null,"rate_limit":{)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(head, body, strlen(head), body);
  free(body);
}

void test_PRIVACYMYDATA_upgrade_url_is_shown_off_the_pro_tier(void)
{
  TEST_ASSERT_EQUAL_STRING("https://api.contrastcyber.com/pricing", PRICING_PAGE_URL);

  char* free_body = static_PRIVACYMYDATABody(REQUEST_TIER_FREE, 30, 29);
  const char* free_head = R"({"tier":"free","upgrade_url":"https://api.contrastcyber.com/pricing","key_expires_at":)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(free_head, free_body, strlen(free_head), free_body);
  free(free_body);

  char* pro_body = static_PRIVACYMYDATABody(REQUEST_TIER_PRO, 500, 499);
  const char* pro_head = R"({"tier":"pro","upgrade_url":null,"key_expires_at":)";
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(pro_head, pro_body, strlen(pro_head), pro_body);
  free(pro_body);
}

void test_PRIVACYMYDATA_key_expiry_is_written_only_on_the_pro_tier(void)
{
  const DbApiKeyExpiry_t expiry = { true, 1798761600 };
  char* free_body = static_PRIVACYMYDATAKeyBody(REQUEST_TIER_FREE, expiry, 30, 29, 1760004000);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(free_body, R"(,"key_expires_at":null,"key_expires_at_utc":null,"rate_limit":{)"), free_body);
  free(free_body);

  char* pro_body = static_PRIVACYMYDATAKeyBody(REQUEST_TIER_PRO, expiry, 500, 499, 1760004000);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(pro_body, R"(,"key_expires_at":1798761600,"key_expires_at_utc":"2027-01-01T00:00:00Z","rate_limit":{)"), pro_body);
  free(pro_body);
}

void test_WEBHOOK_status_and_APIKEYCLAIM_write_one_member(void)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_WEBHOOK_status_response("ignored", json_buf);
  char* ignored = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"status":"ignored"})" "\n", ignored);
  free(ignored);

  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_WEBHOOK_status_response("duplicate", json_buf);
  char* duplicate = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"status":"duplicate"})" "\n", duplicate);
  free(duplicate);

  const char* key = "contrastapi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb";
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_APIKEYCLAIM_response(key, json_buf);
  char* claim = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"api_key":"contrastapi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb"})" "\n", claim);
  free(claim);
}

static char* static_PASSWORDCHECKBody(uint64_t breach_count)
{
  PASSWORDCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  memcpy(record.ma_hashPrefix, "5BAA6", sizeof("5BAA6"));
  record.m_breachCount = breach_count;

  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_PASSWORDCHECK_response(&record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_PASSWORDCHECK_found_golden(void)
{
  char* body = static_PASSWORDCHECKBody(3861493);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hash_prefix":"5BAA6","found":true,"breach_count":3861493,)"
      R"("summary":"This password has been seen 3,861,493 times in data breaches."})" "\n", body);
  free(body);
}

void test_PASSWORDCHECK_not_found_golden(void)
{
  char* body = static_PASSWORDCHECKBody(0);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hash_prefix":"5BAA6","found":false,"breach_count":0,)"
      R"("summary":"This password has not been found in any known data breaches."})" "\n", body);
  free(body);
}

void test_PASSWORDCHECK_summary_groups_the_count_in_threes(void)
{
  static const struct { uint64_t m_count; const char* mp_summary; } cases[] = {
    { 1,          R"("summary":"This password has been seen once in data breaches.")" },
    { 2,          R"("summary":"This password has been seen 2 times in data breaches.")" },
    { 999,        R"("summary":"This password has been seen 999 times in data breaches.")" },
    { 1000,       R"("summary":"This password has been seen 1,000 times in data breaches.")" },
    { 9999,       R"("summary":"This password has been seen 9,999 times in data breaches.")" },
    { 100000,     R"("summary":"This password has been seen 100,000 times in data breaches.")" },
    { 1000000,    R"("summary":"This password has been seen 1,000,000 times in data breaches.")" },
    { UINT64_MAX, R"("summary":"This password has been seen 18,446,744,073,709,551,615 times in data breaches.")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char* body = static_PASSWORDCHECKBody(cases[i].m_count);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_summary), body);
    free(body);
  }
}

static DnsRecordText_t        DNSLOOKUP_FIX_A[]          = { { (char*)"192.0.2.1", 9 }, { (char*)"10.1.2.3", 8 } };
static DnsRecordText_t        DNSLOOKUP_FIX_AAAA[]       = { { (char*)"2001:db8::1", 11 } };
static DnsMxRecord_t          DNSLOOKUP_FIX_MX[]         = { { 10, (char*)"mx1.example.net" }, { 65535, (char*)"mx2.example.org" } };
static DnsRecordText_t        DNSLOOKUP_FIX_NS[]         = { { (char*)"ns1.example.net", 15 } };
static DnsRecordText_t        DNSLOOKUP_FIX_TXT[]        = { { (char*)"v=spf1 -all", 11 }, { (char*)"a\0b\"c\xff", 6 }, { (char*)"txt-3", 5 } };
static DnsRecordText_t        DNSLOOKUP_FIX_CNAME[]      = { { (char*)"edge.example.net", 16 } };
static DnsSoaRecord_t         DNSLOOKUP_FIX_SOA          = { (char*)"ns1.example.com", (char*)"hostmaster.example.org", 4000000001u };
static DnsCaaRecord_t         DNSLOOKUP_FIX_CAA[]        = {
  { 0,   { (char*)"issue", 5 }, { (char*)"letsencrypt.org", 15 } },
  { 128, { (char*)"iodef", 5 }, { (char*)"mailto:a@b.c\0x", 14 } },
};
static const DnsTxtService_t  DNSLOOKUP_FIX_SERVICES[]   = { { "svc-a", "word-a" }, { "svc-b", "word-b" } };
static const DnsRecordText_t* DNSLOOKUP_FIX_NON_PUBLIC[] = { &DNSLOOKUP_FIX_A[1], &DNSLOOKUP_FIX_AAAA[0] };

static void static_fillDNSLOOKUPRecord(DNSLOOKUPRecord_t* record)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "example.com");
  DnsAnswer_t* answers = record->ma_answers;
  answers[DNS_RECORD_TYPE_A].m_recordCount     = 2;
  answers[DNS_RECORD_TYPE_A].mp_texts          = DNSLOOKUP_FIX_A;
  answers[DNS_RECORD_TYPE_AAAA].m_recordCount  = 1;
  answers[DNS_RECORD_TYPE_AAAA].mp_texts       = DNSLOOKUP_FIX_AAAA;
  answers[DNS_RECORD_TYPE_MX].m_recordCount    = 2;
  answers[DNS_RECORD_TYPE_MX].mp_mxRecords     = DNSLOOKUP_FIX_MX;
  answers[DNS_RECORD_TYPE_NS].m_recordCount    = 1;
  answers[DNS_RECORD_TYPE_NS].mp_texts         = DNSLOOKUP_FIX_NS;
  answers[DNS_RECORD_TYPE_TXT].m_recordCount   = 3;
  answers[DNS_RECORD_TYPE_TXT].mp_texts        = DNSLOOKUP_FIX_TXT;
  answers[DNS_RECORD_TYPE_CNAME].m_recordCount = 1;
  answers[DNS_RECORD_TYPE_CNAME].mp_texts      = DNSLOOKUP_FIX_CNAME;
  answers[DNS_RECORD_TYPE_SOA].m_recordCount   = 1;
  answers[DNS_RECORD_TYPE_SOA].mp_soaRecord    = &DNSLOOKUP_FIX_SOA;
  answers[DNS_RECORD_TYPE_CAA].m_recordCount   = 2;
  answers[DNS_RECORD_TYPE_CAA].mp_caaRecords   = DNSLOOKUP_FIX_CAA;
  record->mp_nonPublicAddresses   = DNSLOOKUP_FIX_NON_PUBLIC;
  record->m_nonPublicAddressCount = 2;
  record->ma_services[0]          = &DNSLOOKUP_FIX_SERVICES[0];
  record->ma_services[1]          = &DNSLOOKUP_FIX_SERVICES[1];
  record->m_serviceCount          = 2;
}

static char* static_DNSLOOKUPBody(const DNSLOOKUPRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_DNSLOOKUP_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_DNSLOOKUP_golden(void)
{
  DNSLOOKUPRecord_t record;
  static_fillDNSLOOKUPRecord(&record);
  char* body = static_DNSLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.com","records":{"a":["192.0.2.1","10.1.2.3"],"aaaa":["2001:db8::1"],)"
    R"("mx":[{"priority":10,"host":"mx1.example.net"},{"priority":65535,"host":"mx2.example.org"}],)"
    R"("ns":["ns1.example.net"],"txt":["v=spf1 -all","a\u0000b\"c)" "\xEF\xBF\xBD" R"(","txt-3"],"total_txt_records":3,)"
    R"("cname":["edge.example.net"],"soa":{"mname":"ns1.example.com","rname":"hostmaster.example.org","serial":4000000001},)"
    R"("caa":[{"flags":0,"tag":"issue","value":"letsencrypt.org"},{"flags":128,"tag":"iodef","value":"mailto:a@b.c\u0000x"}]},)"
    R"("unavailable":{},"non_public_addresses":["10.1.2.3","2001:db8::1"],)"
    R"("services":[{"name":"svc-a","evidence":"word-a"},{"name":"svc-b","evidence":"word-b"}],)"
    R"("summary":"2 A, 1 AAAA, 1 NS, 2 MX, 3 TXT, 1 CNAME, 1 SOA, 2 CAA records for example.com"})" "\n", body);
  free(body);
}

void test_DNSLOOKUP_each_failed_status_has_its_reason(void)
{
  static const struct { DnsAnswerStatus_t m_status; const char* mp_reason; } cases[] = {
    { DNS_ANSWER_NXDOMAIN,        "nxdomain" },
    { DNS_ANSWER_SERVER_ERROR,    "server_error" },
    { DNS_ANSWER_TRUNCATED,       "truncated" },
    { DNS_ANSWER_MALFORMED,       "malformed_answer" },
    { DNS_ANSWER_NO_MEMORY,       "no_memory" },
    { DNS_ANSWER_TIMEOUT,         "timeout" },
    { DNS_ANSWER_NO_RESOLVER,     "no_resolver" },
    { DNS_ANSWER_BAD_QUESTION,    "bad_question" },
    { DNS_ANSWER_NOT_PUBLIC_NAME, "not_public_name" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    DNSLOOKUPRecord_t record;
    static_fillDNSLOOKUPRecord(&record);
    record.ma_answers[DNS_RECORD_TYPE_TXT].m_status      = cases[i].m_status;
    record.ma_answers[DNS_RECORD_TYPE_TXT].m_recordCount = 0;
    record.ma_answers[DNS_RECORD_TYPE_TXT].mp_texts      = NULL;
    char* body = static_DNSLOOKUPBody(&record);

    char unavailable[64];
    snprintf(unavailable, sizeof(unavailable), R"("unavailable":{"txt":"%s"},)", cases[i].mp_reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("ns":["ns1.example.net"],"txt":null,"total_txt_records":null,"cname":)"), cases[i].mp_reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, unavailable), cases[i].mp_reason);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("summary":"2 A, 1 AAAA, 1 NS, 2 MX, 1 CNAME, 1 SOA, 2 CAA records for example.com; 1 record type unavailable"})"), cases[i].mp_reason);
    free(body);
  }
}

void test_DNSLOOKUP_two_failed_types(void)
{
  DNSLOOKUPRecord_t record;
  static_fillDNSLOOKUPRecord(&record);
  memset(&record.ma_answers[DNS_RECORD_TYPE_MX], 0, sizeof(DnsAnswer_t));
  memset(&record.ma_answers[DNS_RECORD_TYPE_NS], 0, sizeof(DnsAnswer_t));
  record.ma_answers[DNS_RECORD_TYPE_MX].m_status = DNS_ANSWER_TIMEOUT;
  record.ma_answers[DNS_RECORD_TYPE_NS].m_status = DNS_ANSWER_SERVER_ERROR;
  char* body = static_DNSLOOKUPBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("aaaa":["2001:db8::1"],"mx":null,"ns":null,"txt":)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("unavailable":{"mx":"timeout","ns":"server_error"},)"), body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, R"("summary":"2 A, 1 AAAA, 3 TXT, 1 CNAME, 1 SOA, 2 CAA records for example.com; 2 record types unavailable"})"), body);
  free(body);
}

void test_DNSLOOKUP_no_records_golden(void)
{
  DNSLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "example.org");
  char* body = static_DNSLOOKUPBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.org","records":{"a":[],"aaaa":[],"mx":[],"ns":[],"txt":[],"total_txt_records":0,)"
    R"("cname":[],"soa":null,"caa":[]},"unavailable":{},"non_public_addresses":[],"services":[],)"
    R"("summary":"No records for example.org"})" "\n", body);
  free(body);
}

static const DnsTakeoverSuffix_t DNSTAKEOVERCHECK_FIX_PROVIDER = { "Provider Z", "azurewebsites.net" };

static void static_fillDNSTAKEOVERCHECKRecord(DNSTAKEOVERCHECKRecord_t* record, bool is_target_found)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_hostname, sizeof(record->ma_hostname), "%s", "shop.example.com");
  snprintf(record->ma_hostnameChain[0], sizeof(record->ma_hostnameChain[0]), "%s", "shop-example.azurewebsites.net");
  record->m_hostnameChainLength   = 1;
  record->m_isTargetFound = is_target_found;
  record->mp_matchedSuffix     = &DNSTAKEOVERCHECK_FIX_PROVIDER;
}

static char* static_DNSTAKEOVERCHECKBody(const DNSTAKEOVERCHECKRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_DNSTAKEOVERCHECK_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_DNSTAKEOVERCHECK_dangling_with_provider_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, false);
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"shop-example.azurewebsites.net","chain":["shop-example.azurewebsites.net"],)"
    R"("target_exists":false,"dangling":true,"provider":"Provider Z","takeover_possible":true,)"
    R"("summary":"shop.example.com points to shop-example.azurewebsites.net, which does not exist. )"
    R"(Provider Z lets anyone claim that name, so shop.example.com can be taken over."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_target_found_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, true);
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"shop-example.azurewebsites.net","chain":["shop-example.azurewebsites.net"],)"
    R"("target_exists":true,"dangling":false,"provider":"Provider Z","takeover_possible":false,)"
    R"("summary":"shop.example.com points to shop-example.azurewebsites.net, which exists."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_dangling_without_provider_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, false);
  snprintf(record.ma_hostnameChain[0], sizeof(record.ma_hostnameChain[0]), "%s", "old.example.net");
  record.mp_matchedSuffix = NULL;
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"old.example.net","chain":["old.example.net"],"target_exists":false,)"
    R"("dangling":true,"provider":null,"takeover_possible":null,)"
    R"("summary":"shop.example.com points to old.example.net, which does not exist. )"
    R"(This check knows no service that lets anyone claim that name."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_target_found_without_provider_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, true);
  snprintf(record.ma_hostnameChain[0], sizeof(record.ma_hostnameChain[0]), "%s", "live.example.net");
  record.mp_matchedSuffix = NULL;
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"live.example.net","chain":["live.example.net"],"target_exists":true,)"
    R"("dangling":false,"provider":null,"takeover_possible":null,)"
    R"("summary":"shop.example.com points to live.example.net, which exists."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_chain_of_two_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, false);
  snprintf(record.ma_hostnameChain[0], sizeof(record.ma_hostnameChain[0]), "%s", "a.example.org");
  snprintf(record.ma_hostnameChain[1], sizeof(record.ma_hostnameChain[1]), "%s", "shop-example.azurewebsites.net");
  record.m_hostnameChainLength = 2;
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"a.example.org","chain":["a.example.org","shop-example.azurewebsites.net"],)"
    R"("target_exists":false,"dangling":true,"provider":"Provider Z","takeover_possible":true,)"
    R"("summary":"shop.example.com points through 2 CNAME records to shop-example.azurewebsites.net, which does not exist. )"
    R"(Provider Z lets anyone claim that name, so shop.example.com can be taken over."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_no_cname_golden(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, false);
  record.m_hostnameChainLength = 0;
  record.mp_matchedSuffix   = NULL;
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":null,"chain":[],"target_exists":null,)"
    R"("dangling":false,"provider":null,"takeover_possible":false,)"
    R"("summary":"shop.example.com has no CNAME record, so it has no dangling CNAME."})" "\n", body);
  free(body);
}

void test_DNSTAKEOVERCHECK_cname_is_escaped(void)
{
  DNSTAKEOVERCHECKRecord_t record;
  static_fillDNSTAKEOVERCHECKRecord(&record, true);
  snprintf(record.ma_hostnameChain[0], sizeof(record.ma_hostnameChain[0]), "%s", "a\\\"b.example.net");
  char* body = static_DNSTAKEOVERCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"hostname":"shop.example.com","cname":"a\\\"b.example.net","chain":["a\\\"b.example.net"],"target_exists":true,)"
    R"("dangling":false,"provider":"Provider Z","takeover_possible":false,)"
    R"("summary":"shop.example.com points to a\\\"b.example.net, which exists."})" "\n", body);
  free(body);
}

static char EMAILAUTHCHECK_FIX_SPF[] = "v=spf1 include:_spf.example.net ip4:192.0.2.0/24 exists:x.example.net -all exp=e.example.net";
static char EMAILAUTHCHECK_FIX_OTHER_TXT[] = "google-site-verification=x";
static char EMAILAUTHCHECK_FIX_DMARC[] = "v=DMARC1; p=reject; sp=quarantine; np=none; t=y; psd=n; rua=mailto:a@example.com,https://r.example.net; ruf=mailto:f@example.com";
static char EMAILAUTHCHECK_FIX_MX_1[] = "mx1.example.net";
static char EMAILAUTHCHECK_FIX_MX_2[] = "mx2.example.net";
static char EMAILAUTHCHECK_FIX_RSA[] = "rsa";

static const EmailDataProvider_t EMAILAUTHCHECK_FIX_PROVIDERS[2] = {
  { "Provider A", { "a.example.net" }, { "s1" } },
  { "Provider B", { "b.example.net" }, { NULL } },
};

static EmailAuthSpan_t static_EMAILAUTHCHECKSpan(const char* text, size_t offset, size_t length)
{
  return (EmailAuthSpan_t){ text + offset, length };
}

static void static_fillEMAILAUTHCHECKRecord(EMAILAUTHCHECKRecord_t* record, DnsRecordText_t* texts)
{
  memset(record, 0, sizeof(*record));
  snprintf(record->ma_domain, sizeof(record->ma_domain), "%s", "example.com");

  texts[0] = (DnsRecordText_t){ EMAILAUTHCHECK_FIX_OTHER_TXT, strlen(EMAILAUTHCHECK_FIX_OTHER_TXT) };
  texts[1] = (DnsRecordText_t){ EMAILAUTHCHECK_FIX_SPF, strlen(EMAILAUTHCHECK_FIX_SPF) };
  texts[2] = (DnsRecordText_t){ EMAILAUTHCHECK_FIX_DMARC, strlen(EMAILAUTHCHECK_FIX_DMARC) };
  record->m_spfAnswer      = (DnsAnswer_t){ DNS_ANSWER_OK, 2, texts, NULL, NULL, NULL, false };
  record->m_spfRecordCount = 1;
  record->m_spfRecordIndex = 1;
  record->m_spfRecord.ma_terms[0] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_INCLUDE, EMAILAUTH_QUALIFIER_PASS, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 15, 16), -1, -1 };
  record->m_spfRecord.ma_terms[1] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_IP4, EMAILAUTH_QUALIFIER_NEUTRAL, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 36, 12), 24, -1 };
  record->m_spfRecord.ma_terms[2] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_EXISTS, EMAILAUTH_QUALIFIER_SOFTFAIL, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 56, 13), -1, -1 };
  record->m_spfRecord.ma_terms[3] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_ALL, EMAILAUTH_QUALIFIER_FAIL, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 74, 0), -1, -1 };
  record->m_spfRecord.ma_terms[4] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_EXP, EMAILAUTH_QUALIFIER_PASS, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 79, 13), -1, -1 };
  record->m_spfRecord.m_termCount          = 5;
  record->m_spfRecord.m_dnsLookupTermCount = 3;
  record->m_spfRecord.m_invalidTermCount   = 2;
  record->m_spfRecord.m_unreadTermCount    = 1;

  snprintf(record->ma_dmarcNames[0], sizeof(record->ma_dmarcNames[0]), "%s", "_dmarc.example.com");
  record->ma_dmarcAnswers[0] = (DnsAnswer_t){ DNS_ANSWER_OK, 1, &texts[2], NULL, NULL, NULL, false };
  record->m_dmarcNameCount   = 1;
  record->m_dmarcStatus      = DNS_ANSWER_OK;
  record->m_dmarcSource      = EMAILCHECK_DMARC_SOURCE_DOMAIN;
  EmailAuthDmarc_t* dmarc = &record->m_dmarcRecord;
  dmarc->m_policy                     = EMAILAUTH_DMARC_POLICY_REJECT;
  dmarc->m_subdomainPolicy            = EMAILAUTH_DMARC_POLICY_QUARANTINE;
  dmarc->m_nonexistentSubdomainPolicy = EMAILAUTH_DMARC_POLICY_NONE;
  dmarc->m_testMode                   = EMAILAUTH_DMARC_TEST_MODE_ON;
  dmarc->m_domainRole                 = EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL;
  dmarc->ma_aggregateUris[0].m_uri    = static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_DMARC, 60, 20);
  dmarc->ma_aggregateUris[1].m_uri    = static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_DMARC, 81, 21);
  dmarc->m_aggregateUriCount          = 2;
  dmarc->ma_failureUris[0].m_uri      = static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_DMARC, 108, 20);
  dmarc->m_failureUriCount            = 1;
  record->m_isDmarcApplied     = true;
  record->m_appliedDmarcPolicy = EMAILAUTH_DMARC_POLICY_QUARANTINE;

  static DnsMxRecord_t mx_records[2];
  mx_records[0] = (DnsMxRecord_t){ 10, EMAILAUTHCHECK_FIX_MX_1 };
  mx_records[1] = (DnsMxRecord_t){ 20, EMAILAUTHCHECK_FIX_MX_2 };
  record->m_mxAnswer = (DnsAnswer_t){ DNS_ANSWER_OK, 2, NULL, mx_records, NULL, NULL, true };
  record->ma_mailProviders[0] = &EMAILAUTHCHECK_FIX_PROVIDERS[0];
  record->ma_mailProviders[1] = &EMAILAUTHCHECK_FIX_PROVIDERS[1];
  record->m_mailProviderCount = 2;
  record->m_mtaStsAnswer.m_status = DNS_ANSWER_OK;
  record->m_hasMtaStsRecord       = true;

  snprintf(record->ma_dkimSelectors[0].ma_selector, sizeof(record->ma_dkimSelectors[0].ma_selector), "%s", "google");
  snprintf(record->ma_dkimSelectors[1].ma_selector, sizeof(record->ma_dkimSelectors[1].ma_selector), "%s", "s1");
  record->ma_dkimSelectors[0].m_hasKeyRecord                 = true;
  record->ma_dkimSelectors[0].m_firstKeyRecord.m_keyState    = EMAILAUTH_DKIM_KEY_PRESENT;
  record->ma_dkimSelectors[0].m_firstKeyRecord.m_keyTypeName = static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_RSA, 0, 3);
  record->ma_dkimSelectors[0].m_firstKeyRecord.m_keyBits     = 2048;
  record->ma_dkimSelectors[0].m_firstKeyRecord.m_isTestMode  = true;
  record->m_dkimSelectorCount  = 2;
  record->m_dkimSelectorSource = EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER;
  record->m_dkimStatus         = DNS_ANSWER_OK;
  record->m_dkimKeyStatus      = EMAILCHECK_DKIM_KEY_FOUND;

  const EmailCheckItem_t checks[] = {
    { EMAILCHECK_KIND_SPF_ALL,       EMAILCHECK_RESULT_PASS },
    { EMAILCHECK_KIND_SPF_PTR,       EMAILCHECK_RESULT_WARN },
    { EMAILCHECK_KIND_DMARC_POLICY,  EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_DKIM_KEY_SIZE, EMAILCHECK_RESULT_WARN },
    { EMAILCHECK_KIND_DKIM_KEY_SIZE, EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_SPF_WIDE_RANGE, EMAILCHECK_RESULT_FAIL },
  };
  memcpy(record->ma_checks, checks, sizeof(checks));
  record->m_checkCount = (int)(sizeof(checks) / sizeof(checks[0]));
}

static char* static_EMAILAUTHCHECKBody(const EMAILAUTHCHECKRecord_t* record)
{
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_EMAILAUTHCHECK_response(record, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_EMAILAUTHCHECK_answered_golden(void)
{
  EMAILAUTHCHECKRecord_t record;
  DnsRecordText_t        texts[4];
  static_fillEMAILAUTHCHECKRecord(&record, texts);
  char* body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.com","spf":{"available":true,"record_count":1,"record":"v=spf1 include:_spf.example.net ip4:192.0.2.0/24 exists:x.example.net -all exp=e.example.net",)"
    R"("terms":[{"kind":"include","qualifier":"pass","value":"_spf.example.net"},{"kind":"ip4","qualifier":"neutral","value":"192.0.2.0/24"},)"
    R"({"kind":"exists","qualifier":"softfail","value":"x.example.net"},{"kind":"all","qualifier":"fail","value":null},)"
    R"({"kind":"exp","qualifier":null,"value":"e.example.net"}],)"
    R"("dns_lookup_term_count":3,"invalid_term_count":2,"unread_term_count":1},)"
    R"("dmarc":{"available":true,"record_name":"_dmarc.example.com","source":"domain",)"
    R"("record":"v=DMARC1; p=reject; sp=quarantine; np=none; t=y; psd=n; rua=mailto:a@example.com,https://r.example.net; ruf=mailto:f@example.com",)"
    R"("policy":"reject","subdomain_policy":"quarantine","nonexistent_subdomain_policy":"none","applied_policy":"quarantine",)"
    R"("test_mode":true,"domain_role":"organizational","aggregate_report_uris":["mailto:a@example.com","https://r.example.net"],)"
    R"("failure_report_uris":["mailto:f@example.com"]},)"
    R"("dkim":{"available":true,"key_status":"found","selector_source":"provider","tested_selectors":["google","s1"],)"
    R"("keys":[{"selector":"google","state":"present","key_type":"rsa","key_bits":2048,"test_mode":true}]},)"
    R"("mx":{"available":true,"null_mx":true,"hosts":[{"priority":10,"host":"mx1.example.net"},{"priority":20,"host":"mx2.example.net"}]},)"
    R"("mail_providers":["Provider A","Provider B"],"mta_sts":{"available":true,"record_found":true},)"
    R"("checks":[{"id":"spf_all","result":"pass","severity":"high","detail":"The SPF record's all is -all or ~all, or it has a redirect and no all."},)"
    R"({"id":"spf_ptr","result":"warn","severity":"low","detail":"The SPF record uses ptr. RFC 7208 asks domains not to use it."},)"
    R"({"id":"dmarc_policy","result":"fail","severity":"high","detail":"A policy tag of the DMARC record is not valid and its rua= tag holds no valid address, so receivers apply no DMARC."},)"
    R"({"id":"dkim_key_size","result":"warn","severity":"high","detail":"An rsa key is under 2048 bits or over 4096 bits. Some receivers do not read a key over 4096 bits."},)"
    R"({"id":"dkim_key_size","result":"fail","severity":"high","detail":"An rsa key is under 1024 bits, so receivers must not trust its signatures."},)"
    R"({"id":"spf_wide_range","result":"fail","severity":"high","detail":"A mechanism allows every address, with a prefix length of 0."}],)"
    R"("check_counts":{"pass":1,"warn":2,"fail":3}})" "\n", body);
  free(body);
}

void test_EMAILAUTHCHECK_failed_sections_golden(void)
{
  EMAILAUTHCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "example.com");
  record.m_spfAnswer.m_status    = DNS_ANSWER_TIMEOUT;
  record.m_dmarcStatus           = DNS_ANSWER_SERVER_ERROR;
  record.m_dkimStatus            = DNS_ANSWER_NO_RESOLVER;
  record.m_mxAnswer.m_status     = DNS_ANSWER_MALFORMED;
  record.m_mtaStsAnswer.m_status = DNS_ANSWER_BAD_QUESTION;
  char* body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.com","spf":{"available":false,"reason":"timeout"},"dmarc":{"available":false,"reason":"server_error"},)"
    R"("dkim":{"available":false,"reason":"no_resolver"},"mx":{"available":false,"reason":"malformed_answer"},"mail_providers":[],)"
    R"("mta_sts":{"available":false,"reason":"bad_question"},"checks":[],"check_counts":{"pass":0,"warn":0,"fail":0}})" "\n", body);
  free(body);
}

void test_EMAILAUTHCHECK_inherited_dmarc_and_two_spf_records_golden(void)
{
  EMAILAUTHCHECKRecord_t record;
  DnsRecordText_t        texts[4];
  static_fillEMAILAUTHCHECKRecord(&record, texts);
  static char inherited[] = "v=DMARC1; p=bogus; psd=y";
  texts[3] = (DnsRecordText_t){ inherited, strlen(inherited) };
  record.m_spfRecordCount = 2;
  snprintf(record.ma_dmarcNames[1], sizeof(record.ma_dmarcNames[1]), "%s", "_dmarc.com");
  record.ma_dmarcAnswers[1] = (DnsAnswer_t){ DNS_ANSWER_OK, 1, &texts[3], NULL, NULL, NULL, false };
  record.m_dmarcNameCount   = 2;
  record.m_dmarcSource      = EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX;
  record.m_dmarcNameIndex   = 1;
  memset(&record.m_dmarcRecord, 0, sizeof(record.m_dmarcRecord));
  record.m_dmarcRecord.m_policy     = EMAILAUTH_DMARC_POLICY_INVALID;
  record.m_dmarcRecord.m_domainRole = EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX;
  record.m_isDmarcApplied           = false;
  record.ma_dkimSelectors[0].m_firstKeyRecord.m_keyState = EMAILAUTH_DKIM_KEY_UNREADABLE;
  record.ma_dkimSelectors[0].m_firstKeyRecord.m_keyBits  = 0;
  record.ma_dkimSelectors[1].m_hasKeyRecord                 = true;
  record.ma_dkimSelectors[1].m_firstKeyRecord.m_keyState    = EMAILAUTH_DKIM_KEY_REVOKED;
  record.ma_dkimSelectors[1].m_firstKeyRecord.m_keyTypeName = static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_RSA, 0, 3);
  record.m_mxAnswer           = (DnsAnswer_t){ DNS_ANSWER_NXDOMAIN, 0, NULL, NULL, NULL, NULL, false };
  record.m_mtaStsAnswer.m_status = DNS_ANSWER_NXDOMAIN;
  record.m_hasMtaStsRecord    = false;
  record.m_checkCount         = 0;
  char* body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_EQUAL_STRING(
    R"({"domain":"example.com","spf":{"available":true,"record_count":2,"record":null,"terms":null,"dns_lookup_term_count":null,)"
    R"("invalid_term_count":null,"unread_term_count":null},)"
    R"("dmarc":{"available":true,"record_name":"_dmarc.com","source":"public_suffix","record":"v=DMARC1; p=bogus; psd=y",)"
    R"("policy":"invalid","subdomain_policy":null,"nonexistent_subdomain_policy":null,"applied_policy":null,)"
    R"("test_mode":false,"domain_role":"public_suffix","aggregate_report_uris":[],"failure_report_uris":[]},)"
    R"("dkim":{"available":true,"key_status":"found","selector_source":"provider","tested_selectors":["google","s1"],)"
    R"("keys":[{"selector":"google","state":"unreadable","key_type":"rsa","key_bits":null,"test_mode":true},)"
    R"({"selector":"s1","state":"revoked","key_type":"rsa","key_bits":null,"test_mode":false}]},)"
    R"("mx":{"available":true,"null_mx":false,"hosts":[]},"mail_providers":["Provider A","Provider B"],)"
    R"("mta_sts":{"available":true,"record_found":false},"checks":[],"check_counts":{"pass":0,"warn":0,"fail":0}})" "\n", body);
  free(body);
}

void test_EMAILAUTHCHECK_nxdomain_spf_answer_is_available(void)
{
  EMAILAUTHCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "example.com");
  record.m_spfAnswer.m_status = DNS_ANSWER_NXDOMAIN;
  char* body = static_EMAILAUTHCHECKBody(&record);
  static const char spf[] =
    R"({"domain":"example.com","spf":{"available":true,"record_count":0,"record":null,"terms":null,"dns_lookup_term_count":null,)"
    R"("invalid_term_count":null,"unread_term_count":null},"dmarc":)";
  TEST_ASSERT_EQUAL_STRING_LEN(spf, body, strlen(spf));
  free(body);
}

void test_EMAILAUTHCHECK_every_check_has_its_id_severity_and_sentence(void)
{
  static const struct {
    EmailCheckKind_t m_kind;
    const char*      mp_id;
    const char*      mp_severity;
    bool             ma_hasResult[3];
  } kinds[EMAILCHECK_KIND_COUNT] = {
    { EMAILCHECK_KIND_SPF_RECORD,          "spf_record",          "high",   { true, false, true } },
    { EMAILCHECK_KIND_SPF_SYNTAX,          "spf_syntax",          "high",   { true, false, true } },
    { EMAILCHECK_KIND_SPF_LOOKUP_LIMIT,    "spf_lookup_limit",    "high",   { true, false, true } },
    { EMAILCHECK_KIND_SPF_ALL,             "spf_all",             "high",   { true, true,  true } },
    { EMAILCHECK_KIND_SPF_IGNORED_TERMS,   "spf_ignored_terms",   "low",    { true, true,  false } },
    { EMAILCHECK_KIND_SPF_PTR,             "spf_ptr",             "low",    { true, true,  false } },
    { EMAILCHECK_KIND_SPF_WIDE_RANGE,      "spf_wide_range",      "high",   { true, true,  true } },
    { EMAILCHECK_KIND_SPF_RECORD_SIZE,     "spf_record_size",     "low",    { true, true,  false } },
    { EMAILCHECK_KIND_DMARC_RECORD,        "dmarc_record",        "high",   { true, false, true } },
    { EMAILCHECK_KIND_DMARC_POLICY,        "dmarc_policy",        "high",   { true, true,  true } },
    { EMAILCHECK_KIND_DMARC_TEST_MODE,     "dmarc_test_mode",     "medium", { true, true,  false } },
    { EMAILCHECK_KIND_DMARC_REPORTING,     "dmarc_reporting",     "low",    { true, true,  false } },
    { EMAILCHECK_KIND_DKIM_KEY_FOUND,      "dkim_key_found",      "high",   { true, true,  true } },
    { EMAILCHECK_KIND_DKIM_KEY_USABLE,     "dkim_key_usable",     "high",   { true, true,  true } },
    { EMAILCHECK_KIND_DKIM_KEY_SIZE,       "dkim_key_size",       "high",   { true, true,  true } },
    { EMAILCHECK_KIND_DKIM_KEY_FORMAT,     "dkim_key_format",     "low",    { true, true,  false } },
    { EMAILCHECK_KIND_DKIM_TEST_MODE,      "dkim_test_mode",      "medium", { true, true,  false } },
    { EMAILCHECK_KIND_DKIM_KEY_RESTRICTED, "dkim_key_restricted", "high",   { true, false, true } },
    { EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS,  "dkim_multiple_keys",  "low",    { true, true,  false } },
    { EMAILCHECK_KIND_MX,                  "mx",                  "low",    { true, true,  false } },
    { EMAILCHECK_KIND_MTA_STS,             "mta_sts",             "low",    { true, true,  false } },
  };
  static const char* const result_names[] = { "pass", "warn", "fail" };
  for (int i = 0; i < EMAILCHECK_KIND_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_INT(i, kinds[i].m_kind);
    for (int result = 0; result < 3; result++)
    {
      if (!kinds[i].ma_hasResult[result])
        continue;
      EMAILAUTHCHECKRecord_t record;
      memset(&record, 0, sizeof(record));
      record.ma_checks[0] = (EmailCheckItem_t){ kinds[i].m_kind, (EmailCheckResult_t)result };
      record.m_checkCount = 1;
      char* body = static_EMAILAUTHCHECKBody(&record);
      char  needle[128];
      snprintf(needle, sizeof(needle), R"("checks":[{"id":"%s","result":"%s","severity":"%s","detail":")", kinds[i].mp_id, result_names[result], kinds[i].mp_severity);
      const char* found = strstr(body, needle);
      TEST_ASSERT_NOT_NULL_MESSAGE(found, needle);
      TEST_ASSERT_TRUE_MESSAGE(found[strlen(needle)] >= 'A' && found[strlen(needle)] <= 'Z', needle);
      free(body);
    }
  }
}

void test_EMAILAUTHCHECK_record_bytes_are_escaped(void)
{
  EMAILAUTHCHECKRecord_t record;
  DnsRecordText_t        texts[4];
  static_fillEMAILAUTHCHECKRecord(&record, texts);
  static char spf[] = "v=spf1 a:x\"y\0z -all";
  texts[1] = (DnsRecordText_t){ spf, sizeof(spf) - 1 };
  record.m_spfRecord.ma_terms[0] = (EmailAuthSpfTerm_t){ EMAILAUTH_SPF_TERM_A, EMAILAUTH_QUALIFIER_PASS, static_EMAILAUTHCHECKSpan(spf, 9, 5), -1, -1 };
  record.m_spfRecord.m_termCount = 1;
  char* body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("record":"v=spf1 a:x\"y\u0000z -all","terms":[{"kind":"a","qualifier":"pass","value":"x\"y\u0000z"}])"));
  free(body);
}

void test_EMAILAUTHCHECK_every_name_value_is_written(void)
{
  static const char* const kinds[] = { "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect", "exp", "unknown_modifier", "invalid" };
  const int                kind_count = (int)(sizeof(kinds) / sizeof(kinds[0]));
  EMAILAUTHCHECKRecord_t record;
  DnsRecordText_t        texts[4];
  static_fillEMAILAUTHCHECKRecord(&record, texts);
  for (int k = 0; k < kind_count; k++)
    record.m_spfRecord.ma_terms[k] = (EmailAuthSpfTerm_t){ (EmailAuthSpfTermKind_t)k, EMAILAUTH_QUALIFIER_PASS, static_EMAILAUTHCHECKSpan(EMAILAUTHCHECK_FIX_SPF, 0, 0), -1, -1 };
  record.m_spfRecord.m_termCount    = kind_count;
  record.m_dmarcSource              = EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL;
  record.m_dmarcRecord.m_domainRole = EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX;
  record.m_dkimKeyStatus            = EMAILCHECK_DKIM_KEY_NOT_FOUND;
  record.m_dkimSelectorSource       = EMAILCHECK_DKIM_SELECTOR_SOURCE_CALLER_GIVEN;
  record.ma_dkimSelectors[0].m_firstKeyRecord.m_keyState = EMAILAUTH_DKIM_KEY_UNKNOWN_TYPE;
  char terms[1024];
  size_t used = (size_t)snprintf(terms, sizeof(terms), "%s", R"("terms":[)");
  for (int k = 0; k < kind_count; k++)
    used += (size_t)snprintf(terms + used, sizeof(terms) - used, R"(%s{"kind":"%s","qualifier":%s,"value":null})", k > 0 ? "," : "", kinds[k], k <= EMAILAUTH_SPF_TERM_EXISTS ? "\"pass\"" : "null");
  snprintf(terms + used, sizeof(terms) - used, "]");
  char* body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, terms), terms);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("source":"organizational")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("domain_role":"not_public_suffix")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("key_status":"not_found","selector_source":"given")"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("state":"unknown_type")"));
  free(body);
  record.m_dmarcRecord.m_domainRole = EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID;
  body = static_EMAILAUTHCHECKBody(&record);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("domain_role":"invalid")"));
  free(body);
}

void test_EMAILAUTHCHECK_each_result_writes_its_detail_sentence(void)
{
  static const char* const details[EMAILCHECK_KIND_COUNT][EMAILCHECK_RESULT_COUNT] = {
    { "The domain has one SPF record.", NULL, "The domain has no SPF record, or more than one." },
    { "Every term of the SPF record is valid.", NULL, "A term of the SPF record is not valid, so receivers treat the record as an error." },
    { "The SPF record's own terms make at most 10 DNS lookups. The records of its include and redirect domains are not read.", NULL, "The SPF record makes more than 10 DNS lookups, so receivers treat it as an error." },
    { "The SPF record's all is -all or ~all, or it has a redirect and no all.", "The SPF record's all is ?all, or it has neither all nor redirect, so it does not turn other senders away.", "The SPF record's all is +all, so every sender it does not name passes." },
    { "No mechanism follows all, and no redirect stands next to all.", "A mechanism follows all, or a redirect stands next to all. Receivers ignore that mechanism or redirect.", NULL },
    { "The SPF record has no ptr mechanism.", "The SPF record uses ptr. RFC 7208 asks domains not to use it.", NULL },
    { "No mechanism of the SPF record allows a wide address range.", "A mechanism allows an IPv4 range wider than /16 or an IPv6 range wider than /32.", "A mechanism allows every address, with a prefix length of 0." },
    { "The SPF record is at most 450 bytes.", "The SPF record is longer than 450 bytes, so its answer may not fit a 512-byte UDP message.", NULL },
    { "A DMARC record applies to the domain.", NULL, "No DMARC record applies to the domain, or its own name holds more than one." },
    { "The DMARC policy quarantines or rejects mail that fails.", "The DMARC policy is none, so mail that fails is delivered.", "A policy tag of the DMARC record is not valid and its rua= tag holds no valid address, so receivers apply no DMARC." },
    { "The DMARC record has no t=y, or the policy it applies is not quarantine or reject, so t=y weakens no policy.", "The DMARC record has t=y, so receivers apply none instead of quarantine, or quarantine instead of reject.", NULL },
    { "The DMARC record asks for aggregate reports.", "The rua= tag of the DMARC record holds no valid address, so receivers send no aggregate report.", NULL },
    { "A DKIM selector holds a key record.", "None of the selectors tried holds a key record. The domain may sign with another selector.", "The selector given holds no key record." },
    { "A DKIM key can be read.", "No DKIM key can be read, and one is of a type receivers ignore.", "Every DKIM key is revoked or cannot be read." },
    { "The rsa key of each selector is 2048 to 4096 bits.", "An rsa key is under 2048 bits or over 4096 bits. Some receivers do not read a key over 4096 bits.", "An rsa key is under 1024 bits, so receivers must not trust its signatures." },
    { "No DKIM key is a bare RSAPublicKey or has a negative modulus, and no key record has v=DKIM1 after another tag.", "A key is a bare RSAPublicKey, which OpenDKIM and rspamd do not read, a key's modulus is negative in DER, or a record has v=DKIM1 after another tag.", NULL },
    { "No selector's DKIM key is in test mode.", "A DKIM key has t=y, so receivers treat signed mail like unsigned mail.", NULL },
    { "The DKIM key of each selector may sign mail with sha256.", NULL, "The h= or the s= tag of a DKIM key keeps it from signing mail with sha256." },
    { "No selector holds more than one key record.", "A selector holds more than one key record. The check read the first.", NULL },
    { "The domain has MX hosts, or a null MX that says it takes no mail.", "The domain has no MX record, so senders deliver to its own address.", NULL },
    { "The domain publishes an MTA-STS record.", "The domain publishes no MTA-STS record, or more than one, so senders may deliver its mail without TLS.", NULL }
  };
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
    for (int result = 0; result < EMAILCHECK_RESULT_COUNT; result++)
    {
      if (details[kind][result] == NULL)
        continue;
      EMAILAUTHCHECKRecord_t record;
      memset(&record, 0, sizeof(record));
      record.ma_checks[0] = (EmailCheckItem_t){ (EmailCheckKind_t)kind, (EmailCheckResult_t)result };
      record.m_checkCount = 1;
      char* body = static_EMAILAUTHCHECKBody(&record);
      char needle[512];
      snprintf(needle, sizeof(needle), R"("detail":"%s"})", details[kind][result]);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, needle), needle);
      free(body);
    }
}

static char* static_readDocsFile(const char* path)
{
  FILE* file = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, fseek(file, 0, SEEK_END), path);
  long size = ftell(file);
  TEST_ASSERT_TRUE_MESSAGE(size > 0, path);
  rewind(file);

  char* text = (char*)malloc((size_t)size + 1);
  TEST_ASSERT_NOT_NULL(text);
  size_t read_len = fread(text, 1, (size_t)size, file);
  fclose(file);
  TEST_ASSERT_EQUAL_size_t((size_t)size, read_len);
  text[size] = '\0';
  return text;
}

void test_EMAILAUTHCHECK_docs_checks_table_matches_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
  {
    EMAILAUTHCHECKRecord_t record;
    memset(&record, 0, sizeof(record));
    record.ma_checks[0] = (EmailCheckItem_t){ (EmailCheckKind_t)kind, EMAILCHECK_RESULT_PASS };
    record.m_checkCount = 1;
    char* body = static_EMAILAUTHCHECKBody(&record);
    char id[64], severity[16];
    const char* at = strstr(body, R"("checks":[{"id":")");
    TEST_ASSERT_NOT_NULL(at);
    TEST_ASSERT_EQUAL_INT(2, sscanf(at, R"("checks":[{"id":"%63[^"]","result":"pass","severity":"%15[^"]")", id, severity));
    char row[128];
    snprintf(row, sizeof(row), "| `%s` | %s |", id, severity);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(docs, row), row);
    free(body);
  }
  char common[64];
  snprintf(common, sizeof(common), "tries %d common selectors", EMAILDATA_COMMON_DKIM_SELECTOR_COUNT);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(docs, common), common);
  const struct { EmailAuthDmarcDomainRole_t m_role; const char* mp_letter; } roles[] = {
    { EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX, "y" }, { EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL, "n" }, { EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX, "u" },
  };
  for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++)
  {
    EMAILAUTHCHECKRecord_t record;
    DnsRecordText_t        texts[4];
    static_fillEMAILAUTHCHECKRecord(&record, texts);
    record.m_dmarcRecord.m_domainRole = roles[i].m_role;
    char* body = static_EMAILAUTHCHECKBody(&record);
    char name[32];
    const char* at = strstr(body, R"("domain_role":")");
    TEST_ASSERT_NOT_NULL(at);
    TEST_ASSERT_EQUAL_INT(1, sscanf(at, R"("domain_role":"%31[^"]")", name));
    char phrase[64];
    snprintf(phrase, sizeof(phrase), "`%s` for `%s`", name, roles[i].mp_letter);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(docs, phrase), phrase);
    free(body);
  }
  free(docs);
}

void test_docs_name_each_value_of_takeover_possible(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  const char* row = strstr(docs, "| `takeover_possible` |");
  TEST_ASSERT_NOT_NULL(row);
  const char* row_end = strchr(row, '\n');
  TEST_ASSERT_NOT_NULL(row_end);
  static char lower_row[1024];
  size_t row_len = (size_t)(row_end - row);
  TEST_ASSERT_LESS_THAN_size_t(sizeof(lower_row), row_len);
  for (size_t i = 0; i < row_len; i++)
    lower_row[i] = (row[i] >= 'A' && row[i] <= 'Z') ? (char)(row[i] - 'A' + 'a') : row[i];
  lower_row[row_len] = '\0';
  free(docs);

  static const struct {
    int         m_chainLength;
    bool        m_isTargetFound;
    bool        m_hasProvider;
    const char* mp_tail;
  } cases[] = {
    { 0, false, false, " when `cname` is null" },
    { 1, false, true,  " when `dangling` is true" },
    { 1, true,  true,  " when it is false" },
    { 1, false, false, " when the cname leads to a service the check does not know" },
  };
  char word[16] = "";
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    DNSTAKEOVERCHECKRecord_t record;
    static_fillDNSTAKEOVERCHECKRecord(&record, cases[i].m_isTargetFound);
    record.m_hostnameChainLength = cases[i].m_chainLength;
    if (!cases[i].m_hasProvider)
      record.mp_matchedSuffix = NULL;
    char* body = static_DNSTAKEOVERCHECKBody(&record);
    const char* at = strstr(body, R"("takeover_possible":)");
    TEST_ASSERT_NOT_NULL(at);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, sscanf(at, R"("takeover_possible":%15[a-z])", word), body);
    char phrase[128];
    int written = snprintf(phrase, sizeof(phrase), "%s%s", word, cases[i].mp_tail);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(phrase));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(lower_row, phrase), phrase);
    free(body);
  }

  static const struct {
    const char* mp_path;
    const char* mp_head;
    const char* mp_tail;
  } copies[] = {
    { "docs/MCP_Documentation.md", "`takeover_possible` is ", " for a CNAME to a service the" },
    { "web/llms.txt",              "takeover_possible is ",   " when the check cannot tell" },
  };
  for (size_t i = 0; i < sizeof(copies) / sizeof(copies[0]); i++)
  {
    char* text = static_readDocsFile(copies[i].mp_path);
    char phrase[128];
    int written = snprintf(phrase, sizeof(phrase), "%s%s%s", copies[i].mp_head, word, copies[i].mp_tail);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(phrase));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(text, phrase), phrase);
    free(text);
  }
}

#define DOCS_MEMBER_NAME_ROOM 16
#define DOCS_MEMBER_NAME_LEN  64

static int static_readMemberNames(const char* object, char names[][DOCS_MEMBER_NAME_LEN])
{
  TEST_ASSERT_EQUAL_CHAR('{', object[0]);
  int depth = 0;
  int count = 0;
  for (const char* at = object; *at != '\0'; at++)
  {
    if (*at == '"')
    {
      const char* end = at + 1;
      while (*end != '\0' && *end != '"')
        end += (end[0] == '\\' && end[1] != '\0') ? 2 : 1;
      TEST_ASSERT_EQUAL_CHAR('"', *end);
      if (depth == 1 && end[1] == ':')
      {
        size_t name_len = (size_t)(end - at - 1);
        TEST_ASSERT_LESS_THAN_INT(DOCS_MEMBER_NAME_ROOM, count);
        TEST_ASSERT_LESS_THAN_size_t(DOCS_MEMBER_NAME_LEN, name_len);
        memcpy(names[count], at + 1, name_len);
        names[count][name_len] = '\0';
        count++;
      }
      at = end;
    }
    else if (*at == '{' || *at == '[')
      depth++;
    else if (*at == '}' || *at == ']')
    {
      depth--;
      if (depth == 0)
        return count;
    }
  }
  TEST_FAIL_MESSAGE("the object does not end");
  return count;
}

static char* static_sectionOf(const char* text, const char* heading)
{
  const char* start = strstr(text, heading);
  TEST_ASSERT_NOT_NULL_MESSAGE(start, heading);
  size_t      level = strspn(heading, "#");
  const char* end   = strchr(start, '\n');
  for (; end != NULL; end = strchr(end + 1, '\n'))
  {
    size_t hashes = strspn(end + 1, "#");
    if (hashes > 0 && hashes <= level && end[1 + hashes] == ' ')
      break;
  }
  size_t section_len = end != NULL ? (size_t)(end - start) : strlen(start);
  char* section = (char*)malloc(section_len + 1);
  TEST_ASSERT_NOT_NULL(section);
  memcpy(section, start, section_len);
  section[section_len] = '\0';
  return section;
}

static void static_assertMembersAreDocumented(const char* section, const char* mcp_section, char names[][DOCS_MEMBER_NAME_LEN], int name_count)
{
  TEST_ASSERT_TRUE(name_count > 0);
  for (int i = 0; i < name_count; i++)
  {
    char needle[DOCS_MEMBER_NAME_LEN + 8];
    snprintf(needle, sizeof(needle), "\n| `%s` |", names[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, needle), needle);
    snprintf(needle, sizeof(needle), "\"%s\": ", names[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, needle), needle);
    if (mcp_section != NULL)
    {
      snprintf(needle, sizeof(needle), "\"%s\":", names[i]);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mcp_section, needle), needle);
    }
  }
}

void test_docs_cert_search_copies_match_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* section = static_sectionOf(docs, "## Cert Search");
  free(docs);
  char* mcp_docs = static_readDocsFile("docs/MCP_Documentation.md");
  char* mcp_section = static_sectionOf(mcp_docs, "### `cert_search`");
  free(mcp_docs);

  static CERTSEARCHRecord_t record;
  static_fillCERTSEARCHRecord(&record);
  record.m_certificateList.m_isComplete = true;
  char* body = static_CERTSEARCHBody(&record);
  char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  static_assertMembersAreDocumented(section, mcp_section, names, static_readMemberNames(body, names));
  char word[16];
  char needle[160];
  TEST_ASSERT_EQUAL_INT(1, sscanf(strstr(body, R"("complete":)"), R"("complete":%15[a-z])", word));
  snprintf(needle, sizeof(needle), "\"complete\": %s,", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, needle), needle);
  snprintf(needle, sizeof(needle), "\"complete\":%s, \"certificate_count\":", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mcp_section, needle), needle);
  free(body);
  free(mcp_section);

  static_fillCERTSEARCHRecord(&record);
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", "shop.example.com");
  record.m_certificateList.m_keptCount     = 0;
  record.m_certificateList.m_readCount     = 0;
  record.m_certificateList.m_isComplete    = true;
  body = static_CERTSEARCHBody(&record);
  size_t body_len = strlen(body);
  TEST_ASSERT_TRUE(body_len > 0 && body[body_len - 1] == '\n');
  body[body_len - 1] = '\0';
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, body), body);
  TEST_ASSERT_EQUAL_INT(1, sscanf(strstr(body, R"("complete":)"), R"("complete":%15[a-z])", word));
  free(body);
  char* llms = static_readDocsFile("web/llms.txt");
  snprintf(needle, sizeof(needle), "with complete %s only when the walk reaches the empty page", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(llms, needle), needle);
  free(llms);

  char cap[64];
  snprintf(cap, sizeof(cap), "The answer lists up to %d.", CERTSPOTTER_CERTIFICATE_MAX_COUNT);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, cap), cap);
  snprintf(cap, sizeof(cap), "among those read, at most %d.", CERTSPOTTER_CERTIFICATE_MAX_COUNT);
  const char* row = strstr(section, "\n| `certificates` |");
  TEST_ASSERT_NOT_NULL(row);
  const char* cap_hit = strstr(row, cap);
  TEST_ASSERT_TRUE_MESSAGE(cap_hit != NULL && cap_hit < strchr(row + 1, '\n'), cap);
  free(section);

  static const struct {
    const char* mp_path;
    const char* mp_head;
    const char* mp_tail;
  } copies[] = {
    { "docs/MCP_Documentation.md", "answer lists up to ", " certificates whose validity starts last among those read" },
    { "web/llms.txt",              "up to ",              " certificates whose validity starts last" },
    { "web/pages/index.html",      "5 pages: up to ",     " whose validity starts last" },
  };
  for (size_t i = 0; i < sizeof(copies) / sizeof(copies[0]); i++)
  {
    char* text = static_readDocsFile(copies[i].mp_path);
    char phrase[160];
    int written = snprintf(phrase, sizeof(phrase), "%s%d%s", copies[i].mp_head, CERTSPOTTER_CERTIFICATE_MAX_COUNT, copies[i].mp_tail);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(phrase));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(text, phrase), phrase);
    free(text);
  }
}

static void static_collapseSpaces(char* text)
{
  size_t out = 0;
  for (size_t k = 0; text[k] != '\0'; k++)
  {
    bool is_space = text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n';
    if (!is_space)
      text[out++] = text[k];
    else if (out == 0 || text[out - 1] != ' ')
      text[out++] = ' ';
  }
  text[out] = '\0';
}

void test_docs_name_the_page_cap_of_the_cert_spotter_walk(void)
{
  const int page_count    = CERTSPOTTER_MAX_PAGE_COUNT;
  const int request_count = CERTSPOTTER_MAX_PAGE_COUNT + 1;
  static const struct {
    const char* mp_path;
    const char* mp_head;
    const char* mp_tail;
    bool        m_isRequestCount;
  } copies[] = {
    { "docs/API_Documentation.md",            "answer page by page, up to ",                                " pages. The answer",             false },
    { "docs/API_Documentation.md",            "It reads at most ",                                          " pages that hold certificates,", false },
    { "docs/API_Documentation.md",            "so it sends at most ",                                       " requests, and the sixth",       true  },
    { "docs/API_Documentation.md",            "When the cap of ",                                           " pages stops the walk",          false },
    { "docs/MCP_Documentation.md",            "page by page, up to ",                                       " pages, and",                    false },
    { "docs/MCP_Documentation.md",            "When the cap of ",                                           " pages stops the walk",          false },
    { "docs/MCP_Documentation.md",            "One call sends up to ",                                      " requests",                      true  },
    { "web/llms.txt",                         "read page by page up to ",                                   " pages,",                        false },
    { "web/pages/domain_monitoring_api.html", "the first ",                                                 " pages of Cert Spotter",         false },
  };
  for (size_t i = 0; i < sizeof(copies) / sizeof(copies[0]); i++)
  {
    char* text = static_readDocsFile(copies[i].mp_path);
    static_collapseSpaces(text);
    char phrase[160];
    int written = snprintf(phrase, sizeof(phrase), "%s%d%s", copies[i].mp_head, copies[i].m_isRequestCount ? request_count : page_count, copies[i].mp_tail);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(phrase));
    const char* hit = strstr(text, phrase);
    TEST_ASSERT_NOT_NULL_MESSAGE(hit, phrase);
    TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, phrase), phrase);
    free(text);
  }
}

void test_docs_subdomain_enum_members_match_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* section = static_sectionOf(docs, "## Subdomain Enum");
  free(docs);
  char* mcp_docs = static_readDocsFile("docs/MCP_Documentation.md");
  char* mcp_section = static_sectionOf(mcp_docs, "### `subdomain_enum`");
  free(mcp_docs);

  SUBDOMAINENUMRecord_t record;
  static_fillSUBDOMAINENUMRecord(&record);
  record.m_isCertificateLogAnswerEmpty = false;
  char* body = static_SUBDOMAINENUMBody(&record);
  char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  static_assertMembersAreDocumented(section, mcp_section, names, static_readMemberNames(body, names));
  const char* at = strstr(body, R"("certificate_logs_complete":)");
  TEST_ASSERT_NOT_NULL(at);
  char word[16];
  TEST_ASSERT_EQUAL_INT(1, sscanf(at, R"("certificate_logs_complete":%15[a-z])", word));
  char example[64];
  snprintf(example, sizeof(example), "\"certificate_logs_complete\": %s\n", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, example), example);
  free(body);
  free(section);

  record.m_isCertificateLogAnswerEmpty = true;
  body = static_SUBDOMAINENUMBody(&record);
  TEST_ASSERT_EQUAL_INT(1, sscanf(strstr(body, R"("certificate_logs_complete":)"), R"("certificate_logs_complete":%15[a-z])", word));
  free(body);
  char needle[160];
  snprintf(needle, sizeof(needle), "`certificate_logs_complete` is %s only when that page is empty.", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mcp_section, needle), needle);
  free(mcp_section);
  char* llms = static_readDocsFile("web/llms.txt");
  snprintf(needle, sizeof(needle), "certificate_logs_complete is %s only when Cert Spotter's first page is empty", word);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(llms, needle), needle);
  free(llms);
}

void test_docs_name_both_values_of_has_public_poc(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  const char* row = strstr(docs, "| `has_public_poc` ");
  TEST_ASSERT_NOT_NULL(row);
  const char* row_end = strchr(row, '\n');
  TEST_ASSERT_NOT_NULL(row_end);
  const bool found[] = { true, false };
  for (size_t i = 0; i < sizeof(found) / sizeof(found[0]); i++)
  {
    CVERISKSCORERecord_t record;
    memset(&record, 0, sizeof(record));
    strncpy(record.ma_label, "LOW", CVERISKSCORE_LABEL_LEN);
    record.m_hasPublicPoc = found[i];
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_CVERISKSCORE_response(&record, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    const char* at = strstr(body, R"("has_public_poc":)");
    TEST_ASSERT_NOT_NULL(at);
    char value[16];
    TEST_ASSERT_EQUAL_INT(1, sscanf(at, R"("has_public_poc":%15[a-z])", value));
    char phrase[32];
    int written = snprintf(phrase, sizeof(phrase), "`%s` when", value);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(phrase));
    const char* hit = strstr(row, phrase);
    TEST_ASSERT_TRUE_MESSAGE(hit != NULL && hit < row_end, phrase);
    free(body);
  }
  const char* never_hit = strstr(row, "Never `false`");
  TEST_ASSERT_TRUE_MESSAGE(never_hit != NULL && never_hit < row_end, "the has_public_poc row says Never `false`");
  const char* second_false = strstr(never_hit + strlen("Never `false`"), "`false`");
  TEST_ASSERT_TRUE_MESSAGE(second_false == NULL || second_false > row_end, "the has_public_poc row names `false` once");
  const char* first_false = strstr(row, "`false`");
  TEST_ASSERT_TRUE_MESSAGE(first_false == never_hit + strlen("Never "), "the only `false` of the row is the one after Never");
  const char* false_hit = strstr(row, "`false` when");
  TEST_ASSERT_TRUE_MESSAGE(false_hit == NULL || false_hit > row_end, "the has_public_poc row names `false` when");
  free(docs);
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md" };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
  {
    char* text = static_readDocsFile(paths[i]);
    int key_count = 0;
    for (const char* at = strstr(text, R"("has_public_poc")"); at != NULL; at = strstr(at + 1, R"("has_public_poc")"))
    {
      const char* value = at + strlen(R"("has_public_poc")");
      value += strspn(value, " \t");
      TEST_ASSERT_EQUAL_CHAR_MESSAGE(':', *value, paths[i]);
      value += 1 + strspn(value + 1, " \t");
      size_t word_len = strspn(value, "abcdefghijklmnopqrstuvwxyz");
      TEST_ASSERT_TRUE_MESSAGE(word_len == 4 && (strncmp(value, "true", 4) == 0 || strncmp(value, "null", 4) == 0), paths[i]);
      const char* after = value + word_len + strspn(value + word_len, " \t");
      TEST_ASSERT_TRUE_MESSAGE(*after == ',' || *after == '}' || *after == '\n', paths[i]);
      key_count++;
    }
    TEST_ASSERT_TRUE_MESSAGE(key_count > 0, paths[i]);
    free(text);
  }
}

static char* static_CVESEARCHFilterNoteBody(const char* vendor)
{
  CveListResult_t results = { .m_total = 23, .m_count = 0, .mp_items = NULL };
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  strncpy(params.ma_vendor, vendor, CVESEARCH_VENDOR_LEN);
  params.m_limit = 20;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_CVESEARCH_response(&results, &params, json_buf);
  return static_finishJsonBuf(json_buf);
}

void test_docs_product_filter_note_copies_match_the_server(void)
{
  char with_names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  char without_names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  char* body = static_CVESEARCHFilterNoteBody("apache");
  char* bare_body = static_CVESEARCHFilterNoteBody("");
  int with_count = static_readMemberNames(body, with_names);
  int without_count = static_readMemberNames(bare_body, without_names);
  free(bare_body);
  TEST_ASSERT_EQUAL_INT(without_count + 1, with_count);
  const char* member = NULL;
  for (int i = 0; i < with_count && member == NULL; i++)
    if (i >= without_count || strcmp(with_names[i], without_names[i]) != 0)
      member = with_names[i];
  TEST_ASSERT_NOT_NULL(member);

  char needle[256];
  snprintf(needle, sizeof(needle), "\"%.*s\":\"", DOCS_MEMBER_NAME_LEN - 1, member);
  const char* note_start = strstr(body, needle);
  TEST_ASSERT_NOT_NULL_MESSAGE(note_start, needle);
  note_start += strlen(needle);
  const char* note_end = strchr(note_start, '"');
  TEST_ASSERT_NOT_NULL(note_end);
  static char note[512];
  size_t note_len = (size_t)(note_end - note_start);
  TEST_ASSERT_LESS_THAN_size_t(sizeof(note), note_len);
  memcpy(note, note_start, note_len);
  note[note_len] = '\0';

  char* docs = static_readDocsFile("docs/API_Documentation.md");
  snprintf(needle, sizeof(needle), "\n| `%.*s` | string |", DOCS_MEMBER_NAME_LEN - 1, member);
  TEST_ASSERT_EQUAL_INT_MESSAGE(3, static_countOccurrences(docs, needle), needle);
  snprintf(needle, sizeof(needle), "#### `%.*s`", DOCS_MEMBER_NAME_LEN - 1, member);
  char* section = static_sectionOf(docs, needle);
  static char quoted_note[600];
  snprintf(quoted_note, sizeof(quoted_note), "\n`\"%s\"`\n", note);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(section, quoted_note), quoted_note);
  free(section);
  free(docs);

  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md" };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
  {
    char* text = static_readDocsFile(paths[i]);
    snprintf(needle, sizeof(needle), "\"%.*s\":", DOCS_MEMBER_NAME_LEN - 1, member);
    int copy_count = 0;
    for (const char* at = strstr(text, needle); at != NULL; at = strstr(at + 1, needle))
    {
      const char* value = at + strlen(needle);
      value += strspn(value, " ");
      TEST_ASSERT_EQUAL_CHAR_MESSAGE('"', value[0], paths[i]);
      TEST_ASSERT_TRUE_MESSAGE(strncmp(value + 1, note, note_len) == 0 && value[1 + note_len] == '"', paths[i]);
      copy_count++;
    }
    TEST_ASSERT_TRUE_MESSAGE(copy_count > 0, paths[i]);
    free(text);
  }

  char* llms = static_readDocsFile("web/llms.txt");
  static const char* const lines[] = { "\n- GET /cve_search?", "\n- GET /cve_leading?", "\n- GET /cve_triage?", "\n- GET /product_exposure?" };
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++)
  {
    const char* line = strstr(llms, lines[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(line, lines[i]);
    const char* line_end = strchr(line + 1, '\n');
    const char* hit = strstr(line, member);
    TEST_ASSERT_TRUE_MESSAGE(hit != NULL && (line_end == NULL || hit < line_end), lines[i]);
  }
  free(llms);
  free(body);
}


void test_VENDORKEYEDIT_apply_response_shapes(void)
{
  VENDORKEYEDITApplyResult_t result;
  memset(&result, 0, sizeof(result));
  result.m_shodan.m_outcome                = VENDORKEYEDIT_OUTCOME_SAVED;
  result.m_shodan.m_isConfigured           = true;
  result.m_abuseIpDb.m_outcome             = VENDORKEYEDIT_OUTCOME_UNAVAILABLE;
  result.m_abuseIpDb.m_retryAfterSeconds   = 29;
  JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
  char* body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"shodan":{"result":"saved","configured":true},"abuseipdb":{"result":"vendor_unavailable","configured":false,"retry_after_seconds":29}})" "\n", body);
  free(body);

  memset(&result, 0, sizeof(result));
  result.m_shodan.m_outcome      = VENDORKEYEDIT_OUTCOME_DELETED;
  result.m_abuseIpDb.m_outcome   = VENDORKEYEDIT_OUTCOME_REJECTED;
  result.m_abuseIpDb.m_isConfigured = true;
  result.mp_manageUrl            = "https://api.contrastcyber.com/vendor-keys#l=0a1b";
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"shodan":{"result":"deleted","configured":false},"abuseipdb":{"result":"rejected","configured":true},"manage_url":"https://api.contrastcyber.com/vendor-keys#l=0a1b"})" "\n", body);
  free(body);

  memset(&result, 0, sizeof(result));
  result.m_abuseIpDb.m_outcome = VENDORKEYEDIT_OUTCOME_UNAVAILABLE;
  result.mp_manageUrl          = "";
  json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
  body = static_finishJsonBuf(json_buf);
  TEST_ASSERT_EQUAL_STRING(R"({"shodan":{"result":"unchanged","configured":false},"abuseipdb":{"result":"vendor_unavailable","configured":false},"manage_url":null})" "\n", body);
  free(body);
}

void test_VENDORKEYEDIT_status_response_names_each_state(void)
{
  const struct { VENDORKEYEDITState_t m_shodan; VENDORKEYEDITState_t m_abuseIpDb; int64_t m_expiresIn; const char* mp_body; } cases[] = {
    { VENDORKEYEDIT_STATE_WORKING,        VENDORKEYEDIT_STATE_REJECTED,       873, R"({"shodan":{"state":"working"},"abuseipdb":{"state":"rejected"},"expires_in_seconds":873})" "\n" },
    { VENDORKEYEDIT_STATE_REJECTED,       VENDORKEYEDIT_STATE_NOT_CONFIGURED, 0,   R"({"shodan":{"state":"rejected"},"abuseipdb":{"state":"not_configured"},"expires_in_seconds":0})" "\n" },
    { VENDORKEYEDIT_STATE_UNAVAILABLE,    VENDORKEYEDIT_STATE_WORKING,        12,  R"({"shodan":{"state":"vendor_unavailable"},"abuseipdb":{"state":"working"},"expires_in_seconds":12})" "\n" },
    { VENDORKEYEDIT_STATE_NOT_CONFIGURED, VENDORKEYEDIT_STATE_UNAVAILABLE,    5,   R"({"shodan":{"state":"not_configured"},"abuseipdb":{"state":"vendor_unavailable"},"expires_in_seconds":5})" "\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    VENDORKEYEDITStatusResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_shodanState      = cases[i].m_shodan;
    result.m_abuseIpDbState   = cases[i].m_abuseIpDb;
    result.m_expiresInSeconds = cases[i].m_expiresIn;
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_VENDORKEYEDIT_statusResponse(&result, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, body);
    free(body);
  }
}

static bool static_hasFieldRow(const char* section, const char* name)
{
  char quoted[DOCS_MEMBER_NAME_LEN + 4];
  snprintf(quoted, sizeof(quoted), "`%.*s`", DOCS_MEMBER_NAME_LEN - 1, name);
  for (const char* line = strstr(section, "\n| "); line != NULL; line = strstr(line + 1, "\n| "))
  {
    const char* cell_end = strstr(line + 3, " |");
    const char* hit      = strstr(line + 3, quoted);
    if (cell_end != NULL && hit != NULL && hit < cell_end)
      return true;
  }
  return false;
}

static void static_readStringValue(const char* body, const char* name, char* out, size_t out_size)
{
  char needle[DOCS_MEMBER_NAME_LEN + 8];
  snprintf(needle, sizeof(needle), "\"%.*s\":\"", DOCS_MEMBER_NAME_LEN - 1, name);
  const char* start = strstr(body, needle);
  TEST_ASSERT_NOT_NULL_MESSAGE(start, needle);
  start += strlen(needle);
  const char* end = strchr(start, '"');
  TEST_ASSERT_NOT_NULL(end);
  TEST_ASSERT_LESS_THAN_size_t(out_size, (size_t)(end - start));
  snprintf(out, out_size, "%.*s", (int)(end - start), start);
}

static const char* static_objectAfter(const char* body, const char* name)
{
  char needle[DOCS_MEMBER_NAME_LEN + 8];
  snprintf(needle, sizeof(needle), "\"%.*s\":{", DOCS_MEMBER_NAME_LEN - 1, name);
  const char* start = strstr(body, needle);
  TEST_ASSERT_NOT_NULL_MESSAGE(start, needle);
  return start + strlen(needle) - 1;
}

void test_docs_ip_lookup_vendor_slots_match_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* ip_section = static_sectionOf(docs, "## IP Lookup");
  free(docs);
  char* section = static_sectionOf(ip_section, "### The vendor slots");
  free(ip_section);

  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  static const IPLOOKUPSlotState_t states[] = {
    IPLOOKUP_SLOT_PRO_KEY_REQUIRED, IPLOOKUP_SLOT_KEY_MISSING, IPLOOKUP_SLOT_KEY_REJECTED,
    IPLOOKUP_SLOT_VENDOR_UNAVAILABLE, IPLOOKUP_SLOT_DB_ERROR,
  };
  char reasons[5][DOCS_MEMBER_NAME_LEN];
  for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
  {
    IPLOOKUPVendorSlots_t slots;
    static_fillIPLOOKUPSlots(&slots);
    slots.m_reputation.m_slotState       = states[i];
    slots.m_internetExposure.m_slotState = states[i];
    char* body = static_IPLOOKUPSlotsBody(&record, &slots);
    static_readStringValue(body, "reason", reasons[i], sizeof(reasons[i]));
    free(body);
    char row[DOCS_MEMBER_NAME_LEN + 8];
    snprintf(row, sizeof(row), "\n| `%.*s` |", DOCS_MEMBER_NAME_LEN - 1, reasons[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(section, row), row);
  }

  IPLOOKUPVendorSlots_t slots;
  static_fillIPLOOKUPSlots(&slots);
  char* body = static_IPLOOKUPSlotsBody(&record, &slots);
  static const char* const slot_names[] = { "reputation", "internet_exposure" };
  for (size_t s = 0; s < sizeof(slot_names) / sizeof(slot_names[0]); s++)
  {
    char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
    int name_count = static_readMemberNames(static_objectAfter(body, slot_names[s]), names);
    TEST_ASSERT_TRUE(name_count > 2);
    for (int n = 0; n < name_count; n++)
    {
      if (strcmp(names[n], "available") == 0 || strcmp(names[n], "source") == 0)
        continue;
      char row[DOCS_MEMBER_NAME_LEN + 8];
      snprintf(row, sizeof(row), "\n| `%.*s` |", DOCS_MEMBER_NAME_LEN - 1, names[n]);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(section, row), row);
    }
  }
  free(body);
  free(section);

  char* mcp_docs = static_readDocsFile("docs/MCP_Documentation.md");
  char* mcp_section = static_sectionOf(mcp_docs, "### `ip_lookup`");
  free(mcp_docs);
  char list[512];
  snprintf(list, sizeof(list), "`%s`,\n`%s`, `%s`, `%s` or `%s`", reasons[0], reasons[1], reasons[2], reasons[3], reasons[4]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(mcp_section, list), list);
  free(mcp_section);
}


void test_docs_ip_lookup_count_query_source_matches_the_server(void)
{
  IPLOOKUPRecord_t record;
  static_fillIPLOOKUPRecord(&record);
  IPLOOKUPVendorSlots_t slots;
  static_fillIPLOOKUPSlots(&slots);
  slots.m_shodanHost.m_isFromFacets = true;
  char* body = static_IPLOOKUPSlotsBody(&record, &slots);
  char source[DOCS_MEMBER_NAME_LEN];
  static_readStringValue(strstr(body, "\"internet_exposure\":"), "source", source, sizeof(source));
  char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  int name_count = static_readMemberNames(static_objectAfter(body, "reputation"), names);
  free(body);

  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* ip_section = static_sectionOf(docs, "## IP Lookup");
  free(docs);
  char phrase[160];
  snprintf(phrase, sizeof(phrase), "A key of a free Shodan account gets `%s`", source);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(ip_section, phrase), phrase);
  snprintf(phrase, sizeof(phrase), "Always `[]` for `%s` |", source);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(ip_section, phrase), phrase);
  snprintf(phrase, sizeof(phrase), "and always for `%s` |", source);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(ip_section, phrase), phrase);
  const char* example = strstr(ip_section, "\"reputation\": {\"available\": true");
  TEST_ASSERT_NOT_NULL(example);
  const char* example_end = strchr(example, '\n');
  TEST_ASSERT_NOT_NULL(example_end);
  for (int n = 0; n < name_count; n++)
  {
    snprintf(phrase, sizeof(phrase), "\"%.*s\": ", DOCS_MEMBER_NAME_LEN - 1, names[n]);
    const char* hit = strstr(example, phrase);
    TEST_ASSERT_TRUE_MESSAGE(hit != NULL && hit < example_end, phrase);
  }
  free(ip_section);

  char* mcp_docs = static_readDocsFile("docs/MCP_Documentation.md");
  char* mcp_section = static_sectionOf(mcp_docs, "### `ip_lookup`");
  free(mcp_docs);
  snprintf(phrase, sizeof(phrase), "`%s`: ports, CVE ids and tags, but `hostnames` `[]` and `last_update` `null`", source);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(mcp_section, phrase), phrase);
  free(mcp_section);
}

void test_vendor_keys_script_knows_each_result_and_state(void)
{
  char* script = static_readDocsFile("web/static/js/vendor_keys.js");

  static const VENDORKEYEDITOutcome_t outcomes[] = {
    VENDORKEYEDIT_OUTCOME_SAVED, VENDORKEYEDIT_OUTCOME_DELETED, VENDORKEYEDIT_OUTCOME_REJECTED,
    VENDORKEYEDIT_OUTCOME_UNAVAILABLE, VENDORKEYEDIT_OUTCOME_UNCHANGED,
  };
  for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); i++)
  {
    VENDORKEYEDITApplyResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_shodan.m_outcome = outcomes[i];
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    char name[DOCS_MEMBER_NAME_LEN];
    static_readStringValue(body, "result", name, sizeof(name));
    char phrase[DOCS_MEMBER_NAME_LEN + 24];
    snprintf(phrase, sizeof(phrase), "if (result === '%.*s')", DOCS_MEMBER_NAME_LEN - 1, name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(script, phrase), phrase);
    free(body);
  }

  static const VENDORKEYEDITState_t states[] = {
    VENDORKEYEDIT_STATE_NOT_CONFIGURED, VENDORKEYEDIT_STATE_WORKING, VENDORKEYEDIT_STATE_REJECTED,
    VENDORKEYEDIT_STATE_UNAVAILABLE,
  };
  for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
  {
    VENDORKEYEDITStatusResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_shodanState = states[i];
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_VENDORKEYEDIT_statusResponse(&result, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    char name[DOCS_MEMBER_NAME_LEN];
    static_readStringValue(body, "state", name, sizeof(name));
    char phrase[DOCS_MEMBER_NAME_LEN + 24];
    snprintf(phrase, sizeof(phrase), "    %.*s: '", DOCS_MEMBER_NAME_LEN - 1, name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(script, phrase), phrase);
    free(body);
  }
  free(script);
}

void test_docs_vendor_key_edit_answers_match_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* edit_section = static_sectionOf(docs, "## Vendor Key Edit");
  free(docs);
  char* apply_section  = static_sectionOf(edit_section, "### Apply");
  char* status_section = static_sectionOf(edit_section, "### Status");
  free(edit_section);

  static const VENDORKEYEDITOutcome_t outcomes[] = {
    VENDORKEYEDIT_OUTCOME_SAVED, VENDORKEYEDIT_OUTCOME_DELETED, VENDORKEYEDIT_OUTCOME_REJECTED,
    VENDORKEYEDIT_OUTCOME_UNAVAILABLE, VENDORKEYEDIT_OUTCOME_UNCHANGED,
  };
  char results[5][DOCS_MEMBER_NAME_LEN];
  for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); i++)
  {
    VENDORKEYEDITApplyResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_shodan.m_outcome              = outcomes[i];
    result.m_shodan.m_retryAfterSeconds    = 7;
    result.m_abuseIpDb.m_outcome           = outcomes[i];
    result.mp_manageUrl                    = "https://api.contrastcyber.com/vendor-keys#l=0a1b";
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    static_readStringValue(body, "result", results[i], sizeof(results[i]));
    char phrase[DOCS_MEMBER_NAME_LEN + 8];
    snprintf(phrase, sizeof(phrase), "`%.*s`: ", DOCS_MEMBER_NAME_LEN - 1, results[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(apply_section, phrase), phrase);

    char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
    int name_count = static_readMemberNames(static_objectAfter(body, "shodan"), names);
    TEST_ASSERT_EQUAL_INT(3, name_count);
    for (int n = 0; n < name_count; n++)
      TEST_ASSERT_TRUE_MESSAGE(static_hasFieldRow(apply_section, names[n]), names[n]);
    name_count = static_readMemberNames(body, names);
    TEST_ASSERT_EQUAL_INT(3, name_count);
    TEST_ASSERT_TRUE_MESSAGE(static_hasFieldRow(apply_section, names[2]), names[2]);
    free(body);
  }

  static const VENDORKEYEDITState_t states[] = {
    VENDORKEYEDIT_STATE_NOT_CONFIGURED, VENDORKEYEDIT_STATE_WORKING, VENDORKEYEDIT_STATE_REJECTED,
    VENDORKEYEDIT_STATE_UNAVAILABLE,
  };
  for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
  {
    VENDORKEYEDITStatusResult_t result;
    memset(&result, 0, sizeof(result));
    result.m_shodanState      = states[i];
    result.m_abuseIpDbState   = states[i];
    result.m_expiresInSeconds = 60;
    JsonBuf_t* json_buf = static_newJsonBuf(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    serialize_VENDORKEYEDIT_statusResponse(&result, json_buf);
    char* body = static_finishJsonBuf(json_buf);
    char state[DOCS_MEMBER_NAME_LEN];
    static_readStringValue(body, "state", state, sizeof(state));
    char phrase[DOCS_MEMBER_NAME_LEN + 8];
    snprintf(phrase, sizeof(phrase), "`%.*s`: ", DOCS_MEMBER_NAME_LEN - 1, state);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(status_section, phrase), phrase);

    char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
    int name_count = static_readMemberNames(body, names);
    TEST_ASSERT_EQUAL_INT(3, name_count);
    for (int n = 0; n < name_count; n++)
    {
      char object_needle[DOCS_MEMBER_NAME_LEN + 8];
      snprintf(object_needle, sizeof(object_needle), "\"%.*s\":{", DOCS_MEMBER_NAME_LEN - 1, names[n]);
      if (strstr(body, object_needle) == NULL)
      {
        TEST_ASSERT_TRUE_MESSAGE(static_hasFieldRow(status_section, names[n]), names[n]);
        continue;
      }
      char inner[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
      int inner_count = static_readMemberNames(static_objectAfter(body, names[n]), inner);
      TEST_ASSERT_EQUAL_INT(1, inner_count);
      char path[2 * DOCS_MEMBER_NAME_LEN];
      snprintf(path, sizeof(path), "%.*s.%.*s", DOCS_MEMBER_NAME_LEN - 1, names[n], DOCS_MEMBER_NAME_LEN - 1, inner[0]);
      TEST_ASSERT_TRUE_MESSAGE(static_hasFieldRow(status_section, path), path);
    }
    free(body);
  }
  free(apply_section);
  free(status_section);

  char* mcp_docs = static_readDocsFile("docs/MCP_Documentation.md");
  char* mcp_section = static_sectionOf(mcp_docs, "### `vendor_key_edit`");
  free(mcp_docs);
  char list[512];
  snprintf(list, sizeof(list), "one of `%s`, `%s`, `%s`, `%s` and `%s`", results[0], results[1], results[2], results[3], results[4]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(mcp_section, list), list);
  free(mcp_section);
}

void test_docs_privacy_vendor_keys_members_match_the_server(void)
{
  char* docs = static_readDocsFile("docs/API_Documentation.md");
  char* section = static_sectionOf(docs, "## Privacy");
  free(docs);
  PRIVACYMYDATAVendorKeys_t vendor_keys = { true, false, PRIVACYMYDATA_TEST_MANAGE_URL };
  char member[1024];
  static_PRIVACYMYDATAVendorKeysMember(&vendor_keys, member, sizeof(member));
  const char* object = static_objectAfter(member, "vendor_keys");
  char names[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
  int name_count = static_readMemberNames(object, names);
  TEST_ASSERT_EQUAL_INT(3, name_count);
  for (int n = 0; n < name_count; n++)
  {
    char row[3 * DOCS_MEMBER_NAME_LEN];
    char inner_needle[DOCS_MEMBER_NAME_LEN + 8];
    snprintf(inner_needle, sizeof(inner_needle), "\"%.*s\":{", DOCS_MEMBER_NAME_LEN - 1, names[n]);
    if (strstr(object, inner_needle) == NULL)
    {
      snprintf(row, sizeof(row), "\n| `vendor_keys.%.*s` |", DOCS_MEMBER_NAME_LEN - 1, names[n]);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(section, row), row);
      continue;
    }
    char inner[DOCS_MEMBER_NAME_ROOM][DOCS_MEMBER_NAME_LEN];
    int inner_count = static_readMemberNames(static_objectAfter(object, names[n]), inner);
    TEST_ASSERT_EQUAL_INT(1, inner_count);
    snprintf(row, sizeof(row), "\n| `vendor_keys.%.*s.%.*s` |", DOCS_MEMBER_NAME_LEN - 1, names[n], DOCS_MEMBER_NAME_LEN - 1, inner[0]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_countOccurrences(section, row), row);
  }
  free(section);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_CVELOOKUP_metasploit_fields_in_json);
  RUN_TEST(test_CVEEXPLOIT_no_results_serializes);
  RUN_TEST(test_CVEEXPLOIT_with_github_results_serializes);
  RUN_TEST(test_CVEEXPLOIT_with_metasploit_serializes);
  RUN_TEST(test_CVETRIAGE_json_shape);
  RUN_TEST(test_CVETRIAGEBULK_json_envelope);
  RUN_TEST(test_PRODUCTEXPOSURE_json_shape);
  RUN_TEST(test_CVETRIAGE_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_CVETRIAGE_over_ceiling_hands_back_no_body);
  RUN_TEST(test_CVETRIAGE_escape_heavy_item_is_escaped_and_complete);
  RUN_TEST(test_HEALTH_serializes_every_section);
  RUN_TEST(test_HEALTH_null_db_serializes_unavailable_and_null_db);
  RUN_TEST(test_HEALTH_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_HEALTH_over_ceiling_hands_back_no_body);
  RUN_TEST(test_HEALTH_every_string_is_escaped_through_its_own_class);
  RUN_TEST(test_HEALTH_no_feed_writes_an_empty_list);
  RUN_TEST(test_HEALTH_feed_count_past_its_array_is_clamped);
  RUN_TEST(test_error_golden);
  RUN_TEST(test_error_code_is_escaped);
  RUN_TEST(test_CVERISKSCORE_golden);
  RUN_TEST(test_CVERISKSCORE_golden_no_poc_whole_numbers);
  RUN_TEST(test_CVERISKSCORE_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_CVERISKSCORE_over_ceiling_hands_back_no_body);
  RUN_TEST(test_CVERISKSCORE_label_is_escaped);
  RUN_TEST(test_CVESEARCH_golden_empty);
  RUN_TEST(test_CVESEARCH_golden_two_items);
  RUN_TEST(test_CVESEARCH_golden_sources);
  RUN_TEST(test_CVESEARCH_golden_escapes_every_class);
  RUN_TEST(test_CVESEARCH_golden_next_offset_clamped_at_int_max);
  RUN_TEST(test_CVELEADING_golden_critical_verdict);
  RUN_TEST(test_CVELEADING_golden_high_verdict);
  RUN_TEST(test_CVELEADING_golden_moderate_verdict);
  RUN_TEST(test_CVELEADING_golden_empty_none_verdict);
  RUN_TEST(test_KEVLOOKUP_golden_full);
  RUN_TEST(test_KEVLOOKUP_golden_null_cwes);
  RUN_TEST(test_KEVLOOKUP_writes_a_stored_byte_that_is_not_valid_utf8_as_u_fffd);
  RUN_TEST(test_json_members_follow_the_text_rules);
  RUN_TEST(test_CWELOOKUP_golden_filled_heap);
  RUN_TEST(test_CWELOOKUP_golden_null_heap);
  RUN_TEST(test_CWELOOKUP_golden_empty_heap_matches_null_heap);
  RUN_TEST(test_CVELOOKUP_golden_ghsa_hint_url);
  RUN_TEST(test_CVELOOKUP_golden_sources);
  RUN_TEST(test_CVELOOKUP_golden_metasploit_null_when_the_feed_is_not_loaded);
  RUN_TEST(test_CVELOOKUP_nuclei_templates_not_synced_when_the_feed_is_not_loaded);
  RUN_TEST(test_CVELOOKUP_nuclei_templates_count_is_written_apart_from_the_list);
  RUN_TEST(test_CVELOOKUP_golden_ghsa_null_when_enriched_without_advisory);
  RUN_TEST(test_CVELOOKUP_golden_ghsa_advisory_is_written_as_it_is);
  RUN_TEST(test_CVELOOKUP_golden_ghsa_not_synced);
  RUN_TEST(test_CVELOOKUP_golden_ghsa_database_error);
  RUN_TEST(test_CVELOOKUP_golden_ransomware_null_outside_kev);
  RUN_TEST(test_CVELOOKUP_cvss_v4_follows_its_vector_and_range);
  RUN_TEST(test_CVELOOKUP_golden_ssvc_object);
  RUN_TEST(test_CVELOOKUP_ssvc_without_a_time_writes_scored_at_null);
  RUN_TEST(test_CVELOOKUP_ssvc_escapes_every_string_field);
  RUN_TEST(test_CVELOOKUP_cvss_v3_follows_its_vector_and_range);
  RUN_TEST(test_CVELOOKUP_booleans_follow_their_own_fields);
  RUN_TEST(test_CVELOOKUP_one_metasploit_module_is_a_module);
  RUN_TEST(test_CVELOOKUP_golden_raw_json_fields_passed_through);
  RUN_TEST(test_CVELOOKUP_golden_description_escaped);
  RUN_TEST(test_CVELOOKUPBULK_golden_zero_successful);
  RUN_TEST(test_CVELOOKUPBULK_golden_not_processed_ids);
  RUN_TEST(test_CVELOOKUPBULK_golden_newline_between_elements);
  RUN_TEST(test_CVEEXPLOIT_golden_all_sources_available_and_empty);
  RUN_TEST(test_CVEEXPLOIT_golden_unavailable_sources_hide_their_other_fields);
  RUN_TEST(test_CVEEXPLOIT_golden_github_unavailable_metasploit_found);
  RUN_TEST(test_CVEEXPLOIT_golden_empty_metasploit_table_is_not_synced);
  RUN_TEST(test_CVEEXPLOIT_golden_empty_github_table_is_not_synced);
  RUN_TEST(test_CVEEXPLOIT_golden_all_sources_two_items);
  RUN_TEST(test_CVEEXPLOIT_item_counts_past_their_arrays_are_clamped);
  RUN_TEST(test_PRODUCTEXPOSURE_top_cve_count_past_its_array_is_clamped);
  RUN_TEST(test_CVEEXPLOIT_golden_cve_not_in_local_database_is_unknown);
  RUN_TEST(test_CVEEXPLOIT_golden_nvd_every_slot_is_written);
  RUN_TEST(test_CVEEXPLOIT_has_public_exploit_follows_every_source);
  RUN_TEST(test_CVEEXPLOIT_golden_github_only_is_not_proof);
  RUN_TEST(test_CVEEXPLOIT_golden_exploitdb_entries);
  RUN_TEST(test_CVEEXPLOIT_golden_exploitdb_unavailable_hides_its_fields);
  RUN_TEST(test_CVEEXPLOIT_golden_empty_exploitdb_table_is_not_synced);
  RUN_TEST(test_CVEEXPLOIT_has_module_follows_the_total_not_the_stored_names);
  RUN_TEST(test_CVETRIAGE_golden_empty);
  RUN_TEST(test_CVETRIAGE_golden_two_items);
  RUN_TEST(test_CVETRIAGEBULK_golden_zero_successful);
  RUN_TEST(test_CVETRIAGEBULK_golden_not_processed_ids);
  RUN_TEST(test_CVETRIAGEBULK_golden_two_items);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_no_top_cves);
  RUN_TEST(test_PRODUCTEXPOSURE_envelope_strings_are_escaped);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_two_top_cves);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_one_cycle);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_cycle_without_date);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_lts_cycle);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_variants);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_no_series);
  RUN_TEST(test_PRODUCTEXPOSURE_golden_eol_two_variants);
  RUN_TEST(test_PRODUCTEXPOSURE_eol_counts_past_their_arrays_are_clamped);
  RUN_TEST(test_CVESEARCH_golden_product_filter_note);
  RUN_TEST(test_CVESEARCH_golden_product_filter_note_for_a_product);
  RUN_TEST(test_CVELEADING_golden_product_filter_note);
  RUN_TEST(test_CVETRIAGE_golden_product_filter_note);
  RUN_TEST(test_CVE_lists_without_a_product_filter_write_no_product_filter_note);
  RUN_TEST(test_CVE_lists_with_one_product_filter_write_product_filter_note);
  RUN_TEST(test_CVSSCALCULATOR_golden);
  RUN_TEST(test_CVSSCALCULATOR_each_member_lands_under_its_own_key);
  RUN_TEST(test_CVSSCALCULATOR_vector_is_escaped);
  RUN_TEST(test_CVSSCALCULATOR_whole_number_scores_keep_one_decimal);
  RUN_TEST(test_CWELOOKUP_golden_mixed_heap_states);
  RUN_TEST(test_CVELOOKUP_golden_mixed_raw_json_fields);
  RUN_TEST(test_CVELOOKUP_golden_mixed_raw_json_fields_paired_the_other_way);
  RUN_TEST(test_CVELOOKUP_long_cwes_is_written_whole);
  RUN_TEST(test_CVELOOKUP_long_cve_tags_is_written_whole);
  RUN_TEST(test_CVELOOKUP_null_cwes_is_written_as_empty_array);
  RUN_TEST(test_CVETRIAGE_golden_next_offset_clamped_at_int_max);
  RUN_TEST(test_CPESEARCH_golden_empty);
  RUN_TEST(test_CPESEARCH_golden_two_items);
  RUN_TEST(test_CPESEARCH_golden_next_offset_clamped_at_int_max);
  RUN_TEST(test_CVEPRODUCTS_golden_page);
  RUN_TEST(test_CVEPRODUCTS_golden_no_page);
  RUN_TEST(test_CVEPRODUCTS_golden_next_offset_clamped_at_int_max);
  RUN_TEST(test_D3FENDFORATTACK_golden_empty);
  RUN_TEST(test_D3FENDFORATTACK_golden_two_defenses);
  RUN_TEST(test_D3FENDFORATTACK_counts_each_tactic_alone);
  RUN_TEST(test_D3FENDFORATTACK_digital_artifact_is_escaped);
  RUN_TEST(test_DRIVERLOOKUP_golden_found);
  RUN_TEST(test_DRIVERLOOKUP_golden_not_found);
  RUN_TEST(test_DRIVERLOOKUP_golden_catalog_not_loaded);
  RUN_TEST(test_EMAILADDRESSCHECK_golden_mx_route);
  RUN_TEST(test_EMAILADDRESSCHECK_echoed_address_is_escaped);
  RUN_TEST(test_EMAILADDRESSCHECK_each_route);
  RUN_TEST(test_EMAILADDRESSCHECK_disposable_of_each_list_state);
  RUN_TEST(test_IPLOOKUP_golden_every_source_loaded_with_matches);
  RUN_TEST(test_IPLOOKUP_golden_ipv6_cdn_that_is_not_a_tor_exit);
  RUN_TEST(test_IPLOOKUP_golden_every_source_loaded_without_a_match);
  RUN_TEST(test_IPLOOKUP_an_empty_as_text_is_null_alone);
  RUN_TEST(test_IPLOOKUP_as_1_is_a_number);
  RUN_TEST(test_IPLOOKUP_one_source_not_loaded_and_a_failed_ptr);
  RUN_TEST(test_IPLOOKUP_golden_each_source_not_loaded);
  RUN_TEST(test_IPLOOKUP_golden_nothing_loaded_and_ptr_timed_out);
  RUN_TEST(test_IPLOOKUP_golden_each_failed_ptr_answer);
  RUN_TEST(test_IPLOOKUP_ptr_name_is_escaped_by_its_byte_count);
  RUN_TEST(test_IPLOOKUP_golden_both_vendor_slots_filled);
  RUN_TEST(test_IPLOOKUP_internet_exposure_from_the_count_query);
  RUN_TEST(test_IPLOOKUP_reputation_empty_texts_and_whitelist_values);
  RUN_TEST(test_IPLOOKUP_each_empty_vendor_slot);
  RUN_TEST(test_ASNLOOKUP_golden_as_target);
  RUN_TEST(test_ASNLOOKUP_golden_ip_target_with_its_prefix);
  RUN_TEST(test_ASNLOOKUP_golden_empty_country_is_null_alone);
  RUN_TEST(test_ASNLOOKUP_golden_empty_family_and_a_count_past_its_list);
  RUN_TEST(test_ASNLOOKUP_next_offset_follows_the_larger_family);
  RUN_TEST(test_DRIVERLOOKUPBULK_golden_loaded);
  RUN_TEST(test_DRIVERLOOKUPBULK_golden_catalog_not_loaded_and_not_known);
  RUN_TEST(test_DRIVERLOOKUPBULK_golden_no_record_read_is_unknown);
  RUN_TEST(test_PACKAGECHECKBULK_golden_loaded);
  RUN_TEST(test_PACKAGECHECKBULK_golden_not_synced_and_not_known);
  RUN_TEST(test_PACKAGECHECKBULK_golden_no_package_read_is_unknown);
  RUN_TEST(test_PACKAGECHECK_golden_with_a_version);
  RUN_TEST(test_PACKAGECHECK_golden_not_synced_and_no_fixed_version);
  RUN_TEST(test_PACKAGECHECK_without_a_version_writes_no_fixed_version);
  RUN_TEST(test_PACKAGECHECK_fixed_version_is_escaped);
  RUN_TEST(test_PACKAGECHECK_next_offset_is_the_offset_after_the_page);
  RUN_TEST(test_PACKAGECHECK_golden_with_eol);
  RUN_TEST(test_PACKAGECHECK_eol_is_the_eol_of_product_exposure);
  RUN_TEST(test_CPESEARCH_golden_vendor_escaped);
  RUN_TEST(test_CVELOOKUPBULK_golden_counters_all_distinct);
  RUN_TEST(test_CVELOOKUP_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_CVELOOKUP_over_ceiling_hands_back_no_body);
  RUN_TEST(test_CVELOOKUPBULK_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_CVELOOKUPBULK_over_ceiling_hands_back_no_body);
  RUN_TEST(test_CVELOOKUP_record_escapes_every_string_field);
  RUN_TEST(test_CVELEADING_golden_kev_count_includes_last_item);
  RUN_TEST(test_CVELEADING_golden_critical_band_lower_edge);
  RUN_TEST(test_CVELEADING_clamps_nonfinite_top_epss);
  RUN_TEST(test_CVELEADING_clamps_out_of_range_item_fields);
  RUN_TEST(test_CVELEADING_clamps_negative_and_infinite_item_fields);
  RUN_TEST(test_CVELEADING_clamps_infinite_top_epss_drives_verdict);
  RUN_TEST(test_CVELEADING_clamps_negative_zero_to_positive_zero);
  RUN_TEST(test_CVELEADING_growth_produces_the_same_bytes_as_a_preallocated_buffer);
  RUN_TEST(test_CVELEADING_over_ceiling_hands_back_no_body);
  RUN_TEST(test_CVESEARCH_item_escapes_every_field_through_the_shared_writer);
  RUN_TEST(test_CVELEADING_envelope_summary_escapes_the_repeated_cve_id);
  RUN_TEST(test_CVESEARCH_publishes_out_of_range_epss_unclamped);
  RUN_TEST(test_list_widest_full_page_stays_under_the_default_ceiling);
  RUN_TEST(test_CVE_lists_write_cvss_v4_from_its_flag_and_range);
  RUN_TEST(test_CVE_lists_write_cvss_v3_from_its_flag_and_range);
  RUN_TEST(test_CVELEADING_widest_summary_sentence_fits_its_buffer);
  RUN_TEST(test_KEVLOOKUP_every_field_is_escaped_through_its_own_class);
  RUN_TEST(test_CWELOOKUP_every_field_is_escaped_through_its_own_class);
  RUN_TEST(test_CVEEXPLOIT_every_string_is_escaped_through_its_own_class);
  RUN_TEST(test_PRIVACYMYDATA_golden);
  RUN_TEST(test_PRIVACYMYDATA_key_credit_budget_is_metered_by_the_key);
  RUN_TEST(test_PRIVACYMYDATA_vendor_keys_golden);
  RUN_TEST(test_PRIVACYMYDATA_vendor_keys_without_a_link_are_null);
  RUN_TEST(test_PRIVACYMYDATA_no_vendor_keys_is_null);
  RUN_TEST(test_PRIVACYMYDATA_resets_at_utc_is_the_reset_in_utc);
  RUN_TEST(test_PRIVACYMYDATA_unrepresentable_reset_has_a_null_utc_time);
  RUN_TEST(test_PRIVACYMYDATA_key_expiry_is_null_without_an_expiry);
  RUN_TEST(test_PRIVACYMYDATA_key_expires_at_names_the_expiry_in_utc);
  RUN_TEST(test_PRIVACYMYDATA_unrepresentable_key_expiry_has_a_null_utc_time);
  RUN_TEST(test_PRIVACYMYDATA_upgrade_url_is_shown_off_the_pro_tier);
  RUN_TEST(test_PRIVACYMYDATA_key_expiry_is_written_only_on_the_pro_tier);
  RUN_TEST(test_WEBHOOK_status_and_APIKEYCLAIM_write_one_member);
  RUN_TEST(test_PASSWORDCHECK_found_golden);
  RUN_TEST(test_PASSWORDCHECK_not_found_golden);
  RUN_TEST(test_PASSWORDCHECK_summary_groups_the_count_in_threes);
  RUN_TEST(test_DNSLOOKUP_golden);
  RUN_TEST(test_DNSLOOKUP_each_failed_status_has_its_reason);
  RUN_TEST(test_DNSLOOKUP_two_failed_types);
  RUN_TEST(test_DNSLOOKUP_no_records_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_dangling_with_provider_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_target_found_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_dangling_without_provider_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_target_found_without_provider_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_chain_of_two_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_no_cname_golden);
  RUN_TEST(test_DNSTAKEOVERCHECK_cname_is_escaped);
  RUN_TEST(test_EMAILAUTHCHECK_answered_golden);
  RUN_TEST(test_EMAILAUTHCHECK_failed_sections_golden);
  RUN_TEST(test_EMAILAUTHCHECK_inherited_dmarc_and_two_spf_records_golden);
  RUN_TEST(test_EMAILAUTHCHECK_nxdomain_spf_answer_is_available);
  RUN_TEST(test_EMAILAUTHCHECK_every_check_has_its_id_severity_and_sentence);
  RUN_TEST(test_EMAILAUTHCHECK_record_bytes_are_escaped);
  RUN_TEST(test_EMAILAUTHCHECK_every_name_value_is_written);
  RUN_TEST(test_EMAILAUTHCHECK_each_result_writes_its_detail_sentence);
  RUN_TEST(test_EMAILAUTHCHECK_docs_checks_table_matches_the_server);
  RUN_TEST(test_docs_name_each_value_of_takeover_possible);
  RUN_TEST(test_docs_cert_search_copies_match_the_server);
  RUN_TEST(test_docs_name_the_page_cap_of_the_cert_spotter_walk);
  RUN_TEST(test_docs_subdomain_enum_members_match_the_server);
  RUN_TEST(test_docs_name_both_values_of_has_public_poc);
  RUN_TEST(test_SSLCHECK_full_result_golden);
  RUN_TEST(test_SSLCHECK_every_problem_in_bit_order);
  RUN_TEST(test_SSLCHECK_each_problem_bit_writes_its_own_name);
  RUN_TEST(test_SSLCHECK_empty_texts_are_null_golden);
  RUN_TEST(test_SSLCHECK_renegotiation_null_and_each_revocation_name);
  RUN_TEST(test_SSLCHECK_certificate_names_are_escaped);
  RUN_TEST(test_SSLCHECK_listed_on_and_unavailable_follow_the_list_state);
  RUN_TEST(test_HEADERSCHECK_each_result_golden);
  RUN_TEST(test_HEADERSCHECK_redirect_target_golden);
  RUN_TEST(test_HEADERSCHECK_redirect_limit_golden);
  RUN_TEST(test_HEADERSCHECK_long_value_is_cut_at_a_whole_character);
  RUN_TEST(test_HEADERSCHECK_long_url_and_redirect_target_are_cut_at_a_whole_character);
  RUN_TEST(test_HEADERSCHECK_value_is_escaped);
  RUN_TEST(test_HEADERSCHECK_set_cookie_value_is_never_written);
  RUN_TEST(test_WHOISLOOKUP_full_registration_golden);
  RUN_TEST(test_WHOISLOOKUP_empty_texts_and_missing_iana_id_are_null_golden);
  RUN_TEST(test_WHOISLOOKUP_dnssec_signed_true_false_null_and_iana_id_zero);
  RUN_TEST(test_WHOISLOOKUP_lists_stop_at_their_max_and_count_all);
  RUN_TEST(test_WHOISLOOKUP_texts_from_the_server_are_escaped);
  RUN_TEST(test_WHOISLOOKUP_each_unavailable_reason_golden);
  RUN_TEST(test_WHOISLOOKUP_answer_from_a_whois_server_golden);
  RUN_TEST(test_WAYBACKLOOKUP_three_captures_golden);
  RUN_TEST(test_WAYBACKLOOKUP_years_online_is_the_year_difference_at_least_one);
  RUN_TEST(test_WAYBACKLOOKUP_one_capture_is_the_first_and_the_last_day);
  RUN_TEST(test_WAYBACKLOOKUP_host_without_a_capture_golden);
  RUN_TEST(test_WAYBACKLOOKUP_quota_exhausted_golden);
  RUN_TEST(test_CERTSEARCH_two_certificates_golden);
  RUN_TEST(test_CERTSEARCH_complete_walk_of_many_pages_golden);
  RUN_TEST(test_CERTSEARCH_each_unknown_value_is_null);
  RUN_TEST(test_CERTSEARCH_dns_names_stop_at_the_kept_count);
  RUN_TEST(test_CERTSEARCH_escapes_the_text_cert_spotter_sends);
  RUN_TEST(test_CERTSEARCH_host_without_a_certificate_golden);
  RUN_TEST(test_CERTSEARCH_page_of_refused_certificates_is_not_complete);
  RUN_TEST(test_CERTSEARCH_quota_exhausted_golden);
  RUN_TEST(test_SUBDOMAINENUM_dns_confirmed_names_first_in_strcmp_order_golden);
  RUN_TEST(test_SUBDOMAINENUM_lists_at_most_fifty_names_and_counts_them_all);
  RUN_TEST(test_SUBDOMAINENUM_quota_exhausted_golden);
  RUN_TEST(test_SUBDOMAINENUM_upstream_error_golden);
  RUN_TEST(test_SUBDOMAINENUM_empty_list_golden);
  RUN_TEST(test_SUBDOMAINENUM_each_wildcard_value);
  RUN_TEST(test_SUBDOMAINENUM_escapes_a_name);
  RUN_TEST(test_WATCHLISTEDIT_golden);
  RUN_TEST(test_WATCHLISTEDIT_golden_each_kind);
  RUN_TEST(test_WATCHLISTEDIT_domain_items_golden);
  RUN_TEST(test_WATCHLISTEDIT_ssl_check_item_golden);
  RUN_TEST(test_WATCHLISTEDIT_empty_list_golden);
  RUN_TEST(test_WATCHLISTEDIT_package_items_golden);
  RUN_TEST(test_WATCHLISTEDIT_package_list_golden);
  RUN_TEST(test_WATCHLISTEDIT_problems_golden);
  RUN_TEST(test_WATCHLISTEDIT_problems_give_each_problem_its_reason);
  RUN_TEST(test_WATCHLISTEDIT_problems_of_most_elements_fit_the_ceiling);
  RUN_TEST(test_WATCHLISTEDIT_item_writes_only_its_set_fields);
  RUN_TEST(test_WATCHLISTEVENTS_golden);
  RUN_TEST(test_WATCHLISTEVENTS_no_position_golden);
  RUN_TEST(test_WATCHLISTEVENTS_cves_map_keeps_the_entry_order);
  RUN_TEST(test_WATCHLISTEVENTS_dns_events_golden);
  RUN_TEST(test_WATCHLISTEVENTS_ip_events_golden);
  RUN_TEST(test_WATCHLISTEVENTS_tls_events_and_a_dns_first_value_golden);
  RUN_TEST(test_WATCHLISTEVENTS_expiry_bucket_reads_one_or_two_digits);
  RUN_TEST(test_WATCHLISTEVENTS_domain_expiring_golden);
  RUN_TEST(test_WATCHLISTEVENTS_registrar_changed_golden);
  RUN_TEST(test_WATCHLISTEVENTS_transfer_lock_removed_golden);
  RUN_TEST(test_WATCHLISTEVENTS_security_header_removed_golden);
  RUN_TEST(test_WATCHLISTEVENTS_cert_unexpected_golden);
  RUN_TEST(test_WATCHLISTEVENTS_dnssec_disabled_golden);
  RUN_TEST(test_WATCHLISTEVENTS_email_auth_degraded_golden);
  RUN_TEST(test_WATCHLISTEVENTS_domains_map_golden);
  RUN_TEST(test_WATCHLISTEVENTS_only_the_whole_null_mx_line_becomes_0_dot);
  RUN_TEST(test_WATCHLISTEVENTS_package_events_golden);
  RUN_TEST(test_WATCHLISTEVENTS_eol_events_golden);
  RUN_TEST(test_WATCHLISTEVENTS_worst_case_size);
  RUN_TEST(test_IMAGEINSPECT_golden_lists_the_matched_types_in_order);
  RUN_TEST(test_IMAGEINSPECT_lists_only_the_kept_offsets);
  RUN_TEST(test_IMAGEINSPECT_no_match_gives_an_empty_list);
  RUN_TEST(test_IMAGEINSPECT_golden_writes_each_metadata_field_and_indicator);
  RUN_TEST(test_IMAGEINSPECT_escapes_the_metadata_texts);
  RUN_TEST(test_IMAGEINSPECT_writes_the_severity_of_each_kind);
  RUN_TEST(test_docs_product_filter_note_copies_match_the_server);
  RUN_TEST(test_VENDORKEYEDIT_apply_response_shapes);
  RUN_TEST(test_VENDORKEYEDIT_status_response_names_each_state);
  RUN_TEST(test_docs_ip_lookup_vendor_slots_match_the_server);
  RUN_TEST(test_docs_ip_lookup_count_query_source_matches_the_server);
  RUN_TEST(test_docs_vendor_key_edit_answers_match_the_server);
  RUN_TEST(test_vendor_keys_script_knows_each_result_and_state);
  RUN_TEST(test_docs_privacy_vendor_keys_members_match_the_server);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
