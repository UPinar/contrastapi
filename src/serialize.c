#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include <time.h>

#include "serialize.h"
#include "version.h"
#include "validate.h"
#include "macro.h"
#include "pricing.h"
#include "emailcheck.h"
#include "header_check.h"

#define PRIVACYMYDATA_UTC_TIME_BUF_SIZE 32

#define PASSWORDCHECK_COUNT_BUF_SIZE 27

#define CVELEADING_SUMMARY_BUF_SIZE   256

#define CVELOOKUP_GHSA_DATABASE_ERROR_JSON R"({"available":false,"reason":"database_error"})"
#define CVELOOKUP_GHSA_NOT_SYNCED_JSON     R"({"available":false,"reason":"not_synced"})"

static const char* const CVELOOKUP_SSVC_LEVEL_KEYS[SSVC_MISSION_WELLBEING_LEVEL_COUNT] = { "low", "medium", "high" };

#define D3FEND_URI_PREFIX "http://d3fend.mitre.org/ontologies/d3fend.owl#"

#define IMAGEINSPECT_SIGNATURE_NOTE "A signature match is a sign, not proof: the compressed data of an image can hold the same bytes by chance."

#define IMAGEINSPECT_INDICATOR_NOTE "An indicator is a sign, not proof. Metadata is easy to write, to edit and to strip, and absent metadata is not a sign of forgery."

#define CVE_PRODUCT_FILTER_NOTE "This filter matches names exactly. It can miss a CVE whose CNA spelled the vendor or product another way. Use cpe_search to find other spellings."

static const char* const IMAGEINSPECT_IDENTIFIER_NAMES[EXIFCLIENT_IDENTIFIER_COUNT] = {
  "serial_number", "owner_name", "unique_id", "host_computer", "author", "copyright", "person_in_image", "original_file_name"
};
_Static_assert(EXIFCLIENT_IDENTIFIER_COUNT == 8, "IMAGEINSPECT_IDENTIFIER_NAMES names each ExifClientIdentifier_t");

static const char* const D3FENDFORATTACK_TACTIC_NAMES[] = {
  "Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"
};

#define CVEEXPLOIT_GITHUB_UNAVAILABLE_JSON \
  R"({"source":"github","available":false,"reason":"database_error","count":0,"top_results":[]})"
#define CVEEXPLOIT_GITHUB_NOT_SYNCED_JSON \
  R"({"source":"github","available":false,"reason":"not_synced","count":0,"top_results":[]})"
#define CVEEXPLOIT_METASPLOIT_UNAVAILABLE_JSON \
  R"({"source":"metasploit","available":false,"reason":"database_error","has_module":false,"count":0,"top_results":[]})"
#define CVEEXPLOIT_METASPLOIT_NOT_SYNCED_JSON \
  R"({"source":"metasploit","available":false,"reason":"not_synced","has_module":false,"count":0,"top_results":[]})"

#define CVEEXPLOIT_EXPLOITDB_LICENSE "GPL-2.0-only"
#define CVEEXPLOIT_EXPLOITDB_UNAVAILABLE_JSON \
  R"({"source":"exploitdb","available":false,"reason":"database_error","license":")" CVEEXPLOIT_EXPLOITDB_LICENSE R"(","count":0,"top_results":[]})"
#define CVEEXPLOIT_EXPLOITDB_NOT_SYNCED_JSON \
  R"({"source":"exploitdb","available":false,"reason":"not_synced","license":")" CVEEXPLOIT_EXPLOITDB_LICENSE R"(","count":0,"top_results":[]})"

#define CVELOOKUP_NUCLEI_TEMPLATES_NOT_SYNCED_JSON \
  R"("nuclei_templates":{"source":"nuclei-templates","available":false,"reason":"not_synced","count":0,"templates":[]})"

#define DRIVERLOOKUP_DATA_SOURCE_LOADED_JSON \
  R"("data_source":{"source":"loldrivers","available":true,"license":"Apache-2.0"})"
#define DRIVERLOOKUP_DATA_SOURCE_NOT_SYNCED_JSON \
  R"("data_source":{"source":"loldrivers","available":false,"reason":"not_synced","license":"Apache-2.0"})"
#define DRIVERLOOKUP_DATA_SOURCE_UNKNOWN_JSON \
  R"("data_source":{"source":"loldrivers","available":null,"license":"Apache-2.0"})"

#define PACKAGECHECK_DATA_SOURCE_LOADED_JSON \
  R"("data_source":{"source":"osv","available":true})"
#define PACKAGECHECK_DATA_SOURCE_NOT_SYNCED_JSON \
  R"("data_source":{"source":"osv","available":false,"reason":"not_synced"})"
#define PACKAGECHECK_DATA_SOURCE_UNKNOWN_JSON \
  R"("data_source":{"source":"osv","available":null})"

#define CVEEXPLOIT_NVD_DATABASE_ERROR_JSON \
  R"({"source":"nvd","available":false,"reason":"database_error","count":0,"top_results":[]})"
#define CVEEXPLOIT_NVD_NOT_IN_DATABASE_JSON \
  R"({"source":"nvd","available":false,"reason":"cve_not_in_database","count":0,"top_results":[]})"

static double static_clampDouble(double value, double low, double high);
static int    static_clampItemCount(int count, int max_count);
static void   static_IMAGEINSPECTWriteText(const char* key, const char* text, JsonBuf_t* json_buf);
static void   static_IMAGEINSPECTWriteMetadata(const ExifClientResult_t* exif, JsonBuf_t* json_buf);
static void   static_IMAGEINSPECTWriteIndicators(const ImageIndicatorResult_t* indicators, JsonBuf_t* json_buf);

static void static_writeCvssScore(const char* key, double score, bool has_score, JsonBuf_t* json_buf)
{
  assert(key != NULL);

  if (has_score)
    jsonbuf_appendFormat(json_buf, R"("%s":%.1f,)", key, static_clampDouble(score, 0.0, 10.0));
  else
    jsonbuf_appendFormat(json_buf, R"("%s":null,)", key);
}

static void static_writeCvssVector(const char* key, const char* vector, JsonBuf_t* json_buf)
{
  assert(key    != NULL);
  assert(vector != NULL);

  if (*vector)
  {
    jsonbuf_appendFormat(json_buf, R"("%s":")", key);
    jsonbuf_appendEscaped(json_buf, vector);
    jsonbuf_appendFormat(json_buf, R"(",)");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("%s":null,)", key);
  }
}

static void static_writeTextOrNull(const char* key, const char* text, JsonBuf_t* json_buf)
{
  assert(key  != NULL);
  assert(text != NULL);

  if (*text)
  {
    jsonbuf_appendFormat(json_buf, R"("%s":")", key);
    jsonbuf_appendEscaped(json_buf, text);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("%s":null)", key);
  }
}

static void static_writeProductFilterNote(const char* vendor, const char* product, JsonBuf_t* json_buf)
{
  assert(vendor   != NULL);
  assert(product  != NULL);
  assert(json_buf != NULL);

  if (vendor[0] == '\0' && product[0] == '\0')
    return;

  jsonbuf_appendFormat(json_buf, R"("product_filter_note":")" CVE_PRODUCT_FILTER_NOTE R"(",)");
}

static void static_CVELOOKUPWriteSsvc(const CVELOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  if (*record->ma_ssvcVersion == '\0')
  {
    jsonbuf_appendFormat(json_buf, R"("ssvc":null,)");
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("ssvc":{"exploitation":")");
  jsonbuf_appendEscaped(json_buf, record->ma_ssvcExploitation);
  jsonbuf_appendFormat(json_buf, R"(","automatable":")");
  jsonbuf_appendEscaped(json_buf, record->ma_ssvcAutomatable);
  jsonbuf_appendFormat(json_buf, R"(","technical_impact":")");
  jsonbuf_appendEscaped(json_buf, record->ma_ssvcTechnicalImpact);
  jsonbuf_appendFormat(json_buf, R"(","version":")");
  jsonbuf_appendEscaped(json_buf, record->ma_ssvcVersion);
  jsonbuf_appendFormat(json_buf, R"(",)");

  if (*record->ma_ssvcScoredAt)
  {
    jsonbuf_appendFormat(json_buf, R"("scored_at":")");
    jsonbuf_appendEscaped(json_buf, record->ma_ssvcScoredAt);
    jsonbuf_appendFormat(json_buf, R"(",)");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("scored_at":null,)");
  }

  jsonbuf_appendFormat(json_buf, R"("mission_wellbeing":{)");
  for (int level = 0; level < SSVC_MISSION_WELLBEING_LEVEL_COUNT; level++)
  {
    if (level > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"("%s":{"decision":")", CVELOOKUP_SSVC_LEVEL_KEYS[level]);
    jsonbuf_appendEscaped(json_buf, record->m_ssvcResult.ma_decisions[level]);
    jsonbuf_appendFormat(json_buf, R"(","remediation_advice":")");
    jsonbuf_appendEscaped(json_buf, record->m_ssvcResult.ma_remediationAdvice[level]);
    jsonbuf_appendFormat(json_buf, R"("})");
  }
  jsonbuf_appendFormat(json_buf, "}},");
}

static void static_CVELOOKUPWriteRecord(const CVELOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"cve_id":")");
  jsonbuf_appendEscaped(json_buf, record->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(","severity":")");
  jsonbuf_appendEscaped(json_buf, record->ma_severity);
  jsonbuf_appendFormat(json_buf, R"(",)");

  static_writeCvssScore("cvss_v3", record->m_cvssV3, *record->ma_cvssV3Vector != '\0', json_buf);
  static_writeCvssVector("cvss_v3_vector", record->ma_cvssV3Vector, json_buf);
  static_writeTextOrNull("cvss_v3_source", record->ma_cvssV3Source, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeCvssScore("cvss_v4", record->m_cvssV4, *record->ma_cvssV4Vector != '\0', json_buf);
  static_writeCvssVector("cvss_v4_vector", record->ma_cvssV4Vector, json_buf);
  static_writeTextOrNull("cvss_v4_source", record->ma_cvssV4Source, json_buf);
  jsonbuf_appendFormat(json_buf, ",");

  jsonbuf_appendFormat(json_buf, R"("published_time":")");
  jsonbuf_appendEscaped(json_buf, record->ma_publishedTime);
  jsonbuf_appendFormat(json_buf, R"(","epss_score":%.5f,)", record->m_epssScore);
  jsonbuf_appendFormat(json_buf, R"("epss_percentile":%.5f,)", record->m_epssPercentile);
  jsonbuf_appendFormat(json_buf, R"("cwe_id":")");
  jsonbuf_appendEscaped(json_buf, record->ma_cweId);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeTextOrNull("cwe_source", record->ma_cweSource, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"cwes":)");
  jsonbuf_appendJsonText(json_buf, record->mp_cwes ? record->mp_cwes : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"in_kev":%s,)", record->m_inKev ? "true" : "false");
  jsonbuf_appendFormat(json_buf, R"("kev_date_added":")");
  jsonbuf_appendEscaped(json_buf, record->ma_kevDateAdded);
  jsonbuf_appendFormat(json_buf, R"(","vulnerability_status":")");
  jsonbuf_appendEscaped(json_buf, record->ma_vulnerabilityStatus);
  jsonbuf_appendFormat(json_buf, R"(","affected_products":)");
  jsonbuf_appendJsonText(json_buf, record->mp_affectedProducts ? record->mp_affectedProducts : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"affected_product_count":%d,"product_count_by_vendor":)", record->m_affectedProductCount);
  jsonbuf_appendJsonText(json_buf, record->mp_productCountByVendor ? record->mp_productCountByVendor : "{}");
  jsonbuf_appendFormat(json_buf, R"(,"refs":)");
  jsonbuf_appendJsonText(json_buf, record->mp_refs ? record->mp_refs : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"ref_count":%d,)", record->m_refCount);
  jsonbuf_appendFormat(json_buf, R"("poc_count":%d,)", record->m_pocCount);
  jsonbuf_appendFormat(json_buf, R"("vendor_advisory_count":%d,)", record->m_vendorAdvisoryCount);
  jsonbuf_appendFormat(json_buf, R"("epss_trend":)");
  jsonbuf_appendJsonText(json_buf, record->mp_epssTrend ? record->mp_epssTrend : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"cve_tags":)");
  jsonbuf_appendJsonText(json_buf, record->mp_cveTags ? record->mp_cveTags : "[]");
  jsonbuf_appendFormat(json_buf, ",");
  if (record->m_isMetasploitFeedLoaded)
  {
    jsonbuf_appendFormat(json_buf, R"("has_metasploit_module":%s,)", record->m_metasploitModuleCount > 0 ? "true" : "false");
    jsonbuf_appendFormat(json_buf, R"("metasploit_module_count":%d,)", record->m_metasploitModuleCount);
  }
  else
    jsonbuf_appendFormat(json_buf, R"("has_metasploit_module":null,"metasploit_module_count":null,)");

  if (record->m_isNucleiTemplateFeedLoaded)
  {
    jsonbuf_appendFormat(json_buf, R"("nuclei_templates":{"source":"nuclei-templates","available":true,"count":%d,"templates":)",
                         record->m_nucleiTemplateCount);
    jsonbuf_appendJsonText(json_buf, record->mp_nucleiTemplates ? record->mp_nucleiTemplates : "[]");
    jsonbuf_appendFormat(json_buf, "},");
  }
  else
    jsonbuf_appendFormat(json_buf, CVELOOKUP_NUCLEI_TEMPLATES_NOT_SYNCED_JSON ",");
  jsonbuf_appendFormat(json_buf, R"("description":")");
  jsonbuf_appendEscaped(json_buf, record->ma_description);
  jsonbuf_appendFormat(json_buf, R"(",)");

  if (*record->ma_ransomwareCampaign)
  {
    jsonbuf_appendFormat(json_buf, R"("ransomware_campaign":")");
    jsonbuf_appendEscaped(json_buf, record->ma_ransomwareCampaign);
    jsonbuf_appendFormat(json_buf, R"(",)");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("ransomware_campaign":null,)");
  }

  static_CVELOOKUPWriteSsvc(record, json_buf);

  if (!record->m_isGhsaAsked)
  {
    jsonbuf_appendFormat(json_buf, R"("ghsa":"/cve_lookup/)");
    jsonbuf_appendEscaped(json_buf, record->ma_cveId);
    jsonbuf_appendFormat(json_buf, R"(?include_ghsa=true")");
  }
  else if (record->m_ghsaUnavailable)
    jsonbuf_appendFormat(json_buf, R"("ghsa":)" CVELOOKUP_GHSA_DATABASE_ERROR_JSON);
  else if (!record->m_isGhsaFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("ghsa":)" CVELOOKUP_GHSA_NOT_SYNCED_JSON);
  else if (record->mp_ghsa)
  {
    jsonbuf_appendFormat(json_buf, R"("ghsa":)");
    jsonbuf_appendJsonText(json_buf, record->mp_ghsa);
  }
  else
    jsonbuf_appendFormat(json_buf, R"("ghsa":null)");
  
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_CVELOOKUP_response(const CVELOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  static_CVELOOKUPWriteRecord(record, json_buf);
  jsonbuf_appendFormat(json_buf, "\n");
}

static void static_writeNotProcessedIds(const char (*ids)[BULK_ID_MAX_LEN + 1], int count, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("not_processed":[)");
  for (int i = 0; i < count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    jsonbuf_appendFormat(json_buf, R"(")");
    jsonbuf_appendEscaped(json_buf, ids[i]);
    jsonbuf_appendFormat(json_buf, R"(")");
  }
  jsonbuf_appendFormat(json_buf, "],");
}

void serialize_CVELOOKUPBULK_response(const CVELOOKUPBULKResult_t* results, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf,
    R"({"total":%d,"processed":%d,"successful":%d,"skipped":%d,"failed":%d,)",
    results->m_total, results->m_processed, results->m_successful, results->m_skipped, results->m_failed);
  static_writeNotProcessedIds(results->mp_notProcessedIds, results->m_notProcessedCount, json_buf);
  jsonbuf_appendFormat(json_buf, R"("results":[)");

  for (int i = 0; i < results->m_successful; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    static_CVELOOKUPWriteRecord(&results->mp_items[i], json_buf);
    jsonbuf_appendFormat(json_buf, "\n");
  }

  jsonbuf_appendFormat(json_buf, "]}");
}

void serialize_CVEPRODUCTS_response(const CVEPRODUCTSResult_t* result, const CVEPRODUCTSParams_t* params, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  long next_offset = (long)params->m_offset + result->m_listedProductCount;
  jsonbuf_appendFormat(json_buf, R"({"cve_id":")");
  jsonbuf_appendEscaped(json_buf, params->ma_cveId);
  jsonbuf_appendFormat(json_buf,
    R"(","total":%d,"limit":%d,"offset":%d,"next_offset":%d,"results":)",
    result->m_affectedProductCount, params->m_limit, params->m_offset,
    next_offset > INT_MAX ? INT_MAX : (int)next_offset);
  jsonbuf_appendJsonText(json_buf, result->mp_affectedProducts ? result->mp_affectedProducts : "[]");
  jsonbuf_appendFormat(json_buf, "}\n");
}

static void static_cveListWriteItem(const CveListItem_t* item, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"cve_id":")");
  jsonbuf_appendEscaped(json_buf, item->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(","severity":")");
  jsonbuf_appendEscaped(json_buf, item->ma_severity);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeCvssScore("cvss_v3", item->m_cvssV3, item->m_hasCvssV3, json_buf);
  static_writeTextOrNull("cvss_v3_source", item->ma_cvssV3Source, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeCvssScore("cvss_v4", item->m_cvssV4, item->m_hasCvssV4, json_buf);
  static_writeTextOrNull("cvss_v4_source", item->ma_cvssV4Source, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  jsonbuf_appendFormat(json_buf, R"("epss_score":%.5f,)", item->m_epssScore);
  jsonbuf_appendFormat(json_buf, R"("epss_percentile":%.5f,)", item->m_epssPercentile);
  jsonbuf_appendFormat(json_buf, R"("in_kev":%s,)", item->m_inKev ? "true" : "false");
  jsonbuf_appendFormat(json_buf, R"("published_time":")");
  jsonbuf_appendEscaped(json_buf, item->ma_publishedTime);
  jsonbuf_appendFormat(json_buf, R"(","cwe_id":")");
  jsonbuf_appendEscaped(json_buf, item->ma_cweId);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeTextOrNull("cwe_source", item->ma_cweSource, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_CVESEARCH_response(const CveListResult_t* results, const CVESEARCHParams_t* params, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  long next_offset = (long)params->m_offset + results->m_count;
  jsonbuf_appendFormat(json_buf,
    R"({"total":%d,"limit":%d,"offset":%d,"next_offset":%d,)",
    results->m_total, params->m_limit, params->m_offset,
    next_offset > INT_MAX ? INT_MAX : (int)next_offset);
  static_writeProductFilterNote(params->ma_vendor, params->ma_product, json_buf);
  jsonbuf_appendFormat(json_buf, R"("results":[)");

  for (int i = 0; i < results->m_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    static_cveListWriteItem(&results->mp_items[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, R"(]})" "\n");
}

static void static_KEVLOOKUPWriteRecord(const KEVLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"cve_id":")");
  jsonbuf_appendEscaped(json_buf, record->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(","in_kev":%s,"date_added":")", record->m_inKev ? "true" : "false");
  jsonbuf_appendEscaped(json_buf, record->ma_dateAdded);
  jsonbuf_appendFormat(json_buf, R"(","vendor_project":")");
  jsonbuf_appendEscaped(json_buf, record->ma_vendorProject);
  jsonbuf_appendFormat(json_buf, R"(","product":")");
  jsonbuf_appendEscaped(json_buf, record->ma_product);
  jsonbuf_appendFormat(json_buf, R"(","patch_deadline":")");
  jsonbuf_appendEscaped(json_buf, record->ma_patchDeadline);
  jsonbuf_appendFormat(json_buf, R"(","required_action":")");
  jsonbuf_appendEscaped(json_buf, record->ma_requiredAction);
  jsonbuf_appendFormat(json_buf, R"(","known_ransomware_use":%s,)", record->m_knownRansomwareUse ? "true" : "false");
  jsonbuf_appendFormat(json_buf, R"("vulnerability_name":")");
  jsonbuf_appendEscaped(json_buf, record->ma_vulnerabilityName);
  jsonbuf_appendFormat(json_buf, R"(","short_description":")");
  jsonbuf_appendEscaped(json_buf, record->ma_shortDescription);
  jsonbuf_appendFormat(json_buf, R"(","notes":")");
  jsonbuf_appendEscaped(json_buf, record->mp_notes);
  jsonbuf_appendFormat(json_buf, R"(","cwes":)");
  jsonbuf_appendJsonText(json_buf, record->mp_cwes ? record->mp_cwes : "null");
  jsonbuf_appendFormat(json_buf, R"(,"date_removed":")");
  jsonbuf_appendEscaped(json_buf, record->ma_dateRemoved);
  jsonbuf_appendFormat(json_buf, R"("})");
}

void serialize_KEVLOOKUP_response(const KEVLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  static_KEVLOOKUPWriteRecord(record, json_buf);
  jsonbuf_appendFormat(json_buf, "\n");
}

static void static_CWELOOKUPWriteRecord(const CWELOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"cwe_id":")");
  jsonbuf_appendEscaped(json_buf, record->ma_cweId);
  jsonbuf_appendFormat(json_buf, R"(","name":")");
  jsonbuf_appendEscaped(json_buf, record->ma_name);
  jsonbuf_appendFormat(json_buf, R"(","abstraction":")");
  jsonbuf_appendEscaped(json_buf, record->ma_abstraction);
  jsonbuf_appendFormat(json_buf, R"(","status":")");
  jsonbuf_appendEscaped(json_buf, record->ma_status);
  jsonbuf_appendFormat(json_buf, R"(","description":")");
  jsonbuf_appendEscaped(json_buf, record->ma_description);
  jsonbuf_appendFormat(json_buf, R"(","extended_description":)");
  if (record->mp_extendedDescription && *record->mp_extendedDescription)
  {
    jsonbuf_appendFormat(json_buf, R"(")");
    jsonbuf_appendEscaped(json_buf, record->mp_extendedDescription);
    jsonbuf_appendFormat(json_buf, R"(")");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, R"(,"likelihood_of_exploit":")");
  jsonbuf_appendEscaped(json_buf, record->ma_likelihood);
  jsonbuf_appendFormat(json_buf, R"(","mitigations":)");
  jsonbuf_appendJsonText(json_buf, (record->mp_mitigations && *record->mp_mitigations) ? record->mp_mitigations : "null");
  jsonbuf_appendFormat(json_buf, R"(,"examples":)");
  jsonbuf_appendJsonText(json_buf, (record->mp_examples && *record->mp_examples) ? record->mp_examples : "null");
  jsonbuf_appendFormat(json_buf, ",");
  jsonbuf_appendFormat(json_buf, R"("parent_cwe":")");
  jsonbuf_appendEscaped(json_buf, record->ma_parentCwe);
  jsonbuf_appendFormat(json_buf, R"(","cve_count":%d,)", record->m_cveCount);
  jsonbuf_appendFormat(json_buf, R"("kev_count":%d,)", record->m_kevCount);
  jsonbuf_appendFormat(json_buf, R"("avg_cvss":%.2f,)", record->m_avgCvss);
  jsonbuf_appendFormat(json_buf, R"("avg_epss":%.4f,)", record->m_avgEpss);
  jsonbuf_appendFormat(json_buf, R"("updated_at":")");
  jsonbuf_appendEscaped(json_buf, record->ma_updatedAt);
  jsonbuf_appendFormat(json_buf, R"("})");
}

void serialize_CWELOOKUP_response(const CWELOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  static_CWELOOKUPWriteRecord(record, json_buf);
  jsonbuf_appendFormat(json_buf, "\n");
}

static double static_clampDouble(double value, double low, double high)
{
  assert(low <= high);

  if (!isfinite(value) || value <= low) 
    return low;
  else if (value > high)                      
    return high;
  else                                      
    return value;
}

static int static_clampItemCount(int count, int max_count)
{
  return count < max_count ? count : max_count;
}

static void static_cveListWriteItemClamped(const CveListItem_t* item, JsonBuf_t* json_buf)
{
  CveListItem_t clamped = *item;
  clamped.m_epssScore      = static_clampDouble(item->m_epssScore, 0.0, 1.0);
  clamped.m_epssPercentile = static_clampDouble(item->m_epssPercentile, 0.0, 1.0);

  static_cveListWriteItem(&clamped, json_buf);
}

void serialize_CVELEADING_response(const CveListResult_t* results, const CVELEADINGParams_t* params, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  int kev_count = 0;
  for (int i = 0; i < results->m_count; i++)
    if (results->mp_items[i].m_inKev) kev_count++;

  double top_epss = static_clampDouble((results->m_count > 0) ? results->mp_items[0].m_epssScore : 0.0, 0.0, 1.0);

  const char* verdict;
  if (results->m_count <= 0)
    verdict = "none";
  else if (top_epss >= 0.5)
    verdict = "critical";
  else if (top_epss >= 0.2)
    verdict = "high";
  else if (top_epss >= 0.05)
    verdict = "moderate";
  else
    verdict = "low";

  char summary[CVELEADING_SUMMARY_BUF_SIZE];
  int summary_len;
  if (results->m_count <= 0)
    summary_len = snprintf(summary, sizeof(summary), "No CVEs matched this filter.");
  else
    summary_len = snprintf(summary, sizeof(summary),
                          "%d CVE%s ranked by exploitation probability; %s leads at %.1f%% (EPSS, next 30 days). %d in CISA KEV.",
                          results->m_count,
                          results->m_count == 1 ? "" : "s",
                          results->mp_items[0].ma_cveId,
                          top_epss * 100.0,
                          kev_count);
  if (summary_len < 0 || (size_t)summary_len >= sizeof(summary)) summary[0] = '\0';

  jsonbuf_appendFormat(json_buf,
    R"({"count":%d,"total":%d,"limit":%d,"verdict":"%s","summary":")",
    results->m_count, results->m_total, params->m_limit, verdict);
  jsonbuf_appendEscaped(json_buf, summary);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeProductFilterNote(params->ma_vendor, params->ma_product, json_buf);
  jsonbuf_appendFormat(json_buf, R"("results":[)");

  for (int i = 0; i < results->m_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    static_cveListWriteItemClamped(&results->mp_items[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, R"(]})" "\n");
}

void serialize_HEALTH_response(const HEALTHData_t* db, JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);

  if (!db)
  {
    jsonbuf_appendFormat(json_buf, R"({"status":"unavailable","version":"%s","db":null})" "\n", CONTRASTAPI_VERSION);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"({"status":"ok","version":"%s","db":{)", CONTRASTAPI_VERSION);

  jsonbuf_appendFormat(json_buf, R"("nvd":{)");
  jsonbuf_appendFormat(json_buf, R"("cve_count":%d,)", db->m_cveCount);
  jsonbuf_appendFormat(json_buf, R"("last_added":{"cve_id":")");
  jsonbuf_appendEscaped(json_buf, db->ma_nvdLastCveId);
  jsonbuf_appendFormat(json_buf, R"(","published_time":")");
  jsonbuf_appendEscaped(json_buf, db->ma_nvdLastPublishedTime);
  jsonbuf_appendFormat(json_buf, R"("}},)");

  jsonbuf_appendFormat(json_buf, R"("kev":{)");
  jsonbuf_appendFormat(json_buf, R"("entry_count":%d,)", db->m_kevCount);
  jsonbuf_appendFormat(json_buf, R"("last_added":{"cve_id":")");
  jsonbuf_appendEscaped(json_buf, db->ma_kevLastCveId);
  jsonbuf_appendFormat(json_buf, R"(","date_added":")");
  jsonbuf_appendEscaped(json_buf, db->ma_kevLastDateAdded);
  jsonbuf_appendFormat(json_buf, R"("}},)");

  jsonbuf_appendFormat(json_buf, R"("cwe":{)");
  jsonbuf_appendFormat(json_buf, R"("entry_count":%d,)", db->m_cweCount);
  jsonbuf_appendFormat(json_buf, R"("last_updated":{"cwe_id":")");
  jsonbuf_appendEscaped(json_buf, db->ma_cweLastId);
  jsonbuf_appendFormat(json_buf, R"(","updated_at":")");
  jsonbuf_appendEscaped(json_buf, db->ma_cweLastUpdatedAt);
  jsonbuf_appendFormat(json_buf, R"("}},)");

  jsonbuf_appendFormat(json_buf, R"("feeds":[)");
  int feed_count = static_clampItemCount(db->m_feedCount, HEALTH_MAX_FEEDS);
  for (int i = 0; i < feed_count; i++)
  {
    const HEALTHFeed_t* feed = &db->ma_feeds[i];
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"({"name":")");
    jsonbuf_appendEscaped(json_buf, feed->ma_name);
    if (*feed->ma_lastSynced)
    {
      jsonbuf_appendFormat(json_buf, R"(","last_synced":")");
      jsonbuf_appendEscaped(json_buf, feed->ma_lastSynced);
      jsonbuf_appendFormat(json_buf, R"(",)");
    }
    else
      jsonbuf_appendFormat(json_buf, R"(","last_synced":null,)");
    jsonbuf_appendFormat(json_buf, R"("last_status":")");
    jsonbuf_appendEscaped(json_buf, feed->ma_lastStatus);
    jsonbuf_appendFormat(json_buf, R"(","records_updated":%d})", feed->m_recordsUpdated);
  }
  jsonbuf_appendFormat(json_buf, R"(])");

  jsonbuf_appendFormat(json_buf, R"(}})" "\n");
}

void serialize_CRYPTOCHECKOUT_response(const char* invoice_id, const char* invoice_url, const char* order_id, JsonBuf_t* json_buf)
{
  assert(invoice_id != NULL);
  assert(invoice_url != NULL);
  assert(order_id != NULL);

  jsonbuf_appendFormat(json_buf, R"({"invoice_id":")");
  jsonbuf_appendEscaped(json_buf, invoice_id);
  jsonbuf_appendFormat(json_buf, R"(","invoice_url":")");
  jsonbuf_appendEscaped(json_buf, invoice_url);
  jsonbuf_appendFormat(json_buf, R"(","order_id":")");
  jsonbuf_appendEscaped(json_buf, order_id);
  jsonbuf_appendFormat(json_buf, R"("})" "\n");
}

void serialize_WEBHOOK_status_response(const char* status_text, JsonBuf_t* json_buf)
{
  assert(status_text != NULL);

  jsonbuf_appendFormat(json_buf, R"({"status":")");
  jsonbuf_appendEscaped(json_buf, status_text);
  jsonbuf_appendFormat(json_buf, R"("})" "\n");
}

void serialize_APIKEYCLAIM_response(const char* api_key, JsonBuf_t* json_buf)
{
  assert(api_key != NULL);

  jsonbuf_appendFormat(json_buf, R"({"api_key":")");
  jsonbuf_appendEscaped(json_buf, api_key);
  jsonbuf_appendFormat(json_buf, R"("})" "\n");
}

void serialize_error_response(const char* code, const char* message, JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"error":{"code":")");
  jsonbuf_appendEscaped(json_buf, code);
  jsonbuf_appendFormat(json_buf, R"(","message":")");
  jsonbuf_appendEscaped(json_buf, message);
  jsonbuf_appendFormat(json_buf, R"("}})" "\n");
}

void serialize_CVERISKSCORE_response(const CVERISKSCORERecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, "{");
  jsonbuf_appendFormat(json_buf, R"("score":%.1f,)", record->m_score);
  jsonbuf_appendFormat(json_buf, R"("label":")");
  jsonbuf_appendEscaped(json_buf, record->ma_label);
  jsonbuf_appendFormat(json_buf, R"(",)");
  jsonbuf_appendFormat(json_buf, R"("has_public_poc":%s,)", record->m_hasPublicPoc ? "true" : "null");
  jsonbuf_appendFormat(json_buf,
              R"("components":{)"
              R"("exploitability":{"score":%.2f,"max":60.00},)"
              R"("impact":{"score":%.2f,"max":30.00},)"
              R"("evidence":{"score":%.2f,"max":10.00})"
              R"(}})" "\n",
              record->m_exploitabilityComponent, record->m_impactComponent, record->m_evidenceComponent);
}

static const char* static_CVEEXPLOITHasPublicExploitJson(const CVEEXPLOITRecord_t* record)
{
  bool metasploit_found = record->m_metasploitAvailable && record->m_metasploitModuleTotal > 0;
  bool nvd_found        = record->m_nvdAvailable        && record->m_nvdExploitRefTotal > 0;
  bool exploitdb_found  = record->m_exploitdbAvailable  && record->m_exploitdbEntryTotal > 0;

  if (metasploit_found || nvd_found || exploitdb_found)
    return "true";
  else
    return "null";
}

static void static_CVEEXPLOITWriteGithubSource(const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_githubAvailable)
  {
    if (record->m_isGithubTableEmpty)
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_GITHUB_NOT_SYNCED_JSON);
    else
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_GITHUB_UNAVAILABLE_JSON);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"({"source":"github","available":true,"count":%d,)", record->m_githubPocRepoTotal);
  jsonbuf_appendFormat(json_buf, R"("top_results":[)");
  int repo_count = static_clampItemCount(record->m_githubTopStarredRepoCount, CVEEXPLOIT_MAX_GITHUB_REPOS);
  for (int i = 0; i < repo_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"({"url":")");
    jsonbuf_appendEscaped(json_buf, record->ma_githubTopStarredRepos[i].ma_url);
    jsonbuf_appendFormat(json_buf, R"(","name":")");
    jsonbuf_appendEscaped(json_buf, record->ma_githubTopStarredRepos[i].ma_name);
    jsonbuf_appendFormat(json_buf, R"(","stars":%d})", record->ma_githubTopStarredRepos[i].m_starCount);
  }
  jsonbuf_appendFormat(json_buf, R"(]})");
}

static void static_CVEEXPLOITWriteMetasploitSource(const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_metasploitAvailable)
  {
    if (record->m_isMetasploitTableEmpty)
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_METASPLOIT_NOT_SYNCED_JSON);
    else
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_METASPLOIT_UNAVAILABLE_JSON);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"({"source":"metasploit","available":true,"has_module":%s,"count":%d,)",
                       record->m_metasploitModuleTotal > 0 ? "true" : "false", record->m_metasploitModuleTotal);
  jsonbuf_appendFormat(json_buf, R"("top_results":[)");
  int module_count = static_clampItemCount(record->m_metasploitModuleCount, CVEEXPLOIT_METASPLOIT_MAX_MODULES);
  for (int i = 0; i < module_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"({"name":")");
    jsonbuf_appendEscaped(json_buf, record->ma_metasploitModules[i].ma_name);
    jsonbuf_appendFormat(json_buf, R"(","type":")");
    jsonbuf_appendEscaped(json_buf, record->ma_metasploitModules[i].ma_type);
    jsonbuf_appendFormat(json_buf, R"("})");
  }
  jsonbuf_appendFormat(json_buf, R"(]})");
}

static void static_CVEEXPLOITWriteNvdSource(const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_nvdAvailable)
  {
    if (record->m_cveNotInLocalDatabase)
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_NVD_NOT_IN_DATABASE_JSON);
    else
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_NVD_DATABASE_ERROR_JSON);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"({"source":"nvd","available":true,"count":%d,)", record->m_nvdExploitRefTotal);
  jsonbuf_appendFormat(json_buf, R"("top_results":[)");
  int ref_count = static_clampItemCount(record->m_nvdExploitRefCount, CVEEXPLOIT_NVD_MAX_REFS);
  for (int i = 0; i < ref_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"({"url":")");
    jsonbuf_appendEscaped(json_buf, record->ma_nvdExploitRefs[i].ma_url);
    jsonbuf_appendFormat(json_buf, R"("})");
  }
  jsonbuf_appendFormat(json_buf, R"(]})");
}

static void static_CVEEXPLOITWriteExploitdbSource(const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_exploitdbAvailable)
  {
    if (record->m_isExploitdbTableEmpty)
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_EXPLOITDB_NOT_SYNCED_JSON);
    else
      jsonbuf_appendFormat(json_buf, CVEEXPLOIT_EXPLOITDB_UNAVAILABLE_JSON);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"({"source":"exploitdb","available":true,"license":")" CVEEXPLOIT_EXPLOITDB_LICENSE R"(","count":%d,)",
                       record->m_exploitdbEntryTotal);
  jsonbuf_appendFormat(json_buf, R"("top_results":[)");
  int entry_count = static_clampItemCount(record->m_exploitdbEntryCount, CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES);
  for (int i = 0; i < entry_count; i++)
  {
    const CVEEXPLOITExploitdbEntry_t* entry = &record->ma_exploitdbEntries[i];
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    jsonbuf_appendFormat(json_buf, R"({"edb_id":%d,"url":")", entry->m_edbId);
    jsonbuf_appendEscaped(json_buf, entry->ma_url);
    jsonbuf_appendFormat(json_buf, R"(","type":")");
    jsonbuf_appendEscaped(json_buf, entry->ma_type);
    jsonbuf_appendFormat(json_buf, R"(","platform":")");
    jsonbuf_appendEscaped(json_buf, entry->ma_platform);
    if (entry->ma_datePublished[0] == '\0')
      jsonbuf_appendFormat(json_buf, R"(","date_published":null,)");
    else
    {
      jsonbuf_appendFormat(json_buf, R"(","date_published":")");
      jsonbuf_appendEscaped(json_buf, entry->ma_datePublished);
      jsonbuf_appendFormat(json_buf, R"(",)");
    }
    jsonbuf_appendFormat(json_buf, R"("verified":%s})", entry->m_isVerified ? "true" : "false");
  }
  jsonbuf_appendFormat(json_buf, R"(]})");
}

void serialize_CVEEXPLOIT_response(const CVEEXPLOITRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"cve_id":")");
  jsonbuf_appendEscaped(json_buf, record->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(",)");
  if (record->m_githubAvailable)
    jsonbuf_appendFormat(json_buf, R"("exploits_found":%d,)", record->m_githubPocRepoTotal);
  else
    jsonbuf_appendFormat(json_buf, R"("exploits_found":null,)");
  jsonbuf_appendFormat(json_buf, R"("has_public_exploit":%s,)", static_CVEEXPLOITHasPublicExploitJson(record));
  if (record->m_nvdAvailable)
    jsonbuf_appendFormat(json_buf, R"("in_kev":%s,)", record->m_inKev ? "true" : "false");
  else
    jsonbuf_appendFormat(json_buf, R"("in_kev":null,)");
  jsonbuf_appendFormat(json_buf, R"("sources":[)");
  static_CVEEXPLOITWriteGithubSource(record, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_CVEEXPLOITWriteMetasploitSource(record, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_CVEEXPLOITWriteNvdSource(record, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_CVEEXPLOITWriteExploitdbSource(record, json_buf);
  jsonbuf_appendFormat(json_buf, R"(]})" "\n");
}

static void static_CVETRIAGEWriteItem(const CVETRIAGEItem_t* item, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "{\"cve_id\":\"");
  jsonbuf_appendEscaped(json_buf, item->ma_cveId);
  jsonbuf_appendFormat(json_buf, "\",\"risk_score\":%.1f,", item->m_riskScore);
  jsonbuf_appendFormat(json_buf, "\"label\":\"");
  jsonbuf_appendEscaped(json_buf, item->ma_label);
  jsonbuf_appendFormat(json_buf, "\"}");
}

void serialize_CVETRIAGE_response(const CVETRIAGEResult_t* results, const CVETRIAGEParams_t* params, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  long next_offset = (long)params->m_offset + results->m_count;
  jsonbuf_appendFormat(json_buf,
    "{\"total\":%d,\"limit\":%d,\"offset\":%d,\"next_offset\":%d,",
    results->m_total, params->m_limit, params->m_offset,
    next_offset > INT_MAX ? INT_MAX : (int)next_offset);
  static_writeProductFilterNote(params->ma_vendor, params->ma_product, json_buf);
  jsonbuf_appendFormat(json_buf, "\"results\":[");

  for (int i = 0; i < results->m_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    static_CVETRIAGEWriteItem(&results->mp_items[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, "]}\n");
}

void serialize_CVETRIAGEBULK_response(const CVETRIAGEBULKResult_t* results, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf,
    "{\"total\":%d,\"processed\":%d,\"successful\":%d,\"skipped\":%d,\"failed\":%d,",
    results->m_total, results->m_processed, results->m_successful, results->m_skipped, results->m_failed);
  static_writeNotProcessedIds(results->mp_notProcessedIds, results->m_notProcessedCount, json_buf);
  jsonbuf_appendFormat(json_buf, "\"results\":[");

  for (int i = 0; i < results->m_successful; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_CVETRIAGEWriteItem(&results->mp_items[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, "]}\n");
}

static void static_PRODUCTEXPOSUREWriteEol(const PRODUCTEXPOSUREEol_t* eol, JsonBuf_t* json_buf)
{
  if (!eol->m_hasEol)
  {
    jsonbuf_appendFormat(json_buf, R"("eol":null)");
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("eol":{"source":"endoflife.date","product":")");
  jsonbuf_appendEscaped(json_buf, eol->ma_eolProduct);
  jsonbuf_appendFormat(json_buf, R"(","url":")");
  jsonbuf_appendEscaped(json_buf, eol->ma_eolUrl);
  jsonbuf_appendFormat(json_buf, R"(",)");

  int series_cycle_count = static_clampItemCount(eol->m_eolSeriesCycleCount, PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX);
  if (series_cycle_count == 1)
  {
    const PRODUCTEXPOSUREEolCycle_t* cycle = &eol->ma_eolSeriesCycles[0];
    jsonbuf_appendFormat(json_buf, R"("cycle":{"name":")");
    jsonbuf_appendEscaped(json_buf, cycle->ma_name);
    jsonbuf_appendFormat(json_buf, R"(",)");
    static_writeTextOrNull("eol_date", cycle->ma_eolDate, json_buf);
    jsonbuf_appendFormat(json_buf, R"(,"is_eol":%s,"is_maintained":%s,"is_lts":%s,)",
                         cycle->m_isEol ? "true" : "false", cycle->m_isMaintained ? "true" : "false", cycle->m_isLts ? "true" : "false");
    static_writeTextOrNull("latest_version", cycle->ma_latestVersion, json_buf);
    jsonbuf_appendFormat(json_buf, R"(},"cycle_variants":null,)");
  }
  else if (series_cycle_count > 1)
  {
    jsonbuf_appendFormat(json_buf, R"("cycle":null,"cycle_variants":[)");
    for (int i = 0; i < series_cycle_count; i++)
    {
      const PRODUCTEXPOSUREEolCycle_t* variant = &eol->ma_eolSeriesCycles[i];
      jsonbuf_appendFormat(json_buf, i > 0 ? R"(,{"name":")" : R"({"name":")");
      jsonbuf_appendEscaped(json_buf, variant->ma_name);
      jsonbuf_appendFormat(json_buf, R"(",)");
      static_writeTextOrNull("eol_date", variant->ma_eolDate, json_buf);
      jsonbuf_appendFormat(json_buf, R"(,"is_eol":%s,"is_maintained":%s})",
                           variant->m_isEol ? "true" : "false", variant->m_isMaintained ? "true" : "false");
    }
    jsonbuf_appendFormat(json_buf, R"(],)");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("cycle":null,"cycle_variants":null,)");
  }

  jsonbuf_appendFormat(json_buf, R"("maintained_cycles":[)");
  int maintained_cycle_count = static_clampItemCount(eol->m_eolMaintainedCycleCount, PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX);
  for (int i = 0; i < maintained_cycle_count; i++)
  {
    const PRODUCTEXPOSUREEolCycle_t* maintained = &eol->ma_eolMaintainedCycles[i];
    jsonbuf_appendFormat(json_buf, i > 0 ? R"(,{"name":")" : R"({"name":")");
    jsonbuf_appendEscaped(json_buf, maintained->ma_name);
    jsonbuf_appendFormat(json_buf, R"(",)");
    static_writeTextOrNull("eol_date", maintained->ma_eolDate, json_buf);
    jsonbuf_appendFormat(json_buf, R"(,"is_lts":%s})", maintained->m_isLts ? "true" : "false");
  }
  jsonbuf_appendFormat(json_buf, R"(],"maintained_cycles_truncated":%s})", eol->m_hasMoreEolMaintainedCycles ? "true" : "false");
}

void serialize_PRODUCTEXPOSURE_response(const PRODUCTEXPOSURERecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, "{\"vendor\":\"");
  jsonbuf_appendEscaped(json_buf, record->ma_vendor);
  jsonbuf_appendFormat(json_buf, "\",\"product\":\"");
  jsonbuf_appendEscaped(json_buf, record->ma_product);
  jsonbuf_appendFormat(json_buf,
    "\",\"exposure\":{\"total_cves\":%d,\"critical\":%d,\"high\":%d,\"medium\":%d,\"low\":%d,\"kev_count\":%d,",
    record->m_totalCveCount, record->m_criticalCount, record->m_highCount, record->m_mediumCount, record->m_lowCount, record->m_kevCount);
  jsonbuf_appendFormat(json_buf,
    "\"max_cvss\":%.1f,\"avg_cvss\":%.2f,\"max_epss\":%.4f,\"poc_backed_count\":%d,\"worst_risk_score\":%.1f,",
    record->m_maxCvss, record->m_avgCvss, record->m_maxEpss, record->m_pocBackedCount, record->m_worstRiskScore);
  jsonbuf_appendFormat(json_buf, "\"most_recent_published\":\"");
  jsonbuf_appendEscaped(json_buf, record->ma_mostRecentPublished);
  jsonbuf_appendFormat(json_buf, "\"},");
  static_writeProductFilterNote(record->ma_vendor, record->ma_product, json_buf);
  jsonbuf_appendFormat(json_buf, "\"top_cves\":[");
  int top_cve_count = static_clampItemCount(record->m_topCveCount, PRODUCTEXPOSURE_TOP_N);
  for (int i = 0; i < top_cve_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_CVETRIAGEWriteItem(&record->ma_topCves[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, "],");
  static_PRODUCTEXPOSUREWriteEol(&record->m_eol, json_buf);
  jsonbuf_appendFormat(json_buf, "}\n");
}

void serialize_CPESEARCH_response(const CPESEARCHResult_t* results, const CPESEARCHParams_t* params, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  long next_offset = (long)params->m_offset + results->m_count;
  jsonbuf_appendFormat(json_buf,
    "{\"total\":%d,\"limit\":%d,\"offset\":%d,\"next_offset\":%d,\"results\":[",
    results->m_total, params->m_limit, params->m_offset,
    next_offset > INT_MAX ? INT_MAX : (int)next_offset);

  for (int i = 0; i < results->m_count; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    const CPESEARCHItem_t* item = &results->mp_items[i];
    jsonbuf_appendFormat(json_buf, "{\"vendor\":\"");
    jsonbuf_appendEscaped(json_buf, item->ma_vendor);
    jsonbuf_appendFormat(json_buf, "\",\"product\":\"");
    jsonbuf_appendEscaped(json_buf, item->ma_product);
    jsonbuf_appendFormat(json_buf, "\",\"vulnerable_cve_count\":%d,\"product_named_by\":", item->m_vulnerableCveCount);
    jsonbuf_appendJsonText(json_buf, item->mp_productNamedBy ? item->mp_productNamedBy : "[]");
    jsonbuf_appendFormat(json_buf, "}");
  }

  jsonbuf_appendFormat(json_buf, "]}\n");
}

void serialize_CVSSCALCULATOR_response(const CvssResult_t* result, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, "{\"version\":\"%s\",\"vector\":\"", result->ma_version);
  jsonbuf_appendEscaped(json_buf, result->ma_vector);
  jsonbuf_appendFormat(json_buf, "\",\"base_score\":%.1f,\"base_severity\":\"%s\",", result->m_baseScore, result->ma_baseSeverity);
  jsonbuf_appendFormat(json_buf, "\"metrics\":{\"attack_vector\":\"%s\",\"attack_complexity\":\"%s\",\"privileges_required\":\"%s\",\"user_interaction\":\"%s\",\"scope\":\"%s\",\"confidentiality_impact\":\"%s\",\"integrity_impact\":\"%s\",\"availability_impact\":\"%s\"},", result->ma_attackVector, result->ma_attackComplexity, result->ma_privilegesRequired, result->ma_userInteraction, result->ma_scope, result->ma_confidentialityImpact, result->ma_integrityImpact, result->ma_availabilityImpact);
  jsonbuf_appendFormat(json_buf, "\"temporal_score\":%.1f,\"environmental_score\":%.1f,", result->m_temporalScore, result->m_environmentalScore);
  jsonbuf_appendFormat(json_buf, "\"summary\":\"CVSS v%s %s (%.1f). AV=%s, AC=%s, PR=%s, UI=%s, Scope=%s.\"}\n", result->ma_version, result->ma_baseSeverity, result->m_baseScore, result->ma_attackVector, result->ma_attackComplexity, result->ma_privilegesRequired, result->ma_userInteraction, result->ma_scope);
}

static void static_PRIVACYMYDATAWriteUtcTime(const char* key, time_t seconds, JsonBuf_t* json_buf)
{
  assert(key != NULL);

  char      utc_time[PRIVACYMYDATA_UTC_TIME_BUF_SIZE];
  struct tm utc_tm;
  if (gmtime_r(&seconds, &utc_tm) != NULL && strftime(utc_time, sizeof(utc_time), "%Y-%m-%dT%H:%M:%SZ", &utc_tm) > 0)
    jsonbuf_appendFormat(json_buf, R"("%s":"%s",)", key, utc_time);
  else
    jsonbuf_appendFormat(json_buf, R"("%s":null,)", key);
}

static void static_PRIVACYMYDATAWriteVendorKeys(const PRIVACYMYDATAVendorKeys_t* vendor_keys, JsonBuf_t* json_buf)
{
  if (vendor_keys == NULL)
  {
    jsonbuf_appendFormat(json_buf, R"("vendor_keys":null,)");
    return;
  }
  assert(vendor_keys->mp_manageUrl != NULL);
  if (vendor_keys->mp_manageUrl[0] == '\0')
  {
    jsonbuf_appendFormat(json_buf, R"("vendor_keys":{"shodan":{"configured":null},"abuseipdb":{"configured":null},"manage_url":null},)");
    return;
  }
  jsonbuf_appendFormat(json_buf, R"("vendor_keys":{"shodan":{"configured":%s},"abuseipdb":{"configured":%s},"manage_url":")",
                       vendor_keys->m_isShodanConfigured ? "true" : "false", vendor_keys->m_isAbuseIpDbConfigured ? "true" : "false");
  jsonbuf_appendEscaped(json_buf, vendor_keys->mp_manageUrl);
  jsonbuf_appendFormat(json_buf, R"("},)");
}

void serialize_PRIVACYMYDATA_response(const RequestCreditBudget_t* credit_budget, const char* resets_in, const PRIVACYMYDATAVendorKeys_t* vendor_keys, JsonBuf_t* json_buf)
{
  assert(credit_budget != NULL);
  assert(resets_in != NULL);
  assert(json_buf != NULL);

  const RateLimitInfo_t*  rl_info    = &credit_budget->m_rateLimitInfo;
  const DbApiKeyExpiry_t* key_expiry = &credit_budget->m_keyExpiry;
  bool                    is_pro     = credit_budget->m_tier == REQUEST_TIER_PRO;
  jsonbuf_appendFormat(json_buf, R"({"tier":"%s",)", is_pro ? "pro" : "free");
  if (is_pro)
    jsonbuf_appendFormat(json_buf, R"("upgrade_url":null,)");
  else
    jsonbuf_appendFormat(json_buf, R"("upgrade_url":")" PRICING_PAGE_URL R"(",)");
  if (is_pro && key_expiry->m_hasExpiry)
  {
    jsonbuf_appendFormat(json_buf, R"("key_expires_at":%lld,)", (long long)key_expiry->m_expiresAt);
    static_PRIVACYMYDATAWriteUtcTime("key_expires_at_utc", (time_t)key_expiry->m_expiresAt, json_buf);
  }
  else
    jsonbuf_appendFormat(json_buf, R"("key_expires_at":null,"key_expires_at_utc":null,)");
  jsonbuf_appendFormat(json_buf, R"("rate_limit":{"hourly_limit":%u,"remaining_in_window":%d,"resets_at":%lld,)",
                       rl_info->m_limit, rl_info->m_remaining, (long long)rl_info->m_reset);
  static_PRIVACYMYDATAWriteUtcTime("resets_at_utc", rl_info->m_reset, json_buf);
  jsonbuf_appendFormat(json_buf, R"("resets_in":")");
  jsonbuf_appendEscaped(json_buf, resets_in);
  jsonbuf_appendFormat(json_buf, R"("},)");

  jsonbuf_appendFormat(json_buf, R"("stored":{"metered_by":"%s","hash":")", is_pro ? "key_sha256" : "ip_hmac");
  jsonbuf_appendEscaped(json_buf, credit_budget->ma_budgetHash);
  jsonbuf_appendFormat(json_buf, R"("},)");
  static_PRIVACYMYDATAWriteVendorKeys(vendor_keys, json_buf);
  jsonbuf_appendFormat(json_buf, R"("policy":")" PRICING_PRIVACY_POLICY_URL R"("})" "\n");
}

static void static_formatCountWithCommas(uint64_t count, char text_out[PASSWORDCHECK_COUNT_BUF_SIZE])
{
  char digits[PASSWORDCHECK_COUNT_BUF_SIZE];
  int  digit_count = snprintf(digits, sizeof(digits), "%" PRIu64, count);
  assert(digit_count > 0 && (size_t)digit_count < sizeof(digits));

  size_t used = 0;
  for (int i = 0; i < digit_count; i++)
  {
    if (i > 0 && (digit_count - i) % 3 == 0)
      text_out[used++] = ',';
    text_out[used++] = digits[i];
  }
  text_out[used] = '\0';
}

void serialize_PASSWORDCHECK_response(const PASSWORDCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"hash_prefix":"%s","found":%s,"breach_count":%)" PRIu64 ",",
                       record->ma_hashPrefix, record->m_breachCount > 0 ? "true" : "false", record->m_breachCount);
  if (record->m_breachCount == 1)
    jsonbuf_appendFormat(json_buf, R"("summary":"This password has been seen once in data breaches."})" "\n");
  else if (record->m_breachCount > 0)
  {
    char count_text[PASSWORDCHECK_COUNT_BUF_SIZE];
    static_formatCountWithCommas(record->m_breachCount, count_text);
    jsonbuf_appendFormat(json_buf, R"("summary":"This password has been seen %s times in data breaches."})" "\n", count_text);
  }
  else
    jsonbuf_appendFormat(json_buf, R"("summary":"This password has not been found in any known data breaches."})" "\n");
}

static const char* const DNSLOOKUP_TYPE_KEYS[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT] = {
  "a", "aaaa", "mx", "ns", "txt", "cname", "soa", "caa",
};

static const char* const DNSLOOKUP_TYPE_UPPER_NAMES[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT] = {
  "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA",
};

static const DnsRecordType_t DNSLOOKUP_SUMMARY_ORDER[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT] = {
  DNS_RECORD_TYPE_A, DNS_RECORD_TYPE_AAAA, DNS_RECORD_TYPE_NS, DNS_RECORD_TYPE_MX,
  DNS_RECORD_TYPE_TXT, DNS_RECORD_TYPE_CNAME, DNS_RECORD_TYPE_SOA, DNS_RECORD_TYPE_CAA,
};

static const char* static_DNSLOOKUPReason(DnsAnswerStatus_t status)
{
  switch (status)
  {
    case DNS_ANSWER_OK:              break;
    case DNS_ANSWER_NXDOMAIN:        return "nxdomain";
    case DNS_ANSWER_SERVER_ERROR:    return "server_error";
    case DNS_ANSWER_TRUNCATED:       return "truncated";
    case DNS_ANSWER_MALFORMED:       return "malformed_answer";
    case DNS_ANSWER_NO_MEMORY:       return "no_memory";
    case DNS_ANSWER_TIMEOUT:         return "timeout";
    case DNS_ANSWER_NO_RESOLVER:     return "no_resolver";
    case DNS_ANSWER_BAD_QUESTION:    return "bad_question";
    case DNS_ANSWER_NOT_PUBLIC_NAME: return "not_public_name";
  }
  assert(false && "an answered type has no reason");
  return "unknown";
}

static void static_DNSLOOKUPWriteTexts(const DnsAnswer_t* answer, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "[");
  for (int i = 0; i < answer->m_recordCount; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscapedBytes(json_buf, answer->mp_texts[i].mp_bytes, answer->mp_texts[i].m_byteCount);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static void static_DNSLOOKUPWriteRecords(DnsRecordType_t type, const DnsAnswer_t* answer, JsonBuf_t* json_buf)
{
  if (answer->m_status != DNS_ANSWER_OK || (type == DNS_RECORD_TYPE_SOA && answer->m_recordCount == 0))
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }

  switch (type)
  {
    case DNS_RECORD_TYPE_MX:
      jsonbuf_appendFormat(json_buf, "[");
      for (int i = 0; i < answer->m_recordCount; i++)
      {
        jsonbuf_appendFormat(json_buf, R"(%s{"priority":%u,"host":")", i > 0 ? "," : "", (unsigned int)answer->mp_mxRecords[i].m_priority);
        jsonbuf_appendEscaped(json_buf, answer->mp_mxRecords[i].mp_hostname);
        jsonbuf_appendFormat(json_buf, R"("})");
      }
      jsonbuf_appendFormat(json_buf, "]");
      break;
    case DNS_RECORD_TYPE_SOA:
      jsonbuf_appendFormat(json_buf, R"({"mname":")");
      jsonbuf_appendEscaped(json_buf, answer->mp_soaRecord->mp_primaryNameServer);
      jsonbuf_appendFormat(json_buf, R"(","rname":")");
      jsonbuf_appendEscaped(json_buf, answer->mp_soaRecord->mp_adminEmail);
      jsonbuf_appendFormat(json_buf, R"(","serial":%u})", (unsigned int)answer->mp_soaRecord->m_serial);
      break;
    case DNS_RECORD_TYPE_CAA:
      jsonbuf_appendFormat(json_buf, "[");
      for (int i = 0; i < answer->m_recordCount; i++)
      {
        const DnsCaaRecord_t* caa = &answer->mp_caaRecords[i];
        jsonbuf_appendFormat(json_buf, R"(%s{"flags":%u,"tag":")", i > 0 ? "," : "", (unsigned int)caa->m_flags);
        jsonbuf_appendEscapedBytes(json_buf, caa->m_tag.mp_bytes, caa->m_tag.m_byteCount);
        jsonbuf_appendFormat(json_buf, R"(","value":")");
        jsonbuf_appendEscapedBytes(json_buf, caa->m_value.mp_bytes, caa->m_value.m_byteCount);
        jsonbuf_appendFormat(json_buf, R"("})");
      }
      jsonbuf_appendFormat(json_buf, "]");
      break;
    case DNS_RECORD_TYPE_A:
    case DNS_RECORD_TYPE_AAAA:
    case DNS_RECORD_TYPE_NS:
    case DNS_RECORD_TYPE_TXT:
    case DNS_RECORD_TYPE_CNAME:
    case DNS_RECORD_TYPE_PTR:
      static_DNSLOOKUPWriteTexts(answer, json_buf);
      break;
  }
}

static void static_DNSLOOKUPWriteSummary(const DNSLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("summary":")");
  int named_type_count  = 0;
  int unavailable_count = 0;
  for (int i = 0; i < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; i++)
  {
    DnsRecordType_t type = DNSLOOKUP_SUMMARY_ORDER[i];
    const DnsAnswer_t* answer = &record->ma_answers[type];
    if (answer->m_status != DNS_ANSWER_OK)
      unavailable_count++;
    else if (answer->m_recordCount > 0)
    {
      jsonbuf_appendFormat(json_buf, "%s%d %s", named_type_count > 0 ? ", " : "", answer->m_recordCount, DNSLOOKUP_TYPE_UPPER_NAMES[type]);
      named_type_count++;
    }
  }

  jsonbuf_appendFormat(json_buf, named_type_count > 0 ? " records for " : "No records for ");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  if (unavailable_count > 0)
    jsonbuf_appendFormat(json_buf, "; %d record type%s unavailable", unavailable_count, unavailable_count == 1 ? "" : "s");
  jsonbuf_appendFormat(json_buf, "\"");
}

void serialize_DNSLOOKUP_response(const DNSLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  jsonbuf_appendFormat(json_buf, R"(","records":{)");
  for (int type = 0; type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; type++)
  {
    const DnsAnswer_t* answer = &record->ma_answers[type];
    jsonbuf_appendFormat(json_buf, R"(%s"%s":)", type > 0 ? "," : "", DNSLOOKUP_TYPE_KEYS[type]);
    static_DNSLOOKUPWriteRecords((DnsRecordType_t)type, answer, json_buf);

    if (type == DNS_RECORD_TYPE_TXT && answer->m_status == DNS_ANSWER_OK)
      jsonbuf_appendFormat(json_buf, R"(,"total_txt_records":%d)", answer->m_recordCount);
    else if (type == DNS_RECORD_TYPE_TXT)
      jsonbuf_appendFormat(json_buf, R"(,"total_txt_records":null)");
  }

  jsonbuf_appendFormat(json_buf, R"(},"unavailable":{)");
  int unavailable_count = 0;
  for (int type = 0; type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; type++)
  {
    DnsAnswerStatus_t status = record->ma_answers[type].m_status;
    if (status == DNS_ANSWER_OK)
      continue;
    jsonbuf_appendFormat(json_buf, R"(%s"%s":"%s")", unavailable_count > 0 ? "," : "", DNSLOOKUP_TYPE_KEYS[type], static_DNSLOOKUPReason(status));
    unavailable_count++;
  }

  jsonbuf_appendFormat(json_buf, R"(},"non_public_addresses":[)");
  for (int i = 0; i < record->m_nonPublicAddressCount; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscaped(json_buf, record->mp_nonPublicAddresses[i]->mp_bytes);
    jsonbuf_appendFormat(json_buf, "\"");
  }

  jsonbuf_appendFormat(json_buf, R"(],"services":[)");
  for (int i = 0; i < record->m_serviceCount; i++)
    jsonbuf_appendFormat(json_buf, R"(%s{"name":"%s","evidence":"%s"})", i > 0 ? "," : "", record->ma_services[i]->mp_serviceName, record->ma_services[i]->mp_evidence);

  jsonbuf_appendFormat(json_buf, "],");
  static_DNSLOOKUPWriteSummary(record, json_buf);
  jsonbuf_appendFormat(json_buf, "}\n");
}

static void static_DNSTAKEOVERCHECKWriteVerdict(const DNSTAKEOVERCHECKRecord_t* record, bool is_dangling, JsonBuf_t* json_buf)
{
  if (!is_dangling)
    jsonbuf_appendFormat(json_buf, ", which exists.");
  else if (record->mp_matchedSuffix != NULL)
  {
    jsonbuf_appendFormat(json_buf, ", which does not exist. %s lets anyone claim that name, so ", record->mp_matchedSuffix->mp_serviceName);
    jsonbuf_appendEscaped(json_buf, record->ma_hostname);
    jsonbuf_appendFormat(json_buf, " can be taken over.");
  }
  else
    jsonbuf_appendFormat(json_buf, ", which does not exist. This check knows no service that lets anyone claim that name.");
}

static const char* static_DNSTAKEOVERCHECKTakeoverPossibleJson(const DNSTAKEOVERCHECKRecord_t* record)
{
  if (record->m_hostnameChainLength == 0)
    return "false";
  else if (record->mp_matchedSuffix == NULL)
    return "null";
  else if (record->m_isTargetFound)
    return "false";
  else
    return "true";
}

void serialize_DNSTAKEOVERCHECK_response(const DNSTAKEOVERCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  bool has_cname            = record->m_hostnameChainLength > 0;
  bool is_dangling          = has_cname && !record->m_isTargetFound;
  const char* last_hostname = has_cname ? record->ma_hostnameChain[record->m_hostnameChainLength - 1] : NULL;

  jsonbuf_appendFormat(json_buf, R"({"hostname":")");
  jsonbuf_appendEscaped(json_buf, record->ma_hostname);
  if (has_cname)
  {
    jsonbuf_appendFormat(json_buf, R"(","cname":")");
    jsonbuf_appendEscaped(json_buf, record->ma_hostnameChain[0]);
    jsonbuf_appendFormat(json_buf, R"(","chain":[)");
    for (int i = 0; i < record->m_hostnameChainLength; i++)
    {
      jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
      jsonbuf_appendEscaped(json_buf, record->ma_hostnameChain[i]);
      jsonbuf_appendFormat(json_buf, "\"");
    }
    jsonbuf_appendFormat(json_buf, R"(],"target_exists":%s,)", record->m_isTargetFound ? "true" : "false");
  }
  else
    jsonbuf_appendFormat(json_buf, R"(","cname":null,"chain":[],"target_exists":null,)");

  jsonbuf_appendFormat(json_buf, R"("dangling":%s,)", is_dangling ? "true" : "false");
  if (record->mp_matchedSuffix != NULL)
    jsonbuf_appendFormat(json_buf, R"("provider":"%s",)", record->mp_matchedSuffix->mp_serviceName);
  else
    jsonbuf_appendFormat(json_buf, R"("provider":null,)");
  jsonbuf_appendFormat(json_buf, R"("takeover_possible":%s,"summary":")", static_DNSTAKEOVERCHECKTakeoverPossibleJson(record));

  jsonbuf_appendEscaped(json_buf, record->ma_hostname);
  if (!has_cname)
  {
    jsonbuf_appendFormat(json_buf, R"( has no CNAME record, so it has no dangling CNAME."})" "\n");
    return;
  }
  if (record->m_hostnameChainLength == 1)
    jsonbuf_appendFormat(json_buf, " points to ");
  else
    jsonbuf_appendFormat(json_buf, " points through %d CNAME records to ", record->m_hostnameChainLength);
  jsonbuf_appendEscaped(json_buf, last_hostname);
  static_DNSTAKEOVERCHECKWriteVerdict(record, is_dangling, json_buf);
  jsonbuf_appendFormat(json_buf, "\"}\n");
}

static const char* static_SSLCHECKRevokeStatusName(TlsProbeRevokeStatus_t revoke_status)
{
  switch (revoke_status)
  {
    case TLSPROBE_REVOKE_NOT_SENT:
      return "not_sent";
    case TLSPROBE_REVOKE_NOT_REVOKED:
      return "not_revoked";
    case TLSPROBE_REVOKE_REVOKED:
      return "revoked";
    case TLSPROBE_REVOKE_UNKNOWN:
      return "unknown";
    case TLSPROBE_REVOKE_UNUSABLE:
      break;
  }
  return "unusable";
}

static const char* static_SSLCHECKSecureRenegotiationValue(TlsProbeSecureRenegotiation_t secure_renegotiation)
{
  switch (secure_renegotiation)
  {
    case TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED:
      return "true";
    case TLSPROBE_SECURE_RENEGOTIATION_NOT_SUPPORTED:
      return "false";
    case TLSPROBE_SECURE_RENEGOTIATION_NOT_APPLICABLE:
      break;
  }
  return "null";
}

static void static_SSLCHECKWriteListedOn(const SSLCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  if (record->m_isBlacklistUnavailable || !record->m_isBlacklistFeedLoaded)
  {
    jsonbuf_appendFormat(json_buf, R"("listed_on":null)");
    return;
  }
  if (record->ma_blacklistListingReason[0] == '\0')
  {
    jsonbuf_appendFormat(json_buf, R"("listed_on":[])");
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("listed_on":[{"source":"sslbl","listing_reason":")");
  jsonbuf_appendEscaped(json_buf, record->ma_blacklistListingReason);
  jsonbuf_appendFormat(json_buf, R"(","listing_time":")");
  jsonbuf_appendEscaped(json_buf, record->ma_blacklistListingTime);
  jsonbuf_appendFormat(json_buf, R"("}])");
}

static void static_SSLCHECKWriteCertificate(const SSLCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  const TlsProbeCertificate_t* certificate = &record->m_result.m_serverCertificate;

  jsonbuf_appendFormat(json_buf, R"("certificate":{)");
  static_writeTextOrNull("subject", certificate->ma_subject, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("issuer", certificate->ma_issuer, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("serial_number", certificate->ma_serialHex, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"sha256_fingerprint":")");
  jsonbuf_appendEscaped(json_buf, certificate->ma_sha256Hex);
  jsonbuf_appendFormat(json_buf, R"(","sha1_fingerprint":")");
  jsonbuf_appendEscaped(json_buf, certificate->ma_sha1Hex);
  jsonbuf_appendFormat(json_buf, R"(","valid_from":")");
  jsonbuf_appendEscaped(json_buf, certificate->ma_validFrom);
  jsonbuf_appendFormat(json_buf, R"(","valid_until":")");
  jsonbuf_appendEscaped(json_buf, certificate->ma_validUntil);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeTextOrNull("signature_algorithm", certificate->ma_signatureAlgorithm, json_buf);
  if (certificate->ma_keyType[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"key":{"type":")");
    jsonbuf_appendEscaped(json_buf, certificate->ma_keyType);
    jsonbuf_appendFormat(json_buf, R"(","bits":%d})", certificate->m_keyBits);
  }
  else
    jsonbuf_appendFormat(json_buf, R"(,"key":null)");

  jsonbuf_appendFormat(json_buf, R"(,"dns_names":[)");
  for (int i = 0; i < certificate->m_dnsNameCount; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscaped(json_buf, certificate->ma_dnsNames[i]);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, R"(],"dns_names_truncated":%s,)", certificate->m_isDnsNameListTruncated ? "true" : "false");
  static_SSLCHECKWriteListedOn(record, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_SSLCHECK_response(const SSLCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  const TlsProbeResult_t* result = &record->m_result;

  jsonbuf_appendFormat(json_buf, R"({"hostname":")");
  jsonbuf_appendEscaped(json_buf, result->ma_hostname);
  jsonbuf_appendFormat(json_buf, R"(","ip_address":")");
  jsonbuf_appendEscaped(json_buf, result->ma_ipAddress);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_writeTextOrNull("checked_at", record->ma_checkedAt, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("protocol", result->ma_protocol, json_buf);
  if (result->ma_cipherName[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"cipher":{"name":")");
    jsonbuf_appendEscaped(json_buf, result->ma_cipherName);
    jsonbuf_appendFormat(json_buf, R"(","bits":%d})", result->m_cipherBits);
  }
  else
    jsonbuf_appendFormat(json_buf, R"(,"cipher":null)");
  if (result->ma_keyExchangeGroup[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"key_exchange":{"group":")");
    jsonbuf_appendEscaped(json_buf, result->ma_keyExchangeGroup);
    jsonbuf_appendFormat(json_buf, R"(","bits":%d})", result->m_keyExchangeBits);
  }
  else
    jsonbuf_appendFormat(json_buf, R"(,"key_exchange":null)");
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("alpn_protocol", result->ma_alpnProtocol, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"secure_renegotiation":%s,"trusted":%s,"problems":[)",
                       static_SSLCHECKSecureRenegotiationValue(result->m_secureRenegotiation),
                       result->m_isTrusted ? "true" : "false");

  bool is_first = true;
  for (int i = 0; i < TLSPROBE_PROBLEM_NAME_COUNT; i++)
  {
    if ((result->m_problems & tlsprobe_problemNames[i].m_bit) == 0)
      continue;
    jsonbuf_appendFormat(json_buf, is_first ? R"("%s")" : R"(,"%s")", tlsprobe_problemNames[i].mp_name);
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, R"(],"revocation":"%s","days_remaining":%d,)",
                       static_SSLCHECKRevokeStatusName(result->m_revokeStatus), result->m_daysRemaining);

  static_SSLCHECKWriteCertificate(record, json_buf);

  jsonbuf_appendFormat(json_buf, R"(,"chain":[)");
  for (int i = 0; i < result->m_chainCount; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",{" : "{");
    static_writeTextOrNull("subject", result->ma_chain[i].ma_subjectFullName, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    static_writeTextOrNull("issuer", result->ma_chain[i].ma_issuerFullName, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    static_writeTextOrNull("valid_until", result->ma_chain[i].ma_validUntil, json_buf);
    jsonbuf_appendFormat(json_buf, "}");
  }
  jsonbuf_appendFormat(json_buf, R"(],"chain_truncated":%s,"unavailable":{)", result->m_isChainTruncated ? "true" : "false");
  if (record->m_isBlacklistUnavailable)
    jsonbuf_appendFormat(json_buf, R"("listed_on":"database_error")");
  else if (!record->m_isBlacklistFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("listed_on":"not_synced")");
  jsonbuf_appendFormat(json_buf, "}}\n");
}

static void static_HEADERSCHECKWriteFinding(const HeaderCheckFinding_t* finding, bool is_full_header_value_included, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"header":"%s","severity":"%s","result":"%s","issues":[)",
                       header_check_headerName(finding->m_header),
                       header_check_severityName(finding->m_severity),
                       header_check_resultName(finding->m_result));
  for (int i = 0; i < finding->m_issueCount; i++)
  {
    char issue_text[HEADER_CHECK_ISSUE_TEXT_SIZE];
    header_check_writeIssueText(&finding->ma_issues[i], issue_text, sizeof(issue_text));
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscaped(json_buf, issue_text);
    jsonbuf_appendFormat(json_buf, "\"");
  }

  if (finding->mp_value == NULL)
    jsonbuf_appendFormat(json_buf, R"(],"value":null)");
  else
  {
    bool is_value_cut = finding->m_isValueCut && !is_full_header_value_included;
    jsonbuf_appendFormat(json_buf, R"(],"value":")");
    jsonbuf_appendEscapedBytes(json_buf, finding->mp_value, is_value_cut ? finding->m_shownValueLen : finding->m_valueLen);
    jsonbuf_appendFormat(json_buf, "\"");
    if (is_value_cut)
      jsonbuf_appendFormat(json_buf, R"(,"total_value_length":%zu)", finding->m_valueCodePointCount);
  }

  if (finding->m_header == HEADER_CHECK_HEADER_SET_COOKIE)
    jsonbuf_appendFormat(json_buf, R"(,"cookie_count":%zu)", finding->m_cookieCount);

  if (finding->m_result != HEADER_CHECK_RESULT_PASS)
  {
    jsonbuf_appendFormat(json_buf, R"(,"remediation":")");
    jsonbuf_appendEscaped(json_buf, header_check_ruleRemediation(finding->m_header));
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_HEADERSCHECKWriteUrl(const char* member_name, const char* url, bool is_full_header_value_included, JsonBuf_t* json_buf)
{
  size_t code_point_count = 0;
  size_t shown_len        = header_check_shownLength(url, &code_point_count);
  bool   is_url_cut       = code_point_count > HEADER_CHECK_SHOWN_VALUE_MAX_CODE_POINTS && !is_full_header_value_included;
  jsonbuf_appendFormat(json_buf, R"("%s":")", member_name);
  jsonbuf_appendEscapedBytes(json_buf, url, is_url_cut ? shown_len : strlen(url));
  jsonbuf_appendFormat(json_buf, "\"");
  if (is_url_cut)
    jsonbuf_appendFormat(json_buf, R"(,"total_%s_length":%zu)", member_name, code_point_count);
}

void serialize_HEADERSCHECK_response(const HEADERSCHECKRecord_t* record, const HEADERSCHECKParams_t* params, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  const HeaderFetchResult_t* fetch = &record->m_fetchResult;

  jsonbuf_appendFormat(json_buf, "{");
  static_HEADERSCHECKWriteUrl("url", fetch->mp_url, params->m_isFullHeaderValueIncluded, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"status_code":%d,"redirect_count":%d,)", fetch->m_httpStatus, fetch->m_followedRedirectCount);
  if (fetch->mp_unfollowedRedirectUrl != NULL)
  {
    static_HEADERSCHECKWriteUrl("redirect_to", fetch->mp_unfollowedRedirectUrl, params->m_isFullHeaderValueIncluded, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    if (fetch->m_isRedirectLimitReached)
      jsonbuf_appendFormat(json_buf, R"("redirect_limit_reached":true,)");
  }
  static_writeTextOrNull("checked_at", record->ma_checkedAt, json_buf);

  jsonbuf_appendFormat(json_buf, R"(,"findings":[)");
  for (int i = 0; i < HEADER_CHECK_RULE_COUNT; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_HEADERSCHECKWriteFinding(&record->m_report.ma_findings[i], params->m_isFullHeaderValueIncluded, json_buf);
  }
  jsonbuf_appendFormat(json_buf, "]}\n");
}

static const char* static_WHOISLOOKUPUnavailableReasonText(WHOISLOOKUPUnavailableReason_t unavailable_reason)
{
  switch (unavailable_reason)
  {
    case WHOISLOOKUP_UNAVAILABLE_NO_REGISTRY_SERVER:
      return "no_registry_server";
    case WHOISLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED:
      return "quota_exhausted";
    case WHOISLOOKUP_UNAVAILABLE_NONE:
      break;
  }
  return "";
}

static void static_WHOISLOOKUPWriteTextList(const char* key, const char* count_key, const char* texts, size_t text_size, int count, int max_count, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("%s":[)", key);
  for (int i = 0; i < count && i < max_count; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscaped(json_buf, texts + (size_t)i * text_size);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, R"(],"%s":%d)", count_key, count);
}

void serialize_WHOISLOOKUP_response(const WHOISLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);
  assert(record->m_unavailableReason != WHOISLOOKUP_UNAVAILABLE_NONE ||
         (record->mp_rdapServerBaseUrl != NULL) != (record->mp_whoisServerHost != NULL));

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  if (record->m_unavailableReason != WHOISLOOKUP_UNAVAILABLE_NONE)
  {
    jsonbuf_appendFormat(json_buf, R"(","available":false,"reason":"%s","retry_after_seconds":)",
                         static_WHOISLOOKUPUnavailableReasonText(record->m_unavailableReason));
    if (record->m_unavailableReason == WHOISLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED)
      jsonbuf_appendFormat(json_buf, "%u}\n", record->m_retryAfterSeconds);
    else
      jsonbuf_appendFormat(json_buf, "null}\n");
    return;
  }

  const RdapRegistration_t* registration = &record->m_registration;
  jsonbuf_appendFormat(json_buf, R"(","available":true,)");
  static_writeTextOrNull("rdap_server", record->mp_rdapServerBaseUrl != NULL ? record->mp_rdapServerBaseUrl : "", json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("whois_server", record->mp_whoisServerHost != NULL ? record->mp_whoisServerHost : "", json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("registrar_name", registration->ma_registrarName, json_buf);
  if (registration->m_registrarIanaId >= 0)
    jsonbuf_appendFormat(json_buf, R"(,"registrar_iana_id":%ld,)", registration->m_registrarIanaId);
  else
    jsonbuf_appendFormat(json_buf, R"(,"registrar_iana_id":null,)");
  static_writeTextOrNull("created_at", registration->ma_createdAt, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("updated_at", registration->ma_updatedAt, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("expires_at", registration->ma_expiresAt, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_WHOISLOOKUPWriteTextList("status", "status_count", registration->ma_statuses[0], sizeof(registration->ma_statuses[0]),
                                  registration->m_statusCount, RDAP_STATUS_MAX_COUNT, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_WHOISLOOKUPWriteTextList("name_servers", "name_server_count", registration->ma_nameServers[0], sizeof(registration->ma_nameServers[0]),
                                  registration->m_nameServerCount, RDAP_NAME_SERVER_MAX_COUNT, json_buf);
  switch (registration->m_delegationSigned)
  {
    case RDAP_DELEGATION_SIGNED_YES:
      jsonbuf_appendFormat(json_buf, R"(,"dnssec_signed":true})" "\n");
      break;
    case RDAP_DELEGATION_SIGNED_NO:
      jsonbuf_appendFormat(json_buf, R"(,"dnssec_signed":false})" "\n");
      break;
    case RDAP_DELEGATION_SIGNED_UNKNOWN:
      jsonbuf_appendFormat(json_buf, R"(,"dnssec_signed":null})" "\n");
      break;
  }
}

#define WAYBACKLOOKUP_CAPTURE_URL_PREFIX  "https://web.archive.org/web/"
#define WAYBACKLOOKUP_ARCHIVE_URL_PREFIX  "https://web.archive.org/web/*/"

static int static_WAYBACKLOOKUPYear(const char* timestamp)
{
  return (timestamp[0] - '0') * 1000 + (timestamp[1] - '0') * 100 + (timestamp[2] - '0') * 10 + (timestamp[3] - '0');
}

static void static_WAYBACKLOOKUPWriteDay(const char* key, const char* timestamp, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("%s":"%.4s-%.2s-%.2s")", key, timestamp, timestamp + 4, timestamp + 6);
}

static void static_WAYBACKLOOKUPWriteCapture(const char* domain, const WaybackCapture_t* capture, JsonBuf_t* json_buf)
{
  const char* timestamp = capture->ma_timestamp;
  jsonbuf_appendFormat(json_buf, R"({"captured_at":"%.4s-%.2s-%.2sT%.2s:%.2s:%.2sZ",)", timestamp, timestamp + 4, timestamp + 6, timestamp + 8, timestamp + 10, timestamp + 12);
  
  if (capture->m_httpStatus > 0)
    jsonbuf_appendFormat(json_buf, R"("http_status":%d,)", capture->m_httpStatus);
  else
    jsonbuf_appendFormat(json_buf, R"("http_status":null,)");
  
  static_writeTextOrNull("media_type", capture->ma_mediaType, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"url":")" WAYBACKLOOKUP_CAPTURE_URL_PREFIX "%s/", timestamp);
  jsonbuf_appendEscaped(json_buf, domain);
  jsonbuf_appendFormat(json_buf, R"("})");
}

void serialize_WAYBACKLOOKUP_response(const WAYBACKLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  if (record->m_unavailableReason == WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED)
  {
    jsonbuf_appendFormat(json_buf, R"(","available":false,"reason":"quota_exhausted","retry_after_seconds":%u})" "\n", record->m_retryAfterSeconds);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"(","available":true,)");
  if (record->m_latestCaptureCount > 0)
  {
    const char* first_timestamp = record->m_firstCapture.ma_timestamp;
    const char* last_timestamp  = record->ma_latestCaptures[0].ma_timestamp;
    int         years_online    = static_WAYBACKLOOKUPYear(last_timestamp) - static_WAYBACKLOOKUPYear(first_timestamp);
    static_WAYBACKLOOKUPWriteDay("first_seen", first_timestamp, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    static_WAYBACKLOOKUPWriteDay("last_seen", last_timestamp, json_buf);
    jsonbuf_appendFormat(json_buf, R"(,"years_online":%d,)", years_online > 1 ? years_online : 1);
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"("first_seen":null,"last_seen":null,"years_online":null,)");
  }

  jsonbuf_appendFormat(json_buf, R"("latest_captures":[)");
  for (int i = 0; i < record->m_latestCaptureCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_WAYBACKLOOKUPWriteCapture(record->ma_domain, &record->ma_latestCaptures[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, R"(],"archive_url":")" WAYBACKLOOKUP_ARCHIVE_URL_PREFIX);
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  jsonbuf_appendFormat(json_buf, R"("})" "\n");
}

static void static_CERTSEARCHWriteCertificate(const CertSpotterCertificate_t* certificate, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"sha256_fingerprint":"%s",)", certificate->ma_sha256Hex);
  static_writeTextOrNull("issuer", certificate->ma_issuer, json_buf);

  if (certificate->m_isCaaDomainListKnown)
  {
    jsonbuf_appendFormat(json_buf, R"(,"issuer_caa_domains":[)");
    for (int i = 0; i < certificate->m_caaDomainCount; i++)
    {
      jsonbuf_appendFormat(json_buf, i > 0 ? R"(,")" : R"(")");
      jsonbuf_appendEscaped(json_buf, certificate->ma_caaDomains[i]);
      jsonbuf_appendFormat(json_buf, "\"");
    }
    jsonbuf_appendFormat(json_buf, "]");
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"(,"issuer_caa_domains":null)");
  }

  static const char* const REVOKED_TEXTS[] = {
    [CERTSPOTTER_REVOCATION_UNKNOWN]     = "null",
    [CERTSPOTTER_REVOCATION_NOT_REVOKED] = "false",
    [CERTSPOTTER_REVOCATION_REVOKED]     = "true",
  };
  jsonbuf_appendFormat(json_buf, R"(,"valid_from":"%s","valid_until":"%s","revoked":%s,"dns_names":[)",
                       certificate->ma_validFrom, certificate->ma_validUntil, REVOKED_TEXTS[certificate->m_revocation]);

  int kept_count = certificate->m_dnsNameCount < CERTSPOTTER_DNS_NAME_MAX_COUNT ? certificate->m_dnsNameCount : CERTSPOTTER_DNS_NAME_MAX_COUNT;
  for (int i = 0; i < kept_count; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? R"(,")" : R"(")");
    jsonbuf_appendEscaped(json_buf, certificate->ma_dnsNames[i]);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, R"(],"dns_name_count":%d})", certificate->m_dnsNameCount);
}

void serialize_CERTSEARCH_response(const CERTSEARCHRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  if (record->m_unavailableReason == CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED)
  {
    jsonbuf_appendFormat(json_buf, R"(","available":false,"reason":"quota_exhausted","retry_after_seconds":%u})" "\n", record->m_retryAfterSeconds);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"(","available":true,"complete":%s,"certificate_count":%d,"certificates":[)",
                       record->m_certificateList.m_isComplete ? "true" : "false", record->m_certificateList.m_readCount);
  for (int i = 0; i < record->m_certificateList.m_keptCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_CERTSEARCHWriteCertificate(&record->m_certificateList.ma_certificates[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, "]}\n");
}

static const char* const SUBDOMAINENUM_WILDCARD_TEXTS[] = {
  [SUBDOMAIN_WILDCARD_ABSENT]       = "absent",
  [SUBDOMAIN_WILDCARD_PRESENT]      = "present",
  [SUBDOMAIN_WILDCARD_UNDETERMINED] = "undetermined",
};

static bool static_SUBDOMAINENUMIsListedBefore(const SubdomainNameSet_t* name_set, int a, int b)
{
  const unsigned int dns_sources = SUBDOMAIN_SOURCE_DNS_WORDLIST | SUBDOMAIN_SOURCE_DNS_RECORDS;
  bool is_a_confirmed = (name_set->mp_sources[a] & dns_sources) != 0;
  bool is_b_confirmed = (name_set->mp_sources[b] & dns_sources) != 0;
  if (is_a_confirmed != is_b_confirmed)
    return is_a_confirmed;
  return strcmp(name_set->mp_names[a], name_set->mp_names[b]) < 0;
}

static void static_SUBDOMAINENUMWriteName(const SubdomainNameSet_t* name_set, int index, JsonBuf_t* json_buf)
{
  static const struct { unsigned int m_bit; const char* mp_text; } SOURCE_TEXTS[] = {
    { SUBDOMAIN_SOURCE_CERTIFICATE_LOGS, "certificate_logs" },
    { SUBDOMAIN_SOURCE_DNS_WORDLIST,     "dns_wordlist" },
    { SUBDOMAIN_SOURCE_DNS_RECORDS,      "dns_records" },
  };

  jsonbuf_appendFormat(json_buf, R"({"hostname":")");
  jsonbuf_appendEscaped(json_buf, name_set->mp_names[index]);
  jsonbuf_appendFormat(json_buf, R"(","sources":[)");
  bool is_first = true;
  for (size_t i = 0; i < sizeof(SOURCE_TEXTS) / sizeof(SOURCE_TEXTS[0]); i++)
  {
    if ((name_set->mp_sources[index] & SOURCE_TEXTS[i].m_bit) == 0)
      continue;
    jsonbuf_appendFormat(json_buf, is_first ? R"("%s")" : R"(,"%s")", SOURCE_TEXTS[i].mp_text);
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, "]}");
}

void serialize_SUBDOMAINENUM_response(const SUBDOMAINENUMRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  const SubdomainNameSet_t* name_set = record->mp_nameSet;
  int name_count   = name_set->m_count < SUBDOMAIN_MAX_NAME_COUNT ? name_set->m_count : SUBDOMAIN_MAX_NAME_COUNT;
  int listed_count = name_count < SUBDOMAINENUM_MAX_LISTED_NAME_COUNT ? name_count : SUBDOMAINENUM_MAX_LISTED_NAME_COUNT;

  int order[SUBDOMAIN_MAX_NAME_COUNT];
  for (int i = 0; i < name_count; i++)
    order[i] = i;
  for (int place = 0; place < listed_count; place++)
  {
    int first = place;
    for (int i = place + 1; i < name_count; i++)
    {
      if (static_SUBDOMAINENUMIsListedBefore(name_set, order[i], order[first]))
        first = i;
    }
    int moved    = order[place];
    order[place] = order[first];
    order[first] = moved;
  }

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  jsonbuf_appendFormat(json_buf, R"(","subdomain_count":%d,"subdomains":[)", name_set->m_count);
  for (int place = 0; place < listed_count; place++)
  {
    if (place > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_SUBDOMAINENUMWriteName(name_set, order[place], json_buf);
  }
  jsonbuf_appendFormat(json_buf, R"(],"wildcard_dns":"%s",)", SUBDOMAINENUM_WILDCARD_TEXTS[record->m_wildcardDns]);

  switch (record->m_certificateLogStatus)
  {
    case SUBDOMAINENUM_CERTIFICATE_LOGS_AVAILABLE:
      jsonbuf_appendFormat(json_buf, R"("certificate_logs_available":true,"certificate_logs_complete":%s})" "\n",
                           record->m_isCertificateLogAnswerEmpty ? "true" : "false");
      break;
    case SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED:
      jsonbuf_appendFormat(json_buf, R"("certificate_logs_available":false,"certificate_logs_reason":"quota_exhausted","retry_after_seconds":%u})" "\n", record->m_retryAfterSeconds);
      break;
    case SUBDOMAINENUM_CERTIFICATE_LOGS_UPSTREAM_ERROR:
      jsonbuf_appendFormat(json_buf, R"("certificate_logs_available":false,"certificate_logs_reason":"upstream_error"})" "\n");
      break;
  }
}

static const char* const EMAILAUTHCHECK_CHECK_SEVERITIES[EMAILCHECK_KIND_COUNT] = {
  "high", "high", "high", "high", "low", "low",
  "high", "low", "high", "high", "medium",
  "low", "high", "high", "high", "low",
  "medium", "high", "low", "low", "low",
};

static const char* const EMAILAUTHCHECK_CHECK_DETAILS[EMAILCHECK_KIND_COUNT][EMAILCHECK_RESULT_COUNT] = {
  { "The domain has one SPF record.", NULL, "The domain has no SPF record, or more than one." },
  { "Every term of the SPF record is valid.", NULL, "A term of the SPF record is not valid, so receivers treat the record as an error." },
  { "The SPF record's own terms make at most 10 DNS lookups. The records of its include and redirect domains are not read.", NULL,
    "The SPF record makes more than 10 DNS lookups, so receivers treat it as an error." },
  { "The SPF record's all is -all or ~all, or it has a redirect and no all.", "The SPF record's all is ?all, or it has neither all nor redirect, so it does not turn other senders away.",
    "The SPF record's all is +all, so every sender it does not name passes." },
  { "No mechanism follows all, and no redirect stands next to all.", "A mechanism follows all, or a redirect stands next to all. Receivers ignore that mechanism or redirect.", NULL },
  { "The SPF record has no ptr mechanism.", "The SPF record uses ptr. RFC 7208 asks domains not to use it.", NULL },
  { "No mechanism of the SPF record allows a wide address range.", "A mechanism allows an IPv4 range wider than /16 or an IPv6 range wider than /32.",
    "A mechanism allows every address, with a prefix length of 0." },
  { "The SPF record is at most 450 bytes.", "The SPF record is longer than 450 bytes, so its answer may not fit a 512-byte UDP message.", NULL },
  { "A DMARC record applies to the domain.", NULL, "No DMARC record applies to the domain, or its own name holds more than one." },
  { "The DMARC policy quarantines or rejects mail that fails.", "The DMARC policy is none, so mail that fails is delivered.",
    "A policy tag of the DMARC record is not valid and its rua= tag holds no valid address, so receivers apply no DMARC." },
  { "The DMARC record has no t=y, or the policy it applies is not quarantine or reject, so t=y weakens no policy.",
    "The DMARC record has t=y, so receivers apply none instead of quarantine, or quarantine instead of reject.", NULL },
  { "The DMARC record asks for aggregate reports.", "The rua= tag of the DMARC record holds no valid address, so receivers send no aggregate report.", NULL },
  { "A DKIM selector holds a key record.", "None of the selectors tried holds a key record. The domain may sign with another selector.",
    "The selector given holds no key record." },
  { "A DKIM key can be read.", "No DKIM key can be read, and one is of a type receivers ignore.", "Every DKIM key is revoked or cannot be read." },
  { "The rsa key of each selector is 2048 to 4096 bits.", "An rsa key is under 2048 bits or over 4096 bits. Some receivers do not read a key over 4096 bits.",
    "An rsa key is under 1024 bits, so receivers must not trust its signatures." },
  { "No DKIM key is a bare RSAPublicKey or has a negative modulus, and no key record has v=DKIM1 after another tag.",
    "A key is a bare RSAPublicKey, which OpenDKIM and rspamd do not read, a key's modulus is negative in DER, or a record has v=DKIM1 after another tag.", NULL },
  { "No selector's DKIM key is in test mode.", "A DKIM key has t=y, so receivers treat signed mail like unsigned mail.", NULL },
  { "The DKIM key of each selector may sign mail with sha256.", NULL, "The h= or the s= tag of a DKIM key keeps it from signing mail with sha256." },
  { "No selector holds more than one key record.", "A selector holds more than one key record. The check read the first.", NULL },
  { "The domain has MX hosts, or a null MX that says it takes no mail.", "The domain has no MX record, so senders deliver to its own address.", NULL },
  { "The domain publishes an MTA-STS record.", "The domain publishes no MTA-STS record, or more than one, so senders may deliver its mail without TLS.", NULL },
};

static const char* const EMAILAUTHCHECK_RESULT_NAMES[] = { "pass", "warn", "fail" };

static const char* static_EMAILAUTHCHECKPolicyName(EmailAuthDmarcPolicy_t policy)
{
  switch (policy)
  {
    case EMAILAUTH_DMARC_POLICY_ABSENT:     return NULL;
    case EMAILAUTH_DMARC_POLICY_NONE:       return "none";
    case EMAILAUTH_DMARC_POLICY_QUARANTINE: return "quarantine";
    case EMAILAUTH_DMARC_POLICY_REJECT:     return "reject";
    case EMAILAUTH_DMARC_POLICY_INVALID:    return "invalid";
  }

  return NULL;
}

static void static_EMAILAUTHCHECKWriteNameOrNull(const char* name, JsonBuf_t* json_buf)
{
  if (name == NULL)
    jsonbuf_appendFormat(json_buf, "null");
  else
    jsonbuf_appendFormat(json_buf, "\"%s\"", name);
}

static void static_EMAILAUTHCHECKWriteSpan(EmailAuthSpan_t span, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscapedBytes(json_buf, span.mp_bytes, span.m_byteCount);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_EMAILAUTHCHECKWriteUnavailable(const char* key, DnsAnswerStatus_t status, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("%s":{"available":false,"reason":"%s"},)", key, static_DNSLOOKUPReason(status));
}

static void static_EMAILAUTHCHECKWriteSpf(const EMAILAUTHCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  static const char* const KIND_NAMES[] = {
    "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect", "exp", "unknown_modifier", "invalid",
  };
  static const char* const QUALIFIER_NAMES[] = { "pass", "fail", "softfail", "neutral" };

  const DnsAnswer_t* answer = &record->m_spfAnswer;
  if (answer->m_status != DNS_ANSWER_OK && answer->m_status != DNS_ANSWER_NXDOMAIN)
  {
    static_EMAILAUTHCHECKWriteUnavailable("spf", answer->m_status, json_buf);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("spf":{"available":true,"record_count":%d,"record":)", record->m_spfRecordCount);
  if (record->m_spfRecordCount != 1)
  {
    jsonbuf_appendFormat(json_buf, R"(null,"terms":null,"dns_lookup_term_count":null,"invalid_term_count":null,"unread_term_count":null},)");
    return;
  }

  const DnsRecordText_t* text = &answer->mp_texts[record->m_spfRecordIndex];
  const EmailAuthSpf_t*  spf  = &record->m_spfRecord;
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscapedBytes(json_buf, text->mp_bytes, text->m_byteCount);
  jsonbuf_appendFormat(json_buf, R"(","terms":[)");

  for (int i = 0; i < spf->m_termCount; i++)
  {
    const EmailAuthSpfTerm_t* term = &spf->ma_terms[i];
    bool is_mechanism = term->m_kind <= EMAILAUTH_SPF_TERM_EXISTS;
    jsonbuf_appendFormat(json_buf, R"(%s{"kind":"%s","qualifier":)", i > 0 ? "," : "", KIND_NAMES[term->m_kind]);
    static_EMAILAUTHCHECKWriteNameOrNull(is_mechanism ? QUALIFIER_NAMES[term->m_qualifier] : NULL, json_buf);
    jsonbuf_appendFormat(json_buf, R"(,"value":)");
    if (term->m_value.m_byteCount == 0)
      jsonbuf_appendFormat(json_buf, "null");
    else
      static_EMAILAUTHCHECKWriteSpan(term->m_value, json_buf);
    jsonbuf_appendFormat(json_buf, "}");
  }

  jsonbuf_appendFormat(json_buf, R"(],"dns_lookup_term_count":%d,"invalid_term_count":%d,"unread_term_count":%d},)",
                       spf->m_dnsLookupTermCount, spf->m_invalidTermCount, spf->m_unreadTermCount);
}

static void static_EMAILAUTHCHECKWriteUris(const EmailAuthDmarcUri_t* uris, int uri_count, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "[");
  for (int i = 0; i < uri_count; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? "," : "");
    static_EMAILAUTHCHECKWriteSpan(uris[i].m_uri, json_buf);
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static void static_EMAILAUTHCHECKWriteDmarc(const EMAILAUTHCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  static const char* const SOURCE_NAMES[] = { NULL, "domain", "organizational", "public_suffix" };
  static const char* const DOMAIN_ROLE_NAMES[] = { NULL, "public_suffix", "organizational", "not_public_suffix", "invalid" };

  if (record->m_dmarcStatus != DNS_ANSWER_OK)
  {
    static_EMAILAUTHCHECKWriteUnavailable("dmarc", record->m_dmarcStatus, json_buf);
    return;
  }
  if (record->m_dmarcSource == EMAILCHECK_DMARC_SOURCE_NONE)
  {
    jsonbuf_appendFormat(json_buf, R"("dmarc":{"available":true,"record_name":null,"source":null,"record":null,"policy":null,)"
                                   R"("subdomain_policy":null,"nonexistent_subdomain_policy":null,"applied_policy":null,)"
                                   R"("test_mode":null,"domain_role":null,"aggregate_report_uris":null,"failure_report_uris":null},)");
    return;
  }

  const EmailAuthDmarc_t* dmarc = &record->m_dmarcRecord;
  const DnsRecordText_t*  text  = &record->ma_dmarcAnswers[record->m_dmarcNameIndex].mp_texts[record->m_dmarcRecordIndex];
  jsonbuf_appendFormat(json_buf, R"("dmarc":{"available":true,"record_name":")");
  jsonbuf_appendEscaped(json_buf, record->ma_dmarcNames[record->m_dmarcNameIndex]);
  jsonbuf_appendFormat(json_buf, R"(","source":"%s","record":")", SOURCE_NAMES[record->m_dmarcSource]);
  jsonbuf_appendEscapedBytes(json_buf, text->mp_bytes, text->m_byteCount);
  jsonbuf_appendFormat(json_buf, R"(","policy":)");
  static_EMAILAUTHCHECKWriteNameOrNull(static_EMAILAUTHCHECKPolicyName(dmarc->m_policy), json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"subdomain_policy":)");
  static_EMAILAUTHCHECKWriteNameOrNull(static_EMAILAUTHCHECKPolicyName(dmarc->m_subdomainPolicy), json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"nonexistent_subdomain_policy":)");
  static_EMAILAUTHCHECKWriteNameOrNull(static_EMAILAUTHCHECKPolicyName(dmarc->m_nonexistentSubdomainPolicy), json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"applied_policy":)");
  static_EMAILAUTHCHECKWriteNameOrNull(record->m_isDmarcApplied ? static_EMAILAUTHCHECKPolicyName(record->m_appliedDmarcPolicy) : NULL, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"test_mode":%s,"domain_role":)", dmarc->m_testMode == EMAILAUTH_DMARC_TEST_MODE_ON ? "true" : "false");
  static_EMAILAUTHCHECKWriteNameOrNull(DOMAIN_ROLE_NAMES[dmarc->m_domainRole], json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"aggregate_report_uris":)");
  static_EMAILAUTHCHECKWriteUris(dmarc->ma_aggregateUris, dmarc->m_aggregateUriCount, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"failure_report_uris":)");
  static_EMAILAUTHCHECKWriteUris(dmarc->ma_failureUris, dmarc->m_failureUriCount, json_buf);
  jsonbuf_appendFormat(json_buf, "},");
}

static void static_EMAILAUTHCHECKWriteDkim(const EMAILAUTHCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  static const char* const KEY_STATUS_NAMES[] = { "found", "not_found", "unknown" };
  static const char* const SOURCE_NAMES[]     = { "given", "provider", "common" };
  static const char* const STATE_NAMES[]      = { "present", "revoked", "unreadable", "absent", "unknown_type" };

  if (record->m_dkimStatus != DNS_ANSWER_OK)
  {
    static_EMAILAUTHCHECKWriteUnavailable("dkim", record->m_dkimStatus, json_buf);
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("dkim":{"available":true,"key_status":"%s","selector_source":"%s","tested_selectors":[)",
                       KEY_STATUS_NAMES[record->m_dkimKeyStatus], SOURCE_NAMES[record->m_dkimSelectorSource]);
  for (int i = 0; i < record->m_dkimSelectorCount; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? ",\"" : "\"");
    jsonbuf_appendEscaped(json_buf, record->ma_dkimSelectors[i].ma_selector);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, R"(],"keys":[)");

  int written_count = 0;
  for (int i = 0; i < record->m_dkimSelectorCount; i++)
  {
    const EmailCheckDkimSelector_t* selector = &record->ma_dkimSelectors[i];
    if (!selector->m_hasKeyRecord)
      continue;
    jsonbuf_appendFormat(json_buf, R"(%s{"selector":")", written_count++ > 0 ? "," : "");
    jsonbuf_appendEscaped(json_buf, selector->ma_selector);
    jsonbuf_appendFormat(json_buf, R"(","state":"%s","key_type":)", STATE_NAMES[selector->m_firstKeyRecord.m_keyState]);
    static_EMAILAUTHCHECKWriteSpan(selector->m_firstKeyRecord.m_keyTypeName, json_buf);

    if (selector->m_firstKeyRecord.m_keyBits > 0)
      jsonbuf_appendFormat(json_buf, R"(,"key_bits":%d)", selector->m_firstKeyRecord.m_keyBits);
    else
      jsonbuf_appendFormat(json_buf, R"(,"key_bits":null)");
    jsonbuf_appendFormat(json_buf, R"(,"test_mode":%s})", selector->m_firstKeyRecord.m_isTestMode ? "true" : "false");
  }
  jsonbuf_appendFormat(json_buf, "]},");
}

void serialize_EMAILAUTHCHECK_response(const EMAILAUTHCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_EMAILAUTHCHECKWriteSpf(record, json_buf);
  static_EMAILAUTHCHECKWriteDmarc(record, json_buf);
  static_EMAILAUTHCHECKWriteDkim(record, json_buf);

  const DnsAnswer_t* mx_answer = &record->m_mxAnswer;
  if (mx_answer->m_status != DNS_ANSWER_OK && mx_answer->m_status != DNS_ANSWER_NXDOMAIN)
    static_EMAILAUTHCHECKWriteUnavailable("mx", mx_answer->m_status, json_buf);
  else
  {
    jsonbuf_appendFormat(json_buf, R"("mx":{"available":true,"null_mx":%s,"hosts":)", mx_answer->m_hasNullMx ? "true" : "false");
    if (mx_answer->m_status == DNS_ANSWER_OK)
      static_DNSLOOKUPWriteRecords(DNS_RECORD_TYPE_MX, mx_answer, json_buf);
    else
      jsonbuf_appendFormat(json_buf, "[]");
    jsonbuf_appendFormat(json_buf, "},");
  }

  jsonbuf_appendFormat(json_buf, R"("mail_providers":[)");
  for (int i = 0; i < record->m_mailProviderCount; i++)
    jsonbuf_appendFormat(json_buf, R"(%s"%s")", i > 0 ? "," : "", record->ma_mailProviders[i]->mp_name);
  jsonbuf_appendFormat(json_buf, "],");

  const DnsAnswer_t* mta_sts_answer = &record->m_mtaStsAnswer;
  if (mta_sts_answer->m_status != DNS_ANSWER_OK && mta_sts_answer->m_status != DNS_ANSWER_NXDOMAIN)
    static_EMAILAUTHCHECKWriteUnavailable("mta_sts", mta_sts_answer->m_status, json_buf);
  else
    jsonbuf_appendFormat(json_buf, R"("mta_sts":{"available":true,"record_found":%s},)", record->m_hasMtaStsRecord ? "true" : "false");

  int result_counts[EMAILCHECK_RESULT_COUNT] = { 0, 0, 0 };
  jsonbuf_appendFormat(json_buf, R"("checks":[)");
  for (int i = 0; i < record->m_checkCount; i++)
  {
    EmailCheckItem_t check = record->ma_checks[i];
    result_counts[check.m_result]++;
    jsonbuf_appendFormat(json_buf, R"(%s{"id":"%s","result":"%s","severity":"%s","detail":"%s"})", i > 0 ? "," : "",
                         emailcheck_kindId(check.m_kind), EMAILAUTHCHECK_RESULT_NAMES[check.m_result],
                         EMAILAUTHCHECK_CHECK_SEVERITIES[check.m_kind], EMAILAUTHCHECK_CHECK_DETAILS[check.m_kind][check.m_result]);
  }
  jsonbuf_appendFormat(json_buf, R"(],"check_counts":{"pass":%d,"warn":%d,"fail":%d}})" "\n",
                       result_counts[EMAILCHECK_RESULT_PASS], result_counts[EMAILCHECK_RESULT_WARN], result_counts[EMAILCHECK_RESULT_FAIL]);
}

static const char* static_EMAILADDRESSCHECKRouteName(EmailCheckMailRoute_t mail_route)
{
  switch (mail_route)
  {
    case EMAILCHECK_MAIL_ROUTE_NONE:        return "none";
    case EMAILCHECK_MAIL_ROUTE_MX:          return "mx";
    case EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX: return "implicit_mx";
    case EMAILCHECK_MAIL_ROUTE_NULL_MX:     return "null_mx";
  }
  assert(false && "a mail route has no name");
  return "none";
}

static void static_EMAILADDRESSCHECKWriteDisposable(const EMAILADDRESSCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  if (record->ma_disposableListedDomain[0] != '\0')
    jsonbuf_appendFormat(json_buf, R"("disposable":true,)");
  else if (record->m_isDisposableFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("disposable":false,)");
  else
    jsonbuf_appendFormat(json_buf, R"("disposable":null,)");

  static_writeTextOrNull("disposable_listed_domain", record->ma_disposableListedDomain, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
}

void serialize_EMAILADDRESSCHECK_response(const EMAILADDRESSCHECKRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  bool is_mail_accepted = record->m_isDomainFound &&
                          (record->m_mailRoute == EMAILCHECK_MAIL_ROUTE_MX || record->m_mailRoute == EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX);

  jsonbuf_appendFormat(json_buf, R"({"email":")");
  jsonbuf_appendEscaped(json_buf, record->ma_email);
  jsonbuf_appendFormat(json_buf, R"(","domain":")");
  jsonbuf_appendEscaped(json_buf, record->ma_domain);
  jsonbuf_appendFormat(json_buf, R"(","domain_exists":%s,"accepts_mail":%s,)", record->m_isDomainFound ? "true" : "false", is_mail_accepted ? "true" : "false");
  if (record->m_isDomainFound)
    jsonbuf_appendFormat(json_buf, R"("mail_route":"%s",)", static_EMAILADDRESSCHECKRouteName(record->m_mailRoute));
  else
    jsonbuf_appendFormat(json_buf, R"("mail_route":null,)");

  jsonbuf_appendFormat(json_buf, R"("mx_hosts":)");
  if (record->m_mxAnswer.m_status == DNS_ANSWER_OK)
    static_DNSLOOKUPWriteRecords(DNS_RECORD_TYPE_MX, &record->m_mxAnswer, json_buf);
  else
    jsonbuf_appendFormat(json_buf, "[]");
  jsonbuf_appendFormat(json_buf, ",");

  static_EMAILADDRESSCHECKWriteDisposable(record, json_buf);
  jsonbuf_appendFormat(json_buf, R"("unavailable":{)");
  if (!record->m_isDisposableFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("disposable_listed_domain":"not_synced")");
  jsonbuf_appendFormat(json_buf, "}}\n");
}

static bool static_IPLOOKUPIsPtrUnavailable(DnsAnswerStatus_t status)
{
  return status != DNS_ANSWER_OK && status != DNS_ANSWER_NXDOMAIN;
}

static void static_IPLOOKUPWriteAsn(const IPLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_isAsnFeedLoaded || record->m_asn == 0)
  {
    jsonbuf_appendFormat(json_buf, R"("asn":null,"asn_name":null,"asn_country":null,)");
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("asn":%)" PRIu32 ",", record->m_asn);
  static_writeTextOrNull("asn_name", record->ma_asnName, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("asn_country", record->ma_asnCountry, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
}

static void static_IPLOOKUPWriteCloud(const IPLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  if (!record->m_isCloudFeedLoaded)
  {
    jsonbuf_appendFormat(json_buf, R"("cloud_provider":null,"cloud_service":null,"is_cdn":null,)");
    return;
  }

  static_writeTextOrNull("cloud_provider", record->ma_cloudProvider, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("cloud_service", record->ma_cloudService, json_buf);
  if (record->ma_cloudProvider[0] == '\0')
    jsonbuf_appendFormat(json_buf, R"(,"is_cdn":null,)");
  else
    jsonbuf_appendFormat(json_buf, R"(,"is_cdn":%s,)", record->m_isCdn ? "true" : "false");
}

static void static_IPLOOKUPWriteDatacenter(const IPLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  if (record->m_isDatacenter)
    jsonbuf_appendFormat(json_buf, R"("is_datacenter":true,)");
  else if (record->m_isAsnFeedLoaded && record->m_isCloudFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("is_datacenter":false,)");
  else
    jsonbuf_appendFormat(json_buf, R"("is_datacenter":null,)");
}

static void static_IPLOOKUPWritePtr(const DnsAnswer_t* answer, JsonBuf_t* json_buf)
{
  if (answer->m_status != DNS_ANSWER_OK || answer->m_recordCount == 0)
  {
    jsonbuf_appendFormat(json_buf, R"("ptr":null,)");
    return;
  }

  jsonbuf_appendFormat(json_buf, R"("ptr":")");
  jsonbuf_appendEscapedBytes(json_buf, answer->mp_texts[0].mp_bytes, answer->mp_texts[0].m_byteCount);
  jsonbuf_appendFormat(json_buf, R"(",)");
}

static void static_IPLOOKUPWriteUnavailable(const IPLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  const struct {
    bool        m_isFeedLoaded;
    const char* mp_key;
  } sources[] = {
    { record->m_isAsnFeedLoaded,      "asn" },
    { record->m_isGeoFeedLoaded,      "geo_country" },
    { record->m_isCloudFeedLoaded,    "cloud_provider" },
    { record->m_isTorFeedLoaded,      "is_tor_exit" },
    { record->m_isDropListFeedLoaded, "listed_on" },
  };

  jsonbuf_appendFormat(json_buf, R"("unavailable":{)");
  int unavailable_count = 0;
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
  {
    if (sources[i].m_isFeedLoaded)
      continue;

    jsonbuf_appendFormat(json_buf, R"(%s"%s":"not_synced")", unavailable_count > 0 ? "," : "", sources[i].mp_key);
    unavailable_count++;
  }
  
  DnsAnswerStatus_t ptr_status = record->m_ptrAnswer.m_status;
  if (static_IPLOOKUPIsPtrUnavailable(ptr_status))
    jsonbuf_appendFormat(json_buf, R"(%s"ptr":"%s")", unavailable_count > 0 ? "," : "", static_DNSLOOKUPReason(ptr_status));
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_IPLOOKUPWriteEmptySlot(const IPLOOKUPSlot_t* slot, JsonBuf_t* json_buf)
{
  switch (slot->m_slotState)
  {
    case IPLOOKUP_SLOT_PRO_KEY_REQUIRED:
      jsonbuf_appendFormat(json_buf, R"({"available":false,"reason":"pro_key_required","action_url":")" PRICING_PAGE_URL R"("})");
      return;
    case IPLOOKUP_SLOT_KEY_MISSING:
    case IPLOOKUP_SLOT_KEY_REJECTED:
      jsonbuf_appendFormat(json_buf, R"({"available":false,"reason":"%s","action_url":")" PRICING_PRIVACY_MY_DATA_URL R"(","action_tool":")" PRICING_PRIVACY_MY_DATA_TOOL_NAME R"("})",
                           slot->m_slotState == IPLOOKUP_SLOT_KEY_MISSING ? "vendor_key_missing" : "vendor_key_rejected");
      return;
    case IPLOOKUP_SLOT_VENDOR_UNAVAILABLE:
      jsonbuf_appendFormat(json_buf, R"({"available":false,"reason":"vendor_unavailable")");
      if (slot->m_retryAfterSeconds > 0)
        jsonbuf_appendFormat(json_buf, R"(,"retry_after_seconds":%u)", slot->m_retryAfterSeconds);
      jsonbuf_appendFormat(json_buf, "}");
      return;
    case IPLOOKUP_SLOT_DB_ERROR:
    case IPLOOKUP_SLOT_FILLED:
      break;
  }
  jsonbuf_appendFormat(json_buf, R"({"available":false,"reason":"database_error"})");
}

static void static_IPLOOKUPWriteShodanTexts(const char* key, const ShodanTextArray_t* texts, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"%s":[)", key);
  for (size_t i = 0; i < texts->m_count; i++)
  {
    jsonbuf_appendFormat(json_buf, "%s\"", i > 0 ? "," : "");
    jsonbuf_appendEscaped(json_buf, texts->mp_items[i]);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static void static_IPLOOKUPWriteInternetExposure(const IPLOOKUPVendorSlots_t* slots, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("internet_exposure":)");
  if (slots->m_internetExposure.m_slotState != IPLOOKUP_SLOT_FILLED)
  {
    static_IPLOOKUPWriteEmptySlot(&slots->m_internetExposure, json_buf);
    return;
  }

  const ShodanHost_t* host = &slots->m_shodanHost;
  jsonbuf_appendFormat(json_buf, R"({"available":true,"source":"%s","ports":[)", host->m_isFromFacets ? "shodan_facets" : "shodan");
  for (size_t i = 0; i < host->m_portCount; i++)
    jsonbuf_appendFormat(json_buf, "%s%d", i > 0 ? "," : "", host->mp_ports[i]);
  jsonbuf_appendFormat(json_buf, "]");
  static_IPLOOKUPWriteShodanTexts("vulns", &host->m_vulns, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"vulns_truncated":%s)", host->m_isVulnListCut ? "true" : "false");
  static_IPLOOKUPWriteShodanTexts("hostnames", &host->m_hostnames, json_buf);
  static_IPLOOKUPWriteShodanTexts("tags", &host->m_tags, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("last_update", host->ma_lastUpdate, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_IPLOOKUPWriteReputation(const IPLOOKUPVendorSlots_t* slots, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("reputation":)");
  if (slots->m_reputation.m_slotState != IPLOOKUP_SLOT_FILLED)
  {
    static_IPLOOKUPWriteEmptySlot(&slots->m_reputation, json_buf);
    return;
  }

  const AbuseIpDbReport_t* report = &slots->m_abuseIpDbReport;
  jsonbuf_appendFormat(json_buf, R"({"available":true,"source":"abuseipdb","abuse_confidence_score":%d,"total_reports":%d,"distinct_reporter_count":%d,)",
                       report->m_abuseConfidenceScore, report->m_reportCount, report->m_distinctReporterCount);
  static_writeTextOrNull("last_reported_at", report->ma_lastReportedAt, json_buf);
  const char* whitelist_text = "null";
  if (report->m_whitelist == ABUSEIPDB_WHITELIST_YES)
    whitelist_text = "true";
  else if (report->m_whitelist == ABUSEIPDB_WHITELIST_NO)
    whitelist_text = "false";
  jsonbuf_appendFormat(json_buf, R"(,"is_whitelisted":%s,)", whitelist_text);
  static_writeTextOrNull("usage_type", report->ma_usageType, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_IPLOOKUP_response(const IPLOOKUPRecord_t* record, const IPLOOKUPVendorSlots_t* slots, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(slots    != NULL);
  assert(json_buf != NULL);
  assert(!record->m_isDropListFeedLoaded || record->mp_listedOn != NULL);

  jsonbuf_appendFormat(json_buf, R"({"ip_address":")");
  jsonbuf_appendEscaped(json_buf, record->ma_ipAddress);
  jsonbuf_appendFormat(json_buf, R"(",)");
  static_IPLOOKUPWriteAsn(record, json_buf);

  if (record->m_isGeoFeedLoaded)
    static_writeTextOrNull("geo_country", record->ma_geoCountry, json_buf);
  else
    jsonbuf_appendFormat(json_buf, R"("geo_country":null)");
  jsonbuf_appendFormat(json_buf, ",");

  static_IPLOOKUPWriteCloud(record, json_buf);
  static_IPLOOKUPWriteDatacenter(record, json_buf);

  if (record->m_isTorFeedLoaded)
    jsonbuf_appendFormat(json_buf, R"("is_tor_exit":%s,)", record->m_isTorExit ? "true" : "false");
  else
    jsonbuf_appendFormat(json_buf, R"("is_tor_exit":null,)");

  jsonbuf_appendFormat(json_buf, R"("listed_on":)");
  if (record->m_isDropListFeedLoaded)
    jsonbuf_appendJsonText(json_buf, record->mp_listedOn);
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, ",");

  static_IPLOOKUPWritePtr(&record->m_ptrAnswer, json_buf);
  static_IPLOOKUPWriteReputation(slots, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_IPLOOKUPWriteInternetExposure(slots, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_IPLOOKUPWriteUnavailable(record, json_buf);
  jsonbuf_appendFormat(json_buf, "}\n");
}

static int static_ASNLOOKUPNextOffset(const ASNLOOKUPRecord_t* record, const ASNLOOKUPParams_t* params)
{
  assert(params->m_offset >= 0 && params->m_limit >= 1);
  assert(record->m_ipv4PrefixCount >= 0 && record->m_ipv6PrefixCount >= 0);

  int larger_count = record->m_ipv4PrefixCount > record->m_ipv6PrefixCount ? record->m_ipv4PrefixCount
                                                                           : record->m_ipv6PrefixCount;
  if (larger_count <= params->m_offset)
    return params->m_offset;

  int left_count = larger_count - params->m_offset;
  return params->m_offset + (left_count < params->m_limit ? left_count : params->m_limit);
}

void serialize_ASNLOOKUP_response(const ASNLOOKUPRecord_t* record, const ASNLOOKUPParams_t* params, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);
  assert(record->mp_ipv4Prefixes != NULL && record->mp_ipv6Prefixes != NULL);

  jsonbuf_appendFormat(json_buf, R"({"target":")");
  jsonbuf_appendEscaped(json_buf, params->ma_target);
  jsonbuf_appendFormat(json_buf, R"(","asn":%)" PRIu32 ",", record->m_asn);
  static_writeTextOrNull("asn_name", record->ma_asnName, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("asn_country", record->ma_asnCountry, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_writeTextOrNull("prefix", record->ma_prefix, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"ipv4_prefix_count":%d,"ipv6_prefix_count":%d,"limit":%d,"offset":%d,"next_offset":%d,"ipv4_prefixes":)",
                       record->m_ipv4PrefixCount, record->m_ipv6PrefixCount, params->m_limit, params->m_offset,
                       static_ASNLOOKUPNextOffset(record, params));
  jsonbuf_appendJsonText(json_buf, record->mp_ipv4Prefixes);
  jsonbuf_appendFormat(json_buf, R"(,"ipv6_prefixes":)");
  jsonbuf_appendJsonText(json_buf, record->mp_ipv6Prefixes);
  jsonbuf_appendFormat(json_buf, "}\n");
}

static void static_WATCHLISTEDITWriteCveFilter(const WATCHLISTCVESEARCHItem_t* filter, JsonBuf_t* json_buf)
{
  if (filter->ma_vendor[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"vendor":")");
    jsonbuf_appendEscaped(json_buf, filter->ma_vendor);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  if (filter->ma_product[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"product":")");
    jsonbuf_appendEscaped(json_buf, filter->ma_product);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  if (filter->ma_severity[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"severity":")");
    jsonbuf_appendEscaped(json_buf, filter->ma_severity);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  if (filter->ma_cweId[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"cwe_id":")");
    jsonbuf_appendEscaped(json_buf, filter->ma_cweId);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  if (filter->m_minCvss >= 0.0)
    jsonbuf_appendFormat(json_buf, R"(,"min_cvss":%.1f)", filter->m_minCvss);
  if (filter->m_minEpss >= 0.0)
    jsonbuf_appendFormat(json_buf, R"(,"min_epss":%.5f)", filter->m_minEpss);
  if (filter->m_kevFilter != CVE_KEV_FILTER_ANY)
    jsonbuf_appendFormat(json_buf, R"(,"in_kev":%s)", filter->m_kevFilter == CVE_KEV_FILTER_ONLY_IN_KEV ? "true" : "false");
  if (filter->m_knownRansomware)
    jsonbuf_appendFormat(json_buf, R"(,"known_ransomware":true)");
  if (filter->m_hasNucleiTemplate)
    jsonbuf_appendFormat(json_buf, R"(,"has_nuclei_template":true)");
}

static void static_WATCHLISTEDITWriteCveId(const char* cve_id, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"cve_id":")");
  jsonbuf_appendEscaped(json_buf, cve_id);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_WATCHLISTEDITWriteDomainName(const char* domain_name, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"domain":")");
  jsonbuf_appendEscaped(json_buf, domain_name);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_WATCHLISTEDITWriteItemVersion(const char* version, JsonBuf_t* json_buf)
{
  if (version[0] == '\0')
  {
    jsonbuf_appendFormat(json_buf, R"(,"version":null)");
    return;
  }
  jsonbuf_appendFormat(json_buf, R"(,"version":")");
  jsonbuf_appendEscaped(json_buf, version);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_WATCHLISTEDITWriteItem(const WatchlistItem_t* item, JsonBuf_t* json_buf)
{
  const char* endpoint = watchlist_findEndpointName(item->m_itemKind);
  jsonbuf_appendFormat(json_buf, R"({"endpoint":")");
  jsonbuf_appendEscaped(json_buf, (endpoint != NULL) ? endpoint : "");
  jsonbuf_appendFormat(json_buf, "\"");
  switch (item->m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
      static_WATCHLISTEDITWriteCveId(item->m_cveLookup.ma_cveId, json_buf);
      break;
    case WATCHLIST_ITEM_KEV_LOOKUP:
      static_WATCHLISTEDITWriteCveId(item->m_kevLookup.ma_cveId, json_buf);
      break;
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      static_WATCHLISTEDITWriteCveId(item->m_cveExploit.ma_cveId, json_buf);
      break;
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
      jsonbuf_appendFormat(json_buf, R"(,"vendor":")");
      jsonbuf_appendEscaped(json_buf, item->m_productExposure.ma_vendor);
      jsonbuf_appendFormat(json_buf, R"(","product":")");
      jsonbuf_appendEscaped(json_buf, item->m_productExposure.ma_product);
      jsonbuf_appendFormat(json_buf, "\"");
      static_WATCHLISTEDITWriteItemVersion(item->m_productExposure.ma_version, json_buf);
      jsonbuf_appendFormat(json_buf, R"(,"product_has_cves":%s)", item->m_productExposure.m_hasCves ? "true" : "false");
      break;
    case WATCHLIST_ITEM_CVE_SEARCH:
      static_WATCHLISTEDITWriteCveFilter(&item->m_cveSearch, json_buf);
      break;
    case WATCHLIST_ITEM_DNS_LOOKUP:
      static_WATCHLISTEDITWriteDomainName(item->m_dnsLookup.ma_domainName, json_buf);
      break;
    case WATCHLIST_ITEM_SSL_CHECK:
      static_WATCHLISTEDITWriteDomainName(item->m_sslCheck.ma_domainName, json_buf);
      break;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      static_WATCHLISTEDITWriteDomainName(item->m_whoisLookup.ma_domainName, json_buf);
      break;
    case WATCHLIST_ITEM_HEADERS_CHECK:
      static_WATCHLISTEDITWriteDomainName(item->m_headersCheck.ma_domainName, json_buf);
      break;
    case WATCHLIST_ITEM_CERT_SEARCH:
      static_WATCHLISTEDITWriteDomainName(item->m_certSearch.ma_domainName, json_buf);
      break;
    case WATCHLIST_ITEM_PACKAGE_CHECK:
      jsonbuf_appendFormat(json_buf, R"(,"ecosystem":")");
      jsonbuf_appendEscaped(json_buf, item->m_packageCheck.ma_ecosystem);
      jsonbuf_appendFormat(json_buf, R"(","name":")");
      jsonbuf_appendEscaped(json_buf, item->m_packageCheck.ma_name);
      jsonbuf_appendFormat(json_buf, "\"");
      static_WATCHLISTEDITWriteItemVersion(item->m_packageCheck.ma_version, json_buf);
      break;
    case WATCHLIST_ITEM_IP_LOOKUP:
      jsonbuf_appendFormat(json_buf, R"(,"ip_address":")");
      jsonbuf_appendEscaped(json_buf, item->m_ipLookup.ma_ipAddress);
      jsonbuf_appendFormat(json_buf, "\"");
      break;
  }
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_WATCHLISTEDITItems_response(const WATCHLISTEDITItemsResult_t* result, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(json_buf != NULL);
  assert(result->m_itemCount == 0 || result->mp_items != NULL);

  jsonbuf_appendFormat(json_buf, R"({"items":[)");
  for (int i = 0; i < result->m_itemCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");

    static_WATCHLISTEDITWriteItem(&result->mp_items[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, "]");
  jsonbuf_appendFormat(json_buf, R"(,"item_count":%d,"item_limit":%d,"package_item_count":%d,"package_item_limit":%d})" "\n", result->m_itemCountForCurrentApiKey, WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY, result->m_packageItemCountForCurrentApiKey, WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY);
}

void serialize_WATCHLISTEDITPackageList_response(const WATCHLISTEDITPackageListResult_t* result, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(json_buf != NULL);
  assert(result->m_action == WATCHLISTEDIT_ACTION_ADD || result->m_action == WATCHLISTEDIT_ACTION_REMOVE);

  if (result->m_action == WATCHLISTEDIT_ACTION_ADD)
    jsonbuf_appendFormat(json_buf, R"({"added_count":%d,"unchanged_count":%d)", result->m_addedCount, result->m_unchangedCount);
  else
    jsonbuf_appendFormat(json_buf, R"({"removed_count":%d,"unchanged_count":%d)", result->m_removedCount, result->m_unchangedCount);
  jsonbuf_appendFormat(json_buf, R"(,"package_item_count":%d,"package_item_limit":%d})" "\n", result->m_packageItemCountForCurrentApiKey, WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY);
}

static void static_WATCHLISTEDITWriteEchoedText(const char* key, bool has_text, const char* text, JsonBuf_t* json_buf)
{
  assert(key != NULL);
  assert(!has_text || text != NULL);
  jsonbuf_appendFormat(json_buf, R"(,"%s":)", key);
  if (!has_text)
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscaped(json_buf, text);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_WATCHLISTEDITWriteProblemReason(const WATCHLISTEDITPackageElement_t* element, JsonBuf_t* json_buf)
{
  assert(element != NULL);
  const char* reason = "the element is not a package";
  switch (element->m_problem)
  {
    case PACKAGE_ELEMENT_PROBLEM_REPEATED:
      jsonbuf_appendFormat(json_buf, R"(,"reason":"repeats packages[%d]")", element->m_earlierIndex);
      return;
    case PACKAGE_ELEMENT_PROBLEM_NORMALIZED_REPEAT:
      jsonbuf_appendFormat(json_buf, R"(,"reason":"names the package and version of packages[%d] once the names are normalized")", element->m_earlierIndex);
      return;
    case PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT:     reason = "the element is not a JSON object"; break;
    case PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN:    reason = "the element holds a member other than ecosystem, name and version"; break;
    case PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED:   reason = "the element names one member twice"; break;
    case PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT: reason = "ecosystem must be a string of at most " MACRO_STR(PACKAGECHECK_ECOSYSTEM_MAX_LEN) " bytes, with no \\u0000 and no lone surrogate"; break;
    case PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT:     reason = "name must be a string of at most " MACRO_STR(PACKAGECHECK_NAME_MAX_LEN) " bytes, with no \\u0000 and no lone surrogate"; break;
    case PACKAGE_ELEMENT_PROBLEM_VERSION_NOT_TEXT:  reason = "version must be a string of at most " MACRO_STR(PACKAGECHECK_VERSION_MAX_LEN) " bytes, with no \\u0000 and no lone surrogate"; break;
    case PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN: reason = VALIDATE_PACKAGE_ECOSYSTEM_REFUSAL_MESSAGE; break;
    case PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY:        reason = "name is missing or empty"; break;
    case PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR: reason = "name must not contain a control character"; break;
    case PACKAGE_ELEMENT_PROBLEM_NAME_SPACE:        reason = VALIDATE_PACKAGE_NAME_REFUSAL_MESSAGE; break;
    case PACKAGE_ELEMENT_PROBLEM_VERSION_INVALID:   reason = VALIDATE_PACKAGE_VERSION_REFUSAL_MESSAGE; break;
    case PACKAGE_ELEMENT_PROBLEM_NONE:              break;
  }
  jsonbuf_appendFormat(json_buf, R"(,"reason":")");
  jsonbuf_appendEscaped(json_buf, reason);
  jsonbuf_appendFormat(json_buf, "\"");
}

void serialize_WATCHLISTEDITPackageList_problems_response(const char* message, const WATCHLISTEDITPackageElement_t* elements, int element_count, JsonBuf_t* json_buf)
{
  assert(message  != NULL);
  assert(elements != NULL || element_count == 0);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"error":{"code":"bad_request","message":")");
  jsonbuf_appendEscaped(json_buf, message);
  jsonbuf_appendFormat(json_buf, R"("},"problems":[)");
  bool is_first_row = true;
  for (int i = 0; i < element_count; i++)
  {
    const WATCHLISTEDITPackageElement_t* element = &elements[i];
    if (element->m_problem == PACKAGE_ELEMENT_PROBLEM_NONE)
      continue;

    jsonbuf_appendFormat(json_buf, R"(%s{"index":%d)", is_first_row ? "" : ",", i);
    static_WATCHLISTEDITWriteEchoedText("ecosystem", element->m_hasEcosystem, element->m_package.ma_ecosystem, json_buf);
    static_WATCHLISTEDITWriteEchoedText("name", element->m_hasName, element->m_package.ma_packageName, json_buf);
    static_WATCHLISTEDITWriteEchoedText("version", element->m_hasVersion, element->m_package.ma_version, json_buf);
    static_WATCHLISTEDITWriteProblemReason(element, json_buf);
    jsonbuf_appendFormat(json_buf, "}");
    is_first_row = false;
  }
  jsonbuf_appendFormat(json_buf, "]}\n");
}

static void static_WATCHLISTEVENTSWriteCveScore(JsonBuf_t* json_buf, bool has_value, double value)
{
  if (has_value)
    jsonbuf_appendFormat(json_buf, "%.5f", value);
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_WATCHLISTEVENTSWriteStringOrNull(JsonBuf_t* json_buf, bool is_set, const char* text)
{
  if (is_set)
  {
    jsonbuf_appendFormat(json_buf, R"(")");
    jsonbuf_appendEscaped(json_buf, text);
    jsonbuf_appendFormat(json_buf, R"(")");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_WATCHLISTEVENTSWriteCveEvent(const WATCHLISTEVENTSEvent_t* event, JsonBuf_t* json_buf)
{
  const WATCHLISTEVENTSCveChange_t* change = &event->m_cveChange;
  jsonbuf_appendFormat(json_buf, R"({"event":")");
  jsonbuf_appendEscaped(json_buf, event->ma_eventType);
  jsonbuf_appendFormat(json_buf, R"(","changed_at":")");
  jsonbuf_appendEscaped(json_buf, event->ma_changedAt);
  jsonbuf_appendFormat(json_buf, R"(","cve_id":")");
  jsonbuf_appendEscaped(json_buf, change->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(","previous":)");
  static_WATCHLISTEVENTSWriteCveScore(json_buf, change->m_hasPreviousValue, change->m_previousValue);
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  static_WATCHLISTEVENTSWriteCveScore(json_buf, change->m_hasCurrentValue, change->m_currentValue);
  jsonbuf_appendFormat(json_buf, R"(,"vendor":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, change->m_hasProductPair, change->ma_vendor);
  jsonbuf_appendFormat(json_buf, R"(,"product":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, change->m_hasProductPair, change->ma_product);
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_WATCHLISTEVENTSWriteLines(JsonBuf_t* json_buf, const char* text, bool is_mx_value)
{
  if (text == NULL)
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }
  jsonbuf_appendFormat(json_buf, "[");
  const char* line = (text[0] != '\0') ? text : NULL;
  while (line != NULL)
  {
    const char* line_end = strchr(line, '\n');
    size_t      line_len = (line_end != NULL) ? (size_t)(line_end - line) : strlen(line);
    if (line != text)
      jsonbuf_appendFormat(json_buf, ",");
    jsonbuf_appendFormat(json_buf, "\"");

    if (is_mx_value && line_len == sizeof("null") - 1 && memcmp(line, "null", line_len) == 0)
      jsonbuf_appendFormat(json_buf, "0 .");
    else
      jsonbuf_appendEscapedBytes(json_buf, line, line_len);
    jsonbuf_appendFormat(json_buf, "\"");
    line = (line_end != NULL) ? line_end + 1 : NULL;
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static bool static_WATCHLISTEVENTSFindEmailCheckKind(const char* check_id, EmailCheckKind_t* kind_out)
{
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
  {
    if (strcmp(emailcheck_kindId((EmailCheckKind_t)kind), check_id) == 0)
    {
      *kind_out = (EmailCheckKind_t)kind;
      return true;
    }
  }
  return false;
}

static bool static_WATCHLISTEVENTSTryReadEmailCheckResult(const char* vector, EmailCheckKind_t kind, EmailCheckResult_t* result_out)
{
  if (vector == NULL || strlen(vector) != EMAILCHECK_KIND_COUNT)
    return false;
  switch (vector[kind])
  {
    case 'p':
      *result_out = EMAILCHECK_RESULT_PASS;
      return true;
    case 'w':
      *result_out = EMAILCHECK_RESULT_WARN;
      return true;
    case 'f':
      *result_out = EMAILCHECK_RESULT_FAIL;
      return true;
    default:
      return false;
  }
}

static void static_WATCHLISTEVENTSWriteEmailCheckResult(JsonBuf_t* json_buf, const char* vector, EmailCheckKind_t kind)
{
  EmailCheckResult_t result = EMAILCHECK_RESULT_PASS;
  if (static_WATCHLISTEVENTSTryReadEmailCheckResult(vector, kind, &result))
    jsonbuf_appendFormat(json_buf, "\"%s\"", EMAILAUTHCHECK_RESULT_NAMES[result]);
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_WATCHLISTEVENTSWriteEmailAuthChange(const WATCHLISTDNSLOOKUPChange_t* change, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"check":")");
  jsonbuf_appendEscaped(json_buf, change->ma_degradedEmailCheckId);
  jsonbuf_appendFormat(json_buf, "\"");

  EmailCheckKind_t kind = EMAILCHECK_KIND_SPF_RECORD;
  if (!static_WATCHLISTEVENTSFindEmailCheckKind(change->ma_degradedEmailCheckId, &kind))
  {
    jsonbuf_appendFormat(json_buf, R"(,"previous":null,"current":null,"detail":null)");
    return;
  }
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  static_WATCHLISTEVENTSWriteEmailCheckResult(json_buf, change->mp_previousValue, kind);
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  static_WATCHLISTEVENTSWriteEmailCheckResult(json_buf, change->mp_currentValue, kind);
  jsonbuf_appendFormat(json_buf, R"(,"detail":)");
  EmailCheckResult_t current = EMAILCHECK_RESULT_PASS;
  const char* detail = static_WATCHLISTEVENTSTryReadEmailCheckResult(change->mp_currentValue, kind, &current)
                       ? EMAILAUTHCHECK_CHECK_DETAILS[kind][current] : NULL;
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, detail != NULL, detail);
}

static const char* static_WATCHLISTEVENTSFindDetailLine(const char* text)
{
  const char* line_end = (text != NULL) ? strchr(text, '\n') : NULL;
  return (line_end != NULL) ? line_end + 1 : NULL;
}

static void static_WATCHLISTEVENTSWriteExpiryBucket(JsonBuf_t* json_buf, const char* text)
{
  int digit_count = 0;
  if (text != NULL && text[0] >= '1' && text[0] <= '9')
  {
    if (text[1] == '\n')
      digit_count = 1;
    else if (text[1] >= '0' && text[1] <= '9' && text[2] == '\n')
      digit_count = 2;
  }

  if (digit_count > 0)
    jsonbuf_appendFormat(json_buf, "%.*s", digit_count, text);
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_WATCHLISTEVENTSWriteValidity(JsonBuf_t* json_buf, const char* text)
{
  if (text != NULL && strcmp(text, "valid") == 0)
    jsonbuf_appendFormat(json_buf, "[]");
  else
    static_WATCHLISTEVENTSWriteLines(json_buf, text, false);
}

#define SERIALIZE_IANA_ID_MAX_DIGIT_COUNT 19

static void static_WATCHLISTEVENTSWriteRegistrar(JsonBuf_t* json_buf, const char* text)
{
  if (text == NULL)
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }

  const char* line_end   = strchr(text, '\n');
  size_t      id_len     = (line_end != NULL) ? (size_t)(line_end - text) : strlen(text);
  bool        is_iana_id = id_len >= 1 && id_len <= SERIALIZE_IANA_ID_MAX_DIGIT_COUNT && (id_len == 1 || text[0] != '0');
  for (size_t i = 0; is_iana_id && i < id_len; i++)
    is_iana_id = text[i] >= '0' && text[i] <= '9';

  jsonbuf_appendFormat(json_buf, "[");
  if (is_iana_id)
    jsonbuf_appendFormat(json_buf, "%.*s", (int)id_len, text);
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, ",");
  const char* name = (line_end != NULL) ? line_end + 1 : NULL;
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, name != NULL && name[0] != '\0', name);
  jsonbuf_appendFormat(json_buf, "]");
}

typedef struct {
  const char* mp_previousValue;
  const char* mp_currentValue;
} SerializeDomainValues_t;

static void static_WATCHLISTEVENTSWriteLinesChange(const SerializeDomainValues_t* values, bool is_mx_value, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  static_WATCHLISTEVENTSWriteLines(json_buf, values->mp_previousValue, is_mx_value);
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  static_WATCHLISTEVENTSWriteLines(json_buf, values->mp_currentValue, is_mx_value);
}

static void static_WATCHLISTEVENTSWriteExpiryChange(const SerializeDomainValues_t* values, const char* end_field, JsonBuf_t* json_buf)
{
  const char* expiry = static_WATCHLISTEVENTSFindDetailLine(values->mp_currentValue);
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  static_WATCHLISTEVENTSWriteExpiryBucket(json_buf, values->mp_previousValue);
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  static_WATCHLISTEVENTSWriteExpiryBucket(json_buf, values->mp_currentValue);
  jsonbuf_appendFormat(json_buf, R"(,"%s":)", end_field);
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, expiry != NULL, expiry);
}

static bool static_WATCHLISTEVENTSHasHeaderLine(const char* value, const char* line, size_t line_len)
{
  const char* header = (value != NULL) ? strchr(value, '\n') : NULL;
  while (header != NULL)
  {
    header++;
    size_t header_len = strcspn(header, "\n");
    if (header_len == line_len && memcmp(header, line, line_len) == 0)
      return true;
    header = strchr(header, '\n');
  }
  return false;
}

static void static_WATCHLISTEVENTSWriteHeaderNames(JsonBuf_t* json_buf, const char* text)
{
  const char* names = static_WATCHLISTEVENTSFindDetailLine(text);
  if (text != NULL && names == NULL)
    jsonbuf_appendFormat(json_buf, "[]");
  else
    static_WATCHLISTEVENTSWriteLines(json_buf, names, false);
}

static void static_WATCHLISTEVENTSWriteSecurityHeaderRemoval(const WATCHLISTHEADERSCHECKChange_t* change, JsonBuf_t* json_buf)
{
  const char* current = change->mp_currentValue;
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  static_WATCHLISTEVENTSWriteHeaderNames(json_buf, change->mp_previousValue);
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  static_WATCHLISTEVENTSWriteHeaderNames(json_buf, current);
  jsonbuf_appendFormat(json_buf, R"(,"url":)");
  if (current != NULL)
  {
    jsonbuf_appendFormat(json_buf, "\"");
    jsonbuf_appendEscapedBytes(json_buf, current, strcspn(current, "\n"));
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");

  jsonbuf_appendFormat(json_buf, R"(,"removed":[)");
  bool is_first_name = true;
  const char* header = (change->mp_previousValue != NULL) ? strchr(change->mp_previousValue, '\n') : NULL;
  while (header != NULL)
  {
    header++;
    size_t header_len = strcspn(header, "\n");
    if (!static_WATCHLISTEVENTSHasHeaderLine(current, header, header_len))
    {
      jsonbuf_appendFormat(json_buf, is_first_name ? "\"" : ",\"");
      jsonbuf_appendEscapedBytes(json_buf, header, header_len);
      jsonbuf_appendFormat(json_buf, "\"");
      is_first_name = false;
    }
    header = strchr(header, '\n');
  }
  jsonbuf_appendFormat(json_buf, "]");
}

#define SERIALIZE_CERT_ISSUER_KNOWN_MARK "known"

static void static_WATCHLISTEVENTSWriteCertIssuersChange(const WATCHLISTCERTSEARCHChange_t* change, JsonBuf_t* json_buf)
{
  const char* current = change->mp_currentValue;
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  static_WATCHLISTEVENTSWriteLines(json_buf, change->mp_previousValue, false);

  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  if (current == NULL)
    jsonbuf_appendFormat(json_buf, "null");
  else
  {
    jsonbuf_appendFormat(json_buf, "[");
    for (const char* line = (current[0] != '\0') ? current : NULL; line != NULL; )
    {
      size_t line_len = strcspn(line, "\n");
      size_t mark_len = strcspn(line, " \n");
      size_t key_start = (mark_len < line_len) ? mark_len + 1 : line_len;
      jsonbuf_appendFormat(json_buf, (line != current) ? ",\"" : "\"");
      jsonbuf_appendEscapedBytes(json_buf, line + key_start, line_len - key_start);
      jsonbuf_appendFormat(json_buf, "\"");
      line = (line[line_len] == '\n') ? line + line_len + 1 : NULL;
    }
    jsonbuf_appendFormat(json_buf, "]");
  }

  jsonbuf_appendFormat(json_buf, R"(,"new_issuers":[)");
  bool is_first_issuer = true;
  for (const char* line = (current != NULL && current[0] != '\0') ? current : NULL; line != NULL; )
  {
    size_t line_len = strcspn(line, "\n");
    size_t mark_len = strcspn(line, " \n");
    size_t key_start = (mark_len < line_len) ? mark_len + 1 : line_len;
    bool   is_known  = mark_len == sizeof(SERIALIZE_CERT_ISSUER_KNOWN_MARK) - 1
                    && memcmp(line, SERIALIZE_CERT_ISSUER_KNOWN_MARK, mark_len) == 0;
    if (!is_known)
    {
      jsonbuf_appendFormat(json_buf, is_first_issuer ? R"({"issuer":")" : R"(,{"issuer":")");
      jsonbuf_appendEscapedBytes(json_buf, line + key_start, line_len - key_start);
      jsonbuf_appendFormat(json_buf, R"(","reason":")");
      jsonbuf_appendEscapedBytes(json_buf, line, mark_len);
      jsonbuf_appendFormat(json_buf, "\"}");
      is_first_issuer = false;
    }
    line = (line[line_len] == '\n') ? line + line_len + 1 : NULL;
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static void static_WATCHLISTEVENTSWriteStringChange(const SerializeDomainValues_t* values, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"previous":)");
  if (values->mp_previousValue != NULL)
  {
    jsonbuf_appendFormat(json_buf, "\"");
    jsonbuf_appendEscaped(json_buf, values->mp_previousValue);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, R"(,"current":)");
  if (values->mp_currentValue != NULL)
  {
    jsonbuf_appendFormat(json_buf, "\"");
    jsonbuf_appendEscaped(json_buf, values->mp_currentValue);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_WATCHLISTEVENTSWriteDnsLookupChange(const char* event_type, const WATCHLISTDNSLOOKUPChange_t* change, JsonBuf_t* json_buf)
{
  const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
  if (strcmp(event_type, "email_auth_degraded") == 0)
    static_WATCHLISTEVENTSWriteEmailAuthChange(change, json_buf);
  else if (strcmp(event_type, "ns_changed") == 0 || strcmp(event_type, "hosting_changed") == 0)
    static_WATCHLISTEVENTSWriteLinesChange(&values, false, json_buf);
  else if (strcmp(event_type, "mx_changed") == 0)
    static_WATCHLISTEVENTSWriteLinesChange(&values, true, json_buf);
  else
    static_WATCHLISTEVENTSWriteStringChange(&values, json_buf);
}

static void static_WATCHLISTEVENTSWriteSslCheckChange(const char* event_type, const WATCHLISTSSLCHECKChange_t* change, JsonBuf_t* json_buf)
{
  const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
  if (strcmp(event_type, "cert_expiring") == 0)
    static_WATCHLISTEVENTSWriteExpiryChange(&values, "valid_until", json_buf);
  else if (strcmp(event_type, "cert_invalid") == 0)
  {
    jsonbuf_appendFormat(json_buf, R"(,"previous":)");
    static_WATCHLISTEVENTSWriteValidity(json_buf, change->mp_previousValue);
    jsonbuf_appendFormat(json_buf, R"(,"current":)");
    static_WATCHLISTEVENTSWriteValidity(json_buf, change->mp_currentValue);
  }
  else if (strcmp(event_type, "cert_listed") == 0)
  {
    const char* listing_reason = static_WATCHLISTEVENTSFindDetailLine(change->mp_currentValue);
    jsonbuf_appendFormat(json_buf, R"(,"previous":null,"current":)");
    static_WATCHLISTEVENTSWriteStringOrNull(json_buf, listing_reason != NULL, listing_reason);
  }
  else
    static_WATCHLISTEVENTSWriteStringChange(&values, json_buf);
}

static void static_WATCHLISTEVENTSWriteWhoisLookupChange(const char* event_type, const WATCHLISTWHOISLOOKUPChange_t* change, JsonBuf_t* json_buf)
{
  const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
  if (strcmp(event_type, "domain_expiring") == 0)
    static_WATCHLISTEVENTSWriteExpiryChange(&values, "expires_at", json_buf);
  else if (strcmp(event_type, "registrar_changed") == 0)
  {
    jsonbuf_appendFormat(json_buf, R"(,"previous":)");
    static_WATCHLISTEVENTSWriteRegistrar(json_buf, change->mp_previousValue);
    jsonbuf_appendFormat(json_buf, R"(,"current":)");
    static_WATCHLISTEVENTSWriteRegistrar(json_buf, change->mp_currentValue);
  }
  else if (strcmp(event_type, "transfer_lock_removed") == 0)
    static_WATCHLISTEVENTSWriteLinesChange(&values, false, json_buf);
  else
    static_WATCHLISTEVENTSWriteStringChange(&values, json_buf);
}

static void static_WATCHLISTEVENTSWriteHeadersCheckChange(const char* event_type, const WATCHLISTHEADERSCHECKChange_t* change, JsonBuf_t* json_buf)
{
  const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
  if (strcmp(event_type, "security_header_removed") == 0)
    static_WATCHLISTEVENTSWriteSecurityHeaderRemoval(change, json_buf);
  else
    static_WATCHLISTEVENTSWriteStringChange(&values, json_buf);
}

static void static_WATCHLISTEVENTSWriteCertSearchChange(const char* event_type, const WATCHLISTCERTSEARCHChange_t* change, JsonBuf_t* json_buf)
{
  const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
  if (strcmp(event_type, "cert_unexpected") == 0)
    static_WATCHLISTEVENTSWriteCertIssuersChange(change, json_buf);
  else
    static_WATCHLISTEVENTSWriteStringChange(&values, json_buf);
}

static void static_WATCHLISTEVENTSWriteDomainEvent(const WATCHLISTEVENTSEvent_t* event, JsonBuf_t* json_buf)
{
  const char* event_type = event->ma_eventType;
  jsonbuf_appendFormat(json_buf, R"({"event":")");
  jsonbuf_appendEscaped(json_buf, event_type);
  jsonbuf_appendFormat(json_buf, R"(","changed_at":")");
  jsonbuf_appendEscaped(json_buf, event->ma_changedAt);
  jsonbuf_appendFormat(json_buf, "\"");

  switch (event->m_eventKind)
  {
    case WATCHLIST_EVENT_DNS_LOOKUP:
      static_WATCHLISTEVENTSWriteDnsLookupChange(event_type, &event->m_dnsLookupChange, json_buf);
      break;
    case WATCHLIST_EVENT_SSL_CHECK:
      static_WATCHLISTEVENTSWriteSslCheckChange(event_type, &event->m_sslCheckChange, json_buf);
      break;
    case WATCHLIST_EVENT_WHOIS_LOOKUP:
      static_WATCHLISTEVENTSWriteWhoisLookupChange(event_type, &event->m_whoisLookupChange, json_buf);
      break;
    case WATCHLIST_EVENT_HEADERS_CHECK:
      static_WATCHLISTEVENTSWriteHeadersCheckChange(event_type, &event->m_headersCheckChange, json_buf);
      break;
    case WATCHLIST_EVENT_CERT_SEARCH:
      static_WATCHLISTEVENTSWriteCertSearchChange(event_type, &event->m_certSearchChange, json_buf);
      break;
    case WATCHLIST_EVENT_CVE:
    case WATCHLIST_EVENT_PACKAGE_CHECK:
    case WATCHLIST_EVENT_IP_LOOKUP:
    case WATCHLIST_EVENT_PRODUCT_EXPOSURE:
      break;
  }
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_WATCHLISTEVENTSWritePackageEvent(const WATCHLISTEVENTSEvent_t* event, bool is_version_affected, JsonBuf_t* json_buf)
{
  const WATCHLISTPACKAGECHECKChange_t* change = &event->m_packageCheckChange;
  jsonbuf_appendFormat(json_buf, R"({"event":")");
  jsonbuf_appendEscaped(json_buf, event->ma_eventType);
  jsonbuf_appendFormat(json_buf, R"(","changed_at":")");
  jsonbuf_appendEscaped(json_buf, event->ma_changedAt);
  jsonbuf_appendFormat(json_buf, R"(","cve_id":null,"advisory_id":")");
  jsonbuf_appendEscaped(json_buf, change->ma_advisoryId);
  jsonbuf_appendFormat(json_buf, R"(","fixed_version":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, change->ma_fixedVersion[0] != '\0', change->ma_fixedVersion);
  jsonbuf_appendFormat(json_buf, R"(,"affects_version":%s})", is_version_affected ? "true" : "null");
}

static void static_WATCHLISTEVENTSWriteDropListings(JsonBuf_t* json_buf, const char* text)
{
  if (text == NULL)
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }
  jsonbuf_appendFormat(json_buf, "[");
  const char* line = (text[0] != '\0') ? text : NULL;
  while (line != NULL)
  {
    const char* line_end   = strchr(line, '\n');
    size_t      line_len   = (line_end != NULL) ? (size_t)(line_end - line) : strlen(line);
    const char* space      = memchr(line, ' ', line_len);
    size_t      prefix_len = (space != NULL) ? (size_t)(space - line) : line_len;
    if (line != text)
      jsonbuf_appendFormat(json_buf, ",");
    jsonbuf_appendFormat(json_buf, R"({"prefix":")");
    jsonbuf_appendEscapedBytes(json_buf, line, prefix_len);
    jsonbuf_appendFormat(json_buf, R"(","listing_id":")");
    if (space != NULL)
      jsonbuf_appendEscapedBytes(json_buf, space + 1, line_len - prefix_len - 1);
    jsonbuf_appendFormat(json_buf, R"("})");
    line = (line_end != NULL) ? line_end + 1 : NULL;
  }
  jsonbuf_appendFormat(json_buf, "]");
}

static void static_WATCHLISTEVENTSWriteIpEvent(const WATCHLISTEVENTSEvent_t* event, JsonBuf_t* json_buf)
{
  const WATCHLISTIPLOOKUPChange_t* change = &event->m_ipLookupChange;
  jsonbuf_appendFormat(json_buf, R"({"event":")");
  jsonbuf_appendEscaped(json_buf, event->ma_eventType);
  jsonbuf_appendFormat(json_buf, R"(","changed_at":")");
  jsonbuf_appendEscaped(json_buf, event->ma_changedAt);
  jsonbuf_appendFormat(json_buf, "\"");
  if (strcmp(event->ma_eventType, "hosting_changed") == 0)
  {
    const SerializeDomainValues_t values = { change->mp_previousValue, change->mp_currentValue };
    static_WATCHLISTEVENTSWriteLinesChange(&values, false, json_buf);
  }
  else
  {
    jsonbuf_appendFormat(json_buf, R"(,"previous":)");
    static_WATCHLISTEVENTSWriteDropListings(json_buf, change->mp_previousValue);
    jsonbuf_appendFormat(json_buf, R"(,"current":)");
    static_WATCHLISTEVENTSWriteDropListings(json_buf, change->mp_currentValue);
    jsonbuf_appendFormat(json_buf, R"(,"list_time":")");
    jsonbuf_appendEscaped(json_buf, change->ma_dropListTime);
    jsonbuf_appendFormat(json_buf, R"(","copyright":")");
    jsonbuf_appendEscaped(json_buf, change->ma_dropCopyright);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_WATCHLISTEVENTSWriteEolEvent(const WATCHLISTEVENTSEvent_t* event, JsonBuf_t* json_buf)
{
  const WATCHLISTPRODUCTEXPOSUREChange_t* change = &event->m_productExposureChange;
  jsonbuf_appendFormat(json_buf, R"({"event":")");
  jsonbuf_appendEscaped(json_buf, event->ma_eventType);
  jsonbuf_appendFormat(json_buf, R"(","changed_at":")");
  jsonbuf_appendEscaped(json_buf, event->ma_changedAt);
  jsonbuf_appendFormat(json_buf, R"(","cve_id":null,"eol":{"product":")");
  jsonbuf_appendEscaped(json_buf, change->ma_eolProduct);
  jsonbuf_appendFormat(json_buf, R"(","cycle":")");
  jsonbuf_appendEscaped(json_buf, change->ma_cycle);
  jsonbuf_appendFormat(json_buf, R"(","eol_date":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, change->ma_eolDate[0] != '\0', change->ma_eolDate);
  jsonbuf_appendFormat(json_buf, R"(,"previous_eol_date":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, change->ma_previousEolDate[0] != '\0', change->ma_previousEolDate);
  jsonbuf_appendFormat(json_buf, "}}");
}

static void static_WATCHLISTEVENTSWriteEvent(const WATCHLISTEVENTSEvent_t* event, bool is_version_affected, JsonBuf_t* json_buf)
{
  switch (event->m_eventKind)
  {
    case WATCHLIST_EVENT_CVE:
      static_WATCHLISTEVENTSWriteCveEvent(event, json_buf);
      return;
    case WATCHLIST_EVENT_DNS_LOOKUP:
    case WATCHLIST_EVENT_SSL_CHECK:
    case WATCHLIST_EVENT_WHOIS_LOOKUP:
    case WATCHLIST_EVENT_HEADERS_CHECK:
    case WATCHLIST_EVENT_CERT_SEARCH:
      static_WATCHLISTEVENTSWriteDomainEvent(event, json_buf);
      return;
    case WATCHLIST_EVENT_PACKAGE_CHECK:
      static_WATCHLISTEVENTSWritePackageEvent(event, is_version_affected, json_buf);
      return;
    case WATCHLIST_EVENT_IP_LOOKUP:
      static_WATCHLISTEVENTSWriteIpEvent(event, json_buf);
      return;
    case WATCHLIST_EVENT_PRODUCT_EXPOSURE:
      static_WATCHLISTEVENTSWriteEolEvent(event, json_buf);
      return;
  }
}

static void static_WATCHLISTEVENTSWriteAdvisory(const WATCHLISTPACKAGECHECKAdvisory_t* advisory, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscaped(json_buf, advisory->ma_advisoryId);
  jsonbuf_appendFormat(json_buf, R"(":{"source":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, advisory->ma_source[0] != '\0', advisory->ma_source);
  jsonbuf_appendFormat(json_buf, R"(,"aliases":)");
  jsonbuf_appendJsonText(json_buf, advisory->mp_aliases != NULL ? advisory->mp_aliases : "[]");
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_WATCHLISTEVENTSWriteCveFacts(const WATCHLISTEVENTSCveFacts_t* facts, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscaped(json_buf, facts->ma_cveId);
  jsonbuf_appendFormat(json_buf, R"(":{"risk_score":%.1f,"label":")", facts->m_riskScore);
  jsonbuf_appendEscaped(json_buf, facts->ma_riskLabel);
  jsonbuf_appendFormat(json_buf, R"(","in_kev":%s,"kev_patch_deadline":)", facts->m_isInKev ? "true" : "false");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, facts->m_hasKev, facts->ma_kevPatchDeadline);

  jsonbuf_appendFormat(json_buf, R"(,"known_ransomware":%s,"has_metasploit":%s,"poc_count":%d})",
                       facts->m_kevKnownRansomware ? "true" : "false", facts->m_hasMetasploit ? "true" : "false", facts->m_pocCount);
}

static void static_WATCHLISTEVENTSWriteFailingEmailChecks(JsonBuf_t* json_buf, const char* vector)
{
  if (vector == NULL || strlen(vector) != EMAILCHECK_KIND_COUNT)
  {
    jsonbuf_appendFormat(json_buf, "null");
    return;
  }
  jsonbuf_appendFormat(json_buf, "{");
  bool is_first = true;
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
  {
    EmailCheckResult_t result = EMAILCHECK_RESULT_PASS;
    if (!static_WATCHLISTEVENTSTryReadEmailCheckResult(vector, (EmailCheckKind_t)kind, &result) || result == EMAILCHECK_RESULT_PASS)
      continue;
    jsonbuf_appendFormat(json_buf, R"(%s"%s":"%s")", is_first ? "" : ",", emailcheck_kindId((EmailCheckKind_t)kind), EMAILAUTHCHECK_RESULT_NAMES[result]);
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_WATCHLISTEVENTSWriteDomainDnsFacts(const WATCHLISTDNSLOOKUPFacts_t* dns_facts, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"(,"dns_presence":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, dns_facts->mp_dnsPresenceValue != NULL, dns_facts->mp_dnsPresenceValue);
  jsonbuf_appendFormat(json_buf, R"(,"ns":)");
  static_WATCHLISTEVENTSWriteLines(json_buf, dns_facts->mp_nsValue, false);
  jsonbuf_appendFormat(json_buf, R"(,"mx":)");
  static_WATCHLISTEVENTSWriteLines(json_buf, dns_facts->mp_mxValue, true);
  jsonbuf_appendFormat(json_buf, R"(,"ip_address_reachability":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, dns_facts->mp_ipAddressReachabilityValue != NULL, dns_facts->mp_ipAddressReachabilityValue);
  jsonbuf_appendFormat(json_buf, R"(,"cname_takeover":)");
  static_WATCHLISTEVENTSWriteStringOrNull(json_buf, dns_facts->mp_cnameTakeoverValue != NULL, dns_facts->mp_cnameTakeoverValue);
  jsonbuf_appendFormat(json_buf, R"(,"email_auth_failing":)");
  static_WATCHLISTEVENTSWriteFailingEmailChecks(json_buf, dns_facts->mp_emailAuthValue);
}

static void static_WATCHLISTEVENTSWriteDomainFacts(const WATCHLISTEVENTSDomainFacts_t* facts, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscaped(json_buf, facts->ma_domainName);
  jsonbuf_appendFormat(json_buf, R"(":{"registered_domain":")");
  jsonbuf_appendEscaped(json_buf, facts->ma_registeredDomain);
  jsonbuf_appendFormat(json_buf, "\"");
  static_WATCHLISTEVENTSWriteDomainDnsFacts(&facts->m_dnsFacts, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_WATCHLISTEVENTS_response(const WATCHLISTEVENTSResult_t* result, const WATCHLISTEVENTSParams_t* params, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);
  assert(result->m_eventCount == 0 || result->mp_events != NULL);
  assert(result->m_answerItemCount == 0 || result->mp_answerItems != NULL);
  assert(result->m_pairCount == 0 || result->mp_pairEventIndexes != NULL);
  assert(result->m_cveFactCount == 0 || result->mp_cveFacts != NULL);
  assert(result->m_domainFactCount == 0 || result->mp_domainFacts != NULL);
  assert(result->m_advisoryCount == 0 || result->mp_advisories != NULL);

  jsonbuf_appendFormat(json_buf, R"({"limit":%d,"cursor":)", params->m_limit);
  if (params->ma_cursor[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, "\"");
    jsonbuf_appendEscaped(json_buf, params->ma_cursor);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, R"(,"repeat":%s,"next_cursor":)", params->m_isRepeat ? "true" : "false");
  if (result->ma_nextCursor[0] != '\0')
  {
    jsonbuf_appendFormat(json_buf, "\"");
    jsonbuf_appendEscaped(json_buf, result->ma_nextCursor);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
  jsonbuf_appendFormat(json_buf, R"(,"has_more":%s,"items":[)", result->m_hasMore ? "true" : "false");
  for (int i = 0; i < result->m_answerItemCount; i++)
  {
    const WATCHLISTEVENTSAnswerItem_t* answer_item = &result->mp_answerItems[i];
    assert(answer_item->m_firstPairIndex >= 0 && answer_item->m_pairCount >= 0);
    assert(answer_item->m_firstPairIndex + answer_item->m_pairCount <= result->m_pairCount);
    jsonbuf_appendFormat(json_buf, R"(%s{"item":)", i > 0 ? "," : "");
    static_WATCHLISTEDITWriteItem(&answer_item->m_item, json_buf);
    jsonbuf_appendFormat(json_buf, R"(,"events":[)");
    for (int k = 0; k < answer_item->m_pairCount; k++)
    {
      int event_index = result->mp_pairEventIndexes[answer_item->m_firstPairIndex + k];
      assert(event_index >= 0 && event_index < result->m_eventCount);
      if (k > 0)
        jsonbuf_appendFormat(json_buf, ",");
      bool is_version_affected = false;
      if (result->mp_events[event_index].m_eventKind == WATCHLIST_EVENT_PACKAGE_CHECK)
      {
        assert(result->mp_pairIsVersionAffected != NULL);
        is_version_affected = result->mp_pairIsVersionAffected[answer_item->m_firstPairIndex + k];
      }
      static_WATCHLISTEVENTSWriteEvent(&result->mp_events[event_index], is_version_affected, json_buf);
    }
    jsonbuf_appendFormat(json_buf, "]}");
  }

  jsonbuf_appendFormat(json_buf, R"(],"cves":{)");
  for (int i = 0; i < result->m_cveFactCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_WATCHLISTEVENTSWriteCveFacts(&result->mp_cveFacts[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, R"(},"domains":{)");
  for (int i = 0; i < result->m_domainFactCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_WATCHLISTEVENTSWriteDomainFacts(&result->mp_domainFacts[i], json_buf);
  }

  jsonbuf_appendFormat(json_buf, R"(},"advisories":{)");
  for (int i = 0; i < result->m_advisoryCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_WATCHLISTEVENTSWriteAdvisory(&result->mp_advisories[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, R"(},"attribution":)");
  jsonbuf_appendJsonText(json_buf, result->mp_attribution != NULL ? result->mp_attribution : "[]");
  jsonbuf_appendFormat(json_buf, "}\n");
}

static void static_D3FENDFORATTACKWriteTextOrNull(const char* text, JsonBuf_t* json_buf)
{
  if (*text)
  {
    jsonbuf_appendFormat(json_buf, R"(")");
    jsonbuf_appendEscaped(json_buf, text);
    jsonbuf_appendFormat(json_buf, R"(")");
  }
  else
    jsonbuf_appendFormat(json_buf, "null");
}

static void static_D3FENDFORATTACKWriteDefense(const D3FENDFORATTACKItem_t* defense, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"defense_id":")");
  jsonbuf_appendEscaped(json_buf, defense->ma_defenseId);
  jsonbuf_appendFormat(json_buf, R"(","defense_label":")");
  jsonbuf_appendEscaped(json_buf, defense->ma_defenseLabel);
  jsonbuf_appendFormat(json_buf, R"(","uri":")" D3FEND_URI_PREFIX);
  jsonbuf_appendEscaped(json_buf, defense->ma_defenseId);
  jsonbuf_appendFormat(json_buf, R"(","parent_defense_labels":)");
  jsonbuf_appendJsonText(json_buf, defense->mp_parentDefenseLabels ? defense->mp_parentDefenseLabels : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"defense_tactic":")");
  jsonbuf_appendEscaped(json_buf, defense->ma_defenseTactic);
  jsonbuf_appendFormat(json_buf, R"(","digital_artifact":)");
  static_D3FENDFORATTACKWriteTextOrNull(defense->ma_digitalArtifact, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"attack_technique_ids":)");
  jsonbuf_appendJsonText(json_buf, defense->mp_attackTechniqueIds ? defense->mp_attackTechniqueIds : "[]");
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_D3FENDFORATTACK_response(const D3FENDFORATTACKResult_t* result, const D3FENDFORATTACKParams_t* params, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"attack_technique_id":")");
  jsonbuf_appendEscaped(json_buf, params->ma_attackTechniqueId);
  jsonbuf_appendFormat(json_buf, R"(","attack_techniques":)");
  jsonbuf_appendJsonText(json_buf, result->mp_attackTechniques ? result->mp_attackTechniques : "[]");

  jsonbuf_appendFormat(json_buf, R"(,"defense_count_by_defense_tactic":{)");
  for (size_t i = 0; i < sizeof(D3FENDFORATTACK_TACTIC_NAMES) / sizeof(D3FENDFORATTACK_TACTIC_NAMES[0]); i++)
  {
    int defense_count_per_tactic = 0;
    for (int j = 0; j < result->m_defenseCount; j++)
      if (strcmp(result->mp_defenses[j].ma_defenseTactic, D3FENDFORATTACK_TACTIC_NAMES[i]) == 0)
        defense_count_per_tactic++;

    jsonbuf_appendFormat(json_buf, R"(%s"%s":%d)", i > 0 ? "," : "", D3FENDFORATTACK_TACTIC_NAMES[i], defense_count_per_tactic);
  }

  jsonbuf_appendFormat(json_buf, R"(},"defenses":[)");
  for (int i = 0; i < result->m_defenseCount; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_D3FENDFORATTACKWriteDefense(&result->mp_defenses[i], json_buf);
  }
  jsonbuf_appendFormat(json_buf, "]}\n");
}

static const char* static_fileHashTypeName(const char* file_hash)
{
  switch (strlen(file_hash))
  {
    case VALIDATE_MD5_HEX_LEN:  return "md5";
    case VALIDATE_SHA1_HEX_LEN: return "sha1";
    default:                    return "sha256";
  }
}

static void static_DRIVERLOOKUPWriteHash(const DRIVERLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"({"hash":")");
  jsonbuf_appendEscaped(json_buf, record->ma_fileHash);
  jsonbuf_appendFormat(json_buf, R"(","hash_type":"%s",)", static_fileHashTypeName(record->ma_fileHash));
}

static void static_DRIVERLOOKUPWriteMatches(const DRIVERLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  if (record->m_isDriverFeedLoaded)
  {
    jsonbuf_appendFormat(json_buf, R"("found":%s,"match_count":%d,"matches":)",
                         record->m_matchCount > 0 ? "true" : "false", record->m_matchCount);
    jsonbuf_appendJsonText(json_buf, record->mp_matches ? record->mp_matches : "[]");
  }
  else
    jsonbuf_appendFormat(json_buf, R"("found":null,"match_count":null,"matches":[])");
}

void serialize_DRIVERLOOKUP_response(const DRIVERLOOKUPRecord_t* record, JsonBuf_t* json_buf)
{
  assert(record   != NULL);
  assert(json_buf != NULL);

  static_DRIVERLOOKUPWriteHash(record, json_buf);
  jsonbuf_appendFormat(json_buf, "%s,", record->m_isDriverFeedLoaded ? DRIVERLOOKUP_DATA_SOURCE_LOADED_JSON : DRIVERLOOKUP_DATA_SOURCE_NOT_SYNCED_JSON);
  static_DRIVERLOOKUPWriteMatches(record, json_buf);
  jsonbuf_appendFormat(json_buf, "}\n");
}

void serialize_DRIVERLOOKUPBULK_response(const DRIVERLOOKUPBULKResult_t* results, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf,
    R"({"total":%d,"processed":%d,"successful":%d,"skipped":%d,"failed":%d,)",
    results->m_total, results->m_processed, results->m_successful, results->m_skipped, results->m_failed);
  static_writeNotProcessedIds(results->mp_notProcessedIds, results->m_notProcessedCount, json_buf);
  if (results->m_successful == 0)
    jsonbuf_appendFormat(json_buf, DRIVERLOOKUP_DATA_SOURCE_UNKNOWN_JSON ",");
  else if (results->mp_items[0].m_isDriverFeedLoaded)
    jsonbuf_appendFormat(json_buf, DRIVERLOOKUP_DATA_SOURCE_LOADED_JSON ",");
  else
    jsonbuf_appendFormat(json_buf, DRIVERLOOKUP_DATA_SOURCE_NOT_SYNCED_JSON ",");
  jsonbuf_appendFormat(json_buf, R"("results":[)");

  for (int i = 0; i < results->m_successful; i++)
  {
    if (i > 0)
      jsonbuf_appendFormat(json_buf, ",");
    static_DRIVERLOOKUPWriteHash(&results->mp_items[i], json_buf);
    static_DRIVERLOOKUPWriteMatches(&results->mp_items[i], json_buf);
    jsonbuf_appendFormat(json_buf, "}\n");
  }

  jsonbuf_appendFormat(json_buf, "]}");
}

static void static_writeNotProcessedPackages(const PACKAGECHECKBULKItem_t* items, int count, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("not_processed":[)");
  for (int i = 0; i < count; i++)
  {
    jsonbuf_appendFormat(json_buf, i > 0 ? R"(,{"ecosystem":")" : R"({"ecosystem":")");
    jsonbuf_appendEscaped(json_buf, items[i].ma_ecosystem);
    jsonbuf_appendFormat(json_buf, R"(","name":")");
    jsonbuf_appendEscaped(json_buf, items[i].ma_packageName);
    jsonbuf_appendFormat(json_buf, R"(","version":")");
    jsonbuf_appendEscaped(json_buf, items[i].ma_version);
    jsonbuf_appendFormat(json_buf, R"("})");
  }
  jsonbuf_appendFormat(json_buf, "],");
}

void serialize_PACKAGECHECKBULK_response(const PACKAGECHECKBULKResult_t* results, JsonBuf_t* json_buf)
{
  assert(results  != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf,
    R"({"total":%d,"processed":%d,"successful":%d,"skipped":%d,"failed":%d,)",
    results->m_total, results->m_processed, results->m_successful, results->m_skipped, results->m_failed);
  static_writeNotProcessedPackages(results->mp_notProcessedItems, results->m_notProcessedCount, json_buf);

  if (results->m_successful == 0)
    jsonbuf_appendFormat(json_buf, PACKAGECHECK_DATA_SOURCE_UNKNOWN_JSON ",");
  else if (results->m_isAdvisoryFeedLoaded)
    jsonbuf_appendFormat(json_buf, PACKAGECHECK_DATA_SOURCE_LOADED_JSON ",");
  else
    jsonbuf_appendFormat(json_buf, PACKAGECHECK_DATA_SOURCE_NOT_SYNCED_JSON ",");
  
  jsonbuf_appendFormat(json_buf, R"("results":)");
  jsonbuf_appendJsonText(json_buf, results->mp_results ? results->mp_results : "[]");
  jsonbuf_appendFormat(json_buf, R"(,"attribution":)");
  jsonbuf_appendJsonText(json_buf, results->mp_attribution ? results->mp_attribution : "[]");
  jsonbuf_appendFormat(json_buf, "}\n");
}

void serialize_PACKAGECHECK_response(const PACKAGECHECKResult_t* result, const PACKAGECHECKParams_t* params, JsonBuf_t* json_buf)
{
  assert(result   != NULL);
  assert(params   != NULL);
  assert(json_buf != NULL);

  long page_count  = (long)result->m_resultCount - params->m_offset;
  page_count       = page_count < 0 ? 0 : (page_count > params->m_limit ? params->m_limit : page_count);
  long next_offset = (long)params->m_offset + page_count;

  jsonbuf_appendFormat(json_buf, R"({%s,"has_advisory_data":%s,"total":%d,"limit":%d,"offset":%d,"next_offset":%ld,)",
    result->m_isAdvisoryFeedLoaded ? PACKAGECHECK_DATA_SOURCE_LOADED_JSON : PACKAGECHECK_DATA_SOURCE_NOT_SYNCED_JSON,
    result->m_hasAdvisoryData ? "true" : "false", result->m_resultCount, params->m_limit, params->m_offset, next_offset);
  if (params->ma_version[0] != '\0')
  {
    if (result->ma_fixedVersion[0] == '\0')
      jsonbuf_appendFormat(json_buf, R"("fixed_version":null,)");
    else
    {
      jsonbuf_appendFormat(json_buf, R"("fixed_version":")");
      jsonbuf_appendEscaped(json_buf, result->ma_fixedVersion);
      jsonbuf_appendFormat(json_buf, R"(",)");
    }
  }
  jsonbuf_appendFormat(json_buf, R"("malicious":)");
  jsonbuf_appendJsonText(json_buf, result->mp_malicious ? result->mp_malicious : "null");
  jsonbuf_appendFormat(json_buf, R"(,"results":)");
  jsonbuf_appendJsonText(json_buf, result->mp_results ? result->mp_results : "[]");
  jsonbuf_appendFormat(json_buf, ",");
  static_PRODUCTEXPOSUREWriteEol(&result->m_eol, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"attribution":)");
  jsonbuf_appendJsonText(json_buf, result->mp_attribution ? result->mp_attribution : "[]");
  jsonbuf_appendFormat(json_buf, "}\n");
}

void serialize_IMAGEINSPECT_response(const ImageScanResult_t* result, const ExifClientResult_t* exif, const ImageIndicatorResult_t* indicators, JsonBuf_t* json_buf)
{
  assert(result     != NULL);
  assert(exif       != NULL);
  assert(indicators != NULL);
  assert(json_buf   != NULL);

  jsonbuf_appendFormat(json_buf, R"({"format":"%s","byte_count":%zu,"sha256":"%s","embedded_file_signatures":[)",
                       imagescan_formatName(result->m_format), result->m_byteCount, result->ma_sha256Hex);

  bool is_first_match = true;
  for (int i = 0; i < IMAGESCAN_FILE_TYPE_COUNT; i++)
  {
    const ImageScanSignatureMatch_t* match = &result->ma_signatureMatches[i];
    if (match->m_matchCount == 0)
      continue;

    jsonbuf_appendFormat(json_buf,
                         R"(%s{"file_type":"%s","match_count":%d,"match_offsets":[)",
                         is_first_match ? "" : ",",
                         imagescan_fileTypeName((ImageScanFileType_t)i),
                         match->m_matchCount);

    int offset_count = match->m_matchCount < IMAGESCAN_MAX_MATCH_OFFSETS ? match->m_matchCount : IMAGESCAN_MAX_MATCH_OFFSETS;
    for (int k = 0; k < offset_count; k++)
      jsonbuf_appendFormat(json_buf, "%s%zu", k > 0 ? "," : "", match->ma_matchOffsets[k]);
    jsonbuf_appendFormat(json_buf, "]}");
    
    is_first_match = false;
  }
  
  jsonbuf_appendFormat(json_buf, R"(],"embedded_file_signature_note":")" IMAGEINSPECT_SIGNATURE_NOTE R"(",)");
  static_IMAGEINSPECTWriteMetadata(exif, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_IMAGEINSPECTWriteIndicators(indicators, json_buf);
  jsonbuf_appendFormat(json_buf, "}\n");
}

static void static_IMAGEINSPECTWriteText(const char* key, const char* text, JsonBuf_t* json_buf)
{
  if (*text == '\0')
  {
    jsonbuf_appendFormat(json_buf, R"("%s":null)", key);
    return;
  }
  jsonbuf_appendFormat(json_buf, R"("%s":")", key);
  jsonbuf_appendEscaped(json_buf, text);
  jsonbuf_appendFormat(json_buf, "\"");
}

static void static_IMAGEINSPECTWriteMetadata(const ExifClientResult_t* exif, JsonBuf_t* json_buf)
{
  const struct { const char* mp_key; const char* mp_text; } texts[] = {
    { "camera_make",          exif->ma_cameraMake         },
    { "camera_model",         exif->ma_cameraModel        },
    { "software",             exif->ma_software           },
    { "creator_tool",         exif->ma_creatorTool        },
    { "digital_source_type",  exif->ma_digitalSourceType  },
    { "date_time_original",   exif->ma_dateTimeOriginal   },
    { "offset_time_original", exif->ma_offsetTimeOriginal },
    { "modify_date",          exif->ma_modifyDate         },
    { "gps_date_time",        exif->ma_gpsDateTime        },
  };

  jsonbuf_appendFormat(json_buf, R"("metadata":{)");
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    static_IMAGEINSPECTWriteText(texts[i].mp_key, texts[i].mp_text, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
  }

  if (exif->m_hasGpsPosition)
    jsonbuf_appendFormat(json_buf, R"("gps_position":{"latitude":%.6f,"longitude":%.6f},)", exif->m_gpsLatitude, exif->m_gpsLongitude);
  else
    jsonbuf_appendFormat(json_buf, R"("gps_position":null,)");

  if (exif->m_jpegQualityEstimate > 0)
    jsonbuf_appendFormat(json_buf, R"("jpeg_quality_estimate":%d,)", exif->m_jpegQualityEstimate);
  else
    jsonbuf_appendFormat(json_buf, R"("jpeg_quality_estimate":null,)");

  jsonbuf_appendFormat(json_buf, R"("thumbnail_byte_count":%zu,"c2pa_manifest":%s,)", exif->m_thumbnailByteCount, exif->m_hasC2paManifest ? "true" : "false");
  static_IMAGEINSPECTWriteText("c2pa_claim_generator", exif->ma_c2paClaimGenerator, json_buf);
  jsonbuf_appendFormat(json_buf, R"(,"generator_parameters":%s,"identifiers_present":{)", exif->m_hasGeneratorParameters ? "true" : "false");
  
  for (int i = 0; i < EXIFCLIENT_IDENTIFIER_COUNT; i++)
    jsonbuf_appendFormat(json_buf,
                         R"(%s"%s":%s)",
                         i > 0 ? "," : "",
                         IMAGEINSPECT_IDENTIFIER_NAMES[i],
                         exif->ma_isIdentifierPresent[i] ? "true" : "false");

  jsonbuf_appendFormat(json_buf, R"(},"edit_history":[)");
  for (int i = 0; i < exif->m_editHistoryEntryCount && i < EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT; i++)
  {
    const ExifClientHistoryEntry_t* entry = &exif->ma_editHistoryEntries[i];
    jsonbuf_appendFormat(json_buf, "%s{", i > 0 ? "," : "");
    static_IMAGEINSPECTWriteText("action", entry->ma_action, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    static_IMAGEINSPECTWriteText("when", entry->ma_when, json_buf);
    jsonbuf_appendFormat(json_buf, ",");
    static_IMAGEINSPECTWriteText("software_agent", entry->ma_softwareAgent, json_buf);
    jsonbuf_appendFormat(json_buf, "}");
  }
  jsonbuf_appendFormat(json_buf, R"(],"edit_history_has_more":%s})", exif->m_hasMoreEditHistoryEntries ? "true" : "false");
}

static void static_IMAGEINSPECTWriteIndicators(const ImageIndicatorResult_t* indicators, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("indicators":[)");

  bool is_first = true;
  for (int i = 0; i < IMAGEINDICATOR_KIND_COUNT; i++)
  {
    if (!indicators->ma_isIndicatorPresent[i])
      continue;

    ImageIndicatorKind_t kind = (ImageIndicatorKind_t)i;
    jsonbuf_appendFormat(json_buf,
                         R"(%s{"code":"%s","severity":"%s","note":"%s"})",
                         is_first ? "" : ",",
                         imageindicator_kindName(kind),
                         imageindicator_severityName(imageindicator_kindSeverity(kind)),
                         imageindicator_kindNote(kind));
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, R"(],"indicator_note":")" IMAGEINSPECT_INDICATOR_NOTE R"(")");
}

static const char* static_VENDORKEYEDITOutcomeName(VENDORKEYEDITOutcome_t outcome)
{
  switch (outcome)
  {
    case VENDORKEYEDIT_OUTCOME_SAVED:       return "saved";
    case VENDORKEYEDIT_OUTCOME_DELETED:     return "deleted";
    case VENDORKEYEDIT_OUTCOME_REJECTED:    return "rejected";
    case VENDORKEYEDIT_OUTCOME_UNAVAILABLE: return "vendor_unavailable";
    default:                                return "unchanged";
  }
}

static const char* static_VENDORKEYEDITStateName(VENDORKEYEDITState_t state)
{
  switch (state)
  {
    case VENDORKEYEDIT_STATE_WORKING:     return "working";
    case VENDORKEYEDIT_STATE_REJECTED:    return "rejected";
    case VENDORKEYEDIT_STATE_UNAVAILABLE: return "vendor_unavailable";
    default:                              return "not_configured";
  }
}

static void static_VENDORKEYEDITWriteVendorResult(const char* vendor_name, const VENDORKEYEDITVendorResult_t* vendor_result, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, R"("%s":{"result":"%s","configured":%s)",
                       vendor_name, static_VENDORKEYEDITOutcomeName(vendor_result->m_outcome), vendor_result->m_isConfigured ? "true" : "false");
  if (vendor_result->m_retryAfterSeconds > 0)
    jsonbuf_appendFormat(json_buf, R"(,"retry_after_seconds":%u)", vendor_result->m_retryAfterSeconds);
  jsonbuf_appendFormat(json_buf, "}");
}

void serialize_VENDORKEYEDIT_applyResponse(const VENDORKEYEDITApplyResult_t* result, JsonBuf_t* json_buf)
{
  assert(result != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, "{");
  static_VENDORKEYEDITWriteVendorResult("shodan", &result->m_shodan, json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_VENDORKEYEDITWriteVendorResult("abuseipdb", &result->m_abuseIpDb, json_buf);
  if (result->mp_manageUrl != NULL)
  {
    if (result->mp_manageUrl[0] == '\0')
      jsonbuf_appendFormat(json_buf, R"(,"manage_url":null)");
    else
    {
      jsonbuf_appendFormat(json_buf, R"(,"manage_url":")");
      jsonbuf_appendEscaped(json_buf, result->mp_manageUrl);
      jsonbuf_appendFormat(json_buf, R"(")");
    }
  }
  jsonbuf_appendFormat(json_buf, "}\n");
}

void serialize_VENDORKEYEDIT_statusResponse(const VENDORKEYEDITStatusResult_t* result, JsonBuf_t* json_buf)
{
  assert(result != NULL);
  assert(json_buf != NULL);

  jsonbuf_appendFormat(json_buf, R"({"shodan":{"state":"%s"},"abuseipdb":{"state":"%s"},"expires_in_seconds":%lld})" "\n",
                       static_VENDORKEYEDITStateName(result->m_shodanState),
                       static_VENDORKEYEDITStateName(result->m_abuseIpDbState),
                       (long long)result->m_expiresInSeconds);
}
