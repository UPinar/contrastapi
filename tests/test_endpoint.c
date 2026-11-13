#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "unity/unity.h"
#include "endpoint.h"
#include "bulk.h"
#include "cve.h"
#include "billing.h"
#include "validate.h"
#include "endpoint_run.h"
#include "endpoint_weight.h"
#include "ipguard.h"
#include "jsonbuf.h"
#include "watchlist/watchlist.h"
#include "package.h"
#include "ratelimit.h"
#include "tlsprobe.h"
#include "cache.h"
#include "external/rdap.h"
#include "quota.h"
#include "throttle.h"
#include "external/whois.h"
#include "etld.h"
#include "external/wayback.h"
#include "wayback_stub.h"
#include "certspotter_stub.h"
#include "subdomain_stub.h"
#include "header_fetch_stub.h"
#include "header_check.h"
#include "monotonic.h"
#include "dns.h"
#include "usagelog.h"

static const RequestCharge_t TEST_FULL_CHARGE = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = NULL, .mp_x402Payment = NULL };


#define REST_INPUT(path_segment, query, body, body_len) \
  (&(EndpointRestInput_t){ .mp_pathSegment = (path_segment), .mp_query = (query), .m_body = { (const unsigned char*)(body), (body_len) } })

void setUp(void)    {}
void tearDown(void) {}

static bool static_isMethodAllowed(const Endpoint_t* endpoint, const char* method)
{
  for (int i = 0; endpoint->ma_allowedMethods[i] != NULL; i++)
  {
    if (strcmp(endpoint->ma_allowedMethods[i], method) == 0)
      return true;
  }
  return false;
}

static bool static_isTextType(EndpointParamType_t type)
{
  return type == ENDPOINT_PARAM_TYPE_STRING || type == ENDPOINT_PARAM_TYPE_ENUM || type == ENDPOINT_PARAM_TYPE_CVE_ID || type == ENDPOINT_PARAM_TYPE_CWE_ID;
}

void test_http_paths_and_mcp_names_are_unique(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = i + 1; j < endpoint_count; j++)
    {
      TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(endpoints[i].mp_httpPath, endpoints[j].mp_httpPath), endpoints[i].mp_httpPath);
      if (endpoints[i].mp_mcpToolName != NULL && endpoints[j].mp_mcpToolName != NULL)
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(endpoints[i].mp_mcpToolName, endpoints[j].mp_mcpToolName), endpoints[i].mp_mcpToolName);
    }
  }
}

void test_findByHttpPath_returns_each_row_for_its_own_paths(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    char path[64];
    const char* param = "untouched";

    if (!endpoint->m_hasPathSegment)
    {
      TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByHttpPath(endpoint->mp_httpPath, &param), endpoint->mp_httpPath);
      TEST_ASSERT_NULL_MESSAGE(param, endpoint->mp_httpPath);
      TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByHttpPath(endpoint->mp_httpPath, NULL), endpoint->mp_httpPath);
      continue;
    }

    int written = snprintf(path, sizeof(path), "%sX-1", endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(written > 0 && (size_t)written < sizeof(path), endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByHttpPath(path, &param), path);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("X-1", param, path);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByHttpPath(path, NULL), path);

    written = snprintf(path, sizeof(path), "%.*s", (int)(strlen(endpoint->mp_httpPath) - 1), endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(written > 0 && (size_t)written < sizeof(path), endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByHttpPath(path, &param), path);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", param, path);
  }
}

void test_findByHttpPath_unknown_path_is_NULL(void)
{
  const char* param = NULL;
  TEST_ASSERT_NULL(endpoint_findByHttpPath("/no_such_endpoint", &param));
  TEST_ASSERT_NULL(endpoint_findByHttpPath("/cve_exploitX",     &param));
  TEST_ASSERT_NULL(endpoint_findByHttpPath("/",                 &param));
}

void test_findByHttpPath_path_one_byte_off_a_row_is_NULL(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    size_t path_len = strlen(endpoint->mp_httpPath);
    char path[64];
    TEST_ASSERT_TRUE_MESSAGE(path_len + 1 < sizeof(path), endpoint->mp_httpPath);
    memcpy(path, endpoint->mp_httpPath, path_len + 1);

    size_t changed_index = endpoint->m_hasPathSegment ? path_len - 2 : path_len - 1;
    path[changed_index] = (path[changed_index] == 'X') ? 'Y' : 'X';
    TEST_ASSERT_NULL_MESSAGE(endpoint_findByHttpPath(path, NULL), path);

    if (endpoint->m_hasPathSegment)
    {
      path[path_len - 1] = '\0';
      TEST_ASSERT_NULL_MESSAGE(endpoint_findByHttpPath(path, NULL), path);
    }
  }
}

void test_findByMcpName_returns_each_row_for_its_tool(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName != NULL)
      TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint, endpoint_findByMcpName(endpoint->mp_mcpToolName), endpoint->mp_mcpToolName);
  }

  TEST_ASSERT_NULL(endpoint_findByMcpName(""));
  TEST_ASSERT_NULL(endpoint_findByMcpName("no_such_tool"));
  TEST_ASSERT_NULL(endpoint_findByMcpName("cve_lookupx"));
  TEST_ASSERT_NULL(endpoint_findByMcpName("cve_"));
}

void test_every_row_but_the_four_free_rows_costs_at_least_one_credit(void)
{
  static const char* const free_rows[] = { "/health", "/webhook_lemonsqueezy", "/webhook_nowpayments", "/api_key_claim" };
  const int free_row_count = (int)(sizeof(free_rows) / sizeof(free_rows[0]));
  int found_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    bool is_free_row = false;
    for (int k = 0; k < free_row_count; k++)
      is_free_row = is_free_row || strcmp(endpoints[i].mp_httpPath, free_rows[k]) == 0;
    if (is_free_row)
    {
      found_count++;
      TEST_ASSERT_EQUAL_UINT_MESSAGE(0, endpoints[i].m_creditCost, endpoints[i].mp_httpPath);
    }
    else
      TEST_ASSERT_TRUE_MESSAGE(endpoints[i].m_creditCost >= 1, endpoints[i].mp_httpPath);
  }
  TEST_ASSERT_EQUAL_INT(free_row_count, found_count);
}

void test_only_the_mcp_row_carries_mcp(void)
{
  int transport_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_isMcpEndpoint)
      continue;
    transport_count++;
    TEST_ASSERT_EQUAL_STRING("/mcp", endpoint->mp_httpPath);
    TEST_ASSERT_NULL_MESSAGE(endpoint->mp_mcpToolName, endpoint->mp_httpPath);
  }
  TEST_ASSERT_EQUAL_INT(1, transport_count);
}

void test_only_the_credit_budget_rows_read_the_credit_budget(void)
{
  static const char* const flagged_paths[] = { "/privacy_my_data", "/watchlist_edit", "/watchlist_events", "/vendor_key_edit", "/ip_lookup/" };
  bool seen[5] = { false, false, false, false, false };
  int credit_budget_row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_readsCreditBudget)
      continue;
    credit_budget_row_count++;
    int flagged_index = -1;
    for (int k = 0; k < 5; k++)
    {
      if (strcmp(flagged_paths[k], endpoint->mp_httpPath) == 0)
        flagged_index = k;
    }
    TEST_ASSERT_TRUE_MESSAGE(flagged_index >= 0, endpoint->mp_httpPath);
    seen[flagged_index] = true;
    TEST_ASSERT_NOT_NULL_MESSAGE(endpoint->mp_mcpToolName, endpoint->mp_httpPath);
    TEST_ASSERT_FALSE_MESSAGE(endpoint->m_isMcpEndpoint, endpoint->mp_httpPath);
    for (int j = 0; j < endpoint->m_paramCount; j++)
      TEST_ASSERT_TRUE_MESSAGE(endpoint->mp_params[j].m_offset >= sizeof(const RequestCreditBudget_t*), endpoint->mp_httpPath);
    if (flagged_index == 0)
    {
      TEST_ASSERT_EQUAL_STRING("GET", endpoint->ma_allowedMethods[0]);
      TEST_ASSERT_NULL(endpoint->ma_allowedMethods[1]);
      TEST_ASSERT_EQUAL_size_t(0, endpoint->m_paramsSize);
      TEST_ASSERT_EQUAL_INT(0, endpoint->m_paramCount);
      TEST_ASSERT_EQUAL_STRING("privacy_my_data", endpoint->mp_mcpToolName);
    }
    else
    {
      TEST_ASSERT_TRUE_MESSAGE(endpoint->m_isDbRequired, endpoint->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(endpoint->m_paramCount > 0, endpoint->mp_httpPath);
    }
  }
  TEST_ASSERT_EQUAL_INT(5, credit_budget_row_count);
  TEST_ASSERT_TRUE(seen[0] && seen[1] && seen[2] && seen[3] && seen[4]);
}

void test_only_the_listed_paid_rows_are_payable(void)
{
  static const char* const payable_paths[33] = {
    "/cve_lookup/",         "/cve_lookup_bulk",    "/cve_products/",      "/cve_search",
    "/cve_leading",         "/kev_lookup/",        "/cwe_lookup/",        "/cve_risk_score/",
    "/cve_exploit/",        "/cve_triage",         "/cve_triage_bulk",    "/product_exposure",
    "/cpe_search",          "/cvss_calculator",    "/password_check/",    "/dns_lookup/",
    "/dns_takeover_check/", "/email_auth_check/",  "/email_address_check/", "/ssl_check/",
    "/headers_check/",      "/whois_lookup/",      "/wayback_lookup/",    "/cert_search/",
    "/subdomain_enum/",     "/ip_lookup/",         "/asn_lookup/",        "/d3fend_for_attack/",
    "/driver_lookup/",      "/driver_lookup_bulk", "/package_check",      "/package_check_bulk",
    "/image_inspect",
  };
  bool seen[33] = { false };
  int payable_row_count = 0;
  int credit_budget_payable_row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_isPayable)
      continue;
    payable_row_count++;
    int payable_index = -1;
    for (int k = 0; k < 33; k++)
    {
      TEST_ASSERT_NOT_NULL(payable_paths[k]);
      if (strcmp(payable_paths[k], endpoint->mp_httpPath) == 0)
        payable_index = k;
    }
    TEST_ASSERT_TRUE_MESSAGE(payable_index >= 0, endpoint->mp_httpPath);
    seen[payable_index] = true;
    TEST_ASSERT_TRUE_MESSAGE(endpoint->m_creditCost >= 1, endpoint->mp_httpPath);
    TEST_ASSERT_FALSE_MESSAGE(endpoint->m_isMcpEndpoint, endpoint->mp_httpPath);
    if (endpoint->m_readsCreditBudget)
    {
      TEST_ASSERT_EQUAL_STRING("/ip_lookup/", endpoint->mp_httpPath);
      credit_budget_payable_row_count++;
    }
  }
  TEST_ASSERT_EQUAL_INT(33, payable_row_count);
  for (int k = 0; k < 33; k++)
    TEST_ASSERT_TRUE_MESSAGE(seen[k], payable_paths[k]);
  TEST_ASSERT_EQUAL_INT(1, credit_budget_payable_row_count);
}

void test_path_segment_rows_end_in_a_slash(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_hasPathSegment)
      continue;
    size_t path_len = strlen(endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(path_len > 1, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_CHAR_MESSAGE('/', endpoint->mp_httpPath[path_len - 1], endpoint->mp_httpPath);
  }
}

void test_only_path_segment_rows_bind_a_path_segment_param(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    int path_segment_count = 0;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        path_segment_count++;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(endpoint->m_hasPathSegment ? 1 : 0, path_segment_count, endpoint->mp_httpPath);
  }
}

void test_every_parameter_carries_the_fields_its_type_needs(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParamSpec_t* spec = endpoints[i].mp_params[j].mp_spec;
      TEST_ASSERT_NOT_NULL_MESSAGE(spec, endpoints[i].mp_httpPath);
      EndpointParamType_t type = spec->m_type;

      TEST_ASSERT_EQUAL_INT_MESSAGE(type == ENDPOINT_PARAM_TYPE_ENUM, spec->mp_enumValues != NULL, spec->mp_name);

      if (type == ENDPOINT_PARAM_TYPE_INT || type == ENDPOINT_PARAM_TYPE_DOUBLE || endpoint_isBulkArrayType(type))
        TEST_ASSERT_TRUE_MESSAGE(spec->m_min <= spec->m_max, spec->mp_name);
      else
        TEST_ASSERT_TRUE_MESSAGE(spec->m_min == 0.0 && spec->m_max == 0.0, spec->mp_name);

      if (static_isTextType(type) || endpoint_isIdArrayType(type) || type == ENDPOINT_PARAM_TYPE_BYTES)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_maxLen > 0, spec->mp_name);
      else
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, spec->m_maxLen, spec->mp_name);

      if (spec->m_isOnlyTrueAccepted)
        TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_PARAM_TYPE_BOOL, type, spec->mp_name);

      if (type == ENDPOINT_PARAM_TYPE_CVE_ID || type == ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_validatorFunction == validate_cveId, spec->mp_name);
      else if (type == ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_validatorFunction == validate_fileHashHex, spec->mp_name);
      else if (type == ENDPOINT_PARAM_TYPE_CWE_ID)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_validatorFunction == validate_cweId, spec->mp_name);
      else if (type != ENDPOINT_PARAM_TYPE_STRING)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_validatorFunction == NULL, spec->mp_name);
    }
  }
}

void test_a_row_that_reads_a_body_takes_post_alone(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    bool reads_body = endpoint->m_isMcpEndpoint;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & (ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_REST_RAW_BODY))
        reads_body = true;
    }

    if (reads_body)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("POST", endpoint->ma_allowedMethods[0], endpoint->mp_httpPath);
      TEST_ASSERT_NULL_MESSAGE(endpoint->ma_allowedMethods[1], endpoint->mp_httpPath);
    }
    else if (strcmp(endpoint->mp_httpPath, "/crypto_checkout") == 0)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("POST", endpoint->ma_allowedMethods[0], endpoint->mp_httpPath);
      TEST_ASSERT_NULL_MESSAGE(endpoint->ma_allowedMethods[1], endpoint->mp_httpPath);
    }
    else
      TEST_ASSERT_FALSE_MESSAGE(static_isMethodAllowed(endpoint, "POST"), endpoint->mp_httpPath);
  }
}

void test_every_parameter_is_read_from_a_place_its_row_serves(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      const char* name = param->mp_spec->mp_name;

      TEST_ASSERT_NOT_EQUAL_MESSAGE(0, param->m_sources, name);
      if (param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG)
        TEST_ASSERT_NOT_NULL_MESSAGE(endpoint->mp_mcpToolName, name);
      if (param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY)
        TEST_ASSERT_TRUE_MESSAGE(static_isMethodAllowed(endpoint, "POST"), name);
      if (param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY)
        TEST_ASSERT_TRUE_MESSAGE(static_isMethodAllowed(endpoint, "GET"), name);
      if (param->mp_mcpArgDescription != NULL)
        TEST_ASSERT_TRUE_MESSAGE(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG, name);

      for (int k = j + 1; k < endpoint->m_paramCount; k++)
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(name, endpoint->mp_params[k].mp_spec->mp_name), name);
    }
  }
}

void test_mcp_fields_come_with_a_tool(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    bool has_tool = endpoint->mp_mcpToolName != NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(has_tool, endpoint->mp_mcpToolDescription != NULL, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(has_tool, endpoint->mp_mcpToolTitle != NULL && endpoint->mp_mcpToolTitle[0] != '\0', endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(has_tool, endpoint->m_mcpToolCategory != ENDPOINT_MCP_TOOL_CATEGORY_NONE, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(has_tool, endpoint->m_mcpToolEffect != ENDPOINT_MCP_TOOL_EFFECT_NONE, endpoint->mp_httpPath);
    if (!has_tool)
      TEST_ASSERT_NULL_MESSAGE(endpoint->mp_mcpToolTitle, endpoint->mp_httpPath);
  }
}

void test_mcp_tool_titles_are_unique(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const char* title = endpoints[i].mp_mcpToolTitle;
    if (title == NULL)
      continue;
    size_t title_len = strlen(title);
    TEST_ASSERT_TRUE_MESSAGE(title_len > 0 && !isspace((unsigned char)title[0]) && !isspace((unsigned char)title[title_len - 1]), title);
    for (int j = i + 1; j < endpoint_count; j++)
    {
      if (endpoints[j].mp_mcpToolTitle == NULL)
        continue;
      TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcasecmp(title, endpoints[j].mp_mcpToolTitle), title);
    }
  }
}

void test_mcp_tool_category_names_are_the_home_page_titles(void)
{
  TEST_ASSERT_NULL(endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_NONE));
  TEST_ASSERT_EQUAL_STRING("CVE Intelligence",               endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_CVE));
  TEST_ASSERT_EQUAL_STRING("Package Vulnerabilities (SBOM)", endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_PACKAGE));
  TEST_ASSERT_EQUAL_STRING("Credential Checks",              endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_CREDENTIAL));
  TEST_ASSERT_EQUAL_STRING("Domain Intelligence",            endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN));
  TEST_ASSERT_EQUAL_STRING("IP Intelligence",                endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_IP));
  TEST_ASSERT_EQUAL_STRING("Threat Defense",                 endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE));
  TEST_ASSERT_EQUAL_STRING("Monitoring",                     endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_MONITORING));
  TEST_ASSERT_EQUAL_STRING("Operations",                     endpoint_mcpToolCategoryName(ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS));
}

void test_only_record_lookups_carry_a_not_found_message(void)
{
  static const struct {
    const char* mp_path;
    const char* mp_message;
  } expected[] = {
    { "/cve_lookup/",     "CVE not found" },
    { "/cve_products/",   "CVE not found" },
    { "/kev_lookup/",     "KEV entry not found" },
    { "/cwe_lookup/",     "CWE not found" },
    { "/cve_risk_score/", "CVE not found" },
    { "/dns_lookup/",     "domain does not exist" },
    { "/dns_takeover_check/", "hostname does not exist" },
    { "/email_auth_check/",   "domain does not exist" },
    { "/ssl_check/",          "hostname does not exist" },
    { "/whois_lookup/",       "domain is not registered" },
    { "/asn_lookup/",         "AS not found" },
    { "/api_key_claim",       "no paid order has this order_id yet" },
  };
  const int expected_count = (int)(sizeof(expected) / sizeof(expected[0]));

  int matched = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    const char* message = NULL;
    for (int k = 0; k < expected_count; k++)
      if (strcmp(endpoint->mp_httpPath, expected[k].mp_path) == 0)
        message = expected[k].mp_message;

    if (message == NULL)
    {
      TEST_ASSERT_NULL_MESSAGE(endpoint->mp_notFoundMessage, endpoint->mp_httpPath);
      continue;
    }
    TEST_ASSERT_EQUAL_STRING_MESSAGE(message, endpoint->mp_notFoundMessage, endpoint->mp_httpPath);
    matched++;
  }
  TEST_ASSERT_EQUAL_INT(expected_count, matched);
}

void test_record_lookup_runs_serve_only_rows_with_a_message(void)
{
  static const EndpointRunFunction_t not_found_runs[] = {
    endpoint_CVELOOKUPRun, endpoint_CVEPRODUCTSRun, endpoint_KEVLOOKUPRun, endpoint_CWELOOKUPRun,
    endpoint_CVERISKSCORERun, endpoint_DNSLOOKUPRun, endpoint_DNSTAKEOVERCHECKRun, endpoint_EMAILAUTHCHECKRun,
    endpoint_SSLCHECKRun, endpoint_WHOISLOOKUPRun,
    endpoint_ASNLOOKUPRun,
  };
  const int run_count = (int)(sizeof(not_found_runs) / sizeof(not_found_runs[0]));

  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    for (int k = 0; k < run_count; k++)
      if (endpoint->m_runFunction == not_found_runs[k])
        TEST_ASSERT_NOT_NULL_MESSAGE(endpoint->mp_notFoundMessage, endpoint->mp_httpPath);
  }
}

void test_each_row_holds_its_run_its_db_need_its_upstream_call_and_its_ceiling(void)
{
  static const struct {
    const char*           mp_path;
    EndpointRunFunction_t m_runFunction;
    bool                  m_isDbRequired;
    bool                  m_callsUpstream;
    size_t                m_jsonCeiling;
  } expected[] = {
    { "/health",           endpoint_HEALTHRun,          false, false, JSONBUF_DEFAULT_CEILING },
    { "/cve_lookup/",      endpoint_CVELOOKUPRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_lookup_bulk",  endpoint_CVELOOKUPBULKRun,   true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_products/",    endpoint_CVEPRODUCTSRun,     true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_search",       endpoint_CVESEARCHRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_leading",      endpoint_CVELEADINGRun,      true,  false, JSONBUF_DEFAULT_CEILING },
    { "/kev_lookup/",      endpoint_KEVLOOKUPRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cwe_lookup/",      endpoint_CWELOOKUPRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_risk_score/",  endpoint_CVERISKSCORERun,    true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_exploit/",     endpoint_CVEEXPLOITRun,      true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_triage",       endpoint_CVETRIAGERun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cve_triage_bulk",  endpoint_CVETRIAGEBULKRun,   true,  false, JSONBUF_DEFAULT_CEILING },
    { "/product_exposure", endpoint_PRODUCTEXPOSURERun, true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cpe_search",       endpoint_CPESEARCHRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/cvss_calculator",  endpoint_CVSSCALCULATORRun,  false, false, JSONBUF_DEFAULT_CEILING },
    { "/watchlist_edit",   endpoint_WATCHLISTEDITRun,   true,  false, JSONBUF_DEFAULT_CEILING },
    { "/watchlist_events", endpoint_WATCHLISTEVENTSRun, true,  false, JSONBUF_DEFAULT_CEILING },
    { "/privacy_my_data",  endpoint_PRIVACYMYDATARun,   false, false, JSONBUF_DEFAULT_CEILING },
    { "/vendor_key_edit",  endpoint_VENDORKEYEDITRun,   true,  false, JSONBUF_DEFAULT_CEILING },
    { "/password_check/",  endpoint_PASSWORDCHECKRun,   true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/dns_lookup/",      endpoint_DNSLOOKUPRun,       false, true,  JSONBUF_DEFAULT_CEILING },
    { "/dns_takeover_check/",  endpoint_DNSTAKEOVERCHECKRun,   false, true,  JSONBUF_DEFAULT_CEILING },
    { "/email_auth_check/",    endpoint_EMAILAUTHCHECKRun,     false, true,  JSONBUF_DEFAULT_CEILING },
    { "/email_address_check/", endpoint_EMAILADDRESSCHECKRun,  true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/ssl_check/",           endpoint_SSLCHECKRun,           false, true,  JSONBUF_DEFAULT_CEILING },
    { "/headers_check/",       endpoint_HEADERSCHECKRun,       false, true,  JSONBUF_DEFAULT_CEILING },
    { "/whois_lookup/",        endpoint_WHOISLOOKUPRun,        true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/wayback_lookup/",      endpoint_WAYBACKLOOKUPRun,      true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/cert_search/",         endpoint_CERTSEARCHRun,         true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/subdomain_enum/",      endpoint_SUBDOMAINENUMRun,      true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/ip_lookup/",           endpoint_IPLOOKUPRun,           true,  true,  JSONBUF_DEFAULT_CEILING },
    { "/asn_lookup/",          endpoint_ASNLOOKUPRun,          true,  false, JSONBUF_DEFAULT_CEILING },
    { "/d3fend_for_attack/",   endpoint_D3FENDFORATTACKRun,    true,  false, JSONBUF_DEFAULT_CEILING },
    { "/driver_lookup/",       endpoint_DRIVERLOOKUPRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/driver_lookup_bulk",   endpoint_DRIVERLOOKUPBULKRun,   true,  false, JSONBUF_MAX_CEILING },
    { "/package_check",        endpoint_PACKAGECHECKRun,       true,  false, JSONBUF_DEFAULT_CEILING },
    { "/package_check_bulk",   endpoint_PACKAGECHECKBULKRun,   true,  false, JSONBUF_DEFAULT_CEILING },
    { "/image_inspect",    endpoint_IMAGEINSPECTRun,    false, false, JSONBUF_DEFAULT_CEILING },
    { "/webhook_lemonsqueezy", endpoint_WEBHOOKLEMONSQUEEZYRun, true, false, JSONBUF_DEFAULT_CEILING },
    { "/webhook_nowpayments",  endpoint_WEBHOOKNOWPAYMENTSRun,  true, false, JSONBUF_DEFAULT_CEILING },
    { "/api_key_claim",        endpoint_APIKEYCLAIMRun,         true, false, JSONBUF_DEFAULT_CEILING },
    { "/crypto_checkout",      endpoint_CRYPTOCHECKOUTRun,      false, true, JSONBUF_DEFAULT_CEILING },
    { "/mcp",              NULL,                        false, false, 0 },
  };
  const int expected_count = (int)(sizeof(expected) / sizeof(expected[0]));

  int matched = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    int k = 0;
    while (k < expected_count && strcmp(endpoint->mp_httpPath, expected[k].mp_path) != 0)
      k++;
    TEST_ASSERT_TRUE_MESSAGE(k < expected_count, endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(endpoint->m_runFunction == expected[k].m_runFunction, endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(endpoint->m_isDbRequired == expected[k].m_isDbRequired, endpoint->mp_httpPath);
    TEST_ASSERT_TRUE_MESSAGE(endpoint->m_callsUpstream == expected[k].m_callsUpstream, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(expected[k].m_jsonCeiling, endpoint->m_jsonCeiling, endpoint->mp_httpPath);
    matched++;
  }
  TEST_ASSERT_EQUAL_INT(expected_count, matched);
}

static size_t static_paramsFieldSize(const EndpointParamSpec_t* spec)
{
  switch (spec->m_type)
  {
    case ENDPOINT_PARAM_TYPE_STRING:
    case ENDPOINT_PARAM_TYPE_ENUM:
    case ENDPOINT_PARAM_TYPE_CVE_ID:
    case ENDPOINT_PARAM_TYPE_CWE_ID:
      return spec->m_maxLen + 1;
    case ENDPOINT_PARAM_TYPE_INT:
      return sizeof(int);
    case ENDPOINT_PARAM_TYPE_DOUBLE:
      return sizeof(double);
    case ENDPOINT_PARAM_TYPE_BOOL:
      return sizeof(bool);
    case ENDPOINT_PARAM_TYPE_KEV_FILTER:
      return sizeof(CveKevFilter_t);
    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
      return sizeof(BulkIdsParams_t);
    case ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY:
      return sizeof(PACKAGECHECKBULKParams_t);
    case ENDPOINT_PARAM_TYPE_BYTES:
      return sizeof(EndpointByteSpan_t);
  }
  return 0;
}

static bool static_isWrittenToParams(const EndpointParam_t* param)
{
  return (param->m_sources & (ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_REST_RAW_BODY | ENDPOINT_PARAM_SRC_REST_HEADER | ENDPOINT_PARAM_SRC_MCP_ARG)) != 0;
}

void test_params_write_inside_their_params_struct(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    bool writes_value = false;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      const EndpointParamSpec_t* spec = param->mp_spec;
      if (!static_isWrittenToParams(param))
      {
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, param->m_offset, spec->mp_name);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, param->m_size, spec->mp_name);
        continue;
      }
      writes_value = true;

      TEST_ASSERT_EQUAL_size_t_MESSAGE(static_paramsFieldSize(spec), param->m_size, spec->mp_name);
      TEST_ASSERT_TRUE_MESSAGE(param->m_offset + param->m_size <= endpoint->m_paramsSize, spec->mp_name);

      for (int k = j + 1; k < endpoint->m_paramCount; k++)
      {
        const EndpointParam_t* other = &endpoint->mp_params[k];
        if (!static_isWrittenToParams(other))
          continue;
        bool is_apart = param->m_offset + param->m_size <= other->m_offset || other->m_offset + other->m_size <= param->m_offset;
        TEST_ASSERT_TRUE_MESSAGE(is_apart, spec->mp_name);
      }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(writes_value, endpoint->m_paramsSize > 0, endpoint->mp_httpPath);
  }
}

void test_every_row_fits_the_params_union(void)
{
  for (int i = 0; i < endpoint_count; i++)
    TEST_ASSERT_TRUE_MESSAGE(endpoints[i].m_paramsSize <= sizeof(EndpointAnyParams_t), endpoints[i].mp_httpPath);
}

void test_mcp_tool_description_ends_with_a_price_other_than_one(void)
{
  int priced_count = 0;
  int plain_count  = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName == NULL)
      continue;
    const char* description = endpoint->mp_mcpToolDescription;
    TEST_ASSERT_NOT_NULL_MESSAGE(description, endpoint->mp_mcpToolName);
    const char* price_hit = strstr(description, "Costs ");
    TEST_ASSERT_NULL_MESSAGE(strstr(description, "costs "), endpoint->mp_mcpToolName);
    if (endpoint->m_costRule != ENDPOINT_COST_FLAT || endpoint->m_creditCost == 1)
    {
      TEST_ASSERT_NULL_MESSAGE(price_hit, endpoint->mp_mcpToolName);
      plain_count++;
      continue;
    }

    char sentence[32];
    int written = 0;
    if (endpoint->m_creditCost == 0)
      written = snprintf(sentence, sizeof(sentence), " Costs no credits.");
    else
      written = snprintf(sentence, sizeof(sentence), " Costs %u credits.", endpoint->m_creditCost);
    TEST_ASSERT_TRUE_MESSAGE(written > 0 && (size_t)written < sizeof(sentence), endpoint->mp_mcpToolName);
    size_t description_len = strlen(description);
    size_t sentence_len    = (size_t)written;
    TEST_ASSERT_TRUE_MESSAGE(description_len > sentence_len, endpoint->mp_mcpToolName);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(sentence, description + description_len - sentence_len, endpoint->mp_mcpToolName);
    TEST_ASSERT_TRUE_MESSAGE(price_hit == description + description_len - sentence_len + 1, endpoint->mp_mcpToolName);
    priced_count++;
  }
  TEST_ASSERT_TRUE(priced_count > 0);
  TEST_ASSERT_TRUE(plain_count > 0);
}

void test_price_is_flat_or_counts_the_ids_of_an_accepted_read(void)
{
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  const Endpoint_t* bulk   = endpoint_findByMcpName("cve_lookup_bulk");
  TEST_ASSERT_NOT_NULL(lookup);
  TEST_ASSERT_NOT_NULL(bulk);
  EndpointAnyParams_t params;

  memset(&params, 0, sizeof(params));
  params.m_cveLookup.m_isGhsaIncluded = true;
  TEST_ASSERT_EQUAL_UINT(1, endpoint_price(lookup, ENDPOINT_GATE_OK, &params, lookup->m_paramsSize));
  TEST_ASSERT_EQUAL_UINT(1, endpoint_price(lookup, ENDPOINT_GATE_REJECT_VALUE, &params, lookup->m_paramsSize));

  memset(&params, 0, sizeof(params));
  params.m_bulkIds.m_idCount     = 2;
  params.m_bulkIds.m_skippedIdCount = 1;
  TEST_ASSERT_EQUAL_UINT(2, endpoint_price(bulk, ENDPOINT_GATE_OK, &params, bulk->m_paramsSize));
  TEST_ASSERT_EQUAL_UINT(1, endpoint_price(bulk, ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY, &params, bulk->m_paramsSize));

  params.m_bulkIds.m_idCount     = 0;
  params.m_bulkIds.m_skippedIdCount = 3;
  TEST_ASSERT_EQUAL_UINT(1, endpoint_price(bulk, ENDPOINT_GATE_OK, &params, bulk->m_paramsSize));

  params.m_bulkIds.m_idCount = CVELOOKUPBULK_MAX_IDS;
  TEST_ASSERT_EQUAL_UINT(CVELOOKUPBULK_MAX_IDS, endpoint_price(bulk, ENDPOINT_GATE_OK, &params, bulk->m_paramsSize));

  Endpoint_t priced_row   = *bulk;
  priced_row.m_creditCost = 4;
  params.m_bulkIds.m_idCount = 2;
  TEST_ASSERT_EQUAL_UINT(4, endpoint_price(&priced_row, ENDPOINT_GATE_OK, &params, priced_row.m_paramsSize));
}

void test_isPartialChargeAllowed_only_on_the_bulk_rows(void)
{
  const Endpoint_t* lookup  = endpoint_findByMcpName("cve_lookup");
  const Endpoint_t* exploit = endpoint_findByMcpName("cve_exploit");
  const Endpoint_t* bulk    = endpoint_findByMcpName("cve_lookup_bulk");
  const Endpoint_t* triage  = endpoint_findByMcpName("cve_triage_bulk");
  const Endpoint_t* driver  = endpoint_findByMcpName("driver_lookup_bulk");
  TEST_ASSERT_NOT_NULL(lookup);
  TEST_ASSERT_NOT_NULL(exploit);
  TEST_ASSERT_NOT_NULL(bulk);
  TEST_ASSERT_NOT_NULL(triage);
  TEST_ASSERT_NOT_NULL(driver);

  TEST_ASSERT_FALSE(endpoint_isPartialChargeAllowed(lookup));
  TEST_ASSERT_FALSE(endpoint_isPartialChargeAllowed(exploit));
  TEST_ASSERT_TRUE(endpoint_isPartialChargeAllowed(bulk));
  TEST_ASSERT_TRUE(endpoint_isPartialChargeAllowed(triage));
  TEST_ASSERT_TRUE(endpoint_isPartialChargeAllowed(driver));
}

void test_every_bulk_ids_row_costs_one_credit(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].m_costRule == ENDPOINT_COST_BULK_IDS)
      TEST_ASSERT_EQUAL_UINT_MESSAGE(1, endpoints[i].m_creditCost, endpoints[i].mp_httpPath);
  }
}

static void static_fillFiveIds(BulkIdsParams_t* ids)
{
  memset(ids, 0, sizeof(*ids));
  for (int i = 0; i < 5; i++)
    snprintf(ids->ma_ids[i], sizeof(ids->ma_ids[i]), "CVE-2023-%04d", i + 1);
  ids->m_idCount = 5;
}

void test_limitWorkToCharge_cuts_bulk_ids_to_the_charge(void)
{
  const Endpoint_t* bulk = endpoint_findByMcpName("cve_lookup_bulk");
  TEST_ASSERT_NOT_NULL(bulk);
  EndpointAnyParams_t params;

  static_fillFiveIds(&params.m_bulkIds);
  endpoint_limitWorkToCharge(bulk, &params, ENDPOINT_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(5, params.m_bulkIds.m_idCount);
  TEST_ASSERT_EQUAL_INT(0, params.m_bulkIds.m_notProcessedIdCount);

  static_fillFiveIds(&params.m_bulkIds);
  endpoint_limitWorkToCharge(bulk, &params, 2);
  TEST_ASSERT_EQUAL_INT(2, params.m_bulkIds.m_idCount);
  TEST_ASSERT_EQUAL_INT(3, params.m_bulkIds.m_notProcessedIdCount);
  TEST_ASSERT_EQUAL_UINT(2, endpoint_price(bulk, ENDPOINT_GATE_OK, &params, bulk->m_paramsSize));
  TEST_ASSERT_EQUAL_STRING("CVE-2023-0003", params.m_bulkIds.ma_ids[2]);

  static_fillFiveIds(&params.m_bulkIds);
  endpoint_limitWorkToCharge(bulk, &params, 0);
  TEST_ASSERT_EQUAL_INT(0, params.m_bulkIds.m_idCount);
  TEST_ASSERT_EQUAL_INT(5, params.m_bulkIds.m_notProcessedIdCount);

  for (unsigned int charge = 5; charge <= 6; charge++)
  {
    static_fillFiveIds(&params.m_bulkIds);
    endpoint_limitWorkToCharge(bulk, &params, charge);
    TEST_ASSERT_EQUAL_INT(5, params.m_bulkIds.m_idCount);
    TEST_ASSERT_EQUAL_INT(0, params.m_bulkIds.m_notProcessedIdCount);
  }
}

void test_limitWorkToCharge_cuts_bulk_hashes_to_the_charge(void)
{
  const Endpoint_t* driver = endpoint_findByMcpName("driver_lookup_bulk");
  TEST_ASSERT_NOT_NULL(driver);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  for (int i = 0; i < 5; i++)
    snprintf(params.m_bulkIds.ma_ids[i], sizeof(params.m_bulkIds.ma_ids[i]), "%064d", i + 1);
  params.m_bulkIds.m_idCount = 5;

  TEST_ASSERT_EQUAL_UINT(5, endpoint_price(driver, ENDPOINT_GATE_OK, &params, driver->m_paramsSize));

  endpoint_limitWorkToCharge(driver, &params, 2);
  TEST_ASSERT_EQUAL_INT(2, params.m_bulkIds.m_idCount);
  TEST_ASSERT_EQUAL_INT(3, params.m_bulkIds.m_notProcessedIdCount);
  TEST_ASSERT_EQUAL_UINT(2, endpoint_price(driver, ENDPOINT_GATE_OK, &params, driver->m_paramsSize));
}

void test_only_package_check_bulk_has_a_weigh_function(void)
{
  int weighed_row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].m_weighFunction == NULL)
      continue;
    weighed_row_count++;
    TEST_ASSERT_EQUAL_STRING("/package_check_bulk", endpoints[i].mp_httpPath);
    TEST_ASSERT_TRUE(endpoints[i].m_weighFunction == endpoint_PACKAGECHECKBULKWeigh);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_BULK_IDS, endpoints[i].m_costRule);
  }
  TEST_ASSERT_EQUAL_INT(1, weighed_row_count);
}

static int                 g_weighCallCount   = 0;
static int                 g_weighLastWeighed = 0;
static int                 g_weighAnswer      = 0;
static EndpointRunStatus_t g_weighStatus      = ENDPOINT_RUN_OK;

static EndpointRunStatus_t static_fakeWeigh(PGconn* conn, const EndpointAnyParams_t* params, int weighed_item_count, int* served_item_count_out)
{
  (void)conn;
  (void)params;
  g_weighCallCount++;
  g_weighLastWeighed = weighed_item_count;
  if (g_weighStatus == ENDPOINT_RUN_OK)
    *served_item_count_out = g_weighAnswer;
  return g_weighStatus;
}

static void static_resetWeighedPackages(EndpointAnyParams_t* params)
{
  memset(params, 0, sizeof(*params));
  params->m_packageCheckBulk.m_itemCount        = 5;
  params->m_packageCheckBulk.m_skippedItemCount = 2;
  g_weighCallCount   = 0;
  g_weighLastWeighed = 0;
  g_weighAnswer      = 3;
  g_weighStatus      = ENDPOINT_RUN_OK;
}

void test_limitWorkToWeight_cuts_to_the_served_count(void)
{
  Endpoint_t row = *endpoint_findByMcpName("package_check_bulk");
  row.m_weighFunction = static_fakeWeigh;
  EndpointAnyParams_t params;

  static_resetWeighedPackages(&params);
  TEST_ASSERT_EQUAL_UINT(5, endpoint_price(&row, ENDPOINT_GATE_OK, &params, row.m_paramsSize));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, endpoint_limitWorkToWeight(&row, NULL, &params, 4));
  TEST_ASSERT_EQUAL_INT(1, g_weighCallCount);
  TEST_ASSERT_EQUAL_INT(4, g_weighLastWeighed);
  TEST_ASSERT_EQUAL_INT(3, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(2, params.m_packageCheckBulk.m_notProcessedItemCount);
  TEST_ASSERT_EQUAL_INT(2, params.m_packageCheckBulk.m_skippedItemCount);
  TEST_ASSERT_EQUAL_UINT(3, endpoint_price(&row, ENDPOINT_GATE_OK, &params, row.m_paramsSize));

  static_resetWeighedPackages(&params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, endpoint_limitWorkToWeight(&row, NULL, &params, UINT_MAX));
  TEST_ASSERT_EQUAL_INT(5, g_weighLastWeighed);
  TEST_ASSERT_EQUAL_INT(3, params.m_packageCheckBulk.m_itemCount);

  static_resetWeighedPackages(&params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, endpoint_limitWorkToWeight(&row, NULL, &params, 1));
  TEST_ASSERT_EQUAL_INT(0, g_weighCallCount);
  TEST_ASSERT_EQUAL_INT(1, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(4, params.m_packageCheckBulk.m_notProcessedItemCount);

  static_resetWeighedPackages(&params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, endpoint_limitWorkToWeight(&row, NULL, &params, 0));
  TEST_ASSERT_EQUAL_INT(0, g_weighCallCount);
  TEST_ASSERT_EQUAL_INT(0, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_UINT(1, endpoint_price(&row, ENDPOINT_GATE_OK, &params, row.m_paramsSize));

  static_resetWeighedPackages(&params);
  g_weighStatus = ENDPOINT_RUN_DB_ERROR;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, endpoint_limitWorkToWeight(&row, NULL, &params, 4));
  TEST_ASSERT_EQUAL_INT(5, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(0, params.m_packageCheckBulk.m_notProcessedItemCount);
}

void test_limitWorkToWeight_weighs_two_packages(void)
{
  Endpoint_t row = *endpoint_findByMcpName("package_check_bulk");
  row.m_weighFunction = static_fakeWeigh;
  EndpointAnyParams_t params;
  static_resetWeighedPackages(&params);
  params.m_packageCheckBulk.m_itemCount = 2;
  g_weighAnswer = 1;

  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, endpoint_limitWorkToWeight(&row, NULL, &params, 3));
  TEST_ASSERT_EQUAL_INT(1, g_weighCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_weighLastWeighed);
  TEST_ASSERT_EQUAL_INT(1, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(1, params.m_packageCheckBulk.m_notProcessedItemCount);
}

void test_bulk_rows_write_their_ids_where_runRow_reads_them(void)
{
  int bulk_rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->m_costRule != ENDPOINT_COST_BULK_IDS)
      continue;
    bulk_rows++;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint_isBulkArrayType(endpoint->mp_params[j].mp_spec->m_type))
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, endpoint->mp_params[j].m_offset, endpoint->mp_httpPath);
    }
  }
  TEST_ASSERT_TRUE(bulk_rows > 0);
}

void test_runRow_finishes_a_body_only_on_ok_and_degraded(void)
{
  const Endpoint_t* cvss   = endpoint_findByMcpName("cvss_calculator");
  const Endpoint_t* health = endpoint_findByMcpName("health");
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(cvss);
  TEST_ASSERT_NOT_NULL(health);
  TEST_ASSERT_NOT_NULL(lookup);
  EndpointAnyParams_t params;

  const char* full_args = "{\"vector\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}";
  JsonReadSpan_t full_span = { full_args, strlen(full_args) };
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(cvss, full_span, &params, cvss->m_paramsSize).m_status);
  EndpointRunResult_t run_result = endpoint_runRow(cvss, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  TEST_ASSERT_NOT_NULL(strstr(run_result.mp_body, "\"base_score\":9.8,"));
  free(run_result.mp_body);

  const char* short_args = "{\"vector\":\"CVSS:3.1/AV:N\"}";
  JsonReadSpan_t short_span = { short_args, strlen(short_args) };
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(cvss, short_span, &params, cvss->m_paramsSize).m_status);
  run_result = endpoint_runRow(cvss, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_message);
  TEST_ASSERT_NULL(run_result.mp_body);

  memset(&params, 0, sizeof(params));
  run_result = endpoint_runRow(health, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DEGRADED, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  free(run_result.mp_body);

  memset(&params, 0, sizeof(params));
  run_result = endpoint_runRow(lookup, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);
}

void test_runRow_cuts_only_a_bulk_row_before_the_connection_check(void)
{
  const Endpoint_t* bulk   = endpoint_findByMcpName("cve_lookup_bulk");
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(bulk);
  TEST_ASSERT_NOT_NULL(lookup);
  EndpointAnyParams_t params;

  static_fillFiveIds(&params.m_bulkIds);
  const RequestCharge_t charge_of_2 = { .m_chargedCreditCount = 2, .mp_creditBudget = NULL, .mp_x402Payment = NULL };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(bulk, &params, NULL, &charge_of_2).m_status);
  TEST_ASSERT_EQUAL_INT(2, params.m_bulkIds.m_idCount);
  TEST_ASSERT_EQUAL_INT(3, params.m_bulkIds.m_notProcessedIdCount);

  static_fillFiveIds(&params.m_bulkIds);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(bulk, &params, NULL, &TEST_FULL_CHARGE).m_status);
  TEST_ASSERT_EQUAL_INT(5, params.m_bulkIds.m_idCount);

  memset(&params, 0x5A, sizeof(params));
  EndpointAnyParams_t untouched;
  memcpy(&untouched, &params, sizeof(params));
  const RequestCharge_t charge_of_0 = { .m_chargedCreditCount = 0, .mp_creditBudget = NULL, .mp_x402Payment = NULL };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(lookup, &params, NULL, &charge_of_0).m_status);
  TEST_ASSERT_EQUAL_MEMORY(&untouched, &params, sizeof(params));
}

#define TEST_CREDIT_BUDGET_HASH "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

void test_runRow_hands_the_credit_budget_only_to_its_row(void)
{
  const Endpoint_t* privacy = endpoint_findByMcpName("privacy_my_data");
  const Endpoint_t* lookup  = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(privacy);
  TEST_ASSERT_NOT_NULL(lookup);

  RequestCreditBudget_t credit_budget;
  memset(&credit_budget, 0, sizeof(credit_budget));
  const RequestCharge_t charge_with_budget = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = &credit_budget, .mp_x402Payment = NULL };
  memcpy(credit_budget.ma_budgetHash, TEST_CREDIT_BUDGET_HASH, sizeof(TEST_CREDIT_BUDGET_HASH));
  credit_budget.m_rateLimitInfo.m_limit     = 100;
  credit_budget.m_rateLimitInfo.m_remaining = 99;
  credit_budget.m_rateLimitInfo.m_reset     = time(NULL) + 3661;
  EndpointAnyParams_t params;

  memset(&params, 0, sizeof(params));
  EndpointRunResult_t run_result = endpoint_runRow(privacy, &params, NULL, &charge_with_budget);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, run_result.m_status);
  TEST_ASSERT_EQUAL_PTR(&credit_budget, params.m_privacyMyData.mp_creditBudget);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  TEST_ASSERT_NOT_NULL(strstr(run_result.mp_body, "\"hash\":\"" TEST_CREDIT_BUDGET_HASH "\""));
  TEST_ASSERT_TRUE_MESSAGE(strstr(run_result.mp_body, "\"resets_in\":\"01:01:01\"") != NULL || strstr(run_result.mp_body, "\"resets_in\":\"01:01:00\"") != NULL, run_result.mp_body);
  free(run_result.mp_body);

  memset(&params, 0, sizeof(params));
  run_result = endpoint_runRow(privacy, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CREDIT_BUDGET, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);

  memset(&params, 0x5A, sizeof(params));
  EndpointAnyParams_t untouched;
  memcpy(&untouched, &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(lookup, &params, NULL, &charge_with_budget).m_status);
  TEST_ASSERT_EQUAL_MEMORY(&untouched, &params, sizeof(params));
}

void test_only_an_accepted_request_will_call_upstream(void)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));

  const Endpoint_t* password_check = endpoint_findByMcpName("password_check");
  TEST_ASSERT_NOT_NULL(password_check);
  TEST_ASSERT_TRUE(endpoint_willCallUpstream(password_check, ENDPOINT_GATE_OK, &params));
  TEST_ASSERT_FALSE(endpoint_willCallUpstream(password_check, ENDPOINT_GATE_REJECT_VALUE, &params));

  const Endpoint_t* cve_lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(cve_lookup);
  TEST_ASSERT_FALSE(endpoint_willCallUpstream(cve_lookup, ENDPOINT_GATE_OK, &params));
}

void test_only_the_add_of_a_domain_item_of_watchlist_edit_will_call_upstream(void)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  TEST_ASSERT_FALSE(edit->m_callsUpstream);
  TEST_ASSERT_NOT_NULL(edit->m_callsUpstreamFunction);

  static const struct { const char* mp_arguments; EndpointGateStatus_t m_status; bool m_willCallUpstream; } cases[] = {
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\"}",      ENDPOINT_GATE_OK,           true  },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"shop.example.com\"}",  ENDPOINT_GATE_OK,           true  },
    { "{\"action\":\"add\",\"endpoint\":\"headers_check\",\"domain\":\"example.com\"}",   ENDPOINT_GATE_OK,           true  },
    { "{\"action\":\"remove\",\"endpoint\":\"headers_check\",\"domain\":\"example.com\"}", ENDPOINT_GATE_OK,          false },
    { "{\"action\":\"add\",\"endpoint\":\"cert_search\",\"domain\":\"example.com\"}",     ENDPOINT_GATE_OK,           true  },
    { "{\"action\":\"remove\",\"endpoint\":\"cert_search\",\"domain\":\"example.com\"}",  ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\"}",    ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"remove\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\"}",   ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"remove\",\"endpoint\":\"ssl_check\",\"domain\":\"example.com\"}",    ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"}",   ENDPOINT_GATE_OK,           false },
    { "{}",                                                                               ENDPOINT_GATE_OK,           false },
    { "{\"clear\":true}",                                                                 ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"printer.local\"}",    ENDPOINT_GATE_REJECT_VALUE, false },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\"}",       ENDPOINT_GATE_OK,           false },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"1.2.3.0/24\"}",    ENDPOINT_GATE_REJECT_VALUE, false },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"10.0.0.1\"}",      ENDPOINT_GATE_REJECT_VALUE, false },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"::1\"}",           ENDPOINT_GATE_REJECT_VALUE, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0x5A, sizeof(params));
    JsonReadSpan_t       args_span   = { cases[i].mp_arguments, strlen(cases[i].mp_arguments) };
    EndpointGateResult_t gate_result = endpoint_mcpArgsGate(edit, args_span, &params, edit->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_willCallUpstream, endpoint_willCallUpstream(edit, gate_result.m_status, &params), cases[i].mp_arguments);
  }

  for (int i = 0; i < endpoint_count; i++)
    if (&endpoints[i] != edit && strcmp(endpoints[i].mp_httpPath, "/vendor_key_edit") != 0)
      TEST_ASSERT_NULL_MESSAGE(endpoints[i].m_callsUpstreamFunction, endpoints[i].mp_httpPath);
}

void test_query_specs_carry_a_message_and_a_default(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoints[i].mp_params[j];
      const EndpointParamSpec_t* spec = param->mp_spec;
      if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY))
        continue;

      bool can_refuse = spec->m_type != ENDPOINT_PARAM_TYPE_STRING || spec->m_validatorFunction != NULL;
      TEST_ASSERT_EQUAL_INT_MESSAGE(can_refuse, spec->mp_message != NULL, spec->mp_name);
      if (spec->mp_message != NULL)
      {
        size_t name_len = strlen(spec->mp_name);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(spec->mp_message, spec->mp_name, name_len), spec->mp_name);
        TEST_ASSERT_EQUAL_CHAR_MESSAGE(' ', spec->mp_message[name_len], spec->mp_name);
      }
      if (spec->m_type == ENDPOINT_PARAM_TYPE_ENUM)
      {
        for (int k = 0; spec->mp_enumValues[k] != NULL; k++)
          TEST_ASSERT_NOT_NULL_MESSAGE(strstr(spec->mp_message, spec->mp_enumValues[k]), spec->mp_enumValues[k]);
      }

      if (spec->m_type == ENDPOINT_PARAM_TYPE_INT || spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
        TEST_ASSERT_TRUE_MESSAGE(spec->m_default == -1.0 || (spec->m_default >= spec->m_min && spec->m_default <= spec->m_max), spec->mp_name);
      else
        TEST_ASSERT_TRUE_MESSAGE(spec->m_default == 0.0, spec->mp_name);
    }
  }
}

void test_restQueryGate_writes_the_table_defaults_for_absent_values(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    bool has_required_query = false;
    for (int j = 0; j < endpoint->m_paramCount; j++)
      has_required_query = has_required_query || (endpoint->mp_params[j].m_isRequired && (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_QUERY));
    if (endpoint->m_paramsSize == 0 || has_required_query)
      continue;

    _Alignas(max_align_t) unsigned char params[sizeof(EndpointAnyParams_t)];
    TEST_ASSERT_TRUE(endpoint->m_paramsSize <= sizeof(params));
    memset(params, 0x5A, sizeof(params));
    EndpointGateResult_t gate_result = endpoint_restQueryGate(endpoint, "", params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, endpoint->mp_httpPath);

    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      const EndpointParamSpec_t* spec = param->mp_spec;
      if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY))
        continue;
      const unsigned char* field = params + param->m_offset;
      if (spec->m_type == ENDPOINT_PARAM_TYPE_INT)
      {
        int value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_EQUAL_INT_MESSAGE((int)spec->m_default, value, spec->mp_name);
      }
      else if (spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
      {
        double value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_TRUE_MESSAGE(value == spec->m_default, spec->mp_name);
      }
      else if (spec->m_type == ENDPOINT_PARAM_TYPE_KEV_FILTER)
      {
        CveKevFilter_t value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, value, spec->mp_name);
      }
      else
      {
        for (size_t k = 0; k < param->m_size; k++)
          TEST_ASSERT_EQUAL_HEX8_MESSAGE(0, field[k], spec->mp_name);
      }
    }
  }
}

void test_mcpArgsGate_writes_the_table_defaults_for_absent_arguments(void)
{
  int checked = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName == NULL || endpoint->m_paramsSize == 0)
      continue;
    bool has_required_arg = false;
    for (int j = 0; j < endpoint->m_paramCount; j++)
      has_required_arg = has_required_arg || (endpoint->mp_params[j].m_isRequired && (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_MCP_ARG));

    _Alignas(max_align_t) unsigned char params[sizeof(EndpointAnyParams_t)];
    TEST_ASSERT_TRUE(endpoint->m_paramsSize <= sizeof(params));
    memset(params, 0x5A, sizeof(params));
    JsonReadSpan_t args_span = { "{}", 2 };
    EndpointGateResult_t gate_result = endpoint_mcpArgsGate(endpoint, args_span, params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(has_required_arg ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK, gate_result.m_status, endpoint->mp_mcpToolName);

    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      const EndpointParamSpec_t* spec = param->mp_spec;
      if (!(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG))
        continue;
      const unsigned char* field = params + param->m_offset;
      if (spec->m_type == ENDPOINT_PARAM_TYPE_INT)
      {
        int value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_EQUAL_INT_MESSAGE((int)spec->m_default, value, spec->mp_name);
      }
      else if (spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
      {
        double value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_TRUE_MESSAGE(value == spec->m_default, spec->mp_name);
      }
      else if (spec->m_type == ENDPOINT_PARAM_TYPE_KEV_FILTER)
      {
        CveKevFilter_t value;
        memcpy(&value, field, sizeof(value));
        TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, value, spec->mp_name);
      }
      else
      {
        for (size_t k = 0; k < param->m_size; k++)
          TEST_ASSERT_EQUAL_HEX8_MESSAGE(0, field[k], spec->mp_name);
      }
    }
    checked++;
  }
  TEST_ASSERT_EQUAL_INT(35, checked);
}

void test_gates_write_the_kev_filter_for_absent_true_and_false(void)
{
  static const struct { const char* mp_query; const char* mp_args; CveKevFilter_t m_kevFilter; } cases[] = {
    { "",             "{}",                 CVE_KEV_FILTER_ANY },
    { "in_kev=true",  "{\"in_kev\":true}",  CVE_KEV_FILTER_ONLY_IN_KEV },
    { "in_kev=false", "{\"in_kev\":false}", CVE_KEV_FILTER_NOT_IN_KEV },
  };
  int checked = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      if (param->mp_spec->m_type != ENDPOINT_PARAM_TYPE_KEV_FILTER)
        continue;
      bool is_body_param = (param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY) != 0;
      TEST_ASSERT_TRUE_MESSAGE(is_body_param || (param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY), endpoint->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG, endpoint->mp_httpPath);

      for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
      {
        _Alignas(max_align_t) unsigned char params[2048];
        TEST_ASSERT_TRUE(endpoint->m_paramsSize <= sizeof(params));
        CveKevFilter_t kev_filter;

        memset(params, 0x5A, sizeof(params));
        EndpointGateResult_t gate_result;
        if (is_body_param)
          gate_result = endpoint_restFieldsBodyGate(endpoint, cases[k].mp_args, params, endpoint->m_paramsSize);
        else
          gate_result = endpoint_restQueryGate(endpoint, cases[k].mp_query, params, endpoint->m_paramsSize);
        TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, cases[k].mp_query);
        memcpy(&kev_filter, params + param->m_offset, sizeof(kev_filter));
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_kevFilter, kev_filter, cases[k].mp_query);

        memset(params, 0x5A, sizeof(params));
        JsonReadSpan_t args_span = { cases[k].mp_args, strlen(cases[k].mp_args) };
        gate_result = endpoint_mcpArgsGate(endpoint, args_span, params, endpoint->m_paramsSize);
        TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, cases[k].mp_args);
        memcpy(&kev_filter, params + param->m_offset, sizeof(kev_filter));
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_kevFilter, kev_filter, cases[k].mp_args);
      }
      checked++;
    }
  }
  TEST_ASSERT_EQUAL_INT(3, checked);
}

void test_gates_write_a_bool_or_kev_filter_only_into_its_own_field(void)
{
  static const char* const bool_texts[] = { "true", "false" };
  int checked = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    const char* id_member = "";
    const char* id_query  = "";
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (!endpoint->mp_params[j].m_isRequired)
        continue;
      if (endpoint->mp_params[j].mp_spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID)
        id_member = "\"cve_id\":\"CVE-2021-44228\"";
      else if (endpoint->mp_params[j].mp_spec->m_validatorFunction == validate_fileHashHex)
        id_member = "\"file_hash\":\"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\"";
      else if (strcmp(endpoint->mp_params[j].mp_spec->mp_name, "domain") == 0)
        id_member = "\"domain\":\"www.example.com\"";
      else if (strcmp(endpoint->mp_params[j].mp_spec->mp_name, "vendor") == 0 ||
               strcmp(endpoint->mp_params[j].mp_spec->mp_name, "product") == 0)
      {
        id_member = "\"vendor\":\"apache\",\"product\":\"log4j\"";
        id_query  = "vendor=apache&product=log4j";
      }
      else if (strcmp(endpoint->mp_params[j].mp_spec->mp_name, "action") == 0)
        id_member = "\"action\":\"apply\"";
    }

    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      const EndpointParamSpec_t* spec = param->mp_spec;
      if (spec->m_type != ENDPOINT_PARAM_TYPE_BOOL && spec->m_type != ENDPOINT_PARAM_TYPE_KEV_FILTER)
        continue;

      for (size_t k = 0; k < sizeof(bool_texts) / sizeof(bool_texts[0]); k++)
      {
        bool is_refused = k == 1 && spec->m_isOnlyTrueAccepted;
        for (int is_mcp = 0; is_mcp <= 1; is_mcp++)
        {
          _Alignas(max_align_t) unsigned char without_value[2048];
          _Alignas(max_align_t) unsigned char with_value[2048];
          TEST_ASSERT_TRUE(endpoint->m_paramsSize <= sizeof(without_value));
          memset(without_value, 0x5A, sizeof(without_value));
          memset(with_value, 0x5A, sizeof(with_value));
          char request[192];
          EndpointGateStatus_t without_status;
          EndpointGateStatus_t with_status;
          if (is_mcp)
          {
            TEST_ASSERT_TRUE(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG);
            char base[128];
            int written = snprintf(base, sizeof(base), "{%s}", id_member);
            TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(base));
            written = snprintf(request, sizeof(request), "{%s%s\"%s\":%s}", id_member, *id_member ? "," : "", spec->mp_name, bool_texts[k]);
            TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
            JsonReadSpan_t base_span    = { base, strlen(base) };
            JsonReadSpan_t request_span = { request, strlen(request) };
            without_status = endpoint_mcpArgsGate(endpoint, base_span, without_value, endpoint->m_paramsSize).m_status;
            with_status    = endpoint_mcpArgsGate(endpoint, request_span, with_value, endpoint->m_paramsSize).m_status;
          }
          else if (param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY)
          {
            char base[128];
            int written = snprintf(base, sizeof(base), "{%s}", id_member);
            TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(base));
            written = snprintf(request, sizeof(request), "{%s%s\"%s\":%s}", id_member, *id_member ? "," : "", spec->mp_name, bool_texts[k]);
            TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
            without_status = endpoint_restFieldsBodyGate(endpoint, base, without_value, endpoint->m_paramsSize).m_status;
            with_status    = endpoint_restFieldsBodyGate(endpoint, request, with_value, endpoint->m_paramsSize).m_status;
          }
          else
          {
            TEST_ASSERT_TRUE(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY);
            int written = snprintf(request, sizeof(request), "%s%s%s=%s", id_query, *id_query ? "&" : "", spec->mp_name, bool_texts[k]);
            TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
            without_status = endpoint_restQueryGate(endpoint, id_query, without_value, endpoint->m_paramsSize).m_status;
            with_status    = endpoint_restQueryGate(endpoint, request, with_value, endpoint->m_paramsSize).m_status;
          }

          TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, without_status, request);
          TEST_ASSERT_EQUAL_INT_MESSAGE(is_refused ? ENDPOINT_GATE_REJECT_VALUE : ENDPOINT_GATE_OK, with_status, request);
          if (is_refused)
            continue;
          for (size_t byte_index = 0; byte_index < endpoint->m_paramsSize; byte_index++)
          {
            if (byte_index < param->m_offset || byte_index >= param->m_offset + param->m_size)
              TEST_ASSERT_EQUAL_HEX8_MESSAGE(without_value[byte_index], with_value[byte_index], request);
          }
          checked++;
        }
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(60, checked);
}

void test_mcpArgsGate_stops_at_the_first_refusal_in_table_order(void)
{
  const Endpoint_t* endpoint = endpoint_findByMcpName("cve_search");
  TEST_ASSERT_NOT_NULL(endpoint);
  CVESEARCHParams_t params;

  JsonReadSpan_t args_span = { "{\"sort\":\"x\",\"severity\":\"x\"}", strlen("{\"sort\":\"x\",\"severity\":\"x\"}") };
  EndpointGateResult_t gate_result = endpoint_mcpArgsGate(endpoint, args_span, &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_TRUE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("severity", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name);

  args_span.mp_start = "{\"limit\":0,\"vendor\":\"%\"}";
  args_span.m_len    = strlen(args_span.mp_start);
  gate_result = endpoint_mcpArgsGate(endpoint, args_span, &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_TRUE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("vendor", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name);
}

void test_mcpArgsGate_answers_each_argument_refusal(void)
{
  const struct { const char* mp_tool; const char* mp_args; EndpointGateStatus_t m_status; const char* mp_name; } cases[] = {
    { "cve_search",       "{}",                                                ENDPOINT_GATE_OK,                           NULL               },
    { "cve_search",       "{\"vendor\":7}",                                    ENDPOINT_GATE_REJECT_TYPE,                  "vendor"           },
    { "cve_search",       "{\"vendor\":null}",                                 ENDPOINT_GATE_REJECT_TYPE,                  "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\x\"}",                             ENDPOINT_GATE_REJECT_ESCAPE,                "vendor"           },
    { "cve_search",       "{\"vendor\":\"\"}",                                 ENDPOINT_GATE_OK,                           NULL               },
    { "cve_search",       "{\"lim\":5}",                                       ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,    NULL               },
    { "cve_search",       "{\"limit\":\"5\"}",                                 ENDPOINT_GATE_REJECT_VALUE,                 "limit"            },
    { "cve_search",       "{\"min_cvss\":\"5\"}",                              ENDPOINT_GATE_REJECT_VALUE,                 "min_cvss"         },
    { "cve_search",       "{\"in_kev\":\"true\"}",                             ENDPOINT_GATE_REJECT_VALUE,                 "in_kev"           },
    { "cve_search",       "{\"known_ransomware\":false}",                      ENDPOINT_GATE_REJECT_VALUE,                 "known_ransomware" },
    { "product_exposure", "{\"product\":\"p\"}",                               ENDPOINT_GATE_REJECT_MISSING,               "vendor"           },
    { "product_exposure", "{\"vendor\":7,\"product\":\"p\"}",                  ENDPOINT_GATE_REJECT_TYPE,                  "vendor"           },
    { "product_exposure", "{\"vendor\":\"\",\"product\":\"p\"}",               ENDPOINT_GATE_REJECT_MISSING,               "vendor"           },
    { "product_exposure", "{\"vendor\":\"v\",\"product\":\"p\"}",              ENDPOINT_GATE_OK,                           NULL               },
    { "product_exposure", "{\"vendor\":\"v\",\"product\":\"p\",\"version\":\"22.1\"}", ENDPOINT_GATE_OK,                     NULL               },
    { "product_exposure", "{\"vendor\":\"v\",\"product\":\"p\",\"version\":22}", ENDPOINT_GATE_REJECT_TYPE,                    "version"          },
    { "product_exposure", "{\"vendor\":\"v\",\"product\":\"p\",\"include_rejected\":true}", ENDPOINT_GATE_OK,                NULL               },
    { "product_exposure", "{\"vendor\":\"v\",\"product\":\"p\",\"include_rejected\":\"true\"}", ENDPOINT_GATE_REJECT_VALUE, "include_rejected" },
    { "cve_search",       "{\"vendor\":\"a\\nb\"}",                             ENDPOINT_GATE_REJECT_CONTROL_CHAR,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\u0001b\"}",                        ENDPOINT_GATE_REJECT_CONTROL_CHAR,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\u007fb\"}",                        ENDPOINT_GATE_REJECT_CONTROL_CHAR,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\u0000b\"}",                        ENDPOINT_GATE_REJECT_CONTROL_CHAR,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\ud800b\"}",                        ENDPOINT_GATE_REJECT_INVALID_UTF8,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\\udc00\"}",                         ENDPOINT_GATE_REJECT_INVALID_UTF8,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"m\\u00fcnchen\"}",                    ENDPOINT_GATE_OK,                           NULL               },
    { "cve_search",       "{\"vendor\":\"a\x7f" "b\"}",                          ENDPOINT_GATE_REJECT_CONTROL_CHAR,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"a\xff" "b\"}",                          ENDPOINT_GATE_REJECT_INVALID_UTF8,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"abcdef\xff\"}",                       ENDPOINT_GATE_REJECT_INVALID_UTF8,          "vendor"           },
    { "cve_search",       "{\"vendor\":\"m\xc3\xbc" "nchen\"}",                  ENDPOINT_GATE_OK,                           NULL               },
    { "cve_search",       "{\"vendor\":\"a b~\"}",                                ENDPOINT_GATE_OK,                           NULL               },
    { "cve_search",       "{\"limit\":1000000000000000000000000000000}",       ENDPOINT_GATE_REJECT_VALUE,                 "limit"            },
    { "cve_search",       "{\"limit\":10000000000000000000000000000000}",      ENDPOINT_GATE_REJECT_TOOLONG,               "limit"            },
    { "cve_lookup",       "{\"cve_id\":\"CVE-2021-111111111111111\"}",         ENDPOINT_GATE_OK,                           NULL               },
    { "cve_lookup",       "{\"cve_id\":\"CVE-2021-1111111111111111\"}",        ENDPOINT_GATE_REJECT_VALUE,                 "cve_id"           },
    { "cve_lookup",       "{\"cve_id\":\"CVE-2021-44228\",\"include_ghsa\":\"ttttttttttttttttttttttttttttt\"}",    ENDPOINT_GATE_REJECT_VALUE,   "include_ghsa" },
    { "cve_lookup",       "{\"cve_id\":\"CVE-2021-44228\",\"include_ghsa\":\"tttttttttttttttttttttttttttttt\"}",   ENDPOINT_GATE_REJECT_TOOLONG, "include_ghsa" },
    { "health",           "{}",                                                ENDPOINT_GATE_OK,                           NULL               },
    { "health",           "[]",                                                ENDPOINT_GATE_REJECT_BODY,                  NULL               },
    { "health",           "{\"x\":1}",                                         ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,    NULL               },
    { "cve_search",       "{\"zz\":1}",                                        ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,    NULL               },
    { "cve_search",       "{\"x\":{\"vendor\":\"a\"}}",                        ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,    NULL               },
    { "cve_search",       "{\"vendor\":\"a\",\"vendor\":\"b\"}",               ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME,  "vendor"           },
    { "cve_search",       "{\"vendor\":{}}",                                   ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE, "vendor"           },
    { "cve_search",       "{\"vendor\" : [ ]}",                                ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE, "vendor"           },
    { "cve_search",       "{\"limit\":[5]}",                                   ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE, "limit"            },
    { "product_exposure", "{\"vendor\":{\"vendor\":\"v\"},\"product\":\"p\"}", ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE, "vendor"           },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const Endpoint_t* endpoint = endpoint_findByMcpName(cases[i].mp_tool);
    TEST_ASSERT_NOT_NULL(endpoint);
    TEST_ASSERT_TRUE(endpoint->m_paramsSize <= sizeof(EndpointAnyParams_t));
    EndpointAnyParams_t params;
    JsonReadSpan_t args_span = { cases[i].mp_args, strlen(cases[i].mp_args) };
    EndpointGateResult_t gate_result = endpoint_mcpArgsGate(endpoint, args_span, endpoint->m_paramsSize > 0 ? &params : NULL, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_args);
    if (cases[i].mp_name == NULL)
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, cases[i].mp_args);
    else
    {
      TEST_ASSERT_TRUE_MESSAGE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount, cases[i].mp_args);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_name, endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name, cases[i].mp_args);
    }
  }
}

void test_restQueryGate_refuses_a_decoded_control_character(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/cve_search", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  const struct { const char* mp_query; EndpointGateStatus_t m_status; } cases[] = {
    { "?vendor=a%1Fb",  ENDPOINT_GATE_REJECT_CONTROL_CHAR },
    { "?vendor=a%7Fb",  ENDPOINT_GATE_REJECT_CONTROL_CHAR },
    { "?vendor=a%0Ab",  ENDPOINT_GATE_REJECT_CONTROL_CHAR },
    { "?vendor=a%00b",  ENDPOINT_GATE_REJECT_CONTROL_CHAR },
    { "?vendor=a%zzb",  ENDPOINT_GATE_REJECT_ENCODING },
    { "?vendor=a%20b~", ENDPOINT_GATE_OK },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVESEARCHParams_t params;
    EndpointGateResult_t gate_result = endpoint_restQueryGate(endpoint, cases[i].mp_query, &params, sizeof(params));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_query);
    if (cases[i].m_status != ENDPOINT_GATE_OK)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("vendor", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name, cases[i].mp_query);
  }
}

void test_restQueryGate_refuses_a_value_that_is_not_valid_utf8(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/cve_search", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  const struct { const char* mp_query; EndpointGateStatus_t m_status; } cases[] = {
    { "?vendor=a%FFb",        ENDPOINT_GATE_REJECT_INVALID_UTF8 },
    { "?vendor=a\xff" "b",     ENDPOINT_GATE_REJECT_INVALID_UTF8 },
    { "?vendor=a%C0%80b",     ENDPOINT_GATE_REJECT_INVALID_UTF8 },
    { "?vendor=a%E2%82",      ENDPOINT_GATE_REJECT_INVALID_UTF8 },
    { "?vendor=abcdef%FF",    ENDPOINT_GATE_REJECT_INVALID_UTF8 },
    { "?vendor=%FF%0A",       ENDPOINT_GATE_REJECT_CONTROL_CHAR },
    { "?vendor=m%C3%BCnchen", ENDPOINT_GATE_OK },
    { "?vendor=a%E2%80%AEb",  ENDPOINT_GATE_OK },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVESEARCHParams_t params;
    EndpointGateResult_t gate_result = endpoint_restQueryGate(endpoint, cases[i].mp_query, &params, sizeof(params));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_query);
    if (cases[i].m_status != ENDPOINT_GATE_OK)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("vendor", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name, cases[i].mp_query);
  }
}

void test_restQueryGate_stops_at_the_first_refusal_in_table_order(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/cve_search", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  CVESEARCHParams_t params;

  EndpointGateResult_t gate_result = endpoint_restQueryGate(endpoint, "?sort=x&severity=x", &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_TRUE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("severity", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name);

  gate_result = endpoint_restQueryGate(endpoint, "?limit=0&vendor=%25", &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_TRUE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("vendor", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name);
}

void test_every_row_fits_the_param_name_mask(void)
{
  TEST_ASSERT_TRUE(ENDPOINT_MAX_PARAMS <= (int)(sizeof(unsigned int) * 8));
  for (int i = 0; i < endpoint_count; i++)
    TEST_ASSERT_TRUE_MESSAGE(endpoints[i].m_paramCount <= ENDPOINT_MAX_PARAMS, endpoints[i].mp_httpPath);
}

void test_checkHttpQueryParamNames_refuses_unknown_repeated_and_malformed_names(void)
{
  const struct { const char* mp_path; const char* mp_query; EndpointGateStatus_t m_status; const char* mp_name; } cases[] = {
    { "/cve_search", "",                      ENDPOINT_GATE_OK,                          NULL    },
    { "/cve_search", "?&&limit=5&",           ENDPOINT_GATE_OK,                          NULL    },
    { "/cve_search", "?limit=5&sort=cvss",    ENDPOINT_GATE_OK,                          NULL    },
    { "/cve_search", "?zz=1",                 ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?incl%75de=ghsa",       ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?lim=5",                ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?limitx=5",             ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?LIMIT=5",              ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?vendor",               ENDPOINT_GATE_REJECT_MALFORMED_PARAM,      NULL    },
    { "/cve_search", "?=x",                   ENDPOINT_GATE_REJECT_MALFORMED_PARAM,      NULL    },
    { "/cve_search", "?limit=5&limit=5",      ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME, "limit" },
    { "/cve_search", "?zz=1&limit",           ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/cve_search", "?limit&zz=1",           ENDPOINT_GATE_REJECT_MALFORMED_PARAM,      NULL    },
    { "/health",     "?_=1",                  ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   NULL    },
    { "/health",     "?",                     ENDPOINT_GATE_OK,                          NULL    },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const Endpoint_t* endpoint = endpoint_findByHttpPath(cases[i].mp_path, NULL);
    TEST_ASSERT_NOT_NULL(endpoint);
    EndpointGateResult_t gate_result = endpoint_checkHttpQueryParamNames(endpoint, cases[i].mp_query);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_query);
    if (cases[i].mp_name == NULL)
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, cases[i].mp_query);
    else
    {
      TEST_ASSERT_TRUE_MESSAGE(gate_result.m_refusedParamIndex >= 0 && gate_result.m_refusedParamIndex < endpoint->m_paramCount, cases[i].mp_query);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_name, endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name, cases[i].mp_query);
    }
  }
}

void test_restQueryGate_checks_the_names_first_and_keeps_the_defaults(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/cve_search", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 99;

  EndpointGateResult_t gate_result = endpoint_restQueryGate(endpoint, "?limit=5&zz=1", &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, gate_result.m_refusedParamIndex);
  TEST_ASSERT_EQUAL_INT(CVE_LIST_DEFAULT_LIMIT, params.m_limit);
}

static const EndpointParamSpec_t TEST_SPEC_QUERY_CWE_ID = {
  .mp_name              = "cwe_id",
  .m_type               = ENDPOINT_PARAM_TYPE_CWE_ID,
  .m_maxLen             = CWELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cweId,
  .mp_message           = "cwe_id must be a CWE ID such as CWE-79",
};

static const EndpointParam_t TEST_QUERY_CWE_ID_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_QUERY_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY,
    .m_isRequired         = false,
    .m_offset             = 0,
    .m_size               = CWELOOKUP_ID_MAX_LEN + 1,
  },
};

void test_restQueryGate_checks_a_cwe_id_and_writes_it_into_its_field(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_query_cwe_id",
    .mp_params            = TEST_QUERY_CWE_ID_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = CWELOOKUP_ID_MAX_LEN + 1,
  };
  char field[CWELOOKUP_ID_MAX_LEN + 1];

  EndpointGateResult_t gate_result = endpoint_restQueryGate(&endpoint, "?cwe_id=CWE-79", field, sizeof(field));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, gate_result.m_status);
  TEST_ASSERT_EQUAL_STRING("CWE-79", field);

  gate_result = endpoint_restQueryGate(&endpoint, "?cwe_id=79", field, sizeof(field));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(0, gate_result.m_refusedParamIndex);
}

static const EndpointParamSpec_t TEST_SPEC_QUERY_CVE_ID = {
  .mp_name              = "cve_id",
  .m_type               = ENDPOINT_PARAM_TYPE_CVE_ID,
  .m_maxLen             = CVELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cveId,
  .mp_message           = "cve_id must be a CVE ID such as CVE-2021-44228",
};

static const EndpointParam_t TEST_QUERY_CVE_ID_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_QUERY_CVE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY,
    .m_isRequired         = false,
    .m_offset             = 0,
    .m_size               = CVELOOKUP_ID_MAX_LEN + 1,
  },
};

void test_restQueryGate_checks_a_cve_id_and_writes_it_into_its_field(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_query_cve_id",
    .mp_params            = TEST_QUERY_CVE_ID_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = CVELOOKUP_ID_MAX_LEN + 1,
  };
  char field[CVELOOKUP_ID_MAX_LEN + 1];

  EndpointGateResult_t gate_result = endpoint_restQueryGate(&endpoint, "?cve_id=CVE-2021-44228", field, sizeof(field));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, gate_result.m_status);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", field);

  gate_result = endpoint_restQueryGate(&endpoint, "?cve_id=2021-44228", field, sizeof(field));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
}

static const char* static_wellFormedPathSegmentFor(const EndpointParamSpec_t* spec)
{
  if (spec->m_type == ENDPOINT_PARAM_TYPE_CWE_ID)
    return "CWE-79";
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID)
    return "CVE-2021-44228";
  else if (spec->m_validatorFunction == validate_publicDnsName)
    return "example.com";
  else if (spec->m_validatorFunction == validate_attackTechniqueId)
    return "T1055.012";
  else if (spec->m_validatorFunction == validate_fileHashHex)
    return "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8";
  else if (spec->m_validatorFunction == ipguard_isGloballyReachableIp)
    return "2001:4860:4860::8888";
  else if (spec->m_validatorFunction == validate_asnLookupTarget)
    return "AS15169";
  else if (spec->m_validatorFunction == validate_emailAddress)
    return "name@example.com";
  TEST_ASSERT_TRUE_MESSAGE(spec->m_validatorFunction == validate_sha1Hex, spec->mp_name);
  return "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
}

void test_restPathSegmentGate_checks_each_path_segment_with_its_spec(void)
{
  bool has_cve_row  = false;
  bool has_cwe_row  = false;
  bool has_text_row = false;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_hasPathSegment)
      continue;

    int segment_param_index = -1;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        segment_param_index = j;
    }
    TEST_ASSERT_TRUE_MESSAGE(segment_param_index >= 0, endpoint->mp_httpPath);
    const EndpointParamSpec_t* spec = endpoint->mp_params[segment_param_index].mp_spec;
    TEST_ASSERT_NOT_NULL_MESSAGE(spec->m_validatorFunction, endpoint->mp_httpPath);
    has_cve_row  = has_cve_row  || spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID;
    has_cwe_row  = has_cwe_row  || spec->m_type == ENDPOINT_PARAM_TYPE_CWE_ID;
    has_text_row = has_text_row || spec->m_type == ENDPOINT_PARAM_TYPE_STRING;

    EndpointAnyParams_t params;
    EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(endpoint, NULL, &params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_MISSING, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(segment_param_index, gate_result.m_refusedParamIndex, endpoint->mp_httpPath);

    gate_result = endpoint_restPathSegmentGate(endpoint, "", &params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_MISSING, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(segment_param_index, gate_result.m_refusedParamIndex, endpoint->mp_httpPath);

    gate_result = endpoint_restPathSegmentGate(endpoint, "X-1", &params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(segment_param_index, gate_result.m_refusedParamIndex, endpoint->mp_httpPath);

    gate_result = endpoint_restPathSegmentGate(endpoint, static_wellFormedPathSegmentFor(spec), &params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, endpoint->mp_httpPath);
  }
  TEST_ASSERT_TRUE(has_cve_row);
  TEST_ASSERT_TRUE(has_cwe_row);
  TEST_ASSERT_TRUE(has_text_row);
}

static const EndpointParamSpec_t TEST_SPEC_QUERY_NOTE = {
  .mp_name              = "note",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = 8,
};

static const EndpointParam_t TEST_PATH_AT_ONE_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_QUERY_NOTE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY,
    .m_isRequired         = false,
    .m_offset             = 0,
    .m_size               = 9,
  },
  {
    .mp_spec              = &TEST_SPEC_QUERY_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT,
    .m_isRequired         = true,
    .m_offset             = 9,
    .m_size               = CWELOOKUP_ID_MAX_LEN + 1,
  },
};

void test_gates_write_a_host_name_in_lower_case(void)
{
  int host_row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_hasPathSegment)
      continue;
    const EndpointParam_t* param = NULL;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        param = &endpoint->mp_params[j];
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(param, endpoint->mp_httpPath);
    if (!param->mp_spec->m_isWrittenInLowerCase)
      continue;
    host_row_count++;

    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, endpoint_restPathSegmentGate(endpoint, "Shop.Example.COM", &params, endpoint->m_paramsSize).m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("shop.example.com", (const char*)&params + param->m_offset, endpoint->mp_httpPath);

    char args[64];
    snprintf(args, sizeof(args), "{\"%s\":\"Shop.Example.COM\"}", param->mp_spec->mp_name);
    JsonReadSpan_t args_span = { args, strlen(args) };
    memset(&params, 0, sizeof(params));
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(endpoint, args_span, &params, endpoint->m_paramsSize).m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("shop.example.com", (const char*)&params + param->m_offset, endpoint->mp_httpPath);
  }
  TEST_ASSERT_EQUAL_INT(9, host_row_count);

  const Endpoint_t* email_row = endpoint_findByMcpName("email_address_check");
  TEST_ASSERT_NOT_NULL(email_row);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_restPathSegmentGate(email_row, "Ab@Example.COM", &params, email_row->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_STRING("Ab@Example.COM", (const char*)&params + email_row->mp_params[0].m_offset);
}

void test_host_check_tools_take_domain_and_refuse_hostname(void)
{
  static const char* const tool_names[] = { "dns_takeover_check", "ssl_check", "headers_check" };
  for (size_t i = 0; i < sizeof(tool_names) / sizeof(tool_names[0]); i++)
  {
    const Endpoint_t* endpoint = endpoint_findByMcpName(tool_names[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(endpoint, tool_names[i]);
    const EndpointParam_t* param = NULL;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        param = &endpoint->mp_params[j];
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(param, tool_names[i]);

    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    JsonReadSpan_t domain_span = { "{\"domain\":\"shop.example.com\"}", strlen("{\"domain\":\"shop.example.com\"}") };
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(endpoint, domain_span, &params, endpoint->m_paramsSize).m_status, tool_names[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("shop.example.com", (const char*)&params + param->m_offset, tool_names[i]);

    memset(&params, 0, sizeof(params));
    JsonReadSpan_t hostname_span = { "{\"hostname\":\"shop.example.com\"}", strlen("{\"hostname\":\"shop.example.com\"}") };
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, endpoint_mcpArgsGate(endpoint, hostname_span, &params, endpoint->m_paramsSize).m_status, tool_names[i]);
  }
}

void test_every_public_dns_name_param_is_named_domain(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParamSpec_t* spec = endpoints[i].mp_params[j].mp_spec;
      if (spec->m_validatorFunction == validate_publicDnsName)
        TEST_ASSERT_EQUAL_STRING_MESSAGE("domain", spec->mp_name, endpoints[i].mp_httpPath);
    }
  }
}

void test_restPathSegmentGate_names_the_path_segment_param_wherever_it_sits(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_path_at_one/",
    .m_hasPathSegment     = true,
    .mp_params            = TEST_PATH_AT_ONE_PARAMS,
    .m_paramCount         = 2,
    .m_paramsSize         = 9 + CWELOOKUP_ID_MAX_LEN + 1,
  };
  char params[9 + CWELOOKUP_ID_MAX_LEN + 1];

  EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(&endpoint, "", params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(1, gate_result.m_refusedParamIndex);

  gate_result = endpoint_restPathSegmentGate(&endpoint, "79", params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(1, gate_result.m_refusedParamIndex);

  gate_result = endpoint_restPathSegmentGate(&endpoint, "CWE-79", params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, gate_result.m_refusedParamIndex);
}

void test_restPathSegmentGate_refuses_an_id_longer_than_the_spec_m_maxLen(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_hasPathSegment)
      continue;

    const EndpointParamSpec_t* spec = NULL;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        spec = endpoint->mp_params[j].mp_spec;
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(spec, endpoint->mp_httpPath);

    const char* prefix = spec->m_type == ENDPOINT_PARAM_TYPE_CWE_ID ? "CWE-" : spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID ? "CVE-2021-" : "";
    char id[VALIDATE_EMAIL_ADDRESS_MAX_LEN + 2];
    TEST_ASSERT_TRUE_MESSAGE(spec->m_maxLen + 1 < sizeof(id), endpoint->mp_httpPath);
    memset(id, '1', sizeof(id));
    memcpy(id, prefix, strlen(prefix));
    id[spec->m_maxLen + 1] = '\0';

    EndpointAnyParams_t params;
    EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(endpoint, id, &params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status, endpoint->mp_httpPath);
  }
}

void test_restPathSegmentGate_writes_an_accepted_id_into_its_field_alone(void)
{
  int checked = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint->m_hasPathSegment)
      continue;

    const EndpointParam_t* param = NULL;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
        param = &endpoint->mp_params[j];
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(param, endpoint->mp_httpPath);

    unsigned char params[sizeof(EndpointAnyParams_t)];
    TEST_ASSERT_TRUE_MESSAGE(endpoint->m_paramsSize <= sizeof(params), endpoint->mp_httpPath);
    memset(params, 0x5A, sizeof(params));

    EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(endpoint, "X-1", params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status, endpoint->mp_httpPath);
    for (size_t k = 0; k < sizeof(params); k++)
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5A, params[k], endpoint->mp_httpPath);

    const char* id = static_wellFormedPathSegmentFor(param->mp_spec);
    gate_result = endpoint_restPathSegmentGate(endpoint, id, params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(id, (const char*)params + param->m_offset, endpoint->mp_httpPath);
    size_t written_end = param->m_offset + strlen(id) + 1;
    for (size_t k = 0; k < sizeof(params); k++)
    {
      if (k >= param->m_offset && k < written_end)
        continue;
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5A, params[k], endpoint->mp_httpPath);
    }
    checked++;
  }
  TEST_ASSERT_EQUAL_INT(21, checked);
}

static const EndpointParam_t TEST_FIELD_OF_SIX_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_QUERY_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT,
    .m_isRequired         = true,
    .m_offset             = 0,
    .m_size               = 6,
  },
};

void test_restPathSegmentGate_refuses_an_id_that_its_field_cannot_hold(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_field_of_six/",
    .m_hasPathSegment     = true,
    .mp_params            = TEST_FIELD_OF_SIX_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = 6,
  };
  unsigned char buffer[16];
  memset(buffer, 0x5A, sizeof(buffer));

  EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(&endpoint, "CWE-79", buffer, endpoint.m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
  TEST_ASSERT_EQUAL_INT(0, gate_result.m_refusedParamIndex);
  for (size_t k = 0; k < sizeof(buffer); k++)
    TEST_ASSERT_EQUAL_HEX8(0x5A, buffer[k]);
}

static const EndpointParam_t TEST_PATH_NOTE_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_QUERY_NOTE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT,
    .m_isRequired         = true,
    .m_offset             = 0,
    .m_size               = 9,
  },
};

void test_writeGateRefusalMessage_missing_text_path_segment_names_its_param(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_path_note/",
    .m_hasPathSegment     = true,
    .mp_params            = TEST_PATH_NOTE_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = 9,
  };
  char message[ENDPOINT_MESSAGE_BUF_SIZE] = "";
  const EndpointGateResult_t missing = { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = 0 };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&endpoint, missing, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("note is required", message);
}

void test_writeGateRefusalMessage_missing_query_id_names_its_param(void)
{
  const Endpoint_t cve_endpoint = {
    .mp_httpPath          = "/test_query_cve_id",
    .mp_params            = TEST_QUERY_CVE_ID_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = CVELOOKUP_ID_MAX_LEN + 1,
  };
  const Endpoint_t cwe_endpoint = {
    .mp_httpPath          = "/test_query_cwe_id",
    .mp_params            = TEST_QUERY_CWE_ID_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = CWELOOKUP_ID_MAX_LEN + 1,
  };
  char message[ENDPOINT_MESSAGE_BUF_SIZE] = "";
  const EndpointGateResult_t missing = { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = 0 };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&cve_endpoint, missing, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("cve_id is required", message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&cwe_endpoint, missing, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("cwe_id is required", message);
}

void test_PASSWORDCHECKRun_refuses_a_value_that_is_not_a_hash(void)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_passwordCheck.ma_sha1Hash, sizeof(params.m_passwordCheck.ma_sha1Hash), "%s", "5BAA6");
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  const char* message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, endpoint_PASSWORDCHECKRun(NULL, &params, json_buf, &message));
  TEST_ASSERT_EQUAL_STRING(VALIDATE_SHA1_HEX_REFUSAL_MESSAGE, message);
  jsonbuf_destroy(json_buf);
}

static void static_padBulkObject(char* out, size_t len)
{
  static const char head[] = "{\"cve_ids\":[\"CVE-2021-44228\"";
  static const char tail[] = "]}";
  size_t head_len = sizeof(head) - 1;
  size_t tail_len = sizeof(tail) - 1;
  TEST_ASSERT_TRUE(len >= head_len + tail_len);
  memcpy(out, head, head_len);
  memset(out + head_len, ' ', len - head_len - tail_len);
  memcpy(out + len - tail_len, tail, tail_len + 1);
  TEST_ASSERT_EQUAL_size_t(len, strlen(out));
}

void test_restBulkBodyGate_reads_the_ids_and_names_each_refusal(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/cve_lookup_bulk", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  static char longest_body[ENDPOINT_JSON_OBJECT_BUF_SIZE];
  static char too_large_body[ENDPOINT_JSON_OBJECT_BUF_SIZE + 1];
  static_padBulkObject(longest_body, sizeof(longest_body) - 1);
  static_padBulkObject(too_large_body, sizeof(too_large_body) - 1);
  static char too_many[2048];
  int used = snprintf(too_many, sizeof(too_many), "{\"cve_ids\":[");
  for (int i = 0; i < CVELOOKUPBULK_MAX_IDS + 1; i++)
    used += snprintf(too_many + used, sizeof(too_many) - (size_t)used, "%s\"CVE-2021-%05d\"", i == 0 ? "" : ",", i);
  snprintf(too_many + used, sizeof(too_many) - (size_t)used, "]}");

  const struct { const char* mp_body; EndpointGateStatus_t m_status; bool m_namesArray; int m_count; int m_skippedCount; } cases[] = {
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\"]}",      ENDPOINT_GATE_OK,                          false, 2, 0 },
    { "{\"cve_ids\":[\"not-a-cve\"]}",                                ENDPOINT_GATE_OK,                          false, 0, 1 },
    { "{\"cve_ids\":[\"CVE-2021-1234\"]}",                            ENDPOINT_GATE_OK,                          false, 1, 0 },
    { "{\"cve_ids\":[\"cve-2021-44228\"]}",                           ENDPOINT_GATE_OK,                          false, 0, 1 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",5]}",                       ENDPOINT_GATE_OK,                          false, 1, 1 },
    { "{\"cve_ids\":[\"CVE-2021-1111111111111111\"]}",              ENDPOINT_GATE_OK,                          false, 0, 1 },
    { "{\"cve_ids\":[\"CVE-2021-4422\\u0038\"]}",                   ENDPOINT_GATE_OK,                          false, 1, 0 },
    { "{\"cve_ids\":[\"CVE-2021-4422\\ud800\"]}",                   ENDPOINT_GATE_OK,                          false, 0, 1 },
    { "{\"cve_ids\":[\"CVE-2021-44228\\x\"]}",                      ENDPOINT_GATE_OK,                          false, 0, 1 },
    { NULL,                                                         ENDPOINT_GATE_REJECT_MISSING,              true,  0, 0 },
    { "",                                                           ENDPOINT_GATE_REJECT_MISSING,              true,  0, 0 },
    { "not json",                                                   ENDPOINT_GATE_REJECT_BODY,                 true,  0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"\xff\"]}",                 ENDPOINT_GATE_REJECT_BODY,                 true,  0, 0 },
    { "[{\"cve_ids\":[\"CVE-2021-44228\"]}]",                       ENDPOINT_GATE_REJECT_BODY,                 true,  0, 0 },
    { "{}",                                                         ENDPOINT_GATE_REJECT_MISSING,              true,  0, 0 },
    { "{\"cve_ids\":\"CVE-2021-44228\"}",                           ENDPOINT_GATE_REJECT_TYPE,                 true,  0, 0 },
    { longest_body,                                                 ENDPOINT_GATE_OK,                          false, 1, 0 },
    { too_large_body,                                               ENDPOINT_GATE_REJECT_BODY_TOO_LARGE,       true,  0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\"],\"x\":1}",                 ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   false, 0, 0 },
    { "{\"cve_idsx\":[\"CVE-2021-44228\"]}",                        ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   false, 0, 0 },
    { "{\"cve_id\":[\"CVE-2021-44228\"]}",                          ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   false, 0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\"],\"cve_ids\":[\"CVE-1\"]}", ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME, true,  0, 0 },
    { "{\"cve_ids\":[]}",                                           ENDPOINT_GATE_REJECT_ITEMS_EMPTY,          true,  0, 0 },
    { too_many,                                                     ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY,       true,  0, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const char* label = cases[i].mp_body != NULL ? cases[i].mp_body : "NULL";
    BulkIdsParams_t ids;
    memset(&ids, 0x5A, sizeof(ids));
    EndpointGateResult_t gate_result = endpoint_restBulkBodyGate(endpoint, cases[i].mp_body, &ids, sizeof(ids));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, label);
    if (cases[i].m_namesArray)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("cve_ids", endpoint->mp_params[gate_result.m_refusedParamIndex].mp_spec->mp_name, label);
    else
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, label);
    if (gate_result.m_status != ENDPOINT_GATE_OK)
      continue;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_count, ids.m_idCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_skippedCount, ids.m_skippedIdCount, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, ids.m_notProcessedIdCount, label);
  }

  BulkIdsParams_t ids;
  endpoint_restBulkBodyGate(endpoint, "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\"]}", &ids, sizeof(ids));
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", ids.ma_ids[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", ids.ma_ids[1]);
  endpoint_restBulkBodyGate(endpoint, "{\"cve_ids\":[\"CVE-2021-4422\\u0038\"]}", &ids, sizeof(ids));
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", ids.ma_ids[0]);
}

void test_appendParamNameList_writes_the_names_or_leaves_the_message(void)
{
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  const Endpoint_t* health = endpoint_findByMcpName("health");
  TEST_ASSERT_NOT_NULL(lookup);
  TEST_ASSERT_NOT_NULL(health);
  const char* expected = "x cve_id, include_ghsa";
  char message[64];

  strcpy(message, "x");
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_NAME_LIST_WRITTEN, endpoint_appendParamNameListToRefusalMessage(lookup, ENDPOINT_PARAM_SRC_MCP_ARG, message, strlen(expected) + 1));
  TEST_ASSERT_EQUAL_STRING(expected, message);

  strcpy(message, "x");
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_NAME_LIST_TOO_LONG, endpoint_appendParamNameListToRefusalMessage(lookup, ENDPOINT_PARAM_SRC_MCP_ARG, message, strlen(expected)));
  TEST_ASSERT_EQUAL_STRING("x", message);

  strcpy(message, "x");
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_NAME_LIST_EMPTY, endpoint_appendParamNameListToRefusalMessage(health, ENDPOINT_PARAM_SRC_MCP_ARG, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("x", message);
}

void test_bulk_gates_read_a_body_and_arguments_alike(void)
{
  static char too_many[2048];
  int used = snprintf(too_many, sizeof(too_many), "{\"cve_ids\":[");
  for (int i = 0; i < CVELOOKUPBULK_MAX_IDS + 1; i++)
    used += snprintf(too_many + used, sizeof(too_many) - (size_t)used, "%s\"CVE-2021-%05d\"", i == 0 ? "" : ",", i);
  snprintf(too_many + used, sizeof(too_many) - (size_t)used, "]}");
  static char longest_object[ENDPOINT_JSON_OBJECT_BUF_SIZE];
  static char too_large_object[ENDPOINT_JSON_OBJECT_BUF_SIZE + 1];
  static_padBulkObject(longest_object, sizeof(longest_object) - 1);
  static_padBulkObject(too_large_object, sizeof(too_large_object) - 1);

  const struct { const char* mp_object; EndpointGateStatus_t m_status; int m_count; int m_skippedCount; const char* mp_firstId; } cases[] = {
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"not-a-cve\"]}",                   ENDPOINT_GATE_OK,                          1, 1, "CVE-2021-44228" },
    { "{\"cve_ids\":[\"not-a-cve\",\"CVE-2021-44228\"]}",                   ENDPOINT_GATE_OK,                          1, 1, "CVE-2021-44228" },
    { "{}",                                                               ENDPOINT_GATE_REJECT_MISSING,              0, 0, NULL },
    { "{\"cve_ids\":\"CVE-2021-44228\"}",                                 ENDPOINT_GATE_REJECT_TYPE,                 0, 0, NULL },
    { "[\"CVE-2021-44228\"]",                                             ENDPOINT_GATE_REJECT_BODY,                 0, 0, NULL },
    { "{\"cve_ids\":[]}",                                                 ENDPOINT_GATE_REJECT_ITEMS_EMPTY,          0, 0, NULL },
    { too_many,                                                           ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY,       0, 0, NULL },
    { "{\"cve_ids\":[\"CVE-2021-44228\"],\"x\":1}",                       ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,   0, 0, NULL },
    { "{\"cve_ids\":[\"CVE-2021-44228\"],\"cve_ids\":[]}",                ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME, 0, 0, NULL },
    { "{\"cve_ids\":[5,\"CVE-2021-44228\"]}",                             ENDPOINT_GATE_OK,                          1, 1, "CVE-2021-44228" },
    { "{\"cve_ids\":[\"CVE-2021-1111111111111111\",\"CVE-2021-44228\"]}", ENDPOINT_GATE_OK,                          1, 1, "CVE-2021-44228" },
    { longest_object,                                                     ENDPOINT_GATE_OK,                          1, 0, "CVE-2021-44228" },
    { too_large_object,                                                   ENDPOINT_GATE_REJECT_BODY_TOO_LARGE,       0, 0, NULL },
  };
  int rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->m_costRule != ENDPOINT_COST_BULK_IDS || endpoint->mp_params[0].mp_spec->m_type != ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY)
      continue;
    rows++;
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
      EndpointAnyParams_t rest_params;
      EndpointAnyParams_t mcp_params;
      memset(&rest_params, 0x5A, sizeof(rest_params));
      memset(&mcp_params, 0x5A, sizeof(mcp_params));
      JsonReadSpan_t args_span = { cases[k].mp_object, strlen(cases[k].mp_object) };
      EndpointGateResult_t rest_gate_result = endpoint_restBulkBodyGate(endpoint, cases[k].mp_object, &rest_params, endpoint->m_paramsSize);
      EndpointGateResult_t mcp_gate_result  = endpoint_mcpArgsGate(endpoint, args_span, &mcp_params, endpoint->m_paramsSize);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, rest_gate_result.m_status, cases[k].mp_object);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, mcp_gate_result.m_status, cases[k].mp_object);
      if (rest_gate_result.m_status == ENDPOINT_GATE_OK)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_count, rest_params.m_bulkIds.m_idCount, cases[k].mp_object);
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_skippedCount, rest_params.m_bulkIds.m_skippedIdCount, cases[k].mp_object);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[k].mp_firstId, rest_params.m_bulkIds.ma_ids[0], cases[k].mp_object);
      }
      if (mcp_gate_result.m_status == ENDPOINT_GATE_OK)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_count, mcp_params.m_bulkIds.m_idCount, cases[k].mp_object);
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_skippedCount, mcp_params.m_bulkIds.m_skippedIdCount, cases[k].mp_object);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[k].mp_firstId, mcp_params.m_bulkIds.ma_ids[0], cases[k].mp_object);
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(2, rows);
}

void test_bulk_gates_refuse_a_repeated_id_and_name_the_first_pair(void)
{
  TEST_ASSERT_EQUAL_size_t(CVELOOKUP_ID_MAX_LEN, strlen("CVE-2021-111111111111111"));
  const struct { const char* mp_object; EndpointGateStatus_t m_status; int m_duplicateItemIndex; int m_originalItemIndex; } cases[] = {
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\",\"CVE-2021-44228\",\"CVE-2022-12345\"]}", ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 2, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2021-44228\",\"CVE-2021-44228\"]}",                      ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 1, 0 },
    { "{\"cve_ids\":[\"CVE-2021-111111111111111\",\"CVE-2021-111111111111111\"]}",                      ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 1, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2021-4422\\u0038\"]}",                                 ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 1, 0 },
    { "{\"cve_ids\":[5,\"CVE-2021-44228\",\"CVE-2021-44228\"]}",                                       ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 2, 1 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2021-44228\",5]}",                                       ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 1, 0 },
    { "{\"cve_ids\":[\"not-a-cve\",\"CVE-2021-44228\",\"CVE-2021-44228\"]}",                           ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 2, 1 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"cve-2021-44228\"]}",                                         ENDPOINT_GATE_OK,                    0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-4422\",\"CVE-2021-44228\"]}",                                          ENDPOINT_GATE_OK,                    0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2021-4422\"]}",                                          ENDPOINT_GATE_OK,                    0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\",\"CVE-2022-12345\",\"CVE-2021-44228\"]}", ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 2, 1 },
    { "{\"cve_ids\":[\"not-a-cve\",\"not-a-cve\"]}",                                                  ENDPOINT_GATE_OK,                    0, 0 },
    { "{\"cve_ids\":[\"CVE-2021-1111111111111111\",\"CVE-2021-1111111111111111\"]}",                    ENDPOINT_GATE_OK,                    0, 0 },
    { "{\"cve_ids\":[5,5]}",                                                                           ENDPOINT_GATE_OK,                    0, 0 },
  };
  int rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->m_costRule != ENDPOINT_COST_BULK_IDS || endpoint->mp_params[0].mp_spec->m_type != ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY)
      continue;
    rows++;
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
      EndpointAnyParams_t rest_params;
      EndpointAnyParams_t mcp_params;
      memset(&rest_params, 0x5A, sizeof(rest_params));
      memset(&mcp_params, 0x5A, sizeof(mcp_params));
      memset(rest_params.m_bulkIds.ma_ids[1], 0xA5, sizeof(rest_params.m_bulkIds.ma_ids[1]));
      memset(mcp_params.m_bulkIds.ma_ids[1], 0xA5, sizeof(mcp_params.m_bulkIds.ma_ids[1]));
      JsonReadSpan_t args_span = { cases[k].mp_object, strlen(cases[k].mp_object) };
      EndpointGateResult_t gate_results[2];
      gate_results[0] = endpoint_restBulkBodyGate(endpoint, cases[k].mp_object, &rest_params, endpoint->m_paramsSize);
      gate_results[1] = endpoint_mcpArgsGate(endpoint, args_span, &mcp_params, endpoint->m_paramsSize);
      for (int g = 0; g < 2; g++)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, gate_results[g].m_status, cases[k].mp_object);
        if (gate_results[g].m_status != ENDPOINT_GATE_REJECT_ITEMS_REPEATED)
          continue;
        TEST_ASSERT_EQUAL_STRING_MESSAGE("cve_ids", endpoint->mp_params[gate_results[g].m_refusedParamIndex].mp_spec->mp_name, cases[k].mp_object);
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_duplicateItemIndex, gate_results[g].m_duplicateItemIndex, cases[k].mp_object);
        TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_originalItemIndex, gate_results[g].m_originalItemIndex, cases[k].mp_object);
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(2, rows);
}

void test_checkHttpQueryParamNames_refuses_a_name_the_row_reads_from_elsewhere(void)
{
  int checked = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoints[i].mp_params[j];
      if (param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY)
        continue;
      char query[64];
      snprintf(query, sizeof(query), "?%s=x", param->mp_spec->mp_name);
      EndpointGateResult_t gate_result = endpoint_checkHttpQueryParamNames(&endpoints[i], query);
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, gate_result.m_status, query);
      checked++;
    }
  }
  TEST_ASSERT_TRUE(checked > 0);
}

void test_restBulkBodyGate_rows_bind_one_body_array(void)
{
  const BulkIdsParams_t* ids = NULL;
  int bulk_rows = 0;
  int json_body_rows = 0;
  int beside_member_rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    int body_param_count = 0;
    int mcp_param_count  = 0;
    int beside_array_count = 0;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      if (param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG)
        mcp_param_count++;
      if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY))
        continue;
      body_param_count++;
      if (endpoint->m_costRule == ENDPOINT_COST_BULK_IDS && param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(PACKAGECHECKBULK_MAX_ITEMS, (int)param->mp_spec->m_max, endpoint->mp_httpPath);
        TEST_ASSERT_FALSE_MESSAGE(param->mp_spec->m_isPackageVersionOptional, endpoint->mp_httpPath);
      }
      else if (endpoint->m_costRule == ENDPOINT_COST_BULK_IDS)
      {
        TEST_ASSERT_TRUE_MESSAGE(endpoint_isIdArrayType(param->mp_spec->m_type), endpoint->mp_httpPath);
        TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_max <= sizeof(ids->ma_ids) / sizeof(ids->ma_ids[0]), endpoint->mp_httpPath);
        TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_maxLen + 1 <= sizeof(ids->ma_ids[0]), endpoint->mp_httpPath);
      }
      else if (endpoint_hasPackageArrayWithOtherMembers(endpoint) && endpoint_isBulkArrayType(param->mp_spec->m_type))
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY, param->mp_spec->m_type, endpoint->mp_httpPath);
        TEST_ASSERT_EQUAL_INT_MESSAGE(WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY, (int)param->mp_spec->m_max, endpoint->mp_httpPath);
        TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_isPackageVersionOptional, endpoint->mp_httpPath);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG, param->m_sources, endpoint->mp_httpPath);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(sizeof(PACKAGECHECKBULKParams_t), param->m_size, endpoint->mp_httpPath);
        beside_array_count++;
      }
      else
      {
        TEST_ASSERT_FALSE_MESSAGE(endpoint_isBulkArrayType(param->mp_spec->m_type), endpoint->mp_httpPath);
        if (endpoint->mp_mcpToolName != NULL)
          TEST_ASSERT_TRUE_MESSAGE(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG, endpoint->mp_httpPath);
        else
          TEST_ASSERT_EQUAL_UINT_MESSAGE(ENDPOINT_PARAM_SRC_REST_BODY, param->m_sources, endpoint->mp_httpPath);
        TEST_ASSERT_TRUE_MESSAGE(param->m_size > 0 && param->m_offset + param->m_size <= endpoint->m_paramsSize, endpoint->mp_httpPath);
      }
    }
    if (endpoint_hasPackageArrayWithOtherMembers(endpoint))
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, beside_array_count, endpoint->mp_httpPath);
      TEST_ASSERT_EQUAL_STRING("/watchlist_edit", endpoint->mp_httpPath);
      beside_member_rows++;
    }
    if (endpoint->m_costRule == ENDPOINT_COST_BULK_IDS)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, body_param_count, endpoint->mp_httpPath);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, mcp_param_count, endpoint->mp_httpPath);
      TEST_ASSERT_FALSE_MESSAGE(endpoint_hasPackageArrayWithOtherMembers(endpoint), endpoint->mp_httpPath);
      bulk_rows++;
    }
    else if (body_param_count > 0)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("POST", endpoint->ma_allowedMethods[0], endpoint->mp_httpPath);
      TEST_ASSERT_NULL_MESSAGE(endpoint->ma_allowedMethods[1], endpoint->mp_httpPath);
      if (endpoint->mp_mcpToolName != NULL)
        TEST_ASSERT_EQUAL_INT_MESSAGE(body_param_count, mcp_param_count, endpoint->mp_httpPath);
      else
        TEST_ASSERT_EQUAL_STRING("/api_key_claim", endpoint->mp_httpPath);
      json_body_rows++;
    }
  }
  TEST_ASSERT_EQUAL_INT(4, bulk_rows);
  TEST_ASSERT_EQUAL_INT(3, json_body_rows);
  TEST_ASSERT_EQUAL_INT(1, beside_member_rows);
}

static void static_writeLongestBulkId(const EndpointParamSpec_t* spec, int index, char* id_out, size_t id_size)
{
  switch (spec->m_type)
  {
    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
      snprintf(id_out, id_size, "CVE-2021-%0*d", (int)(spec->m_maxLen - strlen("CVE-2021-")), index);
      break;
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
      snprintf(id_out, id_size, "%0*x", (int)spec->m_maxLen, (unsigned int)index);
      break;
    default:
      TEST_FAIL_MESSAGE("static_writeLongestBulkId has no id for this array type");
  }
  TEST_ASSERT_EQUAL_size_t(spec->m_maxLen, strlen(id_out));
  TEST_ASSERT_TRUE(spec->m_validatorFunction(id_out));
}

void test_isIdArrayType_names_the_two_id_array_types(void)
{
  int id_array_type_count = 0;
  for (int type = ENDPOINT_PARAM_TYPE_STRING; type <= ENDPOINT_PARAM_TYPE_BYTES; type++)
  {
    bool is_id_array = type == ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY || type == ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY;
    if (is_id_array)
    {
      TEST_ASSERT_TRUE(endpoint_isIdArrayType((EndpointParamType_t)type));
      id_array_type_count++;
    }
    else
      TEST_ASSERT_FALSE(endpoint_isIdArrayType((EndpointParamType_t)type));
  }
  TEST_ASSERT_EQUAL_INT(2, id_array_type_count);
}

static const EndpointParamSpec_t TEST_SPEC_FILE_HASHES = {
  .mp_name              = "hashes",
  .m_type               = ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY,
  .m_min                = 1,
  .m_max                = 4,
  .m_maxLen             = VALIDATE_SHA256_HEX_LEN,
  .m_validatorFunction  = validate_fileHashHex,
};

static const EndpointParam_t TEST_FILE_HASHES_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_FILE_HASHES,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .m_offset             = 0,
    .m_size               = sizeof(BulkIdsParams_t),
  },
};

static const Endpoint_t TEST_FILE_HASHES_ROW = {
  .mp_httpPath          = "/test_file_hashes",
  .ma_allowedMethods    = {"POST", NULL},
  .mp_mcpToolName       = "test_file_hashes",
  .m_creditCost         = 1,
  .m_costRule           = ENDPOINT_COST_BULK_IDS,
  .mp_params            = TEST_FILE_HASHES_PARAMS,
  .m_paramCount         = 1,
  .m_paramsSize         = sizeof(BulkIdsParams_t),
};

void test_file_hash_array_gates_keep_each_hash_in_lower_case(void)
{
  static const char object[] =
    R"({"hashes":["5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8","5f4DCC3b5aa765d61d8327deb882cf99","xyz",5]})";
  BulkIdsParams_t ids[2];
  memset(ids, 0x5A, sizeof(ids));
  JsonReadSpan_t args_span = { object, strlen(object) };
  EndpointGateResult_t gate_results[2];
  gate_results[0] = endpoint_restBulkBodyGate(&TEST_FILE_HASHES_ROW, object, &ids[0], sizeof(ids[0]));
  gate_results[1] = endpoint_mcpArgsGate(&TEST_FILE_HASHES_ROW, args_span, &ids[1], sizeof(ids[1]));
  for (int g = 0; g < 2; g++)
  {
    TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, gate_results[g].m_status);
    TEST_ASSERT_EQUAL_INT(2, ids[g].m_idCount);
    TEST_ASSERT_EQUAL_INT(2, ids[g].m_skippedIdCount);
    TEST_ASSERT_EQUAL_STRING("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", ids[g].ma_ids[0]);
    TEST_ASSERT_EQUAL_STRING("5f4dcc3b5aa765d61d8327deb882cf99", ids[g].ma_ids[1]);
  }
}

void test_file_hash_array_gates_refuse_two_spellings_of_one_hash(void)
{
  const struct { const char* mp_object; EndpointGateStatus_t m_status; int m_duplicateItemIndex; int m_originalItemIndex; } cases[] = {
    { R"({"hashes":["5F4DCC3B5AA765D61D8327DEB882CF99","5f4dcc3b5aa765d61d8327deb882cf99"]})", ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 1, 0 },
    { R"({"hashes":["5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8","5f4dcc3b5aa765d61d8327deb882cf99","5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"]})", ENDPOINT_GATE_REJECT_ITEMS_REPEATED, 2, 0 },
    { R"({"hashes":["5f4dcc3b5aa765d61d8327deb882cf99","5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"]})", ENDPOINT_GATE_OK, 0, 0 },
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
  {
    BulkIdsParams_t ids[2];
    memset(ids, 0x5A, sizeof(ids));
    JsonReadSpan_t args_span = { cases[k].mp_object, strlen(cases[k].mp_object) };
    EndpointGateResult_t gate_results[2];
    gate_results[0] = endpoint_restBulkBodyGate(&TEST_FILE_HASHES_ROW, cases[k].mp_object, &ids[0], sizeof(ids[0]));
    gate_results[1] = endpoint_mcpArgsGate(&TEST_FILE_HASHES_ROW, args_span, &ids[1], sizeof(ids[1]));
    for (int g = 0; g < 2; g++)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, gate_results[g].m_status, cases[k].mp_object);
      if (gate_results[g].m_status != ENDPOINT_GATE_REJECT_ITEMS_REPEATED)
        continue;
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_duplicateItemIndex, gate_results[g].m_duplicateItemIndex, cases[k].mp_object);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_originalItemIndex, gate_results[g].m_originalItemIndex, cases[k].mp_object);
    }
  }
}

void test_bulk_rows_take_their_most_ids_at_their_longest(void)
{
  int rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->m_costRule != ENDPOINT_COST_BULK_IDS || !endpoint_isIdArrayType(endpoint->mp_params[0].mp_spec->m_type))
      continue;
    rows++;
    const EndpointParamSpec_t* spec = endpoint->mp_params[0].mp_spec;
    static char object[ENDPOINT_JSON_OBJECT_BUF_SIZE * 2];
    int used = snprintf(object, sizeof(object), "{\"%s\":[", spec->mp_name);
    for (int k = 0; k < (int)spec->m_max; k++)
    {
      char id[BULK_ID_MAX_LEN + 1];
      static_writeLongestBulkId(spec, k, id, sizeof(id));
      used += snprintf(object + used, sizeof(object) - (size_t)used, "%s\"%s\"", k == 0 ? "" : ",", id);
    }
    used += snprintf(object + used, sizeof(object) - (size_t)used, "]}");
    TEST_ASSERT_TRUE_MESSAGE((size_t)used < sizeof(object), endpoint->mp_httpPath);

    EndpointAnyParams_t rest_params;
    EndpointAnyParams_t mcp_params;
    JsonReadSpan_t args_span = { object, (size_t)used };
    EndpointGateResult_t rest_gate_result = endpoint_restBulkBodyGate(endpoint, object, &rest_params, endpoint->m_paramsSize);
    EndpointGateResult_t mcp_gate_result  = endpoint_mcpArgsGate(endpoint, args_span, &mcp_params, endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, rest_gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, mcp_gate_result.m_status, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)spec->m_max, rest_params.m_bulkIds.m_idCount, endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)spec->m_max, mcp_params.m_bulkIds.m_idCount, endpoint->mp_httpPath);
  }
  TEST_ASSERT_TRUE(rows > 0);
}

void test_isBulkArrayType_names_the_three_bulk_array_types(void)
{
  int bulk_array_type_count = 0;
  for (int type = ENDPOINT_PARAM_TYPE_STRING; type <= ENDPOINT_PARAM_TYPE_BYTES; type++)
  {
    bool is_bulk_array = type == ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY || type == ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY || type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY;
    TEST_ASSERT_EQUAL_INT(is_bulk_array, endpoint_isBulkArrayType((EndpointParamType_t)type));
    if (is_bulk_array)
      bulk_array_type_count++;
  }
  TEST_ASSERT_EQUAL_INT(3, bulk_array_type_count);
}

static const Endpoint_t* static_packageRow(void)
{
  const Endpoint_t* row = endpoint_findByMcpName("package_check_bulk");
  TEST_ASSERT_NOT_NULL(row);
  return row;
}

static JsonReadSpan_t static_spanOfText(const char* text)
{
  JsonReadSpan_t span = { text, strlen(text) };
  return span;
}

void test_tryReadPackageItem_reads_the_three_members(void)
{
  PACKAGECHECKBULKItem_t item;
  TEST_ASSERT_TRUE(endpoint_tryReadPackageItem(static_spanOfText(R"({"version":"3.2.0","ecosystem":"PyPI","name":"a\/b"})"), &item));
  TEST_ASSERT_EQUAL_STRING("PyPI", item.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("a/b", item.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("3.2.0", item.ma_version);
}

void test_tryReadPackageItem_skips_each_element_that_breaks_a_rule(void)
{
  static const struct {
    const char* mp_element;
    bool        m_isKept;
  } cases[] = {
    { R"({"ecosystem":"npm","name":"lodash","version":"4.17.20"})",              true  },
    { R"({"ecosystem":"pypi","name":"Django","version":"3.2.0rc1"})",            true  },
    { R"({"ecosystem":"npm","name":"lodash","version":"1.x-beta"})",             true  },
    { R"({"ecosystem":"npm","name":"lodash","version":"x1"})",                   true  },
    { R"("lodash")",                                                             false },
    { R"(["npm","lodash","4.17.20"])",                                           false },
    { R"(1)",                                                                    false },
    { R"({"ecosystem":"npm","name":"lodash"})",                                  false },
    { R"({"ecosystem":"npm","version":"4.17.20"})",                              false },
    { R"({"name":"lodash","version":"4.17.20"})",                                false },
    { R"({"ecosystem":"npm","name":"lodash","version":"4.17.20","purl":"x"})",   false },
    { R"({"ecosystem":"npm","name":"lodash","version":"4.17.20",})",            false },
    { R"({"ecosystem":"npm","name":"lodash","version":"4.17.20" 1})",           false },
    { R"({"ecosystem":"npm","name":"lodash","name":"x","version":"4.17.20"})",   false },
    { R"({"ecosystem":"npm","name":"lodash","version":4})",                      false },
    { R"({"ecosystem":"npm","name":null,"version":"4.17.20"})",                  false },
    { R"({"ecosystem":"deb","name":"lodash","version":"4.17.20"})",              false },
    { R"({"ecosystem":"npm","name":"","version":"4.17.20"})",                    false },
    { R"({"ecosystem":"npm","name":"lo dash","version":"4.17.20"})",             false },
    { R"({"ecosystem":"npm","name":"lo\ndash","version":"4.17.20"})",            false },
    { R"({"ecosystem":"npm","name":"lodash","version":""})",                     false },
    { R"({"ecosystem":"npm","name":"lodash","version":"^4.17.20"})",             false },
    { R"({"ecosystem":"npm","name":"lodash","version":"~4.17"})",                false },
    { R"({"ecosystem":"PyPI","name":"django","version":">=3.2"})",               false },
    { R"({"ecosystem":"npm","name":"lodash","version":"4.x"})",                  false },
    { R"({"ecosystem":"npm","name":"lodash","version":"4.17.X"})",               false },
    { R"({"ecosystem":"npm","name":"lodash","version":"*"})",                    false },
    { R"({"ecosystem":"npm","name":"lodash","version":"1 - 2"})",                false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    PACKAGECHECKBULKItem_t item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isKept, endpoint_tryReadPackageItem(static_spanOfText(cases[i].mp_element), &item), cases[i].mp_element);
  }

  PACKAGECHECKBULKItem_t item;
  TEST_ASSERT_TRUE(endpoint_tryReadPackageItem(static_spanOfText("{\"ecosystem\":\"npm\",\"name\":\"lo\\u0064ash\",\"version\":\"4.17.20\"}"), &item));
  TEST_ASSERT_EQUAL_STRING("lodash", item.ma_packageName);
  TEST_ASSERT_FALSE(endpoint_tryReadPackageItem(static_spanOfText("{\"ecosystem\":\"npm\",\"name\":\"lo\\ud800ash\",\"version\":\"4.17.20\"}"), &item));
  TEST_ASSERT_FALSE(endpoint_tryReadPackageItem(static_spanOfText("{\"ecosystem\":\"npm\",\"name\":\"lo\\u0000dash\",\"version\":\"4.17.20\"}"), &item));
  TEST_ASSERT_FALSE(endpoint_tryReadPackageItem(static_spanOfText("{\"ecosystem\":\"npm\",\"name\":\"lodash\\x\",\"version\":\"4.17.20\"}"), &item));
}

void test_tryReadPackageItem_takes_a_name_and_a_version_at_their_limits(void)
{
  static char element[1024];
  static char text[PACKAGECHECK_NAME_MAX_LEN + 2];
  PACKAGECHECKBULKItem_t item;
  for (size_t len = PACKAGECHECK_NAME_MAX_LEN; len <= PACKAGECHECK_NAME_MAX_LEN + 1; len++)
  {
    memset(text, 'n', len);
    text[len] = '\0';
    snprintf(element, sizeof(element), R"({"ecosystem":"npm","name":"%s","version":"1.0.0"})", text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(len == PACKAGECHECK_NAME_MAX_LEN, endpoint_tryReadPackageItem(static_spanOfText(element), &item), "name");
  }
  for (size_t len = PACKAGECHECK_VERSION_MAX_LEN; len <= PACKAGECHECK_VERSION_MAX_LEN + 1; len++)
  {
    memset(text, '1', len);
    text[len] = '\0';
    snprintf(element, sizeof(element), R"({"ecosystem":"npm","name":"lodash","version":"%s"})", text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(len == PACKAGECHECK_VERSION_MAX_LEN, endpoint_tryReadPackageItem(static_spanOfText(element), &item), "version");
  }
}

static EndpointGateResult_t static_readPackagesOnBothTransports(const char* object, EndpointAnyParams_t* params_out)
{
  const Endpoint_t*    row         = static_packageRow();
  EndpointAnyParams_t  mcp_params;
  EndpointGateResult_t rest_result = endpoint_restBulkBodyGate(row, object, params_out, row->m_paramsSize);
  EndpointGateResult_t mcp_result  = endpoint_mcpArgsGate(row, static_spanOfText(object), &mcp_params, row->m_paramsSize);
  TEST_ASSERT_EQUAL_INT_MESSAGE(rest_result.m_status, mcp_result.m_status, object);
  if (rest_result.m_status == ENDPOINT_GATE_OK)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(params_out->m_packageCheckBulk.m_itemCount, mcp_params.m_packageCheckBulk.m_itemCount, object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(params_out->m_packageCheckBulk.m_skippedItemCount, mcp_params.m_packageCheckBulk.m_skippedItemCount, object);
  }
  if (rest_result.m_status == ENDPOINT_GATE_REJECT_ITEMS_REPEATED)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(rest_result.m_duplicateItemIndex, mcp_result.m_duplicateItemIndex, object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rest_result.m_originalItemIndex, mcp_result.m_originalItemIndex, object);
  }
  return rest_result;
}

void test_package_gates_keep_three_packages_and_skip_two_elements(void)
{
  const char* items =
    R"([{"ecosystem":"npm","name":"lodash","version":"4.17.20"},"x",)"
    R"({"ecosystem":"PyPI","name":"django","version":"3.2.0"},)"
    R"({"ecosystem":"npm","name":"express","version":"^4.17.1"},)"
    R"({"ecosystem":"Go","name":"golang.org/x/net","version":"v0.1.0"}])";
  static char object[1024];
  snprintf(object, sizeof(object), R"({"items":%s})", items);

  EndpointAnyParams_t params;
  memset(&params, 0x5A, sizeof(params));
  EndpointGateResult_t result = static_readPackagesOnBothTransports(object, &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(3, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(2, params.m_packageCheckBulk.m_skippedItemCount);
  TEST_ASSERT_EQUAL_INT(0, params.m_packageCheckBulk.m_notProcessedItemCount);
  TEST_ASSERT_EQUAL_size_t(strlen(items), params.m_packageCheckBulk.m_itemArraySpan.m_len);
  TEST_ASSERT_EQUAL_MEMORY(items, params.m_packageCheckBulk.m_itemArraySpan.mp_start, strlen(items));
}

void test_package_gates_refuse_a_repeated_package(void)
{
  static const struct {
    const char* mp_items;
    int         m_duplicate;
    int         m_original;
  } repeats[] = {
    { R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"NPM","name":"a","version":"1.0.0"}])", 1, 0 },
    { R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"npm","name":"b","version":"1.0.0"},{"ecosystem":"npm","name":"a","version":"1.0.0"}])", 2, 0 },
    { R"(["x",{"ecosystem":"npm","name":"a","version":"1.0.0"},"x",{"ecosystem":"npm","name":"a","version":"1.0.0"}])", 3, 1 },
    { R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"npm","name":"b","version":"2.0.0"},{"ecosystem":"npm","name":"b","version":"2.0.0"}])", 2, 1 },
  };
  static const char* const distinct[] = {
    R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"npm","name":"A","version":"1.0.0"}])",
    R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"npm","name":"a","version":"1.0.1"}])",
    R"([{"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"PyPI","name":"a","version":"1.0.0"}])",
    R"([{"ecosystem":"npm","name":"ab","version":"1.0.0"},{"ecosystem":"npm","name":"a","version":"b1.0.0"}])",
    R"([{"ecosystem":"npm","name":"a","version":"^1"},{"ecosystem":"npm","name":"a","version":"^1"}])",
  };
  static char object[1024];
  EndpointAnyParams_t params;
  for (size_t i = 0; i < sizeof(repeats) / sizeof(repeats[0]); i++)
  {
    snprintf(object, sizeof(object), R"({"items":%s})", repeats[i].mp_items);
    EndpointGateResult_t result = static_readPackagesOnBothTransports(object, &params);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_ITEMS_REPEATED, result.m_status, object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(repeats[i].m_duplicate, result.m_duplicateItemIndex, object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(repeats[i].m_original, result.m_originalItemIndex, object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_refusedParamIndex, object);
  }
  for (size_t i = 0; i < sizeof(distinct) / sizeof(distinct[0]); i++)
  {
    snprintf(object, sizeof(object), R"({"items":%s})", distinct[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, static_readPackagesOnBothTransports(object, &params).m_status, object);
  }
}

static size_t static_writePackageObject(char* object, size_t object_size, int item_count, size_t pad_count)
{
  int used = snprintf(object, object_size, R"({"items":[)");
  for (int k = 0; k < item_count; k++)
    used += snprintf(object + used, object_size - (size_t)used, R"(%s{"ecosystem":"npm","name":"p%d","version":"1.0.0"})", k == 0 ? "" : ",", k);
  TEST_ASSERT_TRUE((size_t)used + pad_count + 3 <= object_size);
  memset(object + used, ' ', pad_count);
  used += (int)pad_count;
  used += snprintf(object + used, object_size - (size_t)used, "]}");
  return (size_t)used;
}

void test_package_gates_take_500_packages_and_refuse_501(void)
{
  static char object[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE];
  EndpointAnyParams_t params;

  static_writePackageObject(object, sizeof(object), PACKAGECHECKBULK_MAX_ITEMS, 0);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, static_readPackagesOnBothTransports(object, &params).m_status);
  TEST_ASSERT_EQUAL_INT(PACKAGECHECKBULK_MAX_ITEMS, params.m_packageCheckBulk.m_itemCount);

  static_writePackageObject(object, sizeof(object), PACKAGECHECKBULK_MAX_ITEMS + 1, 0);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY, static_readPackagesOnBothTransports(object, &params).m_status);
}

void test_package_gates_take_an_object_shorter_than_64_KiB(void)
{
  static char object[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE + 1];
  EndpointAnyParams_t params;
  size_t unpadded_len = static_writePackageObject(object, sizeof(object), 3, 0);
  for (size_t object_len = PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE - 1; object_len <= PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE; object_len++)
  {
    TEST_ASSERT_EQUAL_size_t(object_len, static_writePackageObject(object, sizeof(object), 3, object_len - unpadded_len));
    EndpointGateStatus_t expected = object_len < PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE ? ENDPOINT_GATE_OK : ENDPOINT_GATE_REJECT_BODY_TOO_LARGE;
    TEST_ASSERT_EQUAL_INT(expected, static_readPackagesOnBothTransports(object, &params).m_status);
  }

  int package_rows = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    bool is_package_row = strcmp(endpoints[i].mp_httpPath, "/package_check_bulk") == 0 || strcmp(endpoints[i].mp_httpPath, "/watchlist_edit") == 0;
    TEST_ASSERT_EQUAL_size_t_MESSAGE(is_package_row ? PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE : ENDPOINT_JSON_OBJECT_BUF_SIZE, endpoint_jsonObjectSizeLimit(&endpoints[i]), endpoints[i].mp_httpPath);
    package_rows += is_package_row;
  }
  TEST_ASSERT_EQUAL_INT(2, package_rows);
}

void test_package_price_counts_the_kept_packages_and_the_cut_keeps_the_first(void)
{
  const Endpoint_t*   row = static_packageRow();
  EndpointAnyParams_t params;
  static const unsigned int charges[]          = { ENDPOINT_FULL_CHARGE, 2, 0 };
  static const int          kept_counts[]      = { 5, 2, 0 };
  static const int          not_processed[]    = { 0, 3, 5 };
  for (size_t i = 0; i < sizeof(charges) / sizeof(charges[0]); i++)
  {
    memset(&params, 0, sizeof(params));
    params.m_packageCheckBulk.m_itemCount        = 5;
    params.m_packageCheckBulk.m_skippedItemCount = 2;
    if (i == 0)
    {
      TEST_ASSERT_EQUAL_UINT(5, endpoint_price(row, ENDPOINT_GATE_OK, &params, row->m_paramsSize));
      TEST_ASSERT_EQUAL_UINT(1, endpoint_price(row, ENDPOINT_GATE_REJECT_ITEMS_REPEATED, &params, row->m_paramsSize));
    }
    endpoint_limitWorkToCharge(row, &params, charges[i]);
    TEST_ASSERT_EQUAL_INT(kept_counts[i], params.m_packageCheckBulk.m_itemCount);
    TEST_ASSERT_EQUAL_INT(not_processed[i], params.m_packageCheckBulk.m_notProcessedItemCount);
    TEST_ASSERT_EQUAL_INT(2, params.m_packageCheckBulk.m_skippedItemCount);
    if (charges[i] == 2)
      TEST_ASSERT_EQUAL_UINT(2, endpoint_price(row, ENDPOINT_GATE_OK, &params, row->m_paramsSize));
  }
  TEST_ASSERT_EQUAL_INT(RL_KEY_CREDIT_LIMIT, PACKAGECHECKBULK_MAX_ITEMS);
}

void test_writeGateRefusalMessage_answers_fallback_for_a_refusal_with_no_parameter(void)
{
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(lookup);
  TEST_ASSERT_TRUE(lookup->m_paramCount > 0);
  const EndpointGateResult_t refusals[] = {
    { .m_status = ENDPOINT_GATE_REJECT_BODY,    .m_refusedParamIndex = -1 },
    { .m_status = ENDPOINT_GATE_OK,             .m_refusedParamIndex = -1 },
    { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = -1 },
    { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = lookup->m_paramCount },
    { .m_status = ENDPOINT_GATE_REJECT_BODY,    .m_refusedParamIndex = 0 },
  };
  for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++)
  {
    char message[ENDPOINT_MESSAGE_BUF_SIZE] = "untouched";
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_REFUSAL_MESSAGE_FALLBACK, endpoint_writeGateRefusalMessage(lookup, refusals[i], message, sizeof(message)), message);
    TEST_ASSERT_EQUAL_STRING(ENDPOINT_GATE_FALLBACK_REFUSAL_MESSAGE, message);
  }

  char message[ENDPOINT_MESSAGE_BUF_SIZE] = "";
  const EndpointGateResult_t missing = { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = 0 };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(lookup, missing, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("missing CVE ID", message);
}

void test_max_body_byte_count_is_16_mib(void)
{
  TEST_ASSERT_EQUAL_INT(16777216, ENDPOINT_MAX_BODY_BYTE_COUNT);
}

void test_a_bytes_param_is_read_from_the_raw_body_alone(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      bool is_bytes    = param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_BYTES;
      bool is_raw_body = (param->m_sources & ENDPOINT_PARAM_SRC_REST_RAW_BODY) != 0;
      TEST_ASSERT_EQUAL_INT_MESSAGE(is_bytes, is_raw_body, param->mp_spec->mp_name);
      if (!is_raw_body)
        continue;
      TEST_ASSERT_EQUAL_UINT_MESSAGE(ENDPOINT_PARAM_SRC_REST_RAW_BODY, param->m_sources, param->mp_spec->mp_name);
      for (int k = 0; k < endpoint->m_paramCount; k++)
      {
        if (k != j)
          TEST_ASSERT_EQUAL_UINT_MESSAGE(ENDPOINT_PARAM_SRC_REST_HEADER, endpoint->mp_params[k].m_sources, endpoint->mp_httpPath);
      }
    }
  }
}

void test_raw_body_rows_are_image_inspect_and_the_two_webhooks(void)
{
  int image_row_count       = 0;
  int webhook_row_count     = 0;
  int nowpayments_row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (!endpoint_hasRawBodyParam(endpoint))
      continue;
    TEST_ASSERT_FALSE(endpoint->m_hasPathSegment);
    TEST_ASSERT_EQUAL_STRING("POST", endpoint->ma_allowedMethods[0]);
    TEST_ASSERT_NULL(endpoint->ma_allowedMethods[1]);
    TEST_ASSERT_NULL(endpoint->mp_mcpToolName);
    TEST_ASSERT_FALSE(endpoint->m_isMcpEndpoint);
    if (strcmp(endpoint->mp_httpPath, "/webhook_lemonsqueezy") == 0)
    {
      webhook_row_count++;
      continue;
    }
    if (strcmp(endpoint->mp_httpPath, "/webhook_nowpayments") == 0)
    {
      nowpayments_row_count++;
      continue;
    }
    image_row_count++;
    TEST_ASSERT_EQUAL_STRING("/image_inspect", endpoint->mp_httpPath);
    TEST_ASSERT_EQUAL_INT(1, endpoint->m_paramCount);
    const EndpointParam_t* param = &endpoint->mp_params[0];
    TEST_ASSERT_EQUAL_STRING("image", param->mp_spec->mp_name);
    TEST_ASSERT_TRUE(param->m_isRequired);
    TEST_ASSERT_NULL(param->mp_mcpArgDescription);
    TEST_ASSERT_EQUAL_size_t(offsetof(IMAGEINSPECTParams_t, m_image), param->m_offset);
    TEST_ASSERT_EQUAL_size_t(sizeof(IMAGEINSPECTParams_t), endpoint->m_paramsSize);
    TEST_ASSERT_EQUAL_UINT(2, endpoint->m_creditCost);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, endpoint->m_costRule);
    TEST_ASSERT_FALSE(endpoint->m_isDbRequired);
    TEST_ASSERT_FALSE(endpoint->m_callsUpstream);
    TEST_ASSERT_FALSE(endpoint->m_readsCreditBudget);
  }
  TEST_ASSERT_EQUAL_INT(1, image_row_count);
  TEST_ASSERT_EQUAL_INT(1, webhook_row_count);
  TEST_ASSERT_EQUAL_INT(1, nowpayments_row_count);
}

void test_webhook_nowpayments_row_reads_a_raw_body_and_its_signature(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/webhook_nowpayments", NULL);
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("POST", row->ma_allowedMethods[0]);
  TEST_ASSERT_NULL(row->ma_allowedMethods[1]);
  TEST_ASSERT_EQUAL_UINT(0, row->m_creditCost);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, row->m_costRule);
  TEST_ASSERT_TRUE(row->m_isDbRequired);
  TEST_ASSERT_NULL(row->mp_mcpToolName);
  TEST_ASSERT_EQUAL_INT(2, row->m_paramCount);
  TEST_ASSERT_EQUAL_size_t(sizeof(WEBHOOKNOWPAYMENTSParams_t), row->m_paramsSize);

  const EndpointParam_t* body = &row->mp_params[0];
  TEST_ASSERT_EQUAL_STRING("body", body->mp_spec->mp_name);
  TEST_ASSERT_TRUE(body->m_isRequired);
  TEST_ASSERT_EQUAL_size_t(65536, BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT, endpoint_rawBodyByteLimit(row));
  TEST_ASSERT_EQUAL_size_t(BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT, body->mp_spec->m_maxLen);
  TEST_ASSERT_EQUAL_size_t(offsetof(WEBHOOKNOWPAYMENTSParams_t, m_body), body->m_offset);

  const EndpointParam_t* signature = &row->mp_params[1];
  TEST_ASSERT_EQUAL_STRING("x-nowpayments-sig", signature->mp_spec->mp_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_SRC_REST_HEADER, signature->m_sources);
  TEST_ASSERT_FALSE(signature->m_isRequired);
  TEST_ASSERT_EQUAL_size_t(128, BILLING_NOWPAYMENTS_SIGNATURE_LEN);
  TEST_ASSERT_EQUAL_size_t(BILLING_NOWPAYMENTS_SIGNATURE_LEN, signature->mp_spec->m_maxLen);
  TEST_ASSERT_EQUAL_size_t(offsetof(WEBHOOKNOWPAYMENTSParams_t, ma_signature), signature->m_offset);
  TEST_ASSERT_EQUAL_size_t(BILLING_NOWPAYMENTS_SIGNATURE_LEN + 1, signature->m_size);
}

void test_webhook_lemonsqueezy_row_reads_a_raw_body_and_its_signature(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/webhook_lemonsqueezy", NULL);
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_UINT(0, row->m_creditCost);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, row->m_costRule);
  TEST_ASSERT_TRUE(row->m_isDbRequired);
  TEST_ASSERT_FALSE(row->m_callsUpstream);
  TEST_ASSERT_FALSE(row->m_readsCreditBudget);
  TEST_ASSERT_NULL(row->mp_notFoundMessage);
  TEST_ASSERT_EQUAL_INT(2, row->m_paramCount);
  TEST_ASSERT_EQUAL_size_t(sizeof(WEBHOOKLEMONSQUEEZYParams_t), row->m_paramsSize);

  const EndpointParam_t* body = &row->mp_params[0];
  TEST_ASSERT_EQUAL_STRING("body", body->mp_spec->mp_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_TYPE_BYTES, body->mp_spec->m_type);
  TEST_ASSERT_EQUAL_UINT(ENDPOINT_PARAM_SRC_REST_RAW_BODY, body->m_sources);
  TEST_ASSERT_TRUE(body->m_isRequired);
  TEST_ASSERT_EQUAL_size_t(65536, BILLING_LEMONSQUEEZY_BODY_MAX_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(BILLING_LEMONSQUEEZY_BODY_MAX_BYTE_COUNT, body->mp_spec->m_maxLen);
  TEST_ASSERT_EQUAL_size_t(BILLING_LEMONSQUEEZY_BODY_MAX_BYTE_COUNT, endpoint_rawBodyByteLimit(row));
  TEST_ASSERT_TRUE(endpoint_rawBodyByteLimit(row) <= ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(offsetof(WEBHOOKLEMONSQUEEZYParams_t, m_body), body->m_offset);

  const EndpointParam_t* signature = &row->mp_params[1];
  TEST_ASSERT_EQUAL_STRING("X-Signature", signature->mp_spec->mp_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_TYPE_STRING, signature->mp_spec->m_type);
  TEST_ASSERT_EQUAL_UINT(ENDPOINT_PARAM_SRC_REST_HEADER, signature->m_sources);
  TEST_ASSERT_FALSE(signature->m_isRequired);
  TEST_ASSERT_EQUAL_size_t(64, BILLING_LEMONSQUEEZY_SIGNATURE_LEN);
  TEST_ASSERT_EQUAL_size_t(BILLING_LEMONSQUEEZY_SIGNATURE_LEN, signature->mp_spec->m_maxLen);
  TEST_ASSERT_NULL(signature->mp_spec->m_validatorFunction);
  TEST_ASSERT_EQUAL_size_t(offsetof(WEBHOOKLEMONSQUEEZYParams_t, ma_signature), signature->m_offset);
  TEST_ASSERT_EQUAL_size_t(BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1, signature->m_size);
}

void test_api_key_claim_row_reads_an_order_id_from_the_body(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/api_key_claim", NULL);
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("POST", row->ma_allowedMethods[0]);
  TEST_ASSERT_NULL(row->ma_allowedMethods[1]);
  TEST_ASSERT_NULL(row->mp_mcpToolName);
  TEST_ASSERT_EQUAL_UINT(0, row->m_creditCost);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, row->m_costRule);
  TEST_ASSERT_TRUE(row->m_isDbRequired);
  TEST_ASSERT_FALSE(row->m_callsUpstream);
  TEST_ASSERT_FALSE(row->m_readsCreditBudget);
  TEST_ASSERT_EQUAL_STRING("no paid order has this order_id yet", row->mp_notFoundMessage);
  TEST_ASSERT_EQUAL_INT(1, row->m_paramCount);
  TEST_ASSERT_EQUAL_size_t(sizeof(APIKEYCLAIMParams_t), row->m_paramsSize);

  const EndpointParam_t* param = &row->mp_params[0];
  TEST_ASSERT_EQUAL_STRING("order_id", param->mp_spec->mp_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_PARAM_TYPE_STRING, param->mp_spec->m_type);
  TEST_ASSERT_EQUAL_UINT(ENDPOINT_PARAM_SRC_REST_BODY, param->m_sources);
  TEST_ASSERT_TRUE(param->m_isRequired);
  TEST_ASSERT_EQUAL_size_t(36, VALIDATE_UUID_LEN);
  TEST_ASSERT_EQUAL_size_t(VALIDATE_UUID_LEN, param->mp_spec->m_maxLen);
  TEST_ASSERT_TRUE(param->mp_spec->m_validatorFunction == validate_uuid);
  TEST_ASSERT_EQUAL_STRING("order_id must be a UUID: 36 lower-case characters with hyphens", param->mp_spec->mp_message);
  TEST_ASSERT_EQUAL_size_t(offsetof(APIKEYCLAIMParams_t, ma_orderId), param->m_offset);
}

void test_crypto_checkout_row_takes_post_and_no_param(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/crypto_checkout", NULL);
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("POST", row->ma_allowedMethods[0]);
  TEST_ASSERT_NULL(row->ma_allowedMethods[1]);
  TEST_ASSERT_FALSE(row->m_hasPathSegment);
  TEST_ASSERT_NULL(row->mp_mcpToolName);
  TEST_ASSERT_EQUAL_UINT(1, row->m_creditCost);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, row->m_costRule);
  TEST_ASSERT_FALSE(row->m_isPayable);
  TEST_ASSERT_EQUAL_INT(0, row->m_paramCount);
  TEST_ASSERT_NULL(row->mp_params);
  TEST_ASSERT_EQUAL_size_t(0, row->m_paramsSize);
  TEST_ASSERT_TRUE(row->m_runFunction == endpoint_CRYPTOCHECKOUTRun);
  TEST_ASSERT_FALSE(row->m_isDbRequired);
  TEST_ASSERT_TRUE(row->m_callsUpstream);
  TEST_ASSERT_FALSE(row->m_readsCreditBudget);
  TEST_ASSERT_FALSE(endpoint_hasRawBodyParam(row));
}

void test_crypto_checkout_gate_reads_no_param_and_ignores_the_body(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/crypto_checkout", NULL);
  TEST_ASSERT_NOT_NULL(row);
  EndpointAnyParams_t params;
  EndpointRestInput_t input = { .mp_pathSegment = NULL, .mp_query = "" };

  EndpointGateResult_t result = endpoint_restRequestGate(row, &input, &params, row->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);

  static const unsigned char body[] = "{not json";
  input.m_body.mp_bytes    = body;
  input.m_body.m_byteCount = sizeof(body) - 1;
  result = endpoint_restRequestGate(row, &input, &params, row->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);

  input.m_body.mp_bytes    = NULL;
  input.m_body.m_byteCount = 0;
  input.mp_query           = "x=1";
  result = endpoint_restRequestGate(row, &input, &params, row->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, result.m_status);
}

void test_restRequestGate_points_the_image_at_its_body(void)
{
  const Endpoint_t* image = endpoint_findByHttpPath("/image_inspect", NULL);
  TEST_ASSERT_NOT_NULL(image);
  static const char body[] = "ab\0cd";
  EndpointAnyParams_t params;
  memset(&params, 0x5A, sizeof(params));
  EndpointGateResult_t result = endpoint_restRequestGate(image, REST_INPUT(NULL, "", body, 5), &params, image->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);
  TEST_ASSERT_TRUE(params.m_imageInspect.m_image.mp_bytes == (const unsigned char*)body);
  TEST_ASSERT_EQUAL_size_t(5, params.m_imageInspect.m_image.m_byteCount);

  memset(&params, 0x5A, sizeof(params));
  result = endpoint_restRequestGate(image, REST_INPUT(NULL, "", NULL, 0), &params, image->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);
  unsigned char untouched[sizeof(IMAGEINSPECTParams_t)];
  memset(untouched, 0x5A, sizeof(untouched));
  TEST_ASSERT_EQUAL_MEMORY(untouched, &params, sizeof(untouched));
}

typedef struct {
  double             m_before;
  EndpointByteSpan_t m_bytes;
} TestRawBodyParams_t;

static const EndpointParamSpec_t TEST_SPEC_RAW_BODY = {
  .mp_name              = "bytes",
  .m_type               = ENDPOINT_PARAM_TYPE_BYTES,
};

static const EndpointParam_t TEST_OPTIONAL_RAW_BODY_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_RAW_BODY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_RAW_BODY,
    .m_isRequired         = false,
    .m_offset             = offsetof(TestRawBodyParams_t, m_bytes),
    .m_size               = sizeof(EndpointByteSpan_t),
  },
};

void test_restRequestGate_writes_an_optional_raw_body_at_its_offset(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_raw_body",
    .ma_allowedMethods    = {"POST", NULL},
    .mp_params            = TEST_OPTIONAL_RAW_BODY_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = sizeof(TestRawBodyParams_t),
  };
  unsigned char untouched[sizeof(double)];
  memset(untouched, 0x5A, sizeof(untouched));

  static const char body[] = "xyz";
  TestRawBodyParams_t params;
  memset(&params, 0x5A, sizeof(params));
  EndpointGateResult_t result = endpoint_restRequestGate(&endpoint, REST_INPUT(NULL, "", body, 3), &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);
  TEST_ASSERT_TRUE(params.m_bytes.mp_bytes == (const unsigned char*)body);
  TEST_ASSERT_EQUAL_size_t(3, params.m_bytes.m_byteCount);
  TEST_ASSERT_EQUAL_MEMORY(untouched, &params.m_before, sizeof(untouched));

  memset(&params, 0x5A, sizeof(params));
  result = endpoint_restRequestGate(&endpoint, REST_INPUT(NULL, "", NULL, 0), &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);
  TEST_ASSERT_NULL(params.m_bytes.mp_bytes);
  TEST_ASSERT_EQUAL_size_t(0, params.m_bytes.m_byteCount);
  TEST_ASSERT_EQUAL_MEMORY(untouched, &params.m_before, sizeof(untouched));

  TEST_ASSERT_TRUE(endpoint_hasRawBodyParam(&endpoint));
}

#define TEST_HEADER_MAX_LEN 8

typedef struct {
  double             m_before;
  char               ma_signature[TEST_HEADER_MAX_LEN + 1];
  char               ma_q[TEST_HEADER_MAX_LEN + 1];
  EndpointByteSpan_t m_bytes;
} TestHeaderParams_t;

static const EndpointParamSpec_t TEST_SPEC_SIGNATURE_HEADER = {
  .mp_name              = "X-Signature",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = TEST_HEADER_MAX_LEN,
};

static const EndpointParamSpec_t TEST_SPEC_Q = {
  .mp_name              = "q",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = TEST_HEADER_MAX_LEN,
};

static const EndpointParamSpec_t TEST_SPEC_HEADER_RAW_BODY = {
  .mp_name              = "body",
  .m_type               = ENDPOINT_PARAM_TYPE_BYTES,
  .m_maxLen             = 64,
};

static const EndpointParam_t TEST_HEADER_QUERY_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_SIGNATURE_HEADER,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = true,
    .m_offset             = offsetof(TestHeaderParams_t, ma_signature),
    .m_size               = TEST_HEADER_MAX_LEN + 1,
  },
  {
    .mp_spec              = &TEST_SPEC_Q,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY,
    .m_isRequired         = false,
    .m_offset             = offsetof(TestHeaderParams_t, ma_q),
    .m_size               = TEST_HEADER_MAX_LEN + 1,
  },
};

static const EndpointParam_t TEST_OPTIONAL_HEADER_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_SIGNATURE_HEADER,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = false,
    .m_offset             = offsetof(TestHeaderParams_t, ma_signature),
    .m_size               = TEST_HEADER_MAX_LEN + 1,
  },
};

static const EndpointParam_t TEST_HEADER_RAW_BODY_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_HEADER_RAW_BODY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_RAW_BODY,
    .m_isRequired         = true,
    .m_offset             = offsetof(TestHeaderParams_t, m_bytes),
    .m_size               = sizeof(EndpointByteSpan_t),
  },
  {
    .mp_spec              = &TEST_SPEC_SIGNATURE_HEADER,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = true,
    .m_offset             = offsetof(TestHeaderParams_t, ma_signature),
    .m_size               = TEST_HEADER_MAX_LEN + 1,
  },
};

static const Endpoint_t TEST_HEADER_QUERY_ROW = {
  .mp_httpPath          = "/test_header_query",
  .ma_allowedMethods    = {"GET", NULL},
  .mp_params            = TEST_HEADER_QUERY_PARAMS,
  .m_paramCount         = 2,
  .m_paramsSize         = sizeof(TestHeaderParams_t),
};

static const Endpoint_t TEST_OPTIONAL_HEADER_ROW = {
  .mp_httpPath          = "/test_optional_header",
  .ma_allowedMethods    = {"GET", NULL},
  .mp_params            = TEST_OPTIONAL_HEADER_PARAMS,
  .m_paramCount         = 1,
  .m_paramsSize         = sizeof(TestHeaderParams_t),
};

static const Endpoint_t TEST_HEADER_RAW_BODY_ROW = {
  .mp_httpPath          = "/test_header_raw_body",
  .ma_allowedMethods    = {"POST", NULL},
  .mp_params            = TEST_HEADER_RAW_BODY_PARAMS,
  .m_paramCount         = 2,
  .m_paramsSize         = sizeof(TestHeaderParams_t),
};

#define HEADER_INPUT(query, body, body_len, headers, header_count) \
  (&(EndpointRestInput_t){ .mp_query = (query), .m_body = { (const unsigned char*)(body), (body_len) }, .mp_headers = (headers), .m_headerCount = (header_count) })

#define HEADER(name, value) { (name), sizeof(name) - 1, (value), sizeof(value) - 1 }

static EndpointGateResult_t static_readHeaderRow(const Endpoint_t* row, const EndpointRestInput_t* input, TestHeaderParams_t* params_out)
{
  memset(params_out, 0x5A, sizeof(*params_out));
  return endpoint_restRequestGate(row, input, params_out, sizeof(*params_out));
}

void test_restRequestGate_reads_a_header_param_by_its_name_in_any_case(void)
{
  struct phr_header headers[] = { HEADER("X-Signature-Extra", "no"), HEADER("X-Signatur", "no"), HEADER("x-signature", "abc") };
  TestHeaderParams_t params;
  EndpointGateResult_t result = static_readHeaderRow(&TEST_HEADER_QUERY_ROW, HEADER_INPUT("", NULL, 0, headers, 3), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);
  TEST_ASSERT_EQUAL_STRING("abc", params.ma_signature);
  unsigned char untouched[sizeof(double)];
  memset(untouched, 0x5A, sizeof(untouched));
  TEST_ASSERT_EQUAL_MEMORY(untouched, &params.m_before, sizeof(untouched));
}

void test_restRequestGate_refuses_a_missing_required_header(void)
{
  struct phr_header other[] = { HEADER("Accept", "*/*") };
  struct phr_header empty[] = { HEADER("X-Signature", "") };
  TestHeaderParams_t params;

  EndpointGateResult_t result = static_readHeaderRow(&TEST_HEADER_QUERY_ROW, HEADER_INPUT("", NULL, 0, other, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);
  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&TEST_HEADER_QUERY_ROW, result, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("X-Signature is required", message);

  result = static_readHeaderRow(&TEST_HEADER_QUERY_ROW, HEADER_INPUT("", NULL, 0, empty, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, other, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("", params.ma_signature);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, NULL, 0), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("", params.ma_signature);
}

void test_restRequestGate_refuses_a_header_sent_twice(void)
{
  struct phr_header twice[]       = { HEADER("X-Signature", "a"), HEADER("Accept", "*/*"), HEADER("x-SIGNATURE", "a") };
  struct phr_header folded[]      = { HEADER("X-Signature", "a"), { NULL, 0, "b", 1 } };
  struct phr_header other_fold[]  = { HEADER("Accept", "*/*"), { NULL, 0, "b", 1 }, HEADER("X-Signature", "a") };
  TestHeaderParams_t params;

  EndpointGateResult_t result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, twice, 3), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);
  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&TEST_OPTIONAL_HEADER_ROW, result, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("X-Signature appears more than once", message);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, twice, 2), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, folded, 2), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, other_fold, 3), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("a", params.ma_signature);
}

void test_restRequestGate_refuses_a_header_longer_than_its_limit(void)
{
  struct phr_header at_limit[] = { HEADER("X-Signature", "12345678") };
  struct phr_header too_long[] = { HEADER("X-Signature", "123456789") };
  TestHeaderParams_t params;

  EndpointGateResult_t result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, at_limit, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("12345678", params.ma_signature);

  result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, too_long, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_TOOLONG, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);
  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM, endpoint_writeGateRefusalMessage(&TEST_OPTIONAL_HEADER_ROW, result, message, sizeof(message)));
  TEST_ASSERT_EQUAL_STRING("X-Signature is too long", message);
}

void test_restRequestGate_checks_a_header_value_like_a_query_value(void)
{
  struct phr_header headers[] = { HEADER("X-Signature", "a\x7f") };
  TestHeaderParams_t params;
  EndpointGateResult_t result = static_readHeaderRow(&TEST_OPTIONAL_HEADER_ROW, HEADER_INPUT("", NULL, 0, headers, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_CONTROL_CHAR, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_refusedParamIndex);
}

void test_a_header_param_is_never_read_from_the_query(void)
{
  struct phr_header headers[] = { HEADER("X-Signature", "abc") };
  TestHeaderParams_t params;

  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, endpoint_checkHttpQueryParamNames(&TEST_HEADER_QUERY_ROW, "X-Signature=abc").m_status);
  EndpointGateResult_t result = static_readHeaderRow(&TEST_HEADER_QUERY_ROW, HEADER_INPUT("X-Signature=abc", NULL, 0, headers, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, result.m_status);

  result = static_readHeaderRow(&TEST_HEADER_QUERY_ROW, HEADER_INPUT("q=xy", NULL, 0, headers, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("abc", params.ma_signature);
  TEST_ASSERT_EQUAL_STRING("xy", params.ma_q);
}

void test_a_header_param_is_never_read_from_the_mcp_arguments(void)
{
  static const char args[] = "{\"X-Signature\":\"abc\"}";
  JsonReadSpan_t args_span = { args, sizeof(args) - 1 };
  TestHeaderParams_t params;
  memset(&params, 0, sizeof(params));
  EndpointGateResult_t result = endpoint_mcpArgsGate(&TEST_OPTIONAL_HEADER_ROW, args_span, &params, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, result.m_status);
}

void test_restRequestGate_reads_a_header_param_beside_a_raw_body(void)
{
  struct phr_header headers[] = { HEADER("X-Signature", "abc") };
  static const char body[] = "a\0b";
  TestHeaderParams_t params;

  EndpointGateResult_t result = static_readHeaderRow(&TEST_HEADER_RAW_BODY_ROW, HEADER_INPUT("", body, 3, headers, 1), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("abc", params.ma_signature);
  TEST_ASSERT_TRUE(params.m_bytes.mp_bytes == (const unsigned char*)body);
  TEST_ASSERT_EQUAL_size_t(3, params.m_bytes.m_byteCount);

  result = static_readHeaderRow(&TEST_HEADER_RAW_BODY_ROW, HEADER_INPUT("", body, 3, NULL, 0), &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, result.m_status);
  TEST_ASSERT_EQUAL_INT(1, result.m_refusedParamIndex);
}

void test_every_header_param_is_a_string_read_from_the_header_alone(void)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoints[i].mp_params[j];
      if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_HEADER) == 0)
        continue;
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_PARAM_SRC_REST_HEADER, param->m_sources, param->mp_spec->mp_name);
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_PARAM_TYPE_STRING, param->mp_spec->m_type, param->mp_spec->mp_name);
      TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_maxLen > 0, param->mp_spec->mp_name);
    }
  }
}

void test_every_raw_body_spec_has_a_limit_up_to_the_max_body_byte_count(void)
{
  int raw_param_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    for (int j = 0; j < endpoints[i].m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoints[i].mp_params[j];
      if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_RAW_BODY) == 0)
        continue;
      raw_param_count++;
      TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_maxLen > 0, endpoints[i].mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(param->mp_spec->m_maxLen <= ENDPOINT_MAX_BODY_BYTE_COUNT, endpoints[i].mp_httpPath);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(param->mp_spec->m_maxLen, endpoint_rawBodyByteLimit(&endpoints[i]), endpoints[i].mp_httpPath);
    }
  }
  TEST_ASSERT_TRUE(raw_param_count > 0);
}

void test_rawBodyByteLimit_is_the_raw_spec_limit(void)
{
  const Endpoint_t* image = endpoint_findByHttpPath("/image_inspect", NULL);
  TEST_ASSERT_NOT_NULL(image);
  TEST_ASSERT_EQUAL_size_t(ENDPOINT_MAX_BODY_BYTE_COUNT, endpoint_rawBodyByteLimit(image));
  TEST_ASSERT_EQUAL_size_t(64, endpoint_rawBodyByteLimit(&TEST_HEADER_RAW_BODY_ROW));
}

void test_small_raw_body_max_byte_count_is_64_kib(void)
{
  TEST_ASSERT_EQUAL_INT(65536, ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT);
  TEST_ASSERT_TRUE(ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT < ENDPOINT_MAX_BODY_BYTE_COUNT);
}

static void static_padJsonObject(char* out, size_t len)
{
  static const char head[] = "{\"action\":\"add\"";
  static const char tail[] = "}";
  size_t head_len = sizeof(head) - 1;
  size_t tail_len = sizeof(tail) - 1;
  TEST_ASSERT_TRUE(len >= head_len + tail_len);
  memcpy(out, head, head_len);
  memset(out + head_len, ' ', len - head_len - tail_len);
  memcpy(out + len - tail_len, tail, tail_len + 1);
  TEST_ASSERT_EQUAL_size_t(len, strlen(out));
}

static int static_watchlistParamIndex(const Endpoint_t* endpoint, const char* name)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    if (strcmp(endpoint->mp_params[i].mp_spec->mp_name, name) == 0)
      return i;
  }
  TEST_FAIL_MESSAGE(name);
  return -1;
}

void test_restFieldsBodyGate_reads_what_mcpArgsGate_reads(void)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  static char longest_object[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE];
  static char too_large_object[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE + 1];
  static_padJsonObject(longest_object, sizeof(longest_object) - 1);
  static_padJsonObject(too_large_object, sizeof(too_large_object) - 1);
  const int vendor_index = static_watchlistParamIndex(edit, "vendor");
  const int clear_index  = static_watchlistParamIndex(edit, "clear");
  const int action_index = static_watchlistParamIndex(edit, "action");
  const int cvss_index   = static_watchlistParamIndex(edit, "min_cvss");
  const int cve_index    = static_watchlistParamIndex(edit, "cve_id");
  const int ep_index     = static_watchlistParamIndex(edit, "endpoint");
  const int domain_index = static_watchlistParamIndex(edit, "domain");
  const int nuclei_index = static_watchlistParamIndex(edit, "has_nuclei_template");

  const struct { const char* mp_object; EndpointGateStatus_t m_status; int m_refusedParamIndex; } cases[] = {
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"cve_id\":\"CVE-2021-44228\",\"vendor\":\"apache\",\"product\":\"log4j\",\"severity\":\"HIGH\",\"cwe_id\":\"CWE-917\",\"min_cvss\":7.5,\"min_epss\":0.25,\"in_kev\":false,\"known_ransomware\":true,\"has_nuclei_template\":true,\"domain\":\"example.com\",\"clear\":true}", ENDPOINT_GATE_OK, -1 },
    { "{}",                                       ENDPOINT_GATE_OK,                            -1 },
    { "{\"vendor\":\"\"}",                        ENDPOINT_GATE_OK,                            -1 },
    { longest_object,                             ENDPOINT_GATE_OK,                            -1 },
    { too_large_object,                           ENDPOINT_GATE_REJECT_BODY_TOO_LARGE,         -1 },
    { "{\"zz\":1}",                               ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,     -1 },
    { "{\"vendor\":\"a\",\"vendor\":\"b\"}",      ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME,   vendor_index },
    { "{\"vendor\":{}}",                          ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE,  vendor_index },
    { "{\"vendor\":[]}",                          ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE,  vendor_index },
    { "{\"clear\":false}",                        ENDPOINT_GATE_REJECT_VALUE,                  clear_index },
    { "{\"has_nuclei_template\":true}",           ENDPOINT_GATE_OK,                            -1 },
    { "{\"has_nuclei_template\":false}",          ENDPOINT_GATE_REJECT_VALUE,                  nuclei_index },
    { "{\"action\":\"drop\"}",                    ENDPOINT_GATE_REJECT_VALUE,                  action_index },
    { "{\"endpoint\":\"cve_leading\"}",           ENDPOINT_GATE_REJECT_VALUE,                  ep_index },
    { "{\"endpoint\":\"dns_takeover_check\"}",    ENDPOINT_GATE_REJECT_TOOLONG,                ep_index },
    { "{\"domain\":\"printer.local\"}",           ENDPOINT_GATE_REJECT_VALUE,                  domain_index },
    { "{\"hostname\":\"example.com\"}",           ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,     -1 },
    { "{\"min_cvss\":10.1}",                      ENDPOINT_GATE_REJECT_VALUE,                  cvss_index },
    { "{\"cve_id\":\"nope\"}",                    ENDPOINT_GATE_REJECT_VALUE,                  cve_index },
    { "{\"vendor\":\"%\"}",                       ENDPOINT_GATE_REJECT_VALUE,                  vendor_index },
    { "{\"vendor\":\"a\\nb\"}",                   ENDPOINT_GATE_REJECT_CONTROL_CHAR,           vendor_index },
    { "{\"vendor\":\"a\\u0000b\"}",               ENDPOINT_GATE_REJECT_CONTROL_CHAR,           vendor_index },
    { "{\"vendor\":\"a\\udc00b\"}",               ENDPOINT_GATE_REJECT_INVALID_UTF8,           vendor_index },
    { "{\"vendor\":\"apa\\u0063he\"}",            ENDPOINT_GATE_OK,                            -1 },
    { "{\"vendor\":5}",                           ENDPOINT_GATE_REJECT_TYPE,                   vendor_index },
    { "[1]",                                      ENDPOINT_GATE_REJECT_BODY,                   -1 },
    { "\"x\"",                                    ENDPOINT_GATE_REJECT_BODY,                   -1 },
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
  {
    EndpointAnyParams_t rest_params;
    EndpointAnyParams_t mcp_params;
    memset(&rest_params, 0x5A, sizeof(rest_params));
    memset(&mcp_params, 0x5A, sizeof(mcp_params));
    JsonReadSpan_t args_span = { cases[k].mp_object, strlen(cases[k].mp_object) };
    EndpointGateResult_t rest_gate_result = endpoint_restFieldsBodyGate(edit, cases[k].mp_object, &rest_params, edit->m_paramsSize);
    EndpointGateResult_t mcp_gate_result  = endpoint_mcpArgsGate(edit, args_span, &mcp_params, edit->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, rest_gate_result.m_status, cases[k].mp_object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, mcp_gate_result.m_status, cases[k].mp_object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_refusedParamIndex, rest_gate_result.m_refusedParamIndex, cases[k].mp_object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_refusedParamIndex, mcp_gate_result.m_refusedParamIndex, cases[k].mp_object);
    if (cases[k].m_status == ENDPOINT_GATE_OK)
      TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&mcp_params, &rest_params, sizeof(rest_params), cases[k].mp_object);
    if (k == 0)
    {
      const WATCHLISTEDITParams_t* edit_params = &rest_params.m_watchlistEdit;
      TEST_ASSERT_EQUAL_STRING("add", edit_params->ma_action);
      TEST_ASSERT_EQUAL_STRING("cve_search", edit_params->ma_endpoint);
      TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", edit_params->ma_cveId);
      TEST_ASSERT_EQUAL_STRING("apache", edit_params->ma_vendor);
      TEST_ASSERT_EQUAL_STRING("log4j", edit_params->ma_product);
      TEST_ASSERT_EQUAL_STRING("HIGH", edit_params->ma_severity);
      TEST_ASSERT_EQUAL_STRING("CWE-917", edit_params->ma_cweId);
      TEST_ASSERT_EQUAL_FLOAT(7.5, edit_params->m_minCvss);
      TEST_ASSERT_EQUAL_FLOAT(0.25, edit_params->m_minEpss);
      TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_NOT_IN_KEV, edit_params->m_inKev);
      TEST_ASSERT_TRUE(edit_params->m_knownRansomware);
      TEST_ASSERT_TRUE(edit_params->m_hasNucleiTemplate);
      TEST_ASSERT_EQUAL_STRING("example.com", edit_params->ma_domain);
      TEST_ASSERT_TRUE(edit_params->m_isWatchlistCleared);
    }
    if (k == 1)
    {
      const WATCHLISTEDITParams_t* edit_params = &rest_params.m_watchlistEdit;
      TEST_ASSERT_EQUAL_STRING("", edit_params->ma_action);
      TEST_ASSERT_EQUAL_STRING("", edit_params->ma_endpoint);
      TEST_ASSERT_EQUAL_STRING("", edit_params->ma_vendor);
      TEST_ASSERT_EQUAL_STRING("", edit_params->ma_domain);
      TEST_ASSERT_EQUAL_FLOAT(-1.0, edit_params->m_minCvss);
      TEST_ASSERT_EQUAL_FLOAT(-1.0, edit_params->m_minEpss);
      TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ANY, edit_params->m_inKev);
      TEST_ASSERT_FALSE(edit_params->m_knownRansomware);
      TEST_ASSERT_FALSE(edit_params->m_hasNucleiTemplate);
      TEST_ASSERT_FALSE(edit_params->m_isWatchlistCleared);
    }
    if (strcmp(cases[k].mp_object, "{\"has_nuclei_template\":true}") == 0)
    {
      const WATCHLISTEDITParams_t* edit_params = &rest_params.m_watchlistEdit;
      TEST_ASSERT_TRUE(edit_params->m_hasNucleiTemplate);
      TEST_ASSERT_FALSE(edit_params->m_knownRansomware);
    }
  }

  EndpointAnyParams_t params;
  memset(&params, 0x5A, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_BODY, endpoint_restFieldsBodyGate(edit, NULL, &params, edit->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_BODY, endpoint_restFieldsBodyGate(edit, "", &params, edit->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_BODY, endpoint_restFieldsBodyGate(edit, "{\"vendor\":\"a\xff" "b\"}", &params, edit->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_BODY, endpoint_restFieldsBodyGate(edit, "not json", &params, edit->m_paramsSize).m_status);
  JsonReadSpan_t bad_utf8 = { "{\"vendor\":\"a\xff" "b\"}", strlen("{\"vendor\":\"a\xff" "b\"}") };
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_INVALID_UTF8, endpoint_mcpArgsGate(edit, bad_utf8, &params, edit->m_paramsSize).m_status);

  static const char add_body[]     = "{\"action\":\"add\",\"endpoint\":\"kev_lookup\",\"cve_id\":\"CVE-2021-44228\"}";
  static const char cve_ids_body[] = "{\"cve_ids\":[\"CVE-2021-44228\"]}";
  static const char action_body[]  = "{\"action\":\"add\"}";
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_restRequestGate(edit, REST_INPUT(NULL, "", add_body, sizeof(add_body) - 1), &params, edit->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_STRING("kev_lookup", params.m_watchlistEdit.ma_endpoint);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, endpoint_restRequestGate(edit, REST_INPUT(NULL, "", cve_ids_body, sizeof(cve_ids_body) - 1), &params, edit->m_paramsSize).m_status);
  const Endpoint_t* bulk = endpoint_findByMcpName("cve_lookup_bulk");
  TEST_ASSERT_NOT_NULL(bulk);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, endpoint_restRequestGate(bulk, REST_INPUT(NULL, "", action_body, sizeof(action_body) - 1), &params, bulk->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_restRequestGate(bulk, REST_INPUT(NULL, "", cve_ids_body, sizeof(cve_ids_body) - 1), &params, bulk->m_paramsSize).m_status);
  TEST_ASSERT_EQUAL_INT(1, params.m_bulkIds.m_idCount);
}

static EndpointGateResult_t static_readWatchlistOnBothTransports(const char* object, EndpointAnyParams_t* params_out)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  EndpointAnyParams_t mcp_params;
  memset(params_out, 0x5A, sizeof(*params_out));
  memset(&mcp_params, 0x5A, sizeof(mcp_params));
  EndpointGateResult_t rest_result = endpoint_restFieldsBodyGate(edit, object, params_out, edit->m_paramsSize);
  EndpointGateResult_t mcp_result  = endpoint_mcpArgsGate(edit, static_spanOfText(object), &mcp_params, edit->m_paramsSize);
  TEST_ASSERT_EQUAL_INT_MESSAGE(rest_result.m_status, mcp_result.m_status, object);
  TEST_ASSERT_EQUAL_INT_MESSAGE(rest_result.m_refusedParamIndex, mcp_result.m_refusedParamIndex, object);
  if (rest_result.m_status == ENDPOINT_GATE_OK)
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(params_out, &mcp_params, sizeof(mcp_params), object);
  return rest_result;
}

void test_hasPackageArrayWithOtherMembers_takes_one_other_body_member(void)
{
  const EndpointParamSpec_t array_spec = { .mp_name = "packages", .m_type = ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY };
  const EndpointParamSpec_t text_spec  = { .mp_name = "action",   .m_type = ENDPOINT_PARAM_TYPE_STRING };
  const EndpointParam_t     params[]   = {
    { .mp_spec = &array_spec, .m_sources = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG },
    { .mp_spec = &text_spec,  .m_sources = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG },
    { .mp_spec = &text_spec,  .m_sources = ENDPOINT_PARAM_SRC_MCP_ARG },
  };
  Endpoint_t row;
  memset(&row, 0, sizeof(row));
  row.mp_params    = params;
  row.m_paramCount = 2;
  TEST_ASSERT_TRUE(endpoint_hasPackageArrayWithOtherMembers(&row));

  row.m_paramCount = 1;
  TEST_ASSERT_FALSE(endpoint_hasPackageArrayWithOtherMembers(&row));

  const EndpointParam_t mcp_only_params[] = { params[0], params[2] };
  row.mp_params    = mcp_only_params;
  row.m_paramCount = 2;
  TEST_ASSERT_FALSE(endpoint_hasPackageArrayWithOtherMembers(&row));
}

void test_watchlist_gates_refuse_a_missing_required_package_array(void)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  EndpointParam_t params[32];
  TEST_ASSERT_TRUE(edit->m_paramCount <= (int)(sizeof(params) / sizeof(params[0])));
  int package_index = -1;
  for (int i = 0; i < edit->m_paramCount; i++)
  {
    params[i] = edit->mp_params[i];
    if (params[i].mp_spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
    {
      params[i].m_isRequired = true;
      package_index          = i;
    }
  }
  TEST_ASSERT_TRUE(package_index >= 0);
  Endpoint_t row = *edit;
  row.mp_params  = params;

  const char*         object = R"({"action":"add"})";
  EndpointAnyParams_t any_params;
  EndpointGateResult_t rest_result = endpoint_restFieldsBodyGate(&row, object, &any_params, row.m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, rest_result.m_status);
  TEST_ASSERT_EQUAL_INT(package_index, rest_result.m_refusedParamIndex);
  EndpointGateResult_t mcp_result = endpoint_mcpArgsGate(&row, static_spanOfText(object), &any_params, row.m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_MISSING, mcp_result.m_status);
  TEST_ASSERT_EQUAL_INT(package_index, mcp_result.m_refusedParamIndex);
}

void test_watchlist_gates_read_packages_beside_the_members(void)
{
  const char* packages = R"([{"ecosystem":"npm","name":"lodash"},{"ecosystem":"PyPI","name":"django","version":"3.2.0"}])";
  static char object[512];
  snprintf(object, sizeof(object), R"({"action":"add","packages":%s,"endpoint":"package_check"})", packages);

  EndpointAnyParams_t params;
  EndpointGateResult_t result = static_readWatchlistOnBothTransports(object, &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(-1, result.m_refusedParamIndex);
  const WATCHLISTEDITParams_t* edit_params = &params.m_watchlistEdit;
  TEST_ASSERT_EQUAL_STRING("add", edit_params->ma_action);
  TEST_ASSERT_EQUAL_STRING("package_check", edit_params->ma_endpoint);
  TEST_ASSERT_EQUAL_INT(2, edit_params->m_packages.m_itemCount);
  TEST_ASSERT_EQUAL_INT(0, edit_params->m_packages.m_skippedItemCount);
  TEST_ASSERT_EQUAL_INT(0, edit_params->m_packages.m_notProcessedItemCount);
  TEST_ASSERT_EQUAL_size_t(strlen(packages), edit_params->m_packages.m_itemArraySpan.m_len);
  TEST_ASSERT_EQUAL_MEMORY(packages, edit_params->m_packages.m_itemArraySpan.mp_start, strlen(packages));

  result = static_readWatchlistOnBothTransports(R"({"action":"add"})", &params);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, params.m_watchlistEdit.m_packages.m_itemCount);
  TEST_ASSERT_EQUAL_size_t(0, params.m_watchlistEdit.m_packages.m_itemArraySpan.m_len);

  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  memset(&params, 0x5A, sizeof(params));
  result = endpoint_restRequestGate(edit, REST_INPUT(NULL, "", object, strlen(object)), &params, edit->m_paramsSize);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(2, params.m_watchlistEdit.m_packages.m_itemCount);
}

void test_watchlist_gates_check_only_the_packages_array(void)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  const int packages_index = static_watchlistParamIndex(edit, "packages");
  const int action_index   = static_watchlistParamIndex(edit, "action");
  const int vendor_index   = static_watchlistParamIndex(edit, "vendor");

  const struct {
    const char*          mp_object;
    EndpointGateStatus_t m_status;
    int                  m_refusedParamIndex;
    int                  m_elementCount;
  } cases[] = {
    { R"({"packages":[{"ecosystem":"npm","name":"a","version":"^1"}]})",                              ENDPOINT_GATE_OK,                           -1,             1 },
    { R"({"packages":[{"ecosystem":"npm","name":"a"},"x"]})",                                         ENDPOINT_GATE_OK,                           -1,             2 },
    { R"({"packages":[{"ecosystem":"nope","name":"a"},{"ecosystem":"npm"},null,3]})",                 ENDPOINT_GATE_OK,                           -1,             4 },
    { R"({"packages":[{"ecosystem":"npm","name":"a"},{"ecosystem":"NPM","name":"a"}]})",              ENDPOINT_GATE_OK,                           -1,             2 },
    { R"({"packages":"x"})",                                                                          ENDPOINT_GATE_REJECT_TYPE,                  packages_index, 0 },
    { R"({"packages":{"ecosystem":"npm","name":"a"}})",                                               ENDPOINT_GATE_REJECT_TYPE,                  packages_index, 0 },
    { R"({"packages":[]})",                                                                           ENDPOINT_GATE_REJECT_ITEMS_EMPTY,           packages_index, 0 },
    { R"({"packages":[{"ecosystem":"npm","name":"a"}],"packages":[{"ecosystem":"npm","name":"b"}]})", ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME,  packages_index, 0 },
    { R"({"action":["add"],"packages":[{"ecosystem":"npm","name":"a"}]})",                            ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE, action_index,   0 },
    { R"({"packages":["x"],"vendor":"%"})",                                                           ENDPOINT_GATE_REJECT_VALUE,                 vendor_index,   0 },
    { R"({"packages":[{"ecosystem":"npm","name":"a"}],"sbom":"app"})",                                ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME,    -1,             0 },
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
  {
    EndpointAnyParams_t params;
    EndpointGateResult_t result = static_readWatchlistOnBothTransports(cases[k].mp_object, &params);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_status, result.m_status, cases[k].mp_object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_refusedParamIndex, result.m_refusedParamIndex, cases[k].mp_object);
    if (cases[k].m_status == ENDPOINT_GATE_OK)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_elementCount, params.m_watchlistEdit.m_packages.m_itemCount, cases[k].mp_object);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, params.m_watchlistEdit.m_packages.m_skippedItemCount, cases[k].mp_object);
    }
  }
}

static size_t static_writeWatchlistPackageObject(char* object, size_t object_size, int item_count, size_t pad_count)
{
  int used = snprintf(object, object_size, R"({"packages":[)");
  for (int k = 0; k < item_count; k++)
    used += snprintf(object + used, object_size - (size_t)used, R"(%s{"ecosystem":"npm","name":"p%d"})", k == 0 ? "" : ",", k);
  TEST_ASSERT_TRUE((size_t)used + pad_count + 3 <= object_size);
  memset(object + used, ' ', pad_count);
  used += (int)pad_count;
  used += snprintf(object + used, object_size - (size_t)used, "]}");
  return (size_t)used;
}

void test_watchlist_gates_take_500_packages_in_an_object_shorter_than_64_KiB(void)
{
  static char object[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE + 1];
  EndpointAnyParams_t params;

  static_writeWatchlistPackageObject(object, sizeof(object), WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY, 0);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, static_readWatchlistOnBothTransports(object, &params).m_status);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY, params.m_watchlistEdit.m_packages.m_itemCount);

  static_writeWatchlistPackageObject(object, sizeof(object), WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY + 1, 0);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY, static_readWatchlistOnBothTransports(object, &params).m_status);

  size_t unpadded_len = static_writeWatchlistPackageObject(object, sizeof(object), 3, 0);
  for (size_t object_len = PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE - 1; object_len <= PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE; object_len++)
  {
    TEST_ASSERT_EQUAL_size_t(object_len, static_writeWatchlistPackageObject(object, sizeof(object), 3, object_len - unpadded_len));
    EndpointGateStatus_t expected = object_len < PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE ? ENDPOINT_GATE_OK : ENDPOINT_GATE_REJECT_BODY_TOO_LARGE;
    TEST_ASSERT_EQUAL_INT(expected, static_readWatchlistOnBothTransports(object, &params).m_status);
  }

  static const char head[] = R"({"packages":[{"ecosystem":"npm","name":"a"}],"vendor":")";
  for (size_t copy_len = ENDPOINT_JSON_OBJECT_BUF_SIZE - 1; copy_len <= ENDPOINT_JSON_OBJECT_BUF_SIZE; copy_len++)
  {
    size_t vendor_len = copy_len - strlen(R"({"vendor":""})");
    size_t used = (size_t)snprintf(object, sizeof(object), "%s", head);
    memset(object + used, 'a', vendor_len);
    used += vendor_len;
    snprintf(object + used, sizeof(object) - used, "\"}");
    EndpointGateStatus_t expected = copy_len < ENDPOINT_JSON_OBJECT_BUF_SIZE ? ENDPOINT_GATE_REJECT_TOOLONG : ENDPOINT_GATE_REJECT_BODY_TOO_LARGE;
    TEST_ASSERT_EQUAL_INT(expected, static_readWatchlistOnBothTransports(object, &params).m_status);
  }
}

static void static_readOnePackageElement(const char* array, WATCHLISTEDITPackageElement_t* element_out)
{
  PACKAGECHECKBULKParams_t       package_list = { .m_itemArraySpan = static_spanOfText(array), .m_itemCount = 1 };
  WATCHLISTEDITPackageElement_t* elements = NULL;
  TEST_ASSERT_TRUE_MESSAGE(endpoint_readWatchlistPackageElements(&package_list, &elements), array);
  TEST_ASSERT_NOT_NULL_MESSAGE(elements, array);
  *element_out = elements[0];
  free(elements);
}

void test_readWatchlistPackageElements_reads_every_element_with_its_problem(void)
{
  const char* array = R"([{"ecosystem":"npm","name":"lodash","version":"4.17.20"},"x",{"ecosystem":"PyPI","name":"lodash","version":"4.17.20"},)"
                      R"({"ecosystem":"NPM","name":"lodash","version":"4.17.20"},{"ecosystem":"npm","name":"lodash"},{"ecosystem":"npm","name":"lodash","version":"^4"}])";
  PACKAGECHECKBULKParams_t       package_list = { .m_itemArraySpan = static_spanOfText(array), .m_itemCount = 6 };
  WATCHLISTEDITPackageElement_t* elements = NULL;
  TEST_ASSERT_TRUE(endpoint_readWatchlistPackageElements(&package_list, &elements));
  TEST_ASSERT_NOT_NULL(elements);
  const PackageElementProblem_t expected_problems[6] = { PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT, PACKAGE_ELEMENT_PROBLEM_NONE,
                                                         PACKAGE_ELEMENT_PROBLEM_REPEATED, PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NONE };
  const int  expected_earlier[6]     = { -1, -1, -1, 0, -1, -1 };
  const bool expected_has_version[6] = { true, false, true, true, false, true };
  const bool expected_has_name[6]    = { true, false, true, true, true, true };
  for (int i = 0; i < 6; i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "element %d", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_problems[i], elements[i].m_problem, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_earlier[i], elements[i].m_earlierIndex, label);
    TEST_ASSERT_EQUAL_MESSAGE(expected_has_name[i], elements[i].m_hasName, label);
    TEST_ASSERT_EQUAL_MESSAGE(expected_has_name[i], elements[i].m_hasEcosystem, label);
    TEST_ASSERT_EQUAL_MESSAGE(expected_has_version[i], elements[i].m_hasVersion, label);
  }
  TEST_ASSERT_EQUAL_STRING("NPM", elements[3].m_package.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("lodash", elements[3].m_package.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("PyPI", elements[2].m_package.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("", elements[4].m_package.ma_version);
  TEST_ASSERT_EQUAL_STRING("^4", elements[5].m_package.ma_version);
  free(elements);

  PACKAGECHECKBULKParams_t empty_list = { .m_itemArraySpan = { NULL, 0 }, .m_itemCount = 0 };
  elements = (WATCHLISTEDITPackageElement_t*)&empty_list;
  TEST_ASSERT_TRUE(endpoint_readWatchlistPackageElements(&empty_list, &elements));
  TEST_ASSERT_NULL(elements);
}

void test_readWatchlistPackageElements_compares_only_packages(void)
{
  const struct { const char* mp_array; int m_count; PackageElementProblem_t ma_problems[3]; int ma_earlier[3]; } cases[] = {
    { R"([{"ecosystem":"npm","name":"a b"},{"ecosystem":"npm","name":"a b","version":"1"}])", 2,
      { PACKAGE_ELEMENT_PROBLEM_NAME_SPACE, PACKAGE_ELEMENT_PROBLEM_NAME_SPACE, PACKAGE_ELEMENT_PROBLEM_NONE }, { -1, -1, -1 } },
    { R"([{"ecosystem":"npm","name":"a","extra":1},{"ecosystem":"npm","name":"a"}])", 2,
      { PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN, PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NONE }, { -1, -1, -1 } },
    { R"([{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"a"}])", 3,
      { PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_REPEATED, PACKAGE_ELEMENT_PROBLEM_REPEATED }, { -1, 0, 0 } },
    { R"([{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"a","version":""},{"ecosystem":"npm","name":"a","version":"1"}])", 3,
      { PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_REPEATED, PACKAGE_ELEMENT_PROBLEM_NONE }, { -1, 0, -1 } },
    { R"([{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"b"},{"ecosystem":"npm","name":"b"}])", 3,
      { PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_REPEATED }, { -1, -1, 1 } },
    { R"([{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"A"},{"ecosystem":"npm","name":"b"}])", 3,
      { PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NONE, PACKAGE_ELEMENT_PROBLEM_NONE }, { -1, -1, -1 } },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    PACKAGECHECKBULKParams_t       package_list = { .m_itemArraySpan = static_spanOfText(cases[c].mp_array), .m_itemCount = cases[c].m_count };
    WATCHLISTEDITPackageElement_t* elements = NULL;
    TEST_ASSERT_TRUE(endpoint_readWatchlistPackageElements(&package_list, &elements));
    for (int i = 0; i < cases[c].m_count; i++)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].ma_problems[i], elements[i].m_problem, cases[c].mp_array);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].ma_earlier[i], elements[i].m_earlierIndex, cases[c].mp_array);
    }
    free(elements);
  }
}

void test_readWatchlistPackageElements_gives_each_rule_its_problem(void)
{
  static char long_name_array[PACKAGECHECK_NAME_MAX_LEN + 64];
  static char longest_name_array[PACKAGECHECK_NAME_MAX_LEN + 64];
  char name[PACKAGECHECK_NAME_MAX_LEN + 2];
  memset(name, 'n', sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';
  snprintf(long_name_array, sizeof(long_name_array), R"([{"ecosystem":"npm","name":"%s"}])", name);
  name[sizeof(name) - 2] = '\0';
  snprintf(longest_name_array, sizeof(longest_name_array), R"([{"ecosystem":"npm","name":"%s"}])", name);

  const struct { const char* mp_array; PackageElementProblem_t m_problem; bool m_hasEcosystem; bool m_hasName; bool m_hasVersion; } cases[] = {
    { R"(["npm"])",                                                 PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT,      false, false, false },
    { R"([[{"ecosystem":"npm","name":"a"}]])",                      PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT,      false, false, false },
    { R"([{"ecosystem":"npm","name":"a","extra":"1"}])",            PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN,     true,  true,  false },
    { R"([{"ecosystem":"npm","name":"a","name":"b"}])",             PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED,    true,  true,  false },
    { R"([{"ecosystem":"npm","extra":"1","name":"a","name":"b"}])", PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN,     true,  true,  false },
    { R"([{"name":"a","name":"b","extra":"1"}])",                   PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED,    false, true,  false },
    { R"([{"ecosystem":7,"name":"a"}])",                            PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT, false, true,  false },
    { R"([{"ecosystem":"npm","name":null}])",                       PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      true,  false, false },
    { R"([{"ecosystem":"npm","name":"a","version":1}])",            PACKAGE_ELEMENT_PROBLEM_VERSION_NOT_TEXT,   true,  true,  false },
    { R"([{"ecosystem":7,"name":null,"version":1}])",               PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT, false, false, false },
    { R"([{"ecosystem":"npm","name":null,"version":1}])",           PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      true,  false, false },
    { R"([{"ecosystem":"npm","name":"a\u0000"}])",                  PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      true,  false, false },
    { R"([{"ecosystem":"javascript-registry","name":"a"}])",        PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT, false, true,  false },
    { long_name_array,                                              PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      true,  false, false },
    { longest_name_array,                                           PACKAGE_ELEMENT_PROBLEM_NONE,               true,  true,  false },
    { R"([{"ecosystem":"cpan","name":"a"}])",                       PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN,  true,  true,  false },
    { R"([{"name":"a"}])",                                          PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN,  false, true,  false },
    { R"([{"ecosystem":"npm"}])",                                   PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY,         true,  false, false },
    { R"([{"ecosystem":"npm","name":""}])",                         PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY,         true,  true,  false },
    { R"([{"ecosystem":"npm","name":"a\tb"}])",                     PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR,  true,  true,  false },
    { R"([{"ecosystem":"npm","name":"a b\t"}])",                    PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR,  true,  true,  false },
    { R"([{"ecosystem":"npm","name":"a b"}])",                      PACKAGE_ELEMENT_PROBLEM_NAME_SPACE,         true,  true,  false },
    { R"([{"ecosystem":"npm","name":"a","version":"1 0"}])",        PACKAGE_ELEMENT_PROBLEM_VERSION_INVALID,    true,  true,  true  },
    { R"([{"ecosystem":"npm","name":"a b","version":"1 0"}])",      PACKAGE_ELEMENT_PROBLEM_NAME_SPACE,         true,  true,  true  },
    { R"([{"ecosystem":"cpan","name":"","version":"1 0"}])",        PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN,  true,  true,  true  },
    { R"([{"ecosystem":"pypi","name":"a","version":""}])",          PACKAGE_ELEMENT_PROBLEM_NONE,               true,  true,  true  },
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
  {
    WATCHLISTEDITPackageElement_t element;
    static_readOnePackageElement(cases[k].mp_array, &element);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_problem, element.m_problem, cases[k].mp_array);
    TEST_ASSERT_EQUAL_MESSAGE(cases[k].m_hasEcosystem, element.m_hasEcosystem, cases[k].mp_array);
    TEST_ASSERT_EQUAL_MESSAGE(cases[k].m_hasName, element.m_hasName, cases[k].mp_array);
    TEST_ASSERT_EQUAL_MESSAGE(cases[k].m_hasVersion, element.m_hasVersion, cases[k].mp_array);
    if (!element.m_hasEcosystem)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", element.m_package.ma_ecosystem, cases[k].mp_array);
    if (!element.m_hasName)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", element.m_package.ma_packageName, cases[k].mp_array);
    if (!element.m_hasVersion)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", element.m_package.ma_version, cases[k].mp_array);
  }

  WATCHLISTEDITPackageElement_t element;
  static_readOnePackageElement(R"([{"ecosystem":"cpan","name":"a\"b","version":"1 0"}])", &element);
  TEST_ASSERT_EQUAL_STRING("cpan", element.m_package.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("a\"b", element.m_package.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("1 0", element.m_package.ma_version);
}

void test_watchlist_findItemKind_gives_each_endpoint_its_kind(void)
{
  static const struct { const char* mp_endpoint; WatchlistItemKind_t m_kind; } cases[] = {
    { "cve_lookup",       WATCHLIST_ITEM_CVE_LOOKUP },
    { "kev_lookup",       WATCHLIST_ITEM_KEV_LOOKUP },
    { "cve_exploit",      WATCHLIST_ITEM_CVE_EXPLOIT },
    { "product_exposure", WATCHLIST_ITEM_PRODUCT_EXPOSURE },
    { "cve_search",       WATCHLIST_ITEM_CVE_SEARCH },
    { "dns_lookup",       WATCHLIST_ITEM_DNS_LOOKUP },
    { "ssl_check",        WATCHLIST_ITEM_SSL_CHECK },
    { "whois_lookup",     WATCHLIST_ITEM_WHOIS_LOOKUP },
    { "headers_check",    WATCHLIST_ITEM_HEADERS_CHECK },
    { "cert_search",      WATCHLIST_ITEM_CERT_SEARCH },
    { "package_check",    WATCHLIST_ITEM_PACKAGE_CHECK },
    { "ip_lookup",        WATCHLIST_ITEM_IP_LOOKUP },
  };
  TEST_ASSERT_EQUAL_INT(12, WATCHLIST_ITEM_KIND_COUNT);
  TEST_ASSERT_EQUAL_INT((int)strlen("product_exposure"), WATCHLIST_ENDPOINT_MAX_LEN);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    WatchlistItemKind_t kind = (WatchlistItemKind_t)-1;
    TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(cases[i].mp_endpoint, &kind), cases[i].mp_endpoint);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_kind, kind, cases[i].mp_endpoint);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)i, (int)kind, cases[i].mp_endpoint);
  }

  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  const EndpointParamSpec_t* spec = edit->mp_params[static_watchlistParamIndex(edit, "endpoint")].mp_spec;
  size_t spec_name_count = 0;
  for (; spec->mp_enumValues[spec_name_count] != NULL; spec_name_count++)
  {
    WatchlistItemKind_t kind;
    TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(spec->mp_enumValues[spec_name_count], &kind), spec->mp_enumValues[spec_name_count]);
    if (spec_name_count < sizeof(cases) / sizeof(cases[0]))
      TEST_ASSERT_EQUAL_STRING(cases[spec_name_count].mp_endpoint, spec->mp_enumValues[spec_name_count]);
  }
  TEST_ASSERT_EQUAL_size_t(sizeof(cases) / sizeof(cases[0]), spec_name_count);
  TEST_ASSERT_EQUAL_STRING("endpoint must be one of cve_lookup, kev_lookup, cve_exploit, product_exposure, cve_search, dns_lookup, ssl_check, whois_lookup, headers_check, cert_search, package_check, ip_lookup", spec->mp_message);

  static const char* const no_kind[] = { "cve_leading", "cve_triage", "dns_takeover_check", "" };
  for (size_t i = 0; i < sizeof(no_kind) / sizeof(no_kind[0]); i++)
  {
    WatchlistItemKind_t kind = (WatchlistItemKind_t)-1;
    TEST_ASSERT_FALSE_MESSAGE(watchlist_findItemKind(no_kind[i], &kind), no_kind[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, (int)kind, no_kind[i]);
  }
}

void test_watchlist_findEndpointName_gives_each_kind_its_endpoint(void)
{
  static const struct { WatchlistItemKind_t m_kind; const char* mp_endpoint; } cases[] = {
    { WATCHLIST_ITEM_CVE_LOOKUP,       "cve_lookup" },
    { WATCHLIST_ITEM_KEV_LOOKUP,       "kev_lookup" },
    { WATCHLIST_ITEM_CVE_EXPLOIT,      "cve_exploit" },
    { WATCHLIST_ITEM_PRODUCT_EXPOSURE, "product_exposure" },
    { WATCHLIST_ITEM_CVE_SEARCH,       "cve_search" },
    { WATCHLIST_ITEM_DNS_LOOKUP,       "dns_lookup" },
    { WATCHLIST_ITEM_SSL_CHECK,        "ssl_check" },
    { WATCHLIST_ITEM_WHOIS_LOOKUP,     "whois_lookup" },
    { WATCHLIST_ITEM_HEADERS_CHECK,    "headers_check" },
    { WATCHLIST_ITEM_CERT_SEARCH,      "cert_search" },
    { WATCHLIST_ITEM_PACKAGE_CHECK,    "package_check" },
    { WATCHLIST_ITEM_IP_LOOKUP,        "ip_lookup" },
  };
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_ITEM_KIND_COUNT, sizeof(cases) / sizeof(cases[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_endpoint, watchlist_findEndpointName(cases[i].m_kind), cases[i].mp_endpoint);
    WatchlistItemKind_t kind = (WatchlistItemKind_t)-1;
    TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(watchlist_findEndpointName(cases[i].m_kind), &kind), cases[i].mp_endpoint);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_kind, kind, cases[i].mp_endpoint);
  }
  TEST_ASSERT_NULL(watchlist_findEndpointName((WatchlistItemKind_t)WATCHLIST_ITEM_KIND_COUNT));
  TEST_ASSERT_NULL(watchlist_findEndpointName((WatchlistItemKind_t)-1));
}

void test_watchlist_isDomainItemKind_is_true_for_the_five_domain_kinds(void)
{
  static const struct { WatchlistItemKind_t m_kind; bool m_isDomain; } cases[] = {
    { WATCHLIST_ITEM_CVE_LOOKUP,       false },
    { WATCHLIST_ITEM_KEV_LOOKUP,       false },
    { WATCHLIST_ITEM_CVE_EXPLOIT,      false },
    { WATCHLIST_ITEM_PRODUCT_EXPOSURE, false },
    { WATCHLIST_ITEM_CVE_SEARCH,       false },
    { WATCHLIST_ITEM_DNS_LOOKUP,       true },
    { WATCHLIST_ITEM_SSL_CHECK,        true },
    { WATCHLIST_ITEM_WHOIS_LOOKUP,     true },
    { WATCHLIST_ITEM_HEADERS_CHECK,    true },
    { WATCHLIST_ITEM_CERT_SEARCH,      true },
    { WATCHLIST_ITEM_PACKAGE_CHECK,    false },
    { WATCHLIST_ITEM_IP_LOOKUP,        false },
  };
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_ITEM_KIND_COUNT, sizeof(cases) / sizeof(cases[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[32];
    snprintf(label, sizeof(label), "kind %d", (int)cases[i].m_kind);
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_isDomain, watchlist_isDomainItemKind(cases[i].m_kind), label);
  }
  TEST_ASSERT_FALSE(watchlist_isDomainItemKind((WatchlistItemKind_t)WATCHLIST_ITEM_KIND_COUNT));
  TEST_ASSERT_FALSE(watchlist_isDomainItemKind((WatchlistItemKind_t)-1));
}

void test_watchlist_findDomainEventKind_gives_each_domain_kind_its_lane(void)
{
  static const struct { WatchlistItemKind_t m_itemKind; WatchlistEventKind_t m_eventKind; } lanes[] = {
    { WATCHLIST_ITEM_DNS_LOOKUP,    WATCHLIST_EVENT_DNS_LOOKUP },
    { WATCHLIST_ITEM_SSL_CHECK,     WATCHLIST_EVENT_SSL_CHECK },
    { WATCHLIST_ITEM_WHOIS_LOOKUP,  WATCHLIST_EVENT_WHOIS_LOOKUP },
    { WATCHLIST_ITEM_HEADERS_CHECK, WATCHLIST_EVENT_HEADERS_CHECK },
    { WATCHLIST_ITEM_CERT_SEARCH,   WATCHLIST_EVENT_CERT_SEARCH },
  };
  for (size_t i = 0; i < sizeof(lanes) / sizeof(lanes[0]); i++)
  {
    char label[32];
    snprintf(label, sizeof(label), "kind %d", (int)lanes[i].m_itemKind);
    WatchlistEventKind_t event_kind = (WatchlistEventKind_t)-1;
    TEST_ASSERT_TRUE_MESSAGE(watchlist_findDomainEventKind(lanes[i].m_itemKind, &event_kind), label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(lanes[i].m_eventKind, event_kind, label);
  }

  static const WatchlistItemKind_t no_lane[] = {
    WATCHLIST_ITEM_CVE_LOOKUP, WATCHLIST_ITEM_KEV_LOOKUP, WATCHLIST_ITEM_CVE_EXPLOIT, WATCHLIST_ITEM_PRODUCT_EXPOSURE,
    WATCHLIST_ITEM_CVE_SEARCH, WATCHLIST_ITEM_PACKAGE_CHECK, WATCHLIST_ITEM_IP_LOOKUP, (WatchlistItemKind_t)WATCHLIST_ITEM_KIND_COUNT,
  };
  for (size_t i = 0; i < sizeof(no_lane) / sizeof(no_lane[0]); i++)
  {
    char label[32];
    snprintf(label, sizeof(label), "kind %d", (int)no_lane[i]);
    WatchlistEventKind_t event_kind = (WatchlistEventKind_t)-1;
    TEST_ASSERT_FALSE_MESSAGE(watchlist_findDomainEventKind(no_lane[i], &event_kind), label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, (int)event_kind, label);
  }
}

void test_watchlist_findDomainName_reads_the_name_of_a_domain_item_only(void)
{
  WatchlistItem_t item;
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_DNS_LOOKUP;
  snprintf(item.m_dnsLookup.ma_domainName, sizeof(item.m_dnsLookup.ma_domainName), "%s", "dns.example.com");
  TEST_ASSERT_EQUAL_STRING("dns.example.com", watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_SSL_CHECK;
  snprintf(item.m_sslCheck.ma_domainName, sizeof(item.m_sslCheck.ma_domainName), "%s", "tls.example.com");
  TEST_ASSERT_EQUAL_STRING("tls.example.com", watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_WHOIS_LOOKUP;
  snprintf(item.m_whoisLookup.ma_domainName, sizeof(item.m_whoisLookup.ma_domainName), "%s", "example.org");
  TEST_ASSERT_EQUAL_STRING("example.org", watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_HEADERS_CHECK;
  snprintf(item.m_headersCheck.ma_domainName, sizeof(item.m_headersCheck.ma_domainName), "%s", "www.example.net");
  TEST_ASSERT_EQUAL_STRING("www.example.net", watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_CERT_SEARCH;
  snprintf(item.m_certSearch.ma_domainName, sizeof(item.m_certSearch.ma_domainName), "%s", "ct.example.com");
  TEST_ASSERT_EQUAL_STRING("ct.example.com", watchlist_findDomainName(&item));

  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_CVE_LOOKUP;
  snprintf(item.m_cveLookup.ma_cveId, sizeof(item.m_cveLookup.ma_cveId), "%s", "CVE-2021-44228");
  TEST_ASSERT_NULL(watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_PACKAGE_CHECK;
  snprintf(item.m_packageCheck.ma_ecosystem, sizeof(item.m_packageCheck.ma_ecosystem), "%s", "npm");
  TEST_ASSERT_NULL(watchlist_findDomainName(&item));
  memset(&item, 0, sizeof(item));
  item.m_itemKind = WATCHLIST_ITEM_IP_LOOKUP;
  snprintf(item.m_ipLookup.ma_ipAddress, sizeof(item.m_ipLookup.ma_ipAddress), "%s", "8.8.8.8");
  TEST_ASSERT_NULL(watchlist_findDomainName(&item));
}

static void static_watchlistBudget(RequestCreditBudget_t* budget, RequestTier_t tier)
{
  memset(budget, 0, sizeof(*budget));
  memcpy(budget->ma_budgetHash, TEST_CREDIT_BUDGET_HASH, sizeof(TEST_CREDIT_BUDGET_HASH));
  budget->m_tier = tier;
}

static EndpointRunStatus_t static_runWatchlistRow(const Endpoint_t* endpoint, const char* object, const char* query, const RequestCreditBudget_t* budget, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  EndpointGateResult_t gate_result;
  if (object != NULL)
    gate_result = endpoint_restFieldsBodyGate(endpoint, object, &params, endpoint->m_paramsSize);
  else
    gate_result = endpoint_restQueryGate(endpoint, query, &params, endpoint->m_paramsSize);
  TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, gate_result.m_status, object != NULL ? object : query);
  params.m_privacyMyData.mp_creditBudget = budget;
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  EndpointRunStatus_t run_status = endpoint->m_runFunction(NULL, &params, json_buf, message_out);
  jsonbuf_destroy(json_buf);
  return run_status;
}

void test_WATCHLISTEDITRun_refuses_each_wrong_shape_before_the_db(void)
{
  static const char* const CVE_ONLY_MESSAGE     = "cve_lookup, kev_lookup and cve_exploit items take exactly one cve_id";
  static const char* const PRODUCT_MESSAGE      = "product_exposure items take one vendor and one product, and may take a version";
  static const char* const NEEDS_ACTION_MESSAGE = "an item needs action=add or action=remove";
  static const char* const DOMAIN_ONLY_MESSAGE  = "dns_lookup, ssl_check, whois_lookup, headers_check and cert_search items take exactly one domain";
  static const char* const SEARCH_MESSAGE       = "cve_search items take at least one filter and no cve_id, domain, ecosystem, name, version or ip_address";
  static const char* const IP_MESSAGE           = "ip_lookup items take exactly one ip_address";
  static const char* const PACKAGE_MESSAGE      = "package_check items take one ecosystem and one name, and may take a version";
  static const char* const MIN_EPSS_MESSAGE     = "min_epss of a cve_search item takes at most three decimals";
  static const char* const LIST_ACTION_MESSAGE  = "packages need action=add or action=remove";
  static const char* const LIST_FIELD_MESSAGE   = "packages take no item field, and endpoint only as package_check";
  const struct { const char* mp_object; RequestTier_t m_tier; const char* mp_message; } cases[] = {
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_FREE, "watchlist needs a Pro API key: https://api.contrastcyber.com/pricing" },
    { "{}",                                                                            REQUEST_TIER_FREE, "watchlist needs a Pro API key: https://api.contrastcyber.com/pricing" },
    { "{\"clear\":true,\"action\":\"add\"}",                                           REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"endpoint\":\"cve_lookup\"}",                                  REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"vendor\":\"apache\"}",                                        REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"min_epss\":0.1}",                                             REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"known_ransomware\":true}",                                    REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"has_nuclei_template\":true}",                                 REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"domain\":\"example.com\"}",                                 REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"domain\":\"example.com\"}",                                                  REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"endpoint\":\"cve_lookup\"}",                                                 REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"cve_id\":\"CVE-2021-44228\"}",                                               REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"vendor\":\"apache\"}",                                                       REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"product\":\"log4j\"}",                                                       REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"severity\":\"HIGH\"}",                                                       REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"cwe_id\":\"CWE-79\"}",                                                       REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"min_cvss\":0}",                                                              REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"min_epss\":0}",                                                              REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"in_kev\":false}",                                                            REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"known_ransomware\":true}",                                                   REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"has_nuclei_template\":true}",                                                REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"action\":\"add\"}",                                                          REQUEST_TIER_PRO,  "an item needs an endpoint" },
    { "{\"action\":\"remove\",\"cve_id\":\"CVE-2021-44228\"}",                         REQUEST_TIER_PRO,  "an item needs an endpoint" },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\"}",                              REQUEST_TIER_PRO,  CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"kev_lookup\",\"cve_id\":\"CVE-2021-44228\",\"vendor\":\"apache\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_exploit\",\"cve_id\":\"CVE-2021-44228\",\"min_epss\":0.5}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\",\"in_kev\":true}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\",\"has_nuclei_template\":true}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\"}",  REQUEST_TIER_PRO,  PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"product\":\"log4j\"}",  REQUEST_TIER_PRO,  PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"version\":\"2.14.1\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"severity\":\"HIGH\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"known_ransomware\":true}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"has_nuclei_template\":true}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\"}",                              REQUEST_TIER_PRO,  SEARCH_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_search\"}",                           REQUEST_TIER_PRO,  SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO,  SEARCH_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_search\",\"cve_id\":\"CVE-2021-44228\",\"vendor\":\"apache\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"ecosystem\":\"npm\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"has_nuclei_template\":true,\"domain\":\"example.com\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.1505}",             REQUEST_TIER_PRO,  MIN_EPSS_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.0005}",             REQUEST_TIER_PRO,  MIN_EPSS_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.9999}",             REQUEST_TIER_PRO,  MIN_EPSS_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_search\",\"cwe_id\":\"CWE-79\",\"min_epss\":0.12345}", REQUEST_TIER_PRO, MIN_EPSS_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_exploit\",\"cve_id\":\"CVE-2021-44228\",\"min_epss\":0.1505}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\"}",                              REQUEST_TIER_PRO,  DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"vendor\":\"apache\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"has_nuclei_template\":true}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"min_cvss\":7}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"co.uk\"}",       REQUEST_TIER_PRO,  ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"dns_lookup\",\"domain\":\"gov.uk\"}",   REQUEST_TIER_PRO,  ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\"}",                               REQUEST_TIER_PRO,  DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"example.org\",\"product\":\"log4j\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"ssl_check\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"com.au\"}",       REQUEST_TIER_PRO,  ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\"}",                            REQUEST_TIER_PRO,  DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"headers_check\",\"domain\":\"example.com\",\"vendor\":\"acme\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cert_search\",\"domain\":\"example.com\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"clear\":true,\"ecosystem\":\"npm\"}",                                     REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"clear\":true,\"version\":\"1.0.0\"}",                                     REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"ecosystem\":\"npm\"}",                                                     REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"name\":\"lodash\"}",                                                       REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"version\":\"1.0.0\"}",                                                     REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"action\":\"add\",\"ecosystem\":\"npm\",\"name\":\"lodash\"}",              REQUEST_TIER_PRO,  "an item needs an endpoint" },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\"}",                           REQUEST_TIER_PRO,  PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\"}",     REQUEST_TIER_PRO,  PACKAGE_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"package_check\",\"name\":\"lodash\"}",    REQUEST_TIER_PRO,  PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"name\":\"lodash\",\"version\":\"4.17.20\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"version\":\"4.17.20\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"vendor\":\"apache\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"product\":\"log4j\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"min_cvss\":7}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"has_nuclei_template\":true}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\",\"ecosystem\":\"npm\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"kev_lookup\",\"cve_id\":\"CVE-2021-44228\",\"name\":\"lodash\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_exploit\",\"cve_id\":\"CVE-2021-44228\",\"version\":\"1.0.0\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"name\":\"lodash\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"vendor\":\"apache\",\"ecosystem\":\"npm\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"severity\":\"HIGH\",\"name\":\"lodash\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"has_nuclei_template\":true,\"version\":\"1.0.0\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"name\":\"lodash\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"example.com\",\"ecosystem\":\"npm\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\",\"version\":\"1.0.0\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"clear\":true,\"ip_address\":\"8.8.8.8\"}",                                REQUEST_TIER_PRO,  "clear takes no action and no item" },
    { "{\"ip_address\":\"8.8.8.8\"}",                                                REQUEST_TIER_PRO,  NEEDS_ACTION_MESSAGE },
    { "{\"action\":\"add\",\"ip_address\":\"8.8.8.8\"}",                             REQUEST_TIER_PRO,  "an item needs an endpoint" },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\"}",                             REQUEST_TIER_PRO,  IP_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"ip_lookup\"}",                          REQUEST_TIER_PRO,  IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\",\"min_cvss\":7}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\",\"ecosystem\":\"npm\"}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\",\"version\":\"1.0.0\"}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"domain\":\"example.com\"}", REQUEST_TIER_PRO, IP_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, CVE_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, PRODUCT_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"vendor\":\"apache\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, SEARCH_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, DOMAIN_ONLY_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, PACKAGE_MESSAGE },
    { "{\"clear\":true,\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, "clear takes no action and no item" },
    { "{\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_ACTION_MESSAGE },
    { "{\"endpoint\":\"package_check\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_ACTION_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_FIELD_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_FIELD_MESSAGE },
    { "{\"action\":\"remove\",\"version\":\"1.0.0\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_FIELD_MESSAGE },
    { "{\"action\":\"remove\",\"cve_id\":\"CVE-2021-44228\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, LIST_FIELD_MESSAGE },
    { "{\"action\":\"add\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\"}]}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"package_check\",\"packages\":[\"x\"]}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"8.8.8.8\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"ip_lookup\",\"ip_address\":\"2606:4700:0000::1111\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"package_check\",\"ecosystem\":\"PyPI\",\"name\":\"Django\",\"version\":\"4.2.1\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"package_check\",\"ecosystem\":\"maven\",\"name\":\"org.apache.logging.log4j:log4j-core\",\"version\":\"2.14.1\"}", REQUEST_TIER_PRO, NULL },
    { "{}",                                                                            REQUEST_TIER_PRO,  NULL },
    { "{\"clear\":true}",                                                              REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"kev_lookup\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_exploit\",\"cve_id\":\"CVE-2021-44228\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"version\":\"2.14.1\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"version\":\"2.14.1\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"vendor\":\"apache\"}",           REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"product\":\"log4j\"}",           REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"severity\":\"HIGH\"}",           REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"cwe_id\":\"CWE-79\"}",           REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_cvss\":0}",                  REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0}",                  REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.001}",              REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.151}",              REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.29}",               REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":0.999}",              REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"min_epss\":1}",                  REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"in_kev\":false}",                REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"known_ransomware\":true}",       REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"has_nuclei_template\":true}",    REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"cve_search\",\"has_nuclei_template\":true}", REQUEST_TIER_PRO,  NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"vendor\":\"apache\",\"min_cvss\":0,\"in_kev\":false}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"severity\":\"HIGH\",\"cwe_id\":\"CWE-79\",\"min_epss\":0,\"known_ransomware\":true,\"product\":\"log4j\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"example.co.uk\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"dns_lookup\",\"domain\":\"www.example.com\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"shop.example.org\"}", REQUEST_TIER_PRO, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"ssl_check\",\"domain\":\"example.net\"}", REQUEST_TIER_PRO, NULL },
  };
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RequestCreditBudget_t budget;
    static_watchlistBudget(&budget, cases[i].m_tier);
    const char* message = NULL;
    EndpointRunStatus_t run_status = static_runWatchlistRow(edit, cases[i].mp_object, NULL, &budget, &message);
    if (cases[i].mp_message != NULL)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, run_status, cases[i].mp_object);
      TEST_ASSERT_NOT_NULL_MESSAGE(message, cases[i].mp_object);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_message, message, cases[i].mp_object);
    }
    else
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_DB_ERROR, run_status, cases[i].mp_object);
  }
}

static DnsAnswerStatus_t g_fakeAskStatus        = DNS_ANSWER_OK;
static int               g_fakeAskRecordCount   = 0;
static int               g_fakeAskCallCount     = 0;
static int               g_fakeAskQuestionCount = 0;
static DnsRecordType_t   g_fakeAskType          = DNS_RECORD_TYPE_PTR;
static int               g_fakeAskDeadlineMs    = 0;
static char              g_fakeAskName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static int               g_fakeAnswerFreeCount  = 0;

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out);
void __real_dns_answerFree(DnsAnswer_t* answer);
void __wrap_dns_answerFree(DnsAnswer_t* answer);

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  g_fakeAskCallCount++;
  g_fakeAskQuestionCount = question_count;
  g_fakeAskType          = questions[0].m_type;
  g_fakeAskDeadlineMs    = deadline_ms;
  snprintf(g_fakeAskName, sizeof(g_fakeAskName), "%s", questions[0].mp_domainName);
  for (int i = 0; i < question_count; i++)
  {
    memset(&answers_out[i], 0, sizeof(answers_out[i]));
    answers_out[i].m_status = g_fakeAskStatus;
    if (g_fakeAskStatus != DNS_ANSWER_OK || g_fakeAskRecordCount == 0)
      continue;
    answers_out[i].mp_texts = calloc((size_t)g_fakeAskRecordCount, sizeof(DnsRecordText_t));
    TEST_ASSERT_NOT_NULL(answers_out[i].mp_texts);
    for (int r = 0; r < g_fakeAskRecordCount; r++)
    {
      answers_out[i].mp_texts[r].mp_bytes = strdup("192.0.2.7");
      TEST_ASSERT_NOT_NULL(answers_out[i].mp_texts[r].mp_bytes);
      answers_out[i].mp_texts[r].m_byteCount = strlen("192.0.2.7");
    }
    answers_out[i].m_recordCount = g_fakeAskRecordCount;
  }
}

void __wrap_dns_answerFree(DnsAnswer_t* answer)
{
  g_fakeAnswerFreeCount++;
  __real_dns_answerFree(answer);
}

static void static_resetFakeAsk(void)
{
  g_fakeAskStatus        = DNS_ANSWER_OK;
  g_fakeAskRecordCount   = 0;
  g_fakeAskCallCount     = 0;
  g_fakeAskQuestionCount = 0;
  g_fakeAskType          = DNS_RECORD_TYPE_PTR;
  g_fakeAskDeadlineMs    = 0;
  g_fakeAskName[0]       = '\0';
  g_fakeAnswerFreeCount  = 0;
}

void test_WATCHLISTEDITRun_asks_dns_only_for_the_add_of_a_domain_item(void)
{
  static const char* const NOT_IN_DNS_MESSAGE = "domain does not exist in DNS";
  const struct {
    const char*         mp_object;
    DnsAnswerStatus_t   m_dnsStatus;
    int                 m_recordCount;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_message;
    int                 m_askCount;
    const char*         mp_askName;
  } cases[] = {
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"Gone.Example.COM\"}",   DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_REFUSED,  NOT_IN_DNS_MESSAGE, 1, "gone.example.com" },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"shop.example.org\"}",    DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_REFUSED,  NOT_IN_DNS_MESSAGE, 1, "shop.example.org" },
    { "{\"action\":\"add\",\"endpoint\":\"headers_check\",\"domain\":\"Web.Example.org\"}", DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_REFUSED,  NOT_IN_DNS_MESSAGE, 1, "web.example.org" },
    { "{\"action\":\"add\",\"endpoint\":\"headers_check\",\"domain\":\"www.example.org\"}", DNS_ANSWER_OK,            1, ENDPOINT_RUN_DB_ERROR, NULL,               1, "www.example.org" },
    { "{\"action\":\"remove\",\"endpoint\":\"headers_check\",\"domain\":\"gone.example.org\"}", DNS_ANSWER_NXDOMAIN,  0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cert_search\",\"domain\":\"Ct.Example.org\"}",   DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_REFUSED,  NOT_IN_DNS_MESSAGE, 1, "ct.example.org" },
    { "{\"action\":\"add\",\"endpoint\":\"cert_search\",\"domain\":\"www.example.org\"}",  DNS_ANSWER_OK,            1, ENDPOINT_RUN_DB_ERROR, NULL,               1, "www.example.org" },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"www.example.com\"}",    DNS_ANSWER_OK,            2, ENDPOINT_RUN_DB_ERROR, NULL,               1, "www.example.com" },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"mail.example.net\"}",    DNS_ANSWER_OK,            0, ENDPOINT_RUN_DB_ERROR, NULL,               1, "mail.example.net" },
    { "{\"action\":\"add\",\"endpoint\":\"ssl_check\",\"domain\":\"api.example.co.uk\"}",   DNS_ANSWER_SERVER_ERROR,  0, ENDPOINT_RUN_DB_ERROR, NULL,               1, "api.example.co.uk" },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"slow.example.com\"}",   DNS_ANSWER_TIMEOUT,       0, ENDPOINT_RUN_DB_ERROR, NULL,               1, "slow.example.com" },
    { "{\"action\":\"add\",\"endpoint\":\"dns_lookup\",\"domain\":\"co.uk\"}",              DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_REFUSED,  ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE, 0, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"dns_lookup\",\"domain\":\"gone.example.com\"}", DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{\"action\":\"remove\",\"endpoint\":\"ssl_check\",\"domain\":\"gone.example.org\"}",  DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{}",                                                                                       DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{\"clear\":true}",                                                                         DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"}",      DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\"}", DNS_ANSWER_NXDOMAIN, 0, ENDPOINT_RUN_DB_ERROR, NULL, 0, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"cve_search\",\"vendor\":\"example.com\"}",          DNS_ANSWER_NXDOMAIN,      0, ENDPOINT_RUN_DB_ERROR, NULL,               0, NULL },
  };
  TEST_ASSERT_EQUAL_INT(5000, DNS_LOOKUP_DEADLINE_MS);
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFakeAsk();
    g_fakeAskStatus       = cases[i].m_dnsStatus;
    g_fakeAskRecordCount  = cases[i].m_recordCount;
    RequestCreditBudget_t budget;
    static_watchlistBudget(&budget, REQUEST_TIER_PRO);
    const char* message = NULL;
    EndpointRunStatus_t run_status = static_runWatchlistRow(edit, cases[i].mp_object, NULL, &budget, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, run_status, cases[i].mp_object);
    if (cases[i].mp_message != NULL)
    {
      TEST_ASSERT_NOT_NULL_MESSAGE(message, cases[i].mp_object);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_message, message, cases[i].mp_object);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_askCount, g_fakeAskCallCount, cases[i].mp_object);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_askCount, g_fakeAnswerFreeCount, cases[i].mp_object);
    if (cases[i].m_askCount > 0)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_fakeAskQuestionCount, cases[i].mp_object);
      TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_RECORD_TYPE_A, g_fakeAskType, cases[i].mp_object);
      TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_LOOKUP_DEADLINE_MS, g_fakeAskDeadlineMs, cases[i].mp_object);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_askName, g_fakeAskName, cases[i].mp_object);
    }
  }
  static_resetFakeAsk();
}

void test_WATCHLISTEVENTSRun_refuses_each_wrong_shape_before_the_db(void)
{
  const struct { const char* mp_query; RequestTier_t m_tier; const char* mp_message; } cases[] = {
    { "",                              REQUEST_TIER_FREE, "watchlist needs a Pro API key: https://api.contrastcyber.com/pricing" },
    { "cursor=41",                     REQUEST_TIER_FREE, "watchlist needs a Pro API key: https://api.contrastcyber.com/pricing" },
    { "cursor=41&repeat=true",         REQUEST_TIER_PRO,  "cursor and repeat cannot be combined" },
    { "repeat=true&cursor=0&limit=1",  REQUEST_TIER_PRO,  "cursor and repeat cannot be combined" },
    { "",                              REQUEST_TIER_PRO,  NULL },
    { "cursor=41",                     REQUEST_TIER_PRO,  NULL },
    { "cursor=0",                      REQUEST_TIER_PRO,  NULL },
    { "repeat=true",                   REQUEST_TIER_PRO,  NULL },
    { "limit=1",                       REQUEST_TIER_PRO,  NULL },
  };
  const Endpoint_t* events = endpoint_findByMcpName("watchlist_events");
  TEST_ASSERT_NOT_NULL(events);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    RequestCreditBudget_t budget;
    static_watchlistBudget(&budget, cases[i].m_tier);
    const char* message = NULL;
    EndpointRunStatus_t run_status = static_runWatchlistRow(events, NULL, cases[i].mp_query, &budget, &message);
    if (cases[i].mp_message != NULL)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, run_status, cases[i].mp_query);
      TEST_ASSERT_NOT_NULL_MESSAGE(message, cases[i].mp_query);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_message, message, cases[i].mp_query);
    }
    else
      TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_DB_ERROR, run_status, cases[i].mp_query);
  }
}

void test_WATCHLISTEVENTS_row_takes_three_params_and_costs_one_credit(void)
{
  const Endpoint_t* events = endpoint_findByMcpName("watchlist_events");
  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL_INT(3, events->m_paramCount);
  static const char* const names[] = { "limit", "cursor", "repeat" };
  for (int i = 0; i < events->m_paramCount; i++)
    TEST_ASSERT_EQUAL_STRING(names[i], events->mp_params[i].mp_spec->mp_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_COST_FLAT, events->m_costRule);
  TEST_ASSERT_EQUAL_UINT(1, events->m_creditCost);

  static const char* const queries[] = { "kev=true", "exploit=true", "limit=1&kev=false" };
  static const char* const objects[] = { "{\"kev\":true}", "{\"exploit\":true}", "{\"limit\":1,\"exploit\":false}" };
  for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    EndpointGateResult_t gate_result = endpoint_restQueryGate(events, queries[i], &params, events->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, gate_result.m_status, queries[i]);
    JsonReadSpan_t args_span = { objects[i], strlen(objects[i]) };
    gate_result = endpoint_mcpArgsGate(events, args_span, &params, events->m_paramsSize);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME, gate_result.m_status, objects[i]);
  }
}

void test_runRow_hands_the_credit_budget_to_both_watchlist_rows(void)
{
  TEST_ASSERT_EQUAL_size_t(0, offsetof(WATCHLISTEDITParams_t, mp_creditBudget));
  TEST_ASSERT_EQUAL_size_t(0, offsetof(WATCHLISTEVENTSParams_t, mp_creditBudget));
  TEST_ASSERT_EQUAL_size_t(0, offsetof(VENDORKEYEDITParams_t, mp_creditBudget));
  TEST_ASSERT_EQUAL_size_t(0, offsetof(IPLOOKUPParams_t, mp_creditBudget));
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  const RequestCharge_t charge_with_budget = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = &credit_budget, .mp_x402Payment = NULL };
  static const char* const tools[] = { "watchlist_edit", "watchlist_events", "vendor_key_edit", "ip_lookup" };
  for (size_t i = 0; i < 4; i++)
  {
    const Endpoint_t* row = endpoint_findByMcpName(tools[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(row, tools[i]);
    EndpointAnyParams_t params;
    memset(&params, 0x5A, sizeof(params));
    EndpointAnyParams_t untouched;
    memcpy(&untouched, &params, sizeof(params));
    EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &charge_with_budget);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status, tools[i]);
    TEST_ASSERT_NULL_MESSAGE(run_result.mp_body, tools[i]);
    if (i == 0)
      TEST_ASSERT_EQUAL_PTR(&credit_budget, params.m_watchlistEdit.mp_creditBudget);
    else if (i == 1)
      TEST_ASSERT_EQUAL_PTR(&credit_budget, params.m_watchlistEvents.mp_creditBudget);
    else if (i == 2)
      TEST_ASSERT_EQUAL_PTR(&credit_budget, params.m_vendorKeyEdit.mp_creditBudget);
    else
      TEST_ASSERT_EQUAL_PTR(&credit_budget, params.m_ipLookup.mp_creditBudget);
    untouched.m_privacyMyData.mp_creditBudget = &credit_budget;
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&untouched, &params, sizeof(params), tools[i]);

    memset(&params, 0x5A, sizeof(params));
    run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_NO_CREDIT_BUDGET, run_result.m_status, tools[i]);
    TEST_ASSERT_NULL_MESSAGE(run_result.mp_body, tools[i]);
  }
}

void test_appendSchemaBounds_prints_each_bound_as_its_exact_double(void)
{
  static const EndpointParamSpec_t number_spec = { .mp_name = "x", .m_type = ENDPOINT_PARAM_TYPE_DOUBLE, .m_min = 0.1, .m_max = 1e7, .m_default = 1234567.5 };
  static const EndpointParamSpec_t int_spec    = { .mp_name = "y", .m_type = ENDPOINT_PARAM_TYPE_INT, .m_min = -10, .m_max = 10, .m_default = -5 };
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  endpoint_appendSchemaBounds(&number_spec, json_buf);
  endpoint_appendSchemaBounds(&int_spec, json_buf);
  char* text = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_EQUAL_STRING(",\"minimum\":0.10000000000000001,\"maximum\":10000000,\"default\":1234567.5"
                           ",\"minimum\":-10,\"maximum\":10,\"default\":-5", text);
  free(text);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(221, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}


void test_DNSLOOKUPRun_refuses_a_name_that_is_not_public(void)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_dnsLookup.ma_domain, sizeof(params.m_dnsLookup.ma_domain), "%s", "printer.local");
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  const char* message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, endpoint_DNSLOOKUPRun(NULL, &params, json_buf, &message));
  TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
  jsonbuf_destroy(json_buf);
}

void test_DNSTAKEOVERCHECKRun_refuses_a_name_that_is_not_public(void)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_dnsTakeoverCheck.ma_hostname, sizeof(params.m_dnsTakeoverCheck.ma_hostname), "%s", "router.home.arpa");
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  const char* message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, endpoint_DNSTAKEOVERCHECKRun(NULL, &params, json_buf, &message));
  TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
  jsonbuf_destroy(json_buf);
}

extern DnsLookupStatus_t g_stub_EMAILAUTHCHECK_status;

void test_EMAILAUTHCHECKRun_refusal_names_what_was_refused(void)
{
  g_stub_EMAILAUTHCHECK_status = DNS_LOOKUP_INVALID_NAME;
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_emailAuthCheck.ma_domain, sizeof(params.m_emailAuthCheck.ma_domain), "%s", "example.com");
  snprintf(params.m_emailAuthCheck.ma_dkimSelector, sizeof(params.m_emailAuthCheck.ma_dkimSelector), "%s", "google");
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  const char* message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, endpoint_EMAILAUTHCHECKRun(NULL, &params, json_buf, &message));
  TEST_ASSERT_EQUAL_STRING(EMAILCHECK_NAME_TOO_LONG_REFUSAL_MESSAGE, message);
  char too_long_refusal[80];
  snprintf(too_long_refusal, sizeof(too_long_refusal), "dkim_selector and domain make a name longer than %d bytes", VALIDATE_DOMAIN_NAME_MAX_LEN);
  TEST_ASSERT_EQUAL_STRING(too_long_refusal, message);

  params.m_emailAuthCheck.ma_dkimSelector[0] = '\0';
  message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, endpoint_EMAILAUTHCHECKRun(NULL, &params, json_buf, &message));
  TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
  jsonbuf_destroy(json_buf);
  g_stub_EMAILAUTHCHECK_status = DNS_LOOKUP_OK;
}

extern TlsProbeStatus_t         g_stub_TLSPROBE_status;
extern TlsProbeHandshakeError_t g_stub_TLSPROBE_handshake_error;
extern int                      g_stub_TLSPROBE_call_count;
extern char                     g_stub_TLSPROBE_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern int                      g_stub_CACHE_get_count;
extern char                     g_stub_CACHE_last_get_key[CACHE_KEY_MAX_LEN + 1];
extern char                     g_stub_CACHE_last_put_key[CACHE_KEY_MAX_LEN + 1];

void test_SSLCHECKRun_names_why_each_probe_failed(void)
{
  static const struct {
    TlsProbeStatus_t         m_probeStatus;
    TlsProbeHandshakeError_t m_handshakeError;
    EndpointRunStatus_t      m_runStatus;
    const char*              mp_message;
  } cases[] = {
    { TLSPROBE_INVALID_NAME,                   TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_REFUSED,            VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE },
    { TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_REFUSED,            "hostname has no globally reachable address" },
    { TLSPROBE_NAME_NOT_FOUND,                 TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_NOT_FOUND,          NULL },
    { TLSPROBE_RESOLVE_FAILED,                 TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_UPSTREAM_ERROR,     NULL },
    { TLSPROBE_CONNECT_FAILED,                 TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_TARGET_UNREACHABLE, "no address of the host name took a connection on port 443" },
    { TLSPROBE_TIMEOUT,                        TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_TARGET_UNREACHABLE, "the TLS handshake did not finish within 5000 ms" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_TARGET_UNREACHABLE, "the TLS handshake failed" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS,              ENDPOINT_RUN_TARGET_UNREACHABLE, "the server on port 443 did not answer with TLS" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_PEER_CLOSED,                 ENDPOINT_RUN_TARGET_UNREACHABLE, "the server closed the connection during the TLS handshake" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_PROTOCOL_VERSION,            ENDPOINT_RUN_TARGET_UNREACHABLE, "the server takes none of the TLS versions the check offers, TLS 1.0 to TLS 1.3 (protocol_version alert)" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE,           ENDPOINT_RUN_TARGET_UNREACHABLE, "the server ended the TLS handshake with a handshake_failure alert, such as when it shares no cipher with the check" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME,           ENDPOINT_RUN_TARGET_UNREACHABLE, "the server does not serve the host name over TLS (unrecognized_name alert)" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED, ENDPOINT_RUN_TARGET_UNREACHABLE, "the server requires a client certificate" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT,                 ENDPOINT_RUN_TARGET_UNREACHABLE, "the server ended the TLS handshake with an alert" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_NO_CERTIFICATE,              ENDPOINT_RUN_TARGET_UNREACHABLE, "the server sent no certificate the check can read" },
    { TLSPROBE_HANDSHAKE_FAILED,               TLSPROBE_HANDSHAKE_ERROR_OTHER,                       ENDPOINT_RUN_TARGET_UNREACHABLE, "the TLS handshake failed" },
    { TLSPROBE_NO_MEMORY,                      TLSPROBE_HANDSHAKE_ERROR_NONE,                        ENDPOINT_RUN_NO_MEMORY,          NULL },
  };
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_sslCheck.ma_hostname, sizeof(params.m_sslCheck.ma_hostname), "%s", "shop.example.com");
  g_stub_CACHE_get_count = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_TLSPROBE_status          = cases[i].m_probeStatus;
    g_stub_TLSPROBE_handshake_error = cases[i].m_handshakeError;
    g_stub_TLSPROBE_last_hostname[0] = '\0';
    JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    TEST_ASSERT_NOT_NULL(json_buf);
    const char* message = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, endpoint_SSLCHECKRun(NULL, &params, json_buf, &message), cases[i].mp_message);
    if (cases[i].mp_message == NULL)
      TEST_ASSERT_NULL(message);
    else
      TEST_ASSERT_EQUAL_STRING(cases[i].mp_message, message);
    TEST_ASSERT_EQUAL_STRING("shop.example.com", g_stub_TLSPROBE_last_hostname);
    jsonbuf_destroy(json_buf);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  g_stub_TLSPROBE_status          = TLSPROBE_OK;
  g_stub_TLSPROBE_handshake_error = TLSPROBE_HANDSHAKE_ERROR_NONE;
}

void test_runRow_hands_the_reason_of_an_unreachable_target_on(void)
{
  const Endpoint_t* row = endpoint_findByMcpName("ssl_check");
  TEST_ASSERT_NOT_NULL(row);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_sslCheck.ma_hostname, sizeof(params.m_sslCheck.ma_hostname), "%s", "shop.example.com");

  g_stub_TLSPROBE_status = TLSPROBE_CONNECT_FAILED;
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_TARGET_UNREACHABLE, run_result.m_status);
  TEST_ASSERT_EQUAL_STRING("no address of the host name took a connection on port 443", run_result.mp_message);
  TEST_ASSERT_NULL(run_result.mp_body);

  g_stub_TLSPROBE_status = TLSPROBE_OK;
  run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  TEST_ASSERT_EQUAL_STRING_LEN("{\"hostname\":\"shop.example.com\",", run_result.mp_body, strlen("{\"hostname\":\"shop.example.com\","));
  free(run_result.mp_body);
}

extern const char* const        g_stub_RDAP_default_server_base_url;
extern const RdapRegistration_t g_stub_RDAP_default_registration;
extern const char*              g_stub_RDAP_server_base_url;
extern RdapStatus_t             g_stub_RDAP_lookup_status;
extern RdapRegistration_t       g_stub_RDAP_registration;
extern int                      g_stub_RDAP_find_count;
extern int                      g_stub_RDAP_lookup_count;
extern char                     g_stub_RDAP_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                     g_stub_RDAP_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                     g_stub_RDAP_last_lookup_base_url[256];

extern unsigned int g_stub_RDAP_retry_after_seconds;

extern QuotaStatus_t g_stub_QUOTA_reserve_status;
extern int           g_stub_QUOTA_reserve_count;
extern PGconn*       g_stub_QUOTA_last_reserve_conn;
extern QuotaRule_t   g_stub_QUOTA_last_reserve_rule;

extern bool         g_stub_QUOTA_hold_read_result;
extern unsigned int g_stub_QUOTA_hold_seconds;
extern int          g_stub_QUOTA_hold_read_count;
extern PGconn*      g_stub_QUOTA_last_hold_read_conn;
extern char         g_stub_QUOTA_last_hold_read_name[];
extern int          g_stub_QUOTA_hold_set_count;
extern PGconn*      g_stub_QUOTA_last_hold_set_conn;
extern char         g_stub_QUOTA_last_hold_set_name[];
extern unsigned int g_stub_QUOTA_last_hold_set_seconds;

extern unsigned int g_stub_QUOTA_window_remaining_seconds;
extern QuotaRule_t  g_stub_QUOTA_last_window_remaining_rule;

extern ThrottleStatus_t g_stub_THROTTLE_charge_status;
extern unsigned int     g_stub_THROTTLE_retry_after_seconds;
extern int              g_stub_THROTTLE_charge_count;
extern PGconn*          g_stub_THROTTLE_last_conn;
extern ThrottleRule_t   g_stub_THROTTLE_last_rule;
extern char             g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN + 1];
extern unsigned int     g_stub_THROTTLE_last_charged_count;

extern const WhoisServer_t  g_stub_WHOIS_test_server;
extern const WhoisServer_t* g_stub_WHOIS_server;
extern WhoisStatus_t        g_stub_WHOIS_lookup_status;
extern RdapRegistration_t   g_stub_WHOIS_registration;
extern int                  g_stub_WHOIS_find_count;
extern int                  g_stub_WHOIS_lookup_count;
extern char                 g_stub_WHOIS_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char                 g_stub_WHOIS_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern const WhoisServer_t* g_stub_WHOIS_last_lookup_server;

extern CacheStatus_t g_stub_CACHE_get_status;
extern const char*   g_stub_CACHE_get_body;
extern bool          g_stub_CACHE_put_result;
extern int           g_stub_CACHE_put_count;
extern int           g_stub_CACHE_free_count;
extern PGconn*       g_stub_CACHE_last_get_conn;
extern PGconn*       g_stub_CACHE_last_put_conn;
extern char          g_stub_CACHE_last_put_body[];
extern size_t        g_stub_CACHE_last_put_body_len;
extern bool          g_stub_CACHE_last_put_is_error;
extern unsigned int  g_stub_CACHE_last_put_expires_after_seconds;

#define WHOISLOOKUP_TEST_CONN ((PGconn*)7)

#define WHOISLOOKUP_STUB_BODY                                                                                         \
  "{\"domain\":\"example.co.uk\",\"available\":true,\"rdap_server\":\"https://rdap.example.test/\","                 \
  "\"whois_server\":null,"                                                                                           \
  "\"registrar_name\":\"Stub Registrar LLC\",\"registrar_iana_id\":1234,"                                            \
  "\"created_at\":\"2001-02-03T04:05:06Z\",\"updated_at\":\"2025-06-07T08:09:10Z\",\"expires_at\":\"2030-11-12T13:14:15Z\"," \
  "\"status\":[\"client transfer prohibited\",\"server delete prohibited\"],\"status_count\":2,"                     \
  "\"name_servers\":[\"ns1.stub-dns.test\",\"ns2.stub-dns.test\"],\"name_server_count\":2,\"dnssec_signed\":true}\n"

static void static_WHOISLOOKUPResetStubs(void)
{
  g_stub_RDAP_server_base_url         = g_stub_RDAP_default_server_base_url;
  g_stub_RDAP_lookup_status           = RDAP_OK;
  g_stub_RDAP_registration            = g_stub_RDAP_default_registration;
  g_stub_RDAP_find_count              = 0;
  g_stub_RDAP_lookup_count            = 0;
  g_stub_RDAP_last_find_name[0]       = '\0';
  g_stub_RDAP_last_lookup_name[0]     = '\0';
  g_stub_RDAP_last_lookup_base_url[0] = '\0';
  g_stub_RDAP_retry_after_seconds     = 0;
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
  g_stub_THROTTLE_last_target_name[0]   = '\0';
  g_stub_THROTTLE_last_charged_count    = 0;
  g_stub_QUOTA_hold_read_result         = true;
  g_stub_QUOTA_hold_seconds             = 0;
  g_stub_QUOTA_hold_read_count          = 0;
  g_stub_QUOTA_last_hold_read_conn      = NULL;
  g_stub_QUOTA_last_hold_read_name[0]   = '\0';
  g_stub_QUOTA_hold_set_count           = 0;
  g_stub_QUOTA_last_hold_set_conn       = NULL;
  g_stub_QUOTA_last_hold_set_name[0]    = '\0';
  g_stub_QUOTA_last_hold_set_seconds    = 0;
  g_stub_QUOTA_window_remaining_seconds = 0;
  memset(&g_stub_QUOTA_last_window_remaining_rule, 0, sizeof(g_stub_QUOTA_last_window_remaining_rule));
  g_stub_QUOTA_reserve_status         = QUOTA_GRANTED;
  g_stub_QUOTA_reserve_count          = 0;
  g_stub_QUOTA_last_reserve_conn      = NULL;
  memset(&g_stub_QUOTA_last_reserve_rule, 0, sizeof(g_stub_QUOTA_last_reserve_rule));
  g_stub_CACHE_get_status             = CACHE_MISS;
  g_stub_CACHE_get_body               = "{}\n";
  g_stub_CACHE_put_result             = true;
  g_stub_CACHE_get_count              = 0;
  g_stub_CACHE_put_count              = 0;
  g_stub_CACHE_free_count             = 0;
  g_stub_CACHE_last_get_conn          = NULL;
  g_stub_CACHE_last_put_conn          = NULL;
  g_stub_CACHE_last_get_key[0]        = '\0';
  g_stub_CACHE_last_put_key[0]        = '\0';
  g_stub_CACHE_last_put_body[0]       = '\0';
  g_stub_CACHE_last_put_body_len      = 0;
  g_stub_CACHE_last_put_is_error      = false;
  g_stub_CACHE_last_put_expires_after_seconds = 0;
}

static char* static_WHOISLOOKUPRun(const char* domain, PGconn* conn, EndpointRunStatus_t* status_out, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_whoisLookup.ma_domain, sizeof(params.m_whoisLookup.ma_domain), "%s", domain);
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  *status_out  = endpoint_WHOISLOOKUPRun(conn, &params, json_buf, message_out);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

static void static_assertWHOISLOOKUPCountedServerRequest(const char* rule_name, unsigned int charge_limit, const char* target_name)
{
  TEST_ASSERT_TRUE(g_stub_THROTTLE_last_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_NOT_NULL(g_stub_THROTTLE_last_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_STRING(rule_name, g_stub_THROTTLE_last_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60, g_stub_THROTTLE_last_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(charge_limit, g_stub_THROTTLE_last_rule.m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING(target_name, g_stub_THROTTLE_last_target_name);
  TEST_ASSERT_EQUAL_UINT(1, g_stub_THROTTLE_last_charged_count);
}

void test_WHOISLOOKUPRun_asks_about_the_registrable_domain_and_keeps_the_answer(void)
{
  static_WHOISLOOKUPResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(WHOISLOOKUP_STUB_BODY, body);

  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_find_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_find_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("rdap:example.co.uk", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  static_assertWHOISLOOKUPCountedServerRequest("rdap", 30, "rdap.example.test");
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_lookup_name);
  TEST_ASSERT_EQUAL_STRING("https://rdap.example.test/", g_stub_RDAP_last_lookup_base_url);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("rdap:example.co.uk", g_stub_CACHE_last_put_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_put_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_size_t(strlen(body), g_stub_CACHE_last_put_body_len);
  TEST_ASSERT_FALSE(g_stub_CACHE_last_put_is_error);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_CACHE_last_put_expires_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_find_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  free(body);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_refuses_a_public_suffix_before_any_call(void)
{
  static_WHOISLOOKUPResetStubs();
  static const char* const domains[] = { "co.uk", "CO.UK", "gov.uk" };
  for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); i++)
  {
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun(domains[i], WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, status, domains[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE, message, domains[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, domains[i]);
    free(body);
  }
  TEST_ASSERT_EQUAL_STRING("domain is a public suffix, such as co.uk; name a domain registered under it", ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_find_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_find_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_without_a_registry_server_answers_unavailable_and_calls_nothing_else(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_server_base_url = NULL;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"no_registry_server\",\"retry_after_seconds\":null}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_find_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_find_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WHOIS_find_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_WHOIS_last_find_name);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_sends_a_cached_answer_as_it_was_kept(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"domain\":\"example.co.uk\",\"kept\":true}\n";
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"kept\":true}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("rdap:example.co.uk", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_refused_charge_names_its_wait_and_a_failed_charge_is_a_db_error(void)
{
  static_WHOISLOOKUPResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  g_stub_THROTTLE_charge_status       = THROTTLE_REFUSED;
  g_stub_THROTTLE_retry_after_seconds = 17;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":17}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  free(body);

  g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
  body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(2, g_stub_THROTTLE_charge_count);
  free(body);

  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_held_server_names_the_wait_and_an_unread_hold_is_a_db_error(void)
{
  static_WHOISLOOKUPResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  g_stub_QUOTA_hold_seconds = 42;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":42}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_read_name);
  free(body);

  g_stub_QUOTA_hold_read_result       = false;
  g_stub_QUOTA_last_hold_read_name[0] = '\0';
  body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(2, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_read_name);
  free(body);

  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_rate_limited_answer_holds_the_server_for_its_wait(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_lookup_status       = RDAP_RATE_LIMITED;
  g_stub_RDAP_retry_after_seconds = 120;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":120}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_set_conn == WHOISLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example.test", g_stub_QUOTA_last_hold_set_name);
  TEST_ASSERT_EQUAL_UINT(120, g_stub_QUOTA_last_hold_set_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_names_each_failed_lookup_and_keeps_none(void)
{
  static const struct {
    RdapStatus_t        m_lookupStatus;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_message;
  } cases[] = {
    { RDAP_NOT_REGISTERED, ENDPOINT_RUN_NOT_FOUND,      NULL },
    { RDAP_UPSTREAM_ERROR, ENDPOINT_RUN_UPSTREAM_ERROR, NULL },
    { RDAP_INVALID_NAME,   ENDPOINT_RUN_REFUSED,        VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE },
  };
  static_WHOISLOOKUPResetStubs();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_RDAP_lookup_status       = cases[i].m_lookupStatus;
    g_stub_RDAP_last_lookup_name[0] = '\0';
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, cases[i].mp_message);
    if (cases[i].mp_message == NULL)
      TEST_ASSERT_NULL(message);
    else
      TEST_ASSERT_EQUAL_STRING(cases[i].mp_message, message);
    TEST_ASSERT_EQUAL_STRING("", body);
    TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_lookup_name);
    free(body);
  }
  TEST_ASSERT_EQUAL_INT(3, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put(void)
{
  static const struct { CacheStatus_t m_getStatus; bool m_putResult; } cases[] = {
    { CACHE_MISS,  true  },
    { CACHE_ERROR, true  },
    { CACHE_MISS,  false },
  };
  static_WHOISLOOKUPResetStubs();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_CACHE_get_status       = cases[i].m_getStatus;
    g_stub_CACHE_put_result       = cases[i].m_putResult;
    g_stub_CACHE_last_put_body[0] = '\0';
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_EQUAL_STRING(WHOISLOOKUP_STUB_BODY, body);
    TEST_ASSERT_EQUAL_STRING(WHOISLOOKUP_STUB_BODY, g_stub_CACHE_last_put_body);
    TEST_ASSERT_EQUAL_INT((int)i + 1, g_stub_RDAP_lookup_count);
    TEST_ASSERT_EQUAL_INT((int)i + 1, g_stub_CACHE_put_count);
    free(body);
  }
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_names_the_server_by_its_host_and_sends_nothing_for_a_bad_base_url(void)
{
  char max_host[THROTTLE_TARGET_NAME_MAX_LEN + 1];
  memset(max_host, 'h', THROTTLE_TARGET_NAME_MAX_LEN);
  max_host[THROTTLE_TARGET_NAME_MAX_LEN] = '\0';
  char max_url[sizeof("https://") + THROTTLE_TARGET_NAME_MAX_LEN + 1];
  snprintf(max_url, sizeof(max_url), "https://%s/", max_host);
  char over_url[sizeof("https://") + THROTTLE_TARGET_NAME_MAX_LEN + 2];
  snprintf(over_url, sizeof(over_url), "https://%sh/", max_host);

  char max_hold_name[sizeof("rdap:") + THROTTLE_TARGET_NAME_MAX_LEN];
  snprintf(max_hold_name, sizeof(max_hold_name), "rdap:%s", max_host);

  const struct { const char* mp_baseUrl; const char* mp_target; const char* mp_holdName; } accepted[] = {
    { "https://rdap.example.test:8443/rdap/", "rdap.example.test", "rdap:rdap.example.test" },
    { max_url,                                max_host,            max_hold_name },
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
  {
    static_WHOISLOOKUPResetStubs();
    g_stub_RDAP_server_base_url = accepted[i].mp_baseUrl;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, accepted[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_THROTTLE_charge_count, accepted[i].mp_target);
    static_assertWHOISLOOKUPCountedServerRequest("rdap", 30, accepted[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(accepted[i].mp_holdName, g_stub_QUOTA_last_hold_read_name, accepted[i].mp_target);
    free(body);
  }

  const char* const refused[] = { "http://rdap.example.test/", "https:///", over_url };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_WHOISLOOKUPResetStubs();
    g_stub_RDAP_server_base_url = refused[i];
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_UPSTREAM_ERROR, status, refused[i]);
    TEST_ASSERT_NULL_MESSAGE(message, refused[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, refused[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_read_count, refused[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_THROTTLE_charge_count, refused[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_RDAP_lookup_count, refused[i]);
    free(body);
  }
  static_WHOISLOOKUPResetStubs();
}

#define WHOISLOOKUP_WHOIS_BODY                                                                                        \
  "{\"domain\":\"example.co.uk\",\"available\":true,\"rdap_server\":null,\"whois_server\":\"whois.example.test\","    \
  "\"registrar_name\":\"Stub Registrar LLC\",\"registrar_iana_id\":1234,"                                            \
  "\"created_at\":\"2001-02-03T04:05:06Z\",\"updated_at\":\"2025-06-07T08:09:10Z\",\"expires_at\":\"2030-11-12T13:14:15Z\"," \
  "\"status\":[\"client transfer prohibited\",\"server delete prohibited\"],\"status_count\":2,"                     \
  "\"name_servers\":[\"ns1.stub-dns.test\",\"ns2.stub-dns.test\"],\"name_server_count\":2,\"dnssec_signed\":true}\n"

void test_WHOISLOOKUPRun_without_an_rdap_server_asks_the_whois_server_and_keeps_the_answer(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_server_base_url = NULL;
  g_stub_WHOIS_server         = &g_stub_WHOIS_test_server;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(WHOISLOOKUP_WHOIS_BODY, body);

  TEST_ASSERT_EQUAL_INT(1, g_stub_WHOIS_find_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_WHOIS_last_find_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("whois:example.co.uk", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  static_assertWHOISLOOKUPCountedServerRequest("whois", 10, "whois.example.test");
  TEST_ASSERT_EQUAL_INT(1, g_stub_WHOIS_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_WHOIS_last_lookup_name);
  TEST_ASSERT_TRUE(g_stub_WHOIS_last_lookup_server == &g_stub_WHOIS_test_server);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("whois:example.co.uk", g_stub_CACHE_last_put_key);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_CACHE_last_put_expires_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  free(body);
  static_WHOISLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_names_each_failed_whois_query_and_keeps_none(void)
{
  static const struct {
    ThrottleStatus_t    m_chargeStatus;
    WhoisStatus_t       m_lookupStatus;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_message;
    const char*         mp_body;
  } cases[] = {
    { THROTTLE_CHARGED, WHOIS_NOT_REGISTERED, ENDPOINT_RUN_NOT_FOUND,      NULL, "" },
    { THROTTLE_CHARGED, WHOIS_UPSTREAM_ERROR, ENDPOINT_RUN_UPSTREAM_ERROR, NULL, "" },
    { THROTTLE_CHARGED, WHOIS_INVALID_NAME,   ENDPOINT_RUN_REFUSED,        VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, "" },
    { THROTTLE_REFUSED, WHOIS_OK,             ENDPOINT_RUN_OK,             NULL,
      "{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":9}\n" },
    { THROTTLE_ERROR,   WHOIS_OK,             ENDPOINT_RUN_DB_ERROR,       NULL, "" },
  };
  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_server_base_url         = NULL;
  g_stub_WHOIS_server                 = &g_stub_WHOIS_test_server;
  g_stub_THROTTLE_retry_after_seconds = 9;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    g_stub_THROTTLE_charge_status = cases[i].m_chargeStatus;
    g_stub_WHOIS_lookup_status    = cases[i].m_lookupStatus;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    if (cases[i].mp_message == NULL)
      TEST_ASSERT_NULL_MESSAGE(message, label);
    else
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_message, message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    free(body);
  }
  TEST_ASSERT_EQUAL_INT(5, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(3, g_stub_WHOIS_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_WHOISLOOKUPResetStubs();
}

void test_runRow_refuses_whois_lookup_without_a_connection_before_the_run(void)
{
  static_WHOISLOOKUPResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("whois_lookup");
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("/whois_lookup/", row->mp_httpPath);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_whoisLookup.ma_domain, sizeof(params.m_whoisLookup.ma_domain), "%s", "www.example.co.uk");
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);
  TEST_ASSERT_NULL(run_result.mp_message);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_find_count);
  static_WHOISLOOKUPResetStubs();
}

extern const WaybackStubAnswer_t g_stub_WAYBACK_default_answers[2];
extern WaybackStubAnswer_t       g_stub_WAYBACK_answers[2];
extern int                       g_stub_WAYBACK_lookup_count;
extern char                      g_stub_WAYBACK_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern WaybackOrder_t            g_stub_WAYBACK_orders[2];
extern int                       g_stub_WAYBACK_capture_limits[2];
extern int64_t                   g_stub_WAYBACK_deadlines[2];
extern void                    (*g_stub_WAYBACK_on_call)(void);

extern QuotaStatus_t g_stub_QUOTA_reserve_statuses[4];
extern int           g_stub_QUOTA_reserve_status_count;

#define WAYBACKLOOKUP_TEST_CONN ((PGconn*)8)

#define WAYBACKLOOKUP_STUB_BODY \
  "{\"domain\":\"www.example.com\",\"available\":true,\"first_seen\":\"2019-03-05\",\"last_seen\":\"2026-10-24\",\"years_online\":7,\"latest_captures\":[" \
  "{\"captured_at\":\"2026-10-24T16:22:30Z\",\"http_status\":200,\"media_type\":\"text/html\",\"url\":\"https://web.archive.org/web/20261024162230/www.example.com\"}" \
  ",{\"captured_at\":\"2019-03-05T01:02:03Z\",\"http_status\":301,\"media_type\":\"text/plain\",\"url\":\"https://web.archive.org/web/20190305010203/www.example.com\"}" \
  "],\"archive_url\":\"https://web.archive.org/web/*/www.example.com\"}\n"

#define WAYBACKLOOKUP_UNAVAILABLE_BODY "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":7}\n"

static const WaybackCapture_t WAYBACKLOOKUP_TEN_CAPTURES[10] = {
  { "20260915081122", 203, "application/xhtml+xml" },
  { "20250812172233", 206, "text/csv" },
  { "20240711063344", 302, "application/json" },
  { "20230610194455", 307, "image/png" },
  { "20220509005506", 308, "text/css" },
  { "20210408111617", 410, "application/xml" },
  { "20200307222728", 451, "image/gif" },
  { "20190206033839", 500, "font/woff2" },
  { "20180105144950", 502, "audio/ogg" },
  { "20170104155901", 503, "video/mp4" }
};

static bool    g_isClockFake  = false;
static int64_t g_fakeClockMs  = 0;
static int64_t g_movedClockMs = 0;

int64_t __real_monotonic_nowMs(void);
int64_t __wrap_monotonic_nowMs(void);

int64_t __wrap_monotonic_nowMs(void)
{
  return g_isClockFake ? g_fakeClockMs : __real_monotonic_nowMs();
}

static void static_WAYBACKLOOKUPResetStubs(void)
{
  static_WHOISLOOKUPResetStubs();
  memcpy(g_stub_WAYBACK_answers, g_stub_WAYBACK_default_answers, sizeof(g_stub_WAYBACK_answers));
  g_stub_WAYBACK_lookup_count        = 0;
  g_stub_WAYBACK_last_lookup_name[0] = '\0';
  memset(g_stub_WAYBACK_orders, 0xFF, sizeof(g_stub_WAYBACK_orders));
  memset(g_stub_WAYBACK_capture_limits, 0xFF, sizeof(g_stub_WAYBACK_capture_limits));
  memset(g_stub_WAYBACK_deadlines, 0xFF, sizeof(g_stub_WAYBACK_deadlines));
  g_stub_WAYBACK_on_call             = NULL;
  g_stub_QUOTA_reserve_status_count  = 0;
  g_isClockFake                      = false;
  g_fakeClockMs                      = 0;
  g_movedClockMs                     = 0;
}

static void static_WAYBACKLOOKUPSetFirstAnswer(int count)
{
  WaybackStubAnswer_t* answer = &g_stub_WAYBACK_answers[0];
  memset(answer, 0, sizeof(*answer));
  answer->m_status       = WAYBACK_OK;
  answer->m_captureCount = count;
  for (int i = 0; i < count; i++)
    answer->ma_captures[i] = WAYBACKLOOKUP_TEN_CAPTURES[i];
}

static char* static_WAYBACKLOOKUPRun(const char* domain, EndpointRunStatus_t* status_out, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_waybackLookup.ma_domain, sizeof(params.m_waybackLookup.ma_domain), "%s", domain);
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  *status_out  = endpoint_WAYBACKLOOKUPRun(WAYBACKLOOKUP_TEST_CONN, &params, json_buf, message_out);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

static void static_assertWAYBACKLOOKUPRule(const QuotaRule_t* rule)
{
  TEST_ASSERT_NOT_NULL(rule->mp_sourceName);
  TEST_ASSERT_EQUAL_STRING("wayback", rule->mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(10, rule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(2, rule->m_callLimit);
}

void test_WAYBACKLOOKUPRun_short_list_costs_one_request_and_is_kept_for_a_day(void)
{
  static_WAYBACKLOOKUPResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(WAYBACKLOOKUP_STUB_BODY, body);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("wayback:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == WAYBACKLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == WAYBACKLOOKUP_TEST_CONN);
  static_assertWAYBACKLOOKUPRule(&g_stub_QUOTA_last_reserve_rule);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_WAYBACK_last_lookup_name);
  TEST_ASSERT_EQUAL_INT(WAYBACK_ORDER_NEWEST_FIRST, g_stub_WAYBACK_orders[0]);
  TEST_ASSERT_EQUAL_INT(10, g_stub_WAYBACK_capture_limits[0]);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("wayback:www.example.com", g_stub_CACHE_last_put_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_put_conn == WAYBACKLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_size_t(strlen(body), g_stub_CACHE_last_put_body_len);
  TEST_ASSERT_FALSE(g_stub_CACHE_last_put_is_error);
  TEST_ASSERT_EQUAL_UINT(86400, g_stub_CACHE_last_put_expires_after_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == WAYBACKLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("wayback", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_nine_days_cost_one_request_and_ten_cost_two(void)
{
  static_WAYBACKLOOKUPResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  static_WAYBACKLOOKUPSetFirstAnswer(9);
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING(
    "{\"domain\":\"www.example.com\",\"available\":true,\"first_seen\":\"2018-01-05\",\"last_seen\":\"2026-09-15\",\"years_online\":8,\"latest_captures\":["
    "{\"captured_at\":\"2026-09-15T08:11:22Z\",\"http_status\":203,\"media_type\":\"application/xhtml+xml\",\"url\":\"https://web.archive.org/web/20260915081122/www.example.com\"}"
    ",{\"captured_at\":\"2025-08-12T17:22:33Z\",\"http_status\":206,\"media_type\":\"text/csv\",\"url\":\"https://web.archive.org/web/20250812172233/www.example.com\"}"
    ",{\"captured_at\":\"2024-07-11T06:33:44Z\",\"http_status\":302,\"media_type\":\"application/json\",\"url\":\"https://web.archive.org/web/20240711063344/www.example.com\"}"
    ",{\"captured_at\":\"2023-06-10T19:44:55Z\",\"http_status\":307,\"media_type\":\"image/png\",\"url\":\"https://web.archive.org/web/20230610194455/www.example.com\"}"
    ",{\"captured_at\":\"2022-05-09T00:55:06Z\",\"http_status\":308,\"media_type\":\"text/css\",\"url\":\"https://web.archive.org/web/20220509005506/www.example.com\"}"
    ",{\"captured_at\":\"2021-04-08T11:16:17Z\",\"http_status\":410,\"media_type\":\"application/xml\",\"url\":\"https://web.archive.org/web/20210408111617/www.example.com\"}"
    ",{\"captured_at\":\"2020-03-07T22:27:28Z\",\"http_status\":451,\"media_type\":\"image/gif\",\"url\":\"https://web.archive.org/web/20200307222728/www.example.com\"}"
    ",{\"captured_at\":\"2019-02-06T03:38:39Z\",\"http_status\":500,\"media_type\":\"font/woff2\",\"url\":\"https://web.archive.org/web/20190206033839/www.example.com\"}"
    ",{\"captured_at\":\"2018-01-05T14:49:50Z\",\"http_status\":502,\"media_type\":\"audio/ogg\",\"url\":\"https://web.archive.org/web/20180105144950/www.example.com\"}"
    "],\"archive_url\":\"https://web.archive.org/web/*/www.example.com\"}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  free(body);

  static_WAYBACKLOOKUPResetStubs();
  static_WAYBACKLOOKUPSetFirstAnswer(10);
  body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(
    "{\"domain\":\"www.example.com\",\"available\":true,\"first_seen\":\"2002-01-20\",\"last_seen\":\"2026-09-15\",\"years_online\":24,\"latest_captures\":["
    "{\"captured_at\":\"2026-09-15T08:11:22Z\",\"http_status\":203,\"media_type\":\"application/xhtml+xml\",\"url\":\"https://web.archive.org/web/20260915081122/www.example.com\"}"
    ",{\"captured_at\":\"2025-08-12T17:22:33Z\",\"http_status\":206,\"media_type\":\"text/csv\",\"url\":\"https://web.archive.org/web/20250812172233/www.example.com\"}"
    ",{\"captured_at\":\"2024-07-11T06:33:44Z\",\"http_status\":302,\"media_type\":\"application/json\",\"url\":\"https://web.archive.org/web/20240711063344/www.example.com\"}"
    ",{\"captured_at\":\"2023-06-10T19:44:55Z\",\"http_status\":307,\"media_type\":\"image/png\",\"url\":\"https://web.archive.org/web/20230610194455/www.example.com\"}"
    ",{\"captured_at\":\"2022-05-09T00:55:06Z\",\"http_status\":308,\"media_type\":\"text/css\",\"url\":\"https://web.archive.org/web/20220509005506/www.example.com\"}"
    ",{\"captured_at\":\"2021-04-08T11:16:17Z\",\"http_status\":410,\"media_type\":\"application/xml\",\"url\":\"https://web.archive.org/web/20210408111617/www.example.com\"}"
    ",{\"captured_at\":\"2020-03-07T22:27:28Z\",\"http_status\":451,\"media_type\":\"image/gif\",\"url\":\"https://web.archive.org/web/20200307222728/www.example.com\"}"
    ",{\"captured_at\":\"2019-02-06T03:38:39Z\",\"http_status\":500,\"media_type\":\"font/woff2\",\"url\":\"https://web.archive.org/web/20190206033839/www.example.com\"}"
    ",{\"captured_at\":\"2018-01-05T14:49:50Z\",\"http_status\":502,\"media_type\":\"audio/ogg\",\"url\":\"https://web.archive.org/web/20180105144950/www.example.com\"}"
    ",{\"captured_at\":\"2017-01-04T15:59:01Z\",\"http_status\":503,\"media_type\":\"video/mp4\",\"url\":\"https://web.archive.org/web/20170104155901/www.example.com\"}"
    "],\"archive_url\":\"https://web.archive.org/web/*/www.example.com\"}\n", body);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_QUOTA_reserve_count);
  static_assertWAYBACKLOOKUPRule(&g_stub_QUOTA_last_reserve_rule);
  TEST_ASSERT_EQUAL_INT(WAYBACK_ORDER_NEWEST_FIRST, g_stub_WAYBACK_orders[0]);
  TEST_ASSERT_EQUAL_INT(10, g_stub_WAYBACK_capture_limits[0]);
  TEST_ASSERT_EQUAL_INT(WAYBACK_ORDER_OLDEST_FIRST, g_stub_WAYBACK_orders[1]);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_capture_limits[1]);
  TEST_ASSERT_TRUE(g_stub_WAYBACK_deadlines[1] == g_stub_WAYBACK_deadlines[0]);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_WAYBACK_last_lookup_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

static int g_waybackWaitCallCount = 0;

static void static_WAYBACKLOOKUPWaitOnFirstCall(void)
{
  if (g_waybackWaitCallCount++ != 0)
    return;
  const int64_t start_ms = monotonic_nowMs();
  while (monotonic_nowMs() < start_ms + 2)
    ;
}

void test_WAYBACKLOOKUPRun_deadline_is_ten_seconds_after_the_run_starts(void)
{
  static_WAYBACKLOOKUPResetStubs();
  static_WAYBACKLOOKUPSetFirstAnswer(10);
  g_waybackWaitCallCount = 0;
  g_stub_WAYBACK_on_call = static_WAYBACKLOOKUPWaitOnFirstCall;
  EndpointRunStatus_t status;
  const char* message;
  int64_t before_ms = monotonic_nowMs();
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  int64_t after_ms = monotonic_nowMs();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_TRUE(g_stub_WAYBACK_deadlines[0] >= before_ms + 10000);
  TEST_ASSERT_TRUE(g_stub_WAYBACK_deadlines[0] <= after_ms + 10000);
  TEST_ASSERT_TRUE(g_stub_WAYBACK_deadlines[1] == g_stub_WAYBACK_deadlines[0]);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_host_without_a_capture_is_an_empty_answer_and_is_kept(void)
{
  static_WAYBACKLOOKUPResetStubs();
  static_WAYBACKLOOKUPSetFirstAnswer(0);
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(
    "{\"domain\":\"www.example.com\",\"available\":true,\"first_seen\":null,\"last_seen\":null,\"years_online\":null,\"latest_captures\":["
    "],\"archive_url\":\"https://web.archive.org/web/*/www.example.com\"}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_used_up_quota_is_unavailable_and_unread_quota_is_a_db_error(void)
{
  static const struct {
    QuotaStatus_t       ma_statuses[2];
    int                 m_statusCount;
    int                 m_firstCaptureCount;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_body;
    int                 m_lookupCount;
  } cases[] = {
    { { QUOTA_EXHAUSTED, QUOTA_GRANTED }, 1, 2,  ENDPOINT_RUN_OK,       WAYBACKLOOKUP_UNAVAILABLE_BODY, 0 },
    { { QUOTA_GRANTED, QUOTA_EXHAUSTED }, 2, 10, ENDPOINT_RUN_OK,       WAYBACKLOOKUP_UNAVAILABLE_BODY, 1 },
    { { QUOTA_ERROR, QUOTA_GRANTED },     1, 2,  ENDPOINT_RUN_DB_ERROR, "",                             0 },
    { { QUOTA_GRANTED, QUOTA_ERROR },     2, 10, ENDPOINT_RUN_DB_ERROR, "",                             1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_WAYBACKLOOKUPResetStubs();
    static_WAYBACKLOOKUPSetFirstAnswer(cases[i].m_firstCaptureCount);
    g_stub_QUOTA_reserve_statuses[0]      = cases[i].ma_statuses[0];
    g_stub_QUOTA_reserve_statuses[1]      = cases[i].ma_statuses[1];
    g_stub_QUOTA_reserve_status_count     = cases[i].m_statusCount;
    g_stub_QUOTA_window_remaining_seconds = 7;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    if (cases[i].m_runStatus == ENDPOINT_RUN_OK)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("wayback", g_stub_QUOTA_last_window_remaining_rule.mp_sourceName, label);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(10, g_stub_QUOTA_last_window_remaining_rule.m_windowSeconds, label);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_statusCount, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_lookupCount, g_stub_WAYBACK_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_rate_limited_answer_holds_the_cdx_server_for_its_wait(void)
{
  for (int limited_call = 0; limited_call < 2; limited_call++)
  {
    static_WAYBACKLOOKUPResetStubs();
    static_WAYBACKLOOKUPSetFirstAnswer(10);
    g_stub_WAYBACK_answers[limited_call].m_status            = WAYBACK_RATE_LIMITED;
    g_stub_WAYBACK_answers[limited_call].m_retryAfterSeconds = 75;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_NULL(message);
    TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":75}\n", body);
    TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
    TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_set_conn == WAYBACKLOOKUP_TEST_CONN);
    TEST_ASSERT_EQUAL_STRING("wayback", g_stub_QUOTA_last_hold_set_name);
    TEST_ASSERT_EQUAL_UINT(75, g_stub_QUOTA_last_hold_set_seconds);
    TEST_ASSERT_EQUAL_INT(limited_call + 1, g_stub_WAYBACK_lookup_count);
    TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

static void static_WAYBACKLOOKUPStartHold(void)
{
  g_stub_QUOTA_hold_seconds = 33;
}

void test_WAYBACKLOOKUPRun_held_cdx_server_names_the_wait_and_an_unread_hold_is_a_db_error(void)
{
  static const char* const held_body = "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":33}\n";
  EndpointRunStatus_t status;
  const char* message;

  static_WAYBACKLOOKUPResetStubs();
  g_stub_QUOTA_hold_seconds = 33;
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(held_body, body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == WAYBACKLOOKUP_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("wayback", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);

  static_WAYBACKLOOKUPResetStubs();
  static_WAYBACKLOOKUPSetFirstAnswer(10);
  g_stub_WAYBACK_on_call = static_WAYBACKLOOKUPStartHold;
  body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(held_body, body);
  TEST_ASSERT_EQUAL_INT(2, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);

  static_WAYBACKLOOKUPResetStubs();
  g_stub_QUOTA_hold_read_result = false;
  body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WHOISLOOKUPRun_and_WAYBACKLOOKUPRun_one_second_hold_still_holds(void)
{
  EndpointRunStatus_t status;
  const char* message;
  static_WHOISLOOKUPResetStubs();
  g_stub_QUOTA_hold_seconds = 1;
  char* body = static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1}\n", body);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  free(body);
  static_WHOISLOOKUPResetStubs();

  static_WAYBACKLOOKUPResetStubs();
  g_stub_QUOTA_hold_seconds = 1;
  body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1}\n", body);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_docs_name_the_throttle_limits_of_the_whois_lookup_run(void)
{
  EndpointRunStatus_t status;
  const char* message;
  static_WHOISLOOKUPResetStubs();
  free(static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message));
  unsigned int rdap_limit = g_stub_THROTTLE_last_rule.m_chargeLimit;
  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_server_base_url = NULL;
  g_stub_WHOIS_server         = &g_stub_WHOIS_test_server;
  free(static_WHOISLOOKUPRun("www.example.co.uk", WHOISLOOKUP_TEST_CONN, &status, &message));
  unsigned int whois_limit = g_stub_THROTTLE_last_rule.m_chargeLimit;
  static_WHOISLOOKUPResetStubs();

  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md" };
  static const struct { const char* mp_tail; const char* mp_head; int m_limit; } copies[] = {
    { " requests in each minute", "at most ", 0 },
    { " queries to one WHOIS server", "", 1 },
    { " queries to the WHOIS server", "", 1 },
  };
  unsigned int limits[] = { rdap_limit, whois_limit };
  static char docs[1 << 21];
  int seen = 0;
  for (size_t p = 0; p < 2; p++)
  {
    FILE* file = fopen(paths[p], "rb");
    TEST_ASSERT_NOT_NULL(file);
    size_t len = fread(docs, 1, sizeof(docs) - 1, file);
    fclose(file);
    docs[len] = '\0';
    for (size_t k = 0; k < len; k++)
      if (docs[k] == '\n')
        docs[k] = ' ';
    for (size_t c = 0; c < sizeof(copies) / sizeof(copies[0]); c++)
    {
      for (const char* at = strstr(docs, copies[c].mp_tail); at != NULL; at = strstr(at + 1, copies[c].mp_tail))
      {
        char head[64];
        int head_len = snprintf(head, sizeof(head), "%s%u", copies[c].mp_head, limits[copies[c].m_limit]);
        TEST_ASSERT_TRUE_MESSAGE(at - docs >= head_len && strncmp(at - head_len, head, (size_t)head_len) == 0, copies[c].mp_tail);
        seen++;
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(7, seen);
}

void test_docs_name_the_watchlist_caps(void)
{
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md" };
  static const struct { const char* mp_tail; long m_cap; } copies[] = {
    { " package items",                     WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY },
    { " items that are not package items",  WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY },
    { " pairs of an item and an event",     WATCHLIST_ANSWER_PAIR_MAX_COUNT },
    { " items as the CVE and domain items", WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY },
  };
  static char docs[1 << 21];
  int seen = 0;
  for (size_t p = 0; p < 2; p++)
  {
    FILE* file = fopen(paths[p], "rb");
    TEST_ASSERT_NOT_NULL(file);
    size_t len = fread(docs, 1, sizeof(docs) - 1, file);
    fclose(file);
    docs[len] = '\0';
    for (size_t k = 0; k < len; k++)
      if (docs[k] == '\n')
        docs[k] = ' ';
    for (size_t c = 0; c < sizeof(copies) / sizeof(copies[0]); c++)
    {
      for (const char* at = strstr(docs, copies[c].mp_tail); at != NULL; at = strstr(at + 1, copies[c].mp_tail))
      {
        const char* digits = at;
        while (digits > docs && isdigit((unsigned char)digits[-1]))
          digits--;
        if (digits == at)
          continue;
        TEST_ASSERT_EQUAL_INT_MESSAGE(copies[c].m_cap, strtol(digits, NULL, 10), copies[c].mp_tail);
        seen++;
      }
    }
  }
  TEST_ASSERT_EQUAL_INT(13, seen);
}

typedef struct {
  const char*   mp_head;
  unsigned long m_value;
} PackageWeightCopy_t;

static int static_countPackageWeightCopies(const char* const* paths, size_t path_count, const PackageWeightCopy_t* copies, size_t copy_count)
{
  static char docs[1 << 21];
  int seen = 0;
  for (size_t p = 0; p < path_count; p++)
  {
    FILE* file = fopen(paths[p], "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(file, paths[p]);
    size_t len = fread(docs, 1, sizeof(docs) - 1, file);
    fclose(file);
    docs[len] = '\0';
    for (size_t k = 0; k < len; k++)
      if (docs[k] == '\n')
        docs[k] = ' ';
    for (size_t c = 0; c < copy_count; c++)
    {
      for (const char* at = strstr(docs, copies[c].mp_head); at != NULL; at = strstr(at + 1, copies[c].mp_head))
      {
        unsigned long value = 0;
        const char* digit = at + strlen(copies[c].mp_head);
        TEST_ASSERT_TRUE_MESSAGE(*digit >= '0' && *digit <= '9', copies[c].mp_head);
        for (; (*digit >= '0' && *digit <= '9') || *digit == ','; digit++)
          if (*digit != ',')
            value = value * 10 + (unsigned long)(*digit - '0');
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(copies[c].m_value, value, copies[c].mp_head);
        seen++;
      }
    }
  }
  return seen;
}

void test_docs_name_the_weight_budget_of_package_check_bulk(void)
{
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md" };
  static const PackageWeightCopy_t copies[] = {
    { "Each package weighs ",   PACKAGECHECKBULK_ITEM_BASE_WEIGHT },
    { "a package weighs ",      PACKAGECHECKBULK_ITEM_BASE_WEIGHT },
    { "before them is below ",  PACKAGECHECKBULK_WEIGHT_BUDGET },
    { "before each is below ",  PACKAGECHECKBULK_WEIGHT_BUDGET },
    { "A package item weighs ", PACKAGECHECKBULK_ITEM_BASE_WEIGHT },
    { "also weigh at most ",    PACKAGECHECKBULK_WEIGHT_BUDGET },
    { "1 for each ",            PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT },
  };
  enum { PATH_COUNT = sizeof(paths) / sizeof(paths[0]), COPY_KIND_COUNT = sizeof(copies) / sizeof(copies[0]) };
  int seen = static_countPackageWeightCopies(paths, PATH_COUNT, copies, COPY_KIND_COUNT);
  TEST_ASSERT_EQUAL_INT(12, seen);
}

static void static_WAYBACKLOOKUPMoveClock(void)
{
  g_fakeClockMs = g_movedClockMs;
}

void test_WAYBACKLOOKUPRun_passed_deadline_sends_no_second_request(void)
{
  static const struct {
    int64_t             m_movedClockMs;
    EndpointRunStatus_t m_runStatus;
    int                 m_callCount;
    int                 m_putCount;
  } cases[] = {
    { 10999, ENDPOINT_RUN_OK,             2, 1 },
    { 11000, ENDPOINT_RUN_UPSTREAM_ERROR, 1, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_WAYBACKLOOKUPResetStubs();
    static_WAYBACKLOOKUPSetFirstAnswer(10);
    g_isClockFake          = true;
    g_fakeClockMs          = 1000;
    g_movedClockMs         = cases[i].m_movedClockMs;
    g_stub_WAYBACK_on_call = static_WAYBACKLOOKUPMoveClock;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_WAYBACK_deadlines[0] == 11000, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_callCount, g_stub_WAYBACK_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_callCount, g_stub_QUOTA_hold_read_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_callCount, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_putCount, g_stub_CACHE_put_count, label);
    if (cases[i].m_runStatus != ENDPOINT_RUN_OK)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, label);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_failed_or_wrong_sized_answer_is_an_upstream_error(void)
{
  static const struct {
    int             m_firstCaptureCount;
    WaybackStatus_t m_firstStatus;
    WaybackStatus_t m_secondStatus;
    int             m_secondCaptureCount;
    int             m_lookupCount;
  } cases[] = {
    { 2,  WAYBACK_UPSTREAM_ERROR, WAYBACK_OK,             1, 1 },
    { 10, WAYBACK_OK,             WAYBACK_UPSTREAM_ERROR, 1, 2 },
    { 10, WAYBACK_OK,             WAYBACK_OK,             0, 2 },
    { 10, WAYBACK_OK,             WAYBACK_OK,             2, 2 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_WAYBACKLOOKUPResetStubs();
    static_WAYBACKLOOKUPSetFirstAnswer(cases[i].m_firstCaptureCount);
    g_stub_WAYBACK_answers[0].m_status       = cases[i].m_firstStatus;
    g_stub_WAYBACK_answers[1].m_status       = cases[i].m_secondStatus;
    g_stub_WAYBACK_answers[1].m_captureCount = cases[i].m_secondCaptureCount;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_UPSTREAM_ERROR, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_lookupCount, g_stub_WAYBACK_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_refused_name_gets_the_text_of_the_gate(void)
{
  for (int refused_call = 0; refused_call < 2; refused_call++)
  {
    static_WAYBACKLOOKUPResetStubs();
    static_WAYBACKLOOKUPSetFirstAnswer(10);
    g_stub_WAYBACK_answers[refused_call].m_status = WAYBACK_INVALID_NAME;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, status);
    TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
    TEST_ASSERT_EQUAL_STRING("", body);
    TEST_ASSERT_EQUAL_INT(refused_call + 1, g_stub_WAYBACK_lookup_count);
    TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_sends_a_cached_answer_as_it_was_kept(void)
{
  static_WAYBACKLOOKUPResetStubs();
  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"domain\":\"www.example.com\",\"kept\":true}\n";
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"kept\":true}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("wayback:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_longest_name_is_asked_and_kept_whole(void)
{
  static_WAYBACKLOOKUPResetStubs();
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (int i = 0; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    name[i] = (i % 64 == 63) ? '.' : 'a';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN - 1] = 'b';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN]     = '\0';
  char key[sizeof("wayback:") + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(key, sizeof(key), "wayback:%s", name);
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_WAYBACKLOOKUPRun(name, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING(name, g_stub_WAYBACK_last_lookup_name);
  TEST_ASSERT_EQUAL_STRING(key, g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_STRING(key, g_stub_CACHE_last_put_key);
  free(body);
  static_WAYBACKLOOKUPResetStubs();
}

void test_WAYBACKLOOKUPRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put(void)
{
  static const struct { CacheStatus_t m_getStatus; bool m_putResult; } cases[] = {
    { CACHE_MISS,  true  },
    { CACHE_ERROR, true  },
    { CACHE_MISS,  false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_WAYBACKLOOKUPResetStubs();
    g_stub_CACHE_get_status = cases[i].m_getStatus;
    g_stub_CACHE_put_result = cases[i].m_putResult;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_WAYBACKLOOKUPRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_EQUAL_STRING(WAYBACKLOOKUP_STUB_BODY, body);
    TEST_ASSERT_EQUAL_STRING(WAYBACKLOOKUP_STUB_BODY, g_stub_CACHE_last_put_body);
    TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
    TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
    free(body);
  }
  static_WAYBACKLOOKUPResetStubs();
}

void test_runRow_refuses_wayback_lookup_without_a_connection_before_the_run(void)
{
  static_WAYBACKLOOKUPResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("wayback_lookup");
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("/wayback_lookup/", row->mp_httpPath);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_waybackLookup.ma_domain, sizeof(params.m_waybackLookup.ma_domain), "%s", "www.example.com");
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);
  TEST_ASSERT_NULL(run_result.mp_message);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
  static_WAYBACKLOOKUPResetStubs();
}

#define CERTSEARCH_TEST_CONN ((PGconn*)10)

#define CERTSEARCH_STUB_BODY \
  "{\"domain\":\"www.example.com\",\"available\":true,\"complete\":false,\"certificate_count\":3,\"certificates\":[" \
  "{\"sha256_fingerprint\":\"aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899\",\"issuer\":\"Stub Trust CA\"," \
  "\"issuer_caa_domains\":[\"stubtrust.example\",\"stub-ca.example\"],\"valid_from\":\"2026-09-01T01:02:03Z\"," \
  "\"valid_until\":\"2026-12-01T04:05:06Z\",\"revoked\":true,\"dns_names\":[\"stub.example.com\",\"www.stub.example.com\"],\"dns_name_count\":2}" \
  ",{\"sha256_fingerprint\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"issuer\":null," \
  "\"issuer_caa_domains\":null,\"valid_from\":\"2026-03-04T07:08:09Z\",\"valid_until\":\"2027-03-05T10:11:12Z\",\"revoked\":null," \
  "\"dns_names\":[\"*.stub.example.com\",\"n01.stub.example.com\",\"n02.stub.example.com\",\"n03.stub.example.com\"," \
  "\"n04.stub.example.com\",\"n05.stub.example.com\",\"n06.stub.example.com\",\"n07.stub.example.com\",\"n08.stub.example.com\"," \
  "\"n09.stub.example.com\",\"n10.stub.example.com\",\"n11.stub.example.com\",\"n12.stub.example.com\",\"n13.stub.example.com\"," \
  "\"n14.stub.example.com\",\"n15.stub.example.com\",\"n16.stub.example.com\",\"n17.stub.example.com\",\"n18.stub.example.com\"," \
  "\"n19.stub.example.com\"],\"dns_name_count\":25}]}\n"

static void static_CERTSEARCHResetStubs(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_CERTSPOTTER_answer              = g_stub_CERTSPOTTER_default_answer;
  g_stub_CERTSPOTTER_lookup_count        = 0;
  g_stub_CERTSPOTTER_last_lookup_name[0] = '\0';
  g_stub_CERTSPOTTER_last_lookup_conn    = NULL;
  g_stub_CERTSPOTTER_last_lookup_rule    = NULL;
  g_stub_CERTSPOTTER_on_call             = NULL;
  g_stub_CERTSPOTTER_has_api_key         = true;
  g_stub_QUOTA_reserve_status_count      = 0;
}

static char* static_CERTSEARCHRun(const char* domain, EndpointRunStatus_t* status_out, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_certSearch.ma_domain, sizeof(params.m_certSearch.ma_domain), "%s", domain);
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  *status_out  = endpoint_CERTSEARCHRun(CERTSEARCH_TEST_CONN, &params, json_buf, message_out);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

static void static_assertCERTSEARCHRule(const QuotaRule_t* rule)
{
  TEST_ASSERT_NOT_NULL(rule->mp_sourceName);
  TEST_ASSERT_EQUAL_STRING("certspotter_name", rule->mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, rule->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(80, rule->m_callLimit);
}

void test_CERTSEARCHRun_answer_costs_one_request_and_is_kept_for_a_day(void)
{
  static_CERTSEARCHResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(CERTSEARCH_STUB_BODY, body);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == CERTSEARCH_TEST_CONN);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == CERTSEARCH_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("certspotter", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == CERTSEARCH_TEST_CONN);
  static_assertCERTSEARCHRule(&g_stub_QUOTA_last_reserve_rule);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_CERTSPOTTER_last_lookup_name);
  TEST_ASSERT_TRUE(g_stub_CERTSPOTTER_last_lookup_conn == CERTSEARCH_TEST_CONN);
  TEST_ASSERT_NOT_NULL(g_stub_CERTSPOTTER_last_lookup_rule);
  static_assertCERTSEARCHRule(g_stub_CERTSPOTTER_last_lookup_rule);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_put_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_put_conn == CERTSEARCH_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_size_t(strlen(body), g_stub_CACHE_last_put_body_len);
  TEST_ASSERT_FALSE(g_stub_CACHE_last_put_is_error);
  TEST_ASSERT_EQUAL_UINT(86400, g_stub_CACHE_last_put_expires_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  free(body);
  static_CERTSEARCHResetStubs();
}

static void static_readCollapsedDocs(const char* path, char* text, size_t size)
{
  FILE* file = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
  size_t len = fread(text, 1, size - 1, file);
  fclose(file);
  TEST_ASSERT_TRUE_MESSAGE(len > 0 && len < size - 1, path);
  size_t out = 0;
  for (size_t k = 0; k < len; k++)
  {
    bool is_space = text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n';
    if (!is_space)
      text[out++] = text[k];
    else if (out == 0 || text[out - 1] != ' ')
      text[out++] = ' ';
  }
  text[out] = '\0';
}

void test_docs_bot_page_names_the_cert_search_hourly_limit(void)
{
  static_CERTSEARCHResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  free(static_CERTSEARCHRun("www.example.com", &status, &message));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NOT_NULL(g_stub_CERTSPOTTER_last_lookup_rule);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_CERTSPOTTER_last_lookup_rule->m_windowSeconds);
  unsigned int call_limit = (unsigned int)g_stub_CERTSPOTTER_last_lookup_rule->m_callLimit;
  char copies[3][128];
  snprintf(copies[0], sizeof(copies[0]), "The server sends at most %u such requests for its callers in each hour of the clock.", call_limit);
  snprintf(copies[1], sizeof(copies[1]), "apart from the %u requests an hour of <code>/cert_search</code> callers", call_limit);
  snprintf(copies[2], sizeof(copies[2]), "one request for each page of the answer, and at most %d for one call.", CERTSPOTTER_MAX_PAGE_COUNT + 1);
  static_CERTSEARCHResetStubs();

  static char page[1 << 20];
  static_readCollapsedDocs("web/pages/bot.html", page, sizeof(page));
  for (size_t c = 0; c < sizeof(copies) / sizeof(copies[0]); c++)
  {
    const char* hit = strstr(page, copies[c]);
    TEST_ASSERT_NOT_NULL_MESSAGE(hit, copies[c]);
    TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, copies[c]), copies[c]);
  }
}

static void static_assertDocsCopyOnce(const char* path, const char* copy)
{
  static char docs[1 << 21];
  static_readCollapsedDocs(path, docs, sizeof(docs));
  const char* hit = strstr(docs, copy);
  TEST_ASSERT_NOT_NULL_MESSAGE(hit, copy);
  TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, copy), copy);
}

void test_docs_name_the_cert_search_hourly_limit(void)
{
  static_CERTSEARCHResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  free(static_CERTSEARCHRun("www.example.com", &status, &message));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NOT_NULL(g_stub_CERTSPOTTER_last_lookup_rule);
  const QuotaRule_t rule = *g_stub_CERTSPOTTER_last_lookup_rule;
  static_CERTSEARCHResetStubs();
  unsigned int call_limit = (unsigned int)rule.m_callLimit;

  static const char* const api_path = "docs/API_Documentation.md";
  struct {
    const char* mp_path;
    char        ma_copy[160];
  } copies[5];
  copies[0].mp_path = api_path;
  snprintf(copies[0].ma_copy, sizeof(copies[0].ma_copy), "The server sends at most %u requests to Cert Spotter in each hour of the clock, for all callers together.", call_limit);
  copies[1].mp_path = api_path;
  snprintf(copies[1].ma_copy, sizeof(copies[1].ma_copy), "The server has sent %u requests to Cert Spotter for its callers in this hour of the clock", call_limit);
  copies[2].mp_path = api_path;
  snprintf(copies[2].ma_copy, sizeof(copies[2].ma_copy), "This limit is apart from the %u requests of `/cert_search/`.", call_limit);
  copies[3].mp_path = api_path;
  snprintf(copies[3].ma_copy, sizeof(copies[3].ma_copy), "The server sends at most %u requests in each hour, for all callers together.", call_limit);
  copies[4].mp_path = "docs/MCP_Documentation.md";
  snprintf(copies[4].ma_copy, sizeof(copies[4].ma_copy), "The server sends at most %u requests to Cert Spotter in each hour of the clock, for all callers together.", call_limit);
  for (size_t c = 0; c < sizeof(copies) / sizeof(copies[0]); c++)
    static_assertDocsCopyOnce(copies[c].mp_path, copies[c].ma_copy);
}

void test_docs_llms_names_the_watchable_domain_endpoints(void)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  const EndpointParamSpec_t* spec = edit->mp_params[static_watchlistParamIndex(edit, "endpoint")].mp_spec;
  const char* domain_names[16];
  int domain_name_count = 0;
  for (size_t i = 0; spec->mp_enumValues[i] != NULL; i++)
  {
    WatchlistItemKind_t kind;
    TEST_ASSERT_TRUE_MESSAGE(watchlist_findItemKind(spec->mp_enumValues[i], &kind), spec->mp_enumValues[i]);
    if (!watchlist_isDomainItemKind(kind))
      continue;
    TEST_ASSERT_TRUE(domain_name_count < (int)(sizeof(domain_names) / sizeof(domain_names[0])));
    domain_names[domain_name_count++] = spec->mp_enumValues[i];
  }
  TEST_ASSERT_EQUAL_INT(5, domain_name_count);

  char copy[256];
  size_t copy_len = (size_t)snprintf(copy, sizeof(copy), "%s", "or a ");
  for (int i = 0; i < domain_name_count; i++)
  {
    const char* separator = (i == 0) ? "" : (i == domain_name_count - 1) ? " or " : ", ";
    copy_len += (size_t)snprintf(copy + copy_len, sizeof(copy) - copy_len, "%s%s", separator, domain_names[i]);
    TEST_ASSERT_TRUE(copy_len < sizeof(copy));
  }
  snprintf(copy + copy_len, sizeof(copy) - copy_len, "%s", " domain");

  static char llms[1 << 20];
  static_readCollapsedDocs("web/llms.txt", llms, sizeof(llms));
  const char* hit = strstr(llms, copy);
  TEST_ASSERT_NOT_NULL_MESSAGE(hit, copy);
  TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, copy), copy);
}

void test_docs_name_the_ip_watch_comparison_interval(void)
{
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md", "web/pages/ip_intelligence_api.html", "web/pages/privacy.html" };
  static const char* const head = "about every ";
  static char docs[1 << 21];
  TEST_ASSERT_EQUAL_INT(900, MAINTENANCE_INTERVAL_SECONDS);
  int seen = 0;
  for (size_t p = 0; p < sizeof(paths) / sizeof(paths[0]); p++)
  {
    static_readCollapsedDocs(paths[p], docs, sizeof(docs));
    for (const char* at = strstr(docs, head); at != NULL; at = strstr(at + 1, head))
    {
      char* number_end = NULL;
      long minute_count = strtol(at + strlen(head), &number_end, 10);
      if (number_end == at + strlen(head) || strncmp(number_end, " minutes", strlen(" minutes")) != 0)
        continue;
      TEST_ASSERT_EQUAL_INT_MESSAGE(15, minute_count, paths[p]);
      TEST_ASSERT_EQUAL_INT_MESSAGE(MAINTENANCE_INTERVAL_SECONDS, minute_count * 60, paths[p]);
      seen++;
    }
  }
  TEST_ASSERT_EQUAL_INT(6, seen);
}

void test_CERTSEARCHRun_host_without_a_certificate_is_an_empty_answer_and_is_kept(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CERTSPOTTER_answer.m_certificateList.m_keptCount     = 0;
  g_stub_CERTSPOTTER_answer.m_certificateList.m_readCount     = 0;
  g_stub_CERTSPOTTER_answer.m_certificateList.m_isComplete    = true;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"available\":true,\"complete\":true,\"certificate_count\":0,\"certificates\":[]}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_sends_a_cached_answer_as_it_was_kept(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"domain\":\"www.example.com\",\"kept\":true}\n";
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"kept\":true}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put(void)
{
  static const struct { CacheStatus_t m_getStatus; bool m_putResult; } cases[] = {
    { CACHE_MISS,  true  },
    { CACHE_ERROR, true  },
    { CACHE_MISS,  false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_CERTSEARCHResetStubs();
    g_stub_CACHE_get_status = cases[i].m_getStatus;
    g_stub_CACHE_put_result = cases[i].m_putResult;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(CERTSEARCH_STUB_BODY, body, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(CERTSEARCH_STUB_BODY, g_stub_CACHE_last_put_body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_held_cert_spotter_names_the_wait_and_an_unread_hold_is_a_db_error(void)
{
  static const struct {
    unsigned int        m_holdSeconds;
    bool                m_holdReadResult;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_body;
  } cases[] = {
    { 47, true,  ENDPOINT_RUN_OK,       "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":47}\n" },
    { 1,  true,  ENDPOINT_RUN_OK,       "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1}\n" },
    { 47, false, ENDPOINT_RUN_DB_ERROR, "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_CERTSEARCHResetStubs();
    g_stub_QUOTA_hold_seconds     = cases[i].m_holdSeconds;
    g_stub_QUOTA_hold_read_result = cases[i].m_holdReadResult;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_hold_read_count, label);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_QUOTA_last_hold_read_conn == CERTSEARCH_TEST_CONN, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter", g_stub_QUOTA_last_hold_read_name, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CERTSPOTTER_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_used_up_quota_is_unavailable_and_unread_quota_is_a_db_error(void)
{
  static const struct {
    QuotaStatus_t       m_quotaStatus;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_body;
  } cases[] = {
    { QUOTA_EXHAUSTED, ENDPOINT_RUN_OK,       "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n" },
    { QUOTA_ERROR,     ENDPOINT_RUN_DB_ERROR, "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_CERTSEARCHResetStubs();
    g_stub_QUOTA_reserve_status           = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds = 1800;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    if (cases[i].m_runStatus == ENDPOINT_RUN_OK)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter_name", g_stub_QUOTA_last_window_remaining_rule.mp_sourceName, label);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(3600, g_stub_QUOTA_last_window_remaining_rule.m_windowSeconds, label);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_rate_limited_answer_holds_cert_spotter_for_its_wait(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CERTSPOTTER_answer.m_status            = CERTSPOTTER_RATE_LIMITED;
  g_stub_CERTSPOTTER_answer.m_retryAfterSeconds = 75;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":75}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_set_conn == CERTSEARCH_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("certspotter", g_stub_QUOTA_last_hold_set_name);
  TEST_ASSERT_EQUAL_UINT(75, g_stub_QUOTA_last_hold_set_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_walk_cut_after_a_page_answers_no_part_and_is_not_kept(void)
{
  static const struct {
    CertSpotterStatus_t m_lookupStatus;
    EndpointRunStatus_t m_runStatus;
    int                 m_holdSetCount;
    const char*         mp_body;
  } cases[] = {
    { CERTSPOTTER_QUOTA_EXHAUSTED, ENDPOINT_RUN_OK,             0, "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n" },
    { CERTSPOTTER_RATE_LIMITED,    ENDPOINT_RUN_OK,             1, "{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":75}\n" },
    { CERTSPOTTER_UPSTREAM_ERROR,  ENDPOINT_RUN_UPSTREAM_ERROR, 0, "" },
    { CERTSPOTTER_DB_ERROR,        ENDPOINT_RUN_DB_ERROR,       0, "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_CERTSEARCHResetStubs();
    g_stub_CERTSPOTTER_answer.m_status            = cases[i].m_lookupStatus;
    g_stub_CERTSPOTTER_answer.m_retryAfterSeconds = 75;
    g_stub_QUOTA_window_remaining_seconds         = 1800;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_holdSetCount, g_stub_QUOTA_hold_set_count, label);
    if (cases[i].m_holdSetCount > 0)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter", g_stub_QUOTA_last_hold_set_name, label);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(75, g_stub_QUOTA_last_hold_set_seconds, label);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_failed_lookup_or_missing_key_is_an_upstream_error(void)
{
  static const CertSpotterStatus_t statuses[] = { CERTSPOTTER_UPSTREAM_ERROR, CERTSPOTTER_NO_API_KEY };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_CERTSEARCHResetStubs();
    g_stub_CERTSPOTTER_answer.m_status            = statuses[i];
    g_stub_CERTSPOTTER_answer.m_retryAfterSeconds = 75;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_UPSTREAM_ERROR, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_without_a_key_spends_no_quota_and_sends_a_kept_answer(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CERTSPOTTER_has_api_key = false;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_UPSTREAM_ERROR, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"domain\":\"www.example.com\",\"kept\":true}\n";
  body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"www.example.com\",\"kept\":true}\n", body);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_refused_name_gets_the_text_of_the_gate(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CERTSPOTTER_answer.m_status = CERTSPOTTER_INVALID_NAME;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, status);
  TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCHRun_longest_name_is_asked_and_kept_whole(void)
{
  static_CERTSEARCHResetStubs();
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (int i = 0; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    name[i] = (i % 64 == 63) ? '.' : 'a';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN - 1] = 'b';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN]     = '\0';
  char key[sizeof("certspotter:") + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(key, sizeof(key), "certspotter:%s", name);
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_CERTSEARCHRun(name, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING(name, g_stub_CERTSPOTTER_last_lookup_name);
  TEST_ASSERT_EQUAL_STRING(key, g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_STRING(key, g_stub_CACHE_last_put_key);
  free(body);
  static_CERTSEARCHResetStubs();
}

void test_CERTSEARCH_row_asks_cert_spotter_about_the_name_in_lower_case(void)
{
  static_CERTSEARCHResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("cert_search");
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("/cert_search/", row->mp_httpPath);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_restPathSegmentGate(row, "WWW.Example.COM", &params, row->m_paramsSize).m_status);
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, CERTSEARCH_TEST_CONN, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_CERTSPOTTER_last_lookup_name);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_get_key);
  free(run_result.mp_body);
  static_CERTSEARCHResetStubs();
}

void test_runRow_refuses_cert_search_without_a_connection_before_the_run(void)
{
  static_CERTSEARCHResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("cert_search");
  TEST_ASSERT_NOT_NULL(row);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_certSearch.ma_domain, sizeof(params.m_certSearch.ma_domain), "%s", "www.example.com");
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);
  TEST_ASSERT_NULL(run_result.mp_message);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_lookup_count);
  static_CERTSEARCHResetStubs();
}

#define SUBDOMAINENUM_TEST_CONN ((PGconn*)11)

#define SUBDOMAINENUM_FULL_BODY                                                                   \
  "{\"domain\":\"example.com\",\"subdomain_count\":4,\"subdomains\":["                            \
  "{\"hostname\":\"mail.example.com\",\"sources\":[\"dns_records\"]},"                            \
  "{\"hostname\":\"www.example.com\",\"sources\":[\"certificate_logs\",\"dns_wordlist\"]},"       \
  "{\"hostname\":\"api.example.com\",\"sources\":[\"certificate_logs\"]},"                        \
  "{\"hostname\":\"dev.example.com\",\"sources\":[\"certificate_logs\"]}],"                       \
  "\"wildcard_dns\":\"absent\",\"certificate_logs_available\":true,\"certificate_logs_complete\":false}\n"

#define SUBDOMAINENUM_DNS_ONLY_HEAD                                                               \
  "{\"domain\":\"example.com\",\"subdomain_count\":2,\"subdomains\":["                            \
  "{\"hostname\":\"mail.example.com\",\"sources\":[\"dns_records\"]},"                            \
  "{\"hostname\":\"www.example.com\",\"sources\":[\"dns_wordlist\"]}],"                           \
  "\"wildcard_dns\":\"absent\",\"certificate_logs_available\":false,"

static void static_SUBDOMAINENUMResetStubs(void)
{
  static_CERTSEARCHResetStubs();
  g_stub_CERTSPOTTER_subtree_answer         = g_stub_CERTSPOTTER_default_subtree_answer;
  g_stub_CERTSPOTTER_subtree_lookup_count   = 0;
  g_stub_CERTSPOTTER_last_subtree_domain[0] = '\0';
  g_stub_SUBDOMAIN_dns_answer               = g_stub_SUBDOMAIN_default_dns_answer;
  g_stub_SUBDOMAIN_lookup_count             = 0;
  g_stub_SUBDOMAIN_last_lookup_domain[0]    = '\0';
  g_stub_SUBDOMAIN_create_fails             = false;
  g_stub_SUBDOMAIN_create_count             = 0;
  g_stub_SUBDOMAIN_destroy_count            = 0;
}

static char* static_SUBDOMAINENUMRun(const char* domain, EndpointRunStatus_t* status_out, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_subdomainEnum.ma_domain, sizeof(params.m_subdomainEnum.ma_domain), "%s", domain);
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  *status_out  = endpoint_SUBDOMAINENUMRun(SUBDOMAINENUM_TEST_CONN, &params, json_buf, message_out);
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(g_stub_SUBDOMAIN_create_count, g_stub_SUBDOMAIN_destroy_count, "a name set was not freed");
  return body;
}

void test_SUBDOMAINENUMRun_answer_merges_dns_and_certificate_logs_and_is_kept_for_a_day(void)
{
  static_SUBDOMAINENUMResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(SUBDOMAINENUM_FULL_BODY, body);

  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_SUBDOMAIN_last_lookup_domain);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_hold_read_conn == SUBDOMAINENUM_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING("certspotter_subtree", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == SUBDOMAINENUM_TEST_CONN);
  TEST_ASSERT_NOT_NULL(g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_STRING("certspotter_subtree", g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_QUOTA_last_reserve_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(5, g_stub_QUOTA_last_reserve_rule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_CERTSPOTTER_last_subtree_domain);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == SUBDOMAINENUM_TEST_CONN);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_put_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_put_conn == SUBDOMAINENUM_TEST_CONN);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_size_t(strlen(body), g_stub_CACHE_last_put_body_len);
  TEST_ASSERT_FALSE(g_stub_CACHE_last_put_is_error);
  TEST_ASSERT_EQUAL_UINT(86400, g_stub_CACHE_last_put_expires_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_create_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

static int g_dnsLookupCountAtCertSpotterCall = -1;

static void static_recordDnsLookupCount(void)
{
  g_dnsLookupCountAtCertSpotterCall = g_stub_SUBDOMAIN_lookup_count;
}

void test_SUBDOMAINENUMRun_asks_dns_before_cert_spotter(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_dnsLookupCountAtCertSpotterCall = -1;
  g_stub_CERTSPOTTER_on_call        = static_recordDnsLookupCount;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  g_stub_CERTSPOTTER_on_call = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_INT(1, g_dnsLookupCountAtCertSpotterCall);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_asks_about_the_registrable_domain_of_a_name(void)
{
  static_SUBDOMAINENUMResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("www.shop.example.co.uk", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING_LEN("{\"domain\":\"example.co.uk\",", body, strlen("{\"domain\":\"example.co.uk\","));
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_SUBDOMAIN_last_lookup_domain);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_CERTSPOTTER_last_subtree_domain);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.co.uk", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.co.uk", g_stub_CACHE_last_put_key);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_refuses_a_public_suffix_before_any_question(void)
{
  static_SUBDOMAINENUMResetStubs();
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("co.uk", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, status);
  TEST_ASSERT_EQUAL_STRING(ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE, message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_create_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_sends_a_cached_answer_as_it_was_kept(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"domain\":\"example.com\",\"kept\":true}\n";
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("www.example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("{\"domain\":\"example.com\",\"kept\":true}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_create_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put(void)
{
  static const struct { CacheStatus_t m_getStatus; bool m_putResult; } cases[] = {
    { CACHE_MISS,  true  },
    { CACHE_ERROR, true  },
    { CACHE_MISS,  false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_SUBDOMAINENUMResetStubs();
    g_stub_CACHE_get_status = cases[i].m_getStatus;
    g_stub_CACHE_put_result = cases[i].m_putResult;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SUBDOMAINENUM_FULL_BODY, body, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SUBDOMAINENUM_FULL_BODY, g_stub_CACHE_last_put_body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_SUBDOMAIN_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_subtree_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, label);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_without_a_key_answers_the_dns_names_for_ten_minutes(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_CERTSPOTTER_has_api_key = false;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING(SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"upstream_error\"}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_put_key);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  TEST_ASSERT_EQUAL_UINT(600, g_stub_CACHE_last_put_expires_after_seconds);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_held_cert_spotter_answers_the_dns_names_with_the_wait(void)
{
  static const struct { unsigned int m_holdSeconds; const char* mp_body; } cases[] = {
    { 47, SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":47}\n" },
    { 1,  SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":1}\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_SUBDOMAINENUMResetStubs();
    g_stub_QUOTA_hold_seconds = cases[i].m_holdSeconds;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_hold_read_count, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter_subtree", g_stub_QUOTA_last_hold_read_name, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_SUBDOMAIN_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CERTSPOTTER_subtree_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(600, g_stub_CACHE_last_put_expires_after_seconds, label);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_unread_hold_is_a_db_error(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_QUOTA_hold_read_result = false;
  g_stub_QUOTA_hold_seconds     = 47;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_used_up_quota_answers_the_dns_names_and_unread_quota_is_a_db_error(void)
{
  static const struct {
    QuotaStatus_t       m_quotaStatus;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_body;
    int                 m_dnsLookupCount;
    int                 m_putCount;
  } cases[] = {
    { QUOTA_EXHAUSTED, ENDPOINT_RUN_OK,       SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n", 1, 1 },
    { QUOTA_ERROR,     ENDPOINT_RUN_DB_ERROR, "",                                                                                                            0, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_SUBDOMAINENUMResetStubs();
    g_stub_QUOTA_reserve_status           = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds = 1800;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_reserve_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_dnsLookupCount, g_stub_SUBDOMAIN_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CERTSPOTTER_subtree_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_putCount, g_stub_CACHE_put_count, label);
    if (cases[i].m_putCount > 0)
    {
      TEST_ASSERT_EQUAL_UINT_MESSAGE(1800, g_stub_CACHE_last_put_expires_after_seconds, label);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter_subtree", g_stub_QUOTA_last_window_remaining_rule.mp_sourceName, label);
      TEST_ASSERT_EQUAL_UINT_MESSAGE(3600, g_stub_QUOTA_last_window_remaining_rule.m_windowSeconds, label);
    }
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_rate_limited_answer_holds_cert_spotter_for_its_wait(void)
{
  static const struct { unsigned int m_waitSeconds; const char* mp_body; unsigned int m_keepSeconds; } cases[] = {
    { 1800, SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n", 1800 },
    { 599,  SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":599}\n",  600  },
    { 600,  SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":600}\n",  600  },
    { 601,  SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":601}\n",  601  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_SUBDOMAINENUMResetStubs();
    g_stub_CERTSPOTTER_subtree_answer.m_status            = CERTSPOTTER_RATE_LIMITED;
    g_stub_CERTSPOTTER_subtree_answer.m_retryAfterSeconds = cases[i].m_waitSeconds;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_QUOTA_last_hold_set_conn == SUBDOMAINENUM_TEST_CONN, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("certspotter_subtree", g_stub_QUOTA_last_hold_set_name, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_waitSeconds, g_stub_QUOTA_last_hold_set_seconds, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_SUBDOMAIN_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_subtree_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_keepSeconds, g_stub_CACHE_last_put_expires_after_seconds, label);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_failed_certificate_log_lookup_answers_the_dns_names_for_ten_minutes(void)
{
  static const CertSpotterStatus_t statuses[] = { CERTSPOTTER_UPSTREAM_ERROR, CERTSPOTTER_NO_API_KEY };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    static_SUBDOMAINENUMResetStubs();
    g_stub_CERTSPOTTER_subtree_answer.m_status            = statuses[i];
    g_stub_CERTSPOTTER_subtree_answer.m_retryAfterSeconds = 3600;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, label);
    TEST_ASSERT_NULL_MESSAGE(message, label);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(SUBDOMAINENUM_DNS_ONLY_HEAD "\"certificate_logs_reason\":\"upstream_error\"}\n", body, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_SUBDOMAIN_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CERTSPOTTER_subtree_lookup_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_QUOTA_hold_set_count, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(600, g_stub_CACHE_last_put_expires_after_seconds, label);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_refused_name_gets_the_text_of_the_gate(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_CERTSPOTTER_subtree_answer.m_status = CERTSPOTTER_INVALID_NAME;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, status);
  TEST_ASSERT_EQUAL_STRING(VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE, message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_set_that_cannot_be_made_is_no_memory(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_SUBDOMAIN_create_fails = true;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_MEMORY, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_EQUAL_STRING("", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_wildcard_verdict_reaches_the_answer(void)
{
  static const struct { SubdomainWildcard_t m_wildcardDns; const char* mp_member; } cases[] = {
    { SUBDOMAIN_WILDCARD_PRESENT,      "\"wildcard_dns\":\"present\"" },
    { SUBDOMAIN_WILDCARD_UNDETERMINED, "\"wildcard_dns\":\"undetermined\"" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_SUBDOMAINENUMResetStubs();
    g_stub_SUBDOMAIN_dns_answer.m_wildcardDns = cases[i].m_wildcardDns;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, cases[i].mp_member);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_member), cases[i].mp_member);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_undetermined_wildcard_answer_is_kept_for_ten_minutes(void)
{
  static const struct { QuotaStatus_t m_quotaStatus; const char* mp_member; } cases[] = {
    { QUOTA_GRANTED,   "\"certificate_logs_available\":true" },
    { QUOTA_EXHAUSTED, "\"retry_after_seconds\":1800" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_SUBDOMAINENUMResetStubs();
    g_stub_SUBDOMAIN_dns_answer.m_wildcardDns = SUBDOMAIN_WILDCARD_UNDETERMINED;
    g_stub_QUOTA_reserve_status               = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds     = 1800;
    EndpointRunStatus_t status;
    const char* message;
    char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_OK, status, cases[i].mp_member);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, "\"wildcard_dns\":\"undetermined\""), cases[i].mp_member);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, cases[i].mp_member), cases[i].mp_member);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CACHE_put_count, cases[i].mp_member);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(600, g_stub_CACHE_last_put_expires_after_seconds, cases[i].mp_member);
    free(body);
  }
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUMRun_empty_certificate_log_answer_is_complete(void)
{
  static_SUBDOMAINENUMResetStubs();
  g_stub_CERTSPOTTER_subtree_answer.m_nameCount     = 0;
  g_stub_CERTSPOTTER_subtree_answer.m_isAnswerEmpty = true;
  EndpointRunStatus_t status;
  const char* message;
  char* body = static_SUBDOMAINENUMRun("example.com", &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING(
    "{\"domain\":\"example.com\",\"subdomain_count\":2,\"subdomains\":["
    "{\"hostname\":\"mail.example.com\",\"sources\":[\"dns_records\"]},"
    "{\"hostname\":\"www.example.com\",\"sources\":[\"dns_wordlist\"]}],"
    "\"wildcard_dns\":\"absent\",\"certificate_logs_available\":true,\"certificate_logs_complete\":true}\n", body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
  free(body);
  static_SUBDOMAINENUMResetStubs();
}

void test_SUBDOMAINENUM_row_asks_about_the_name_in_lower_case(void)
{
  static_SUBDOMAINENUMResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("subdomain_enum");
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_EQUAL_STRING("/subdomain_enum/", row->mp_httpPath);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_restPathSegmentGate(row, "WWW.Example.COM", &params, row->m_paramsSize).m_status);
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, SUBDOMAINENUM_TEST_CONN, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, run_result.m_status);
  TEST_ASSERT_NOT_NULL(run_result.mp_body);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_SUBDOMAIN_last_lookup_domain);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_CERTSPOTTER_last_subtree_domain);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_get_key);
  free(run_result.mp_body);
  static_SUBDOMAINENUMResetStubs();
}

void test_runRow_refuses_subdomain_enum_without_a_connection_before_the_run(void)
{
  static_SUBDOMAINENUMResetStubs();
  const Endpoint_t* row = endpoint_findByMcpName("subdomain_enum");
  TEST_ASSERT_NOT_NULL(row);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_subdomainEnum.ma_domain, sizeof(params.m_subdomainEnum.ma_domain), "%s", "example.com");
  EndpointRunResult_t run_result = endpoint_runRow(row, &params, NULL, &TEST_FULL_CHARGE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, run_result.m_status);
  TEST_ASSERT_NULL(run_result.mp_body);
  TEST_ASSERT_NULL(run_result.mp_message);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  static_SUBDOMAINENUMResetStubs();
}

void test_IPLOOKUPRun_refuses_a_text_that_holds_no_address(void)
{
  static const char* const texts[] = { "8.8.8.8x", "2001:4860::88888" };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.m_ipLookup.ma_ipAddress, sizeof(params.m_ipLookup.ma_ipAddress), "%s", texts[i]);
    JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    TEST_ASSERT_NOT_NULL(json_buf);
    const char* message = NULL;

    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, endpoint_IPLOOKUPRun(NULL, &params, json_buf, &message), texts[i]);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(IPGUARD_GLOBALLY_REACHABLE_IP_REFUSAL_MESSAGE, message, texts[i]);
    char* body = jsonbuf_finish(json_buf);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, texts[i]);
    free(body);
    jsonbuf_destroy(json_buf);
  }
}

void test_ASNLOOKUPRun_refuses_a_text_that_holds_no_target(void)
{
  static const char* const texts[] = { "AS0", "AS015169", "4294967296", "1.10", "8.8.8.8x" };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.m_asnLookup.ma_target, sizeof(params.m_asnLookup.ma_target), "%s", texts[i]);
    JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    TEST_ASSERT_NOT_NULL(json_buf);
    const char* message = NULL;

    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, endpoint_ASNLOOKUPRun(NULL, &params, json_buf, &message), texts[i]);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(VALIDATE_ASN_LOOKUP_TARGET_REFUSAL_MESSAGE, message, texts[i]);
    char* body = jsonbuf_finish(json_buf);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, texts[i]);
    free(body);
    jsonbuf_destroy(json_buf);
  }
}

void test_only_the_email_spec_decodes_its_path_segment(void)
{
  int decoded_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      if (!param->mp_spec->m_isPathSegmentPercentDecoded)
        continue;
      TEST_ASSERT_EQUAL_STRING("/email_address_check/", endpoint->mp_httpPath);
      TEST_ASSERT_EQUAL_STRING("email", param->mp_spec->mp_name);
      TEST_ASSERT_TRUE((param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0);
      decoded_count++;
    }
  }
  TEST_ASSERT_EQUAL_INT(1, decoded_count);
}

#define EMAILADDRESSCHECK_ENCODED_LOCAL_PART \
  "%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B" \
  "%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B"

void test_restPathSegmentGate_decodes_the_email_segment(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/email_address_check/x", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);

  static const char label_63[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  char domain_190[200];
  char domain_191[200];
  int  written = snprintf(domain_190, sizeof(domain_190), "%s.%s.%.62s", label_63, label_63, label_63);
  TEST_ASSERT_EQUAL_INT(190, written);
  written = snprintf(domain_191, sizeof(domain_191), "%s.%s.%s", label_63, label_63, label_63);
  TEST_ASSERT_EQUAL_INT(191, written);
  char segment_254[512];
  char segment_255[512];
  char decoded_254[VALIDATE_EMAIL_ADDRESS_MAX_LEN + 1];
  written = snprintf(segment_254, sizeof(segment_254), "%s%%40%s", EMAILADDRESSCHECK_ENCODED_LOCAL_PART, domain_190);
  TEST_ASSERT_TRUE(written > VALIDATE_EMAIL_ADDRESS_MAX_LEN && (size_t)written < sizeof(segment_254));
  written = snprintf(segment_255, sizeof(segment_255), "%s%%40%s", EMAILADDRESSCHECK_ENCODED_LOCAL_PART, domain_191);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(segment_255));
  written = snprintf(decoded_254, sizeof(decoded_254), "%.63s@%s", "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++", domain_190);
  TEST_ASSERT_EQUAL_INT(VALIDATE_EMAIL_ADDRESS_MAX_LEN, written);

  const struct { const char* mp_segment; EndpointGateStatus_t m_status; const char* mp_decoded; } cases[] = {
    { "first.last%2Btag%40Example.COM", ENDPOINT_GATE_OK,                 "first.last+tag@Example.COM" },
    { "a+b@example.com",                ENDPOINT_GATE_OK,                 "a+b@example.com" },
    { "a%25b@example.com",              ENDPOINT_GATE_OK,                 "a%b@example.com" },
    { "a%2fb@example.com",              ENDPOINT_GATE_OK,                 "a/b@example.com" },
    { segment_254,                      ENDPOINT_GATE_OK,                 decoded_254 },
    { segment_255,                      ENDPOINT_GATE_REJECT_VALUE,       NULL },
    { "a%2@example.com",                ENDPOINT_GATE_REJECT_ENCODING,    NULL },
    { "a%zz@example.com",               ENDPOINT_GATE_REJECT_ENCODING,    NULL },
    { "a@example.com%4",                ENDPOINT_GATE_REJECT_ENCODING,    NULL },
    { "a%00@example.com",               ENDPOINT_GATE_REJECT_CONTROL_CHAR, NULL },
    { "a%0Ab@example.com",              ENDPOINT_GATE_REJECT_VALUE,       NULL },
    { "a%20b@example.com",              ENDPOINT_GATE_REJECT_VALUE,       NULL },
    { "a%40b@example.com",              ENDPOINT_GATE_REJECT_VALUE,       NULL },
    { "a@example.local",                ENDPOINT_GATE_REJECT_VALUE,       NULL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0x5A, sizeof(params));

    EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(endpoint, cases[i].mp_segment, &params, endpoint->m_paramsSize);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_segment);
    if (cases[i].mp_decoded != NULL)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(-1, gate_result.m_refusedParamIndex, cases[i].mp_segment);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_decoded, params.m_emailAddressCheck.ma_email, cases[i].mp_segment);
      const unsigned char* after = (const unsigned char*)&params + strlen(cases[i].mp_decoded) + 1;
      for (const unsigned char* byte = after; byte < (const unsigned char*)&params + endpoint->m_paramsSize; byte++)
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5A, *byte, cases[i].mp_segment);
      continue;
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, gate_result.m_refusedParamIndex, cases[i].mp_segment);
    const unsigned char* bytes = (const unsigned char*)&params;
    for (size_t j = 0; j < endpoint->m_paramsSize; j++)
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5A, bytes[j], cases[i].mp_segment);
  }
}

static const EndpointParamSpec_t TEST_SPEC_DECODED_NOTE = {
  .mp_name                       = "note",
  .m_type                        = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen                      = 5,
  .m_isPathSegmentPercentDecoded = true,
};

static const EndpointParam_t TEST_DECODED_FIELD_OF_SIX_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_DECODED_NOTE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT,
    .m_isRequired         = true,
    .m_offset             = 0,
    .m_size               = 6,
  },
};

void test_restPathSegmentGate_holds_a_decoded_segment_to_its_field(void)
{
  const Endpoint_t endpoint = {
    .mp_httpPath          = "/test_decoded_field_of_six/",
    .m_hasPathSegment     = true,
    .mp_params            = TEST_DECODED_FIELD_OF_SIX_PARAMS,
    .m_paramCount         = 1,
    .m_paramsSize         = 6,
  };
  static const struct { const char* mp_segment; EndpointGateStatus_t m_status; const char* mp_decoded; } cases[] = {
    { "abcd",            ENDPOINT_GATE_OK,           "abcd"  },
    { "abcde",           ENDPOINT_GATE_OK,           "abcde" },
    { "%61%62%63%64%65", ENDPOINT_GATE_OK,           "abcde" },
    { "abcdef",          ENDPOINT_GATE_REJECT_VALUE, NULL },
    { "ab%63def",        ENDPOINT_GATE_REJECT_VALUE, NULL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    unsigned char buffer[16];
    memset(buffer, 0x5A, sizeof(buffer));

    EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(&endpoint, cases[i].mp_segment, buffer, endpoint.m_paramsSize);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, gate_result.m_status, cases[i].mp_segment);
    size_t untouched_from = 0;
    if (cases[i].mp_decoded != NULL)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_decoded, (const char*)buffer, cases[i].mp_segment);
      untouched_from = strlen(cases[i].mp_decoded) + 1;
    }
    for (size_t k = untouched_from; k < sizeof(buffer); k++)
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5A, buffer[k], cases[i].mp_segment);
  }
}

void test_restPathSegmentGate_leaves_another_segment_encoded(void)
{
  const Endpoint_t* endpoint = endpoint_findByHttpPath("/dns_lookup/x", NULL);
  TEST_ASSERT_NOT_NULL(endpoint);
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));

  EndpointGateResult_t gate_result = endpoint_restPathSegmentGate(endpoint, "example%2Ecom", &params, endpoint->m_paramsSize);

  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_VALUE, gate_result.m_status);
}

void test_EMAILADDRESSCHECKRun_refuses_a_text_that_holds_no_address(void)
{
  static const char* const texts[] = { "example.com", "@example.com", "a@", "a..b@example.com", "a@example.local" };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.m_emailAddressCheck.ma_email, sizeof(params.m_emailAddressCheck.ma_email), "%s", texts[i]);
    JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
    TEST_ASSERT_NOT_NULL(json_buf);
    const char* message = NULL;

    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_RUN_REFUSED, endpoint_EMAILADDRESSCHECKRun(NULL, &params, json_buf, &message), texts[i]);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE, message, texts[i]);
    char* body = jsonbuf_finish(json_buf);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, texts[i]);
    free(body);
    jsonbuf_destroy(json_buf);
  }
}

#define USAGELOG_TEST_INSTANCE_PORT 8002

static char g_usageLines[USAGELOG_DRAIN_BUF_SIZE];

static void static_beginUsageRecord(void)
{
  usagelog_start(USAGELOG_TEST_INSTANCE_PORT);
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  usagelog_beginRequest();
}

static int static_writeUsageRecord(void)
{
  usagelog_writeRequest();
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  int line_count = 0;
  for (const char* c = g_usageLines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

static void static_fillThreeIds(BulkIdsParams_t* ids)
{
  memset(ids, 0, sizeof(*ids));
  for (int i = 0; i < 3; i++)
    snprintf(ids->ma_ids[i], sizeof(ids->ma_ids[i]), "CVE-2023-%04d", i + 1);
  ids->m_idCount = 3;
}

void test_runRow_gives_the_usage_log_the_ids_the_gate_kept(void)
{
  const Endpoint_t* bulk = endpoint_findByMcpName("cve_lookup_bulk");
  TEST_ASSERT_NOT_NULL(bulk);
  EndpointAnyParams_t params;
  static_fillThreeIds(&params.m_bulkIds);
  const RequestCharge_t charge_of_2 = { .m_chargedCreditCount = 2, .mp_creditBudget = NULL, .mp_x402Payment = NULL };

  static_beginUsageRecord();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(bulk, &params, NULL, &charge_of_2).m_status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_EQUAL_INT(2, params.m_bulkIds.m_idCount);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"item_count\":3}\n"), g_usageLines);
}

void test_runRow_gives_the_usage_log_the_packages_the_gate_kept(void)
{
  const Endpoint_t*   row = static_packageRow();
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_packageCheckBulk.m_itemCount = 4;
  const RequestCharge_t charge_of_2 = { .m_chargedCreditCount = 2, .mp_creditBudget = NULL, .mp_x402Payment = NULL };

  static_beginUsageRecord();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(row, &params, NULL, &charge_of_2).m_status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_EQUAL_INT(2, params.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"item_count\":4}\n"), g_usageLines);
}

void test_runRow_gives_no_item_count_on_a_row_that_is_not_bulk(void)
{
  const Endpoint_t* bulk   = endpoint_findByMcpName("cve_lookup_bulk");
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(bulk);
  TEST_ASSERT_NOT_NULL(lookup);
  EndpointAnyParams_t params;

  static_fillThreeIds(&params.m_bulkIds);
  static_beginUsageRecord();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(bulk, &params, NULL, &TEST_FULL_CHARGE).m_status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"item_count\":3}\n"), g_usageLines);

  memset(&params, 0, sizeof(params));
  static_beginUsageRecord();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_NO_CONNECTION, endpoint_runRow(lookup, &params, NULL, &TEST_FULL_CHARGE).m_status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NULL_MESSAGE(strstr(g_usageLines, "\"item_count\""), g_usageLines);
}

#define HEADERSCHECK_TEST_CONN ((PGconn*)9)

#define HEADERSCHECK_CHECKED_AT_MASK "YYYY-MM-DDTHH:MM:SSZ"

#define HEADERSCHECK_STUB_BODY \
  "{\"url\":\"https://www.stub.example.com/\",\"status_code\":200,\"redirect_count\":1,\"checked_at\":\"YYYY-MM-DDTHH:MM:SSZ\",\"findings\":[" \
  "{\"header\":\"Content-Security-Policy\",\"severity\":\"high\",\"result\":\"pass\",\"issues\":[],\"value\":\"default-src 'self'; object-src 'none'; base-uri 'self'\"}" \
  ",{\"header\":\"Strict-Transport-Security\",\"severity\":\"high\",\"result\":\"fail\",\"issues\":[\"Missing includeSubDomains directive\"],\"value\":\"max-age=31536000\",\"remediation\":\"Add Strict-Transport-Security: max-age=63072000; includeSubDomains\"}" \
  ",{\"header\":\"X-Content-Type-Options\",\"severity\":\"medium\",\"result\":\"pass\",\"issues\":[],\"value\":\"nosniff\"}" \
  ",{\"header\":\"X-Frame-Options\",\"severity\":\"medium\",\"result\":\"missing\",\"issues\":[],\"value\":null,\"remediation\":\"Add X-Frame-Options: DENY or SAMEORIGIN\"}" \
  ",{\"header\":\"Referrer-Policy\",\"severity\":\"low\",\"result\":\"fail\",\"issues\":[\"Policy unsafe-url sends the full URL, path and query included, to every origin\"],\"value\":\"unsafe-url\",\"remediation\":\"Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer\"}" \
  ",{\"header\":\"Permissions-Policy\",\"severity\":\"low\",\"result\":\"missing\",\"issues\":[],\"value\":null,\"remediation\":\"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())\"}" \
  ",{\"header\":\"X-XSS-Protection\",\"severity\":\"low\",\"result\":\"warn\",\"issues\":[\"A value other than 0 turns on the legacy XSS filter, which can create XSS vulnerabilities\"],\"value\":\"1; mode=block\",\"remediation\":\"Remove X-XSS-Protection or set it to 0; use Content-Security-Policy against XSS\"}" \
  ",{\"header\":\"Set-Cookie\",\"severity\":\"medium\",\"result\":\"fail\",\"issues\":[\"Cookies with no Secure attribute: 1\"],\"value\":null,\"cookie_count\":2,\"remediation\":\"Mark every cookie Secure with SameSite=Lax or Strict, and mark session cookies HttpOnly\"}" \
  ",{\"header\":\"Access-Control-Allow-Origin\",\"severity\":\"low\",\"result\":\"warn\",\"issues\":[\"Allowing the origin null lets any sandboxed frame read the answer\"],\"value\":\"null\",\"remediation\":\"Send Access-Control-Allow-Origin with one trusted origin; never null, and never * with credentials\"}" \
  "]}" "\n"

static void static_HEADERSCHECKResetStubs(void)
{
  static_WHOISLOOKUPResetStubs();
  g_stub_HEADER_FETCH_error            = HTTP_ERROR_NONE;
  g_stub_HEADER_FETCH_answer           = g_stub_HEADER_FETCH_default_answer;
  g_stub_HEADER_FETCH_call_count       = 0;
  g_stub_HEADER_FETCH_last_hostname[0] = '\0';
  g_stub_HEADER_FETCH_free_count       = 0;
  g_stub_HEADER_FETCH_on_call          = NULL;
}

static void static_HEADERSCHECKMaskCheckedAt(char* body, const char* before, const char* after)
{
  char* member = strstr(body, "\"checked_at\":\"");
  TEST_ASSERT_NOT_NULL_MESSAGE(member, body);
  char* value = member + strlen("\"checked_at\":\"");
  TEST_ASSERT_EQUAL_CHAR_MESSAGE('"', value[sizeof(HEADERSCHECK_CHECKED_AT_MASK) - 1], body);
  char checked_at[sizeof(HEADERSCHECK_CHECKED_AT_MASK)];
  memcpy(checked_at, value, sizeof(checked_at) - 1);
  checked_at[sizeof(checked_at) - 1] = '\0';
  TEST_ASSERT_TRUE_MESSAGE(strcmp(before, checked_at) <= 0 && strcmp(checked_at, after) <= 0, checked_at);
  memcpy(value, HEADERSCHECK_CHECKED_AT_MASK, sizeof(HEADERSCHECK_CHECKED_AT_MASK) - 1);
}

static void static_HEADERSCHECKUtcText(time_t when, char* text_out)
{
  struct tm when_utc;
  TEST_ASSERT_NOT_NULL(gmtime_r(&when, &when_utc));
  TEST_ASSERT_EQUAL_size_t(HEADERSCHECK_CHECKED_AT_TEXT_SIZE - 1, strftime(text_out, HEADERSCHECK_CHECKED_AT_TEXT_SIZE, "%Y-%m-%dT%H:%M:%SZ", &when_utc));
}

static char* static_HEADERSCHECKRun(PGconn* conn, const char* hostname, bool is_full_header_value_included, EndpointRunStatus_t* status_out, const char** message_out)
{
  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.m_headersCheck.ma_hostname, sizeof(params.m_headersCheck.ma_hostname), "%s", hostname);
  params.m_headersCheck.m_isFullHeaderValueIncluded = is_full_header_value_included;
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  *message_out = NULL;
  *status_out  = endpoint_HEADERSCHECKRun(conn, &params, json_buf, message_out);
  size_t body_len = jsonbuf_length(json_buf);
  char*  body     = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  if (body_len == 0)
  {
    free(body);
    return NULL;
  }
  return body;
}

void test_HEADERSCHECKRun_names_why_each_fetch_failed(void)
{
  static const struct {
    HttpError_t         m_fetchError;
    EndpointRunStatus_t m_runStatus;
    const char*         mp_message;
  } cases[] = {
    { HTTP_ERROR_TIMEOUT,        ENDPOINT_RUN_TARGET_UNREACHABLE, "the site did not answer in time: a connection may take 2000 ms, and the whole fetch 5000 ms" },
    { HTTP_ERROR_RESOLVE,        ENDPOINT_RUN_TARGET_UNREACHABLE, "the host name did not resolve" },
    { HTTP_ERROR_CONNECT,        ENDPOINT_RUN_TARGET_UNREACHABLE, "no address of the site took a connection on port 443" },
    { HTTP_ERROR_TLS,            ENDPOINT_RUN_TARGET_UNREACHABLE, "the TLS handshake with the site failed, or its certificate did not verify; /ssl_check shows why" },
    { HTTP_ERROR_BODY_TOO_LARGE, ENDPOINT_RUN_UPSTREAM_ERROR,     NULL },
    { HTTP_ERROR_BLOCKED,        ENDPOINT_RUN_REFUSED,            "hostname resolves to an address that is not globally reachable" },
    { HTTP_ERROR_OTHER,          ENDPOINT_RUN_UPSTREAM_ERROR,     NULL },
  };
  static_HEADERSCHECKResetStubs();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_HEADER_FETCH_error            = cases[i].m_fetchError;
    g_stub_HEADER_FETCH_last_hostname[0] = '\0';
    EndpointRunStatus_t status;
    const char*         message;
    char* body = static_HEADERSCHECKRun(HEADERSCHECK_TEST_CONN, "shop.example.com", false, &status, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_runStatus, status, cases[i].mp_message);
    if (cases[i].mp_message == NULL)
      TEST_ASSERT_NULL(message);
    else
      TEST_ASSERT_EQUAL_STRING(cases[i].mp_message, message);
    TEST_ASSERT_NULL(body);
    TEST_ASSERT_EQUAL_STRING("shop.example.com", g_stub_HEADER_FETCH_last_hostname);
  }
  TEST_ASSERT_EQUAL_INT(7, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(7, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_without_a_connection_writes_the_rated_fetch(void)
{
  static_HEADERSCHECKResetStubs();
  char before[HEADERSCHECK_CHECKED_AT_TEXT_SIZE];
  char after[HEADERSCHECK_CHECKED_AT_TEXT_SIZE];
  static_HEADERSCHECKUtcText(time(NULL), before);
  EndpointRunStatus_t status;
  const char*         message;
  char* body = static_HEADERSCHECKRun(NULL, "www.stub.example.com", false, &status, &message);
  static_HEADERSCHECKUtcText(time(NULL), after);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NULL(message);
  TEST_ASSERT_NOT_NULL(body);
  static_HEADERSCHECKMaskCheckedAt(body, before, after);
  TEST_ASSERT_EQUAL_STRING(HEADERSCHECK_STUB_BODY, body);
  free(body);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_hands_the_set_cookie_copy_count_to_the_rule(void)
{
  static_HEADERSCHECKResetStubs();
  g_stub_HEADER_FETCH_answer.m_setCookieCopyCount = 60;
  EndpointRunStatus_t status;
  const char*         message;
  char* body = static_HEADERSCHECKRun(NULL, "www.stub.example.com", false, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(body, "\"Cookies not checked: 58\"],\"value\":null,\"cookie_count\":60,"), body);
  free(body);
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_cache_key_holds_the_variant_and_a_name_of_253_bytes(void)
{
  char hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(hostname, 'a', 63);
  hostname[63] = '.';
  memset(hostname + 64, 'b', 63);
  hostname[127] = '.';
  memset(hostname + 128, 'c', 63);
  hostname[191] = '.';
  memset(hostname + 192, 'd', 57);
  memcpy(hostname + 249, ".com", sizeof(".com"));
  TEST_ASSERT_EQUAL_size_t(VALIDATE_DOMAIN_NAME_MAX_LEN, strlen(hostname));

  static const struct { bool m_isFullHeaderValueIncluded; const char* mp_keyPrefix; } cases[] = {
    { false, "headers_check:cut:" },
    { true,  "headers_check:full:" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_HEADERSCHECKResetStubs();
    char expected_key[CACHE_KEY_MAX_LEN + 1];
    snprintf(expected_key, sizeof(expected_key), "%s%s", cases[i].mp_keyPrefix, hostname);
    EndpointRunStatus_t status;
    const char*         message;
    char* body = static_HEADERSCHECKRun(HEADERSCHECK_TEST_CONN, hostname, cases[i].m_isFullHeaderValueIncluded, &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING(hostname, g_stub_HEADER_FETCH_last_hostname);
    TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
    TEST_ASSERT_EQUAL_STRING(expected_key, g_stub_CACHE_last_get_key);
    TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == HEADERSCHECK_TEST_CONN);
    TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
    TEST_ASSERT_EQUAL_STRING(expected_key, g_stub_CACHE_last_put_key);
    TEST_ASSERT_TRUE(g_stub_CACHE_last_put_conn == HEADERSCHECK_TEST_CONN);
    TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
    TEST_ASSERT_FALSE(g_stub_CACHE_last_put_is_error);
    TEST_ASSERT_EQUAL_UINT(3600, g_stub_CACHE_last_put_expires_after_seconds);
    free(body);
  }
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_sends_a_kept_answer_without_a_fetch(void)
{
  static_HEADERSCHECKResetStubs();
  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = "{\"url\":\"https://example.com/\",\"kept\":true}\n";
  EndpointRunStatus_t status;
  const char*         message;
  char* body = static_HEADERSCHECKRun(HEADERSCHECK_TEST_CONN, "example.com", true, &status, &message);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
  TEST_ASSERT_EQUAL_STRING("{\"url\":\"https://example.com/\",\"kept\":true}\n", body);
  free(body);
  TEST_ASSERT_EQUAL_STRING("headers_check:full:example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_fetches_on_a_cache_error_and_answers_past_a_failed_put(void)
{
  static const struct { CacheStatus_t m_getStatus; bool m_putResult; } cases[] = {
    { CACHE_ERROR, true  },
    { CACHE_MISS,  false },
  };
  static_HEADERSCHECKResetStubs();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_CACHE_get_status       = cases[i].m_getStatus;
    g_stub_CACHE_put_result       = cases[i].m_putResult;
    g_stub_CACHE_last_put_body[0] = '\0';
    EndpointRunStatus_t status;
    const char*         message;
    char* body = static_HEADERSCHECKRun(HEADERSCHECK_TEST_CONN, "www.stub.example.com", false, &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"findings\":["));
    TEST_ASSERT_EQUAL_STRING(body, g_stub_CACHE_last_put_body);
    TEST_ASSERT_EQUAL_INT((int)i + 1, g_stub_HEADER_FETCH_call_count);
    TEST_ASSERT_EQUAL_INT((int)i + 1, g_stub_CACHE_put_count);
    free(body);
  }
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_keeps_no_body_longer_than_the_cache_takes(void)
{
  static char value[CACHE_MAX_BODY_LEN + 1];
  static_HEADERSCHECKResetStubs();
  value[0] = 'a';
  value[1] = '\0';
  g_stub_HEADER_FETCH_answer.ma_capturedHeaderValues[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = value;
  EndpointRunStatus_t status;
  const char*         message;
  char* body = static_HEADERSCHECKRun(NULL, "www.stub.example.com", true, &status, &message);
  TEST_ASSERT_NOT_NULL(body);
  size_t other_len = strlen(body) - 1;
  free(body);

  for (size_t extra_len = 0; extra_len < 2; extra_len++)
  {
    size_t value_len = CACHE_MAX_BODY_LEN - other_len + extra_len;
    memset(value, 'a', value_len);
    value[value_len]       = '\0';
    g_stub_CACHE_put_count = 0;
    body = static_HEADERSCHECKRun(HEADERSCHECK_TEST_CONN, "www.stub.example.com", true, &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_size_t(CACHE_MAX_BODY_LEN + extra_len, strlen(body));
    TEST_ASSERT_EQUAL_INT(extra_len == 0 ? 1 : 0, g_stub_CACHE_put_count);
    free(body);
  }
  static_HEADERSCHECKResetStubs();
}

void test_HEADERSCHECKRun_rates_an_error_page_and_shows_a_redirect_target(void)
{
  static const struct { int m_status; const char* mp_unfollowedRedirectUrl; const char* mp_bodyStart; } cases[] = {
    { 403, NULL,                     "{\"url\":\"https://example.com/\",\"status_code\":403,\"redirect_count\":0,\"checked_at\":\"" },
    { 301, "https://other.example/", "{\"url\":\"https://example.com/\",\"status_code\":301,\"redirect_count\":0,\"redirect_to\":\"https://other.example/\",\"checked_at\":\"" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_HEADERSCHECKResetStubs();
    g_stub_HEADER_FETCH_answer.m_httpStatus             = cases[i].m_status;
    g_stub_HEADER_FETCH_answer.mp_url                   = "https://example.com/";
    g_stub_HEADER_FETCH_answer.m_followedRedirectCount  = 0;
    g_stub_HEADER_FETCH_answer.mp_unfollowedRedirectUrl = cases[i].mp_unfollowedRedirectUrl;
    EndpointRunStatus_t status;
    const char*         message;
    char* body = static_HEADERSCHECKRun(NULL, "example.com", false, &status, &message);
    TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, status);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING_LEN(cases[i].mp_bodyStart, body, strlen(cases[i].mp_bodyStart));
    free(body);
  }
  static_HEADERSCHECKResetStubs();
}

void test_watchlist_findAddRequirement_gives_each_kind_its_requirement(void)
{
  static const struct { WatchlistItemKind_t m_kind; WatchlistAddRequirement_t m_requirement; } cases[] = {
    { WATCHLIST_ITEM_CVE_LOOKUP,       WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_KEV_LOOKUP,       WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_CVE_EXPLOIT,      WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_PRODUCT_EXPOSURE, WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_CVE_SEARCH,       WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_DNS_LOOKUP,       WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
    { WATCHLIST_ITEM_SSL_CHECK,        WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
    { WATCHLIST_ITEM_WHOIS_LOOKUP,     WATCHLIST_ADD_REQUIRES_REGISTERED_DOMAIN_WITH_REGISTRY_SERVER },
    { WATCHLIST_ITEM_HEADERS_CHECK,    WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
    { WATCHLIST_ITEM_CERT_SEARCH,      WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN },
    { WATCHLIST_ITEM_PACKAGE_CHECK,    WATCHLIST_ADD_REQUIRES_NOTHING },
    { WATCHLIST_ITEM_IP_LOOKUP,        WATCHLIST_ADD_REQUIRES_NOTHING },
  };
  TEST_ASSERT_EQUAL_INT(0, WATCHLIST_ADD_REQUIRES_NOTHING);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_KIND_COUNT, sizeof(cases) / sizeof(cases[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requirement, watchlist_findAddRequirement(cases[i].m_kind), watchlist_findEndpointName(cases[i].m_kind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ADD_REQUIRES_NOTHING, watchlist_findAddRequirement((WatchlistItemKind_t)WATCHLIST_ITEM_KIND_COUNT));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ADD_REQUIRES_NOTHING, watchlist_findAddRequirement((WatchlistItemKind_t)-1));
}

static EndpointRunStatus_t static_runWhoisEdit(const char* object, const char** message_out)
{
  const Endpoint_t* edit = endpoint_findByMcpName("watchlist_edit");
  TEST_ASSERT_NOT_NULL(edit);
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget, REQUEST_TIER_PRO);
  return static_runWatchlistRow(edit, object, NULL, &budget, message_out);
}

void test_WATCHLISTEDITRun_whois_add_of_a_name_under_its_registered_domain_is_refused(void)
{
  static const char* const NOT_REGISTERED_MESSAGE = "whois_lookup items take a registered domain, such as example.com, not a name under it";
  static const struct { const char* mp_object; EndpointRunStatus_t m_status; const char* mp_message; } cases[] = {
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"www.example.com\"}",      ENDPOINT_RUN_REFUSED,  NOT_REGISTERED_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"a.b.example.co.uk\"}",    ENDPOINT_RUN_REFUSED,  NOT_REGISTERED_MESSAGE },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\"}",          ENDPOINT_RUN_DB_ERROR, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.co.uk\"}",        ENDPOINT_RUN_DB_ERROR, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"Example.COM\"}",          ENDPOINT_RUN_DB_ERROR, NULL },
    { "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"co.uk\"}",                ENDPOINT_RUN_REFUSED,  ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE },
    { "{\"action\":\"remove\",\"endpoint\":\"whois_lookup\",\"domain\":\"www.example.com\"}",   ENDPOINT_RUN_DB_ERROR, NULL },
  };
  static_WHOISLOOKUPResetStubs();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const char* message = NULL;
    EndpointRunStatus_t run_status = static_runWhoisEdit(cases[i].mp_object, &message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, run_status, cases[i].mp_object);
    if (cases[i].mp_message != NULL)
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_message, message, cases[i].mp_object);
  }
}

void test_WATCHLISTEDITRun_whois_add_for_a_tld_without_a_registry_server_is_refused(void)
{
  static const char* const NO_SERVER_MESSAGE = "whois_lookup items take a domain whose TLD has an RDAP or WHOIS server";
  static const char* const ADD    = "{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\"}";
  static const char* const REMOVE = "{\"action\":\"remove\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\"}";
  const char* message = NULL;

  static_WHOISLOOKUPResetStubs();
  g_stub_RDAP_server_base_url = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_REFUSED, static_runWhoisEdit(ADD, &message));
  TEST_ASSERT_EQUAL_STRING(NO_SERVER_MESSAGE, message);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_RDAP_last_find_name);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_WHOIS_last_find_name);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, static_runWhoisEdit(REMOVE, &message));

  g_stub_WHOIS_server = &g_stub_WHOIS_test_server;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, static_runWhoisEdit(ADD, &message));

  static_WHOISLOOKUPResetStubs();
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, static_runWhoisEdit(ADD, &message));
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WHOIS_lookup_count);
  static_WHOISLOOKUPResetStubs();
}

void test_WATCHLISTEDITRun_whois_add_asks_no_dns(void)
{
  static_WHOISLOOKUPResetStubs();
  static_resetFakeAsk();
  g_fakeAskStatus = DNS_ANSWER_NXDOMAIN;
  const char* message = NULL;
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_DB_ERROR, static_runWhoisEdit("{\"action\":\"add\",\"endpoint\":\"whois_lookup\",\"domain\":\"example.com\"}", &message));
  TEST_ASSERT_EQUAL_INT(0, g_fakeAskCallCount);
  static_resetFakeAsk();
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_http_paths_and_mcp_names_are_unique);
  RUN_TEST(test_findByHttpPath_returns_each_row_for_its_own_paths);
  RUN_TEST(test_findByHttpPath_unknown_path_is_NULL);
  RUN_TEST(test_findByHttpPath_path_one_byte_off_a_row_is_NULL);
  RUN_TEST(test_findByMcpName_returns_each_row_for_its_tool);
  RUN_TEST(test_every_row_but_the_four_free_rows_costs_at_least_one_credit);
  RUN_TEST(test_only_the_mcp_row_carries_mcp);
  RUN_TEST(test_only_the_credit_budget_rows_read_the_credit_budget);
  RUN_TEST(test_only_the_listed_paid_rows_are_payable);
  RUN_TEST(test_path_segment_rows_end_in_a_slash);
  RUN_TEST(test_only_path_segment_rows_bind_a_path_segment_param);
  RUN_TEST(test_every_parameter_carries_the_fields_its_type_needs);
  RUN_TEST(test_every_parameter_is_read_from_a_place_its_row_serves);
  RUN_TEST(test_a_row_that_reads_a_body_takes_post_alone);
  RUN_TEST(test_mcp_fields_come_with_a_tool);
  RUN_TEST(test_mcp_tool_titles_are_unique);
  RUN_TEST(test_mcp_tool_category_names_are_the_home_page_titles);
  RUN_TEST(test_only_record_lookups_carry_a_not_found_message);
  RUN_TEST(test_record_lookup_runs_serve_only_rows_with_a_message);
  RUN_TEST(test_each_row_holds_its_run_its_db_need_its_upstream_call_and_its_ceiling);
  RUN_TEST(test_params_write_inside_their_params_struct);
  RUN_TEST(test_every_row_fits_the_params_union);
  RUN_TEST(test_appendSchemaBounds_prints_each_bound_as_its_exact_double);
  RUN_TEST(test_mcp_tool_description_ends_with_a_price_other_than_one);
  RUN_TEST(test_price_is_flat_or_counts_the_ids_of_an_accepted_read);
  RUN_TEST(test_isPartialChargeAllowed_only_on_the_bulk_rows);
  RUN_TEST(test_every_bulk_ids_row_costs_one_credit);
  RUN_TEST(test_limitWorkToCharge_cuts_bulk_ids_to_the_charge);
  RUN_TEST(test_limitWorkToCharge_cuts_bulk_hashes_to_the_charge);
  RUN_TEST(test_only_package_check_bulk_has_a_weigh_function);
  RUN_TEST(test_limitWorkToWeight_cuts_to_the_served_count);
  RUN_TEST(test_limitWorkToWeight_weighs_two_packages);
  RUN_TEST(test_bulk_rows_write_their_ids_where_runRow_reads_them);
  RUN_TEST(test_runRow_finishes_a_body_only_on_ok_and_degraded);
  RUN_TEST(test_runRow_cuts_only_a_bulk_row_before_the_connection_check);
  RUN_TEST(test_runRow_hands_the_credit_budget_only_to_its_row);
  RUN_TEST(test_only_an_accepted_request_will_call_upstream);
  RUN_TEST(test_only_the_add_of_a_domain_item_of_watchlist_edit_will_call_upstream);
  RUN_TEST(test_query_specs_carry_a_message_and_a_default);
  RUN_TEST(test_restQueryGate_writes_the_table_defaults_for_absent_values);
  RUN_TEST(test_restQueryGate_stops_at_the_first_refusal_in_table_order);
  RUN_TEST(test_restQueryGate_refuses_a_decoded_control_character);
  RUN_TEST(test_restQueryGate_refuses_a_value_that_is_not_valid_utf8);
  RUN_TEST(test_mcpArgsGate_writes_the_table_defaults_for_absent_arguments);
  RUN_TEST(test_gates_write_the_kev_filter_for_absent_true_and_false);
  RUN_TEST(test_gates_write_a_bool_or_kev_filter_only_into_its_own_field);
  RUN_TEST(test_mcpArgsGate_stops_at_the_first_refusal_in_table_order);
  RUN_TEST(test_mcpArgsGate_answers_each_argument_refusal);
  RUN_TEST(test_every_row_fits_the_param_name_mask);
  RUN_TEST(test_checkHttpQueryParamNames_refuses_unknown_repeated_and_malformed_names);
  RUN_TEST(test_restQueryGate_checks_the_names_first_and_keeps_the_defaults);
  RUN_TEST(test_restQueryGate_checks_a_cwe_id_and_writes_it_into_its_field);
  RUN_TEST(test_restQueryGate_checks_a_cve_id_and_writes_it_into_its_field);
  RUN_TEST(test_restPathSegmentGate_checks_each_path_segment_with_its_spec);
  RUN_TEST(test_gates_write_a_host_name_in_lower_case);
  RUN_TEST(test_host_check_tools_take_domain_and_refuse_hostname);
  RUN_TEST(test_every_public_dns_name_param_is_named_domain);
  RUN_TEST(test_restPathSegmentGate_names_the_path_segment_param_wherever_it_sits);
  RUN_TEST(test_restPathSegmentGate_refuses_an_id_longer_than_the_spec_m_maxLen);
  RUN_TEST(test_restPathSegmentGate_writes_an_accepted_id_into_its_field_alone);
  RUN_TEST(test_restPathSegmentGate_refuses_an_id_that_its_field_cannot_hold);
  RUN_TEST(test_restBulkBodyGate_reads_the_ids_and_names_each_refusal);
  RUN_TEST(test_restBulkBodyGate_rows_bind_one_body_array);
  RUN_TEST(test_bulk_rows_take_their_most_ids_at_their_longest);
  RUN_TEST(test_isIdArrayType_names_the_two_id_array_types);
  RUN_TEST(test_isBulkArrayType_names_the_three_bulk_array_types);
  RUN_TEST(test_tryReadPackageItem_reads_the_three_members);
  RUN_TEST(test_tryReadPackageItem_skips_each_element_that_breaks_a_rule);
  RUN_TEST(test_tryReadPackageItem_takes_a_name_and_a_version_at_their_limits);
  RUN_TEST(test_package_gates_keep_three_packages_and_skip_two_elements);
  RUN_TEST(test_package_gates_refuse_a_repeated_package);
  RUN_TEST(test_package_gates_take_500_packages_and_refuse_501);
  RUN_TEST(test_package_gates_take_an_object_shorter_than_64_KiB);
  RUN_TEST(test_package_price_counts_the_kept_packages_and_the_cut_keeps_the_first);
  RUN_TEST(test_file_hash_array_gates_keep_each_hash_in_lower_case);
  RUN_TEST(test_file_hash_array_gates_refuse_two_spellings_of_one_hash);
  RUN_TEST(test_bulk_gates_read_a_body_and_arguments_alike);
  RUN_TEST(test_bulk_gates_refuse_a_repeated_id_and_name_the_first_pair);
  RUN_TEST(test_appendParamNameList_writes_the_names_or_leaves_the_message);
  RUN_TEST(test_checkHttpQueryParamNames_refuses_a_name_the_row_reads_from_elsewhere);
  RUN_TEST(test_writeGateRefusalMessage_answers_fallback_for_a_refusal_with_no_parameter);
  RUN_TEST(test_writeGateRefusalMessage_missing_text_path_segment_names_its_param);
  RUN_TEST(test_writeGateRefusalMessage_missing_query_id_names_its_param);
  RUN_TEST(test_PASSWORDCHECKRun_refuses_a_value_that_is_not_a_hash);
  RUN_TEST(test_DNSLOOKUPRun_refuses_a_name_that_is_not_public);
  RUN_TEST(test_DNSTAKEOVERCHECKRun_refuses_a_name_that_is_not_public);
  RUN_TEST(test_EMAILAUTHCHECKRun_refusal_names_what_was_refused);
  RUN_TEST(test_SSLCHECKRun_names_why_each_probe_failed);
  RUN_TEST(test_runRow_hands_the_reason_of_an_unreachable_target_on);
  RUN_TEST(test_HEADERSCHECKRun_names_why_each_fetch_failed);
  RUN_TEST(test_HEADERSCHECKRun_without_a_connection_writes_the_rated_fetch);
  RUN_TEST(test_HEADERSCHECKRun_hands_the_set_cookie_copy_count_to_the_rule);
  RUN_TEST(test_HEADERSCHECKRun_cache_key_holds_the_variant_and_a_name_of_253_bytes);
  RUN_TEST(test_HEADERSCHECKRun_sends_a_kept_answer_without_a_fetch);
  RUN_TEST(test_HEADERSCHECKRun_fetches_on_a_cache_error_and_answers_past_a_failed_put);
  RUN_TEST(test_HEADERSCHECKRun_keeps_no_body_longer_than_the_cache_takes);
  RUN_TEST(test_HEADERSCHECKRun_rates_an_error_page_and_shows_a_redirect_target);
  RUN_TEST(test_WHOISLOOKUPRun_asks_about_the_registrable_domain_and_keeps_the_answer);
  RUN_TEST(test_WHOISLOOKUPRun_refuses_a_public_suffix_before_any_call);
  RUN_TEST(test_WHOISLOOKUPRun_without_a_registry_server_answers_unavailable_and_calls_nothing_else);
  RUN_TEST(test_WHOISLOOKUPRun_sends_a_cached_answer_as_it_was_kept);
  RUN_TEST(test_WHOISLOOKUPRun_refused_charge_names_its_wait_and_a_failed_charge_is_a_db_error);
  RUN_TEST(test_WHOISLOOKUPRun_held_server_names_the_wait_and_an_unread_hold_is_a_db_error);
  RUN_TEST(test_WHOISLOOKUPRun_rate_limited_answer_holds_the_server_for_its_wait);
  RUN_TEST(test_WHOISLOOKUPRun_names_each_failed_lookup_and_keeps_none);
  RUN_TEST(test_WHOISLOOKUPRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put);
  RUN_TEST(test_WHOISLOOKUPRun_names_the_server_by_its_host_and_sends_nothing_for_a_bad_base_url);
  RUN_TEST(test_WHOISLOOKUPRun_without_an_rdap_server_asks_the_whois_server_and_keeps_the_answer);
  RUN_TEST(test_WHOISLOOKUPRun_names_each_failed_whois_query_and_keeps_none);
  RUN_TEST(test_runRow_refuses_whois_lookup_without_a_connection_before_the_run);
  RUN_TEST(test_WAYBACKLOOKUPRun_short_list_costs_one_request_and_is_kept_for_a_day);
  RUN_TEST(test_WAYBACKLOOKUPRun_nine_days_cost_one_request_and_ten_cost_two);
  RUN_TEST(test_WAYBACKLOOKUPRun_deadline_is_ten_seconds_after_the_run_starts);
  RUN_TEST(test_WAYBACKLOOKUPRun_host_without_a_capture_is_an_empty_answer_and_is_kept);
  RUN_TEST(test_WAYBACKLOOKUPRun_used_up_quota_is_unavailable_and_unread_quota_is_a_db_error);
  RUN_TEST(test_WAYBACKLOOKUPRun_rate_limited_answer_holds_the_cdx_server_for_its_wait);
  RUN_TEST(test_WAYBACKLOOKUPRun_held_cdx_server_names_the_wait_and_an_unread_hold_is_a_db_error);
  RUN_TEST(test_WHOISLOOKUPRun_and_WAYBACKLOOKUPRun_one_second_hold_still_holds);
  RUN_TEST(test_docs_name_the_throttle_limits_of_the_whois_lookup_run);
  RUN_TEST(test_docs_name_the_watchlist_caps);
  RUN_TEST(test_docs_name_the_weight_budget_of_package_check_bulk);
  RUN_TEST(test_WAYBACKLOOKUPRun_passed_deadline_sends_no_second_request);
  RUN_TEST(test_WAYBACKLOOKUPRun_failed_or_wrong_sized_answer_is_an_upstream_error);
  RUN_TEST(test_WAYBACKLOOKUPRun_refused_name_gets_the_text_of_the_gate);
  RUN_TEST(test_WAYBACKLOOKUPRun_sends_a_cached_answer_as_it_was_kept);
  RUN_TEST(test_WAYBACKLOOKUPRun_longest_name_is_asked_and_kept_whole);
  RUN_TEST(test_WAYBACKLOOKUPRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put);
  RUN_TEST(test_runRow_refuses_wayback_lookup_without_a_connection_before_the_run);
  RUN_TEST(test_CERTSEARCHRun_answer_costs_one_request_and_is_kept_for_a_day);
  RUN_TEST(test_docs_bot_page_names_the_cert_search_hourly_limit);
  RUN_TEST(test_docs_name_the_cert_search_hourly_limit);
  RUN_TEST(test_docs_llms_names_the_watchable_domain_endpoints);
  RUN_TEST(test_docs_name_the_ip_watch_comparison_interval);
  RUN_TEST(test_CERTSEARCHRun_host_without_a_certificate_is_an_empty_answer_and_is_kept);
  RUN_TEST(test_CERTSEARCHRun_sends_a_cached_answer_as_it_was_kept);
  RUN_TEST(test_CERTSEARCHRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put);
  RUN_TEST(test_CERTSEARCHRun_held_cert_spotter_names_the_wait_and_an_unread_hold_is_a_db_error);
  RUN_TEST(test_CERTSEARCHRun_used_up_quota_is_unavailable_and_unread_quota_is_a_db_error);
  RUN_TEST(test_CERTSEARCHRun_rate_limited_answer_holds_cert_spotter_for_its_wait);
  RUN_TEST(test_CERTSEARCHRun_walk_cut_after_a_page_answers_no_part_and_is_not_kept);
  RUN_TEST(test_CERTSEARCHRun_failed_lookup_or_missing_key_is_an_upstream_error);
  RUN_TEST(test_CERTSEARCHRun_without_a_key_spends_no_quota_and_sends_a_kept_answer);
  RUN_TEST(test_CERTSEARCHRun_refused_name_gets_the_text_of_the_gate);
  RUN_TEST(test_CERTSEARCHRun_longest_name_is_asked_and_kept_whole);
  RUN_TEST(test_CERTSEARCH_row_asks_cert_spotter_about_the_name_in_lower_case);
  RUN_TEST(test_runRow_refuses_cert_search_without_a_connection_before_the_run);
  RUN_TEST(test_SUBDOMAINENUMRun_answer_merges_dns_and_certificate_logs_and_is_kept_for_a_day);
  RUN_TEST(test_SUBDOMAINENUMRun_asks_dns_before_cert_spotter);
  RUN_TEST(test_SUBDOMAINENUMRun_asks_about_the_registrable_domain_of_a_name);
  RUN_TEST(test_SUBDOMAINENUMRun_refuses_a_public_suffix_before_any_question);
  RUN_TEST(test_SUBDOMAINENUMRun_sends_a_cached_answer_as_it_was_kept);
  RUN_TEST(test_SUBDOMAINENUMRun_asks_on_a_cache_miss_or_error_and_answers_past_a_failed_put);
  RUN_TEST(test_SUBDOMAINENUMRun_without_a_key_answers_the_dns_names_for_ten_minutes);
  RUN_TEST(test_SUBDOMAINENUMRun_held_cert_spotter_answers_the_dns_names_with_the_wait);
  RUN_TEST(test_SUBDOMAINENUMRun_unread_hold_is_a_db_error);
  RUN_TEST(test_SUBDOMAINENUMRun_used_up_quota_answers_the_dns_names_and_unread_quota_is_a_db_error);
  RUN_TEST(test_SUBDOMAINENUMRun_rate_limited_answer_holds_cert_spotter_for_its_wait);
  RUN_TEST(test_SUBDOMAINENUMRun_failed_certificate_log_lookup_answers_the_dns_names_for_ten_minutes);
  RUN_TEST(test_SUBDOMAINENUMRun_refused_name_gets_the_text_of_the_gate);
  RUN_TEST(test_SUBDOMAINENUMRun_set_that_cannot_be_made_is_no_memory);
  RUN_TEST(test_SUBDOMAINENUMRun_wildcard_verdict_reaches_the_answer);
  RUN_TEST(test_SUBDOMAINENUMRun_undetermined_wildcard_answer_is_kept_for_ten_minutes);
  RUN_TEST(test_SUBDOMAINENUMRun_empty_certificate_log_answer_is_complete);
  RUN_TEST(test_SUBDOMAINENUM_row_asks_about_the_name_in_lower_case);
  RUN_TEST(test_runRow_refuses_subdomain_enum_without_a_connection_before_the_run);
  RUN_TEST(test_IPLOOKUPRun_refuses_a_text_that_holds_no_address);
  RUN_TEST(test_only_the_email_spec_decodes_its_path_segment);
  RUN_TEST(test_restPathSegmentGate_decodes_the_email_segment);
  RUN_TEST(test_restPathSegmentGate_leaves_another_segment_encoded);
  RUN_TEST(test_restPathSegmentGate_holds_a_decoded_segment_to_its_field);
  RUN_TEST(test_EMAILADDRESSCHECKRun_refuses_a_text_that_holds_no_address);
  RUN_TEST(test_ASNLOOKUPRun_refuses_a_text_that_holds_no_target);
  RUN_TEST(test_max_body_byte_count_is_16_mib);
  RUN_TEST(test_a_bytes_param_is_read_from_the_raw_body_alone);
  RUN_TEST(test_raw_body_rows_are_image_inspect_and_the_two_webhooks);
  RUN_TEST(test_webhook_lemonsqueezy_row_reads_a_raw_body_and_its_signature);
  RUN_TEST(test_webhook_nowpayments_row_reads_a_raw_body_and_its_signature);
  RUN_TEST(test_api_key_claim_row_reads_an_order_id_from_the_body);
  RUN_TEST(test_crypto_checkout_row_takes_post_and_no_param);
  RUN_TEST(test_crypto_checkout_gate_reads_no_param_and_ignores_the_body);
  RUN_TEST(test_restRequestGate_points_the_image_at_its_body);
  RUN_TEST(test_restRequestGate_writes_an_optional_raw_body_at_its_offset);
  RUN_TEST(test_restFieldsBodyGate_reads_what_mcpArgsGate_reads);
  RUN_TEST(test_watchlist_gates_read_packages_beside_the_members);
  RUN_TEST(test_hasPackageArrayWithOtherMembers_takes_one_other_body_member);
  RUN_TEST(test_watchlist_gates_refuse_a_missing_required_package_array);
  RUN_TEST(test_watchlist_gates_check_only_the_packages_array);
  RUN_TEST(test_watchlist_gates_take_500_packages_in_an_object_shorter_than_64_KiB);
  RUN_TEST(test_readWatchlistPackageElements_reads_every_element_with_its_problem);
  RUN_TEST(test_readWatchlistPackageElements_compares_only_packages);
  RUN_TEST(test_readWatchlistPackageElements_gives_each_rule_its_problem);
  RUN_TEST(test_watchlist_findItemKind_gives_each_endpoint_its_kind);
  RUN_TEST(test_watchlist_findEndpointName_gives_each_kind_its_endpoint);
  RUN_TEST(test_watchlist_isDomainItemKind_is_true_for_the_five_domain_kinds);
  RUN_TEST(test_watchlist_findDomainEventKind_gives_each_domain_kind_its_lane);
  RUN_TEST(test_watchlist_findDomainName_reads_the_name_of_a_domain_item_only);
  RUN_TEST(test_watchlist_findAddRequirement_gives_each_kind_its_requirement);
  RUN_TEST(test_WATCHLISTEDITRun_refuses_each_wrong_shape_before_the_db);
  RUN_TEST(test_WATCHLISTEDITRun_asks_dns_only_for_the_add_of_a_domain_item);
  RUN_TEST(test_WATCHLISTEDITRun_whois_add_of_a_name_under_its_registered_domain_is_refused);
  RUN_TEST(test_WATCHLISTEDITRun_whois_add_for_a_tld_without_a_registry_server_is_refused);
  RUN_TEST(test_WATCHLISTEDITRun_whois_add_asks_no_dns);
  RUN_TEST(test_WATCHLISTEVENTSRun_refuses_each_wrong_shape_before_the_db);
  RUN_TEST(test_WATCHLISTEVENTS_row_takes_three_params_and_costs_one_credit);
  RUN_TEST(test_runRow_hands_the_credit_budget_to_both_watchlist_rows);
  RUN_TEST(test_runRow_gives_the_usage_log_the_ids_the_gate_kept);
  RUN_TEST(test_runRow_gives_the_usage_log_the_packages_the_gate_kept);
  RUN_TEST(test_runRow_gives_no_item_count_on_a_row_that_is_not_bulk);
  RUN_TEST(test_restRequestGate_reads_a_header_param_by_its_name_in_any_case);
  RUN_TEST(test_restRequestGate_refuses_a_missing_required_header);
  RUN_TEST(test_restRequestGate_refuses_a_header_sent_twice);
  RUN_TEST(test_restRequestGate_refuses_a_header_longer_than_its_limit);
  RUN_TEST(test_restRequestGate_checks_a_header_value_like_a_query_value);
  RUN_TEST(test_a_header_param_is_never_read_from_the_query);
  RUN_TEST(test_a_header_param_is_never_read_from_the_mcp_arguments);
  RUN_TEST(test_restRequestGate_reads_a_header_param_beside_a_raw_body);
  RUN_TEST(test_every_header_param_is_a_string_read_from_the_header_alone);
  RUN_TEST(test_every_raw_body_spec_has_a_limit_up_to_the_max_body_byte_count);
  RUN_TEST(test_rawBodyByteLimit_is_the_raw_spec_limit);
  RUN_TEST(test_small_raw_body_max_byte_count_is_64_kib);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
