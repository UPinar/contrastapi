#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "openapi.h"
#include "endpoint.h"
#include "jsonbuf.h"
#include "jsonread.h"
#include "version.h"

#define TEST_OPENAPI_TEXT_BUF_SIZE 4096

static char*          g_document = NULL;
static JsonReadSpan_t g_root;

static char* static_buildDocument(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_MAX_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_TRUE(openapi_appendDocument(json_buf));
  char* document = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(document);
  return document;
}

static JsonReadSpan_t static_at(JsonReadSpan_t start, ...)
{
  va_list keys;
  va_start(keys, start);

  JsonReadSpan_t span = start;
  for (const char* key = va_arg(keys, const char*); key != NULL; key = va_arg(keys, const char*))
  {
    JsonReadSpan_t value;
    JsonReadStatus_t status = jsonread_objectKey(span, key, &value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, status, key);
    span = value;
  }

  va_end(keys);
  return span;
}

static void static_assertRaw(JsonReadSpan_t span, const char* expected)
{
  char* text = malloc(span.m_len + 1);
  TEST_ASSERT_NOT_NULL(text);
  memcpy(text, span.mp_start, span.m_len);
  text[span.m_len] = '\0';
  TEST_ASSERT_EQUAL_STRING(expected, text);
  free(text);
}

static void static_assertString(JsonReadSpan_t span, const char* expected)
{
  char text[TEST_OPENAPI_TEXT_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(span, text, sizeof(text)));
  TEST_ASSERT_EQUAL_STRING(expected, text);
}

static void static_assertKeyAbsent(JsonReadSpan_t object, const char* key)
{
  JsonReadSpan_t value;
  TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NOTFOUND, jsonread_objectKey(object, key, &value), key);
}

static JsonReadSpan_t static_findParameter(JsonReadSpan_t parameters, const char* name)
{
  size_t         offset = 0;
  JsonReadSpan_t element;
  while (jsonread_arrayNextElement(parameters, &offset, &element) == JSONREAD_OK)
  {
    JsonReadSpan_t name_span;
    if (jsonread_objectKey(element, "name", &name_span) != JSONREAD_OK)
      continue;
    char text[TEST_OPENAPI_TEXT_BUF_SIZE];
    if (jsonread_spanToStrStatus(name_span, text, sizeof(text)) == JSONREAD_OK && strcmp(text, name) == 0)
      return element;
  }
  TEST_FAIL_MESSAGE(name);
  return element;
}

static int static_memberCount(JsonReadSpan_t object)
{
  int            count  = 0;
  size_t         offset = 0;
  JsonReadSpan_t key;
  JsonReadSpan_t value;
  while (jsonread_objectNextMember(object, &offset, &key, &value) == JSONREAD_OK)
    count++;
  return count;
}

static size_t static_elementCount(JsonReadSpan_t array)
{
  size_t count = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayLen(array, &count));
  return count;
}

static JsonReadSpan_t static_findOperation(JsonReadSpan_t paths, const Endpoint_t* row)
{
  char path[256];
  strcpy(path, row->mp_httpPath);
  for (int j = 0; row->m_hasPathSegment && j < row->m_paramCount; j++)
  {
    if ((row->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) == 0)
      continue;
    strcat(path, "{");
    strcat(path, row->mp_params[j].mp_spec->mp_name);
    strcat(path, "}");
  }

  char method[16];
  size_t k = 0;
  for (; row->ma_allowedMethods[0][k] != '\0'; k++)
    method[k] = (char)(row->ma_allowedMethods[0][k] - 'A' + 'a');
  method[k] = '\0';

  return static_at(paths, path, method, NULL);
}

static bool static_isStringInArray(JsonReadSpan_t array, const char* wanted)
{
  size_t         offset = 0;
  JsonReadSpan_t element;
  while (jsonread_arrayNextElement(array, &offset, &element) == JSONREAD_OK)
  {
    char text[TEST_OPENAPI_TEXT_BUF_SIZE];
    if (jsonread_spanToStrStatus(element, text, sizeof(text)) == JSONREAD_OK && strcmp(text, wanted) == 0)
      return true;
  }
  return false;
}

static void static_assertStringOrAbsent(JsonReadSpan_t object, const char* key, const char* expected)
{
  if (expected == NULL)
    static_assertKeyAbsent(object, key);
  else
    static_assertString(static_at(object, key, NULL), expected);
}

static void static_assertSchemaFollowsSpec(JsonReadSpan_t schema, const EndpointParamSpec_t* spec)
{
  const char* type_name = endpoint_jsonSchemaTypeName(spec->m_type);
  static_assertString(static_at(schema, "type", NULL), type_name);
  if (spec->m_type == ENDPOINT_PARAM_TYPE_ENUM)
  {
    JsonReadSpan_t values = static_at(schema, "enum", NULL);
    size_t         count  = 0;
    for (; spec->mp_enumValues[count] != NULL; count++)
      TEST_ASSERT_TRUE_MESSAGE(static_isStringInArray(values, spec->mp_enumValues[count]), spec->mp_name);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(count, static_elementCount(values), spec->mp_name);
  }
  else
    static_assertKeyAbsent(schema, "enum");
  if (spec->m_isOnlyTrueAccepted)
    static_assertRaw(static_at(schema, "const", NULL), "true");
  else
    static_assertKeyAbsent(schema, "const");
  if (strcmp(type_name, "string") == 0)
  {
    long max_len = 0;
    TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToLongStatus(static_at(schema, "maxLength", NULL), &max_len));
    TEST_ASSERT_EQUAL_INT64_MESSAGE((long long)spec->m_maxLen, (long long)max_len, spec->mp_name);
  }
  if (spec->m_type == ENDPOINT_PARAM_TYPE_INT || spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
  {
    double bound = 0;
    TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_at(schema, "minimum", NULL), &bound));
    TEST_ASSERT_TRUE_MESSAGE(bound == spec->m_min, spec->mp_name);
    if (spec->m_max == INT_MAX)
      static_assertKeyAbsent(schema, "maximum");
    else
    {
      TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_at(schema, "maximum", NULL), &bound));
      TEST_ASSERT_TRUE_MESSAGE(bound == spec->m_max, spec->mp_name);
    }
    if (spec->m_default == -1.0)
      static_assertKeyAbsent(schema, "default");
    else
    {
      TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_at(schema, "default", NULL), &bound));
      TEST_ASSERT_TRUE_MESSAGE(bound == spec->m_default, spec->mp_name);
    }
  }
  else if (endpoint_isBulkArrayType(spec->m_type))
  {
    long max_items = 0;
    TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToLongStatus(static_at(schema, "maxItems", NULL), &max_items));
    TEST_ASSERT_EQUAL_INT64_MESSAGE((long long)spec->m_max, (long long)max_items, spec->mp_name);
    static_assertRaw(static_at(schema, "minItems", NULL), "1");
    static_assertRaw(static_at(schema, "items", NULL),
                     spec->m_type != ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY ? "{\"type\":\"string\"}" :
                     spec->m_isPackageVersionOptional ? "{\"$ref\":\"#/components/schemas/PackageItemOptionalVersion\"}" :
                     "{\"$ref\":\"#/components/schemas/PackageItem\"}");
  }
}

void setUp(void)
{
  g_document = static_buildDocument();
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(g_document, strlen(g_document), &g_root));
}

void tearDown(void)
{
  free(g_document);
  g_document = NULL;
}

static void test_document_is_one_json_object_in_its_key_order(void)
{
  TEST_ASSERT_EQUAL_size_t(strlen(g_document), g_root.m_len);
  TEST_ASSERT_EQUAL_CHAR('{', g_document[0]);
  TEST_ASSERT_EQUAL_CHAR('}', g_document[strlen(g_document) - 1]);

  const char* keys[] = { "\"openapi\":", "\"info\":", "\"servers\":", "\"security\":", "\"tags\":", "\"paths\":", "\"components\":" };
  const char* previous = g_document;
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    const char* found = strstr(previous, keys[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(found, keys[i]);
    previous = found;
  }
  TEST_ASSERT_EQUAL_INT(7, static_memberCount(g_root));
}

static void test_document_is_openapi_3_1_0(void)
{
  static_assertString(static_at(g_root, "openapi", NULL), "3.1.0");
}

static void test_info_names_the_api_and_its_version(void)
{
  static_assertString(static_at(g_root, "info", "title", NULL), "ContrastAPI");
  static_assertString(static_at(g_root, "info", "version", NULL), CONTRASTAPI_VERSION);

  static_assertString(static_at(g_root, "info", "description", NULL),
                      "Security intelligence REST API for CVE, package, credential, domain, IP and threat defense lookups, priced in credits.");
}

static void test_servers_name_the_public_host(void)
{
  static_assertRaw(static_at(g_root, "servers", NULL), "[{\"url\":\"https://api.contrastcyber.com\"}]");
}

static void test_security_takes_a_key_header_a_bearer_key_or_none(void)
{
  static_assertRaw(static_at(g_root, "security", NULL), "[{\"ApiKeyHeader\":[]},{\"BearerAuth\":[]},{}]");
}

static void test_security_schemes_name_the_key_header_and_bearer(void)
{
  static_assertRaw(static_at(g_root, "components", "securitySchemes", "ApiKeyHeader", NULL),
                   "{\"type\":\"apiKey\",\"in\":\"header\",\"name\":\"X-API-Key\"}");
  static_assertRaw(static_at(g_root, "components", "securitySchemes", "BearerAuth", NULL),
                   "{\"type\":\"http\",\"scheme\":\"bearer\"}");
}

static void test_rate_limit_headers_are_four_components(void)
{
  JsonReadSpan_t headers = static_at(g_root, "components", "headers", NULL);
  TEST_ASSERT_EQUAL_INT(4, static_memberCount(headers));

  const char* names[]   = { "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset-Machine", "X-RateLimit-Reset-Human" };
  const char* schemas[] = { "{\"type\":\"integer\"}", "{\"type\":\"integer\"}", "{\"type\":\"integer\"}", "{\"type\":\"string\"}" };
  const char* descriptions[] = { "The credits the caller may spend in one window.",
                                 "The credits left in the current window.",
                                 "The Unix time, in seconds, at which the window resets.",
                                 "The time left until the window resets, as HH:MM:SS." };
  for (size_t i = 0; i < 4; i++)
  {
    static_assertRaw(static_at(headers, names[i], "schema", NULL), schemas[i]);
    static_assertString(static_at(headers, names[i], "description", NULL), descriptions[i]);
  }
}

static void test_error_response_refers_to_the_error_schema(void)
{
  JsonReadSpan_t error = static_at(g_root, "components", "responses", "Error", NULL);
  static_assertRaw(static_at(error, "content", "application/json", "schema", NULL), "{\"$ref\":\"#/components/schemas/Error\"}");
  TEST_ASSERT_EQUAL_CHAR('"', static_at(error, "description", NULL).mp_start[0]);

  static_assertRaw(static_at(g_root, "components", "schemas", "Error", NULL),
                   "{\"type\":\"object\",\"required\":[\"error\"],\"properties\":{\"error\":{\"type\":\"object\",\"required\":[\"code\",\"message\"],"
                   "\"properties\":{\"code\":{\"type\":\"string\"},\"message\":{\"type\":\"string\"}}}}}");
}

static void test_package_item_schema_is_the_tools_list_item_schema(void)
{
  static_assertRaw(static_at(g_root, "components", "schemas", "PackageItem", NULL),
                   "{\"type\":\"object\",\"properties\":{\"ecosystem\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"},\"version\":{\"type\":\"string\"}},"
                   "\"required\":[\"ecosystem\",\"name\",\"version\"],\"additionalProperties\":false}");
}

static void test_package_item_optional_version_schema_leaves_out_the_version(void)
{
  static_assertRaw(static_at(g_root, "components", "schemas", "PackageItemOptionalVersion", NULL),
                   "{\"type\":\"object\",\"properties\":{\"ecosystem\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"},\"version\":{\"type\":\"string\"}},"
                   "\"required\":[\"ecosystem\",\"name\"],\"additionalProperties\":false}");
}

static void test_tags_list_every_category_in_home_page_order(void)
{
  static_assertRaw(static_at(g_root, "tags", NULL),
                   "[{\"name\":\"CVE Intelligence\"},{\"name\":\"Package Vulnerabilities (SBOM)\"},{\"name\":\"Credential Checks\"},"
                   "{\"name\":\"Domain Intelligence\"},{\"name\":\"IP Intelligence\"},{\"name\":\"Threat Defense\"},"
                   "{\"name\":\"Monitoring\"},{\"name\":\"Operations\"}]");
}

static void test_document_holds_40_operations(void)
{
  JsonReadSpan_t paths = static_at(g_root, "paths", NULL);

  int            operation_count = 0;
  size_t         offset          = 0;
  JsonReadSpan_t key;
  JsonReadSpan_t path_item;
  while (jsonread_objectNextMember(paths, &offset, &key, &path_item) == JSONREAD_OK)
    operation_count += static_memberCount(path_item);

  TEST_ASSERT_EQUAL_INT(40, operation_count);
  TEST_ASSERT_EQUAL_INT(40, static_memberCount(paths));
}

static void test_mcp_row_has_no_path(void)
{
  JsonReadSpan_t paths = static_at(g_root, "paths", NULL);
  static_assertKeyAbsent(paths, "/mcp");
  static_assertKeyAbsent(paths, "/cve_lookup/");
}

static void test_cve_lookup_names_its_path_segment(void)
{
  JsonReadSpan_t path_item = static_at(g_root, "paths", "/cve_lookup/{cve_id}", NULL);
  TEST_ASSERT_EQUAL_INT(1, static_memberCount(path_item));

  JsonReadSpan_t operation = static_at(path_item, "get", NULL);
  static_assertString(static_at(operation, "operationId", NULL), "cve_lookup");
  static_assertString(static_at(operation, "summary", NULL), "CVE Lookup");
  static_assertRaw(static_at(operation, "tags", NULL), "[\"CVE Intelligence\"]");
  static_assertRaw(static_at(operation, "x-credit-cost", NULL), "1");
  static_assertKeyAbsent(operation, "x-credit-cost-per-item");
  static_assertKeyAbsent(operation, "requestBody");

  char description[TEST_OPENAPI_TEXT_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(static_at(operation, "description", NULL), description, sizeof(description)));
  TEST_ASSERT_EQUAL_STRING_LEN("Full CVE record by ID (CVSS, EPSS, KEV, CWE", description, 43);

  JsonReadSpan_t parameters = static_at(operation, "parameters", NULL);
  TEST_ASSERT_EQUAL_size_t(2, static_elementCount(parameters));
  static_assertRaw(static_findParameter(parameters, "cve_id"),
                   "{\"name\":\"cve_id\",\"in\":\"path\",\"required\":true,\"description\":\"CVE ID, e.g. CVE-2021-44228\","
                   "\"schema\":{\"type\":\"string\",\"maxLength\":24}}");
  static_assertRaw(static_findParameter(parameters, "include_ghsa"),
                   "{\"name\":\"include_ghsa\",\"in\":\"query\",\"required\":false,"
                   "\"description\":\"Add the GitHub Security Advisory of the CVE, from the local copy of the GitHub Advisory Database\","
                   "\"schema\":{\"type\":\"boolean\"}}");
}

static void test_operation_keys_come_in_their_order(void)
{
  JsonReadSpan_t operation = static_at(g_root, "paths", "/cve_lookup/{cve_id}", "get", NULL);

  const char* keys[] = { "\"operationId\":", "\"summary\":", "\"description\":", "\"tags\":", "\"x-credit-cost\":", "\"parameters\":", "\"responses\":" };
  const char* previous = operation.mp_start;
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    const char* found = strstr(previous, keys[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(found, keys[i]);
    TEST_ASSERT_TRUE_MESSAGE(found < operation.mp_start + operation.m_len, keys[i]);
    previous = found;
  }
  TEST_ASSERT_EQUAL_INT(7, static_memberCount(operation));
}

static void test_responses_name_the_rate_limit_headers_and_the_error(void)
{
  JsonReadSpan_t responses = static_at(g_root, "paths", "/cve_lookup/{cve_id}", "get", "responses", NULL);
  TEST_ASSERT_EQUAL_INT(2, static_memberCount(responses));

  JsonReadSpan_t ok = static_at(responses, "200", NULL);
  TEST_ASSERT_EQUAL_CHAR('"', static_at(ok, "description", NULL).mp_start[0]);
  static_assertRaw(static_at(ok, "headers", NULL),
                   "{\"X-RateLimit-Limit\":{\"$ref\":\"#/components/headers/X-RateLimit-Limit\"},"
                   "\"X-RateLimit-Remaining\":{\"$ref\":\"#/components/headers/X-RateLimit-Remaining\"},"
                   "\"X-RateLimit-Reset-Machine\":{\"$ref\":\"#/components/headers/X-RateLimit-Reset-Machine\"},"
                   "\"X-RateLimit-Reset-Human\":{\"$ref\":\"#/components/headers/X-RateLimit-Reset-Human\"}}");
  static_assertRaw(static_at(ok, "content", NULL), "{\"application/json\":{\"schema\":{\"type\":\"object\"}}}");
  static_assertRaw(static_at(responses, "default", NULL), "{\"$ref\":\"#/components/responses/Error\"}");
}

static void test_free_health_lists_no_rate_limit_headers(void)
{
  JsonReadSpan_t ok = static_at(g_root, "paths", "/health", "get", "responses", "200", NULL);
  static_assertKeyAbsent(ok, "headers");
  static_assertRaw(static_at(ok, "content", NULL), "{\"application/json\":{\"schema\":{\"type\":\"object\"}}}");
}

static void test_cve_lookup_description_is_its_row_tool_description(void)
{
  const Endpoint_t* row = NULL;
  for (int i = 0; i < endpoint_count && row == NULL; i++)
    if (strcmp(endpoints[i].mp_httpPath, "/cve_lookup/") == 0)
      row = &endpoints[i];
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_NOT_NULL(row->mp_mcpToolDescription);
  static_assertString(static_at(g_root, "paths", "/cve_lookup/{cve_id}", "get", "description", NULL), row->mp_mcpToolDescription);
}

static void test_cve_search_query_params_carry_their_schemas(void)
{
  JsonReadSpan_t operation  = static_at(g_root, "paths", "/cve_search", "get", NULL);
  JsonReadSpan_t parameters = static_at(operation, "parameters", NULL);
  TEST_ASSERT_EQUAL_size_t(15, static_elementCount(parameters));
  static_assertKeyAbsent(operation, "requestBody");

  static_assertRaw(static_findParameter(parameters, "severity"),
                   "{\"name\":\"severity\",\"in\":\"query\",\"required\":false,"
                   "\"schema\":{\"type\":\"string\",\"enum\":[\"CRITICAL\",\"HIGH\",\"MEDIUM\",\"LOW\",\"NONE\"],\"maxLength\":16}}");
  static_assertRaw(static_at(static_findParameter(parameters, "limit"), "schema", NULL),
                   "{\"type\":\"integer\",\"minimum\":1,\"maximum\":100,\"default\":20}");
  static_assertRaw(static_at(static_findParameter(parameters, "offset"), "schema", NULL),
                   "{\"type\":\"integer\",\"minimum\":0,\"maximum\":10000,\"default\":0}");
  static_assertRaw(static_at(static_findParameter(parameters, "min_cvss"), "schema", NULL),
                   "{\"type\":\"number\",\"minimum\":0,\"maximum\":10}");
  static_assertRaw(static_at(static_findParameter(parameters, "known_ransomware"), "schema", NULL),
                   "{\"type\":\"boolean\",\"const\":true}");
  static_assertRaw(static_at(static_findParameter(parameters, "in_kev"), "schema", NULL),
                   "{\"type\":\"boolean\"}");
  static_assertRaw(static_at(static_findParameter(parameters, "vendor"), "schema", NULL),
                   "{\"type\":\"string\",\"maxLength\":128}");
  static_assertRaw(static_at(static_findParameter(parameters, "sort"), "schema", NULL),
                   "{\"type\":\"string\",\"enum\":[\"published_time\",\"epss\",\"cvss\"],\"maxLength\":15}");
  static_assertRaw(static_findParameter(parameters, "include_rejected"),
                   "{\"name\":\"include_rejected\",\"in\":\"query\",\"required\":false,"
                   "\"description\":\"Also list the CVEs that NVD marks Rejected\","
                   "\"schema\":{\"type\":\"boolean\"}}");
}

static void test_cve_search_number_params_carry_their_default(void)
{
  JsonReadSpan_t parameters = static_at(g_root, "paths", "/cve_search", "get", "parameters", NULL);
  JsonReadSpan_t limit      = static_at(static_findParameter(parameters, "limit"), "schema", NULL);
  JsonReadSpan_t offset     = static_at(static_findParameter(parameters, "offset"), "schema", NULL);
  JsonReadSpan_t min_cvss   = static_at(static_findParameter(parameters, "min_cvss"), "schema", NULL);

  static_assertRaw(static_at(limit, "default", NULL), "20");
  static_assertRaw(static_at(offset, "default", NULL), "0");
  static_assertRaw(static_at(offset, "maximum", NULL), "10000");
  static_assertKeyAbsent(min_cvss, "default");
}

static void test_offset_maximum_is_on_the_three_capped_lists_only(void)
{
  static const char* const capped_paths[] = { "/cve_triage", "/cpe_search" };
  for (size_t i = 0; i < sizeof(capped_paths) / sizeof(capped_paths[0]); i++)
  {
    JsonReadSpan_t parameters = static_at(g_root, "paths", capped_paths[i], "get", "parameters", NULL);
    JsonReadSpan_t offset     = static_at(static_findParameter(parameters, "offset"), "schema", NULL);
    static_assertRaw(static_at(offset, "minimum", NULL), "0");
    static_assertRaw(static_at(offset, "maximum", NULL), "10000");
    static_assertRaw(static_at(offset, "default", NULL), "0");
  }

  JsonReadSpan_t parameters = static_at(g_root, "paths", "/cve_products/{cve_id}", "get", "parameters", NULL);
  JsonReadSpan_t offset     = static_at(static_findParameter(parameters, "offset"), "schema", NULL);
  static_assertRaw(static_at(offset, "minimum", NULL), "0");
  static_assertKeyAbsent(offset, "maximum");
}

static void test_product_exposure_query_params_carry_include_rejected(void)
{
  JsonReadSpan_t parameters = static_at(g_root, "paths", "/product_exposure", "get", "parameters", NULL);
  TEST_ASSERT_EQUAL_size_t(4, static_elementCount(parameters));
  static_assertRaw(static_findParameter(parameters, "include_rejected"),
                   "{\"name\":\"include_rejected\",\"in\":\"query\",\"required\":false,"
                   "\"description\":\"Also count and list the CVEs that NVD marks Rejected\","
                   "\"schema\":{\"type\":\"boolean\"}}");
}

static void test_package_check_query_param_is_required_when_the_row_requires_it(void)
{
  JsonReadSpan_t parameters = static_at(g_root, "paths", "/package_check", "get", "parameters", NULL);
  static_assertRaw(static_at(static_findParameter(parameters, "ecosystem"), "required", NULL), "true");
  static_assertRaw(static_at(static_findParameter(parameters, "version"), "required", NULL), "false");
  static_assertString(static_at(static_findParameter(parameters, "ecosystem"), "in", NULL), "query");
}

static void test_price_comes_from_the_row(void)
{
  static_assertRaw(static_at(g_root, "paths", "/cert_search/{domain}", "get", "x-credit-cost", NULL), "2");
  static_assertRaw(static_at(g_root, "paths", "/health", "get", "x-credit-cost", NULL), "0");
  static_assertRaw(static_at(g_root, "paths", "/image_inspect", "post", "x-credit-cost", NULL), "2");
}

static void test_health_has_no_parameters_and_no_body(void)
{
  JsonReadSpan_t operation = static_at(g_root, "paths", "/health", "get", NULL);
  static_assertKeyAbsent(operation, "parameters");
  static_assertKeyAbsent(operation, "requestBody");
  static_assertRaw(static_at(operation, "tags", NULL), "[\"Operations\"]");
}

static void test_cve_lookup_bulk_takes_a_json_body(void)
{
  JsonReadSpan_t path_item = static_at(g_root, "paths", "/cve_lookup_bulk", NULL);
  static_assertKeyAbsent(path_item, "get");

  JsonReadSpan_t operation = static_at(path_item, "post", NULL);
  static_assertString(static_at(operation, "operationId", NULL), "cve_lookup_bulk");
  static_assertRaw(static_at(operation, "x-credit-cost", NULL), "1");
  static_assertRaw(static_at(operation, "x-credit-cost-per-item", NULL), "true");
  static_assertKeyAbsent(operation, "parameters");

  JsonReadSpan_t body = static_at(operation, "requestBody", NULL);
  static_assertRaw(static_at(body, "required", NULL), "true");

  JsonReadSpan_t schema = static_at(body, "content", "application/json", "schema", NULL);
  static_assertString(static_at(schema, "type", NULL), "object");
  static_assertRaw(static_at(schema, "required", NULL), "[\"cve_ids\"]");
  static_assertRaw(static_at(schema, "additionalProperties", NULL), "false");
  TEST_ASSERT_EQUAL_INT(4, static_memberCount(schema));

  static_assertRaw(static_at(schema, "properties", NULL),
                   "{\"cve_ids\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"minItems\":1,\"maxItems\":50,"
                   "\"description\":\"CVE IDs\"}}");
}

static void test_package_check_bulk_items_refer_to_package_item(void)
{
  JsonReadSpan_t operation = static_at(g_root, "paths", "/package_check_bulk", "post", NULL);
  static_assertRaw(static_at(operation, "x-credit-cost-per-item", NULL), "true");

  JsonReadSpan_t items = static_at(operation, "requestBody", "content", "application/json", "schema", "properties", "items", NULL);
  static_assertRaw(static_at(items, "items", NULL), "{\"$ref\":\"#/components/schemas/PackageItem\"}");
  static_assertRaw(static_at(items, "maxItems", NULL), "500");
}

static void test_watchlist_edit_body_has_no_required_list(void)
{
  JsonReadSpan_t schema = static_at(g_root, "paths", "/watchlist_edit", "post", "requestBody", "content", "application/json", "schema", NULL);
  static_assertKeyAbsent(schema, "required");
  TEST_ASSERT_EQUAL_INT(3, static_memberCount(schema));
  TEST_ASSERT_EQUAL_INT(19, static_memberCount(static_at(schema, "properties", NULL)));
  static_assertKeyAbsent(static_at(schema, "properties", NULL), "sbom");
  static_assertString(static_at(schema, "properties", "action", "type", NULL), "string");
  static_assertString(static_at(schema, "properties", "ecosystem", "type", NULL), "string");
  static_assertString(static_at(schema, "properties", "name", "type", NULL), "string");
  static_assertString(static_at(schema, "properties", "version", "type", NULL), "string");
  static_assertString(static_at(schema, "properties", "ip_address", "type", NULL), "string");
  static_assertRaw(static_at(schema, "properties", "packages", "items", NULL), "{\"$ref\":\"#/components/schemas/PackageItemOptionalVersion\"}");
  static_assertRaw(static_at(schema, "properties", "packages", "maxItems", NULL), "500");
}

static void test_image_inspect_takes_an_octet_stream(void)
{
  JsonReadSpan_t operation = static_at(g_root, "paths", "/image_inspect", "post", NULL);
  static_assertString(static_at(operation, "operationId", NULL), "image_inspect");
  static_assertKeyAbsent(operation, "summary");
  static_assertKeyAbsent(operation, "description");
  static_assertKeyAbsent(operation, "tags");
  static_assertKeyAbsent(operation, "parameters");
  static_assertKeyAbsent(operation, "x-credit-cost-per-item");
  static_assertRaw(static_at(operation, "requestBody", NULL),
                   "{\"required\":true,\"content\":{\"application/octet-stream\":{\"schema\":"
                   "{\"type\":\"string\",\"contentMediaType\":\"application/octet-stream\"}}}}");
}

static void test_every_tool_row_has_its_tool_name_as_operation_id(void)
{
  JsonReadSpan_t paths      = static_at(g_root, "paths", NULL);
  int            tool_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* row = &endpoints[i];
    if (row->mp_mcpToolName == NULL)
      continue;

    static_assertString(static_at(static_findOperation(paths, row), "operationId", NULL), row->mp_mcpToolName);
    tool_count++;
  }
  TEST_ASSERT_EQUAL_INT(37, tool_count);
}

static void test_every_operation_follows_its_row(void)
{
  JsonReadSpan_t paths     = static_at(g_root, "paths", NULL);
  int            row_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* row = &endpoints[i];
    if (!openapi_isRowInDocument(row))
      continue;
    JsonReadSpan_t operation = static_findOperation(paths, row);

    char cost[16];
    snprintf(cost, sizeof(cost), "%u", row->m_creditCost);
    static_assertRaw(static_at(operation, "x-credit-cost", NULL), cost);
    static_assertStringOrAbsent(operation, "summary", row->mp_mcpToolTitle);
    static_assertStringOrAbsent(operation, "description", row->mp_mcpToolDescription);
    JsonReadSpan_t responses = static_at(operation, "responses", NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, static_memberCount(responses), row->mp_httpPath);
    static_assertRaw(static_at(responses, "default", NULL), "{\"$ref\":\"#/components/responses/Error\"}");
    static_assertRaw(static_at(responses, "200", "content", NULL), "{\"application/json\":{\"schema\":{\"type\":\"object\"}}}");
    int listed_count = 0;
    int body_count   = 0;
    for (int j = 0; j < row->m_paramCount; j++)
    {
      int sources = row->mp_params[j].m_sources;
      if ((sources & (ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_REST_QUERY)) != 0)
        listed_count++;
      else if ((sources & ENDPOINT_PARAM_SRC_REST_BODY) != 0)
        body_count++;
    }
    if (listed_count == 0)
      static_assertKeyAbsent(operation, "parameters");
    else
      TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)listed_count, static_elementCount(static_at(operation, "parameters", NULL)), row->mp_httpPath);
    if (body_count > 0 && !endpoint_hasRawBodyParam(row))
    {
      static_assertRaw(static_at(operation, "requestBody", "required", NULL), "true");
      TEST_ASSERT_EQUAL_INT_MESSAGE(body_count, static_memberCount(static_at(operation, "requestBody", "content", "application/json", "schema", "properties", NULL)), row->mp_httpPath);
    }

    const char* category = endpoint_mcpToolCategoryName(row->m_mcpToolCategory);
    if (category == NULL)
      static_assertKeyAbsent(operation, "tags");
    else
    {
      JsonReadSpan_t tags = static_at(operation, "tags", NULL);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(1, static_elementCount(tags), row->mp_httpPath);
      TEST_ASSERT_TRUE_MESSAGE(static_isStringInArray(tags, category), row->mp_httpPath);
    }

    if (row->m_costRule == ENDPOINT_COST_BULK_IDS)
      static_assertRaw(static_at(operation, "x-credit-cost-per-item", NULL), "true");
    else
      static_assertKeyAbsent(operation, "x-credit-cost-per-item");

    JsonReadSpan_t ok = static_at(operation, "responses", "200", NULL);
    if (row->m_creditCost > 0)
      static_assertRaw(static_at(ok, "headers", NULL),
                       "{\"X-RateLimit-Limit\":{\"$ref\":\"#/components/headers/X-RateLimit-Limit\"},"
                       "\"X-RateLimit-Remaining\":{\"$ref\":\"#/components/headers/X-RateLimit-Remaining\"},"
                       "\"X-RateLimit-Reset-Machine\":{\"$ref\":\"#/components/headers/X-RateLimit-Reset-Machine\"},"
                       "\"X-RateLimit-Reset-Human\":{\"$ref\":\"#/components/headers/X-RateLimit-Reset-Human\"}}");
    else
      static_assertKeyAbsent(ok, "headers");

    for (int j = 0; j < row->m_paramCount; j++)
    {
      const EndpointParam_t* param   = &row->mp_params[j];
      bool                   is_path = (param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0;
      if (is_path || (param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY) != 0)
      {
        JsonReadSpan_t parameter = static_findParameter(static_at(operation, "parameters", NULL), param->mp_spec->mp_name);
        static_assertString(static_at(parameter, "in", NULL), is_path ? "path" : "query");
        static_assertRaw(static_at(parameter, "required", NULL), (is_path || param->m_isRequired) ? "true" : "false");
        static_assertStringOrAbsent(parameter, "description", param->mp_mcpArgDescription);
        static_assertSchemaFollowsSpec(static_at(parameter, "schema", NULL), param->mp_spec);
      }
      else if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY) != 0 && !endpoint_hasRawBodyParam(row))
      {
        JsonReadSpan_t schema   = static_at(operation, "requestBody", "content", "application/json", "schema", NULL);
        JsonReadSpan_t property = static_at(schema, "properties", param->mp_spec->mp_name, NULL);
        static_assertRaw(static_at(schema, "additionalProperties", NULL), "false");
        static_assertStringOrAbsent(property, "description", param->mp_mcpArgDescription);
        static_assertSchemaFollowsSpec(property, param->mp_spec);
        JsonReadSpan_t required;
        bool is_listed = jsonread_objectKey(schema, "required", &required) == JSONREAD_OK
                         && static_isStringInArray(required, param->mp_spec->mp_name);
        TEST_ASSERT_EQUAL_INT_MESSAGE(param->m_isRequired, is_listed, param->mp_spec->mp_name);
      }
    }
    row_count++;
  }
  TEST_ASSERT_EQUAL_INT(40, row_count);
}

static void test_buffer_that_stops_at_its_ceiling_answers_false(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(64, 1024);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(openapi_appendDocument(json_buf));
  jsonbuf_destroy(json_buf);
}

static const EndpointParamSpec_t TEST_SPEC_HEADER = { .mp_name = "X-Signature", .m_type = ENDPOINT_PARAM_TYPE_STRING, .m_maxLen = 64 };
static const EndpointParamSpec_t TEST_SPEC_QUERY  = { .mp_name = "q",           .m_type = ENDPOINT_PARAM_TYPE_STRING, .m_maxLen = 64 };
static const EndpointParam_t TEST_HEADER_PARAMS[] = { { .mp_spec = &TEST_SPEC_HEADER, .m_sources = ENDPOINT_PARAM_SRC_REST_HEADER, .m_isRequired = true, .m_size = 65 } };
static const EndpointParam_t TEST_QUERY_PARAMS[]  = { { .mp_spec = &TEST_SPEC_QUERY,  .m_sources = ENDPOINT_PARAM_SRC_REST_QUERY,  .m_isRequired = true, .m_size = 65 } };
static const Endpoint_t TEST_HEADER_ROW = { .mp_httpPath = "/test_header", .ma_allowedMethods = {"POST", NULL}, .mp_params = TEST_HEADER_PARAMS, .m_paramCount = 1, .m_paramsSize = 65 };
static const Endpoint_t TEST_QUERY_ROW  = { .mp_httpPath = "/test_query",  .ma_allowedMethods = {"GET", NULL},  .mp_params = TEST_QUERY_PARAMS,  .m_paramCount = 1, .m_paramsSize = 65 };
static const Endpoint_t TEST_MCP_ROW    = { .mp_httpPath = "/test_mcp",    .ma_allowedMethods = {"POST", NULL}, .m_isMcpEndpoint = true };

static void test_a_row_with_a_header_param_is_not_in_the_document(void)
{
  TEST_ASSERT_FALSE(openapi_isRowInDocument(&TEST_HEADER_ROW));
  TEST_ASSERT_TRUE(openapi_isRowInDocument(&TEST_QUERY_ROW));
  TEST_ASSERT_FALSE(openapi_isRowInDocument(&TEST_MCP_ROW));
}

static void test_only_the_claim_row_of_the_two_billing_rows_is_in_the_document(void)
{
  const Endpoint_t* webhook = endpoint_findByHttpPath("/webhook_lemonsqueezy", NULL);
  const Endpoint_t* claim   = endpoint_findByHttpPath("/api_key_claim", NULL);
  TEST_ASSERT_NOT_NULL(webhook);
  TEST_ASSERT_NOT_NULL(claim);
  TEST_ASSERT_FALSE(openapi_isRowInDocument(webhook));
  TEST_ASSERT_TRUE(openapi_isRowInDocument(claim));

  JsonReadSpan_t paths = static_at(g_root, "paths", NULL);
  static_assertKeyAbsent(paths, "/webhook_lemonsqueezy");
  static_assertRaw(static_at(paths, "/api_key_claim", "post", "x-credit-cost", NULL), "0");
}

static void test_crypto_checkout_appears_as_a_post_with_no_input(void)
{
  const Endpoint_t* row = endpoint_findByHttpPath("/crypto_checkout", NULL);
  TEST_ASSERT_NOT_NULL(row);
  TEST_ASSERT_TRUE(openapi_isRowInDocument(row));

  JsonReadSpan_t path_item = static_at(g_root, "paths", "/crypto_checkout", NULL);
  static_assertKeyAbsent(path_item, "get");
  static_assertRaw(static_at(path_item, "post", "x-credit-cost", NULL), "1");
  JsonReadSpan_t operation = static_at(path_item, "post", NULL);
  static_assertKeyAbsent(operation, "requestBody");
  static_assertKeyAbsent(operation, "parameters");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_document_is_one_json_object_in_its_key_order);
  RUN_TEST(test_document_is_openapi_3_1_0);
  RUN_TEST(test_info_names_the_api_and_its_version);
  RUN_TEST(test_servers_name_the_public_host);
  RUN_TEST(test_security_takes_a_key_header_a_bearer_key_or_none);
  RUN_TEST(test_security_schemes_name_the_key_header_and_bearer);
  RUN_TEST(test_rate_limit_headers_are_four_components);
  RUN_TEST(test_error_response_refers_to_the_error_schema);
  RUN_TEST(test_package_item_schema_is_the_tools_list_item_schema);
  RUN_TEST(test_tags_list_every_category_in_home_page_order);
  RUN_TEST(test_document_holds_40_operations);
  RUN_TEST(test_mcp_row_has_no_path);
  RUN_TEST(test_cve_lookup_names_its_path_segment);
  RUN_TEST(test_operation_keys_come_in_their_order);
  RUN_TEST(test_responses_name_the_rate_limit_headers_and_the_error);
  RUN_TEST(test_free_health_lists_no_rate_limit_headers);
  RUN_TEST(test_cve_lookup_description_is_its_row_tool_description);
  RUN_TEST(test_cve_search_query_params_carry_their_schemas);
  RUN_TEST(test_cve_search_number_params_carry_their_default);
  RUN_TEST(test_offset_maximum_is_on_the_three_capped_lists_only);
  RUN_TEST(test_product_exposure_query_params_carry_include_rejected);
  RUN_TEST(test_package_check_query_param_is_required_when_the_row_requires_it);
  RUN_TEST(test_price_comes_from_the_row);
  RUN_TEST(test_health_has_no_parameters_and_no_body);
  RUN_TEST(test_cve_lookup_bulk_takes_a_json_body);
  RUN_TEST(test_package_check_bulk_items_refer_to_package_item);
  RUN_TEST(test_watchlist_edit_body_has_no_required_list);
  RUN_TEST(test_package_item_optional_version_schema_leaves_out_the_version);
  RUN_TEST(test_image_inspect_takes_an_octet_stream);
  RUN_TEST(test_every_tool_row_has_its_tool_name_as_operation_id);
  RUN_TEST(test_every_operation_follows_its_row);
  RUN_TEST(test_buffer_that_stops_at_its_ceiling_answers_false);
  RUN_TEST(test_a_row_with_a_header_param_is_not_in_the_document);
  RUN_TEST(test_only_the_claim_row_of_the_two_billing_rows_is_in_the_document);
  RUN_TEST(test_crypto_checkout_appears_as_a_post_with_no_input);
  return UNITY_END();
}
