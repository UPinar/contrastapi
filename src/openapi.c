#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "openapi.h"
#include "endpoint.h"
#include "jsonbuf.h"
#include "pricing.h"
#include "version.h"

#define OPENAPI_SPEC_VERSION "3.1.0"

#define OPENAPI_API_DESCRIPTION \
  "Security intelligence REST API for CVE, package, credential, domain, IP and threat defense lookups, priced in credits."

typedef struct {
  const char* mp_name;
  const char* mp_schemaType;
  const char* mp_description;
} OpenApiRateLimitHeader_t;

static const OpenApiRateLimitHeader_t OPENAPI_RATE_LIMIT_HEADERS[] = {
  { "X-RateLimit-Limit",         "integer", "The credits the caller may spend in one window." },
  { "X-RateLimit-Remaining",     "integer", "The credits left in the current window." },
  { "X-RateLimit-Reset-Machine", "integer", "The Unix time, in seconds, at which the window resets." },
  { "X-RateLimit-Reset-Human",   "string",  "The time left until the window resets, as HH:MM:SS." },
};

static const char*            static_findShapeProblem        (const Endpoint_t* row);
static void                   static_appendTags              (JsonBuf_t* json_buf);
static void                   static_appendPaths             (JsonBuf_t* json_buf);
static void                   static_appendComponents        (JsonBuf_t* json_buf);

static const EndpointParam_t* static_findPathSegmentParam    (const Endpoint_t* row);
static void                   static_appendOperation         (const Endpoint_t* row, const char* http_method, JsonBuf_t* json_buf);
static void                   static_appendOperationId       (const Endpoint_t* row, JsonBuf_t* json_buf);
static void                   static_appendParameters        (const Endpoint_t* row, JsonBuf_t* json_buf);
static void                   static_appendRequestBody       (const Endpoint_t* row, JsonBuf_t* json_buf);
static void                   static_appendResponses         (const Endpoint_t* row, JsonBuf_t* json_buf);
static void                   static_appendParamSchema       (const EndpointParamSpec_t* spec, const char* description, JsonBuf_t* json_buf);

bool openapi_appendDocument(JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);

  for (int i = 0; i < endpoint_count; i++)
  {
    const char* problem = static_findShapeProblem(&endpoints[i]);
    if (problem != NULL)
    {
      fprintf(stderr, "openapi_appendDocument: the row %s %s\n", endpoints[i].mp_httpPath, problem);
      return false;
    }
  }

  jsonbuf_appendFormat(json_buf, "{\"openapi\":\"" OPENAPI_SPEC_VERSION "\"");
  jsonbuf_appendFormat(json_buf, ",\"info\":{\"title\":\"ContrastAPI\",\"version\":\"" CONTRASTAPI_VERSION "\",\"description\":\"" OPENAPI_API_DESCRIPTION "\"}");
  jsonbuf_appendFormat(json_buf, ",\"servers\":[{\"url\":\"" PRICING_API_BASE_URL "\"}]");
  jsonbuf_appendFormat(json_buf, ",\"security\":[{\"ApiKeyHeader\":[]},{\"BearerAuth\":[]},{}]");

  jsonbuf_appendFormat(json_buf, ",");
  static_appendTags(json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_appendPaths(json_buf);
  jsonbuf_appendFormat(json_buf, ",");
  static_appendComponents(json_buf);

  return jsonbuf_appendFormat(json_buf, "}");
}

bool openapi_isRowInDocument(const Endpoint_t* row)
{
  assert(row != NULL);

  if (row->m_isMcpEndpoint)
    return false;
  for (int i = 0; i < row->m_paramCount; i++)
  {
    if ((row->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_REST_HEADER) != 0)
      return false;
  }
  return true;
}

static const char* static_findShapeProblem(const Endpoint_t* row)
{
  if (!openapi_isRowInDocument(row))
    return NULL;
  if (row->ma_allowedMethods[0] == NULL || row->ma_allowedMethods[1] != NULL)
    return "does not have exactly one HTTP method";

  int segment_count = 0;
  for (int i = 0; i < row->m_paramCount; i++)
  {
    const EndpointParam_t* param = &row->mp_params[i];
    if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0)
      segment_count++;

    bool is_described = (param->m_sources & (ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_REST_BODY)) != 0;
    if (is_described && strcmp(endpoint_jsonSchemaTypeName(param->mp_spec->m_type), "string") == 0 && param->mp_spec->m_maxLen == 0)
      return "has a string param without a length limit";
  }

  if (segment_count != (row->m_hasPathSegment ? 1 : 0))
    return "has path segment params that do not match m_hasPathSegment";
  return NULL;
}

static void static_appendTags(JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"tags\":[");

  for (int category = ENDPOINT_MCP_TOOL_CATEGORY_CVE; category <= ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS; category++)
  {
    jsonbuf_appendFormat(json_buf, "%s{\"name\":\"", category == ENDPOINT_MCP_TOOL_CATEGORY_CVE ? "" : ",");
    jsonbuf_appendEscaped(json_buf, endpoint_mcpToolCategoryName((EndpointMcpToolCategory_t)category));
    jsonbuf_appendFormat(json_buf, "\"}");
  }

  jsonbuf_appendFormat(json_buf, "]");
}

static void static_appendPaths(JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"paths\":{");

  bool is_first = true;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* row = &endpoints[i];
    if (!openapi_isRowInDocument(row))
      continue;

    jsonbuf_appendFormat(json_buf, "%s\"", is_first ? "" : ",");
    jsonbuf_appendEscaped(json_buf, row->mp_httpPath);
    const EndpointParam_t* segment_param = static_findPathSegmentParam(row);
    if (segment_param != NULL)
    {
      jsonbuf_appendFormat(json_buf, "{");
      jsonbuf_appendEscaped(json_buf, segment_param->mp_spec->mp_name);
      jsonbuf_appendFormat(json_buf, "}");
    }
    jsonbuf_appendFormat(json_buf, "\":{");
    static_appendOperation(row, row->ma_allowedMethods[0], json_buf);
    jsonbuf_appendFormat(json_buf, "}");
    is_first = false;
  }

  jsonbuf_appendFormat(json_buf, "}");
}

static void static_appendComponents(JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"components\":{\"securitySchemes\":{");
  jsonbuf_appendFormat(json_buf, "\"ApiKeyHeader\":{\"type\":\"apiKey\",\"in\":\"header\",\"name\":\"X-API-Key\"}");
  jsonbuf_appendFormat(json_buf, ",\"BearerAuth\":{\"type\":\"http\",\"scheme\":\"bearer\"}}");

  jsonbuf_appendFormat(json_buf, ",\"headers\":{");
  for (size_t i = 0; i < sizeof(OPENAPI_RATE_LIMIT_HEADERS) / sizeof(OPENAPI_RATE_LIMIT_HEADERS[0]); i++)
  {
    const OpenApiRateLimitHeader_t* header = &OPENAPI_RATE_LIMIT_HEADERS[i];
    jsonbuf_appendFormat(json_buf, "%s\"%s\":{\"description\":\"%s\",\"schema\":{\"type\":\"%s\"}}",
                         i == 0 ? "" : ",", header->mp_name, header->mp_description, header->mp_schemaType);
  }
  jsonbuf_appendFormat(json_buf, "}");

  jsonbuf_appendFormat(json_buf, R"(,"responses":{"Error":{"description":"An error. The body names an error code and a message.",)"
                                 R"("content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}})");

  jsonbuf_appendFormat(json_buf, R"(,"schemas":{"Error":{"type":"object","required":["error"],"properties":{"error":{"type":"object",)"
                                 R"("required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"}}}}})");
  jsonbuf_appendFormat(json_buf, ",\"PackageItem\":");
  jsonbuf_appendJsonText(json_buf, ENDPOINT_PACKAGE_ITEM_SCHEMA_JSON);
  jsonbuf_appendFormat(json_buf, ",\"PackageItemOptionalVersion\":");
  jsonbuf_appendJsonText(json_buf, ENDPOINT_PACKAGE_ITEM_OPTIONAL_VERSION_SCHEMA_JSON);
  jsonbuf_appendFormat(json_buf, "}}");
}

static const EndpointParam_t* static_findPathSegmentParam(const Endpoint_t* row)
{
  for (int i = 0; i < row->m_paramCount; i++)
  {
    if ((row->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0)
      return &row->mp_params[i];
  }
  return NULL;
}

static void static_appendOperation(const Endpoint_t* row, const char* http_method, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"");
  for (size_t i = 0; http_method[i] != '\0'; i++)
    jsonbuf_appendFormat(json_buf, "%c", tolower((unsigned char)http_method[i]));
  jsonbuf_appendFormat(json_buf, "\":{\"operationId\":\"");
  static_appendOperationId(row, json_buf);
  jsonbuf_appendFormat(json_buf, "\"");

  if (row->mp_mcpToolTitle != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"summary\":\"");
    jsonbuf_appendEscaped(json_buf, row->mp_mcpToolTitle);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  if (row->mp_mcpToolDescription != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"description\":\"");
    jsonbuf_appendEscaped(json_buf, row->mp_mcpToolDescription);
    jsonbuf_appendFormat(json_buf, "\"");
  }

  const char* category_name = endpoint_mcpToolCategoryName(row->m_mcpToolCategory);
  if (category_name != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"tags\":[\"");
    jsonbuf_appendEscaped(json_buf, category_name);
    jsonbuf_appendFormat(json_buf, "\"]");
  }

  jsonbuf_appendFormat(json_buf, ",\"x-credit-cost\":%u", row->m_creditCost);
  if (row->m_costRule == ENDPOINT_COST_BULK_IDS)
    jsonbuf_appendFormat(json_buf, ",\"x-credit-cost-per-item\":true");

  static_appendParameters(row, json_buf);
  static_appendRequestBody(row, json_buf);
  static_appendResponses(row, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

static void static_appendOperationId(const Endpoint_t* row, JsonBuf_t* json_buf)
{
  const char* cursor = row->mp_httpPath;
  while (*cursor != '\0')
  {
    const char* slash = strchr(cursor, '/');
    size_t      run   = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);
    jsonbuf_appendEscapedBytes(json_buf, cursor, run);
    cursor += run;
    if (*cursor == '/')
      cursor++;
  }
}

static void static_appendParameters(const Endpoint_t* row, JsonBuf_t* json_buf)
{
  bool is_first = true;
  for (int i = 0; i < row->m_paramCount; i++)
  {
    const EndpointParam_t* param   = &row->mp_params[i];
    bool                   is_path = (param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0;
    if (!is_path && (param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY) == 0)
      continue;

    jsonbuf_appendFormat(json_buf, "%s{\"name\":\"", is_first ? ",\"parameters\":[" : ",");
    jsonbuf_appendEscaped(json_buf, param->mp_spec->mp_name);
    if (is_path)
      jsonbuf_appendFormat(json_buf, "\",\"in\":\"path\",\"required\":true");
    else
      jsonbuf_appendFormat(json_buf, "\",\"in\":\"query\",\"required\":%s", param->m_isRequired ? "true" : "false");
    if (param->mp_mcpArgDescription != NULL)
    {
      jsonbuf_appendFormat(json_buf, ",\"description\":\"");
      jsonbuf_appendEscaped(json_buf, param->mp_mcpArgDescription);
      jsonbuf_appendFormat(json_buf, "\"");
    }
    jsonbuf_appendFormat(json_buf, ",\"schema\":");
    static_appendParamSchema(param->mp_spec, NULL, json_buf);
    jsonbuf_appendFormat(json_buf, "}");
    is_first = false;
  }

  if (!is_first)
    jsonbuf_appendFormat(json_buf, "]");
}

static void static_appendRequestBody(const Endpoint_t* row, JsonBuf_t* json_buf)
{
  if (endpoint_hasRawBodyParam(row))
  {
    jsonbuf_appendFormat(json_buf, R"(,"requestBody":{"required":true,"content":{"application/octet-stream":{"schema":)"
                                   R"({"type":"string","contentMediaType":"application/octet-stream"}}}})");
    return;
  }
  if (!endpoint_hasRestBodyParam(row))
    return;

  jsonbuf_appendFormat(json_buf, R"(,"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{)");
  bool is_first = true;
  for (int i = 0; i < row->m_paramCount; i++)
  {
    const EndpointParam_t* param = &row->mp_params[i];
    if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY) == 0)
      continue;
    jsonbuf_appendFormat(json_buf, "%s\"", is_first ? "" : ",");
    jsonbuf_appendEscaped(json_buf, param->mp_spec->mp_name);
    jsonbuf_appendFormat(json_buf, "\":");
    static_appendParamSchema(param->mp_spec, param->mp_mcpArgDescription, json_buf);
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, "}");

  is_first = true;
  for (int i = 0; i < row->m_paramCount; i++)
  {
    const EndpointParam_t* param = &row->mp_params[i];
    if ((param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY) == 0 || !param->m_isRequired)
      continue;
    jsonbuf_appendFormat(json_buf, "%s\"", is_first ? ",\"required\":[" : ",");
    jsonbuf_appendEscaped(json_buf, param->mp_spec->mp_name);
    jsonbuf_appendFormat(json_buf, "\"");
    is_first = false;
  }
  if (!is_first)
    jsonbuf_appendFormat(json_buf, "]");

  jsonbuf_appendFormat(json_buf, ",\"additionalProperties\":false}}}}");
}

static void static_appendResponses(const Endpoint_t* row, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, ",\"responses\":{\"200\":{\"description\":\"The answer of the endpoint.\"");
  if (row->m_creditCost > 0)
  {
    jsonbuf_appendFormat(json_buf, ",\"headers\":{");
    for (size_t i = 0; i < sizeof(OPENAPI_RATE_LIMIT_HEADERS) / sizeof(OPENAPI_RATE_LIMIT_HEADERS[0]); i++)
    {
      const char* name = OPENAPI_RATE_LIMIT_HEADERS[i].mp_name;
      jsonbuf_appendFormat(json_buf, "%s\"%s\":{\"$ref\":\"#/components/headers/%s\"}", i == 0 ? "" : ",", name, name);
    }
    jsonbuf_appendFormat(json_buf, "}");
  }
  jsonbuf_appendFormat(json_buf, R"(,"content":{"application/json":{"schema":{"type":"object"}}}},"default":{"$ref":"#/components/responses/Error"}})");
}

static void static_appendParamSchema(const EndpointParamSpec_t* spec, const char* description, JsonBuf_t* json_buf)
{
  const char* type_name = endpoint_jsonSchemaTypeName(spec->m_type);
  jsonbuf_appendFormat(json_buf, "{\"type\":\"%s\"", type_name);

  if (spec->m_type == ENDPOINT_PARAM_TYPE_ENUM)
  {
    assert(spec->mp_enumValues != NULL);
    jsonbuf_appendFormat(json_buf, ",\"enum\":[");
    for (size_t i = 0; spec->mp_enumValues[i] != NULL; i++)
    {
      jsonbuf_appendFormat(json_buf, "%s\"", i == 0 ? "" : ",");
      jsonbuf_appendEscaped(json_buf, spec->mp_enumValues[i]);
      jsonbuf_appendFormat(json_buf, "\"");
    }
    jsonbuf_appendFormat(json_buf, "]");
  }
  else if (endpoint_isIdArrayType(spec->m_type))
    jsonbuf_appendFormat(json_buf, ",\"items\":{\"type\":\"string\"}");
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY && spec->m_isPackageVersionOptional)
    jsonbuf_appendFormat(json_buf, ",\"items\":{\"$ref\":\"#/components/schemas/PackageItemOptionalVersion\"}");
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
    jsonbuf_appendFormat(json_buf, ",\"items\":{\"$ref\":\"#/components/schemas/PackageItem\"}");

  if (spec->m_isOnlyTrueAccepted)
    jsonbuf_appendFormat(json_buf, ",\"const\":true");

  endpoint_appendSchemaBounds(spec, json_buf);

  if (description != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"description\":\"");
    jsonbuf_appendEscaped(json_buf, description);
    jsonbuf_appendFormat(json_buf, "\"");
  }

  jsonbuf_appendFormat(json_buf, "}");
}
