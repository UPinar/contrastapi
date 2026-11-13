#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcp.h"
#include "bytes.h"
#include "jsonrpc.h"
#include "picohttpparser.h"
#include "jsonread.h"
#include "jsonbuf.h"
#include "endpoint.h"
#include "version.h"
#include "usagelog.h"

#define MCP_REQUESTED_VERSION_BUF_SIZE    32

#define MCP_INVALID_PARAMS_PREFIX "Invalid params: "
#define MCP_MESSAGE_BUF_SIZE      (ENDPOINT_MESSAGE_BUF_SIZE + sizeof(MCP_INVALID_PARAMS_PREFIX) - 1)

#define MCP_NOTIFICATION_PREFIX "notifications/"

#define MCP_ENVELOPE_JSONBUF_CEILING  JSONBUF_MAX_CEILING

#define MCP_ENVELOPE_FAILED_MESSAGE  "Internal error: the tool result could not be encoded"

static const char* const MCP_SUPPORTED_VERSIONS[] = {
  MCP_PROTOCOL_VERSION,
  "2025-06-18",
  "2025-03-26",
};
static const size_t MCP_SUPPORTED_COUNT = sizeof(MCP_SUPPORTED_VERSIONS) / sizeof(MCP_SUPPORTED_VERSIONS[0]);

#define MCP_MODERN_PROTOCOL_VERSION "2026-07-28"

static const char* const MCP_HANDSHAKE_VERSIONS[] = {
  "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25",
};
static const size_t MCP_HANDSHAKE_COUNT = sizeof(MCP_HANDSHAKE_VERSIONS) / sizeof(MCP_HANDSHAKE_VERSIONS[0]);

#define MCP_META_KEY_PROTOCOL_VERSION    "io.modelcontextprotocol/protocolVersion"
#define MCP_META_KEY_CLIENT_INFO         "io.modelcontextprotocol/clientInfo"
#define MCP_META_KEY_CLIENT_CAPABILITIES "io.modelcontextprotocol/clientCapabilities"

#define MCP_META_KEY_TOOL_CATEGORY       "com.contrastcyber/category"

#define MCP_SERVER_INFO_JSON \
  "\"serverInfo\":{\"name\":\"contrastapi\",\"title\":\"ContrastAPI\",\"version\":\"" CONTRASTAPI_VERSION "\"}"

static const char MCP_DISCOVER_RESULT[] =
  "{\"cacheScope\":\"public\",\"ttlMs\":3600000,"
  "\"supportedVersions\":[\"" MCP_MODERN_PROTOCOL_VERSION "\"],"
  "\"capabilities\":{\"tools\":{}},"
  MCP_SERVER_INFO_JSON ","
  "\"instructions\":\"" MCP_SERVER_INSTRUCTIONS "\"}";

static const char* const MCP_USAGE_LOG_METHOD_NAMES[] = {
  "initialize", "tools/list", "ping", "tools/call", "server/discover", "notifications/initialized",
};

typedef enum {
  MCP_TOOL_KIND_JSON = 0,
  MCP_TOOL_KIND_JSON_TOOL_ERROR,
  MCP_TOOL_KIND_TOOL_ERROR,
  MCP_TOOL_KIND_PROTOCOL_ERROR,
} McpToolKind_t;

typedef struct {
  McpToolKind_t m_kind;
  char*         mp_json;
  int           m_protocolErrorCode;
  char          ma_message[MCP_MESSAGE_BUF_SIZE];
} McpToolResult_t;

static char*        static_handleMCPToolsCall              (const JsonRpcRequest_t* req, PGconn* conn, const RequestCharge_t* charge, bool is_modern, int* protocol_code_out, McpRunReport_t* run_report);
static char*        static_encodeToolResult                (const char* id_raw, const McpToolResult_t* result, bool is_modern, size_t* meta_offset_out);
static char*        static_buildInitializeResult           (const JsonRpcRequest_t* req);
static const char*  static_negotiateVersion                (const JsonRpcRequest_t* req);
static char*        static_buildRpcResultEnvelope          (const char* id_raw, const char* result_json);
static char*        static_buildToolsListResponse          (const char* id_raw, bool is_modern);
static char*        static_buildRpcErrorEnvelope           (const char* id_raw, int code, const char* message);
static char*        static_buildUnsupportedVersionEnvelope (const char* id_raw, const char* envelope_version);
static char*        static_buildToolContent                (const char* id_raw, const char* text, bool is_error, bool is_modern, size_t* meta_offset_out);
static void         static_setUsageLogMethodName           (const char* rpc_method);

static bool   static_isMcpArg                  (const EndpointParam_t* param);
static void   static_appendMcpArgSchema        (const EndpointParam_t* param, JsonBuf_t* json_buf);
static void   static_appendMcpArgProperties    (const Endpoint_t* endpoint, JsonBuf_t* json_buf);
static void   static_appendMcpRequiredList     (const Endpoint_t* endpoint, JsonBuf_t* json_buf);
static void   static_appendMcpToolAnnotations  (const Endpoint_t* endpoint, JsonBuf_t* json_buf);
static void   static_appendMcpToolMeta         (const Endpoint_t* endpoint, JsonBuf_t* json_buf);
static void   static_appendMcpTool             (const Endpoint_t* endpoint, JsonBuf_t* json_buf);

static char* static_buildParseErrorEnvelope   (JsonRpcStatus_t parse_status, int* rpc_code_out);
static bool  static_isRefusedBeforeDispatch   (const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out);
static bool  static_dispatchModern            (const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report);
static char* static_classifyModernInbound     (const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, int* status_out);
static int   static_modernHttpStatus          (int code);
static char* static_buildModernResult         (const char* id_raw, const char* result_json);
static bool  static_isMcpRoutingHeaderMatched (McpRoutingHeaders_t* headers_out, const char* name, size_t name_len, const char* value, size_t value_len);

static void static_setResultJson            (McpToolResult_t* result_out, char* json);
static void static_setToolError             (McpToolResult_t* result_out, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
static void static_setProtocolError         (McpToolResult_t* result_out, int code, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
static bool static_areArgsAccepted          (const Endpoint_t* endpoint, JsonReadSpan_t args_span, void* params_out, size_t params_size, McpToolResult_t* result_out);
static void static_setUnknownArgError       (const Endpoint_t* endpoint, McpToolResult_t* result_out);

static void static_runTool                  (const Endpoint_t* endpoint, JsonReadSpan_t args_span, McpToolResult_t* result_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report);

void mcp_readRoutingHeaders(const struct phr_header* headers, size_t header_count, McpRoutingHeaders_t* headers_out)
{
  assert(headers != NULL || header_count == 0);
  assert(headers_out != NULL);

  memset(headers_out, 0, sizeof(*headers_out));

  bool prev_was_routing = false;
  for (size_t i = 0; i < header_count; i++)
  {
    if (headers[i].name == NULL)
    {
      if (prev_was_routing)
        headers_out->m_duplicated = true;
      continue;
    }
    prev_was_routing = static_isMcpRoutingHeaderMatched(headers_out, headers[i].name, headers[i].name_len,
                                                        headers[i].value, headers[i].value_len);
  }
}

static bool static_isMcpRoutingHeaderMatched(McpRoutingHeaders_t* headers_out, const char* name, size_t name_len, const char* value, size_t value_len)
{
  struct { const char* mp_headerName; bool* mp_has; char* mp_valueBuf; size_t m_valueBufSize; } const targets[] = {
    { "mcp-protocol-version", &headers_out->m_hasProtocolVersion, headers_out->ma_protocolVersion, sizeof(headers_out->ma_protocolVersion) },
    { "mcp-method",           &headers_out->m_hasMethod,          headers_out->ma_method,          sizeof(headers_out->ma_method)          },
    { "mcp-name",             &headers_out->m_hasName,            headers_out->ma_name,            sizeof(headers_out->ma_name)            },
  };
  const size_t target_count = sizeof(targets) / sizeof(targets[0]);

  for (size_t i = 0; i < target_count; i++)
  {
    if (!bytes_isEqual(name, name_len, targets[i].mp_headerName, true))
      continue;

    if (*targets[i].mp_has)
    {
      headers_out->m_duplicated = true;
      return true;
    }
    *targets[i].mp_has = true;

    size_t copy_len = (value_len < targets[i].m_valueBufSize - 1) ? value_len : targets[i].m_valueBufSize - 1;
    memcpy(targets[i].mp_valueBuf, value, copy_len);
    targets[i].mp_valueBuf[copy_len] = '\0';
    return true;
  }
  return false;
}

bool mcp_isModernEra(const McpRoutingHeaders_t* routing_headers)
{
  if (!routing_headers || !routing_headers->m_hasProtocolVersion)
    return false;

  for (size_t i = 0; i < MCP_HANDSHAKE_COUNT; i++)
    if (strcmp(routing_headers->ma_protocolVersion, MCP_HANDSHAKE_VERSIONS[i]) == 0)
      return false;

  return true;
}

bool mcp_dispatch(const char* body, size_t len, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report_out)
{
  assert(body       != NULL);
  assert(json_out   != NULL);
  assert(status_out != NULL);

  *json_out   = NULL;
  *status_out = 200;
  if (run_report_out)
    memset(run_report_out, 0, sizeof(*run_report_out));

  bool is_modern = mcp_isModernEra(routing_headers);

  JsonRpcRequest_t jsonrpc_req          = { 0 };
  JsonRpcStatus_t jsonrpc_parse_status  = jsonrpc_parse(body, len, &jsonrpc_req);

  if (jsonrpc_parse_status != JSONRPC_OK)
  {
    int rpc_code = 0;
    *json_out = static_buildParseErrorEnvelope(jsonrpc_parse_status, &rpc_code);
    if (is_modern)
      *status_out = static_modernHttpStatus(rpc_code);
    return *json_out != NULL;
  }

  static_setUsageLogMethodName(jsonrpc_req.ma_rpcMethod);

  if (is_modern)
    return static_dispatchModern(&jsonrpc_req, routing_headers, json_out, status_out, conn, charge, run_report_out);

  if (!jsonrpc_req.m_hasId)
  {
    *status_out = 202;
    return true;
  }

  if (strcmp(jsonrpc_req.ma_rpcMethod, "initialize") == 0)
    *json_out = static_buildInitializeResult(&jsonrpc_req);
  else if (strcmp(jsonrpc_req.ma_rpcMethod, "tools/list") == 0)
    *json_out = static_buildToolsListResponse(jsonrpc_req.ma_id, false);
  else if (strcmp(jsonrpc_req.ma_rpcMethod, "ping") == 0)
    *json_out = static_buildRpcResultEnvelope(jsonrpc_req.ma_id, "{}");
  else if (strcmp(jsonrpc_req.ma_rpcMethod, "tools/call") == 0)
    *json_out = static_handleMCPToolsCall(&jsonrpc_req, conn, charge, false, NULL, run_report_out);
  else
    *json_out = static_buildRpcErrorEnvelope(jsonrpc_req.ma_id, JSONRPC_ERR_METHOD, "Method not found");

  return *json_out != NULL;
}

static int static_modernHttpStatus(int code)
{
  switch (code)
  {
    case JSONRPC_ERR_METHOD:
      return 404;
    case JSONRPC_ERR_PARSE:
    case JSONRPC_ERR_INVALID_REQ:
    case JSONRPC_ERR_PARAMS:
    case JSONRPC_ERR_HEADER_MISMATCH:
    case JSONRPC_ERR_UNSUPPORTED_VERSION:
      return 400;
    default:
      return 200;
  }
}

static char* static_classifyModernInbound(const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, int* status_out)
{
  assert(routing_headers != NULL);

  JsonReadSpan_t meta_span, probe_span, pv_span;
  char envelope_version[MCP_HEADER_PROTOCOL_VERSION_MAX_LEN + 1];

  bool meta_ok =
      req->m_hasParams &&
      jsonread_objectKey(req->m_params, "_meta", &meta_span) == JSONREAD_OK &&
      jsonread_objectKey(meta_span, MCP_META_KEY_PROTOCOL_VERSION, &pv_span) == JSONREAD_OK &&
      jsonread_spanToStrStatus(pv_span, envelope_version, sizeof(envelope_version)) == JSONREAD_OK &&
      jsonread_objectKey(meta_span, MCP_META_KEY_CLIENT_INFO, &probe_span) == JSONREAD_OK &&
      jsonread_objectKey(meta_span, MCP_META_KEY_CLIENT_CAPABILITIES, &probe_span) == JSONREAD_OK;

  if (!meta_ok)
  {
    *status_out = static_modernHttpStatus(JSONRPC_ERR_PARAMS);
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS,
        "params._meta must carry the reserved protocol-version, client-info and "
        "client-capabilities envelope keys");
  }

  if (!routing_headers->m_hasProtocolVersion || strcmp(routing_headers->ma_protocolVersion, envelope_version) != 0)
  {
    *status_out = static_modernHttpStatus(JSONRPC_ERR_HEADER_MISMATCH);
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_HEADER_MISMATCH,
        "mcp-protocol-version header does not match the request envelope's protocol version");
  }

  if (!routing_headers->m_hasMethod || strcmp(routing_headers->ma_method, req->ma_rpcMethod) != 0)
  {
    *status_out = static_modernHttpStatus(JSONRPC_ERR_HEADER_MISMATCH);
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_HEADER_MISMATCH,
        "mcp-method header does not match the request body's method");
  }

  if (strcmp(req->ma_rpcMethod, "tools/call") == 0 && req->m_hasParams)
  {
    JsonReadSpan_t name_span;
    char body_name[MCP_HEADER_NAME_MAX_LEN + 1];
    if (jsonread_objectKey(req->m_params, "name", &name_span) == JSONREAD_OK &&
        jsonread_spanToStrStatus(name_span, body_name, sizeof(body_name)) == JSONREAD_OK)
    {
      if (!routing_headers->m_hasName || strcmp(routing_headers->ma_name, body_name) != 0)
      {
        *status_out = static_modernHttpStatus(JSONRPC_ERR_HEADER_MISMATCH);
        return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_HEADER_MISMATCH,
            "mcp-name header does not match the request body's 'name' parameter");
      }
    }
  }

  if (strcmp(envelope_version, MCP_MODERN_PROTOCOL_VERSION) != 0)
  {
    *status_out = static_modernHttpStatus(JSONRPC_ERR_UNSUPPORTED_VERSION);
    return static_buildUnsupportedVersionEnvelope(req->ma_id, envelope_version);
  }

  return NULL;
}

static char* static_buildParseErrorEnvelope(JsonRpcStatus_t parse_status, int* rpc_code_out)
{
  assert(parse_status != JSONRPC_OK);
  if (parse_status == JSONRPC_MALFORMED)
  {
    *rpc_code_out = JSONRPC_ERR_PARSE;
    return static_buildRpcErrorEnvelope("null", JSONRPC_ERR_PARSE, "Parse error");
  }
  *rpc_code_out = JSONRPC_ERR_INVALID_REQ;
  return static_buildRpcErrorEnvelope("null", JSONRPC_ERR_INVALID_REQ, "Invalid Request");
}

static bool static_isRefusedBeforeDispatch(const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out)
{
  assert(routing_headers != NULL);

  if (!req->m_hasId)
  {
    *json_out   = static_buildRpcErrorEnvelope("null", JSONRPC_ERR_INVALID_REQ,
                                    "Body must be a single JSON-RPC request object");
    *status_out = static_modernHttpStatus(JSONRPC_ERR_INVALID_REQ);
    return true;
  }

  if (routing_headers->m_duplicated)
  {
    *json_out   = static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_HEADER_MISMATCH,
                                    "a routing header appears more than once");
    *status_out = static_modernHttpStatus(JSONRPC_ERR_HEADER_MISMATCH);
    return true;
  }

  int   ladder_status = 200;
  char* rejection     = static_classifyModernInbound(req, routing_headers, &ladder_status);
  if (rejection || ladder_status != 200)
  {
    *json_out   = rejection;
    *status_out = ladder_status;
    return true;
  }
  return false;
}

bool mcp_tryBuildModernRefusal(const char* body, size_t len, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out)
{
  assert(body       != NULL);
  assert(json_out   != NULL);
  assert(status_out != NULL);

  if (!mcp_isModernEra(routing_headers))
    return false;

  char* refusal        = NULL;
  int   refusal_status = 200;
  JsonRpcRequest_t request = { 0 };
  JsonRpcStatus_t  parse_status = jsonrpc_parse(body, len, &request);
  if (parse_status != JSONRPC_OK)
  {
    int rpc_code = 0;
    refusal        = static_buildParseErrorEnvelope(parse_status, &rpc_code);
    refusal_status = static_modernHttpStatus(rpc_code);
  }
  else if (!static_isRefusedBeforeDispatch(&request, routing_headers, &refusal, &refusal_status))
    return false;

  *json_out   = refusal;
  *status_out = refusal ? refusal_status : 500;
  return true;
}

static bool static_dispatchModern(const JsonRpcRequest_t* req, const McpRoutingHeaders_t* routing_headers, char** json_out, int* status_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report)
{
  assert(routing_headers != NULL);

  if (static_isRefusedBeforeDispatch(req, routing_headers, json_out, status_out))
    return *json_out != NULL;

  if (strcmp(req->ma_rpcMethod, "server/discover") == 0)
    *json_out = static_buildModernResult(req->ma_id, MCP_DISCOVER_RESULT);
  else if (strcmp(req->ma_rpcMethod, "tools/list") == 0)
    *json_out = static_buildToolsListResponse(req->ma_id, true);
  else if (strcmp(req->ma_rpcMethod, "ping") == 0)
    *json_out = static_buildModernResult(req->ma_id, "{}");
  else if (strcmp(req->ma_rpcMethod, "tools/call") == 0)
  {
    int protocol_code = 0;
    *json_out   = static_handleMCPToolsCall(req, conn, charge, true, &protocol_code, run_report);
    *status_out = static_modernHttpStatus(protocol_code);
  }
  else
  {
    *json_out   = static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_METHOD, "Method not found");
    *status_out = static_modernHttpStatus(JSONRPC_ERR_METHOD);
  }

  return *json_out != NULL;
}

static char* static_buildModernResult(const char* id_raw, const char* result_json)
{
  assert(result_json[0] == '{');

  const char* rest = result_json + 1;
  const char* sep  = (*rest == '}') ? "" : ",";

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonbuf_appendFormat(json_buf, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"resultType\":\"complete\"%s%s}", id_raw, sep, rest);
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

McpToolCallStatus_t mcp_readToolCall(const JsonRpcRequest_t* request, char name_out[MCP_TOOL_NAME_MAX_LEN + 1], JsonReadSpan_t* args_out)
{
  assert(request  != NULL);
  assert(name_out != NULL);
  assert(args_out != NULL);

  if (!request->m_hasParams)
    return MCP_TOOL_CALL_NO_PARAMS;

  JsonReadSpan_t name_span;
  if (jsonread_objectKey(request->m_params, "name", &name_span) != JSONREAD_OK)
    return MCP_TOOL_CALL_NO_NAME;
  if (jsonread_spanToStrStatus(name_span, name_out, MCP_TOOL_NAME_MAX_LEN + 1) != JSONREAD_OK)
    return MCP_TOOL_CALL_BAD_NAME;

  if (jsonread_objectKey(request->m_params, "arguments", args_out) != JSONREAD_OK)
  {
    args_out->mp_start = "{}";
    args_out->m_len    = 2;
  }
  return MCP_TOOL_CALL_OK;
}

void mcp_readPaymentMeta(const char* body, McpPaymentMeta_t* meta_out)
{
  assert(body     != NULL);
  assert(meta_out != NULL);

  meta_out->m_status        = MCP_PAYMENT_META_NONE;
  meta_out->m_span.mp_start = NULL;
  meta_out->m_span.m_len    = 0;

  JsonRpcRequest_t request;
  if (jsonrpc_parse(body, strlen(body), &request) != JSONRPC_OK)
    return;
  if (!request.m_hasId || !request.m_hasParams || strcmp(request.ma_rpcMethod, "tools/call") != 0)
    return;

  JsonReadSpan_t meta_span;
  if (jsonread_objectKey(request.m_params, "_meta", &meta_span) != JSONREAD_OK || !jsonread_isObject(meta_span))
    return;

  JsonReadMember_t members[] = { { .mp_key = MCP_META_KEY_X402_PAYMENT } };
  if (!jsonread_tryFindMembers(meta_span, members, sizeof(members) / sizeof(members[0])))
    meta_out->m_status = MCP_PAYMENT_META_REPEATED;
  else if (members[0].m_isFound)
  {
    meta_out->m_status = MCP_PAYMENT_META_FOUND;
    meta_out->m_span   = members[0].m_valueSpan;
  }
}

void mcp_creditCost(const char* body, EndpointPrice_t* price_out)
{
  assert(price_out != NULL);
  price_out->m_creditCost             = 1;
  price_out->m_isPartialChargeAllowed = false;
  price_out->m_willCallUpstream       = false;
  price_out->m_isPaymentOfferable     = false;
  price_out->mp_pricedEndpoint        = NULL;
  price_out->mp_weighedEndpoint       = NULL;

  JsonRpcRequest_t request;
  if (jsonrpc_parse(body, strlen(body), &request) != JSONRPC_OK)
    return;
  if (!request.m_hasId)
  {
    if (strncmp(request.ma_rpcMethod, MCP_NOTIFICATION_PREFIX, strlen(MCP_NOTIFICATION_PREFIX)) == 0)
      price_out->m_creditCost = 0;
    return;
  }

  if (strcmp(request.ma_rpcMethod, "tools/list") == 0)
    return;
  else if ( strcmp(request.ma_rpcMethod, "initialize") == 0       ||
            strcmp(request.ma_rpcMethod, "server/discover") == 0  ||
            strcmp(request.ma_rpcMethod, "ping") == 0)
  {
    price_out->m_creditCost = 0;
    return;
  }
  else if (strcmp(request.ma_rpcMethod, "tools/call") != 0)
    return;

  char           tool_name[MCP_TOOL_NAME_MAX_LEN + 1];
  JsonReadSpan_t args_span;
  if (mcp_readToolCall(&request, tool_name, &args_span) != MCP_TOOL_CALL_OK)
    return;
  const Endpoint_t* endpoint = endpoint_findByMcpName(tool_name);
  if (endpoint == NULL)
    return;

  EndpointAnyParams_t* params         = &price_out->m_weighedParams;
  price_out->mp_pricedEndpoint        = endpoint;
  price_out->m_isPartialChargeAllowed = endpoint_isPartialChargeAllowed(endpoint);
  EndpointGateResult_t gate_result    = endpoint_mcpArgsGate(endpoint, args_span, params, endpoint->m_paramsSize);
  price_out->m_willCallUpstream       = endpoint_willCallUpstream(endpoint, gate_result.m_status, params);
  price_out->m_isPaymentOfferable     = endpoint->m_isPayable && gate_result.m_status == ENDPOINT_GATE_OK;

  if (gate_result.m_status == ENDPOINT_GATE_OK && endpoint->m_weighFunction != NULL)
    price_out->mp_weighedEndpoint = endpoint;

  price_out->m_creditCost = endpoint_price(endpoint, gate_result.m_status, params, endpoint->m_paramsSize);
}

static char* static_handleMCPToolsCall(const JsonRpcRequest_t* req, PGconn* conn, const RequestCharge_t* charge, bool is_modern, int* protocol_code_out, McpRunReport_t* run_report)
{
  if (protocol_code_out) *protocol_code_out = 0;

  char                tool_name[MCP_TOOL_NAME_MAX_LEN + 1];
  JsonReadSpan_t      args_span;
  McpToolCallStatus_t call_status = mcp_readToolCall(req, tool_name, &args_span);
  if (call_status == MCP_TOOL_CALL_NO_PARAMS)
  {
    if (protocol_code_out) *protocol_code_out = JSONRPC_ERR_PARAMS;
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "missing params");
  }
  else if (call_status == MCP_TOOL_CALL_NO_NAME)
  {
    if (protocol_code_out) *protocol_code_out = JSONRPC_ERR_PARAMS;
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "missing tool name");
  }
  else if (call_status == MCP_TOOL_CALL_BAD_NAME)
  {
    char message[MCP_MESSAGE_BUF_SIZE];
    snprintf(message, sizeof(message),
             MCP_INVALID_PARAMS_PREFIX "tool name must be a JSON string of at most %d characters", MCP_TOOL_NAME_MAX_LEN);

    if (protocol_code_out)
      *protocol_code_out = JSONRPC_ERR_PARAMS;

    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS, message);
  }

  const Endpoint_t* endpoint = endpoint_findByMcpName(tool_name);
  if (endpoint == NULL || endpoint->m_runFunction == NULL)
  {
    usagelog_setUnknownName(tool_name, strlen(tool_name));
    if (protocol_code_out) *protocol_code_out = JSONRPC_ERR_PARAMS;
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS, "Unknown tool");
  }
  usagelog_setEndpointName(endpoint);
  if (run_report)
    run_report->mp_endpoint = endpoint;

  if (args_span.m_len == 0 || args_span.mp_start[0] != '{')
  {
    if (protocol_code_out) *protocol_code_out = JSONRPC_ERR_PARAMS;
    return static_buildRpcErrorEnvelope(req->ma_id, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "arguments must be a JSON object");
  }

  McpToolResult_t mcp_tool_result;
  memset(&mcp_tool_result, 0, sizeof(mcp_tool_result));
  static_runTool(endpoint, args_span, &mcp_tool_result, conn, charge, run_report);

  if (protocol_code_out && mcp_tool_result.m_kind == MCP_TOOL_KIND_PROTOCOL_ERROR)
    *protocol_code_out = mcp_tool_result.m_protocolErrorCode;

  size_t meta_offset = 0;
  char*  response    = static_encodeToolResult(req->ma_id, &mcp_tool_result, is_modern, &meta_offset);
  if (run_report)
    run_report->m_resultMetaOffset = meta_offset;
  
  free(mcp_tool_result.mp_json);
  return response;
}

static char* static_encodeToolResult(const char* id_raw, const McpToolResult_t* result, bool is_modern, size_t* meta_offset_out)
{
  *meta_offset_out = 0;
  if (result->m_kind == MCP_TOOL_KIND_PROTOCOL_ERROR)
    return static_buildRpcErrorEnvelope(id_raw, result->m_protocolErrorCode, result->ma_message);

  bool is_error = (result->m_kind != MCP_TOOL_KIND_JSON);
  const char* text = (result->m_kind == MCP_TOOL_KIND_TOOL_ERROR) ? result->ma_message : result->mp_json;

  char* response = static_buildToolContent(id_raw, text, is_error, is_modern, meta_offset_out);
  if (response)
    return response;

  return static_buildRpcErrorEnvelope(id_raw, JSONRPC_ERR_INTERNAL, MCP_ENVELOPE_FAILED_MESSAGE);
}

static char* static_buildInitializeResult(const JsonRpcRequest_t* req)
{
  JsonBuf_t* result_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (!result_buf)
    return NULL;

  jsonbuf_appendFormat(result_buf,
    "{\"protocolVersion\":\"%s\",\"capabilities\":{\"tools\":{}},"
    MCP_SERVER_INFO_JSON ","
    "\"instructions\":\"" MCP_SERVER_INSTRUCTIONS "\"}",
    static_negotiateVersion(req));
  char* result_json = jsonbuf_finish(result_buf);
  jsonbuf_destroy(result_buf);
  if (!result_json)
    return NULL;

  char* response = static_buildRpcResultEnvelope(req->ma_id, result_json);
  free(result_json);
  return response;
}

static const char* static_negotiateVersion(const JsonRpcRequest_t* req)
{
  JsonReadSpan_t version_span;
  char requested_version[MCP_REQUESTED_VERSION_BUF_SIZE];
  if (req->m_hasParams                                                                                      &&
      jsonread_objectKey(req->m_params, "protocolVersion", &version_span) == JSONREAD_OK                    &&
      jsonread_spanToStrStatus(version_span, requested_version, sizeof(requested_version)) == JSONREAD_OK)
  {
    for (size_t i = 0; i < MCP_SUPPORTED_COUNT; i++)
      if (strcmp(requested_version, MCP_SUPPORTED_VERSIONS[i]) == 0)
        return MCP_SUPPORTED_VERSIONS[i];
  }
  return MCP_PROTOCOL_VERSION;
}

static char* static_buildRpcResultEnvelope(const char* id_raw, const char* result_json)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonrpc_serializeResult(id_raw, result_json, json_buf);
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

static void static_setUsageLogMethodName(const char* rpc_method)
{
  for (size_t i = 0; i < sizeof(MCP_USAGE_LOG_METHOD_NAMES) / sizeof(MCP_USAGE_LOG_METHOD_NAMES[0]); i++)
  {
    if (strcmp(rpc_method, MCP_USAGE_LOG_METHOD_NAMES[i]) == 0)
    {
      usagelog_setMcpMethodName(MCP_USAGE_LOG_METHOD_NAMES[i]);
      return;
    }
  }
  usagelog_setUnknownName(rpc_method, strlen(rpc_method));
}

static bool static_isMcpArg(const EndpointParam_t* param)
{
  return (param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG) != 0;
}

static void static_appendMcpArgSchema(const EndpointParam_t* param, JsonBuf_t* json_buf)
{
  const EndpointParamSpec_t* spec = param->mp_spec;
  assert(spec->m_type != ENDPOINT_PARAM_TYPE_ENUM || spec->mp_enumValues != NULL);

  jsonbuf_appendFormat(json_buf, "\"");
  jsonbuf_appendEscaped(json_buf, spec->mp_name);
  jsonbuf_appendFormat(json_buf, "\":{\"type\":\"%s\"", endpoint_jsonSchemaTypeName(spec->m_type));

  if (spec->m_type == ENDPOINT_PARAM_TYPE_ENUM)
  {
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
    jsonbuf_appendFormat(json_buf, ",\"items\":%s", ENDPOINT_PACKAGE_ITEM_OPTIONAL_VERSION_SCHEMA_JSON);
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
    jsonbuf_appendFormat(json_buf, ",\"items\":%s", ENDPOINT_PACKAGE_ITEM_SCHEMA_JSON);

  if (spec->m_isOnlyTrueAccepted)
    jsonbuf_appendFormat(json_buf, ",\"const\":true");

  endpoint_appendSchemaBounds(spec, json_buf);

  if (param->mp_mcpArgDescription != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"description\":\"");
    jsonbuf_appendEscaped(json_buf, param->mp_mcpArgDescription);
    jsonbuf_appendFormat(json_buf, "\"");
  }

  jsonbuf_appendFormat(json_buf, "}");
}

static void static_appendMcpArgProperties(const Endpoint_t* endpoint, JsonBuf_t* json_buf)
{
  jsonbuf_appendFormat(json_buf, "\"properties\":{");

  bool is_first = true;
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!static_isMcpArg(param))
      continue;
    if (!is_first)
      jsonbuf_appendFormat(json_buf, ",");
    static_appendMcpArgSchema(param, json_buf);
    is_first = false;
  }

  jsonbuf_appendFormat(json_buf, "}");
}

static void static_appendMcpRequiredList(const Endpoint_t* endpoint, JsonBuf_t* json_buf)
{
  bool is_first = true;
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!static_isMcpArg(param) || !param->m_isRequired)
      continue;
    jsonbuf_appendFormat(json_buf, "%s\"", is_first ? ",\"required\":[" : ",");
    jsonbuf_appendEscaped(json_buf, param->mp_spec->mp_name);
    jsonbuf_appendFormat(json_buf, "\"");
    is_first = false;
  }

  if (!is_first)
    jsonbuf_appendFormat(json_buf, "]");
}

static void static_appendMcpToolAnnotations(const Endpoint_t* endpoint, JsonBuf_t* json_buf)
{
  const char* open_world = (endpoint->m_callsUpstream || endpoint->m_callsUpstreamFunction != NULL) ? "true" : "false";

  switch (endpoint->m_mcpToolEffect)
  {
    case ENDPOINT_MCP_TOOL_EFFECT_NONE:
      break;
    case ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY:
      jsonbuf_appendFormat(json_buf, ",\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":%s}", open_world);
      break;
    case ENDPOINT_MCP_TOOL_EFFECT_MOVES_POSITION:
      jsonbuf_appendFormat(json_buf, ",\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":false,\"idempotentHint\":false,\"openWorldHint\":%s}", open_world);
      break;
    case ENDPOINT_MCP_TOOL_EFFECT_EDITS:
      jsonbuf_appendFormat(json_buf, ",\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":true,\"idempotentHint\":true,\"openWorldHint\":%s}", open_world);
      break;
  }
}

static void static_appendMcpToolMeta(const Endpoint_t* endpoint, JsonBuf_t* json_buf)
{
  const char* category_name = endpoint_mcpToolCategoryName(endpoint->m_mcpToolCategory);
  if (category_name == NULL)
    return;

  jsonbuf_appendFormat(json_buf, ",\"_meta\":{\"" MCP_META_KEY_TOOL_CATEGORY "\":\"");
  jsonbuf_appendEscaped(json_buf, category_name);
  jsonbuf_appendFormat(json_buf, "\"}");
}

static void static_appendMcpTool(const Endpoint_t* endpoint, JsonBuf_t* json_buf)
{
  assert(endpoint->mp_mcpToolName != NULL);

  jsonbuf_appendFormat(json_buf, "{\"name\":\"");
  jsonbuf_appendEscaped(json_buf, endpoint->mp_mcpToolName);
  jsonbuf_appendFormat(json_buf, "\"");
  if (endpoint->mp_mcpToolTitle != NULL)
  {
    jsonbuf_appendFormat(json_buf, ",\"title\":\"");
    jsonbuf_appendEscaped(json_buf, endpoint->mp_mcpToolTitle);
    jsonbuf_appendFormat(json_buf, "\"");
  }
  jsonbuf_appendFormat(json_buf, ",\"description\":\"");
  jsonbuf_appendEscaped(json_buf, endpoint->mp_mcpToolDescription);
  jsonbuf_appendFormat(json_buf, "\",\"inputSchema\":{\"type\":\"object\",");

  static_appendMcpArgProperties(endpoint, json_buf);
  static_appendMcpRequiredList(endpoint, json_buf);
  jsonbuf_appendFormat(json_buf, ",\"additionalProperties\":false}");
  static_appendMcpToolAnnotations(endpoint, json_buf);
  static_appendMcpToolMeta(endpoint, json_buf);
  jsonbuf_appendFormat(json_buf, "}");
}

static char* static_buildToolsListResponse(const char* id_raw, bool is_modern)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (!json_buf)
    return NULL;

  jsonbuf_appendFormat(json_buf, "{\"tools\":[");
  bool is_first = true;
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].mp_mcpToolName == NULL)
      continue;
    if (!is_first)
      jsonbuf_appendFormat(json_buf, ",");
    static_appendMcpTool(&endpoints[i], json_buf);
    is_first = false;
  }
  jsonbuf_appendFormat(json_buf, "]}");

  char* result_json = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  if (!result_json)
    return NULL;

  char* response = is_modern ? static_buildModernResult(id_raw, result_json) : static_buildRpcResultEnvelope(id_raw, result_json);
  free(result_json);
  return response;
}

static char* static_buildRpcErrorEnvelope(const char* id_raw, int code, const char* message)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonrpc_serializeError(id_raw, code, message, NULL, json_buf);
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

static char* static_buildUnsupportedVersionEnvelope(const char* id_raw, const char* envelope_version)
{
  JsonBuf_t* data_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (!data_buf)
    return NULL;

  jsonbuf_appendFormat(data_buf, "{\"supported\":[\"" MCP_MODERN_PROTOCOL_VERSION "\"],\"requested\":\"");
  jsonbuf_appendEscaped(data_buf, envelope_version);
  jsonbuf_appendFormat(data_buf, "\"}");
  char* data_json = jsonbuf_finish(data_buf);
  jsonbuf_destroy(data_buf);
  if (!data_json)
    return NULL;

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
  {
    free(data_json);
    return NULL;
  }

  jsonrpc_serializeError(id_raw, JSONRPC_ERR_UNSUPPORTED_VERSION, "Unsupported protocol version", data_json, json_buf);
  free(data_json);
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

static char* static_buildToolContent(const char* id_raw, const char* text, bool is_error, bool is_modern, size_t* meta_offset_out)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonbuf_appendFormat(json_buf, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{", id_raw);
  size_t meta_offset = jsonbuf_length(json_buf);
  jsonbuf_appendFormat(json_buf, "\"content\":[{\"type\":\"text\",\"text\":\"");
  jsonbuf_appendEscaped(json_buf, text);
  jsonbuf_appendFormat(json_buf, "\"}],\"isError\":%s%s}}", is_error ? "true" : "false", is_modern ? ",\"resultType\":\"complete\"" : "");
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  if (response && meta_offset_out)
    *meta_offset_out = meta_offset;
  return response;
}

char* mcp_buildToolErrorResult(const char* id_raw, const char* text, bool is_modern)
{
  assert(id_raw != NULL);
  assert(text   != NULL);
  return static_buildToolContent(id_raw, text, true, is_modern, NULL);
}

char* mcp_buildPaymentRequiredResult(const char* id_raw, const char* payment_required_json, bool is_modern)
{
  assert(id_raw                != NULL);
  assert(payment_required_json != NULL);

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonbuf_appendFormat(json_buf, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"", id_raw);
  jsonbuf_appendEscaped(json_buf, payment_required_json);
  jsonbuf_appendFormat(json_buf, "\"}],\"structuredContent\":");
  jsonbuf_appendJsonText(json_buf, payment_required_json);
  jsonbuf_appendFormat(json_buf, ",\"isError\":true%s}}", is_modern ? ",\"resultType\":\"complete\"" : "");
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

char* mcp_buildResultWithMeta(const char* response_json, size_t meta_offset, const char* meta_key, const char* meta_value_json)
{
  assert(response_json   != NULL);
  assert(meta_key        != NULL);
  assert(meta_value_json != NULL);
  assert(meta_offset > 0 && meta_offset <= strlen(response_json));
  assert(response_json[meta_offset - 1] == '{');
  assert(meta_offset <= INT_MAX);

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, MCP_ENVELOPE_JSONBUF_CEILING);
  if (!json_buf)
    return NULL;

  jsonbuf_appendFormat(json_buf, "%.*s\"_meta\":{\"%s\":", (int)meta_offset, response_json, meta_key);
  jsonbuf_appendJsonText(json_buf, meta_value_json);
  jsonbuf_appendFormat(json_buf, "},");
  jsonbuf_appendJsonText(json_buf, response_json + meta_offset);
  char* response = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response;
}

static void static_runTool(const Endpoint_t* endpoint, JsonReadSpan_t args_span, McpToolResult_t* result_out, PGconn* conn, const RequestCharge_t* charge, McpRunReport_t* run_report)
{
  assert(endpoint->m_runFunction != NULL);

  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  if (!static_areArgsAccepted(endpoint, args_span, &params, endpoint->m_paramsSize, result_out))
  {
    usagelog_setGateRefused();
    return;
  }

  EndpointRunResult_t run_result = endpoint_runRow(endpoint, &params, conn, charge);
  usagelog_setRunStatus(run_result.m_status);
  if (run_report)
  {
    run_report->m_isRun     = true;
    run_report->m_runStatus = run_result.m_status;
  }
  switch (run_result.m_status)
  {
    case ENDPOINT_RUN_OK:
      static_setResultJson(result_out, run_result.mp_body);
      run_result.mp_body = NULL;
      break;
    case ENDPOINT_RUN_NOT_FOUND:
      static_setToolError(result_out, "%s", endpoint->mp_notFoundMessage);
      break;
    case ENDPOINT_RUN_REFUSED:
      static_setToolError(result_out, "%s", run_result.mp_message);
      break;
    case ENDPOINT_RUN_REFUSED_WITH_BODY:
      static_setResultJson(result_out, run_result.mp_body);
      result_out->m_kind = MCP_TOOL_KIND_JSON_TOOL_ERROR;
      run_result.mp_body = NULL;
      break;
    case ENDPOINT_RUN_NO_CONNECTION:
    case ENDPOINT_RUN_DEGRADED:
      static_setProtocolError(result_out, JSONRPC_ERR_INTERNAL, "Internal error: database unavailable");
      break;
    case ENDPOINT_RUN_DB_ERROR:
      static_setProtocolError(result_out, JSONRPC_ERR_INTERNAL, "Internal error: database query failed");
      break;
    case ENDPOINT_RUN_UPSTREAM_ERROR:
      static_setProtocolError(result_out, JSONRPC_ERR_INTERNAL, "Internal error: upstream unavailable");
      break;
    case ENDPOINT_RUN_TARGET_UNREACHABLE:
      static_setToolError(result_out, "%s", run_result.mp_message);
      break;
    case ENDPOINT_RUN_NO_CREDIT_BUDGET:
    case ENDPOINT_RUN_NO_MEMORY:
    case ENDPOINT_RUN_UNAUTHORIZED:
    case ENDPOINT_RUN_GONE:
      static_setProtocolError(result_out, JSONRPC_ERR_INTERNAL, "Internal error");
      break;
  }
  free(run_result.mp_body);
}

static void static_setResultJson(McpToolResult_t* result_out, char* json)
{
  assert(json != NULL);

  result_out->m_kind   = MCP_TOOL_KIND_JSON;
  result_out->mp_json  = json;
}

static void static_setToolError(McpToolResult_t* result_out, const char* fmt, ...)
{
  result_out->m_kind = MCP_TOOL_KIND_TOOL_ERROR;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(result_out->ma_message, sizeof(result_out->ma_message), fmt, ap);
  va_end(ap);
}

static void static_setProtocolError(McpToolResult_t* result_out, int code, const char* fmt, ...)
{
  result_out->m_kind              = MCP_TOOL_KIND_PROTOCOL_ERROR;
  result_out->m_protocolErrorCode = code;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(result_out->ma_message, sizeof(result_out->ma_message), fmt, ap);
  va_end(ap);
}

static bool static_areArgsAccepted(const Endpoint_t* endpoint, JsonReadSpan_t args_span, void* params_out, size_t params_size, McpToolResult_t* result_out)
{
  assert(endpoint   != NULL);
  assert(result_out != NULL);

  EndpointGateResult_t gate_result = endpoint_mcpArgsGate(endpoint, args_span, params_out, params_size);
  if (gate_result.m_status == ENDPOINT_GATE_OK)
    return true;

  if (gate_result.m_status == ENDPOINT_GATE_REJECT_BODY_TOO_LARGE)
  {
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "arguments too large");
    return false;
  }
  else if (gate_result.m_status == ENDPOINT_GATE_REJECT_BODY)
  {
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "arguments must be a JSON object");
    return false;
  }
  else if (gate_result.m_status == ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME)
  {
    static_setUnknownArgError(endpoint, result_out);
    return false;
  }

  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  if (endpoint_writeGateRefusalMessage(endpoint, gate_result, message, sizeof(message)) == ENDPOINT_REFUSAL_MESSAGE_FALLBACK)
  {
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "%s", message);
    return false;
  }
  const EndpointParam_t* param = &endpoint->mp_params[gate_result.m_refusedParamIndex];
  bool is_wrong_type_shape = gate_result.m_status == ENDPOINT_GATE_REJECT_TYPE && param->m_isRequired;
  if (gate_result.m_status == ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME   ||
      gate_result.m_status == ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE  ||
      gate_result.m_status == ENDPOINT_GATE_REJECT_MISSING                ||
      is_wrong_type_shape)
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "%s", message);
  else
    static_setToolError(result_out, "%s", message);
  return false;
}

static void static_setUnknownArgError(const Endpoint_t* endpoint, McpToolResult_t* result_out)
{
  static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "unknown argument; this tool takes");

  EndpointParamNameListStatus_t list_status = endpoint_appendParamNameListToRefusalMessage(endpoint, ENDPOINT_PARAM_SRC_MCP_ARG, result_out->ma_message, sizeof(result_out->ma_message));
  if (list_status == ENDPOINT_PARAM_NAME_LIST_EMPTY)
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "this tool takes no arguments");
  else if (list_status == ENDPOINT_PARAM_NAME_LIST_TOO_LONG)
    static_setProtocolError(result_out, JSONRPC_ERR_PARAMS, MCP_INVALID_PARAMS_PREFIX "unknown argument");
}
