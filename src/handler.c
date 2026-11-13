#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "handler.h"
#include "response.h"
#include "serialize.h"
#include "jsonbuf.h"
#include "mcp.h"
#include "endpoint.h"
#include "usagelog.h"
#include "x402_request.h"

#define HANDLER_ALLOWED_METHODS_BUF_SIZE  48
#define HANDLER_RETRY_AFTER_DATA_BUF_SIZE 48

#define HANDLER_UNAUTHORIZED_MESSAGE      "Invalid API key"
#define HANDLER_API_KEY_INACTIVE_MESSAGE  "API key expired or revoked"
#define HANDLER_RATE_LIMITED_MESSAGE      "rate limit exceeded"
#define HANDLER_UPSTREAM_BUSY_MESSAGE     "upstream service busy"
#define HANDLER_INTERNAL_ERROR_MESSAGE    "internal server error"

#define HANDLER_UPSTREAM_UNAVAILABLE_MESSAGE "upstream service unavailable"

#define HANDLER_PAYMENT_REQUIRED_MESSAGE      "Payment required: pay with x402 or retry after the reset."
#define HANDLER_PAYMENT_REFUSED_MESSAGE       "The payment was refused."
#define HANDLER_PAYMENT_ALREADY_USED_MESSAGE  "This payment was already used."
#define HANDLER_PAYMENT_PENDING_MESSAGE       "The payment is pending: retry with the same payment."
#define HANDLER_PAYMENT_INVALID_MESSAGE       "The payment header is not valid."
#define HANDLER_PAYMENT_NOT_OFFERED_MESSAGE   "This endpoint does not accept payment."
#define HANDLER_PAYMENT_BUSY_MESSAGE          "This payment or another one from its wallet is in flight: retry shortly."
#define HANDLER_PAYMENT_LIMITED_MESSAGE       "Too many payment attempts: retry later."
#define HANDLER_PAYMENT_UNAVAILABLE_MESSAGE   "Payments are unavailable right now: retry shortly."

#define HANDLER_MCP_PAYMENT_INVALID_MESSAGE     "The payment in params._meta is not valid."
#define HANDLER_MCP_PAYMENT_NOT_OFFERED_MESSAGE "This tool does not accept payment."

#define HANDLER_MCP_RESOURCE_URL_PREFIX   "mcp://tool/"
#define HANDLER_MCP_RESOURCE_URL_BUF_SIZE 48

#define HANDLER_RETRY_AFTER_LINE_BUF_SIZE 32
_Static_assert(HANDLER_RETRY_AFTER_LINE_BUF_SIZE >= sizeof("Retry-After: 4294967295\r\n"),
               "HANDLER_RETRY_AFTER_LINE_BUF_SIZE must fit the longest Retry-After line");

#define HANDLER_HEALTH_RETRY_AFTER_SEC     5

#define HANDLER_UPSTREAM_BUSY_RETRY_AFTER_SEC  5

#define HANDLER_RAW_BODY_BUSY_MESSAGE         "too many raw request bodies at once"
#define HANDLER_RAW_BODY_BUSY_RETRY_AFTER_SEC 10

static const char INTERNAL_ERROR_BODY[] =
  R"({"error":{"code":"internal_error","message":")" HANDLER_INTERNAL_ERROR_MESSAGE R"("}})" "\n";

static const char MCP_INTERNAL_ERROR_BODY[] =
  R"({"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":")" HANDLER_INTERNAL_ERROR_MESSAGE R"("}})";

static void   static_sendNotFound                 (int client_fd, const Endpoint_t* endpoint);
static char*  static_errorBody                    (const char* err_code, const char* message);
static void   static_sendError                    (int client_fd, int status_code, const char* status_text, const char* err_code, const char* message);

static char*  static_mcpErrorEnvelope            (const char* body, int rpc_code, const char* message, const char* data_json);
static char*  static_mcpRetryAfterErrorEnvelope  (const char* body, int rpc_code, const char* message, unsigned int retry_after_sec);
static void   static_sendMcpError                 (int client_fd, int status_code, const char* status_text, const char* body, int rpc_code, const char* message);

static void   static_sendRestGateRefusal          (int client_fd, const Endpoint_t* endpoint, EndpointGateResult_t gate_result);
static void   static_sendRunAnswer                (int client_fd, const Endpoint_t* endpoint, EndpointRunResult_t run_result);
static void   static_sendPaidAnswer               (int client_fd, const Endpoint_t* endpoint, PGconn* conn, const RequestCharge_t* charge, const char* body);
static void   static_sendPaymentOffer             (int client_fd, const Endpoint_t* endpoint, unsigned int credit_count, const char* err_code, const char* message, bool has_retry_after, unsigned int retry_after_sec);
static void   static_sendRetryAfterError          (int client_fd, int status_code, const char* status_text, const char* err_code, const char* message, unsigned int retry_after_sec);
static const char* static_mcpIdOfBody             (const char* body, JsonRpcRequest_t* request_out);
static const char* static_mcpReasonPhrase         (int status_code);
static void   static_sendMcpRetryAfterError       (int client_fd, int status_code, const char* status_text, const char* body, int rpc_code, const char* message, unsigned int retry_after_sec);
static void   static_sendMcpPaymentRequiredResult (int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, const char* error_text, unsigned int retry_after_sec, bool is_modern);
static void   static_sendPaidMcpAnswer            (int client_fd, const char* body, PGconn* conn, const RequestCharge_t* charge, const McpRunReport_t* run_report, const char* response_json, bool is_modern);


void handler_MCP(int client_fd, const char* body, const McpRoutingHeaders_t* routing_headers, PGconn* conn, const RequestCharge_t* charge)
{
  assert(client_fd >= 0);

  const char* request_body = body ? body : "";
  char*       response_json = NULL;
  int         status_code   = 200;
  bool        is_modern     = mcp_isModernEra(routing_headers);
  McpRunReport_t run_report;

  if (!mcp_dispatch(request_body, strlen(request_body), routing_headers, &response_json, &status_code, conn, charge, &run_report))
  {
    if (charge->mp_x402Payment != NULL)
      x402_request_dbReleaseUnserved(conn, charge->mp_x402Payment, X402_REQUEST_UNSERVED_FAILED_RUN);

    handler_mcpInternalError(client_fd, request_body);
    return;
  }

  if (charge->mp_x402Payment != NULL 
      && run_report.m_isRun 
      && run_report.m_runStatus == ENDPOINT_RUN_OK 
      && run_report.m_resultMetaOffset > 0)
  {
    static_sendPaidMcpAnswer(client_fd, request_body, conn, charge, &run_report, response_json, is_modern);
    free(response_json);
    return;
  }
  if (charge->mp_x402Payment != NULL)
  {
    x402_request_dbReleaseUnserved( conn, 
                                    charge->mp_x402Payment,
                                    run_report.m_isRun  ? x402_request_findUnservedKind(run_report.m_runStatus) 
                                                        : X402_REQUEST_UNSERVED_REFUSED_REQUEST);
  }

  if (status_code == 202)
    response_send(client_fd, 202, "Accepted", "");
  else
    response_send(client_fd, status_code, static_mcpReasonPhrase(status_code), response_json ? response_json : "{}");

  free(response_json);
}

void handler_runRestEndpoint(int client_fd, const Endpoint_t* endpoint, const EndpointRestInput_t* input, PGconn* conn, const RequestCharge_t* charge)
{
  assert(client_fd >= 0);
  assert(endpoint->m_runFunction != NULL);
  assert(input != NULL);
  assert(endpoint->m_hasPathSegment || input->mp_pathSegment == NULL);

  EndpointAnyParams_t params;
  memset(&params, 0, sizeof(params));
  EndpointGateResult_t gate_result = endpoint_restRequestGate(endpoint, input, &params, endpoint->m_paramsSize);
  if (gate_result.m_status != ENDPOINT_GATE_OK)
  {
    if (charge->mp_x402Payment != NULL)
      x402_request_dbReleaseUnserved(conn, charge->mp_x402Payment, X402_REQUEST_UNSERVED_REFUSED_REQUEST);

    usagelog_setGateRefused();
    static_sendRestGateRefusal(client_fd, endpoint, gate_result);
    return;
  }

  EndpointRunResult_t run_result = endpoint_runRow(endpoint, &params, conn, charge);
  usagelog_setRunStatus(run_result.m_status);

  if (charge->mp_x402Payment == NULL)
    static_sendRunAnswer(client_fd, endpoint, run_result);
  else if (run_result.m_status == ENDPOINT_RUN_OK)
    static_sendPaidAnswer(client_fd, endpoint, conn, charge, run_result.mp_body);
  else
  {
    x402_request_dbReleaseUnserved(conn, charge->mp_x402Payment, x402_request_findUnservedKind(run_result.m_status));
    static_sendRunAnswer(client_fd, endpoint, run_result);
  }
  if (run_result.mp_body != NULL)
    explicit_bzero(run_result.mp_body, strlen(run_result.mp_body));
  free(run_result.mp_body);
}

static void static_sendRunAnswer(int client_fd, const Endpoint_t* endpoint, EndpointRunResult_t run_result)
{
  switch (run_result.m_status)
  {
    case ENDPOINT_RUN_OK:
      response_send(client_fd, 200, "OK", run_result.mp_body);
      break;
    case ENDPOINT_RUN_DEGRADED:
      if (run_result.mp_body)
        response_sendServiceUnavailable503(client_fd, HANDLER_HEALTH_RETRY_AFTER_SEC, run_result.mp_body);
      else
        handler_internalError(client_fd);
      break;
    case ENDPOINT_RUN_NOT_FOUND:
      static_sendNotFound(client_fd, endpoint);
      break;
    case ENDPOINT_RUN_REFUSED:
      handler_badRequest(client_fd, run_result.mp_message);
      break;
    case ENDPOINT_RUN_REFUSED_WITH_BODY:
      response_send(client_fd, 400, "Bad Request", run_result.mp_body);
      break;
    case ENDPOINT_RUN_UPSTREAM_ERROR:
      static_sendError(client_fd, 502, "Bad Gateway", "upstream_unavailable", HANDLER_UPSTREAM_UNAVAILABLE_MESSAGE);
      break;
    case ENDPOINT_RUN_TARGET_UNREACHABLE:
      static_sendError(client_fd, 504, "Gateway Timeout", "target_unreachable", run_result.mp_message);
      break;
    case ENDPOINT_RUN_UNAUTHORIZED:
      static_sendError(client_fd, 401, "Unauthorized", "invalid_signature", run_result.mp_message);
      break;
    case ENDPOINT_RUN_GONE:
      static_sendError(client_fd, 410, "Gone", "gone", run_result.mp_message);
      break;
    case ENDPOINT_RUN_NO_CONNECTION:
    case ENDPOINT_RUN_NO_CREDIT_BUDGET:
    case ENDPOINT_RUN_DB_ERROR:
    case ENDPOINT_RUN_NO_MEMORY:
      handler_internalError(client_fd);
      break;
  }
}


void handler_badRequest(int client_fd, const char* message)
{
  static_sendError(client_fd, 400, "Bad Request", "bad_request", message);
}

void handler_httpQueryParamNameRefused(int client_fd, const Endpoint_t* endpoint, EndpointGateResult_t gate_result)
{
  assert(endpoint != NULL);

  if (gate_result.m_status == ENDPOINT_GATE_REJECT_MALFORMED_PARAM)
  {
    handler_badRequest(client_fd, "every query parameter must be name=value");
    return;
  }

  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  if (gate_result.m_status == ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME)
  {
    endpoint_writeGateRefusalMessage(endpoint, gate_result, message, sizeof(message));
    handler_badRequest(client_fd, message);
    return;
  }

  if (gate_result.m_status != ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME)
  {
    fprintf(stderr, "handler_httpQueryParamNameRefused: refusal %d is not a parameter name refusal\n", (int)gate_result.m_status);
    handler_badRequest(client_fd, "unknown query parameter");
    return;
  }
  int message_len = snprintf(message, sizeof(message), "unknown query parameter; this endpoint takes");
  EndpointParamNameListStatus_t list_status = endpoint_appendParamNameListToRefusalMessage(endpoint, ENDPOINT_PARAM_SRC_REST_QUERY, message, sizeof(message));
  if (list_status == ENDPOINT_PARAM_NAME_LIST_EMPTY)
    message_len = snprintf(message, sizeof(message), "this endpoint takes no query parameters");
  else if (list_status == ENDPOINT_PARAM_NAME_LIST_TOO_LONG)
    message_len = snprintf(message, sizeof(message), "unknown query parameter");
  assert(message_len > 0 && (size_t)message_len < sizeof(message));

  (void)message_len;
  handler_badRequest(client_fd, message);
}

void handler_uriTooLong(int client_fd)
{
  static_sendError(client_fd, 414, "URI Too Long", "uri_too_long", "request target too long");
}

void handler_contentTooLarge(int client_fd)
{
  static_sendError(client_fd, 413, "Content Too Large", "content_too_large", "request body too large");
}

void handler_headerFieldsTooLarge(int client_fd)
{
  static_sendError(client_fd, 431, "Request Header Fields Too Large", "request_header_fields_too_large", "request header fields too large");
}

void handler_transferEncodingNotImplemented(int client_fd)
{
  static_sendError(client_fd, 501, "Not Implemented", "not_implemented", "Transfer-Encoding is not supported; send Content-Length");
}

void handler_unauthorized(int client_fd)
{
  static_sendError(client_fd, 401, "Unauthorized", "unauthorized", HANDLER_UNAUTHORIZED_MESSAGE);
}

void handler_apiKeyInactive(int client_fd)
{
  static_sendError(client_fd, 401, "Unauthorized", "api_key_inactive", HANDLER_API_KEY_INACTIVE_MESSAGE);
}

void handler_endpointNotFound(int client_fd)
{
  static_sendError(client_fd, 404, "Not Found", "not_found", "endpoint not found");
}

void handler_httpMethodNotAllowed(int client_fd, const char* const allowed_methods[])
{
  assert(allowed_methods && allowed_methods[0]);

  char allowed_http_methods_str[HANDLER_ALLOWED_METHODS_BUF_SIZE] = { 0 };
  size_t methods_str_len = 0;
  for (int i = 0; allowed_methods[i] && methods_str_len < sizeof(allowed_http_methods_str) - 1; i++)
  {
    int appended_len = snprintf(allowed_http_methods_str + methods_str_len, sizeof(allowed_http_methods_str) - methods_str_len, "%s%s", i > 0 ? ", " : "", allowed_methods[i]);

    if (appended_len > 0 && appended_len < (int)(sizeof(allowed_http_methods_str) - methods_str_len))
      methods_str_len += (size_t)appended_len;
    else
      break;
  }
  assert(methods_str_len > 0);

  char* response_body = static_errorBody("method_not_allowed", "method not allowed for this endpoint");
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }

  response_sendMethodNotAllowed405(client_fd, allowed_http_methods_str, response_body);
  free(response_body);
}

void handler_rateLimited(int client_fd, unsigned int retry_after_sec)
{
  char* response_body = static_errorBody("rate_limited", HANDLER_RATE_LIMITED_MESSAGE);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }

  response_sendTooManyRequests429(client_fd, retry_after_sec, response_body);
  free(response_body);
}

void handler_paymentRequired(int client_fd, const Endpoint_t* endpoint, unsigned int credit_count, unsigned int retry_after_sec)
{
  static_sendPaymentOffer(client_fd, endpoint, credit_count, "payment_required", HANDLER_PAYMENT_REQUIRED_MESSAGE, true, retry_after_sec);
}

void handler_paymentRefused(int client_fd, const Endpoint_t* endpoint, unsigned int credit_count)
{
  static_sendPaymentOffer(client_fd, endpoint, credit_count, "payment_refused", HANDLER_PAYMENT_REFUSED_MESSAGE, false, 0);
}

void handler_paymentAlreadyUsed(int client_fd, const Endpoint_t* endpoint, unsigned int credit_count)
{
  static_sendPaymentOffer(client_fd, endpoint, credit_count, "payment_already_used", HANDLER_PAYMENT_ALREADY_USED_MESSAGE, false, 0);
}

void handler_paymentPending(int client_fd, unsigned int retry_after_sec)
{
  static_sendRetryAfterError(client_fd, 402, "Payment Required", "payment_pending", HANDLER_PAYMENT_PENDING_MESSAGE, retry_after_sec);
}

void handler_paymentInvalid(int client_fd)
{
  static_sendError(client_fd, 400, "Bad Request", "payment_invalid", HANDLER_PAYMENT_INVALID_MESSAGE);
}

void handler_paymentNotOffered(int client_fd)
{
  static_sendError(client_fd, 400, "Bad Request", "payment_not_offered", HANDLER_PAYMENT_NOT_OFFERED_MESSAGE);
}

void handler_paymentBusy(int client_fd, unsigned int retry_after_sec)
{
  static_sendRetryAfterError(client_fd, 429, "Too Many Requests", "payment_busy", HANDLER_PAYMENT_BUSY_MESSAGE, retry_after_sec);
}

void handler_paymentLimited(int client_fd, unsigned int retry_after_sec)
{
  static_sendRetryAfterError(client_fd, 429, "Too Many Requests", "payment_limited", HANDLER_PAYMENT_LIMITED_MESSAGE, retry_after_sec);
}

void handler_paymentUnavailable(int client_fd, unsigned int retry_after_sec)
{
  static_sendRetryAfterError(client_fd, 503, "Service Unavailable", "payment_unavailable", HANDLER_PAYMENT_UNAVAILABLE_MESSAGE, retry_after_sec);
}

void handler_upstreamBusy(int client_fd)
{
  char* response_body = static_errorBody("upstream_busy", HANDLER_UPSTREAM_BUSY_MESSAGE);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }

  response_sendServiceUnavailable503(client_fd, HANDLER_UPSTREAM_BUSY_RETRY_AFTER_SEC, response_body);
  free(response_body);
}

void handler_rawBodyBusy(int client_fd)
{
  char* response_body = static_errorBody("raw_body_busy", HANDLER_RAW_BODY_BUSY_MESSAGE);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }

  response_sendServiceUnavailable503(client_fd, HANDLER_RAW_BODY_BUSY_RETRY_AFTER_SEC, response_body);
  free(response_body);
}

void handler_internalError(int client_fd)
{
  response_send(client_fd, 500, "Internal Server Error", INTERNAL_ERROR_BODY);
}

void handler_mcpUnauthorized(int client_fd, const char* body)
{
  static_sendMcpError(client_fd, 401, "Unauthorized", body, JSONRPC_ERR_UNAUTHORIZED, HANDLER_UNAUTHORIZED_MESSAGE);
}

void handler_mcpApiKeyInactive(int client_fd, const char* body)
{
  static_sendMcpError(client_fd, 401, "Unauthorized", body, JSONRPC_ERR_API_KEY_INACTIVE, HANDLER_API_KEY_INACTIVE_MESSAGE);
}

void handler_mcpRateLimited(int client_fd, const char* body, unsigned int retry_after_sec)
{
  char* envelope = static_mcpRetryAfterErrorEnvelope(body, JSONRPC_ERR_RATE_LIMITED, HANDLER_RATE_LIMITED_MESSAGE, retry_after_sec);
  if (!envelope)
  {
    response_send(client_fd, 500, "Internal Server Error", MCP_INTERNAL_ERROR_BODY);
    return;
  }

  response_sendTooManyRequests429(client_fd, retry_after_sec, envelope);
  free(envelope);
}

void handler_mcpUpstreamBusy(int client_fd, const char* body)
{
  char* envelope = static_mcpRetryAfterErrorEnvelope(body, JSONRPC_ERR_UPSTREAM_BUSY, HANDLER_UPSTREAM_BUSY_MESSAGE, HANDLER_UPSTREAM_BUSY_RETRY_AFTER_SEC);
  if (!envelope)
  {
    response_send(client_fd, 500, "Internal Server Error", MCP_INTERNAL_ERROR_BODY);
    return;
  }

  response_sendServiceUnavailable503(client_fd, HANDLER_UPSTREAM_BUSY_RETRY_AFTER_SEC, envelope);
  free(envelope);
}

void handler_mcpInternalError(int client_fd, const char* body)
{
  static_sendMcpError(client_fd, 500, "Internal Server Error", body, JSONRPC_ERR_INTERNAL, HANDLER_INTERNAL_ERROR_MESSAGE);
}

void handler_mcpPaymentRequired(int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, unsigned int retry_after_sec, bool is_modern)
{
  static_sendMcpPaymentRequiredResult(client_fd, body, tool_endpoint, credit_count, HANDLER_PAYMENT_REQUIRED_MESSAGE, retry_after_sec, is_modern);
}

void handler_mcpPaymentRefused(int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, bool is_modern)
{
  static_sendMcpPaymentRequiredResult(client_fd, body, tool_endpoint, credit_count, HANDLER_PAYMENT_REFUSED_MESSAGE, 0, is_modern);
}

void handler_mcpPaymentAlreadyUsed(int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, bool is_modern)
{
  static_sendMcpPaymentRequiredResult(client_fd, body, tool_endpoint, credit_count, HANDLER_PAYMENT_ALREADY_USED_MESSAGE, 0, is_modern);
}

void handler_mcpPaymentPending(int client_fd, const char* body, unsigned int retry_after_sec, bool is_modern)
{
  JsonRpcRequest_t request;
  char* result = mcp_buildToolErrorResult(static_mcpIdOfBody(body, &request), HANDLER_PAYMENT_PENDING_MESSAGE, is_modern);
  if (!result)
  {
    handler_mcpInternalError(client_fd, body);
    return;
  }
  response_sendWithRetryAfter(client_fd, 200, "OK", retry_after_sec, result);
  free(result);
}

void handler_mcpPaymentInvalid(int client_fd, const char* body, bool is_modern)
{
  int status_code = is_modern ? 400 : 200;
  static_sendMcpError(client_fd, status_code, static_mcpReasonPhrase(status_code), body, JSONRPC_ERR_PARAMS, HANDLER_MCP_PAYMENT_INVALID_MESSAGE);
}

void handler_mcpPaymentNotOffered(int client_fd, const char* body, bool is_modern)
{
  int status_code = is_modern ? 400 : 200;
  static_sendMcpError(client_fd, status_code, static_mcpReasonPhrase(status_code), body, JSONRPC_ERR_PARAMS, HANDLER_MCP_PAYMENT_NOT_OFFERED_MESSAGE);
}

void handler_mcpPaymentBusy(int client_fd, const char* body, unsigned int retry_after_sec)
{
  static_sendMcpRetryAfterError(client_fd, 429, "Too Many Requests", body, JSONRPC_ERR_RATE_LIMITED, HANDLER_PAYMENT_BUSY_MESSAGE, retry_after_sec);
}

void handler_mcpPaymentLimited(int client_fd, const char* body, unsigned int retry_after_sec)
{
  static_sendMcpRetryAfterError(client_fd, 429, "Too Many Requests", body, JSONRPC_ERR_RATE_LIMITED, HANDLER_PAYMENT_LIMITED_MESSAGE, retry_after_sec);
}

void handler_mcpPaymentUnavailable(int client_fd, const char* body, unsigned int retry_after_sec)
{
  static_sendMcpRetryAfterError(client_fd, 503, "Service Unavailable", body, JSONRPC_ERR_UPSTREAM_BUSY, HANDLER_PAYMENT_UNAVAILABLE_MESSAGE, retry_after_sec);
}

void handler_mcpLadderRefusal(int client_fd, char* json, int status_code)
{
  if (!json)
    response_send(client_fd, 500, "Internal Server Error", MCP_INTERNAL_ERROR_BODY);
  else
    response_send(client_fd, status_code, static_mcpReasonPhrase(status_code), json);
  free(json);
}

static void static_sendPaidAnswer(int client_fd, const Endpoint_t* endpoint, PGconn* conn, const RequestCharge_t* charge, const char* body)
{
  X402RequestReceipt_t receipt;
  char                 receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  switch (x402_request_dbCloseAfterRun(conn, charge->mp_x402Payment, &receipt))
  {
    case X402_REQUEST_CLOSE_SERVE:
      if (!x402_request_tryWriteReceiptLine(&receipt, receipt_line, sizeof(receipt_line)))
        fprintf(stderr, "handler_runRestEndpoint: the receipt line did not fit; the answer is served without it\n");
      response_sendWithExtraHeaders(client_fd, 200, "OK", receipt_line, body);
      usagelog_setCreditCount(charge->m_chargedCreditCount);
      break;
    case X402_REQUEST_CLOSE_REFUSED:
      handler_paymentRefused(client_fd, endpoint, charge->m_chargedCreditCount);
      break;
    case X402_REQUEST_CLOSE_PENDING:
      handler_paymentPending(client_fd, X402_REQUEST_PENDING_RETRY_AFTER_SEC);
      break;
  }
}

static void static_sendPaidMcpAnswer(int client_fd, const char* body, PGconn* conn, const RequestCharge_t* charge, const McpRunReport_t* run_report, const char* response_json, bool is_modern)
{
  X402RequestReceipt_t receipt;
  switch (x402_request_dbCloseAfterRun(conn, charge->mp_x402Payment, &receipt))
  {
    case X402_REQUEST_CLOSE_SERVE:
    {
      char*      answer   = NULL;
      JsonBuf_t* json_buf = jsonbuf_create(HANDLER_ERROR_JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
      if (json_buf && x402_request_appendReceipt(json_buf, &receipt))
      {
        char* receipt_json = jsonbuf_finish(json_buf);
        if (receipt_json)
          answer = mcp_buildResultWithMeta(response_json, run_report->m_resultMetaOffset, MCP_META_KEY_X402_PAYMENT_RESPONSE, receipt_json);
        
        free(receipt_json);
      }
      jsonbuf_destroy(json_buf);

      if (!answer)
        fprintf(stderr, "handler_MCP: the receipt did not fit; the answer is served without it\n");
      response_send(client_fd, 200, "OK", answer ? answer : response_json);
      free(answer);
      usagelog_setCreditCount(charge->m_chargedCreditCount);
      break;
    }
    case X402_REQUEST_CLOSE_REFUSED:
      handler_mcpPaymentRefused(client_fd, body, run_report->mp_endpoint, charge->m_chargedCreditCount, is_modern);
      break;
    case X402_REQUEST_CLOSE_PENDING:
      handler_mcpPaymentPending(client_fd, body, X402_REQUEST_PENDING_RETRY_AFTER_SEC, is_modern);
      break;
  }
}

static void static_sendMcpPaymentRequiredResult(int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, const char* error_text, unsigned int retry_after_sec, bool is_modern)
{
  assert(tool_endpoint != NULL);
  assert(tool_endpoint->mp_mcpToolName != NULL);

  _Static_assert(HANDLER_MCP_RESOURCE_URL_BUF_SIZE >= sizeof(HANDLER_MCP_RESOURCE_URL_PREFIX) + MCP_TOOL_NAME_MAX_LEN,
                 "HANDLER_MCP_RESOURCE_URL_BUF_SIZE must fit the resource URL of the longest tool name");
  char resource_url[HANDLER_MCP_RESOURCE_URL_BUF_SIZE];
  int  resource_url_len = snprintf(resource_url, sizeof(resource_url), HANDLER_MCP_RESOURCE_URL_PREFIX "%s", tool_endpoint->mp_mcpToolName);
  assert(resource_url_len > 0 && (size_t)resource_url_len < sizeof(resource_url));
  (void)resource_url_len;

  char*      payment_required_json = NULL;
  JsonBuf_t* json_buf              = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (json_buf && x402_request_appendPaymentRequired(json_buf, resource_url, credit_count, error_text))
    payment_required_json = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);

  JsonRpcRequest_t request;
  char* result = payment_required_json ? mcp_buildPaymentRequiredResult(static_mcpIdOfBody(body, &request), payment_required_json, is_modern) : NULL;
  free(payment_required_json);
  if (!result)
  {
    handler_mcpInternalError(client_fd, body);
    return;
  }

  if (retry_after_sec > 0)
    response_sendWithRetryAfter(client_fd, 200, "OK", retry_after_sec, result);
  else
    response_send(client_fd, 200, "OK", result);
  free(result);
}

static void static_sendPaymentOffer(int client_fd, const Endpoint_t* endpoint, unsigned int credit_count, const char* err_code, const char* message, bool has_retry_after, unsigned int retry_after_sec)
{
  char extra_headers[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE + HANDLER_RETRY_AFTER_LINE_BUF_SIZE];
  if (!x402_request_tryWritePaymentRequired(endpoint, credit_count, message, extra_headers, X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE))
  {
    handler_internalError(client_fd);
    return;
  }
  if (has_retry_after)
  {
    size_t line_len = strlen(extra_headers);
    snprintf(extra_headers + line_len, sizeof(extra_headers) - line_len, "Retry-After: %u\r\n", retry_after_sec);
  }

  char* response_body = static_errorBody(err_code, message);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }
  response_sendWithExtraHeaders(client_fd, 402, "Payment Required", extra_headers, response_body);
  free(response_body);
}

static void static_sendRetryAfterError(int client_fd, int status_code, const char* status_text, const char* err_code, const char* message, unsigned int retry_after_sec)
{
  char retry_after_line[HANDLER_RETRY_AFTER_LINE_BUF_SIZE];
  snprintf(retry_after_line, sizeof(retry_after_line), "Retry-After: %u\r\n", retry_after_sec);

  char* response_body = static_errorBody(err_code, message);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }
  response_sendWithExtraHeaders(client_fd, status_code, status_text, retry_after_line, response_body);
  free(response_body);
}

static char* static_errorBody(const char* err_code, const char* message)
{
  JsonBuf_t* json_buf = jsonbuf_create(HANDLER_ERROR_JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (!json_buf)
    return NULL;

  serialize_error_response(err_code, message, json_buf);
  char* response_body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return response_body;
}

static void static_sendError(int client_fd, int status_code, const char* status_text, const char* err_code, const char* message)
{
  char* response_body = static_errorBody(err_code, message);
  if (!response_body)
  {
    handler_internalError(client_fd);
    return;
  }

  response_send(client_fd, status_code, status_text, response_body);
  free(response_body);
}

static char* static_mcpErrorEnvelope(const char* body, int rpc_code, const char* message, const char* data_json)
{
  assert(body != NULL);

  JsonRpcRequest_t request;
  const char* id_raw = static_mcpIdOfBody(body, &request);

  JsonBuf_t* json_buf = jsonbuf_create(HANDLER_ERROR_JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (!json_buf)
    return NULL;

  jsonrpc_serializeError(id_raw, rpc_code, message, data_json, json_buf);
  char* envelope = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  return envelope;
}

static const char* static_mcpIdOfBody(const char* body, JsonRpcRequest_t* request_out)
{
  assert(body != NULL);
  if (jsonrpc_parse(body, strlen(body), request_out) == JSONRPC_OK && request_out->m_hasId)
    return request_out->ma_id;
  
  return "null";
}

static const char* static_mcpReasonPhrase(int status_code)
{
  if (status_code == 400)
    return "Bad Request";
  else if (status_code == 404)
    return "Not Found";
  else if (status_code == 500)
    return "Internal Server Error";
  return "OK";
}

static void static_sendMcpRetryAfterError(int client_fd, int status_code, const char* status_text, const char* body, int rpc_code, const char* message, unsigned int retry_after_sec)
{
  char* envelope = static_mcpRetryAfterErrorEnvelope(body, rpc_code, message, retry_after_sec);
  if (!envelope)
  {
    response_send(client_fd, 500, "Internal Server Error", MCP_INTERNAL_ERROR_BODY);
    return;
  }
  response_sendWithRetryAfter(client_fd, status_code, status_text, retry_after_sec, envelope);
  free(envelope);
}

static char* static_mcpRetryAfterErrorEnvelope(const char* body, int rpc_code, const char* message, unsigned int retry_after_sec)
{
  _Static_assert(HANDLER_RETRY_AFTER_DATA_BUF_SIZE >= sizeof(R"({"retry_after_seconds":4294967295})"),
                 "HANDLER_RETRY_AFTER_DATA_BUF_SIZE must fit error.data for any unsigned int");
  char data_json[HANDLER_RETRY_AFTER_DATA_BUF_SIZE];
  int data_json_len = snprintf(data_json, sizeof(data_json), R"({"retry_after_seconds":%u})", retry_after_sec);
  assert(data_json_len > 0 && (size_t)data_json_len < sizeof(data_json));
  (void)data_json_len;

  return static_mcpErrorEnvelope(body, rpc_code, message, data_json);
}

static void static_sendMcpError(int client_fd, int status_code, const char* status_text, const char* body, int rpc_code, const char* message)
{
  char* envelope = static_mcpErrorEnvelope(body, rpc_code, message, NULL);
  if (!envelope)
  {
    response_send(client_fd, 500, "Internal Server Error", MCP_INTERNAL_ERROR_BODY);
    return;
  }

  response_send(client_fd, status_code, status_text, envelope);
  free(envelope);
}

static void static_sendNotFound(int client_fd, const Endpoint_t* endpoint)
{
  assert(client_fd >= 0);
  assert(endpoint->mp_notFoundMessage != NULL);

  static_sendError(client_fd, 404, "Not Found", "not_found", endpoint->mp_notFoundMessage);
}

static void static_sendRestGateRefusal(int client_fd, const Endpoint_t* endpoint, EndpointGateResult_t gate_result)
{
  assert(endpoint != NULL);

  if (gate_result.m_status == ENDPOINT_GATE_REJECT_BODY)
  {
    handler_badRequest(client_fd, "body must be a JSON object");
    return;
  }
  else if (gate_result.m_status == ENDPOINT_GATE_REJECT_BODY_TOO_LARGE)
  {
    handler_badRequest(client_fd, "body too large");
    return;
  }
  else if (gate_result.m_status == ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME && endpoint_hasRestBodyParam(endpoint))
  {
    char body_message[ENDPOINT_MESSAGE_BUF_SIZE];
    int body_message_len = snprintf(body_message, sizeof(body_message), "unknown body parameter; the body takes only");
    assert(body_message_len > 0 && (size_t)body_message_len < sizeof(body_message));
    (void)body_message_len;

    if (endpoint_appendParamNameListToRefusalMessage(endpoint, ENDPOINT_PARAM_SRC_REST_BODY, body_message, sizeof(body_message)) != ENDPOINT_PARAM_NAME_LIST_WRITTEN)
      snprintf(body_message, sizeof(body_message), "unknown body parameter");

    handler_badRequest(client_fd, body_message);
    return;
  }
  else if (gate_result.m_status == ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME || gate_result.m_status == ENDPOINT_GATE_REJECT_MALFORMED_PARAM)
  {
    handler_httpQueryParamNameRefused(client_fd, endpoint, gate_result);
    return;
  }

  char message[ENDPOINT_MESSAGE_BUF_SIZE];
  if (endpoint_writeGateRefusalMessage(endpoint, gate_result, message, sizeof(message)) == ENDPOINT_REFUSAL_MESSAGE_FALLBACK)
  {
    handler_badRequest(client_fd, message);
    return;
  }
  const EndpointParam_t* param = &endpoint->mp_params[gate_result.m_refusedParamIndex];
  bool is_bad_path_segment = gate_result.m_status == ENDPOINT_GATE_REJECT_VALUE &&
                            (param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT);
  if (is_bad_path_segment && param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_CWE_ID)
    static_sendError(client_fd, 400, "Bad Request", "invalid_cwe_id", message);
  else if (is_bad_path_segment && param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID)
    static_sendError(client_fd, 400, "Bad Request", "invalid_cve_id", message);
  else
    handler_badRequest(client_fd, message);
}
