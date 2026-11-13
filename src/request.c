#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "request.h"
#include "receive.h"
#include "auth.h"
#include "db.h"
#include "ratelimit.h"
#include "response.h"
#include "router.h"
#include "endpoint.h"
#include "handler.h"
#include "mcp.h"
#include "upstream.h"
#include "pages.h"
#include "usagelog.h"
#include "x402.h"
#include "x402_request.h"

#define REQUEST_LINE_OVERHEAD  (REQUEST_METHOD_MAX_LEN + 1 + (sizeof(" HTTP/1.1\r\n") - 1))
#define REQUEST_HEADER_BLOCK_END       (sizeof("\r\n") - 1)
#define REQUEST_HEADER_BLOCK_RESERVE   512

_Static_assert(REQUEST_LINE_OVERHEAD + REQUEST_TARGET_MAX_LEN + REQUEST_HEADER_BLOCK_END + REQUEST_HEADER_BLOCK_RESERVE + ENDPOINT_JSON_OBJECT_BUF_SIZE < REQUEST_BUFFER_SIZE,
               "request-target cap plus a full MCP arguments object no longer leaves the body "
               "room inside REQUEST_BUFFER_SIZE; such a body is refused with 413, not a 414");

typedef enum {
  REQUEST_ACCESS_OK = 0,
  REQUEST_ACCESS_UNAUTHORIZED,
  REQUEST_ACCESS_API_KEY_INACTIVE,
  REQUEST_ACCESS_RATE_LIMITED,
  REQUEST_ACCESS_PAYMENT_REQUIRED,
  REQUEST_ACCESS_PAYMENT_INVALID,
  REQUEST_ACCESS_PAYMENT_NOT_OFFERED,
  REQUEST_ACCESS_PAYMENT_REFUSED,
  REQUEST_ACCESS_PAYMENT_ALREADY_USED,
  REQUEST_ACCESS_PAYMENT_PENDING,
  REQUEST_ACCESS_PAYMENT_BUSY,
  REQUEST_ACCESS_PAYMENT_LIMITED,
  REQUEST_ACCESS_PAYMENT_UNAVAILABLE,
  REQUEST_ACCESS_MCP_REFUSED,
  REQUEST_ACCESS_UPSTREAM_BUSY,
  REQUEST_ACCESS_INTERNAL_ERROR
} RequestAccessStatus_t;

typedef struct {
  RequestAccessStatus_t m_status;
  unsigned int          m_retryAfterSec;
  unsigned int          m_chargedCreditCount;
  unsigned int          m_paymentCreditCount;
  bool                  m_hasOpenPayment;
  bool                  m_isCreditBudgetChecked;
  RequestCreditBudget_t m_creditBudget;
  const Endpoint_t*     mp_pricedEndpoint;
  char*                 mp_mcpRefusalJson;
  int                   m_mcpRefusalStatus;
} RequestAccessResult_t;

_Static_assert(ENDPOINT_MCP_ENVELOPE_RESERVE_BYTE_COUNT >= X402_PAYMENT_JSON_MAX_BYTE_COUNT + 1024,
               "the /mcp envelope reserve must hold the largest x402 payment and the envelope");

static RequestAccessResult_t static_checkRequestAccess             (PGconn* conn, const ReceiveResult_t* request, const Endpoint_t* endpoint, const McpRoutingHeaders_t* routing_headers, EndpointPrice_t* price, const char* client_ip, const char* ip_secret, X402RequestPayment_t* payment_out);
static RequestAccessResult_t static_dbOpenPayment                  (PGconn* conn, EndpointPrice_t* price, const X402RequestPaymentSource_t* source, bool is_source_repeated, const char* client_ip, const char* ip_secret, X402RequestPayment_t* payment_out);
static bool                  static_isMcpLadderRefused             (const ReceiveResult_t* request, const McpRoutingHeaders_t* routing_headers, RequestAccessResult_t* access_result);
static bool                  static_tryWeighWholeRequest           (PGconn* conn, EndpointPrice_t* price);
static RequestAccessResult_t static_chargeCreditCost               (PGconn* conn, const char* credit_budget_hash, RequestTier_t tier, const EndpointPrice_t* price);
static RequestAccessResult_t static_chargeRefusedKey               (PGconn* conn, const EndpointPrice_t* price, const char* client_ip, const char* ip_secret, RequestAccessStatus_t refusal_status);
static void                  static_sendAccessRefusal              (int client_fd, const Endpoint_t* endpoint, const char* body, bool is_modern, RequestAccessResult_t access_result);
static void                  static_httpRequestCreditCost          (const Endpoint_t* endpoint, const char* path_segment, const RouterParsedRequest_t* req, EndpointPrice_t* price_out);
static void                  static_readPathAndQuery               (const char* target, size_t target_len, char* path_out, const char** query_out);
static void                  static_readRealIp                     (const ReceiveResult_t* request, char* real_ip_out);

void request_readHead(const ReceiveResult_t* request, RequestHead_t* head_out)
{
  assert(request != NULL);
  assert(head_out != NULL);

  memset(head_out, 0, sizeof(*head_out));

  if (request->m_methodLen > REQUEST_METHOD_MAX_LEN)
  {
    head_out->m_status = REQUEST_HEAD_ERR_METHODTOOLONG;
    return;
  }
  if (request->m_requestTargetLen > REQUEST_TARGET_MAX_LEN)
  {
    head_out->m_status = REQUEST_HEAD_ERR_TARGETTOOLONG;
    return;
  }

  memcpy(head_out->ma_method, request->mp_method, request->m_methodLen);
  head_out->ma_method[request->m_methodLen] = '\0';
  static_readPathAndQuery(request->mp_requestTarget, request->m_requestTargetLen, head_out->ma_path, &head_out->mp_query);

  head_out->m_status = REQUEST_HEAD_OK;
}

bool request_isRawBodyPlaceNeeded(const RequestHead_t* head)
{
  assert(head != NULL);

  if (head->m_status != REQUEST_HEAD_OK)
    return false;

  const Endpoint_t* endpoint = endpoint_findByHttpPath(head->ma_path, NULL);

  return  endpoint != NULL                                          && 
          endpoint_isHttpMethodAllowed(endpoint, head->ma_method)   && 
          endpoint_hasRawBodyParam(endpoint)                        &&
          endpoint_rawBodyByteLimit(endpoint) > ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT;
}

size_t request_maxBodyByteCount(const RequestHead_t* head, size_t head_len)
{
  assert(head != NULL);
  assert(head_len < REQUEST_BUFFER_SIZE);

  size_t room_after_head = REQUEST_BUFFER_SIZE - 1 - head_len;
  
  if (head->m_status != REQUEST_HEAD_OK)
    return room_after_head;

  const Endpoint_t* endpoint = endpoint_findByHttpPath(head->ma_path, NULL);
  if (endpoint == NULL || !endpoint_isHttpMethodAllowed(endpoint, head->ma_method))
    return room_after_head;

  if (endpoint_hasRawBodyParam(endpoint))
    return endpoint_rawBodyByteLimit(endpoint);

  size_t row_max_body_byte_count = 0;
  if (endpoint->m_isMcpEndpoint)
    row_max_body_byte_count = ENDPOINT_MCP_MAX_BODY_BYTE_COUNT;
  else if (endpoint_hasRestBodyParam(endpoint))
    row_max_body_byte_count = endpoint_jsonObjectSizeLimit(endpoint);
  
  return row_max_body_byte_count > room_after_head ? row_max_body_byte_count : room_after_head;
}

static void static_readPathAndQuery(const char* target, size_t target_len, char* path_out, const char** query_out)
{
  assert(target_len <= REQUEST_TARGET_MAX_LEN);

  memcpy(path_out, target, target_len);
  path_out[target_len] = '\0';

  const char* query = path_out + target_len;
  char* query_separator = strchr(path_out, '?');
  if (query_separator)
  {
    *query_separator = '\0';
    query = query_separator + 1;
  }

  size_t path_len = strlen(path_out);
  while (path_len > 1 && path_out[path_len - 1] == '/')
    path_out[--path_len] = '\0';

  if (query_out)
    *query_out = query;
}

void request_handle(const ReceiveResult_t* request, const RequestHead_t* head, int client_fd, const char* client_ip, const char* ip_secret, PGconn* conn)
{
  assert(request != NULL);
  assert(head != NULL);

  response_clearRateLimitInfo();

  if (head->m_status == REQUEST_HEAD_ERR_TARGETTOOLONG)
  {
    handler_uriTooLong(client_fd);
    goto done;
  }
  else if (head->m_status != REQUEST_HEAD_OK)
    goto done;

  response_setHeadRequest(strcmp(head->ma_method, "HEAD") == 0);

  RouterParsedRequest_t req = {
    .mp_method      = head->ma_method,
    .mp_path        = head->ma_path,
    .mp_query       = head->mp_query,
    .mp_body        = request->mp_body,
    .m_bodyLen      = request->m_bodyLen,
    .mp_headers     = request->ma_headers,
    .m_headerCount  = request->m_headerCount,
  };

  char real_ip[INET6_ADDRSTRLEN];
  static_readRealIp(request, real_ip);
  const char* metered_ip = client_ip;
  if (real_ip[0] != '\0' && strcmp(client_ip, "127.0.0.1") == 0)
    metered_ip = real_ip;

  const char* path_segment   = NULL;
  const Endpoint_t* endpoint = endpoint_findByHttpPath(req.mp_path, &path_segment);

  if (endpoint == NULL)
    req.mp_webFile = pages_findServedFile(req.mp_path);

  if (endpoint != NULL)
  {
    usagelog_setSurface(endpoint->m_isMcpEndpoint ? USAGELOG_SURFACE_MCP : USAGELOG_SURFACE_REST);
    usagelog_setEndpointName(endpoint);
  }
  else if (req.mp_webFile != NULL)
  {
    usagelog_setSurface(USAGELOG_SURFACE_WEB);
    usagelog_setWebFileName(req.mp_webFile);
  }
  else
  {
    const char* first_path_segment = req.mp_path + strspn(req.mp_path, "/");
    usagelog_setSurface(USAGELOG_SURFACE_REST);
    usagelog_setUnknownName(first_path_segment, strcspn(first_path_segment, "/"));
  }

  bool has_raw_body_param = endpoint != NULL && endpoint_hasRawBodyParam(endpoint);
  if (!has_raw_body_param && memchr(req.mp_body, '\0', req.m_bodyLen))
  {
    handler_badRequest(client_fd, "request body must not contain a NUL byte");
    goto done;
  }

  EndpointPrice_t price;
  static_httpRequestCreditCost(endpoint, path_segment, &req, &price);

  McpRoutingHeaders_t mcp_headers;
  const McpRoutingHeaders_t* routing_headers = NULL;
  if (endpoint != NULL && endpoint->m_isMcpEndpoint)
  {
    mcp_readRoutingHeaders(request->ma_headers, request->m_headerCount, &mcp_headers);
    routing_headers          = &mcp_headers;
    req.mp_mcpRoutingHeaders = &mcp_headers;
  }
  bool is_modern = routing_headers != NULL && mcp_isModernEra(routing_headers);

  if (price.m_willCallUpstream && !upstream_tryEnter())
  {
    RequestAccessResult_t busy_result = { .m_status = REQUEST_ACCESS_UPSTREAM_BUSY };
    static_sendAccessRefusal(client_fd, endpoint, req.mp_body, is_modern, busy_result);
    goto done;
  }

  X402RequestPayment_t  payment;
  RequestAccessResult_t access_result = static_checkRequestAccess(conn, request, endpoint, routing_headers, &price, metered_ip, ip_secret, &payment);
  if (access_result.m_status != REQUEST_ACCESS_OK)
    static_sendAccessRefusal(client_fd, endpoint, req.mp_body, is_modern, access_result);
  else
  {
    RequestCharge_t charge = {
      .m_chargedCreditCount = access_result.m_chargedCreditCount,
      .mp_creditBudget      = access_result.m_isCreditBudgetChecked ? &access_result.m_creditBudget : NULL,
      .mp_x402Payment       = access_result.m_hasOpenPayment ? &payment : NULL,
    };
    usagelog_setCreditCount(access_result.m_hasOpenPayment ? 0 : access_result.m_chargedCreditCount);
    router_dispatch(&req, endpoint, path_segment, client_fd, conn, &charge);
  }

  if (price.m_willCallUpstream)
    upstream_leave();

done:
  response_setHeadRequest(false);
  close(client_fd);
}

static void static_readRealIp(const ReceiveResult_t* request, char* real_ip_out)
{
  real_ip_out[0] = '\0';
  ReceiveHeader_t real_ip = receive_findHeader(request, "x-real-ip");
  char            candidate[INET6_ADDRSTRLEN];
  if (real_ip.m_status == RECEIVE_HEADER_FOUND && real_ip.m_len > 0 && real_ip.m_len < sizeof(candidate))
  {
    memcpy(candidate, real_ip.mp_value, real_ip.m_len);
    candidate[real_ip.m_len] = '\0';

    unsigned char parsed[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, candidate, parsed) == 1 || inet_pton(AF_INET6, candidate, parsed) == 1)
      memcpy(real_ip_out, candidate, real_ip.m_len + 1);
  }
}

static RequestAccessResult_t static_checkRequestAccess(PGconn* conn, const ReceiveResult_t* request, const Endpoint_t* endpoint, const McpRoutingHeaders_t* routing_headers, EndpointPrice_t* price, const char* client_ip, const char* ip_secret, X402RequestPayment_t* payment_out)
{
  assert(request != NULL);
  assert(price   != NULL);

  RequestAccessResult_t access_result = { .m_status = REQUEST_ACCESS_OK };
  AuthApiKeyParseResult_t auth_result = auth_parseApiKey(request->ma_headers, request->m_headerCount);

  if (auth_result.m_apiKeyStatus == AUTH_API_KEY_MALFORMED)
  {
    usagelog_setTier(USAGELOG_TIER_PRO_REFUSED);
    access_result.m_status = REQUEST_ACCESS_UNAUTHORIZED;
    return access_result;
  }

  if (!conn)
  {
    if (price->m_creditCost > 0)
      access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
    return access_result;
  }

  if (auth_result.m_apiKeyStatus == AUTH_API_KEY_VALID_FORMAT)
  {
    char key_hash[SHA256_HEX_LEN + 1];
    auth_hashApiKey(auth_result.ma_apiKey, key_hash);
    DbApiKeyState_t  key_state  = DB_API_KEY_UNKNOWN;
    DbApiKeyExpiry_t key_expiry = { 0 };
    if (db_readApiKeyState(conn, key_hash, &key_state, &key_expiry) != DB_OK)
    {
      access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
      return access_result;
    }

    if (key_state == DB_API_KEY_ACTIVE)
    {
      usagelog_setTier(USAGELOG_TIER_PRO);
      access_result = static_chargeCreditCost(conn, key_hash, REQUEST_TIER_PRO, price);
      access_result.m_creditBudget.m_keyExpiry = key_expiry;
      return access_result;
    }

    usagelog_setTier(USAGELOG_TIER_PRO_REFUSED);
    return static_chargeRefusedKey(conn, price, client_ip, ip_secret,
                                   key_state == DB_API_KEY_INACTIVE ? REQUEST_ACCESS_API_KEY_INACTIVE
                                                                    : REQUEST_ACCESS_UNAUTHORIZED);
  }
  else if (auth_result.m_apiKeyStatus == AUTH_API_KEY_NONE)
  {
    if (x402_request_isOn() && endpoint != NULL && !endpoint->m_isMcpEndpoint)
    {
      ReceiveHeader_t payment_header = receive_findUniqueHeader(request, X402_REQUEST_PAYMENT_HEADER_NAME);
      if (payment_header.m_status != RECEIVE_HEADER_NONE)
      {
        X402RequestPaymentSource_t source = { .m_kind = X402_REQUEST_PAYMENT_SOURCE_HEADER_BASE64, .mp_text = payment_header.mp_value, .m_len = payment_header.m_len };
        return static_dbOpenPayment(conn, price, &source, payment_header.m_status != RECEIVE_HEADER_FOUND, client_ip, ip_secret, payment_out);
      }
    }
    else if (x402_request_isOn() && endpoint != NULL)
    {
      McpPaymentMeta_t meta;
      mcp_readPaymentMeta(request->mp_body, &meta);
      if (meta.m_status != MCP_PAYMENT_META_NONE)
      {
        if (static_isMcpLadderRefused(request, routing_headers, &access_result))
          return access_result;
        X402RequestPaymentSource_t source = { .m_kind = X402_REQUEST_PAYMENT_SOURCE_JSON, .mp_text = meta.m_span.mp_start, .m_len = meta.m_span.m_len };
        return static_dbOpenPayment(conn, price, &source, meta.m_status == MCP_PAYMENT_META_REPEATED, client_ip, ip_secret, payment_out);
      }
    }

    if (price->m_creditCost == 0)
      return access_result;

    char ip_hash[SHA256_HEX_LEN + 1];
    auth_hashIp(client_ip, ip_secret, ip_hash);
    access_result = static_chargeCreditCost(conn, ip_hash, REQUEST_TIER_FREE, price);
    if (access_result.m_status == REQUEST_ACCESS_RATE_LIMITED && x402_request_isOn() && price->m_isPaymentOfferable)
    {
      if (price->mp_weighedEndpoint != NULL)
      {
        X402RequestOpenStatus_t weigh_status = x402_request_dbThrottleWeigh(conn, ip_hash).m_status;
        if (weigh_status == X402_REQUEST_OPEN_LIMITED)
          return access_result;
        else if (weigh_status != X402_REQUEST_OPEN_OK)
        {
          response_clearRateLimitInfo();
          access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
          return access_result;
        }
      }
      if (!static_tryWeighWholeRequest(conn, price))
      {
        response_clearRateLimitInfo();
        access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
        return access_result;
      }
      if (endpoint != NULL && endpoint->m_isMcpEndpoint && static_isMcpLadderRefused(request, routing_headers, &access_result))
      {
        response_clearRateLimitInfo();
        return access_result;
      }
      access_result.m_status             = REQUEST_ACCESS_PAYMENT_REQUIRED;
      access_result.m_paymentCreditCount = price->m_creditCost;
      access_result.mp_pricedEndpoint    = price->mp_pricedEndpoint;
    }
    return access_result;
  }

  return access_result;
}

static bool static_isMcpLadderRefused(const ReceiveResult_t* request, const McpRoutingHeaders_t* routing_headers, RequestAccessResult_t* access_result)
{
  char* refusal_json   = NULL;
  int   refusal_status = 0;
  if (!mcp_tryBuildModernRefusal(request->mp_body, request->m_bodyLen, routing_headers, &refusal_json, &refusal_status))
    return false;
  
  access_result->m_status           = REQUEST_ACCESS_MCP_REFUSED;
  access_result->mp_mcpRefusalJson  = refusal_json;
  access_result->m_mcpRefusalStatus = refusal_status;
  return true;
}

static RequestAccessResult_t static_dbOpenPayment(PGconn* conn, EndpointPrice_t* price, const X402RequestPaymentSource_t* source, bool is_source_repeated, const char* client_ip, const char* ip_secret, X402RequestPayment_t* payment_out)
{
  assert(price       != NULL);
  assert(source      != NULL);
  assert(payment_out != NULL);

  RequestAccessResult_t access_result = { .m_status = REQUEST_ACCESS_OK };
  usagelog_setTier(USAGELOG_TIER_X402);

  size_t max_source_len = 0;
  switch (source->m_kind)
  {
    case X402_REQUEST_PAYMENT_SOURCE_HEADER_BASE64:
      max_source_len = X402_PAYMENT_HEADER_MAX_LEN;
      break;
    case X402_REQUEST_PAYMENT_SOURCE_JSON:
      max_source_len = X402_PAYMENT_JSON_MAX_BYTE_COUNT;
      break;
  }
  if (is_source_repeated || source->m_len > max_source_len)
  {
    access_result.m_status = REQUEST_ACCESS_PAYMENT_INVALID;
    return access_result;
  }
  const Endpoint_t* endpoint = price->mp_pricedEndpoint;
  if (endpoint == NULL || !endpoint->m_isPayable)
  {
    access_result.m_status = REQUEST_ACCESS_PAYMENT_NOT_OFFERED;
    return access_result;
  }
  if (!price->m_isPaymentOfferable)
    return access_result;

  char ip_hash[SHA256_HEX_LEN + 1];
  auth_hashIp(client_ip, ip_secret, ip_hash);

  X402RequestOpenResult_t open_result = { .m_status = X402_REQUEST_OPEN_OK };
  if (price->mp_weighedEndpoint != NULL)
    open_result = x402_request_dbCheckBeforeWeigh(conn, source, ip_hash);
  if (open_result.m_status == X402_REQUEST_OPEN_OK && !static_tryWeighWholeRequest(conn, price))
  {
    access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
    return access_result;
  }

  unsigned int credit_count = price->m_creditCost;
  if (open_result.m_status == X402_REQUEST_OPEN_OK)
    open_result = x402_request_dbOpenPayment(conn, source, credit_count, ip_secret, ip_hash, payment_out);
  access_result.m_retryAfterSec = open_result.m_retryAfterSec;
  switch (open_result.m_status)
  {
    case X402_REQUEST_OPEN_OK:
    {
      access_result.m_hasOpenPayment        = true;
      access_result.m_chargedCreditCount    = credit_count;
      access_result.m_isCreditBudgetChecked = true;
      access_result.m_creditBudget.m_tier   = REQUEST_TIER_X402;
      int credit_budget_hash_len = snprintf(access_result.m_creditBudget.ma_budgetHash, sizeof(access_result.m_creditBudget.ma_budgetHash), "%s", ip_hash);
      assert(credit_budget_hash_len == SHA256_HEX_LEN);
      (void)credit_budget_hash_len;
      break;
    }
    case X402_REQUEST_OPEN_MALFORMED:
      access_result.m_status = REQUEST_ACCESS_PAYMENT_INVALID;
      break;
    case X402_REQUEST_OPEN_REFUSED:
      access_result.m_status             = REQUEST_ACCESS_PAYMENT_REFUSED;
      access_result.m_paymentCreditCount = credit_count;
      access_result.mp_pricedEndpoint    = endpoint;
      break;
    case X402_REQUEST_OPEN_ALREADY_USED:
      access_result.m_status             = REQUEST_ACCESS_PAYMENT_ALREADY_USED;
      access_result.m_paymentCreditCount = credit_count;
      access_result.mp_pricedEndpoint    = endpoint;
      break;
    case X402_REQUEST_OPEN_PENDING:
      access_result.m_status = REQUEST_ACCESS_PAYMENT_PENDING;
      break;
    case X402_REQUEST_OPEN_BUSY:
      access_result.m_status = REQUEST_ACCESS_PAYMENT_BUSY;
      break;
    case X402_REQUEST_OPEN_LIMITED:
      access_result.m_status = REQUEST_ACCESS_PAYMENT_LIMITED;
      break;
    case X402_REQUEST_OPEN_UNAVAILABLE:
      access_result.m_status = REQUEST_ACCESS_PAYMENT_UNAVAILABLE;
      break;
    case X402_REQUEST_OPEN_ERROR:
      access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
      break;
  }
  return access_result;
}

static bool static_tryWeighWholeRequest(PGconn* conn, EndpointPrice_t* price)
{
  if (price->mp_weighedEndpoint == NULL)
    return true;
  if (endpoint_limitWorkToWeight(price->mp_weighedEndpoint, conn, &price->m_weighedParams, UINT_MAX) != ENDPOINT_RUN_OK)
    return false;
  price->m_creditCost = endpoint_price(price->mp_weighedEndpoint, ENDPOINT_GATE_OK, &price->m_weighedParams, price->mp_weighedEndpoint->m_paramsSize);
  return true;
}

static RequestAccessResult_t static_chargeCreditCost(PGconn* conn, const char* credit_budget_hash, RequestTier_t tier, const EndpointPrice_t* price)
{
  assert(credit_budget_hash != NULL);
  assert(price              != NULL);

  RequestAccessResult_t access_result = { .m_status = REQUEST_ACCESS_OK };
  unsigned int credit_cost = price->m_creditCost;
  if (credit_cost == 0)
    return access_result;

  const bool has_api_key = tier == REQUEST_TIER_PRO;

  RateLimitInfo_t   rl_info   = { 0 };
  RateLimitStatus_t rl_status = RATELIMIT_ALLOW;
  if (price->mp_weighedEndpoint != NULL)
  {
    unsigned int remaining_credit_count = 0;
    rl_status = ratelimit_dbCreditBudgetRemaining(conn, credit_budget_hash, has_api_key, &rl_info, &remaining_credit_count);
    if (rl_status == RATELIMIT_ALLOW)
    {
      EndpointAnyParams_t budget_params = price->m_weighedParams;
      if (endpoint_limitWorkToWeight(price->mp_weighedEndpoint, conn, &budget_params, remaining_credit_count) != ENDPOINT_RUN_OK)
      {
        access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
        return access_result;
      }
      credit_cost = endpoint_price(price->mp_weighedEndpoint, ENDPOINT_GATE_OK, &budget_params, price->mp_weighedEndpoint->m_paramsSize);
    }
  }

  if (rl_status == RATELIMIT_ALLOW)
    rl_status = ratelimit_dbCreditBudgetCheck(conn, credit_budget_hash, has_api_key, credit_cost, price->m_isPartialChargeAllowed, &rl_info, &access_result.m_chargedCreditCount);
  if (rl_status == RATELIMIT_ERROR)
  {
    access_result.m_status = REQUEST_ACCESS_INTERNAL_ERROR;
    return access_result;
  }

  access_result.m_isCreditBudgetChecked        = true;
  access_result.m_creditBudget.m_tier          = tier;
  access_result.m_creditBudget.m_rateLimitInfo = rl_info;
  int credit_budget_hash_len = snprintf(access_result.m_creditBudget.ma_budgetHash, sizeof(access_result.m_creditBudget.ma_budgetHash), "%s", credit_budget_hash);
  assert(credit_budget_hash_len == SHA256_HEX_LEN);
  (void)credit_budget_hash_len;

  response_setRateLimitInfo(rl_info.m_limit, rl_info.m_remaining, rl_info.m_reset);
  if (rl_status == RATELIMIT_DENY)
  {
    time_t now = time(NULL);
    access_result.m_status        = REQUEST_ACCESS_RATE_LIMITED;
    access_result.m_retryAfterSec = (rl_info.m_reset > now) ? (unsigned int)(rl_info.m_reset - now) : 0;
  }
  return access_result;
}

static RequestAccessResult_t static_chargeRefusedKey(PGconn* conn, const EndpointPrice_t* price, const char* client_ip, const char* ip_secret, RequestAccessStatus_t refusal_status)
{
  assert(price != NULL);

  char ip_hash[SHA256_HEX_LEN + 1];
  auth_hashIp(client_ip, ip_secret, ip_hash);
  EndpointPrice_t refused_key_price = {
    .m_creditCost             = price->m_creditCost > 0 ? price->m_creditCost : 1,
    .m_isPartialChargeAllowed = price->m_creditCost > 0 && price->m_isPartialChargeAllowed,
    .mp_weighedEndpoint       = NULL,
  };
  RequestAccessResult_t access_result = static_chargeCreditCost(conn, ip_hash, REQUEST_TIER_FREE, &refused_key_price);
  if (access_result.m_status != REQUEST_ACCESS_OK)
    return access_result;

  response_clearRateLimitInfo();
  access_result.m_status = refusal_status;
  return access_result;
}

static void static_sendAccessRefusal(int client_fd, const Endpoint_t* endpoint, const char* body, bool is_modern, RequestAccessResult_t access_result)
{
  assert(body != NULL);
  assert(access_result.m_status != REQUEST_ACCESS_OK);

  bool is_mcp_request = endpoint != NULL && endpoint->m_isMcpEndpoint;
  switch (access_result.m_status)
  {
    case REQUEST_ACCESS_UNAUTHORIZED:
      if (is_mcp_request)
        handler_mcpUnauthorized(client_fd, body);
      else
        handler_unauthorized(client_fd);
      break;
    case REQUEST_ACCESS_API_KEY_INACTIVE:
      if (is_mcp_request)
        handler_mcpApiKeyInactive(client_fd, body);
      else
        handler_apiKeyInactive(client_fd);
      break;
    case REQUEST_ACCESS_RATE_LIMITED:
      if (is_mcp_request)
        handler_mcpRateLimited(client_fd, body, access_result.m_retryAfterSec);
      else
        handler_rateLimited(client_fd, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_PAYMENT_REQUIRED:
      if (is_mcp_request)
        handler_mcpPaymentRequired(client_fd, body, access_result.mp_pricedEndpoint, access_result.m_paymentCreditCount, access_result.m_retryAfterSec, is_modern);
      else
        handler_paymentRequired(client_fd, endpoint, access_result.m_paymentCreditCount, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_PAYMENT_INVALID:
      if (is_mcp_request)
        handler_mcpPaymentInvalid(client_fd, body, is_modern);
      else
        handler_paymentInvalid(client_fd);
      break;
    case REQUEST_ACCESS_PAYMENT_NOT_OFFERED:
      if (is_mcp_request)
        handler_mcpPaymentNotOffered(client_fd, body, is_modern);
      else
        handler_paymentNotOffered(client_fd);
      break;
    case REQUEST_ACCESS_PAYMENT_REFUSED:
      if (is_mcp_request)
        handler_mcpPaymentRefused(client_fd, body, access_result.mp_pricedEndpoint, access_result.m_paymentCreditCount, is_modern);
      else
        handler_paymentRefused(client_fd, endpoint, access_result.m_paymentCreditCount);
      break;
    case REQUEST_ACCESS_PAYMENT_ALREADY_USED:
      if (is_mcp_request)
        handler_mcpPaymentAlreadyUsed(client_fd, body, access_result.mp_pricedEndpoint, access_result.m_paymentCreditCount, is_modern);
      else
        handler_paymentAlreadyUsed(client_fd, endpoint, access_result.m_paymentCreditCount);
      break;
    case REQUEST_ACCESS_PAYMENT_PENDING:
      if (is_mcp_request)
        handler_mcpPaymentPending(client_fd, body, access_result.m_retryAfterSec, is_modern);
      else
        handler_paymentPending(client_fd, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_PAYMENT_BUSY:
      if (is_mcp_request)
        handler_mcpPaymentBusy(client_fd, body, access_result.m_retryAfterSec);
      else
        handler_paymentBusy(client_fd, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_PAYMENT_LIMITED:
      if (is_mcp_request)
        handler_mcpPaymentLimited(client_fd, body, access_result.m_retryAfterSec);
      else
        handler_paymentLimited(client_fd, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_PAYMENT_UNAVAILABLE:
      if (is_mcp_request)
        handler_mcpPaymentUnavailable(client_fd, body, access_result.m_retryAfterSec);
      else
        handler_paymentUnavailable(client_fd, access_result.m_retryAfterSec);
      break;
    case REQUEST_ACCESS_MCP_REFUSED:
      handler_mcpLadderRefusal(client_fd, access_result.mp_mcpRefusalJson, access_result.m_mcpRefusalStatus);
      break;
    case REQUEST_ACCESS_UPSTREAM_BUSY:
      if (is_mcp_request)
        handler_mcpUpstreamBusy(client_fd, body);
      else
        handler_upstreamBusy(client_fd);
      break;
    case REQUEST_ACCESS_INTERNAL_ERROR:
      if (is_mcp_request)
        handler_mcpInternalError(client_fd, body);
      else
        handler_internalError(client_fd);
      break;
    case REQUEST_ACCESS_OK:
      break;
  }
}

static void static_httpRequestCreditCost(const Endpoint_t* endpoint, const char* path_segment, const RouterParsedRequest_t* req, EndpointPrice_t* price_out)
{
  assert(req            != NULL);
  assert(req->mp_method != NULL);
  assert(req->mp_body   != NULL);
  assert(req->mp_query  != NULL);
  assert(price_out      != NULL);

  price_out->m_creditCost             = 1;
  price_out->m_isPartialChargeAllowed = false;
  price_out->m_willCallUpstream       = false;
  price_out->m_isPaymentOfferable     = false;
  price_out->mp_pricedEndpoint        = endpoint;
  price_out->mp_weighedEndpoint       = NULL;

  if (endpoint == NULL)
  {
    price_out->m_creditCost = 0;
    return;
  }

  if (!endpoint_isHttpMethodAllowed(endpoint, req->mp_method))
  {
    bool is_mcp_get_or_delete = endpoint->m_isMcpEndpoint &&
                                (strcmp(req->mp_method, "GET") == 0 || strcmp(req->mp_method, "DELETE") == 0);
    price_out->m_creditCost = is_mcp_get_or_delete ? 0 : endpoint->m_creditCost;
    return;
  }

  if (endpoint_checkHttpQueryParamNames(endpoint, req->mp_query).m_status != ENDPOINT_GATE_OK)
  {
    price_out->m_creditCost = endpoint->m_creditCost;
    return;
  }

  if (endpoint->m_isMcpEndpoint)
  {
    mcp_creditCost(req->mp_body, price_out);
    return;
  }

  EndpointRestInput_t input = {
    .mp_pathSegment = path_segment,
    .mp_query       = req->mp_query,
    .m_body         = { .mp_bytes = (const unsigned char*)req->mp_body, .m_byteCount = req->m_bodyLen },
    .mp_headers     = req->mp_headers,
    .m_headerCount  = req->m_headerCount,
  };
  EndpointAnyParams_t* params         = &price_out->m_weighedParams;
  EndpointGateResult_t gate_result    = endpoint_restRequestGate(endpoint, &input, params, endpoint->m_paramsSize);
  price_out->m_willCallUpstream       = endpoint_willCallUpstream(endpoint, gate_result.m_status, params);
  price_out->m_isPartialChargeAllowed = endpoint_isPartialChargeAllowed(endpoint);
  price_out->m_isPaymentOfferable     = endpoint->m_isPayable && gate_result.m_status == ENDPOINT_GATE_OK;

  if (gate_result.m_status == ENDPOINT_GATE_OK && endpoint->m_weighFunction != NULL)
    price_out->mp_weighedEndpoint = endpoint;

  price_out->m_creditCost = endpoint_price(endpoint, gate_result.m_status, params, endpoint->m_paramsSize);
}
