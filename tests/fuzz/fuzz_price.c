#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint.h"
#include "mcp.h"
#include "request.h"

#define FUZZ_PRICE_MAX_INPUT_BYTE_COUNT (1 + REQUEST_TARGET_MAX_LEN + 2 + ENDPOINT_MCP_MAX_BODY_BYTE_COUNT)

static char* static_copyWithNul(const uint8_t* bytes, size_t len)
{
  char* copy = malloc(len + 1);
  if (copy == NULL)
    abort();
  memcpy(copy, bytes, len);
  copy[len] = '\0';
  return copy;
}

static void static_priceRequest(const Endpoint_t* endpoint, const char* path_segment, const char* query, const char* body, size_t body_len)
{
  EndpointPrice_t price;
  if (endpoint_checkHttpQueryParamNames(endpoint, query).m_status != ENDPOINT_GATE_OK)
    return;

  if (endpoint->m_isMcpEndpoint)
  {
    mcp_creditCost(body, &price);
    return;
  }

  EndpointRestInput_t input = {
    .mp_pathSegment = path_segment,
    .mp_query       = query,
    .m_body         = { .mp_bytes = (const unsigned char*)body, .m_byteCount = body_len },
  };
  EndpointAnyParams_t* params      = &price.m_weighedParams;
  EndpointGateResult_t gate_result = endpoint_restRequestGate(endpoint, &input, params, endpoint->m_paramsSize);
  (void)endpoint_willCallUpstream(endpoint, gate_result.m_status, params);
  (void)endpoint_isPartialChargeAllowed(endpoint);
  (void)endpoint_price(endpoint, gate_result.m_status, params, endpoint->m_paramsSize);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1 || size > FUZZ_PRICE_MAX_INPUT_BYTE_COUNT)
    return -1;

  const Endpoint_t* endpoint = &endpoints[data[0] % endpoint_count];
  const uint8_t* rest = data + 1;
  size_t rest_len     = size - 1;

  const uint8_t* segment_end = memchr(rest, '\n', rest_len);
  if (segment_end == NULL)
    return -1;
  size_t segment_len = (size_t)(segment_end - rest);
  const uint8_t* query_start = segment_end + 1;
  const uint8_t* query_end   = memchr(query_start, '\n', rest_len - segment_len - 1);
  if (query_end == NULL)
    return -1;
  size_t query_len = (size_t)(query_end - query_start);
  if (segment_len + 1 + query_len > REQUEST_TARGET_MAX_LEN ||
      memchr(rest, '\0', segment_len) != NULL || memchr(query_start, '\0', query_len) != NULL)
    return -1;

  const uint8_t* body_start = query_end + 1;
  size_t body_len = size - (size_t)(body_start - data);
  if (!endpoint_hasRawBodyParam(endpoint) && memchr(body_start, '\0', body_len) != NULL)
    return -1;

  char* path_segment = static_copyWithNul(rest, segment_len);
  char* query        = static_copyWithNul(query_start, query_len);
  char* body         = static_copyWithNul(body_start, body_len);

  static_priceRequest(endpoint, endpoint->m_hasPathSegment ? path_segment : NULL, query, body, body_len);

  free(path_segment);
  free(query);
  free(body);
  return 0;
}
