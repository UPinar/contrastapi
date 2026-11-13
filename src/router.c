#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "router.h"
#include "endpoint.h"
#include "handler.h"
#include "pages.h"

void router_dispatch(const RouterParsedRequest_t* req, const Endpoint_t* endpoint, const char* path_segment, int client_fd, PGconn* conn, const RequestCharge_t* charge)
{
  assert(req != NULL);
  assert(req->mp_method != NULL);

  const char* http_method = req->mp_method;

  if (endpoint == NULL)
  {
    if (req->mp_webFile == NULL)
      handler_endpointNotFound(client_fd);
    else if (!pages_isHttpMethodAllowed(http_method))
      handler_httpMethodNotAllowed(client_fd, pages_allowedMethods);
    else
      pages_send(client_fd, req->mp_webFile);
    return;
  }

  if (!endpoint_isHttpMethodAllowed(endpoint, http_method))
  {
    handler_httpMethodNotAllowed(client_fd, endpoint->ma_allowedMethods);
    return;
  }

  EndpointGateResult_t param_name_check_result = endpoint_checkHttpQueryParamNames(endpoint, req->mp_query);
  if (param_name_check_result.m_status != ENDPOINT_GATE_OK)
  {
    handler_httpQueryParamNameRefused(client_fd, endpoint, param_name_check_result);
    return;
  }

  bool        is_post  = strcmp(http_method, "POST") == 0;
  const char* body     = is_post ? req->mp_body : NULL;
  size_t      body_len = is_post ? req->m_bodyLen : 0;
  if (endpoint->m_isMcpEndpoint)
  {
    handler_MCP(client_fd, body, req->mp_mcpRoutingHeaders, conn, charge);
    return;
  }

  EndpointRestInput_t input = {
    .mp_pathSegment = path_segment,
    .mp_query       = req->mp_query,
    .m_body         = { .mp_bytes = (const unsigned char*)body, .m_byteCount = body_len },
    .mp_headers     = req->mp_headers,
    .m_headerCount  = req->m_headerCount,
  };
  handler_runRestEndpoint(client_fd, endpoint, &input, conn, charge);
}
