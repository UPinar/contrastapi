#ifndef ROUTER_H
#define ROUTER_H

#include <libpq-fe.h>

#include "endpoint.h"
#include "mcp.h"
#include "pages.h"
#include "picohttpparser.h"
#include "request.h"

typedef struct {
  const char*                 mp_method;
  const char*                 mp_path;
  const char*                 mp_query;
  const char*                 mp_body;
  size_t                      m_bodyLen;
  const McpRoutingHeaders_t*  mp_mcpRoutingHeaders;
  const PagesFile_t*          mp_webFile;
  const struct phr_header*    mp_headers;
  size_t                      m_headerCount;
} RouterParsedRequest_t;

void router_dispatch(const RouterParsedRequest_t* req, const Endpoint_t* endpoint, const char* path_segment, int client_fd, PGconn* conn, const RequestCharge_t* charge);

#endif
