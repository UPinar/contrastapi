#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint.h"
#include "handler.h"
#include "mcp.h"

#define FUZZ_MCP_HEADER_COUNT 3

static const char* const FUZZ_MCP_HEADER_NAMES[FUZZ_MCP_HEADER_COUNT] = {
  "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name",
};

#define FUZZ_MCP_RETRY_AFTER_SEC 60

#define FUZZ_MCP_STUB_CONN ((PGconn*)1)

static int g_nullFd = -1;

static RequestCreditBudget_t g_creditBudget;

static const char* static_readHeaderValues(char* text, uint8_t header_bits, struct phr_header* headers_out, size_t* count_out)
{
  char* cursor = text;
  *count_out = 0;
  for (int i = 0; i < FUZZ_MCP_HEADER_COUNT; i++)
  {
    char* value_end = strchr(cursor, '\n');
    if (value_end == NULL)
      return NULL;
    *value_end = '\0';
    if (header_bits & (1u << i))
    {
      struct phr_header* header = &headers_out[*count_out];
      header->name      = FUZZ_MCP_HEADER_NAMES[i];
      header->name_len  = strlen(FUZZ_MCP_HEADER_NAMES[i]);
      header->value     = cursor;
      header->value_len = (size_t)(value_end - cursor);
      (*count_out)++;
    }
    cursor = value_end + 1;
  }
  return cursor;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1 || memchr(data + 1, '\0', size - 1) != NULL)
    return -1;
  if (g_nullFd < 0)
  {
    g_nullFd = open("/dev/null", O_WRONLY);
    if (g_nullFd < 0)
      abort();
  }

  char* text = malloc(size);
  if (text == NULL)
    abort();
  memcpy(text, data + 1, size - 1);
  text[size - 1] = '\0';

  struct phr_header headers[FUZZ_MCP_HEADER_COUNT];
  size_t header_count = 0;
  const char* body = static_readHeaderValues(text, data[0], headers, &header_count);
  if (body == NULL)
  {
    free(text);
    return -1;
  }

  McpRoutingHeaders_t routing_headers;
  mcp_readRoutingHeaders(headers, header_count, &routing_headers);

  RequestCharge_t charge = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = &g_creditBudget, .mp_x402Payment = NULL };
  char* response_json = NULL;
  int   status_code   = 200;
  if (!mcp_dispatch(body, strlen(body), &routing_headers, &response_json, &status_code, FUZZ_MCP_STUB_CONN, &charge, NULL))
    handler_mcpInternalError(g_nullFd, body);
  free(response_json);

  handler_mcpUnauthorized(g_nullFd, body);
  handler_mcpRateLimited(g_nullFd, body, FUZZ_MCP_RETRY_AFTER_SEC);

  free(text);
  return 0;
}
