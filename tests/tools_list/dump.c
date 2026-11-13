#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcp.h"

int main(void)
{
  static const char body[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

  char* json_out = NULL;
  int   status   = 0;
  if (!mcp_dispatch(body, sizeof(body) - 1, NULL, &json_out, &status, NULL, NULL, NULL))
  {
    fprintf(stderr, "tools_list: mcp_dispatch failed\n");
    return EXIT_FAILURE;
  }
  if (status != 200 || json_out == NULL)
  {
    fprintf(stderr, "tools_list: tools/list answered status %d%s\n", status, json_out == NULL ? " without a body" : "");
    free(json_out);
    return EXIT_FAILURE;
  }

  size_t length  = strlen(json_out);
  size_t written = fwrite(json_out, 1, length, stdout);
  free(json_out);
  if (written != length || fflush(stdout) != 0)
  {
    fprintf(stderr, "tools_list: writing the document failed\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
