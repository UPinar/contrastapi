#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonbuf.h"
#include "openapi.h"

int main(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (json_buf == NULL)
  {
    fprintf(stderr, "openapi: no buffer\n");
    return EXIT_FAILURE;
  }
  if (!openapi_appendDocument(json_buf))
  {
    fprintf(stderr, "openapi: no document; a row was refused or the buffer is full\n");
    jsonbuf_destroy(json_buf);
    return EXIT_FAILURE;
  }

  char* document = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  if (document == NULL)
  {
    fprintf(stderr, "openapi: the buffer failed\n");
    return EXIT_FAILURE;
  }

  size_t length  = strlen(document);
  size_t written = fwrite(document, 1, length, stdout);
  free(document);
  if (written != length || fflush(stdout) != 0)
  {
    fprintf(stderr, "openapi: writing the document failed\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
