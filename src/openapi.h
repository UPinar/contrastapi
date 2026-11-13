#ifndef OPENAPI_H
#define OPENAPI_H

#include <stdbool.h>

#include "endpoint.h"
#include "jsonbuf.h"

bool openapi_appendDocument  (JsonBuf_t* json_buf);
bool openapi_isRowInDocument (const Endpoint_t* row);

#endif
