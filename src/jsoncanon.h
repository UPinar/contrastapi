#ifndef JSONCANON_H
#define JSONCANON_H

#include <stdbool.h>
#include <stddef.h>

#include "jsonbuf.h"

#define JSONCANON_OBJECT_MEMBER_MAX 256

#define JSONCANON_FLOAT_TOKEN_MAX 64

#define JSONCANON_FLOAT_TEXT_MAX 1024

bool jsoncanon_tryWrite(const char* body, size_t body_len, JsonBuf_t* json_buf);

#endif
