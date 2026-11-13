#ifndef JSONBUF_H
#define JSONBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSONBUF_INITIAL_CAP     4096
#define JSONBUF_DEFAULT_CEILING (4 * 1024 * 1024)
#define JSONBUF_MAX_CEILING     (16 * 1024 * 1024)

typedef struct JsonBuf JsonBuf_t;

JsonBuf_t* jsonbuf_create             (size_t initial_cap, size_t ceiling)          __attribute__((warn_unused_result));
bool       jsonbuf_appendFormat       (JsonBuf_t* json_buf, const char* fmt, ...)   __attribute__((format(printf, 2, 3)));
bool       jsonbuf_appendEscaped      (JsonBuf_t* json_buf, const char* str);
bool       jsonbuf_appendEscapedBytes (JsonBuf_t* json_buf, const char* bytes, size_t byte_count);
bool       jsonbuf_appendJsonText     (JsonBuf_t* json_buf, const char* json_text);
char*      jsonbuf_finish             (JsonBuf_t* json_buf)                         __attribute__((warn_unused_result));
void       jsonbuf_destroy            (JsonBuf_t* json_buf);

bool jsonbuf_isCodePointHidden(uint32_t code_point);

size_t jsonbuf_length   (const JsonBuf_t* json_buf);
size_t jsonbuf_capacity (const JsonBuf_t* json_buf);
size_t jsonbuf_ceiling  (const JsonBuf_t* json_buf);

#endif
