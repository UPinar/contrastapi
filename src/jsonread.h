#ifndef JSONREAD_H
#define JSONREAD_H

#include <stdbool.h>
#include <stddef.h>

#define JSON_MIN_UNESCAPED_CHAR 0x20

typedef enum {
  JSONREAD_OK = 0,
  JSONREAD_ERR_NOTFOUND,
  JSONREAD_ERR_SYNTAX,
  JSONREAD_ERR_DEPTH,
  JSONREAD_ERR_TOOLONG,
  JSONREAD_ERR_TYPE,
  JSONREAD_ERR_RANGE,
  JSONREAD_ERR_NESTED,
  JSONREAD_ERR_NUL,
  JSONREAD_ERR_LONE_SURROGATE
} JsonReadStatus_t;

JsonReadStatus_t jsonread_strStatus     (const char* json, const char* key, char* out_buf, size_t out_buf_size);
JsonReadStatus_t jsonread_intStatus     (const char* json, const char* key, long* value_out);
JsonReadStatus_t jsonread_doubleStatus  (const char* json, const char* key, double* value_out);
JsonReadStatus_t jsonread_boolStatus    (const char* json, const char* key, bool* value_out);

#define JSONREAD_MAX_DEPTH 32

typedef struct {
  const char* mp_start;
  size_t      m_len;
} JsonReadSpan_t;

JsonReadStatus_t jsonread_root                  (const char* json, size_t len, JsonReadSpan_t* span_out);
JsonReadStatus_t jsonread_objectKey             (JsonReadSpan_t object_span, const char* key, JsonReadSpan_t* value_out);
JsonReadStatus_t jsonread_objectNextMember      (JsonReadSpan_t object_span, size_t* member_offset, JsonReadSpan_t* key_out, JsonReadSpan_t* value_out);
JsonReadStatus_t jsonread_arrayNextElement      (JsonReadSpan_t array_span, size_t* element_offset, JsonReadSpan_t* element_out);
JsonReadStatus_t jsonread_arrayLen              (JsonReadSpan_t array_span, size_t* element_count_out);
JsonReadStatus_t jsonread_spanToRawStringStatus (JsonReadSpan_t span, char* buf, size_t buf_size);

JsonReadStatus_t jsonread_spanToStrStatus (JsonReadSpan_t span, char* out_buf, size_t out_buf_size);

JsonReadStatus_t jsonread_spanToLongStatus(JsonReadSpan_t span, long* value_out);

JsonReadStatus_t jsonread_spanToDoubleStatus(JsonReadSpan_t span, double* value_out);

JsonReadStatus_t jsonread_spanToBoolStatus(JsonReadSpan_t span, bool* value_out);

bool jsonread_isSpanEqual(JsonReadSpan_t span, const char* text);

typedef struct {
  const char*     mp_key;
  bool            m_isFound;
  JsonReadSpan_t  m_valueSpan;
} JsonReadMember_t;

bool jsonread_tryFindMembers (JsonReadSpan_t object_span, JsonReadMember_t* members, size_t member_count);
bool jsonread_isObject       (JsonReadSpan_t span);
bool jsonread_isArray        (JsonReadSpan_t span);

bool jsonread_isNumberToken(const char* cursor, const char* end);

#endif
