#ifndef QUERY_H
#define QUERY_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  QUERY_OK = 0,
  QUERY_NOTFOUND,
  QUERY_TOOLONG,
  QUERY_BADENCODING,
  QUERY_NUL
} QueryStatus_t;

QueryStatus_t query_paramGetStatus(const char* query_str, const char* param_name, char* out_buf, size_t out_buf_size);

QueryStatus_t query_percentDecode(const char* text, size_t text_len, bool is_plus_a_space, char* out_buf, size_t out_buf_size);

typedef struct {
  const char* mp_start;
  size_t      m_len;
  bool        m_hasValue;
} QueryParamName_t;

bool query_nextParamName(const char* query_str, size_t* offset, QueryParamName_t* name_out);

#endif
