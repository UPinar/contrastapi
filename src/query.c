#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "query.h"
#include "bytes.h"

QueryStatus_t query_paramGetStatus(const char* query_str, const char* param_name, char* out_buf, size_t out_buf_size)
{
  assert(param_name   != NULL);
  assert(out_buf      != NULL);
  assert(out_buf_size  > 0);

  out_buf[0] = '\0';

  if (!query_str || !*query_str)
    return QUERY_NOTFOUND;

  const char* cursor = (*query_str == '?') ? query_str + 1 : query_str;
  size_t name_len = strlen(param_name);

  while (*cursor)
  {
    if (strncmp(cursor, param_name, name_len) == 0 && *(cursor + name_len) == '=')
    {
      const char* value = cursor + name_len + 1;
      return query_percentDecode(value, strcspn(value, "&"), true, out_buf, out_buf_size);
    }

    while (*cursor && *cursor != '&')
      cursor++;
    if (*cursor == '&')
      cursor++;
  }

  return QUERY_NOTFOUND;
}

QueryStatus_t query_percentDecode(const char* text, size_t text_len, bool is_plus_a_space, char* out_buf, size_t out_buf_size)
{
  assert(text         != NULL);
  assert(out_buf      != NULL);
  assert(out_buf_size  > 0);

  size_t out_pos = 0;
  size_t text_pos = 0;
  while (text_pos < text_len)
  {
    char   byte    = text[text_pos];
    size_t raw_len = 1;
    if (byte == '+' && is_plus_a_space)
      byte = ' ';
    else if (byte == '%')
    {
      bool is_escape_whole = text_pos + 2 < text_len;
      int  high = is_escape_whole ? bytes_hexDigitValue(text[text_pos + 1]) : -1;
      int  low  = is_escape_whole ? bytes_hexDigitValue(text[text_pos + 2]) : -1;
      if (high < 0 || low < 0)
      {
        out_buf[0] = '\0';
        return QUERY_BADENCODING;
      }
      if (high == 0 && low == 0)
      {
        out_buf[0] = '\0';
        return QUERY_NUL;
      }
      byte    = (char)(high * 16 + low);
      raw_len = 3;
    }

    if (out_pos == out_buf_size - 1)
    {
      out_buf[0] = '\0';
      return QUERY_TOOLONG;
    }
    out_buf[out_pos++] = byte;
    text_pos += raw_len;
  }
  out_buf[out_pos] = '\0';
  return QUERY_OK;
}

bool query_nextParamName(const char* query_str, size_t* offset, QueryParamName_t* name_out)
{
  assert(query_str != NULL);
  assert(offset    != NULL);
  assert(name_out  != NULL);

  if (*offset == 0 && query_str[0] == '?')
    *offset = 1;

  while (query_str[*offset] == '&')
    (*offset)++;
  if (query_str[*offset] == '\0')
    return false;

  const char* cursor = query_str + *offset;
  size_t name_len = 0;
  while (cursor[name_len] != '\0' && cursor[name_len] != '&' && cursor[name_len] != '=')
    name_len++;

  name_out->mp_start   = cursor;
  name_out->m_len      = name_len;
  name_out->m_hasValue = (cursor[name_len] == '=');

  size_t segment_len = name_len;
  while (cursor[segment_len] != '\0' && cursor[segment_len] != '&')
    segment_len++;
  *offset += segment_len;
  return true;
}
