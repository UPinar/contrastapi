#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "jsonread.h"
#include "bytes.h"

#define JSONREAD_KEY_PATTERN_BUF_SIZE  256

#define JSONREAD_UNICODE_ESCAPE_LEN  5
#define JSONREAD_ESCAPE_MAX_LEN      (2 * JSONREAD_UNICODE_ESCAPE_LEN + 1)

#define JSONREAD_UTF8_MAX_LEN         4
#define JSONREAD_UTF8_ONE_BYTE_MAX    0x7Fu
#define JSONREAD_UTF8_TWO_BYTE_MAX    0x7FFu
#define JSONREAD_UTF8_THREE_BYTE_MAX  0xFFFFu
#define JSONREAD_UTF8_FOUR_BYTE_MAX   0x10FFFFu

#define JSONREAD_UTF8_LEAD_TWO        0xC0u
#define JSONREAD_UTF8_LEAD_THREE      0xE0u
#define JSONREAD_UTF8_LEAD_FOUR       0xF0u
#define JSONREAD_UTF8_CONTINUATION    0x80u
#define JSONREAD_UTF8_DATA_BITS       6
#define JSONREAD_UTF8_DATA_MASK       0x3Fu

#define JSONREAD_HIGH_SURROGATE_MIN     0xD800u
#define JSONREAD_HIGH_SURROGATE_MAX     0xDBFFu
#define JSONREAD_LOW_SURROGATE_MIN      0xDC00u
#define JSONREAD_LOW_SURROGATE_MAX      0xDFFFu
#define JSONREAD_SURROGATE_DATA_BITS    10
#define JSONREAD_FIRST_PAIR_CODE_POINT  0x10000u

static const char*      static_findTopLevelValue    (const char* json, const char* key, JsonReadStatus_t* status_out);
static bool             static_isKeyTextAnywhere    (const char* json, const char* key);
static bool             static_isValueEnd           (char c);
static const char*      static_skipToValueEnd       (const char* cursor);
static const char*      static_skipDigits           (const char* cursor, const char* end);
static const char*      static_skipWhitespace       (const char* cursor, const char* end);
static const char*      static_skipString           (const char* cursor, const char* end);
static const char*      static_skipValue            (const char* cursor, const char* end, int depth, JsonReadStatus_t* status_out);
static const char*      static_skipInnerValue       (const char* cursor, const char* end, JsonReadStatus_t* status_out);
static bool             static_isAt                 (const char* cursor, const char* end, char expected);
static JsonReadStatus_t static_readObjectMember     (const char* cursor, const char* end, JsonReadSpan_t* key_out, JsonReadSpan_t* value_out, const char** member_end_out);
static JsonReadStatus_t static_decodeEscape         (const char** cursor, const char* end, char* out_buf, size_t out_buf_size, size_t* out_len);
static bool             static_tryReadUnicodeEscape (const char* cursor, const char* end, uint32_t* value_out);
static size_t           static_writeUtf8            (uint32_t code_point, char* out);

JsonReadStatus_t jsonread_strStatus(const char* json, const char* key, char* out_buf, size_t out_buf_size)
{
  assert(json         != NULL);
  assert(key          != NULL);
  assert(out_buf      != NULL);
  assert(out_buf_size  > 0);

  JsonReadStatus_t status = JSONREAD_OK;
  size_t i = 0;

  const char* cursor = static_findTopLevelValue(json, key, &status);
  if (!cursor)
  {
    if (status != JSONREAD_ERR_NOTFOUND)
      out_buf[0] = '\0';
    return status;
  }
  if (*cursor != '"')
  {
    out_buf[0] = '\0';
    return JSONREAD_ERR_TYPE;
  }
  cursor++;

  while (*cursor && i < out_buf_size - 1)
  {
    if (*cursor == '"')
      break;
    if (*cursor == '\\')
    {
      cursor++;
      status = static_decodeEscape(&cursor, cursor + strnlen(cursor, JSONREAD_ESCAPE_MAX_LEN), out_buf, out_buf_size, &i);
      if (status != JSONREAD_OK)
        goto done;
      continue;
    }
    else
    {
      out_buf[i++] = *cursor;
    }
    cursor++;
  }

  if (*cursor == '\0')
    status = JSONREAD_ERR_SYNTAX;
  else if (*cursor != '"')
    status = JSONREAD_ERR_TOOLONG;

done:
  if (status != JSONREAD_OK)
    i = 0;
  out_buf[i] = '\0';
  return status;
}

bool jsonread_isNumberToken(const char* cursor, const char* end)
{
  assert(cursor != NULL && cursor <= end);

  if (cursor < end && *cursor == '-')
    cursor++;
  if (cursor >= end)
    return false;

  if (*cursor == '0')
    cursor++;
  else if (*cursor >= '1' && *cursor <= '9')
    cursor = static_skipDigits(cursor, end);
  else
    return false;

  if (cursor < end && *cursor == '.')
  {
    const char* fraction = cursor + 1;
    cursor = static_skipDigits(fraction, end);
    if (cursor == fraction)
      return false;
  }

  if (cursor < end && (*cursor == 'e' || *cursor == 'E'))
  {
    cursor++;
    if (cursor < end && (*cursor == '+' || *cursor == '-'))
      cursor++;
    const char* exponent = cursor;
    cursor = static_skipDigits(exponent, end);
    if (cursor == exponent)
      return false;
  }

  return cursor == end;
}

JsonReadStatus_t jsonread_intStatus(const char* json, const char* key, long* value_out)
{
  assert(json != NULL);
  assert(key  != NULL);
  assert(value_out  != NULL);

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_start = static_findTopLevelValue(json, key, &status);
  if (!value_start)
    return status;
  
  const char* token_end = static_skipToValueEnd(value_start);
  if (!jsonread_isNumberToken(value_start, token_end))
    return JSONREAD_ERR_TYPE;

  char* parse_end; errno = 0;
  long parsed_value = strtol(value_start, &parse_end, 10);
  if (parse_end != token_end)
    return JSONREAD_ERR_TYPE;
  if (errno != 0)
    return JSONREAD_ERR_RANGE;

  *value_out = parsed_value;
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_doubleStatus(const char* json, const char* key, double* value_out)
{
  assert(json != NULL);
  assert(key  != NULL);
  assert(value_out  != NULL);

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_start = static_findTopLevelValue(json, key, &status);
  if (!value_start)
    return status;

  const char* token_end = static_skipToValueEnd(value_start);
  if (!jsonread_isNumberToken(value_start, token_end))
    return JSONREAD_ERR_TYPE;

  char* parse_end; errno = 0;
  double parsed_value = strtod(value_start, &parse_end);
  if (parse_end != token_end)
    return JSONREAD_ERR_TYPE;
  if (errno != 0)
    return JSONREAD_ERR_RANGE;

  *value_out = parsed_value;
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_boolStatus(const char* json, const char* key, bool* value_out)
{
  assert(json != NULL);
  assert(key  != NULL);
  assert(value_out  != NULL);

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_start = static_findTopLevelValue(json, key, &status);
  if (!value_start)
    return status;

  if (strncmp(value_start, "true", 4) == 0 && static_isValueEnd(value_start[4]))
  {
    *value_out = true;
    return JSONREAD_OK;
  }
  else if (strncmp(value_start, "false", 5) == 0 && static_isValueEnd(value_start[5]))
  {
    *value_out = false;
    return JSONREAD_OK;
  }

  return JSONREAD_ERR_TYPE;
}

JsonReadStatus_t jsonread_root(const char* json, size_t len, JsonReadSpan_t* span_out)
{
  assert(span_out  != NULL);

  if (!json)
  {
    fprintf(stderr, "jsonread_root: no JSON text\n");
    return JSONREAD_ERR_SYNTAX;
  }

  const char* end = json + len;

  if ((size_t)(end - json) >= 3 &&
      (unsigned char)json[0] == 0xEF &&
      (unsigned char)json[1] == 0xBB &&
      (unsigned char)json[2] == 0xBF)
    json += 3;

  const char* cursor = static_skipWhitespace(json, end);
  if (cursor >= end)
    return JSONREAD_ERR_SYNTAX;

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_end = static_skipValue(cursor, end, 0, &status);
  if (!value_end)
    return status;

  if (static_skipWhitespace(value_end, end) != end)
    return JSONREAD_ERR_SYNTAX;

  span_out->mp_start = cursor;
  span_out->m_len = (size_t)(value_end - cursor);
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_objectKey(JsonReadSpan_t object_span, const char* key, JsonReadSpan_t* value_out)
{
  assert(key != NULL);
  assert(value_out != NULL);
  assert(object_span.m_len == 0 || object_span.mp_start != NULL);

  const char*      end    = object_span.mp_start + object_span.m_len;
  const char*      cursor = static_skipWhitespace(object_span.mp_start, end);
  JsonReadStatus_t status = JSONREAD_OK;

  if (cursor >= end || *cursor != '{')
    return JSONREAD_ERR_SYNTAX;
  cursor++;

  for (;;)
  {
    cursor = static_skipWhitespace(cursor, end);
    if (cursor >= end) return JSONREAD_ERR_SYNTAX;
    if (*cursor == '}') return JSONREAD_ERR_NOTFOUND;
    if (*cursor != '"') return JSONREAD_ERR_SYNTAX;

    const char* member_key_start = cursor + 1;
    const char* member_key_end   = static_skipString(cursor, end);
    if (!member_key_end) return JSONREAD_ERR_SYNTAX;

    size_t member_key_len = (size_t)(member_key_end - 1 - member_key_start);
    bool match = bytes_isEqual(member_key_start, member_key_len, key, false);

    cursor = static_skipWhitespace(member_key_end, end);
    if (cursor >= end || *cursor != ':') return JSONREAD_ERR_SYNTAX;
    cursor++;
    cursor = static_skipWhitespace(cursor, end);

    const char* value_start = cursor;
    const char* value_end   = static_skipInnerValue(cursor, end, &status);
    if (!value_end) return status;

    if (match)
    {
      value_out->mp_start = value_start;
      value_out->m_len    = (size_t)(value_end - value_start);
      return JSONREAD_OK;
    }

    cursor = static_skipWhitespace(value_end, end);
    if (cursor >= end) return JSONREAD_ERR_SYNTAX;
    if (*cursor == '}') return JSONREAD_ERR_NOTFOUND;
    if (*cursor != ',') return JSONREAD_ERR_SYNTAX;
    cursor++;
  }
}

JsonReadStatus_t jsonread_objectNextMember(JsonReadSpan_t object_span, size_t* member_offset, JsonReadSpan_t* key_out, JsonReadSpan_t* value_out)
{
  assert(member_offset != NULL);
  assert(key_out != NULL);
  assert(value_out != NULL);
  assert(object_span.m_len == 0 || object_span.mp_start != NULL);
  assert(*member_offset <= object_span.m_len);

  const char* end    = object_span.mp_start + object_span.m_len;
  const char* cursor = static_skipWhitespace(object_span.mp_start + *member_offset, end);

  if (*member_offset == 0)
  {
    if (!static_isAt(cursor, end, '{'))
      return JSONREAD_ERR_SYNTAX;
    cursor = static_skipWhitespace(cursor + 1, end);
    if (static_isAt(cursor, end, '}'))
      return JSONREAD_ERR_NOTFOUND;
  }
  else
  {
    if (static_isAt(cursor, end, '}'))
      return JSONREAD_ERR_NOTFOUND;
    if (!static_isAt(cursor, end, ','))
      return JSONREAD_ERR_SYNTAX;
    cursor = static_skipWhitespace(cursor + 1, end);
  }

  const char* member_end = NULL;
  JsonReadStatus_t status = static_readObjectMember(cursor, end, key_out, value_out, &member_end);
  if (status != JSONREAD_OK)
    return status;

  *member_offset = (size_t)(member_end - object_span.mp_start);
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_arrayNextElement(JsonReadSpan_t array_span, size_t* element_offset, JsonReadSpan_t* element_out)
{
  assert(element_offset != NULL);
  assert(element_out != NULL);
  assert(array_span.m_len == 0 || array_span.mp_start != NULL);
  assert(*element_offset <= array_span.m_len);

  const char* end    = array_span.mp_start + array_span.m_len;
  const char* cursor = static_skipWhitespace(array_span.mp_start + *element_offset, end);

  if (*element_offset == 0)
  {
    if (!static_isAt(cursor, end, '['))
      return JSONREAD_ERR_SYNTAX;

    cursor = static_skipWhitespace(cursor + 1, end);
    if (static_isAt(cursor, end, ']'))
      return JSONREAD_ERR_NOTFOUND;
  }
  else
  {
    if (static_isAt(cursor, end, ']'))
      return JSONREAD_ERR_NOTFOUND;
    if (!static_isAt(cursor, end, ','))
      return JSONREAD_ERR_SYNTAX;

    cursor = static_skipWhitespace(cursor + 1, end);
  }

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_end   = static_skipInnerValue(cursor, end, &status);
  if (!value_end)
    return status;

  element_out->mp_start = cursor;
  element_out->m_len    = (size_t)(value_end - cursor);

  *element_offset = (size_t)(value_end - array_span.mp_start);
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_arrayLen(JsonReadSpan_t array_span, size_t* element_count_out)
{
  assert(element_count_out != NULL);
  assert(array_span.m_len == 0 || array_span.mp_start != NULL);

  const char*      end           = array_span.mp_start + array_span.m_len;
  const char*      cursor        = static_skipWhitespace(array_span.mp_start, end);
  JsonReadStatus_t status        = JSONREAD_OK;
  size_t           element_count = 0;

  if (cursor >= end || *cursor != '[')
    return JSONREAD_ERR_SYNTAX;
  cursor++;
  cursor = static_skipWhitespace(cursor, end);
  if (cursor < end && *cursor == ']') { *element_count_out = 0; return JSONREAD_OK; }

  for (;;)
  {
    const char* value_end = static_skipInnerValue(cursor, end, &status);
    if (!value_end) 
      return status;

    element_count++;
    
    cursor = static_skipWhitespace(value_end, end);
    if (cursor >= end) 
      return JSONREAD_ERR_SYNTAX;
    if (*cursor == ']') 
    { 
      *element_count_out = element_count; 
      return JSONREAD_OK; 
    }
    if (*cursor != ',') 
      return JSONREAD_ERR_SYNTAX;
    cursor++;
    cursor = static_skipWhitespace(cursor, end);
  }
}

#define JSONREAD_NUMBER_TEXT_BUF_SIZE 24

JsonReadStatus_t jsonread_spanToLongStatus(JsonReadSpan_t span, long* value_out)
{
  assert(value_out != NULL);
  assert(span.m_len == 0 || span.mp_start != NULL);

  char number_text[JSONREAD_NUMBER_TEXT_BUF_SIZE];
  if (span.m_len == 0)
    return JSONREAD_ERR_TYPE;
  if (span.m_len >= sizeof(number_text))
  {
    size_t byte_index = (span.mp_start[0] == '-') ? 1 : 0;
    for (; byte_index < span.m_len; byte_index++)
    {
      if (span.mp_start[byte_index] < '0' || span.mp_start[byte_index] > '9')
        return JSONREAD_ERR_TYPE;
    }
    return JSONREAD_ERR_RANGE;
  }

  memcpy(number_text, span.mp_start, span.m_len);
  number_text[span.m_len] = '\0';

  char* parse_end;
  errno = 0;
  long parsed_value = strtol(number_text, &parse_end, 10);
  if (parse_end == number_text || *parse_end != '\0')
    return JSONREAD_ERR_TYPE;
  if (errno != 0)
    return JSONREAD_ERR_RANGE;

  *value_out = parsed_value;
  return JSONREAD_OK;
}

#define JSONREAD_DOUBLE_TEXT_BUF_SIZE 64

JsonReadStatus_t jsonread_spanToDoubleStatus(JsonReadSpan_t span, double* value_out)
{
  assert(value_out != NULL);
  assert(span.m_len == 0 || span.mp_start != NULL);

  if (span.m_len == 0 || !jsonread_isNumberToken(span.mp_start, span.mp_start + span.m_len))
    return JSONREAD_ERR_TYPE;

  char number_text[JSONREAD_DOUBLE_TEXT_BUF_SIZE];
  if (span.m_len >= sizeof(number_text))
    return JSONREAD_ERR_RANGE;
  memcpy(number_text, span.mp_start, span.m_len);
  number_text[span.m_len] = '\0';

  char* parse_end;
  errno = 0;
  double parsed_value = strtod(number_text, &parse_end);
  if (*parse_end != '\0')
    return JSONREAD_ERR_TYPE;
  if (errno != 0)
    return JSONREAD_ERR_RANGE;

  *value_out = parsed_value;
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_spanToBoolStatus(JsonReadSpan_t span, bool* value_out)
{
  assert(value_out != NULL);
  assert(span.m_len == 0 || span.mp_start != NULL);

  if (jsonread_isSpanEqual(span, "true"))
  {
    *value_out = true;
    return JSONREAD_OK;
  }
  else if (jsonread_isSpanEqual(span, "false"))
  {
    *value_out = false;
    return JSONREAD_OK;
  }

  return JSONREAD_ERR_TYPE;
}

bool jsonread_isSpanEqual(JsonReadSpan_t span, const char* text)
{
  return bytes_isEqual(span.mp_start, span.m_len, text, false);
}

bool jsonread_isObject(JsonReadSpan_t span)
{
  return span.m_len > 0 && span.mp_start[0] == '{';
}

bool jsonread_isArray(JsonReadSpan_t span)
{
  return span.m_len > 0 && span.mp_start[0] == '[';
}

bool jsonread_tryFindMembers(JsonReadSpan_t object_span, JsonReadMember_t* members, size_t member_count)
{
  assert(members != NULL);

  if (!jsonread_isObject(object_span))
    return false;

  size_t           member_offset = 0;
  JsonReadSpan_t   key_span;
  JsonReadSpan_t   value_span;
  JsonReadStatus_t status;
  while ((status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
  {
    if (memchr(key_span.mp_start, '\\', key_span.m_len) != NULL)
      return false;

    for (size_t i = 0; i < member_count; i++)
    {
      if (!jsonread_isSpanEqual(key_span, members[i].mp_key))
        continue;
      if (members[i].m_isFound)
        return false;

      members[i].m_isFound   = true;
      members[i].m_valueSpan = value_span;
    }
  }
  return status == JSONREAD_ERR_NOTFOUND;
}

JsonReadStatus_t jsonread_spanToRawStringStatus(JsonReadSpan_t span, char* buf, size_t buf_size)
{
  assert(buf != NULL);
  assert(span.m_len == 0 || span.mp_start != NULL);

  if (span.m_len >= buf_size)
    return JSONREAD_ERR_TOOLONG;
  memcpy(buf, span.mp_start, span.m_len);
  buf[span.m_len] = '\0';
  return JSONREAD_OK;
}

JsonReadStatus_t jsonread_spanToStrStatus(JsonReadSpan_t span, char* out_buf, size_t out_buf_size)
{
  assert(out_buf != NULL);
  assert(out_buf_size > 0);
  assert(span.m_len == 0 || span.mp_start != NULL);

  const char* cursor = span.mp_start;
  const char* end    = span.mp_start + span.m_len;
  if (cursor >= end || *cursor != '"')
    return JSONREAD_ERR_TYPE;
  cursor++;

  size_t i = 0;
  while (cursor < end && i < out_buf_size - 1)
  {
    char c = *cursor;
    if (c == '"')
    {
      out_buf[i] = '\0';
      return JSONREAD_OK;
    }
    if (c == '\\')
    {
      cursor++;
      JsonReadStatus_t escape_status = static_decodeEscape(&cursor, end, out_buf, out_buf_size, &i);
      if (escape_status != JSONREAD_OK)
        return escape_status;

      continue;
    }
    else if ((unsigned char)c < JSON_MIN_UNESCAPED_CHAR)
    {
      return JSONREAD_ERR_SYNTAX;
    }
    else
    {
      out_buf[i++] = c;
    }
    cursor++;
  }
  if (cursor < end && *cursor == '"')
  {
    out_buf[i] = '\0';
    return JSONREAD_OK;
  }
  else if (cursor >= end)
    return JSONREAD_ERR_SYNTAX;
  else
    return JSONREAD_ERR_TOOLONG;
}

static const char* static_findTopLevelValue(const char* json, const char* key, JsonReadStatus_t* status_out)
{
  assert(json       != NULL);
  assert(key        != NULL);
  assert(status_out != NULL);

  const char* end    = json + strlen(json);
  const char* cursor = static_skipWhitespace(json, end);

  if (static_isAt(cursor, end, '{'))
  {
    cursor = static_skipWhitespace(cursor + 1, end);
    while (!static_isAt(cursor, end, '}'))
    {
      if (!static_isAt(cursor, end, '"'))
      {
        *status_out = JSONREAD_ERR_SYNTAX;
        return NULL;
      }
      const char* member_key_start = cursor + 1;
      const char* member_key_end   = static_skipString(cursor, end);
      if (!member_key_end)
      {
        *status_out = JSONREAD_ERR_SYNTAX;
        return NULL;
      }
      cursor = static_skipWhitespace(member_key_end, end);
      if (!static_isAt(cursor, end, ':'))
      {
        *status_out = JSONREAD_ERR_SYNTAX;
        return NULL;
      }
      cursor = static_skipWhitespace(cursor + 1, end);

      size_t member_key_len = (size_t)(member_key_end - 1 - member_key_start);
      if (bytes_isEqual(member_key_start, member_key_len, key, false))
      {
        *status_out = JSONREAD_OK;
        return cursor;
      }

      JsonReadStatus_t status = JSONREAD_OK;
      cursor = static_skipInnerValue(cursor, end, &status);
      if (!cursor)
      {
        *status_out = status;
        return NULL;
      }
      cursor = static_skipWhitespace(cursor, end);
      if (static_isAt(cursor, end, ','))
        cursor = static_skipWhitespace(cursor + 1, end);
      else if (!static_isAt(cursor, end, '}'))
      {
        *status_out = JSONREAD_ERR_SYNTAX;
        return NULL;
      }
    }
  }

  *status_out = static_isKeyTextAnywhere(json, key) ? JSONREAD_ERR_NESTED : JSONREAD_ERR_NOTFOUND;
  return NULL;
}

static bool static_isKeyTextAnywhere(const char* json, const char* key)
{
  assert(json != NULL);
  assert(key  != NULL);

  char pattern[JSONREAD_KEY_PATTERN_BUF_SIZE];
  int  pattern_len = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  if (pattern_len <= 0 || (size_t)pattern_len >= sizeof(pattern))
    return false;

  const char* cursor = json;
  while ((cursor = strstr(cursor, pattern)) != NULL)
  {
    cursor += pattern_len;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
      cursor++;
    if (*cursor == ':')
      return true;
  }
  return false;
}

static bool static_isValueEnd(char c)
{
  return c == '\0' || c == ',' || c == '}' || c == ']'
      || c == ' '  || c == '\t' || c == '\n' || c == '\r';
}

static const char* static_skipToValueEnd(const char* cursor)
{
  while (!static_isValueEnd(*cursor))
    cursor++;
  return cursor;
}

static const char* static_skipDigits(const char* cursor, const char* end)
{
  while (cursor < end && *cursor >= '0' && *cursor <= '9')
    cursor++;
  return cursor;
}

static bool static_isAt(const char* cursor, const char* end, char expected)
{
  return cursor < end && *cursor == expected;
}

static JsonReadStatus_t static_readObjectMember(const char* cursor, const char* end, JsonReadSpan_t* key_out, JsonReadSpan_t* value_out, const char** member_end_out)
{
  assert(key_out != NULL);
  assert(value_out != NULL);
  assert(member_end_out != NULL);

  if (!static_isAt(cursor, end, '"'))
    return JSONREAD_ERR_SYNTAX;

  const char* key_start = cursor + 1;
  const char* key_end   = static_skipString(cursor, end);
  if (!key_end)
    return JSONREAD_ERR_SYNTAX;

  cursor = static_skipWhitespace(key_end, end);
  if (!static_isAt(cursor, end, ':'))
    return JSONREAD_ERR_SYNTAX;
  cursor = static_skipWhitespace(cursor + 1, end);

  JsonReadStatus_t status = JSONREAD_OK;
  const char* value_start = cursor;
  const char* value_end   = static_skipInnerValue(cursor, end, &status);
  if (!value_end)
    return status;

  key_out->mp_start   = key_start;
  key_out->m_len      = (size_t)(key_end - 1 - key_start);
  value_out->mp_start = value_start;
  value_out->m_len    = (size_t)(value_end - value_start);
  *member_end_out     = value_end;
  return JSONREAD_OK;
}

static const char* static_skipWhitespace(const char* cursor, const char* end)
{
  while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r'))
    cursor++;
  return cursor;
}

static const char* static_skipString(const char* cursor, const char* end)
{
  if (cursor >= end || *cursor != '"')
  {
    fprintf(stderr, "static_skipString: no opening quote\n");
    return NULL;
  }

  cursor++;
  while (cursor < end)
  {
    unsigned char c = (unsigned char)*cursor;
    if (c == '"')
      return cursor + 1;
    if (c == '\\')
    {
      cursor++;
      if (cursor >= end) return NULL;
      cursor++;
      continue;
    }
    if (c < JSON_MIN_UNESCAPED_CHAR) 
      return NULL;
    cursor++;
  }
  return NULL;
}

static const char* static_skipValue(const char* cursor, const char* end, int depth, JsonReadStatus_t* status_out)
{
  assert(status_out != NULL);

  cursor = static_skipWhitespace(cursor, end);
  if (cursor >= end) 
  { 
    *status_out = JSONREAD_ERR_SYNTAX; 
    return NULL; 
  }

  char c = *cursor;

  if (c == '"')
  {
    const char* value_end = static_skipString(cursor, end);
    if (!value_end) 
      *status_out = JSONREAD_ERR_SYNTAX;
    return value_end;
  }
  else if (c == '{' || c == '[')
  {
    if (depth >= JSONREAD_MAX_DEPTH) 
    { 
      *status_out = JSONREAD_ERR_DEPTH; 
      return NULL; 
    }
    
    char close = (c == '{') ? '}' : ']';
    bool is_object = (c == '{');
    cursor++;
    cursor = static_skipWhitespace(cursor, end);
    if (cursor < end && *cursor == close)
      return cursor + 1;

    for (;;)
    {
      if (is_object)
      {
        cursor = static_skipWhitespace(cursor, end);
        if (cursor >= end || *cursor != '"') { *status_out = JSONREAD_ERR_SYNTAX; return NULL; }
        cursor = static_skipString(cursor, end);
        if (!cursor) { *status_out = JSONREAD_ERR_SYNTAX; return NULL; }
        cursor = static_skipWhitespace(cursor, end);
        if (cursor >= end || *cursor != ':') { *status_out = JSONREAD_ERR_SYNTAX; return NULL; }
        cursor++;
      }
      cursor = static_skipValue(cursor, end, depth + 1, status_out);
      if (!cursor) 
        return NULL;
      cursor = static_skipWhitespace(cursor, end);

      if (cursor >= end) 
      { 
        *status_out = JSONREAD_ERR_SYNTAX; 
        return NULL; 
      }
      if (*cursor == close) 
        return cursor + 1;
      if (*cursor != ',') 
      { 
        *status_out = JSONREAD_ERR_SYNTAX; 
        return NULL; 
      }
      
      cursor++;
    }
  }
  else if (c == 't')
  {
    if (bytes_hasPrefix(cursor, (size_t)(end - cursor), "true", 4, false)) 
      return cursor + 4;

    *status_out = JSONREAD_ERR_SYNTAX; 
    return NULL;
  }
  else if (c == 'f')
  {
    if (bytes_hasPrefix(cursor, (size_t)(end - cursor), "false", 5, false)) 
      return cursor + 5;

    *status_out = JSONREAD_ERR_SYNTAX; 
    return NULL;
  }
  else if (c == 'n')
  {
    if (bytes_hasPrefix(cursor, (size_t)(end - cursor), "null", 4, false)) 
      return cursor + 4;

    *status_out = JSONREAD_ERR_SYNTAX; 
    return NULL;
  }
  else if (c == '-' || (c >= '0' && c <= '9'))
  {
    const char* value_end = cursor;
    while (value_end < end)
    {
      char number_char = *value_end;
      if ((number_char >= '0' && number_char <= '9') || number_char == '-' || number_char == '+'
          || number_char == '.' || number_char == 'e' || number_char == 'E')
        value_end++;
      else
        break;
    }
    if (value_end == cursor) 
    { 
      *status_out = JSONREAD_ERR_SYNTAX; 
      return NULL; 
    }
    
    return value_end;
  }

  *status_out = JSONREAD_ERR_SYNTAX;
  return NULL;
}

static const char* static_skipInnerValue(const char* cursor, const char* end, JsonReadStatus_t* status_out)
{
  return static_skipValue(cursor, end, 1, status_out);
}

static JsonReadStatus_t static_decodeEscape(const char** cursor, const char* end, char* out_buf, size_t out_buf_size, size_t* out_len)
{
  assert(cursor != NULL && *cursor != NULL);
  assert(*cursor <= end);
  assert(out_buf != NULL);
  assert(out_len != NULL);
  assert(*out_len + 1 < out_buf_size);

  const char* escape = *cursor;
  if (escape >= end)
    return JSONREAD_ERR_SYNTAX;

  char     decoded[JSONREAD_UTF8_MAX_LEN];
  size_t   decoded_len = 1;
  size_t   escape_len  = 1;
  uint32_t code_point  = 0;
  switch (*escape)
  {
    case '"':  decoded[0] = '"';  break;
    case '\\': decoded[0] = '\\'; break;
    case '/':  decoded[0] = '/';  break;
    case 'n':  decoded[0] = '\n'; break;
    case 'r':  decoded[0] = '\r'; break;
    case 't':  decoded[0] = '\t'; break;
    case 'b':  decoded[0] = '\b'; break;
    case 'f':  decoded[0] = '\f'; break;
    case 'u':
      if (!static_tryReadUnicodeEscape(escape, end, &code_point))
        return JSONREAD_ERR_SYNTAX;

      escape_len = JSONREAD_UNICODE_ESCAPE_LEN;

      if (code_point == 0)
        return JSONREAD_ERR_NUL;
      if (code_point >= JSONREAD_LOW_SURROGATE_MIN && code_point <= JSONREAD_LOW_SURROGATE_MAX)
        return JSONREAD_ERR_LONE_SURROGATE;
      if (code_point >= JSONREAD_HIGH_SURROGATE_MIN && code_point <= JSONREAD_HIGH_SURROGATE_MAX)
      {
        const char* second_half_escape = escape + JSONREAD_UNICODE_ESCAPE_LEN;
        uint32_t second_half = 0;
        if (second_half_escape >= end || *second_half_escape != '\\'                              ||
            !static_tryReadUnicodeEscape(second_half_escape + 1, end, &second_half)               ||
            second_half < JSONREAD_LOW_SURROGATE_MIN || second_half > JSONREAD_LOW_SURROGATE_MAX)
        {
          return JSONREAD_ERR_LONE_SURROGATE;
        }

        code_point = JSONREAD_FIRST_PAIR_CODE_POINT +
                     ((code_point - JSONREAD_HIGH_SURROGATE_MIN) << JSONREAD_SURROGATE_DATA_BITS) +
                     (second_half - JSONREAD_LOW_SURROGATE_MIN);
        escape_len = JSONREAD_ESCAPE_MAX_LEN;
      }
      decoded_len = static_writeUtf8(code_point, decoded);
      break;
    default:
      return JSONREAD_ERR_SYNTAX;
  }

  if (decoded_len > out_buf_size - 1 - *out_len)
    return JSONREAD_ERR_TOOLONG;

  memcpy(out_buf + *out_len, decoded, decoded_len);
  *out_len += decoded_len;
  *cursor  += escape_len;

  return JSONREAD_OK;
}

static bool static_tryReadUnicodeEscape(const char* cursor, const char* end, uint32_t* value_out)
{
  assert(cursor != NULL);
  assert(cursor <= end);
  assert(value_out != NULL);

  if (end - cursor < JSONREAD_UNICODE_ESCAPE_LEN || *cursor != 'u')
    return false;

  uint32_t value = 0;
  for (int k = 1; k < JSONREAD_UNICODE_ESCAPE_LEN; k++)
  {
    int digit_value = bytes_hexDigitValue(cursor[k]);
    if (digit_value < 0)
      return false;

    value = value * 16 + (uint32_t)digit_value;
  }

  *value_out = value;
  return true;
}

static size_t static_writeUtf8(uint32_t code_point, char* out)
{
  assert(code_point < JSONREAD_HIGH_SURROGATE_MIN || code_point > JSONREAD_LOW_SURROGATE_MAX);
  assert(code_point <= JSONREAD_UTF8_FOUR_BYTE_MAX);
  assert(out != NULL);

  if (code_point <= JSONREAD_UTF8_ONE_BYTE_MAX)
  {
    out[0] = (char)code_point;
    return 1;
  }
  else if (code_point <= JSONREAD_UTF8_TWO_BYTE_MAX)
  {
    out[0] = (char)(JSONREAD_UTF8_LEAD_TWO | (code_point >> JSONREAD_UTF8_DATA_BITS));
    out[1] = (char)(JSONREAD_UTF8_CONTINUATION | (code_point & JSONREAD_UTF8_DATA_MASK));
    return 2;
  }
  else if (code_point <= JSONREAD_UTF8_THREE_BYTE_MAX)
  {
    out[0] = (char)(JSONREAD_UTF8_LEAD_THREE | (code_point >> (2 * JSONREAD_UTF8_DATA_BITS)));
    out[1] = (char)(JSONREAD_UTF8_CONTINUATION | ((code_point >> JSONREAD_UTF8_DATA_BITS) & JSONREAD_UTF8_DATA_MASK));
    out[2] = (char)(JSONREAD_UTF8_CONTINUATION | (code_point & JSONREAD_UTF8_DATA_MASK));
    return 3;
  }
  else
  {
    out[0] = (char)(JSONREAD_UTF8_LEAD_FOUR | (code_point >> (3 * JSONREAD_UTF8_DATA_BITS)));
    out[1] = (char)(JSONREAD_UTF8_CONTINUATION | ((code_point >> (2 * JSONREAD_UTF8_DATA_BITS)) & JSONREAD_UTF8_DATA_MASK));
    out[2] = (char)(JSONREAD_UTF8_CONTINUATION | ((code_point >> JSONREAD_UTF8_DATA_BITS) & JSONREAD_UTF8_DATA_MASK));
    out[3] = (char)(JSONREAD_UTF8_CONTINUATION | (code_point & JSONREAD_UTF8_DATA_MASK));
    return 4;
  }
}
