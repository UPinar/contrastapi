#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsoncanon.h"
#include "jsonread.h"
#include "utf8.h"

#define JSONCANON_BOM     "\xEF\xBB\xBF"
#define JSONCANON_BOM_LEN 3

#define JSONCANON_APPEND_CHUNK_MAX (64 * 1024)

#define JSONCANON_FIRST_RAW_CODE_POINT 0x20u
#define JSONCANON_LAST_RAW_CODE_POINT  0x7Eu

#define JSONCANON_HIGH_SURROGATE_MIN 0xD800u
#define JSONCANON_HIGH_SURROGATE_MAX 0xDBFFu
#define JSONCANON_LOW_SURROGATE_MIN  0xDC00u
#define JSONCANON_LOW_SURROGATE_MAX  0xDFFFu

#define JSONCANON_SUPPLEMENTARY_MIN   0x10000u
#define JSONCANON_SURROGATE_DATA_BITS 10
#define JSONCANON_SURROGATE_DATA_MASK 0x3FFu

#define JSONCANON_HEX_ESCAPE_DIGITS 4
#define JSONCANON_HEX_ESCAPE_LEN    6

#define JSONCANON_FLOAT_MAX_PRECISION 16

#define JSONCANON_FLOAT_SCIENTIFIC_SIZE 32

#define JSONCANON_EXPONENT_FORM_DECIMAL_POINT_MAX 16
#define JSONCANON_EXPONENT_FORM_DECIMAL_POINT_MIN (-3)

typedef struct
{
  JsonReadSpan_t m_key;
  JsonReadSpan_t m_value;
} JsonCanonMember_t;

static bool static_writeValue            (JsonReadSpan_t value, JsonBuf_t* json_buf, size_t* float_count);
static bool static_writeObject           (JsonReadSpan_t object_span, JsonBuf_t* json_buf, size_t* float_count);
static bool static_writeArray            (JsonReadSpan_t array_span, JsonBuf_t* json_buf, size_t* float_count);
static bool static_writeString           (const char* text, size_t text_len, JsonBuf_t* json_buf);
static bool static_writeCodePoint        (uint32_t code_point, JsonBuf_t* json_buf);
static bool static_tryReadEscape         (const char** cursor, uint32_t* code_point_out);
static bool static_tryReadUnicodeEscape  (const char** cursor, uint32_t* code_point_out);
static bool static_tryReadHex4           (const char* text, uint32_t* value_out);
static int  static_hexDigitValue         (char hex_char);
static bool static_writeNumber           (JsonReadSpan_t number, JsonBuf_t* json_buf, size_t* float_count);
static bool static_writeFloat            (JsonReadSpan_t number, JsonBuf_t* json_buf);
static bool static_tryFormatShortest     (double value, char* scientific_text);
static bool static_tryRaiseLastDigit     (char* scientific_text);
static bool static_writeScientificText   (const char* scientific_text, JsonBuf_t* json_buf);
static bool static_appendRaw             (const char* bytes, size_t byte_count, JsonBuf_t* json_buf);
static int  static_compareMembers        (const void* left, const void* right);

bool jsoncanon_tryWrite(const char* body, size_t body_len, JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);

  if (body == NULL)
    return false;
  if (body_len >= JSONCANON_BOM_LEN && memcmp(body, JSONCANON_BOM, JSONCANON_BOM_LEN) == 0)
    return false;

  JsonReadSpan_t root;
  if (jsonread_root(body, body_len, &root) != JSONREAD_OK)
    return false;

  size_t float_count = 0;
  return static_writeObject(root, json_buf, &float_count);
}

static bool static_writeValue(JsonReadSpan_t value, JsonBuf_t* json_buf, size_t* float_count)
{
  char first_byte = value.mp_start[0];

  if (first_byte == '"')
    return static_writeString(value.mp_start + 1, value.m_len - 2, json_buf);
  if (first_byte == '{')
    return static_writeObject(value, json_buf, float_count);
  if (first_byte == '[')
    return static_writeArray(value, json_buf, float_count);
  if (first_byte == 't' || first_byte == 'f' || first_byte == 'n')
    return static_appendRaw(value.mp_start, value.m_len, json_buf);

  return static_writeNumber(value, json_buf, float_count);
}

static bool static_writeObject(JsonReadSpan_t object_span, JsonBuf_t* json_buf, size_t* float_count)
{
  JsonCanonMember_t members[JSONCANON_OBJECT_MEMBER_MAX];
  size_t            member_count  = 0;
  size_t            member_offset = 0;
  JsonReadSpan_t    key;
  JsonReadSpan_t    value;
  JsonReadStatus_t  status;

  while ((status = jsonread_objectNextMember(object_span, &member_offset, &key, &value)) == JSONREAD_OK)
  {
    if (member_count == JSONCANON_OBJECT_MEMBER_MAX)
      return false;
    if (memchr(key.mp_start, '\\', key.m_len) != NULL)
      return false;

    members[member_count].m_key   = key;
    members[member_count].m_value = value;
    member_count++;
  }
  if (status != JSONREAD_ERR_NOTFOUND)
    return false;

  qsort(members, member_count, sizeof(members[0]), static_compareMembers);

  for (size_t i = 1; i < member_count; i++)
  {
    if (static_compareMembers(&members[i - 1], &members[i]) == 0)
      return false;
  }

  if (!jsonbuf_appendFormat(json_buf, "{"))
    return false;

  for (size_t i = 0; i < member_count; i++)
  {
    if (i > 0 && !jsonbuf_appendFormat(json_buf, ","))
      return false;
    if (!static_writeString(members[i].m_key.mp_start, members[i].m_key.m_len, json_buf))
      return false;
    if (!jsonbuf_appendFormat(json_buf, ":"))
      return false;
    if (!static_writeValue(members[i].m_value, json_buf, float_count))
      return false;
  }

  return jsonbuf_appendFormat(json_buf, "}");
}

static bool static_writeArray(JsonReadSpan_t array_span, JsonBuf_t* json_buf, size_t* float_count)
{
  size_t           element_offset = 0;
  bool             is_first       = true;
  JsonReadSpan_t   element;
  JsonReadStatus_t status;

  if (!jsonbuf_appendFormat(json_buf, "["))
    return false;

  while ((status = jsonread_arrayNextElement(array_span, &element_offset, &element)) == JSONREAD_OK)
  {
    if (!is_first && !jsonbuf_appendFormat(json_buf, ","))
      return false;
    is_first = false;

    if (!static_writeValue(element, json_buf, float_count))
      return false;
  }
  if (status != JSONREAD_ERR_NOTFOUND)
    return false;

  return jsonbuf_appendFormat(json_buf, "]");
}

static bool static_writeString(const char* text, size_t text_len, JsonBuf_t* json_buf)
{
  const char* cursor = text;
  const char* end    = text + text_len;

  if (!jsonbuf_appendFormat(json_buf, "\""))
    return false;

  while (cursor < end)
  {
    unsigned char byte = (unsigned char)*cursor;

    if (byte == '\\')
    {
      uint32_t code_point;
      if (!static_tryReadEscape(&cursor, &code_point))
        return false;
      if (!static_writeCodePoint(code_point, json_buf))
        return false;
      continue;
    }

    if (byte >= JSONCANON_FIRST_RAW_CODE_POINT && byte <= JSONCANON_LAST_RAW_CODE_POINT)
    {
      const char* run_end = cursor + 1;
      while (run_end < end && (unsigned char)*run_end >= JSONCANON_FIRST_RAW_CODE_POINT &&
             (unsigned char)*run_end <= JSONCANON_LAST_RAW_CODE_POINT && *run_end != '\\')
        run_end++;
      if (!static_appendRaw(cursor, (size_t)(run_end - cursor), json_buf))
        return false;
      cursor = run_end;
      continue;
    }

    Utf8Sequence_t sequence = utf8_readFirstSequence((const unsigned char*)cursor, (size_t)(end - cursor));
    if (!sequence.m_isValid)
      return false;
    if (!static_writeCodePoint(sequence.m_codePoint, json_buf))
      return false;
    cursor += sequence.m_length;
  }

  return jsonbuf_appendFormat(json_buf, "\"");
}

static bool static_writeCodePoint(uint32_t code_point, JsonBuf_t* json_buf)
{
  switch (code_point)
  {
    case '"':  return jsonbuf_appendFormat(json_buf, "\\\"");
    case '\\': return jsonbuf_appendFormat(json_buf, "\\\\");
    case '\b': return jsonbuf_appendFormat(json_buf, "\\b");
    case '\f': return jsonbuf_appendFormat(json_buf, "\\f");
    case '\n': return jsonbuf_appendFormat(json_buf, "\\n");
    case '\r': return jsonbuf_appendFormat(json_buf, "\\r");
    case '\t': return jsonbuf_appendFormat(json_buf, "\\t");
    default:   break;
  }

  if (code_point >= JSONCANON_FIRST_RAW_CODE_POINT && code_point <= JSONCANON_LAST_RAW_CODE_POINT)
    return jsonbuf_appendFormat(json_buf, "%c", (char)code_point);

  if (code_point < JSONCANON_SUPPLEMENTARY_MIN)
    return jsonbuf_appendFormat(json_buf, "\\u%04x", (unsigned int)code_point);

  uint32_t offset = code_point - JSONCANON_SUPPLEMENTARY_MIN;
  unsigned int high_half = (unsigned int)(JSONCANON_HIGH_SURROGATE_MIN + (offset >> JSONCANON_SURROGATE_DATA_BITS));
  unsigned int low_half  = (unsigned int)(JSONCANON_LOW_SURROGATE_MIN + (offset & JSONCANON_SURROGATE_DATA_MASK));
  return jsonbuf_appendFormat(json_buf, "\\u%04x\\u%04x", high_half, low_half);
}

static bool static_tryReadEscape(const char** cursor, uint32_t* code_point_out)
{
  const char* text = *cursor;

  switch (text[1])
  {
    case '"':  *code_point_out = '"';  break;
    case '\\': *code_point_out = '\\'; break;
    case '/':  *code_point_out = '/';  break;
    case 'b':  *code_point_out = '\b'; break;
    case 'f':  *code_point_out = '\f'; break;
    case 'n':  *code_point_out = '\n'; break;
    case 'r':  *code_point_out = '\r'; break;
    case 't':  *code_point_out = '\t'; break;
    case 'u':  return static_tryReadUnicodeEscape(cursor, code_point_out);
    default:   return false;
  }

  *cursor = text + 2;
  return true;
}

static bool static_tryReadUnicodeEscape(const char** cursor, uint32_t* code_point_out)
{
  const char* text = *cursor;

  uint32_t unit;
  if (!static_tryReadHex4(text + 2, &unit))
    return false;
  if (unit == 0)
    return false;
  if (unit >= JSONCANON_LOW_SURROGATE_MIN && unit <= JSONCANON_LOW_SURROGATE_MAX)
    return false;

  if (unit < JSONCANON_HIGH_SURROGATE_MIN || unit > JSONCANON_HIGH_SURROGATE_MAX)
  {
    *code_point_out = unit;
    *cursor = text + JSONCANON_HEX_ESCAPE_LEN;
    return true;
  }

  const char* second = text + JSONCANON_HEX_ESCAPE_LEN;
  if (second[0] != '\\' || second[1] != 'u')
    return false;

  uint32_t low_unit;
  if (!static_tryReadHex4(second + 2, &low_unit))
    return false;
  if (low_unit < JSONCANON_LOW_SURROGATE_MIN || low_unit > JSONCANON_LOW_SURROGATE_MAX)
    return false;

  *code_point_out = JSONCANON_SUPPLEMENTARY_MIN
                  + ((unit - JSONCANON_HIGH_SURROGATE_MIN) << JSONCANON_SURROGATE_DATA_BITS)
                  + (low_unit - JSONCANON_LOW_SURROGATE_MIN);
  *cursor = second + JSONCANON_HEX_ESCAPE_LEN;
  return true;
}

static bool static_tryReadHex4(const char* text, uint32_t* value_out)
{
  uint32_t value = 0;

  for (int i = 0; i < JSONCANON_HEX_ESCAPE_DIGITS; i++)
  {
    int digit = static_hexDigitValue(text[i]);
    if (digit < 0)
      return false;
    value = (value << 4) | (uint32_t)digit;
  }

  *value_out = value;
  return true;
}

static int static_hexDigitValue(char hex_char)
{
  if (hex_char >= '0' && hex_char <= '9')
    return hex_char - '0';
  if (hex_char >= 'a' && hex_char <= 'f')
    return hex_char - 'a' + 10;
  if (hex_char >= 'A' && hex_char <= 'F')
    return hex_char - 'A' + 10;
  return -1;
}

static bool static_writeNumber(JsonReadSpan_t number, JsonBuf_t* json_buf, size_t* float_count)
{
  if (!jsonread_isNumberToken(number.mp_start, number.mp_start + number.m_len))
    return false;

  bool is_float = memchr(number.mp_start, '.', number.m_len) != NULL
               || memchr(number.mp_start, 'e', number.m_len) != NULL
               || memchr(number.mp_start, 'E', number.m_len) != NULL;
  if (is_float)
  {
    if (*float_count == JSONCANON_FLOAT_TOKEN_MAX)
      return false;
    (*float_count)++;
    return static_writeFloat(number, json_buf);
  }

  if (number.m_len == 2 && memcmp(number.mp_start, "-0", 2) == 0)
    return jsonbuf_appendFormat(json_buf, "0");

  return static_appendRaw(number.mp_start, number.m_len, json_buf);
}

static bool static_writeFloat(JsonReadSpan_t number, JsonBuf_t* json_buf)
{
  if (number.m_len > JSONCANON_FLOAT_TEXT_MAX)
    return false;

  char token[JSONCANON_FLOAT_TEXT_MAX + 1];
  memcpy(token, number.mp_start, number.m_len);
  token[number.m_len] = '\0';

  char*  parse_end;
  double value = strtod(token, &parse_end);
  if (*parse_end != '\0' || !isfinite(value))
    return false;

  char scientific_text[JSONCANON_FLOAT_SCIENTIFIC_SIZE];
  if (!static_tryFormatShortest(value, scientific_text))
    return false;

  return static_writeScientificText(scientific_text, json_buf);
}

static bool static_tryFormatShortest(double value, char* scientific_text)
{
  for (int precision = 0; precision <= JSONCANON_FLOAT_MAX_PRECISION; precision++)
  {
    int text_len = snprintf(scientific_text, JSONCANON_FLOAT_SCIENTIFIC_SIZE, "%.*e", precision, value);
    if (text_len < 0 || (size_t)text_len >= JSONCANON_FLOAT_SCIENTIFIC_SIZE)
      return false;

    if (strtod(scientific_text, NULL) == value)
      return true;

    char raised[JSONCANON_FLOAT_SCIENTIFIC_SIZE];
    memcpy(raised, scientific_text, (size_t)text_len + 1);
    if (static_tryRaiseLastDigit(raised) && strtod(raised, NULL) == value)
    {
      memcpy(scientific_text, raised, (size_t)text_len + 1);
      return true;
    }
  }

  return false;
}

static bool static_tryRaiseLastDigit(char* scientific_text)
{
  size_t mantissa_length = strcspn(scientific_text, "e");
  if (scientific_text[mantissa_length] == '\0')
    return false;

  char* first_digit = scientific_text;
  if (*first_digit == '-')
    first_digit++;

  for (char* digit = scientific_text + mantissa_length - 1; digit >= first_digit; digit--)
  {
    if (*digit == '.')
      continue;
    if (*digit != '9')
    {
      (*digit)++;
      return true;
    }
    *digit = '0';
  }

  return false;
}

static bool static_writeScientificText(const char* scientific_text, JsonBuf_t* json_buf)
{
  static const char ZEROES[] = "0000000000000000";

  const char* cursor = scientific_text;
  bool        is_negative = *cursor == '-';
  if (is_negative)
    cursor++;

  char   digits[JSONCANON_FLOAT_MAX_PRECISION + 2];
  size_t digit_count = 0;
  for (; *cursor != 'e'; cursor++)
  {
    if (*cursor != '.')
      digits[digit_count++] = *cursor;
  }
  cursor++;

  bool is_exponent_negative = *cursor == '-';
  cursor++;
  int exponent = 0;
  for (; *cursor != '\0'; cursor++)
    exponent = exponent * 10 + (*cursor - '0');
  if (is_exponent_negative)
    exponent = -exponent;

  int decimal_point = exponent + 1;
  int shown = (int)digit_count;

  if (is_negative && !jsonbuf_appendFormat(json_buf, "-"))
    return false;

  if (decimal_point > JSONCANON_EXPONENT_FORM_DECIMAL_POINT_MAX || decimal_point < JSONCANON_EXPONENT_FORM_DECIMAL_POINT_MIN)
  {
    if (!jsonbuf_appendFormat(json_buf, "%c", digits[0]))
      return false;
    if (shown > 1 && !jsonbuf_appendFormat(json_buf, ".%.*s", shown - 1, digits + 1))
      return false;
    return jsonbuf_appendFormat(json_buf, "e%c%02d", is_exponent_negative ? '-' : '+', abs(exponent));
  }

  if (decimal_point <= 0)
    return jsonbuf_appendFormat(json_buf, "0.%.*s%.*s", -decimal_point, ZEROES, shown, digits);

  if (decimal_point >= shown)
    return jsonbuf_appendFormat(json_buf, "%.*s%.*s.0", shown, digits, decimal_point - shown, ZEROES);

  return jsonbuf_appendFormat(json_buf, "%.*s.%.*s", decimal_point, digits, shown - decimal_point, digits + decimal_point);
}

static bool static_appendRaw(const char* bytes, size_t byte_count, JsonBuf_t* json_buf)
{
  while (byte_count > 0)
  {
    size_t piece = byte_count > JSONCANON_APPEND_CHUNK_MAX ? JSONCANON_APPEND_CHUNK_MAX : byte_count;
    if (!jsonbuf_appendFormat(json_buf, "%.*s", (int)piece, bytes))
      return false;
    bytes      += piece;
    byte_count -= piece;
  }

  return true;
}

static int static_compareMembers(const void* left, const void* right)
{
  const JsonCanonMember_t* left_member  = left;
  const JsonCanonMember_t* right_member = right;

  size_t shared_len = left_member->m_key.m_len < right_member->m_key.m_len
                    ? left_member->m_key.m_len
                    : right_member->m_key.m_len;

  int order = memcmp(left_member->m_key.mp_start, right_member->m_key.mp_start, shared_len);
  if (order != 0)
    return order;
  if (left_member->m_key.m_len == right_member->m_key.m_len)
    return 0;
  return left_member->m_key.m_len < right_member->m_key.m_len ? -1 : 1;
}
