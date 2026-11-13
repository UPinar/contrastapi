#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonbuf.h"
#include "jsonread.h"
#include "utf8.h"

static const char HEX_DIGITS[] = "0123456789abcdef";

#define JSONBUF_ESCAPE_MAX_BYTE_COUNT 6

static const char REPLACEMENT_CHARACTER_BYTES[] = "\xEF\xBF\xBD";

struct JsonBuf {
  char*  mp_data;
  size_t m_len;
  size_t m_capacity;
  size_t m_ceiling;
  bool   m_failed;
};

typedef size_t (*JsonBufSequenceWriterFunction_t)(Utf8Sequence_t sequence, const unsigned char* bytes, char* out);

static bool   static_jsonbufReserve           (JsonBuf_t* json_buf, size_t extra);
static bool   static_jsonbufAppendSequences   (JsonBuf_t* json_buf, const char* str, size_t str_len, JsonBufSequenceWriterFunction_t sequence_writer_function);
static size_t static_jsonbufEscapeSequence    (Utf8Sequence_t sequence, const unsigned char* bytes, char* out);
static size_t static_jsonbufJsonTextSequence  (Utf8Sequence_t sequence, const unsigned char* bytes, char* out);
static size_t static_jsonbufEscapeByte        (unsigned char c, char* out);

JsonBuf_t* jsonbuf_create(size_t initial_cap, size_t ceiling)
{
  if (initial_cap == 0 || ceiling == 0)
  {
    fprintf(stderr, "jsonbuf_create: a size of 0 bytes cannot hold the terminator\n");
    return NULL;
  }

  if (ceiling > JSONBUF_MAX_CEILING)
    ceiling = JSONBUF_MAX_CEILING;

  if (initial_cap > ceiling)
    initial_cap = ceiling;

  JsonBuf_t* json_buf = malloc(sizeof(*json_buf));
  if (!json_buf)
  {
    fprintf(stderr, "jsonbuf_create: malloc of the buffer handle failed\n");
    return NULL;
  }

  json_buf->mp_data = malloc(initial_cap);
  if (!json_buf->mp_data)
  {
    fprintf(stderr, "jsonbuf_create: malloc of %zu bytes failed\n", initial_cap);
    free(json_buf);
    return NULL;
  }

  json_buf->m_len      = 0;
  json_buf->m_capacity = initial_cap;
  json_buf->m_ceiling  = ceiling;
  json_buf->m_failed   = false;

  json_buf->mp_data[0] = '\0';
  return json_buf;
}

char* jsonbuf_finish(JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);

  char* body = json_buf->mp_data;

  if (json_buf->m_failed)
  {
    free(body);
    body = NULL;
  }

  json_buf->mp_data    = NULL;
  json_buf->m_len      = 0;
  json_buf->m_capacity = 0;
  json_buf->m_ceiling  = 0;
  json_buf->m_failed   = true;

  return body;
}

void jsonbuf_destroy(JsonBuf_t* json_buf)
{
  if (!json_buf)
    return;

  free(json_buf->mp_data);
  free(json_buf);
}

size_t jsonbuf_length(const JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);
  return json_buf->m_len;
}

size_t jsonbuf_capacity(const JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);
  return json_buf->m_capacity;
}

size_t jsonbuf_ceiling(const JsonBuf_t* json_buf)
{
  assert(json_buf != NULL);
  return json_buf->m_ceiling;
}

bool jsonbuf_appendFormat(JsonBuf_t* json_buf, const char* fmt, ...)
{
  assert(json_buf != NULL);
  assert(fmt != NULL);

  if (json_buf->m_failed)
    return false;

  if (!json_buf->mp_data)
  {
    json_buf->m_failed = true;
    return false;
  }

  if (json_buf->m_len >= json_buf->m_capacity)
  {
    fprintf(stderr, "jsonbuf_appendFormat: m_len %zu is not below m_capacity %zu\n",
            json_buf->m_len, json_buf->m_capacity);
    json_buf->m_failed = true;
    return false;
  }

  size_t  available_bytes = json_buf->m_capacity - json_buf->m_len;
  va_list probe_args;
  va_start(probe_args, fmt);
  int needed_chars = vsnprintf(json_buf->mp_data + json_buf->m_len, available_bytes, fmt, probe_args);
  va_end(probe_args);

  if (needed_chars < 0)
  {
    json_buf->mp_data[json_buf->m_len] = '\0';
    json_buf->m_failed = true;
    return false;
  }

  if (!static_jsonbufReserve(json_buf, (size_t)needed_chars))
  {
    json_buf->mp_data[json_buf->m_len] = '\0';
    return false;
  }

  if ((size_t)needed_chars < available_bytes)
  {
    json_buf->m_len += (size_t)needed_chars;
    return true;
  }

  va_list write_args;
  va_start(write_args, fmt);
  int written_chars = vsnprintf(json_buf->mp_data + json_buf->m_len, json_buf->m_capacity - json_buf->m_len, fmt, write_args);
  va_end(write_args);

  if ((size_t)written_chars >= json_buf->m_capacity - json_buf->m_len)
  {
    json_buf->mp_data[json_buf->m_len] = '\0';
    json_buf->m_failed = true;
    return false;
  }

  json_buf->m_len += (size_t)written_chars;
  return true;
}

bool jsonbuf_appendEscaped(JsonBuf_t* json_buf, const char* str)
{
  size_t byte_count = str != NULL ? strlen(str) : 0;
  return jsonbuf_appendEscapedBytes(json_buf, str, byte_count);
}

bool jsonbuf_appendEscapedBytes(JsonBuf_t* json_buf, const char* bytes, size_t byte_count)
{
  assert(json_buf != NULL);

  if (json_buf->m_failed)
    return false;

  if (!json_buf->mp_data)
  {
    json_buf->m_failed = true;
    return false;
  }

  if (json_buf->m_len >= json_buf->m_capacity)
  {
    fprintf(stderr, "jsonbuf_appendEscapedBytes: m_len %zu is not below m_capacity %zu\n", json_buf->m_len, json_buf->m_capacity);
    json_buf->m_failed = true;
    return false;
  }

  if (!bytes)
    return true;

  return static_jsonbufAppendSequences(json_buf, bytes, byte_count, static_jsonbufEscapeSequence);
}

bool jsonbuf_appendJsonText(JsonBuf_t* json_buf, const char* json_text)
{
  assert(json_buf != NULL);

  if (json_buf->m_failed)
    return false;

  if (!json_buf->mp_data)
  {
    json_buf->m_failed = true;
    return false;
  }

  if (json_buf->m_len >= json_buf->m_capacity)
  {
    fprintf(stderr, "jsonbuf_appendJsonText: m_len %zu is not below m_capacity %zu\n", json_buf->m_len, json_buf->m_capacity);
    json_buf->m_failed = true;
    return false;
  }

  if (!json_text)
    return true;

  return static_jsonbufAppendSequences(json_buf, json_text, strlen(json_text), static_jsonbufJsonTextSequence);
}

bool jsonbuf_isCodePointHidden(uint32_t code_point)
{
  return code_point == 0x7F
      || (code_point >= 0x200B && code_point <= 0x200D)
      || (code_point >= 0x2028 && code_point <= 0x202E)
      || code_point == 0x2060
      || (code_point >= 0x2066 && code_point <= 0x2069)
      || code_point == 0xFEFF;
}

static bool static_jsonbufReserve(JsonBuf_t* json_buf, size_t extra)
{
  size_t effective_ceiling = json_buf->m_ceiling < JSONBUF_MAX_CEILING ? json_buf->m_ceiling : JSONBUF_MAX_CEILING;

  if (json_buf->m_len + extra + 1 > effective_ceiling)
  {
    fprintf(stderr, "static_jsonbufReserve: ceiling of %zu bytes reached\n", effective_ceiling);
    json_buf->m_failed = true;
    return false;
  }

  if (json_buf->m_len + extra + 1 > json_buf->m_capacity)
  {
    size_t new_capacity = json_buf->m_capacity * 2 + extra + 1;
    if (new_capacity > effective_ceiling)
      new_capacity = effective_ceiling;

    char* expanded_data = realloc(json_buf->mp_data, new_capacity);
    if (!expanded_data)
    {
      fprintf(stderr, "static_jsonbufReserve: realloc to %zu bytes failed\n", new_capacity);
      json_buf->m_failed = true;
      return false;
    }
    json_buf->mp_data = expanded_data;
    json_buf->m_capacity   = new_capacity;
  }

  return true;
}

static bool static_jsonbufAppendSequences(JsonBuf_t* json_buf, const char* str, size_t str_len, JsonBufSequenceWriterFunction_t sequence_writer_function)
{
  const unsigned char* input = (const unsigned char*)str;
  size_t input_len = str_len;

  size_t written_len = 0;
  char scratch[JSONBUF_ESCAPE_MAX_BYTE_COUNT];
  for (size_t read_pos = 0; read_pos < input_len; )
  {
    Utf8Sequence_t sequence = utf8_readFirstSequence(input + read_pos, input_len - read_pos);
    written_len += sequence_writer_function(sequence, input + read_pos, scratch);
    read_pos    += sequence.m_length;
  }

  if (!static_jsonbufReserve(json_buf, written_len))
    return false;

  char* write_cursor = json_buf->mp_data + json_buf->m_len;
  for (size_t read_pos = 0; read_pos < input_len; )
  {
    Utf8Sequence_t sequence = utf8_readFirstSequence(input + read_pos, input_len - read_pos);
    write_cursor += sequence_writer_function(sequence, input + read_pos, write_cursor);
    read_pos     += sequence.m_length;
  }

  json_buf->m_len += written_len;
  json_buf->mp_data[json_buf->m_len] = '\0';
  return true;
}

static size_t static_jsonbufEscapeSequence(Utf8Sequence_t sequence, const unsigned char* bytes, char* out)
{
  uint32_t code_point         = sequence.m_codePoint;
  size_t   written_byte_count = 0;

  if (!sequence.m_isValid)
  {
    written_byte_count = sizeof(REPLACEMENT_CHARACTER_BYTES) - 1;
    memcpy(out, REPLACEMENT_CHARACTER_BYTES, written_byte_count);
  }
  else if (jsonbuf_isCodePointHidden(code_point))
  {
    assert(code_point <= 0xFFFF);
    out[0] = '\\';
    out[1] = 'u';
    out[2] = HEX_DIGITS[(code_point >> 12) & 0x0f];
    out[3] = HEX_DIGITS[(code_point >> 8) & 0x0f];
    out[4] = HEX_DIGITS[(code_point >> 4) & 0x0f];
    out[5] = HEX_DIGITS[code_point & 0x0f];
    written_byte_count = JSONBUF_ESCAPE_MAX_BYTE_COUNT;
  }
  else if (sequence.m_length == 1)
    written_byte_count = static_jsonbufEscapeByte(bytes[0], out);
  else
  {
    written_byte_count = sequence.m_length;
    memcpy(out, bytes, written_byte_count);
  }

  assert(written_byte_count <= JSONBUF_ESCAPE_MAX_BYTE_COUNT);
  return written_byte_count;
}

static size_t static_jsonbufJsonTextSequence(Utf8Sequence_t sequence, const unsigned char* bytes, char* out)
{
  if (!sequence.m_isValid || jsonbuf_isCodePointHidden(sequence.m_codePoint))
    return static_jsonbufEscapeSequence(sequence, bytes, out);

  assert(sequence.m_length <= JSONBUF_ESCAPE_MAX_BYTE_COUNT);
  memcpy(out, bytes, sequence.m_length);
  return sequence.m_length;
}

static size_t static_jsonbufEscapeByte(unsigned char c, char* out)
{
  assert(c < 0x80 && c != 0x7F);

  char shortcut = '\0';
  switch (c)
  {
    case '"':  shortcut = '"';  break;
    case '\\': shortcut = '\\'; break;
    case '\b': shortcut = 'b';  break;
    case '\f': shortcut = 'f';  break;
    case '\n': shortcut = 'n';  break;
    case '\r': shortcut = 'r';  break;
    case '\t': shortcut = 't';  break;
    default:   break;
  }

  if (shortcut != '\0')
  {
    out[0] = '\\';
    out[1] = shortcut;
    return 2;
  }
  else if (c < JSON_MIN_UNESCAPED_CHAR)
  {
    out[0] = '\\';
    out[1] = 'u';
    out[2] = '0';
    out[3] = '0';
    out[4] = HEX_DIGITS[c >> 4];
    out[5] = HEX_DIGITS[c & 0x0f];
    return JSONBUF_ESCAPE_MAX_BYTE_COUNT;
  }
  else
  {
    out[0] = (char)c;
    return 1;
  }
}
