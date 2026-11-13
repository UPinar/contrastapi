#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jsonread.h"
#include "jsonrpc.h"

#define FUZZ_JSONREAD_MAX_DEPTH 64

static char* static_copyExact(const uint8_t* data, size_t size)
{
  char* copy = malloc(size > 0 ? size : 1);
  if (copy == NULL)
    abort();
  memcpy(copy, data, size);
  return copy;
}

static void static_readEveryLeaf(JsonReadSpan_t span)
{
  long   long_value   = 0;
  double double_value = 0;
  bool   bool_value   = false;
  char   one_byte[1];

  char* fit = malloc(span.m_len + 1);
  if (fit == NULL)
    abort();
  (void)jsonread_spanToStrStatus(span, fit, span.m_len + 1);
  (void)jsonread_spanToStrStatus(span, one_byte, sizeof(one_byte));
  (void)jsonread_spanToRawStringStatus(span, fit, span.m_len + 1);
  (void)jsonread_spanToRawStringStatus(span, one_byte, sizeof(one_byte));
  free(fit);

  (void)jsonread_spanToLongStatus(span, &long_value);
  (void)jsonread_spanToDoubleStatus(span, &double_value);
  (void)jsonread_spanToBoolStatus(span, &bool_value);
  (void)jsonread_isSpanEqual(span, "null");
  (void)jsonread_isNumberToken(span.mp_start, span.mp_start + span.m_len);
}

static void static_walkValue(JsonReadSpan_t span, int depth)
{
  if (depth > FUZZ_JSONREAD_MAX_DEPTH || span.m_len == 0)
    return;

  static_readEveryLeaf(span);

  if (span.mp_start[0] == '{')
  {
    JsonReadSpan_t key_value;
    (void)jsonread_objectKey(span, "name", &key_value);

    size_t member_offset = 0;
    JsonReadSpan_t key;
    JsonReadSpan_t value;
    while (jsonread_objectNextMember(span, &member_offset, &key, &value) == JSONREAD_OK)
    {
      static_readEveryLeaf(key);
      static_walkValue(value, depth + 1);
    }
  }
  else if (span.mp_start[0] == '[')
  {
    size_t element_count = 0;
    (void)jsonread_arrayLen(span, &element_count);

    size_t element_offset = 0;
    JsonReadSpan_t element;
    while (jsonread_arrayNextElement(span, &element_offset, &element) == JSONREAD_OK)
      static_walkValue(element, depth + 1);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  char* exact = static_copyExact(data, size);

  JsonReadSpan_t root;
  if (jsonread_root(exact, size, &root) == JSONREAD_OK)
    static_walkValue(root, 0);

  JsonRpcRequest_t request;
  (void)jsonrpc_parse(exact, size, &request);
  free(exact);

  char* text = malloc(size + 1);
  if (text == NULL)
    abort();
  memcpy(text, data, size);
  text[size] = '\0';

  char   str_value[32];
  char   one_byte[1];
  long   long_value   = 0;
  double double_value = 0;
  bool   bool_value   = false;
  (void)jsonread_strStatus(text, "name", str_value, sizeof(str_value));
  (void)jsonread_strStatus(text, "name", one_byte, sizeof(one_byte));
  (void)jsonread_intStatus(text, "id", &long_value);
  (void)jsonread_doubleStatus(text, "id", &double_value);
  (void)jsonread_boolStatus(text, "id", &bool_value);
  free(text);

  return 0;
}
