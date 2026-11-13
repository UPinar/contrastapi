#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "query.h"

#define FUZZ_QUERY_NAME_BUF_SIZE 64

#define FUZZ_QUERY_VALUE_BUF_SIZE 64

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  char value[FUZZ_QUERY_VALUE_BUF_SIZE];
  char one_byte[1];

  char* exact = malloc(size > 0 ? size : 1);
  if (exact == NULL)
    abort();
  memcpy(exact, data, size);
  (void)query_percentDecode(exact, size, true, value, sizeof(value));
  (void)query_percentDecode(exact, size, false, one_byte, sizeof(one_byte));
  free(exact);

  char* query = malloc(size + 1);
  if (query == NULL)
    abort();
  memcpy(query, data, size);
  query[size] = '\0';

  size_t name_offset = 0;
  QueryParamName_t name;
  while (query_nextParamName(query, &name_offset, &name))
  {
    char name_text[FUZZ_QUERY_NAME_BUF_SIZE];
    size_t name_len = name.m_len < sizeof(name_text) - 1 ? name.m_len : sizeof(name_text) - 1;
    memcpy(name_text, name.mp_start, name_len);
    name_text[name_len] = '\0';

    (void)query_paramGetStatus(query, name_text, value, sizeof(value));
    (void)query_paramGetStatus(query, name_text, one_byte, sizeof(one_byte));
  }
  free(query);

  return 0;
}
