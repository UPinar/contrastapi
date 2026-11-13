#ifndef UTF8_H
#define UTF8_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UTF8_REPLACEMENT_CHARACTER 0xFFFDu

typedef struct
{
  bool     m_isValid;
  uint32_t m_codePoint;
  size_t   m_length;
} Utf8Sequence_t;

Utf8Sequence_t utf8_readFirstSequence(const unsigned char* text, size_t remaining);
bool           utf8_isTextValid      (const char* text, size_t len);

#endif
