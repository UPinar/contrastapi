#include <assert.h>

#include "utf8.h"

#define UTF8_ONE_BYTE_MAX 0x7F

#define UTF8_CONTINUATION_BYTE_MIN 0x80
#define UTF8_CONTINUATION_BYTE_MAX 0xBF

#define UTF8_CONTINUATION_BYTE_DATA_BITS 6
#define UTF8_CONTINUATION_BYTE_DATA_MASK 0x3F

typedef struct
{
  unsigned char m_leadByteMin;
  unsigned char m_leadByteMax;
  unsigned char m_secondByteMin;
  unsigned char m_secondByteMax;
  size_t        m_sequenceLength;
} Utf8LeadByteRow_t;

static const Utf8LeadByteRow_t LEAD_BYTE_TABLE[] = {
  { 0xC2, 0xDF,   UTF8_CONTINUATION_BYTE_MIN, UTF8_CONTINUATION_BYTE_MAX,   2 },
  { 0xE0, 0xE0,   0xA0,                       UTF8_CONTINUATION_BYTE_MAX,   3 },
  { 0xE1, 0xEC,   UTF8_CONTINUATION_BYTE_MIN, UTF8_CONTINUATION_BYTE_MAX,   3 },
  { 0xED, 0xED,   UTF8_CONTINUATION_BYTE_MIN, 0x9F,                         3 },
  { 0xEE, 0xEF,   UTF8_CONTINUATION_BYTE_MIN, UTF8_CONTINUATION_BYTE_MAX,   3 },
  { 0xF0, 0xF0,   0x90,                       UTF8_CONTINUATION_BYTE_MAX,   4 },
  { 0xF1, 0xF3,   UTF8_CONTINUATION_BYTE_MIN, UTF8_CONTINUATION_BYTE_MAX,   4 },
  { 0xF4, 0xF4,   UTF8_CONTINUATION_BYTE_MIN, 0x8F,                         4 },
};

static const Utf8LeadByteRow_t* static_findLeadByteRow(unsigned char lead_byte);

Utf8Sequence_t utf8_readFirstSequence(const unsigned char* text, size_t remaining)
{
  assert(text != NULL);
  assert(remaining > 0);

  const Utf8Sequence_t invalid = { false, UTF8_REPLACEMENT_CHARACTER, 1 };
  unsigned char lead_byte = text[0];

  if (lead_byte <= UTF8_ONE_BYTE_MAX)
    return (Utf8Sequence_t){ true, lead_byte, 1 };

  const Utf8LeadByteRow_t* row = static_findLeadByteRow(lead_byte);
  if (row == NULL)
    return invalid;

  uint32_t code_point = lead_byte & (0x7F >> row->m_sequenceLength);
  for (size_t i = 1; i < row->m_sequenceLength; i++)
  {
    unsigned char low  = i == 1 ? row->m_secondByteMin : UTF8_CONTINUATION_BYTE_MIN;
    unsigned char high = i == 1 ? row->m_secondByteMax : UTF8_CONTINUATION_BYTE_MAX;
    if (i >= remaining || text[i] < low || text[i] > high)
      return invalid;
    code_point = (code_point << UTF8_CONTINUATION_BYTE_DATA_BITS) | (text[i] & UTF8_CONTINUATION_BYTE_DATA_MASK);
  }

  return (Utf8Sequence_t){ true, code_point, row->m_sequenceLength };
}

bool utf8_isTextValid(const char* text, size_t len)
{
  assert(text != NULL);

  const unsigned char* bytes    = (const unsigned char*)text;
  size_t               position = 0;
  while (position < len)
  {
    Utf8Sequence_t sequence = utf8_readFirstSequence(bytes + position, len - position);
    if (!sequence.m_isValid)
      return false;
    position += sequence.m_length;
  }
  return true;
}

static const Utf8LeadByteRow_t* static_findLeadByteRow(unsigned char lead_byte)
{
  for (size_t i = 0; i < sizeof(LEAD_BYTE_TABLE) / sizeof(LEAD_BYTE_TABLE[0]); i++)
  {
    if (lead_byte >= LEAD_BYTE_TABLE[i].m_leadByteMin && lead_byte <= LEAD_BYTE_TABLE[i].m_leadByteMax)
      return &LEAD_BYTE_TABLE[i];
  }
  return NULL;
}
