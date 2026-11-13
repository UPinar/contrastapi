#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "utf8.h"

void setUp(void)    {}
void tearDown(void) {}

typedef struct
{
  const char* mp_name;
  const char* mp_bytes;
  size_t      m_remaining;
  bool        m_expectedIsValid;
  uint32_t    m_expectedCodePoint;
  size_t      m_expectedLength;
} Utf8SequenceRow_t;

static const Utf8SequenceRow_t SEQUENCE_TABLE[] = {
  { "ASCII 'A'",                               "A",                1, true,  0x41,     1 },
  { "U+0000 inside the given length",          "\0",               1, true,  0x00,     1 },
  { "U+007F, the last one-byte code point",    "\x7f",             1, true,  0x7F,     1 },
  { "U+0080, the first two-byte code point",   "\xc2\x80",         2, true,  0x80,     2 },
  { "e-acute",                                 "\xc3\xa9",         2, true,  0xE9,     2 },
  { "U+07FF, the last two-byte code point",    "\xdf\xbf",         2, true,  0x7FF,    2 },
  { "U+0800, the first three-byte code point", "\xe0\xa0\x80",     3, true,  0x800,    3 },
  { "euro sign",                               "\xe2\x82\xac",     3, true,  0x20AC,   3 },
  { "U+D7FF, just below the surrogates",       "\xed\x9f\xbf",     3, true,  0xD7FF,   3 },
  { "U+E000, just above the surrogates",       "\xee\x80\x80",     3, true,  0xE000,   3 },
  { "U+FFFF, the last three-byte code point",  "\xef\xbf\xbf",     3, true,  0xFFFF,   3 },
  { "U+10000, the first four-byte code point", "\xf0\x90\x80\x80", 4, true,  0x10000,  4 },
  { "grinning face U+1F600",                   "\xf0\x9f\x98\x80", 4, true,  0x1F600,  4 },
  { "U+E0100, a lead between F0 and F4",       "\xf3\xa0\x84\x80", 4, true,  0xE0100,  4 },
  { "U+10FFFF, the last code point",           "\xf4\x8f\xbf\xbf", 4, true,  0x10FFFF, 4 },

  { "lone continuation byte 0x80",             "\x80",             1, false, 0xFFFD,   1 },
  { "lone continuation byte 0xBF",             "\xbf",             1, false, 0xFFFD,   1 },
  { "overlong lead 0xC0",                      "\xc0\x80",         2, false, 0xFFFD,   1 },
  { "overlong lead 0xC1",                      "\xc1\xbf",         2, false, 0xFFFD,   1 },
  { "lead 0xF5, never used",                   "\xf5\x80\x80\x80", 4, false, 0xFFFD,   1 },
  { "lead 0xFF, never used",                   "\xff",             1, false, 0xFFFD,   1 },

  { "overlong three bytes E0 9F",              "\xe0\x9f\xbf",     3, false, 0xFFFD,   1 },
  { "overlong four bytes F0 8F",               "\xf0\x8f\xbf\xbf", 4, false, 0xFFFD,   1 },
  { "surrogate ED A0",                         "\xed\xa0\x80",     3, false, 0xFFFD,   1 },
  { "above U+10FFFF, F4 90",                   "\xf4\x90\x80\x80", 4, false, 0xFFFD,   1 },
  { "two-byte lead before ASCII",              "\xc3\x41",         2, false, 0xFFFD,   1 },
  { "two-byte lead before 0xC0",               "\xc3\xc0",         2, false, 0xFFFD,   1 },

  { "third byte 0xC0 after E2 82",             "\xe2\x82\xc0",     3, false, 0xFFFD,   1 },
  { "fourth byte 0xC0 after F0 9F 98",         "\xf0\x9f\x98\xc0", 4, false, 0xFFFD,   1 },
  { "three-byte lead cut short by a NUL",      "\xe2\x82\x00",     3, false, 0xFFFD,   1 },

  { "three-byte lead alone at the end",        "\xe2",             1, false, 0xFFFD,   1 },
  { "three-byte lead cut short at the end",    "\xe2\x82",         2, false, 0xFFFD,   1 },
  { "four-byte lead cut short at the end",     "\xf0\x9f\x98",     3, false, 0xFFFD,   1 },
  { "a valid sequence read only in part",      "\xe2\x82\xac",     2, false, 0xFFFD,   1 },
};

void test_readFirstSequence_answers_every_row_of_the_table(void)
{
  for (size_t i = 0; i < sizeof(SEQUENCE_TABLE) / sizeof(SEQUENCE_TABLE[0]); i++)
  {
    const Utf8SequenceRow_t* row      = &SEQUENCE_TABLE[i];
    Utf8Sequence_t           sequence = utf8_readFirstSequence((const unsigned char*)row->mp_bytes, row->m_remaining);
    TEST_ASSERT_TRUE_MESSAGE(sequence.m_isValid == row->m_expectedIsValid, row->mp_name);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(row->m_expectedCodePoint, sequence.m_codePoint, row->mp_name);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(row->m_expectedLength, sequence.m_length, row->mp_name);
  }
}

void test_isTextValid_checks_the_given_length_from_end_to_end(void)
{
  const struct { const char* mp_text; size_t m_len; bool m_isValid; } cases[] = {
    { "",                      0, true  },
    { "abc",                   3, true  },
    { "m\xc3\xbcnchen",        8, true  },
    { "a\0b",                  3, true  },
    { "\xff" "abc",            4, false },
    { "a\xff" "b",             3, false },
    { "abc\xff",               4, false },
    { "abc\xff",               3, true  },
    { "ab\xc3\xa9",            3, false },
    { "ab\xe2\x82",            4, false },
    { "\xc3\xa9\xed\xa0\x80",  5, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char message[64];
    snprintf(message, sizeof(message), "case %zu", i);
    TEST_ASSERT_TRUE_MESSAGE(utf8_isTextValid(cases[i].mp_text, cases[i].m_len) == cases[i].m_isValid, message);
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(3, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_readFirstSequence_answers_every_row_of_the_table);
  RUN_TEST(test_isTextValid_checks_the_given_length_from_end_to_end);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
