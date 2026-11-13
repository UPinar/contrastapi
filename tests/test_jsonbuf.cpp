#include <stdio.h>
#include <string.h>

#include "unity/unity.h"

extern "C" {
#include "jsonbuf.h"
#include "http.h"
void* __real_realloc(void* ptr, size_t size);
void* __wrap_realloc(void* ptr, size_t size);
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size);
}

static int g_reallocFailAfter = -1;
static int g_mallocFailAfter  = -1;

extern "C" void* __wrap_realloc(void* ptr, size_t size)
{
  if (g_reallocFailAfter < 0)
    return __real_realloc(ptr, size);

  if (g_reallocFailAfter == 0)
  {
    g_reallocFailAfter = -1;
    return NULL;
  }

  g_reallocFailAfter--;
  return __real_realloc(ptr, size);
}

static bool g_dirtyMalloc = false;

extern "C" void* __wrap_malloc(size_t size)
{
  if (g_mallocFailAfter == 0)
  {
    g_mallocFailAfter = -1;
    return NULL;
  }

  if (g_mallocFailAfter > 0)
    g_mallocFailAfter--;

  void* allocated = __real_malloc(size);
  if (allocated && g_dirtyMalloc)
    memset(allocated, 'Z', size);

  return allocated;
}

void setUp(void)    { g_reallocFailAfter = -1; g_mallocFailAfter = -1; g_dirtyMalloc = false; }
void tearDown(void) { g_reallocFailAfter = -1; g_mallocFailAfter = -1; g_dirtyMalloc = false; }

static const char DIGITS_10[] = "0123456789";
static const char DIGITS_25[] = "0123456789012345678901234";
static const char DIGITS_29[] = "01234567890123456789012345678";
static const char DIGITS_40[] = "0123456789012345678901234567890123456789";
static const char HEX_16[]    = "0123456789abcdef";

static_assert(sizeof(DIGITS_10) - 1 == 10, "DIGITS_10 must stay 10 bytes");
static_assert(sizeof(DIGITS_25) - 1 == 25, "DIGITS_25 must stay 25 bytes");
static_assert(sizeof(DIGITS_29) - 1 == 29, "DIGITS_29 must stay 29 bytes");
static_assert(sizeof(DIGITS_40) - 1 == 40, "DIGITS_40 must stay 40 bytes");
static_assert(sizeof(HEX_16)    - 1 == 16, "HEX_16 must stay 16 bytes");

void test_create_allocates_empty_terminated_buffer(void)
{
  g_dirtyMalloc = true;
  JsonBuf_t* buf = jsonbuf_create(64, 128);
  g_dirtyMalloc = false;

  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, jsonbuf_length(buf), "create must write m_len");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(64, jsonbuf_capacity(buf), "create must write m_capacity");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(128, jsonbuf_ceiling(buf), "create must write m_ceiling");
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendFormat(buf, "x"), "create must write m_failed");

  jsonbuf_destroy(buf);
}

void test_finish_detaches_body_and_leaves_buffer_inert(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);

  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "abc"));

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(body, "a healthy buffer must hand its body over");
  TEST_ASSERT_EQUAL_STRING("abc", body);

  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, jsonbuf_length(buf), "a detached buffer must not keep a stale m_len");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, jsonbuf_capacity(buf), "a detached buffer must not keep a stale m_capacity");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, jsonbuf_ceiling(buf), "a detached buffer must not keep a stale ceiling");

  TEST_ASSERT_FALSE_MESSAGE(jsonbuf_appendFormat(buf, "def"), "appendFormat after finish must be inert");
  TEST_ASSERT_FALSE_MESSAGE(jsonbuf_appendEscaped(buf, "def"), "appendEscaped after finish must be inert");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "finishing twice must not hand the body out twice");

  free(body);
  jsonbuf_destroy(buf);
}

void test_finish_returns_null_on_a_failed_buffer(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 32);

  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, DIGITS_10));
  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "%s", DIGITS_25));

  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "a failed buffer must not hand a truncated body over");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, jsonbuf_length(buf), "the refused buffer must be left inert");

  jsonbuf_destroy(buf);
}

void test_destroy_of_null_is_a_noop(void)
{
  jsonbuf_destroy(NULL);
  TEST_PASS();
}

void test_appendFormat_formats_and_advances(void)
{
  JsonBuf_t* buf = jsonbuf_create(64, 128);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, R"("count":%d,)", 42));
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, R"("epss":%.5f)", 0.5));

  TEST_ASSERT_EQUAL_size_t(strlen(R"("count":42,"epss":0.50000)"), jsonbuf_length(buf));

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_EQUAL_STRING(R"("count":42,"epss":0.50000)", body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_growth_past_initial_capacity_preserves_content(void)
{
  char expected[5001] = "";

  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  for (int chunk_index = 0; chunk_index < 500; chunk_index++)
  {
    TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, DIGITS_10));
    strcat(expected, DIGITS_10);
  }

  TEST_ASSERT_TRUE(jsonbuf_capacity(buf) > JSONBUF_INITIAL_CAP);
  TEST_ASSERT_EQUAL_size_t(5000, jsonbuf_length(buf));

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(expected, body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_ceiling_refuses_append_and_sets_failed(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 32);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, DIGITS_10));

  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "%s", DIGITS_25));
  TEST_ASSERT_EQUAL_size_t_MESSAGE(10, jsonbuf_length(buf), "a refused append must not move the length");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "the refusal must stick all the way to the handoff");

  jsonbuf_destroy(buf);
}

void test_realloc_failure_during_growth_sets_failed(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);
  g_reallocFailAfter = 1;

  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "%s", DIGITS_40));
  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "%s", DIGITS_40));
  TEST_ASSERT_EQUAL_size_t(40, jsonbuf_length(buf));
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "a lost allocation must reach the handoff as NULL");

  jsonbuf_destroy(buf);
}

void test_failed_buffer_ignores_later_appends(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 32);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "01234"));
  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "%s", DIGITS_29));

  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "xy"));
  TEST_ASSERT_FALSE(jsonbuf_appendEscaped(buf, "z"));
  TEST_ASSERT_FALSE(jsonbuf_appendJsonText(buf, "w"));
  TEST_ASSERT_EQUAL_size_t_MESSAGE(5, jsonbuf_length(buf), "an absorbed append must not move the length");

  jsonbuf_destroy(buf);
}

static void static_expectedEscape(unsigned char byte_value, char* out, size_t out_size)
{
  const char* shortcut = NULL;
  switch (byte_value)
  {
    case '"':  shortcut = "\\\""; break;
    case '\\': shortcut = "\\\\"; break;
    case '\b': shortcut = "\\b";  break;
    case '\f': shortcut = "\\f";  break;
    case '\n': shortcut = "\\n";  break;
    case '\r': shortcut = "\\r";  break;
    case '\t': shortcut = "\\t";  break;
    default:   break;
  }

  if (shortcut)
    snprintf(out, out_size, "%s", shortcut);
  else if (byte_value < 0x20 || byte_value == 0x7f)
    snprintf(out, out_size, "\\u%04x", (unsigned int)byte_value);
  else if (byte_value >= 0x80)
    snprintf(out, out_size, "\xef\xbf\xbd");
  else
    snprintf(out, out_size, "%c", byte_value);
}

void test_every_byte_follows_the_escape_rule(void)
{
  for (int byte_value = 1; byte_value < 256; byte_value++)
  {
    char input[2]     = { (char)byte_value, '\0' };
    char expected[16] = "";
    char message[64]  = "";

    static_expectedEscape((unsigned char)byte_value, expected, sizeof(expected));

    JsonBuf_t* buf = jsonbuf_create(4, 64);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE(jsonbuf_appendEscaped(buf, input));

    snprintf(message, sizeof(message), "byte 0x%02x escaped differently", (unsigned int)byte_value);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(strlen(expected), jsonbuf_length(buf), message);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < jsonbuf_capacity(buf), message);

    char* body = jsonbuf_finish(buf);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, body, message);
    free(body);
    jsonbuf_destroy(buf);
  }
}

typedef struct
{
  const char* mp_name;
  const char* mp_input;
  const char* mp_expected;
} EscapeRow_t;

static const EscapeRow_t ESCAPE_TABLE[] = {
  { "plain ASCII",                          "a",          "a"              },
  { "0x20, the first byte copied as is",    " ",          " "              },
  { "quotation mark",                       "\"",         "\\\""           },
  { "reverse solidus",                      "\\",         "\\\\"           },
  { "solidus, which JSON may leave as is",  "/",          "/"              },
  { "backspace",                            "\b",         "\\b"            },
  { "horizontal tab",                       "\t",         "\\t"            },
  { "line feed",                            "\n",         "\\n"            },
  { "form feed",                            "\f",         "\\f"            },
  { "carriage return",                      "\r",         "\\r"            },
  { "0x01, the lowest control byte",        "\x01",       "\\u0001"        },
  { "0x0b, between two shortcuts",          "\x0b",       "\\u000b"        },
  { "0x1f, the highest control byte",       "\x1f",       "\\u001f"        },
  { "0x7f, hidden though JSON need not escape it", "\x7f", "\\u007f"        },
  { "0x80, a lone continuation byte",       "\x80",       "\xef\xbf\xbd"   },
  { "0xff, which never starts a sequence",  "\xff",       "\xef\xbf\xbd"   },
  { "e-acute, two UTF-8 bytes",             "\xc3\xa9",   "\xc3\xa9"       },
  { "euro sign, three UTF-8 bytes",         "\xe2\x82\xac", "\xe2\x82\xac" },
  { "U+1F600, four UTF-8 bytes",            "\xf0\x9f\x98\x80", "\xf0\x9f\x98\x80" },
  { "U+FFFD sent as valid UTF-8",           "\xef\xbf\xbd", "\xef\xbf\xbd" },
  { "overlong C0 80, one U+FFFD per byte",  "\xc0\x80",   "\xef\xbf\xbd\xef\xbf\xbd" },
  { "overlong E0 80 80, one U+FFFD per byte", "\xe0\x80\x80", "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" },
  { "surrogate ED A0 80, one U+FFFD per byte", "\xed\xa0\x80", "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" },
  { "above U+10FFFF, one U+FFFD per byte",  "\xf4\x90\x80\x80", "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" },
  { "a sequence cut short by the end, one U+FFFD per byte", "a\xe2\x82", "a\xef\xbf\xbd\xef\xbf\xbd" },
  { "a sequence cut short by ASCII, one U+FFFD per byte", "\xe2\x82" "b", "\xef\xbf\xbd\xef\xbf\xbd" "b" },
  { "a four-byte sequence cut short, one U+FFFD per byte", "\xf0\x9f\x98" "!", "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd!" },
  { "U+200B, zero width space",             "\xe2\x80\x8b", "\\u200b"        },
  { "U+200D, zero width joiner",            "\xe2\x80\x8d", "\\u200d"        },
  { "U+2028, line separator",               "\xe2\x80\xa8", "\\u2028"        },
  { "U+2029, paragraph separator",          "\xe2\x80\xa9", "\\u2029"        },
  { "U+202A, the first bidi embedding",     "\xe2\x80\xaa", "\\u202a"        },
  { "U+202E, right-to-left override",       "\xe2\x80\xae", "\\u202e"        },
  { "U+2060, word joiner",                  "\xe2\x81\xa0", "\\u2060"        },
  { "U+2066, the first bidi isolate",       "\xe2\x81\xa6", "\\u2066"        },
  { "U+2069, the last bidi isolate",        "\xe2\x81\xa9", "\\u2069"        },
  { "U+FEFF, byte order mark",              "\xef\xbb\xbf", "\\ufeff"        },
  { "U+202F, just past the bidi range",     "\xe2\x80\xaf", "\xe2\x80\xaf"   },
  { "hidden code point between text",       "a\xe2\x80\xae" "b", "a\\u202eb" },
  { "a run that mixes three classes",       "a\"b\\c\n",  "a\\\"b\\\\c\\n" },
  { "empty string",                         "",           ""               },
  { "a \\u00XX escape followed by more bytes", "a\x01" "b\x1f" "c", "a\\u0001b\\u001fc" },
};

void test_escape_table_row_by_row(void)
{
  for (size_t i = 0; i < sizeof(ESCAPE_TABLE) / sizeof(ESCAPE_TABLE[0]); i++)
  {
    const EscapeRow_t* row = &ESCAPE_TABLE[i];

    JsonBuf_t* buf = jsonbuf_create(4, 64);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendEscaped(buf, row->mp_input), row->mp_name);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(strlen(row->mp_expected), jsonbuf_length(buf), row->mp_name);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < jsonbuf_capacity(buf), row->mp_name);

    char* body = jsonbuf_finish(buf);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(row->mp_expected, body, row->mp_name);
    free(body);
    jsonbuf_destroy(buf);
  }
}

static const EscapeRow_t JSON_TEXT_TABLE[] = {
  { "punctuation, quotes and escapes copied", R"(["a\"b","c\\d",{"k":[1,null]}])", R"(["a\"b","c\\d",{"k":[1,null]}])" },
  { "a \\u escape copied",                    "[\"\\u00e9\"]", "[\"\\u00e9\"]" },
  { "a line feed between members copied",     "[1,\n2]",          "[1,\n2]"          },
  { "e-acute copied",                         "[\"\xc3\xa9\"]", "[\"\xc3\xa9\"]" },
  { "U+1F600 copied",                         "[\"\xf0\x9f\x98\x80\"]", "[\"\xf0\x9f\x98\x80\"]" },
  { "U+202E becomes its escape",              "[\"a\xe2\x80\xae" "b\"]", "[\"a\\u202eb\"]" },
  { "U+FEFF becomes its escape",              "[\"\xef\xbb\xbf\"]", "[\"\\ufeff\"]" },
  { "0x7f becomes its escape",                "[\"\x7f\"]",      "[\"\\u007f\"]" },
  { "0xff becomes U+FFFD",                    "[\"\xff\"]",      "[\"\xef\xbf\xbd\"]" },
  { "a cut sequence, one U+FFFD per byte",    "[\"\xe2\x82\"]", "[\"\xef\xbf\xbd\xef\xbf\xbd\"]" },
  { "empty string",                           "",                 ""                 },
};

void test_appendJsonText_table_row_by_row(void)
{
  for (size_t i = 0; i < sizeof(JSON_TEXT_TABLE) / sizeof(JSON_TEXT_TABLE[0]); i++)
  {
    const EscapeRow_t* row = &JSON_TEXT_TABLE[i];

    JsonBuf_t* buf = jsonbuf_create(4, 64);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendJsonText(buf, row->mp_input), row->mp_name);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(strlen(row->mp_expected), jsonbuf_length(buf), row->mp_name);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < jsonbuf_capacity(buf), row->mp_name);

    char* body = jsonbuf_finish(buf);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(row->mp_expected, body, row->mp_name);
    free(body);
    jsonbuf_destroy(buf);
  }
}

void test_appendJsonText_treats_null_as_empty(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "ab"));

  TEST_ASSERT_TRUE(jsonbuf_appendJsonText(buf, NULL));
  TEST_ASSERT_EQUAL_size_t(2, jsonbuf_length(buf));

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_EQUAL_STRING("ab", body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_ceiling_refuses_appendJsonText_too(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 32);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, DIGITS_10));

  TEST_ASSERT_FALSE(jsonbuf_appendJsonText(buf, DIGITS_25));
  TEST_ASSERT_EQUAL_size_t(10, jsonbuf_length(buf));
  TEST_ASSERT_NULL(jsonbuf_finish(buf));

  jsonbuf_destroy(buf);
}

void test_appendJsonText_on_detached_buffer_is_inert(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);
  TEST_ASSERT_NOT_NULL(buf);
  free(jsonbuf_finish(buf));

  TEST_ASSERT_FALSE(jsonbuf_appendJsonText(buf, "[1]"));
  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(buf));
  TEST_ASSERT_NULL(jsonbuf_finish(buf));

  jsonbuf_destroy(buf);
}

void test_isCodePointHidden_pins_every_range_edge(void)
{
  const struct { uint32_t m_codePoint; bool m_isHidden; } cases[] = {
    { 0x7E,   false }, { 0x7F,   true  }, { 0x80,   false },
    { 0x200A, false }, { 0x200B, true  }, { 0x200D, true  }, { 0x200E, false },
    { 0x2027, false }, { 0x2028, true  }, { 0x2029, true  }, { 0x202A, true  }, { 0x202E, true  }, { 0x202F, false },
    { 0x205F, false }, { 0x2060, true  }, { 0x2061, false },
    { 0x2065, false }, { 0x2066, true  }, { 0x2069, true  }, { 0x206A, false },
    { 0xFEFE, false }, { 0xFEFF, true  }, { 0xFF00, false },
    { 0x41,   false }, { 0xFFFD, false }, { 0x1F600, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char message[32];
    snprintf(message, sizeof(message), "U+%04X", (unsigned int)cases[i].m_codePoint);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_isCodePointHidden(cases[i].m_codePoint) == cases[i].m_isHidden, message);
  }
}

void test_every_append_leaves_buffer_nul_terminated(void)
{
  static const char* const STAGE_NAMES[] = {
    "after an appendFormat that fitted",
    "after an appendEscaped that grew the buffer",
    "after the closing appendFormat",
  };

  for (int stage = 0; stage < 3; stage++)
  {
    JsonBuf_t* buf = jsonbuf_create(8, 4096);
    TEST_ASSERT_NOT_NULL(buf);

    TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, R"({"id":")"));
    if (stage >= 1)
      TEST_ASSERT_TRUE(jsonbuf_appendEscaped(buf, "CVE-2021-44228"));
    if (stage >= 2)
      TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, R"("})"));

    if (stage == 0)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(8, jsonbuf_capacity(buf),
        "7 bytes + NUL exactly fills the capacity and must not trigger a growth");

    size_t length = jsonbuf_length(buf);
    char*  body   = jsonbuf_finish(buf);

    TEST_ASSERT_NOT_NULL_MESSAGE(body, STAGE_NAMES[stage]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(length, strlen(body), STAGE_NAMES[stage]);
    if (stage == 2)
      TEST_ASSERT_EQUAL_STRING(R"({"id":"CVE-2021-44228"})", body);

    free(body);
    jsonbuf_destroy(buf);
  }
}

void test_ceiling_bounds_len_and_cap_not_just_the_reserve_call(void)
{
  JsonBuf_t* buf = jsonbuf_create(64, 512);
  TEST_ASSERT_NOT_NULL(buf);

  for (int append_index = 0; append_index < 64; append_index++)
  {
    (void)jsonbuf_appendFormat(buf, "%s", DIGITS_40);

    if (append_index == 0)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(64, jsonbuf_capacity(buf), "the first append fits, so nothing grows");
    else if (append_index == 1)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(169, jsonbuf_capacity(buf), "growth is m_capacity * 2 + extra + 1, not a doubling");
    else if (append_index == 4)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(379, jsonbuf_capacity(buf), "the next step is 169 * 2 + 41, not 338");
    else if (append_index == 9)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(512, jsonbuf_capacity(buf), "the last step is clamped to the ceiling");
  }

  TEST_ASSERT_EQUAL_size_t_MESSAGE(480, jsonbuf_length(buf), "a refused append must not move m_len");
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < 512, "m_len walked past the ceiling");
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_capacity(buf) <= 512, "m_capacity grew past the ceiling");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "the ceiling must have been hit");

  jsonbuf_destroy(buf);
}

void test_appendFormat_on_detached_buffer_is_inert(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);

  TEST_ASSERT_NOT_NULL(buf);
  free(jsonbuf_finish(buf));

  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "x"));
  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(buf));
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "a detached buffer must not come back to life");

  jsonbuf_destroy(buf);
}

void test_appendEscaped_treats_null_as_empty(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "ab"));

  TEST_ASSERT_TRUE(jsonbuf_appendEscaped(buf, NULL));
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendFormat(buf, "%s", ""), "an empty fragment is not an encoding failure");
  TEST_ASSERT_EQUAL_size_t(2, jsonbuf_length(buf));

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("ab", body, "a zero-byte fragment must not have failed the buffer");
  free(body);
  jsonbuf_destroy(buf);
}

void test_ceiling_refuses_appendEscaped_too(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 32);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, DIGITS_10));

  TEST_ASSERT_FALSE(jsonbuf_appendEscaped(buf, DIGITS_25));
  TEST_ASSERT_EQUAL_size_t(10, jsonbuf_length(buf));
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "the refusal must stick all the way to the handoff");

  jsonbuf_destroy(buf);
}

void test_ceiling_budgets_the_terminating_nul(void)
{
  JsonBuf_t* fits = jsonbuf_create(8, 32);
  TEST_ASSERT_NOT_NULL(fits);
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendFormat(fits, "%31s", ""), "31 bytes + NUL = 32 must fit exactly");
  TEST_ASSERT_EQUAL_size_t(31, jsonbuf_length(fits));
  size_t fitted_length = jsonbuf_length(fits);
  char*  fitted_body   = jsonbuf_finish(fits);
  TEST_ASSERT_NOT_NULL(fitted_body);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(fitted_length, strlen(fitted_body),
    "m_len must count the bytes vsnprintf actually wrote, not the ones it wanted to");
  free(fitted_body);
  jsonbuf_destroy(fits);

  JsonBuf_t* overflows = jsonbuf_create(8, 32);
  TEST_ASSERT_NOT_NULL(overflows);
  TEST_ASSERT_FALSE_MESSAGE(jsonbuf_appendFormat(overflows, "%32s", ""), "32 bytes + NUL = 33 must not fit");
  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(overflows));
  TEST_ASSERT_NULL(jsonbuf_finish(overflows));
  jsonbuf_destroy(overflows);
}

void test_appendFormat_encoding_failure_sets_failed(void)
{
  wchar_t bad_wide[2];

  bad_wide[0] = (wchar_t)0xD800;
  bad_wide[1] = 0;

  JsonBuf_t* buf = jsonbuf_create(64, 128);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, R"({"a":)"));

  TEST_ASSERT_FALSE(jsonbuf_appendFormat(buf, "xy%ls", bad_wide));
  TEST_ASSERT_EQUAL_size_t_MESSAGE(5, jsonbuf_length(buf), "a failed encode must not move the length");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "an encoding failure must reach the handoff as NULL");

  jsonbuf_destroy(buf);
}

void test_create_reports_allocation_failure(void)
{
  g_mallocFailAfter = 0;
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_create(64, 128), "a failed handle allocation must return NULL");

  g_mallocFailAfter = 1;
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_create(64, 128), "a failed body allocation must return NULL");
}

void test_exact_capacity_fit_still_grows_and_leaves_room_for_the_nul(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 1024);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendFormat(buf, "%s", HEX_16));

  TEST_ASSERT_EQUAL_size_t(16, jsonbuf_length(buf));
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < jsonbuf_capacity(buf), "no room left for the NUL");

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_EQUAL_STRING(HEX_16, body);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(16, strlen(body), "the terminator must sit at the length");
  free(body);

  jsonbuf_destroy(buf);
}

void test_ceiling_budgets_the_nul_for_an_expanded_escaped_value(void)
{
  JsonBuf_t* fits = jsonbuf_create(8, 32);
  TEST_ASSERT_NOT_NULL(fits);
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendEscaped(fits, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" "a"), "30 + 1 bytes + NUL = 32 must fit exactly");
  TEST_ASSERT_EQUAL_size_t(31, jsonbuf_length(fits));
  jsonbuf_destroy(fits);

  JsonBuf_t* overflows = jsonbuf_create(8, 32);
  TEST_ASSERT_NOT_NULL(overflows);
  TEST_ASSERT_FALSE_MESSAGE(jsonbuf_appendEscaped(overflows, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" "ab"), "30 + 2 bytes + NUL = 33 must not fit");
  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(overflows));
  jsonbuf_destroy(overflows);
}

void test_exact_escaped_fit_grows_before_writing_the_nul(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 1024);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(jsonbuf_appendEscaped(buf, HEX_16));

  TEST_ASSERT_EQUAL_size_t(16, jsonbuf_length(buf));
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_length(buf) < jsonbuf_capacity(buf), "closing NUL landed outside the capacity");

  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_EQUAL_STRING(HEX_16, body);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(16, strlen(body), "the closing NUL must sit at the length");
  free(body);

  jsonbuf_destroy(buf);
}

void test_create_starts_empty_even_when_the_heap_block_is_dirty(void)
{
  g_dirtyMalloc = true;
  JsonBuf_t* fresh = jsonbuf_create(64, 128);
  TEST_ASSERT_NOT_NULL(fresh);
  g_dirtyMalloc = false;

  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(fresh));

  char* body = jsonbuf_finish(fresh);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", body, "create must write the terminator, not inherit a zero page");
  free(body);
  jsonbuf_destroy(fresh);
}

void test_production_capacities_are_pinned(void)
{
  TEST_ASSERT_EQUAL_size_t_MESSAGE(4096u, (size_t)JSONBUF_INITIAL_CAP,
    "the starting capacity of a response buffer - moving it is a review, not an edit");
  TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)HTTP_MAX_BODY, (size_t)JSONBUF_DEFAULT_CEILING,
    "these are equal by choice; raising the upstream limit is not a licence to raise this one");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(4u * 1024u * 1024u, (size_t)JSONBUF_DEFAULT_CEILING,
    "4 MiB is a reviewed DoS decision - moving it is a review, not an edit");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(16u * 1024u * 1024u, (size_t)JSONBUF_MAX_CEILING,
    "16 MiB is a reviewed DoS decision - moving it is a review, not an edit");
  TEST_ASSERT_TRUE(JSONBUF_DEFAULT_CEILING > JSONBUF_INITIAL_CAP);
}

void test_create_clamps_the_ceiling_to_the_maximum_and_the_start_to_the_ceiling(void)
{
  JsonBuf_t* generous = jsonbuf_create(4096, 64u * 1024u * 1024u);
  TEST_ASSERT_NOT_NULL(generous);
  TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)JSONBUF_MAX_CEILING, jsonbuf_ceiling(generous),
    "a caller may ask for less than JSONBUF_MAX_CEILING, never more");
  jsonbuf_destroy(generous);

  JsonBuf_t* oversized_start = jsonbuf_create(32u * 1024u * 1024u, 32u * 1024u * 1024u);
  TEST_ASSERT_NOT_NULL(oversized_start);
  TEST_ASSERT_EQUAL_size_t((size_t)JSONBUF_MAX_CEILING, jsonbuf_ceiling(oversized_start));
  TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)JSONBUF_MAX_CEILING, jsonbuf_capacity(oversized_start),
    "the starting capacity is clamped too, or a buffer would start above its ceiling");
  jsonbuf_destroy(oversized_start);

  JsonBuf_t* row_sized_start = jsonbuf_create(12u * 1024u * 1024u, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL_MESSAGE(row_sized_start, "a start sized from a row must be clamped, not refused");
  TEST_ASSERT_EQUAL_size_t((size_t)JSONBUF_DEFAULT_CEILING, jsonbuf_capacity(row_sized_start));
  TEST_ASSERT_EQUAL_size_t((size_t)JSONBUF_DEFAULT_CEILING, jsonbuf_ceiling(row_sized_start));
  jsonbuf_destroy(row_sized_start);
}

void test_a_ceiling_above_the_default_grows_up_to_the_maximum(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_MAX_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendFormat(buf, "%*s", (int)JSONBUF_DEFAULT_CEILING, ""),
    "a buffer whose ceiling is above JSONBUF_DEFAULT_CEILING must grow past it");
  TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendFormat(buf, "%*s", (int)(JSONBUF_MAX_CEILING - JSONBUF_DEFAULT_CEILING - 1), ""),
    "JSONBUF_MAX_CEILING - 1 bytes + NUL must fit exactly");
  TEST_ASSERT_EQUAL_size_t((size_t)JSONBUF_MAX_CEILING - 1, jsonbuf_length(buf));
  TEST_ASSERT_FALSE_MESSAGE(jsonbuf_appendFormat(buf, " "), "one byte past the maximum ceiling must be refused");
  TEST_ASSERT_NULL(jsonbuf_finish(buf));
  jsonbuf_destroy(buf);
}

void test_appendEscaped_on_detached_buffer_is_inert(void)
{
  JsonBuf_t* buf = jsonbuf_create(16, 64);

  TEST_ASSERT_NOT_NULL(buf);
  free(jsonbuf_finish(buf));

  TEST_ASSERT_FALSE(jsonbuf_appendEscaped(buf, "hello"));
  TEST_ASSERT_EQUAL_size_t(0, jsonbuf_length(buf));
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_finish(buf), "a detached buffer must not come back to life");

  jsonbuf_destroy(buf);
}

void test_a_zero_size_is_refused_at_create(void)
{
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_create(4096, 0), "a zero ceiling must be refused");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_create(0, 4096), "a zero start must be refused");
  TEST_ASSERT_NULL_MESSAGE(jsonbuf_create(0, 0), "both zero must be refused");
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(36, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}


void test_appendEscapedBytes_reads_by_the_count(void)
{
  static const struct {
    const char* mp_name;
    const char* mp_bytes;
    size_t      m_byteCount;
    const char* mp_expected;
  } cases[] = {
    { "a NUL byte between two letters", "a\0b",       3, "a\\u0000b" },
    { "a NUL byte at the end",          "ab\0",       3, "ab\\u0000" },
    { "the count stops before the end", "abcdef",     3, "abc" },
    { "a count of 0",                   "abc",        0, "" },
    { "a character cut by the count",   "\xc3\xa9",   1, "\xef\xbf\xbd" },
    { "NULL bytes",                     NULL,         5, "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonBuf_t* buf = jsonbuf_create(4, 64);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE_MESSAGE(jsonbuf_appendEscapedBytes(buf, cases[i].mp_bytes, cases[i].m_byteCount), cases[i].mp_name);
    char* body = jsonbuf_finish(buf);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_expected, body, cases[i].mp_name);
    free(body);
    jsonbuf_destroy(buf);
  }
}

void test_appendEscapedBytes_on_a_failed_buffer_is_refused(void)
{
  JsonBuf_t* buf = jsonbuf_create(4, 8);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_FALSE(jsonbuf_appendEscaped(buf, "0123456789"));
  TEST_ASSERT_FALSE(jsonbuf_appendEscapedBytes(buf, "a", 1));
  TEST_ASSERT_NULL(jsonbuf_finish(buf));
  jsonbuf_destroy(buf);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_create_allocates_empty_terminated_buffer);
  RUN_TEST(test_finish_detaches_body_and_leaves_buffer_inert);
  RUN_TEST(test_finish_returns_null_on_a_failed_buffer);
  RUN_TEST(test_destroy_of_null_is_a_noop);
  RUN_TEST(test_appendFormat_formats_and_advances);
  RUN_TEST(test_growth_past_initial_capacity_preserves_content);
  RUN_TEST(test_ceiling_refuses_append_and_sets_failed);
  RUN_TEST(test_realloc_failure_during_growth_sets_failed);
  RUN_TEST(test_failed_buffer_ignores_later_appends);
  RUN_TEST(test_every_byte_follows_the_escape_rule);
  RUN_TEST(test_escape_table_row_by_row);
  RUN_TEST(test_isCodePointHidden_pins_every_range_edge);
  RUN_TEST(test_every_append_leaves_buffer_nul_terminated);
  RUN_TEST(test_ceiling_bounds_len_and_cap_not_just_the_reserve_call);
  RUN_TEST(test_appendFormat_on_detached_buffer_is_inert);
  RUN_TEST(test_appendEscaped_treats_null_as_empty);
  RUN_TEST(test_appendJsonText_table_row_by_row);
  RUN_TEST(test_appendJsonText_treats_null_as_empty);
  RUN_TEST(test_ceiling_refuses_appendJsonText_too);
  RUN_TEST(test_appendJsonText_on_detached_buffer_is_inert);
  RUN_TEST(test_ceiling_refuses_appendEscaped_too);
  RUN_TEST(test_ceiling_budgets_the_terminating_nul);
  RUN_TEST(test_appendFormat_encoding_failure_sets_failed);
  RUN_TEST(test_create_reports_allocation_failure);
  RUN_TEST(test_exact_capacity_fit_still_grows_and_leaves_room_for_the_nul);
  RUN_TEST(test_exact_escaped_fit_grows_before_writing_the_nul);
  RUN_TEST(test_ceiling_budgets_the_nul_for_an_expanded_escaped_value);
  RUN_TEST(test_create_starts_empty_even_when_the_heap_block_is_dirty);
  RUN_TEST(test_production_capacities_are_pinned);
  RUN_TEST(test_create_clamps_the_ceiling_to_the_maximum_and_the_start_to_the_ceiling);
  RUN_TEST(test_a_ceiling_above_the_default_grows_up_to_the_maximum);
  RUN_TEST(test_appendEscaped_on_detached_buffer_is_inert);
  RUN_TEST(test_a_zero_size_is_refused_at_create);
  RUN_TEST(test_appendEscapedBytes_reads_by_the_count);
  RUN_TEST(test_appendEscapedBytes_on_a_failed_buffer_is_refused);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
