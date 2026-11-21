#include <string.h>

#include <openssl/evp.h>

#include "unity/unity.h"
#include "bytes.h"

typedef enum {
  TEST_DIGEST_PASS = 0,
  TEST_DIGEST_FAIL,
  TEST_DIGEST_SHORT_LENGTH,
  TEST_DIGEST_FAIL_HASHED,
} BytesTestDigestFault_t;

static BytesTestDigestFault_t g_digestFault = TEST_DIGEST_PASS;

int __real_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl);

int __wrap_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl)
{
  BytesTestDigestFault_t fault = g_digestFault;
  g_digestFault = TEST_DIGEST_PASS;
  if (fault == TEST_DIGEST_FAIL)
    return 0;
  int digest_status = __real_EVP_Digest(data, count, md, size, type, impl);
  if (fault == TEST_DIGEST_SHORT_LENGTH)
    *size = 20;
  return fault == TEST_DIGEST_FAIL_HASHED ? 0 : digest_status;
}

void setUp(void)    { g_digestFault = TEST_DIGEST_PASS; }
void tearDown(void) {}

void test_same_bytes_are_equal(void)
{
  TEST_ASSERT_TRUE(bytes_isEqual("abc", 3, "abc", false));
  TEST_ASSERT_TRUE(bytes_isEqual("abc", 3, "abc", true));
}

void test_one_different_byte_is_not_equal(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("abd", 3, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("abd", 3, "abc", true));
  TEST_ASSERT_FALSE(bytes_isEqual("xbc", 3, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("xbc", 3, "abc", true));
}

void test_shorter_span_is_not_equal(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("abc", 2, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("abc", 2, "abc", true));
}

void test_longer_span_is_not_equal(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("abcd", 4, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("abcd", 4, "abc", true));
  TEST_ASSERT_FALSE(bytes_isEqual("abc\0", 4, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("abc\0", 4, "abc", true));
}

void test_byte_after_the_span_is_not_read(void)
{
  TEST_ASSERT_TRUE(bytes_isEqual("abcX", 3, "abc", false));
  TEST_ASSERT_TRUE(bytes_isEqual("ABCX", 3, "abc", true));
}

void test_other_case_is_not_equal_when_case_is_kept(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("ABC", 3, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("abc", 3, "abC", false));
}

void test_other_case_is_equal_when_case_is_ignored(void)
{
  TEST_ASSERT_TRUE(bytes_isEqual("ABC", 3, "abc", true));
  TEST_ASSERT_TRUE(bytes_isEqual("aBc", 3, "ABC", true));
  TEST_ASSERT_TRUE(bytes_isEqual("az", 2, "AZ", true));
}

void test_only_ascii_letters_fold_when_case_is_ignored(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("@", 1, "`", true));
  TEST_ASSERT_FALSE(bytes_isEqual("[", 1, "{", true));
  TEST_ASSERT_FALSE(bytes_isEqual("\xC4", 1, "\xE4", true));
}

void test_empty_span_equals_only_the_empty_text(void)
{
  TEST_ASSERT_TRUE(bytes_isEqual(NULL, 0, "", false));
  TEST_ASSERT_TRUE(bytes_isEqual(NULL, 0, "", true));
  TEST_ASSERT_FALSE(bytes_isEqual(NULL, 0, "a", false));
  TEST_ASSERT_FALSE(bytes_isEqual(NULL, 0, "a", true));
}

void test_nul_inside_the_span_is_not_equal(void)
{
  TEST_ASSERT_FALSE(bytes_isEqual("a\0c", 3, "abc", false));
  TEST_ASSERT_FALSE(bytes_isEqual("a\0c", 3, "abc", true));
}

void test_prefix_is_found_at_the_start(void)
{
  TEST_ASSERT_TRUE(bytes_hasPrefix("abcdef", 6, "abc", 3, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("abcdef", 6, "abc", 3, true));
}

void test_prefix_needs_a_span_at_least_as_long(void)
{
  TEST_ASSERT_TRUE(bytes_hasPrefix("abc", 3, "abc", 3, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("abc", 3, "abc", 3, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("abc", 2, "abc", 3, false));
  TEST_ASSERT_FALSE(bytes_hasPrefix("abc", 2, "abc", 3, true));
}

void test_prefix_with_one_different_byte_is_not_found(void)
{
  TEST_ASSERT_FALSE(bytes_hasPrefix("xbcdef", 6, "abc", 3, false));
  TEST_ASSERT_FALSE(bytes_hasPrefix("xbcdef", 6, "abc", 3, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("abxdef", 6, "abc", 3, false));
  TEST_ASSERT_FALSE(bytes_hasPrefix("abxdef", 6, "abc", 3, true));
}

void test_prefix_case_rule(void)
{
  TEST_ASSERT_FALSE(bytes_hasPrefix("ABCdef", 6, "abc", 3, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("ABCdef", 6, "abc", 3, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("abcdef", 6, "aBC", 3, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("abcdef", 6, "aBC", 3, true));
}

void test_prefix_folds_only_ascii_letters(void)
{
  TEST_ASSERT_FALSE(bytes_hasPrefix("@x", 2, "`", 1, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("[x", 2, "{", 1, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("\xC4x", 2, "\xE4", 1, true));
}

void test_prefix_with_a_nul_compares_every_byte(void)
{
  TEST_ASSERT_TRUE(bytes_hasPrefix("PE\0\0x", 5, "PE\0\0", 4, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("PE\0\0x", 5, "PE\0\0", 4, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix("PE\0Xx", 5, "PE\0\0", 4, false));
  TEST_ASSERT_FALSE(bytes_hasPrefix("PE\0Xx", 5, "PE\0\0", 4, true));
}

void test_prefix_empty(void)
{
  TEST_ASSERT_TRUE(bytes_hasPrefix(NULL, 0, "", 0, false));
  TEST_ASSERT_TRUE(bytes_hasPrefix("a", 1, "", 0, true));
  TEST_ASSERT_FALSE(bytes_hasPrefix(NULL, 0, "a", 1, false));
  TEST_ASSERT_FALSE(bytes_hasPrefix(NULL, 0, "a", 1, true));
}

void test_suffix_is_found_at_the_end(void)
{
  TEST_ASSERT_TRUE(bytes_hasSuffix("abcdef", 6, "def", 3, false));
  TEST_ASSERT_TRUE(bytes_hasSuffix("abcdef", 6, "def", 3, true));
  TEST_ASSERT_FALSE(bytes_hasSuffix("abcDEF", 6, "def", 3, false));
  TEST_ASSERT_TRUE(bytes_hasSuffix("abcDEF", 6, "def", 3, true));
}

void test_suffix_needs_a_span_at_least_as_long(void)
{
  TEST_ASSERT_TRUE(bytes_hasSuffix("def", 3, "def", 3, false));
  TEST_ASSERT_TRUE(bytes_hasSuffix("def", 3, "def", 3, true));
  TEST_ASSERT_FALSE(bytes_hasSuffix("ef", 2, "def", 3, false));
  TEST_ASSERT_FALSE(bytes_hasSuffix("ef", 2, "def", 3, true));
}

void test_suffix_with_one_different_byte_is_not_found(void)
{
  TEST_ASSERT_FALSE(bytes_hasSuffix("abcxef", 6, "def", 3, false));
  TEST_ASSERT_FALSE(bytes_hasSuffix("abcxef", 6, "def", 3, true));
  TEST_ASSERT_FALSE(bytes_hasSuffix("abcdex", 6, "def", 3, false));
  TEST_ASSERT_FALSE(bytes_hasSuffix("abcdex", 6, "def", 3, true));
}

void test_suffix_empty(void)
{
  TEST_ASSERT_TRUE(bytes_hasSuffix(NULL, 0, "", 0, false));
  TEST_ASSERT_TRUE(bytes_hasSuffix("a", 1, "", 0, true));
  TEST_ASSERT_FALSE(bytes_hasSuffix(NULL, 0, "a", 1, false));
  TEST_ASSERT_FALSE(bytes_hasSuffix(NULL, 0, "a", 1, true));
}

void test_name_under_suffix_is_the_suffix_or_below_a_dot(void)
{
  TEST_ASSERT_TRUE(bytes_isNameUnderSuffix("google.com", 10, "google.com"));
  TEST_ASSERT_TRUE(bytes_isNameUnderSuffix("GOOGLE.Com", 10, "google.com"));
  TEST_ASSERT_TRUE(bytes_isNameUnderSuffix("mail.google.com", 15, "google.com"));
}

void test_name_under_suffix_needs_the_dot_and_the_whole_suffix(void)
{
  TEST_ASSERT_FALSE(bytes_isNameUnderSuffix("notgoogle.com", 13, "google.com"));
  TEST_ASSERT_FALSE(bytes_isNameUnderSuffix("oogle.com", 9, "google.com"));
  TEST_ASSERT_FALSE(bytes_isNameUnderSuffix("google.org", 10, "google.com"));
  TEST_ASSERT_FALSE(bytes_isNameUnderSuffix("mail.google.co", 14, "google.com"));
}

void test_hex_digit_values(void)
{
  TEST_ASSERT_EQUAL_INT(0, bytes_hexDigitValue('0'));
  TEST_ASSERT_EQUAL_INT(5, bytes_hexDigitValue('5'));
  TEST_ASSERT_EQUAL_INT(9, bytes_hexDigitValue('9'));
  TEST_ASSERT_EQUAL_INT(10, bytes_hexDigitValue('a'));
  TEST_ASSERT_EQUAL_INT(12, bytes_hexDigitValue('c'));
  TEST_ASSERT_EQUAL_INT(15, bytes_hexDigitValue('f'));
  TEST_ASSERT_EQUAL_INT(10, bytes_hexDigitValue('A'));
  TEST_ASSERT_EQUAL_INT(13, bytes_hexDigitValue('D'));
  TEST_ASSERT_EQUAL_INT(15, bytes_hexDigitValue('F'));
}

void test_hex_digit_value_of_other_bytes_is_minus_one(void)
{
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('/'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue(':'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('`'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('g'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('@'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('G'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('\0'));
  TEST_ASSERT_EQUAL_INT(-1, bytes_hexDigitValue('\xFF'));
}

void test_write_hex_writes_two_lower_case_digits_per_byte(void)
{
  const unsigned char bytes[] = { 0x00, 0x0F, 0xF0, 0xFF, 0x5A };
  char hex[12];
  memset(hex, 'X', sizeof(hex));

  bytes_writeHex(bytes, sizeof(bytes), hex);

  TEST_ASSERT_EQUAL_STRING("000ff0ff5a", hex);
  TEST_ASSERT_EQUAL_CHAR('X', hex[11]);
}

void test_write_hex_of_no_bytes_is_the_empty_text(void)
{
  char hex[2] = { 'X', 'X' };

  bytes_writeHex(NULL, 0, hex);

  TEST_ASSERT_EQUAL_CHAR('\0', hex[0]);
  TEST_ASSERT_EQUAL_CHAR('X', hex[1]);
}

void test_read_hex_reads_digits_of_either_case(void)
{
  unsigned char bytes[6];
  memset(bytes, 0xEE, sizeof(bytes));

  TEST_ASSERT_TRUE(bytes_tryReadHex("00ff0FF05a", 10, bytes));

  const unsigned char expected[] = { 0x00, 0xFF, 0x0F, 0xF0, 0x5A };
  TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, bytes, sizeof(expected));
  TEST_ASSERT_EQUAL_HEX8(0xEE, bytes[5]);
}

void test_read_hex_refuses_an_odd_count_or_a_byte_that_is_not_a_digit(void)
{
  unsigned char bytes[2];

  TEST_ASSERT_FALSE(bytes_tryReadHex("abc", 3, bytes));
  TEST_ASSERT_FALSE(bytes_tryReadHex("0g", 2, bytes));
  TEST_ASSERT_FALSE(bytes_tryReadHex("g0", 2, bytes));
  TEST_ASSERT_FALSE(bytes_tryReadHex("0 ", 2, bytes));
  TEST_ASSERT_FALSE(bytes_tryReadHex("a\xFF", 2, bytes));
}

void test_read_hex_of_no_digits_writes_nothing(void)
{
  unsigned char bytes[1] = { 0xEE };

  TEST_ASSERT_TRUE(bytes_tryReadHex("", 0, bytes));

  TEST_ASSERT_EQUAL_HEX8(0xEE, bytes[0]);
}

void test_writeSha256Hex_hashes_every_byte_nul_bytes_included(void)
{
  static const struct {
    const char* mp_bytes;
    size_t      m_byteCount;
    const char* mp_hex;
  } cases[] = {
    { "",                 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "abc",              3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { "\x00\x01\x02\x00", 4, "856aaf43b61beefd07691ab6e60cd50522b8c08721f6570dba877c5222745b04" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char hex[BYTES_SHA256_HEX_LEN + 1];
    memset(hex, 'Z', sizeof(hex));
    TEST_ASSERT_TRUE(bytes_writeSha256Hex((const unsigned char*)cases[i].mp_bytes, cases[i].m_byteCount, hex));
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_hex, hex);
  }
}

void test_writeSha256Hex_answers_false_and_empty_when_openssl_fails(void)
{
  static const BytesTestDigestFault_t faults[] = { TEST_DIGEST_FAIL, TEST_DIGEST_SHORT_LENGTH, TEST_DIGEST_FAIL_HASHED };
  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    char hex[BYTES_SHA256_HEX_LEN + 1];
    memset(hex, 'Z', sizeof(hex));
    g_digestFault = faults[i];
    TEST_ASSERT_FALSE(bytes_writeSha256Hex((const unsigned char*)"abc", 3, hex));
    TEST_ASSERT_EQUAL_STRING("", hex);
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(33, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_same_bytes_are_equal);
  RUN_TEST(test_one_different_byte_is_not_equal);
  RUN_TEST(test_shorter_span_is_not_equal);
  RUN_TEST(test_longer_span_is_not_equal);
  RUN_TEST(test_byte_after_the_span_is_not_read);
  RUN_TEST(test_other_case_is_not_equal_when_case_is_kept);
  RUN_TEST(test_other_case_is_equal_when_case_is_ignored);
  RUN_TEST(test_only_ascii_letters_fold_when_case_is_ignored);
  RUN_TEST(test_empty_span_equals_only_the_empty_text);
  RUN_TEST(test_nul_inside_the_span_is_not_equal);
  RUN_TEST(test_prefix_is_found_at_the_start);
  RUN_TEST(test_prefix_needs_a_span_at_least_as_long);
  RUN_TEST(test_prefix_with_one_different_byte_is_not_found);
  RUN_TEST(test_prefix_case_rule);
  RUN_TEST(test_prefix_folds_only_ascii_letters);
  RUN_TEST(test_prefix_with_a_nul_compares_every_byte);
  RUN_TEST(test_prefix_empty);
  RUN_TEST(test_suffix_is_found_at_the_end);
  RUN_TEST(test_suffix_needs_a_span_at_least_as_long);
  RUN_TEST(test_suffix_with_one_different_byte_is_not_found);
  RUN_TEST(test_suffix_empty);
  RUN_TEST(test_name_under_suffix_is_the_suffix_or_below_a_dot);
  RUN_TEST(test_name_under_suffix_needs_the_dot_and_the_whole_suffix);
  RUN_TEST(test_hex_digit_values);
  RUN_TEST(test_hex_digit_value_of_other_bytes_is_minus_one);
  RUN_TEST(test_write_hex_writes_two_lower_case_digits_per_byte);
  RUN_TEST(test_write_hex_of_no_bytes_is_the_empty_text);
  RUN_TEST(test_read_hex_reads_digits_of_either_case);
  RUN_TEST(test_read_hex_refuses_an_odd_count_or_a_byte_that_is_not_a_digit);
  RUN_TEST(test_read_hex_of_no_digits_writes_nothing);
  RUN_TEST(test_writeSha256Hex_hashes_every_byte_nul_bytes_included);
  RUN_TEST(test_writeSha256Hex_answers_false_and_empty_when_openssl_fails);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
