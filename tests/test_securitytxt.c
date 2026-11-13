#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "securitytxt.h"

#define NOW_EPOCH        1767225600
#define JUNE_FIRST_EPOCH 1780272000

#define CONTACT_LINE   "Contact: mailto:a@example.com\n"
#define EXPIRES_LINE   "Expires: 2026-06-01T00:00:00Z\n"
#define CANONICAL_LINE "Canonical: https://example.com/.well-known/security.txt\n"
#define CANONICAL_URL  "https://example.com/.well-known/security.txt"

#define SIGNED_HEAD "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
#define SIGNED_TAIL "-----BEGIN PGP SIGNATURE-----\n\niQEzBAEBCAAdFiEE\n-----END PGP SIGNATURE-----\n"

static SecurityTxtReport_t g_report;
static char                g_body[64 * 1024];
static size_t              g_bodyLen;

void setUp(void)
{
  g_bodyLen = 0;
  memset(&g_report, 0, sizeof(g_report));
}
void tearDown(void) {}

static void static_appendBytes(const char* bytes, size_t len)
{
  TEST_ASSERT_TRUE(g_bodyLen + len <= sizeof(g_body));
  memcpy(g_body + g_bodyLen, bytes, len);
  g_bodyLen += len;
}

static void static_append(const char* text)
{
  static_appendBytes(text, strlen(text));
}

static void static_appendRepeated(const char* text, int count)
{
  for (int i = 0; i < count; i++)
    static_append(text);
}

static void static_appendPolicyLine(size_t line_len)
{
  static const char PREFIX[] = "Policy: https://example.com/";
  static_append(PREFIX);
  for (size_t i = sizeof(PREFIX) - 1; i < line_len; i++)
    static_append("a");
  static_append("\n");
}

static void static_parseAt(int64_t now_epoch)
{
  securitytxt_parse(g_body, g_bodyLen, false, now_epoch, &g_report);
}

static void static_parse(void)
{
  static_parseAt(NOW_EPOCH);
}

static void static_parseText(const char* text)
{
  g_bodyLen = 0;
  static_append(text);
  static_parse();
}

static void static_assertIssueCount(int count)
{
  TEST_ASSERT_EQUAL_INT(count, g_report.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(count, g_report.m_issueTotalCount);
}

static void static_assertIssue(int index, SecurityTxtIssueCode_t issue_code, SecurityTxtField_t field, int line)
{
  TEST_ASSERT_TRUE(index < g_report.m_issueKeptCount);
  TEST_ASSERT_EQUAL_STRING(securitytxt_issueCodeName(issue_code), securitytxt_issueCodeName(g_report.ma_issues[index].m_issueCode));
  TEST_ASSERT_EQUAL_INT(field, g_report.ma_issues[index].m_field);
  TEST_ASSERT_EQUAL_INT(line, g_report.ma_issues[index].m_lineNumber);
}

static void static_assertOneIssue(SecurityTxtIssueCode_t issue_code, SecurityTxtField_t field, int line)
{
  static_assertIssueCount(1);
  static_assertIssue(0, issue_code, field, line);
}

static void static_assertSpan(SecurityTxtField_t field, int index, size_t offset, size_t len, int line)
{
  TEST_ASSERT_TRUE(index < g_report.ma_valueKeptCount[field]);
  TEST_ASSERT_EQUAL_size_t(offset, g_report.ma_values[field][index].m_offset);
  TEST_ASSERT_EQUAL_size_t(len, g_report.ma_values[field][index].m_len);
  TEST_ASSERT_EQUAL_INT(line, g_report.ma_values[field][index].m_lineNumber);
}

static void static_assertSeverityCounts(int error_count, int warning_count, int info_count)
{
  TEST_ASSERT_EQUAL_INT(error_count, g_report.ma_issueCountBySeverity[SECURITYTXT_SEVERITY_ERROR]);
  TEST_ASSERT_EQUAL_INT(warning_count, g_report.ma_issueCountBySeverity[SECURITYTXT_SEVERITY_WARNING]);
  TEST_ASSERT_EQUAL_INT(info_count, g_report.ma_issueCountBySeverity[SECURITYTXT_SEVERITY_INFO]);
}

void test_minimal_file_reads_contact_and_expires_with_no_issue(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE);

  static_assertIssueCount(0);
  static_assertSeverityCounts(0, 0, 0);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CONTACT]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_EXPIRES]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES]);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 9, 20, 1);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 20, 2);
  TEST_ASSERT_TRUE(g_report.m_isExpiresDateRead);
  TEST_ASSERT_EQUAL_INT64(JUNE_FIRST_EPOCH, g_report.m_expiresEpoch);
  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
}

void test_cut_body_raises_only_file_too_large(void)
{
  static_append(CONTACT_LINE);
  securitytxt_parse(g_body, g_bodyLen, true, NOW_EPOCH, &g_report);

  static_assertOneIssue(SECURITYTXT_ISSUE_FILE_TOO_LARGE, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(1, 0, 0);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT]);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CONTACT]);
}

void test_empty_body_raises_contact_missing_then_expires_missing(void)
{
  static_parseText("");

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  static_assertIssue(1, SECURITYTXT_ISSUE_EXPIRES_MISSING, SECURITYTXT_FIELD_EXPIRES, 0);
  static_assertSeverityCounts(2, 0, 0);
  TEST_ASSERT_FALSE(g_report.m_isExpiresDateRead);
}

void test_byte_order_mark_is_skipped_and_raises_byte_order_mark(void)
{
  static_append("\xEF\xBB\xBF");
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();

  static_assertOneIssue(SECURITYTXT_ISSUE_BYTE_ORDER_MARK, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(0, 1, 0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 12, 20, 1);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 42, 20, 2);
}

void test_byte_order_mark_alone_raises_byte_order_mark_and_both_missing(void)
{
  static_parseText("\xEF\xBB\xBF");

  static_assertIssueCount(3);
  static_assertIssue(0, SECURITYTXT_ISSUE_BYTE_ORDER_MARK, SECURITYTXT_FIELD_NONE, 0);
  static_assertIssue(1, SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  static_assertIssue(2, SECURITYTXT_ISSUE_EXPIRES_MISSING, SECURITYTXT_FIELD_EXPIRES, 0);
}

void test_two_bytes_of_a_byte_order_mark_raise_invalid_utf8(void)
{
  static_append("\xEF\xBB\n");
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_INVALID_UTF8, SECURITYTXT_FIELD_NONE, 0);
  static_assertIssue(1, SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 1);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 12, 20, 2);
}

void test_invalid_utf8_raises_one_issue_and_the_values_are_kept(void)
{
  static_append(CONTACT_LINE);
  static_append("Policy: https://example.com/\xff\n");
  static_append("Hiring: https://example.com/\xfe\n");
  static_append(EXPIRES_LINE);
  static_parse();

  static_assertOneIssue(SECURITYTXT_ISSUE_INVALID_UTF8, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(1, 0, 0);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 38, 21, 2);
  static_assertSpan(SECURITYTXT_FIELD_HIRING, 0, 68, 21, 3);
}

void test_nul_bytes_raise_one_contains_nul_byte(void)
{
  static const char POLICY[] = "Policy: https://example.com/\0a\n#\0\n";
  static_append(CONTACT_LINE);
  static_appendBytes(POLICY, sizeof(POLICY) - 1);
  static_append(EXPIRES_LINE);
  static_parse();

  static_assertOneIssue(SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE, SECURITYTXT_FIELD_NONE, 0);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 38, 22, 2);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 73, 20, 4);
}

void test_lone_cr_ends_a_line_and_raises_invalid_line_ending(void)
{
  static_parseText("Contact: mailto:a@example.com\rExpires: 2026-06-01T00:00:00Z\r");

  static_assertOneIssue(SECURITYTXT_ISSUE_INVALID_LINE_ENDING, SECURITYTXT_FIELD_NONE, 1);
  static_assertSeverityCounts(0, 1, 0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 9, 20, 1);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 20, 2);
}

void test_cr_before_crlf_is_a_lone_cr(void)
{
  static_parseText("# a\r\r\nContact: mailto:a@example.com\r\n" EXPIRES_LINE);

  static_assertOneIssue(SECURITYTXT_ISSUE_INVALID_LINE_ENDING, SECURITYTXT_FIELD_NONE, 1);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 15, 20, 3);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 46, 20, 4);
}

void test_lf_before_cr_leaves_a_lone_cr(void)
{
  static_parseText("# a\n\rContact: mailto:a@example.com\n" EXPIRES_LINE);

  static_assertOneIssue(SECURITYTXT_ISSUE_INVALID_LINE_ENDING, SECURITYTXT_FIELD_NONE, 2);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 14, 20, 3);
}

void test_crlf_line_endings_raise_no_issue(void)
{
  static_parseText("Contact: mailto:a@example.com\r\nExpires: 2026-06-01T00:00:00Z\r\n");

  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 9, 20, 1);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 40, 20, 2);
}

void test_last_line_without_a_line_end_is_read(void)
{
  static_parseText(CONTACT_LINE "Expires: 2026-06-01T00:00:00Z");

  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 20, 2);
}

void test_bytes_after_the_body_are_not_read(void)
{
  static_append(CONTACT_LINE "Expires: 2026-06-01T00:00:00Zx");
  g_bodyLen--;
  static_parse();
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 20, 2);

  g_bodyLen = 0;
  static_append(CONTACT_LINE "Expires: 2026-06-01T00:00:00Z\r");
  g_bodyLen--;
  static_parse();
  static_assertIssueCount(0);

  g_bodyLen = 0;
  static_append(CONTACT_LINE "Expires: 2026-06-01T00:00:00Z\r\n");
  g_bodyLen--;
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_INVALID_LINE_ENDING, SECURITYTXT_FIELD_NONE, 2);

  g_bodyLen = 0;
  static_append(CONTACT_LINE "Expires: 2026-06-01T00:00:00z");
  g_bodyLen--;
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);

  g_bodyLen = 0;
  static_append(CONTACT_LINE "Expires: 2026-06-01T00:00:00+02:00");
  g_bodyLen--;
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);

  g_bodyLen = 0;
  static_append(CONTACT_LINE EXPIRES_LINE "Policy: abc:");
  g_bodyLen--;
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_POLICY, 3);
}

void test_field_lines_of_2047_and_2048_bytes_are_read(void)
{
  static_appendPolicyLine(2047);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 8, 2039, 1);

  g_bodyLen = 0;
  static_appendPolicyLine(2048);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 8, 2040, 1);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 2058, 20, 2);
}

void test_field_line_of_2049_bytes_raises_line_too_long(void)
{
  static_appendPolicyLine(2049);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();

  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_TOO_LONG, SECURITYTXT_FIELD_POLICY, 1);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_POLICY]);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_POLICY]);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 2059, 20, 2);
}

void test_long_line_of_no_known_field_raises_line_too_long_on_no_field(void)
{
  static_append("X-Foo: ");
  for (int i = 0; i < 2042; i++)
    static_append("a");
  static_append("\n");
  for (int i = 0; i < 2049; i++)
    static_append("b");
  static_append("\n");
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_LINE_TOO_LONG, SECURITYTXT_FIELD_NONE, 1);
  static_assertIssue(1, SECURITYTXT_ISSUE_LINE_TOO_LONG, SECURITYTXT_FIELD_NONE, 2);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
}

void test_lines_999_and_1000_are_read(void)
{
  static_appendRepeated("#\n", 997);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 2033, 20, 999);

  g_bodyLen = 0;
  static_appendRepeated("#\n", 998);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 2035, 20, 1000);
}

void test_line_1001_is_not_read_and_raises_too_many_lines(void)
{
  static_appendRepeated("#\n", 999);
  static_append(CONTACT_LINE EXPIRES_LINE EXPIRES_LINE);
  static_parse();

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_TOO_MANY_LINES, SECURITYTXT_FIELD_NONE, 1001);
  static_assertIssue(1, SECURITYTXT_ISSUE_EXPIRES_MISSING, SECURITYTXT_FIELD_EXPIRES, 0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 2007, 20, 1000);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES]);
}

void test_whole_signed_envelope_is_signed_and_its_fields_are_read(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 60, 44, 4);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 114, 20, 5);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 144, 20, 6);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
}

void test_signed_file_without_canonical_raises_signed_without_canonical(void)
{
  static_parseText(SIGNED_HEAD CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNED_WITHOUT_CANONICAL, SECURITYTXT_FIELD_CANONICAL, 0);
  static_assertSeverityCounts(0, 0, 1);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 58, 20, 4);
}

void test_dash_escaped_line_is_read_after_its_dash(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE "- " CONTACT_LINE "- # Contact: mailto:b@example.com\n" EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 116, 20, 5);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 180, 20, 7);

  static_parseText(SIGNED_HEAD "- -----BEGIN PGP SIGNATURE-----\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);
  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 4);
}

void test_dash_in_an_unsigned_file_is_part_of_the_name(void)
{
  static_parseText("- " CONTACT_LINE EXPIRES_LINE);

  static_assertOneIssue(SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  TEST_ASSERT_EQUAL_INT(1, g_report.m_unknownFieldCount);

  static_parseText(EXPIRES_LINE "- " CONTACT_LINE);
  static_assertOneIssue(SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  TEST_ASSERT_EQUAL_INT(1, g_report.m_unknownFieldCount);
}

void test_blank_lines_before_the_envelope_and_two_hash_lines_are_read(void)
{
  static_parseText("\n \n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nHash: SHA512\n\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 76, 44, 7);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 130, 20, 8);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 160, 20, 9);
}

void test_header_line_in_lower_case_does_not_sign_the_file(void)
{
  static_parseText("-----begin pgp signed message-----\nHash: SHA256\n\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
}

void test_signed_envelope_with_crlf_endings_is_signed(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\n"
                   "Canonical: https://example.com/.well-known/security.txt\r\n"
                   "Contact: mailto:a@example.com\r\nExpires: 2026-06-01T00:00:00Z\r\n"
                   "-----BEGIN PGP SIGNATURE-----\r\n\r\niQEzBAEBCAAdFiEE\r\n-----END PGP SIGNATURE-----\r\n");

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 118, 20, 5);
}

void test_header_without_a_blank_line_raises_signature_malformed(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(1, 0, 0);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 59, 44, 3);
}

void test_envelope_without_a_signature_raises_signature_malformed_and_reads_to_the_end(void)
{
  static_parseText(SIGNED_HEAD CONTACT_LINE EXPIRES_LINE "Policy: https://example.com/policy\n");

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 117, 26, 6);
}

void test_signature_without_an_end_raises_signature_malformed(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE "-----BEGIN PGP SIGNATURE-----\nPolicy: https://example.com/policy\n");

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_POLICY]);
}

void test_signature_malformed_is_raised_once(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE);

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
}

void test_header_alone_raises_signature_malformed(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n");

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(3);
  static_assertIssue(0, SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
  static_assertIssue(1, SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  static_assertIssue(2, SECURITYTXT_ISSUE_EXPIRES_MISSING, SECURITYTXT_FIELD_EXPIRES, 0);
}

void test_envelope_without_a_hash_line_raises_signature_malformed(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\n\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 47, 44, 3);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 131, 20, 5);

  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 60, 44, 4);

  static_parseText("-----BEGIN PGP SIGNED MESSAGE-----\nHashes: SHA256\n\n" CONTACT_LINE EXPIRES_LINE SIGNED_TAIL);
  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
}

void test_line_after_the_signature_raises_text_after_signature_once(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL "\nPolicy: https://example.com/policy\nx\n");

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_TEXT_AFTER_SIGNATURE, SECURITYTXT_FIELD_NONE, 12);
  static_assertSeverityCounts(0, 1, 0);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_POLICY]);
}

void test_blank_lines_after_the_signature_raise_nothing(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE SIGNED_TAIL "\n \t\n");

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertIssueCount(0);
}

void test_header_with_a_trailing_space_is_not_an_envelope(void)
{
  static_parseText("-----BEGIN PGP SIGNED MESSAGE----- \n" CONTACT_LINE EXPIRES_LINE);

  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 1);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 45, 20, 2);
}

void test_signature_line_with_a_trailing_space_is_a_content_line(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE "-----BEGIN PGP SIGNATURE----- \n" SIGNED_TAIL);

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 7);
}

void test_comments_and_blank_lines_are_skipped(void)
{
  static_parseText("# Contact: mailto:x\n\n \t \n" CONTACT_LINE EXPIRES_LINE);

  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CONTACT]);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 34, 20, 4);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 64, 20, 5);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
}

void test_line_without_a_colon_raises_line_syntax_invalid(void)
{
  static_parseText(CONTACT_LINE "garbage\n" EXPIRES_LINE);

  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 2);
  static_assertSeverityCounts(0, 1, 0);
}

void test_line_with_an_empty_name_raises_line_syntax_invalid(void)
{
  static_parseText(CONTACT_LINE " \t: mailto:b@example.com\n" EXPIRES_LINE);

  static_assertOneIssue(SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 2);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CONTACT]);
}

void test_names_are_read_in_any_case_and_values_trimmed(void)
{
  static_parseText(" \tcOnTaCt \t:\t  mailto:a@example.com \t\n" EXPIRES_LINE);

  static_assertIssueCount(0);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 15, 20, 1);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 47, 20, 2);
}

void test_every_field_name_is_read(void)
{
  static_parseText("ACKNOWLEDGMENTS: https://example.com/a\n"
                   "canonical: https://example.com/.well-known/security.txt\n"
                   CONTACT_LINE
                   "CSAF: https://example.com/provider-metadata.json\n"
                   "encryption: https://example.com/k\n"
                   EXPIRES_LINE
                   "hiring: https://example.com/h\n"
                   "POLICY: https://example.com/p\n"
                   "preferred-languages: en\n");

  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
  static_assertSpan(SECURITYTXT_FIELD_ACKNOWLEDGMENTS, 0, 17, 21, 1);
  static_assertSpan(SECURITYTXT_FIELD_CANONICAL, 0, 50, 44, 2);
  static_assertSpan(SECURITYTXT_FIELD_CONTACT, 0, 104, 20, 3);
  static_assertSpan(SECURITYTXT_FIELD_CSAF, 0, 131, 42, 4);
  static_assertSpan(SECURITYTXT_FIELD_ENCRYPTION, 0, 186, 21, 5);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 217, 20, 6);
  static_assertSpan(SECURITYTXT_FIELD_HIRING, 0, 246, 21, 7);
  static_assertSpan(SECURITYTXT_FIELD_POLICY, 0, 276, 21, 8);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 0, 319, 2, 9);
  for (int field = 0; field < SECURITYTXT_FIELD_COUNT; field++)
    TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[field]);
}

void test_unknown_fields_are_only_counted(void)
{
  static_parseText(CONTACT_LINE "X-Foo: bar\nFoo:\nContacts: mailto:b@example.com\n" EXPIRES_LINE);

  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(3, g_report.m_unknownFieldCount);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CONTACT]);
}

void test_empty_value_raises_field_empty_and_keeps_nothing(void)
{
  static_parseText(CONTACT_LINE "Policy: \t \nExpires:\n" EXPIRES_LINE);

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_FIELD_EMPTY, SECURITYTXT_FIELD_POLICY, 2);
  static_assertIssue(1, SECURITYTXT_ISSUE_FIELD_EMPTY, SECURITYTXT_FIELD_EXPIRES, 3);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_POLICY]);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_POLICY]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES]);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 59, 20, 4);
  TEST_ASSERT_TRUE(g_report.m_isExpiresDateRead);
}

#define HIRING_LINE "Hiring: https://example.com/jobs\n"

void test_19_and_20_values_of_a_field_are_kept(void)
{
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(HIRING_LINE, 19);
  static_parse();
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(19, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_HIRING]);
  TEST_ASSERT_EQUAL_INT(19, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_HIRING]);
  static_assertSpan(SECURITYTXT_FIELD_HIRING, 18, 662, 24, 21);

  g_bodyLen = 0;
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(HIRING_LINE, 20);
  static_parse();
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_HIRING]);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_HIRING]);
  static_assertSpan(SECURITYTXT_FIELD_HIRING, 19, 695, 24, 22);
}

void test_21st_value_raises_too_many_values_and_is_not_kept(void)
{
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(HIRING_LINE, 21);
  static_parse();

  static_assertOneIssue(SECURITYTXT_ISSUE_TOO_MANY_VALUES, SECURITYTXT_FIELD_HIRING, 23);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_HIRING]);
  TEST_ASSERT_EQUAL_INT(21, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_HIRING]);
  static_assertSpan(SECURITYTXT_FIELD_HIRING, 19, 695, 24, 22);
}

void test_too_many_values_is_raised_once_for_each_field(void)
{
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(HIRING_LINE, 22);
  static_appendRepeated("Policy: https://example.com/p\n", 21);
  static_parse();

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_TOO_MANY_VALUES, SECURITYTXT_FIELD_HIRING, 23);
  static_assertIssue(1, SECURITYTXT_ISSUE_TOO_MANY_VALUES, SECURITYTXT_FIELD_POLICY, 45);
  TEST_ASSERT_EQUAL_INT(22, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_HIRING]);
  TEST_ASSERT_EQUAL_INT(21, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_POLICY]);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_POLICY]);
}

void test_value_with_no_scheme_raises_uri_invalid_in_each_uri_field(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE
                   "Acknowledgments: example.com/a\n"
                   "Canonical: /security.txt\n"
                   "Contact: a@example.com\n"
                   "CSAF: 1https://example.com/provider-metadata.json\n"
                   "Encryption: :https://example.com/k\n"
                   "Hiring: ht tp://example.com/\n"
                   "Policy: https//example.com/policy\n");

  static_assertIssueCount(7);
  static_assertIssue(0, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_ACKNOWLEDGMENTS, 3);
  static_assertIssue(1, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CANONICAL, 4);
  static_assertIssue(2, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CONTACT, 5);
  static_assertIssue(3, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CSAF, 6);
  static_assertIssue(4, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_ENCRYPTION, 7);
  static_assertIssue(5, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_HIRING, 8);
  static_assertIssue(6, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_POLICY, 9);
  static_assertSeverityCounts(7, 0, 0);
  TEST_ASSERT_EQUAL_INT(2, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_POLICY]);
}

void test_every_scheme_byte_is_read(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE
                   "Policy: a+b-c.9Z:x\n"
                   "Hiring: Z:\n"
                   "Acknowledgments: tel:+1-201-555-0123\n");

  static_assertIssueCount(0);
}

void test_bytes_beside_the_scheme_bytes_raise_uri_invalid(void)
{
  static const char* const VALUES[] = { "@:x", "[:x", "`:x", "{:x", "a@:x", "a[:x", "a`:x", "a{:x",
                                        "a/:x", "a*:x", "a,:x", "a;:x" };
  int value_count = (int)(sizeof(VALUES) / sizeof(VALUES[0]));

  static_append(CONTACT_LINE EXPIRES_LINE);
  for (int i = 0; i < value_count; i++)
  {
    static_append("Hiring: ");
    static_append(VALUES[i]);
    static_append("\n");
  }
  static_parse();

  static_assertIssueCount(value_count);
  for (int i = 0; i < value_count; i++)
    static_assertIssue(i, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_HIRING, 3 + i);
}

void test_http_scheme_raises_uri_not_https(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE
                   "Policy: http://example.com/p\n"
                   "Hiring: HTTP://example.com/h\n"
                   "Acknowledgments: hTtP:x\n"
                   "Canonical: https://example.com/c\n"
                   "Encryption: httpx://example.com/k\n"
                   "Contact: htt://x\n"
                   "CSAF: http:/provider-metadata.json\n");

  static_assertIssueCount(4);
  static_assertIssue(0, SECURITYTXT_ISSUE_URI_NOT_HTTPS, SECURITYTXT_FIELD_POLICY, 3);
  static_assertIssue(1, SECURITYTXT_ISSUE_URI_NOT_HTTPS, SECURITYTXT_FIELD_HIRING, 4);
  static_assertIssue(2, SECURITYTXT_ISSUE_URI_NOT_HTTPS, SECURITYTXT_FIELD_ACKNOWLEDGMENTS, 5);
  static_assertIssue(3, SECURITYTXT_ISSUE_URI_NOT_HTTPS, SECURITYTXT_FIELD_CSAF, 9);
  static_assertSeverityCounts(4, 0, 0);
}

void test_key_in_encryption_raises_only_encryption_holds_key(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE
                   "Encryption: -----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                   "Policy: -----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                   "Encryption: -----BEGI\n"
                   "Encryption: -----BEGIN\n");

  static_assertIssueCount(4);
  static_assertIssue(0, SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY, SECURITYTXT_FIELD_ENCRYPTION, 3);
  static_assertIssue(1, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_POLICY, 4);
  static_assertIssue(2, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_ENCRYPTION, 5);
  static_assertIssue(3, SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY, SECURITYTXT_FIELD_ENCRYPTION, 6);
  static_assertSeverityCounts(4, 0, 0);
  static_assertSpan(SECURITYTXT_FIELD_ENCRYPTION, 0, 72, 36, 3);
  TEST_ASSERT_EQUAL_INT(3, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_ENCRYPTION]);
}

void test_lower_case_begin_in_encryption_is_not_a_key(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Encryption: -----begin pgp public key block-----\n");

  static_assertIssueCount(1);
  static_assertIssue(0, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_ENCRYPTION, 3);
}

void test_csaf_path_must_end_in_provider_metadata(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE
                   "CSAF: https://example.com/.well-known/csaf/provider-metadata.json\n"
                   "CSAF: https://example.com/provider-metadata.json?x=1#f\n"
                   "CSAF: https://example.com/provider-metadata.json#f\n"
                   "CSAF: https://example.com/csaf.json\n"
                   "CSAF: https://example.com/a?provider-metadata.json\n"
                   "CSAF: https://example.com/a#provider-metadata.json\n"
                   "CSAF: https://example.com/provider-metadata.jso\n"
                   "CSAF: x:provider-metadata.json\n"
                   "CSAF: x:a\n"
                   "CSAF: provider-metadata.json\n"
                   "CSAF: /provider-metadata.json\n");

  static_assertIssueCount(9);
  static_assertIssue(0, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 6);
  static_assertIssue(1, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 7);
  static_assertIssue(2, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 8);
  static_assertIssue(3, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 9);
  static_assertIssue(4, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 10);
  static_assertIssue(5, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 11);
  static_assertIssue(6, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CSAF, 12);
  static_assertIssue(7, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 12);
  static_assertIssue(8, SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CSAF, 13);
  static_assertSeverityCounts(2, 7, 0);
}

void test_csaf_path_needs_a_slash_before_provider_metadata(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "CSAF: https://example.com/fooprovider-metadata.json\n");

  static_assertOneIssue(SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 3);

  static_parseText(CONTACT_LINE EXPIRES_LINE "CSAF: https://example.com/Provider-Metadata.json\n");
  static_assertOneIssue(SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, SECURITYTXT_FIELD_CSAF, 3);
}

static void static_parseExpires(const char* date_text, int64_t now_epoch)
{
  g_bodyLen = 0;
  static_append(CONTACT_LINE "Expires: ");
  static_append(date_text);
  static_append("\n");
  static_parseAt(now_epoch);
}

void test_each_date_form_is_read(void)
{
  static const struct { const char* m_text; int64_t m_epoch; } CASES[] = {
    { "2026-06-01T00:00:00Z",        1780272000 },
    { "2026-06-01t00:00:00z",        1780272000 },
    { "2026-06-01T02:00:00+02:00",   1780272000 },
    { "2026-05-31T18:30:00-05:30",   1780272000 },
    { "2026-06-01T23:59:00+23:59",   1780272000 },
    { "2026-06-01T00:00:00.123456Z", 1780272000 },
    { "2026-05-31T23:59:60Z",        1780272000 },
    { "2026-12-31T23:59:59Z",        1798761599 },
    { "2026-01-01T00:00:00Z",        1767225600 },
    { "2026-07-31T00:00:00Z",        1785456000 },
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseExpires(CASES[i].m_text, NOW_EPOCH);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_report.m_issueTotalCount, CASES[i].m_text);
    TEST_ASSERT_TRUE_MESSAGE(g_report.m_isExpiresDateRead, CASES[i].m_text);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(CASES[i].m_epoch, g_report.m_expiresEpoch, CASES[i].m_text);
    static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, strlen(CASES[i].m_text), 2);
  }
}

void test_last_day_of_each_month_is_read_and_the_next_is_not(void)
{
  static const int LAST_DAYS[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  char date_text[32];
  for (int month = 1; month <= 12; month++)
  {
    snprintf(date_text, sizeof(date_text), "2026-%02d-%02dT00:00:00Z", month, LAST_DAYS[month - 1]);
    static_parseExpires(date_text, NOW_EPOCH);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_report.m_issueTotalCount, date_text);
    TEST_ASSERT_TRUE_MESSAGE(g_report.m_isExpiresDateRead, date_text);

    snprintf(date_text, sizeof(date_text), "2026-%02d-%02dT00:00:00Z", month, LAST_DAYS[month - 1] + 1);
    static_parseExpires(date_text, NOW_EPOCH);
    TEST_ASSERT_FALSE_MESSAGE(g_report.m_isExpiresDateRead, date_text);
    static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
  }
}

void test_leap_days_follow_the_gregorian_rule(void)
{
  static_parseExpires("2024-02-29T00:00:00Z", 1709164800);
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT64(1709164800, g_report.m_expiresEpoch);

  static_parseExpires("2000-02-29T00:00:00Z", 951782400);
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT64(951782400, g_report.m_expiresEpoch);

  static_parseExpires("2025-02-29T00:00:00Z", NOW_EPOCH);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
  static_parseExpires("2100-02-29T00:00:00Z", NOW_EPOCH);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
  static_parseExpires("1900-02-29T00:00:00Z", NOW_EPOCH);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
  static_parseExpires("2024-04-31T00:00:00Z", NOW_EPOCH);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
}

void test_invalid_dates_raise_expires_invalid(void)
{
  static const char* const CASES[] = {
    "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-06-00T00:00:00Z",
    "2026-06-01T24:00:00Z", "2026-06-01T00:60:00Z", "2026-06-01T00:00:61Z",
    "2026-06-01 00:00:00Z", "2026-06-01T00:00:00", "2026-06-01T00:00:00Zx",
    "2026-06-01T00:00:00.Z", "2026-06-01T00:00:00+0200", "2026-06-01T00:00:00+24:00",
    "2026-06-01T00:00:00+02:60", "2026-6-01T00:00:00Z", "Mon, 01 Jun 2026 00:00:00 GMT",
    "2026-06-01T00:00:0Z", "+2026-06-01T00:00:00Z", "2026-06-01T00:00:00+02:00x",
    "2026-06-01T00:00:00.5", "2026/06/01T00:00:00Z", "2026-06-01T00-00-00Z",
    "2026-06-01T00:00:00*02:00", "2026-06-01T00:00:00+2:00", "x026-06-01T00:00:00Z",
    "2026-06-01T00:00:00+/0:00", "2026-06-01T00:00:00+0/:00", "2026-06-01T00:00:00+00:/0",
    "2026-06-01T00:00:00+00:0/", "2026-06-01T00:00:00+02x00", "2026/06-01T00:00:00Z",
    "2026-06/01T00:00:00Z", "2026-06-01T00-00:00Z", "2026-06-01T00:00-00Z",
    "2024-01-32T00:00:00Z",
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseExpires(CASES[i], NOW_EPOCH);
    TEST_ASSERT_FALSE_MESSAGE(g_report.m_isExpiresDateRead, CASES[i]);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(0, g_report.m_expiresEpoch, CASES[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_report.m_issueTotalCount, CASES[i]);
    static_assertIssue(0, SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
    static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, strlen(CASES[i]), 2);
  }
}

void test_date_before_now_raises_expired(void)
{
  static_parseExpires("2026-06-01T00:00:00Z", JUNE_FIRST_EPOCH + 1);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRED, SECURITYTXT_FIELD_EXPIRES, 2);
  static_assertSeverityCounts(1, 0, 0);
  TEST_ASSERT_TRUE(g_report.m_isExpiresDateRead);

  static_parseExpires("2026-06-01T00:00:00Z", JUNE_FIRST_EPOCH);
  static_assertIssueCount(0);
}

void test_date_more_than_a_year_ahead_raises_expires_too_far_ahead(void)
{
  static_parseExpires("2026-06-01T00:00:00Z", JUNE_FIRST_EPOCH - 31536000);
  static_assertIssueCount(0);

  static_parseExpires("2026-06-01T00:00:00Z", JUNE_FIRST_EPOCH - 31536000 - 1);
  static_assertOneIssue(SECURITYTXT_ISSUE_EXPIRES_TOO_FAR_AHEAD, SECURITYTXT_FIELD_EXPIRES, 2);
  static_assertSeverityCounts(0, 1, 0);
}

void test_second_expires_raises_expires_duplicate_and_the_first_is_read(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Expires: 2027-01-01T00:00:00Z\nExpires: junk\n");

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_EXPIRES_DUPLICATE, SECURITYTXT_FIELD_EXPIRES, 3);
  static_assertIssue(1, SECURITYTXT_ISSUE_EXPIRES_DUPLICATE, SECURITYTXT_FIELD_EXPIRES, 4);
  TEST_ASSERT_EQUAL_INT64(JUNE_FIRST_EPOCH, g_report.m_expiresEpoch);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_EXPIRES]);
  TEST_ASSERT_EQUAL_INT(3, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES]);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 20, 2);
}

void test_invalid_first_expires_is_the_one_read(void)
{
  static_parseText(CONTACT_LINE "Expires: junk\n" EXPIRES_LINE);

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, 2);
  static_assertIssue(1, SECURITYTXT_ISSUE_EXPIRES_DUPLICATE, SECURITYTXT_FIELD_EXPIRES, 3);
  TEST_ASSERT_FALSE(g_report.m_isExpiresDateRead);
  static_assertSpan(SECURITYTXT_FIELD_EXPIRES, 0, 39, 4, 2);
}

void test_preferred_languages_tags_are_split_and_trimmed(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: en, fr-CA ,de\n");

  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(3, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  TEST_ASSERT_EQUAL_INT(3, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 0, 81, 2, 3);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 1, 85, 5, 3);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 2, 92, 2, 3);
}

void test_valid_tag_shapes_raise_nothing(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: x-klingon, zh-Hant-TW, abcdefgh, en-12345678, A-b1C2, Zz-09\n");

  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(6, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
}

void test_invalid_tag_shapes_raise_language_tag_invalid(void)
{
  static const char* const CASES[] = {
    "abcdefghi", "en-123456789", "en-", "-en", "e1", "en_US", "e@", "@n", "[n", "`n", "{n",
    "en-a/", "en-a:", "en-@", "en-[", "en-`", "en-{", "en--us",
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    g_bodyLen = 0;
    static_append(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: ");
    static_append(CASES[i]);
    static_append("\n");
    static_parse();
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_report.m_issueTotalCount, CASES[i]);
    static_assertIssue(0, SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 3);
    static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 0, 81, strlen(CASES[i]), 3);
  }
}

void test_empty_tag_is_invalid_and_kept(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: en,,fr\n");

  static_assertOneIssue(SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 3);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 0, 81, 2, 3);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 1, 84, 0, 3);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 2, 85, 2, 3);
}

void test_two_invalid_tags_raise_one_issue(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: abcdefghi, en_US\n");

  static_assertOneIssue(SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 3);
  TEST_ASSERT_EQUAL_INT(2, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
}

void test_second_preferred_languages_line_raises_duplicate(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: en\nPreferred-Languages: fr, de\nPreferred-Languages: x_y\n");

  static_assertIssueCount(2);
  static_assertIssue(0, SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 4);
  static_assertIssue(1, SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 5);
  static_assertSeverityCounts(2, 0, 0);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  TEST_ASSERT_EQUAL_INT(1, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 0, 81, 2, 3);
}

void test_21_tags_raise_too_many_values(void)
{
  static_append(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: ");
  static_appendRepeated("en,", 19);
  static_append("en\n");
  static_parse();
  static_assertIssueCount(0);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);

  g_bodyLen = 0;
  static_append(CONTACT_LINE EXPIRES_LINE "Preferred-Languages: ");
  static_appendRepeated("en,", 20);
  static_append("en\n");
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_TOO_MANY_VALUES, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 3);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  TEST_ASSERT_EQUAL_INT(21, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES]);
  static_assertSpan(SECURITYTXT_FIELD_PREFERRED_LANGUAGES, 19, 138, 2, 3);
}

void test_issues_past_the_cap_are_counted_but_not_kept(void)
{
  static_append(SIGNED_HEAD CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated("x\n", 51);
  static_append("Policy: https://example.com/\xff\n");
  static_append(SIGNED_TAIL);
  static_parse();

  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);
  TEST_ASSERT_EQUAL_INT(50, g_report.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(53, g_report.m_issueTotalCount);
  static_assertSeverityCounts(1, 51, 1);
  static_assertIssue(0, SECURITYTXT_ISSUE_INVALID_UTF8, SECURITYTXT_FIELD_NONE, 0);
  static_assertIssue(1, SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 6);
  static_assertIssue(49, SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 54);

  securitytxt_checkResponse(&g_report, g_body, NULL, CANONICAL_URL, true);
  TEST_ASSERT_EQUAL_INT(50, g_report.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(55, g_report.m_issueTotalCount);
  static_assertSeverityCounts(2, 52, 1);
}

void test_parse_clears_a_reused_report(void)
{
  static_parseText(SIGNED_HEAD CANONICAL_LINE CONTACT_LINE EXPIRES_LINE "X-Foo: bar\nPolicy: http://x\n" SIGNED_TAIL);
  TEST_ASSERT_TRUE(g_report.m_isOpenPgpSigned);

  static_parseText("");
  TEST_ASSERT_FALSE(g_report.m_isOpenPgpSigned);
  TEST_ASSERT_FALSE(g_report.m_isExpiresDateRead);
  TEST_ASSERT_EQUAL_INT64(0, g_report.m_expiresEpoch);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_unknownFieldCount);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_POLICY]);
  TEST_ASSERT_EQUAL_INT(0, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CANONICAL]);
  TEST_ASSERT_EQUAL_size_t(0, g_report.ma_values[SECURITYTXT_FIELD_CONTACT][0].m_offset);
  static_assertIssueCount(2);
  static_assertSeverityCounts(2, 0, 0);
}

static void static_parseMinimal(void)
{
  static_parseText(CANONICAL_LINE CONTACT_LINE EXPIRES_LINE);
  static_assertIssueCount(0);
}

void test_text_plain_with_charset_utf8_passes(void)
{
  static const char* const CASES[] = {
    "text/plain; charset=utf-8", "text/plain;charset=\"UTF-8\"", "TEXT/Plain; Charset=UTF-8",
    "text/plain; format=flowed; charset=utf-8", " text/plain ; charset = utf-8 ",
    "text/plain; charset=utf-8; format=flowed", "text/plain; charset=utf-8; charset=latin1",
    "text/plain; flowed; charset=utf-8",
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseMinimal();
    securitytxt_checkResponse(&g_report, g_body, CASES[i], CANONICAL_URL, false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_report.m_issueTotalCount, CASES[i]);
  }
}

void test_other_content_types_raise_content_type_invalid(void)
{
  static const char* const CASES[] = {
    "", "text/html; charset=utf-8", "text/plain", "text/plain;", "text/plain; charset=iso-8859-1",
    "text/plain; charset=\"utf-8", "text/plain; charset=utf-8\"", "text/plainx; charset=utf-8",
    "text/plai; charset=utf-8", "text/plain; charset=", "text/plain; xcharset=utf-8",
    "text/plain; charset=utf-88", "text/plain; charset=utf-", "text/plain; charset=\"\"",
    "text/plain; charset=\"", "text/plain charset=utf-8", "text/plain; charsetutf-8",
    "text/plain; charse=utf-8", "text/plain; charset=latin1; charset=utf-8",
    "text/plain; charset=xutf-8\"", "text/plain; charset=\"utf-8x",
  };
  static_parseMinimal();
  securitytxt_checkResponse(&g_report, g_body, NULL, CANONICAL_URL, false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(1, 0, 0);

  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseMinimal();
    securitytxt_checkResponse(&g_report, g_body, CASES[i], CANONICAL_URL, false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_report.m_issueTotalCount, CASES[i]);
    static_assertIssue(0, SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID, SECURITYTXT_FIELD_NONE, 0);
  }
}

#define GOOD_CONTENT_TYPE "text/plain; charset=utf-8"

void test_canonical_equal_to_the_final_url_passes(void)
{
  static const char* const CASES[] = {
    CANONICAL_URL, "HTTPS://EXAMPLE.COM/.well-known/security.txt",
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseMinimal();
    securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CASES[i], false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_report.m_issueTotalCount, CASES[i]);
  }
}

void test_canonical_unequal_to_the_final_url_raises_canonical_mismatch(void)
{
  static const char* const CASES[] = {
    "https://example.com/.well-known/SECURITY.txt", "https://example.com/.well-known/security.txt/",
    "https://example.com/.well-known/security.tx", "https://example.org/.well-known/security.txt",
    "https://example.com/.Well-known/security.txt", "httpz://example.com/.well-known/security.txt",
    "https;//example.com/.well-known/security.txt",
  };
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    static_parseMinimal();
    securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CASES[i], false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_report.m_issueTotalCount, CASES[i]);
    static_assertIssue(0, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
    static_assertSeverityCounts(0, 1, 0);
  }

  static_parseMinimal();
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, NULL, false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

void test_any_canonical_equal_to_the_final_url_passes(void)
{
  static_parseText("Canonical: https://example.com/a\nCanonical: https://example.com/b\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://example.com/a", false);
  static_assertIssueCount(0);

  static_parseText("Canonical: https://example.com/a\nCanonical: https://example.com/b\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://example.com/b", false);
  static_assertIssueCount(0);
}

void test_canonical_without_a_path_or_authority(void)
{
  static_parseText("Canonical: https://example.com\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "HTTPS://EXAMPLE.COM", false);
  static_assertIssueCount(0);

  static_parseText("Canonical: a://\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "A://", false);
  static_assertIssueCount(0);

  static_parseText("Canonical: mailto:a@example.com\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "mailto:a@example.com", false);
  static_assertIssueCount(0);

  static_parseText("Canonical: mailto:a@example.com\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "MAILTO:a@example.com", false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

void test_bytes_beside_the_capitals_are_not_folded(void)
{
  static_parseText("Canonical: https://a@example.com/\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://a`example.com/", false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);

  static_parseText("Canonical: https://[::1]/\n" CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://{::1]/", false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

void test_nul_byte_in_a_canonical_host_does_not_match(void)
{
  static const char CANONICAL[] = "Canonical: https://exa\0ple.com/\n";
  static_appendBytes(CANONICAL, sizeof(CANONICAL) - 1);
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_parse();
  static_assertOneIssue(SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE, SECURITYTXT_FIELD_NONE, 0);

  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://example.com/", false);
  static_assertIssueCount(2);
  static_assertIssue(1, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

static void static_assertCanonicalMatch(const char* canonical, const char* final_url, bool is_matched)
{
  char text[256];
  int  text_len = snprintf(text, sizeof(text), "Canonical: %s\n" CONTACT_LINE EXPIRES_LINE, canonical);
  TEST_ASSERT_TRUE(text_len > 0 && (size_t)text_len < sizeof(text));
  static_parseText(text);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_report.m_issueTotalCount, canonical);

  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, final_url, false);
  TEST_ASSERT_EQUAL_INT_MESSAGE(is_matched ? 0 : 1, g_report.m_issueTotalCount, final_url);
  if (!is_matched)
    static_assertIssue(0, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

void test_canonical_user_info_matches_byte_for_byte(void)
{
  static_assertCanonicalMatch("https://User@Example.COM/a", "https://User@example.com/a", true);
  static_assertCanonicalMatch("https://User@Example.COM/a", "https://user@example.com/a", false);
  static_assertCanonicalMatch("https://a@B@Example.com/", "https://a@B@EXAMPLE.com/", true);
  static_assertCanonicalMatch("https://a@B@Example.com/", "https://a@b@example.com/", false);
}

void test_separator_past_the_scheme_folds_nothing(void)
{
  static const char* const CASES[][2] = {
    { "1a://B", "1a://b" },
    { "://B",   "://b"   },
  };

  static_assertCanonicalMatch("mailto:X?u=http://h", "MAILTO:x?U=HTTP://h", false);
  static_assertCanonicalMatch("mailto:x?u=HTTP://h", "MAILTO:x?u=http://h", false);
  static_assertCanonicalMatch("mailto:X?u=http://h", "mailto:X?u=http://h", true);

  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    char text[128];
    int  text_len = snprintf(text, sizeof(text), "Canonical: %s\n" CONTACT_LINE EXPIRES_LINE, CASES[i][0]);
    TEST_ASSERT_TRUE(text_len > 0 && (size_t)text_len < sizeof(text));
    static_parseText(text);
    static_assertOneIssue(SECURITYTXT_ISSUE_URI_INVALID, SECURITYTXT_FIELD_CANONICAL, 1);
    securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CASES[i][1], false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_report.m_issueTotalCount, CASES[i][1]);
    static_assertIssue(1, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
  }
}

void test_authority_ends_at_slash_query_or_fragment(void)
{
  static_assertCanonicalMatch("HTTPS://EXAMPLE.COM/A", "https://example.com/A", true);
  static_assertCanonicalMatch("HTTPS://EXAMPLE.COM/A", "https://example.com/a", false);
  static_assertCanonicalMatch("https://Example.com:8443/A", "https://example.COM:8443/A", true);
  static_assertCanonicalMatch("https://Example.com:8443/A", "https://example.com:8443/a", false);
  static_assertCanonicalMatch("https://Example.com?Q=1", "https://example.com?Q=1", true);
  static_assertCanonicalMatch("https://Example.com?Q=1", "https://example.com?q=1", false);
  static_assertCanonicalMatch("https://Example.com#Top", "https://example.com#Top", true);
  static_assertCanonicalMatch("https://Example.com#Top", "https://example.com#top", false);
}

#define OTHER_CANONICAL_LINE "Canonical: https://example.com/x\n"

void test_canonical_mismatch_on_both_sides_of_the_value_cap(void)
{
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(OTHER_CANONICAL_LINE, 20);
  static_append(CANONICAL_LINE);
  static_parse();
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL]);
  TEST_ASSERT_EQUAL_INT(21, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CANONICAL]);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CANONICAL_URL, false);
  static_assertOneIssue(SECURITYTXT_ISSUE_TOO_MANY_VALUES, SECURITYTXT_FIELD_CANONICAL, 23);

  g_bodyLen = 0;
  static_append(CONTACT_LINE EXPIRES_LINE);
  static_appendRepeated(OTHER_CANONICAL_LINE, 20);
  static_parse();
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL]);
  TEST_ASSERT_EQUAL_INT(20, g_report.ma_valueTotalCount[SECURITYTXT_FIELD_CANONICAL]);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CANONICAL_URL, false);
  static_assertOneIssue(SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
}

void test_no_canonical_raises_no_mismatch(void)
{
  static_parseText(CONTACT_LINE EXPIRES_LINE);
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, "https://example.org/x", false);
  static_assertIssueCount(0);
}

void test_redirect_to_another_host_raises_redirected_to_other_host(void)
{
  static_parseMinimal();
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CANONICAL_URL, true);
  static_assertOneIssue(SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(0, 1, 0);

  static_parseMinimal();
  securitytxt_checkResponse(&g_report, g_body, GOOD_CONTENT_TYPE, CANONICAL_URL, false);
  static_assertIssueCount(0);
}

void test_response_issues_come_in_order_after_the_parse_issues(void)
{
  static_parseText(CANONICAL_LINE CONTACT_LINE EXPIRES_LINE "garbage\n");
  securitytxt_checkResponse(&g_report, g_body, "text/html", "https://example.org/", true);

  static_assertIssueCount(4);
  static_assertIssue(0, SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, 4);
  static_assertIssue(1, SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID, SECURITYTXT_FIELD_NONE, 0);
  static_assertIssue(2, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
  static_assertIssue(3, SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, SECURITYTXT_FIELD_NONE, 0);
  static_assertSeverityCounts(1, 3, 0);
}

void test_field_names(void)
{
  TEST_ASSERT_EQUAL_STRING("acknowledgments", securitytxt_fieldName(SECURITYTXT_FIELD_ACKNOWLEDGMENTS));
  TEST_ASSERT_EQUAL_STRING("canonical", securitytxt_fieldName(SECURITYTXT_FIELD_CANONICAL));
  TEST_ASSERT_EQUAL_STRING("contact", securitytxt_fieldName(SECURITYTXT_FIELD_CONTACT));
  TEST_ASSERT_EQUAL_STRING("csaf", securitytxt_fieldName(SECURITYTXT_FIELD_CSAF));
  TEST_ASSERT_EQUAL_STRING("encryption", securitytxt_fieldName(SECURITYTXT_FIELD_ENCRYPTION));
  TEST_ASSERT_EQUAL_STRING("expires", securitytxt_fieldName(SECURITYTXT_FIELD_EXPIRES));
  TEST_ASSERT_EQUAL_STRING("hiring", securitytxt_fieldName(SECURITYTXT_FIELD_HIRING));
  TEST_ASSERT_EQUAL_STRING("policy", securitytxt_fieldName(SECURITYTXT_FIELD_POLICY));
  TEST_ASSERT_EQUAL_STRING("preferred_languages", securitytxt_fieldName(SECURITYTXT_FIELD_PREFERRED_LANGUAGES));
  TEST_ASSERT_NULL(securitytxt_fieldName(SECURITYTXT_FIELD_COUNT));
  TEST_ASSERT_NULL(securitytxt_fieldName(SECURITYTXT_FIELD_NONE));
}

void test_issue_code_names_and_severities(void)
{
  static const struct { SecurityTxtIssueCode_t m_issueCode; const char* m_name; SecurityTxtSeverity_t m_severity; } CASES[] = {
    { SECURITYTXT_ISSUE_CONTACT_MISSING,               "contact_missing",               SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_EXPIRES_MISSING,               "expires_missing",               SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_EXPIRES_DUPLICATE,             "expires_duplicate",             SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_EXPIRES_INVALID,               "expires_invalid",               SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_EXPIRED,                       "expired",                       SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_EXPIRES_TOO_FAR_AHEAD,         "expires_too_far_ahead",         SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE, "preferred_languages_duplicate", SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID,          "language_tag_invalid",          SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY,          "encryption_holds_key",          SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_URI_INVALID,                   "uri_invalid",                   SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_URI_NOT_HTTPS,                 "uri_not_https",                 SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA,    "csaf_not_provider_metadata",    SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID,          "content_type_invalid",          SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_CANONICAL_MISMATCH,            "canonical_mismatch",            SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST,      "redirected_to_other_host",      SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_SIGNATURE_MALFORMED,           "signature_malformed",           SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_TEXT_AFTER_SIGNATURE,          "text_after_signature",          SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_SIGNED_WITHOUT_CANONICAL,      "signed_without_canonical",      SECURITYTXT_SEVERITY_INFO    },
    { SECURITYTXT_ISSUE_INVALID_LINE_ENDING,           "invalid_line_ending",           SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_INVALID_UTF8,                  "invalid_utf8",                  SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE,             "contains_nul_byte",             SECURITYTXT_SEVERITY_ERROR   },
    { SECURITYTXT_ISSUE_BYTE_ORDER_MARK,               "byte_order_mark",               SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID,           "line_syntax_invalid",           SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_FIELD_EMPTY,                   "field_empty",                   SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_LINE_TOO_LONG,                 "line_too_long",                 SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_TOO_MANY_LINES,                "too_many_lines",                SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_TOO_MANY_VALUES,               "too_many_values",               SECURITYTXT_SEVERITY_WARNING },
    { SECURITYTXT_ISSUE_FILE_TOO_LARGE,                "file_too_large",                SECURITYTXT_SEVERITY_ERROR   },
  };
  TEST_ASSERT_EQUAL_INT(SECURITYTXT_ISSUE_CODE_COUNT, (int)(sizeof(CASES) / sizeof(CASES[0])));
  for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(i, CASES[i].m_issueCode);
    TEST_ASSERT_EQUAL_STRING(CASES[i].m_name, securitytxt_issueCodeName(CASES[i].m_issueCode));
    TEST_ASSERT_EQUAL_INT_MESSAGE(CASES[i].m_severity, securitytxt_issueSeverity(CASES[i].m_issueCode), CASES[i].m_name);
  }
  TEST_ASSERT_NULL(securitytxt_issueCodeName(SECURITYTXT_ISSUE_CODE_COUNT));
  TEST_ASSERT_EQUAL_INT(SECURITYTXT_SEVERITY_COUNT, securitytxt_issueSeverity(SECURITYTXT_ISSUE_CODE_COUNT));
}

void test_severity_names(void)
{
  TEST_ASSERT_EQUAL_STRING("error", securitytxt_severityName(SECURITYTXT_SEVERITY_ERROR));
  TEST_ASSERT_EQUAL_STRING("warning", securitytxt_severityName(SECURITYTXT_SEVERITY_WARNING));
  TEST_ASSERT_EQUAL_STRING("info", securitytxt_severityName(SECURITYTXT_SEVERITY_INFO));
  TEST_ASSERT_NULL(securitytxt_severityName(SECURITYTXT_SEVERITY_COUNT));
}

void test_limits_hold_their_values(void)
{
  TEST_ASSERT_EQUAL_INT(32768, SECURITYTXT_MAX_BODY_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(2048, SECURITYTXT_MAX_LINE_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(1000, SECURITYTXT_MAX_LINE_COUNT);
  TEST_ASSERT_EQUAL_INT(20, SECURITYTXT_MAX_VALUE_COUNT);
  TEST_ASSERT_EQUAL_INT(50, SECURITYTXT_MAX_ISSUE_COUNT);
  TEST_ASSERT_EQUAL_INT(31536000, SECURITYTXT_EXPIRES_MAX_AHEAD_SECONDS);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(91, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_minimal_file_reads_contact_and_expires_with_no_issue);
  RUN_TEST(test_cut_body_raises_only_file_too_large);
  RUN_TEST(test_empty_body_raises_contact_missing_then_expires_missing);
  RUN_TEST(test_byte_order_mark_is_skipped_and_raises_byte_order_mark);
  RUN_TEST(test_byte_order_mark_alone_raises_byte_order_mark_and_both_missing);
  RUN_TEST(test_two_bytes_of_a_byte_order_mark_raise_invalid_utf8);
  RUN_TEST(test_invalid_utf8_raises_one_issue_and_the_values_are_kept);
  RUN_TEST(test_nul_bytes_raise_one_contains_nul_byte);
  RUN_TEST(test_lone_cr_ends_a_line_and_raises_invalid_line_ending);
  RUN_TEST(test_cr_before_crlf_is_a_lone_cr);
  RUN_TEST(test_lf_before_cr_leaves_a_lone_cr);
  RUN_TEST(test_crlf_line_endings_raise_no_issue);
  RUN_TEST(test_last_line_without_a_line_end_is_read);
  RUN_TEST(test_bytes_after_the_body_are_not_read);
  RUN_TEST(test_field_lines_of_2047_and_2048_bytes_are_read);
  RUN_TEST(test_field_line_of_2049_bytes_raises_line_too_long);
  RUN_TEST(test_long_line_of_no_known_field_raises_line_too_long_on_no_field);
  RUN_TEST(test_lines_999_and_1000_are_read);
  RUN_TEST(test_line_1001_is_not_read_and_raises_too_many_lines);
  RUN_TEST(test_whole_signed_envelope_is_signed_and_its_fields_are_read);
  RUN_TEST(test_signed_file_without_canonical_raises_signed_without_canonical);
  RUN_TEST(test_dash_escaped_line_is_read_after_its_dash);
  RUN_TEST(test_dash_in_an_unsigned_file_is_part_of_the_name);
  RUN_TEST(test_blank_lines_before_the_envelope_and_two_hash_lines_are_read);
  RUN_TEST(test_header_line_in_lower_case_does_not_sign_the_file);
  RUN_TEST(test_signed_envelope_with_crlf_endings_is_signed);
  RUN_TEST(test_header_without_a_blank_line_raises_signature_malformed);
  RUN_TEST(test_envelope_without_a_signature_raises_signature_malformed_and_reads_to_the_end);
  RUN_TEST(test_signature_without_an_end_raises_signature_malformed);
  RUN_TEST(test_signature_malformed_is_raised_once);
  RUN_TEST(test_header_alone_raises_signature_malformed);
  RUN_TEST(test_envelope_without_a_hash_line_raises_signature_malformed);
  RUN_TEST(test_line_after_the_signature_raises_text_after_signature_once);
  RUN_TEST(test_blank_lines_after_the_signature_raise_nothing);
  RUN_TEST(test_header_with_a_trailing_space_is_not_an_envelope);
  RUN_TEST(test_signature_line_with_a_trailing_space_is_a_content_line);
  RUN_TEST(test_comments_and_blank_lines_are_skipped);
  RUN_TEST(test_line_without_a_colon_raises_line_syntax_invalid);
  RUN_TEST(test_line_with_an_empty_name_raises_line_syntax_invalid);
  RUN_TEST(test_names_are_read_in_any_case_and_values_trimmed);
  RUN_TEST(test_every_field_name_is_read);
  RUN_TEST(test_unknown_fields_are_only_counted);
  RUN_TEST(test_empty_value_raises_field_empty_and_keeps_nothing);
  RUN_TEST(test_19_and_20_values_of_a_field_are_kept);
  RUN_TEST(test_21st_value_raises_too_many_values_and_is_not_kept);
  RUN_TEST(test_too_many_values_is_raised_once_for_each_field);
  RUN_TEST(test_value_with_no_scheme_raises_uri_invalid_in_each_uri_field);
  RUN_TEST(test_every_scheme_byte_is_read);
  RUN_TEST(test_bytes_beside_the_scheme_bytes_raise_uri_invalid);
  RUN_TEST(test_http_scheme_raises_uri_not_https);
  RUN_TEST(test_key_in_encryption_raises_only_encryption_holds_key);
  RUN_TEST(test_lower_case_begin_in_encryption_is_not_a_key);
  RUN_TEST(test_csaf_path_must_end_in_provider_metadata);
  RUN_TEST(test_csaf_path_needs_a_slash_before_provider_metadata);
  RUN_TEST(test_each_date_form_is_read);
  RUN_TEST(test_last_day_of_each_month_is_read_and_the_next_is_not);
  RUN_TEST(test_leap_days_follow_the_gregorian_rule);
  RUN_TEST(test_invalid_dates_raise_expires_invalid);
  RUN_TEST(test_date_before_now_raises_expired);
  RUN_TEST(test_date_more_than_a_year_ahead_raises_expires_too_far_ahead);
  RUN_TEST(test_second_expires_raises_expires_duplicate_and_the_first_is_read);
  RUN_TEST(test_invalid_first_expires_is_the_one_read);
  RUN_TEST(test_preferred_languages_tags_are_split_and_trimmed);
  RUN_TEST(test_valid_tag_shapes_raise_nothing);
  RUN_TEST(test_invalid_tag_shapes_raise_language_tag_invalid);
  RUN_TEST(test_empty_tag_is_invalid_and_kept);
  RUN_TEST(test_two_invalid_tags_raise_one_issue);
  RUN_TEST(test_second_preferred_languages_line_raises_duplicate);
  RUN_TEST(test_21_tags_raise_too_many_values);
  RUN_TEST(test_issues_past_the_cap_are_counted_but_not_kept);
  RUN_TEST(test_parse_clears_a_reused_report);
  RUN_TEST(test_text_plain_with_charset_utf8_passes);
  RUN_TEST(test_other_content_types_raise_content_type_invalid);
  RUN_TEST(test_canonical_equal_to_the_final_url_passes);
  RUN_TEST(test_canonical_unequal_to_the_final_url_raises_canonical_mismatch);
  RUN_TEST(test_any_canonical_equal_to_the_final_url_passes);
  RUN_TEST(test_canonical_without_a_path_or_authority);
  RUN_TEST(test_bytes_beside_the_capitals_are_not_folded);
  RUN_TEST(test_nul_byte_in_a_canonical_host_does_not_match);
  RUN_TEST(test_canonical_user_info_matches_byte_for_byte);
  RUN_TEST(test_separator_past_the_scheme_folds_nothing);
  RUN_TEST(test_authority_ends_at_slash_query_or_fragment);
  RUN_TEST(test_canonical_mismatch_on_both_sides_of_the_value_cap);
  RUN_TEST(test_no_canonical_raises_no_mismatch);
  RUN_TEST(test_redirect_to_another_host_raises_redirected_to_other_host);
  RUN_TEST(test_response_issues_come_in_order_after_the_parse_issues);
  RUN_TEST(test_field_names);
  RUN_TEST(test_issue_code_names_and_severities);
  RUN_TEST(test_severity_names);
  RUN_TEST(test_limits_hold_their_values);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
