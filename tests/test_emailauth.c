#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "unity/unity.h"
#include "emailauth.h"

void setUp(void)    {}
void tearDown(void) {}

#define KEY_BASE64_SIZE 2100

#define RECORD_SIZE 2400

#define KEY_DER_PADDED_LEN 1536

#define RSA_2048_KEY_INFO_LEN 294

#define SPF_RECORD_SIZE 1024

#define RFC_8463_ED25519_KEY "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" /* gitleaks:allow */

typedef struct {
  EmailAuthSpfTermKind_t m_kind;
  const char*            mp_value;
  int                    m_ip4PrefixLength;
  int                    m_ip6PrefixLength;
} SpfExpectedTerm_t;

static DnsRecordText_t static_text(const char* text)
{
  return (DnsRecordText_t){ (char*)text, strlen(text) };
}

static bool static_isSpan(EmailAuthSpan_t span, const char* text)
{
  return span.m_byteCount == strlen(text) && memcmp(span.mp_bytes, text, span.m_byteCount) == 0;
}

static EVP_PKEY* static_rsaKey(int key_bits)
{
  static EVP_PKEY* key_1024 = NULL;
  static EVP_PKEY* key_2048 = NULL;
  EVP_PKEY**       key      = key_bits == 1024 ? &key_1024 : &key_2048;
  if (*key == NULL)
    *key = EVP_RSA_gen((unsigned int)key_bits);
  TEST_ASSERT_NOT_NULL(*key);
  return *key;
}

static void static_writeKeyBase64(EVP_PKEY* key, bool is_bare_rsa, int padded_der_len, char* base64_out)
{
  unsigned char* der     = NULL;
  int            der_len = is_bare_rsa ? i2d_PublicKey(key, &der) : i2d_PUBKEY(key, &der);
  TEST_ASSERT_TRUE(der_len > 0);

  unsigned char padded_der[KEY_BASE64_SIZE] = { 0 };
  int           written_len = padded_der_len > 0 ? padded_der_len : der_len;
  TEST_ASSERT_TRUE(written_len >= der_len && written_len / 3 * 4 + 4 < KEY_BASE64_SIZE);
  memcpy(padded_der, der, (size_t)der_len);
  OPENSSL_free(der);

  EVP_EncodeBlock((unsigned char*)base64_out, padded_der, written_len);
}

static EmailAuthDkim_t static_parseDkimWith(const char* before, const char* text, const char* after)
{
  static char record[RECORD_SIZE];
  int         record_len = snprintf(record, sizeof(record), "%s%s%s", before, text, after);
  TEST_ASSERT_TRUE(record_len >= 0 && (size_t)record_len < sizeof(record));

  DnsRecordText_t record_text = static_text(record);
  EmailAuthDkim_t dkim        = { 0 };
  emailauth_parseDkim(&record_text, &dkim);
  return dkim;
}

static EmailAuthDmarc_t static_parseDmarc(const char* record)
{
  DnsRecordText_t  record_text = static_text(record);
  EmailAuthDmarc_t dmarc       = { 0 };
  TEST_ASSERT_TRUE_MESSAGE(emailauth_isDmarcRecord(&record_text), record);
  emailauth_parseDmarc(&record_text, &dmarc);
  return dmarc;
}

static void static_parseSpf(const char* record, EmailAuthSpf_t* spf)
{
  DnsRecordText_t record_text = static_text(record);
  TEST_ASSERT_TRUE_MESSAGE(emailauth_isSpfRecord(&record_text), record);
  emailauth_parseSpf(&record_text, spf);
}

static void static_assertSpfTerms(const char* record, const SpfExpectedTerm_t* expected, int term_count)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf(record, &spf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(term_count, spf.m_termCount, record);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, spf.m_invalidTermCount, record);
  for (int i = 0; i < term_count; i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_kind, spf.ma_terms[i].m_kind, expected[i].mp_value);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(spf.ma_terms[i].m_value, expected[i].mp_value), expected[i].mp_value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_ip4PrefixLength, spf.ma_terms[i].m_ip4PrefixLength, expected[i].mp_value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_ip6PrefixLength, spf.ma_terms[i].m_ip6PrefixLength, expected[i].mp_value);
  }
}

static void static_assertEachSpfTermInvalid(const char* const* terms, int term_count)
{
  char record[SPF_RECORD_SIZE] = "v=spf1";
  for (int i = 0; i < term_count; i++)
  {
    TEST_ASSERT_TRUE(strlen(record) + 1 + strlen(terms[i]) < sizeof(record));
    strcat(record, " ");
    strcat(record, terms[i]);
  }

  EmailAuthSpf_t spf = { 0 };
  static_parseSpf(record, &spf);
  TEST_ASSERT_EQUAL_INT(term_count, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(term_count, spf.m_invalidTermCount);
  TEST_ASSERT_EQUAL_INT(0, spf.m_dnsLookupTermCount);
  for (int i = 0; i < term_count; i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_SPF_TERM_INVALID, spf.ma_terms[i].m_kind, terms[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_QUALIFIER_PASS, spf.ma_terms[i].m_qualifier, terms[i]);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(spf.ma_terms[i].m_value, terms[i]), terms[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, spf.ma_terms[i].m_ip4PrefixLength, terms[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, spf.ma_terms[i].m_ip6PrefixLength, terms[i]);
  }
}

static void static_writeBytesBase64(const unsigned char* bytes, int byte_count, char* base64_out)
{
  TEST_ASSERT_TRUE(byte_count / 3 * 4 + 4 < KEY_BASE64_SIZE);
  EVP_EncodeBlock((unsigned char*)base64_out, bytes, byte_count);
}

void test_isSpfRecord_accepts_the_version_alone_or_before_a_space(void)
{
  static const char* const records[] = { "v=spf1", "v=spf1 -all", "V=SPF1 ~all" };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    DnsRecordText_t record = static_text(records[i]);
    TEST_ASSERT_TRUE_MESSAGE(emailauth_isSpfRecord(&record), records[i]);
  }
}

void test_isSpfRecord_refuses_another_version_or_no_space(void)
{
  static const char* const records[] = { "v=spf10", "v=spf2 -all", "v=spf1-all", " v=spf1", "v=spf1\t-all", "v=spf", "" };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    DnsRecordText_t record = static_text(records[i]);
    TEST_ASSERT_FALSE_MESSAGE(emailauth_isSpfRecord(&record), records[i]);
  }
}

void test_isDmarcRecord_accepts_v_DMARC1_first(void)
{
  static const char* const records[] = { "v=DMARC1; p=none", "v=DMARC1", "v=DMARC1;", " V = DMARC1 ;p=reject" };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    DnsRecordText_t record = static_text(records[i]);
    TEST_ASSERT_TRUE_MESSAGE(emailauth_isDmarcRecord(&record), records[i]);
  }
}

void test_isDmarcRecord_refuses_any_other_first_tag(void)
{
  static const char* const records[] = { "v=dmarc1; p=none", "p=none; v=DMARC1", "v=DMARC2", "v=DMARC10", "v DMARC1", ";", "" };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    DnsRecordText_t record = static_text(records[i]);
    TEST_ASSERT_FALSE_MESSAGE(emailauth_isDmarcRecord(&record), records[i]);
  }
}

void test_countSpfRecords_counts_and_finds_the_first(void)
{
  DnsRecordText_t texts[3] = { static_text("google-site-verification=x"), static_text("v=DMARC1; p=none"), static_text("v=spf10") };
  int             index    = -1;
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_NONE, emailauth_countSpfRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(-1, index);

  texts[1] = static_text("v=spf1 -all");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_ONE, emailauth_countSpfRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(1, index);

  texts[2] = static_text("v=spf1 a -all");
  index    = -1;
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_MANY, emailauth_countSpfRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(1, index);

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_NONE, emailauth_countSpfRecords(NULL, 0, &index));
}

void test_countDmarcRecords_counts_and_finds_the_first(void)
{
  DnsRecordText_t texts[3] = { static_text("v=spf1 -all"), static_text("v=dmarc1; p=none"), static_text("x") };
  int             index    = -1;
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_NONE, emailauth_countDmarcRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(-1, index);

  texts[2] = static_text("v=DMARC1; p=reject");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_ONE, emailauth_countDmarcRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(2, index);

  texts[0] = static_text("v=DMARC1; p=none");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_RECORD_MANY, emailauth_countDmarcRecords(texts, 3, &index));
  TEST_ASSERT_EQUAL_INT(0, index);
}

void test_parseSpf_reads_each_qualifier(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 +a -mx ~ptr ?all exists:x.example", &spf);
  static const EmailAuthSpfTermKind_t kinds[]      = { EMAILAUTH_SPF_TERM_A, EMAILAUTH_SPF_TERM_MX, EMAILAUTH_SPF_TERM_PTR, EMAILAUTH_SPF_TERM_ALL, EMAILAUTH_SPF_TERM_EXISTS };
  static const EmailAuthQualifier_t   qualifiers[] = { EMAILAUTH_QUALIFIER_PASS, EMAILAUTH_QUALIFIER_FAIL, EMAILAUTH_QUALIFIER_SOFTFAIL, EMAILAUTH_QUALIFIER_NEUTRAL, EMAILAUTH_QUALIFIER_PASS };
  TEST_ASSERT_EQUAL_INT(5, spf.m_termCount);
  for (int i = 0; i < 5; i++)
  {
    TEST_ASSERT_EQUAL_INT(kinds[i], spf.ma_terms[i].m_kind);
    TEST_ASSERT_EQUAL_INT(qualifiers[i], spf.ma_terms[i].m_qualifier);
  }
  TEST_ASSERT_EQUAL_INT(0, spf.m_invalidTermCount);
}

void test_parseSpf_reads_each_mechanism_and_its_value(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 include:_spf.google.com a:mail.example.com/24 mx/26 a/24 ip4:192.0.2.0/24 ip6:2001:db8::/32 exists:%{i}.x.example ptr:example.net ptr a mx all", &spf);
  static const struct { EmailAuthSpfTermKind_t m_kind; const char* mp_value; } expected[] = {
    { EMAILAUTH_SPF_TERM_INCLUDE, "_spf.google.com" },
    { EMAILAUTH_SPF_TERM_A,       "mail.example.com/24" },
    { EMAILAUTH_SPF_TERM_MX,      "/26" },
    { EMAILAUTH_SPF_TERM_A,       "/24" },
    { EMAILAUTH_SPF_TERM_IP4,     "192.0.2.0/24" },
    { EMAILAUTH_SPF_TERM_IP6,     "2001:db8::/32" },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%{i}.x.example" },
    { EMAILAUTH_SPF_TERM_PTR,     "example.net" },
    { EMAILAUTH_SPF_TERM_PTR,     "" },
    { EMAILAUTH_SPF_TERM_A,       "" },
    { EMAILAUTH_SPF_TERM_MX,      "" },
    { EMAILAUTH_SPF_TERM_ALL,     "" },
  };
  TEST_ASSERT_EQUAL_INT(12, spf.m_termCount);
  for (int i = 0; i < 12; i++)
  {
    TEST_ASSERT_EQUAL_INT(expected[i].m_kind, spf.ma_terms[i].m_kind);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(spf.ma_terms[i].m_value, expected[i].mp_value), expected[i].mp_value);
  }
  TEST_ASSERT_EQUAL_INT(0, spf.m_invalidTermCount);
}

void test_parseSpf_reads_each_kind_of_modifier(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 REDIRECT=_spf.example.com exp=explain.example.com foo-bar.b_z=val x=", &spf);
  static const struct { EmailAuthSpfTermKind_t m_kind; const char* mp_value; } expected[] = {
    { EMAILAUTH_SPF_TERM_REDIRECT,         "_spf.example.com" },
    { EMAILAUTH_SPF_TERM_EXP,              "explain.example.com" },
    { EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER, "val" },
    { EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER, "" },
  };
  TEST_ASSERT_EQUAL_INT(4, spf.m_termCount);
  for (int i = 0; i < 4; i++)
  {
    TEST_ASSERT_EQUAL_INT(expected[i].m_kind, spf.ma_terms[i].m_kind);
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_QUALIFIER_PASS, spf.ma_terms[i].m_qualifier);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(spf.ma_terms[i].m_value, expected[i].mp_value), expected[i].mp_value);
  }
  TEST_ASSERT_EQUAL_INT(0, spf.m_invalidTermCount);
}

void test_parseSpf_marks_each_term_rfc_7208_does_not_allow(void)
{
  static const char* const terms[] = {
    "include", "include:", "ip4", "ip6", "ip6:", "ip6/64", "exists", "a:", "ptr/24", "all:x", "allx",
    "-redirect=x", "redirect=", "exp=", "foo", "1x=y", "a\tb", "+", "~", "!all",
  };
  static_assertEachSpfTermInvalid(terms, (int)(sizeof(terms) / sizeof(terms[0])));
}

void test_parseSpf_reads_names_in_any_case(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 INCLUDE:x.example -ALL", &spf);
  TEST_ASSERT_EQUAL_INT(2, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_INCLUDE, spf.ma_terms[0].m_kind);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_ALL, spf.ma_terms[1].m_kind);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_QUALIFIER_FAIL, spf.ma_terms[1].m_qualifier);
}

void test_parseSpf_skips_runs_of_spaces(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1   a    -all  ", &spf);
  TEST_ASSERT_EQUAL_INT(2, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_A, spf.ma_terms[0].m_kind);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_ALL, spf.ma_terms[1].m_kind);

  static_parseSpf("v=spf1", &spf);
  TEST_ASSERT_EQUAL_INT(0, spf.m_termCount);
}

void test_parseSpf_counts_the_dns_lookup_terms(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 include:a.example a mx ptr exists:b.example redirect=c.example ip4:192.0.2.1 ip6:::1 all exp=d.example foo=bar", &spf);
  TEST_ASSERT_EQUAL_INT(6, spf.m_dnsLookupTermCount);

  static_parseSpf("v=spf1 ip4:192.0.2.1 ip6:::1 all exp=d.example foo=bar", &spf);
  TEST_ASSERT_EQUAL_INT(0, spf.m_dnsLookupTermCount);

  static_parseSpf("v=spf1 include a: exists redirect=", &spf);
  TEST_ASSERT_EQUAL_INT(0, spf.m_dnsLookupTermCount);
  TEST_ASSERT_EQUAL_INT(4, spf.m_invalidTermCount);
}

void test_parseSpf_keeps_the_first_terms_and_counts_the_rest(void)
{
  char record[512] = "v=spf1";
  for (int i = 0; i < EMAILAUTH_SPF_MAX_TERM_COUNT; i++)
    strcat(record, " a");

  EmailAuthSpf_t spf = { 0 };
  static_parseSpf(record, &spf);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_MAX_TERM_COUNT, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(0, spf.m_unreadTermCount);

  strcat(record, " mx ptr include:x.example bad bad");
  static_parseSpf(record, &spf);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_MAX_TERM_COUNT, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(5, spf.m_unreadTermCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_MAX_TERM_COUNT + 3, spf.m_dnsLookupTermCount);
  TEST_ASSERT_EQUAL_INT(2, spf.m_invalidTermCount);
}

void test_parseSpf_reads_ip4_and_ip6_networks(void)
{
  static const SpfExpectedTerm_t expected[] = {
    { EMAILAUTH_SPF_TERM_IP4, "192.0.2.1",          -1,  -1 },
    { EMAILAUTH_SPF_TERM_IP4, "0.0.0.0/0",           0,  -1 },
    { EMAILAUTH_SPF_TERM_IP4, "192.0.2.0/32",       32,  -1 },
    { EMAILAUTH_SPF_TERM_IP4, "198.51.100.0/9",      9,  -1 },
    { EMAILAUTH_SPF_TERM_IP6, "::1/128",            -1, 128 },
    { EMAILAUTH_SPF_TERM_IP6, "::ffff:192.0.2.1",   -1,  -1 },
    { EMAILAUTH_SPF_TERM_IP6, "2001:db8::/0",       -1,   0 },
    { EMAILAUTH_SPF_TERM_IP6, "2001:db8::/48",      -1,  48 },
  };
  static_assertSpfTerms("v=spf1 ip4:192.0.2.1 ip4:0.0.0.0/0 ip4:192.0.2.0/32 ip4:198.51.100.0/9 ip6:::1/128 ip6:::ffff:192.0.2.1 ip6:2001:db8::/0 ip6:2001:db8::/48",
                        expected, (int)(sizeof(expected) / sizeof(expected[0])));
}

void test_parseSpf_marks_wrong_ip_networks_invalid(void)
{
  static const char* const terms[] = {
    "ip4:999.1.1.1", "ip4:192.0.2.1/33", "ip4:192.0.2.1/", "ip4:192.0.2.1/032", "ip4:192.0.2.1/00",
    "ip4:192.0.2.1/4294967328", "ip4:01.2.3.4", "ip4:1.2.3", "ip4:::1", "ip4:192.0.2.0/24/24",
    "ip6:zz", "ip6:::1/129", "ip6:::1//64", "ip6:192.0.2.1", "ip6:fe80::1%eth0",
    "ip6:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000",
    "ip6:0000:0000:0000:0000:0000:0000:0000:0000:000000",
  };
  TEST_ASSERT_EQUAL_size_t(strlen("ip6:") + INET6_ADDRSTRLEN, strlen(terms[sizeof(terms) / sizeof(terms[0]) - 1]));
  static_assertEachSpfTermInvalid(terms, (int)(sizeof(terms) / sizeof(terms[0])));
}

void test_parseSpf_an_ip4_term_with_a_nul_byte_is_invalid(void)
{
  static const char record_bytes[] = "v=spf1 ip4:192.0.2.1\0x -all";
  DnsRecordText_t   record         = { (char*)record_bytes, sizeof(record_bytes) - 1 };
  EmailAuthSpf_t    spf            = { 0 };
  emailauth_parseSpf(&record, &spf);
  TEST_ASSERT_EQUAL_INT(2, spf.m_termCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_INVALID, spf.ma_terms[0].m_kind);
  TEST_ASSERT_EQUAL_size_t(strlen("ip4:192.0.2.1") + 2, spf.ma_terms[0].m_value.m_byteCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_TERM_ALL, spf.ma_terms[1].m_kind);
  TEST_ASSERT_EQUAL_INT(1, spf.m_invalidTermCount);
}

void test_parseSpf_reads_the_prefix_lengths_of_a_and_mx(void)
{
  static const SpfExpectedTerm_t expected[] = {
    { EMAILAUTH_SPF_TERM_A,  "/24",                  24,  -1 },
    { EMAILAUTH_SPF_TERM_A,  "//64",                 -1,  64 },
    { EMAILAUTH_SPF_TERM_MX, "/25//65",              25,  65 },
    { EMAILAUTH_SPF_TERM_A,  "mail.example.com/26//66", 26, 66 },
    { EMAILAUTH_SPF_TERM_A,  "mail.example.com/24",  24,  -1 },
    { EMAILAUTH_SPF_TERM_MX, "example.com//127",     -1, 127 },
    { EMAILAUTH_SPF_TERM_A,  "/32//128",             32, 128 },
    { EMAILAUTH_SPF_TERM_MX, "/0//0",                 0,   0 },
    { EMAILAUTH_SPF_TERM_A,  "example.com",          -1,  -1 },
  };
  static_assertSpfTerms("v=spf1 a/24 a//64 mx/25//65 a:mail.example.com/26//66 a:mail.example.com/24 mx:example.com//127 a/32//128 mx/0//0 a:example.com",
                        expected, (int)(sizeof(expected) / sizeof(expected[0])));
}

void test_parseSpf_marks_wrong_prefix_lengths_invalid(void)
{
  static const char* const terms[] = {
    "a/33", "a//129", "a/99", "a/", "a//", "a///64", "mx/024", "mx//064", "a:/24",
    "mx//64/24", "a:example.com/24x", "mx/24/",
  };
  static_assertEachSpfTermInvalid(terms, (int)(sizeof(terms) / sizeof(terms[0])));
}

void test_parseSpf_reads_domain_specs_and_macros(void)
{
  static const SpfExpectedTerm_t expected[] = {
    { EMAILAUTH_SPF_TERM_INCLUDE, "example.com.",                                      -1, -1 },
    { EMAILAUTH_SPF_TERM_INCLUDE, "_spf.example-1.com",                                -1, -1 },
    { EMAILAUTH_SPF_TERM_INCLUDE, "x.1-2",                                             -1, -1 },
    { EMAILAUTH_SPF_TERM_INCLUDE, "..example",                                         -1, -1 },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%{s}%{l}%{o}%{d}%{i}%{p}%{h}%{v}.x.example",        -1, -1 },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%{S}%{L}%{O}%{D}%{I}%{P}%{H}%{V}.x.example",        -1, -1 },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%{ir}.%{i2r.-}.%{d10R+,/_=}.x.example",             -1, -1 },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%{i01}.x.example",                                  -1, -1 },
    { EMAILAUTH_SPF_TERM_EXISTS,  "%%%_%-.x.example",                                  -1, -1 },
    { EMAILAUTH_SPF_TERM_INCLUDE, "%{d}",                                              -1, -1 },
    { EMAILAUTH_SPF_TERM_PTR,     "!~.example",                                        -1, -1 },
    { EMAILAUTH_SPF_TERM_EXP,     "explain.%{d}",                                      -1, -1 },
    { EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER, "%{i}x",                                    -1, -1 },
  };
  static_assertSpfTerms("v=spf1 include:example.com. include:_spf.example-1.com include:x.1-2 include:..example "
                        "exists:%{s}%{l}%{o}%{d}%{i}%{p}%{h}%{v}.x.example exists:%{S}%{L}%{O}%{D}%{I}%{P}%{H}%{V}.x.example "
                        "exists:%{ir}.%{i2r.-}.%{d10R+,/_=}.x.example exists:%{i01}.x.example exists:%%%_%-.x.example include:%{d} ptr:!~.example "
                        "exp=explain.%{d} foo=%{i}x",
                        expected, (int)(sizeof(expected) / sizeof(expected[0])));
}

void test_parseSpf_marks_wrong_domain_specs_and_macros_invalid(void)
{
  static const char* const terms[] = {
    "include:localhost", "include:192.0.2.1", "include:example.-com", "include:example.com-",
    "include:example.com..", "include:%{d}.", "exists:%x.example", "exists:%", "exists:%{z}.x.example",
    "exists:%{c}.x.example", "exists:%{r}.x.example", "exists:%{t}.x.example", "exists:%{i.x.example",
    "exists:%{i;}.x.example", "exists:%{}.x.example",
    "exists:%{d0}.x.example", "exists:%{i00}.x.example", "exists:%{d0r}.x.example", "exists:%{i0.}.x.example", "exists:%{irr}.x.example", "exists:%{ir2}.x.example", "exists:a\x7f.example", "exists:a\tb.example",
    "redirect=localhost", "exp=%{c}.example", "foo=%x", "ptr:%{d}x",
  };
  static_assertEachSpfTermInvalid(terms, (int)(sizeof(terms) / sizeof(terms[0])));
}

void test_parseSpf_marks_a_second_redirect_or_exp_invalid(void)
{
  EmailAuthSpf_t spf = { 0 };
  static_parseSpf("v=spf1 redirect=a.example exp=x.example REDIRECT=b.example EXP=y.example", &spf);
  static const struct { EmailAuthSpfTermKind_t m_kind; const char* mp_value; } expected[] = {
    { EMAILAUTH_SPF_TERM_REDIRECT, "a.example" },
    { EMAILAUTH_SPF_TERM_EXP,      "x.example" },
    { EMAILAUTH_SPF_TERM_INVALID,  "REDIRECT=b.example" },
    { EMAILAUTH_SPF_TERM_INVALID,  "EXP=y.example" },
  };
  TEST_ASSERT_EQUAL_INT(4, spf.m_termCount);
  for (int i = 0; i < 4; i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_kind, spf.ma_terms[i].m_kind, expected[i].mp_value);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(spf.ma_terms[i].m_value, expected[i].mp_value), expected[i].mp_value);
  }
  TEST_ASSERT_EQUAL_INT(1, spf.m_dnsLookupTermCount);
  TEST_ASSERT_EQUAL_INT(2, spf.m_invalidTermCount);

  static_parseSpf("v=spf1 redirect=localhost exp=%{c}.example redirect=b.example exp=y.example redirectx=c.example", &spf);
  static const EmailAuthSpfTermKind_t kinds[] = {
    EMAILAUTH_SPF_TERM_INVALID, EMAILAUTH_SPF_TERM_INVALID, EMAILAUTH_SPF_TERM_INVALID, EMAILAUTH_SPF_TERM_INVALID,
    EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER,
  };
  TEST_ASSERT_EQUAL_INT(5, spf.m_termCount);
  for (int i = 0; i < 5; i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(kinds[i], spf.ma_terms[i].m_kind, "after an invalid first redirect= and exp=");
  TEST_ASSERT_EQUAL_INT(0, spf.m_dnsLookupTermCount);
  TEST_ASSERT_EQUAL_INT(4, spf.m_invalidTermCount);

  char record[SPF_RECORD_SIZE] = "v=spf1 redirect=a.example";
  for (int i = 1; i < EMAILAUTH_SPF_MAX_TERM_COUNT; i++)
    strcat(record, " a");
  strcat(record, " redirect=b.example");
  static_parseSpf(record, &spf);
  TEST_ASSERT_EQUAL_INT(1, spf.m_unreadTermCount);
  TEST_ASSERT_EQUAL_INT(1, spf.m_invalidTermCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_SPF_MAX_TERM_COUNT, spf.m_dnsLookupTermCount);
}

void test_parseDmarc_reads_each_tag(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; p=reject; sp=quarantine; np=none; pct=50; aspf=s; adkim=r; t=y; psd=n; "
                                             "rua=mailto:a@example.com, mailto:b@example.net!10m; ruf=mailto:c@example.org; fo=1");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, dmarc.m_nonexistentSubdomainPolicy);
  TEST_ASSERT_TRUE(dmarc.m_isPercentValid);
  TEST_ASSERT_EQUAL_INT(50, dmarc.m_percent);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_STRICT, dmarc.m_spfAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_RELAXED, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_TEST_MODE_ON, dmarc.m_testMode);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL, dmarc.m_domainRole);
  TEST_ASSERT_TRUE(dmarc.m_isFailureOptionsValid);
  TEST_ASSERT_EQUAL_UINT(EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL, dmarc.m_failureOptions);
  TEST_ASSERT_EQUAL_INT(2, dmarc.m_aggregateUriCount);
  TEST_ASSERT_EQUAL_INT(2, dmarc.m_validAggregateUriCount);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[0].m_uri, "mailto:a@example.com"));
  TEST_ASSERT_FALSE(dmarc.ma_aggregateUris[0].m_hasSizeLimit);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[1].m_uri, "mailto:b@example.net"));
  TEST_ASSERT_TRUE(dmarc.ma_aggregateUris[1].m_hasSizeLimit);
  TEST_ASSERT_EQUAL_INT(1, dmarc.m_failureUriCount);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_failureUris[0].m_uri, "mailto:c@example.org"));
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_skippedUriCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_invalidTagCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_repeatedTagCount);

  dmarc = static_parseDmarc("v=DMARC1; p=none; sp=reject; np=quarantine; aspf=r; adkim=s; t=n; psd=y; fo=0:d");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, dmarc.m_nonexistentSubdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_RELAXED, dmarc.m_spfAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_STRICT, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_TEST_MODE_OFF, dmarc.m_testMode);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX, dmarc.m_domainRole);
  TEST_ASSERT_EQUAL_UINT(EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL | EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL, dmarc.m_failureOptions);
}

void test_parseDmarc_gives_the_default_of_each_tag(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_ABSENT, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_ABSENT, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_ABSENT, dmarc.m_nonexistentSubdomainPolicy);
  TEST_ASSERT_TRUE(dmarc.m_isPercentValid);
  TEST_ASSERT_EQUAL_INT(100, dmarc.m_percent);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_RELAXED, dmarc.m_spfAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_RELAXED, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_TEST_MODE_ABSENT, dmarc.m_testMode);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_DOMAIN_ROLE_ABSENT, dmarc.m_domainRole);
  TEST_ASSERT_TRUE(dmarc.m_isFailureOptionsValid);
  TEST_ASSERT_EQUAL_UINT(EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL, dmarc.m_failureOptions);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_aggregateUriCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_validAggregateUriCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_failureUriCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_invalidTagCount);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_repeatedTagCount);
}

void test_parseDmarc_reads_each_policy_value(void)
{
  static const struct { const char* mp_record; EmailAuthDmarcPolicy_t m_policy; } cases[] = {
    { "v=DMARC1; p=NONE",       EMAILAUTH_DMARC_POLICY_NONE },
    { "v=DMARC1; p=Quarantine", EMAILAUTH_DMARC_POLICY_QUARANTINE },
    { "v=DMARC1; p=rejecT",     EMAILAUTH_DMARC_POLICY_REJECT },
    { "v=DMARC1; p=bogus",      EMAILAUTH_DMARC_POLICY_INVALID },
    { "v=DMARC1; p=",           EMAILAUTH_DMARC_POLICY_INVALID },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_policy, static_parseDmarc(cases[i].mp_record).m_policy, cases[i].mp_record);

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_INVALID, static_parseDmarc("v=DMARC1; p=none; sp=all").m_subdomainPolicy);
}

void test_parseDmarc_reads_pct_from_0_to_100(void)
{
  static const struct { const char* mp_record; bool m_isValid; int m_percent; } cases[] = {
    { "v=DMARC1; pct=0",    true,  0 },
    { "v=DMARC1; pct=99",   true,  99 },
    { "v=DMARC1; pct=100",  true,  100 },
    { "v=DMARC1; pct=050",  true,  50 },
    { "v=DMARC1; pct= 7 ",  true,  7 },
    { "v=DMARC1; pct=101",  false, 100 },
    { "v=DMARC1; pct=0100", false, 100 },
    { "v=DMARC1; pct=-1",   false, 100 },
    { "v=DMARC1; pct=5a",   false, 100 },
    { "v=DMARC1; pct=",     false, 100 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EmailAuthDmarc_t dmarc = static_parseDmarc(cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isValid, dmarc.m_isPercentValid, cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_percent, dmarc.m_percent, cases[i].mp_record);
  }
}

void test_parseDmarc_reads_each_alignment_value(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; adkim=S; aspf=R");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_STRICT, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_RELAXED, dmarc.m_spfAlignment);

  dmarc = static_parseDmarc("v=DMARC1; adkim=x; aspf=");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_INVALID, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_INVALID, dmarc.m_spfAlignment);
}

void test_parseDmarc_reads_np_t_and_psd(void)
{
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, static_parseDmarc("v=DMARC1; np=Reject").m_nonexistentSubdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_INVALID, static_parseDmarc("v=DMARC1; np=bogus").m_nonexistentSubdomainPolicy);

  static const struct { const char* mp_record; EmailAuthDmarcTestMode_t m_testMode; } test_modes[] = {
    { "v=DMARC1; t=y",   EMAILAUTH_DMARC_TEST_MODE_ON },
    { "v=DMARC1; t=Y",   EMAILAUTH_DMARC_TEST_MODE_ON },
    { "v=DMARC1; t=N",   EMAILAUTH_DMARC_TEST_MODE_OFF },
    { "v=DMARC1; t=yes", EMAILAUTH_DMARC_TEST_MODE_INVALID },
    { "v=DMARC1; t=",    EMAILAUTH_DMARC_TEST_MODE_INVALID },
  };
  for (size_t i = 0; i < sizeof(test_modes) / sizeof(test_modes[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(test_modes[i].m_testMode, static_parseDmarc(test_modes[i].mp_record).m_testMode, test_modes[i].mp_record);

  static const struct { const char* mp_record; EmailAuthDmarcDomainRole_t m_domainRole; } domain_roles[] = {
    { "v=DMARC1; psd=Y",  EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX },
    { "v=DMARC1; psd=n",  EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL },
    { "v=DMARC1; psd=N",  EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL },
    { "v=DMARC1; psd=u",  EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX },
    { "v=DMARC1; psd=U",  EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX },
    { "v=DMARC1; psd=x",  EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID },
    { "v=DMARC1; psd=yn", EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID },
    { "v=DMARC1; psd=",   EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID },
  };
  for (size_t i = 0; i < sizeof(domain_roles) / sizeof(domain_roles[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(domain_roles[i].m_domainRole, static_parseDmarc(domain_roles[i].mp_record).m_domainRole, domain_roles[i].mp_record);
}

void test_parseDmarc_reads_fo(void)
{
  static const struct { const char* mp_record; bool m_isValid; unsigned int m_failureOptions; } cases[] = {
    { "v=DMARC1; fo=0",     true,  EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=1",     true,  EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL },
    { "v=DMARC1; fo=d",     true,  EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL },
    { "v=DMARC1; fo=s",     true,  EMAILAUTH_DMARC_FAILURE_OPTION_SPF_FAIL },
    { "v=DMARC1; fo=d:s",   true,  EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL | EMAILAUTH_DMARC_FAILURE_OPTION_SPF_FAIL },
    { "v=DMARC1; fo=S:1:D", true,  EMAILAUTH_DMARC_FAILURE_OPTION_SPF_FAIL | EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL | EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL },
    { "v=DMARC1; fo=0:1",   false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=1:0",   false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=d:d",   false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=x",     false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=",      false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=1:",    false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=:1",    false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=1::d",  false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=ds",    false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=d,s",   false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
    { "v=DMARC1; fo=1 : d", false, EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EmailAuthDmarc_t dmarc = static_parseDmarc(cases[i].mp_record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isValid, dmarc.m_isFailureOptionsValid, cases[i].mp_record);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_failureOptions, dmarc.m_failureOptions, cases[i].mp_record);
  }
}

void test_parseDmarc_reads_the_report_addresses_up_to_the_cap(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; rua= a , b,,c ,");
  TEST_ASSERT_EQUAL_INT(3, dmarc.m_aggregateUriCount);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[0].m_uri, "a"));
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[1].m_uri, "b"));
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[2].m_uri, "c"));

  dmarc = static_parseDmarc("v=DMARC1; rua=1,2,3,4,5,6,7,8");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_MAX_URI_COUNT, dmarc.m_aggregateUriCount);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_aggregateUris[7].m_uri, "8"));
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_skippedUriCount);

  dmarc = static_parseDmarc("v=DMARC1; rua=1,2,3,4,5,6,7,8,9,10; ruf=1,2,3,4,5,6,7,8,9");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_MAX_URI_COUNT, dmarc.m_aggregateUriCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_MAX_URI_COUNT, dmarc.m_failureUriCount);
  TEST_ASSERT_TRUE(static_isSpan(dmarc.ma_failureUris[7].m_uri, "8"));
  TEST_ASSERT_EQUAL_INT(3, dmarc.m_skippedUriCount);
}

void test_parseDmarc_reads_the_kind_of_each_report_address(void)
{
  static const struct { const char* mp_text; EmailAuthDmarcUriKind_t m_kind; const char* mp_uri; bool m_hasSizeLimit; } addresses[] = {
    { "mailto:a@example.com",         EMAILAUTH_DMARC_URI_MAILTO,       "mailto:a@example.com",    false },
    { "mailto:b@example.com!10m",     EMAILAUTH_DMARC_URI_MAILTO,       "mailto:b@example.com",    true },
    { "MAILTO:c@example.com!5K",      EMAILAUTH_DMARC_URI_MAILTO,       "MAILTO:c@example.com",    true },
    { "mailto:d@example.com!7",       EMAILAUTH_DMARC_URI_MAILTO,       "mailto:d@example.com",    true },
    { "mailto:e@example.com!2g",      EMAILAUTH_DMARC_URI_MAILTO,       "mailto:e@example.com",    true },
    { "mailto:f@example.com!3T",      EMAILAUTH_DMARC_URI_MAILTO,       "mailto:f@example.com",    true },
    { "https://r.example/~x",         EMAILAUTH_DMARC_URI_OTHER_SCHEME, "https://r.example/~x",    false },
    { "a1+b-c.d:x",                   EMAILAUTH_DMARC_URI_OTHER_SCHEME, "a1+b-c.d:x",              false },
    { "a",                            EMAILAUTH_DMARC_URI_INVALID,      "a",                       false },
    { "mailto:",                      EMAILAUTH_DMARC_URI_INVALID,      "mailto:",                 false },
    { "x:",                           EMAILAUTH_DMARC_URI_INVALID,      "x:",                      false },
    { "mailto:x",                     EMAILAUTH_DMARC_URI_INVALID,      "mailto:x",                false },
    { "mailto:@x",                    EMAILAUTH_DMARC_URI_INVALID,      "mailto:@x",               false },
    { "mailto:x@",                    EMAILAUTH_DMARC_URI_INVALID,      "mailto:x@",               false },
    { "mailto:a@b.example!",          EMAILAUTH_DMARC_URI_INVALID,      "mailto:a@b.example!",     false },
    { "mailto:a@b.example!x",         EMAILAUTH_DMARC_URI_INVALID,      "mailto:a@b.example!x",    false },
    { "mailto:a@b.example!10x",       EMAILAUTH_DMARC_URI_INVALID,      "mailto:a@b.example!10x",  false },
    { "mailto:a@b.example!10mm",      EMAILAUTH_DMARC_URI_INVALID,      "mailto:a@b.example!10mm", false },
    { "mailto:a@b.example!1!2",       EMAILAUTH_DMARC_URI_INVALID,      "mailto:a@b.example!1!2",  false },
    { "mailto:a b@example.com",       EMAILAUTH_DMARC_URI_INVALID,      "mailto:a b@example.com",  false },
    { "mailto:a\x7f@example.com",     EMAILAUTH_DMARC_URI_INVALID,      "mailto:a\x7f@example.com", false },
    { "1x:y",                         EMAILAUTH_DMARC_URI_INVALID,      "1x:y",                    false },
    { "a_b:y",                        EMAILAUTH_DMARC_URI_INVALID,      "a_b:y",                   false },
  };
  const size_t address_count = sizeof(addresses) / sizeof(addresses[0]);
  for (size_t i = 0; i < address_count; i++)
  {
    char record[128];
    int  record_len = snprintf(record, sizeof(record), "v=DMARC1; rua=%s", addresses[i].mp_text);
    TEST_ASSERT_TRUE(record_len > 0 && (size_t)record_len < sizeof(record));

    EmailAuthDmarc_t dmarc = static_parseDmarc(record);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, dmarc.m_aggregateUriCount, addresses[i].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(addresses[i].m_kind, dmarc.ma_aggregateUris[0].m_kind, addresses[i].mp_text);
    TEST_ASSERT_TRUE_MESSAGE(static_isSpan(dmarc.ma_aggregateUris[0].m_uri, addresses[i].mp_uri), addresses[i].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(addresses[i].m_hasSizeLimit, dmarc.ma_aggregateUris[0].m_hasSizeLimit, addresses[i].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(addresses[i].m_kind != EMAILAUTH_DMARC_URI_INVALID ? 1 : 0, dmarc.m_validAggregateUriCount, addresses[i].mp_text);
  }
}

void test_parseDmarc_counts_the_valid_aggregate_addresses_past_the_cap(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; rua=1,2,3,4,5,6,7,8,mailto:a@example.com; ruf=mailto:b@example.com,mailto:c@example.com");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_MAX_URI_COUNT, dmarc.m_aggregateUriCount);
  TEST_ASSERT_EQUAL_INT(1, dmarc.m_skippedUriCount);
  TEST_ASSERT_EQUAL_INT(1, dmarc.m_validAggregateUriCount);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_URI_MAILTO, dmarc.ma_failureUris[0].m_kind);
}

void test_parseDmarc_counts_invalid_and_repeated_tags(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; p=none; p=reject; garbage; =x; 1a=b; a-b=c; sp=reject; ri=86400; x_y=z; x_y=w; "
                                             "np=quarantine; np=reject; t=y; t=n; psd=y; psd=n; fo=1; fo=0");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, dmarc.m_nonexistentSubdomainPolicy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_TEST_MODE_ON, dmarc.m_testMode);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX, dmarc.m_domainRole);
  TEST_ASSERT_EQUAL_UINT(EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL, dmarc.m_failureOptions);
  TEST_ASSERT_EQUAL_INT(4, dmarc.m_invalidTagCount);
  TEST_ASSERT_EQUAL_INT(5, dmarc.m_repeatedTagCount);
}

void test_parseDmarc_reads_tag_names_in_any_case(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1; P=reject; SP=none; PCT=10; ASPF=s; ADKIM=s; RUA=mailto:x@example.com");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(10, dmarc.m_percent);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_STRICT, dmarc.m_spfAlignment);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_ALIGNMENT_STRICT, dmarc.m_dkimAlignment);
  TEST_ASSERT_EQUAL_INT(1, dmarc.m_aggregateUriCount);
}

void test_parseDmarc_skips_the_spaces_around_a_tag(void)
{
  EmailAuthDmarc_t dmarc = static_parseDmarc("v=DMARC1 ;\tp = reject ;\r\n sp=none;");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_REJECT, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_NONE, dmarc.m_subdomainPolicy);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_invalidTagCount);

  dmarc = static_parseDmarc("v=DMARC1;; p=quarantine;  ");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DMARC_POLICY_QUARANTINE, dmarc.m_policy);
  TEST_ASSERT_EQUAL_INT(0, dmarc.m_invalidTagCount);
}

void test_parseDkim_reads_an_rsa_key_and_its_size(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  static const char* const tags_before[] = { "v=DKIM1; k=rsa; p=", "p=" };
  for (size_t i = 0; i < sizeof(tags_before) / sizeof(tags_before[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(tags_before[i], key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState, tags_before[i]);
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_TYPE_RSA, dkim.m_keyType);
    TEST_ASSERT_TRUE(static_isSpan(dkim.m_keyTypeName, "rsa"));
    TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);
    TEST_ASSERT_FALSE(dkim.m_isBareRsaKey);
    TEST_ASSERT_FALSE(dkim.m_isTestMode);
    TEST_ASSERT_FALSE(dkim.m_isVersionMisplaced);
    TEST_ASSERT_TRUE(dkim.m_isSha256Allowed);
    TEST_ASSERT_TRUE(dkim.m_isEmailServiceAllowed);
  }

  static_writeKeyBase64(static_rsaKey(2048), false, RSA_2048_KEY_INFO_LEN + 1, key_base64);
  TEST_ASSERT_EQUAL_STRING("==", key_base64 + strlen(key_base64) - 2);
  TEST_ASSERT_EQUAL_INT(2048, static_parseDkimWith("p=", key_base64, "").m_keyBits);
}

void test_parseDkim_reads_a_bare_rsa_public_key(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(1024), true, 0, key_base64);
  TEST_ASSERT_EQUAL_CHAR('=', key_base64[strlen(key_base64) - 1]);

  EmailAuthDkim_t dkim = static_parseDkimWith("v=DKIM1; p=", key_base64, "");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
  TEST_ASSERT_EQUAL_INT(1024, dkim.m_keyBits);
  TEST_ASSERT_TRUE(dkim.m_isBareRsaKey);
}

void test_parseDkim_flags_a_negative_rsa_modulus(void)
{
  unsigned char* der     = NULL;
  int            der_len = i2d_PublicKey(static_rsaKey(1024), &der);
  TEST_ASSERT_EQUAL_INT(140, der_len);
  TEST_ASSERT_EQUAL_HEX8(0x00, der[6]);
  TEST_ASSERT_TRUE((der[7] & 0x80) != 0);

  unsigned char negative[140] = { 0x30, 0x81, 0x88, 0x02, 0x81, 0x80 };
  memcpy(negative + 6, der + 7, (size_t)der_len - 7);
  int negative_len = der_len - 1;

  static const unsigned char rsa_algorithm[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
  unsigned char info[200] = { 0x30, 0x81, (unsigned char)(sizeof(rsa_algorithm) + 3 + 1 + negative_len) };
  int           info_len  = 3;
  memcpy(info + info_len, rsa_algorithm, sizeof(rsa_algorithm));
  info_len += (int)sizeof(rsa_algorithm);
  info[info_len++] = 0x03;
  info[info_len++] = 0x81;
  info[info_len++] = (unsigned char)(1 + negative_len);
  info[info_len++] = 0x00;
  memcpy(info + info_len, negative, (size_t)negative_len);
  info_len += negative_len;

  unsigned char low_top[140];
  memcpy(low_top, negative, (size_t)negative_len);
  low_top[6] = 0x9a;
  unsigned char no_top[140];
  memcpy(no_top, negative, (size_t)negative_len);
  no_top[6] = 0x5a;

  const struct {
    const unsigned char* mp_der;
    int                  m_derLen;
    int                  m_keyBits;
    bool                 m_isRsaModulusNegative;
  } cases[] = {
    { negative, negative_len, 1024, true },
    { info,     info_len,     1024, true },
    { der,      der_len,      1024, false },
    { low_top,  negative_len, 1024, true },
    { no_top,   negative_len, 1023, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char key_base64[KEY_BASE64_SIZE];
    static_writeBytesBase64(cases[i].mp_der, cases[i].m_derLen, key_base64);
    EmailAuthDkim_t dkim = static_parseDkimWith("v=DKIM1; p=", key_base64, "");
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
    TEST_ASSERT_EQUAL_INT(cases[i].m_keyBits, dkim.m_keyBits);
    TEST_ASSERT_EQUAL_INT(cases[i].m_isRsaModulusNegative, dkim.m_isRsaModulusNegative);
  }
  OPENSSL_free(der);
}

void test_parseDkim_skips_spaces_inside_the_key(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  char   spaced_key[KEY_BASE64_SIZE + 8] = "";
  size_t key_len = strlen(key_base64);
  size_t quarter = key_len / 4;
  snprintf(spaced_key, sizeof(spaced_key), "%.*s %.*s\t%.*s\r\n%s",
           (int)quarter, key_base64, (int)quarter, key_base64 + quarter, (int)quarter, key_base64 + 2 * quarter, key_base64 + 3 * quarter);

  EmailAuthDkim_t dkim = static_parseDkimWith("v=DKIM1; p=", spaced_key, "");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
  TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);
}

void test_parseDkim_an_empty_key_is_revoked(void)
{
  static const char* const records[] = { "v=DKIM1; k=rsa; p=", "p=  ;" };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith("", records[i], "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_REVOKED, dkim.m_keyState, records[i]);
    TEST_ASSERT_EQUAL_INT(0, dkim.m_keyBits);
  }
}

void test_parseDkim_records_that_are_not_key_records(void)
{
  static const char* const records[] = {
    "v=spf1 include:_spf.google.com ~all", "v=DMARC1; p=none", "google-site-verification=abc",
    "k=rsa; t=y", "v=dkim1; p=QUJD", "",
  };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith("", records[i], "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_ABSENT, dkim.m_keyState, records[i]);
    TEST_ASSERT_EQUAL_INT(0, dkim.m_keyBits);
  }
}

void test_parseDkim_records_that_cannot_be_read(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);
  static const struct { const char* mp_before; const char* mp_after; } tags[] = {
    { "p=", "; p=QUJD" }, { "p=", "; v=DKIM2" }, { "p=", "; garbage" }, { "t=y; p=", "; t=s" },
    { "h=sha256; p=", "; h=sha1" }, { "x=1; p=", "; x=2" }, { "h=; p=", "" }, { "s=; p=", "" },
    { "garbage; v=DKIM2; p=", "" },
  };
  for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(tags[i].mp_before, key_base64, tags[i].mp_after);
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNREADABLE, dkim.m_keyState, tags[i].mp_before);
    TEST_ASSERT_EQUAL_INT(0, dkim.m_keyBits);
  }

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_UNREADABLE, static_parseDkimWith("", "v=DKIM1; k=rsa; t=y", "").m_keyState);

  EVP_PKEY* ec_key = EVP_EC_gen("P-256");
  TEST_ASSERT_NOT_NULL(ec_key);
  char ec_key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(ec_key, false, 0, ec_key_base64);
  EVP_PKEY_free(ec_key);

  EVP_PKEY* ed25519_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  TEST_ASSERT_NOT_NULL(ed25519_key);
  char ed25519_key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(ed25519_key, false, 0, ed25519_key_base64);
  EVP_PKEY_free(ed25519_key);

  char dashed_key[KEY_BASE64_SIZE + 4];
  snprintf(dashed_key, sizeof(dashed_key), "%s---", key_base64);

  char triple_padded_key[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, RSA_2048_KEY_INFO_LEN + 3, triple_padded_key);
  size_t triple_padded_len = strlen(triple_padded_key);
  TEST_ASSERT_EQUAL_STRING("AAAA", triple_padded_key + triple_padded_len - 4);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, static_parseDkimWith("p=", triple_padded_key, "").m_keyState);
  memcpy(triple_padded_key + triple_padded_len - 3, "===", 3);

  const char* keys[] = { "!!!!", "=", dashed_key, triple_padded_key, "QUJD", "QUJ", ec_key_base64, ed25519_key_base64 };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith("v=DKIM1; p=", keys[i], "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNREADABLE, dkim.m_keyState, keys[i]);
    TEST_ASSERT_EQUAL_INT(0, dkim.m_keyBits);
    TEST_ASSERT_FALSE(dkim.m_isBareRsaKey);
  }
}

void test_parseDkim_an_rsa_key_info_with_a_frame_byte_changed_cannot_be_read(void)
{
  unsigned char* der     = NULL;
  int            der_len = i2d_PUBKEY(static_rsaKey(2048), &der);
  TEST_ASSERT_EQUAL_INT(RSA_2048_KEY_INFO_LEN, der_len);

  static const unsigned char rsa_key_info_frame[] = {
    0x30, 0x82, 0x01, 0x22,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x0f, 0x00,
  };
  TEST_ASSERT_EQUAL_HEX8_ARRAY(rsa_key_info_frame, der, sizeof(rsa_key_info_frame));

  static const struct { int m_offset; unsigned char m_byte; } changes[] = {
    { 0, 0x31 }, { 0, 0xb0 }, { 0, 0x10 }, { 16, 0x0a }, { 19, 0x04 }, { 19, 0x83 }, { 19, 0x23 }, { 23, 0x01 },
  };
  for (size_t i = 0; i < sizeof(changes) / sizeof(changes[0]); i++)
  {
    unsigned char changed_der[RSA_2048_KEY_INFO_LEN];
    memcpy(changed_der, der, sizeof(changed_der));
    changed_der[changes[i].m_offset] = changes[i].m_byte;
    char key_base64[KEY_BASE64_SIZE];
    EVP_EncodeBlock((unsigned char*)key_base64, changed_der, der_len);

    char change_name[16];
    int  change_name_len = snprintf(change_name, sizeof(change_name), "%d=0x%02x", changes[i].m_offset, changes[i].m_byte);
    TEST_ASSERT_TRUE(change_name_len > 0 && (size_t)change_name_len < sizeof(change_name));
    EmailAuthDkim_t dkim = static_parseDkimWith("p=", key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNREADABLE, dkim.m_keyState, change_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, dkim.m_keyBits, change_name);
  }
  OPENSSL_free(der);
}

void test_parseDkim_an_rsa_key_info_whose_lengths_disagree_cannot_be_read(void)
{
  unsigned char* der     = NULL;
  int            der_len = i2d_PUBKEY(static_rsaKey(2048), &der);
  TEST_ASSERT_EQUAL_INT(RSA_2048_KEY_INFO_LEN, der_len);

  static const struct {
    const char* mp_name;
    int         m_sequenceLenChange;
    int         m_bitStringLenChange;
    int         m_byteCountAdded;
  } cases[] = {
    { "a byte after the BIT STRING",         1,  0, 1 },
    { "the last key byte after the frame",  -1, -1, 0 },
    { "the BIT STRING past the SEQUENCE",   -1,  0, 0 },
    { "both lengths past the value",         1,  1, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    unsigned char changed_der[RSA_2048_KEY_INFO_LEN + 1] = { 0 };
    memcpy(changed_der, der, RSA_2048_KEY_INFO_LEN);
    changed_der[3]  = (unsigned char)(changed_der[3] + cases[i].m_sequenceLenChange);
    changed_der[22] = (unsigned char)(changed_der[22] + cases[i].m_bitStringLenChange);
    char key_base64[KEY_BASE64_SIZE];
    EVP_EncodeBlock((unsigned char*)key_base64, changed_der, RSA_2048_KEY_INFO_LEN + cases[i].m_byteCountAdded);

    EmailAuthDkim_t dkim = static_parseDkimWith("p=", key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNREADABLE, dkim.m_keyState, cases[i].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, dkim.m_keyBits, cases[i].mp_name);
  }
  OPENSSL_free(der);
}

void test_parseDkim_reads_tag_names_in_their_case_only(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_ABSENT, static_parseDkimWith("P=", key_base64, "").m_keyState);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, static_parseDkimWith("p=", key_base64, "; V=DKIM2").m_keyState);

  EmailAuthDkim_t dkim = static_parseDkimWith("K=ed25519; p=", key_base64, "");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
  TEST_ASSERT_TRUE(static_isSpan(dkim.m_keyTypeName, "rsa"));
  TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);
}

void test_parseDkim_reads_an_ed25519_key(void)
{
  static const char* const keys[] = { RFC_8463_ED25519_KEY, "11qYAYKxCrfVS/7T yWQHOg7hcvPa\tpiMlrwIaaPcHURo=", "++++++++++++++++++++++++++++++++++++++++++8=" }; /* gitleaks:allow */
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith("v=DKIM1; k=ed25519; p=", keys[i], "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState, keys[i]);
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_TYPE_ED25519, dkim.m_keyType);
    TEST_ASSERT_TRUE(static_isSpan(dkim.m_keyTypeName, "ed25519"));
    TEST_ASSERT_EQUAL_INT(256, dkim.m_keyBits);
    TEST_ASSERT_FALSE(dkim.m_isBareRsaKey);
  }
}

void test_parseDkim_an_ed25519_key_that_is_not_32_bytes_cannot_be_read(void)
{
  unsigned char key_bytes[33];
  for (size_t i = 0; i < sizeof(key_bytes); i++)
    key_bytes[i] = (unsigned char)(i * 7 + 1);
  char short_key[KEY_BASE64_SIZE];
  char long_key[KEY_BASE64_SIZE];
  static_writeBytesBase64(key_bytes, 31, short_key);
  static_writeBytesBase64(key_bytes, 33, long_key);
  TEST_ASSERT_EQUAL_size_t(44, strlen(short_key));
  TEST_ASSERT_EQUAL_size_t(44, strlen(long_key));

  char middle_padded_key[] = RFC_8463_ED25519_KEY;
  middle_padded_key[10]    = '=';
  char triple_padded_key[] = RFC_8463_ED25519_KEY;
  triple_padded_key[41]    = '=';
  triple_padded_key[42]    = '=';
  char unpadded_key[]      = RFC_8463_ED25519_KEY;
  unpadded_key[43]         = '\0';

  EVP_PKEY* ed25519_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  TEST_ASSERT_NOT_NULL(ed25519_key);
  char ed25519_key_info[KEY_BASE64_SIZE];
  static_writeKeyBase64(ed25519_key, false, 0, ed25519_key_info);
  EVP_PKEY_free(ed25519_key);

  const char* keys[] = { short_key, long_key, middle_padded_key, triple_padded_key, unpadded_key, ed25519_key_info, "QUJD" };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith("k=ed25519; p=", keys[i], "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNREADABLE, dkim.m_keyState, keys[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, dkim.m_keyBits, keys[i]);
  }
}

void test_parseDkim_a_key_of_an_unknown_type_is_ignored(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  static const char* const tags_before[] = { "k=foo; p=", "k=RSA; p=", "k=ED25519; p=" };
  for (size_t i = 0; i < sizeof(tags_before) / sizeof(tags_before[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(tags_before[i], key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_UNKNOWN_TYPE, dkim.m_keyState, tags_before[i]);
    TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_TYPE_OTHER, dkim.m_keyType);
    TEST_ASSERT_EQUAL_INT(0, dkim.m_keyBits);
  }
  TEST_ASSERT_TRUE(static_isSpan(static_parseDkimWith("k=foo; p=", key_base64, "").m_keyTypeName, "foo"));

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_REVOKED, static_parseDkimWith("k=foo; p=", "", "").m_keyState);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_UNREADABLE, static_parseDkimWith("k=foo; p=", key_base64, "; garbage").m_keyState);
}

void test_parseDkim_a_late_v_dkim1_is_read_and_flagged(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  static const struct { const char* mp_before; const char* mp_after; } tags[] = {
    { "p=", "; v=DKIM1" }, { "x=y; v=DKIM1; p=", "" },
  };
  for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(tags[i].mp_before, key_base64, tags[i].mp_after);
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState, tags[i].mp_before);
    TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);
    TEST_ASSERT_TRUE_MESSAGE(dkim.m_isVersionMisplaced, tags[i].mp_before);
    TEST_ASSERT_FALSE_MESSAGE(dkim.m_isTestMode, tags[i].mp_before);
  }
}

void test_parseDkim_reads_the_hash_and_service_lists(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  static const struct { const char* mp_tagsBefore; bool m_isSha256Allowed; bool m_isEmailServiceAllowed; } cases[] = {
    { "h=sha256; s=other; p=",            true,  false },
    { "h=sha1; s=email; p=",              false, true },
    { "h=sha1:sha256; s=*; p=",           true,  true },
    { "h= sha1 : sha256 ; s=other:email; p=", true, true },
    { "h=foo; s=other:EMAIL; p=",         false, false },
    { "h=SHA256; p=",                     false, true },
    { "s=*:other; p=",                    true,  true },
    { "s=:other; p=",                     true,  false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(cases[i].mp_tagsBefore, key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState, cases[i].mp_tagsBefore);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isSha256Allowed, dkim.m_isSha256Allowed, cases[i].mp_tagsBefore);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isEmailServiceAllowed, dkim.m_isEmailServiceAllowed, cases[i].mp_tagsBefore);
  }
}

void test_parseDkim_reads_up_to_the_cap_of_tags(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  char tags_before[256] = "";
  for (int i = 1; i < EMAILAUTH_DKIM_MAX_TAG_COUNT; i++)
  {
    char tag[16];
    int  tag_len = snprintf(tag, sizeof(tag), "x%d=a; ", i);
    TEST_ASSERT_TRUE(tag_len > 0 && (size_t)tag_len < sizeof(tag) && strlen(tags_before) + (size_t)tag_len < sizeof(tags_before));
    strcat(tags_before, tag);
  }
  strcat(tags_before, "p=");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, static_parseDkimWith(tags_before, key_base64, "").m_keyState);

  char more_tags_before[272];
  int  more_tags_len = snprintf(more_tags_before, sizeof(more_tags_before), "x0=a; %s", tags_before);
  TEST_ASSERT_TRUE(more_tags_len > 0 && (size_t)more_tags_len < sizeof(more_tags_before));
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_UNREADABLE, static_parseDkimWith(more_tags_before, key_base64, "").m_keyState);

  EmailAuthDkim_t dkim = static_parseDkimWith("K=x; k=rsa; p=", key_base64, "");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
  TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, static_parseDkimWith("ab=1; a=2; p=", key_base64, "").m_keyState);
}

void test_parseDkim_reads_the_test_flag(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, 0, key_base64);

  static const struct { const char* mp_tagsBefore; bool m_isTestMode; } cases[] = {
    { "t=y; p=",        true },
    { "t=s:y; p=",      true },
    { "t= s : y ; p=",  true },
    { "t=s; p=",        false },
    { "t=Y; p=",        false },
    { "t=yy; p=",       false },
    { "p=",             false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    EmailAuthDkim_t dkim = static_parseDkimWith(cases[i].mp_tagsBefore, key_base64, "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState, cases[i].mp_tagsBefore);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isTestMode, dkim.m_isTestMode, cases[i].mp_tagsBefore);
    TEST_ASSERT_FALSE_MESSAGE(dkim.m_isVersionMisplaced, cases[i].mp_tagsBefore);
  }
}

void test_parseDkim_reads_a_key_up_to_the_cap(void)
{
  char key_base64[KEY_BASE64_SIZE];
  static_writeKeyBase64(static_rsaKey(2048), false, KEY_DER_PADDED_LEN, key_base64);
  TEST_ASSERT_EQUAL_size_t(2048, strlen(key_base64));

  char spaced_key[KEY_BASE64_SIZE + 2];
  snprintf(spaced_key, sizeof(spaced_key), "%.1024s %s", key_base64, key_base64 + 1024);
  EmailAuthDkim_t dkim = static_parseDkimWith("p=", spaced_key, "");
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_PRESENT, dkim.m_keyState);
  TEST_ASSERT_EQUAL_INT(2048, dkim.m_keyBits);

  static_writeKeyBase64(static_rsaKey(2048), false, KEY_DER_PADDED_LEN + 3, key_base64);
  TEST_ASSERT_EQUAL_size_t(2052, strlen(key_base64));
  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_UNREADABLE, static_parseDkimWith("p=", key_base64, "").m_keyState);
}

void test_parseDkim_leaves_the_error_queue_as_it_was(void)
{
  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, 1);

  TEST_ASSERT_EQUAL_INT(EMAILAUTH_DKIM_KEY_UNREADABLE, static_parseDkimWith("p=", "QUJD", "").m_keyState);
  TEST_ASSERT_EQUAL_INT(ERR_LIB_USER, ERR_GET_LIB(ERR_get_error()));
  TEST_ASSERT_EQUAL_UINT64(0, ERR_get_error());
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_isSpfRecord_accepts_the_version_alone_or_before_a_space);
  RUN_TEST(test_isSpfRecord_refuses_another_version_or_no_space);
  RUN_TEST(test_isDmarcRecord_accepts_v_DMARC1_first);
  RUN_TEST(test_isDmarcRecord_refuses_any_other_first_tag);
  RUN_TEST(test_countSpfRecords_counts_and_finds_the_first);
  RUN_TEST(test_countDmarcRecords_counts_and_finds_the_first);

  RUN_TEST(test_parseSpf_reads_each_qualifier);
  RUN_TEST(test_parseSpf_reads_each_mechanism_and_its_value);
  RUN_TEST(test_parseSpf_reads_each_kind_of_modifier);
  RUN_TEST(test_parseSpf_marks_each_term_rfc_7208_does_not_allow);
  RUN_TEST(test_parseSpf_reads_names_in_any_case);
  RUN_TEST(test_parseSpf_skips_runs_of_spaces);
  RUN_TEST(test_parseSpf_counts_the_dns_lookup_terms);
  RUN_TEST(test_parseSpf_keeps_the_first_terms_and_counts_the_rest);
  RUN_TEST(test_parseSpf_reads_ip4_and_ip6_networks);
  RUN_TEST(test_parseSpf_marks_wrong_ip_networks_invalid);
  RUN_TEST(test_parseSpf_an_ip4_term_with_a_nul_byte_is_invalid);
  RUN_TEST(test_parseSpf_reads_the_prefix_lengths_of_a_and_mx);
  RUN_TEST(test_parseSpf_marks_wrong_prefix_lengths_invalid);
  RUN_TEST(test_parseSpf_reads_domain_specs_and_macros);
  RUN_TEST(test_parseSpf_marks_wrong_domain_specs_and_macros_invalid);
  RUN_TEST(test_parseSpf_marks_a_second_redirect_or_exp_invalid);

  RUN_TEST(test_parseDmarc_reads_each_tag);
  RUN_TEST(test_parseDmarc_gives_the_default_of_each_tag);
  RUN_TEST(test_parseDmarc_reads_each_policy_value);
  RUN_TEST(test_parseDmarc_reads_pct_from_0_to_100);
  RUN_TEST(test_parseDmarc_reads_each_alignment_value);
  RUN_TEST(test_parseDmarc_reads_np_t_and_psd);
  RUN_TEST(test_parseDmarc_reads_fo);
  RUN_TEST(test_parseDmarc_reads_the_report_addresses_up_to_the_cap);
  RUN_TEST(test_parseDmarc_reads_the_kind_of_each_report_address);
  RUN_TEST(test_parseDmarc_counts_the_valid_aggregate_addresses_past_the_cap);
  RUN_TEST(test_parseDmarc_counts_invalid_and_repeated_tags);
  RUN_TEST(test_parseDmarc_reads_tag_names_in_any_case);
  RUN_TEST(test_parseDmarc_skips_the_spaces_around_a_tag);

  RUN_TEST(test_parseDkim_reads_an_rsa_key_and_its_size);
  RUN_TEST(test_parseDkim_reads_a_bare_rsa_public_key);
  RUN_TEST(test_parseDkim_flags_a_negative_rsa_modulus);
  RUN_TEST(test_parseDkim_skips_spaces_inside_the_key);
  RUN_TEST(test_parseDkim_an_empty_key_is_revoked);
  RUN_TEST(test_parseDkim_records_that_are_not_key_records);
  RUN_TEST(test_parseDkim_records_that_cannot_be_read);
  RUN_TEST(test_parseDkim_an_rsa_key_info_with_a_frame_byte_changed_cannot_be_read);
  RUN_TEST(test_parseDkim_an_rsa_key_info_whose_lengths_disagree_cannot_be_read);
  RUN_TEST(test_parseDkim_reads_tag_names_in_their_case_only);
  RUN_TEST(test_parseDkim_reads_an_ed25519_key);
  RUN_TEST(test_parseDkim_an_ed25519_key_that_is_not_32_bytes_cannot_be_read);
  RUN_TEST(test_parseDkim_a_key_of_an_unknown_type_is_ignored);
  RUN_TEST(test_parseDkim_a_late_v_dkim1_is_read_and_flagged);
  RUN_TEST(test_parseDkim_reads_the_hash_and_service_lists);
  RUN_TEST(test_parseDkim_reads_up_to_the_cap_of_tags);
  RUN_TEST(test_parseDkim_reads_the_test_flag);
  RUN_TEST(test_parseDkim_reads_a_key_up_to_the_cap);
  RUN_TEST(test_parseDkim_leaves_the_error_queue_as_it_was);
  return UNITY_END();
}
