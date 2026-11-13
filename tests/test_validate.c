#include <string.h>
#include <stdio.h>

#include "unity/unity.h"
#include "validate.h"
#include "keyvault.h"

void setUp(void)    {}
void tearDown(void) {}

void test_search_plain_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchString("apache"));
}

void test_search_empty_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchString(""));
}

void test_search_percent_invalid(void)
{
  TEST_ASSERT_FALSE(validate_searchString("log%"));
}

void test_search_underscore_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchString("log_4j"));
  TEST_ASSERT_TRUE(validate_searchString("windows_10"));
}

void test_searchQuery_three_bytes_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchQuery("log"));
}

void test_searchQuery_two_bytes_invalid(void)
{
  TEST_ASSERT_FALSE(validate_searchQuery("lo"));
}

void test_searchQuery_empty_invalid(void)
{
  TEST_ASSERT_FALSE(validate_searchQuery(""));
}

void test_searchQuery_counts_bytes_not_characters(void)
{
  TEST_ASSERT_TRUE(validate_searchQuery("\xc3\xbc" "a"));
  TEST_ASSERT_FALSE(validate_searchQuery("\xc3\xbc"));
}

void test_searchQuery_only_spaces_invalid(void)
{
  TEST_ASSERT_FALSE(validate_searchQuery("   "));
  TEST_ASSERT_FALSE(validate_searchQuery("      "));
}

void test_searchQuery_one_non_space_byte_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchQuery("a  "));
  TEST_ASSERT_TRUE(validate_searchQuery(" a "));
  TEST_ASSERT_TRUE(validate_searchQuery("  a"));
  TEST_ASSERT_TRUE(validate_searchQuery("windows 10"));
}

void test_searchQuery_percent_and_punctuation_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchQuery("100% cpu"));
  TEST_ASSERT_FALSE(validate_searchString("100% cpu"));
  TEST_ASSERT_TRUE(validate_searchQuery("notepad++"));
  TEST_ASSERT_TRUE(validate_searchQuery("notepad\\+\\+"));
  TEST_ASSERT_TRUE(validate_searchQuery("log_4j"));
}

void test_searchQuery_long_query_valid(void)
{
  char query[129];
  memset(query, 'a', sizeof(query) - 1);
  query[sizeof(query) - 1] = '\0';
  TEST_ASSERT_TRUE(validate_searchQuery(query));
}

void test_searchQuery_non_ascii_only_valid(void)
{
  TEST_ASSERT_TRUE(validate_searchQuery("\xc3\xbc\xc3\xbc"));
}

void test_date_valid(void)
{
  TEST_ASSERT_TRUE(validate_date("2021-12-10"));
}

void test_date_min_month_day_valid(void)
{
  TEST_ASSERT_TRUE(validate_date("2021-01-01"));
}

void test_date_wrong_length_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-12-1"));
  TEST_ASSERT_FALSE(validate_date("2021-12-100"));
}

void test_date_bad_separator_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021/12/10"));
}

void test_date_non_digit_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-1A-10"));
}

void test_date_month_zero_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-00-10"));
}

void test_date_month_over_12_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-13-10"));
}

void test_date_day_zero_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-12-00"));
}

void test_date_day_over_31_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-12-32"));
}

void test_date_day_over_month_length_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2021-04-31"));
  TEST_ASSERT_FALSE(validate_date("2021-06-31"));
  TEST_ASSERT_FALSE(validate_date("2021-09-31"));
  TEST_ASSERT_FALSE(validate_date("2021-11-31"));
}

void test_date_last_day_of_31_day_month_valid(void)
{
  TEST_ASSERT_TRUE(validate_date("2021-01-31"));
  TEST_ASSERT_TRUE(validate_date("2021-12-31"));
}

void test_date_last_day_of_30_day_month_valid(void)
{
  TEST_ASSERT_TRUE(validate_date("2021-04-30"));
}

void test_date_february_over_29_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2026-02-31"));
  TEST_ASSERT_FALSE(validate_date("2026-02-30"));
}

void test_date_february_29_common_year_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("2023-02-29"));
}

void test_date_february_29_leap_year_valid(void)
{
  TEST_ASSERT_TRUE(validate_date("2024-02-29"));
}

void test_date_february_29_century_rule(void)
{
  TEST_ASSERT_FALSE(validate_date("1900-02-29"));
  TEST_ASSERT_TRUE(validate_date("2000-02-29"));
}

void test_date_year_zero_invalid(void)
{
  TEST_ASSERT_FALSE(validate_date("0000-01-01"));
  TEST_ASSERT_TRUE(validate_date("0001-01-01"));
}

void test_date_every_month_length_pinned_both_directions(void)
{
  static const struct { const char* mp_lastValid; const char* mp_firstInvalid; } month_bounds[12] = {
    { "2021-01-31", "2021-01-32" }, { "2021-02-28", "2021-02-29" },
    { "2021-03-31", "2021-03-32" }, { "2021-04-30", "2021-04-31" },
    { "2021-05-31", "2021-05-32" }, { "2021-06-30", "2021-06-31" },
    { "2021-07-31", "2021-07-32" }, { "2021-08-31", "2021-08-32" },
    { "2021-09-30", "2021-09-31" }, { "2021-10-31", "2021-10-32" },
    { "2021-11-30", "2021-11-31" }, { "2021-12-31", "2021-12-32" },
  };

  for (int month_index = 0; month_index < 12; month_index++)
  {
    TEST_ASSERT_TRUE_MESSAGE (validate_date(month_bounds[month_index].mp_lastValid),   month_bounds[month_index].mp_lastValid);
    TEST_ASSERT_FALSE_MESSAGE(validate_date(month_bounds[month_index].mp_firstInvalid), month_bounds[month_index].mp_firstInvalid);
  }
}

void test_date_leap_february_upper_bound(void)
{
  TEST_ASSERT_TRUE(validate_date("2024-02-29"));
  TEST_ASSERT_FALSE(validate_date("2024-02-30"));
  TEST_ASSERT_FALSE(validate_date("2024-02-31"));
}

void test_cveId_null_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId(NULL));
}

void test_cveId_empty_string_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId(""));
}

void test_cveId_lowercase_prefix_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("cve-2021-44228"));
}

void test_cveId_wrong_prefix_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVX-2021-44228"));
}

void test_cveId_valid_4digit_sequence(void)
{
  TEST_ASSERT_TRUE(validate_cveId("CVE-2021-1234"));
}

void test_cveId_valid_5digit_sequence(void)
{
  TEST_ASSERT_TRUE(validate_cveId("CVE-2021-12345"));
}

void test_cveId_valid_min_sequence(void)
{
  TEST_ASSERT_TRUE(validate_cveId("CVE-1999-0001"));
}


void test_cveId_year_3digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-999-44228"));
}

void test_cveId_year_5digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-20210-44228"));
}

void test_cveId_year_with_letters_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-20AB-44228"));
}

void test_cveId_sequence_3digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021-123"));
}

void test_cveId_sequence_with_letters_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021-ABCD"));
}

void test_cveId_missing_first_dash_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE2021-44228"));
}

void test_cveId_missing_second_dash_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-202144228"));
}

void test_cveId_first_separator_must_be_a_dash(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE_2021-44228"));
}

void test_cveId_second_separator_must_be_a_dash(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021_44228"));
}

void test_cveId_trailing_chars_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021-44228-extra"));
}

void test_cveId_trailing_space_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021-44228 "));
}

void test_cveId_sequence_15digits_valid(void)
{
  TEST_ASSERT_TRUE(validate_cveId("CVE-2021-123456789012345"));
}

void test_cveId_sequence_16digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cveId("CVE-2021-1234567890123456"));
}

void test_cweId_null_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId(NULL));
}

void test_cweId_empty_string_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId(""));
}

void test_cweId_lowercase_prefix_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("cwe-79"));
}

void test_cweId_wrong_prefix_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWX-79"));
}

void test_cweId_valid_1digit(void)
{
  TEST_ASSERT_TRUE(validate_cweId("CWE-7"));
}

void test_cweId_valid_2digit(void)
{
  TEST_ASSERT_TRUE(validate_cweId("CWE-79"));
}

void test_cweId_valid_3digit(void)
{
  TEST_ASSERT_TRUE(validate_cweId("CWE-352"));
}

void test_cweId_valid_5digit_max(void)
{
  TEST_ASSERT_TRUE(validate_cweId("CWE-12345"));
}

void test_cweId_zero_digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE-"));
}

void test_cweId_6digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE-123456"));
}

void test_cweId_non_digit_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE-AB"));
}

void test_cweId_trailing_chars_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE-79-extra"));
}

void test_cweId_trailing_space_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE-79 "));
}

void test_cweId_missing_dash_invalid(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE79"));
}

void test_cweId_separator_must_be_a_dash(void)
{
  TEST_ASSERT_FALSE(validate_cweId("CWE_79"));
}

#define SHA1_OF_PASSWORD "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

void test_sha1Hex_lowercase_valid(void)
{
  TEST_ASSERT_TRUE(validate_sha1Hex(SHA1_OF_PASSWORD));
}

void test_sha1Hex_uppercase_valid(void)
{
  TEST_ASSERT_TRUE(validate_sha1Hex("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"));
}

void test_sha1Hex_39_digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_sha1Hex("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd"));
}

void test_sha1Hex_41_digits_invalid(void)
{
  TEST_ASSERT_FALSE(validate_sha1Hex(SHA1_OF_PASSWORD "0"));
}

void test_sha1Hex_empty_invalid(void)
{
  TEST_ASSERT_FALSE(validate_sha1Hex(""));
}

void test_sha1Hex_five_digit_prefix_invalid(void)
{
  TEST_ASSERT_FALSE(validate_sha1Hex("5BAA6"));
}

void test_sha1Hex_each_end_of_each_hex_range_pinned(void)
{
  static const char refused_bytes[]  = { '/', ':', '@', 'G', '`', 'g' };
  static const char accepted_bytes[] = { '0', '9', 'A', 'F', 'a', 'f' };
  char sha1_hex[] = SHA1_OF_PASSWORD;

  for (size_t i = 0; i < sizeof(refused_bytes); i++)
  {
    char message[] = "refused byte ?";
    message[13] = refused_bytes[i];
    memcpy(sha1_hex, SHA1_OF_PASSWORD, sizeof(sha1_hex));
    sha1_hex[0] = refused_bytes[i];
    TEST_ASSERT_FALSE_MESSAGE(validate_sha1Hex(sha1_hex), message);
    memcpy(sha1_hex, SHA1_OF_PASSWORD, sizeof(sha1_hex));
    sha1_hex[39] = refused_bytes[i];
    TEST_ASSERT_FALSE_MESSAGE(validate_sha1Hex(sha1_hex), message);
  }
  for (size_t i = 0; i < sizeof(accepted_bytes); i++)
  {
    char message[] = "accepted byte ?";
    message[14] = accepted_bytes[i];
    memcpy(sha1_hex, SHA1_OF_PASSWORD, sizeof(sha1_hex));
    sha1_hex[0]  = accepted_bytes[i];
    sha1_hex[39] = accepted_bytes[i];
    TEST_ASSERT_TRUE_MESSAGE(validate_sha1Hex(sha1_hex), message);
  }
}

void test_fileHashHex_each_length_pinned(void)
{
  char file_hash_hex[VALIDATE_SHA256_HEX_LEN + 2];
  char message[32];

  for (size_t len = 0; len <= VALIDATE_SHA256_HEX_LEN + 1; len++)
  {
    bool is_valid = len == VALIDATE_MD5_HEX_LEN || len == VALIDATE_SHA1_HEX_LEN || len == VALIDATE_SHA256_HEX_LEN;
    memset(file_hash_hex, 'a', len);
    file_hash_hex[len] = '\0';
    snprintf(message, sizeof(message), "%zu lower-case digits", len);
    if (is_valid)
      TEST_ASSERT_TRUE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
    memset(file_hash_hex, 'F', len);
    snprintf(message, sizeof(message), "%zu upper-case digits", len);
    if (is_valid)
      TEST_ASSERT_TRUE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
  }
}

void test_fileHashHex_each_end_of_each_hex_range_pinned(void)
{
  static const char   refused_bytes[]  = { '/', ':', '@', 'G', '`', 'g' };
  static const char   accepted_bytes[] = { '0', '9', 'A', 'F', 'a', 'f' };
  static const size_t lengths[]        = { VALIDATE_MD5_HEX_LEN, VALIDATE_SHA1_HEX_LEN, VALIDATE_SHA256_HEX_LEN };
  char file_hash_hex[VALIDATE_SHA256_HEX_LEN + 1];
  char message[48];

  for (size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++)
  {
    size_t len = lengths[l];
    for (size_t i = 0; i < sizeof(refused_bytes); i++)
    {
      snprintf(message, sizeof(message), "refused byte %c, length %zu", refused_bytes[i], len);
      memset(file_hash_hex, '5', len);
      file_hash_hex[len] = '\0';
      file_hash_hex[0] = refused_bytes[i];
      TEST_ASSERT_FALSE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
      file_hash_hex[0] = '5';
      file_hash_hex[len - 1] = refused_bytes[i];
      TEST_ASSERT_FALSE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
    }
    for (size_t i = 0; i < sizeof(accepted_bytes); i++)
    {
      snprintf(message, sizeof(message), "accepted byte %c, length %zu", accepted_bytes[i], len);
      memset(file_hash_hex, '5', len);
      file_hash_hex[len] = '\0';
      file_hash_hex[0]       = accepted_bytes[i];
      file_hash_hex[len - 1] = accepted_bytes[i];
      TEST_ASSERT_TRUE_MESSAGE(validate_fileHashHex(file_hash_hex), message);
    }
  }
}

void test_domainName_accepted_names(void)
{
  static const char* const accepted_names[] = {
    "example.com", "motomax.com.tr", "a.b", "1.com", "123.com", "a--b.com", "xn--n3h.com",
    "Example.COM", "a1.b2-c.d",
  };
  for (size_t i = 0; i < sizeof(accepted_names) / sizeof(accepted_names[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(validate_domainName(accepted_names[i]), accepted_names[i]);
}

void test_domainName_refused_names(void)
{
  static const char* const refused_names[] = {
    "", "com", "localhost",
    "example..com", ".example.com", "example.com.", "example.com..", ".",
    "-a.com", "a-.com", "a.-b", "a.b-", "xn--.com", "--.com",
    "a_b.com", "_dmarc.x.com", "*.x.com", "ex ample.com", "b\xc3\xbcro.de",
    "1.2.3.4", "1.2.3.4.", "999.1.1.1", "example.123", "a.1", "0x7f.1", "a.1b",
    "https://x.com", " x.com", "x.com ", "x.com:80", "x.com/a",
  };
  for (size_t i = 0; i < sizeof(refused_names) / sizeof(refused_names[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(validate_domainName(refused_names[i]), refused_names[i]);
}

static void static_writeDomainName(char* name_out, size_t name_len, size_t label_len)
{
  memset(name_out, 'a', name_len);
  for (size_t dot = label_len; dot < name_len; dot += label_len + 1)
    name_out[dot] = '.';
  name_out[name_len] = '\0';
}

void test_domainName_label_of_63_bytes_valid(void)
{
  char domain_name[VALIDATE_DOMAIN_LABEL_MAX_LEN + 5];
  static_writeDomainName(domain_name, VALIDATE_DOMAIN_LABEL_MAX_LEN + 4, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  TEST_ASSERT_TRUE(validate_domainName(domain_name));
}

void test_domainName_label_of_64_bytes_invalid(void)
{
  char domain_name[VALIDATE_DOMAIN_LABEL_MAX_LEN + 6];
  static_writeDomainName(domain_name, VALIDATE_DOMAIN_LABEL_MAX_LEN + 5, VALIDATE_DOMAIN_LABEL_MAX_LEN + 1);
  TEST_ASSERT_FALSE(validate_domainName(domain_name));
}

void test_domainName_last_label_of_64_bytes_invalid(void)
{
  char domain_name[3 + VALIDATE_DOMAIN_LABEL_MAX_LEN + 2];
  memcpy(domain_name, "ab.", 3);
  memset(domain_name + 3, 'a', VALIDATE_DOMAIN_LABEL_MAX_LEN + 1);
  domain_name[3 + VALIDATE_DOMAIN_LABEL_MAX_LEN + 1] = '\0';
  TEST_ASSERT_FALSE(validate_domainName(domain_name));
  domain_name[3 + VALIDATE_DOMAIN_LABEL_MAX_LEN] = '\0';
  TEST_ASSERT_TRUE(validate_domainName(domain_name));
}

void test_domainName_253_bytes_valid(void)
{
  char domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  static_writeDomainName(domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  TEST_ASSERT_TRUE(validate_domainName(domain_name));
}

void test_domainName_254_bytes_invalid(void)
{
  char domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  static_writeDomainName(domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN + 1, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  TEST_ASSERT_FALSE(validate_domainName(domain_name));
}

void test_publicDnsName_accepted_names(void)
{
  static const char* const accepted_names[] = {
    "example.com", "EXAMPLE.COM", "localhost.example.com", "local.com", "test.example",
    "home.arpa.example", "arpa.example", "xn--p1ai.xn--p1ai", "a.testing", "a.localnet",
    "a.myhome", "a.homes", "a.lans", "a.arpas", "a.corporate", "a.privates", "a.onions",
  };
  for (size_t i = 0; i < sizeof(accepted_names) / sizeof(accepted_names[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(validate_publicDnsName(accepted_names[i]), accepted_names[i]);
}

void test_publicDnsName_refused_names(void)
{
  static const char* const refused_names[] = {
    "a.alt", "a.internal", "a.invalid", "printer.local", "foo.localhost", "x.onion", "site.test",
    "A.ALT", "a.INTERNAL", "a.Invalid", "Printer.LOCAL", "foo.LocalHost", "x.Onion", "Site.Test",
    "a.intranet", "x.private", "x.corp", "nas.home", "router.lan", "host.localdomain",
    "a.INTRANET", "x.Private", "x.CORP", "nas.Home", "router.LAN", "host.LocalDomain",
    "printer.office.local", "home.arpa", "HOME.ARPA", "router.home.arpa", "a.b.Home.Arpa",
    "10.in-addr.arpa", "1.0.0.127.in-addr.arpa", "0.8.e.f.ip6.arpa", "x.ARPA",
    "localhost", "example.com.", "1.2.3.4", "",
  };
  for (size_t i = 0; i < sizeof(refused_names) / sizeof(refused_names[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(validate_publicDnsName(refused_names[i]), refused_names[i]);
}

void test_publicUnderscoredDnsName_accepted_names(void)
{
  static const char* const accepted_names[] = {
    "example.com", "EXAMPLE.COM", "_dmarc.example.com", "_DMARC.Example.COM", "_a.example.com",
    "selector1._domainkey.example.com", "_mta-sts.example.com", "_25._tcp.mail.example.com",
    "selector1-example-com._domainkey.example.onmicrosoft.com",
  };
  for (size_t i = 0; i < sizeof(accepted_names) / sizeof(accepted_names[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(validate_publicUnderscoredDnsName(accepted_names[i]), accepted_names[i]);
}

void test_publicUnderscoredDnsName_refused_names(void)
{
  static const char* const refused_names[] = {
    "_.example.com", "__dmarc.example.com", "_-dmarc.example.com", "_dmarc-.example.com",
    "a_b.example.com", "dmarc_.example.com", "example._com", "_dmarc",
    "_dmarc.printer.local", "_dmarc.example.TEST", "1.0.0.127.in-addr.arpa", "_dmarc.x.arpa",
    "_dmarc.example.com.", "",
  };
  for (size_t i = 0; i < sizeof(refused_names) / sizeof(refused_names[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(validate_publicUnderscoredDnsName(refused_names[i]), refused_names[i]);
}

void test_publicUnderscoredDnsName_label_length_counts_the_underscore(void)
{
  char domain_name[VALIDATE_DOMAIN_LABEL_MAX_LEN + 6];
  domain_name[0] = '_';
  memset(domain_name + 1, 'a', VALIDATE_DOMAIN_LABEL_MAX_LEN);
  memcpy(domain_name + 1 + VALIDATE_DOMAIN_LABEL_MAX_LEN, ".com", 5);
  TEST_ASSERT_FALSE(validate_publicUnderscoredDnsName(domain_name));

  memcpy(domain_name + VALIDATE_DOMAIN_LABEL_MAX_LEN, ".com", 5);
  TEST_ASSERT_TRUE(validate_publicUnderscoredDnsName(domain_name));
}

void test_publicUnderscoredDnsName_name_length_limit(void)
{
  char domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  static_writeDomainName(domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  domain_name[0] = '_';
  TEST_ASSERT_TRUE(validate_publicUnderscoredDnsName(domain_name));

  static_writeDomainName(domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN + 1, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  domain_name[0] = '_';
  TEST_ASSERT_FALSE(validate_publicUnderscoredDnsName(domain_name));
}

void test_dkimSelector_accepted_selectors(void)
{
  static const char* const accepted_selectors[] = {
    "google", "selector1", "s1", "20230601", "a", "hs1-12345", "s1.mail", "SELECTOR1", "0.1",
  };
  for (size_t i = 0; i < sizeof(accepted_selectors) / sizeof(accepted_selectors[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(validate_dkimSelector(accepted_selectors[i]), accepted_selectors[i]);
}

void test_dkimSelector_refused_selectors(void)
{
  static const char* const refused_selectors[] = {
    "", "_domainkey", "sel_1", "_s.mail", "s1._x.mail", "-a", "a-", "a..b", ".a", "a.", "sel ector", "sel/1", "a%40b", "\xc3\xa9",
  };
  for (size_t i = 0; i < sizeof(refused_selectors) / sizeof(refused_selectors[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(validate_dkimSelector(refused_selectors[i]), refused_selectors[i]);
}

void test_dkimSelector_label_length_limit(void)
{
  char dkim_selector[2 + VALIDATE_DOMAIN_LABEL_MAX_LEN + 2];
  memcpy(dkim_selector, "a.", 2);
  memset(dkim_selector + 2, 'a', VALIDATE_DOMAIN_LABEL_MAX_LEN);
  dkim_selector[2 + VALIDATE_DOMAIN_LABEL_MAX_LEN] = '\0';
  TEST_ASSERT_TRUE(validate_dkimSelector(dkim_selector));

  dkim_selector[2 + VALIDATE_DOMAIN_LABEL_MAX_LEN]     = 'a';
  dkim_selector[2 + VALIDATE_DOMAIN_LABEL_MAX_LEN + 1] = '\0';
  TEST_ASSERT_FALSE(validate_dkimSelector(dkim_selector));
}

void test_dkimSelector_selector_length_limit(void)
{
  char dkim_selector[VALIDATE_DKIM_SELECTOR_MAX_LEN + 2];
  static_writeDomainName(dkim_selector, VALIDATE_DKIM_SELECTOR_MAX_LEN, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  TEST_ASSERT_TRUE(validate_dkimSelector(dkim_selector));

  char key_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  int  key_name_len = snprintf(key_name, sizeof(key_name), "%s._domainkey.a.b", dkim_selector);
  TEST_ASSERT_EQUAL_INT(VALIDATE_DOMAIN_NAME_MAX_LEN, key_name_len);
  TEST_ASSERT_TRUE(validate_domainName("a.b"));
  TEST_ASSERT_TRUE(validate_publicUnderscoredDnsName(key_name));

  static_writeDomainName(dkim_selector, VALIDATE_DKIM_SELECTOR_MAX_LEN + 1, VALIDATE_DOMAIN_LABEL_MAX_LEN);
  TEST_ASSERT_FALSE(validate_dkimSelector(dkim_selector));
}

void test_watchlistCursor_each_shape_pinned(void)
{
  static const struct { const char* mp_cursor; bool m_isValid; } cases[] = {
    { "0",                    true  },
    { "1",                    true  },
    { "9",                    true  },
    { "10",                   true  },
    { "123456789012345678",   true  },
    { "999999999999999999",   true  },
    { "1234567890123456789",  false },
    { "01",                   false },
    { "00",                   false },
    { "",                     false },
    { "+1",                   false },
    { "-1",                   false },
    { " 1",                   false },
    { "1 ",                   false },
    { "1.0",                  false },
    { "1e3",                  false },
    { "0x1",                  false },
    { "1a",                   false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_watchlistCursor(cases[i].mp_cursor), cases[i].mp_cursor);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_watchlistCursor(cases[i].mp_cursor), cases[i].mp_cursor);
  }
  TEST_ASSERT_EQUAL_size_t(18, strlen("123456789012345678"));
}

void test_attackTechniqueId_each_shape_pinned(void)
{
  static const struct { const char* mp_id; bool m_isValid; } cases[] = {
    { "T1059",                                 true  },
    { "T1059.001",                             true  },
    { "T0000.000",                             true  },
    { "T9999.999",                             true  },
    { "",                                      false },
    { "T",                                     false },
    { "T105",                                  false },
    { "T10590",                                false },
    { "T1059.",                                false },
    { "T1059.01",                              false },
    { "T1059.0001",                            false },
    { "T10591001",                             false },
    { "T1059..01",                             false },
    { "T105A",                                 false },
    { "T1059.00a",                             false },
    { "t1059",                                 false },
    { "t1059.001",                             false },
    { "DE-0007",                               false },
    { "T1059\n",                               false },
    { "T1059.001\n",                           false },
    { "T\xd9\xa1\xd9\xa0\xd9\xa5\xd9\xa9", false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_attackTechniqueId(cases[i].mp_id), cases[i].mp_id);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_attackTechniqueId(cases[i].mp_id), cases[i].mp_id);
  }
}

void test_attackTechniqueId_each_byte_next_to_its_range_refused(void)
{
  char id[] = "T1059.001";
  char message[32];
  for (size_t i = 0; i < sizeof(id) - 1; i++)
  {
    const char original = id[i];
    const char refused[2] = {
      i == 0 ? 'S' : i == 5 ? '-' : '/',
      i == 0 ? 'U' : i == 5 ? '/' : ':',
    };
    for (size_t k = 0; k < 2; k++)
    {
      id[i] = refused[k];
      snprintf(message, sizeof(message), "index %zu byte %c", i, refused[k]);
      TEST_ASSERT_FALSE_MESSAGE(validate_attackTechniqueId(id), message);
    }
    if (i != 0 && i != 5)
    {
      id[i] = '0';
      TEST_ASSERT_TRUE_MESSAGE(validate_attackTechniqueId(id), "0");
      id[i] = '9';
      TEST_ASSERT_TRUE_MESSAGE(validate_attackTechniqueId(id), "9");
    }
    id[i] = original;
  }
  TEST_ASSERT_TRUE(validate_attackTechniqueId(id));
}

void test_packageEcosystem_each_name_in_any_case_and_no_other(void)
{
  static const struct { const char* mp_value; bool m_isValid; } cases[] = {
    { "npm",       true  }, { "PyPI",      true  }, { "Maven",     true  },
    { "Go",        true  }, { "NuGet",     true  }, { "RubyGems",  true  },
    { "crates.io", true  }, { "Packagist", true  }, { "SwiftURL",  true  },
    { "NPM",       true  }, { "pypi",      true  }, { "MAVEN",     true  },
    { "go",        true  }, { "nuget",     true  }, { "rubygems",  true  },
    { "CRATES.IO", true  }, { "packagist", true  }, { "swifturl",  true  },
    { "",          false }, { "npm ",      false }, { " npm",      false },
    { "Pub",       false }, { "Hex",       false }, { "npmx",      false },
    { "crates_io", false }, { "cratesio",  false }, { "PyP",       false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_packageEcosystem(cases[i].mp_value), cases[i].mp_value);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_packageEcosystem(cases[i].mp_value), cases[i].mp_value);
  }
}

void test_packageName_refuses_a_space_alone(void)
{
  static const struct { const char* mp_value; bool m_isValid; } cases[] = {
    { "lodash",                                true  },
    { "@babel/core",                           true  },
    { "org.apache.logging.log4j:log4j-core",   true  },
    { "golang.org/x/net",                      true  },
    { "100%",                                  true  },
    { "Gun\xd0\xb0.Forms.Net",                 true  },
    { "a b",                                   false },
    { " lodash",                               false },
    { "lodash ",                               false },
    { " ",                                     false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_packageName(cases[i].mp_value), cases[i].mp_value);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_packageName(cases[i].mp_value), cases[i].mp_value);
  }
}

void test_packageVersion_each_end_of_the_visible_range_pinned(void)
{
  static const struct { const char* mp_value; bool m_isValid; } cases[] = {
    { "4.17.20",                           true  },
    { "v1.2.3+incompatible",               true  },
    { "0.0.0-20191109021931-daa7c04131f5", true  },
    { "1.0!",                              true  },
    { "1.0~",                              true  },
    { "1.0 ",                              false },
    { "1.0\x7f",                           false },
    { "1.0\xc3\xa9",                       false },
    { "1.0\t",                             false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_packageVersion(cases[i].mp_value), cases[i].mp_value);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_packageVersion(cases[i].mp_value), cases[i].mp_value);
  }
}

void test_packageExactVersion_refuses_each_range_spelling(void)
{
  static const struct { const char* mp_value; bool m_isValid; } cases[] = {
    { "4.17.20",             true  },
    { "v1.2.3+incompatible", true  },
    { "1.0.0-rc.1",          true  },
    { "1.0.xx",              true  },
    { "x1.0",                true  },
    { "1.X0",                true  },
    { "",                    false },
    { "1.0 ",                false },
    { "^4.0.0",              false },
    { "~1.2",                false },
    { "<2",                  false },
    { ">1",                  false },
    { "=1.0",                false },
    { "1.*",                 false },
    { "1||2",                false },
    { "1,2",                 false },
    { "1.x",                 false },
    { "1.X",                 false },
    { "x",                   false },
    { "x.1",                 false },
    { "1.x.3",               false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_packageExactVersion(cases[i].mp_value), cases[i].mp_value);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_packageExactVersion(cases[i].mp_value), cases[i].mp_value);
  }
}

void test_asn_each_shape_pinned(void)
{
  static const struct { const char* mp_text; bool m_isValid; } cases[] = {
    { "1",                     true  },
    { "AS1",                   true  },
    { "as1",                   true  },
    { "15169",                 true  },
    { "AS15169",               true  },
    { "as15169",               true  },
    { "1000000000",            true  },
    { "4294967295",            true  },
    { "AS4294967295",          true  },
    { "",                      false },
    { "AS",                    false },
    { "as",                    false },
    { "0",                     false },
    { "AS0",                   false },
    { "015169",                false },
    { "AS015169",              false },
    { "4294967296",            false },
    { "AS4294967296",          false },
    { "10000000000",           false },
    { "18446744073709551617",  false },
    { "As15169",               false },
    { "aS15169",               false },
    { "ASN15169",              false },
    { "AS 15169",              false },
    { " 15169",                false },
    { "+15169",                false },
    { "-1",                    false },
    { "AS-1",                  false },
    { "1.10",                  false },
    { "AS1.10",                false },
    { "15169a",                false },
    { "15169\n",               false },
    { "AS15169AS",             false },
    { "\xd9\xa1",              false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_asn(cases[i].mp_text), cases[i].mp_text);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_asn(cases[i].mp_text), cases[i].mp_text);
  }
  TEST_ASSERT_EQUAL_INT(10, VALIDATE_ASN_MAX_DIGITS);
}

void test_asnLookupTarget_accepts_an_as_number_or_a_public_address(void)
{
  static const struct { const char* mp_text; bool m_isValid; } cases[] = {
    { "AS15169",               true  },
    { "15169",                 true  },
    { "8.8.8.8",               true  },
    { "2001:4860:4860::8888",  true  },
    { "10.0.0.1",              false },
    { "::1",                   false },
    { "192.0.2.1",             false },
    { "8.8.8.0/24",            false },
    { "example.com",           false },
    { "AS0",                   false },
    { "",                      false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_asnLookupTarget(cases[i].mp_text), cases[i].mp_text);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_asnLookupTarget(cases[i].mp_text), cases[i].mp_text);
  }
}

void test_emailAddress_each_shape_pinned(void)
{
  static const struct { const char* mp_text; bool m_isValid; } cases[] = {
    { "a@example.com",                        true  },
    { "Name.Last@Example.COM",                true  },
    { "name+tag@example.com",                 true  },
    { "a.b.c@mail.example.co.uk",             true  },
    { "!#$%&'*+-/=?^_`{|}~@example.com",      true  },
    { "7@example.org",                        true  },
    { "",                                     false },
    { "@",                                    false },
    { "example.com",                          false },
    { "a@",                                   false },
    { "@example.com",                         false },
    { ".a@example.com",                       false },
    { "a.@example.com",                       false },
    { "a..b@example.com",                     false },
    { ".@example.com",                        false },
    { "a b@example.com",                      false },
    { "a\"b@example.com",                     false },
    { "\"a b\"@example.com",                  false },
    { "a(b)@example.com",                     false },
    { "a,b@example.com",                      false },
    { "a:b@example.com",                      false },
    { "a;b@example.com",                      false },
    { "a<b>@example.com",                     false },
    { "a[b]@example.com",                     false },
    { "a\\b@example.com",                     false },
    { "a@b@example.com",                      false },
    { "\xc3\xa4@example.com",                 false },
    { "a\x01@example.com",                    false },
    { "a\x7f@example.com",                    false },
    { "a@example",                            false },
    { "a@example.com.",                       false },
    { "a@exam_ple.com",                       false },
    { "a@-example.com",                       false },
    { "a@localhost",                          false },
    { "a@example.local",                      false },
    { "a@printer.home.arpa",                  false },
    { "a@1.2.3.4",                            false },
    { "a@[192.0.2.1]",                        false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_emailAddress(cases[i].mp_text), cases[i].mp_text);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_emailAddress(cases[i].mp_text), cases[i].mp_text);
  }
}

static void static_writeEmailOfLengths(size_t local_part_len, size_t domain_len, char* email_out)
{
  memset(email_out, 'a', local_part_len);
  email_out[local_part_len] = '@';
  char* domain = email_out + local_part_len + 1;
  for (size_t i = 0; i < domain_len; i++)
    domain[i] = (i % 64 == 63) ? '.' : 'b';
  domain[domain_len - 3] = '.';
  domain[domain_len]     = '\0';
}

void test_emailAddress_length_edges(void)
{
  static const struct { size_t m_localPartLen; size_t m_domainLen; bool m_isValid; } cases[] = {
    { 64,  20,  true  },
    { 65,  20,  false },
    { 1,   20,  true  },
    { 63,  190, true  },
    { 63,  191, false },
    { 64,  189, true  },
    { 64,  190, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char email[512];
    static_writeEmailOfLengths(cases[i].m_localPartLen, cases[i].m_domainLen, email);
    char label[64];
    snprintf(label, sizeof(label), "local part %zu, domain %zu", cases[i].m_localPartLen, cases[i].m_domainLen);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_localPartLen + 1 + cases[i].m_domainLen, strlen(email), label);
    if (cases[i].m_isValid)
      TEST_ASSERT_TRUE_MESSAGE(validate_emailAddress(email), label);
    else
      TEST_ASSERT_FALSE_MESSAGE(validate_emailAddress(email), label);
  }
  TEST_ASSERT_EQUAL_INT(254, VALIDATE_EMAIL_ADDRESS_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(64, VALIDATE_EMAIL_LOCAL_PART_MAX_LEN);
}

void test_emailAddress_each_byte_of_a_one_byte_local_part(void)
{
  static const char atext_symbols[] = "!#$%&'*+-/=?^_`{|}~";
  for (int byte = 1; byte < 256; byte++)
  {
    char email[32];
    snprintf(email, sizeof(email), "%c@example.com", byte);
    bool is_atext = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
                    strchr(atext_symbols, byte) != NULL;
    char label[16];
    snprintf(label, sizeof(label), "byte 0x%02X", byte);
    TEST_ASSERT_EQUAL_MESSAGE(is_atext, validate_emailAddress(email), label);
  }
}

#define UUID_DIGITS_FORWARD  "01234567-89ab-cdef-0123-456789abcdef"
#define UUID_DIGITS_BACKWARD "fedcba98-7654-3210-fedc-ba9876543210"
_Static_assert(sizeof(UUID_DIGITS_FORWARD) - 1 == VALIDATE_UUID_LEN, "UUID_DIGITS_FORWARD");

void test_uuid_every_lower_hex_digit_valid(void)
{
  TEST_ASSERT_TRUE(validate_uuid(UUID_DIGITS_FORWARD));
  TEST_ASSERT_TRUE(validate_uuid(UUID_DIGITS_BACKWARD));
  TEST_ASSERT_TRUE(validate_uuid("00000000-0000-0000-0000-000000000000"));
}

void test_uuid_byte_beside_a_digit_range_refused_at_every_position(void)
{
  static const char decoys[] = { '/', ':', '`', 'g', 'A', 'F', '-' };
  for (size_t position = 0; position < VALIDATE_UUID_LEN; position++)
  {
    if (UUID_DIGITS_FORWARD[position] == '-')
      continue;
    for (size_t d = 0; d < sizeof(decoys); d++)
    {
      char uuid[VALIDATE_UUID_LEN + 1];
      memcpy(uuid, UUID_DIGITS_FORWARD, sizeof(uuid));
      uuid[position] = decoys[d];
      TEST_ASSERT_FALSE_MESSAGE(validate_uuid(uuid), uuid);
    }
  }
}

void test_uuid_hyphen_moved_or_replaced_refused(void)
{
  static const size_t hyphens[] = { 8, 13, 18, 23 };
  for (size_t h = 0; h < 4; h++)
  {
    char uuid[VALIDATE_UUID_LEN + 1];
    size_t p = hyphens[h];

    memcpy(uuid, UUID_DIGITS_FORWARD, sizeof(uuid));
    uuid[p] = uuid[p - 1];
    uuid[p - 1] = '-';
    TEST_ASSERT_FALSE_MESSAGE(validate_uuid(uuid), uuid);

    memcpy(uuid, UUID_DIGITS_FORWARD, sizeof(uuid));
    uuid[p] = uuid[p + 1];
    uuid[p + 1] = '-';
    TEST_ASSERT_FALSE_MESSAGE(validate_uuid(uuid), uuid);

    memcpy(uuid, UUID_DIGITS_FORWARD, sizeof(uuid));
    uuid[p] = 'a';
    TEST_ASSERT_FALSE_MESSAGE(validate_uuid(uuid), uuid);
  }
}

void test_uuid_length_and_other_forms_refused(void)
{
  TEST_ASSERT_FALSE(validate_uuid("01234567-89ab-cdef-0123-456789abcde"));
  TEST_ASSERT_FALSE(validate_uuid("01234567-89ab-cdef-0123-456789abcdef0"));
  TEST_ASSERT_FALSE(validate_uuid(""));
  TEST_ASSERT_FALSE(validate_uuid("{01234567-89ab-cdef-0123-456789abcdef}"));
  TEST_ASSERT_FALSE(validate_uuid("urn:uuid:01234567-89ab-cdef-0123-456789abcdef"));
  TEST_ASSERT_FALSE(validate_uuid("01234567-89AB-CDEF-0123-456789ABCDEF"));
  TEST_ASSERT_FALSE(validate_uuid("0123456789abcdef0123456789abcdef"));
}


void test_vendorKeyLink_takes_64_lower_case_hex_digits(void)
{
  TEST_ASSERT_EQUAL_INT(64, KEYVAULT_VENDOR_KEY_LINK_LEN);
  char link[KEYVAULT_VENDOR_KEY_LINK_LEN + 2];
  for (size_t i = 0; i < KEYVAULT_VENDOR_KEY_LINK_LEN; i++)
    link[i] = "0123456789abcdef"[i % 16];
  link[KEYVAULT_VENDOR_KEY_LINK_LEN] = '\0';
  TEST_ASSERT_TRUE(validate_vendorKeyLink(link));
  link[KEYVAULT_VENDOR_KEY_LINK_LEN - 1] = '\0';
  TEST_ASSERT_FALSE(validate_vendorKeyLink(link));
  link[KEYVAULT_VENDOR_KEY_LINK_LEN - 1] = 'f';
  link[KEYVAULT_VENDOR_KEY_LINK_LEN]     = 'a';
  link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1] = '\0';
  TEST_ASSERT_FALSE(validate_vendorKeyLink(link));
  link[KEYVAULT_VENDOR_KEY_LINK_LEN] = '\0';
  link[5] = 'F';
  TEST_ASSERT_FALSE(validate_vendorKeyLink(link));
  link[5] = 'g';
  TEST_ASSERT_FALSE(validate_vendorKeyLink(link));
  link[5] = 'f';
  TEST_ASSERT_TRUE(validate_vendorKeyLink(link));
}

void test_vendorKey_takes_1_to_128_printable_bytes(void)
{
  TEST_ASSERT_FALSE(validate_vendorKey(""));
  TEST_ASSERT_TRUE(validate_vendorKey("k"));
  TEST_ASSERT_TRUE(validate_vendorKey("a ~b"));
  char key[KEYVAULT_VENDOR_KEY_MAX_LEN + 2];
  memset(key, 'z', KEYVAULT_VENDOR_KEY_MAX_LEN);
  key[KEYVAULT_VENDOR_KEY_MAX_LEN] = '\0';
  TEST_ASSERT_TRUE(validate_vendorKey(key));
  key[KEYVAULT_VENDOR_KEY_MAX_LEN]     = 'z';
  key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1] = '\0';
  TEST_ASSERT_FALSE(validate_vendorKey(key));
  TEST_ASSERT_FALSE(validate_vendorKey("a\tb"));
  TEST_ASSERT_FALSE(validate_vendorKey("a\x7f" "b"));
  TEST_ASSERT_FALSE(validate_vendorKey("a\x80" "b"));
  TEST_ASSERT_FALSE(validate_vendorKey("a\x1f" "b"));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_search_plain_valid);
  RUN_TEST(test_search_empty_valid);
  RUN_TEST(test_search_percent_invalid);
  RUN_TEST(test_search_underscore_valid);
  RUN_TEST(test_searchQuery_three_bytes_valid);
  RUN_TEST(test_searchQuery_two_bytes_invalid);
  RUN_TEST(test_searchQuery_empty_invalid);
  RUN_TEST(test_searchQuery_counts_bytes_not_characters);
  RUN_TEST(test_searchQuery_only_spaces_invalid);
  RUN_TEST(test_searchQuery_one_non_space_byte_valid);
  RUN_TEST(test_searchQuery_percent_and_punctuation_valid);
  RUN_TEST(test_searchQuery_long_query_valid);
  RUN_TEST(test_searchQuery_non_ascii_only_valid);
  RUN_TEST(test_date_valid);
  RUN_TEST(test_date_min_month_day_valid);
  RUN_TEST(test_date_wrong_length_invalid);
  RUN_TEST(test_date_bad_separator_invalid);
  RUN_TEST(test_date_non_digit_invalid);
  RUN_TEST(test_date_month_zero_invalid);
  RUN_TEST(test_date_month_over_12_invalid);
  RUN_TEST(test_date_day_zero_invalid);
  RUN_TEST(test_date_day_over_31_invalid);
  RUN_TEST(test_date_day_over_month_length_invalid);
  RUN_TEST(test_date_last_day_of_31_day_month_valid);
  RUN_TEST(test_date_last_day_of_30_day_month_valid);
  RUN_TEST(test_date_february_over_29_invalid);
  RUN_TEST(test_date_february_29_common_year_invalid);
  RUN_TEST(test_date_february_29_leap_year_valid);
  RUN_TEST(test_date_february_29_century_rule);
  RUN_TEST(test_date_year_zero_invalid);
  RUN_TEST(test_date_every_month_length_pinned_both_directions);
  RUN_TEST(test_date_leap_february_upper_bound);

  RUN_TEST(test_cveId_null_invalid);
  RUN_TEST(test_cveId_empty_string_invalid);
  RUN_TEST(test_cveId_lowercase_prefix_invalid);
  RUN_TEST(test_cveId_wrong_prefix_invalid);
  RUN_TEST(test_cveId_valid_4digit_sequence);
  RUN_TEST(test_cveId_valid_5digit_sequence);
  RUN_TEST(test_cveId_valid_min_sequence);
  RUN_TEST(test_cveId_year_3digits_invalid);
  RUN_TEST(test_cveId_year_5digits_invalid);
  RUN_TEST(test_cveId_year_with_letters_invalid);
  RUN_TEST(test_cveId_sequence_3digits_invalid);
  RUN_TEST(test_cveId_sequence_with_letters_invalid);
  RUN_TEST(test_cveId_missing_first_dash_invalid);
  RUN_TEST(test_cveId_missing_second_dash_invalid);
  RUN_TEST(test_cveId_first_separator_must_be_a_dash);
  RUN_TEST(test_cveId_second_separator_must_be_a_dash);
  RUN_TEST(test_cveId_trailing_chars_invalid);
  RUN_TEST(test_cveId_trailing_space_invalid);
  RUN_TEST(test_cveId_sequence_15digits_valid);
  RUN_TEST(test_cveId_sequence_16digits_invalid);

  RUN_TEST(test_cweId_null_invalid);
  RUN_TEST(test_cweId_empty_string_invalid);
  RUN_TEST(test_cweId_lowercase_prefix_invalid);
  RUN_TEST(test_cweId_wrong_prefix_invalid);
  RUN_TEST(test_cweId_valid_1digit);
  RUN_TEST(test_cweId_valid_2digit);
  RUN_TEST(test_cweId_valid_3digit);
  RUN_TEST(test_cweId_valid_5digit_max);
  RUN_TEST(test_cweId_zero_digits_invalid);
  RUN_TEST(test_cweId_6digits_invalid);
  RUN_TEST(test_cweId_non_digit_invalid);
  RUN_TEST(test_cweId_trailing_chars_invalid);
  RUN_TEST(test_cweId_trailing_space_invalid);
  RUN_TEST(test_cweId_missing_dash_invalid);
  RUN_TEST(test_cweId_separator_must_be_a_dash);

  RUN_TEST(test_sha1Hex_lowercase_valid);
  RUN_TEST(test_sha1Hex_uppercase_valid);
  RUN_TEST(test_sha1Hex_39_digits_invalid);
  RUN_TEST(test_sha1Hex_41_digits_invalid);
  RUN_TEST(test_sha1Hex_empty_invalid);
  RUN_TEST(test_sha1Hex_five_digit_prefix_invalid);
  RUN_TEST(test_sha1Hex_each_end_of_each_hex_range_pinned);
  RUN_TEST(test_fileHashHex_each_length_pinned);
  RUN_TEST(test_fileHashHex_each_end_of_each_hex_range_pinned);

  RUN_TEST(test_domainName_accepted_names);
  RUN_TEST(test_domainName_refused_names);
  RUN_TEST(test_domainName_label_of_63_bytes_valid);
  RUN_TEST(test_domainName_label_of_64_bytes_invalid);
  RUN_TEST(test_domainName_last_label_of_64_bytes_invalid);
  RUN_TEST(test_domainName_253_bytes_valid);
  RUN_TEST(test_domainName_254_bytes_invalid);
  RUN_TEST(test_publicDnsName_accepted_names);
  RUN_TEST(test_publicDnsName_refused_names);
  RUN_TEST(test_publicUnderscoredDnsName_accepted_names);
  RUN_TEST(test_publicUnderscoredDnsName_refused_names);
  RUN_TEST(test_publicUnderscoredDnsName_label_length_counts_the_underscore);
  RUN_TEST(test_publicUnderscoredDnsName_name_length_limit);
  RUN_TEST(test_dkimSelector_accepted_selectors);
  RUN_TEST(test_dkimSelector_refused_selectors);
  RUN_TEST(test_dkimSelector_label_length_limit);
  RUN_TEST(test_dkimSelector_selector_length_limit);
  RUN_TEST(test_watchlistCursor_each_shape_pinned);
  RUN_TEST(test_attackTechniqueId_each_shape_pinned);
  RUN_TEST(test_attackTechniqueId_each_byte_next_to_its_range_refused);
  RUN_TEST(test_packageEcosystem_each_name_in_any_case_and_no_other);
  RUN_TEST(test_packageName_refuses_a_space_alone);
  RUN_TEST(test_packageVersion_each_end_of_the_visible_range_pinned);
  RUN_TEST(test_packageExactVersion_refuses_each_range_spelling);
  RUN_TEST(test_asn_each_shape_pinned);
  RUN_TEST(test_asnLookupTarget_accepts_an_as_number_or_a_public_address);
  RUN_TEST(test_emailAddress_each_shape_pinned);
  RUN_TEST(test_emailAddress_length_edges);
  RUN_TEST(test_emailAddress_each_byte_of_a_one_byte_local_part);
  RUN_TEST(test_uuid_every_lower_hex_digit_valid);
  RUN_TEST(test_uuid_byte_beside_a_digit_range_refused_at_every_position);
  RUN_TEST(test_uuid_hyphen_moved_or_replaced_refused);
  RUN_TEST(test_uuid_length_and_other_forms_refused);
  RUN_TEST(test_vendorKeyLink_takes_64_lower_case_hex_digits);
  RUN_TEST(test_vendorKey_takes_1_to_128_printable_bytes);
  return UNITY_END();
}
