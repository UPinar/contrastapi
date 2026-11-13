#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "unity/unity.h"
#include "etld.h"

void setUp(void)    {}
void tearDown(void) {}

typedef struct {
  const char* mp_domainName;
  const char* mp_publicSuffix;
  const char* mp_registrableDomain;
} EtldCase_t;

static bool static_isLowerCaseLdhName(const char* text)
{
  size_t label_len = 0;
  char   previous  = '.';
  for (const char* byte = text; ; byte++)
  {
    if (*byte == '.' || *byte == '\0')
    {
      if (label_len == 0 || label_len > 63 || previous == '-')
        return false;
      if (*byte == '\0')
        return true;
      label_len = 0;
    }
    else if (islower((unsigned char)*byte) || isdigit((unsigned char)*byte) || (*byte == '-' && label_len > 0))
      label_len++;
    else
      return false;
    previous = *byte;
  }
}

void test_ruleOffsets_hold_the_rules_in_strcmp_order(void)
{
  TEST_ASSERT_TRUE(etld_ruleCount > 1);
  TEST_ASSERT_EQUAL_UINT32(0, etld_ruleOffsets[0]);
  for (int i = 1; i < etld_ruleCount; i++)
  {
    const char* previous_rule = etld_ruleText + etld_ruleOffsets[i - 1];
    const char* rule          = etld_ruleText + etld_ruleOffsets[i];
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(etld_ruleOffsets[i - 1] + strlen(previous_rule) + 1, etld_ruleOffsets[i], rule);
    TEST_ASSERT_TRUE_MESSAGE(strcmp(previous_rule, rule) < 0, rule);
  }
}

void test_every_rule_is_lower_case_ldh_after_its_prefix(void)
{
  for (int i = 0; i < etld_ruleCount; i++)
  {
    const char* rule = etld_ruleText + etld_ruleOffsets[i];
    const char* name = rule;
    if (rule[0] == '!')
    {
      name = rule + 1;
      TEST_ASSERT_NOT_NULL_MESSAGE(strchr(name, '.'), rule);
    }
    else if (strncmp(rule, "*.", 2) == 0)
      name = rule + 2;
    TEST_ASSERT_TRUE_MESSAGE(static_isLowerCaseLdhName(name), rule);
  }
}

void test_find_and_findPlusOne_agree_with_tldextract(void)
{
  static const EtldCase_t cases[] = {
    { "example.com", "com", "example.com" },
    { "www.example.com", "com", "example.com" },
    { "a.b.c.example.com", "com", "example.com" },
    { "example.co.uk", "co.uk", "example.co.uk" },
    { "www.example.co.uk", "co.uk", "example.co.uk" },
    { "co.uk", "co.uk", NULL },
    { "example.uk", "uk", "example.uk" },
    { "www.ck", "ck", "www.ck" },
    { "a.www.ck", "ck", "www.ck" },
    { "c.ck", "c.ck", NULL },
    { "b.c.ck", "c.ck", "b.c.ck" },
    { "city.kawasaki.jp", "kawasaki.jp", "city.kawasaki.jp" },
    { "a.b.city.kawasaki.jp", "kawasaki.jp", "city.kawasaki.jp" },
    { "foo.kawasaki.jp", "foo.kawasaki.jp", NULL },
    { "a.foo.kawasaki.jp", "foo.kawasaki.jp", "a.foo.kawasaki.jp" },
    { "kawasaki.jp", "jp", "kawasaki.jp" },
    { "user.github.io", "io", "github.io" },
    { "github.io", "io", "github.io" },
    { "example.xn--p1ai", "xn--p1ai", "example.xn--p1ai" },
    { "www.example.xn--p1ai", "xn--p1ai", "example.xn--p1ai" },
    { "xn--85x722f.xn--55qx5d.cn", "xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn" },
    { "a.xn--55qx5d.cn", "xn--55qx5d.cn", "a.xn--55qx5d.cn" },
    { "xn--55qx5d.cn", "xn--55qx5d.cn", NULL },
    { "shop.example.com.tr", "com.tr", "example.com.tr" },
    { "example.k12.ak.us", "k12.ak.us", "example.k12.ak.us" },
    { "a.example.k12.ak.us", "k12.ak.us", "example.k12.ak.us" },
    { "www.EXAMPLE.CO.UK", "CO.UK", "EXAMPLE.CO.UK" },
    { "Example.Com", "Com", "Example.Com" },
    { "x.sch.uk", "x.sch.uk", NULL },
    { "y.x.sch.uk", "x.sch.uk", "y.x.sch.uk" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const char* domain_name = cases[i].mp_domainName;
    size_t      name_len    = strlen(domain_name);

    const char* public_suffix = etld_find(domain_name);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(domain_name + name_len - strlen(cases[i].mp_publicSuffix), public_suffix, domain_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_publicSuffix, public_suffix, domain_name);

    const char* registrable_domain = etld_findPlusOne(domain_name);
    if (cases[i].mp_registrableDomain == NULL)
      TEST_ASSERT_NULL_MESSAGE(registrable_domain, domain_name);
    else
    {
      TEST_ASSERT_EQUAL_PTR_MESSAGE(domain_name + name_len - strlen(cases[i].mp_registrableDomain), registrable_domain, domain_name);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_registrableDomain, registrable_domain, domain_name);
    }
  }
}

void test_a_name_no_rule_matches_takes_its_last_label_as_its_public_suffix(void)
{
  static const EtldCase_t cases[] = {
    { "example.notatld", "notatld", "example.notatld" },
    { "a.b.notatld", "notatld", "b.notatld" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_publicSuffix, etld_find(cases[i].mp_domainName), cases[i].mp_domainName);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_registrableDomain, etld_findPlusOne(cases[i].mp_domainName), cases[i].mp_domainName);
  }
}

void test_both_refuse_a_name_validate_domainName_refuses(void)
{
  static const char* const refused_names[] = {
    "", "com", "example.com.", "1.2.3.4", "-a.example.com", "exa mple.com",
  };
  for (size_t i = 0; i < sizeof(refused_names) / sizeof(refused_names[0]); i++)
  {
    TEST_ASSERT_NULL_MESSAGE(etld_find(refused_names[i]), refused_names[i]);
    TEST_ASSERT_NULL_MESSAGE(etld_findPlusOne(refused_names[i]), refused_names[i]);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ruleOffsets_hold_the_rules_in_strcmp_order);
  RUN_TEST(test_every_rule_is_lower_case_ldh_after_its_prefix);

  RUN_TEST(test_find_and_findPlusOne_agree_with_tldextract);
  RUN_TEST(test_a_name_no_rule_matches_takes_its_last_label_as_its_public_suffix);
  RUN_TEST(test_both_refuse_a_name_validate_domainName_refuses);
  return UNITY_END();
}
