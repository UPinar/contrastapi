#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "unity/unity.h"
#include "emaildata.h"
#include "validate.h"

void setUp(void)    {}
void tearDown(void) {}

static const EmailDataProvider_t* static_findProvider(const char* host_name)
{
  return emaildata_findProvider(host_name, strlen(host_name));
}

static bool static_isUnderSuffix(const char* domain_name, const char* suffix)
{
  size_t name_len   = strlen(domain_name);
  size_t suffix_len = strlen(suffix);
  if (name_len < suffix_len || strcmp(domain_name + name_len - suffix_len, suffix) != 0)
    return false;
  return name_len == suffix_len || domain_name[name_len - suffix_len - 1] == '.';
}

void test_every_provider_has_a_name_a_suffix_and_no_gap(void)
{
  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
  {
    const EmailDataProvider_t* provider = &emaildata_providers[i];
    TEST_ASSERT_NOT_NULL(provider->mp_name);
    TEST_ASSERT_TRUE_MESSAGE(provider->mp_name[0] != '\0', "empty name");
    TEST_ASSERT_NOT_NULL_MESSAGE(provider->ma_suffixes[0], provider->mp_name);
    for (int j = 1; j < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT; j++)
      if (provider->ma_suffixes[j - 1] == NULL)
        TEST_ASSERT_NULL_MESSAGE(provider->ma_suffixes[j], provider->mp_name);
    for (int j = 1; j < EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT; j++)
      if (provider->ma_dkimSelectors[j - 1] == NULL)
        TEST_ASSERT_NULL_MESSAGE(provider->ma_dkimSelectors[j], provider->mp_name);
  }
}

void test_every_suffix_is_lower_case_ldh_with_a_dot(void)
{
  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT && emaildata_providers[i].ma_suffixes[j] != NULL; j++)
    {
      const char* suffix = emaildata_providers[i].ma_suffixes[j];
      TEST_ASSERT_TRUE_MESSAGE(validate_domainName(suffix), suffix);
      for (const char* byte = suffix; *byte != '\0'; byte++)
        TEST_ASSERT_TRUE_MESSAGE(islower((unsigned char)*byte) || isdigit((unsigned char)*byte) || *byte == '-' || *byte == '.', suffix);
    }
}

void test_no_suffix_covers_another_suffix(void)
{
  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT && emaildata_providers[i].ma_suffixes[j] != NULL; j++)
      for (int k = 0; k < EMAILDATA_PROVIDER_COUNT; k++)
        for (int m = 0; m < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT && emaildata_providers[k].ma_suffixes[m] != NULL; m++)
        {
          if (i == k && j == m)
            continue;
          TEST_ASSERT_FALSE_MESSAGE(static_isUnderSuffix(emaildata_providers[i].ma_suffixes[j], emaildata_providers[k].ma_suffixes[m]), emaildata_providers[i].ma_suffixes[j]);
        }
}

void test_documented_selectors_pinned(void)
{
  static const struct {
    const char* mp_hostName;
    const char* mp_name;
    const char* ma_dkimSelectors[EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT];
  } cases[] = {
    { "mx01.mail.icloud.com",                    "Apple iCloud",     { "sig1" } },
    { "in1-smtp.messagingengine.com",            "Fastmail",         { "fm1", "fm2", "fm3", "mesmtp" } },
    { "aspmx.l.google.com",                      "Google Workspace", { "google" } },
    { "spf.mandrillapp.com",                     "Mailchimp Transactional", { "mte1", "mte2" } },
    { "mxa.mailgun.org",                         "Mailgun",          { "pdk1", "pdk2" } },
    { "contoso-com.mail.protection.outlook.com", "Microsoft 365",    { "selector1", "selector2" } },
    { "sendgrid.net",                            "SendGrid",         { "s1", "s2" } },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const EmailDataProvider_t* provider = static_findProvider(cases[i].mp_hostName);
    TEST_ASSERT_NOT_NULL_MESSAGE(provider, cases[i].mp_hostName);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_name, provider->mp_name);
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT; j++)
      if (cases[i].ma_dkimSelectors[j] == NULL)
        TEST_ASSERT_NULL_MESSAGE(provider->ma_dkimSelectors[j], cases[i].mp_name);
      else
        TEST_ASSERT_EQUAL_STRING(cases[i].ma_dkimSelectors[j], provider->ma_dkimSelectors[j]);
  }
}

void test_providers_without_documented_selectors_have_none(void)
{
  static const char* const host_names[] = {
    "mx.zoho.eu", "mail.protonmail.ch", "mx1.pphosted.com",
    "amazonses.com", "spf.brevo.com", "servers.mcsv.net", "spf.mtasv.net", "_spf.sparkpostmail.com",
  };
  for (size_t i = 0; i < sizeof(host_names) / sizeof(host_names[0]); i++)
  {
    const EmailDataProvider_t* provider = static_findProvider(host_names[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(provider, host_names[i]);
    TEST_ASSERT_NULL_MESSAGE(provider->ma_dkimSelectors[0], host_names[i]);
  }
}

void test_every_provider_pinned(void)
{
  static const EmailDataProvider_t expected[] = {
    { "Amazon SES",       { "amazonses.com" },                              { NULL } },
    { "Apple iCloud",     { "icloud.com", "mail.me.com" },                  { "sig1" } },
    { "Barracuda",        { "barracudanetworks.com", "ess.barracuda.com" }, { NULL } },
    { "Brevo",            { "brevo.com", "sendinblue.com" },                { NULL } },
    { "Fastmail",         { "fastmail.com", "messagingengine.com" },        { "fm1", "fm2", "fm3", "mesmtp" } },
    { "FireEye",          { "fireeyecloud.com" },                           { NULL } },
    { "Forcepoint",       { "forcepoint.com" },                             { NULL } },
    { "GoDaddy",          { "secureserver.net" },                           { NULL } },
    { "Google Workspace", { "google.com", "googlemail.com" },               { "google" } },
    { "Infomaniak",       { "infomaniak.ch" },                              { NULL } },
    { "IONOS",            { "kundenserver.de" },                            { NULL } },
    { "Mailchimp",        { "mcsv.net" },                                   { NULL } },
    { "Mailchimp Transactional", { "mandrillapp.com" },                     { "mte1", "mte2" } },
    { "Mailgun",          { "mailgun.org" },                                { "pdk1", "pdk2" } },
    { "Microsoft 365",    { "outlook.com", "outlook.de" },                  { "selector1", "selector2" } },
    { "Migadu",           { "migadu.com" },                                 { NULL } },
    { "Mimecast",         { "mimecast.com" },                               { NULL } },
    { "Namecheap",        { "registrar-servers.com" },                      { NULL } },
    { "OVH",              { "ovh.net" },                                    { NULL } },
    { "pair Networks",    { "pair.com" },                                   { NULL } },
    { "Postmark",         { "mtasv.net" },                                  { NULL } },
    { "Proofpoint",       { "pphosted.com" },                               { NULL } },
    { "ProtonMail",       { "protonmail.ch" },                              { NULL } },
    { "Rackspace",        { "emailsrvr.com" },                              { NULL } },
    { "SendGrid",         { "sendgrid.net" },                               { "s1", "s2" } },
    { "Sophos",           { "sophos.com" },                                 { NULL } },
    { "SparkPost",        { "sparkpostmail.com" },                          { NULL } },
    { "Symantec",         { "messagelabs.com" },                            { NULL } },
    { "Tutanota",         { "tutanota.de" },                                { NULL } },
    { "Yahoo Mail",       { "yahoodns.net" },                               { NULL } },
    { "Yandex Mail",      { "yandex.net", "yandex.ru" },                    { NULL } },
    { "Zoho Mail",        { "zoho.com", "zoho.eu", "zohomail.com" },        { NULL } },
  };
  TEST_ASSERT_EQUAL_INT(EMAILDATA_PROVIDER_COUNT, (int)(sizeof(expected) / sizeof(expected[0])));
  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_STRING(expected[i].mp_name, emaildata_providers[i].mp_name);
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT; j++)
    {
      if (expected[i].ma_suffixes[j] == NULL)
      {
        TEST_ASSERT_NULL_MESSAGE(emaildata_providers[i].ma_suffixes[j], expected[i].mp_name);
        continue;
      }
      TEST_ASSERT_EQUAL_STRING(expected[i].ma_suffixes[j], emaildata_providers[i].ma_suffixes[j]);
      const EmailDataProvider_t* provider = static_findProvider(expected[i].ma_suffixes[j]);
      TEST_ASSERT_NOT_NULL_MESSAGE(provider, expected[i].ma_suffixes[j]);
      TEST_ASSERT_EQUAL_STRING(expected[i].mp_name, provider->mp_name);
    }
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT; j++)
      if (expected[i].ma_dkimSelectors[j] == NULL)
        TEST_ASSERT_NULL_MESSAGE(emaildata_providers[i].ma_dkimSelectors[j], expected[i].mp_name);
      else
        TEST_ASSERT_EQUAL_STRING(expected[i].ma_dkimSelectors[j], emaildata_providers[i].ma_dkimSelectors[j]);
  }
}

void test_common_selectors_pinned(void)
{
  static const char* const expected[] = {
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "everlytickey1", "mxvault",
  };
  TEST_ASSERT_EQUAL_INT(EMAILDATA_COMMON_DKIM_SELECTOR_COUNT, (int)(sizeof(expected) / sizeof(expected[0])));
  for (int i = 0; i < EMAILDATA_COMMON_DKIM_SELECTOR_COUNT; i++)
    TEST_ASSERT_EQUAL_STRING(expected[i], emaildata_commonDkimSelectors[i]);
}

void test_every_selector_is_one_validate_dkimSelector_accepts(void)
{
  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT && emaildata_providers[i].ma_dkimSelectors[j] != NULL; j++)
      TEST_ASSERT_TRUE_MESSAGE(validate_dkimSelector(emaildata_providers[i].ma_dkimSelectors[j]), emaildata_providers[i].ma_dkimSelectors[j]);
  for (int i = 0; i < EMAILDATA_COMMON_DKIM_SELECTOR_COUNT; i++)
    TEST_ASSERT_TRUE_MESSAGE(validate_dkimSelector(emaildata_commonDkimSelectors[i]), emaildata_commonDkimSelectors[i]);
}

void test_findProvider_matches_a_suffix_or_a_name_under_it(void)
{
  static const struct { const char* mp_hostName; const char* mp_name; } cases[] = {
    { "google.com",                  "Google Workspace" },
    { "_spf.google.com",             "Google Workspace" },
    { "ALT1.ASPMX.L.GOOGLE.COM",     "Google Workspace" },
    { "spf.protection.outlook.com",  "Microsoft 365" },
    { "spf.messagingengine.com",     "Fastmail" },
    { "spf.sendinblue.com",          "Brevo" },
    { "_spf.protonmail.ch",          "ProtonMail" },
    { "zohomail.com",                "Zoho Mail" },
    { "mx.yandex.ru",                "Yandex Mail" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const EmailDataProvider_t* provider = static_findProvider(cases[i].mp_hostName);
    TEST_ASSERT_NOT_NULL_MESSAGE(provider, cases[i].mp_hostName);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_name, provider->mp_name, cases[i].mp_hostName);
  }
}

void test_findProvider_needs_the_whole_suffix_after_a_dot(void)
{
  static const char* const host_names[] = {
    "notgoogle.com", "not-google.com", "mx1google.com", "google.com.example.net", "oogle.com", "", "inbound-smtp.us-east-1.amazonaws.com",
  };
  for (size_t i = 0; i < sizeof(host_names) / sizeof(host_names[0]); i++)
    TEST_ASSERT_NULL_MESSAGE(static_findProvider(host_names[i]), host_names[i]);
}

void test_findProvider_reads_only_the_given_length(void)
{
  const EmailDataProvider_t* provider = emaildata_findProvider("aspmx.l.google.comX", 18);
  TEST_ASSERT_NOT_NULL(provider);
  TEST_ASSERT_EQUAL_STRING("Google Workspace", provider->mp_name);

  TEST_ASSERT_NULL(emaildata_findProvider("google.com", 9));
}

void test_findProvider_ignores_one_dot_at_the_end(void)
{
  const EmailDataProvider_t* provider = static_findProvider("_spf.google.com.");
  TEST_ASSERT_NOT_NULL(provider);
  TEST_ASSERT_EQUAL_STRING("Google Workspace", provider->mp_name);

  TEST_ASSERT_NULL(static_findProvider("_spf.google.com.."));
  TEST_ASSERT_NULL(static_findProvider("."));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_every_provider_has_a_name_a_suffix_and_no_gap);
  RUN_TEST(test_every_suffix_is_lower_case_ldh_with_a_dot);
  RUN_TEST(test_no_suffix_covers_another_suffix);
  RUN_TEST(test_documented_selectors_pinned);
  RUN_TEST(test_providers_without_documented_selectors_have_none);
  RUN_TEST(test_every_provider_pinned);

  RUN_TEST(test_common_selectors_pinned);
  RUN_TEST(test_every_selector_is_one_validate_dkimSelector_accepts);

  RUN_TEST(test_findProvider_matches_a_suffix_or_a_name_under_it);
  RUN_TEST(test_findProvider_needs_the_whole_suffix_after_a_dot);
  RUN_TEST(test_findProvider_reads_only_the_given_length);
  RUN_TEST(test_findProvider_ignores_one_dot_at_the_end);
  return UNITY_END();
}
