#include <assert.h>

#include "emaildata.h"
#include "bytes.h"

const EmailDataProvider_t emaildata_providers[EMAILDATA_PROVIDER_COUNT] = {
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

const char* const emaildata_commonDkimSelectors[EMAILDATA_COMMON_DKIM_SELECTOR_COUNT] = {
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "k3",
  "mail",
  "dkim",
  "s1",
  "s2",
  "everlytickey1",
  "mxvault",
};

const EmailDataProvider_t* emaildata_findProvider(const char* host_name, size_t host_name_len)
{
  assert(host_name != NULL);

  if (host_name_len > 0 && host_name[host_name_len - 1] == '.')
    host_name_len--;

  for (int i = 0; i < EMAILDATA_PROVIDER_COUNT; i++)
  {
    const EmailDataProvider_t* provider = &emaildata_providers[i];
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT && provider->ma_suffixes[j] != NULL; j++)
      if (bytes_isNameUnderSuffix(host_name, host_name_len, provider->ma_suffixes[j]))
        return provider;
  }

  return NULL;
}
