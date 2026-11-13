/*
 * dns_table.c — the services dns_lookupDomain looks for in TXT records, and the name
 * suffixes dns_checkTakeover knows.
 *
 * Many services ask a customer to publish a TXT record that proves the customer owns
 * the domain. The record holds a word the service picked, such as
 * "google-site-verification". A domain whose TXT records hold such a word shows that
 * it uses the service.
 *
 * dns_txtServices comes from the nuclei-templates file dns/txt-service-detect.yaml, at
 * commit bf9f2b16be45e0f37fc97705ce32b69f17cf0f12 of
 * https://github.com/projectdiscovery/nuclei-templates. Each entry is one matcher of that
 * file: its name and its one word, in the file's order.
 * tests/dns_gen/txt_services_gen.py writes the entries from the file.
 *
 * The nuclei-templates license:
 *
 *   MIT License
 *
 *   Copyright (c) 2025 ProjectDiscovery, Inc.
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all
 *   copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.
 *
 * dns_takeoverSuffixes comes from fingerprints.json of "Can I take over XYZ?" by
 * EdOverflow, at commit 5bd4e12837911c8475486f1da922c9b9c706e632 of
 * https://github.com/EdOverflow/can-i-take-over-xyz. That work is licensed under
 * Creative Commons Attribution 4.0 International
 * (https://creativecommons.org/licenses/by/4.0/). The entries here are changed. A
 * service is kept when the file marks it "Vulnerable" and its fingerprint is NXDOMAIN.
 * Each CNAME suffix of a kept service appears once.
 * tests/dns_gen/takeover_suffixes_gen.py writes the entries from the file.
 */

#include "dns.h"

const DnsTxtService_t dns_txtServices[DNS_TXT_SERVICE_COUNT] = {
  { "keybase",                  "keybase-site-verification" },
  { "salesloft-drift",          "drift-domain-verification" },
  { "proton-mail",              "protonmail-verification" },
  { "webex",                    "webexdomainverification" },
  { "apple",                    "apple-domain-verification" },
  { "facebook",                 "facebook-domain-verification" },
  { "autodesk",                 "autodesk-domain-verification" },
  { "stripe",                   "stripe-verification" },
  { "atlassian",                "atlassian-domain-verification" },
  { "adobe-sign",               "adobe-sign-verification" },
  { "zoho",                     "zoho-verification" },
  { "have-i-been-pwned",        "have-i-been-pwned-verification" },
  { "knowbe4",                  "knowbe4-site-verification" },
  { "jamf",                     "jamf-site-verification" },
  { "parallels",                "parallels-domain-verification" },
  { "dropbox",                  "dropbox-domain-verification" },
  { "vmware-cloud",             "vmware-cloud-verification" },
  { "canva",                    "canva-site-verification" },
  { "mongodb",                  "mongodb-site-verification" },
  { "slack",                    "slack-domain-verification" },
  { "teamViewer",               "teamviewer-sso-verification" },
  { "bugcrowd",                 "bugcrowd-verification" },
  { "cisco",                    "cisco-site-verification" },
  { "palo-alto-networks",       "paloaltonetworks-site-verification" },
  { "twilio",                   "twilio-domain-verification" },
  { "dell-technologies",        "dell-technologies-domain-verification" },
  { "1password",                "1password-site-verification" },
  { "duo",                      "duo_sso_verification" },
  { "sophos",                   "sophos-domain-verification" },
  { "pinterest",                "pinterest-site-verification" },
  { "citrix",                   "citrix-verification-code" },
  { "zapier",                   "zapier-domain-verification-challenge" },
  { "uber",                     "uber-domain-verification" },
  { "zoom",                     "zoom-domain-verification" },
  { "lastpass",                 "lastpass-verification-code" },
  { "google-workspace",         "google-site-verification" },
  { "flexera",                  "flexera-domain-verification" },
  { "yandex",                   "yandex-verification" },
  { "calendly",                 "calendly-site-verification" },
  { "docusign",                 "docusign" },
  { "whimsical",                "whimsical" },
  { "nintex",                   "nintex." },
  { "openai",                   "openai-domain-verification" },
  { "mailerlite",               "mailerlite-domain-verification" },
  { "docker",                   "docker-verification" },
  { "shopify",                  "shopify-verification-code" },
  { "smartsheet",               "smartsheet-site-validation" },
  { "site24x7",                 "site24x7-signals-domain-verification" },
  { "dynatrace",                "dynatrace-site-verification" },
  { "cisco-cloud-intelligence", "cisco-ci-domain-verification" },
  { "infor-cloudsuite",         "infor-cloudsuite-domain-verification" },
  { "postman",                  "postman-domain-verification" },
  { "miro",                     "miro-verification" },
  { "microsoft-federation",     "msfpkey" },
  { "dynamics-365-marketing",   "d365mktkey" },
  { "zoom-alternative",         "zoom_verify" },
  { "brevo",                    "brevo-code" },
  { "perplexity-ai",            "perplexity-ai-domain-verification" },
  { "pexip",                    "pexip-ms-tenant-domain-verification" },
  { "anthropic",                "anthropic-domain-verification" },
  { "airtable",                 "airtable-verification" },
  { "wrike",                    "wrike-verification" },
  { "salesforce-pardot",        "pardot" },
  { "notion",                   "notion-domain-verification" },
  { "jetbrains",                "jetbrains-domain-verification" },
  { "onetrust",                 "onetrust-domain-verification" },
  { "nulab",                    "nulab-verification-code" },
  { "sap-successfactors",       "successfactors-site-verification" },
  { "synthesia",                "synthesia" },
  { "monday",                   "monday-com-verification" },
  { "globalsign",               "globalsign-domain-verification" },
  { "heyhack",                  "heyhack-verification" },
  { "foxit",                    "foxit-domain-verification" },
  { "facebook-workplace",       "workplace-domain-verification" },
  { "pendo",                    "pendo-domain-verification" },
  { "stytch",                   "stytch_verification_dns" },
  { "mixpanel",                 "mixpanel-domain-verify" },
  { "astro",                    "astro-domain-verification" },
  { "box",                      "box-domain-verification" },
  { "wiz",                      "wiz-domain-verification" },
  { "figma",                    "figma-domain-verification" },
  { "solarwinds",               "solarwinds-service0desk-verification" },
  { "hubspot",                  "hubspot-domain-verification" },
  { "microsoft-domain",         "ms-domain-verification" },
  { "swisssign",                "swisssign-check" },
  { "infoblox",                 "infoblox-domain-mastery" },
  { "ahrefs",                   "ahrefs-site-verification" },
  { "logmein",                  "logmein-verification-code" },
  { "mailru",                   "mailru-verification" },
  { "mandrill",                 "mandrill_verify" },
  { "nitro",                    "nitro-verification-code" },
  { "parkable",                 "parkable-domain-verification" },
  { "seculio",                  "seculio-domain-verification-code" },
  { "trustpilot",               "trustpilot-one-time-verification" },
  { "esputnik",                 "esputnik-verification" },
  { "atlassian-sending",        "atlassian-sending-domain-verification" },
};

const DnsTakeoverSuffix_t dns_takeoverSuffixes[DNS_TAKEOVER_SUFFIX_COUNT] = {
  { "AWS/Elastic Beanstalk", "elasticbeanstalk.com" },
  { "Discourse",             "trydiscourse.com" },
  { "Microsoft Azure",       "cloudapp.net" },
  { "Microsoft Azure",       "cloudapp.azure.com" },
  { "Microsoft Azure",       "azurewebsites.net" },
  { "Microsoft Azure",       "blob.core.windows.net" },
  { "Microsoft Azure",       "azure-api.net" },
  { "Microsoft Azure",       "azurehdinsight.net" },
  { "Microsoft Azure",       "azureedge.net" },
  { "Microsoft Azure",       "azurecontainer.io" },
  { "Microsoft Azure",       "database.windows.net" },
  { "Microsoft Azure",       "azuredatalakestore.net" },
  { "Microsoft Azure",       "search.windows.net" },
  { "Microsoft Azure",       "azurecr.io" },
  { "Microsoft Azure",       "redis.cache.windows.net" },
  { "Microsoft Azure",       "servicebus.windows.net" },
  { "Microsoft Azure",       "visualstudio.com" },
};
