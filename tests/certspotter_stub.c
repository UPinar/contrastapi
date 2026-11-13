#include <stddef.h>
#include <string.h>

#include "certspotter_stub.h"

#define CERTSPOTTER_STUB_DEFAULT_ANSWER {                                                                     \
  .m_status          = CERTSPOTTER_OK,                                                                        \
  .m_certificateList = {                                                                                      \
    .m_keptCount     = 2,                                                                                     \
    .m_readCount     = 3,                                                                                     \
    .ma_certificates = {                                                                                      \
      { .ma_sha256Hex           = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899",         \
        .ma_issuer              = "Stub Trust CA",                                                            \
        .ma_caaDomains          = { "stubtrust.example", "stub-ca.example" },                                 \
        .m_caaDomainCount       = 2,                                                                          \
        .m_isCaaDomainListKnown = true,                                                                       \
        .ma_validFrom           = "2026-09-01T01:02:03Z",                                                     \
        .ma_validUntil          = "2026-12-01T04:05:06Z",                                                     \
        .m_revocation           = CERTSPOTTER_REVOCATION_REVOKED,                                             \
        .ma_dnsNames            = { "stub.example.com", "www.stub.example.com" },                             \
        .m_dnsNameCount         = 2 },                                                                        \
      { .ma_sha256Hex           = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",         \
        .ma_issuer              = "",                                                                         \
        .m_isCaaDomainListKnown = false,                                                                      \
        .ma_validFrom           = "2026-03-04T07:08:09Z",                                                     \
        .ma_validUntil          = "2027-03-05T10:11:12Z",                                                     \
        .m_revocation           = CERTSPOTTER_REVOCATION_UNKNOWN,                                             \
        .ma_dnsNames            = { "*.stub.example.com", "n01.stub.example.com", "n02.stub.example.com",     \
                                    "n03.stub.example.com", "n04.stub.example.com", "n05.stub.example.com",   \
                                    "n06.stub.example.com", "n07.stub.example.com", "n08.stub.example.com",   \
                                    "n09.stub.example.com", "n10.stub.example.com", "n11.stub.example.com",   \
                                    "n12.stub.example.com", "n13.stub.example.com", "n14.stub.example.com",   \
                                    "n15.stub.example.com", "n16.stub.example.com", "n17.stub.example.com",   \
                                    "n18.stub.example.com", "n19.stub.example.com" },                         \
        .m_dnsNameCount         = CERTSPOTTER_DNS_NAME_MAX_COUNT + 5 },                                       \
    },                                                                                                        \
  },                                                                                                          \
}

const CertSpotterStubAnswer_t g_stub_CERTSPOTTER_default_answer = CERTSPOTTER_STUB_DEFAULT_ANSWER;
CertSpotterStubAnswer_t       g_stub_CERTSPOTTER_answer         = CERTSPOTTER_STUB_DEFAULT_ANSWER;

int                 g_stub_CERTSPOTTER_lookup_count = 0;
char                g_stub_CERTSPOTTER_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
PGconn*             g_stub_CERTSPOTTER_last_lookup_conn = NULL;
const QuotaRule_t*  g_stub_CERTSPOTTER_last_lookup_rule = NULL;

bool g_stub_CERTSPOTTER_has_api_key = true;

void (*g_stub_CERTSPOTTER_on_call)(void) = NULL;

bool certspotter_hasApiKey(void)
{
  return g_stub_CERTSPOTTER_has_api_key;
}

CertSpotterStatus_t certspotter_lookupCertificates(PGconn* conn, const QuotaRule_t* quota_rule, const char* host_name, CertSpotterCertificateList_t* list_out, unsigned int* retry_after_seconds_out)
{
  g_stub_CERTSPOTTER_lookup_count++;
  if (g_stub_CERTSPOTTER_on_call)
    g_stub_CERTSPOTTER_on_call();
  strncpy(g_stub_CERTSPOTTER_last_lookup_name, host_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_CERTSPOTTER_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  g_stub_CERTSPOTTER_last_lookup_conn = conn;
  g_stub_CERTSPOTTER_last_lookup_rule = quota_rule;

  memset(list_out, 0, sizeof(*list_out));
  *retry_after_seconds_out = 0;

  const CertSpotterStubAnswer_t* answer = &g_stub_CERTSPOTTER_answer;
  if (answer->m_status == CERTSPOTTER_INVALID_NAME || answer->m_status == CERTSPOTTER_NO_API_KEY)
    return answer->m_status;

  switch (quota_dbReserve(conn, quota_rule))
  {
    case QUOTA_GRANTED:
      break;
    case QUOTA_EXHAUSTED:
      return CERTSPOTTER_QUOTA_EXHAUSTED;
    case QUOTA_ERROR:
      return CERTSPOTTER_DB_ERROR;
  }

  if (answer->m_status == CERTSPOTTER_OK)
    *list_out = answer->m_certificateList;
  else if (answer->m_status == CERTSPOTTER_RATE_LIMITED)
    *retry_after_seconds_out = answer->m_retryAfterSeconds;
  return answer->m_status;
}

#define CERTSPOTTER_STUB_DEFAULT_SUBTREE_ANSWER {                                       \
  .m_status            = CERTSPOTTER_OK,                                                \
  .ma_names            = { "*.dev.example.com", "www.example.com", "api.example.com" }, \
  .m_nameCount         = 3,                                                             \
  .m_isAnswerEmpty     = false,                                                         \
  .m_retryAfterSeconds = 0,                                                             \
}

const CertSpotterStubSubtreeAnswer_t g_stub_CERTSPOTTER_default_subtree_answer = CERTSPOTTER_STUB_DEFAULT_SUBTREE_ANSWER;
CertSpotterStubSubtreeAnswer_t       g_stub_CERTSPOTTER_subtree_answer         = CERTSPOTTER_STUB_DEFAULT_SUBTREE_ANSWER;

int  g_stub_CERTSPOTTER_subtree_lookup_count = 0;
char g_stub_CERTSPOTTER_last_subtree_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

CertSpotterStatus_t certspotter_lookupSubdomainNames(const char* domain, SubdomainNameSet_t* name_set, bool* is_answer_empty_out, unsigned int* retry_after_seconds_out)
{
  g_stub_CERTSPOTTER_subtree_lookup_count++;
  if (g_stub_CERTSPOTTER_on_call)
    g_stub_CERTSPOTTER_on_call();
  strncpy(g_stub_CERTSPOTTER_last_subtree_domain, domain, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_CERTSPOTTER_last_subtree_domain[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  *is_answer_empty_out     = false;
  *retry_after_seconds_out = 0;

  const CertSpotterStubSubtreeAnswer_t* answer = &g_stub_CERTSPOTTER_subtree_answer;
  if (answer->m_status == CERTSPOTTER_OK)
  {
    for (int i = 0; i < answer->m_nameCount && i < CERTSPOTTER_STUB_SUBTREE_NAME_MAX_COUNT; i++)
      subdomain_addName(name_set, answer->ma_names[i], domain, SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
    *is_answer_empty_out = answer->m_isAnswerEmpty;
  }
  else if (answer->m_status == CERTSPOTTER_RATE_LIMITED)
  {
    *retry_after_seconds_out = answer->m_retryAfterSeconds;
  }
  return answer->m_status;
}
