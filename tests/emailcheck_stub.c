#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "emailcheck.h"

DnsLookupStatus_t g_stub_EMAILAUTHCHECK_status = DNS_LOOKUP_OK;

int g_stub_EMAILAUTHCHECK_call_count = 0;
int g_stub_EMAILAUTHCHECK_free_count = 0;

char g_stub_EMAILAUTHCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1]          = "";
char g_stub_EMAILAUTHCHECK_last_dkim_selector[VALIDATE_DKIM_SELECTOR_MAX_LEN + 1] = "";

void (*g_stub_EMAILAUTHCHECK_on_call)(void) = NULL;

DnsLookupStatus_t emailcheck_checkDomain(const char* domain, const char* dkim_selector, EMAILAUTHCHECKRecord_t* record_out)
{
  g_stub_EMAILAUTHCHECK_call_count++;
  if (g_stub_EMAILAUTHCHECK_on_call)
    g_stub_EMAILAUTHCHECK_on_call();
  strncpy(g_stub_EMAILAUTHCHECK_last_domain, domain, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_EMAILAUTHCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  strncpy(g_stub_EMAILAUTHCHECK_last_dkim_selector, dkim_selector != NULL ? dkim_selector : "", VALIDATE_DKIM_SELECTOR_MAX_LEN);
  g_stub_EMAILAUTHCHECK_last_dkim_selector[VALIDATE_DKIM_SELECTOR_MAX_LEN] = '\0';

  memset(record_out, 0, sizeof(*record_out));
  for (size_t i = 0; domain[i] != '\0' && i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    record_out->ma_domain[i] = (char)tolower((unsigned char)domain[i]);
  if (g_stub_EMAILAUTHCHECK_status != DNS_LOOKUP_OK)
    return g_stub_EMAILAUTHCHECK_status;

  record_out->m_mtaStsAnswer.m_status = DNS_ANSWER_NXDOMAIN;
  record_out->m_dkimSelectorSource    = EMAILCHECK_DKIM_SELECTOR_SOURCE_COMMON;
  record_out->m_dkimKeyStatus         = EMAILCHECK_DKIM_KEY_UNKNOWN;
  const EmailCheckItem_t checks[] = {
    { EMAILCHECK_KIND_SPF_RECORD,     EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_DMARC_RECORD,   EMAILCHECK_RESULT_FAIL },
    { EMAILCHECK_KIND_DKIM_KEY_FOUND, EMAILCHECK_RESULT_WARN },
    { EMAILCHECK_KIND_MX,             EMAILCHECK_RESULT_WARN },
    { EMAILCHECK_KIND_MTA_STS,        EMAILCHECK_RESULT_WARN },
  };
  memcpy(record_out->ma_checks, checks, sizeof(checks));
  record_out->m_checkCount = (int)(sizeof(checks) / sizeof(checks[0]));
  return DNS_LOOKUP_OK;
}

void emailcheck_EMAILAUTHCHECKRecordFree(EMAILAUTHCHECKRecord_t* record)
{
  g_stub_EMAILAUTHCHECK_free_count++;
  if (record != NULL)
    memset(record, 0, sizeof(*record));
}

DnsLookupStatus_t     g_stub_EMAILADDRESSCHECK_dns_status = DNS_LOOKUP_OK;
EmailCheckMailRoute_t g_stub_EMAILADDRESSCHECK_mail_route = EMAILCHECK_MAIL_ROUTE_MX;

int  g_stub_EMAILADDRESSCHECK_dns_call_count                              = 0;
int  g_stub_EMAILADDRESSCHECK_free_count                                  = 0;
char g_stub_EMAILADDRESSCHECK_last_dns_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

static char EMAILADDRESSCHECK_STUB_MX_HOST_1[] = "mx1.mail.example.net";
static char EMAILADDRESSCHECK_STUB_MX_HOST_2[] = "mx2.mail.example.net";
static DnsMxRecord_t EMAILADDRESSCHECK_STUB_MX_RECORDS[] = {
  { 10, EMAILADDRESSCHECK_STUB_MX_HOST_1 },
  { 20, EMAILADDRESSCHECK_STUB_MX_HOST_2 },
};

DnsLookupStatus_t emailcheck_checkAddressDomain(const char* domain, EMAILADDRESSCHECKRecord_t* record)
{
  g_stub_EMAILADDRESSCHECK_dns_call_count++;
  snprintf(g_stub_EMAILADDRESSCHECK_last_dns_domain, sizeof(g_stub_EMAILADDRESSCHECK_last_dns_domain), "%s", domain);

  record->m_isDomainFound = false;
  record->m_mailRoute     = EMAILCHECK_MAIL_ROUTE_NONE;
  memset(&record->m_mxAnswer, 0, sizeof(record->m_mxAnswer));
  if (g_stub_EMAILADDRESSCHECK_dns_status == DNS_LOOKUP_NOT_FOUND)
    record->m_mxAnswer.m_status = DNS_ANSWER_NXDOMAIN;
  if (g_stub_EMAILADDRESSCHECK_dns_status != DNS_LOOKUP_OK)
    return g_stub_EMAILADDRESSCHECK_dns_status;

  record->m_isDomainFound = true;
  record->m_mailRoute     = g_stub_EMAILADDRESSCHECK_mail_route;
  if (g_stub_EMAILADDRESSCHECK_mail_route == EMAILCHECK_MAIL_ROUTE_MX)
  {
    record->m_mxAnswer.mp_mxRecords  = EMAILADDRESSCHECK_STUB_MX_RECORDS;
    record->m_mxAnswer.m_recordCount = (int)(sizeof(EMAILADDRESSCHECK_STUB_MX_RECORDS) / sizeof(EMAILADDRESSCHECK_STUB_MX_RECORDS[0]));
  }
  record->m_mxAnswer.m_hasNullMx = g_stub_EMAILADDRESSCHECK_mail_route == EMAILCHECK_MAIL_ROUTE_NULL_MX;
  return DNS_LOOKUP_OK;
}

void emailcheck_EMAILADDRESSCHECKRecordFree(EMAILADDRESSCHECKRecord_t* record)
{
  g_stub_EMAILADDRESSCHECK_free_count++;
  if (record != NULL)
    memset(record, 0, sizeof(*record));
}
