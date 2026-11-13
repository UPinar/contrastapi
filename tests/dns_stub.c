#include <ctype.h>
#include <netinet/in.h>
#include <string.h>

#include "dns.h"

DnsLookupStatus_t g_stub_DNSLOOKUP_status = DNS_LOOKUP_OK;

int g_stub_DNSLOOKUP_call_count = 0;
int g_stub_DNSLOOKUP_free_count = 0;

char g_stub_DNSLOOKUP_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

void (*g_stub_DNSLOOKUP_on_call)(void) = NULL;

static DnsRecordText_t STUB_A[]   = { { "93.184.215.14", 13 }, { "10.0.0.7", 8 } };
static DnsMxRecord_t   STUB_MX[]  = { { 10, "mail.example.com" } };
static DnsRecordText_t STUB_NS[]  = { { "a.iana-servers.net", 18 }, { "b.iana-servers.net", 18 } };
static DnsRecordText_t STUB_TXT[] = { { "v=spf1 -all", 11 }, { "google-site-verification=abc", 28 } };
static DnsSoaRecord_t  STUB_SOA   = { "ns.icann.org", "noc.dns.icann.org", 2024081450 };

static const DnsTxtService_t STUB_GOOGLE_WORKSPACE = { "google-workspace", "google-site-verification" };

DnsLookupStatus_t dns_lookupDomain(const char* domain, DNSLOOKUPRecord_t* record_out)
{
  g_stub_DNSLOOKUP_call_count++;
  if (g_stub_DNSLOOKUP_on_call)
    g_stub_DNSLOOKUP_on_call();
  strncpy(g_stub_DNSLOOKUP_last_domain, domain, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_DNSLOOKUP_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  memset(record_out, 0, sizeof(*record_out));
  for (size_t i = 0; domain[i] != '\0' && i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    record_out->ma_domain[i] = (char)tolower((unsigned char)domain[i]);
  if (g_stub_DNSLOOKUP_status != DNS_LOOKUP_OK)
    return g_stub_DNSLOOKUP_status;

  DnsAnswer_t* answers = record_out->ma_answers;
  answers[DNS_RECORD_TYPE_A]     = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK, .m_recordCount = 2, .mp_texts = STUB_A };
  answers[DNS_RECORD_TYPE_AAAA]  = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK };
  answers[DNS_RECORD_TYPE_MX]    = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK, .m_recordCount = 1, .mp_mxRecords = STUB_MX };
  answers[DNS_RECORD_TYPE_NS]    = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK, .m_recordCount = 2, .mp_texts = STUB_NS };
  answers[DNS_RECORD_TYPE_TXT]   = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK, .m_recordCount = 2, .mp_texts = STUB_TXT };
  answers[DNS_RECORD_TYPE_CNAME] = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK };
  answers[DNS_RECORD_TYPE_SOA]   = (DnsAnswer_t){ .m_status = DNS_ANSWER_OK, .m_recordCount = 1, .mp_soaRecord = &STUB_SOA };
  answers[DNS_RECORD_TYPE_CAA]   = (DnsAnswer_t){ .m_status = DNS_ANSWER_TIMEOUT };

  static const DnsRecordText_t* non_public_addresses[] = { &STUB_A[1] };
  record_out->mp_nonPublicAddresses   = non_public_addresses;
  record_out->m_nonPublicAddressCount = 1;
  record_out->ma_services[0]          = &STUB_GOOGLE_WORKSPACE;
  record_out->m_serviceCount          = 1;
  return DNS_LOOKUP_OK;
}

void dns_DNSLOOKUPRecordFree(DNSLOOKUPRecord_t* record)
{
  g_stub_DNSLOOKUP_free_count++;
  memset(record, 0, sizeof(*record));
}

DnsLookupStatus_t g_stub_DNSTAKEOVERCHECK_status = DNS_LOOKUP_OK;

static const DnsTakeoverSuffix_t STUB_AZURE_CLOUDAPP = { "Microsoft Azure", "cloudapp.net" };

int g_stub_DNSTAKEOVERCHECK_call_count = 0;

char g_stub_DNSTAKEOVERCHECK_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

void (*g_stub_DNSTAKEOVERCHECK_on_call)(void) = NULL;

DnsLookupStatus_t dns_checkTakeover(const char* hostname, DNSTAKEOVERCHECKRecord_t* record_out)
{
  g_stub_DNSTAKEOVERCHECK_call_count++;
  if (g_stub_DNSTAKEOVERCHECK_on_call)
    g_stub_DNSTAKEOVERCHECK_on_call();
  strncpy(g_stub_DNSTAKEOVERCHECK_last_hostname, hostname, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_DNSTAKEOVERCHECK_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  memset(record_out, 0, sizeof(*record_out));
  for (size_t i = 0; hostname[i] != '\0' && i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    record_out->ma_hostname[i] = (char)tolower((unsigned char)hostname[i]);
  if (g_stub_DNSTAKEOVERCHECK_status != DNS_LOOKUP_OK)
    return g_stub_DNSTAKEOVERCHECK_status;

  record_out->m_hostnameChainLength = 1;
  strncpy(record_out->ma_hostnameChain[0], "shop-example.cloudapp.net", DNS_NAME_TEXT_SIZE - 1);
  record_out->mp_matchedSuffix = &STUB_AZURE_CLOUDAPP;
  return DNS_LOOKUP_OK;
}

DnsAnswerStatus_t g_stub_PTR_status       = DNS_ANSWER_OK;
int               g_stub_PTR_record_count = 1;

int g_stub_PTR_call_count = 0;
int g_stub_PTR_free_count = 0;

char g_stub_PTR_last_ip_address[INET6_ADDRSTRLEN] = "";

void (*g_stub_PTR_on_call)(void) = NULL;

static DnsRecordText_t STUB_PTR[] = { { "one.one.one.one", 15 }, { "alias.example.net", 17 } };

void dns_lookupPtr(const char* ip_address, DnsAnswer_t* answer_out)
{
  g_stub_PTR_call_count++;
  if (g_stub_PTR_on_call)
    g_stub_PTR_on_call();
  strncpy(g_stub_PTR_last_ip_address, ip_address, INET6_ADDRSTRLEN - 1);
  g_stub_PTR_last_ip_address[INET6_ADDRSTRLEN - 1] = '\0';

  memset(answer_out, 0, sizeof(*answer_out));
  answer_out->m_status = g_stub_PTR_status;
  if (g_stub_PTR_status != DNS_ANSWER_OK)
    return;
  answer_out->m_recordCount = g_stub_PTR_record_count;
  answer_out->mp_texts      = g_stub_PTR_record_count > 0 ? STUB_PTR : NULL;
}

void dns_answerFree(DnsAnswer_t* answer)
{
  g_stub_PTR_free_count++;
  DnsAnswerStatus_t status = answer->m_status;
  memset(answer, 0, sizeof(*answer));
  answer->m_status = status;
}

DnsAnswerStatus_t g_stub_ASKQUESTIONS_status = DNS_ANSWER_OK;

int  g_stub_ASKQUESTIONS_call_count = 0;
char g_stub_ASKQUESTIONS_last_domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

void dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  (void)deadline_ms;
  g_stub_ASKQUESTIONS_call_count++;
  strncpy(g_stub_ASKQUESTIONS_last_domain_name, questions[0].mp_domainName, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_ASKQUESTIONS_last_domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  for (int i = 0; i < question_count; i++)
  {
    memset(&answers_out[i], 0, sizeof(answers_out[i]));
    answers_out[i].m_status = g_stub_ASKQUESTIONS_status;
  }
}
