#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "watchlist_cert_search.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/watchlist_domain_scan.h"
#include "db.h"
#include "dns.h"
#include "etld.h"
#include "external/certspotter.h"
#include "quota.h"
#include "usagelog.h"
#include "validate.h"

static const QuotaRule_t WATCHLIST_CERT_SEARCH_HOURLY_QUOTA_RULE = { "domain_scan_ct", 3600, 20 };

#define WATCHLIST_CERT_SEARCH_CAA_MAX_NAME_COUNT DNS_MAX_QUESTION_COUNT

static bool                         static_isIssuerKeyValidAsLine           (const char* key);
static void                         static_sortIssuersByKey                 (const CertSpotterCertificateList_t* list, const CertSpotterIssuer_t** sorted_out);
static bool                         static_isIssuerPermitted                (const DnsAnswer_t* host_set, const DnsAnswer_t* wildcard_set, const CertSpotterIssuer_t* issuer);
static bool                         static_isIssuerPermittedBySet           (const DnsAnswer_t* caa_set, bool is_wildcard, const CertSpotterIssuer_t* issuer);
static bool                         static_isIssuerPermittedByTag           (const DnsAnswer_t* caa_set, const char* tag, const CertSpotterIssuer_t* issuer);
static bool                         static_hasCaaTag                        (const DnsAnswer_t* caa_set, const char* tag);
static bool                         static_isCaaTag                         (const DnsCaaRecord_t* record, const char* tag);
static bool                         static_isCaaValueNamingIssuer           (const DnsRecordText_t* value, const CertSpotterIssuer_t* issuer);
static bool                         static_tryFindCaaIssuerDomain           (const DnsRecordText_t* value, size_t* domain_start_out, size_t* domain_len_out);
static bool                         static_isCaaParameterListWellFormed     (const char* bytes, size_t byte_count, size_t start);
static bool                         static_isCaaParameterValueByte          (char byte);
static size_t                       static_findCaaTokenEnd                  (const char* bytes, size_t byte_count, size_t start, const char* stop_bytes);
static size_t                       static_findCaaSpaceEnd                  (const char* bytes, size_t byte_count, size_t start);
static WatchlistDomainScanOutcome_t static_scanCtDomain                     (PGconn* conn, const WatchlistDomainScanClaim_t* claim);
static void                         static_judgeCertIssuers                 (const char* host, const char* registered_domain, const CertSpotterCertificateList_t* list, WatchlistDomainScanValue_t* value);
static int                          static_countCaaNames                    (const char* host, const char* registered_domain);
static bool                         static_tryFindFirstAnswerWithCaaRecords (const DnsAnswer_t* answers, int first_index, int answer_count, const DnsAnswer_t** set_out);

bool watchlist_cert_search_scanNextDomains(PGconn* conn)
{
  const WatchlistDomainScanLane_t lane = {
    .mp_laneName    = DB_DOMAIN_WATCH_LANE_CT,
    .m_scanFunction = static_scanCtDomain,
    .m_capEvent     = USAGELOG_EVENT_CT_SCAN_CAP_REACHED,
  };

  return watchlist_domain_scan_scanNextLaneDomains(conn, &lane);
}

#define WATCHLIST_CERT_SEARCH_REASON_NEW_ISSUER   "new_issuer "
#define WATCHLIST_CERT_SEARCH_REASON_CAA_MISMATCH "caa_mismatch "

#define WATCHLIST_CERT_SEARCH_ISSUER_LINE_SIZE (sizeof(WATCHLIST_CERT_SEARCH_REASON_CAA_MISMATCH) + CERTSPOTTER_ISSUER_KEY_MAX_LEN)

#define WATCHLIST_CERT_SEARCH_CAA_CRITICAL_FLAG 0x80

static const char* const WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAGS[] = {
  "issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone",
};

#define WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAG_COUNT ((int)(sizeof(WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAGS) / sizeof(WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAGS[0])))

bool watchlist_cert_search_tryWriteCertIssuers(const CertSpotterCertificateList_t* list, const DnsAnswer_t* host_set, const DnsAnswer_t* wildcard_set, WatchlistDomainValue_t* value_out)
{
  assert(list      != NULL);
  assert(value_out != NULL);
  assert(list->m_issuerCount >= 0 && list->m_issuerCount <= CERTSPOTTER_ISSUER_MAX_COUNT);

  if (!list->m_isComplete || list->m_isIssuerDropped)
    return false;

  for (int i = 0; i < list->m_issuerCount; i++)
  {
    if (!static_isIssuerKeyValidAsLine(list->ma_issuers[i].ma_key))
      return false;
  }

  const CertSpotterIssuer_t* issuers[CERTSPOTTER_ISSUER_MAX_COUNT];
  static_sortIssuersByKey(list, issuers);

  char line_texts[CERTSPOTTER_ISSUER_MAX_COUNT][WATCHLIST_CERT_SEARCH_ISSUER_LINE_SIZE];
  WatchlistDomainLine_t lines[CERTSPOTTER_ISSUER_MAX_COUNT];
  for (int n = 0; n < list->m_issuerCount; n++)
  {
    const CertSpotterIssuer_t* issuer = issuers[n];
    const char* reason = static_isIssuerPermitted(host_set, wildcard_set, issuer) ? WATCHLIST_CERT_SEARCH_REASON_NEW_ISSUER : WATCHLIST_CERT_SEARCH_REASON_CAA_MISMATCH;
    int line_len = snprintf(line_texts[n], sizeof(line_texts[n]), "%s%s", reason, issuer->ma_key);
    lines[n] = (WatchlistDomainLine_t){ .mp_prefix = line_texts[n], .m_prefixLen = (size_t)line_len, .mp_domainName = "", .m_domainNameLen = 0 };
  }

  WatchlistDomainValue_t value;
  if (!watchlist_domain_tryWriteLinesAsGiven(lines, list->m_issuerCount, &value) || value.m_keptItemCount != value.m_itemCount)
    return false;

  memcpy(value_out, &value, sizeof(*value_out));
  return true;
}

static bool static_isIssuerKeyValidAsLine(const char* key)
{
  bool is_blank = true;
  for (const char* byte = key; *byte != '\0'; byte++)
  {
    if ((unsigned char)*byte < 0x20 || (unsigned char)*byte > 0x7e)
      return false;
    if (*byte != ' ')
      is_blank = false;
  }
  return !is_blank;
}

static void static_sortIssuersByKey(const CertSpotterCertificateList_t* list, const CertSpotterIssuer_t** sorted_out)
{
  for (int i = 0; i < list->m_issuerCount; i++)
  {
    const CertSpotterIssuer_t* issuer = &list->ma_issuers[i];
    int j = i;
    while (j > 0 && strcmp(sorted_out[j - 1]->ma_key, issuer->ma_key) > 0)
    {
      sorted_out[j] = sorted_out[j - 1];
      j--;
    }
    sorted_out[j] = issuer;
  }
}

bool watchlist_cert_search_isHostCaaSetNeeded(const CertSpotterIssuer_t* issuer)
{
  assert(issuer != NULL);
  return issuer->m_isSeenOnExactName || !issuer->m_isSeenOnWildcardName;
}

bool watchlist_cert_search_isWildcardCaaSetNeeded(const CertSpotterIssuer_t* issuer)
{
  assert(issuer != NULL);
  return issuer->m_isSeenOnWildcardName;
}

static bool static_isIssuerPermitted(const DnsAnswer_t* host_set, const DnsAnswer_t* wildcard_set, const CertSpotterIssuer_t* issuer)
{
  if (watchlist_cert_search_isHostCaaSetNeeded(issuer) && !static_isIssuerPermittedBySet(host_set, false, issuer))
    return false;

  if (watchlist_cert_search_isWildcardCaaSetNeeded(issuer) && !static_isIssuerPermittedBySet(wildcard_set, true, issuer))
    return false;

  return true;
}

static bool static_isIssuerPermittedBySet(const DnsAnswer_t* caa_set, bool is_wildcard, const CertSpotterIssuer_t* issuer)
{
  if (caa_set == NULL || caa_set->m_recordCount == 0)
    return true;

  for (int i = 0; i < caa_set->m_recordCount; i++)
  {
    const DnsCaaRecord_t* record = &caa_set->mp_caaRecords[i];
    if ((record->m_flags & WATCHLIST_CERT_SEARCH_CAA_CRITICAL_FLAG) == 0)
      continue;

    bool is_known = false;
    for (int t = 0; t < WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAG_COUNT && !is_known; t++)
      is_known = static_isCaaTag(record, WATCHLIST_CERT_SEARCH_CAA_KNOWN_TAGS[t]);
    if (!is_known)
      return false;
  }

  const char* tag = (is_wildcard && static_hasCaaTag(caa_set, "issuewild")) ? "issuewild" : "issue";
  return static_isIssuerPermittedByTag(caa_set, tag, issuer);
}

static bool static_isIssuerPermittedByTag(const DnsAnswer_t* caa_set, const char* tag, const CertSpotterIssuer_t* issuer)
{
  if (!static_hasCaaTag(caa_set, tag))
    return true;
  
  for (int i = 0; i < caa_set->m_recordCount; i++)
  {
    const DnsCaaRecord_t* record = &caa_set->mp_caaRecords[i];
    if (static_isCaaTag(record, tag) && static_isCaaValueNamingIssuer(&record->m_value, issuer))
      return true;
  }
  return false;
}

static bool static_hasCaaTag(const DnsAnswer_t* caa_set, const char* tag)
{
  for (int i = 0; i < caa_set->m_recordCount; i++)
  {
    if (static_isCaaTag(&caa_set->mp_caaRecords[i], tag))
      return true;
  }
  return false;
}

static bool static_isCaaTag(const DnsCaaRecord_t* record, const char* tag)
{
  size_t tag_len = strlen(tag);
  return record->m_tag.m_byteCount == tag_len && strncasecmp(record->m_tag.mp_bytes, tag, tag_len) == 0;
}

static bool static_isCaaValueNamingIssuer(const DnsRecordText_t* value, const CertSpotterIssuer_t* issuer)
{
  size_t domain_start = 0;
  size_t domain_len   = 0;
  if (!static_tryFindCaaIssuerDomain(value, &domain_start, &domain_len))
    return false;

  const char* domain = value->mp_bytes + domain_start;
  for (int i = 0; i < issuer->m_caaDomainCount; i++)
  {
    if (strlen(issuer->ma_caaDomains[i]) == domain_len && strncasecmp(issuer->ma_caaDomains[i], domain, domain_len) == 0)
      return true;
  }
  return false;
}

static bool static_tryFindCaaIssuerDomain(const DnsRecordText_t* value, size_t* domain_start_out, size_t* domain_len_out)
{
  const char* bytes        = value->mp_bytes;
  size_t      byte_count   = value->m_byteCount;
  size_t      domain_start = static_findCaaSpaceEnd(bytes, byte_count, 0);
  size_t      i            = domain_start;
  if (i < byte_count && bytes[i] != ';')
  {
    for (;;)
    {
      size_t label_end = static_findCaaTokenEnd(bytes, byte_count, i, ". \t;");
      if (!validate_letterDigitHyphenLabel(bytes + i, label_end - i))
        return false;
      i = label_end;
      if (i == byte_count || bytes[i] != '.')
        break;
      i++;
    }
  }
  size_t domain_len = i - domain_start;

  i = static_findCaaSpaceEnd(bytes, byte_count, i);
  if (i < byte_count && (bytes[i] != ';' || !static_isCaaParameterListWellFormed(bytes, byte_count, i + 1)))
    return false;

  *domain_start_out = domain_start;
  *domain_len_out   = domain_len;
  return true;
}

static bool static_isCaaParameterListWellFormed(const char* bytes, size_t byte_count, size_t start)
{
  size_t i = static_findCaaSpaceEnd(bytes, byte_count, start);
  if (i == byte_count)
    return true;

  for (;;)
  {
    size_t tag_end = static_findCaaTokenEnd(bytes, byte_count, i, "= \t;");
    if (!validate_letterDigitHyphenLabel(bytes + i, tag_end - i))
      return false;

    i = static_findCaaSpaceEnd(bytes, byte_count, tag_end);
    if (i == byte_count || bytes[i] != '=')
      return false;

    i = static_findCaaSpaceEnd(bytes, byte_count, i + 1);
    while (i < byte_count && static_isCaaParameterValueByte(bytes[i]))
      i++;

    i = static_findCaaSpaceEnd(bytes, byte_count, i);
    if (i == byte_count)
      return true;
    if (bytes[i] != ';')
      return false;

    i = static_findCaaSpaceEnd(bytes, byte_count, i + 1);
    if (i == byte_count)
      return false;
  }
}

static bool static_isCaaParameterValueByte(char byte)
{
  unsigned char value_byte = (unsigned char)byte;
  return (value_byte >= 0x21 && value_byte <= 0x3A) || (value_byte >= 0x3C && value_byte <= 0x7E);
}

static size_t static_findCaaTokenEnd(const char* bytes, size_t byte_count, size_t start, const char* stop_bytes)
{
  size_t stop_byte_count = strlen(stop_bytes);
  size_t i               = start;
  while (i < byte_count && memchr(stop_bytes, bytes[i], stop_byte_count) == NULL)
    i++;
  return i;
}

static size_t static_findCaaSpaceEnd(const char* bytes, size_t byte_count, size_t start)
{
  size_t i = start;
  while (i < byte_count && (bytes[i] == ' ' || bytes[i] == '\t'))
    i++;
  return i;
}

static WatchlistDomainScanOutcome_t static_scanCtDomain(PGconn* conn, const WatchlistDomainScanClaim_t* claim)
{
  DbCtScanRecord_t scan = { .mp_domain = claim->ma_domain, .mp_claimedUntil = claim->ma_claimedUntil };
  WatchlistDomainScanValue_t value;
  memset(&value, 0, sizeof(value));
  WatchlistDomainScanOutcome_t outcome = WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED;

  const char* registered_domain = validate_publicDnsName(claim->ma_domain) ? etld_findPlusOne(claim->ma_domain) : NULL;
  if (registered_domain != NULL
      && certspotter_hasApiKey()
      && static_countCaaNames(claim->ma_domain, registered_domain) <= WATCHLIST_CERT_SEARCH_CAA_MAX_NAME_COUNT)
  {
    unsigned int hold_seconds = 0;
    if (!quota_dbTryReadHoldRemainingSeconds(conn, CERTSPOTTER_HOLD_NAME, &hold_seconds))
      return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;

    if (hold_seconds > 0)
      scan.m_retryAfterSeconds = watchlist_domain_scan_clampDeferSeconds(hold_seconds);
    else
    {
      CertSpotterCertificateList_t list;
      unsigned int retry_after_seconds = 0;
      switch (certspotter_lookupCertificates(conn, &WATCHLIST_CERT_SEARCH_HOURLY_QUOTA_RULE, claim->ma_domain, &list, &retry_after_seconds))
      {
        case CERTSPOTTER_OK:
          static_judgeCertIssuers(claim->ma_domain, registered_domain, &list, &value);
          scan.mp_certIssuersValue = watchlist_domain_scan_valueOrNull(&value);
          break;
        case CERTSPOTTER_QUOTA_EXHAUSTED:
          scan.m_retryAfterSeconds = watchlist_domain_scan_clampDeferSeconds(quota_windowRemainingSeconds(&WATCHLIST_CERT_SEARCH_HOURLY_QUOTA_RULE, time(NULL)));
          outcome = WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED;
          break;
        case CERTSPOTTER_RATE_LIMITED:
          quota_dbSetHold(conn, CERTSPOTTER_HOLD_NAME, retry_after_seconds);
          scan.m_retryAfterSeconds = watchlist_domain_scan_clampDeferSeconds(retry_after_seconds);
          break;
        case CERTSPOTTER_DB_ERROR:
          return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
        case CERTSPOTTER_UPSTREAM_ERROR:
        case CERTSPOTTER_NO_API_KEY:
        case CERTSPOTTER_INVALID_NAME:
          break;
      }
    }
  }

  if (db_recordCtScan(conn, &scan) != DB_OK)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;

  return outcome;
}

static void static_judgeCertIssuers(const char* host, const char* registered_domain, const CertSpotterCertificateList_t* list, WatchlistDomainScanValue_t* value)
{
  if (!list->m_isComplete || list->m_isIssuerDropped)
    return;

  DnsQuestion_t questions[WATCHLIST_CERT_SEARCH_CAA_MAX_NAME_COUNT];
  int question_count = 0;
  for (const char* name = host; name != registered_domain; name = strchr(name, '.') + 1)
    questions[question_count++] = (DnsQuestion_t){ .mp_domainName = name, .m_type = DNS_RECORD_TYPE_CAA };
  questions[question_count++] = (DnsQuestion_t){ .mp_domainName = registered_domain, .m_type = DNS_RECORD_TYPE_CAA };

  DnsAnswer_t answers[WATCHLIST_CERT_SEARCH_CAA_MAX_NAME_COUNT];
  dns_askQuestions(questions, question_count, DNS_LOOKUP_DEADLINE_MS, answers);

  const DnsAnswer_t* host_set     = NULL;
  const DnsAnswer_t* wildcard_set = NULL;
  bool is_host_set_known     = static_tryFindFirstAnswerWithCaaRecords(answers, 0, question_count, &host_set);
  bool is_wildcard_set_known = static_tryFindFirstAnswerWithCaaRecords(answers, 1, question_count, &wildcard_set);
  bool needs_host_set        = false;
  bool needs_wildcard_set    = false;
  for (int i = 0; i < list->m_issuerCount; i++)
  {
    needs_host_set     = needs_host_set     || watchlist_cert_search_isHostCaaSetNeeded(&list->ma_issuers[i]);
    needs_wildcard_set = needs_wildcard_set || watchlist_cert_search_isWildcardCaaSetNeeded(&list->ma_issuers[i]);
  }

  if ((is_host_set_known || !needs_host_set) && (is_wildcard_set_known || !needs_wildcard_set))
    value->m_hasValue = watchlist_cert_search_tryWriteCertIssuers(list, host_set, wildcard_set, &value->m_value);
  
  for (int i = 0; i < question_count; i++)
    dns_answerFree(&answers[i]);
}

static bool static_tryFindFirstAnswerWithCaaRecords(const DnsAnswer_t* answers, int first_index, int answer_count, const DnsAnswer_t** set_out)
{
  *set_out = NULL;
  for (int i = first_index; i < answer_count; i++)
  {
    if (answers[i].m_status == DNS_ANSWER_OK && answers[i].m_recordCount > 0)
    {
      *set_out = &answers[i];
      return true;
    }
    if (answers[i].m_status != DNS_ANSWER_OK && answers[i].m_status != DNS_ANSWER_NXDOMAIN)
      return false;
  }
  return true;
}

static int static_countCaaNames(const char* host, const char* registered_domain)
{
  int name_count = 1;
  for (const char* name = host; name != registered_domain; name = strchr(name, '.') + 1)
    name_count++;
  return name_count;
}
