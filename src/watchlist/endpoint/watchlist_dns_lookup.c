#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "watchlist_dns_lookup.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/watchlist_domain_scan.h"
#include "db.h"
#include "dns.h"
#include "emailcheck.h"
#include "ipguard.h"
#include "quota.h"
#include "usagelog.h"
#include "validate.h"

static const QuotaRule_t WATCHLIST_DNS_LOOKUP_DAILY_QUOTA_RULE = { "domain_scan_dns", 86400, 200000 };

static int64_t g_dnsCapLineDay = -1;

enum {
  WATCHLIST_DNS_LOOKUP_QUESTION_NS = 0,
  WATCHLIST_DNS_LOOKUP_QUESTION_MX,
  WATCHLIST_DNS_LOOKUP_QUESTION_A,
  WATCHLIST_DNS_LOOKUP_QUESTION_AAAA,
  WATCHLIST_DNS_LOOKUP_QUESTION_COUNT
};
_Static_assert(WATCHLIST_DNS_LOOKUP_QUESTION_COUNT == WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT, "watchlist_dns_lookup_tryWriteDnsPresence reads every answer of the first round");

#define WATCHLIST_DNS_LOOKUP_EMAIL_CHECK_IDS_SIZE (EMAILCHECK_KIND_COUNT * (EMAILCHECK_KIND_ID_MAX_LEN + 1))

typedef struct {
  WatchlistDomainScanValue_t m_dnsPresenceValue;
  WatchlistDomainScanValue_t m_nsValue;
  WatchlistDomainScanValue_t m_mxValue;
  WatchlistDomainScanValue_t m_ipAddressReachabilityValue;
  WatchlistDomainScanValue_t m_cnameTakeoverValue;
  WatchlistDomainScanValue_t m_emailAuthValue;
  char                       ma_hostingIpAddresses[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  int                        m_questionCount;
} WATCHLISTDNSLOOKUPScanValues_t;

static bool                         static_tryReadRecordCount   (const DnsAnswer_t* answer, int* record_count_out);
static WatchlistDomainLine_t        static_domainNameLine       (const char* prefix, size_t prefix_len, const char* domain_name, size_t domain_name_len);
static size_t                       static_writeMxPrefix        (uint16_t priority, char* prefix_out);
static WatchlistDomainScanOutcome_t static_scanDnsDomain        (PGconn* conn, const WatchlistDomainScanClaim_t* claim);
static void                         static_readDnsValues        (const WatchlistDomainScanClaim_t* claim, WATCHLISTDNSLOOKUPScanValues_t* values);
static void                         static_readEmailAuthValue   (const char* domain, WATCHLISTDNSLOOKUPScanValues_t* values);
static bool                         static_tryJoinEmailCheckIds (char* ids_out, size_t ids_size);
static const char*                  static_textOrNull           (const char* text);

bool watchlist_dns_lookup_scanNextDomains(PGconn* conn)
{
  const WatchlistDomainScanLane_t lane = {
    .mp_laneName    = DB_DOMAIN_WATCH_LANE_DNS,
    .m_scanFunction = static_scanDnsDomain,
    .mp_capLineDay  = &g_dnsCapLineDay,
    .m_capEvent     = USAGELOG_EVENT_DNS_SCAN_CAP_REACHED,
  };

  return watchlist_domain_scan_scanNextLaneDomains(conn, &lane);
}

#define WATCHLIST_DNS_LOOKUP_MAX_LINE_COUNT (DNS_ANSWER_MAX_RECORD_COUNT + 1)

#define WATCHLIST_DNS_LOOKUP_MX_PREFIX_SIZE 6

bool watchlist_dns_lookup_tryWriteDnsPresence(const DnsAnswer_t* answers, DnsLookupStatus_t takeover_status, const DNSTAKEOVERCHECKRecord_t* takeover_record, WatchlistDomainValue_t* value_out)
{
  assert(answers         != NULL);
  assert(takeover_record != NULL);
  assert(value_out       != NULL);

  if (takeover_status == DNS_LOOKUP_OK && takeover_record->m_hostnameChainLength > 0)
    return watchlist_domain_tryWriteState("found", value_out);

  bool is_all_nxdomain = true;
  for (int i = 0; i < WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT; i++)
  {
    if (answers[i].m_status == DNS_ANSWER_OK || answers[i].m_status == DNS_ANSWER_NOT_PUBLIC_NAME)
      return watchlist_domain_tryWriteState("found", value_out);
    else if (answers[i].m_status != DNS_ANSWER_NXDOMAIN)
      is_all_nxdomain = false;
  }

  if (!is_all_nxdomain || takeover_status != DNS_LOOKUP_NOT_FOUND)
    return false;

  return watchlist_domain_tryWriteState("not_found", value_out);
}

bool watchlist_dns_lookup_tryWriteNsNames(const DnsAnswer_t* ns_answer, WatchlistDomainValue_t* value_out)
{
  assert(ns_answer != NULL);
  assert(value_out != NULL);

  int record_count = 0;
  if (!static_tryReadRecordCount(ns_answer, &record_count))
    return false;

  WatchlistDomainLine_t lines[WATCHLIST_DNS_LOOKUP_MAX_LINE_COUNT];
  for (int i = 0; i < record_count; i++)
    lines[i] = static_domainNameLine("", 0, ns_answer->mp_texts[i].mp_bytes, ns_answer->mp_texts[i].m_byteCount);

  return watchlist_domain_tryWriteLines(lines, record_count, value_out);
}

bool watchlist_dns_lookup_tryWriteMxRecords(const DnsAnswer_t* mx_answer, WatchlistDomainValue_t* value_out)
{
  assert(mx_answer != NULL);
  assert(value_out != NULL);

  int record_count = 0;
  if (!static_tryReadRecordCount(mx_answer, &record_count))
    return false;

  WatchlistDomainLine_t lines[WATCHLIST_DNS_LOOKUP_MAX_LINE_COUNT];
  char prefixes[DNS_ANSWER_MAX_RECORD_COUNT][WATCHLIST_DNS_LOOKUP_MX_PREFIX_SIZE];
  for (int i = 0; i < record_count; i++)
  {
    const DnsMxRecord_t* record = &mx_answer->mp_mxRecords[i];
    size_t prefix_len = static_writeMxPrefix(record->m_priority, prefixes[i]);
    lines[i] = static_domainNameLine(prefixes[i], prefix_len, record->mp_hostname, strlen(record->mp_hostname));
  }

  int line_count = record_count;
  if (mx_answer->m_status == DNS_ANSWER_OK && mx_answer->m_hasNullMx)
  {
    lines[line_count] = static_domainNameLine("null", strlen("null"), "", 0);
    line_count++;
  }
  return watchlist_domain_tryWriteLines(lines, line_count, value_out);
}

bool watchlist_dns_lookup_tryWriteIpAddressReachability(const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer, WatchlistDomainValue_t* value_out)
{
  assert(a_answer    != NULL);
  assert(aaaa_answer != NULL);
  assert(value_out   != NULL);

  if (a_answer->m_status == DNS_ANSWER_NOT_PUBLIC_NAME || aaaa_answer->m_status == DNS_ANSWER_NOT_PUBLIC_NAME)
    return watchlist_domain_tryWriteState("not_public", value_out);
  if ((a_answer->m_status    != DNS_ANSWER_OK && a_answer->m_status    != DNS_ANSWER_NXDOMAIN) ||
      (aaaa_answer->m_status != DNS_ANSWER_OK && aaaa_answer->m_status != DNS_ANSWER_NXDOMAIN))
    return false;

  const DnsAnswer_t* answers[2] = { a_answer, aaaa_answer };
  int address_count = 0;
  for (int i = 0; i < 2; i++)
  {
    for (int j = 0; j < answers[i]->m_recordCount; j++)
    {
      if (!ipguard_isGloballyReachableIp(answers[i]->mp_texts[j].mp_bytes))
        return watchlist_domain_tryWriteState("not_public", value_out);

      address_count++;
    }
  }
  return watchlist_domain_tryWriteState(address_count == 0 ? "empty" : "public", value_out);
}

void watchlist_dns_lookup_writeHostingIpAddresses(const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer, char* addresses_out, size_t addresses_size)
{
  assert(a_answer       != NULL);
  assert(aaaa_answer    != NULL);
  assert(addresses_out  != NULL);
  assert(addresses_size >  0);

  addresses_out[0] = '\0';
  if ((a_answer->m_status != DNS_ANSWER_OK && a_answer->m_status != DNS_ANSWER_NXDOMAIN)      ||
      (aaaa_answer->m_status != DNS_ANSWER_OK && aaaa_answer->m_status != DNS_ANSWER_NXDOMAIN))
    return;

  const DnsAnswer_t* answers[2] = { a_answer, aaaa_answer };
  size_t addresses_len = 0;
  for (int i = 0; i < 2; i++)
  {
    for (int j = 0; j < answers[i]->m_recordCount; j++)
    {
      const char* address = answers[i]->mp_texts[j].mp_bytes;
      if (!ipguard_isGloballyReachableIp(address))
      {
        addresses_out[0] = '\0';
        return;
      }

      size_t left_size = addresses_size - addresses_len;
      int    piece_len = snprintf(addresses_out + addresses_len, left_size, "%s%s", addresses_len > 0 ? "," : "", address);
      if (piece_len < 0 || (size_t)piece_len >= left_size)
      {
        addresses_out[0] = '\0';
        return;
      }
      addresses_len += (size_t)piece_len;
    }
  }
}

bool watchlist_dns_lookup_tryWriteCnameTakeover(DnsLookupStatus_t status, const DNSTAKEOVERCHECKRecord_t* record, WatchlistDomainValue_t* value_out)
{
  assert(record    != NULL);
  assert(value_out != NULL);

  if (status != DNS_LOOKUP_OK)
    return false;
  if (record->m_hostnameChainLength <= 0 || record->m_isTargetFound)
    return watchlist_domain_tryWriteState("none", value_out);
  if (record->mp_matchedSuffix == NULL)
    return watchlist_domain_tryWriteState("vulnerable", value_out);

  char text[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  int text_len = snprintf(text, sizeof(text), "vulnerable %s", record->mp_matchedSuffix->mp_serviceName);
  if (text_len < 0 || (size_t)text_len >= sizeof(text))
    return false;

  return watchlist_domain_tryWriteState(text, value_out);
}

bool watchlist_dns_lookup_tryWriteEmailCheckResults(const EmailCheckItem_t* checks, int check_count, WatchlistDomainValue_t* value_out)
{
  assert(checks != NULL || check_count == 0);
  assert(check_count >= 0);
  assert(value_out != NULL);

  static const char RESULT_LETTERS[] = {
    [EMAILCHECK_RESULT_PASS] = 'p',
    [EMAILCHECK_RESULT_WARN] = 'w',
    [EMAILCHECK_RESULT_FAIL] = 'f',
  };
  char check_results[EMAILCHECK_KIND_COUNT + 1];
  memset(check_results, '-', EMAILCHECK_KIND_COUNT);
  check_results[EMAILCHECK_KIND_COUNT] = '\0';
  for (int i = 0; i < check_count; i++)
  {
    assert((int)checks[i].m_kind >= 0 && (int)checks[i].m_kind < EMAILCHECK_KIND_COUNT);
    assert((int)checks[i].m_result >= 0 && (size_t)checks[i].m_result < sizeof(RESULT_LETTERS));
    check_results[checks[i].m_kind] = RESULT_LETTERS[checks[i].m_result];
  }

  return watchlist_domain_tryWriteState(check_results, value_out);
}

static bool static_tryReadRecordCount(const DnsAnswer_t* answer, int* record_count_out)
{
  if (answer->m_status == DNS_ANSWER_NXDOMAIN)
  {
    *record_count_out = 0;
    return true;
  }
  else if (answer->m_status != DNS_ANSWER_OK || answer->m_recordCount < 0 || answer->m_recordCount > DNS_ANSWER_MAX_RECORD_COUNT)
    return false;

  *record_count_out = answer->m_recordCount;
  return true;
}

static WatchlistDomainLine_t static_domainNameLine(const char* prefix, size_t prefix_len, const char* domain_name, size_t domain_name_len)
{
  if (domain_name_len > 0 && domain_name[domain_name_len - 1] == '.')
    domain_name_len--;
  WatchlistDomainLine_t line = { .mp_prefix = prefix, .m_prefixLen = prefix_len, .mp_domainName = domain_name, .m_domainNameLen = domain_name_len };
  return line;
}

static size_t static_writeMxPrefix(uint16_t priority, char* prefix_out)
{
  char   reversed_digits[WATCHLIST_DNS_LOOKUP_MX_PREFIX_SIZE - 1];
  size_t digit_count = 0;
  do
  {
    reversed_digits[digit_count] = (char)('0' + priority % 10);
    digit_count++;
    priority /= 10;
  } while (priority > 0);

  for (size_t i = 0; i < digit_count; i++)
    prefix_out[i] = reversed_digits[digit_count - 1 - i];
  prefix_out[digit_count] = ' ';
  return digit_count + 1;
}

static WatchlistDomainScanOutcome_t static_scanDnsDomain(PGconn* conn, const WatchlistDomainScanClaim_t* claim)
{
  QuotaStatus_t quota_status = quota_dbReserve(conn, &WATCHLIST_DNS_LOOKUP_DAILY_QUOTA_RULE);
  if (quota_status == QUOTA_EXHAUSTED)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED;
  else if (quota_status != QUOTA_GRANTED)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;

  WATCHLISTDNSLOOKUPScanValues_t values;
  static_readDnsValues(claim, &values);
  char email_check_ids[WATCHLIST_DNS_LOOKUP_EMAIL_CHECK_IDS_SIZE];
  bool has_email_check_ids = static_tryJoinEmailCheckIds(email_check_ids, sizeof(email_check_ids));

  const DbDnsScanRecord_t scan = {
    .mp_domain                     = claim->ma_domain,
    .mp_claimedUntil               = claim->ma_claimedUntil,
    .mp_dnsPresenceValue           = watchlist_domain_scan_valueOrNull(&values.m_dnsPresenceValue),
    .mp_nsValue                    = watchlist_domain_scan_valueOrNull(&values.m_nsValue),
    .mp_mxValue                    = watchlist_domain_scan_valueOrNull(&values.m_mxValue),
    .mp_ipAddressReachabilityValue = watchlist_domain_scan_valueOrNull(&values.m_ipAddressReachabilityValue),
    .mp_cnameTakeoverValue         = watchlist_domain_scan_valueOrNull(&values.m_cnameTakeoverValue),
    .mp_emailAuthValue             = has_email_check_ids ? watchlist_domain_scan_valueOrNull(&values.m_emailAuthValue) : NULL,
    .mp_emailCheckIds              = static_textOrNull(email_check_ids),
    .mp_hostingIpAddresses         = static_textOrNull(values.ma_hostingIpAddresses),
    .m_questionCount               = values.m_questionCount,
  };

  if (db_recordDnsScan(conn, &scan) != DB_OK)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
  return WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED;
}

static void static_readDnsValues(const WatchlistDomainScanClaim_t* claim, WATCHLISTDNSLOOKUPScanValues_t* values)
{
  memset(values, 0, sizeof(*values));
  if (!validate_publicDnsName(claim->ma_domain))
    return;
  dns_resetQuestionCount();

  const DnsQuestion_t questions[WATCHLIST_DNS_LOOKUP_QUESTION_COUNT] = {
    [WATCHLIST_DNS_LOOKUP_QUESTION_NS]   = { claim->ma_domain, DNS_RECORD_TYPE_NS   },
    [WATCHLIST_DNS_LOOKUP_QUESTION_MX]   = { claim->ma_domain, DNS_RECORD_TYPE_MX   },
    [WATCHLIST_DNS_LOOKUP_QUESTION_A]    = { claim->ma_domain, DNS_RECORD_TYPE_A    },
    [WATCHLIST_DNS_LOOKUP_QUESTION_AAAA] = { claim->ma_domain, DNS_RECORD_TYPE_AAAA },
  };
  DnsAnswer_t answers[WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT];
  dns_askQuestions(questions, WATCHLIST_DNS_LOOKUP_QUESTION_COUNT, DNS_LOOKUP_DEADLINE_MS, answers);

  values->m_nsValue.m_hasValue                    = watchlist_dns_lookup_tryWriteNsNames(&answers[WATCHLIST_DNS_LOOKUP_QUESTION_NS], &values->m_nsValue.m_value);
  values->m_mxValue.m_hasValue                    = watchlist_dns_lookup_tryWriteMxRecords(&answers[WATCHLIST_DNS_LOOKUP_QUESTION_MX], &values->m_mxValue.m_value);
  values->m_ipAddressReachabilityValue.m_hasValue = watchlist_dns_lookup_tryWriteIpAddressReachability(&answers[WATCHLIST_DNS_LOOKUP_QUESTION_A], &answers[WATCHLIST_DNS_LOOKUP_QUESTION_AAAA], &values->m_ipAddressReachabilityValue.m_value);
  watchlist_dns_lookup_writeHostingIpAddresses(&answers[WATCHLIST_DNS_LOOKUP_QUESTION_A], &answers[WATCHLIST_DNS_LOOKUP_QUESTION_AAAA], values->ma_hostingIpAddresses, sizeof(values->ma_hostingIpAddresses));

  DNSTAKEOVERCHECKRecord_t takeover_record;
  DnsLookupStatus_t takeover_status = dns_checkTakeover(claim->ma_domain, &takeover_record);
  values->m_cnameTakeoverValue.m_hasValue = watchlist_dns_lookup_tryWriteCnameTakeover(takeover_status, &takeover_record, &values->m_cnameTakeoverValue.m_value);
  values->m_dnsPresenceValue.m_hasValue   = watchlist_dns_lookup_tryWriteDnsPresence(answers, takeover_status, &takeover_record, &values->m_dnsPresenceValue.m_value);
  for (int i = 0; i < WATCHLIST_DNS_LOOKUP_DNS_PRESENCE_ANSWER_COUNT; i++)
    dns_answerFree(&answers[i]);

  static_readEmailAuthValue(claim->ma_domain, values);
  values->m_questionCount = dns_readQuestionCount();
}

static void static_readEmailAuthValue(const char* domain, WATCHLISTDNSLOOKUPScanValues_t* values)
{
  EMAILAUTHCHECKRecord_t record;
  if (emailcheck_checkDomain(domain, NULL, &record) == DNS_LOOKUP_OK)
    values->m_emailAuthValue.m_hasValue = watchlist_dns_lookup_tryWriteEmailCheckResults(record.ma_checks, record.m_checkCount, &values->m_emailAuthValue.m_value);
  emailcheck_EMAILAUTHCHECKRecordFree(&record);
}

static bool static_tryJoinEmailCheckIds(char* ids_out, size_t ids_size)
{
  ids_out[0] = '\0';
  size_t ids_len = 0;
  for (int kind = 0; kind < EMAILCHECK_KIND_COUNT; kind++)
  {
    const char* id = emailcheck_kindId((EmailCheckKind_t)kind);
    int written = id != NULL ? snprintf(ids_out + ids_len, ids_size - ids_len, "%s%s", kind > 0 ? "," : "", id) : -1;
    if (written < 0 || (size_t)written >= ids_size - ids_len)
    {
      ids_out[0] = '\0';
      return false;
    }
    ids_len += (size_t)written;
  }
  return true;
}

static const char* static_textOrNull(const char* text)
{
  assert(text != NULL);

  return text[0] != '\0' ? text : NULL;
}
