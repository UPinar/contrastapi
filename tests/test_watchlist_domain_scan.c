#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "unity/unity.h"
#include "watchlist/endpoint/watchlist_cert_search.h"
#include "watchlist/endpoint/watchlist_dns_lookup.h"
#include "watchlist/watchlist_domain_scan.h"
#include "watchlist/endpoint/watchlist_headers_check.h"
#include "watchlist/endpoint/watchlist_ssl_check.h"
#include "watchlist/endpoint/watchlist_whois_lookup.h"
#include "db.h"
#include "dns.h"
#include "watchlist/watchlist_domain.h"
#include "emailcheck.h"
#include "external/rdap.h"
#include "quota.h"
#include "registryask.h"
#include "tlsprobe.h"
#include "usagelog.h"
#include "header_check.h"
#include "header_fetch.h"
#include "http.h"
#include "throttle.h"
#include "external/certspotter.h"
#include "robotstxt.h"
#include <stdlib.h>

#define FAKE_START_MS 1000000

static int64_t g_nowMs;
static int64_t g_dnsAskAdvanceMs;

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

static char g_fakeConnection;
#define FAKE_CONN ((PGconn*)&g_fakeConnection)

#define FAKE_RECORD_MAX 4

#define FAKE_CLAIM_BATCH_MAX 4

typedef struct {
  DbStatus_t                 m_status;
  int                        m_claimCount;
  WatchlistDomainScanClaim_t ma_claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
} FakeClaimBatch_t;

#define FAKE_CLAIM_CALL_MAX 8

static FakeClaimBatch_t g_claimBatches[FAKE_CLAIM_BATCH_MAX];
static int              g_claimBatchCount;
static int              g_claimCallCount;
static bool             g_isEveryClaimOnFakeConn;
static char             g_claimLaneNames[FAKE_CLAIM_CALL_MAX][16];

DbStatus_t __wrap_db_claimDomainLaneScans(PGconn* conn, const char* lane_name, WatchlistDomainScanClaim_t* claims_out, int* claim_count_out)
{
  int call_index = g_claimCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_CLAIM_CALL_MAX);
  g_isEveryClaimOnFakeConn = g_isEveryClaimOnFakeConn && conn == FAKE_CONN;
  snprintf(g_claimLaneNames[call_index], sizeof(g_claimLaneNames[call_index]), "%s", lane_name);

  *claim_count_out = 0;
  if (call_index >= g_claimBatchCount)
    return DB_OK;

  const FakeClaimBatch_t* batch = &g_claimBatches[call_index];
  TEST_ASSERT_TRUE(batch->m_claimCount <= DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT);
  if (batch->m_status != DB_OK)
    return batch->m_status;
  memcpy(claims_out, batch->ma_claims, sizeof(batch->ma_claims[0]) * (size_t)batch->m_claimCount);
  *claim_count_out = batch->m_claimCount;
  return DB_OK;
}

static void static_noteCall(char letter);
static void static_fillCaaAnswer(const char* name, DnsAnswer_t* answer);

static QuotaStatus_t g_quotaStatuses[4];
static int           g_quotaStatusCount;
static int           g_quotaCallCount;
static QuotaRule_t   g_lastQuotaRule;
static bool          g_isEveryQuotaOnFakeConn;

QuotaStatus_t __wrap_quota_dbReserve(PGconn* conn, const QuotaRule_t* rule)
{
  int call_index = g_quotaCallCount++;
  static_noteCall('Q');
  g_lastQuotaRule = *rule;
  g_isEveryQuotaOnFakeConn = g_isEveryQuotaOnFakeConn && conn == FAKE_CONN;
  return call_index < g_quotaStatusCount ? g_quotaStatuses[call_index] : QUOTA_GRANTED;
}

#define FAKE_DNS_KIND_COUNT 6
enum { DNS_KIND_DNS_PRESENCE = 0, DNS_KIND_NS, DNS_KIND_MX, DNS_KIND_IP_ADDRESS_REACHABILITY, DNS_KIND_CNAME_TAKEOVER, DNS_KIND_EMAIL_AUTH };

typedef struct {
  char ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
  bool ma_hasValue[FAKE_DNS_KIND_COUNT];
  char ma_valueTexts[FAKE_DNS_KIND_COUNT][WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  char ma_valueSha256s[FAKE_DNS_KIND_COUNT][WATCHLIST_DOMAIN_SHA256_HEX_LEN + 1];
  bool m_hasEmailCheckIds;
  char ma_emailCheckIds[512];
  bool m_hasHostingIpAddresses;
  char ma_hostingIpAddresses[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  int  m_questionCount;
} RecordedDnsScan_t;

static RecordedDnsScan_t g_dnsRecords[FAKE_RECORD_MAX];
static int               g_dnsRecordCallCount;
static DbStatus_t        g_dnsRecordStatus;
static bool              g_isEveryDnsRecordOnFakeConn;

DbStatus_t __wrap_db_recordDnsScan(PGconn* conn, const DbDnsScanRecord_t* scan)
{
  int call_index = g_dnsRecordCallCount++;
  g_isEveryDnsRecordOnFakeConn = g_isEveryDnsRecordOnFakeConn && conn == FAKE_CONN;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  TEST_ASSERT_NOT_NULL(scan->mp_domain);
  TEST_ASSERT_NOT_NULL(scan->mp_claimedUntil);

  RecordedDnsScan_t* recorded = &g_dnsRecords[call_index];
  memset(recorded, 0, sizeof(*recorded));
  snprintf(recorded->ma_domain, sizeof(recorded->ma_domain), "%s", scan->mp_domain);
  snprintf(recorded->ma_claimedUntil, sizeof(recorded->ma_claimedUntil), "%s", scan->mp_claimedUntil);

  const WatchlistDomainValue_t* values[FAKE_DNS_KIND_COUNT] = {
    scan->mp_dnsPresenceValue, scan->mp_nsValue, scan->mp_mxValue,
    scan->mp_ipAddressReachabilityValue, scan->mp_cnameTakeoverValue, scan->mp_emailAuthValue,
  };
  for (int kind = 0; kind < FAKE_DNS_KIND_COUNT; kind++)
  {
    recorded->ma_hasValue[kind] = values[kind] != NULL;
    if (values[kind] != NULL)
    {
      snprintf(recorded->ma_valueTexts[kind], sizeof(recorded->ma_valueTexts[kind]), "%s", values[kind]->ma_text);
      snprintf(recorded->ma_valueSha256s[kind], sizeof(recorded->ma_valueSha256s[kind]), "%s", values[kind]->ma_sha256Hex);
    }
  }
  recorded->m_hasEmailCheckIds = scan->mp_emailCheckIds != NULL;
  if (scan->mp_emailCheckIds != NULL)
    snprintf(recorded->ma_emailCheckIds, sizeof(recorded->ma_emailCheckIds), "%s", scan->mp_emailCheckIds);
  recorded->m_hasHostingIpAddresses = scan->mp_hostingIpAddresses != NULL;
  if (scan->mp_hostingIpAddresses != NULL)
    snprintf(recorded->ma_hostingIpAddresses, sizeof(recorded->ma_hostingIpAddresses), "%s", scan->mp_hostingIpAddresses);
  recorded->m_questionCount = scan->m_questionCount;

  return g_dnsRecordStatus;
}

typedef struct {
  DnsAnswerStatus_t m_status;
  int               m_recordCount;
  bool              m_hasNullMx;
} FakeDnsAnswer_t;

static char            g_nsName[]      = "ns1.example.net";
static DnsRecordText_t g_nsTexts[]     = { { g_nsName, sizeof(g_nsName) - 1 } };
static char            g_mxHost[]      = "mx.example.net";
static DnsMxRecord_t   g_mxRecords[]   = { { 10, g_mxHost } };
static char            g_aAddress[]    = "93.184.216.34";
static DnsRecordText_t g_aTexts[]      = { { g_aAddress, sizeof(g_aAddress) - 1 } };
static char            g_aaaaAddress[] = "2606:2800:220:1:248:1893:25c8:1946";
static DnsRecordText_t g_aaaaTexts[]   = { { g_aaaaAddress, sizeof(g_aaaaAddress) - 1 } };
static char            g_privateAddress[] = "10.0.0.7";
static DnsRecordText_t g_privateTexts[]   = { { g_privateAddress, sizeof(g_privateAddress) - 1 } };

static bool g_isAAddressPrivate;

static DnsRecordText_t* g_aTextsOverride;

static FakeDnsAnswer_t g_dnsAnswers[DNS_RECORD_TYPE_COUNT];

typedef struct {
  int             m_questionCount;
  int             m_deadlineMs;
  char            ma_names[DNS_MAX_QUESTION_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsRecordType_t ma_types[DNS_MAX_QUESTION_COUNT];
} DnsAskCall_t;

static DnsAskCall_t g_dnsAskCalls[FAKE_RECORD_MAX];
static int          g_dnsAskCallCount;
static int          g_answerFreeCount;
static int          g_openAnswerCount;

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  int call_index = g_dnsAskCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  TEST_ASSERT_TRUE(question_count > 0 && question_count <= DNS_MAX_QUESTION_COUNT);
  DnsAskCall_t* call = &g_dnsAskCalls[call_index];
  call->m_questionCount = question_count;
  call->m_deadlineMs    = deadline_ms;
  for (int i = 0; i < question_count; i++)
  {
    snprintf(call->ma_names[i], sizeof(call->ma_names[i]), "%s", questions[i].mp_domainName);
    call->ma_types[i] = questions[i].m_type;

    const FakeDnsAnswer_t* fake = &g_dnsAnswers[questions[i].m_type];
    DnsAnswer_t* answer = &answers_out[i];
    memset(answer, 0, sizeof(*answer));
    if (questions[i].m_type == DNS_RECORD_TYPE_CAA)
    {
      static_fillCaaAnswer(questions[i].mp_domainName, answer);
      g_openAnswerCount++;
      continue;
    }
    answer->m_status      = fake->m_status;
    answer->m_recordCount = fake->m_recordCount;
    answer->m_hasNullMx   = fake->m_hasNullMx;
    if (fake->m_recordCount > 0)
    {
      if (questions[i].m_type == DNS_RECORD_TYPE_NS)
        answer->mp_texts = g_nsTexts;
      else if (questions[i].m_type == DNS_RECORD_TYPE_MX)
        answer->mp_mxRecords = g_mxRecords;
      else if (questions[i].m_type == DNS_RECORD_TYPE_A)
        answer->mp_texts = g_aTextsOverride != NULL ? g_aTextsOverride : g_isAAddressPrivate ? g_privateTexts : g_aTexts;
      else if (questions[i].m_type == DNS_RECORD_TYPE_AAAA)
        answer->mp_texts = g_aaaaTexts;
    }
    g_openAnswerCount++;
  }
  g_nowMs += g_dnsAskAdvanceMs;
}

void __wrap_dns_answerFree(DnsAnswer_t* answer)
{
  g_answerFreeCount++;
  g_openAnswerCount--;
  DnsAnswerStatus_t status = answer->m_status;
  memset(answer, 0, sizeof(*answer));
  answer->m_status = status;
}

static DnsLookupStatus_t   g_takeoverStatus;
static bool                g_hasTakeoverChain;
static const char*         g_takeoverLastName;
static const DnsTakeoverSuffix_t g_takeoverSuffix = { "Example Cloud", "cloud.example.net" };
static int                 g_takeoverCallCount;
static char                g_lastTakeoverHostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

DnsLookupStatus_t __wrap_dns_checkTakeover(const char* hostname, DNSTAKEOVERCHECKRecord_t* record_out)
{
  g_takeoverCallCount++;
  snprintf(g_lastTakeoverHostname, sizeof(g_lastTakeoverHostname), "%s", hostname);
  memset(record_out, 0, sizeof(*record_out));
  if (g_takeoverLastName != NULL)
  {
    record_out->m_hostnameChainLength = 2;
    snprintf(record_out->ma_hostnameChain[0], sizeof(record_out->ma_hostnameChain[0]), "%s", "alias.example.net");
    snprintf(record_out->ma_hostnameChain[1], sizeof(record_out->ma_hostnameChain[1]), "%s", g_takeoverLastName);
    record_out->m_isTargetFound = true;
  }
  else if (g_takeoverStatus == DNS_LOOKUP_OK && g_hasTakeoverChain)
  {
    record_out->m_hostnameChainLength = 1;
    snprintf(record_out->ma_hostnameChain[0], sizeof(record_out->ma_hostnameChain[0]), "%s", "shop.cloud.example.net");
    record_out->m_isTargetFound  = false;
    record_out->mp_matchedSuffix = &g_takeoverSuffix;
  }
  return g_takeoverStatus;
}

typedef struct {
  DnsLookupStatus_t         m_status;
  EmailCheckDkimKeyStatus_t m_dkimKeyStatus;
  int                       m_checkCount;
  EmailCheckItem_t          ma_checks[4];
} FakeEmailRun_t;

static const FakeEmailRun_t g_defaultEmailRun = {
  DNS_LOOKUP_OK, EMAILCHECK_DKIM_KEY_UNKNOWN,
  2, { { EMAILCHECK_KIND_SPF_RECORD, EMAILCHECK_RESULT_PASS }, { EMAILCHECK_KIND_MX, EMAILCHECK_RESULT_PASS } },
};

static FakeEmailRun_t g_emailRuns[4];
static int            g_emailRunCount;
static int            g_emailCallCount;
static int            g_emailFreeCount;
static int            g_openEmailRecordCount;
static char           g_emailDomains[4][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static bool           g_isEmailSelectorNull[4];

DnsLookupStatus_t __wrap_emailcheck_checkDomain(const char* domain, const char* dkim_selector, EMAILAUTHCHECKRecord_t* record_out)
{
  int call_index = g_emailCallCount++;
  TEST_ASSERT_TRUE(call_index < 4);
  snprintf(g_emailDomains[call_index], sizeof(g_emailDomains[call_index]), "%s", domain);
  g_isEmailSelectorNull[call_index] = dkim_selector == NULL;

  const FakeEmailRun_t* run = call_index < g_emailRunCount ? &g_emailRuns[call_index] : &g_defaultEmailRun;
  memset(record_out, 0, sizeof(*record_out));
  g_openEmailRecordCount++;
  if (run->m_status != DNS_LOOKUP_OK)
    return run->m_status;

  record_out->m_dkimKeyStatus = run->m_dkimKeyStatus;
  record_out->m_checkCount    = run->m_checkCount;
  memcpy(record_out->ma_checks, run->ma_checks, sizeof(run->ma_checks[0]) * (size_t)run->m_checkCount);
  return DNS_LOOKUP_OK;
}

void __wrap_emailcheck_EMAILAUTHCHECKRecordFree(EMAILAUTHCHECKRecord_t* record)
{
  g_emailFreeCount++;
  g_openEmailRecordCount--;
  memset(record, 0, sizeof(*record));
}

static int g_missingKindId;

const char* __real_emailcheck_kindId(EmailCheckKind_t kind);

const char* __wrap_emailcheck_kindId(EmailCheckKind_t kind)
{
  return (int)kind == g_missingKindId ? NULL : __real_emailcheck_kindId(kind);
}

typedef struct {
  int m_askCallCount;
  int m_takeoverCallCount;
  int m_emailCallCount;
} QuestionCountCall_t;

static int                 g_questionCounts[FAKE_RECORD_MAX];
static QuestionCountCall_t g_questionCountResets[FAKE_RECORD_MAX];
static int                 g_questionCountResetCount;
static QuestionCountCall_t g_questionCountReads[FAKE_RECORD_MAX];
static int                 g_questionCountReadCount;

static QuestionCountCall_t static_questionCountCall(void)
{
  QuestionCountCall_t call = { g_dnsAskCallCount, g_takeoverCallCount, g_emailCallCount };
  return call;
}

void __wrap_dns_resetQuestionCount(void)
{
  int call_index = g_questionCountResetCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  g_questionCountResets[call_index] = static_questionCountCall();
}

int __wrap_dns_readQuestionCount(void)
{
  int call_index = g_questionCountReadCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  g_questionCountReads[call_index] = static_questionCountCall();
  return g_questionCounts[call_index];
}

static void static_resetDnsFakes(void)
{
  g_dnsAskAdvanceMs            = 0;
  memset(g_dnsRecords, 0, sizeof(g_dnsRecords));
  g_dnsRecordCallCount         = 0;
  g_dnsRecordStatus            = DB_OK;
  g_isEveryDnsRecordOnFakeConn = true;
  memset(g_dnsAnswers, 0, sizeof(g_dnsAnswers));
  g_dnsAnswers[DNS_RECORD_TYPE_NS]   = (FakeDnsAnswer_t){ DNS_ANSWER_OK, 1, false };
  g_dnsAnswers[DNS_RECORD_TYPE_MX]   = (FakeDnsAnswer_t){ DNS_ANSWER_OK, 0, false };
  g_dnsAnswers[DNS_RECORD_TYPE_A]    = (FakeDnsAnswer_t){ DNS_ANSWER_OK, 1, false };
  g_dnsAnswers[DNS_RECORD_TYPE_AAAA] = (FakeDnsAnswer_t){ DNS_ANSWER_OK, 0, false };
  memset(g_dnsAskCalls, 0, sizeof(g_dnsAskCalls));
  g_dnsAskCallCount            = 0;
  g_answerFreeCount            = 0;
  g_openAnswerCount            = 0;
  g_isAAddressPrivate          = false;
  g_aTextsOverride             = NULL;
  g_takeoverStatus             = DNS_LOOKUP_OK;
  g_hasTakeoverChain           = false;
  g_takeoverLastName           = NULL;
  g_takeoverCallCount          = 0;
  g_lastTakeoverHostname[0]    = '\0';
  memset(g_emailRuns, 0, sizeof(g_emailRuns));
  g_emailRunCount              = 0;
  g_emailCallCount             = 0;
  memset(g_isEmailSelectorNull, 0, sizeof(g_isEmailSelectorNull));
  g_missingKindId              = -1;
  g_emailFreeCount             = 0;
  g_openEmailRecordCount       = 0;
  memset(g_questionCounts, 0, sizeof(g_questionCounts));
  memset(g_questionCountResets, 0, sizeof(g_questionCountResets));
  g_questionCountResetCount    = 0;
  memset(g_questionCountReads, 0, sizeof(g_questionCountReads));
  g_questionCountReadCount     = 0;
}

#define FAKE_TLS_KIND_COUNT 4
enum { TLS_KIND_CERTIFICATE_EXPIRY = 0, TLS_KIND_CERTIFICATE_VALIDITY, TLS_KIND_CERTIFICATE_LISTING, TLS_KIND_TLS_PROTOCOL };

typedef struct {
  char ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
  bool ma_hasValue[FAKE_TLS_KIND_COUNT];
  char ma_valueTexts[FAKE_TLS_KIND_COUNT][WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  char ma_valueSha256s[FAKE_TLS_KIND_COUNT][WATCHLIST_DOMAIN_SHA256_HEX_LEN + 1];
} RecordedTlsScan_t;

static RecordedTlsScan_t g_tlsRecords[FAKE_RECORD_MAX];
static int               g_tlsRecordCallCount;
static DbStatus_t        g_tlsRecordStatus;
static bool              g_isEveryTlsRecordOnFakeConn;

DbStatus_t __wrap_db_recordTlsScan(PGconn* conn, const DbTlsScanRecord_t* scan)
{
  int call_index = g_tlsRecordCallCount++;
  g_isEveryTlsRecordOnFakeConn = g_isEveryTlsRecordOnFakeConn && conn == FAKE_CONN;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  TEST_ASSERT_NOT_NULL(scan->mp_domain);
  TEST_ASSERT_NOT_NULL(scan->mp_claimedUntil);

  RecordedTlsScan_t* recorded = &g_tlsRecords[call_index];
  memset(recorded, 0, sizeof(*recorded));
  snprintf(recorded->ma_domain, sizeof(recorded->ma_domain), "%s", scan->mp_domain);
  snprintf(recorded->ma_claimedUntil, sizeof(recorded->ma_claimedUntil), "%s", scan->mp_claimedUntil);
  const WatchlistDomainValue_t* values[FAKE_TLS_KIND_COUNT] = {
    scan->mp_certificateExpiryValue, scan->mp_certificateValidityValue,
    scan->mp_certificateListingValue, scan->mp_tlsProtocolValue,
  };
  for (int kind = 0; kind < FAKE_TLS_KIND_COUNT; kind++)
  {
    recorded->ma_hasValue[kind] = values[kind] != NULL;
    if (values[kind] != NULL)
    {
      snprintf(recorded->ma_valueTexts[kind], sizeof(recorded->ma_valueTexts[kind]), "%s", values[kind]->ma_text);
      snprintf(recorded->ma_valueSha256s[kind], sizeof(recorded->ma_valueSha256s[kind]), "%s", values[kind]->ma_sha256Hex);
    }
  }
  return g_tlsRecordStatus;
}

static TlsProbeStatus_t g_probeStatuses[FAKE_RECORD_MAX];
static TlsProbeResult_t g_probeResults[FAKE_RECORD_MAX];
static int              g_probeCallCount;
static int64_t          g_probeAdvanceMs;
static char             g_probeHostnames[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

TlsProbeStatus_t __wrap_tlsprobe_probeHost(const char* hostname, TlsProbeResult_t* result_out)
{
  int call_index = g_probeCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  snprintf(g_probeHostnames[call_index], sizeof(g_probeHostnames[call_index]), "%s", hostname);
  g_nowMs += g_probeAdvanceMs;

  memset(result_out, 0, sizeof(*result_out));
  if (g_probeStatuses[call_index] == TLSPROBE_OK)
    *result_out = g_probeResults[call_index];
  return g_probeStatuses[call_index];
}

static DbStatus_t  g_sslcheckStatus;
static bool        g_isSslcheckFeedLoaded;
static const char* g_sslcheckListingReasons[FAKE_RECORD_MAX];
static int         g_sslcheckCallCount;
static bool        g_isEverySslcheckOnFakeConn;
static char        g_sslcheckSha1s[FAKE_RECORD_MAX][TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE];

DbStatus_t __wrap_db_SSLCHECK(PGconn* conn, const char* sha1_hex, SSLCHECKRecord_t* record_out)
{
  int call_index = g_sslcheckCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  g_isEverySslcheckOnFakeConn = g_isEverySslcheckOnFakeConn && conn == FAKE_CONN;
  snprintf(g_sslcheckSha1s[call_index], sizeof(g_sslcheckSha1s[call_index]), "%s", sha1_hex);

  record_out->m_isBlacklistFeedLoaded      = false;
  record_out->ma_blacklistListingReason[0] = '\0';
  record_out->ma_blacklistListingTime[0]   = '\0';
  if (g_sslcheckStatus != DB_OK)
    return g_sslcheckStatus;

  record_out->m_isBlacklistFeedLoaded = g_isSslcheckFeedLoaded;
  const char* reason = g_sslcheckListingReasons[call_index] != NULL ? g_sslcheckListingReasons[call_index] : "";
  snprintf(record_out->ma_blacklistListingReason, sizeof(record_out->ma_blacklistListingReason), "%s", reason);
  if (reason[0] != '\0')
    snprintf(record_out->ma_blacklistListingTime, sizeof(record_out->ma_blacklistListingTime), "%s", "2026-09-01T08:00:00Z");
  return DB_OK;
}

static void static_resetTlsFakes(void)
{
  memset(g_tlsRecords, 0, sizeof(g_tlsRecords));
  g_tlsRecordCallCount         = 0;
  g_tlsRecordStatus            = DB_OK;
  g_isEveryTlsRecordOnFakeConn = true;
  for (int i = 0; i < FAKE_RECORD_MAX; i++)
    g_probeStatuses[i] = TLSPROBE_OK;
  memset(g_probeResults, 0, sizeof(g_probeResults));
  g_probeCallCount             = 0;
  g_probeAdvanceMs             = 0;
  memset(g_probeHostnames, 0, sizeof(g_probeHostnames));
  g_sslcheckStatus             = DB_OK;
  g_isSslcheckFeedLoaded       = true;
  memset(g_sslcheckListingReasons, 0, sizeof(g_sslcheckListingReasons));
  g_sslcheckCallCount          = 0;
  g_isEverySslcheckOnFakeConn  = true;
  memset(g_sslcheckSha1s, 0, sizeof(g_sslcheckSha1s));
}

static char g_callOrder[64];

static void static_noteCall(char letter)
{
  size_t len = strlen(g_callOrder);
  TEST_ASSERT_TRUE(len + 1 < sizeof(g_callOrder));
  g_callOrder[len]     = letter;
  g_callOrder[len + 1] = '\0';
}

static time_t g_nowEpoch;

time_t __wrap_time(time_t* time_out)
{
  if (time_out != NULL)
    *time_out = g_nowEpoch;
  return g_nowEpoch;
}

#define FAKE_RDAP_BASE_URL "https://rdap.example.net/"
static bool g_isServerFound;
static int  g_findCallCount;
static char g_findDomains[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

bool __wrap_registryask_tryFindServer(const char* registrable_domain, RegistryAskServer_t* server_out)
{
  int call_index = g_findCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('F');
  snprintf(g_findDomains[call_index], sizeof(g_findDomains[call_index]), "%s", registrable_domain);
  server_out->mp_rdapServerBaseUrl = g_isServerFound ? FAKE_RDAP_BASE_URL : NULL;
  server_out->mp_whoisServer       = NULL;
  return g_isServerFound;
}

static RegistryAskStatus_t       g_registryAskStatuses[FAKE_RECORD_MAX];
static RdapRegistration_t        g_registryAskRegistrations[FAKE_RECORD_MAX];
static unsigned int              g_registryAskRetries[FAKE_RECORD_MAX];
static int                       g_registryAskCallCount;
static int64_t                   g_registryAskAdvanceMs;
static bool                      g_isEveryRegistryAskOnFakeConn;
static const RegistryAskThrottleRules_t* g_registryAskThrottleRules[FAKE_RECORD_MAX];
static const QuotaRule_t*        g_registryAskDailyQuotaRules[FAKE_RECORD_MAX];
static const char*               g_registryAskServerBaseUrls[FAKE_RECORD_MAX];
static char                      g_registryAskDomains[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

RegistryAskStatus_t __wrap_registryask_askDomain(PGconn* conn, const RegistryAskThrottleRules_t* throttle_rules, const QuotaRule_t* daily_quota_rule, const RegistryAskServer_t* server, const char* registrable_domain, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  int call_index = g_registryAskCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('A');
  g_isEveryRegistryAskOnFakeConn           = g_isEveryRegistryAskOnFakeConn && conn == FAKE_CONN;
  g_registryAskThrottleRules[call_index]   = throttle_rules;
  g_registryAskDailyQuotaRules[call_index] = daily_quota_rule;
  g_registryAskServerBaseUrls[call_index]  = server->mp_rdapServerBaseUrl;
  snprintf(g_registryAskDomains[call_index], sizeof(g_registryAskDomains[call_index]), "%s", registrable_domain);
  g_nowMs += g_registryAskAdvanceMs;

  *registration_out        = g_registryAskRegistrations[call_index];
  *retry_after_seconds_out = g_registryAskRetries[call_index];
  return g_registryAskStatuses[call_index];
}

#define FAKE_RDAP_WHOIS_KIND_COUNT 4
enum { RDAP_WHOIS_KIND_REGISTRATION_EXPIRY = 0, RDAP_WHOIS_KIND_REGISTRAR, RDAP_WHOIS_KIND_TRANSFER_LOCK, RDAP_WHOIS_KIND_DNSSEC_DELEGATION };

typedef struct {
  char         ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char         ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
  bool         ma_hasValue[FAKE_RDAP_WHOIS_KIND_COUNT];
  char         ma_valueTexts[FAKE_RDAP_WHOIS_KIND_COUNT][WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  unsigned int m_retryAfterSeconds;
} RecordedRdapWhoisScan_t;

static RecordedRdapWhoisScan_t g_rdapWhoisRecords[FAKE_RECORD_MAX];
static int                     g_rdapWhoisRecordCallCount;
static DbStatus_t              g_rdapWhoisRecordStatus;
static bool                    g_isEveryRdapWhoisRecordOnFakeConn;

DbStatus_t __wrap_db_recordRdapWhoisScan(PGconn* conn, const DbRdapWhoisScanRecord_t* scan)
{
  int call_index = g_rdapWhoisRecordCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('R');
  g_isEveryRdapWhoisRecordOnFakeConn = g_isEveryRdapWhoisRecordOnFakeConn && conn == FAKE_CONN;
  TEST_ASSERT_NOT_NULL(scan->mp_domain);
  TEST_ASSERT_NOT_NULL(scan->mp_claimedUntil);

  RecordedRdapWhoisScan_t* recorded = &g_rdapWhoisRecords[call_index];
  memset(recorded, 0, sizeof(*recorded));
  snprintf(recorded->ma_domain, sizeof(recorded->ma_domain), "%s", scan->mp_domain);
  snprintf(recorded->ma_claimedUntil, sizeof(recorded->ma_claimedUntil), "%s", scan->mp_claimedUntil);
  const WatchlistDomainValue_t* values[FAKE_RDAP_WHOIS_KIND_COUNT] = {
    scan->mp_registrationExpiryValue, scan->mp_registrarValue,
    scan->mp_transferLockValue,       scan->mp_dnssecDelegationValue,
  };
  for (int kind = 0; kind < FAKE_RDAP_WHOIS_KIND_COUNT; kind++)
  {
    recorded->ma_hasValue[kind] = values[kind] != NULL;
    if (values[kind] != NULL)
      snprintf(recorded->ma_valueTexts[kind], sizeof(recorded->ma_valueTexts[kind]), "%s", values[kind]->ma_text);
  }
  recorded->m_retryAfterSeconds = scan->m_retryAfterSeconds;
  return g_rdapWhoisRecordStatus;
}

static UsageLogEvent_t g_usageEvents[8];
static int             g_usageEventCount;

void __wrap_usagelog_writeEvent(UsageLogEvent_t event)
{
  TEST_ASSERT_TRUE(g_usageEventCount < 8);
  g_usageEvents[g_usageEventCount++] = event;
}

#define FAKE_NOW_EPOCH 1793404800

static void static_resetRdapWhoisFakes(void)
{
  g_callOrder[0]                     = '\0';
  g_nowEpoch                         = FAKE_NOW_EPOCH;
  g_isServerFound                    = true;
  g_findCallCount                    = 0;
  memset(g_findDomains, 0, sizeof(g_findDomains));
  for (int i = 0; i < FAKE_RECORD_MAX; i++)
    g_registryAskStatuses[i] = REGISTRYASK_OK;
  memset(g_registryAskRegistrations, 0, sizeof(g_registryAskRegistrations));
  memset(g_registryAskRetries, 0, sizeof(g_registryAskRetries));
  g_registryAskCallCount             = 0;
  g_registryAskAdvanceMs             = 0;
  g_isEveryRegistryAskOnFakeConn     = true;
  memset(g_registryAskThrottleRules, 0, sizeof(g_registryAskThrottleRules));
  memset(g_registryAskDailyQuotaRules, 0, sizeof(g_registryAskDailyQuotaRules));
  memset(g_registryAskServerBaseUrls, 0, sizeof(g_registryAskServerBaseUrls));
  memset(g_registryAskDomains, 0, sizeof(g_registryAskDomains));
  memset(g_rdapWhoisRecords, 0, sizeof(g_rdapWhoisRecords));
  g_rdapWhoisRecordCallCount         = 0;
  g_rdapWhoisRecordStatus            = DB_OK;
  g_isEveryRdapWhoisRecordOnFakeConn = true;
  g_usageEventCount                  = 0;
}

typedef struct {
  HttpError_t  m_error;
  int          m_status;
  const char*  mp_url;
  const char*  mp_body;
  bool         m_isBodyCut;
  const char*  mp_csp;
  const char*  mp_hsts;
} FakeFetch_t;

static FakeFetch_t     g_robotsFetches[FAKE_RECORD_MAX];
static int             g_robotsFetchCallCount;
static char            g_robotsFetchHostnames[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static FakeFetch_t     g_homeFetches[FAKE_RECORD_MAX];
static int             g_homeFetchCallCount;
static char            g_homeFetchHostnames[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static int             g_fetchResultFreeCount;
static int             g_robotsTxtFreeCount;

static char* static_copyText(const char* text)
{
  if (text == NULL)
    return NULL;
  size_t len = strlen(text);
  char* copy = calloc(len + 1, 1);
  TEST_ASSERT_NOT_NULL(copy);
  memcpy(copy, text, len);
  return copy;
}

HttpError_t __wrap_header_fetch_fetchRobotsTxt(const char* hostname, HeaderFetchRobotsTxt_t* result_out)
{
  int call_index = g_robotsFetchCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('B');
  snprintf(g_robotsFetchHostnames[call_index], sizeof(g_robotsFetchHostnames[call_index]), "%s", hostname);

  const FakeFetch_t* fetch = &g_robotsFetches[call_index];
  memset(result_out, 0, sizeof(*result_out));
  if (fetch->m_error != HTTP_ERROR_NONE)
    return fetch->m_error;
  result_out->m_httpStatus = fetch->m_status;
  result_out->mp_body      = static_copyText(fetch->mp_body);
  result_out->m_bodyLen    = fetch->mp_body != NULL ? strlen(fetch->mp_body) : 0;
  result_out->m_isBodyCut  = fetch->m_isBodyCut;
  return HTTP_ERROR_NONE;
}

HttpError_t __wrap_header_fetch_fetchHomePage(const char* hostname, HeaderFetchResult_t* result_out)
{
  int call_index = g_homeFetchCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('G');
  snprintf(g_homeFetchHostnames[call_index], sizeof(g_homeFetchHostnames[call_index]), "%s", hostname);

  const FakeFetch_t* fetch = &g_homeFetches[call_index];
  memset(result_out, 0, sizeof(*result_out));
  if (fetch->m_error != HTTP_ERROR_NONE)
    return fetch->m_error;
  result_out->m_httpStatus               = fetch->m_status;
  result_out->mp_url                     = static_copyText(fetch->mp_url);
  result_out->mp_capturedHeaderValues    = calloc(HEADER_CHECK_HEADER_COUNT, sizeof(char*));
  TEST_ASSERT_NOT_NULL(result_out->mp_capturedHeaderValues);
  result_out->m_capturedHeaderValueCount = HEADER_CHECK_HEADER_COUNT;
  result_out->mp_capturedHeaderValues[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]   = static_copyText(fetch->mp_csp);
  result_out->mp_capturedHeaderValues[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = static_copyText(fetch->mp_hsts);
  return HTTP_ERROR_NONE;
}

void __wrap_header_fetch_resultFree(HeaderFetchResult_t* result)
{
  g_fetchResultFreeCount++;
  free(result->mp_url);
  free(result->mp_unfollowedRedirectUrl);
  for (int i = 0; i < result->m_capturedHeaderValueCount; i++)
    free(result->mp_capturedHeaderValues[i]);
  free(result->mp_capturedHeaderValues);
  memset(result, 0, sizeof(*result));
}

void __wrap_header_fetch_robotsTxtFree(HeaderFetchRobotsTxt_t* result)
{
  g_robotsTxtFreeCount++;
  free(result->mp_body);
  memset(result, 0, sizeof(*result));
}

static ThrottleStatus_t g_throttleStatuses[FAKE_RECORD_MAX];
static unsigned int     g_throttleRetries[FAKE_RECORD_MAX];
static int              g_throttleCallCount;
static ThrottleRule_t   g_throttleRules[FAKE_RECORD_MAX];
static char             g_throttleTargets[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static unsigned int     g_throttleCounts[FAKE_RECORD_MAX];
static bool             g_isEveryThrottleOnFakeConn;

ThrottleStatus_t __wrap_throttle_dbCharge(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int charged_count, unsigned int* retry_after_seconds_out)
{
  int call_index = g_throttleCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('T');
  g_isEveryThrottleOnFakeConn = g_isEveryThrottleOnFakeConn && conn == FAKE_CONN;
  g_throttleRules[call_index]  = *rule;
  g_throttleCounts[call_index] = charged_count;
  snprintf(g_throttleTargets[call_index], sizeof(g_throttleTargets[call_index]), "%s", target_name);
  *retry_after_seconds_out = g_throttleRetries[call_index];
  return g_throttleStatuses[call_index];
}

typedef struct {
  char         ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char         ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
  bool         m_hasValue;
  char         ma_valueText[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  char         ma_valueSha256[WATCHLIST_DOMAIN_SHA256_HEX_LEN + 1];
  unsigned int m_retryAfterSeconds;
} RecordedHeadersScan_t;

static RecordedHeadersScan_t g_headersRecords[FAKE_RECORD_MAX];
static int                   g_headersRecordCallCount;
static DbStatus_t            g_headersRecordStatus;
static bool                  g_isEveryHeadersRecordOnFakeConn;

DbStatus_t __wrap_db_recordHeadersScan(PGconn* conn, const DbHeadersScanRecord_t* scan)
{
  int call_index = g_headersRecordCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  static_noteCall('R');
  g_isEveryHeadersRecordOnFakeConn = g_isEveryHeadersRecordOnFakeConn && conn == FAKE_CONN;
  TEST_ASSERT_NOT_NULL(scan->mp_domain);
  TEST_ASSERT_NOT_NULL(scan->mp_claimedUntil);

  RecordedHeadersScan_t* recorded = &g_headersRecords[call_index];
  memset(recorded, 0, sizeof(*recorded));
  snprintf(recorded->ma_domain, sizeof(recorded->ma_domain), "%s", scan->mp_domain);
  snprintf(recorded->ma_claimedUntil, sizeof(recorded->ma_claimedUntil), "%s", scan->mp_claimedUntil);
  recorded->m_hasValue = scan->mp_securityHeadersValue != NULL;
  if (scan->mp_securityHeadersValue != NULL)
  {
    snprintf(recorded->ma_valueText, sizeof(recorded->ma_valueText), "%s", scan->mp_securityHeadersValue->ma_text);
    snprintf(recorded->ma_valueSha256, sizeof(recorded->ma_valueSha256), "%s", scan->mp_securityHeadersValue->ma_sha256Hex);
  }
  recorded->m_retryAfterSeconds = scan->m_retryAfterSeconds;
  return g_headersRecordStatus;
}

#define FAKE_ROBOTS_ALLOW_ALL "User-agent: *\nDisallow: /private\n"

static void static_resetHeadersFakes(void)
{
  for (int i = 0; i < FAKE_RECORD_MAX; i++)
  {
    g_robotsFetches[i] = (FakeFetch_t){ .m_status = 200, .mp_body = FAKE_ROBOTS_ALLOW_ALL };
    g_homeFetches[i]   = (FakeFetch_t){ .m_status = 200, .mp_url = "https://example.com/" };
    g_throttleStatuses[i] = THROTTLE_CHARGED;
  }
  g_robotsFetchCallCount           = 0;
  g_homeFetchCallCount             = 0;
  g_fetchResultFreeCount           = 0;
  g_robotsTxtFreeCount             = 0;
  memset(g_robotsFetchHostnames, 0, sizeof(g_robotsFetchHostnames));
  memset(g_homeFetchHostnames, 0, sizeof(g_homeFetchHostnames));
  memset(g_throttleRetries, 0, sizeof(g_throttleRetries));
  memset(g_throttleRules, 0, sizeof(g_throttleRules));
  memset(g_throttleTargets, 0, sizeof(g_throttleTargets));
  memset(g_throttleCounts, 0, sizeof(g_throttleCounts));
  g_throttleCallCount              = 0;
  g_isEveryThrottleOnFakeConn      = true;
  memset(g_headersRecords, 0, sizeof(g_headersRecords));
  g_headersRecordCallCount         = 0;
  g_headersRecordStatus            = DB_OK;
  g_isEveryHeadersRecordOnFakeConn = true;
}

static bool g_isRobotsParseFailing;
bool __real_robotstxt_parse(const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out);
bool __wrap_robotstxt_parse(const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out)
{
  if (g_isRobotsParseFailing)
  {
    memset(robots_out, 0, sizeof(*robots_out));
    return false;
  }
  return __real_robotstxt_parse(body, body_len, is_body_cut, product_token, robots_out);
}

static bool g_hasCertSpotterKey;

bool __wrap_certspotter_hasApiKey(void)
{
  return g_hasCertSpotterKey;
}

static bool         g_isHoldRead;
static unsigned int g_holdSeconds;
static char         g_holdReadName[32];
static int          g_holdReadCallCount;

bool __wrap_quota_dbTryReadHoldRemainingSeconds(PGconn* conn, const char* hold_name, unsigned int* remaining_seconds_out)
{
  TEST_ASSERT_TRUE(conn == FAKE_CONN);
  g_holdReadCallCount++;
  static_noteCall('H');
  snprintf(g_holdReadName, sizeof(g_holdReadName), "%s", hold_name);
  *remaining_seconds_out = g_holdSeconds;
  return g_isHoldRead;
}

static char         g_setHoldName[32];
static unsigned int g_setHoldSeconds;
static int          g_setHoldCallCount;

bool __wrap_quota_dbSetHold(PGconn* conn, const char* hold_name, unsigned int hold_seconds)
{
  TEST_ASSERT_TRUE(conn == FAKE_CONN);
  g_setHoldCallCount++;
  static_noteCall('S');
  snprintf(g_setHoldName, sizeof(g_setHoldName), "%s", hold_name);
  g_setHoldSeconds = hold_seconds;
  return true;
}

static unsigned int g_windowRemainingSeconds;
static time_t       g_lastWindowNow;

unsigned int __wrap_quota_windowRemainingSeconds(const QuotaRule_t* rule, time_t now)
{
  g_lastWindowNow = now;
  g_lastQuotaRule = *rule;
  return g_windowRemainingSeconds;
}

static CertSpotterCertificateList_t g_ctList;
static CertSpotterStatus_t          g_ctStatus;
static unsigned int                 g_ctRetry;
static char                         g_ctHosts[FAKE_RECORD_MAX][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static int                          g_ctLookupCallCount;

CertSpotterStatus_t __wrap_certspotter_lookupCertificates(PGconn* conn, const QuotaRule_t* quota_rule, const char* host_name,
                                                          CertSpotterCertificateList_t* list_out, unsigned int* retry_after_seconds_out)
{
  int call_index = g_ctLookupCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  snprintf(g_ctHosts[call_index], sizeof(g_ctHosts[call_index]), "%s", host_name);
  QuotaStatus_t quota_status = __wrap_quota_dbReserve(conn, quota_rule);
  static_noteCall('C');
  memset(list_out, 0, sizeof(*list_out));
  if (quota_status == QUOTA_EXHAUSTED)
    return CERTSPOTTER_QUOTA_EXHAUSTED;
  if (quota_status == QUOTA_ERROR)
    return CERTSPOTTER_DB_ERROR;
  memcpy(list_out, &g_ctList, sizeof(*list_out));
  *retry_after_seconds_out = g_ctRetry;
  return g_ctStatus;
}

typedef struct {
  const char*       mp_name;
  DnsAnswerStatus_t m_status;
  DnsCaaRecord_t*   mp_records;
  int               m_recordCount;
} FakeCaaName_t;

static FakeCaaName_t g_caaNames[4];
static int           g_caaNameCount;

static void static_fillCaaAnswer(const char* name, DnsAnswer_t* answer)
{
  for (int i = 0; i < g_caaNameCount; i++)
  {
    if (strcmp(g_caaNames[i].mp_name, name) != 0)
      continue;
    answer->m_status      = g_caaNames[i].m_status;
    answer->m_recordCount = g_caaNames[i].m_recordCount;
    answer->mp_caaRecords = g_caaNames[i].mp_records;
    return;
  }
  answer->m_status = DNS_ANSWER_OK;
}

typedef struct {
  char         ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char         ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
  bool         m_hasValue;
  char         ma_valueText[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  char         ma_valueSha256[WATCHLIST_DOMAIN_SHA256_HEX_LEN + 1];
  unsigned int m_retryAfterSeconds;
} RecordedCtScan_t;

static RecordedCtScan_t g_ctRecords[FAKE_RECORD_MAX];
static int              g_ctRecordCallCount;
static DbStatus_t       g_ctRecordStatus;

DbStatus_t __wrap_db_recordCtScan(PGconn* conn, const DbCtScanRecord_t* scan)
{
  int call_index = g_ctRecordCallCount++;
  TEST_ASSERT_TRUE(call_index < FAKE_RECORD_MAX);
  TEST_ASSERT_TRUE(conn == FAKE_CONN);
  static_noteCall('R');
  TEST_ASSERT_NOT_NULL(scan->mp_domain);
  TEST_ASSERT_NOT_NULL(scan->mp_claimedUntil);

  RecordedCtScan_t* recorded = &g_ctRecords[call_index];
  memset(recorded, 0, sizeof(*recorded));
  snprintf(recorded->ma_domain, sizeof(recorded->ma_domain), "%s", scan->mp_domain);
  snprintf(recorded->ma_claimedUntil, sizeof(recorded->ma_claimedUntil), "%s", scan->mp_claimedUntil);
  recorded->m_hasValue = scan->mp_certIssuersValue != NULL;
  if (scan->mp_certIssuersValue != NULL)
  {
    snprintf(recorded->ma_valueText, sizeof(recorded->ma_valueText), "%s", scan->mp_certIssuersValue->ma_text);
    snprintf(recorded->ma_valueSha256, sizeof(recorded->ma_valueSha256), "%s", scan->mp_certIssuersValue->ma_sha256Hex);
  }
  recorded->m_retryAfterSeconds = scan->m_retryAfterSeconds;
  return g_ctRecordStatus;
}

static void static_resetCtFakes(void)
{
  g_hasCertSpotterKey      = true;
  g_isHoldRead             = true;
  g_holdSeconds            = 0;
  g_holdReadCallCount      = 0;
  memset(g_holdReadName, 0, sizeof(g_holdReadName));
  memset(g_setHoldName, 0, sizeof(g_setHoldName));
  g_setHoldSeconds         = 0;
  g_setHoldCallCount       = 0;
  g_windowRemainingSeconds = 1200;
  g_lastWindowNow          = 0;
  memset(&g_ctList, 0, sizeof(g_ctList));
  g_ctList.m_isComplete    = true;
  g_ctList.m_issuerCount   = 1;
  snprintf(g_ctList.ma_issuers[0].ma_key, sizeof(g_ctList.ma_issuers[0].ma_key), "letsencrypt.org");
  snprintf(g_ctList.ma_issuers[0].ma_caaDomains[0], sizeof(g_ctList.ma_issuers[0].ma_caaDomains[0]), "letsencrypt.org");
  g_ctList.ma_issuers[0].m_caaDomainCount       = 1;
  g_ctList.ma_issuers[0].m_isCaaDomainListKnown = true;
  g_ctList.ma_issuers[0].m_isSeenOnExactName    = true;
  g_ctStatus               = CERTSPOTTER_OK;
  g_ctRetry                = 0;
  memset(g_ctHosts, 0, sizeof(g_ctHosts));
  g_ctLookupCallCount      = 0;
  memset(g_caaNames, 0, sizeof(g_caaNames));
  g_caaNameCount           = 0;
  memset(g_ctRecords, 0, sizeof(g_ctRecords));
  g_ctRecordCallCount      = 0;
  g_ctRecordStatus         = DB_OK;
}

void setUp(void)
{
  g_isRobotsParseFailing   = false;
  g_nowMs                  = FAKE_START_MS;
  memset(g_claimBatches, 0, sizeof(g_claimBatches));
  g_claimBatchCount        = 0;
  g_claimCallCount         = 0;
  g_isEveryClaimOnFakeConn = true;
  memset(g_claimLaneNames, 0, sizeof(g_claimLaneNames));
  g_quotaStatusCount       = 0;
  g_quotaCallCount         = 0;
  memset(&g_lastQuotaRule, 0, sizeof(g_lastQuotaRule));
  g_isEveryQuotaOnFakeConn = true;
  static_resetDnsFakes();
  static_resetTlsFakes();
  static_resetRdapWhoisFakes();
  static_resetHeadersFakes();
  static_resetCtFakes();
}

void tearDown(void) {}

static WatchlistDomainScanClaim_t static_claim(const char* domain, const char* claimed_until)
{
  WatchlistDomainScanClaim_t claim;
  memset(&claim, 0, sizeof(claim));
  snprintf(claim.ma_domain, sizeof(claim.ma_domain), "%s", domain);
  snprintf(claim.ma_claimedUntil, sizeof(claim.ma_claimedUntil), "%s", claimed_until);
  return claim;
}

static void static_queueClaims(DbStatus_t status, int claim_count, const WatchlistDomainScanClaim_t* claims)
{
  TEST_ASSERT_TRUE(g_claimBatchCount < FAKE_CLAIM_BATCH_MAX);
  TEST_ASSERT_TRUE(claim_count <= DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT);
  FakeClaimBatch_t* batch = &g_claimBatches[g_claimBatchCount++];
  batch->m_status     = status;
  batch->m_claimCount = claim_count;
  for (int i = 0; i < claim_count; i++)
    batch->ma_claims[i] = claims[i];
}

static void static_queueOneClaim(WatchlistDomainScanClaim_t claim)
{
  static_queueClaims(DB_OK, 1, &claim);
}

#define EMAIL_CHECK_IDS "spf_record,spf_syntax,spf_lookup_limit,spf_all,spf_ignored_terms,spf_ptr," \
                        "spf_wide_range,spf_record_size,dmarc_record,dmarc_policy,dmarc_test_mode," \
                        "dmarc_reporting,dkim_key_found,dkim_key_usable,dkim_key_size,dkim_key_format," \
                        "dkim_test_mode,dkim_key_restricted,dkim_multiple_keys,mx,mta_sts"

static void static_assertEverythingFreed(void)
{
  TEST_ASSERT_EQUAL_INT(0, g_openAnswerCount);
  TEST_ASSERT_EQUAL_INT(0, g_openEmailRecordCount);
  TEST_ASSERT_EQUAL_INT(4 * g_dnsAskCallCount, g_answerFreeCount);
  TEST_ASSERT_EQUAL_INT(g_emailCallCount, g_emailFreeCount);
}

void test_scanNextDnsDomains_scans_each_claimed_domain_and_records_each_kind(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "2026-10-26 12:00:00.1+00"),
    static_claim("b.example.org", "2026-10-26 12:00:00.2+00"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_dnsAnswers[DNS_RECORD_TYPE_MX].m_recordCount = 1;
  g_hasTakeoverChain = true;

  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_claimCallCount);
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_LANE_DNS, g_claimLaneNames[0]);
  TEST_ASSERT_EQUAL_STRING("dns", g_claimLaneNames[1]);
  TEST_ASSERT_EQUAL_INT(2, g_quotaCallCount);
  TEST_ASSERT_EQUAL_STRING("domain_scan_dns", g_lastQuotaRule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(86400, g_lastQuotaRule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(200000, g_lastQuotaRule.m_callLimit);
  TEST_ASSERT_TRUE(g_isEveryClaimOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryQuotaOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryDnsRecordOnFakeConn);

  static const DnsRecordType_t types[4] = { DNS_RECORD_TYPE_NS, DNS_RECORD_TYPE_MX, DNS_RECORD_TYPE_A, DNS_RECORD_TYPE_AAAA };
  TEST_ASSERT_EQUAL_INT(2, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_emailCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_takeoverCallCount);
  TEST_ASSERT_EQUAL_STRING("b.example.org", g_lastTakeoverHostname);
  TEST_ASSERT_EQUAL_INT(2, g_dnsRecordCallCount);
  for (int d = 0; d < 2; d++)
  {
    const DnsAskCall_t* ask = &g_dnsAskCalls[d];
    TEST_ASSERT_EQUAL_INT(4, ask->m_questionCount);
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS, ask->m_deadlineMs);
    for (int q = 0; q < 4; q++)
    {
      TEST_ASSERT_EQUAL_STRING(claims[d].ma_domain, ask->ma_names[q]);
      TEST_ASSERT_EQUAL_INT(types[q], ask->ma_types[q]);
    }
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_domain, g_emailDomains[d]);
    TEST_ASSERT_TRUE(g_isEmailSelectorNull[d]);

    const RecordedDnsScan_t* recorded = &g_dnsRecords[d];
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_domain, recorded->ma_domain);
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_claimedUntil, recorded->ma_claimedUntil);
    TEST_ASSERT_TRUE(recorded->m_hasEmailCheckIds);
    TEST_ASSERT_EQUAL_STRING(EMAIL_CHECK_IDS, recorded->ma_emailCheckIds);
    TEST_ASSERT_TRUE(recorded->m_hasHostingIpAddresses);
    TEST_ASSERT_EQUAL_STRING("93.184.216.34", recorded->ma_hostingIpAddresses);
    static const char* const texts[FAKE_DNS_KIND_COUNT] = {
      "found", "ns1.example.net", "10 mx.example.net", "public", "vulnerable Example Cloud", "p------------------p-",
    };
    for (int kind = 0; kind < FAKE_DNS_KIND_COUNT; kind++)
    {
      TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[kind], texts[kind]);
      TEST_ASSERT_EQUAL_STRING(texts[kind], recorded->ma_valueTexts[kind]);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(WATCHLIST_DOMAIN_SHA256_HEX_LEN, strlen(recorded->ma_valueSha256s[kind]), texts[kind]);
      for (int other = 0; other < kind; other++)
        TEST_ASSERT_TRUE_MESSAGE(strcmp(recorded->ma_valueSha256s[kind], recorded->ma_valueSha256s[other]) != 0, texts[kind]);
    }
  }
  static_assertEverythingFreed();
}

void test_scanNextDnsDomains_claim_with_no_domain_ends_the_run(void)
{
  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_dnsRecordCallCount);
}

void test_scanNextDnsDomains_failed_claim_fails_the_run(void)
{
  static_queueClaims(DB_ERROR, 0, NULL);

  TEST_ASSERT_FALSE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
}

void test_scanNextDnsDomains_stops_when_the_run_deadline_passes(void)
{
  TEST_ASSERT_EQUAL_INT(30000, WATCHLIST_DOMAIN_SCAN_RUN_DEADLINE_MS);
  const WatchlistDomainScanClaim_t four[4] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
    static_claim("c.example.com", "u3"), static_claim("d.example.com", "u4"),
  };
  static const struct {
    int64_t m_roundMs;
    int     ma_claimCounts[2];
    int     m_scanCount;
    int     m_claimCallCount;
  } cases[] = {
    { 15000, { 4, 0 }, 2, 1 },
    { 15000, { 2, 2 }, 2, 1 },
    { 14999, { 2, 1 }, 3, 2 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_dnsAskAdvanceMs = cases[c].m_roundMs;
    static_queueClaims(DB_OK, cases[c].ma_claimCounts[0], four);
    if (cases[c].ma_claimCounts[1] > 0)
      static_queueClaims(DB_OK, cases[c].ma_claimCounts[1], four);
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_dnsRecordCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_quotaCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_claimCallCount, g_claimCallCount, message);
  }
}

void test_scanNextDnsDomains_quota_refusal_ends_the_run_with_nothing_written(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
  };
  static const struct {
    QuotaStatus_t ma_statuses[2];
    bool          m_isRunOk;
    int           m_scanCount;
  } cases[] = {
    { { QUOTA_EXHAUSTED, QUOTA_GRANTED }, true,  0 },
    { { QUOTA_ERROR,     QUOTA_GRANTED }, false, 0 },
    { { QUOTA_GRANTED,   QUOTA_EXHAUSTED }, true, 1 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueClaims(DB_OK, 2, claims);
    g_quotaStatuses[0] = cases[c].ma_statuses[0];
    g_quotaStatuses[1] = cases[c].ma_statuses[1];
    g_quotaStatusCount = 2;
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_isRunOk, watchlist_dns_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount + 1, g_quotaCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_dnsAskCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_takeoverCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_emailCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_dnsRecordCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_claimCallCount, message);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_failed_record_fails_the_run(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_dnsRecordStatus = DB_ERROR;

  TEST_ASSERT_FALSE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_dnsRecordCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  static_assertEverythingFreed();
}

void test_scanNextDnsDomains_checks_email_on_every_scan(void)
{
  static const struct {
    const char*       mp_name;
    DnsAnswerStatus_t m_mxStatus;
    int               m_mxRecordCount;
    bool              m_hasNullMx;
  } cases[] = {
    { "no mx host", DNS_ANSWER_OK,           0, false },
    { "mx host",    DNS_ANSWER_OK,           1, false },
    { "null mx",    DNS_ANSWER_OK,           0, true  },
    { "failed mx",  DNS_ANSWER_SERVER_ERROR, 1, true  },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    g_dnsAnswers[DNS_RECORD_TYPE_MX] = (FakeDnsAnswer_t){ cases[c].m_mxStatus, cases[c].m_mxRecordCount, cases[c].m_hasNullMx };

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_emailCallCount, cases[c].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_dnsRecordCallCount, cases[c].mp_name);
    TEST_ASSERT_TRUE_MESSAGE(g_dnsRecords[0].ma_hasValue[DNS_KIND_EMAIL_AUTH], cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("p------------------p-", g_dnsRecords[0].ma_valueTexts[DNS_KIND_EMAIL_AUTH], cases[c].mp_name);
    TEST_ASSERT_TRUE_MESSAGE(g_dnsRecords[0].ma_hasValue[DNS_KIND_DNS_PRESENCE], cases[c].mp_name);
    TEST_ASSERT_TRUE_MESSAGE(g_dnsRecords[0].ma_hasValue[DNS_KIND_CNAME_TAKEOVER], cases[c].mp_name);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_checks_email_once_with_no_selector(void)
{
  static const struct {
    const char*               mp_name;
    DnsLookupStatus_t         m_status;
    EmailCheckDkimKeyStatus_t m_keyStatus;
    EmailCheckResult_t        m_keyFoundResult;
    const char*               mp_value;
  } cases[] = {
    { "key not found", DNS_LOOKUP_OK,        EMAILCHECK_DKIM_KEY_NOT_FOUND, EMAILCHECK_RESULT_FAIL, "------------f--------" },
    { "key found",     DNS_LOOKUP_OK,        EMAILCHECK_DKIM_KEY_FOUND,     EMAILCHECK_RESULT_PASS, "------------p--------" },
    { "no answer",     DNS_LOOKUP_NO_ANSWER, EMAILCHECK_DKIM_KEY_NOT_FOUND, EMAILCHECK_RESULT_FAIL, NULL },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    g_emailRuns[0] = (FakeEmailRun_t){ cases[c].m_status, cases[c].m_keyStatus, 1,
                                       { { EMAILCHECK_KIND_DKIM_KEY_FOUND, cases[c].m_keyFoundResult } } };
    g_emailRunCount = 1;

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_emailCallCount, cases[c].mp_name);
    TEST_ASSERT_TRUE_MESSAGE(g_isEmailSelectorNull[0], cases[c].mp_name);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].mp_value != NULL, g_dnsRecords[0].ma_hasValue[DNS_KIND_EMAIL_AUTH], cases[c].mp_name);
    if (cases[c].mp_value != NULL)
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].mp_value, g_dnsRecords[0].ma_valueTexts[DNS_KIND_EMAIL_AUTH], cases[c].mp_name);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_failed_answer_leaves_out_only_its_kind(void)
{
  static const struct {
    const char* mp_name;
    bool        m_isNsFailed;
    bool        m_isAaaaFailed;
    bool        m_isRoundTimedOut;
    bool        m_isTakeoverFailed;
    bool        m_isEmailFailed;
    bool        ma_hasValue[FAKE_DNS_KIND_COUNT];
  } cases[] = {
    { "ns",       true,  false, false, false, false, { true,  false, true,  true,  true,  true } },
    { "aaaa",     false, true,  false, false, false, { true,  true,  true,  false, true,  true } },
    { "round",    false, false, true,  false, false, { false, false, false, false, true,  true } },
    { "takeover", false, false, false, true,  false, { true,  true,  true,  true,  false, true } },
    { "email",    false, false, false, false, true,  { true,  true,  true,  true,  true,  false } },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    if (cases[c].m_isNsFailed)
      g_dnsAnswers[DNS_RECORD_TYPE_NS] = (FakeDnsAnswer_t){ DNS_ANSWER_SERVER_ERROR, 0, false };
    if (cases[c].m_isAaaaFailed)
      g_dnsAnswers[DNS_RECORD_TYPE_AAAA] = (FakeDnsAnswer_t){ DNS_ANSWER_SERVER_ERROR, 0, false };
    if (cases[c].m_isRoundTimedOut)
    {
      g_dnsAnswers[DNS_RECORD_TYPE_NS]   = (FakeDnsAnswer_t){ DNS_ANSWER_TIMEOUT, 0, false };
      g_dnsAnswers[DNS_RECORD_TYPE_MX]   = (FakeDnsAnswer_t){ DNS_ANSWER_TIMEOUT, 0, false };
      g_dnsAnswers[DNS_RECORD_TYPE_A]    = (FakeDnsAnswer_t){ DNS_ANSWER_TIMEOUT, 0, false };
      g_dnsAnswers[DNS_RECORD_TYPE_AAAA] = (FakeDnsAnswer_t){ DNS_ANSWER_TIMEOUT, 0, false };
    }
    if (cases[c].m_isTakeoverFailed)
      g_takeoverStatus = DNS_LOOKUP_NO_ANSWER;
    if (cases[c].m_isEmailFailed)
    {
      g_emailRuns[0] = g_defaultEmailRun;
      g_emailRuns[0].m_status = DNS_LOOKUP_NO_ANSWER;
      g_emailRunCount = 1;
    }

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_dnsRecordCallCount, cases[c].mp_name);
    for (int kind = 0; kind < FAKE_DNS_KIND_COUNT; kind++)
    {
      char message[32] = "";
      snprintf(message, sizeof(message), "%s kind %d", cases[c].mp_name, kind);
      TEST_ASSERT_EQUAL_MESSAGE(cases[c].ma_hasValue[kind], g_dnsRecords[0].ma_hasValue[kind], message);
    }
    TEST_ASSERT_TRUE_MESSAGE(g_dnsRecords[0].m_hasEmailCheckIds, cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(EMAIL_CHECK_IDS, g_dnsRecords[0].ma_emailCheckIds, cases[c].mp_name);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_sends_every_check_id_in_letter_order(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"),
    static_claim("b.example.org", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_emailRuns[0] = (FakeEmailRun_t){ DNS_LOOKUP_OK, EMAILCHECK_DKIM_KEY_UNKNOWN, 4,
                                     { { EMAILCHECK_KIND_MTA_STS,      EMAILCHECK_RESULT_FAIL },
                                       { EMAILCHECK_KIND_SPF_RECORD,   EMAILCHECK_RESULT_FAIL },
                                       { EMAILCHECK_KIND_MX,           EMAILCHECK_RESULT_PASS },
                                       { EMAILCHECK_KIND_DMARC_RECORD, EMAILCHECK_RESULT_WARN } } };
  g_emailRuns[1] = (FakeEmailRun_t){ DNS_LOOKUP_OK, EMAILCHECK_DKIM_KEY_UNKNOWN, 4,
                                     { { EMAILCHECK_KIND_MTA_STS,      EMAILCHECK_RESULT_PASS },
                                       { EMAILCHECK_KIND_SPF_RECORD,   EMAILCHECK_RESULT_PASS },
                                       { EMAILCHECK_KIND_MX,           EMAILCHECK_RESULT_PASS },
                                       { EMAILCHECK_KIND_DMARC_RECORD, EMAILCHECK_RESULT_PASS } } };
  g_emailRunCount = 2;

  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_dnsRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("f-------w----------pf", g_dnsRecords[0].ma_valueTexts[DNS_KIND_EMAIL_AUTH]);
  TEST_ASSERT_EQUAL_STRING("p-------p----------pp", g_dnsRecords[1].ma_valueTexts[DNS_KIND_EMAIL_AUTH]);
  for (int d = 0; d < 2; d++)
  {
    TEST_ASSERT_TRUE(g_dnsRecords[d].m_hasEmailCheckIds);
    TEST_ASSERT_EQUAL_STRING(EMAIL_CHECK_IDS, g_dnsRecords[d].ma_emailCheckIds);
  }
  static_assertEverythingFreed();
}

void test_scanNextDnsDomains_sends_no_email_value_without_the_check_ids(void)
{
  static_queueOneClaim(static_claim("a.example.com", "u1"));
  g_missingKindId = EMAILCHECK_KIND_MTA_STS;

  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_emailCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_dnsRecordCallCount);
  TEST_ASSERT_FALSE(g_dnsRecords[0].m_hasEmailCheckIds);
  TEST_ASSERT_FALSE(g_dnsRecords[0].ma_hasValue[DNS_KIND_EMAIL_AUTH]);
  for (int kind = 0; kind < DNS_KIND_EMAIL_AUTH; kind++)
    TEST_ASSERT_TRUE(g_dnsRecords[0].ma_hasValue[kind]);
  static_assertEverythingFreed();
}

void test_scanNextDnsDomains_name_that_is_not_public_is_asked_nothing(void)
{
  static_queueOneClaim(static_claim("printer.local", "u1"));
  g_questionCounts[0] = 37;

  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_takeoverCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_emailCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_dnsRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("printer.local", g_dnsRecords[0].ma_domain);
  TEST_ASSERT_EQUAL_STRING("u1", g_dnsRecords[0].ma_claimedUntil);
  for (int kind = 0; kind < FAKE_DNS_KIND_COUNT; kind++)
    TEST_ASSERT_FALSE(g_dnsRecords[0].ma_hasValue[kind]);
  TEST_ASSERT_FALSE(g_dnsRecords[0].m_hasHostingIpAddresses);
  TEST_ASSERT_EQUAL_INT(0, g_dnsRecords[0].m_questionCount);
  TEST_ASSERT_TRUE(g_dnsRecords[0].m_hasEmailCheckIds);
  TEST_ASSERT_EQUAL_STRING(EMAIL_CHECK_IDS, g_dnsRecords[0].ma_emailCheckIds);
}

void test_scanNextDnsDomains_records_the_question_count_of_each_domain(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"),
    static_claim("b.example.org", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_questionCounts[0] = 23;
  g_questionCounts[1] = 61;

  TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_dnsRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("a.example.com", g_dnsRecords[0].ma_domain);
  TEST_ASSERT_EQUAL_INT(23, g_dnsRecords[0].m_questionCount);
  TEST_ASSERT_EQUAL_STRING("b.example.org", g_dnsRecords[1].ma_domain);
  TEST_ASSERT_EQUAL_INT(61, g_dnsRecords[1].m_questionCount);
  TEST_ASSERT_EQUAL_INT(2, g_emailCallCount);

  TEST_ASSERT_EQUAL_INT(2, g_questionCountResetCount);
  for (int i = 0; i < 2; i++)
  {
    TEST_ASSERT_EQUAL_INT(i, g_questionCountResets[i].m_askCallCount);
    TEST_ASSERT_EQUAL_INT(i, g_questionCountResets[i].m_takeoverCallCount);
    TEST_ASSERT_EQUAL_INT(i, g_questionCountResets[i].m_emailCallCount);
  }
  TEST_ASSERT_EQUAL_INT(2, g_questionCountReadCount);
  TEST_ASSERT_EQUAL_INT(1, g_questionCountReads[0].m_askCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_questionCountReads[0].m_takeoverCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_questionCountReads[0].m_emailCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_questionCountReads[1].m_askCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_questionCountReads[1].m_takeoverCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_questionCountReads[1].m_emailCallCount);
  static_assertEverythingFreed();
}

void test_scanNextDnsDomains_sends_the_public_addresses_whatever_the_cname_chain_holds(void)
{
  static const char* const JOINED = "93.184.216.34,2606:2800:220:1:248:1893:25c8:1946";
  static const struct {
    const char*       mp_name;
    const char*       mp_lastName;
    DnsLookupStatus_t m_takeoverStatus;
    bool              m_isAAddressPrivate;
    bool              m_isAaaaFailed;
    const char*       mp_addresses;
  } cases[] = {
    { "akamai name",            "a.example.akamaiedge.net",      DNS_LOOKUP_OK,        false, false, JOINED },
    { "cloudfront name",        "d111111abcdef8.cloudfront.net", DNS_LOOKUP_OK,        false, false, JOINED },
    { "no cdn",                 "web.example.net",               DNS_LOOKUP_OK,        false, false, JOINED },
    { "no chain",               NULL,                            DNS_LOOKUP_OK,        false, false, JOINED },
    { "chain failed, cdn",      "a.example.akamaiedge.net",      DNS_LOOKUP_NO_ANSWER, false, false, JOINED },
    { "chain failed, no cdn",   "web.example.net",               DNS_LOOKUP_NO_ANSWER, false, false, JOINED },
    { "chain not found",        NULL,                            DNS_LOOKUP_NOT_FOUND, false, false, JOINED },
    { "private address, cdn",   "a.example.akamaiedge.net",      DNS_LOOKUP_OK,        true,  false, NULL   },
    { "private address",        "web.example.net",               DNS_LOOKUP_OK,        true,  false, NULL   },
    { "aaaa failed, cdn",       "a.example.akamaiedge.net",      DNS_LOOKUP_OK,        false, true,  NULL   },
    { "aaaa failed",            "web.example.net",               DNS_LOOKUP_OK,        false, true,  NULL   },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    g_dnsAnswers[DNS_RECORD_TYPE_AAAA].m_recordCount = 1;
    if (cases[c].m_isAaaaFailed)
      g_dnsAnswers[DNS_RECORD_TYPE_AAAA] = (FakeDnsAnswer_t){ DNS_ANSWER_SERVER_ERROR, 0, false };
    g_isAAddressPrivate = cases[c].m_isAAddressPrivate;
    g_takeoverLastName  = cases[c].mp_lastName;
    g_takeoverStatus    = cases[c].m_takeoverStatus;

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_dnsRecordCallCount, cases[c].mp_name);
    const RecordedDnsScan_t* recorded = &g_dnsRecords[0];
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].mp_addresses != NULL, recorded->m_hasHostingIpAddresses, cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].mp_addresses != NULL ? cases[c].mp_addresses : "", recorded->ma_hostingIpAddresses, cases[c].mp_name);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_dangling_cname_is_found(void)
{
  static const struct {
    const char*       mp_name;
    DnsLookupStatus_t m_takeoverStatus;
    bool              m_hasTakeoverChain;
    const char*       mp_presence;
    const char*       mp_takeover;
  } cases[] = {
    { "dangling", DNS_LOOKUP_OK,        true,  "found",     "vulnerable Example Cloud" },
    { "gone",     DNS_LOOKUP_NOT_FOUND, false, "not_found", NULL                       },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    g_dnsAnswers[DNS_RECORD_TYPE_NS]   = (FakeDnsAnswer_t){ DNS_ANSWER_NXDOMAIN, 0, false };
    g_dnsAnswers[DNS_RECORD_TYPE_MX]   = (FakeDnsAnswer_t){ DNS_ANSWER_NXDOMAIN, 0, false };
    g_dnsAnswers[DNS_RECORD_TYPE_A]    = (FakeDnsAnswer_t){ DNS_ANSWER_NXDOMAIN, 0, false };
    g_dnsAnswers[DNS_RECORD_TYPE_AAAA] = (FakeDnsAnswer_t){ DNS_ANSWER_NXDOMAIN, 0, false };
    g_takeoverStatus   = cases[c].m_takeoverStatus;
    g_hasTakeoverChain = cases[c].m_hasTakeoverChain;

    TEST_ASSERT_TRUE_MESSAGE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_dnsRecordCallCount, cases[c].mp_name);
    const RecordedDnsScan_t* recorded = &g_dnsRecords[0];
    TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[DNS_KIND_DNS_PRESENCE], cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].mp_presence, recorded->ma_valueTexts[DNS_KIND_DNS_PRESENCE], cases[c].mp_name);
    TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[DNS_KIND_IP_ADDRESS_REACHABILITY], cases[c].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("empty", recorded->ma_valueTexts[DNS_KIND_IP_ADDRESS_REACHABILITY], cases[c].mp_name);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].mp_takeover != NULL, recorded->ma_hasValue[DNS_KIND_CNAME_TAKEOVER], cases[c].mp_name);
    if (cases[c].mp_takeover != NULL)
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].mp_takeover, recorded->ma_valueTexts[DNS_KIND_CNAME_TAKEOVER], cases[c].mp_name);
    static_assertEverythingFreed();
  }
}

void test_scanNextDnsDomains_sends_an_address_list_of_the_value_max_len(void)
{
  static char long_a[] = "93.184.216.34";
  static char short_a[] = "93.184.216.3";
  static DnsRecordText_t texts[147];
  static char expected[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 2];
  for (int extra = 0; extra < 2; extra++)
  {
    setUp();
    size_t len = 0;
    for (int i = 0; i < 147; i++)
    {
      char* address = i < 138 + extra ? long_a : short_a;
      texts[i] = (DnsRecordText_t){ address, strlen(address) };
      len += (size_t)snprintf(expected + len, sizeof(expected) - len, "%s%s", i > 0 ? "," : "", address);
    }
    TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_VALUE_MAX_LEN + (size_t)extra, len);
    static_queueOneClaim(static_claim("a.example.com", "u1"));
    g_dnsAnswers[DNS_RECORD_TYPE_A].m_recordCount = 147;
    g_aTextsOverride = texts;
    TEST_ASSERT_TRUE(watchlist_dns_lookup_scanNextDomains(FAKE_CONN));
    TEST_ASSERT_EQUAL_INT(1, g_dnsRecordCallCount);
    TEST_ASSERT_EQUAL(extra == 0, g_dnsRecords[0].m_hasHostingIpAddresses);
    TEST_ASSERT_EQUAL_STRING(extra == 0 ? expected : "", g_dnsRecords[0].ma_hostingIpAddresses);
    static_assertEverythingFreed();
  }
}

static void static_setProbeResult(int n, int days_remaining, const char* valid_until, unsigned int problems, const char* protocol,
                                  const char* sha1_hex, const char* sha256_hex)
{
  TlsProbeResult_t* result = &g_probeResults[n];
  memset(result, 0, sizeof(*result));
  result->m_daysRemaining = days_remaining;
  snprintf(result->m_serverCertificate.ma_validUntil, sizeof(result->m_serverCertificate.ma_validUntil), "%s", valid_until);
  result->m_problems = problems;
  snprintf(result->ma_protocol, sizeof(result->ma_protocol), "%s", protocol);
  snprintf(result->m_serverCertificate.ma_sha1Hex, sizeof(result->m_serverCertificate.ma_sha1Hex), "%s", sha1_hex);
  snprintf(result->m_serverCertificate.ma_sha256Hex, sizeof(result->m_serverCertificate.ma_sha256Hex), "%s", sha256_hex);
}

#define TEST_SHA1_A   "1111111111111111111111111111111111111111"
#define TEST_SHA1_B   "2222222222222222222222222222222222222222"
#define TEST_SHA256_A "3333333333333333333333333333333333333333333333333333333333333333"
#define TEST_SHA256_B "4444444444444444444444444444444444444444444444444444444444444444"

void test_scanNextTlsDomains_probes_each_claimed_domain_and_records_four_values(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "2026-10-30 09:00:00.1+00"),
    static_claim("b.example.org", "2026-10-30 09:00:00.2+00"),
  };
  static_queueClaims(DB_OK, 2, claims);
  static_setProbeResult(0, 5, "2026-11-04T08:00:00Z", TLSPROBE_PROBLEM_HOSTNAME_MISMATCH | TLSPROBE_PROBLEM_SELF_SIGNED, "TLSv1.2", TEST_SHA1_A, TEST_SHA256_A);
  static_setProbeResult(1, 90, "2027-01-28T08:00:00Z", 0, "TLSv1.3", TEST_SHA1_B, TEST_SHA256_B);
  g_sslcheckListingReasons[0] = "Dridex C&C";
  g_sslcheckListingReasons[1] = "";

  TEST_ASSERT_TRUE(watchlist_ssl_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_claimCallCount);
  TEST_ASSERT_EQUAL_STRING("tls", g_claimLaneNames[0]);
  TEST_ASSERT_EQUAL_STRING("tls", g_claimLaneNames[1]);
  TEST_ASSERT_EQUAL_INT(2, g_quotaCallCount);
  TEST_ASSERT_EQUAL_STRING("domain_scan_tls", g_lastQuotaRule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(86400, g_lastQuotaRule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(20000, g_lastQuotaRule.m_callLimit);
  TEST_ASSERT_TRUE(g_isEveryClaimOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryQuotaOnFakeConn);
  TEST_ASSERT_TRUE(g_isEverySslcheckOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryTlsRecordOnFakeConn);
  TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_dnsRecordCallCount);

  TEST_ASSERT_EQUAL_INT(2, g_probeCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_sslcheckCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_tlsRecordCallCount);
  static const char* const sha1s[2] = { TEST_SHA1_A, TEST_SHA1_B };
  static const char* const texts[2][FAKE_TLS_KIND_COUNT] = {
    { "7\n2026-11-04T08:00:00Z",    "self_signed\nhostname_mismatch", "listed\nDridex C&C", "TLSv1.2" },
    { "none\n2027-01-28T08:00:00Z", "valid",                          "not_listed",         "TLSv1.3" },
  };
  for (int d = 0; d < 2; d++)
  {
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_domain, g_probeHostnames[d]);
    TEST_ASSERT_EQUAL_STRING(sha1s[d], g_sslcheckSha1s[d]);

    const RecordedTlsScan_t* recorded = &g_tlsRecords[d];
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_domain, recorded->ma_domain);
    TEST_ASSERT_EQUAL_STRING(claims[d].ma_claimedUntil, recorded->ma_claimedUntil);
    for (int kind = 0; kind < FAKE_TLS_KIND_COUNT; kind++)
    {
      TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[kind], texts[d][kind]);
      TEST_ASSERT_EQUAL_STRING(texts[d][kind], recorded->ma_valueTexts[kind]);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(WATCHLIST_DOMAIN_SHA256_HEX_LEN, strlen(recorded->ma_valueSha256s[kind]), texts[d][kind]);
      for (int other = 0; other < kind; other++)
        TEST_ASSERT_TRUE_MESSAGE(strcmp(recorded->ma_valueSha256s[kind], recorded->ma_valueSha256s[other]) != 0, texts[d][kind]);
    }
  }
}

void test_scanNextTlsDomains_claim_with_no_domain_ends_the_run(void)
{
  TEST_ASSERT_TRUE(watchlist_ssl_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_probeCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_tlsRecordCallCount);
}

void test_scanNextTlsDomains_failed_claim_fails_the_run(void)
{
  static_queueClaims(DB_ERROR, 0, NULL);

  TEST_ASSERT_FALSE(watchlist_ssl_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_probeCallCount);
}

void test_scanNextTlsDomains_quota_refusal_ends_the_run_with_nothing_written(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
  };
  static const struct {
    QuotaStatus_t ma_statuses[2];
    bool          m_isRunOk;
    int           m_scanCount;
  } cases[] = {
    { { QUOTA_EXHAUSTED, QUOTA_GRANTED },   true,  0 },
    { { QUOTA_ERROR,     QUOTA_GRANTED },   false, 0 },
    { { QUOTA_GRANTED,   QUOTA_EXHAUSTED }, true,  1 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    static_queueClaims(DB_OK, 2, claims);
    static_setProbeResult(0, 40, "2026-12-09T00:00:00Z", 0, "TLSv1.3", TEST_SHA1_A, TEST_SHA256_A);
    g_quotaStatuses[0] = cases[c].ma_statuses[0];
    g_quotaStatuses[1] = cases[c].ma_statuses[1];
    g_quotaStatusCount = 2;
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_isRunOk, watchlist_ssl_check_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount + 1, g_quotaCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_probeCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_sslcheckCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_tlsRecordCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_claimCallCount, message);
  }
}

void test_scanNextTlsDomains_failed_probe_records_no_value(void)
{
  static const TlsProbeStatus_t statuses[] = {
    TLSPROBE_INVALID_NAME, TLSPROBE_NAME_NOT_FOUND, TLSPROBE_RESOLVE_FAILED, TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE,
    TLSPROBE_CONNECT_FAILED, TLSPROBE_TIMEOUT, TLSPROBE_HANDSHAKE_FAILED, TLSPROBE_NO_MEMORY,
  };
  for (size_t c = 0; c < sizeof(statuses) / sizeof(statuses[0]); c++)
  {
    setUp();
    const WatchlistDomainScanClaim_t claim = static_claim("a.example.com", "2026-10-30 09:00:00.3+00");
    static_queueClaims(DB_OK, 1, &claim);
    static_setProbeResult(0, 3, "2026-11-02T00:00:00Z", TLSPROBE_PROBLEM_EXPIRED, "TLSv1", TEST_SHA1_A, TEST_SHA256_A);
    g_probeStatuses[0] = statuses[c];
    char message[16] = "";
    snprintf(message, sizeof(message), "status %d", (int)statuses[c]);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_probeCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_sslcheckCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_tlsRecordCallCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("a.example.com", g_tlsRecords[0].ma_domain, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-30 09:00:00.3+00", g_tlsRecords[0].ma_claimedUntil, message);
    for (int kind = 0; kind < FAKE_TLS_KIND_COUNT; kind++)
      TEST_ASSERT_FALSE_MESSAGE(g_tlsRecords[0].ma_hasValue[kind], message);
  }
}

void test_scanNextTlsDomains_unread_list_leaves_out_only_the_listing(void)
{
  static const struct {
    DbStatus_t  m_status;
    bool        m_isFeedLoaded;
    bool        m_hasListing;
  } cases[] = {
    { DB_ERROR, true,  false },
    { DB_OK,    false, false },
    { DB_OK,    true,  true  },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    const WatchlistDomainScanClaim_t claim = static_claim("a.example.com", "u1");
    static_queueClaims(DB_OK, 1, &claim);
    static_setProbeResult(0, 2, "2026-11-01T06:00:00Z", TLSPROBE_PROBLEM_CHAIN_INCOMPLETE, "TLSv1.1", TEST_SHA1_A, TEST_SHA256_A);
    g_sslcheckStatus           = cases[c].m_status;
    g_isSslcheckFeedLoaded     = cases[c].m_isFeedLoaded;
    g_sslcheckListingReasons[0] = "";
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_sslcheckCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_tlsRecordCallCount, message);
    const RecordedTlsScan_t* recorded = &g_tlsRecords[0];
    TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[TLS_KIND_CERTIFICATE_EXPIRY], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("7\n2026-11-01T06:00:00Z", recorded->ma_valueTexts[TLS_KIND_CERTIFICATE_EXPIRY], message);
    TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[TLS_KIND_CERTIFICATE_VALIDITY], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("chain_incomplete", recorded->ma_valueTexts[TLS_KIND_CERTIFICATE_VALIDITY], message);
    TEST_ASSERT_TRUE_MESSAGE(recorded->ma_hasValue[TLS_KIND_TLS_PROTOCOL], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("TLSv1.1", recorded->ma_valueTexts[TLS_KIND_TLS_PROTOCOL], message);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_hasListing, recorded->ma_hasValue[TLS_KIND_CERTIFICATE_LISTING], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].m_hasListing ? "not_listed" : "", recorded->ma_valueTexts[TLS_KIND_CERTIFICATE_LISTING], message);
  }
}

void test_scanNextTlsDomains_probe_with_no_end_and_no_protocol_leaves_out_only_those_kinds(void)
{
  const WatchlistDomainScanClaim_t claim = static_claim("a.example.com", "u1");
  static_queueClaims(DB_OK, 1, &claim);
  static_setProbeResult(0, 2, "", TLSPROBE_PROBLEM_CHAIN_INCOMPLETE, "", TEST_SHA1_A, TEST_SHA256_A);
  g_sslcheckStatus            = DB_OK;
  g_isSslcheckFeedLoaded      = true;
  g_sslcheckListingReasons[0] = "";

  TEST_ASSERT_TRUE(watchlist_ssl_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_tlsRecordCallCount);
  const RecordedTlsScan_t* recorded = &g_tlsRecords[0];
  TEST_ASSERT_FALSE(recorded->ma_hasValue[TLS_KIND_CERTIFICATE_EXPIRY]);
  TEST_ASSERT_TRUE(recorded->ma_hasValue[TLS_KIND_CERTIFICATE_VALIDITY]);
  TEST_ASSERT_EQUAL_STRING("chain_incomplete", recorded->ma_valueTexts[TLS_KIND_CERTIFICATE_VALIDITY]);
  TEST_ASSERT_TRUE(recorded->ma_hasValue[TLS_KIND_CERTIFICATE_LISTING]);
  TEST_ASSERT_EQUAL_STRING("not_listed", recorded->ma_valueTexts[TLS_KIND_CERTIFICATE_LISTING]);
  TEST_ASSERT_FALSE(recorded->ma_hasValue[TLS_KIND_TLS_PROTOCOL]);
}

void test_scanNextTlsDomains_failed_record_fails_the_run(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_tlsRecordStatus = DB_ERROR;

  TEST_ASSERT_FALSE(watchlist_ssl_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_tlsRecordCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_probeCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
}

void test_scanNextTlsDomains_stops_when_the_run_deadline_passes(void)
{
  const WatchlistDomainScanClaim_t four[4] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
    static_claim("c.example.com", "u3"), static_claim("d.example.com", "u4"),
  };
  static const struct {
    int64_t m_probeMs;
    int     ma_claimCounts[2];
    int     m_scanCount;
    int     m_claimCallCount;
  } cases[] = {
    { 15000, { 4, 0 }, 2, 1 },
    { 15000, { 2, 2 }, 2, 1 },
    { 14999, { 2, 1 }, 3, 2 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_probeAdvanceMs = cases[c].m_probeMs;
    static_queueClaims(DB_OK, cases[c].ma_claimCounts[0], four);
    if (cases[c].ma_claimCounts[1] > 0)
      static_queueClaims(DB_OK, cases[c].ma_claimCounts[1], four);
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_ssl_check_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_tlsRecordCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_probeCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_claimCallCount, g_claimCallCount, message);
  }
}

static void static_setRegistration(int n, const char* expires_at)
{
  RdapRegistration_t* registration = &g_registryAskRegistrations[n];
  memset(registration, 0, sizeof(*registration));
  snprintf(registration->ma_expiresAt, sizeof(registration->ma_expiresAt), "%s", expires_at);
  registration->m_registrarIanaId = 292;
  snprintf(registration->ma_registrarName, sizeof(registration->ma_registrarName), "%s", "MarkMonitor Inc.");
  snprintf(registration->ma_statuses[0], sizeof(registration->ma_statuses[0]), "%s", "serverTransferProhibited");
  snprintf(registration->ma_statuses[1], sizeof(registration->ma_statuses[1]), "%s", "active");
  snprintf(registration->ma_statuses[2], sizeof(registration->ma_statuses[2]), "%s", "client transfer prohibited");
  registration->m_statusCount      = 3;
  registration->m_delegationSigned = RDAP_DELEGATION_SIGNED_YES;
}

static void static_assertNoValue(int n, unsigned int retry_after_seconds, const char* message)
{
  for (int kind = 0; kind < FAKE_RDAP_WHOIS_KIND_COUNT; kind++)
    TEST_ASSERT_FALSE_MESSAGE(g_rdapWhoisRecords[n].ma_hasValue[kind], message);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(retry_after_seconds, g_rdapWhoisRecords[n].m_retryAfterSeconds, message);
}

void test_scanNextRdapWhoisDomains_records_the_four_values_of_a_registration(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("example.com", "2026-10-31 09:00:00.1+00"),
    static_claim("example.org", "2026-10-31 09:00:00.2+00"),
  };
  static_queueClaims(DB_OK, 2, claims);
  static_setRegistration(0, "2026-11-20T04:00:00Z");
  static_setRegistration(1, "2027-01-29");
  g_registryAskRegistrations[1].m_registrarIanaId  = -1;
  g_registryAskRegistrations[1].m_statusCount      = 1;
  g_registryAskRegistrations[1].m_delegationSigned = RDAP_DELEGATION_SIGNED_NO;

  TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_claimCallCount);
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_LANE_RDAP_WHOIS, g_claimLaneNames[0]);
  TEST_ASSERT_EQUAL_STRING("rdap_whois", g_claimLaneNames[1]);
  TEST_ASSERT_EQUAL_STRING("FARFAR", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_STRING("example.com", g_findDomains[0]);
  TEST_ASSERT_EQUAL_STRING("example.org", g_findDomains[1]);
  TEST_ASSERT_EQUAL_STRING("example.com", g_registryAskDomains[0]);
  TEST_ASSERT_EQUAL_STRING("example.org", g_registryAskDomains[1]);
  TEST_ASSERT_EQUAL_STRING(FAKE_RDAP_BASE_URL, g_registryAskServerBaseUrls[0]);

  TEST_ASSERT_EQUAL_INT(2, g_rdapWhoisRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("example.com", g_rdapWhoisRecords[0].ma_domain);
  TEST_ASSERT_EQUAL_STRING("2026-10-31 09:00:00.1+00", g_rdapWhoisRecords[0].ma_claimedUntil);
  TEST_ASSERT_EQUAL_STRING("30\n2026-11-20T04:00:00Z", g_rdapWhoisRecords[0].ma_valueTexts[RDAP_WHOIS_KIND_REGISTRATION_EXPIRY]);
  TEST_ASSERT_EQUAL_STRING("292\nMarkMonitor Inc.", g_rdapWhoisRecords[0].ma_valueTexts[RDAP_WHOIS_KIND_REGISTRAR]);
  TEST_ASSERT_EQUAL_STRING("client transfer prohibited\nserver transfer prohibited", g_rdapWhoisRecords[0].ma_valueTexts[RDAP_WHOIS_KIND_TRANSFER_LOCK]);
  TEST_ASSERT_EQUAL_STRING("signed", g_rdapWhoisRecords[0].ma_valueTexts[RDAP_WHOIS_KIND_DNSSEC_DELEGATION]);
  TEST_ASSERT_EQUAL_UINT(0, g_rdapWhoisRecords[0].m_retryAfterSeconds);
  TEST_ASSERT_EQUAL_STRING("example.org", g_rdapWhoisRecords[1].ma_domain);
  TEST_ASSERT_EQUAL_STRING("2026-10-31 09:00:00.2+00", g_rdapWhoisRecords[1].ma_claimedUntil);
  TEST_ASSERT_EQUAL_STRING("none\n2027-01-29", g_rdapWhoisRecords[1].ma_valueTexts[RDAP_WHOIS_KIND_REGISTRATION_EXPIRY]);
  TEST_ASSERT_EQUAL_STRING("-\nMarkMonitor Inc.", g_rdapWhoisRecords[1].ma_valueTexts[RDAP_WHOIS_KIND_REGISTRAR]);
  TEST_ASSERT_EQUAL_STRING("server transfer prohibited", g_rdapWhoisRecords[1].ma_valueTexts[RDAP_WHOIS_KIND_TRANSFER_LOCK]);
  TEST_ASSERT_EQUAL_STRING("unsigned", g_rdapWhoisRecords[1].ma_valueTexts[RDAP_WHOIS_KIND_DNSSEC_DELEGATION]);
  for (int n = 0; n < 2; n++)
    for (int kind = 0; kind < FAKE_RDAP_WHOIS_KIND_COUNT; kind++)
      TEST_ASSERT_TRUE(g_rdapWhoisRecords[n].ma_hasValue[kind]);

  TEST_ASSERT_TRUE(g_isEveryClaimOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryRegistryAskOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryRdapWhoisRecordOnFakeConn);
  TEST_ASSERT_EQUAL_INT(0, g_tlsRecordCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_probeCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_usageEventCount);
}

void test_scanNextRdapWhoisDomains_quota_refusal_ends_the_run_with_nothing_written(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("example.com", "u1"), static_claim("example.org", "u2"),
  };
  static const struct {
    RegistryAskStatus_t ma_statuses[2];
    const char*         mp_callOrder;
    int                 m_recordCount;
  } cases[] = {
    { { REGISTRYASK_DAILY_QUOTA_EXHAUSTED, REGISTRYASK_OK                    }, "FA",    0 },
    { { REGISTRYASK_OK,                    REGISTRYASK_DAILY_QUOTA_EXHAUSTED }, "FARFA", 1 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_nowEpoch = FAKE_NOW_EPOCH + (time_t)(100 + c) * 86400;
    static_queueClaims(DB_OK, 2, claims);
    g_registryAskStatuses[0] = cases[c].ma_statuses[0];
    g_registryAskStatuses[1] = cases[c].ma_statuses[1];

    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN), cases[c].mp_callOrder);

    TEST_ASSERT_EQUAL_STRING(cases[c].mp_callOrder, g_callOrder);
    TEST_ASSERT_EQUAL_INT(cases[c].m_recordCount, g_rdapWhoisRecordCallCount);
    TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  }
}

void test_scanNextRdapWhoisDomains_unavailable_server_defers_with_its_wait(void)
{
  static const unsigned int waits[][2] = {
    { 0, 1 }, { 1, 1 }, { 2, 2 }, { 3599, 3599 }, { 3600, 3600 }, { 3601, 3600 }, { 7200, 3600 },
  };
  for (size_t c = 0; c < sizeof(waits) / sizeof(waits[0]); c++)
  {
    setUp();
    const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
    static_queueClaims(DB_OK, 1, &claim);
    static_setRegistration(0, "2026-11-20");
    g_registryAskStatuses[0] = REGISTRYASK_UNAVAILABLE;
    g_registryAskRetries[0]  = waits[c][0];
    char message[24] = "";
    snprintf(message, sizeof(message), "wait %u", waits[c][0]);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_rdapWhoisRecordCallCount, message);
    static_assertNoValue(0, waits[c][1], message);
  }
}

void test_scanNextRdapWhoisDomains_not_registered_and_upstream_error_record_no_value(void)
{
  static const RegistryAskStatus_t statuses[] = { REGISTRYASK_NOT_REGISTERED, REGISTRYASK_INVALID_NAME, REGISTRYASK_UPSTREAM_ERROR };
  for (size_t c = 0; c < sizeof(statuses) / sizeof(statuses[0]); c++)
  {
    setUp();
    const WatchlistDomainScanClaim_t claim = static_claim("example.com", "2026-10-31 09:00:00.3+00");
    static_queueClaims(DB_OK, 1, &claim);
    static_setRegistration(0, "2026-11-20");
    g_registryAskStatuses[0] = statuses[c];
    g_registryAskRetries[0]  = 30;
    char message[16] = "";
    snprintf(message, sizeof(message), "status %d", (int)statuses[c]);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_rdapWhoisRecordCallCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", g_rdapWhoisRecords[0].ma_domain, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-31 09:00:00.3+00", g_rdapWhoisRecords[0].ma_claimedUntil, message);
    static_assertNoValue(0, 0, message);
  }
}

void test_scanNextRdapWhoisDomains_name_without_a_registry_server_records_no_value_and_asks_nothing(void)
{
  const WatchlistDomainScanClaim_t claim = static_claim("example.zz", "u1");
  static_queueClaims(DB_OK, 1, &claim);
  g_isServerFound = false;

  TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("FR", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_registryAskCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_rdapWhoisRecordCallCount);
  static_assertNoValue(0, 0, "no server");
}

void test_scanNextRdapWhoisDomains_db_error_of_the_ask_fails_the_run_with_no_record(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("example.com", "u1"), static_claim("example.org", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_registryAskStatuses[0] = REGISTRYASK_DB_ERROR;

  TEST_ASSERT_FALSE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("FA", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_rdapWhoisRecordCallCount);
}

void test_scanNextRdapWhoisDomains_passes_the_watchlist_scan_rules(void)
{
  const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
  static_queueClaims(DB_OK, 1, &claim);

  TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_registryAskCallCount);
  TEST_ASSERT_TRUE(g_registryAskThrottleRules[0] == &registryask_watchlistScanThrottleRules);
  TEST_ASSERT_NOT_NULL(g_registryAskDailyQuotaRules[0]);
  TEST_ASSERT_EQUAL_STRING("domain_scan_rdap_whois", g_registryAskDailyQuotaRules[0]->mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(86400,                      g_registryAskDailyQuotaRules[0]->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(10000,                      g_registryAskDailyQuotaRules[0]->m_callLimit);
}

void test_scanNextRdapWhoisDomains_passes_the_clock_to_the_expiry_writer(void)
{
  static const struct {
    time_t      m_nowEpoch;
    const char* mp_text;
  } cases[] = {
    { 1796083200 - 30 * 86400, "30\n2026-12-01" },
    { 1796083200 - 31 * 86400, "none\n2026-12-01" },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_nowEpoch = cases[c].m_nowEpoch;
    const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
    static_queueClaims(DB_OK, 1, &claim);
    static_setRegistration(0, "2026-12-01");

    TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, g_rdapWhoisRecords[0].ma_valueTexts[RDAP_WHOIS_KIND_REGISTRATION_EXPIRY]);
  }
}

void test_scanNextRdapWhoisDomains_failed_record_fails_the_run(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("example.com", "u1"), static_claim("example.org", "u2"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_rdapWhoisRecordStatus = DB_ERROR;

  TEST_ASSERT_FALSE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("FAR", g_callOrder);
}

void test_scanNextRdapWhoisDomains_stops_when_the_run_deadline_passes(void)
{
  const WatchlistDomainScanClaim_t four[4] = {
    static_claim("a.example.com", "u1"), static_claim("b.example.com", "u2"),
    static_claim("c.example.com", "u3"), static_claim("d.example.com", "u4"),
  };
  static const struct {
    int64_t m_askMs;
    int     ma_claimCounts[2];
    int     m_scanCount;
    int     m_claimCallCount;
  } cases[] = {
    { 15000, { 4, 0 }, 2, 1 },
    { 14999, { 2, 1 }, 3, 2 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_registryAskAdvanceMs = cases[c].m_askMs;
    static_queueClaims(DB_OK, cases[c].ma_claimCounts[0], four);
    if (cases[c].ma_claimCounts[1] > 0)
      static_queueClaims(DB_OK, cases[c].ma_claimCounts[1], four);
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_rdapWhoisRecordCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_scanCount, g_registryAskCallCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_claimCallCount, g_claimCallCount, message);
  }
}

void test_scanNextRdapWhoisDomains_claim_with_no_domain_ends_the_run(void)
{
  TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_findCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_registryAskCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_rdapWhoisRecordCallCount);
}

void test_scanNextRdapWhoisDomains_failed_claim_fails_the_run(void)
{
  static_queueClaims(DB_ERROR, 0, NULL);

  TEST_ASSERT_FALSE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_claimCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
  TEST_ASSERT_EQUAL_STRING("", g_callOrder);
}

void test_scanNextRdapWhoisDomains_records_each_value_only_when_its_kind_has_one(void)
{
  static const struct {
    const char* mp_expiresAt;
    long        m_registrarIanaId;
    bool        ma_hasValue[FAKE_RDAP_WHOIS_KIND_COUNT];
    const char* ma_texts[FAKE_RDAP_WHOIS_KIND_COUNT];
  } cases[] = {
    { "",           -1,  { false, false, false, true  }, { NULL,               NULL,    NULL, "signed" } },
    { "2026-12-01", 292, { true,  true,  false, false }, { "none\n2026-12-01", "292\n", NULL, NULL     } },
    { "2026-12-01", -1,  { true,  false, false, false }, { "none\n2026-12-01", NULL,    NULL, NULL     } },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
    static_queueClaims(DB_OK, 1, &claim);
    RdapRegistration_t* registration = &g_registryAskRegistrations[0];
    memset(registration, 0, sizeof(*registration));
    snprintf(registration->ma_expiresAt, sizeof(registration->ma_expiresAt), "%s", cases[c].mp_expiresAt);
    registration->m_registrarIanaId  = cases[c].m_registrarIanaId;
    registration->m_delegationSigned = cases[c].ma_hasValue[RDAP_WHOIS_KIND_DNSSEC_DELEGATION] ? RDAP_DELEGATION_SIGNED_YES : RDAP_DELEGATION_SIGNED_UNKNOWN;
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);

    TEST_ASSERT_TRUE_MESSAGE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_rdapWhoisRecordCallCount, message);
    for (int kind = 0; kind < FAKE_RDAP_WHOIS_KIND_COUNT; kind++)
    {
      TEST_ASSERT_EQUAL_MESSAGE(cases[c].ma_hasValue[kind], g_rdapWhoisRecords[0].ma_hasValue[kind], message);
      if (cases[c].ma_texts[kind] != NULL)
        TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].ma_texts[kind], g_rdapWhoisRecords[0].ma_valueTexts[kind], message);
    }
  }
}

static void static_runOneHeadersScan(const char* message)
{
  static_queueOneClaim(static_claim("example.com", "h1"));
  TEST_ASSERT_TRUE_MESSAGE(watchlist_headers_check_scanNextDomains(FAKE_CONN), message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_headersRecordCallCount, message);
}

void test_scanNextHeadersDomains_fetches_robots_then_home_page_and_records_the_value(void)
{
  const WatchlistDomainScanClaim_t claims[2] = {
    static_claim("example.com", "2026-11-01 09:00:00.1+00"),
    static_claim("www.example.org", "2026-11-01 09:00:00.2+00"),
  };
  static_queueClaims(DB_OK, 2, claims);
  g_homeFetches[0] = (FakeFetch_t){ .m_status = 200, .mp_url = "https://www.example.com/", .mp_csp = "default-src 'self'",
                                    .mp_hsts = "max-age=31536000" };
  g_homeFetches[1] = (FakeFetch_t){ .m_status = 200, .mp_url = "https://www.example.org/" };

  TEST_ASSERT_TRUE(watchlist_headers_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_claimCallCount);
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_LANE_HEADERS, g_claimLaneNames[0]);
  TEST_ASSERT_EQUAL_STRING("headers", g_claimLaneNames[1]);
  TEST_ASSERT_EQUAL_STRING("TQBGRTQBGR", g_callOrder);
  TEST_ASSERT_EQUAL_STRING("domain_scan_headers", g_lastQuotaRule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(86400, g_lastQuotaRule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(20000, g_lastQuotaRule.m_callLimit);
  for (int n = 0; n < 2; n++)
  {
    TEST_ASSERT_EQUAL_STRING("headers_scan", g_throttleRules[n].mp_throttleRuleName);
    TEST_ASSERT_EQUAL_UINT(60, g_throttleRules[n].m_windowSeconds);
    TEST_ASSERT_EQUAL_UINT(10, g_throttleRules[n].m_chargeLimit);
    TEST_ASSERT_EQUAL_UINT(2, g_throttleCounts[n]);
  }
  TEST_ASSERT_EQUAL_STRING("example.com", g_throttleTargets[0]);
  TEST_ASSERT_EQUAL_STRING("example.org", g_throttleTargets[1]);
  TEST_ASSERT_EQUAL_STRING("example.com", g_robotsFetchHostnames[0]);
  TEST_ASSERT_EQUAL_STRING("www.example.org", g_robotsFetchHostnames[1]);
  TEST_ASSERT_EQUAL_STRING("example.com", g_homeFetchHostnames[0]);
  TEST_ASSERT_EQUAL_STRING("www.example.org", g_homeFetchHostnames[1]);

  TEST_ASSERT_EQUAL_INT(2, g_headersRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("example.com", g_headersRecords[0].ma_domain);
  TEST_ASSERT_EQUAL_STRING("2026-11-01 09:00:00.1+00", g_headersRecords[0].ma_claimedUntil);
  TEST_ASSERT_TRUE(g_headersRecords[0].m_hasValue);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/\ncontent-security-policy\nstrict-transport-security", g_headersRecords[0].ma_valueText);
  TEST_ASSERT_EQUAL_UINT(0, g_headersRecords[0].m_retryAfterSeconds);
  TEST_ASSERT_EQUAL_STRING("www.example.org", g_headersRecords[1].ma_domain);
  TEST_ASSERT_EQUAL_STRING("2026-11-01 09:00:00.2+00", g_headersRecords[1].ma_claimedUntil);
  TEST_ASSERT_TRUE(g_headersRecords[1].m_hasValue);
  TEST_ASSERT_EQUAL_STRING("https://www.example.org/", g_headersRecords[1].ma_valueText);
  TEST_ASSERT_EQUAL_INT(2, g_robotsTxtFreeCount);
  TEST_ASSERT_EQUAL_INT(2, g_fetchResultFreeCount);
  TEST_ASSERT_TRUE(g_isEveryClaimOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryQuotaOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryThrottleOnFakeConn);
  TEST_ASSERT_TRUE(g_isEveryHeadersRecordOnFakeConn);
  TEST_ASSERT_EQUAL_INT(0, g_usageEventCount);
}

void test_scanNextHeadersDomains_unparsed_robots_txt_fetches_no_home_page(void)
{
  setUp();
  g_isRobotsParseFailing = true;
  g_robotsFetches[0] = (FakeFetch_t){ .m_status = 200, .mp_body = FAKE_ROBOTS_ALLOW_ALL };
  g_homeFetches[0]   = (FakeFetch_t){ .m_status = 200, .mp_url = "https://example.com/", .mp_csp = "default-src 'self'" };
  static_runOneHeadersScan("parse fails");
  TEST_ASSERT_EQUAL_INT(1, g_robotsFetchCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_homeFetchCallCount);
  TEST_ASSERT_FALSE(g_headersRecords[0].m_hasValue);
}

void test_scanNextHeadersDomains_robots_txt_answer_decides_the_home_page_fetch(void)
{
  static char long_user_agent[2200];
  memset(long_user_agent, 0, sizeof(long_user_agent));
  memcpy(long_user_agent, "User-agent: ", 12);
  memset(long_user_agent + 12, 'a', 2100);
  memcpy(long_user_agent + 2112, "\nAllow: /\n", 10);

  static const struct {
    const char*  mp_name;
    HttpError_t  m_error;
    int          m_status;
    const char*  mp_body;
    bool         m_isHomePageFetched;
    bool         m_isBodyCut;
  } cases[] = {
    { "200 allow all",              HTTP_ERROR_NONE,    200, FAKE_ROBOTS_ALLOW_ALL,                                         true , false },
    { "299 empty",                  HTTP_ERROR_NONE,    299, "",                                                            true , false },
    { "200 disallow all",           HTTP_ERROR_NONE,    200, "User-agent: *\nDisallow: /\n",                                false, false },
    { "200 our group disallows",    HTTP_ERROR_NONE,    200, "User-agent: ContrastAPI\nDisallow: /\nUser-agent: *\nAllow: /\n", false, false },
    { "200 our group allows",       HTTP_ERROR_NONE,    200, "User-agent: ContrastAPI\nAllow: /\nUser-agent: *\nDisallow: /\n", true , false },
    { "200 other crawler only",     HTTP_ERROR_NONE,    200, "User-agent: OtherBot\nDisallow: /\n",                         true , false },
    { "200 dropped rule unknown",   HTTP_ERROR_NONE,    200, NULL,                                                          false, false },
    { "200 disallow all, uncut",    HTTP_ERROR_NONE,    200, "User-agent: *\nDisallow: /",                                  false, false },
    { "200 cut in its last line",   HTTP_ERROR_NONE,    200, "User-agent: *\nDisallow: /",                                  true,  true },
    { "400",                        HTTP_ERROR_NONE,    400, "bad",                                                         true , false },
    { "404",                        HTTP_ERROR_NONE,    404, "Disallow: /",                                                 true , false },
    { "499",                        HTTP_ERROR_NONE,    499, "",                                                            true , false },
    { "199",                        HTTP_ERROR_NONE,    199, "",                                                            false, false },
    { "300",                        HTTP_ERROR_NONE,    300, "",                                                            false, false },
    { "302 off the site",           HTTP_ERROR_NONE,    302, "",                                                            false, false },
    { "399",                        HTTP_ERROR_NONE,    399, "",                                                            false, false },
    { "500",                        HTTP_ERROR_NONE,    500, "",                                                            false, false },
    { "503",                        HTTP_ERROR_NONE,    503, "",                                                            false, false },
    { "timeout",                    HTTP_ERROR_TIMEOUT, 0,   NULL,                                                          false, false },
    { "connect",                    HTTP_ERROR_CONNECT, 0,   NULL,                                                          false, false },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_robotsFetches[0] = (FakeFetch_t){ .m_error = cases[c].m_error, .m_status = cases[c].m_status,
                                        .mp_body = cases[c].mp_body != NULL || cases[c].m_error != HTTP_ERROR_NONE ? cases[c].mp_body : long_user_agent,
                                        .m_isBodyCut = cases[c].m_isBodyCut };
    g_homeFetches[0] = (FakeFetch_t){ .m_status = 200, .mp_url = "https://example.com/", .mp_csp = "default-src 'self'" };

    static_runOneHeadersScan(cases[c].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_robotsFetchCallCount, cases[c].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_isHomePageFetched ? 1 : 0, g_homeFetchCallCount, cases[c].mp_name);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_isHomePageFetched, g_headersRecords[0].m_hasValue, cases[c].mp_name);
    if (cases[c].m_isHomePageFetched)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("https://example.com/\ncontent-security-policy", g_headersRecords[0].ma_valueText, cases[c].mp_name);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_headersRecords[0].m_retryAfterSeconds, cases[c].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_error == HTTP_ERROR_NONE ? 1 : 0, g_robotsTxtFreeCount, cases[c].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(g_homeFetchCallCount, g_fetchResultFreeCount, cases[c].mp_name);
  }
}

void test_scanNextHeadersDomains_only_a_2xx_home_page_gives_a_value(void)
{
  static const struct {
    HttpError_t m_error;
    int         m_status;
    bool        m_hasValue;
  } cases[] = {
    { HTTP_ERROR_NONE, 200, true  }, { HTTP_ERROR_NONE, 299, true  }, { HTTP_ERROR_NONE, 199, false }, { HTTP_ERROR_NONE, 301, false },
    { HTTP_ERROR_NONE, 404, false }, { HTTP_ERROR_NONE, 500, false }, { HTTP_ERROR_TLS,  0,   false },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    char message[32] = "";
    snprintf(message, sizeof(message), "case %zu", c);
    g_homeFetches[0] = (FakeFetch_t){ .m_error = cases[c].m_error, .m_status = cases[c].m_status, .mp_url = "https://example.com/" };

    static_runOneHeadersScan(message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_homeFetchCallCount, message);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_hasValue, g_headersRecords[0].m_hasValue, message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_headersRecords[0].m_retryAfterSeconds, message);
  }
}

void test_scanNextHeadersDomains_full_throttle_defers_without_a_request(void)
{
  static const unsigned int retries[]  = { 0, 42, 5000 };
  static const unsigned int expected[] = { 1, 42, 3600 };
  for (size_t c = 0; c < sizeof(retries) / sizeof(retries[0]); c++)
  {
    setUp();
    g_throttleStatuses[0] = THROTTLE_REFUSED;
    g_throttleRetries[0]  = retries[c];

    static_runOneHeadersScan("deferred");

    TEST_ASSERT_EQUAL_STRING("TR", g_callOrder);
    TEST_ASSERT_EQUAL_INT(0, g_quotaCallCount);
    TEST_ASSERT_FALSE(g_headersRecords[0].m_hasValue);
    TEST_ASSERT_EQUAL_UINT(expected[c], g_headersRecords[0].m_retryAfterSeconds);
  }
}

void test_scanNextHeadersDomains_failed_throttle_fails_the_run_with_no_record(void)
{
  static_queueOneClaim(static_claim("example.com", "h1"));
  g_throttleStatuses[0] = THROTTLE_ERROR;

  TEST_ASSERT_FALSE(watchlist_headers_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("T", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_headersRecordCallCount);
}

void test_scanNextHeadersDomains_quota_refusal_ends_the_run_with_nothing_written(void)
{
  static_queueOneClaim(static_claim("example.com", "h1"));
  g_quotaStatuses[0] = QUOTA_EXHAUSTED;
  g_quotaStatusCount = 1;

  TEST_ASSERT_TRUE(watchlist_headers_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("TQ", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_headersRecordCallCount);
}

void test_scanNextHeadersDomains_name_that_is_not_public_is_asked_nothing(void)
{
  static_queueOneClaim(static_claim("example.local", "h1"));

  TEST_ASSERT_TRUE(watchlist_headers_check_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("R", g_callOrder);
  TEST_ASSERT_FALSE(g_headersRecords[0].m_hasValue);
  TEST_ASSERT_EQUAL_UINT(0, g_headersRecords[0].m_retryAfterSeconds);
}

void test_scanNextHeadersDomains_failed_record_fails_the_run(void)
{
  static_queueOneClaim(static_claim("example.com", "h1"));
  g_headersRecordStatus = DB_ERROR;

  TEST_ASSERT_FALSE(watchlist_headers_check_scanNextDomains(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_headersRecordCallCount);
}

static void static_runOneCtScan(const char* host, const char* message)
{
  static_queueOneClaim(static_claim(host, "c1"));
  TEST_ASSERT_TRUE_MESSAGE(watchlist_cert_search_scanNextDomains(FAKE_CONN), message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_ctRecordCallCount, message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_openAnswerCount, message);
}

void test_scanNextCtDomains_reads_the_hold_walks_with_the_scanner_rule_and_records_the_value(void)
{
  static_queueOneClaim(static_claim("www.example.com", "2026-11-01 09:00:00.3+00"));

  TEST_ASSERT_TRUE(watchlist_cert_search_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(2, g_claimCallCount);
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_LANE_CT, g_claimLaneNames[0]);
  TEST_ASSERT_EQUAL_STRING("ct", g_claimLaneNames[1]);
  TEST_ASSERT_EQUAL_STRING("HQCR", g_callOrder);
  TEST_ASSERT_EQUAL_STRING("certspotter", g_holdReadName);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_ctHosts[0]);
  TEST_ASSERT_EQUAL_STRING("domain_scan_ct", g_lastQuotaRule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, g_lastQuotaRule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(20, g_lastQuotaRule.m_callLimit);
  TEST_ASSERT_TRUE(g_isEveryQuotaOnFakeConn);
  TEST_ASSERT_EQUAL_INT(1, g_dnsAskCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_dnsAskCalls[0].m_questionCount);
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS, g_dnsAskCalls[0].m_deadlineMs);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_dnsAskCalls[0].ma_names[0]);
  TEST_ASSERT_EQUAL_STRING("example.com", g_dnsAskCalls[0].ma_names[1]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_CAA, g_dnsAskCalls[0].ma_types[0]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_CAA, g_dnsAskCalls[0].ma_types[1]);
  TEST_ASSERT_EQUAL_INT(0, g_openAnswerCount);
  TEST_ASSERT_EQUAL_INT(1, g_ctRecordCallCount);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_ctRecords[0].ma_domain);
  TEST_ASSERT_EQUAL_STRING("2026-11-01 09:00:00.3+00", g_ctRecords[0].ma_claimedUntil);
  TEST_ASSERT_TRUE(g_ctRecords[0].m_hasValue);
  TEST_ASSERT_EQUAL_STRING("new_issuer letsencrypt.org", g_ctRecords[0].ma_valueText);
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_SHA256_HEX_LEN, strlen(g_ctRecords[0].ma_valueSha256));
  TEST_ASSERT_EQUAL_UINT(0, g_ctRecords[0].m_retryAfterSeconds);
}

void test_scanNextCtDomains_caa_climb_takes_the_first_name_with_records(void)
{
  DnsCaaRecord_t parent_records[] = { { 0, { (char*)"issue", 5 }, { (char*)"pki.goog", 8 } } };
  DnsCaaRecord_t host_records[]   = { { 0, { (char*)"issue", 5 }, { (char*)"letsencrypt.org", 15 } } };

  g_caaNames[0] = (FakeCaaName_t){ "b.example.com", DNS_ANSWER_NXDOMAIN, NULL, 0 };
  g_caaNames[1] = (FakeCaaName_t){ "example.com", DNS_ANSWER_OK, parent_records, 1 };
  g_caaNameCount = 2;
  static_runOneCtScan("a.b.example.com", "parent set");
  TEST_ASSERT_EQUAL_INT(3, g_dnsAskCalls[0].m_questionCount);
  TEST_ASSERT_EQUAL_STRING("a.b.example.com", g_dnsAskCalls[0].ma_names[0]);
  TEST_ASSERT_EQUAL_STRING("b.example.com", g_dnsAskCalls[0].ma_names[1]);
  TEST_ASSERT_EQUAL_STRING("example.com", g_dnsAskCalls[0].ma_names[2]);
  TEST_ASSERT_EQUAL_STRING("caa_mismatch letsencrypt.org", g_ctRecords[0].ma_valueText);

  setUp();
  g_caaNames[0] = (FakeCaaName_t){ "a.b.example.com", DNS_ANSWER_OK, host_records, 1 };
  g_caaNames[1] = (FakeCaaName_t){ "example.com", DNS_ANSWER_OK, parent_records, 1 };
  g_caaNameCount = 2;
  static_runOneCtScan("a.b.example.com", "host set");
  TEST_ASSERT_EQUAL_STRING("new_issuer letsencrypt.org", g_ctRecords[0].ma_valueText);

  setUp();
  g_caaNames[0] = (FakeCaaName_t){ "example.com", DNS_ANSWER_OK, parent_records, 1 };
  g_caaNameCount = 1;
  static_runOneCtScan("example.com", "registered domain");
  TEST_ASSERT_EQUAL_INT(1, g_dnsAskCalls[0].m_questionCount);
  TEST_ASSERT_EQUAL_STRING("caa_mismatch letsencrypt.org", g_ctRecords[0].ma_valueText);
}

void test_scanNextCtDomains_wildcard_issuer_reads_the_set_of_the_parent(void)
{
  DnsCaaRecord_t host_records[]   = { { 0, { (char*)"issue", 5 }, { (char*)"pki.goog", 8 } } };
  DnsCaaRecord_t parent_records[] = { { 0, { (char*)"issue", 5 }, { (char*)"letsencrypt.org", 15 } } };
  static const struct {
    const char*       mp_host;
    DnsAnswerStatus_t m_hostStatus;
    DnsAnswerStatus_t m_parentStatus;
    bool              m_isExact;
    bool              m_isWildcard;
    bool              m_hasValue;
  } cases[] = {
    { "www.example.com", DNS_ANSWER_OK,           DNS_ANSWER_OK,           false, true,  true  },
    { "www.example.com", DNS_ANSWER_SERVER_ERROR, DNS_ANSWER_OK,           false, true,  true  },
    { "www.example.com", DNS_ANSWER_OK,           DNS_ANSWER_SERVER_ERROR, false, true,  false },
    { "example.com",     DNS_ANSWER_OK,           DNS_ANSWER_OK,           false, true,  true  },
    { "www.example.com", DNS_ANSWER_SERVER_ERROR, DNS_ANSWER_OK,           false, false, false },
    { "www.example.com", DNS_ANSWER_SERVER_ERROR, DNS_ANSWER_OK,           true,  true,  false },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_ctList.ma_issuers[0].m_isSeenOnExactName    = cases[c].m_isExact;
    g_ctList.ma_issuers[0].m_isSeenOnWildcardName = cases[c].m_isWildcard;
    bool is_registered = strcmp(cases[c].mp_host, "example.com") == 0;
    g_caaNames[0] = (FakeCaaName_t){ cases[c].mp_host, cases[c].m_hostStatus, host_records, cases[c].m_hostStatus == DNS_ANSWER_OK ? 1 : 0 };
    g_caaNames[1] = (FakeCaaName_t){ "example.com", cases[c].m_parentStatus, parent_records, cases[c].m_parentStatus == DNS_ANSWER_OK ? 1 : 0 };
    g_caaNameCount = is_registered ? 1 : 2;
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);
    static_runOneCtScan(cases[c].mp_host, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_dnsAskCallCount, message);
    TEST_ASSERT_EQUAL_MESSAGE(cases[c].m_hasValue, g_ctRecords[0].m_hasValue, message);
    if (cases[c].m_hasValue)
      TEST_ASSERT_EQUAL_STRING_MESSAGE("new_issuer letsencrypt.org", g_ctRecords[0].ma_valueText, message);
  }
}

void test_scanNextCtDomains_caa_failure_before_the_set_gives_no_value(void)
{
  DnsCaaRecord_t host_records[] = { { 0, { (char*)"issue", 5 }, { (char*)"letsencrypt.org", 15 } } };
  static const DnsAnswerStatus_t failures[] = { DNS_ANSWER_SERVER_ERROR, DNS_ANSWER_TIMEOUT, DNS_ANSWER_TRUNCATED, DNS_ANSWER_MALFORMED,
                                                DNS_ANSWER_NO_MEMORY, DNS_ANSWER_NO_RESOLVER, DNS_ANSWER_NOT_PUBLIC_NAME };
  for (size_t f = 0; f < sizeof(failures) / sizeof(failures[0]); f++)
  {
    setUp();
    g_caaNames[0] = (FakeCaaName_t){ "www.example.com", failures[f], NULL, 0 };
    g_caaNameCount = 1;
    static_runOneCtScan("www.example.com", "host failed");
    TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);

    setUp();
    g_caaNames[0] = (FakeCaaName_t){ "example.com", failures[f], NULL, 0 };
    g_caaNameCount = 1;
    static_runOneCtScan("www.example.com", "parent failed");
    TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);
  }

  setUp();
  g_caaNames[0] = (FakeCaaName_t){ "www.example.com", DNS_ANSWER_OK, host_records, 1 };
  g_caaNames[1] = (FakeCaaName_t){ "example.com", DNS_ANSWER_SERVER_ERROR, NULL, 0 };
  g_caaNameCount = 2;
  static_runOneCtScan("www.example.com", "failure after the set");
  TEST_ASSERT_TRUE(g_ctRecords[0].m_hasValue);
  TEST_ASSERT_EQUAL_STRING("new_issuer letsencrypt.org", g_ctRecords[0].ma_valueText);
}

void test_scanNextCtDomains_held_cert_spotter_defers_without_a_request(void)
{
  static const unsigned int holds[]    = { 1, 42, 5000 };
  static const unsigned int expected[] = { 1, 42, 3600 };
  for (size_t c = 0; c < sizeof(holds) / sizeof(holds[0]); c++)
  {
    setUp();
    g_holdSeconds = holds[c];
    static_runOneCtScan("www.example.com", "held");
    TEST_ASSERT_EQUAL_STRING("HR", g_callOrder);
    TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
    TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);
    TEST_ASSERT_EQUAL_UINT(expected[c], g_ctRecords[0].m_retryAfterSeconds);
  }
}

void test_scanNextCtDomains_failed_hold_read_fails_the_run_with_no_record(void)
{
  g_isHoldRead = false;
  static_queueOneClaim(static_claim("www.example.com", "c1"));
  TEST_ASSERT_FALSE(watchlist_cert_search_scanNextDomains(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("H", g_callOrder);
  TEST_ASSERT_EQUAL_INT(0, g_ctRecordCallCount);
}

void test_scanNextCtDomains_429_sets_the_hold_and_defers(void)
{
  static const unsigned int waits[]    = { 120, 0 };
  static const unsigned int expected[] = { 120, 1 };
  for (size_t c = 0; c < sizeof(waits) / sizeof(waits[0]); c++)
  {
    setUp();
    g_ctStatus = CERTSPOTTER_RATE_LIMITED;
    g_ctRetry  = waits[c];
    static_runOneCtScan("www.example.com", "429");
    TEST_ASSERT_EQUAL_STRING("HQCSR", g_callOrder);
    TEST_ASSERT_EQUAL_STRING("certspotter", g_setHoldName);
    TEST_ASSERT_EQUAL_UINT(waits[c], g_setHoldSeconds);
    TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
    TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);
    TEST_ASSERT_EQUAL_UINT(expected[c], g_ctRecords[0].m_retryAfterSeconds);
  }
}

void test_scanNextCtDomains_spent_share_defers_and_ends_the_run(void)
{
  const WatchlistDomainScanClaim_t claims[2] = { static_claim("www.example.com", "c1"), static_claim("www.example.org", "c2") };
  static_queueClaims(DB_OK, 2, claims);
  g_quotaStatuses[0] = QUOTA_EXHAUSTED;
  g_quotaStatusCount = 1;
  g_nowEpoch         = FAKE_NOW_EPOCH + 214 * 86400;

  TEST_ASSERT_TRUE(watchlist_cert_search_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_STRING("HQCR", g_callOrder);
  TEST_ASSERT_EQUAL_INT(1, g_ctRecordCallCount);
  TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);
  TEST_ASSERT_EQUAL_UINT(1200, g_ctRecords[0].m_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT64(FAKE_NOW_EPOCH + 214 * 86400, (int64_t)g_lastWindowNow);
  TEST_ASSERT_EQUAL_STRING("domain_scan_ct", g_lastQuotaRule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(20, g_lastQuotaRule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(1, g_usageEventCount);
  TEST_ASSERT_EQUAL_INT(USAGELOG_EVENT_CT_SCAN_CAP_REACHED, g_usageEvents[0]);
}

void test_scanNextCtDomains_share_counts_on_a_row_apart_from_cert_search(void)
{
  static_queueOneClaim(static_claim("www.example.com", "c1"));

  TEST_ASSERT_TRUE(watchlist_cert_search_scanNextDomains(FAKE_CONN));

  TEST_ASSERT_EQUAL_INT(1, g_quotaCallCount);
  TEST_ASSERT_NOT_EQUAL(0, strcmp("certspotter_name", g_lastQuotaRule.mp_sourceName));
}

void test_scanNextCtDomains_incomplete_or_failed_walk_records_no_value(void)
{
  static const struct {
    CertSpotterStatus_t m_status;
    bool                m_isComplete;
    bool                m_isIssuerDropped;
    int                 m_dnsAskCallCount;
  } cases[] = {
    { CERTSPOTTER_OK,             false, false, 0 },
    { CERTSPOTTER_OK,             true,  true,  0 },
    { CERTSPOTTER_UPSTREAM_ERROR, true,  false, 0 },
    { CERTSPOTTER_NO_API_KEY,     true,  false, 0 },
    { CERTSPOTTER_INVALID_NAME,   true,  false, 0 },
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_ctStatus                 = cases[c].m_status;
    g_ctList.m_isComplete      = cases[c].m_isComplete;
    g_ctList.m_isIssuerDropped = cases[c].m_isIssuerDropped;
    char message[16] = "";
    snprintf(message, sizeof(message), "case %zu", c);
    static_runOneCtScan("www.example.com", message);
    TEST_ASSERT_FALSE_MESSAGE(g_ctRecords[0].m_hasValue, message);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_ctRecords[0].m_retryAfterSeconds, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[c].m_dnsAskCallCount, g_dnsAskCallCount, message);
  }
}

void test_scanNextCtDomains_db_error_fails_the_run(void)
{
  g_quotaStatuses[0] = QUOTA_ERROR;
  g_quotaStatusCount = 1;
  static_queueOneClaim(static_claim("www.example.com", "c1"));
  TEST_ASSERT_FALSE(watchlist_cert_search_scanNextDomains(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(0, g_ctRecordCallCount);

  setUp();
  g_ctRecordStatus = DB_ERROR;
  static_queueOneClaim(static_claim("www.example.com", "c1"));
  TEST_ASSERT_FALSE(watchlist_cert_search_scanNextDomains(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_ctRecordCallCount);
}

void test_scanNextCtDomains_name_not_public_or_no_key_asks_nothing(void)
{
  static const char* const names[] = { "localhost", "co.uk", "www.example.com" };
  for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++)
  {
    setUp();
    g_hasCertSpotterKey = n < 2;
    static_runOneCtScan(names[n], names[n]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("R", g_callOrder, names[n]);
    TEST_ASSERT_FALSE_MESSAGE(g_ctRecords[0].m_hasValue, names[n]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_ctRecords[0].m_retryAfterSeconds, names[n]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_dnsAskCallCount, names[n]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_holdReadCallCount, names[n]);
  }
}

void test_scanNextCtDomains_host_past_the_question_limit_gives_no_value(void)
{
  char host[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
  for (int labels = 32; labels >= 31; labels--)
  {
    setUp();
    host[0] = '\0';
    for (int i = 0; i < labels; i++)
      strcat(host, "a.");
    strcat(host, "example.com");
    static_runOneCtScan(host, "deep host");
    if (labels == 32)
    {
      TEST_ASSERT_FALSE(g_ctRecords[0].m_hasValue);
      TEST_ASSERT_EQUAL_INT(0, g_dnsAskCallCount);
    }
    else
    {
      TEST_ASSERT_TRUE(g_ctRecords[0].m_hasValue);
      TEST_ASSERT_EQUAL_INT(DNS_MAX_QUESTION_COUNT, g_dnsAskCalls[0].m_questionCount);
    }
  }
}

typedef struct {
  const char*     mp_name;
  bool            (*m_run)(PGconn* conn);
  UsageLogEvent_t m_capEvent;
} CapLane_t;

static const CapLane_t CAP_LANES[] = {
  { "dns",        watchlist_dns_lookup_scanNextDomains,       USAGELOG_EVENT_DNS_SCAN_CAP_REACHED        },
  { "tls",        watchlist_ssl_check_scanNextDomains,       USAGELOG_EVENT_TLS_SCAN_CAP_REACHED        },
  { "rdap_whois", watchlist_whois_lookup_scanNextDomains, USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED },
  { "headers",    watchlist_headers_check_scanNextDomains,   USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED    },
  { "ct",         watchlist_cert_search_scanNextDomains,        USAGELOG_EVENT_CT_SCAN_CAP_REACHED         },
};
enum { CAP_LANE_COUNT = sizeof(CAP_LANES) / sizeof(CAP_LANES[0]) };

static void static_queueFullBreaker(time_t now_epoch)
{
  setUp();
  g_nowEpoch = now_epoch;
  const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
  static_queueClaims(DB_OK, 1, &claim);
  g_quotaStatuses[0]       = QUOTA_EXHAUSTED;
  g_quotaStatusCount       = 1;
  g_registryAskStatuses[0] = REGISTRYASK_DAILY_QUOTA_EXHAUSTED;
}

void test_everyLane_full_breaker_writes_one_cap_line_a_day(void)
{
  static const struct {
    time_t m_secondOfDays;
    int    m_lineCount;
  } runs[] = {
    { 0,                 1 },
    { 86399,             1 },
    { 86400,             2 },
    { 86400 + 60,        2 },
  };
  for (int k = 0; k < CAP_LANE_COUNT; k++)
  {
    time_t first_day = FAKE_NOW_EPOCH + (200 + 2 * k) * 86400;
    int line_count = 0;
    for (size_t r = 0; r < sizeof(runs) / sizeof(runs[0]); r++)
    {
      static_queueFullBreaker(first_day + runs[r].m_secondOfDays);
      char message[32] = "";
      snprintf(message, sizeof(message), "%s run %zu", CAP_LANES[k].mp_name, r);

      TEST_ASSERT_TRUE_MESSAGE(CAP_LANES[k].m_run(FAKE_CONN), message);

      for (int i = 0; i < g_usageEventCount; i++)
        TEST_ASSERT_EQUAL_INT_MESSAGE(CAP_LANES[k].m_capEvent, g_usageEvents[i], message);
      line_count += g_usageEventCount;
      TEST_ASSERT_EQUAL_INT_MESSAGE(runs[r].m_lineCount, line_count, message);
    }
  }
}

void test_everyLane_writes_its_own_cap_line_on_a_day_another_lane_wrote_one(void)
{
  static const int order[CAP_LANE_COUNT] = { 1, 0, 2, 3, 4 };
  for (int n = 0; n < CAP_LANE_COUNT; n++)
  {
    const CapLane_t* lane = &CAP_LANES[order[n]];
    static_queueFullBreaker(FAKE_NOW_EPOCH + 210 * 86400 + n);

    TEST_ASSERT_TRUE_MESSAGE(lane->m_run(FAKE_CONN), lane->mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_usageEventCount, lane->mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(lane->m_capEvent, g_usageEvents[0], lane->mp_name);
  }
}

void test_everyLane_failed_breaker_call_writes_no_cap_line(void)
{
  for (int k = 0; k < CAP_LANE_COUNT; k++)
  {
    static_queueFullBreaker(FAKE_NOW_EPOCH + 212 * 86400);
    g_quotaStatuses[0]       = QUOTA_ERROR;
    g_registryAskStatuses[0] = REGISTRYASK_DB_ERROR;

    TEST_ASSERT_FALSE_MESSAGE(CAP_LANES[k].m_run(FAKE_CONN), CAP_LANES[k].mp_name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_usageEventCount, CAP_LANES[k].mp_name);
  }
}

static size_t static_readCollapsedDocs(const char* path, char* text, size_t size)
{
  FILE* file = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
  size_t len = fread(text, 1, size - 1, file);
  fclose(file);
  TEST_ASSERT_TRUE_MESSAGE(len < size - 1, path);
  size_t out = 0;
  for (size_t k = 0; k < len; k++)
  {
    bool is_space = text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n';
    if (!is_space)
      text[out++] = text[k];
    else if (out == 0 || text[out - 1] != ' ')
      text[out++] = ' ';
  }
  text[out] = '\0';
  return out;
}

static bool static_matchCopy(const char* at, const char* pattern, unsigned long* values_out, int* value_count_out)
{
  *value_count_out = 0;
  for (const char* p = pattern; *p != '\0'; p++)
  {
    if (*p != '#')
    {
      if (*at != *p)
        return false;
      at++;
      continue;
    }
    if (*at < '0' || *at > '9')
      return false;
    unsigned long value = 0;
    for (; *at >= '0' && *at <= '9'; at++)
      value = value * 10 + (unsigned long)(*at - '0');
    values_out[(*value_count_out)++] = value;
  }
  return true;
}

typedef struct {
  const char*   mp_pattern;
  const char*   mp_anchor;
  unsigned long ma_values[4];
  int           m_valueCount;
  int           m_copyCount;
} ScanLimitCopy_t;

enum { SCAN_LIMIT_COPY_KIND_MAX = 16 };

static int static_countScanLimitCopies(const char* const* paths, size_t path_count, const ScanLimitCopy_t* copies, size_t copy_count, int* copy_counts)
{
  TEST_ASSERT_TRUE(copy_count <= SCAN_LIMIT_COPY_KIND_MAX);
  static char docs[1 << 21];
  int anchor_counts[SCAN_LIMIT_COPY_KIND_MAX] = { 0 };
  for (size_t c = 0; c < copy_count; c++)
    copy_counts[c] = 0;
  for (size_t p = 0; p < path_count; p++)
  {
    static_readCollapsedDocs(paths[p], docs, sizeof(docs));
    for (size_t c = 0; c < copy_count; c++)
    {
      for (const char* at = strstr(docs, copies[c].mp_anchor); at != NULL; at = strstr(at + 1, copies[c].mp_anchor))
        anchor_counts[c]++;
      for (const char* at = docs; *at != '\0'; at++)
      {
        unsigned long values[4];
        int value_count;
        if (!static_matchCopy(at, copies[c].mp_pattern, values, &value_count))
          continue;
        TEST_ASSERT_EQUAL_INT_MESSAGE(copies[c].m_valueCount, value_count, copies[c].mp_pattern);
        for (int v = 0; v < value_count; v++)
          TEST_ASSERT_EQUAL_UINT32_MESSAGE(copies[c].ma_values[v], values[v], copies[c].mp_pattern);
        copy_counts[c]++;
      }
    }
  }
  int total = 0;
  for (size_t c = 0; c < copy_count; c++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(copy_counts[c], anchor_counts[c], copies[c].mp_anchor);
    total += copy_counts[c];
  }
  return total;
}

static const QuotaRule_t* static_readRdapWhoisDailyQuotaRule(void)
{
  const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
  static_queueClaims(DB_OK, 1, &claim);
  TEST_ASSERT_TRUE(watchlist_whois_lookup_scanNextDomains(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_registryAskCallCount);
  TEST_ASSERT_NOT_NULL(g_registryAskDailyQuotaRules[0]);
  return g_registryAskDailyQuotaRules[0];
}

void test_docs_name_the_rdap_whois_scan_limits(void)
{
  const QuotaRule_t* daily_rule = static_readRdapWhoisDailyQuotaRule();
  TEST_ASSERT_EQUAL_STRING("domain_scan_rdap_whois", daily_rule->mp_sourceName);
  unsigned long daily_limit = daily_rule->m_callLimit;

  const ThrottleRule_t* user_request_rdap  = registryask_userRequestThrottleRules.mp_rdapRule;
  const ThrottleRule_t* user_request_whois = registryask_userRequestThrottleRules.mp_whoisRule;
  const ThrottleRule_t* watchlist_scan_rdap    = registryask_watchlistScanThrottleRules.mp_rdapRule;
  const ThrottleRule_t* watchlist_scan_whois   = registryask_watchlistScanThrottleRules.mp_whoisRule;
  const ScanLimitCopy_t copies[] = {
    { "at most # RDAP requests a minute to one host and # WHOIS queries a minute to one server", " RDAP requests a minute to one host",
      { watchlist_scan_rdap->m_chargeLimit, watchlist_scan_whois->m_chargeLimit }, 2, 4 },
    { "at least # RDAP requests and # WHOIS queries", " RDAP requests and ",
      { user_request_rdap->m_chargeLimit - watchlist_scan_rdap->m_chargeLimit, user_request_whois->m_chargeLimit - watchlist_scan_whois->m_chargeLimit }, 2, 1 },
    { "whose limits are # and #.", "whose limits are ",
      { user_request_rdap->m_chargeLimit, user_request_whois->m_chargeLimit }, 2, 1 },
    { "at most # RDAP/WHOIS scans in a day", " RDAP/WHOIS scans in a day", { daily_limit }, 1, 1 },
    { "at most # RDAP/WHOIS scans a day",    " RDAP/WHOIS scans a day",    { daily_limit }, 1, 1 },
    { "at most # times a day for all keys", " times a day for all keys", { daily_limit }, 1, 1 },
  };
  enum { COPY_KIND_COUNT = sizeof(copies) / sizeof(copies[0]) };
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md", "web/pages/bot.html" };
  int copy_counts[COPY_KIND_COUNT];
  int total = static_countScanLimitCopies(paths, sizeof(paths) / sizeof(paths[0]), copies, COPY_KIND_COUNT, copy_counts);
  for (size_t c = 0; c < COPY_KIND_COUNT; c++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(copies[c].m_copyCount, copy_counts[c], copies[c].mp_pattern);
  TEST_ASSERT_EQUAL_INT(9, total);
}

static QuotaRule_t static_readLaneDailyQuotaRule(bool (*run)(PGconn*))
{
  const WatchlistDomainScanClaim_t claim = static_claim("example.com", "u1");
  static_queueClaims(DB_OK, 1, &claim);
  static_queueClaims(DB_OK, 0, NULL);
  int quota_call_count = g_quotaCallCount;
  TEST_ASSERT_TRUE(run(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(quota_call_count + 1, g_quotaCallCount);
  return g_lastQuotaRule;
}

void test_docs_name_the_dns_and_tls_scan_limits(void)
{
  QuotaRule_t dns_rule = static_readLaneDailyQuotaRule(watchlist_dns_lookup_scanNextDomains);
  QuotaRule_t tls_rule = static_readLaneDailyQuotaRule(watchlist_ssl_check_scanNextDomains);
  TEST_ASSERT_EQUAL_STRING("domain_scan_dns", dns_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_STRING("domain_scan_tls", tls_rule.mp_sourceName);
  unsigned long dns_limit = dns_rule.m_callLimit;
  unsigned long tls_limit = tls_rule.m_callLimit;

  const ScanLimitCopy_t copies[] = {
    { "at most # DNS scans in a day", " DNS scans in a day", { dns_limit }, 1, 1 },
    { "at most # TLS scans in a day", " TLS scans in a day", { tls_limit }, 1, 1 },
    { "at most # DNS scans a day",    " DNS scans a day",    { dns_limit }, 1, 2 },
    { "at most # TLS scans a day",    " TLS scans a day",    { tls_limit }, 1, 2 },
  };
  enum { COPY_KIND_COUNT = sizeof(copies) / sizeof(copies[0]) };
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md", "web/pages/bot.html" };
  int copy_counts[COPY_KIND_COUNT];
  int total = static_countScanLimitCopies(paths, sizeof(paths) / sizeof(paths[0]), copies, COPY_KIND_COUNT, copy_counts);
  for (size_t c = 0; c < COPY_KIND_COUNT; c++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(copies[c].m_copyCount, copy_counts[c], copies[c].mp_pattern);
  TEST_ASSERT_EQUAL_INT(6, total);
}

void test_docs_name_the_headers_and_ct_scan_limits(void)
{
  QuotaRule_t headers_rule = static_readLaneDailyQuotaRule(watchlist_headers_check_scanNextDomains);
  TEST_ASSERT_EQUAL_STRING("domain_scan_headers", headers_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(86400, headers_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_INT(1, g_throttleCallCount);
  ThrottleRule_t throttle_rule = g_throttleRules[0];
  unsigned long  charge_count  = g_throttleCounts[0];
  TEST_ASSERT_EQUAL_STRING("headers_scan", throttle_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60, throttle_rule.m_windowSeconds);

  static_queueOneClaim(static_claim("www.example.com", "2026-11-01 09:00:00.3+00"));
  TEST_ASSERT_TRUE(watchlist_cert_search_scanNextDomains(FAKE_CONN));
  QuotaRule_t ct_rule = g_lastQuotaRule;
  TEST_ASSERT_EQUAL_STRING("domain_scan_ct", ct_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, ct_rule.m_windowSeconds);

  unsigned long headers_limit  = headers_rule.m_callLimit;
  unsigned long throttle_limit = throttle_rule.m_chargeLimit;
  unsigned long ct_limit       = ct_rule.m_callLimit;
  const ScanLimitCopy_t copies[] = {
    { "at most # headers scans in a day", " headers scans in a day", { headers_limit }, 1, 1 },
    { "at most # headers scans a day",    " headers scans a day",    { headers_limit }, 1, 1 },
    { "at most # such scans a day",       " such scans a day",       { headers_limit }, 1, 1 },
    { "start at most # fetches a minute together, so at most # scans", " fetches a minute together",
      { throttle_limit, throttle_limit / charge_count }, 2, 2 },
    { "starts at most # such fetches in each minute for the names under one registered domain, for all keys together, so at most # scans",
      " such fetches in each minute", { throttle_limit, throttle_limit / charge_count }, 2, 1 },
    { "stop at # requests", " stop at ", { ct_limit }, 1, 4 },
    { "at most # of these requests in each hour", " of these requests in each hour", { ct_limit }, 1, 1 },
  };
  enum { COPY_KIND_COUNT = sizeof(copies) / sizeof(copies[0]) };
  static const char* const paths[] = { "docs/API_Documentation.md", "docs/MCP_Documentation.md", "web/pages/bot.html" };
  int copy_counts[COPY_KIND_COUNT];
  int total = static_countScanLimitCopies(paths, sizeof(paths) / sizeof(paths[0]), copies, COPY_KIND_COUNT, copy_counts);
  for (size_t c = 0; c < COPY_KIND_COUNT; c++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(copies[c].m_copyCount, copy_counts[c], copies[c].mp_pattern);
  TEST_ASSERT_EQUAL_INT(11, total);
}


void test_registration_gate_test_count(void)
{
  int expected_test_count = 67;
  TEST_ASSERT_EQUAL_INT_MESSAGE(expected_test_count, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_scanNextDnsDomains_scans_each_claimed_domain_and_records_each_kind);
  RUN_TEST(test_scanNextDnsDomains_claim_with_no_domain_ends_the_run);
  RUN_TEST(test_scanNextDnsDomains_failed_claim_fails_the_run);
  RUN_TEST(test_scanNextDnsDomains_stops_when_the_run_deadline_passes);
  RUN_TEST(test_scanNextDnsDomains_quota_refusal_ends_the_run_with_nothing_written);
  RUN_TEST(test_scanNextDnsDomains_failed_record_fails_the_run);
  RUN_TEST(test_scanNextDnsDomains_checks_email_on_every_scan);
  RUN_TEST(test_scanNextDnsDomains_checks_email_once_with_no_selector);
  RUN_TEST(test_scanNextDnsDomains_failed_answer_leaves_out_only_its_kind);
  RUN_TEST(test_scanNextDnsDomains_sends_every_check_id_in_letter_order);
  RUN_TEST(test_scanNextDnsDomains_sends_no_email_value_without_the_check_ids);
  RUN_TEST(test_scanNextDnsDomains_name_that_is_not_public_is_asked_nothing);
  RUN_TEST(test_scanNextDnsDomains_records_the_question_count_of_each_domain);
  RUN_TEST(test_scanNextDnsDomains_sends_the_public_addresses_whatever_the_cname_chain_holds);
  RUN_TEST(test_scanNextDnsDomains_dangling_cname_is_found);
  RUN_TEST(test_scanNextDnsDomains_sends_an_address_list_of_the_value_max_len);
  RUN_TEST(test_scanNextTlsDomains_probes_each_claimed_domain_and_records_four_values);
  RUN_TEST(test_scanNextTlsDomains_claim_with_no_domain_ends_the_run);
  RUN_TEST(test_scanNextTlsDomains_failed_claim_fails_the_run);
  RUN_TEST(test_scanNextTlsDomains_quota_refusal_ends_the_run_with_nothing_written);
  RUN_TEST(test_scanNextTlsDomains_failed_probe_records_no_value);
  RUN_TEST(test_scanNextTlsDomains_unread_list_leaves_out_only_the_listing);
  RUN_TEST(test_scanNextTlsDomains_probe_with_no_end_and_no_protocol_leaves_out_only_those_kinds);
  RUN_TEST(test_scanNextTlsDomains_failed_record_fails_the_run);
  RUN_TEST(test_scanNextTlsDomains_stops_when_the_run_deadline_passes);
  RUN_TEST(test_scanNextRdapWhoisDomains_records_the_four_values_of_a_registration);
  RUN_TEST(test_scanNextRdapWhoisDomains_quota_refusal_ends_the_run_with_nothing_written);
  RUN_TEST(test_scanNextRdapWhoisDomains_unavailable_server_defers_with_its_wait);
  RUN_TEST(test_scanNextRdapWhoisDomains_not_registered_and_upstream_error_record_no_value);
  RUN_TEST(test_scanNextRdapWhoisDomains_name_without_a_registry_server_records_no_value_and_asks_nothing);
  RUN_TEST(test_scanNextRdapWhoisDomains_db_error_of_the_ask_fails_the_run_with_no_record);
  RUN_TEST(test_scanNextRdapWhoisDomains_passes_the_watchlist_scan_rules);
  RUN_TEST(test_scanNextRdapWhoisDomains_passes_the_clock_to_the_expiry_writer);
  RUN_TEST(test_scanNextRdapWhoisDomains_failed_record_fails_the_run);
  RUN_TEST(test_scanNextRdapWhoisDomains_stops_when_the_run_deadline_passes);
  RUN_TEST(test_scanNextRdapWhoisDomains_claim_with_no_domain_ends_the_run);
  RUN_TEST(test_scanNextRdapWhoisDomains_failed_claim_fails_the_run);
  RUN_TEST(test_scanNextRdapWhoisDomains_records_each_value_only_when_its_kind_has_one);
  RUN_TEST(test_scanNextHeadersDomains_fetches_robots_then_home_page_and_records_the_value);
  RUN_TEST(test_scanNextHeadersDomains_robots_txt_answer_decides_the_home_page_fetch);
  RUN_TEST(test_scanNextHeadersDomains_unparsed_robots_txt_fetches_no_home_page);
  RUN_TEST(test_scanNextHeadersDomains_only_a_2xx_home_page_gives_a_value);
  RUN_TEST(test_scanNextHeadersDomains_full_throttle_defers_without_a_request);
  RUN_TEST(test_scanNextHeadersDomains_failed_throttle_fails_the_run_with_no_record);
  RUN_TEST(test_scanNextHeadersDomains_quota_refusal_ends_the_run_with_nothing_written);
  RUN_TEST(test_scanNextHeadersDomains_name_that_is_not_public_is_asked_nothing);
  RUN_TEST(test_scanNextHeadersDomains_failed_record_fails_the_run);
  RUN_TEST(test_everyLane_full_breaker_writes_one_cap_line_a_day);
  RUN_TEST(test_everyLane_writes_its_own_cap_line_on_a_day_another_lane_wrote_one);
  RUN_TEST(test_everyLane_failed_breaker_call_writes_no_cap_line);
  RUN_TEST(test_docs_name_the_rdap_whois_scan_limits);
  RUN_TEST(test_docs_name_the_dns_and_tls_scan_limits);
  RUN_TEST(test_docs_name_the_headers_and_ct_scan_limits);
  RUN_TEST(test_scanNextCtDomains_reads_the_hold_walks_with_the_scanner_rule_and_records_the_value);
  RUN_TEST(test_scanNextCtDomains_caa_climb_takes_the_first_name_with_records);
  RUN_TEST(test_scanNextCtDomains_wildcard_issuer_reads_the_set_of_the_parent);
  RUN_TEST(test_scanNextCtDomains_caa_failure_before_the_set_gives_no_value);
  RUN_TEST(test_scanNextCtDomains_held_cert_spotter_defers_without_a_request);
  RUN_TEST(test_scanNextCtDomains_failed_hold_read_fails_the_run_with_no_record);
  RUN_TEST(test_scanNextCtDomains_429_sets_the_hold_and_defers);
  RUN_TEST(test_scanNextCtDomains_spent_share_defers_and_ends_the_run);
  RUN_TEST(test_scanNextCtDomains_share_counts_on_a_row_apart_from_cert_search);
  RUN_TEST(test_scanNextCtDomains_incomplete_or_failed_walk_records_no_value);
  RUN_TEST(test_scanNextCtDomains_db_error_fails_the_run);
  RUN_TEST(test_scanNextCtDomains_name_not_public_or_no_key_asks_nothing);
  RUN_TEST(test_scanNextCtDomains_host_past_the_question_limit_gives_no_value);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
