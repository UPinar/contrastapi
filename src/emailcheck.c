#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "emailcheck.h"
#include "bytes.h"
#include "monotonic.h"

#define EMAILCHECK_ROUND_ONE_MAX_QUESTION_COUNT   5

#define EMAILCHECK_ADDRESS_QUESTION_COUNT   3

#define EMAILCHECK_DMARC_WALK_MAX_LABEL_COUNT   8

#define EMAILCHECK_SPF_MAX_DNS_LOOKUP_COUNT   10

#define EMAILCHECK_SPF_MAX_RECORD_SIZE  450

#define EMAILCHECK_SPF_MIN_IP4_PREFIX_LENGTH  16
#define EMAILCHECK_SPF_MIN_IP6_PREFIX_LENGTH  32

#define EMAILCHECK_DKIM_MIN_RSA_KEY_BITS      1024
#define EMAILCHECK_DKIM_STRONG_RSA_KEY_BITS   2048
#define EMAILCHECK_DKIM_MAX_RSA_KEY_BITS      4096

#define EMAILCHECK_MTA_STS_VERSION     "v=STSv1"
#define EMAILCHECK_MTA_STS_VERSION_LEN (sizeof(EMAILCHECK_MTA_STS_VERSION) - 1)

static DnsLookupStatus_t  static_askFirstRound        (EMAILAUTHCHECKRecord_t* record, const char* given_selector_name);
static void               static_readOwnDmarc         (EMAILAUTHCHECKRecord_t* record);
static DnsLookupStatus_t  static_askSecondRound       (EMAILAUTHCHECKRecord_t* record, bool is_selector_given, int64_t start_ms);
static bool               static_tryJoinName          (char* name_out, const char* label, const char* separator, const char* domain);
static bool               static_isAnswered           (const DnsAnswer_t* answer);
static int                static_countLabels          (const char* name);
static int                static_fillDmarcWalkNames   (EMAILAUTHCHECKRecord_t* record);
static void               static_readSpf              (EMAILAUTHCHECKRecord_t* record);
static void               static_addProvider          (EMAILAUTHCHECKRecord_t* record, const char* host_name, size_t host_name_len);
static void               static_findMxProviders      (EMAILAUTHCHECKRecord_t* record);
static void               static_findSpfProviders     (EMAILAUTHCHECKRecord_t* record);
static void               static_addSelector          (EMAILAUTHCHECKRecord_t* record, const char* selector);
static void               static_chooseSelectors      (EMAILAUTHCHECKRecord_t* record);
static bool               static_isMtaStsRecord       (const DnsRecordText_t* text);
static void               static_readMtaSts           (EMAILAUTHCHECKRecord_t* record);
static void               static_readDmarcWalk        (EMAILAUTHCHECKRecord_t* record);
static void               static_applyDmarcPolicy     (EMAILAUTHCHECKRecord_t* record);
static void               static_readKeyRecords       (EmailCheckDkimSelector_t* selector);
static void               static_readDkim             (EMAILAUTHCHECKRecord_t* record);
static EmailCheckResult_t static_worse                (EmailCheckResult_t first, EmailCheckResult_t second);
static void               static_addCheck             (EMAILAUTHCHECKRecord_t* record, EmailCheckKind_t kind, EmailCheckResult_t result);
static int                static_findSpfAll           (const EmailAuthSpf_t* spf);
static bool               static_hasSpfTerm           (const EmailAuthSpf_t* spf, EmailAuthSpfTermKind_t kind);
static EmailCheckResult_t static_rateSpfAll           (const EmailAuthSpf_t* spf);
static bool               static_hasIgnoredSpfTerm    (const EmailAuthSpf_t* spf);
static EmailCheckResult_t static_rateSpfWideRange     (const EmailAuthSpf_t* spf);
static void               static_rateSpf              (EMAILAUTHCHECKRecord_t* record);
static void               static_rateDmarc            (EMAILAUTHCHECKRecord_t* record);
static void               static_rateDkimKeys         (EMAILAUTHCHECKRecord_t* record);
static void               static_rateDkim             (EMAILAUTHCHECKRecord_t* record);
static void               static_rateRecord           (EMAILAUTHCHECKRecord_t* record);

static DnsLookupStatus_t  static_readMailRoute        (EMAILADDRESSCHECKRecord_t* record, const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer);
static bool               static_hasRecord            (const DnsAnswer_t* answer);

DnsLookupStatus_t emailcheck_checkDomain(const char* domain, const char* dkim_selector, EMAILAUTHCHECKRecord_t* record_out)
{
  assert(domain     != NULL);
  assert(record_out != NULL);

  memset(record_out, 0, sizeof(*record_out));

  if (!validate_publicDnsName(domain))
    return DNS_LOOKUP_INVALID_NAME;
  for (size_t i = 0; domain[i] != '\0'; i++)
    record_out->ma_domain[i] = (char)tolower((unsigned char)domain[i]);

  bool is_selector_given = dkim_selector != NULL && dkim_selector[0] != '\0';
  char given_selector_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  if (is_selector_given)
  {
    if (!validate_dkimSelector(dkim_selector) ||
        !static_tryJoinName(given_selector_name, dkim_selector, "._domainkey.", record_out->ma_domain))
    {
      return DNS_LOOKUP_INVALID_NAME;
    }

    int selector_len = snprintf(record_out->ma_dkimSelectors[0].ma_selector, sizeof(record_out->ma_dkimSelectors[0].ma_selector), "%s", dkim_selector);
    assert(selector_len >= 0 && selector_len <= VALIDATE_DKIM_SELECTOR_MAX_LEN && "validate_dkimSelector accepts no longer selector");
    (void)selector_len;

    record_out->m_dkimSelectorCount  = 1;
    record_out->m_dkimSelectorSource = EMAILCHECK_DKIM_SELECTOR_SOURCE_CALLER_GIVEN;
  }

  int64_t start_ms = monotonic_nowMs();
  DnsLookupStatus_t first_status = static_askFirstRound(record_out, is_selector_given ? given_selector_name : NULL);
  if (first_status != DNS_LOOKUP_OK)
    return first_status;

  static_readSpf(record_out);
  static_findMxProviders(record_out);
  static_findSpfProviders(record_out);
  static_readMtaSts(record_out);
  static_readOwnDmarc(record_out);

  DnsLookupStatus_t second_status = static_askSecondRound(record_out, is_selector_given, start_ms);
  if (second_status != DNS_LOOKUP_OK)
    return second_status;

  static_readDmarcWalk(record_out);
  if (record_out->m_dmarcStatus == DNS_ANSWER_OK && record_out->m_dmarcSource != EMAILCHECK_DMARC_SOURCE_NONE)
    static_applyDmarcPolicy(record_out);
  static_readDkim(record_out);
  static_rateRecord(record_out);

  return DNS_LOOKUP_OK;
}

void emailcheck_EMAILAUTHCHECKRecordFree(EMAILAUTHCHECKRecord_t* record)
{
  if (record == NULL)
    return;

  dns_answerFree(&record->m_spfAnswer);
  dns_answerFree(&record->m_mxAnswer);
  dns_answerFree(&record->m_mtaStsAnswer);
  for (int i = 0; i < EMAILCHECK_DMARC_MAX_NAME_COUNT; i++)
    dns_answerFree(&record->ma_dmarcAnswers[i]);
  for (int i = 0; i < EMAILCHECK_MAX_DKIM_SELECTOR_COUNT; i++)
    dns_answerFree(&record->ma_dkimSelectors[i].m_answer);
  memset(record, 0, sizeof(*record));
}

DnsLookupStatus_t emailcheck_checkAddressDomain(const char* domain, EMAILADDRESSCHECKRecord_t* record)
{
  assert(domain != NULL);
  assert(record != NULL);

  record->m_isDomainFound = false;
  record->m_mailRoute     = EMAILCHECK_MAIL_ROUTE_NONE;
  memset(&record->m_mxAnswer, 0, sizeof(record->m_mxAnswer));

  if (!validate_publicDnsName(domain))
    return DNS_LOOKUP_INVALID_NAME;

  const DnsQuestion_t questions[EMAILCHECK_ADDRESS_QUESTION_COUNT] = {
    { domain, DNS_RECORD_TYPE_MX },
    { domain, DNS_RECORD_TYPE_A },
    { domain, DNS_RECORD_TYPE_AAAA },
  };
  DnsAnswer_t answers[EMAILCHECK_ADDRESS_QUESTION_COUNT];
  dns_askQuestions(questions, EMAILCHECK_ADDRESS_QUESTION_COUNT, DNS_LOOKUP_DEADLINE_MS, answers);

  record->m_mxAnswer = answers[0];
  DnsLookupStatus_t route_status = static_readMailRoute(record, &answers[1], &answers[2]);
  dns_answerFree(&answers[1]);
  dns_answerFree(&answers[2]);

  return route_status;
}

void emailcheck_EMAILADDRESSCHECKRecordFree(EMAILADDRESSCHECKRecord_t* record)
{
  if (record == NULL)
    return;

  dns_answerFree(&record->m_mxAnswer);
  memset(record, 0, sizeof(*record));
}

static DnsLookupStatus_t static_askFirstRound(EMAILAUTHCHECKRecord_t* record, const char* given_selector_name)
{
  DnsQuestion_t questions[DNS_MAX_QUESTION_COUNT];
  DnsAnswer_t*  record_answers[DNS_MAX_QUESTION_COUNT];
  int question_count = 0;

  questions[question_count] = (DnsQuestion_t){ record->ma_domain, DNS_RECORD_TYPE_TXT };
  record_answers[question_count++] = &record->m_spfAnswer;
  questions[question_count] = (DnsQuestion_t){ record->ma_domain, DNS_RECORD_TYPE_MX };
  record_answers[question_count++] = &record->m_mxAnswer;

  bool is_dmarc_name_valid = static_tryJoinName(record->ma_dmarcNames[0], "_dmarc", ".", record->ma_domain);
  if (is_dmarc_name_valid)
  {
    questions[question_count] = (DnsQuestion_t){ record->ma_dmarcNames[0], DNS_RECORD_TYPE_TXT };
    record_answers[question_count++] = &record->ma_dmarcAnswers[0];
  }
  else
    record->ma_dmarcAnswers[0].m_status = DNS_ANSWER_BAD_QUESTION;
  record->m_dmarcNameCount = 1;

  char mta_sts_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  bool is_mta_sts_name_valid = static_tryJoinName(mta_sts_name, "_mta-sts", ".", record->ma_domain);
  if (is_mta_sts_name_valid)
  {
    questions[question_count] = (DnsQuestion_t){ mta_sts_name, DNS_RECORD_TYPE_TXT };
    record_answers[question_count++] = &record->m_mtaStsAnswer;
  }
  else
    record->m_mtaStsAnswer.m_status = DNS_ANSWER_BAD_QUESTION;

  if (given_selector_name != NULL)
  {
    questions[question_count] = (DnsQuestion_t){ given_selector_name, DNS_RECORD_TYPE_TXT };
    record_answers[question_count++] = &record->ma_dkimSelectors[0].m_answer;
  }
  assert(question_count <= EMAILCHECK_ROUND_ONE_MAX_QUESTION_COUNT);

  DnsAnswer_t answers[DNS_MAX_QUESTION_COUNT];
  dns_askQuestions(questions, question_count, DNS_LOOKUP_DEADLINE_MS, answers);
  bool is_any_answered  = false;
  bool is_any_no_memory = false;
  for (int i = 0; i < question_count; i++)
  {
    *record_answers[i] = answers[i];
    is_any_answered  = is_any_answered  || static_isAnswered(&answers[i]);
    is_any_no_memory = is_any_no_memory || answers[i].m_status == DNS_ANSWER_NO_MEMORY;
  }

  if (is_any_no_memory)
    return DNS_LOOKUP_NO_MEMORY;
  if (!is_any_answered)
    return DNS_LOOKUP_NO_ANSWER;

  if (record->m_spfAnswer.m_status  != DNS_ANSWER_OK    &&
      record->m_mxAnswer.m_status   != DNS_ANSWER_OK    &&
      (record->m_spfAnswer.m_status == DNS_ANSWER_NXDOMAIN || record->m_mxAnswer.m_status == DNS_ANSWER_NXDOMAIN))
  {
    return DNS_LOOKUP_NOT_FOUND;
  }

  return DNS_LOOKUP_OK;
}

static void static_readOwnDmarc(EMAILAUTHCHECKRecord_t* record)
{
  const DnsAnswer_t* own_dmarc_answer = &record->ma_dmarcAnswers[0];
  record->m_dmarcStatus = own_dmarc_answer->m_status == DNS_ANSWER_NXDOMAIN ? DNS_ANSWER_OK : own_dmarc_answer->m_status;

  if (own_dmarc_answer->m_status == DNS_ANSWER_OK)
  {
    record->m_ownDmarcRecordCount = emailauth_countDmarcRecords(own_dmarc_answer->mp_texts, own_dmarc_answer->m_recordCount, &record->m_dmarcRecordIndex);
    if (record->m_ownDmarcRecordCount == EMAILAUTH_RECORD_ONE)
    {
      emailauth_parseDmarc(&own_dmarc_answer->mp_texts[record->m_dmarcRecordIndex], &record->m_dmarcRecord);
      record->m_dmarcSource = EMAILCHECK_DMARC_SOURCE_DOMAIN;
    }
  }
}

static DnsLookupStatus_t static_askSecondRound(EMAILAUTHCHECKRecord_t* record, bool is_selector_given, int64_t start_ms)
{
  DnsQuestion_t questions[DNS_MAX_QUESTION_COUNT];
  DnsAnswer_t*  record_answers[DNS_MAX_QUESTION_COUNT];
  int question_count = 0;

  if (record->m_dmarcStatus == DNS_ANSWER_OK && record->m_dmarcSource == EMAILCHECK_DMARC_SOURCE_NONE)
  {
    record->m_dmarcNameCount += static_fillDmarcWalkNames(record);

    for (int i = 1; i < record->m_dmarcNameCount; i++)
    {
      questions[question_count] = (DnsQuestion_t){ record->ma_dmarcNames[i], DNS_RECORD_TYPE_TXT };
      record_answers[question_count++] = &record->ma_dmarcAnswers[i];
    }
  }

  char selector_names[EMAILCHECK_MAX_DKIM_SELECTOR_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  if (!is_selector_given)
  {
    static_chooseSelectors(record);

    for (int i = 0; i < record->m_dkimSelectorCount; i++)
    {
      bool is_name_valid = static_tryJoinName(selector_names[i], record->ma_dkimSelectors[i].ma_selector, "._domainkey.", record->ma_domain);
      assert(is_name_valid && "static_chooseSelectors keeps only the selectors whose name fits");
      (void)is_name_valid;

      questions[question_count] = (DnsQuestion_t){ selector_names[i], DNS_RECORD_TYPE_TXT };
      record_answers[question_count++] = &record->ma_dkimSelectors[i].m_answer;
    }
  }
  assert(question_count <= DNS_MAX_QUESTION_COUNT);
  if (question_count == 0)
    return DNS_LOOKUP_OK;

  DnsAnswer_t answers[DNS_MAX_QUESTION_COUNT];
  int64_t left_ms = DNS_LOOKUP_DEADLINE_MS - (monotonic_nowMs() - start_ms);
  if (left_ms > 0)
    dns_askQuestions(questions, question_count, (int)left_ms, answers);
  else
  {
    for (int i = 0; i < question_count; i++)
      answers[i] = (DnsAnswer_t){ .m_status = DNS_ANSWER_TIMEOUT };
  }

  bool is_any_no_memory = false;
  for (int i = 0; i < question_count; i++)
  {
    *record_answers[i] = answers[i];
    is_any_no_memory = is_any_no_memory || answers[i].m_status == DNS_ANSWER_NO_MEMORY;
  }
  if (is_any_no_memory)
    return DNS_LOOKUP_NO_MEMORY;

  return DNS_LOOKUP_OK;
}

static bool static_tryJoinName(char* name_out, const char* label, const char* separator, const char* domain)
{
  int name_len = snprintf(name_out, VALIDATE_DOMAIN_NAME_MAX_LEN + 1, "%s%s%s", label, separator, domain);
  return name_len >= 0 && name_len <= VALIDATE_DOMAIN_NAME_MAX_LEN && validate_publicUnderscoredDnsName(name_out);
}

static bool static_isAnswered(const DnsAnswer_t* answer)
{
  return answer->m_status == DNS_ANSWER_OK || answer->m_status == DNS_ANSWER_NXDOMAIN;
}

static int static_countLabels(const char* name)
{
  int label_count = 1;
  for (const char* cursor = name; *cursor != '\0'; cursor++)
    if (*cursor == '.')
      label_count++;

  return label_count;
}

static int static_fillDmarcWalkNames(EMAILAUTHCHECKRecord_t* record)
{
  int label_count = static_countLabels(record->ma_domain);
  assert(label_count >= 2 && "validate_publicDnsName accepts no name of one label");
  int start_label_count = label_count <= EMAILCHECK_DMARC_WALK_MAX_LABEL_COUNT  ? label_count - 1
                                                                                : EMAILCHECK_DMARC_WALK_MAX_NAME_COUNT;

  const char* suffix = record->ma_domain;
  for (int skipped = label_count - start_label_count; skipped > 0; skipped--)
    suffix = strchr(suffix, '.') + 1;

  int name_count = 0;
  for (int labels_left = start_label_count; labels_left > 0; labels_left--)
  {
    bool is_name_valid = static_tryJoinName(record->ma_dmarcNames[1 + name_count], "_dmarc", ".", suffix);
    assert(is_name_valid && "a parent name is shorter than the domain's own name");
    (void)is_name_valid;
    name_count++;

    const char* next_dot = strchr(suffix, '.');
    if (next_dot != NULL)
      suffix = next_dot + 1;
  }

  return name_count;
}

static void static_readSpf(EMAILAUTHCHECKRecord_t* record)
{
  const DnsAnswer_t* answer = &record->m_spfAnswer;
  if (answer->m_status != DNS_ANSWER_OK)
    return;

  for (int i = 0; i < answer->m_recordCount; i++)
  {
    if (!emailauth_isSpfRecord(&answer->mp_texts[i]))
      continue;
    if (record->m_spfRecordCount == 0)
      record->m_spfRecordIndex = i;
    record->m_spfRecordCount++;
  }

  if (record->m_spfRecordCount == 1)
    emailauth_parseSpf(&answer->mp_texts[record->m_spfRecordIndex], &record->m_spfRecord);
}

static void static_addProvider(EMAILAUTHCHECKRecord_t* record, const char* host_name, size_t host_name_len)
{
  const EmailDataProvider_t* provider = emaildata_findProvider(host_name, host_name_len);
  if (provider == NULL)
    return;

  for (int i = 0; i < record->m_mailProviderCount; i++)
    if (record->ma_mailProviders[i] == provider)
      return;

  record->ma_mailProviders[record->m_mailProviderCount++] = provider;
}

static void static_findMxProviders(EMAILAUTHCHECKRecord_t* record)
{
  const DnsAnswer_t* mx_answer = &record->m_mxAnswer;
  if (mx_answer->m_status == DNS_ANSWER_OK)
    for (int i = 0; i < mx_answer->m_recordCount; i++)
      static_addProvider(record, mx_answer->mp_mxRecords[i].mp_hostname, strlen(mx_answer->mp_mxRecords[i].mp_hostname));
}

static void static_findSpfProviders(EMAILAUTHCHECKRecord_t* record)
{
  if (record->m_spfRecordCount != 1)
    return;

  for (int i = 0; i < record->m_spfRecord.m_termCount; i++)
  {
    const EmailAuthSpfTerm_t* term = &record->m_spfRecord.ma_terms[i];
    if (term->m_kind == EMAILAUTH_SPF_TERM_INCLUDE || term->m_kind == EMAILAUTH_SPF_TERM_REDIRECT)
      static_addProvider(record, term->m_value.mp_bytes, term->m_value.m_byteCount);
  }
}

static void static_addSelector(EMAILAUTHCHECKRecord_t* record, const char* selector)
{
  if (record->m_dkimSelectorCount == EMAILCHECK_MAX_DKIM_SELECTOR_COUNT)
    return;

  for (int i = 0; i < record->m_dkimSelectorCount; i++)
    if (strcasecmp(record->ma_dkimSelectors[i].ma_selector, selector) == 0)
      return;

  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  if (!static_tryJoinName(name, selector, "._domainkey.", record->ma_domain))
    return;

  EmailCheckDkimSelector_t* added_selector = &record->ma_dkimSelectors[record->m_dkimSelectorCount++];
  int selector_len = snprintf(added_selector->ma_selector, sizeof(added_selector->ma_selector), "%s", selector);
  assert(selector_len >= 0 && selector_len <= VALIDATE_DKIM_SELECTOR_MAX_LEN && "a name of 253 bytes leaves a selector at most 238");
  (void)selector_len;
}

static void static_chooseSelectors(EMAILAUTHCHECKRecord_t* record)
{
  record->m_dkimSelectorSource = EMAILCHECK_DKIM_SELECTOR_SOURCE_COMMON;

  for (int i = 0; i < record->m_mailProviderCount; i++)
  {
    const EmailDataProvider_t* provider = record->ma_mailProviders[i];
    for (int j = 0; j < EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT && provider->ma_dkimSelectors[j] != NULL; j++)
    {
      record->m_dkimSelectorSource = EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER;
      static_addSelector(record, provider->ma_dkimSelectors[j]);
    }
  }

  if (record->m_dkimSelectorSource == EMAILCHECK_DKIM_SELECTOR_SOURCE_COMMON)
    for (int i = 0; i < EMAILDATA_COMMON_DKIM_SELECTOR_COUNT; i++)
      static_addSelector(record, emaildata_commonDkimSelectors[i]);
}

static bool static_isMtaStsRecord(const DnsRecordText_t* text)
{
  if (!bytes_hasPrefix(text->mp_bytes, text->m_byteCount, EMAILCHECK_MTA_STS_VERSION, EMAILCHECK_MTA_STS_VERSION_LEN, false))
  {
    return false;
  }

  size_t cursor = EMAILCHECK_MTA_STS_VERSION_LEN;
  while (cursor < text->m_byteCount && (text->mp_bytes[cursor] == ' ' || text->mp_bytes[cursor] == '\t'))
    cursor++;

  return cursor < text->m_byteCount && text->mp_bytes[cursor] == ';';
}

static void static_readMtaSts(EMAILAUTHCHECKRecord_t* record)
{
  const DnsAnswer_t* answer = &record->m_mtaStsAnswer;
  if (answer->m_status != DNS_ANSWER_OK)
    return;

  int mta_sts_record_count = 0;
  for (int i = 0; i < answer->m_recordCount; i++)
    if (static_isMtaStsRecord(&answer->mp_texts[i]))
      mta_sts_record_count++;
  record->m_hasMtaStsRecord = mta_sts_record_count == 1;
}

static void static_readDmarcWalk(EMAILAUTHCHECKRecord_t* record)
{
  if (record->m_dmarcStatus != DNS_ANSWER_OK || record->m_dmarcNameCount == 1)
    return;

  int  found_text_indexes[EMAILCHECK_DMARC_MAX_NAME_COUNT];
  bool is_found[EMAILCHECK_DMARC_MAX_NAME_COUNT] = { false };
  int  last_found_index = -1;
  EmailAuthDmarc_t last_dmarc;
  for (int i = 1; i < record->m_dmarcNameCount; i++)
  {
    const DnsAnswer_t* answer = &record->ma_dmarcAnswers[i];
    if (answer->m_status == DNS_ANSWER_NXDOMAIN)
      continue;

    if (answer->m_status != DNS_ANSWER_OK)
    {
      record->m_dmarcStatus = answer->m_status;
      return;
    }

    if (emailauth_countDmarcRecords(answer->mp_texts, answer->m_recordCount, &found_text_indexes[i]) != EMAILAUTH_RECORD_ONE)
      continue;

    is_found[i] = true;
    last_found_index  = i;
    emailauth_parseDmarc(&answer->mp_texts[found_text_indexes[i]], &last_dmarc);

    if (last_dmarc.m_domainRole == EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL ||
        last_dmarc.m_domainRole == EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX)
    {
      break;
    }
  }
  if (last_found_index < 0)
    return;

  int applied_index = last_found_index;
  record->m_dmarcSource = EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL;
  if (last_dmarc.m_domainRole == EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX)
  {
    int organizational_label_count = static_countLabels(record->ma_dmarcNames[last_found_index]) + 1;
    record->m_dmarcSource = EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX;
    for (int i = 1; i < last_found_index; i++)
      if (is_found[i] && static_countLabels(record->ma_dmarcNames[i]) == organizational_label_count)
      {
        applied_index         = i;
        record->m_dmarcSource = EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL;
      }
  }

  record->m_dmarcNameIndex   = applied_index;
  record->m_dmarcRecordIndex = found_text_indexes[applied_index];
  emailauth_parseDmarc(&record->ma_dmarcAnswers[applied_index].mp_texts[record->m_dmarcRecordIndex], &record->m_dmarcRecord);
}

static void static_applyDmarcPolicy(EMAILAUTHCHECKRecord_t* record)
{
  const EmailAuthDmarc_t* dmarc = &record->m_dmarcRecord;
  if (dmarc->m_policy == EMAILAUTH_DMARC_POLICY_INVALID || dmarc->m_subdomainPolicy == EMAILAUTH_DMARC_POLICY_INVALID ||
      dmarc->m_nonexistentSubdomainPolicy == EMAILAUTH_DMARC_POLICY_INVALID)
  {
    record->m_isDmarcApplied     = dmarc->m_validAggregateUriCount > 0;
    record->m_appliedDmarcPolicy = EMAILAUTH_DMARC_POLICY_NONE;
    return;
  }

  EmailAuthDmarcPolicy_t policy = dmarc->m_policy;
  if (record->m_dmarcSource != EMAILCHECK_DMARC_SOURCE_DOMAIN && dmarc->m_subdomainPolicy != EMAILAUTH_DMARC_POLICY_ABSENT)
    policy = dmarc->m_subdomainPolicy;
  record->m_isDmarcApplied     = true;
  record->m_appliedDmarcPolicy = policy == EMAILAUTH_DMARC_POLICY_ABSENT ? EMAILAUTH_DMARC_POLICY_NONE : policy;
}

static void static_readKeyRecords(EmailCheckDkimSelector_t* selector)
{
  const DnsAnswer_t* answer = &selector->m_answer;
  for (int i = 0; i < answer->m_recordCount; i++)
  {
    EmailAuthDkim_t key;
    emailauth_parseDkim(&answer->mp_texts[i], &key);
    if (key.m_keyState == EMAILAUTH_DKIM_KEY_ABSENT)
      continue;

    if (selector->m_hasKeyRecord)
    {
      selector->m_hasSecondKeyRecord = true;
      return;
    }
    selector->m_firstKeyRecord = key;
    selector->m_hasKeyRecord   = true;
  }
}

static void static_readDkim(EMAILAUTHCHECKRecord_t* record)
{
  if (record->m_dkimSelectorCount == 0)
  {
    record->m_dkimStatus = DNS_ANSWER_BAD_QUESTION;
    return;
  }

  bool              is_any_key_found = false;
  bool              is_any_answered  = false;
  DnsAnswerStatus_t first_failure    = DNS_ANSWER_OK;
  for (int i = 0; i < record->m_dkimSelectorCount; i++)
  {
    EmailCheckDkimSelector_t* selector = &record->ma_dkimSelectors[i];
    const DnsAnswer_t*        answer   = &selector->m_answer;
    if (!static_isAnswered(answer))
    {
      if (first_failure == DNS_ANSWER_OK)
        first_failure = answer->m_status;
      continue;
    }

    is_any_answered = true;
    static_readKeyRecords(selector);
    if (selector->m_hasKeyRecord)
      is_any_key_found = true;
  }

  if (record->m_dkimSelectorSource == EMAILCHECK_DKIM_SELECTOR_SOURCE_CALLER_GIVEN)
  {
    record->m_dkimStatus    = first_failure;
    record->m_dkimKeyStatus = is_any_key_found ? EMAILCHECK_DKIM_KEY_FOUND : EMAILCHECK_DKIM_KEY_NOT_FOUND;
    return;
  }
  record->m_dkimStatus    = is_any_answered ? DNS_ANSWER_OK : first_failure;
  record->m_dkimKeyStatus = is_any_key_found ? EMAILCHECK_DKIM_KEY_FOUND : EMAILCHECK_DKIM_KEY_UNKNOWN;
}

static EmailCheckResult_t static_worse(EmailCheckResult_t first, EmailCheckResult_t second)
{
  return first > second ? first : second;
}

static void static_addCheck(EMAILAUTHCHECKRecord_t* record, EmailCheckKind_t kind, EmailCheckResult_t result)
{
  assert(record->m_checkCount < EMAILCHECK_KIND_COUNT);
  record->ma_checks[record->m_checkCount++] = (EmailCheckItem_t){ kind, result };
}

static int static_findSpfAll(const EmailAuthSpf_t* spf)
{
  for (int i = 0; i < spf->m_termCount; i++)
    if (spf->ma_terms[i].m_kind == EMAILAUTH_SPF_TERM_ALL)
      return i;
  return -1;
}

static bool static_hasSpfTerm(const EmailAuthSpf_t* spf, EmailAuthSpfTermKind_t kind)
{
  for (int i = 0; i < spf->m_termCount; i++)
    if (spf->ma_terms[i].m_kind == kind)
      return true;
  return false;
}

static EmailCheckResult_t static_rateSpfAll(const EmailAuthSpf_t* spf)
{
  int all_index = static_findSpfAll(spf);
  if (all_index < 0)
    return static_hasSpfTerm(spf, EMAILAUTH_SPF_TERM_REDIRECT) ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN;

  EmailAuthQualifier_t qualifier = spf->ma_terms[all_index].m_qualifier;
  if (qualifier == EMAILAUTH_QUALIFIER_PASS)
    return EMAILCHECK_RESULT_FAIL;
  if (qualifier == EMAILAUTH_QUALIFIER_NEUTRAL)
    return EMAILCHECK_RESULT_WARN;
  return EMAILCHECK_RESULT_PASS;
}

static bool static_hasIgnoredSpfTerm(const EmailAuthSpf_t* spf)
{
  int all_index = static_findSpfAll(spf);
  if (all_index < 0)
    return false;
  if (static_hasSpfTerm(spf, EMAILAUTH_SPF_TERM_REDIRECT))
    return true;

  for (int i = all_index + 1; i < spf->m_termCount; i++)
    if (spf->ma_terms[i].m_kind <= EMAILAUTH_SPF_TERM_EXISTS)
      return true;
  return false;
}

static EmailCheckResult_t static_rateSpfWideRange(const EmailAuthSpf_t* spf)
{
  EmailCheckResult_t result = EMAILCHECK_RESULT_PASS;
  for (int i = 0; i < spf->m_termCount; i++)
  {
    const EmailAuthSpfTerm_t* term = &spf->ma_terms[i];
    bool is_range_term = term->m_kind == EMAILAUTH_SPF_TERM_IP4 || term->m_kind == EMAILAUTH_SPF_TERM_IP6 ||
                         term->m_kind == EMAILAUTH_SPF_TERM_A   || term->m_kind == EMAILAUTH_SPF_TERM_MX;
    if (!is_range_term || term->m_qualifier != EMAILAUTH_QUALIFIER_PASS)
      continue;
    if (term->m_ip4PrefixLength == 0 || term->m_ip6PrefixLength == 0)
      return EMAILCHECK_RESULT_FAIL;
    if ((term->m_ip4PrefixLength > 0 && term->m_ip4PrefixLength < EMAILCHECK_SPF_MIN_IP4_PREFIX_LENGTH) ||
        (term->m_ip6PrefixLength > 0 && term->m_ip6PrefixLength < EMAILCHECK_SPF_MIN_IP6_PREFIX_LENGTH))
    {
      result = EMAILCHECK_RESULT_WARN;
    }
  }
  return result;
}

static void static_rateSpf(EMAILAUTHCHECKRecord_t* record)
{
  bool is_single_record = record->m_spfRecordCount == 1;
  static_addCheck(record, EMAILCHECK_KIND_SPF_RECORD, is_single_record ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_FAIL);
  if (!is_single_record)
    return;

  const EmailAuthSpf_t* spf = &record->m_spfRecord;
  static_addCheck(record, EMAILCHECK_KIND_SPF_SYNTAX, spf->m_invalidTermCount == 0 ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_FAIL);
  static_addCheck(record, EMAILCHECK_KIND_SPF_LOOKUP_LIMIT,
                  spf->m_dnsLookupTermCount <= EMAILCHECK_SPF_MAX_DNS_LOOKUP_COUNT ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_FAIL);
  if (spf->m_unreadTermCount == 0)
  {
    static_addCheck(record, EMAILCHECK_KIND_SPF_ALL,           static_rateSpfAll(spf));
    static_addCheck(record, EMAILCHECK_KIND_SPF_IGNORED_TERMS, static_hasIgnoredSpfTerm(spf) ? EMAILCHECK_RESULT_WARN : EMAILCHECK_RESULT_PASS);
    static_addCheck(record, EMAILCHECK_KIND_SPF_PTR,           static_hasSpfTerm(spf, EMAILAUTH_SPF_TERM_PTR) ? EMAILCHECK_RESULT_WARN : EMAILCHECK_RESULT_PASS);
    static_addCheck(record, EMAILCHECK_KIND_SPF_WIDE_RANGE,    static_rateSpfWideRange(spf));
  }

  size_t record_size = record->m_spfAnswer.mp_texts[record->m_spfRecordIndex].m_byteCount;
  static_addCheck(record, EMAILCHECK_KIND_SPF_RECORD_SIZE, record_size <= EMAILCHECK_SPF_MAX_RECORD_SIZE ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN);
}

static void static_rateDmarc(EMAILAUTHCHECKRecord_t* record)
{
  bool is_record_check_failed = record->m_ownDmarcRecordCount == EMAILAUTH_RECORD_MANY || record->m_dmarcSource == EMAILCHECK_DMARC_SOURCE_NONE;
  static_addCheck(record, EMAILCHECK_KIND_DMARC_RECORD, is_record_check_failed ? EMAILCHECK_RESULT_FAIL : EMAILCHECK_RESULT_PASS);
  if (record->m_dmarcSource == EMAILCHECK_DMARC_SOURCE_NONE)
    return;

  EmailCheckResult_t policy_result = EMAILCHECK_RESULT_PASS;
  if (!record->m_isDmarcApplied)
    policy_result = EMAILCHECK_RESULT_FAIL;
  else if (record->m_appliedDmarcPolicy == EMAILAUTH_DMARC_POLICY_NONE)
    policy_result = EMAILCHECK_RESULT_WARN;

  static_addCheck(record, EMAILCHECK_KIND_DMARC_POLICY, policy_result);
  bool is_policy_enforced = record->m_appliedDmarcPolicy == EMAILAUTH_DMARC_POLICY_QUARANTINE ||
                            record->m_appliedDmarcPolicy == EMAILAUTH_DMARC_POLICY_REJECT;
  bool is_policy_weakened = record->m_dmarcRecord.m_testMode == EMAILAUTH_DMARC_TEST_MODE_ON && is_policy_enforced;

  static_addCheck(record, EMAILCHECK_KIND_DMARC_TEST_MODE, is_policy_weakened ? EMAILCHECK_RESULT_WARN : EMAILCHECK_RESULT_PASS);
  static_addCheck(record, EMAILCHECK_KIND_DMARC_REPORTING,
                  record->m_dmarcRecord.m_validAggregateUriCount > 0 ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN);
}

static void static_rateDkimKeys(EMAILAUTHCHECKRecord_t* record)
{
  EmailCheckResult_t usable_result     = EMAILCHECK_RESULT_FAIL;
  EmailCheckResult_t size_result       = EMAILCHECK_RESULT_PASS;
  EmailCheckResult_t format_result     = EMAILCHECK_RESULT_PASS;
  EmailCheckResult_t test_mode_result  = EMAILCHECK_RESULT_PASS;
  EmailCheckResult_t restricted_result = EMAILCHECK_RESULT_PASS;
  for (int i = 0; i < record->m_dkimSelectorCount; i++)
  {
    const EmailCheckDkimSelector_t* selector = &record->ma_dkimSelectors[i];
    if (!selector->m_hasKeyRecord)
      continue;
    const EmailAuthDkim_t* key = &selector->m_firstKeyRecord;
    if (key->m_keyState == EMAILAUTH_DKIM_KEY_UNKNOWN_TYPE && usable_result == EMAILCHECK_RESULT_FAIL)
      usable_result = EMAILCHECK_RESULT_WARN;
    if (key->m_keyState != EMAILAUTH_DKIM_KEY_PRESENT)
      continue;

    usable_result = EMAILCHECK_RESULT_PASS;
    if (key->m_keyType == EMAILAUTH_DKIM_KEY_TYPE_RSA && key->m_keyBits < EMAILCHECK_DKIM_MIN_RSA_KEY_BITS)
      size_result = EMAILCHECK_RESULT_FAIL;
    else if (key->m_keyType == EMAILAUTH_DKIM_KEY_TYPE_RSA &&
             (key->m_keyBits < EMAILCHECK_DKIM_STRONG_RSA_KEY_BITS || key->m_keyBits > EMAILCHECK_DKIM_MAX_RSA_KEY_BITS))
    {
      size_result = static_worse(size_result, EMAILCHECK_RESULT_WARN);
    }
    if (key->m_isBareRsaKey || key->m_isRsaModulusNegative || key->m_isVersionMisplaced)
      format_result = EMAILCHECK_RESULT_WARN;
    if (key->m_isTestMode)
      test_mode_result = EMAILCHECK_RESULT_WARN;
    if (!key->m_isSha256Allowed || !key->m_isEmailServiceAllowed)
      restricted_result = EMAILCHECK_RESULT_FAIL;
  }

  static_addCheck(record, EMAILCHECK_KIND_DKIM_KEY_USABLE, usable_result);
  if (usable_result != EMAILCHECK_RESULT_PASS)
    return;
  static_addCheck(record, EMAILCHECK_KIND_DKIM_KEY_SIZE, size_result);
  static_addCheck(record, EMAILCHECK_KIND_DKIM_KEY_FORMAT, format_result);
  static_addCheck(record, EMAILCHECK_KIND_DKIM_TEST_MODE, test_mode_result);
  static_addCheck(record, EMAILCHECK_KIND_DKIM_KEY_RESTRICTED, restricted_result);
}

static void static_rateDkim(EMAILAUTHCHECKRecord_t* record)
{
  EmailCheckResult_t found_result = EMAILCHECK_RESULT_PASS;
  if (record->m_dkimKeyStatus == EMAILCHECK_DKIM_KEY_NOT_FOUND)
    found_result = EMAILCHECK_RESULT_FAIL;
  else if (record->m_dkimKeyStatus == EMAILCHECK_DKIM_KEY_UNKNOWN)
    found_result = EMAILCHECK_RESULT_WARN;
  static_addCheck(record, EMAILCHECK_KIND_DKIM_KEY_FOUND, found_result);
  if (record->m_dkimKeyStatus != EMAILCHECK_DKIM_KEY_FOUND)
    return;

  static_rateDkimKeys(record);
  bool has_second_key = false;
  for (int i = 0; i < record->m_dkimSelectorCount; i++)
    has_second_key = has_second_key || record->ma_dkimSelectors[i].m_hasSecondKeyRecord;
  static_addCheck(record, EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS, has_second_key ? EMAILCHECK_RESULT_WARN : EMAILCHECK_RESULT_PASS);
}

static void static_rateRecord(EMAILAUTHCHECKRecord_t* record)
{
  if (static_isAnswered(&record->m_spfAnswer))
    static_rateSpf(record);
  if (record->m_dmarcStatus == DNS_ANSWER_OK)
    static_rateDmarc(record);
  if (record->m_dkimStatus == DNS_ANSWER_OK)
    static_rateDkim(record);
  if (static_isAnswered(&record->m_mxAnswer))
    static_addCheck(record, EMAILCHECK_KIND_MX,
                    record->m_mxAnswer.m_recordCount > 0 || record->m_mxAnswer.m_hasNullMx ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN);
  if (static_isAnswered(&record->m_mtaStsAnswer))
    static_addCheck(record, EMAILCHECK_KIND_MTA_STS, record->m_hasMtaStsRecord ? EMAILCHECK_RESULT_PASS : EMAILCHECK_RESULT_WARN);
}

static DnsLookupStatus_t static_readMailRoute(EMAILADDRESSCHECKRecord_t* record, const DnsAnswer_t* a_answer, const DnsAnswer_t* aaaa_answer)
{
  const DnsAnswer_t* mx_answer = &record->m_mxAnswer;
  if (mx_answer->m_status   == DNS_ANSWER_NO_MEMORY ||
      a_answer->m_status    == DNS_ANSWER_NO_MEMORY ||
      aaaa_answer->m_status == DNS_ANSWER_NO_MEMORY)
  {
    return DNS_LOOKUP_NO_MEMORY;
  }
  if (mx_answer->m_status == DNS_ANSWER_NXDOMAIN)
    return DNS_LOOKUP_NOT_FOUND;
  if (mx_answer->m_status != DNS_ANSWER_OK)
    return DNS_LOOKUP_NO_ANSWER;

  if (mx_answer->m_hasNullMx)
    record->m_mailRoute = EMAILCHECK_MAIL_ROUTE_NULL_MX;
  else if (mx_answer->m_recordCount > 0)
    record->m_mailRoute = EMAILCHECK_MAIL_ROUTE_MX;
  else if (static_hasRecord(a_answer) || static_hasRecord(aaaa_answer))
    record->m_mailRoute = EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX;
  else if (!static_isAnswered(a_answer) || !static_isAnswered(aaaa_answer))
    return DNS_LOOKUP_NO_ANSWER;
  else
    record->m_mailRoute = EMAILCHECK_MAIL_ROUTE_NONE;

  record->m_isDomainFound = true;
  return DNS_LOOKUP_OK;
}

static bool static_hasRecord(const DnsAnswer_t* answer)
{
  return answer->m_recordCount > 0;
}
