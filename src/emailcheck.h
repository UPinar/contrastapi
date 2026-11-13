#ifndef EMAILCHECK_H
#define EMAILCHECK_H

#include <stdbool.h>

#include "dns.h"
#include "emailauth.h"
#include "emaildata.h"
#include "validate.h"

#define EMAILCHECK_DMARC_WALK_MAX_NAME_COUNT 7

#define EMAILCHECK_DMARC_MAX_NAME_COUNT   (1 + EMAILCHECK_DMARC_WALK_MAX_NAME_COUNT)

#define EMAILCHECK_MAX_DKIM_SELECTOR_COUNT  (DNS_MAX_QUESTION_COUNT - EMAILCHECK_DMARC_WALK_MAX_NAME_COUNT)

#define EMAILCHECK_NAME_TOO_LONG_REFUSAL_MESSAGE  "dkim_selector and domain make a name longer than 253 bytes"

typedef enum {
  EMAILCHECK_DMARC_SOURCE_NONE = 0,
  EMAILCHECK_DMARC_SOURCE_DOMAIN,
  EMAILCHECK_DMARC_SOURCE_ORGANIZATIONAL,
  EMAILCHECK_DMARC_SOURCE_PUBLIC_SUFFIX,
} EmailCheckDmarcSource_t;

typedef enum {
  EMAILCHECK_DKIM_SELECTOR_SOURCE_CALLER_GIVEN = 0,
  EMAILCHECK_DKIM_SELECTOR_SOURCE_PROVIDER,
  EMAILCHECK_DKIM_SELECTOR_SOURCE_COMMON,
} EmailCheckDkimSelectorSource_t;

typedef enum {
  EMAILCHECK_DKIM_KEY_FOUND = 0,
  EMAILCHECK_DKIM_KEY_NOT_FOUND,
  EMAILCHECK_DKIM_KEY_UNKNOWN,
} EmailCheckDkimKeyStatus_t;

typedef struct {
  char              ma_selector[VALIDATE_DKIM_SELECTOR_MAX_LEN + 1];
  DnsAnswer_t       m_answer;
  bool              m_hasKeyRecord;
  EmailAuthDkim_t   m_firstKeyRecord;
  bool              m_hasSecondKeyRecord;
} EmailCheckDkimSelector_t;

typedef enum {
  EMAILCHECK_KIND_SPF_RECORD = 0,
  EMAILCHECK_KIND_SPF_SYNTAX,
  EMAILCHECK_KIND_SPF_LOOKUP_LIMIT,
  EMAILCHECK_KIND_SPF_ALL,
  EMAILCHECK_KIND_SPF_IGNORED_TERMS,
  EMAILCHECK_KIND_SPF_PTR,
  EMAILCHECK_KIND_SPF_WIDE_RANGE,
  EMAILCHECK_KIND_SPF_RECORD_SIZE,
  EMAILCHECK_KIND_DMARC_RECORD,
  EMAILCHECK_KIND_DMARC_POLICY,
  EMAILCHECK_KIND_DMARC_TEST_MODE,
  EMAILCHECK_KIND_DMARC_REPORTING,
  EMAILCHECK_KIND_DKIM_KEY_FOUND,
  EMAILCHECK_KIND_DKIM_KEY_USABLE,
  EMAILCHECK_KIND_DKIM_KEY_SIZE,
  EMAILCHECK_KIND_DKIM_KEY_FORMAT,
  EMAILCHECK_KIND_DKIM_TEST_MODE,
  EMAILCHECK_KIND_DKIM_KEY_RESTRICTED,
  EMAILCHECK_KIND_DKIM_MULTIPLE_KEYS,
  EMAILCHECK_KIND_MX,
  EMAILCHECK_KIND_MTA_STS,
} EmailCheckKind_t;

#define EMAILCHECK_KIND_COUNT 21

#define EMAILCHECK_KIND_ID_MAX_LEN 19

typedef enum {
  EMAILCHECK_RESULT_PASS = 0,
  EMAILCHECK_RESULT_WARN,
  EMAILCHECK_RESULT_FAIL,
} EmailCheckResult_t;

#define EMAILCHECK_RESULT_COUNT 3

typedef struct {
  EmailCheckKind_t   m_kind;
  EmailCheckResult_t m_result;
} EmailCheckItem_t;

typedef struct {
  char ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char ma_dkimSelector[VALIDATE_DKIM_SELECTOR_MAX_LEN + 1];
} EMAILAUTHCHECKParams_t;

typedef struct {
  char                            ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsAnswer_t                     m_spfAnswer;
  int                             m_spfRecordCount;
  int                             m_spfRecordIndex;
  EmailAuthSpf_t                  m_spfRecord;
  char                            ma_dmarcNames[EMAILCHECK_DMARC_MAX_NAME_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  DnsAnswer_t                     ma_dmarcAnswers[EMAILCHECK_DMARC_MAX_NAME_COUNT];
  int                             m_dmarcNameCount;
  DnsAnswerStatus_t               m_dmarcStatus;
  EmailAuthRecordCount_t          m_ownDmarcRecordCount;
  EmailCheckDmarcSource_t         m_dmarcSource;
  int                             m_dmarcNameIndex;
  int                             m_dmarcRecordIndex;
  EmailAuthDmarc_t                m_dmarcRecord;
  bool                            m_isDmarcApplied;
  EmailAuthDmarcPolicy_t          m_appliedDmarcPolicy;
  DnsAnswer_t                     m_mxAnswer;
  const EmailDataProvider_t*      ma_mailProviders[EMAILDATA_PROVIDER_COUNT];
  int                             m_mailProviderCount;
  DnsAnswer_t                     m_mtaStsAnswer;
  bool                            m_hasMtaStsRecord;
  EmailCheckDkimSelector_t        ma_dkimSelectors[EMAILCHECK_MAX_DKIM_SELECTOR_COUNT];
  int                             m_dkimSelectorCount;
  EmailCheckDkimSelectorSource_t  m_dkimSelectorSource;
  DnsAnswerStatus_t               m_dkimStatus;
  EmailCheckDkimKeyStatus_t       m_dkimKeyStatus;
  EmailCheckItem_t                ma_checks[EMAILCHECK_KIND_COUNT];
  int                             m_checkCount;
} EMAILAUTHCHECKRecord_t;

typedef struct {
  char  ma_email[VALIDATE_EMAIL_ADDRESS_MAX_LEN + 1];
} EMAILADDRESSCHECKParams_t;

typedef enum {
  EMAILCHECK_MAIL_ROUTE_NONE = 0,
  EMAILCHECK_MAIL_ROUTE_MX,
  EMAILCHECK_MAIL_ROUTE_IMPLICIT_MX,
  EMAILCHECK_MAIL_ROUTE_NULL_MX,
} EmailCheckMailRoute_t;

typedef struct {
  char                    ma_email[VALIDATE_EMAIL_ADDRESS_MAX_LEN + 1];
  char                    ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  bool                    m_isDisposableFeedLoaded;
  char                    ma_disposableListedDomain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  bool                    m_isDomainFound;
  EmailCheckMailRoute_t   m_mailRoute;
  DnsAnswer_t             m_mxAnswer;
} EMAILADDRESSCHECKRecord_t;

DnsLookupStatus_t emailcheck_checkDomain                  (const char* domain, const char* dkim_selector, EMAILAUTHCHECKRecord_t* record_out);
void              emailcheck_EMAILAUTHCHECKRecordFree     (EMAILAUTHCHECKRecord_t* record);
DnsLookupStatus_t emailcheck_checkAddressDomain           (const char* domain, EMAILADDRESSCHECKRecord_t* record);
void              emailcheck_EMAILADDRESSCHECKRecordFree  (EMAILADDRESSCHECKRecord_t* record);
const char*       emailcheck_kindId                       (EmailCheckKind_t kind);

#endif
