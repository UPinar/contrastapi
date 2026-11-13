#ifndef EMAILAUTH_H
#define EMAILAUTH_H

#include <stdbool.h>
#include <stddef.h>

#include "dns.h"

typedef struct {
  const char* mp_bytes;
  size_t      m_byteCount;
} EmailAuthSpan_t;

typedef enum {
  EMAILAUTH_RECORD_NONE = 0,
  EMAILAUTH_RECORD_ONE,
  EMAILAUTH_RECORD_MANY,
} EmailAuthRecordCount_t;

typedef enum {
  EMAILAUTH_QUALIFIER_PASS = 0,
  EMAILAUTH_QUALIFIER_FAIL,
  EMAILAUTH_QUALIFIER_SOFTFAIL,
  EMAILAUTH_QUALIFIER_NEUTRAL,
} EmailAuthQualifier_t;

typedef enum {
  EMAILAUTH_SPF_TERM_ALL = 0,
  EMAILAUTH_SPF_TERM_INCLUDE,
  EMAILAUTH_SPF_TERM_A,
  EMAILAUTH_SPF_TERM_MX,
  EMAILAUTH_SPF_TERM_PTR,
  EMAILAUTH_SPF_TERM_IP4,
  EMAILAUTH_SPF_TERM_IP6,
  EMAILAUTH_SPF_TERM_EXISTS,
  EMAILAUTH_SPF_TERM_REDIRECT,
  EMAILAUTH_SPF_TERM_EXP,
  EMAILAUTH_SPF_TERM_UNKNOWN_MODIFIER,
  EMAILAUTH_SPF_TERM_INVALID,
} EmailAuthSpfTermKind_t;

typedef struct {
  EmailAuthSpfTermKind_t m_kind;
  EmailAuthQualifier_t   m_qualifier;
  EmailAuthSpan_t        m_value;
  int                    m_ip4PrefixLength;
  int                    m_ip6PrefixLength;
} EmailAuthSpfTerm_t;

#define EMAILAUTH_SPF_MAX_TERM_COUNT 64

typedef struct {
  EmailAuthSpfTerm_t ma_terms[EMAILAUTH_SPF_MAX_TERM_COUNT];
  int                m_termCount;
  int                m_unreadTermCount;
  int                m_dnsLookupTermCount;
  int                m_invalidTermCount;
} EmailAuthSpf_t;

typedef enum {
  EMAILAUTH_DMARC_POLICY_ABSENT = 0,
  EMAILAUTH_DMARC_POLICY_NONE,
  EMAILAUTH_DMARC_POLICY_QUARANTINE,
  EMAILAUTH_DMARC_POLICY_REJECT,
  EMAILAUTH_DMARC_POLICY_INVALID,
} EmailAuthDmarcPolicy_t;

typedef enum {
  EMAILAUTH_ALIGNMENT_RELAXED = 0,
  EMAILAUTH_ALIGNMENT_STRICT,
  EMAILAUTH_ALIGNMENT_INVALID,
} EmailAuthAlignment_t;

typedef enum {
  EMAILAUTH_DMARC_TEST_MODE_ABSENT = 0,
  EMAILAUTH_DMARC_TEST_MODE_OFF,
  EMAILAUTH_DMARC_TEST_MODE_ON,
  EMAILAUTH_DMARC_TEST_MODE_INVALID,
} EmailAuthDmarcTestMode_t;

typedef enum {
  EMAILAUTH_DMARC_DOMAIN_ROLE_ABSENT = 0,
  EMAILAUTH_DMARC_DOMAIN_ROLE_PUBLIC_SUFFIX,
  EMAILAUTH_DMARC_DOMAIN_ROLE_ORGANIZATIONAL,
  EMAILAUTH_DMARC_DOMAIN_ROLE_NOT_PUBLIC_SUFFIX,
  EMAILAUTH_DMARC_DOMAIN_ROLE_INVALID,
} EmailAuthDmarcDomainRole_t;

typedef enum {
  EMAILAUTH_DMARC_FAILURE_OPTION_ALL_FAIL  = 1u << 0,
  EMAILAUTH_DMARC_FAILURE_OPTION_ANY_FAIL  = 1u << 1,
  EMAILAUTH_DMARC_FAILURE_OPTION_DKIM_FAIL = 1u << 2,
  EMAILAUTH_DMARC_FAILURE_OPTION_SPF_FAIL  = 1u << 3,
} EmailAuthDmarcFailureOption_t;

typedef enum {
  EMAILAUTH_DMARC_URI_MAILTO = 0,
  EMAILAUTH_DMARC_URI_OTHER_SCHEME,
  EMAILAUTH_DMARC_URI_INVALID,
} EmailAuthDmarcUriKind_t;

typedef struct {
  EmailAuthSpan_t         m_uri;
  EmailAuthDmarcUriKind_t m_kind;
  bool                    m_hasSizeLimit;
} EmailAuthDmarcUri_t;

#define EMAILAUTH_DMARC_MAX_URI_COUNT 8

typedef struct {
  EmailAuthDmarcPolicy_t     m_policy;
  EmailAuthDmarcPolicy_t     m_subdomainPolicy;
  EmailAuthDmarcPolicy_t     m_nonexistentSubdomainPolicy;
  bool                       m_isPercentValid;
  int                        m_percent;
  EmailAuthAlignment_t       m_spfAlignment;
  EmailAuthAlignment_t       m_dkimAlignment;
  EmailAuthDmarcTestMode_t   m_testMode;
  EmailAuthDmarcDomainRole_t m_domainRole;
  bool                       m_isFailureOptionsValid;
  unsigned int               m_failureOptions;
  EmailAuthDmarcUri_t        ma_aggregateUris[EMAILAUTH_DMARC_MAX_URI_COUNT];
  int                        m_aggregateUriCount;
  int                        m_validAggregateUriCount;
  EmailAuthDmarcUri_t        ma_failureUris[EMAILAUTH_DMARC_MAX_URI_COUNT];
  int                        m_failureUriCount;
  int                        m_skippedUriCount;
  int                        m_invalidTagCount;
  int                        m_repeatedTagCount;
} EmailAuthDmarc_t;

#define EMAILAUTH_DKIM_MAX_TAG_COUNT 16

typedef enum {
  EMAILAUTH_DKIM_KEY_PRESENT = 0,
  EMAILAUTH_DKIM_KEY_REVOKED,
  EMAILAUTH_DKIM_KEY_UNREADABLE,
  EMAILAUTH_DKIM_KEY_ABSENT,
  EMAILAUTH_DKIM_KEY_UNKNOWN_TYPE,
} EmailAuthDkimKeyState_t;

typedef enum {
  EMAILAUTH_DKIM_KEY_TYPE_RSA = 0,
  EMAILAUTH_DKIM_KEY_TYPE_ED25519,
  EMAILAUTH_DKIM_KEY_TYPE_OTHER,
} EmailAuthDkimKeyType_t;

typedef struct {
  EmailAuthDkimKeyState_t m_keyState;
  EmailAuthDkimKeyType_t  m_keyType;
  EmailAuthSpan_t         m_keyTypeName;
  bool                    m_isTestMode;
  bool                    m_isSha256Allowed;
  bool                    m_isEmailServiceAllowed;
  bool                    m_isVersionMisplaced;
  int                     m_keyBits;
  bool                    m_isBareRsaKey;
  bool                    m_isRsaModulusNegative;
} EmailAuthDkim_t;

bool                   emailauth_isSpfRecord       (const DnsRecordText_t* text);
bool                   emailauth_isDmarcRecord     (const DnsRecordText_t* text);
EmailAuthRecordCount_t emailauth_countSpfRecords   (const DnsRecordText_t* texts, int text_count, int* first_index_out);
EmailAuthRecordCount_t emailauth_countDmarcRecords (const DnsRecordText_t* texts, int text_count, int* first_index_out);
void                   emailauth_parseSpf          (const DnsRecordText_t* record, EmailAuthSpf_t* spf_out);
void                   emailauth_parseDmarc        (const DnsRecordText_t* record, EmailAuthDmarc_t* dmarc_out);
void                   emailauth_parseDkim         (const DnsRecordText_t* record, EmailAuthDkim_t* dkim_out);

#endif
