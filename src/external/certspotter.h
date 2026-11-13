#ifndef CERTSPOTTER_H
#define CERTSPOTTER_H

#include <stdbool.h>
#include <stddef.h>
#include <libpq-fe.h>

#include "quota.h"
#include "subdomain.h"
#include "validate.h"

#define CERTSPOTTER_LOOKUP_TIMEOUT_MS 10000

#define CERTSPOTTER_HOLD_NAME "certspotter"

#define CERTSPOTTER_MAX_PAGE_COUNT 5

#define CERTSPOTTER_CERTIFICATE_ID_MAX_LEN 20

#define CERTSPOTTER_SUBTREE_TIMEOUT_MS 3000

#define CERTSPOTTER_CERTIFICATE_MAX_COUNT 10

#define CERTSPOTTER_DNS_NAME_MAX_COUNT 20

#define CERTSPOTTER_CAA_DOMAIN_MAX_COUNT 16
#define CERTSPOTTER_CAA_DOMAIN_MAX_LEN   63

#define CERTSPOTTER_ISSUER_MAX_LEN 127

#define CERTSPOTTER_ISSUER_MAX_COUNT   16
#define CERTSPOTTER_ISSUER_KEY_MAX_LEN (CERTSPOTTER_CAA_DOMAIN_MAX_COUNT * (CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1) - 1)

#define CERTSPOTTER_TIME_LEN 20

#define CERTSPOTTER_SHA256_HEX_LEN 64

typedef enum {
  CERTSPOTTER_REVOCATION_UNKNOWN = 0,
  CERTSPOTTER_REVOCATION_NOT_REVOKED,
  CERTSPOTTER_REVOCATION_REVOKED,
} CertSpotterRevocation_t;

typedef struct {
  char                     ma_sha256Hex[CERTSPOTTER_SHA256_HEX_LEN + 1];
  char                     ma_issuer[CERTSPOTTER_ISSUER_MAX_LEN + 1];
  char                     ma_caaDomains[CERTSPOTTER_CAA_DOMAIN_MAX_COUNT][CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1];
  int                      m_caaDomainCount;
  bool                     m_isCaaDomainListKnown;
  char                     ma_validFrom[CERTSPOTTER_TIME_LEN + 1];
  char                     ma_validUntil[CERTSPOTTER_TIME_LEN + 1];
  CertSpotterRevocation_t  m_revocation;
  char                     ma_dnsNames[CERTSPOTTER_DNS_NAME_MAX_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  int                      m_dnsNameCount;
} CertSpotterCertificate_t;

typedef struct {
  char    ma_key[CERTSPOTTER_ISSUER_KEY_MAX_LEN + 1];
  char    ma_caaDomains[CERTSPOTTER_CAA_DOMAIN_MAX_COUNT][CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1];
  int     m_caaDomainCount;
  bool    m_isCaaDomainListKnown;
  bool    m_isSeenOnExactName;
  bool    m_isSeenOnWildcardName;
} CertSpotterIssuer_t;

typedef struct {
  CertSpotterCertificate_t  ma_certificates[CERTSPOTTER_CERTIFICATE_MAX_COUNT];
  int                       m_keptCount;
  int                       m_readCount;
  bool                      m_isComplete;
  CertSpotterIssuer_t       ma_issuers[CERTSPOTTER_ISSUER_MAX_COUNT];
  int                       m_issuerCount;
  bool                      m_isIssuerDropped;
} CertSpotterCertificateList_t;

typedef enum {
  CERTSPOTTER_OK = 0,
  CERTSPOTTER_RATE_LIMITED,
  CERTSPOTTER_UPSTREAM_ERROR,
  CERTSPOTTER_INVALID_NAME,
  CERTSPOTTER_NO_API_KEY,
  CERTSPOTTER_QUOTA_EXHAUSTED,
  CERTSPOTTER_DB_ERROR,
} CertSpotterStatus_t;

typedef enum {
  CERTSEARCH_UNAVAILABLE_NONE = 0,
  CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED,
} CERTSEARCHUnavailableReason_t;

typedef struct {
  char  ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} CERTSEARCHParams_t;

typedef struct {
  char                           ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  CERTSEARCHUnavailableReason_t  m_unavailableReason;
  unsigned int                   m_retryAfterSeconds;
  CertSpotterCertificateList_t   m_certificateList;
} CERTSEARCHRecord_t;

void                certspotter_setApiKey             (const char* api_key);
bool                certspotter_hasApiKey             (void);
CertSpotterStatus_t certspotter_lookupCertificates    (PGconn* conn, const QuotaRule_t* quota_rule, const char* host_name, CertSpotterCertificateList_t* list_out, unsigned int* retry_after_seconds_out);
bool                certspotter_tryReadSubdomainNames (const char* body, size_t body_len, const char* domain, SubdomainNameSet_t* name_set, bool* is_answer_empty_out);
CertSpotterStatus_t certspotter_lookupSubdomainNames  (const char* domain, SubdomainNameSet_t* name_set, bool* is_answer_empty_out, unsigned int* retry_after_seconds_out);

#endif
