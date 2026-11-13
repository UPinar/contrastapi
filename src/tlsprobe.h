#ifndef TLSPROBE_H
#define TLSPROBE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "validate.h"

#define TLSPROBE_PORT 443

#define TLSPROBE_DEADLINE_MS         5000
#define TLSPROBE_RESOLVE_DEADLINE_MS 2500
#define TLSPROBE_CONNECT_DEADLINE_MS 2000

#define TLSPROBE_DNS_NAME_MAX_COUNT 100
#define TLSPROBE_CHAIN_MAX_COUNT    10

#define TLSPROBE_CHAIN_CHECK_SECURITY_LEVEL 2
#define TLSPROBE_CHAIN_CHECK_MAX_DEPTH      10

#define TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE 513

#define TLSPROBE_CERTIFICATE_SHA256_HEX_SIZE  65
#define TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE    41
#define TLSPROBE_CERTIFICATE_SERIAL_HEX_SIZE  41
#define TLSPROBE_TIME_TEXT_SIZE               21

#define TLSPROBE_ALGORITHM_TEXT_SIZE          64
#define TLSPROBE_KEY_TYPE_TEXT_SIZE           64
#define TLSPROBE_KEY_EXCHANGE_GROUP_TEXT_SIZE 64
#define TLSPROBE_PROTOCOL_TEXT_SIZE           16
#define TLSPROBE_ALPN_PROTOCOL_TEXT_SIZE      16
#define TLSPROBE_CIPHER_TEXT_SIZE             64

typedef enum {
  TLSPROBE_OK = 0,
  TLSPROBE_INVALID_NAME,
  TLSPROBE_NAME_NOT_FOUND,
  TLSPROBE_RESOLVE_FAILED,
  TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE,
  TLSPROBE_CONNECT_FAILED,
  TLSPROBE_TIMEOUT,
  TLSPROBE_HANDSHAKE_FAILED,
  TLSPROBE_NO_MEMORY,
} TlsProbeStatus_t;

typedef enum {
  TLSPROBE_PROBLEM_EXPIRED           = 1u << 0,
  TLSPROBE_PROBLEM_NOT_YET_VALID     = 1u << 1,
  TLSPROBE_PROBLEM_SELF_SIGNED       = 1u << 2,
  TLSPROBE_PROBLEM_UNTRUSTED_ROOT    = 1u << 3,
  TLSPROBE_PROBLEM_HOSTNAME_MISMATCH = 1u << 4,
  TLSPROBE_PROBLEM_CHAIN_INCOMPLETE  = 1u << 5,
  TLSPROBE_PROBLEM_OTHER             = 1u << 6,
  TLSPROBE_PROBLEM_WEAK_CRYPTO       = 1u << 7,
} TlsProbeCertificateProblem_t;

typedef struct {
  unsigned int m_bit;
  const char*  mp_name;
} TlsProbeProblemName_t;

#define TLSPROBE_PROBLEM_NAME_COUNT 8

extern const TlsProbeProblemName_t tlsprobe_problemNames[TLSPROBE_PROBLEM_NAME_COUNT];

typedef enum {
  TLSPROBE_REVOKE_NOT_SENT = 0,
  TLSPROBE_REVOKE_NOT_REVOKED,
  TLSPROBE_REVOKE_REVOKED,
  TLSPROBE_REVOKE_UNKNOWN,
  TLSPROBE_REVOKE_UNUSABLE,
} TlsProbeRevokeStatus_t;

typedef enum {
  TLSPROBE_SECURE_RENEGOTIATION_NOT_APPLICABLE = 0,
  TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED,
  TLSPROBE_SECURE_RENEGOTIATION_NOT_SUPPORTED,
} TlsProbeSecureRenegotiation_t;

typedef enum {
  TLSPROBE_HANDSHAKE_ERROR_NONE = 0,
  TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS,
  TLSPROBE_HANDSHAKE_ERROR_PEER_CLOSED,
  TLSPROBE_HANDSHAKE_ERROR_PROTOCOL_VERSION,
  TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE,
  TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME,
  TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED,
  TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT,
  TLSPROBE_HANDSHAKE_ERROR_NO_CERTIFICATE,
  TLSPROBE_HANDSHAKE_ERROR_OTHER,
} TlsProbeHandshakeError_t;

typedef struct {
  char    ma_sha256Hex[TLSPROBE_CERTIFICATE_SHA256_HEX_SIZE];
  char    ma_sha1Hex[TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE];
  char    ma_validFrom[TLSPROBE_TIME_TEXT_SIZE];
  char    ma_validUntil[TLSPROBE_TIME_TEXT_SIZE];
  int64_t m_validUntilUnixSeconds;
  char    ma_issuer[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE];
  char    ma_subject[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE];
  char    ma_serialHex[TLSPROBE_CERTIFICATE_SERIAL_HEX_SIZE];
  char    ma_signatureAlgorithm[TLSPROBE_ALGORITHM_TEXT_SIZE];
  char    ma_keyType[TLSPROBE_KEY_TYPE_TEXT_SIZE];
  int     m_keyBits;
  char    ma_dnsNames[TLSPROBE_DNS_NAME_MAX_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  int     m_dnsNameCount;
  bool    m_isDnsNameListTruncated;
} TlsProbeCertificate_t;

typedef struct {
  char  ma_subjectFullName[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE];
  char  ma_issuerFullName[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE];
  char  ma_validUntil[TLSPROBE_TIME_TEXT_SIZE];
} TlsProbeChainCertificate_t;

typedef struct {
  char                          ma_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char                          ma_ipAddress[INET6_ADDRSTRLEN];
  char                          ma_protocol[TLSPROBE_PROTOCOL_TEXT_SIZE];
  char                          ma_cipherName[TLSPROBE_CIPHER_TEXT_SIZE];
  int                           m_cipherBits;
  char                          ma_keyExchangeGroup[TLSPROBE_KEY_EXCHANGE_GROUP_TEXT_SIZE];
  int                           m_keyExchangeBits;
  char                          ma_alpnProtocol[TLSPROBE_ALPN_PROTOCOL_TEXT_SIZE];
  TlsProbeCertificate_t         m_serverCertificate;
  TlsProbeChainCertificate_t    ma_chain[TLSPROBE_CHAIN_MAX_COUNT];
  int                           m_chainCount;
  bool                          m_isChainTruncated;
  unsigned int                  m_problems;
  bool                          m_isTrusted;
  TlsProbeRevokeStatus_t        m_revokeStatus;
  int                           m_daysRemaining;
  TlsProbeSecureRenegotiation_t m_secureRenegotiation;
  TlsProbeHandshakeError_t      m_handshakeError;
} TlsProbeResult_t;

typedef struct {
  char ma_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} SSLCHECKParams_t;

#define SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN 128

typedef struct {
  TlsProbeResult_t  m_result;
  char              ma_checkedAt[TLSPROBE_TIME_TEXT_SIZE];
  bool              m_isBlacklistUnavailable;
  bool              m_isBlacklistFeedLoaded;
  char              ma_blacklistListingReason[SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN + 1];
  char              ma_blacklistListingTime[TLSPROBE_TIME_TEXT_SIZE];
} SSLCHECKRecord_t;

#define TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE_REFUSAL_MESSAGE "hostname has no globally reachable address"

TlsProbeStatus_t tlsprobe_probeHost          (const char* hostname, TlsProbeResult_t* result_out);
TlsProbeStatus_t tlsprobe_probeIpAddress     (const struct sockaddr* ip_address, socklen_t ip_address_len, const char* hostname, TlsProbeResult_t* result_out);
bool             tlsprobe_tryReadCertificate (const unsigned char* der, size_t der_len, TlsProbeCertificate_t* certificate_out);
unsigned int     tlsprobe_problemsFromCertificateError(long certificate_error_code);
int              tlsprobe_daysRemaining      (int64_t valid_until_unix_seconds, int64_t now_unix_seconds);

#endif
