#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "bytes.h"
#include "datetime.h"
#include "dns.h"
#include "ipguard.h"
#include "monotonic.h"
#include "netconnect.h"
#include "tlsprobe.h"
#include "validate.h"

#define ALLOWED_CLOCK_DIFFERENCE_SECONDS 300

#define ALPN_PROTOCOL_LIST "\x02h2\x08http/1.1"

typedef struct {
  unsigned int m_problems;
  bool         m_isClientCertificateRequested;
} TlsProbeHandshakeState_t;

static pthread_once_t g_tlsSettingsOnce = PTHREAD_ONCE_INIT;
static SSL_CTX*       g_tlsSettings;

static void                   static_buildTlsSettings               (void);
static int                    static_recordCertificateError         (int is_preverify_ok, X509_STORE_CTX* store_context);
static int                    static_recordCertificateRequest       (SSL* ssl, X509** certificate_out, EVP_PKEY** key_out);
static int                    static_recordWeakCrypto               (int is_preverify_ok, X509_STORE_CTX* store_context);
static void                   static_writeLowerCase                 (const char* text, char* text_out);
static void                   static_copyIfFits                     (const char* text, char* text_out, size_t text_out_size);
static void                   static_clearFailedResult              (TlsProbeResult_t* result_out);
static TlsProbeStatus_t       static_probeAnswers                   (const DnsAnswer_t* address_answers, int address_answer_count, int64_t deadline_at, TlsProbeResult_t* result_out);
static TlsProbeStatus_t       static_statusWithoutReachableAddress  (const DnsAnswer_t* address_answers, int address_answer_count);
static TlsProbeStatus_t       static_probeAddressUntil              (const struct sockaddr* address, socklen_t address_len, int64_t deadline_at, TlsProbeResult_t* result_out);
static void                   static_writeIpAddressText             (const struct sockaddr* ip_address, char* text_out);
static TlsProbeStatus_t       static_handshakeAndRead               (int fd, int64_t deadline_at, TlsProbeResult_t* result_out);
static TlsProbeStatus_t       static_runHandshake                   (SSL* ssl, int fd, int64_t deadline_at);
static void                   static_writeHandshakeError            (bool is_client_certificate_requested, TlsProbeResult_t* result_out);
static TlsProbeStatus_t       static_readHandshakeResult            (SSL* ssl, unsigned int problems, TlsProbeResult_t* result_out);
static void                   static_readKeyExchange                (SSL* ssl, TlsProbeResult_t* result_out);
static bool                   static_tryCheckChainAgain             (X509* server_certificate, STACK_OF(X509)* chain, unsigned int* problems_out);
static bool                   static_tryReadX509                    (X509* certificate, TlsProbeCertificate_t* certificate_out);
static bool                   static_tryWriteDigestHex              (X509* certificate, const EVP_MD* digest_type, char* hex_out, size_t hex_size);
static bool                   static_tryWriteCertificateTime        (const ASN1_TIME* asn1_time, char* text_out, int64_t* unix_seconds_out);
static void                   static_writeNamePart                  (const X509_NAME* name, int part_type, char* text_out);
static void                   static_writeFullName                  (const X509_NAME* name, char* text_out);
static void                   static_writeSerialHex                 (const X509* certificate, char* text_out);
static void                   static_readDnsNames                   (const X509* certificate, TlsProbeCertificate_t* certificate_out);
static void                   static_readChain                      (const STACK_OF(X509)* chain, TlsProbeResult_t* result_out);
static TlsProbeRevokeStatus_t static_readRevokeStatus               (SSL* ssl, X509* server_certificate);
static TlsProbeRevokeStatus_t static_readOcspResponse               (SSL* ssl, X509* server_certificate, OCSP_RESPONSE* response);
static TlsProbeRevokeStatus_t static_findCertificateStatus          (OCSP_BASICRESP* basic_response, X509* server_certificate, X509* issuer);
static X509*                  static_findIssuer                     (SSL* ssl, X509* server_certificate, OCSP_BASICRESP* basic_response);

TlsProbeStatus_t tlsprobe_probeHost(const char* hostname, TlsProbeResult_t* result_out)
{
  assert(hostname   != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  int64_t deadline_at = monotonic_nowMs() + TLSPROBE_DEADLINE_MS;

  if (!validate_publicDnsName(hostname))
    return TLSPROBE_INVALID_NAME;

  static_writeLowerCase(hostname, result_out->ma_hostname);

  DnsQuestion_t questions[] = {
    { .mp_domainName = result_out->ma_hostname, .m_type = DNS_RECORD_TYPE_A    },
    { .mp_domainName = result_out->ma_hostname, .m_type = DNS_RECORD_TYPE_AAAA },
  };
  int question_count = (int)(sizeof(questions) / sizeof(questions[0]));
  DnsAnswer_t address_answers[sizeof(questions) / sizeof(questions[0])];
  dns_askQuestions(questions, question_count, TLSPROBE_RESOLVE_DEADLINE_MS, address_answers);

  TlsProbeStatus_t status = static_probeAnswers(address_answers, question_count, deadline_at, result_out);
  if (status != TLSPROBE_OK)
    static_clearFailedResult(result_out);

  for (int i = 0; i < question_count; i++)
    dns_answerFree(&address_answers[i]);

  return status;
}

TlsProbeStatus_t tlsprobe_probeIpAddress(const struct sockaddr* ip_address, socklen_t ip_address_len, const char* hostname, TlsProbeResult_t* result_out)
{
  assert(ip_address != NULL);
  assert(hostname   != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  int64_t deadline_at = monotonic_nowMs() + TLSPROBE_DEADLINE_MS;

  if (!validate_publicDnsName(hostname))
    return TLSPROBE_INVALID_NAME;

  struct sockaddr_storage address_copy = { 0 };
  if (ip_address->sa_family == AF_INET && ip_address_len == sizeof(struct sockaddr_in))
  {
    memcpy(&address_copy, ip_address, ip_address_len);
    ((struct sockaddr_in*)&address_copy)->sin_port = htons(TLSPROBE_PORT);
  }
  else if (ip_address->sa_family == AF_INET6 && ip_address_len == sizeof(struct sockaddr_in6))
  {
    memcpy(&address_copy, ip_address, ip_address_len);
    ((struct sockaddr_in6*)&address_copy)->sin6_port = htons(TLSPROBE_PORT);
  }
  else
  {
    return TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE;
  }

  static_writeLowerCase(hostname, result_out->ma_hostname);

  TlsProbeStatus_t status = static_probeAddressUntil((const struct sockaddr*)&address_copy, ip_address_len, deadline_at, result_out);
  if (status != TLSPROBE_OK)
    static_clearFailedResult(result_out);

  return status;
}

bool tlsprobe_tryReadCertificate(const unsigned char* der, size_t der_len, TlsProbeCertificate_t* certificate_out)
{
  assert(der != NULL || der_len == 0);
  assert(certificate_out != NULL);

  memset(certificate_out, 0, sizeof(*certificate_out));
  if (der_len > LONG_MAX)
    return false;

  const unsigned char* cursor = der;
  X509* certificate = d2i_X509(NULL, &cursor, (long)der_len);
  if (certificate == NULL)
    return false;

  bool is_read = cursor == der + der_len && static_tryReadX509(certificate, certificate_out);
  X509_free(certificate);

  if (!is_read)
    memset(certificate_out, 0, sizeof(*certificate_out));

  return is_read;
}

unsigned int tlsprobe_problemsFromCertificateError(long certificate_error_code)
{
  switch (certificate_error_code)
  {
    case X509_V_OK:
      return 0;
    case X509_V_ERR_CERT_HAS_EXPIRED:
      return TLSPROBE_PROBLEM_EXPIRED;
    case X509_V_ERR_CERT_NOT_YET_VALID:
      return TLSPROBE_PROBLEM_NOT_YET_VALID;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      return TLSPROBE_PROBLEM_SELF_SIGNED;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      return TLSPROBE_PROBLEM_UNTRUSTED_ROOT;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      return TLSPROBE_PROBLEM_CHAIN_INCOMPLETE;
    case X509_V_ERR_HOSTNAME_MISMATCH:
      return TLSPROBE_PROBLEM_HOSTNAME_MISMATCH;
    case X509_V_ERR_EE_KEY_TOO_SMALL:
    case X509_V_ERR_CA_KEY_TOO_SMALL:
    case X509_V_ERR_CA_MD_TOO_WEAK:
      return TLSPROBE_PROBLEM_WEAK_CRYPTO;
    default:
      return TLSPROBE_PROBLEM_OTHER;
  }
}

int tlsprobe_daysRemaining(int64_t valid_until_unix_seconds, int64_t now_unix_seconds)
{
  return datetime_daysUntil(valid_until_unix_seconds, now_unix_seconds);
}

static void static_buildTlsSettings(void)
{
  SSL_CTX* settings = SSL_CTX_new(TLS_client_method());
  if (settings == NULL)
    return;

  if (SSL_CTX_set_min_proto_version(settings, TLS1_VERSION) != 1 || SSL_CTX_set_default_verify_paths(settings) != 1)
  {
    SSL_CTX_free(settings);
    return;
  }

  SSL_CTX_set_security_level(settings, 0);
  SSL_CTX_set_options(settings, SSL_OP_LEGACY_SERVER_CONNECT);
  SSL_CTX_set_verify(settings, SSL_VERIFY_NONE, static_recordCertificateError);
  SSL_CTX_set_client_cert_cb(settings, static_recordCertificateRequest);
  SSL_CTX_set_verify_depth(settings, TLSPROBE_CHAIN_CHECK_MAX_DEPTH);
  g_tlsSettings = settings;
}

static int static_recordCertificateError(int is_preverify_ok, X509_STORE_CTX* store_context)
{
  if (is_preverify_ok == 0)
  {
    const SSL* ssl = X509_STORE_CTX_get_ex_data(store_context, SSL_get_ex_data_X509_STORE_CTX_idx());
    TlsProbeHandshakeState_t* handshake = SSL_get_app_data(ssl);
    handshake->m_problems |= tlsprobe_problemsFromCertificateError(X509_STORE_CTX_get_error(store_context));
  }
  return 1;
}

static int static_recordCertificateRequest(SSL* ssl, X509** certificate_out, EVP_PKEY** key_out)
{
  (void)certificate_out;
  (void)key_out;

  TlsProbeHandshakeState_t* handshake = SSL_get_app_data(ssl);
  handshake->m_isClientCertificateRequested = true;
  return 0;
}

static int static_recordWeakCrypto(int is_preverify_ok, X509_STORE_CTX* store_context)
{
  if (is_preverify_ok == 0)
  {
    unsigned int problem = tlsprobe_problemsFromCertificateError(X509_STORE_CTX_get_error(store_context));
    if (problem == TLSPROBE_PROBLEM_WEAK_CRYPTO)
    {
      unsigned int* problems = X509_STORE_CTX_get_app_data(store_context);
      *problems |= problem;
    }
  }
  return 1;
}

static void static_writeLowerCase(const char* text, char* text_out)
{
  size_t text_len = strlen(text);
  assert(text_len <= VALIDATE_DOMAIN_NAME_MAX_LEN);

  for (size_t i = 0; i < text_len; i++)
    text_out[i] = (char)tolower((unsigned char)text[i]);

  text_out[text_len] = '\0';
}

static void static_copyIfFits(const char* text, char* text_out, size_t text_out_size)
{
  if (text == NULL)
    return;

  size_t text_len = strlen(text);
  if (text_len >= text_out_size)
    return;

  memcpy(text_out, text, text_len + 1);
}

static void static_clearFailedResult(TlsProbeResult_t* result_out)
{
  TlsProbeHandshakeError_t handshake_error = result_out->m_handshakeError;
  memset(result_out, 0, sizeof(*result_out));
  result_out->m_handshakeError = handshake_error;
}

static TlsProbeStatus_t static_probeAnswers(const DnsAnswer_t* address_answers, int address_answer_count, int64_t deadline_at, TlsProbeResult_t* result_out)
{
  bool is_any_globally_reachable = false;
  for (int i = 0; i < address_answer_count; i++)
  {
    for (int record = 0; record < address_answers[i].m_recordCount; record++)
    {
      struct sockaddr_storage address = { 0 };
      socklen_t address_len = 0;
      if (!netconnect_tryBuildSockaddr(address_answers[i].mp_texts[record].mp_bytes, TLSPROBE_PORT, &address, &address_len))
        continue;

      TlsProbeStatus_t status = static_probeAddressUntil((const struct sockaddr*)&address, address_len, deadline_at, result_out);
      if (status == TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE)
        continue;
      if (status != TLSPROBE_CONNECT_FAILED)
        return status;

      is_any_globally_reachable = true;
    }
  }

  if (is_any_globally_reachable)
    return monotonic_nowMs() >= deadline_at ? TLSPROBE_TIMEOUT : TLSPROBE_CONNECT_FAILED;

  return static_statusWithoutReachableAddress(address_answers, address_answer_count);
}

static TlsProbeStatus_t static_statusWithoutReachableAddress(const DnsAnswer_t* address_answers, int address_answer_count)
{
  bool is_any_unreachable = false;
  bool is_any_no_memory   = false;
  bool is_any_unanswered  = false;

  for (int i = 0; i < address_answer_count; i++)
  {
    DnsAnswerStatus_t status = address_answers[i].m_status;
    if (status == DNS_ANSWER_NO_MEMORY)
      is_any_no_memory = true;
    else if (status == DNS_ANSWER_NOT_PUBLIC_NAME || address_answers[i].m_recordCount > 0)
      is_any_unreachable = true;
    else if (status != DNS_ANSWER_OK && status != DNS_ANSWER_NXDOMAIN)
      is_any_unanswered = true;
  }

  if (is_any_no_memory)
    return TLSPROBE_NO_MEMORY;
  if (is_any_unreachable)
    return TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE;

  return is_any_unanswered ? TLSPROBE_RESOLVE_FAILED : TLSPROBE_NAME_NOT_FOUND;
}

static TlsProbeStatus_t static_probeAddressUntil(const struct sockaddr* address, socklen_t address_len, int64_t deadline_at, TlsProbeResult_t* result_out)
{
  if (!ipguard_isGloballyReachableSockaddr(address, address_len))
    return TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE;

  pthread_once(&g_tlsSettingsOnce, static_buildTlsSettings);
  if (g_tlsSettings == NULL)
    return TLSPROBE_NO_MEMORY;

  int fd = netconnect_connectUntil(address, address_len, TLSPROBE_CONNECT_DEADLINE_MS, deadline_at);
  if (fd < 0)
    return TLSPROBE_CONNECT_FAILED;

  static_writeIpAddressText(address, result_out->ma_ipAddress);

  TlsProbeStatus_t status = static_handshakeAndRead(fd, deadline_at, result_out);
  close(fd);

  return status;
}

static void static_writeIpAddressText(const struct sockaddr* ip_address, char* text_out)
{
  if (ip_address->sa_family == AF_INET)
    inet_ntop(AF_INET, &((const struct sockaddr_in*)ip_address)->sin_addr, text_out, INET6_ADDRSTRLEN);
  else
    inet_ntop(AF_INET6, &((const struct sockaddr_in6*)ip_address)->sin6_addr, text_out, INET6_ADDRSTRLEN);
}

static TlsProbeStatus_t static_handshakeAndRead(int fd, int64_t deadline_at, TlsProbeResult_t* result_out)
{
  SSL* ssl = SSL_new(g_tlsSettings);
  if (ssl == NULL)
  {
    ERR_clear_error();
    return TLSPROBE_NO_MEMORY;
  }

  SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);

  TlsProbeHandshakeState_t handshake = { 0 };
  TlsProbeStatus_t status = TLSPROBE_NO_MEMORY;
  if (SSL_set_fd(ssl, fd) == 1                                                &&
      SSL_set_tlsext_host_name(ssl, result_out->ma_hostname) == 1             &&
      SSL_set1_host(ssl, result_out->ma_hostname) == 1                        &&
      SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp) == 1            &&
      SSL_set_app_data(ssl, &handshake) == 1                                  &&
      SSL_set_alpn_protos(ssl, (const unsigned char*)ALPN_PROTOCOL_LIST, sizeof(ALPN_PROTOCOL_LIST) - 1) == 0)
  {
    status = static_runHandshake(ssl, fd, deadline_at);
    if (status == TLSPROBE_HANDSHAKE_FAILED)
      static_writeHandshakeError(handshake.m_isClientCertificateRequested, result_out);
  }
  if (status == TLSPROBE_OK)
    status = static_readHandshakeResult(ssl, handshake.m_problems, result_out);

  SSL_free(ssl);
  ERR_clear_error();

  return status;
}

static TlsProbeStatus_t static_runHandshake(SSL* ssl, int fd, int64_t deadline_at)
{
  for (;;)
  {
    int connect_result = SSL_connect(ssl);
    if (connect_result == 1)
      return TLSPROBE_OK;

    int error           = SSL_get_error(ssl, connect_result);
    short wanted_event  = 0;
    if (error == SSL_ERROR_WANT_READ)
      wanted_event = POLLIN;
    else if (error == SSL_ERROR_WANT_WRITE)
      wanted_event = POLLOUT;
    else
      return TLSPROBE_HANDSHAKE_FAILED;

    if (!netconnect_waitForSocket(fd, wanted_event, deadline_at))
      return monotonic_nowMs() >= deadline_at ? TLSPROBE_TIMEOUT : TLSPROBE_HANDSHAKE_FAILED;
  }
}

static void static_writeHandshakeError(bool is_client_certificate_requested, TlsProbeResult_t* result_out)
{
  unsigned long error  = ERR_peek_last_error();
  int           reason = ERR_GET_REASON(error);

  TlsProbeHandshakeError_t handshake_error = TLSPROBE_HANDSHAKE_ERROR_OTHER;
  if (ERR_GET_LIB(error) != ERR_LIB_SSL)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_OTHER;
  else if (reason == SSL_AD_REASON_OFFSET + SSL_AD_CERTIFICATE_REQUIRED ||
           (is_client_certificate_requested && reason == SSL_AD_REASON_OFFSET + SSL_AD_HANDSHAKE_FAILURE))
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED;
  else if (reason == SSL_AD_REASON_OFFSET + SSL_AD_PROTOCOL_VERSION)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_PROTOCOL_VERSION;
  else if (reason == SSL_AD_REASON_OFFSET + SSL_AD_HANDSHAKE_FAILURE)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE;
  else if (reason == SSL_AD_REASON_OFFSET + SSL_AD_UNRECOGNIZED_NAME)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME;
  else if (reason >= SSL_AD_REASON_OFFSET)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT;
  else if (reason == SSL_R_WRONG_VERSION_NUMBER)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS;
  else if (reason == SSL_R_UNEXPECTED_EOF_WHILE_READING)
    handshake_error = TLSPROBE_HANDSHAKE_ERROR_PEER_CLOSED;

  result_out->m_handshakeError = handshake_error;
}

static TlsProbeStatus_t static_readHandshakeResult(SSL* ssl, unsigned int problems, TlsProbeResult_t* result_out)
{
  X509* server_certificate = SSL_get0_peer_certificate(ssl);
  if (server_certificate == NULL || !static_tryReadX509(server_certificate, &result_out->m_serverCertificate))
  {
    result_out->m_handshakeError = TLSPROBE_HANDSHAKE_ERROR_NO_CERTIFICATE;
    return TLSPROBE_HANDSHAKE_FAILED;
  }

  static_readChain(SSL_get_peer_cert_chain(ssl), result_out);
  static_copyIfFits(SSL_get_version(ssl), result_out->ma_protocol, sizeof(result_out->ma_protocol));

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
  if (cipher != NULL)
  {
    static_copyIfFits(SSL_CIPHER_get_name(cipher), result_out->ma_cipherName, sizeof(result_out->ma_cipherName));
    result_out->m_cipherBits = SSL_CIPHER_get_bits(cipher, NULL);
  }
  static_readKeyExchange(ssl, result_out);

  const unsigned char* alpn_protocol     = NULL;
  unsigned int         alpn_protocol_len = 0;
  SSL_get0_alpn_selected(ssl, &alpn_protocol, &alpn_protocol_len);
  if (alpn_protocol_len > 0 && alpn_protocol_len < sizeof(result_out->ma_alpnProtocol))
    memcpy(result_out->ma_alpnProtocol, alpn_protocol, alpn_protocol_len);

  unsigned int chain_check_problems = 0;
  if (!static_tryCheckChainAgain(server_certificate, SSL_get_peer_cert_chain(ssl), &chain_check_problems))
    return TLSPROBE_NO_MEMORY;
  problems |= chain_check_problems;

  result_out->m_problems      = problems;
  result_out->m_isTrusted     = problems == 0;
  result_out->m_revokeStatus  = static_readRevokeStatus(ssl, server_certificate);
  result_out->m_daysRemaining = tlsprobe_daysRemaining(result_out->m_serverCertificate.m_validUntilUnixSeconds, (int64_t)time(NULL));
  if (SSL_version(ssl) < TLS1_3_VERSION)
    result_out->m_secureRenegotiation = SSL_get_secure_renegotiation_support(ssl) ? TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED
                                                                                  : TLSPROBE_SECURE_RENEGOTIATION_NOT_SUPPORTED;

  return TLSPROBE_OK;
}

static void static_readKeyExchange(SSL* ssl, TlsProbeResult_t* result_out)
{
  EVP_PKEY* temporary_key = NULL;
  if (SSL_get_peer_tmp_key(ssl, &temporary_key) != 1)
    return;

  int group_id = SSL_get_negotiated_group(ssl);
  static_copyIfFits(group_id != 0 ? SSL_group_to_name(ssl, group_id) : EVP_PKEY_get0_type_name(temporary_key),
                    result_out->ma_keyExchangeGroup, sizeof(result_out->ma_keyExchangeGroup));
  result_out->m_keyExchangeBits = EVP_PKEY_get_bits(temporary_key);
  EVP_PKEY_free(temporary_key);
}

static bool static_tryCheckChainAgain(X509* server_certificate, STACK_OF(X509)* chain, unsigned int* problems_out)
{
  *problems_out = 0;

  X509_STORE_CTX* store_context = X509_STORE_CTX_new();
  if (store_context == NULL)
    return false;

  unsigned int problems = 0;
  bool is_chain_check_set_up =
            X509_STORE_CTX_init(store_context, SSL_CTX_get_cert_store(g_tlsSettings), server_certificate, chain) == 1 &&
            X509_STORE_CTX_set_app_data(store_context, &problems) == 1;

  if (is_chain_check_set_up)
  {
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_context);
    X509_VERIFY_PARAM_set_auth_level(param, TLSPROBE_CHAIN_CHECK_SECURITY_LEVEL);
    X509_VERIFY_PARAM_set_depth(param, TLSPROBE_CHAIN_CHECK_MAX_DEPTH);
    X509_STORE_CTX_set_verify_cb(store_context, static_recordWeakCrypto);

    if (X509_verify_cert(store_context) != 1)
      problems |= TLSPROBE_PROBLEM_OTHER;
    *problems_out = problems;
  }

  X509_STORE_CTX_free(store_context);
  return is_chain_check_set_up;
}

static bool static_tryReadX509(X509* certificate, TlsProbeCertificate_t* certificate_out)
{
  memset(certificate_out, 0, sizeof(*certificate_out));

  if (!static_tryWriteDigestHex(certificate, EVP_sha256(), certificate_out->ma_sha256Hex, sizeof(certificate_out->ma_sha256Hex)) ||
      !static_tryWriteDigestHex(certificate, EVP_sha1(), certificate_out->ma_sha1Hex, sizeof(certificate_out->ma_sha1Hex)))
  {
    return false;
  }

  if (!static_tryWriteCertificateTime(X509_get0_notBefore(certificate), certificate_out->ma_validFrom, NULL) ||
      !static_tryWriteCertificateTime(X509_get0_notAfter(certificate), certificate_out->ma_validUntil, &certificate_out->m_validUntilUnixSeconds))
  {
    return false;
  }

  const X509_NAME* issuer = X509_get_issuer_name(certificate);
  static_writeNamePart(issuer, NID_organizationName, certificate_out->ma_issuer);
  if (certificate_out->ma_issuer[0] == '\0')
    static_writeNamePart(issuer, NID_commonName, certificate_out->ma_issuer);

  static_writeNamePart(X509_get_subject_name(certificate), NID_commonName, certificate_out->ma_subject);
  static_writeSerialHex(certificate, certificate_out->ma_serialHex);
  static_copyIfFits(OBJ_nid2ln(X509_get_signature_nid(certificate)), certificate_out->ma_signatureAlgorithm, sizeof(certificate_out->ma_signatureAlgorithm));

  EVP_PKEY* public_key = X509_get0_pubkey(certificate);
  if (public_key != NULL)
  {
    static_copyIfFits(EVP_PKEY_get0_type_name(public_key), certificate_out->ma_keyType, sizeof(certificate_out->ma_keyType));
    certificate_out->m_keyBits = EVP_PKEY_get_bits(public_key);
  }
  static_readDnsNames(certificate, certificate_out);

  return true;
}

static bool static_tryWriteDigestHex(X509* certificate, const EVP_MD* digest_type, char* hex_out, size_t hex_size)
{
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int  digest_len = 0;
  if (X509_digest(certificate, digest_type, digest, &digest_len) != 1 ||
      (size_t)digest_len * 2 + 1 != hex_size)
  {
    return false;
  }

  bytes_writeHex(digest, digest_len, hex_out);
  return true;
}

static bool static_tryWriteCertificateTime(const ASN1_TIME* asn1_time, char* text_out, int64_t* unix_seconds_out)
{
  struct tm broken_down = { 0 };
  if (ASN1_TIME_to_tm(asn1_time, &broken_down) != 1)
    return false;

  char text[TLSPROBE_TIME_TEXT_SIZE];
  int  text_len = snprintf(text, sizeof(text), "%04d-%02d-%02dT%02d:%02d:%02dZ", broken_down.tm_year + 1900, broken_down.tm_mon + 1, broken_down.tm_mday, broken_down.tm_hour, broken_down.tm_min, broken_down.tm_sec);
  if (text_len < 0 || (size_t)text_len >= sizeof(text))
    return false;
  memcpy(text_out, text, (size_t)text_len + 1);

  if (unix_seconds_out != NULL)
    *unix_seconds_out = (int64_t)timegm(&broken_down);

  return true;
}

static void static_writeNamePart(const X509_NAME* name, int part_type, char* text_out)
{
  int part_index = X509_NAME_get_index_by_NID(name, part_type, -1);
  if (part_index < 0)
    return;

  unsigned char* utf8     = NULL;
  int            utf8_len = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, part_index)));
  if (utf8_len >= 0 && utf8_len < TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE && memchr(utf8, '\0', (size_t)utf8_len) == NULL)
  {
    memcpy(text_out, utf8, (size_t)utf8_len);
    text_out[utf8_len] = '\0';
  }

  OPENSSL_free(utf8);
}

static void static_writeFullName(const X509_NAME* name, char* text_out)
{
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    return;

  char* text     = NULL;
  long  text_len = 0;
  if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) >= 0  && 
      (text_len = BIO_get_mem_data(bio, &text)) > 0           && 
      text_len < TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE)
  {
    memcpy(text_out, text, (size_t)text_len);
    text_out[text_len] = '\0';
  }

  BIO_free(bio);
}

static void static_writeSerialHex(const X509* certificate, char* text_out)
{
  BIGNUM* serial = ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), NULL);
  if (serial == NULL)
    return;

  char* hex = BN_bn2hex(serial);
  static_copyIfFits(hex, text_out, TLSPROBE_CERTIFICATE_SERIAL_HEX_SIZE);

  OPENSSL_free(hex);
  BN_free(serial);
}

static void static_readDnsNames(const X509* certificate, TlsProbeCertificate_t* certificate_out)
{
  GENERAL_NAMES* names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
  if (names == NULL)
    return;

  int name_count = sk_GENERAL_NAME_num(names);
  for (int i = 0; i < name_count; i++)
  {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
    if (name->type != GEN_DNS)
      continue;

    const unsigned char* bytes      = ASN1_STRING_get0_data(name->d.dNSName);
    int                  byte_count = ASN1_STRING_length(name->d.dNSName);
    if (byte_count <= 0 || byte_count > VALIDATE_DOMAIN_NAME_MAX_LEN || memchr(bytes, '\0', (size_t)byte_count) != NULL)
      continue;

    if (certificate_out->m_dnsNameCount == TLSPROBE_DNS_NAME_MAX_COUNT)
    {
      certificate_out->m_isDnsNameListTruncated = true;
      break;
    }

    char* dns_name_out = certificate_out->ma_dnsNames[certificate_out->m_dnsNameCount];
    memcpy(dns_name_out, bytes, (size_t)byte_count);
    dns_name_out[byte_count] = '\0';
    certificate_out->m_dnsNameCount++;
  }

  GENERAL_NAMES_free(names);
}

static void static_readChain(const STACK_OF(X509)* chain, TlsProbeResult_t* result_out)
{
  int certificate_count = chain == NULL ? 0 : sk_X509_num(chain);
  for (int i = 0; i < certificate_count; i++)
  {
    if (result_out->m_chainCount == TLSPROBE_CHAIN_MAX_COUNT)
    {
      result_out->m_isChainTruncated = true;
      break;
    }

    const X509* certificate = sk_X509_value(chain, i);
    TlsProbeChainCertificate_t* chain_certificate = &result_out->ma_chain[result_out->m_chainCount];
    static_writeFullName(X509_get_subject_name(certificate), chain_certificate->ma_subjectFullName);
    static_writeFullName(X509_get_issuer_name(certificate), chain_certificate->ma_issuerFullName);
    static_tryWriteCertificateTime(X509_get0_notAfter(certificate), chain_certificate->ma_validUntil, NULL);

    result_out->m_chainCount++;
  }
}

static TlsProbeRevokeStatus_t static_readRevokeStatus(SSL* ssl, X509* server_certificate)
{
  unsigned char* staple = NULL;
  long staple_len = SSL_get_tlsext_status_ocsp_resp(ssl, &staple);
  if (staple == NULL || staple_len <= 0)
    return TLSPROBE_REVOKE_NOT_SENT;

  const unsigned char* cursor = staple;
  OCSP_RESPONSE* response = d2i_OCSP_RESPONSE(NULL, &cursor, staple_len);
  if (response == NULL)
    return TLSPROBE_REVOKE_UNUSABLE;

  TlsProbeRevokeStatus_t status = static_readOcspResponse(ssl, server_certificate, response);
  OCSP_RESPONSE_free(response);

  return status;
}

static TlsProbeRevokeStatus_t static_readOcspResponse(SSL* ssl, X509* server_certificate, OCSP_RESPONSE* response)
{
  if (OCSP_response_status(response) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    return TLSPROBE_REVOKE_UNUSABLE;

  OCSP_BASICRESP* basic_response = OCSP_response_get1_basic(response);
  if (basic_response == NULL)
    return TLSPROBE_REVOKE_UNUSABLE;

  TlsProbeRevokeStatus_t status = TLSPROBE_REVOKE_UNUSABLE;
  if (OCSP_basic_verify(basic_response, SSL_get_peer_cert_chain(ssl), SSL_CTX_get_cert_store(g_tlsSettings), 0) == 1)
  {
    X509* issuer = static_findIssuer(ssl, server_certificate, basic_response);
    status = issuer == NULL ? TLSPROBE_REVOKE_UNKNOWN : static_findCertificateStatus(basic_response, server_certificate, issuer);
  }

  OCSP_BASICRESP_free(basic_response);
  return status;
}

static TlsProbeRevokeStatus_t static_findCertificateStatus(OCSP_BASICRESP* basic_response, X509* server_certificate, X509* issuer)
{
  OCSP_CERTID* certificate_id = OCSP_cert_to_id(NULL, server_certificate, issuer);
  if (certificate_id == NULL)
    return TLSPROBE_REVOKE_UNUSABLE;

  int                    certificate_status = 0;
  ASN1_GENERALIZEDTIME*  this_update        = NULL;
  ASN1_GENERALIZEDTIME*  next_update        = NULL;
  TlsProbeRevokeStatus_t status             = TLSPROBE_REVOKE_UNKNOWN;
  if (OCSP_resp_find_status(basic_response, certificate_id, &certificate_status, NULL, NULL, &this_update, &next_update) == 1)
  {
    if (next_update == NULL || OCSP_check_validity(this_update, next_update, ALLOWED_CLOCK_DIFFERENCE_SECONDS, -1) != 1)
      status = TLSPROBE_REVOKE_UNUSABLE;
    else if (certificate_status == V_OCSP_CERTSTATUS_GOOD)
      status = TLSPROBE_REVOKE_NOT_REVOKED;
    else if (certificate_status == V_OCSP_CERTSTATUS_REVOKED)
      status = TLSPROBE_REVOKE_REVOKED;
  }

  OCSP_CERTID_free(certificate_id);
  return status;
}

static X509* static_findIssuer(SSL* ssl, X509* server_certificate, OCSP_BASICRESP* basic_response)
{
  STACK_OF(X509)* chains[] = { SSL_get0_verified_chain(ssl), SSL_get_peer_cert_chain(ssl) };
  for (size_t chain_index = 0; chain_index < sizeof(chains) / sizeof(chains[0]); chain_index++)
  {
    int certificate_count = chains[chain_index] == NULL ? 0 : sk_X509_num(chains[chain_index]);

    for (int i = 0; i < certificate_count; i++)
    {
      X509* candidate = sk_X509_value(chains[chain_index], i);
      if (X509_check_issued(candidate, server_certificate) != X509_V_OK)
        continue;

      OCSP_CERTID* candidate_id = OCSP_cert_to_id(NULL, server_certificate, candidate);
      bool is_named_or_unknown = candidate_id == NULL || OCSP_resp_find(basic_response, candidate_id, -1) >= 0;

      OCSP_CERTID_free(candidate_id);

      if (is_named_or_unknown && X509_verify(server_certificate, X509_get0_pubkey(candidate)) == 1)
        return candidate;
    }
  }
  return NULL;
}
