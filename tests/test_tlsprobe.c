#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "unity/unity.h"
#include "dns.h"
#include "tlsprobe.h"

void setUp(void);
void tearDown(void);

#define DAY_SECONDS 86400L

#define ALPN_OFFERED "\x02h2\x08http/1.1"

#define NO_NEXT_UPDATE LONG_MIN

static EVP_PKEY* g_caKey;
static X509*     g_caCert;
static EVP_PKEY* g_intermediateKey;
static X509*     g_intermediateCert;
static EVP_PKEY* g_otherCaKey;
static X509*     g_otherCaCert;
static EVP_PKEY* g_serverKey;

static void static_addNameEntry(X509_NAME* name, int nid, const char* bytes, int byte_count)
{
  TEST_ASSERT_EQUAL_INT(1, X509_NAME_add_entry_by_NID(name, nid, V_ASN1_UTF8STRING, (const unsigned char*)bytes, byte_count, -1, 0));
}

static X509* static_newCertificate(EVP_PKEY* key, const char* common_name, long not_before_offset, long not_after_offset)
{
  X509* certificate = X509_new();
  TEST_ASSERT_NOT_NULL(certificate);
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), not_before_offset);
  X509_gmtime_adj(X509_getm_notAfter(certificate), not_after_offset);
  if (common_name != NULL)
    static_addNameEntry(X509_get_subject_name(certificate), NID_commonName, common_name, -1);
  X509_set_pubkey(certificate, key);
  return certificate;
}

static void static_addDnsNames(X509* certificate, const char* const* names, const int* name_lens, int name_count)
{
  GENERAL_NAMES* general_names = GENERAL_NAMES_new();
  for (int i = 0; i < name_count; i++)
  {
    GENERAL_NAME* general_name = GENERAL_NAME_new();
    if (strncmp(names[i], "IP:", 3) == 0)
    {
      unsigned char       address[4];
      ASN1_OCTET_STRING*  octets = ASN1_OCTET_STRING_new();
      TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET, names[i] + 3, address));
      ASN1_OCTET_STRING_set(octets, address, 4);
      GENERAL_NAME_set0_value(general_name, GEN_IPADD, octets);
    }
    else
    {
      ASN1_IA5STRING* text = ASN1_IA5STRING_new();
      ASN1_STRING_set(text, names[i], name_lens == NULL ? (int)strlen(names[i]) : name_lens[i]);
      GENERAL_NAME_set0_value(general_name, GEN_DNS, text);
    }
    sk_GENERAL_NAME_push(general_names, general_name);
  }
  TEST_ASSERT_EQUAL_INT(1, X509_add1_ext_i2d(certificate, NID_subject_alt_name, general_names, 0, 0));
  GENERAL_NAMES_free(general_names);
}

static void static_signWithDigest(X509* certificate, X509* issuer, EVP_PKEY* issuer_key, const EVP_MD* digest)
{
  X509_set_issuer_name(certificate, X509_get_subject_name(issuer != NULL ? issuer : certificate));
  TEST_ASSERT_TRUE(X509_sign(certificate, issuer_key, digest) > 0);
}

static void static_sign(X509* certificate, X509* issuer, EVP_PKEY* issuer_key)
{
  static_signWithDigest(certificate, issuer, issuer_key, EVP_sha256());
}

static X509* static_newAuthority(EVP_PKEY* key, const char* organization, const char* common_name, X509* issuer, EVP_PKEY* issuer_key)
{
  X509* certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 7);
  X509_gmtime_adj(X509_getm_notBefore(certificate), -DAY_SECONDS);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 3650 * DAY_SECONDS);
  static_addNameEntry(X509_get_subject_name(certificate), NID_organizationName, organization, -1);
  static_addNameEntry(X509_get_subject_name(certificate), NID_commonName, common_name, -1);
  X509_set_pubkey(certificate, key);
  X509_EXTENSION* constraints = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
  X509_EXTENSION* usage       = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
  X509_add_ext(certificate, constraints, -1);
  X509_add_ext(certificate, usage, -1);
  X509_EXTENSION_free(constraints);
  X509_EXTENSION_free(usage);
  static_sign(certificate, issuer, issuer != NULL ? issuer_key : key);
  return certificate;
}

static X509* static_newServerCertificate(const char* dns_name, long not_before_offset, long not_after_offset, X509* issuer, EVP_PKEY* issuer_key)
{
  X509* certificate = static_newCertificate(g_serverKey, dns_name, not_before_offset, not_after_offset);
  static_addDnsNames(certificate, &dns_name, NULL, 1);
  static_sign(certificate, issuer, issuer != NULL ? issuer_key : g_serverKey);
  return certificate;
}

static unsigned char* static_toDer(X509* certificate, int* der_len_out)
{
  unsigned char* der = NULL;
  *der_len_out = i2d_X509(certificate, &der);
  TEST_ASSERT_TRUE(*der_len_out > 0);
  return der;
}

static void static_digestHex(const unsigned char* bytes, size_t byte_count, const EVP_MD* digest_type, char* hex_out)
{
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int  digest_len = 0;
  TEST_ASSERT_EQUAL_INT(1, EVP_Digest(bytes, byte_count, digest, &digest_len, digest_type, NULL));
  for (unsigned int i = 0; i < digest_len; i++)
    snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
}

static bool static_readCertificate(X509* certificate, TlsProbeCertificate_t* certificate_out)
{
  int            der_len = 0;
  unsigned char* der     = static_toDer(certificate, &der_len);
  bool           is_read = tlsprobe_tryReadCertificate(der, (size_t)der_len, certificate_out);
  OPENSSL_free(der);
  return is_read;
}

static unsigned char* static_makeOcspResponseWithStatus(int response_status, X509* server_certificate, X509* issuer, X509* signer, EVP_PKEY* signer_key, int certificate_status, long this_update_offset, long next_update_offset, int* der_len_out);
static unsigned char* static_makeOcspResponse(X509* server_certificate, X509* issuer, X509* signer, EVP_PKEY* signer_key, int certificate_status, long this_update_offset, long next_update_offset, int* der_len_out)
{
  return static_makeOcspResponseWithStatus(OCSP_RESPONSE_STATUS_SUCCESSFUL, server_certificate, issuer, signer, signer_key, certificate_status, this_update_offset, next_update_offset, der_len_out);
}

static unsigned char* static_makeOcspResponseWithStatus(int response_status, X509* server_certificate, X509* issuer, X509* signer, EVP_PKEY* signer_key, int certificate_status, long this_update_offset, long next_update_offset, int* der_len_out)
{
  OCSP_CERTID*    certificate_id = OCSP_cert_to_id(NULL, server_certificate, issuer);
  OCSP_BASICRESP* basic_response = OCSP_BASICRESP_new();
  ASN1_TIME*      this_update    = X509_gmtime_adj(NULL, this_update_offset);
  ASN1_TIME*      next_update    = next_update_offset == NO_NEXT_UPDATE ? NULL : X509_gmtime_adj(NULL, next_update_offset);
  ASN1_TIME*      revoked_at     = X509_gmtime_adj(NULL, -DAY_SECONDS);
  TEST_ASSERT_NOT_NULL(OCSP_basic_add1_status(basic_response, certificate_id, certificate_status, OCSP_REVOKED_STATUS_KEYCOMPROMISE, certificate_status == V_OCSP_CERTSTATUS_REVOKED ? revoked_at : NULL, this_update, next_update));
  TEST_ASSERT_EQUAL_INT(1, OCSP_basic_sign(basic_response, signer, signer_key, EVP_sha256(), NULL, 0));
  OCSP_RESPONSE* response = OCSP_response_create(response_status, basic_response);
  unsigned char* der      = NULL;
  *der_len_out = i2d_OCSP_RESPONSE(response, &der);
  TEST_ASSERT_TRUE(*der_len_out > 0);
  OCSP_RESPONSE_free(response);
  OCSP_BASICRESP_free(basic_response);
  OCSP_CERTID_free(certificate_id);
  ASN1_TIME_free(this_update);
  ASN1_TIME_free(next_update);
  ASN1_TIME_free(revoked_at);
  return der;
}

#define FAKE_START_MS   1000000
#define FAKE_MAX_CALLS  16
#define FAKE_FD_LIMIT   1024

typedef enum {
  FAKE_CONNECT_OK = 0,
  FAKE_CONNECT_REFUSED,
  FAKE_CONNECT_PENDING_OK,
  FAKE_CONNECT_PENDING_REFUSED,
  FAKE_CONNECT_PENDING_SILENT,
  FAKE_CONNECT_OK_SILENT,
} FakeConnect_t;

int __real_close(int fd);
int __real_poll(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms);
int __real_getsockopt(int fd, int level, int option_name, void* value, socklen_t* value_len);
int __real_clock_gettime(clockid_t clock_id, struct timespec* time_out);
int __real_SSL_CTX_set_default_verify_paths(SSL_CTX* context);

static pthread_mutex_t g_fakeLock = PTHREAD_MUTEX_INITIALIZER;
static int64_t         g_nowMs;
static FakeConnect_t   g_connectPlan[FAKE_MAX_CALLS];
static int             g_preparedFds[FAKE_MAX_CALLS];
static int             g_preparedCount;
static int             g_preparedNext;
static int             g_socketCallCount;
static int             g_socketFailErrno;
static int             g_socketFamilies[FAKE_MAX_CALLS];
static int             g_socketTypes[FAKE_MAX_CALLS];
static int             g_socketProtocols[FAKE_MAX_CALLS];
static int             g_connectCallCount;
static char            g_connectAddresses[FAKE_MAX_CALLS][INET6_ADDRSTRLEN];
static int             g_connectPorts[FAKE_MAX_CALLS];
static FakeConnect_t   g_fdPlans[FAKE_FD_LIMIT];
static bool            g_isProbeFd[FAKE_FD_LIMIT];
static bool            g_isSilentFd[FAKE_FD_LIMIT];
static int             g_closeCount;
static int             g_pollCount;
static int             g_pollTimeouts[FAKE_MAX_CALLS * 4];
static short           g_pollEvents[FAKE_MAX_CALLS * 4];
static int             g_pollFailErrno;
static int             g_verifyPathsCallCount;
static bool            g_isStoreContextFailing;
static int             g_signatureCheckCount;
static int             g_handshakeStepCount;
static int             g_legacyServerStepCount;
static bool            g_isErrorFromOtherLibrary;
static bool            g_isRenegotiationInfoMissing;

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out)
{
  if (clock_id != CLOCK_MONOTONIC)
    return __real_clock_gettime(clock_id, time_out);
  pthread_mutex_lock(&g_fakeLock);
  time_out->tv_sec  = g_nowMs / 1000;
  time_out->tv_nsec = (long)(g_nowMs % 1000) * 1000000;
  pthread_mutex_unlock(&g_fakeLock);
  return 0;
}

int __wrap_socket(int domain, int type, int protocol)
{
  pthread_mutex_lock(&g_fakeLock);
  int call = g_socketCallCount++;
  g_socketFamilies[call]  = domain;
  g_socketTypes[call]     = type;
  g_socketProtocols[call] = protocol;
  if (g_socketFailErrno != 0)
  {
    pthread_mutex_unlock(&g_fakeLock);
    errno = g_socketFailErrno;
    return -1;
  }

  FakeConnect_t plan = g_connectPlan[call];
  int           fd   = -1;
  if (plan == FAKE_CONNECT_OK || plan == FAKE_CONNECT_PENDING_OK || plan == FAKE_CONNECT_OK_SILENT)
  {
    fd = g_preparedFds[g_preparedNext++];
  }
  else
  {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    {
      pthread_mutex_unlock(&g_fakeLock);
      return -1;
    }
    __real_close(pair[1]);
    fd = pair[0];
  }
  g_fdPlans[fd]    = plan;
  g_isProbeFd[fd]  = true;
  g_isSilentFd[fd] = plan == FAKE_CONNECT_PENDING_SILENT || plan == FAKE_CONNECT_OK_SILENT;
  pthread_mutex_unlock(&g_fakeLock);
  return fd;
}

int __wrap_connect(int fd, const struct sockaddr* address, socklen_t address_len)
{
  (void)address_len;
  pthread_mutex_lock(&g_fakeLock);
  int call = g_connectCallCount++;
  if (address->sa_family == AF_INET)
  {
    const struct sockaddr_in* ipv4 = (const struct sockaddr_in*)address;
    inet_ntop(AF_INET, &ipv4->sin_addr, g_connectAddresses[call], INET6_ADDRSTRLEN);
    g_connectPorts[call] = ntohs(ipv4->sin_port);
  }
  else
  {
    const struct sockaddr_in6* ipv6 = (const struct sockaddr_in6*)address;
    inet_ntop(AF_INET6, &ipv6->sin6_addr, g_connectAddresses[call], INET6_ADDRSTRLEN);
    g_connectPorts[call] = ntohs(ipv6->sin6_port);
  }
  FakeConnect_t plan = g_fdPlans[fd];
  pthread_mutex_unlock(&g_fakeLock);

  if (plan == FAKE_CONNECT_OK || plan == FAKE_CONNECT_OK_SILENT)
    return 0;
  errno = plan == FAKE_CONNECT_REFUSED ? ECONNREFUSED : EINPROGRESS;
  return -1;
}

int __wrap_getsockopt(int fd, int level, int option_name, void* value, socklen_t* value_len)
{
  if (level != SOL_SOCKET || option_name != SO_ERROR || fd < 0 || fd >= FAKE_FD_LIMIT || !g_isProbeFd[fd])
    return __real_getsockopt(fd, level, option_name, value, value_len);
  *(int*)value = g_fdPlans[fd] == FAKE_CONNECT_PENDING_REFUSED ? ECONNREFUSED : 0;
  *value_len   = sizeof(int);
  return 0;
}

int __wrap_poll(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms)
{
  int  fd         = poll_fd_count == 1 ? poll_fds[0].fd : -1;
  bool is_probe   = fd >= 0 && fd < FAKE_FD_LIMIT && g_isProbeFd[fd];
  bool is_silent  = is_probe && g_isSilentFd[fd];
  int  fail_errno = 0;

  pthread_mutex_lock(&g_fakeLock);
  if (is_probe && g_pollCount < (int)(sizeof(g_pollTimeouts) / sizeof(g_pollTimeouts[0])))
  {
    g_pollEvents[g_pollCount]   = poll_fds[0].events;
    g_pollTimeouts[g_pollCount] = timeout_ms;
    g_pollCount++;
  }
  else if (is_probe)
  {
    fail_errno = EBADF;
  }
  if (is_probe && g_pollFailErrno != 0)
  {
    fail_errno      = g_pollFailErrno;
    g_pollFailErrno = 0;
  }
  if (is_silent && fail_errno == 0)
    g_nowMs += timeout_ms;
  pthread_mutex_unlock(&g_fakeLock);

  if (fail_errno != 0)
  {
    errno = fail_errno;
    return -1;
  }
  if (is_silent)
    return 0;
  return __real_poll(poll_fds, poll_fd_count, timeout_ms);
}

int __wrap___poll_chk(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms, size_t poll_fds_size)
{
  (void)poll_fds_size;
  return __wrap_poll(poll_fds, poll_fd_count, timeout_ms);
}

int __wrap_close(int fd)
{
  pthread_mutex_lock(&g_fakeLock);
  if (fd >= 0 && fd < FAKE_FD_LIMIT && g_isProbeFd[fd])
  {
    g_isProbeFd[fd]  = false;
    g_isSilentFd[fd] = false;
    g_closeCount++;
  }
  pthread_mutex_unlock(&g_fakeLock);
  return __real_close(fd);
}

int __wrap_SSL_CTX_set_default_verify_paths(SSL_CTX* context)
{
  g_verifyPathsCallCount++;
  if (__real_SSL_CTX_set_default_verify_paths(context) != 1)
    return 0;
  return X509_STORE_add_cert(SSL_CTX_get_cert_store(context), g_caCert);
}

X509_STORE_CTX* __real_X509_STORE_CTX_new(void);
X509_STORE_CTX* __wrap_X509_STORE_CTX_new(void)
{
  if (g_isStoreContextFailing)
    return NULL;
  return __real_X509_STORE_CTX_new();
}

int __real_SSL_connect(SSL* ssl);
int __wrap_SSL_connect(SSL* ssl)
{
  pthread_mutex_lock(&g_fakeLock);
  g_handshakeStepCount++;
  if ((SSL_get_options(ssl) & SSL_OP_LEGACY_SERVER_CONNECT) != 0)
    g_legacyServerStepCount++;
  pthread_mutex_unlock(&g_fakeLock);
  return __real_SSL_connect(ssl);
}

unsigned long __real_ERR_peek_last_error(void);
unsigned long __wrap_ERR_peek_last_error(void)
{
  if (g_isErrorFromOtherLibrary)
    return ERR_PACK(ERR_LIB_SYS, 0, SSL_R_WRONG_VERSION_NUMBER);
  return __real_ERR_peek_last_error();
}

long __real_SSL_ctrl(SSL* ssl, int command, long number, void* pointer);
long __wrap_SSL_ctrl(SSL* ssl, int command, long number, void* pointer)
{
  if (command == SSL_CTRL_GET_RI_SUPPORT && g_isRenegotiationInfoMissing)
    return 0;
  return __real_SSL_ctrl(ssl, command, number, pointer);
}

int __real_X509_verify(X509* certificate, EVP_PKEY* key);
int __wrap_X509_verify(X509* certificate, EVP_PKEY* key)
{
  pthread_mutex_lock(&g_fakeLock);
  g_signatureCheckCount++;
  pthread_mutex_unlock(&g_fakeLock);
  return __real_X509_verify(certificate, key);
}

#define FAKE_DNS_MAX_ADDRESSES 4

typedef struct {
  DnsAnswerStatus_t m_status;
  const char*       ma_addresses[FAKE_DNS_MAX_ADDRESSES];
} FakeAnswer_t;

static FakeAnswer_t    g_fakeAnswers[2];
static int64_t         g_askAdvanceMs;
static int             g_askCallCount;
static int             g_askQuestionCount;
static int             g_askDeadlineMs;
static char            g_askNames[2][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
static DnsRecordType_t g_askTypes[2];

void __wrap_dns_askQuestions(const DnsQuestion_t* questions, int question_count, int deadline_ms, DnsAnswer_t* answers_out)
{
  g_askCallCount++;
  pthread_mutex_lock(&g_fakeLock);
  g_nowMs += g_askAdvanceMs;
  pthread_mutex_unlock(&g_fakeLock);
  g_askQuestionCount = question_count;
  g_askDeadlineMs    = deadline_ms;
  for (int i = 0; i < question_count && i < 2; i++)
  {
    snprintf(g_askNames[i], sizeof(g_askNames[i]), "%s", questions[i].mp_domainName);
    g_askTypes[i] = questions[i].m_type;

    DnsAnswer_t* answer = &answers_out[i];
    memset(answer, 0, sizeof(*answer));
    answer->m_status = g_fakeAnswers[i].m_status;
    int address_count = 0;
    while (address_count < FAKE_DNS_MAX_ADDRESSES && g_fakeAnswers[i].ma_addresses[address_count] != NULL)
      address_count++;
    if (address_count == 0)
      continue;
    answer->mp_texts = calloc((size_t)address_count, sizeof(DnsRecordText_t));
    for (int record = 0; record < address_count; record++)
    {
      answer->mp_texts[record].mp_bytes    = strdup(g_fakeAnswers[i].ma_addresses[record]);
      answer->mp_texts[record].m_byteCount = strlen(g_fakeAnswers[i].ma_addresses[record]);
    }
    answer->m_recordCount = address_count;
  }
}

typedef enum {
  FAKE_SERVER_TLS = 0,
  FAKE_SERVER_PLAIN_TEXT,
  FAKE_SERVER_SILENT,
  FAKE_SERVER_ALERT,
  FAKE_SERVER_CLOSE,
  FAKE_SERVER_APPLICATION_DATA,
} FakeServerMode_t;

typedef struct {
  FakeServerMode_t     m_mode;
  X509*                mp_serverCertificate;
  EVP_PKEY*            mp_serverKey;
  X509**               mp_extraChain;
  int                  m_extraChainCount;
  int                  m_onlyProtocol;
  const unsigned char* mp_staple;
  int                  m_stapleLen;
  const char*          mp_groups;
  const char*          mp_cipherList;
  bool                 m_isDhAuto;
  bool                 m_isClientCertificateRequired;
  const char*          mp_alpnProtocol;
  unsigned char        m_alert;
  unsigned char        ma_offeredAlpn[64];
  unsigned int         m_offeredAlpnLen;
  int                  m_fd;
  int                  m_preparedIndex;
  pthread_t            m_thread;
  bool                 m_isHandshakeDone;
  bool                 m_isAnswerSent;
  char                 ma_servername[256];
} FakeServer_t;

static int static_stapleResponse(SSL* ssl, void* server_arg)
{
  const FakeServer_t* server = server_arg;
  unsigned char*      copy   = OPENSSL_memdup(server->mp_staple, (size_t)server->m_stapleLen);
  SSL_set_tlsext_status_ocsp_resp(ssl, copy, server->m_stapleLen);
  return SSL_TLSEXT_ERR_OK;
}

static int static_selectAlpnProtocol(SSL* ssl, const unsigned char** protocol_out, unsigned char* protocol_len_out, const unsigned char* offered, unsigned int offered_len, void* server_arg)
{
  (void)ssl;
  FakeServer_t* server = server_arg;
  if (offered_len <= sizeof(server->ma_offeredAlpn))
  {
    memcpy(server->ma_offeredAlpn, offered, offered_len);
    server->m_offeredAlpnLen = offered_len;
  }
  if (server->mp_alpnProtocol == NULL)
    return SSL_TLSEXT_ERR_NOACK;

  size_t protocol_len = strlen(server->mp_alpnProtocol);
  for (unsigned int i = 0; i < offered_len; i += 1u + offered[i])
  {
    if (offered[i] == protocol_len && memcmp(&offered[i + 1], server->mp_alpnProtocol, protocol_len) == 0)
    {
      *protocol_out     = &offered[i + 1];
      *protocol_len_out = (unsigned char)protocol_len;
      return SSL_TLSEXT_ERR_OK;
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static void* static_runServer(void* server_arg)
{
  FakeServer_t* server = server_arg;
  if (server->m_mode == FAKE_SERVER_ALERT)
  {
    const unsigned char alert[] = { 21, 3, 1, 0, 2, 2, server->m_alert };
    char                buf[4096];
    if (read(server->m_fd, buf, sizeof(buf)) > 0)
      server->m_isAnswerSent = write(server->m_fd, alert, sizeof(alert)) == (ssize_t)sizeof(alert);
  }
  else if (server->m_mode == FAKE_SERVER_CLOSE)
  {
    char buf[4096];
    server->m_isAnswerSent = read(server->m_fd, buf, sizeof(buf)) > 0;
  }
  else if (server->m_mode == FAKE_SERVER_APPLICATION_DATA)
  {
    static const unsigned char record[] = { 23, 3, 1, 0, 1, 0 };
    char                       buf[4096];
    if (read(server->m_fd, buf, sizeof(buf)) > 0)
      server->m_isAnswerSent = write(server->m_fd, record, sizeof(record)) == (ssize_t)sizeof(record);
    while (read(server->m_fd, buf, sizeof(buf)) > 0)
      continue;
  }
  else if (server->m_mode == FAKE_SERVER_PLAIN_TEXT)
  {
    static const char answer[] = "HTTP/1.0 400 Bad Request\r\n\r\n";
    char              buf[512];
    if (read(server->m_fd, buf, sizeof(buf)) > 0)
      server->m_isAnswerSent = write(server->m_fd, answer, sizeof(answer) - 1) == (ssize_t)(sizeof(answer) - 1);
  }
  else if (server->m_mode == FAKE_SERVER_SILENT)
  {
    char buf[512];
    while (read(server->m_fd, buf, sizeof(buf)) > 0)
      continue;
  }
  else
  {
    SSL_CTX* context = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_security_level(context, 0);
    SSL_CTX_use_certificate(context, server->mp_serverCertificate);
    SSL_CTX_use_PrivateKey(context, server->mp_serverKey != NULL ? server->mp_serverKey : g_serverKey);
    for (int i = 0; i < server->m_extraChainCount; i++)
      SSL_CTX_add1_chain_cert(context, server->mp_extraChain[i]);
    if (server->m_onlyProtocol != 0)
    {
      SSL_CTX_set_cipher_list(context, "DEFAULT:@SECLEVEL=0");
      SSL_CTX_set_min_proto_version(context, server->m_onlyProtocol);
      SSL_CTX_set_max_proto_version(context, server->m_onlyProtocol);
    }
    if (server->mp_groups != NULL)
      SSL_CTX_set1_groups_list(context, server->mp_groups);
    if (server->mp_cipherList != NULL)
      SSL_CTX_set_cipher_list(context, server->mp_cipherList);
    if (server->m_isDhAuto)
      SSL_CTX_set_dh_auto(context, 1);
    if (server->m_isClientCertificateRequired)
      SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_alpn_select_cb(context, static_selectAlpnProtocol, server);
    if (server->mp_staple != NULL)
    {
      SSL_CTX_set_tlsext_status_cb(context, static_stapleResponse);
      SSL_CTX_set_tlsext_status_arg(context, server);
    }
    SSL* ssl = SSL_new(context);
    SSL_set_fd(ssl, server->m_fd);
    server->m_isHandshakeDone = SSL_accept(ssl) == 1;
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername != NULL)
      snprintf(server->ma_servername, sizeof(server->ma_servername), "%s", servername);
    SSL_free(ssl);
    SSL_CTX_free(context);
  }
  close(server->m_fd);
  return NULL;
}

static void static_startServer(FakeServer_t* server)
{
  int pair[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
  TEST_ASSERT_EQUAL_INT(0, fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK));
  pthread_mutex_lock(&g_fakeLock);
  server->m_preparedIndex          = g_preparedCount;
  g_preparedFds[g_preparedCount++] = pair[0];
  pthread_mutex_unlock(&g_fakeLock);
  server->m_fd = pair[1];
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&server->m_thread, NULL, static_runServer, server));
}

static void static_joinServer(FakeServer_t* server)
{
  pthread_mutex_lock(&g_fakeLock);
  if (g_preparedNext <= server->m_preparedIndex)
  {
    __real_close(g_preparedFds[server->m_preparedIndex]);
    g_preparedFds[server->m_preparedIndex] = -1;
  }
  pthread_mutex_unlock(&g_fakeLock);
  TEST_ASSERT_EQUAL_INT(0, pthread_join(server->m_thread, NULL));
}

static struct sockaddr_in static_globallyReachableAddress(void)
{
  struct sockaddr_in address = { 0 };
  address.sin_family = AF_INET;
  address.sin_port   = htons(8443);
  inet_pton(AF_INET, "93.184.216.34", &address.sin_addr);
  return address;
}

static TlsProbeStatus_t static_probeServer(FakeServer_t* server, TlsProbeResult_t* result_out)
{
  static_startServer(server);
  struct sockaddr_in address = static_globallyReachableAddress();
  TlsProbeStatus_t   status  = tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "Probe.Example", result_out);
  static_joinServer(server);
  return status;
}

static bool static_isResultZero(const TlsProbeResult_t* result)
{
  static const TlsProbeResult_t zero;
  return memcmp(&zero, result, sizeof(zero)) == 0;
}

void setUp(void)
{
  pthread_mutex_lock(&g_fakeLock);
  g_nowMs             = FAKE_START_MS;
  g_preparedCount     = 0;
  g_preparedNext      = 0;
  g_socketCallCount   = 0;
  g_socketFailErrno   = 0;
  g_connectCallCount  = 0;
  g_closeCount        = 0;
  g_pollCount         = 0;
  g_pollFailErrno     = 0;
  g_askAdvanceMs      = 0;
  memset(g_connectPlan, 0, sizeof(g_connectPlan));
  memset(g_connectAddresses, 0, sizeof(g_connectAddresses));
  memset(g_connectPorts, 0, sizeof(g_connectPorts));
  memset(g_pollTimeouts, 0, sizeof(g_pollTimeouts));
  memset(g_pollEvents, 0, sizeof(g_pollEvents));
  pthread_mutex_unlock(&g_fakeLock);

  g_askCallCount     = 0;
  g_askQuestionCount = 0;
  g_askDeadlineMs    = 0;
  memset(g_askNames, 0, sizeof(g_askNames));
  memset(g_fakeAnswers, 0, sizeof(g_fakeAnswers));

  g_isStoreContextFailing = false;
  g_signatureCheckCount   = 0;
  g_handshakeStepCount    = 0;
  g_legacyServerStepCount = 0;
  g_isErrorFromOtherLibrary    = false;
  g_isRenegotiationInfoMissing = false;
}

void tearDown(void) {}

void test_tryReadCertificate_reads_each_field(void)
{
  X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, 0);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 0x0102AB);
  TEST_ASSERT_EQUAL_INT(1, ASN1_TIME_set_string_X509(X509_getm_notBefore(certificate), "20260102030405Z"));
  TEST_ASSERT_EQUAL_INT(1, ASN1_TIME_set_string_X509(X509_getm_notAfter(certificate), "20510203040506Z"));
  const char* names[] = { "probe.example", "IP:198.51.100.7", "www.probe.example" };
  static_addDnsNames(certificate, names, NULL, 3);
  static_sign(certificate, g_caCert, g_caKey);

  int            der_len = 0;
  unsigned char* der     = static_toDer(certificate, &der_len);
  char           expected_sha256[TLSPROBE_CERTIFICATE_SHA256_HEX_SIZE];
  char           expected_sha1[TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE];
  static_digestHex(der, (size_t)der_len, EVP_sha256(), expected_sha256);
  static_digestHex(der, (size_t)der_len, EVP_sha1(), expected_sha1);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(tlsprobe_tryReadCertificate(der, (size_t)der_len, &read));
  TEST_ASSERT_EQUAL_STRING(expected_sha256, read.ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING(expected_sha1, read.ma_sha1Hex);
  TEST_ASSERT_EQUAL_STRING("2026-01-02T03:04:05Z", read.ma_validFrom);
  TEST_ASSERT_EQUAL_STRING("2051-02-03T04:05:06Z", read.ma_validUntil);
  TEST_ASSERT_TRUE(read.m_validUntilUnixSeconds == 2559009906);
  TEST_ASSERT_EQUAL_STRING("Probe Test CA", read.ma_issuer);
  TEST_ASSERT_EQUAL_STRING("probe.example", read.ma_subject);
  TEST_ASSERT_EQUAL_STRING("0102AB", read.ma_serialHex);
  TEST_ASSERT_EQUAL_STRING("ecdsa-with-SHA256", read.ma_signatureAlgorithm);
  TEST_ASSERT_EQUAL_STRING("EC", read.ma_keyType);
  TEST_ASSERT_EQUAL_INT(256, read.m_keyBits);
  TEST_ASSERT_EQUAL_INT(2, read.m_dnsNameCount);
  TEST_ASSERT_EQUAL_STRING("probe.example", read.ma_dnsNames[0]);
  TEST_ASSERT_EQUAL_STRING("www.probe.example", read.ma_dnsNames[1]);
  TEST_ASSERT_FALSE(read.m_isDnsNameListTruncated);

  OPENSSL_free(der);
  X509_free(certificate);
}

void test_tryReadCertificate_reads_an_rsa_key_and_its_size(void)
{
  EVP_PKEY* rsa_key = EVP_RSA_gen(3072);
  TEST_ASSERT_NOT_NULL(rsa_key);
  X509* certificate = static_newCertificate(rsa_key, "probe.example", 0, DAY_SECONDS);
  static_sign(certificate, g_caCert, g_caKey);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_STRING("RSA", read.ma_keyType);
  TEST_ASSERT_EQUAL_INT(3072, read.m_keyBits);

  X509_free(certificate);
  EVP_PKEY_free(rsa_key);
}

void test_tryReadCertificate_reads_a_utctime(void)
{
  X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, 0);
  TEST_ASSERT_EQUAL_INT(1, ASN1_TIME_set_string(X509_getm_notBefore(certificate), "500101000000Z"));
  TEST_ASSERT_EQUAL_INT(1, ASN1_TIME_set_string(X509_getm_notAfter(certificate), "491231235959Z"));
  static_sign(certificate, NULL, g_serverKey);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_STRING("1950-01-01T00:00:00Z", read.ma_validFrom);
  TEST_ASSERT_EQUAL_STRING("2049-12-31T23:59:59Z", read.ma_validUntil);
  TEST_ASSERT_TRUE(read.m_validUntilUnixSeconds == 2524607999);
  X509_free(certificate);
}

void test_tryReadCertificate_issuer_without_an_organization_is_its_common_name(void)
{
  X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
  static_sign(certificate, NULL, g_serverKey);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_STRING("probe.example", read.ma_issuer);
  X509_free(certificate);
}

void test_tryReadCertificate_reads_the_issuer_common_name_from_the_issuer(void)
{
  X509*      certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
  X509_NAME* issuer_name = X509_NAME_new();
  static_addNameEntry(issuer_name, NID_commonName, "Issuer Only CN", -1);
  X509_set_issuer_name(certificate, issuer_name);
  X509_NAME_free(issuer_name);
  TEST_ASSERT_TRUE(X509_sign(certificate, g_serverKey, EVP_sha256()) > 0);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_STRING("Issuer Only CN", read.ma_issuer);
  TEST_ASSERT_EQUAL_STRING("probe.example", read.ma_subject);
  X509_free(certificate);
}

void test_tryReadCertificate_keeps_100_names_and_marks_the_rest(void)
{
  static char  texts[TLSPROBE_DNS_NAME_MAX_COUNT + 1][32];
  const char*  names[TLSPROBE_DNS_NAME_MAX_COUNT + 1];
  for (int i = 0; i <= TLSPROBE_DNS_NAME_MAX_COUNT; i++)
  {
    snprintf(texts[i], sizeof(texts[i]), "host%d.probe.example", i);
    names[i] = texts[i];
  }

  for (int name_count = TLSPROBE_DNS_NAME_MAX_COUNT; name_count <= TLSPROBE_DNS_NAME_MAX_COUNT + 1; name_count++)
  {
    X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
    static_addDnsNames(certificate, names, NULL, name_count);
    static_sign(certificate, NULL, g_serverKey);

    TlsProbeCertificate_t read = { 0 };
    TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
    TEST_ASSERT_EQUAL_INT(TLSPROBE_DNS_NAME_MAX_COUNT, read.m_dnsNameCount);
    TEST_ASSERT_EQUAL_STRING("host0.probe.example", read.ma_dnsNames[0]);
    TEST_ASSERT_EQUAL_STRING("host99.probe.example", read.ma_dnsNames[TLSPROBE_DNS_NAME_MAX_COUNT - 1]);
    TEST_ASSERT_EQUAL(name_count > TLSPROBE_DNS_NAME_MAX_COUNT, read.m_isDnsNameListTruncated);
    X509_free(certificate);
  }
}

void test_tryReadCertificate_skips_a_name_too_long_empty_or_with_a_nul(void)
{
  char longest[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  memset(longest, 'a', sizeof(longest) - 1);
  longest[sizeof(longest) - 1] = '\0';
  const char* names[]     = { longest, longest, "", "evil.example\0.probe.example", "plain.example" };
  const int   name_lens[] = { VALIDATE_DOMAIN_NAME_MAX_LEN + 1, VALIDATE_DOMAIN_NAME_MAX_LEN, 0, 27, 13 };

  X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
  static_addDnsNames(certificate, names, name_lens, 5);
  static_sign(certificate, NULL, g_serverKey);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_INT(2, read.m_dnsNameCount);
  TEST_ASSERT_EQUAL_INT(VALIDATE_DOMAIN_NAME_MAX_LEN, (int)strlen(read.ma_dnsNames[0]));
  TEST_ASSERT_EQUAL_STRING("plain.example", read.ma_dnsNames[1]);
  X509_free(certificate);
}

void test_tryReadCertificate_name_with_a_nul_or_too_long_is_left_out(void)
{
  char organization[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE + 1];
  memset(organization, 'o', sizeof(organization) - 1);
  organization[sizeof(organization) - 1] = '\0';

  for (int organization_len = TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE - 1; organization_len <= TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE; organization_len++)
  {
    X509* certificate = static_newCertificate(g_serverKey, NULL, 0, DAY_SECONDS);
    static_addNameEntry(X509_get_subject_name(certificate), NID_organizationName, organization, organization_len);
    static_addNameEntry(X509_get_subject_name(certificate), NID_commonName, "host\0.example", 13);
    static_sign(certificate, NULL, g_serverKey);

    TlsProbeCertificate_t read = { 0 };
    TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
    TEST_ASSERT_EQUAL_STRING("", read.ma_subject);
    if (organization_len < TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE)
      TEST_ASSERT_EQUAL_INT(organization_len, (int)strlen(read.ma_issuer));
    else
      TEST_ASSERT_EQUAL_STRING("", read.ma_issuer);
    X509_free(certificate);
  }
}

void test_tryReadCertificate_keeps_a_serial_of_20_bytes_and_leaves_out_21(void)
{
  static const char* const serials[] = { "7F0102030405060708090A0B0C0D0E0F10111213", "7F0102030405060708090A0B0C0D0E0F1011121314" };
  for (int i = 0; i < 2; i++)
  {
    X509*   certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
    BIGNUM* serial      = NULL;
    TEST_ASSERT_TRUE(BN_hex2bn(&serial, serials[i]) > 0);
    BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(certificate));
    BN_free(serial);
    static_sign(certificate, NULL, g_serverKey);

    TlsProbeCertificate_t read = { 0 };
    TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
    TEST_ASSERT_EQUAL_STRING(i == 0 ? serials[0] : "", read.ma_serialHex);
    X509_free(certificate);
  }
}

void test_tryReadCertificate_leaves_out_a_negative_serial_of_41_characters(void)
{
  X509*   certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
  BIGNUM* serial      = NULL;
  TEST_ASSERT_TRUE(BN_hex2bn(&serial, "-7F0102030405060708090A0B0C0D0E0F10111213") > 0);
  BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(certificate));
  BN_free(serial);
  static_sign(certificate, NULL, g_serverKey);

  TlsProbeCertificate_t read = { 0 };
  TEST_ASSERT_TRUE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_STRING("", read.ma_serialHex);
  TEST_ASSERT_EQUAL_STRING("ecdsa-with-SHA256", read.ma_signatureAlgorithm);
  X509_free(certificate);
}

void test_tryReadCertificate_refuses_bytes_that_are_not_one_certificate(void)
{
  X509* certificate = static_newCertificate(g_serverKey, "probe.example", 0, DAY_SECONDS);
  static_sign(certificate, NULL, g_serverKey);
  int            der_len = 0;
  unsigned char* der     = static_toDer(certificate, &der_len);
  unsigned char  longer[4096];
  TEST_ASSERT_TRUE(der_len < (int)sizeof(longer));
  memcpy(longer, der, (size_t)der_len);
  longer[der_len] = 0x00;

  static const unsigned char junk[] = "not a certificate";
  TlsProbeCertificate_t      zero   = { 0 };
  TlsProbeCertificate_t      read;

  memset(&read, 0xAB, sizeof(read));
  TEST_ASSERT_FALSE(tlsprobe_tryReadCertificate(der, 0, &read));
  TEST_ASSERT_EQUAL_MEMORY(&zero, &read, sizeof(read));
  memset(&read, 0xAB, sizeof(read));
  TEST_ASSERT_FALSE(tlsprobe_tryReadCertificate(junk, sizeof(junk), &read));
  TEST_ASSERT_EQUAL_MEMORY(&zero, &read, sizeof(read));
  memset(&read, 0xAB, sizeof(read));
  TEST_ASSERT_FALSE(tlsprobe_tryReadCertificate(der, (size_t)der_len - 1, &read));
  TEST_ASSERT_EQUAL_MEMORY(&zero, &read, sizeof(read));
  memset(&read, 0xAB, sizeof(read));
  TEST_ASSERT_FALSE(tlsprobe_tryReadCertificate(longer, (size_t)der_len + 1, &read));
  TEST_ASSERT_EQUAL_MEMORY(&zero, &read, sizeof(read));
  TEST_ASSERT_TRUE(tlsprobe_tryReadCertificate(longer, (size_t)der_len, &read));

  OPENSSL_free(der);
  X509_free(certificate);
}

static X509* static_newCertificateWithBadNotAfter(void)
{
  X509* certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, NULL, NULL);
  TEST_ASSERT_EQUAL_INT(1, ASN1_STRING_set(X509_getm_notAfter(certificate), "261301000000Z", 13));
  static_sign(certificate, NULL, g_serverKey);
  return certificate;
}

void test_tryReadCertificate_refuses_a_validity_period_it_cannot_read(void)
{
  X509*                 certificate = static_newCertificateWithBadNotAfter();
  TlsProbeCertificate_t zero        = { 0 };
  TlsProbeCertificate_t read;
  memset(&read, 0xAB, sizeof(read));
  TEST_ASSERT_FALSE(static_readCertificate(certificate, &read));
  TEST_ASSERT_EQUAL_MEMORY(&zero, &read, sizeof(read));
  X509_free(certificate);
}

void test_problemsFromCertificateError_names_each_code(void)
{
  static const struct { long m_code; unsigned int m_problems; } cases[] = {
    { X509_V_OK,                                        0                                },
    { X509_V_ERR_CERT_HAS_EXPIRED,                      TLSPROBE_PROBLEM_EXPIRED           },
    { X509_V_ERR_CERT_NOT_YET_VALID,                    TLSPROBE_PROBLEM_NOT_YET_VALID     },
    { X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,           TLSPROBE_PROBLEM_SELF_SIGNED       },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,             TLSPROBE_PROBLEM_CHAIN_INCOMPLETE  },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,     TLSPROBE_PROBLEM_CHAIN_INCOMPLETE  },
    { X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,       TLSPROBE_PROBLEM_CHAIN_INCOMPLETE  },
    { X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,             TLSPROBE_PROBLEM_UNTRUSTED_ROOT    },
    { X509_V_ERR_HOSTNAME_MISMATCH,                     TLSPROBE_PROBLEM_HOSTNAME_MISMATCH },
    { X509_V_ERR_EE_KEY_TOO_SMALL,                      TLSPROBE_PROBLEM_WEAK_CRYPTO       },
    { X509_V_ERR_CA_KEY_TOO_SMALL,                      TLSPROBE_PROBLEM_WEAK_CRYPTO       },
    { X509_V_ERR_CA_MD_TOO_WEAK,                        TLSPROBE_PROBLEM_WEAK_CRYPTO       },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE,                TLSPROBE_PROBLEM_OTHER             },
    { X509_V_ERR_INVALID_CA,                            TLSPROBE_PROBLEM_OTHER             },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_problems, tlsprobe_problemsFromCertificateError(cases[i].m_code), "certificate error");
}

void test_daysRemaining_cuts_toward_zero(void)
{
  static const struct { int64_t m_secondsLeft; int m_days; } cases[] = {
    { 2 * DAY_SECONDS,      2  },
    { 2 * DAY_SECONDS - 1,  1  },
    { DAY_SECONDS,          1  },
    { DAY_SECONDS - 1,      0  },
    { 0,                    0  },
    { -(DAY_SECONDS - 1),   0  },
    { -DAY_SECONDS,         -1 },
    { -(DAY_SECONDS + 1),   -1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_INT(cases[i].m_days, tlsprobe_daysRemaining(1800000000 + cases[i].m_secondsLeft, 1800000000));
}

void test_probeHost_refuses_a_name_before_any_question(void)
{
  static const char* const names[] = { "printer.local", "", "two words.example", "probe.example." };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    TlsProbeResult_t result;
    memset(&result, 0xAB, sizeof(result));
    TEST_ASSERT_EQUAL_INT(TLSPROBE_INVALID_NAME, tlsprobe_probeHost(names[i], &result));
    TEST_ASSERT_TRUE(static_isResultZero(&result));
  }
  TEST_ASSERT_EQUAL_INT(0, g_askCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCallCount);
}

void test_probeHost_asks_for_a_and_aaaa_in_one_call(void)
{
  g_fakeAnswers[0].m_status = DNS_ANSWER_NXDOMAIN;
  g_fakeAnswers[1].m_status = DNS_ANSWER_NXDOMAIN;

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_NAME_NOT_FOUND, tlsprobe_probeHost("Probe.EXAMPLE", &result));
  TEST_ASSERT_EQUAL_INT(1, g_askCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_askQuestionCount);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_RESOLVE_DEADLINE_MS, g_askDeadlineMs);
  TEST_ASSERT_EQUAL_STRING("probe.example", g_askNames[0]);
  TEST_ASSERT_EQUAL_STRING("probe.example", g_askNames[1]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_A, g_askTypes[0]);
  TEST_ASSERT_EQUAL_INT(DNS_RECORD_TYPE_AAAA, g_askTypes[1]);
}

void test_probeHost_names_each_answer_without_a_globally_reachable_address(void)
{
  static const struct { FakeAnswer_t ma_answers[2]; TlsProbeStatus_t m_status; } cases[] = {
    { { { DNS_ANSWER_NXDOMAIN,        { NULL } },         { DNS_ANSWER_NXDOMAIN,        { NULL } } },  TLSPROBE_NAME_NOT_FOUND     },
    { { { DNS_ANSWER_OK,              { NULL } },         { DNS_ANSWER_OK,              { NULL } } },  TLSPROBE_NAME_NOT_FOUND     },
    { { { DNS_ANSWER_TIMEOUT,         { NULL } },         { DNS_ANSWER_NXDOMAIN,        { NULL } } },  TLSPROBE_RESOLVE_FAILED     },
    { { { DNS_ANSWER_OK,              { NULL } },         { DNS_ANSWER_SERVER_ERROR,    { NULL } } },  TLSPROBE_RESOLVE_FAILED     },
    { { { DNS_ANSWER_NO_MEMORY,       { NULL } },         { DNS_ANSWER_OK,              { NULL } } },  TLSPROBE_NO_MEMORY          },
    { { { DNS_ANSWER_NOT_PUBLIC_NAME, { NULL } },         { DNS_ANSWER_TIMEOUT,         { NULL } } },  TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE },
    { { { DNS_ANSWER_OK,              { "10.0.0.1" } },   { DNS_ANSWER_OK,              { "::1" } } }, TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE },
    { { { DNS_ANSWER_OK,              { "127.0.0.1" } },  { DNS_ANSWER_TIMEOUT,         { NULL } } },  TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE },
    { { { DNS_ANSWER_OK,              { "10.0.0.1" } },   { DNS_ANSWER_NO_MEMORY,       { NULL } } },  TLSPROBE_NO_MEMORY          },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    memcpy(g_fakeAnswers, cases[i].ma_answers, sizeof(g_fakeAnswers));
    TlsProbeResult_t result;
    memset(&result, 0xAB, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, tlsprobe_probeHost("probe.example", &result), "case");
    TEST_ASSERT_TRUE(static_isResultZero(&result));
  }
  TEST_ASSERT_EQUAL_INT(0, g_socketCallCount);
}

void test_probeHost_connects_only_to_a_globally_reachable_address(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  static_startServer(&server);
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "10.0.0.1", "93.184.216.34" } };
  g_fakeAnswers[1] = (FakeAnswer_t){ DNS_ANSWER_OK, { NULL } };
  g_socketProtocols[0] = -1;

  TlsProbeResult_t result;
  TlsProbeStatus_t status = tlsprobe_probeHost("probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, status);

  TEST_ASSERT_EQUAL_INT(1, g_socketCallCount);
  TEST_ASSERT_EQUAL_INT(AF_INET, g_socketFamilies[0]);
  TEST_ASSERT_EQUAL_INT(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, g_socketTypes[0]);
  TEST_ASSERT_EQUAL_INT(0, g_socketProtocols[0]);
  TEST_ASSERT_EQUAL_STRING("93.184.216.34", g_connectAddresses[0]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_PORT, g_connectPorts[0]);
  TEST_ASSERT_EQUAL_STRING("93.184.216.34", result.ma_ipAddress);
  TEST_ASSERT_EQUAL_STRING("probe.example", result.ma_hostname);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  X509_free(server_certificate);
}

void test_probeHost_tries_the_next_address_after_a_refusal(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  static_startServer(&server);
  g_connectPlan[0] = FAKE_CONNECT_REFUSED;
  g_connectPlan[1] = FAKE_CONNECT_PENDING_REFUSED;
  g_connectPlan[2] = FAKE_CONNECT_PENDING_OK;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "8.8.8.8", "1.1.1.1" } };
  g_fakeAnswers[1] = (FakeAnswer_t){ DNS_ANSWER_OK, { "2606:4700:1234:5678:9abc:def0:1234:5678" } };

  TlsProbeResult_t result;
  TlsProbeStatus_t status = tlsprobe_probeHost("probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, status);

  TEST_ASSERT_EQUAL_INT(3, g_connectCallCount);
  TEST_ASSERT_EQUAL_STRING("8.8.8.8", g_connectAddresses[0]);
  TEST_ASSERT_EQUAL_STRING("1.1.1.1", g_connectAddresses[1]);
  TEST_ASSERT_EQUAL_STRING("2606:4700:1234:5678:9abc:def0:1234:5678", g_connectAddresses[2]);
  TEST_ASSERT_EQUAL_INT(AF_INET6, g_socketFamilies[2]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_PORT, g_connectPorts[2]);
  TEST_ASSERT_EQUAL_STRING("2606:4700:1234:5678:9abc:def0:1234:5678", result.ma_ipAddress);
  TEST_ASSERT_EQUAL_INT(3, g_closeCount);
  X509_free(server_certificate);
}

void test_probeHost_no_address_taking_the_connection_is_connect_failed(void)
{
  g_connectPlan[0] = FAKE_CONNECT_REFUSED;
  g_connectPlan[1] = FAKE_CONNECT_PENDING_REFUSED;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "8.8.8.8", "1.1.1.1" } };
  g_fakeAnswers[1] = (FakeAnswer_t){ DNS_ANSWER_NXDOMAIN, { NULL } };

  TlsProbeResult_t result;
  memset(&result, 0xAB, sizeof(result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_FAILED, tlsprobe_probeHost("probe.example", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(2, g_closeCount);

  setUp();
  g_socketFailErrno = EMFILE;
  g_fakeAnswers[0]  = (FakeAnswer_t){ DNS_ANSWER_OK, { "8.8.8.8" } };
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_FAILED, tlsprobe_probeHost("probe.example", &result));
  TEST_ASSERT_EQUAL_INT(1, g_socketCallCount);
  TEST_ASSERT_EQUAL_INT(0, g_closeCount);
}

void test_probeHost_waits_for_each_connection_until_its_own_deadline(void)
{
  g_connectPlan[0] = FAKE_CONNECT_PENDING_SILENT;
  g_connectPlan[1] = FAKE_CONNECT_PENDING_SILENT;
  g_connectPlan[2] = FAKE_CONNECT_PENDING_SILENT;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "8.8.8.8", "1.1.1.1", "9.9.9.9" } };

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_TIMEOUT, tlsprobe_probeHost("probe.example", &result));
  TEST_ASSERT_EQUAL_INT(3, g_pollCount);
  TEST_ASSERT_EQUAL_INT(POLLOUT, g_pollEvents[0]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_DEADLINE_MS, g_pollTimeouts[0]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_DEADLINE_MS, g_pollTimeouts[1]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_DEADLINE_MS - 2 * TLSPROBE_CONNECT_DEADLINE_MS, g_pollTimeouts[2]);
  TEST_ASSERT_EQUAL_INT(3, g_closeCount);
}

void test_probeHost_connections_that_time_out_before_the_deadline_are_connect_failed(void)
{
  g_connectPlan[0] = FAKE_CONNECT_PENDING_SILENT;
  g_connectPlan[1] = FAKE_CONNECT_PENDING_SILENT;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "8.8.8.8", "1.1.1.1" } };

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_FAILED, tlsprobe_probeHost("probe.example", &result));
  TEST_ASSERT_EQUAL_INT(2, g_pollCount);
}

void test_probeHost_one_deadline_covers_the_lookup(void)
{
  FakeServer_t server = { .m_mode = FAKE_SERVER_SILENT };
  static_startServer(&server);
  g_connectPlan[0] = FAKE_CONNECT_OK_SILENT;
  g_askAdvanceMs   = 1000;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "93.184.216.34" } };

  TlsProbeResult_t result;
  TlsProbeStatus_t status = tlsprobe_probeHost("probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_TIMEOUT, status);
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_DEADLINE_MS - 1000, g_pollTimeouts[0]);
}

void test_probeHost_a_failed_handshake_ends_the_probe(void)
{
  FakeServer_t server = { .m_mode = FAKE_SERVER_PLAIN_TEXT };
  static_startServer(&server);
  g_connectPlan[1] = FAKE_CONNECT_REFUSED;
  g_fakeAnswers[0] = (FakeAnswer_t){ DNS_ANSWER_OK, { "93.184.216.34", "8.8.8.8" } };

  TlsProbeResult_t result;
  TlsProbeStatus_t status = tlsprobe_probeHost("probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_FAILED, status);
  TEST_ASSERT_EQUAL_INT(1, g_connectCallCount);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS, result.m_handshakeError);
  result.m_handshakeError = TLSPROBE_HANDSHAKE_ERROR_NONE;
  TEST_ASSERT_TRUE(static_isResultZero(&result));
}

void test_probeIpAddress_refuses_an_address_that_is_not_globally_reachable(void)
{
  struct sockaddr_in loopback = { .sin_family = AF_INET };
  inet_pton(AF_INET, "127.0.0.1", &loopback.sin_addr);
  struct sockaddr_in private_address = { .sin_family = AF_INET };
  inet_pton(AF_INET, "10.1.2.3", &private_address.sin_addr);
  struct sockaddr_in6 loopback6 = { .sin6_family = AF_INET6 };
  inet_pton(AF_INET6, "::1", &loopback6.sin6_addr);
  struct sockaddr_in  reachable_address = static_globallyReachableAddress();
  struct sockaddr_un  unix_address   = { .sun_family = AF_UNIX };

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&loopback, sizeof(loopback), "probe.example", &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&private_address, sizeof(private_address), "probe.example", &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&loopback6, sizeof(loopback6), "probe.example", &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&reachable_address, sizeof(reachable_address) - 1, "probe.example", &result));
  struct sockaddr_storage longer = { 0 };
  memcpy(&longer, &reachable_address, sizeof(reachable_address));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&longer, sizeof(reachable_address) + 1, "probe.example", &result));
  struct sockaddr_in6 reachable6 = { .sin6_family = AF_INET6 };
  inet_pton(AF_INET6, "2606:4700::1111", &reachable6.sin6_addr);
  memset(&longer, 0, sizeof(longer));
  memcpy(&longer, &reachable6, sizeof(reachable6));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&longer, sizeof(reachable6) + 1, "probe.example", &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE, tlsprobe_probeIpAddress((const struct sockaddr*)&unix_address, sizeof(unix_address), "probe.example", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(0, g_socketCallCount);
}

void test_probeIpAddress_refuses_a_hostname_before_the_connection(void)
{
  struct sockaddr_in address = static_globallyReachableAddress();
  TlsProbeResult_t   result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_INVALID_NAME, tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "router.local", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(0, g_socketCallCount);
}

void test_probeIpAddress_reads_a_trusted_certificate(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));

  TEST_ASSERT_TRUE(server.m_isHandshakeDone);
  TEST_ASSERT_TRUE(g_handshakeStepCount > 0);
  TEST_ASSERT_EQUAL_INT(g_handshakeStepCount, g_legacyServerStepCount);
  TEST_ASSERT_EQUAL_STRING("probe.example", server.ma_servername);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_PORT, g_connectPorts[0]);
  TEST_ASSERT_EQUAL_STRING("probe.example", result.ma_hostname);
  TEST_ASSERT_EQUAL_STRING("93.184.216.34", result.ma_ipAddress);
  TEST_ASSERT_EQUAL_STRING("TLSv1.3", result.ma_protocol);
  TEST_ASSERT_EQUAL_STRING("TLS_AES_256_GCM_SHA384", result.ma_cipherName);
  TEST_ASSERT_EQUAL_INT(256, result.m_cipherBits);
  TEST_ASSERT_EQUAL_STRING("x25519", result.ma_keyExchangeGroup);
  TEST_ASSERT_EQUAL_INT(253, result.m_keyExchangeBits);
  TEST_ASSERT_EQUAL_STRING("", result.ma_alpnProtocol);
  TEST_ASSERT_EQUAL_UINT(sizeof(ALPN_OFFERED) - 1, server.m_offeredAlpnLen);
  TEST_ASSERT_EQUAL_MEMORY(ALPN_OFFERED, server.ma_offeredAlpn, sizeof(ALPN_OFFERED) - 1);
  TEST_ASSERT_EQUAL_UINT(0, result.m_problems);
  TEST_ASSERT_TRUE(result.m_isTrusted);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_REVOKE_NOT_SENT, result.m_revokeStatus);
  TEST_ASSERT_EQUAL_INT(90, result.m_daysRemaining);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_SECURE_RENEGOTIATION_NOT_APPLICABLE, result.m_secureRenegotiation);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_NONE, result.m_handshakeError);

  int            der_len = 0;
  unsigned char* der     = static_toDer(server_certificate, &der_len);
  char           expected_sha256[TLSPROBE_CERTIFICATE_SHA256_HEX_SIZE];
  char           expected_sha1[TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE];
  static_digestHex(der, (size_t)der_len, EVP_sha256(), expected_sha256);
  static_digestHex(der, (size_t)der_len, EVP_sha1(), expected_sha1);
  OPENSSL_free(der);
  TEST_ASSERT_EQUAL_STRING(expected_sha256, result.m_serverCertificate.ma_sha256Hex);
  TEST_ASSERT_EQUAL_STRING(expected_sha1, result.m_serverCertificate.ma_sha1Hex);
  TEST_ASSERT_EQUAL_STRING("Probe Test CA", result.m_serverCertificate.ma_issuer);
  TEST_ASSERT_EQUAL_STRING("probe.example", result.m_serverCertificate.ma_subject);
  TEST_ASSERT_EQUAL_INT(1, result.m_serverCertificate.m_dnsNameCount);

  TEST_ASSERT_EQUAL_INT(1, result.m_chainCount);
  TEST_ASSERT_FALSE(result.m_isChainTruncated);
  TEST_ASSERT_EQUAL_STRING("CN=probe.example", result.ma_chain[0].ma_subjectFullName);
  TEST_ASSERT_EQUAL_STRING("CN=Probe Root,O=Probe Test CA", result.ma_chain[0].ma_issuerFullName);
  TEST_ASSERT_EQUAL_STRING(result.m_serverCertificate.ma_validUntil, result.ma_chain[0].ma_validUntil);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  X509_free(server_certificate);
}

void test_probeIpAddress_connects_to_port_443_of_an_ipv6_address(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  static_startServer(&server);
  struct sockaddr_in6 address = { .sin6_family = AF_INET6, .sin6_port = htons(8443) };
  inet_pton(AF_INET6, "2606:4700::1111", &address.sin6_addr);

  TlsProbeResult_t result;
  TlsProbeStatus_t status = tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, status);
  TEST_ASSERT_EQUAL_INT(AF_INET6, g_socketFamilies[0]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_PORT, g_connectPorts[0]);
  TEST_ASSERT_EQUAL_STRING("2606:4700::1111", result.ma_ipAddress);
  X509_free(server_certificate);
}

void test_probeIpAddress_a_certificate_it_cannot_read_is_handshake_failed(void)
{
  X509*        server_certificate = static_newCertificateWithBadNotAfter();
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  TlsProbeResult_t result;
  memset(&result, 0xAB, sizeof(result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_FAILED, static_probeServer(&server, &result));
  TEST_ASSERT_TRUE(server.m_isHandshakeDone);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_NO_CERTIFICATE, result.m_handshakeError);
  result.m_handshakeError = TLSPROBE_HANDSHAKE_ERROR_NONE;
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  X509_free(server_certificate);
}

void test_probeIpAddress_keeps_a_chain_name_of_512_bytes_and_leaves_out_513(void)
{
  char organization[TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE];
  memset(organization, 'o', sizeof(organization));
  organization[505] = '\0';
  X509* name_of_512 = static_newAuthority(g_otherCaKey, organization, "x", NULL, NULL);
  organization[505] = 'o';
  organization[506] = '\0';
  X509* name_of_513        = static_newAuthority(g_otherCaKey, organization, "x", NULL, NULL);
  X509* server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  X509* extra[]            = { name_of_512, name_of_513 };

  FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = extra, .m_extraChainCount = 2 };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_INT(3, result.m_chainCount);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE - 1, (int)strlen(result.ma_chain[1].ma_subjectFullName));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CERTIFICATE_NAME_TEXT_SIZE - 1, (int)strlen(result.ma_chain[1].ma_issuerFullName));
  TEST_ASSERT_EQUAL_STRING("", result.ma_chain[2].ma_subjectFullName);
  TEST_ASSERT_EQUAL_STRING("", result.ma_chain[2].ma_issuerFullName);
  TEST_ASSERT_EQUAL_STRING(result.ma_chain[0].ma_validUntil, result.m_serverCertificate.ma_validUntil);
  TEST_ASSERT_EQUAL_INT(20, (int)strlen(result.ma_chain[2].ma_validUntil));

  X509_free(name_of_512);
  X509_free(name_of_513);
  X509_free(server_certificate);
}

void test_probeIpAddress_names_each_problem_of_a_certificate(void)
{
  X509* self_signed     = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600, NULL, NULL);
  X509* other_name      = static_newServerCertificate("other.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600, g_caCert, g_caKey);
  X509* expired         = static_newServerCertificate("probe.example", -10 * DAY_SECONDS, -2 * DAY_SECONDS - 3600, g_caCert, g_caKey);
  X509* not_yet_valid   = static_newServerCertificate("probe.example", 2 * DAY_SECONDS, 90 * DAY_SECONDS + 3600, g_caCert, g_caKey);
  X509* untrusted_issue = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600, g_otherCaCert, g_otherCaKey);
  X509* three_reasons   = static_newServerCertificate("other.example", -10 * DAY_SECONDS, -2 * DAY_SECONDS - 3600, NULL, NULL);
  X509* no_intermediate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600, g_intermediateCert, g_intermediateKey);
  X509* no_dns_name     = static_newCertificate(g_serverKey, "probe.example", -DAY_SECONDS, 90 * DAY_SECONDS + 3600);
  static_sign(no_dns_name, g_caCert, g_caKey);
  X509* chain_with_root[] = { g_otherCaCert };

  static const struct { int m_certificateIndex; bool m_isRootSent; unsigned int m_problems; int m_days; } cases[] = {
    { 0, false, TLSPROBE_PROBLEM_SELF_SIGNED,       90 },
    { 1, false, TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, 90 },
    { 2, false, TLSPROBE_PROBLEM_EXPIRED,           -2 },
    { 3, false, TLSPROBE_PROBLEM_NOT_YET_VALID,     90 },
    { 4, false, TLSPROBE_PROBLEM_CHAIN_INCOMPLETE,  90 },
    { 4, true,  TLSPROBE_PROBLEM_UNTRUSTED_ROOT,    90 },
    { 6, false, TLSPROBE_PROBLEM_CHAIN_INCOMPLETE,  90 },
    { 7, false, TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, 90 },
    { 5, false, TLSPROBE_PROBLEM_SELF_SIGNED | TLSPROBE_PROBLEM_HOSTNAME_MISMATCH | TLSPROBE_PROBLEM_EXPIRED, -2 },
  };
  X509* server_certificates[] = { self_signed, other_name, expired, not_yet_valid, untrusted_issue, three_reasons, no_intermediate, no_dns_name };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificates[cases[i].m_certificateIndex] };
    if (cases[i].m_isRootSent)
    {
      server.mp_extraChain     = chain_with_root;
      server.m_extraChainCount = 1;
    }
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_problems, result.m_problems, "problems");
    TEST_ASSERT_FALSE(result.m_isTrusted);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_days, result.m_daysRemaining, "days");
  }
  for (size_t i = 0; i < sizeof(server_certificates) / sizeof(server_certificates[0]); i++)
    X509_free(server_certificates[i]);
}

void test_probeIpAddress_a_weak_key_or_signature_is_weak_crypto(void)
{
  EVP_PKEY* weak_key = EVP_RSA_gen(1024);
  TEST_ASSERT_NOT_NULL(weak_key);
  const char* dns_name = "probe.example";

  X509* sha1_signed = static_newServerCertificate(dns_name, -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  static_signWithDigest(sha1_signed, g_caCert, g_caKey, EVP_sha1());
  X509* weak_server_key = static_newCertificate(weak_key, dns_name, -DAY_SECONDS, 90 * DAY_SECONDS);
  static_addDnsNames(weak_server_key, &dns_name, NULL, 1);
  static_sign(weak_server_key, g_caCert, g_caKey);
  X509* weak_intermediate       = static_newAuthority(weak_key, "Probe Test CA", "Weak Intermediate", g_caCert, g_caKey);
  X509* under_weak_intermediate = static_newServerCertificate(dns_name, -DAY_SECONDS, 90 * DAY_SECONDS, weak_intermediate, weak_key);
  X509* strong                  = static_newServerCertificate(dns_name, -DAY_SECONDS, 90 * DAY_SECONDS, g_intermediateCert, g_intermediateKey);
  EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
  TEST_ASSERT_NOT_NULL(rsa_key);
  X509* rsa_server = static_newCertificate(rsa_key, dns_name, -DAY_SECONDS, 90 * DAY_SECONDS);
  static_addDnsNames(rsa_server, &dns_name, NULL, 1);
  static_sign(rsa_server, g_caCert, g_caKey);

  struct { X509* mp_certificate; EVP_PKEY* mp_key; X509* mp_intermediate; unsigned int m_problems; } cases[] = {
    { sha1_signed,             NULL,     NULL,               TLSPROBE_PROBLEM_WEAK_CRYPTO },
    { weak_server_key,         weak_key, NULL,               TLSPROBE_PROBLEM_WEAK_CRYPTO },
    { under_weak_intermediate, NULL,     weak_intermediate,  TLSPROBE_PROBLEM_WEAK_CRYPTO },
    { strong,                  NULL,     g_intermediateCert, 0                            },
    { rsa_server,              rsa_key,  NULL,               0                            },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = cases[i].mp_certificate, .mp_serverKey = cases[i].mp_key };
    if (cases[i].mp_intermediate != NULL)
    {
      server.mp_extraChain     = &cases[i].mp_intermediate;
      server.m_extraChainCount = 1;
    }
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_problems, result.m_problems, "problems");
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_problems == 0, result.m_isTrusted, "trusted");
  }

  X509_free(sha1_signed);
  X509_free(weak_server_key);
  X509_free(weak_intermediate);
  X509_free(under_weak_intermediate);
  X509_free(strong);
  X509_free(rsa_server);
  EVP_PKEY_free(rsa_key);
  EVP_PKEY_free(weak_key);
}

void test_probeIpAddress_a_chain_check_it_cannot_start_is_no_memory(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  g_isStoreContextFailing = true;

  TlsProbeResult_t result;
  memset(&result, 0xAB, sizeof(result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_NO_MEMORY, static_probeServer(&server, &result));
  TEST_ASSERT_TRUE(server.m_isHandshakeDone);
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  X509_free(server_certificate);
}

void test_probeIpAddress_a_chain_check_that_stops_early_is_a_problem(void)
{
  X509*           constrained      = static_newAuthority(g_intermediateKey, "Probe Test CA", "Constrained Intermediate", g_caCert, g_caKey);
  X509_EXTENSION* name_constraints = X509V3_EXT_conf_nid(NULL, NULL, NID_name_constraints, "permitted;DNS:probe.example");
  TEST_ASSERT_NOT_NULL(name_constraints);
  X509_add_ext(constrained, name_constraints, -1);
  X509_EXTENSION_free(name_constraints);
  static_sign(constrained, g_caCert, g_caKey);

  static const struct { bool m_isSha1; unsigned int m_problems; } cases[] = {
    { false, TLSPROBE_PROBLEM_HOSTNAME_MISMATCH | TLSPROBE_PROBLEM_OTHER                                },
    { true,  TLSPROBE_PROBLEM_HOSTNAME_MISMATCH | TLSPROBE_PROBLEM_OTHER | TLSPROBE_PROBLEM_WEAK_CRYPTO },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    X509* server_certificate = static_newCertificate(g_serverKey, NULL, -DAY_SECONDS, 90 * DAY_SECONDS);
    TEST_ASSERT_EQUAL_INT(1, X509_NAME_add_entry_by_NID(X509_get_subject_name(server_certificate), NID_commonName, V_ASN1_BIT_STRING, (const unsigned char*)"probe.example", -1, -1, 0));
    static_signWithDigest(server_certificate, constrained, g_intermediateKey, cases[i].m_isSha1 ? EVP_sha1() : EVP_sha256());

    X509*            extra[] = { constrained };
    FakeServer_t     server  = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = extra, .m_extraChainCount = 1 };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_problems, result.m_problems, "problems");
    TEST_ASSERT_FALSE_MESSAGE(result.m_isTrusted, "trusted");
    X509_free(server_certificate);
  }
  X509_free(constrained);
}

void test_probeIpAddress_keeps_10_chain_entries_and_marks_the_rest(void)
{
  X509* server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_intermediateCert, g_intermediateKey);
  X509* extra[TLSPROBE_CHAIN_MAX_COUNT];
  extra[0] = g_intermediateCert;
  for (int i = 1; i < TLSPROBE_CHAIN_MAX_COUNT; i++)
    extra[i] = g_otherCaCert;

  for (int extra_count = TLSPROBE_CHAIN_MAX_COUNT - 1; extra_count <= TLSPROBE_CHAIN_MAX_COUNT; extra_count++)
  {
    setUp();
    FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = extra, .m_extraChainCount = extra_count };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
    TEST_ASSERT_EQUAL_INT(TLSPROBE_CHAIN_MAX_COUNT, result.m_chainCount);
    TEST_ASSERT_EQUAL(extra_count == TLSPROBE_CHAIN_MAX_COUNT, result.m_isChainTruncated);
    TEST_ASSERT_EQUAL_STRING("CN=probe.example", result.ma_chain[0].ma_subjectFullName);
    TEST_ASSERT_EQUAL_STRING("CN=Probe Intermediate,O=Probe Test CA", result.ma_chain[1].ma_subjectFullName);
    TEST_ASSERT_EQUAL_STRING("CN=Probe Root,O=Probe Test CA", result.ma_chain[1].ma_issuerFullName);
    TEST_ASSERT_EQUAL_STRING("CN=Other Root,O=Other CA", result.ma_chain[9].ma_subjectFullName);
    TEST_ASSERT_EQUAL_UINT(0, result.m_problems);
  }
  X509_free(server_certificate);
}

static void static_newDeepChain(int intermediate_count, const EVP_MD* top_digest, X509** chain_out)
{
  X509*     issuer     = g_caCert;
  EVP_PKEY* issuer_key = g_caKey;
  for (int i = 0; i < intermediate_count; i++)
  {
    char common_name[32];
    snprintf(common_name, sizeof(common_name), "Deep %d", i);
    X509* authority = static_newAuthority(g_intermediateKey, "Deep CA", common_name, issuer, issuer_key);
    if (i == 0)
      static_signWithDigest(authority, issuer, issuer_key, top_digest);
    chain_out[intermediate_count - 1 - i] = authority;
    issuer     = authority;
    issuer_key = g_intermediateKey;
  }
}

void test_probeIpAddress_a_chain_deeper_than_the_limit_is_a_problem(void)
{
  static const struct { int m_intermediateCount; bool m_isTopSha1; unsigned int m_problems; } cases[] = {
    { TLSPROBE_CHAIN_CHECK_MAX_DEPTH,     false, 0                                                         },
    { TLSPROBE_CHAIN_CHECK_MAX_DEPTH,     true,  TLSPROBE_PROBLEM_WEAK_CRYPTO                              },
    { TLSPROBE_CHAIN_CHECK_MAX_DEPTH + 1, false, TLSPROBE_PROBLEM_OTHER | TLSPROBE_PROBLEM_CHAIN_INCOMPLETE },
    { TLSPROBE_CHAIN_CHECK_MAX_DEPTH + 1, true,  TLSPROBE_PROBLEM_OTHER | TLSPROBE_PROBLEM_CHAIN_INCOMPLETE },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    X509* chain[TLSPROBE_CHAIN_CHECK_MAX_DEPTH + 1];
    static_newDeepChain(cases[i].m_intermediateCount, cases[i].m_isTopSha1 ? EVP_sha1() : EVP_sha256(), chain);
    X509* server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, chain[0], g_intermediateKey);

    FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = chain, .m_extraChainCount = cases[i].m_intermediateCount };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_problems, result.m_problems, "problems");
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_problems == 0, result.m_isTrusted, "trusted");

    X509_free(server_certificate);
    for (int j = 0; j < cases[i].m_intermediateCount; j++)
      X509_free(chain[j]);
  }
}

void test_probeIpAddress_reaches_a_tlsv1_server_and_names_its_protocol(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .m_onlyProtocol = TLS1_VERSION };

  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_STRING("TLSv1", result.ma_protocol);
  TEST_ASSERT_EQUAL_UINT(0, result.m_problems);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED, result.m_secureRenegotiation);
  X509_free(server_certificate);
}

void test_probeIpAddress_reads_the_key_exchange_of_each_kind(void)
{
  EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
  TEST_ASSERT_NOT_NULL(rsa_key);
  const char* dns_name = "probe.example";
  X509* rsa_server = static_newCertificate(rsa_key, dns_name, -DAY_SECONDS, 90 * DAY_SECONDS);
  static_addDnsNames(rsa_server, &dns_name, NULL, 1);
  static_sign(rsa_server, g_caCert, g_caKey);
  X509* ec_server = static_newServerCertificate(dns_name, -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);

  struct { FakeServer_t m_server; const char* mp_group; int m_bits; } cases[] = {
    { { .mp_serverCertificate = ec_server, .mp_groups = "P-256" }, "secp256r1", 256 },
    { { .mp_serverCertificate = rsa_server, .mp_serverKey = rsa_key, .m_onlyProtocol = TLS1_2_VERSION, .mp_cipherList = "DHE-RSA-AES128-GCM-SHA256", .m_isDhAuto = true }, "DH", 2048 },
    { { .mp_serverCertificate = rsa_server, .mp_serverKey = rsa_key, .m_onlyProtocol = TLS1_2_VERSION, .mp_cipherList = "AES128-GCM-SHA256" }, "", 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&cases[i].m_server, &result), "status");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_group, result.ma_keyExchangeGroup, "group");
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_bits, result.m_keyExchangeBits, "bits");
  }
  X509_free(rsa_server);
  X509_free(ec_server);
  EVP_PKEY_free(rsa_key);
}

void test_probeIpAddress_reads_the_alpn_protocol_the_server_picks(void)
{
  X509*       server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  const char* protocols[]        = { "h2", "http/1.1" };
  for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); i++)
  {
    setUp();
    FakeServer_t     server = { .mp_serverCertificate = server_certificate, .mp_alpnProtocol = protocols[i] };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
    TEST_ASSERT_EQUAL_STRING(protocols[i], result.ma_alpnProtocol);
  }
  X509_free(server_certificate);
}

void test_probeIpAddress_reads_secure_renegotiation_below_tls13(void)
{
  X509* server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  static const struct { bool m_isRenegotiationInfoMissing; TlsProbeSecureRenegotiation_t m_secureRenegotiation; } cases[] = {
    { false, TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED     },
    { true,  TLSPROBE_SECURE_RENEGOTIATION_NOT_SUPPORTED },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_isRenegotiationInfoMissing = cases[i].m_isRenegotiationInfoMissing;
    FakeServer_t     server = { .mp_serverCertificate = server_certificate, .m_onlyProtocol = TLS1_2_VERSION };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
    TEST_ASSERT_EQUAL_STRING("TLSv1.2", result.ma_protocol);
    TEST_ASSERT_EQUAL_INT(cases[i].m_secureRenegotiation, result.m_secureRenegotiation);
  }
  X509_free(server_certificate);
}

void test_probeIpAddress_reads_a_stapled_ocsp_response(void)
{
  X509* server_certificate        = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  X509* other_server_certificate  = static_newServerCertificate("other.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  X509* orphan_server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_intermediateCert, g_intermediateKey);
  ASN1_INTEGER_set(X509_get_serialNumber(other_server_certificate), 2);
  static_sign(other_server_certificate, g_caCert, g_caKey);

  int            lens[12];
  unsigned char* staples[12];
  staples[0] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &lens[0]);
  staples[1] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_REVOKED, -3600, DAY_SECONDS, &lens[1]);
  staples[2] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_UNKNOWN, -3600, DAY_SECONDS, &lens[2]);
  staples[3] = static_makeOcspResponse(server_certificate, g_caCert, g_otherCaCert, g_otherCaKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &lens[3]);
  staples[4] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -2 * DAY_SECONDS, -DAY_SECONDS, &lens[4]);
  staples[5] = static_makeOcspResponse(other_server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &lens[5]);
  staples[6] = static_makeOcspResponse(orphan_server_certificate, g_intermediateCert, g_intermediateCert, g_intermediateKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &lens[6]);
  staples[7] = static_makeOcspResponseWithStatus(OCSP_RESPONSE_STATUS_TRYLATER, server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &lens[7]);
  OCSP_RESPONSE* no_body = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL);
  staples[10] = NULL;
  lens[10]    = i2d_OCSP_RESPONSE(no_body, &staples[10]);
  OCSP_RESPONSE_free(no_body);
  staples[8] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -DAY_SECONDS, -200, &lens[8]);
  staples[9] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -DAY_SECONDS, -400, &lens[9]);
  staples[11] = static_makeOcspResponse(server_certificate, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, NO_NEXT_UPDATE, &lens[11]);
  static const unsigned char junk[] = "not an OCSP response";

  static const struct { int m_staple; int m_certificateIndex; TlsProbeRevokeStatus_t m_status; } cases[] = {
    { 0,  0, TLSPROBE_REVOKE_NOT_REVOKED },
    { 1,  0, TLSPROBE_REVOKE_REVOKED     },
    { 2,  0, TLSPROBE_REVOKE_UNKNOWN     },
    { 3,  0, TLSPROBE_REVOKE_UNUSABLE    },
    { 4,  0, TLSPROBE_REVOKE_UNUSABLE    },
    { 5,  0, TLSPROBE_REVOKE_UNKNOWN     },
    { 6,  1, TLSPROBE_REVOKE_UNKNOWN     },
    { 7,  0, TLSPROBE_REVOKE_UNUSABLE    },
    { 8,  0, TLSPROBE_REVOKE_NOT_REVOKED },
    { 9,  0, TLSPROBE_REVOKE_UNUSABLE    },
    { 10, 0, TLSPROBE_REVOKE_UNUSABLE    },
    { 11, 0, TLSPROBE_REVOKE_UNUSABLE    },
    { -1, 0, TLSPROBE_REVOKE_UNUSABLE    },
  };
  X509* server_certificates[] = { server_certificate, orphan_server_certificate };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    FakeServer_t server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificates[cases[i].m_certificateIndex] };
    server.mp_staple  = cases[i].m_staple < 0 ? junk : staples[cases[i].m_staple];
    server.m_stapleLen = cases[i].m_staple < 0 ? (int)sizeof(junk) : lens[cases[i].m_staple];
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, result.m_revokeStatus, "ocsp");
  }

  for (int i = 0; i < 12; i++)
    OPENSSL_free(staples[i]);
  X509_free(server_certificate);
  X509_free(other_server_certificate);
  X509_free(orphan_server_certificate);
}

void test_probeIpAddress_reads_ocsp_signed_by_the_sent_intermediate(void)
{
  X509*           server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_intermediateCert, g_intermediateKey);
  OCSP_CERTID*    certificate_id     = OCSP_cert_to_id(NULL, server_certificate, g_intermediateCert);
  OCSP_BASICRESP* basic_response     = OCSP_BASICRESP_new();
  ASN1_TIME*      this_update        = X509_gmtime_adj(NULL, -3600);
  ASN1_TIME*      next_update        = X509_gmtime_adj(NULL, DAY_SECONDS);
  TEST_ASSERT_NOT_NULL(OCSP_basic_add1_status(basic_response, certificate_id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, this_update, next_update));
  TEST_ASSERT_EQUAL_INT(1, OCSP_basic_sign(basic_response, g_intermediateCert, g_intermediateKey, EVP_sha256(), NULL, OCSP_NOCERTS));
  OCSP_RESPONSE* response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_response);
  unsigned char* der      = NULL;
  int            der_len  = i2d_OCSP_RESPONSE(response, &der);
  TEST_ASSERT_TRUE(der_len > 0);

  X509*        extra[] = { g_intermediateCert };
  FakeServer_t server  = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = extra, .m_extraChainCount = 1, .mp_staple = der, .m_stapleLen = der_len };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_UINT(0, result.m_problems);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_REVOKE_NOT_REVOKED, result.m_revokeStatus);

  OPENSSL_free(der);
  OCSP_RESPONSE_free(response);
  OCSP_BASICRESP_free(basic_response);
  OCSP_CERTID_free(certificate_id);
  ASN1_TIME_free(this_update);
  ASN1_TIME_free(next_update);
  X509_free(server_certificate);
}

void test_probeIpAddress_ocsp_does_not_count_for_a_forged_certificate(void)
{
  static const unsigned char not_a_signature[] = { 0x01, 0x02, 0x03, 0x04 };
  X509* signed_by_another_key = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  static_signWithDigest(signed_by_another_key, g_caCert, g_otherCaKey, EVP_sha256());
  X509*                  unreadable_signature = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  const ASN1_BIT_STRING* signature            = NULL;
  X509_get0_signature(&signature, NULL, unreadable_signature);
  TEST_ASSERT_EQUAL_INT(1, ASN1_BIT_STRING_set((ASN1_BIT_STRING*)signature, (unsigned char*)not_a_signature, sizeof(not_a_signature)));
  TEST_ASSERT_EQUAL_INT(-1, X509_verify(unreadable_signature, X509_get0_pubkey(g_caCert)));

  X509* forged[] = { signed_by_another_key, unreadable_signature };
  for (size_t i = 0; i < sizeof(forged) / sizeof(forged[0]); i++)
  {
    setUp();
    int            staple_len = 0;
    unsigned char* staple     = static_makeOcspResponse(forged[i], g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &staple_len);

    X509*            extra[] = { g_caCert };
    FakeServer_t     server  = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = forged[i], .mp_extraChain = extra, .m_extraChainCount = 1, .mp_staple = staple, .m_stapleLen = staple_len };
    TlsProbeResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_OK, static_probeServer(&server, &result), "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(TLSPROBE_PROBLEM_OTHER, result.m_problems, "problems");
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_REVOKE_UNKNOWN, result.m_revokeStatus, "revoke");
    OPENSSL_free(staple);
  }

  X509_free(signed_by_another_key);
  X509_free(unreadable_signature);
}

void test_probeIpAddress_checks_the_signature_only_of_an_issuer_the_ocsp_response_names(void)
{
  X509*           server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_intermediateCert, g_intermediateKey);
  OCSP_CERTID*    certificate_id     = OCSP_cert_to_id(NULL, server_certificate, g_intermediateCert);
  OCSP_BASICRESP* basic_response     = OCSP_BASICRESP_new();
  ASN1_TIME*      this_update        = X509_gmtime_adj(NULL, -3600);
  ASN1_TIME*      next_update        = X509_gmtime_adj(NULL, DAY_SECONDS);
  TEST_ASSERT_NOT_NULL(OCSP_basic_add1_status(basic_response, certificate_id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, this_update, next_update));
  TEST_ASSERT_EQUAL_INT(1, OCSP_basic_sign(basic_response, g_intermediateCert, g_intermediateKey, EVP_sha256(), NULL, OCSP_RESPID_KEY));
  OCSP_RESPONSE* response   = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_response);
  unsigned char* staple     = NULL;
  int            staple_len = i2d_OCSP_RESPONSE(response, &staple);
  TEST_ASSERT_TRUE(staple_len > 0);
  X509*          extra[4];
  for (int i = 0; i < 3; i++)
    extra[i] = static_newAuthority(g_otherCaKey, "Probe Test CA", "Probe Intermediate", g_caCert, g_caKey);
  extra[3] = g_intermediateCert;

  FakeServer_t     server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate, .mp_extraChain = extra, .m_extraChainCount = 4, .mp_staple = staple, .m_stapleLen = staple_len };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_REVOKE_NOT_REVOKED, result.m_revokeStatus);
  TEST_ASSERT_EQUAL_INT(1, g_signatureCheckCount);

  for (int i = 0; i < 3; i++)
    X509_free(extra[i]);
  OPENSSL_free(staple);
  OCSP_RESPONSE_free(response);
  OCSP_BASICRESP_free(basic_response);
  OCSP_CERTID_free(certificate_id);
  ASN1_TIME_free(this_update);
  ASN1_TIME_free(next_update);
  X509_free(server_certificate);
}

void test_probeIpAddress_reads_ocsp_for_a_self_signed_server_certificate(void)
{
  int            staple_len = 0;
  unsigned char* staple     = static_makeOcspResponse(g_caCert, g_caCert, g_caCert, g_caKey, V_OCSP_CERTSTATUS_GOOD, -3600, DAY_SECONDS, &staple_len);

  FakeServer_t     server = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = g_caCert, .mp_serverKey = g_caKey, .mp_staple = staple, .m_stapleLen = staple_len };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_REVOKE_NOT_REVOKED, result.m_revokeStatus);

  OPENSSL_free(staple);
}

void test_probeIpAddress_a_peer_that_is_not_tls_is_handshake_failed(void)
{
  FakeServer_t server = { .m_mode = FAKE_SERVER_PLAIN_TEXT };
  TlsProbeResult_t result;
  memset(&result, 0xAB, sizeof(result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_FAILED, static_probeServer(&server, &result));
  TEST_ASSERT_TRUE(server.m_isAnswerSent);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS, result.m_handshakeError);
  result.m_handshakeError = TLSPROBE_HANDSHAKE_ERROR_NONE;
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_UINT(0, ERR_peek_error());
}

void test_probeIpAddress_names_why_a_handshake_failed(void)
{
  X509* server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  struct { FakeServer_t m_server; TlsProbeHandshakeError_t m_handshakeError; } cases[] = {
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_PROTOCOL_VERSION      }, TLSPROBE_HANDSHAKE_ERROR_PROTOCOL_VERSION            },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_HANDSHAKE_FAILURE     }, TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE           },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_UNRECOGNIZED_NAME     }, TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME           },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_CERTIFICATE_REQUIRED  }, TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_INTERNAL_ERROR        }, TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT                 },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_ACCESS_DENIED         }, TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT                 },
    { { .m_mode = FAKE_SERVER_ALERT, .m_alert = SSL_AD_CLOSE_NOTIFY          }, TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT                 },
    { { .m_mode = FAKE_SERVER_APPLICATION_DATA                               }, TLSPROBE_HANDSHAKE_ERROR_OTHER                       },
    { { .m_mode = FAKE_SERVER_CLOSE                                          }, TLSPROBE_HANDSHAKE_ERROR_PEER_CLOSED                 },
    { { .mp_serverCertificate = server_certificate, .m_onlyProtocol = TLS1_2_VERSION, .m_isClientCertificateRequired = true }, TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED },
    { { .mp_serverCertificate = server_certificate, .m_onlyProtocol = TLS1_2_VERSION, .mp_cipherList = "NULL-SHA"            }, TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE           },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    TlsProbeResult_t result;
    memset(&result, 0xAB, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(TLSPROBE_HANDSHAKE_FAILED, static_probeServer(&cases[i].m_server, &result), "status");
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_handshakeError, result.m_handshakeError, "handshake error");
    result.m_handshakeError = TLSPROBE_HANDSHAKE_ERROR_NONE;
    TEST_ASSERT_TRUE_MESSAGE(static_isResultZero(&result), "zero");
    TEST_ASSERT_EQUAL_UINT(0, ERR_peek_error());
  }
  X509_free(server_certificate);
}

void test_probeIpAddress_a_tls13_request_for_a_client_certificate_is_ok(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .mp_serverCertificate = server_certificate, .m_isClientCertificateRequired = true };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_STRING("TLSv1.3", result.ma_protocol);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_NONE, result.m_handshakeError);
  X509_free(server_certificate);
}

void test_probeIpAddress_an_error_of_another_library_is_other(void)
{
  g_isErrorFromOtherLibrary = true;
  FakeServer_t     server   = { .m_mode = FAKE_SERVER_PLAIN_TEXT };
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_FAILED, static_probeServer(&server, &result));
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_OTHER, result.m_handshakeError);
}

void test_probeIpAddress_a_silent_peer_times_out_at_the_deadline(void)
{
  FakeServer_t server = { .m_mode = FAKE_SERVER_SILENT };
  static_startServer(&server);
  g_connectPlan[0] = FAKE_CONNECT_OK_SILENT;

  struct sockaddr_in address = static_globallyReachableAddress();
  TlsProbeResult_t   result;
  TlsProbeStatus_t   status  = tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "probe.example", &result);
  static_joinServer(&server);

  TEST_ASSERT_EQUAL_INT(TLSPROBE_TIMEOUT, status);
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT(POLLIN, g_pollEvents[0]);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_DEADLINE_MS, g_pollTimeouts[0]);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_TRUE(static_isResultZero(&result));
}

void test_probeIpAddress_an_interrupted_poll_is_tried_again(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t server             = { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate };
  g_pollFailErrno = EINTR;
  TlsProbeResult_t result;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, static_probeServer(&server, &result));
  TEST_ASSERT_TRUE(g_pollCount >= 2);
  X509_free(server_certificate);
}

void test_probeIpAddress_a_failing_poll_ends_the_probe(void)
{
  FakeServer_t server = { .m_mode = FAKE_SERVER_SILENT };
  static_startServer(&server);
  g_pollFailErrno = EBADF;
  struct sockaddr_in address = static_globallyReachableAddress();
  TlsProbeResult_t   result;
  TlsProbeStatus_t   status  = tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "probe.example", &result);
  static_joinServer(&server);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_FAILED, status);
  TEST_ASSERT_EQUAL_INT(TLSPROBE_HANDSHAKE_ERROR_OTHER, result.m_handshakeError);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);

  setUp();
  g_connectPlan[0] = FAKE_CONNECT_PENDING_SILENT;
  g_pollFailErrno  = EBADF;
  TEST_ASSERT_EQUAL_INT(TLSPROBE_CONNECT_FAILED, tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "probe.example", &result));
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
}

typedef struct {
  TlsProbeStatus_t m_status;
  TlsProbeResult_t m_result;
} ProbeThread_t;

static void* static_runProbe(void* probe_arg)
{
  ProbeThread_t*     probe   = probe_arg;
  struct sockaddr_in address = static_globallyReachableAddress();
  probe->m_status = tlsprobe_probeIpAddress((const struct sockaddr*)&address, sizeof(address), "probe.example", &probe->m_result);
  return NULL;
}

void test_two_probes_at_once_share_one_tls_settings(void)
{
  X509*        server_certificate = static_newServerCertificate("probe.example", -DAY_SECONDS, 90 * DAY_SECONDS, g_caCert, g_caKey);
  FakeServer_t servers[2]         = { { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate }, { .m_mode = FAKE_SERVER_TLS, .mp_serverCertificate = server_certificate } };
  static_startServer(&servers[0]);
  static_startServer(&servers[1]);

  static ProbeThread_t probes[2];
  pthread_t            threads[2];
  for (int i = 0; i < 2; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[i], NULL, static_runProbe, &probes[i]));
  for (int i = 0; i < 2; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_join(threads[i], NULL));
  static_joinServer(&servers[0]);
  static_joinServer(&servers[1]);

  for (int i = 0; i < 2; i++)
  {
    TEST_ASSERT_EQUAL_INT(TLSPROBE_OK, probes[i].m_status);
    TEST_ASSERT_TRUE(probes[i].m_result.m_isTrusted);
  }
  TEST_ASSERT_EQUAL_INT(1, g_verifyPathsCallCount);
  TEST_ASSERT_EQUAL_INT(2, g_closeCount);
  X509_free(server_certificate);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(54, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

static void static_makeAuthorities(void)
{
  g_caKey            = EVP_EC_gen("P-256");
  g_intermediateKey  = EVP_EC_gen("P-256");
  g_otherCaKey       = EVP_EC_gen("P-256");
  g_serverKey        = EVP_EC_gen("P-256");
  g_caCert           = static_newAuthority(g_caKey, "Probe Test CA", "Probe Root", NULL, NULL);
  g_intermediateCert = static_newAuthority(g_intermediateKey, "Probe Test CA", "Probe Intermediate", g_caCert, g_caKey);
  g_otherCaCert      = static_newAuthority(g_otherCaKey, "Other CA", "Other Root", NULL, NULL);
}

int main(void)
{
  signal(SIGPIPE, SIG_IGN);
  UNITY_BEGIN();
  static_makeAuthorities();
  RUN_TEST(test_tryReadCertificate_reads_each_field);
  RUN_TEST(test_tryReadCertificate_reads_an_rsa_key_and_its_size);
  RUN_TEST(test_tryReadCertificate_reads_a_utctime);
  RUN_TEST(test_tryReadCertificate_issuer_without_an_organization_is_its_common_name);
  RUN_TEST(test_tryReadCertificate_reads_the_issuer_common_name_from_the_issuer);
  RUN_TEST(test_tryReadCertificate_keeps_100_names_and_marks_the_rest);
  RUN_TEST(test_tryReadCertificate_skips_a_name_too_long_empty_or_with_a_nul);
  RUN_TEST(test_tryReadCertificate_name_with_a_nul_or_too_long_is_left_out);
  RUN_TEST(test_tryReadCertificate_keeps_a_serial_of_20_bytes_and_leaves_out_21);
  RUN_TEST(test_tryReadCertificate_leaves_out_a_negative_serial_of_41_characters);
  RUN_TEST(test_tryReadCertificate_refuses_bytes_that_are_not_one_certificate);
  RUN_TEST(test_tryReadCertificate_refuses_a_validity_period_it_cannot_read);
  RUN_TEST(test_problemsFromCertificateError_names_each_code);
  RUN_TEST(test_daysRemaining_cuts_toward_zero);
  RUN_TEST(test_probeHost_refuses_a_name_before_any_question);
  RUN_TEST(test_probeHost_asks_for_a_and_aaaa_in_one_call);
  RUN_TEST(test_probeHost_names_each_answer_without_a_globally_reachable_address);
  RUN_TEST(test_two_probes_at_once_share_one_tls_settings);
  RUN_TEST(test_probeHost_connects_only_to_a_globally_reachable_address);
  RUN_TEST(test_probeHost_tries_the_next_address_after_a_refusal);
  RUN_TEST(test_probeHost_no_address_taking_the_connection_is_connect_failed);
  RUN_TEST(test_probeHost_waits_for_each_connection_until_its_own_deadline);
  RUN_TEST(test_probeHost_connections_that_time_out_before_the_deadline_are_connect_failed);
  RUN_TEST(test_probeHost_one_deadline_covers_the_lookup);
  RUN_TEST(test_probeHost_a_failed_handshake_ends_the_probe);
  RUN_TEST(test_probeIpAddress_refuses_an_address_that_is_not_globally_reachable);
  RUN_TEST(test_probeIpAddress_refuses_a_hostname_before_the_connection);
  RUN_TEST(test_probeIpAddress_connects_to_port_443_of_an_ipv6_address);
  RUN_TEST(test_probeIpAddress_reads_a_trusted_certificate);
  RUN_TEST(test_probeIpAddress_names_each_problem_of_a_certificate);
  RUN_TEST(test_probeIpAddress_a_weak_key_or_signature_is_weak_crypto);
  RUN_TEST(test_probeIpAddress_a_chain_check_it_cannot_start_is_no_memory);
  RUN_TEST(test_probeIpAddress_a_chain_check_that_stops_early_is_a_problem);
  RUN_TEST(test_probeIpAddress_keeps_10_chain_entries_and_marks_the_rest);
  RUN_TEST(test_probeIpAddress_a_chain_deeper_than_the_limit_is_a_problem);
  RUN_TEST(test_probeIpAddress_keeps_a_chain_name_of_512_bytes_and_leaves_out_513);
  RUN_TEST(test_probeIpAddress_a_certificate_it_cannot_read_is_handshake_failed);
  RUN_TEST(test_probeIpAddress_reaches_a_tlsv1_server_and_names_its_protocol);
  RUN_TEST(test_probeIpAddress_reads_the_key_exchange_of_each_kind);
  RUN_TEST(test_probeIpAddress_reads_the_alpn_protocol_the_server_picks);
  RUN_TEST(test_probeIpAddress_reads_secure_renegotiation_below_tls13);
  RUN_TEST(test_probeIpAddress_reads_a_stapled_ocsp_response);
  RUN_TEST(test_probeIpAddress_reads_ocsp_signed_by_the_sent_intermediate);
  RUN_TEST(test_probeIpAddress_ocsp_does_not_count_for_a_forged_certificate);
  RUN_TEST(test_probeIpAddress_checks_the_signature_only_of_an_issuer_the_ocsp_response_names);
  RUN_TEST(test_probeIpAddress_reads_ocsp_for_a_self_signed_server_certificate);
  RUN_TEST(test_probeIpAddress_a_peer_that_is_not_tls_is_handshake_failed);
  RUN_TEST(test_probeIpAddress_names_why_a_handshake_failed);
  RUN_TEST(test_probeIpAddress_a_tls13_request_for_a_client_certificate_is_ok);
  RUN_TEST(test_probeIpAddress_an_error_of_another_library_is_other);
  RUN_TEST(test_probeIpAddress_a_silent_peer_times_out_at_the_deadline);
  RUN_TEST(test_probeIpAddress_an_interrupted_poll_is_tried_again);
  RUN_TEST(test_probeIpAddress_a_failing_poll_ends_the_probe);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
