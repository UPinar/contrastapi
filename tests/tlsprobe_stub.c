#include <ctype.h>
#include <string.h>

#include "tlsprobe.h"

#define TLSPROBE_STUB_DEFAULT_RESULT {                                                                        \
  .ma_hostname         = "stub.example.com",                                                                  \
  .ma_ipAddress        = "192.0.2.10",                                                                        \
  .ma_protocol         = "TLSv1.2",                                                                           \
  .ma_cipherName       = "ECDHE-RSA-AES128-GCM-SHA256",                                                       \
  .m_cipherBits        = 128,                                                                                 \
  .ma_keyExchangeGroup = "x25519",                                                                            \
  .m_keyExchangeBits   = 253,                                                                                 \
  .ma_alpnProtocol     = "h2",                                                                                \
  .m_serverCertificate = {                                                                                    \
    .ma_sha256Hex            = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",            \
    .ma_sha1Hex              = "fedcba9876543210fedcba9876543210fedcba98",                                    \
    .ma_validFrom            = "2026-01-02T03:04:05Z",                                                        \
    .ma_validUntil           = "2027-02-03T04:05:06Z",                                                        \
    .m_validUntilUnixSeconds = 1801627506,                                                                    \
    .ma_issuer               = "Stub CA Org",                                                                 \
    .ma_subject              = "stub.example.com",                                                            \
    .ma_serialHex            = "0A1B2C3D",                                                                    \
    .ma_signatureAlgorithm   = "sha256WithRSAEncryption",                                                     \
    .ma_keyType              = "RSA",                                                                         \
    .m_keyBits               = 2048,                                                                          \
    .ma_dnsNames             = { "stub.example.com", "www.stub.example.com" },                                \
    .m_dnsNameCount          = 2,                                                                             \
    .m_isDnsNameListTruncated = false,                                                                        \
  },                                                                                                          \
  .ma_chain = {                                                                                               \
    { "CN=stub.example.com", "CN=Stub Intermediate,O=Stub CA Org,C=US", "2027-02-03T04:05:06Z" },             \
    { "CN=Stub Intermediate,O=Stub CA Org,C=US", "CN=Stub Root,O=Stub CA Org,C=US", "2030-04-05T06:07:08Z" }, \
  },                                                                                                          \
  .m_chainCount          = 2,                                                                                 \
  .m_isChainTruncated    = false,                                                                             \
  .m_problems            = 0,                                                                                 \
  .m_isTrusted           = true,                                                                              \
  .m_revokeStatus        = TLSPROBE_REVOKE_NOT_REVOKED,                                                       \
  .m_daysRemaining       = 102,                                                                               \
  .m_secureRenegotiation = TLSPROBE_SECURE_RENEGOTIATION_SUPPORTED,                                           \
  .m_handshakeError      = TLSPROBE_HANDSHAKE_ERROR_NONE,                                                     \
}

const TlsProbeResult_t g_stub_TLSPROBE_default_result = TLSPROBE_STUB_DEFAULT_RESULT;

TlsProbeStatus_t         g_stub_TLSPROBE_status          = TLSPROBE_OK;
TlsProbeResult_t         g_stub_TLSPROBE_result          = TLSPROBE_STUB_DEFAULT_RESULT;
TlsProbeHandshakeError_t g_stub_TLSPROBE_handshake_error = TLSPROBE_HANDSHAKE_ERROR_NONE;

int  g_stub_TLSPROBE_call_count = 0;
char g_stub_TLSPROBE_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

void (*g_stub_TLSPROBE_on_call)(void) = NULL;

TlsProbeStatus_t tlsprobe_probeHost(const char* hostname, TlsProbeResult_t* result_out)
{
  g_stub_TLSPROBE_call_count++;
  if (g_stub_TLSPROBE_on_call)
    g_stub_TLSPROBE_on_call();
  strncpy(g_stub_TLSPROBE_last_hostname, hostname, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_TLSPROBE_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_TLSPROBE_status != TLSPROBE_OK)
  {
    if (g_stub_TLSPROBE_status == TLSPROBE_HANDSHAKE_FAILED)
      result_out->m_handshakeError = g_stub_TLSPROBE_handshake_error;
    return g_stub_TLSPROBE_status;
  }

  *result_out = g_stub_TLSPROBE_result;
  memset(result_out->ma_hostname, 0, sizeof(result_out->ma_hostname));
  for (size_t i = 0; hostname[i] != '\0' && i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    result_out->ma_hostname[i] = (char)tolower((unsigned char)hostname[i]);
  return TLSPROBE_OK;
}
