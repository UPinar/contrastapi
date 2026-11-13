#ifndef X402_H
#define X402_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jsonbuf.h"
#include "x402_solana.h"

#define X402_VERSION 2

#define X402_SCHEME_EXACT "exact"

#define X402_PAYMENT_JSON_MAX_BYTE_COUNT 2560

#define X402_BASE64_LEN(byte_count) (4 * (((byte_count) + 2) / 3))

#define X402_PAYMENT_HEADER_MAX_LEN X402_BASE64_LEN(X402_PAYMENT_JSON_MAX_BYTE_COUNT)

#define X402_NETWORK_BUF_SIZE 64

typedef struct {
  char      ma_network[X402_NETWORK_BUF_SIZE];
  char      ma_asset[48];
  char      ma_payTo[48];
  char      ma_feePayer[48];
  uint64_t  m_amountAtomic;
  uint32_t  m_maxTimeoutSeconds;
} X402Requirements_t;

typedef enum {
  X402_PAYMENT_OK,
  X402_PAYMENT_MALFORMED,
  X402_PAYMENT_NOT_ACCEPTED
} X402PaymentStatus_t;

typedef struct {
  uint8_t   ma_transaction[X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT];
  size_t    m_transactionByteCount;
} X402Payment_t;

bool                x402_writePaymentRequired     (JsonBuf_t* json_buf, const X402Requirements_t* requirements, const char* resource_url, const char* resource_description, const char* error_text);
bool                x402_writePaymentRequirements (JsonBuf_t* json_buf, const X402Requirements_t* requirements);
bool                x402_writeSettlementResponse  (JsonBuf_t* json_buf, const char* network, const char* signature_text);
bool                x402_tryEncodeBase64          (const uint8_t* bytes, size_t byte_count, char* out, size_t out_size);
X402PaymentStatus_t x402_parsePaymentHeader       (const char* value, size_t value_len, const X402Requirements_t* requirements, X402Payment_t* payment_out);
X402PaymentStatus_t x402_parsePaymentJson         (const char* json, size_t json_len, const X402Requirements_t* requirements, X402Payment_t* payment_out);

#endif
