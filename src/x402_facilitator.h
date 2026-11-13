#ifndef X402_FACILITATOR_H
#define X402_FACILITATOR_H

#include <stdbool.h>

#include "x402.h"
#include "x402_solana.h"

#define X402_FACILITATOR_SOCKET_PATH           "/run/contrastapi-x402/x402.sock"

#define X402_FACILITATOR_VERIFY_TIMEOUT_MS     5000
#define X402_FACILITATOR_SETTLE_TIMEOUT_MS     30000
#define X402_FACILITATOR_SUPPORTED_TIMEOUT_MS  2000

#define X402_FACILITATOR_MAX_ANSWER_BYTE_COUNT 16384

typedef enum {
  X402_FACILITATOR_VERIFY_VALID,
  X402_FACILITATOR_VERIFY_INVALID,
  X402_FACILITATOR_VERIFY_UNAVAILABLE
} X402FacilitatorVerifyStatus_t;

typedef enum {
  X402_FACILITATOR_SETTLE_PAID,
  X402_FACILITATOR_SETTLE_REFUSED,
  X402_FACILITATOR_SETTLE_PENDING
} X402FacilitatorSettleStatus_t;

typedef enum {
  X402_FACILITATOR_SUPPORTED_YES,
  X402_FACILITATOR_SUPPORTED_MISMATCH,
  X402_FACILITATOR_SUPPORTED_UNAVAILABLE
} X402FacilitatorSupportedStatus_t;

typedef struct {
  X402FacilitatorSettleStatus_t m_status;
  bool                          m_hasSignature;
  char                          ma_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
} X402FacilitatorSettlement_t;

X402FacilitatorVerifyStatus_t    x402_facilitator_verify    (const X402Requirements_t* requirements, const X402Payment_t* payment);
X402FacilitatorSettlement_t      x402_facilitator_settle    (const X402Requirements_t* requirements, const X402Payment_t* payment);
X402FacilitatorSupportedStatus_t x402_facilitator_supported (const X402Requirements_t* requirements);

#endif
