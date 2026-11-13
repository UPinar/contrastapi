#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_stub.h"
#include "x402.h"
#include "x402_facilitator.h"

static const int FUZZ_STATUSES[] = { 200, 400, 412, 500, 302, 404, 0 };

static X402Requirements_t static_requirements(void)
{
  X402Requirements_t requirements;
  memset(&requirements, 0, sizeof(requirements));
  snprintf(requirements.ma_network,  sizeof(requirements.ma_network),  "%s", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
  snprintf(requirements.ma_asset,    sizeof(requirements.ma_asset),    "%s", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  snprintf(requirements.ma_payTo,    sizeof(requirements.ma_payTo),    "%s", "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin");
  snprintf(requirements.ma_feePayer, sizeof(requirements.ma_feePayer), "%s", "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9");
  requirements.m_amountAtomic      = 10000;
  requirements.m_maxTimeoutSeconds = 60;
  return requirements;
}

static X402Payment_t static_payment(void)
{
  X402Payment_t payment;
  memset(&payment, 0, sizeof(payment));
  uint8_t* tx  = payment.ma_transaction;
  size_t   len = 0;
  tx[len++] = 1;
  len += 64;
  tx[len++] = 1;
  tx[len++] = 0;
  tx[len++] = 0;
  tx[len++] = 1;
  for (int i = 0; i < 64; i++)
    tx[len++] = (uint8_t)(0x11 + i * 13);
  tx[len++] = 0;
  payment.m_transactionByteCount = len;
  return payment;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size == 0)
    return 0;

  int status = FUZZ_STATUSES[data[0] % (sizeof(FUZZ_STATUSES) / sizeof(FUZZ_STATUSES[0]))];
  size_t body_len = size - 1;
  char*  body     = malloc(body_len + 1);
  if (body == NULL)
    abort();
  memcpy(body, data + 1, body_len);
  body[body_len] = '\0';

  g_stub_answers        = NULL;
  g_stub_next_body_null = false;
  g_stub_next_status    = status;
  g_stub_next_body      = body;
  g_stub_next_error     = HTTP_ERROR_NONE;
  if (status == 0)
    g_stub_next_error = HTTP_ERROR_CONNECT;
  else if (body_len > X402_FACILITATOR_MAX_ANSWER_BYTE_COUNT)
    g_stub_next_error = HTTP_ERROR_BODY_TOO_LARGE;

  X402Requirements_t requirements = static_requirements();
  X402Payment_t      payment      = static_payment();

  (void)x402_facilitator_verify(&requirements, &payment);
  X402FacilitatorSettlement_t settlement = x402_facilitator_settle(&requirements, &payment);
  if (settlement.m_status == X402_FACILITATOR_SETTLE_PAID || settlement.m_hasSignature)
    abort();
  if (strnlen(settlement.ma_signature, sizeof(settlement.ma_signature)) >= sizeof(settlement.ma_signature))
    abort();
  (void)x402_facilitator_supported(&requirements);

  g_stub_next_body = NULL;
  free(body);
  return 0;
}
