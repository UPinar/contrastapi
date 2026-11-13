#include <stddef.h>

#include "x402_facilitator.h"
#include "x402_facilitator_stub.h"

X402FacilitatorVerifyStatus_t    g_stub_X402_FACILITATOR_verify_status    = X402_FACILITATOR_VERIFY_VALID;
X402FacilitatorSettlement_t      g_stub_X402_FACILITATOR_settlement       = { X402_FACILITATOR_SETTLE_PAID, false, "" };
X402FacilitatorSupportedStatus_t g_stub_X402_FACILITATOR_supported_status = X402_FACILITATOR_SUPPORTED_YES;

int                g_stub_X402_FACILITATOR_verify_count    = 0;
int                g_stub_X402_FACILITATOR_settle_count    = 0;
int                g_stub_X402_FACILITATOR_supported_count = 0;
X402Requirements_t g_stub_X402_FACILITATOR_last_verify_requirements;
X402Requirements_t g_stub_X402_FACILITATOR_last_settle_requirements;
X402Requirements_t g_stub_X402_FACILITATOR_last_supported_requirements;
size_t             g_stub_X402_FACILITATOR_last_verify_byte_count = 0;
size_t             g_stub_X402_FACILITATOR_last_settle_byte_count = 0;

X402FacilitatorVerifyStatus_t x402_facilitator_verify(const X402Requirements_t* requirements, const X402Payment_t* payment)
{
  g_stub_X402_FACILITATOR_verify_count++;
  g_stub_X402_FACILITATOR_last_verify_requirements = *requirements;
  g_stub_X402_FACILITATOR_last_verify_byte_count   = payment->m_transactionByteCount;
  return g_stub_X402_FACILITATOR_verify_status;
}

X402FacilitatorSettlement_t x402_facilitator_settle(const X402Requirements_t* requirements, const X402Payment_t* payment)
{
  g_stub_X402_FACILITATOR_settle_count++;
  g_stub_X402_FACILITATOR_last_settle_requirements = *requirements;
  g_stub_X402_FACILITATOR_last_settle_byte_count   = payment->m_transactionByteCount;
  return g_stub_X402_FACILITATOR_settlement;
}

X402FacilitatorSupportedStatus_t x402_facilitator_supported(const X402Requirements_t* requirements)
{
  g_stub_X402_FACILITATOR_supported_count++;
  g_stub_X402_FACILITATOR_last_supported_requirements = *requirements;
  return g_stub_X402_FACILITATOR_supported_status;
}
