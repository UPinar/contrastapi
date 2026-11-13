#ifndef X402_FACILITATOR_STUB_H
#define X402_FACILITATOR_STUB_H

#include <stddef.h>

#include "x402_facilitator.h"

extern X402FacilitatorVerifyStatus_t    g_stub_X402_FACILITATOR_verify_status;
extern X402FacilitatorSettlement_t      g_stub_X402_FACILITATOR_settlement;
extern X402FacilitatorSupportedStatus_t g_stub_X402_FACILITATOR_supported_status;

extern int                g_stub_X402_FACILITATOR_verify_count;
extern int                g_stub_X402_FACILITATOR_settle_count;
extern int                g_stub_X402_FACILITATOR_supported_count;
extern X402Requirements_t g_stub_X402_FACILITATOR_last_verify_requirements;
extern X402Requirements_t g_stub_X402_FACILITATOR_last_settle_requirements;
extern X402Requirements_t g_stub_X402_FACILITATOR_last_supported_requirements;
extern size_t             g_stub_X402_FACILITATOR_last_verify_byte_count;
extern size_t             g_stub_X402_FACILITATOR_last_settle_byte_count;

#endif
