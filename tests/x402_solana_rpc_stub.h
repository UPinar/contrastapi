#ifndef X402_SOLANA_RPC_STUB_H
#define X402_SOLANA_RPC_STUB_H

#include <stddef.h>
#include <stdint.h>

#include "x402_solana.h"
#include "x402_solana_rpc.h"

#define X402_SOLANA_RPC_STUB_URL_BUF_SIZE 1024

extern X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_status;
extern int                            g_stub_X402_SOLANA_RPC_count;
extern char                           g_stub_X402_SOLANA_RPC_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE];
extern char                           g_stub_X402_SOLANA_RPC_last_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];

extern X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_find_status;
extern char                           g_stub_X402_SOLANA_RPC_find_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
extern int                            g_stub_X402_SOLANA_RPC_find_count;
extern char                           g_stub_X402_SOLANA_RPC_find_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE];
extern uint8_t                        g_stub_X402_SOLANA_RPC_find_last_source[X402_SOLANA_ADDRESS_BYTE_COUNT];
extern uint8_t                        g_stub_X402_SOLANA_RPC_find_last_tx[X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT];
extern size_t                         g_stub_X402_SOLANA_RPC_find_last_tx_len;
extern uint8_t                        g_stub_X402_SOLANA_RPC_find_last_fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT];

#endif
