#ifndef X402_SOLANA_RPC_STUB_H
#define X402_SOLANA_RPC_STUB_H

#include "x402_solana.h"
#include "x402_solana_rpc.h"

#define X402_SOLANA_RPC_STUB_URL_BUF_SIZE 1024

extern X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_status;
extern int                            g_stub_X402_SOLANA_RPC_count;
extern char                           g_stub_X402_SOLANA_RPC_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE];
extern char                           g_stub_X402_SOLANA_RPC_last_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];

#endif
