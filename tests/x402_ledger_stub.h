#ifndef X402_LEDGER_STUB_H
#define X402_LEDGER_STUB_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "x402_ledger.h"
#include "x402_solana.h"

extern bool               g_stub_X402_LEDGER_is_hashed;
extern X402LedgerHashes_t g_stub_X402_LEDGER_hashes;
extern int                g_stub_X402_LEDGER_make_hashes_count;
extern const char*        g_stub_X402_LEDGER_last_secret;
extern X402SolanaCheck_t  g_stub_X402_LEDGER_last_check;

extern X402LedgerReservation_t g_stub_X402_LEDGER_reservation;
extern X402LedgerMarkStatus_t  g_stub_X402_LEDGER_mark_settled_status;
extern X402LedgerMarkStatus_t  g_stub_X402_LEDGER_mark_pending_status;
extern X402LedgerMarkStatus_t  g_stub_X402_LEDGER_release_status;

extern int                g_stub_X402_LEDGER_reserve_count;
extern int                g_stub_X402_LEDGER_mark_settled_count;
extern int                g_stub_X402_LEDGER_mark_pending_count;
extern int                g_stub_X402_LEDGER_release_count;
extern int                g_stub_X402_LEDGER_purge_count;
extern X402LedgerHashes_t g_stub_X402_LEDGER_last_reserve_hashes;
extern X402LedgerHashes_t g_stub_X402_LEDGER_last_mark_settled_hashes;
extern X402LedgerHashes_t g_stub_X402_LEDGER_last_mark_pending_hashes;
extern X402LedgerHashes_t g_stub_X402_LEDGER_last_release_hashes;
extern char               g_stub_X402_LEDGER_last_pending_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
extern PGconn*            g_stub_X402_LEDGER_last_conn;

extern void (*g_stub_X402_LEDGER_on_release)(void);

#endif
