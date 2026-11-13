#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "x402_ledger.h"
#include "x402_ledger_stub.h"

bool               g_stub_X402_LEDGER_is_hashed         = true;
X402LedgerHashes_t g_stub_X402_LEDGER_hashes            = { "", "" };
int                g_stub_X402_LEDGER_make_hashes_count = 0;
const char*        g_stub_X402_LEDGER_last_secret       = NULL;
X402SolanaCheck_t  g_stub_X402_LEDGER_last_check;

X402LedgerReservation_t g_stub_X402_LEDGER_reservation         = { X402_LEDGER_RESERVED, "" };
X402LedgerMarkStatus_t  g_stub_X402_LEDGER_mark_settled_status = X402_LEDGER_MARKED;
X402LedgerMarkStatus_t  g_stub_X402_LEDGER_mark_pending_status = X402_LEDGER_MARKED;
X402LedgerMarkStatus_t  g_stub_X402_LEDGER_release_status      = X402_LEDGER_MARKED;

int                g_stub_X402_LEDGER_reserve_count      = 0;
int                g_stub_X402_LEDGER_mark_settled_count = 0;
int                g_stub_X402_LEDGER_mark_pending_count = 0;
int                g_stub_X402_LEDGER_release_count      = 0;
int                g_stub_X402_LEDGER_purge_count        = 0;
X402LedgerHashes_t g_stub_X402_LEDGER_last_reserve_hashes;
X402LedgerHashes_t g_stub_X402_LEDGER_last_mark_settled_hashes;
X402LedgerHashes_t g_stub_X402_LEDGER_last_mark_pending_hashes;
X402LedgerHashes_t g_stub_X402_LEDGER_last_release_hashes;
void (*g_stub_X402_LEDGER_on_release)(void) = NULL;
char               g_stub_X402_LEDGER_last_pending_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE] = "";
PGconn*            g_stub_X402_LEDGER_last_conn = NULL;

bool x402_ledger_tryMakeHashes(const char* secret, const X402SolanaCheck_t* check, X402LedgerHashes_t* hashes_out)
{
  g_stub_X402_LEDGER_make_hashes_count++;
  g_stub_X402_LEDGER_last_secret = secret;
  g_stub_X402_LEDGER_last_check  = *check;

  hashes_out->ma_messageHash[0] = '\0';
  hashes_out->ma_sourceHash[0]  = '\0';
  if (!g_stub_X402_LEDGER_is_hashed)
    return false;
  *hashes_out = g_stub_X402_LEDGER_hashes;
  return true;
}

X402LedgerReservation_t x402_ledger_dbReserve(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  g_stub_X402_LEDGER_reserve_count++;
  g_stub_X402_LEDGER_last_conn           = conn;
  g_stub_X402_LEDGER_last_reserve_hashes = *hashes;
  return g_stub_X402_LEDGER_reservation;
}

X402LedgerMarkStatus_t x402_ledger_dbMarkSettled(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  g_stub_X402_LEDGER_mark_settled_count++;
  g_stub_X402_LEDGER_last_conn                = conn;
  g_stub_X402_LEDGER_last_mark_settled_hashes = *hashes;
  return g_stub_X402_LEDGER_mark_settled_status;
}

X402LedgerMarkStatus_t x402_ledger_dbMarkPending(PGconn* conn, const X402LedgerHashes_t* hashes, const char* signature_text)
{
  g_stub_X402_LEDGER_mark_pending_count++;
  g_stub_X402_LEDGER_last_conn                = conn;
  g_stub_X402_LEDGER_last_mark_pending_hashes = *hashes;
  snprintf(g_stub_X402_LEDGER_last_pending_signature, sizeof(g_stub_X402_LEDGER_last_pending_signature), "%s", signature_text);
  return g_stub_X402_LEDGER_mark_pending_status;
}

X402LedgerMarkStatus_t x402_ledger_dbRelease(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  g_stub_X402_LEDGER_release_count++;
  g_stub_X402_LEDGER_last_conn           = conn;
  g_stub_X402_LEDGER_last_release_hashes = *hashes;
  if (g_stub_X402_LEDGER_on_release != NULL)
    g_stub_X402_LEDGER_on_release();
  return g_stub_X402_LEDGER_release_status;
}

bool x402_ledger_dbPurgeExpiredRows(PGconn* conn)
{
  g_stub_X402_LEDGER_purge_count++;
  g_stub_X402_LEDGER_last_conn = conn;
  return true;
}
