#ifndef X402_LEDGER_H
#define X402_LEDGER_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "x402_solana.h"

#define X402_LEDGER_HASH_TEXT_LEN          64

#define X402_LEDGER_PURGE_BATCH_ROW_COUNT  10000

typedef struct {
  char ma_messageHash[X402_LEDGER_HASH_TEXT_LEN + 1];
  char ma_sourceHash[X402_LEDGER_HASH_TEXT_LEN + 1];
} X402LedgerHashes_t;

typedef enum {
  X402_LEDGER_RESERVED,
  X402_LEDGER_IN_FLIGHT,
  X402_LEDGER_SETTLED,
  X402_LEDGER_PENDING,
  X402_LEDGER_SOURCE_BUSY,
  X402_LEDGER_ERROR
} X402LedgerReserveStatus_t;

typedef struct {
  X402LedgerReserveStatus_t m_status;
  char                      ma_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
} X402LedgerReservation_t;

typedef enum {
  X402_LEDGER_MARKED,
  X402_LEDGER_NOT_MARKED,
  X402_LEDGER_MARK_ERROR
} X402LedgerMarkStatus_t;

bool                    x402_ledger_tryMakeHashes      (const char* secret, const X402SolanaCheck_t* check, X402LedgerHashes_t* hashes_out);
X402LedgerReservation_t x402_ledger_dbReserve          (PGconn* conn, const X402LedgerHashes_t* hashes);
X402LedgerMarkStatus_t  x402_ledger_dbMarkSettled      (PGconn* conn, const X402LedgerHashes_t* hashes);
X402LedgerMarkStatus_t  x402_ledger_dbMarkPending      (PGconn* conn, const X402LedgerHashes_t* hashes, const char* signature_text);
X402LedgerMarkStatus_t  x402_ledger_dbRelease          (PGconn* conn, const X402LedgerHashes_t* hashes);

bool                    x402_ledger_dbPurgeExpiredRows (PGconn* conn);

#endif
