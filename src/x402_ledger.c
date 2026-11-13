#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "bytes.h"
#include "dbhelper.h"
#include "x402_ledger.h"

_Static_assert(X402_LEDGER_HASH_TEXT_LEN == 2 * SHA256_DIGEST_LENGTH,
               "X402_LEDGER_HASH_TEXT_LEN must hold the hex of one SHA-256 digest");
_Static_assert(X402_SOLANA_MESSAGE_HASH_BYTE_COUNT == X402_SOLANA_ADDRESS_BYTE_COUNT,
               "static_tryWriteHash takes 32 bytes for both hashes");

#define X402_LEDGER_MESSAGE_HASH_PREFIX     "x402-message:"
#define X402_LEDGER_SOURCE_HASH_PREFIX      "x402-source:"

#define X402_LEDGER_HASH_INPUT_BUF_SIZE     (sizeof(X402_LEDGER_MESSAGE_HASH_PREFIX) - 1 + X402_SOLANA_ADDRESS_BYTE_COUNT)

#define X402_LEDGER_RESERVE_ANSWER_MAX_LEN 15

#define X402_LEDGER_RESERVE_COLUMNS(X)                                  \
  X(X402_LEDGER_RESERVE_COLUMN_RESERVE_ANSWER, "reserve_answer")        \
  X(X402_LEDGER_RESERVE_COLUMN_SIGNATURE,      "signature")
enum { X402_LEDGER_RESERVE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const X402_LEDGER_RESERVE_COLUMN_NAMES[] = { X402_LEDGER_RESERVE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define X402_LEDGER_MARK_COLUMNS(X)                       \
  X(X402_LEDGER_MARK_COLUMN_IS_MARKED, "is_marked")
enum { X402_LEDGER_MARK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const X402_LEDGER_MARK_COLUMN_NAMES[] = { X402_LEDGER_MARK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define X402_LEDGER_RELEASE_COLUMNS(X)                          \
  X(X402_LEDGER_RELEASE_COLUMN_IS_RELEASED, "is_released")
enum { X402_LEDGER_RELEASE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const X402_LEDGER_RELEASE_COLUMN_NAMES[] = { X402_LEDGER_RELEASE_COLUMNS(DBHELPER_COLUMN_NAME) };

typedef struct {
  const char*               mp_answerText;
  X402LedgerReserveStatus_t m_status;
} X402LedgerReserveAnswer_t;

static const X402LedgerReserveAnswer_t X402_LEDGER_RESERVE_ANSWERS[] = {
  { "reserved",    X402_LEDGER_RESERVED    },
  { "in_flight",   X402_LEDGER_IN_FLIGHT   },
  { "settled",     X402_LEDGER_SETTLED     },
  { "pending",     X402_LEDGER_PENDING     },
  { "source_busy", X402_LEDGER_SOURCE_BUSY },
};

static bool                      static_tryWriteHash      (const char* secret, const char* prefix, const uint8_t bytes[X402_SOLANA_ADDRESS_BYTE_COUNT], char* hex_out);
static X402LedgerReserveStatus_t static_findReserveStatus (const char* answer_text);
static X402LedgerMarkStatus_t    static_findMarkStatus    (bool is_read, bool is_changed);

bool x402_ledger_tryMakeHashes(const char* secret, const X402SolanaCheck_t* check, X402LedgerHashes_t* hashes_out)
{
  assert(check      != NULL);
  assert(hashes_out != NULL);

  hashes_out->ma_messageHash[0] = '\0';
  hashes_out->ma_sourceHash[0]  = '\0';
  if (!secret || *secret == '\0')
  {
    fprintf(stderr, "x402_ledger_tryMakeHashes: no secret\n");
    return false;
  }

  if (!static_tryWriteHash(secret, X402_LEDGER_MESSAGE_HASH_PREFIX, check->ma_messageHash, hashes_out->ma_messageHash) ||
      !static_tryWriteHash(secret, X402_LEDGER_SOURCE_HASH_PREFIX, check->ma_source, hashes_out->ma_sourceHash))
  {
    hashes_out->ma_messageHash[0] = '\0';
    hashes_out->ma_sourceHash[0]  = '\0';
    return false;
  }
  return true;
}

X402LedgerReservation_t x402_ledger_dbReserve(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  assert(hashes != NULL);

  X402LedgerReservation_t reservation = { X402_LEDGER_ERROR, "" };
  if (!conn)
  {
    fprintf(stderr, "x402_ledger_dbReserve: no database connection\n");
    return reservation;
  }

  const char* param_values[] = { hashes->ma_messageHash, hashes->ma_sourceHash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_x402_payment_reserve($1, $2)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return reservation;

  char answer_text[X402_LEDGER_RESERVE_ANSWER_MAX_LEN + 1];
  bool is_read       = PQntuples(res) == 1                                                                                                       
                       && dbhelper_isColumnListEqual(res, X402_LEDGER_RESERVE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(X402_LEDGER_RESERVE_COLUMN_NAMES))
                       && dbhelper_fetchColStr(res, 0, X402_LEDGER_RESERVE_COLUMN_RESERVE_ANSWER, answer_text, sizeof(answer_text) - 1)
                       && dbhelper_fetchColStr(res, 0, X402_LEDGER_RESERVE_COLUMN_SIGNATURE, reservation.ma_signature, sizeof(reservation.ma_signature) - 1);
  bool has_signature = is_read && !PQgetisnull(res, 0, X402_LEDGER_RESERVE_COLUMN_SIGNATURE);
  PQclear(res);

  X402LedgerReserveStatus_t status = is_read ? static_findReserveStatus(answer_text) : X402_LEDGER_ERROR;
  bool is_signature_valid = !has_signature || (status == X402_LEDGER_PENDING && reservation.ma_signature[0] != '\0');
  if (status == X402_LEDGER_ERROR || !is_signature_valid)
  {
    reservation.ma_signature[0] = '\0';
    return reservation;
  }

  reservation.m_status = status;
  return reservation;
}

X402LedgerMarkStatus_t x402_ledger_dbMarkSettled(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  assert(hashes != NULL);

  if (!conn)
  {
    fprintf(stderr, "x402_ledger_dbMarkSettled: no database connection\n");
    return X402_LEDGER_MARK_ERROR;
  }

  const char* param_values[] = { hashes->ma_messageHash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_x402_payment_mark_settled($1) AS is_marked",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return X402_LEDGER_MARK_ERROR;

  bool is_marked = false;
  bool is_read   = PQntuples(res) == 1                                                                                            
                   && dbhelper_isColumnListEqual(res, X402_LEDGER_MARK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(X402_LEDGER_MARK_COLUMN_NAMES))
                   && dbhelper_fetchColBool(res, 0, X402_LEDGER_MARK_COLUMN_IS_MARKED, &is_marked);
  PQclear(res);
  return static_findMarkStatus(is_read, is_marked);
}

X402LedgerMarkStatus_t x402_ledger_dbMarkPending(PGconn* conn, const X402LedgerHashes_t* hashes, const char* signature_text)
{
  assert(hashes         != NULL);
  assert(signature_text != NULL);

  if (!conn)
  {
    fprintf(stderr, "x402_ledger_dbMarkPending: no database connection\n");
    return X402_LEDGER_MARK_ERROR;
  }
  if (strlen(signature_text) > X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE - 1)
  {
    fprintf(stderr, "x402_ledger_dbMarkPending: signature_text is longer than %d characters\n",
            X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE - 1);
    return X402_LEDGER_MARK_ERROR;
  }

  const char* param_values[] = { hashes->ma_messageHash, dbhelper_textOrNull(signature_text) };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_x402_payment_mark_pending($1, $2) AS is_marked",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return X402_LEDGER_MARK_ERROR;

  bool is_marked = false;
  bool is_read   = PQntuples(res) == 1                                                                                               
                   && dbhelper_isColumnListEqual(res, X402_LEDGER_MARK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(X402_LEDGER_MARK_COLUMN_NAMES))
                   && dbhelper_fetchColBool(res, 0, X402_LEDGER_MARK_COLUMN_IS_MARKED, &is_marked);
  PQclear(res);
  return static_findMarkStatus(is_read, is_marked);
}

X402LedgerMarkStatus_t x402_ledger_dbRelease(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  assert(hashes != NULL);

  if (!conn)
  {
    fprintf(stderr, "x402_ledger_dbRelease: no database connection\n");
    return X402_LEDGER_MARK_ERROR;
  }

  const char* param_values[] = { hashes->ma_messageHash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_x402_payment_release($1) AS is_released",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return X402_LEDGER_MARK_ERROR;

  bool is_released = false;
  bool is_read     = PQntuples(res) == 1                                                                                                 
                     && dbhelper_isColumnListEqual(res, X402_LEDGER_RELEASE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(X402_LEDGER_RELEASE_COLUMN_NAMES))
                     && dbhelper_fetchColBool(res, 0, X402_LEDGER_RELEASE_COLUMN_IS_RELEASED, &is_released);
  PQclear(res);
  return static_findMarkStatus(is_read, is_released);
}

bool x402_ledger_dbPurgeExpiredRows(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_x402_payment_purge($1) AS purged_row_count",
                               "purged_row_count",
                               X402_LEDGER_PURGE_BATCH_ROW_COUNT);
}

static bool static_tryWriteHash(const char* secret, const char* prefix, const uint8_t bytes[X402_SOLANA_ADDRESS_BYTE_COUNT], char* hex_out)
{
  assert(secret  != NULL);
  assert(prefix  != NULL);
  assert(bytes   != NULL);
  assert(hex_out != NULL);

  size_t secret_len = strlen(secret);
  size_t prefix_len = strlen(prefix);
  assert(prefix_len + X402_SOLANA_ADDRESS_BYTE_COUNT <= X402_LEDGER_HASH_INPUT_BUF_SIZE);
  if (secret_len > INT_MAX)
  {
    fprintf(stderr, "static_tryWriteHash: secret is too long\n");
    return false;
  }

  unsigned char input[X402_LEDGER_HASH_INPUT_BUF_SIZE];
  memcpy(input, prefix, prefix_len);
  memcpy(input + prefix_len, bytes, X402_SOLANA_ADDRESS_BYTE_COUNT);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int  digest_len = 0;
  if (!HMAC(EVP_sha256(), secret, (int)secret_len, input, prefix_len + X402_SOLANA_ADDRESS_BYTE_COUNT, digest, &digest_len) ||
      digest_len != SHA256_DIGEST_LENGTH)
  {
    fprintf(stderr, "static_tryWriteHash: HMAC failed\n");
    return false;
  }
  bytes_writeHex(digest, SHA256_DIGEST_LENGTH, hex_out);
  return true;
}

static X402LedgerReserveStatus_t static_findReserveStatus(const char* answer_text)
{
  assert(answer_text != NULL);

  for (size_t i = 0; i < sizeof(X402_LEDGER_RESERVE_ANSWERS) / sizeof(X402_LEDGER_RESERVE_ANSWERS[0]); i++)
  {
    if (strcmp(answer_text, X402_LEDGER_RESERVE_ANSWERS[i].mp_answerText) == 0)
      return X402_LEDGER_RESERVE_ANSWERS[i].m_status;
  }
  fprintf(stderr, "static_findReserveStatus: unknown reserve_answer\n");
  return X402_LEDGER_ERROR;
}

static X402LedgerMarkStatus_t static_findMarkStatus(bool is_read, bool is_changed)
{
  if (!is_read)
    return X402_LEDGER_MARK_ERROR;
  return is_changed ? X402_LEDGER_MARKED : X402_LEDGER_NOT_MARKED;
}
