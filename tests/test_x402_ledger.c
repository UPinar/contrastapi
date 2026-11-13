#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "pq_fake.h"
#include "x402_ledger.h"

static const char* const TEST_SECRET = "x402-ledger-test-secret";

static const X402LedgerHashes_t TEST_HASHES = {
  "c5724af0c781d285cbd4c64ba0c33cbfa4b9e30256e3315602fb1ff047598735",
  "76e86a209a4d3b51e6047afca3da8fd20a2b713e11b5657759fd3e16b9554d3f",
};

#define TEST_SENT_HASHES "c5724af0c781d285cbd4c64ba0c33cbfa4b9e30256e3315602fb1ff047598735|" \
                         "76e86a209a4d3b51e6047afca3da8fd20a2b713e11b5657759fd3e16b9554d3f"

#define TEST_MESSAGE_HASH "c5724af0c781d285cbd4c64ba0c33cbfa4b9e30256e3315602fb1ff047598735"

void setUp(void)
{
  pqfake_reset();
}

void tearDown(void) {}

static X402SolanaCheck_t static_makeCheck(unsigned char message_first, unsigned char source_first)
{
  X402SolanaCheck_t check;
  for (int i = 0; i < X402_SOLANA_MESSAGE_HASH_BYTE_COUNT; i++)
    check.ma_messageHash[i] = (uint8_t)(message_first + i);
  for (int i = 0; i < X402_SOLANA_ADDRESS_BYTE_COUNT; i++)
    check.ma_source[i] = (uint8_t)(source_first + i);
  return check;
}

static void static_queueReserveRow(const char* reserve_answer, const char* signature)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 2, 1, { "reserve_answer", "signature" }, { reserve_answer, signature } };
  pqfake_queue(&answer);
}

static void static_queueFlagRow(const char* column_name, const char* flag)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 1, { column_name }, { flag } };
  pqfake_queue(&answer);
}

static X402LedgerMarkStatus_t static_markPendingWithNoSignature(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  return x402_ledger_dbMarkPending(conn, hashes, "");
}

static X402LedgerMarkStatus_t static_markSettled(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  return x402_ledger_dbMarkSettled(conn, hashes);
}

static X402LedgerMarkStatus_t static_release(PGconn* conn, const X402LedgerHashes_t* hashes)
{
  return x402_ledger_dbRelease(conn, hashes);
}

typedef struct {
  X402LedgerMarkStatus_t (*mp_call)(PGconn* conn, const X402LedgerHashes_t* hashes);
  const char*            mp_columnName;
  const char*            mp_functionName;
} TestMarkCall_t;

static const TestMarkCall_t TEST_MARK_CALLS[] = {
  { static_markSettled,                 "is_marked",   "x402_ledger_dbMarkSettled" },
  { static_markPendingWithNoSignature,  "is_marked",   "x402_ledger_dbMarkPending" },
  { static_release,                     "is_released", "x402_ledger_dbRelease"     },
};
#define TEST_MARK_CALL_COUNT ((int)(sizeof(TEST_MARK_CALLS) / sizeof(TEST_MARK_CALLS[0])))

void test_make_hashes_answers_the_known_hmac_of_each_prefix(void)
{
  X402SolanaCheck_t check = static_makeCheck(0x10, 0xa0);
  X402LedgerHashes_t  hashes;
  memset(&hashes, 'x', sizeof(hashes));

  TEST_ASSERT_TRUE(x402_ledger_tryMakeHashes(TEST_SECRET, &check, &hashes));
  TEST_ASSERT_EQUAL_STRING(TEST_HASHES.ma_messageHash, hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING(TEST_HASHES.ma_sourceHash, hashes.ma_sourceHash);
}

void test_make_hashes_keeps_the_message_and_source_hashes_apart_for_the_same_bytes(void)
{
  X402SolanaCheck_t check = static_makeCheck(0x10, 0x10);
  X402LedgerHashes_t  hashes;

  TEST_ASSERT_TRUE(x402_ledger_tryMakeHashes(TEST_SECRET, &check, &hashes));
  TEST_ASSERT_EQUAL_STRING(TEST_HASHES.ma_messageHash, hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING("39d332dfa26a6b2f4b70fd9a03d83a9e7fc3aeb7ab9b0d4acc7ac02c5c98dc01", hashes.ma_sourceHash);
}

void test_make_hashes_depends_on_the_secret(void)
{
  X402SolanaCheck_t check = static_makeCheck(0x10, 0xa0);
  X402LedgerHashes_t  hashes;

  TEST_ASSERT_TRUE(x402_ledger_tryMakeHashes("x402-ledger-other-secret", &check, &hashes));
  TEST_ASSERT_EQUAL_STRING("558347a9f74b0918a00207e72f250987339fbf58c284fc4a0447874fdb95457a", hashes.ma_messageHash);
}

void test_make_hashes_refuses_a_null_or_empty_secret(void)
{
  X402SolanaCheck_t check = static_makeCheck(0x10, 0xa0);
  X402LedgerHashes_t  hashes;

  memset(&hashes, 'x', sizeof(hashes));
  TEST_ASSERT_FALSE(x402_ledger_tryMakeHashes(NULL, &check, &hashes));
  TEST_ASSERT_EQUAL_STRING("", hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING("", hashes.ma_sourceHash);

  memset(&hashes, 'x', sizeof(hashes));
  TEST_ASSERT_FALSE(x402_ledger_tryMakeHashes("", &check, &hashes));
  TEST_ASSERT_EQUAL_STRING("", hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING("", hashes.ma_sourceHash);
}

void test_make_hashes_writes_64_lowercase_hex_digits_and_a_nul(void)
{
  X402SolanaCheck_t check = static_makeCheck(0xf0, 0x7f);
  X402LedgerHashes_t  hashes;
  memset(&hashes, 'x', sizeof(hashes));

  TEST_ASSERT_TRUE(x402_ledger_tryMakeHashes(TEST_SECRET, &check, &hashes));
  TEST_ASSERT_EQUAL_INT(64, X402_LEDGER_HASH_TEXT_LEN);
  const char* const texts[] = { hashes.ma_messageHash, hashes.ma_sourceHash };
  for (int t = 0; t < 2; t++)
  {
    for (int i = 0; i < X402_LEDGER_HASH_TEXT_LEN; i++)
      TEST_ASSERT_TRUE(isdigit((unsigned char)texts[t][i]) || (texts[t][i] >= 'a' && texts[t][i] <= 'f'));
    TEST_ASSERT_EQUAL_CHAR('\0', texts[t][X402_LEDGER_HASH_TEXT_LEN]);
  }
}

void test_reserve_sends_the_two_hashes_in_order_and_answers_reserved(void)
{
  static_queueReserveRow("reserved", NULL);

  X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_RESERVED, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING("", reservation.ma_signature);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_x402_payment_reserve($1, $2)", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(TEST_SENT_HASHES, g_pqfakeLastParamLog);
}

void test_reserve_maps_each_answer_to_its_status(void)
{
  static const char* const answers[] = { "reserved", "in_flight", "settled", "pending", "source_busy" };
  static const X402LedgerReserveStatus_t statuses[] = {
    X402_LEDGER_RESERVED, X402_LEDGER_IN_FLIGHT, X402_LEDGER_SETTLED, X402_LEDGER_PENDING, X402_LEDGER_SOURCE_BUSY,
  };
  for (int i = 0; i < 5; i++)
    static_queueReserveRow(answers[i], NULL);

  for (int i = 0; i < 5; i++)
  {
    X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
    TEST_ASSERT_EQUAL_INT_MESSAGE(statuses[i], reservation.m_status, answers[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", reservation.ma_signature, answers[i]);
  }
}

void test_reserve_copies_the_signature_of_a_pending_payment(void)
{
  static const char* const signature = "5VERYsig2nature3Base58Text4Kc";
  static_queueReserveRow("pending", signature);

  X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_PENDING, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING(signature, reservation.ma_signature);
}

void test_reserve_answers_an_empty_signature_for_a_pending_payment_with_none(void)
{
  static_queueReserveRow("pending", NULL);

  X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_PENDING, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING("", reservation.ma_signature);
}

void test_reserve_fails_for_a_signature_beside_another_answer(void)
{
  static const char* const answers[] = { "reserved", "in_flight", "settled", "source_busy" };
  for (int i = 0; i < 4; i++)
    static_queueReserveRow(answers[i], "5VERYsig2nature3Base58Text4Kc");

  for (int i = 0; i < 4; i++)
  {
    X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_LEDGER_ERROR, reservation.m_status, answers[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", reservation.ma_signature, answers[i]);
  }
}

void test_reserve_fails_for_an_unknown_answer(void)
{
  static const char* const answers[] = { "Reserved", "reserve", "", NULL, "reserved ", "source_busy_", "reservedreservedx" };
  for (int i = 0; i < 7; i++)
    static_queueReserveRow(answers[i], NULL);

  for (int i = 0; i < 7; i++)
    TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES).m_status);
  TEST_ASSERT_EQUAL_INT(7, g_pqfakeCallCount);
}

void test_reserve_fails_for_another_column_list(void)
{
  PqFakeAnswer_t other_name = { PGRES_TUPLES_OK, 2, 1, { "reserve_status", "signature" }, { "reserved", NULL } };
  PqFakeAnswer_t swapped    = { PGRES_TUPLES_OK, 2, 1, { "signature", "reserve_answer" }, { "reserved", NULL } };
  PqFakeAnswer_t one_column = { PGRES_TUPLES_OK, 1, 1, { "reserve_answer" }, { "reserved" } };
  PqFakeAnswer_t three      = { PGRES_TUPLES_OK, 3, 1, { "reserve_answer", "signature", "source_hash" }, { "reserved", NULL, NULL } };
  pqfake_queue(&other_name);
  pqfake_queue(&swapped);
  pqfake_queue(&one_column);
  pqfake_queue(&three);

  for (int i = 0; i < 4; i++)
    TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES).m_status);
  TEST_ASSERT_EQUAL_INT(4, g_pqfakeCallCount);
}

void test_reserve_fails_for_no_row_and_for_two_rows(void)
{
  PqFakeAnswer_t no_row   = { PGRES_TUPLES_OK, 2, 0, { "reserve_answer", "signature" }, { NULL } };
  PqFakeAnswer_t two_rows = { PGRES_TUPLES_OK, 2, 2, { "reserve_answer", "signature" }, { "reserved", NULL } };
  pqfake_queue(&no_row);
  pqfake_queue(&two_rows);

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES).m_status);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES).m_status);
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_reserve_fails_when_the_query_fails(void)
{
  X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING("", reservation.ma_signature);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_reserve_accepts_a_signature_of_88_characters_and_refuses_89(void)
{
  char signature_88[89];
  char signature_89[90];
  memset(signature_88, '5', 88);
  signature_88[88] = '\0';
  memset(signature_89, '6', 89);
  signature_89[89] = '\0';
  static_queueReserveRow("pending", signature_88);
  static_queueReserveRow("pending", signature_89);

  X402LedgerReservation_t reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_PENDING, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING(signature_88, reservation.ma_signature);

  reservation = x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES);
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING("", reservation.ma_signature);
}

void test_reserve_fails_for_an_empty_signature_of_a_pending_payment(void)
{
  static_queueReserveRow("pending", "");

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, x402_ledger_dbReserve(PQFAKE_CONN, &TEST_HASHES).m_status);
}

void test_reserve_fails_for_a_null_connection(void)
{
  static_queueReserveRow("reserved", NULL);
  char text[256];

  pqfake_beginStderrCapture();
  X402LedgerReservation_t reservation = x402_ledger_dbReserve(NULL, &TEST_HASHES);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_ERROR, reservation.m_status);
  TEST_ASSERT_EQUAL_STRING("", reservation.ma_signature);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("x402_ledger_dbReserve: no database connection\n", text);
}

void test_mark_settled_sends_the_message_hash_only(void)
{
  static_queueFlagRow("is_marked", "t");

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARKED, x402_ledger_dbMarkSettled(PQFAKE_CONN, &TEST_HASHES));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_x402_payment_mark_settled($1) AS is_marked", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(TEST_MESSAGE_HASH, g_pqfakeLastParamLog);
}

void test_release_sends_the_message_hash_only(void)
{
  static_queueFlagRow("is_released", "t");

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARKED, x402_ledger_dbRelease(PQFAKE_CONN, &TEST_HASHES));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_x402_payment_release($1) AS is_released", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(TEST_MESSAGE_HASH, g_pqfakeLastParamLog);
}

void test_mark_pending_sends_the_message_hash_and_the_signature(void)
{
  static_queueFlagRow("is_marked", "t");

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARKED, x402_ledger_dbMarkPending(PQFAKE_CONN, &TEST_HASHES, "5VERYsig2nature3Base58Text4Kc"));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_x402_payment_mark_pending($1, $2) AS is_marked", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(TEST_MESSAGE_HASH "|5VERYsig2nature3Base58Text4Kc", g_pqfakeLastParamLog);
}

void test_mark_pending_sends_an_empty_signature_as_null(void)
{
  static_queueFlagRow("is_marked", "t");

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARKED, x402_ledger_dbMarkPending(PQFAKE_CONN, &TEST_HASHES, ""));
  TEST_ASSERT_EQUAL_STRING(TEST_MESSAGE_HASH "|NULL", g_pqfakeLastParamLog);
}

void test_mark_pending_refuses_a_signature_past_88_characters_before_any_query(void)
{
  static_queueFlagRow("is_marked", "t");
  static_queueFlagRow("is_marked", "t");
  char signature[90];
  memset(signature, '7', 89);
  signature[88] = '\0';

  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARKED, x402_ledger_dbMarkPending(PQFAKE_CONN, &TEST_HASHES, signature));
  TEST_ASSERT_EQUAL_STRING(TEST_MESSAGE_HASH "|<88 bytes>", g_pqfakeLastParamLog);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);

  signature[88] = '7';
  signature[89] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_LEDGER_MARK_ERROR, x402_ledger_dbMarkPending(PQFAKE_CONN, &TEST_HASHES, signature));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_each_mark_answers_marked_for_true_and_not_marked_for_false(void)
{
  for (int c = 0; c < TEST_MARK_CALL_COUNT; c++)
  {
    const TestMarkCall_t* call = &TEST_MARK_CALLS[c];
    pqfake_reset();
    static_queueFlagRow(call->mp_columnName, "t");
    static_queueFlagRow(call->mp_columnName, "f");

    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_LEDGER_MARKED, call->mp_call(PQFAKE_CONN, &TEST_HASHES), call->mp_functionName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_LEDGER_NOT_MARKED, call->mp_call(PQFAKE_CONN, &TEST_HASHES), call->mp_functionName);
  }
}

void test_each_mark_fails_for_any_other_answer(void)
{
  for (int c = 0; c < TEST_MARK_CALL_COUNT; c++)
  {
    const TestMarkCall_t* call = &TEST_MARK_CALLS[c];
    const char* other_column = strcmp(call->mp_columnName, "is_marked") == 0 ? "is_released" : "is_marked";
    PqFakeAnswer_t no_row   = { PGRES_TUPLES_OK, 1, 0, { call->mp_columnName }, { NULL } };
    PqFakeAnswer_t two_rows = { PGRES_TUPLES_OK, 1, 2, { call->mp_columnName }, { "t" } };
    pqfake_reset();
    static_queueFlagRow(call->mp_columnName, "true");
    static_queueFlagRow(call->mp_columnName, NULL);
    static_queueFlagRow(other_column, "t");
    pqfake_queue(&no_row);
    pqfake_queue(&two_rows);

    for (int i = 0; i < 6; i++)
      TEST_ASSERT_EQUAL_INT_MESSAGE(X402_LEDGER_MARK_ERROR, call->mp_call(PQFAKE_CONN, &TEST_HASHES), call->mp_functionName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(6, g_pqfakeCallCount, call->mp_functionName);
  }
}

void test_each_mark_fails_for_a_null_connection(void)
{
  for (int c = 0; c < TEST_MARK_CALL_COUNT; c++)
  {
    const TestMarkCall_t* call = &TEST_MARK_CALLS[c];
    pqfake_reset();
    static_queueFlagRow(call->mp_columnName, "t");
    char text[256];
    char expected[256];
    snprintf(expected, sizeof(expected), "%s: no database connection\n", call->mp_functionName);

    pqfake_beginStderrCapture();
    X402LedgerMarkStatus_t status = call->mp_call(NULL, &TEST_HASHES);
    pqfake_endStderrCapture(text, sizeof(text));

    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_LEDGER_MARK_ERROR, status, call->mp_functionName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_pqfakeCallCount, call->mp_functionName);
    TEST_ASSERT_EQUAL_STRING(expected, text);
  }
}

void test_purge_sends_the_batch_and_fails_when_the_query_fails(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "3" } };
  pqfake_queue(&answer);

  TEST_ASSERT_TRUE(x402_ledger_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_x402_payment_purge($1) AS purged_row_count", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("10000", g_pqfakeLastParamLog);
  TEST_ASSERT_FALSE(x402_ledger_dbPurgeExpiredRows(PQFAKE_CONN));
}

void test_purge_runs_again_after_a_full_batch(void)
{
  PqFakeAnswer_t full  = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "10000" } };
  PqFakeAnswer_t empty = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "0" } };
  pqfake_queue(&full);
  pqfake_queue(&empty);

  TEST_ASSERT_TRUE(x402_ledger_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_x402_payment_purge fn_x402_payment_purge ", g_pqfakeCallLog);
}

void test_failed_purge_names_the_purge_function(void)
{
  char text[512];

  pqfake_beginStderrCapture();
  bool is_purged = x402_ledger_dbPurgeExpiredRows(PQFAKE_CONN);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_purged);
  TEST_ASSERT_EQUAL_STRING("dbhelper_executeQueryFrom: x402_ledger_dbPurgeExpiredRows: query failed "
                           "(status no result, sqlstate none, connection ok)\n", text);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(29, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_make_hashes_answers_the_known_hmac_of_each_prefix);
  RUN_TEST(test_make_hashes_keeps_the_message_and_source_hashes_apart_for_the_same_bytes);
  RUN_TEST(test_make_hashes_depends_on_the_secret);
  RUN_TEST(test_make_hashes_refuses_a_null_or_empty_secret);
  RUN_TEST(test_make_hashes_writes_64_lowercase_hex_digits_and_a_nul);
  RUN_TEST(test_reserve_sends_the_two_hashes_in_order_and_answers_reserved);
  RUN_TEST(test_reserve_maps_each_answer_to_its_status);
  RUN_TEST(test_reserve_copies_the_signature_of_a_pending_payment);
  RUN_TEST(test_reserve_answers_an_empty_signature_for_a_pending_payment_with_none);
  RUN_TEST(test_reserve_fails_for_a_signature_beside_another_answer);
  RUN_TEST(test_reserve_fails_for_an_unknown_answer);
  RUN_TEST(test_reserve_fails_for_another_column_list);
  RUN_TEST(test_reserve_fails_for_no_row_and_for_two_rows);
  RUN_TEST(test_reserve_fails_when_the_query_fails);
  RUN_TEST(test_reserve_accepts_a_signature_of_88_characters_and_refuses_89);
  RUN_TEST(test_reserve_fails_for_an_empty_signature_of_a_pending_payment);
  RUN_TEST(test_reserve_fails_for_a_null_connection);
  RUN_TEST(test_mark_settled_sends_the_message_hash_only);
  RUN_TEST(test_release_sends_the_message_hash_only);
  RUN_TEST(test_mark_pending_sends_the_message_hash_and_the_signature);
  RUN_TEST(test_mark_pending_sends_an_empty_signature_as_null);
  RUN_TEST(test_mark_pending_refuses_a_signature_past_88_characters_before_any_query);
  RUN_TEST(test_each_mark_answers_marked_for_true_and_not_marked_for_false);
  RUN_TEST(test_each_mark_fails_for_any_other_answer);
  RUN_TEST(test_each_mark_fails_for_a_null_connection);
  RUN_TEST(test_purge_sends_the_batch_and_fails_when_the_query_fails);
  RUN_TEST(test_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_failed_purge_names_the_purge_function);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
