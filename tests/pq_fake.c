#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "unity/unity.h"
#include "pq_fake.h"

#define PQFAKE_PARAM_LOG_MAX_LEN 64

int  g_pqfakeCallCount = 0;
char g_pqfakeCallLog[PQFAKE_CALL_LOG_BUF_SIZE];
char g_pqfakeLastCommand[PQFAKE_COMMAND_BUF_SIZE];
char g_pqfakeLastParamLog[PQFAKE_PARAM_LOG_BUF_SIZE];

static PqFakeAnswer_t g_queuedAnswers[PQFAKE_QUEUE_LEN];
static int            g_queuedAnswerCount = 0;

static FILE* g_stderrCaptureFile  = NULL;
static int   g_savedStderrFd      = -1;

static time_t g_fakeSecond = 0;

PGresult*      __wrap_PQexecParams(PGconn* conn, const char* command, int n_params, const Oid* param_types,
                                   const char* const* param_values, const int* param_lengths,
                                   const int* param_formats, int result_format);
ConnStatusType __wrap_PQstatus(const PGconn* conn);
time_t         __wrap_time(time_t* seconds_out);

void pqfake_reset(void)
{
  memset(g_queuedAnswers, 0, sizeof(g_queuedAnswers));
  g_queuedAnswerCount     = 0;
  g_pqfakeCallCount       = 0;
  g_pqfakeCallLog[0]      = '\0';
  g_pqfakeLastCommand[0]  = '\0';
  g_pqfakeLastParamLog[0] = '\0';
}

void pqfake_queue(const PqFakeAnswer_t* answer)
{
  assert(g_queuedAnswerCount < PQFAKE_QUEUE_LEN);
  assert(answer->m_columnCount <= PQFAKE_MAX_COLUMNS);
  g_queuedAnswers[g_queuedAnswerCount++] = *answer;
}

static void static_logCommand(const char* command)
{
  const char* name     = strstr(command, "api.");
  int         name_len = 0;
  if (name)
  {
    name    += strlen("api.");
    name_len = (int)strcspn(name, "(");
  }
  else
  {
    name     = command;
    name_len = (int)strcspn(command, " ");
  }
  size_t used = strlen(g_pqfakeCallLog);
  int written = snprintf(g_pqfakeCallLog + used, sizeof(g_pqfakeCallLog) - used, "%.*s ", name_len, name);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_pqfakeCallLog) - used);
  written = snprintf(g_pqfakeLastCommand, sizeof(g_pqfakeLastCommand), "%s", command);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_pqfakeLastCommand));
}

static void static_logParams(int n_params, const char* const* param_values)
{
  g_pqfakeLastParamLog[0] = '\0';
  for (int i = 0; i < n_params && param_values; i++)
  {
    size_t      used      = strlen(g_pqfakeLastParamLog);
    const char* separator = i > 0 ? "|" : "";
    const char* value     = param_values[i];
    int written;
    if (!value)
      written = snprintf(g_pqfakeLastParamLog + used, sizeof(g_pqfakeLastParamLog) - used, "%sNULL", separator);
    else if (strlen(value) > PQFAKE_PARAM_LOG_MAX_LEN)
      written = snprintf(g_pqfakeLastParamLog + used, sizeof(g_pqfakeLastParamLog) - used, "%s<%zu bytes>", separator, strlen(value));
    else
      written = snprintf(g_pqfakeLastParamLog + used, sizeof(g_pqfakeLastParamLog) - used, "%s%s", separator, value);
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_pqfakeLastParamLog) - used);
  }
}

static PGresult* static_nextAnswer(void)
{
  int call_index = g_pqfakeCallCount++;
  if (call_index >= g_queuedAnswerCount)
    return NULL;

  const PqFakeAnswer_t* answer = &g_queuedAnswers[call_index];
  PGresult* result = PQmakeEmptyPGresult(NULL, answer->m_status);
  TEST_ASSERT_NOT_NULL(result);
  if (answer->m_columnCount == 0)
    return result;

  PGresAttDesc columns[PQFAKE_MAX_COLUMNS];
  memset(columns, 0, sizeof(columns));
  for (int col = 0; col < answer->m_columnCount; col++)
    columns[col].name = (char*)(answer->ma_columnNames[col] ? answer->ma_columnNames[col] : "column");
  TEST_ASSERT_TRUE(PQsetResultAttrs(result, answer->m_columnCount, columns));
  for (int row = 0; row < answer->m_rowCount; row++)
  {
    for (int col = 0; col < answer->m_columnCount; col++)
    {
      const char* cell = answer->ma_cells[col];
      TEST_ASSERT_TRUE(PQsetvalue(result, row, col, (char*)cell, cell ? (int)strlen(cell) : -1));
    }
  }
  return result;
}

PGresult* __wrap_PQexecParams(PGconn* conn, const char* command, int n_params, const Oid* param_types,
                              const char* const* param_values, const int* param_lengths,
                              const int* param_formats, int result_format)
{
  (void)conn;
  (void)param_types;
  (void)param_lengths;
  (void)param_formats;
  (void)result_format;
  static_logCommand(command);
  static_logParams(n_params, param_values);
  return static_nextAnswer();
}

ConnStatusType __wrap_PQstatus(const PGconn* conn)
{
  (void)conn;
  return CONNECTION_OK;
}

time_t __wrap_time(time_t* seconds_out)
{
  g_fakeSecond++;
  if (seconds_out)
    *seconds_out = g_fakeSecond;
  return g_fakeSecond;
}

void pqfake_beginStderrCapture(void)
{
  g_stderrCaptureFile = tmpfile();
  TEST_ASSERT_NOT_NULL(g_stderrCaptureFile);
  fflush(stderr);
  g_savedStderrFd = dup(STDERR_FILENO);
  TEST_ASSERT_TRUE(g_savedStderrFd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(g_stderrCaptureFile), STDERR_FILENO) >= 0);
}

void pqfake_endStderrCapture(char* text, size_t text_size)
{
  assert(text_size > 0);
  assert(g_stderrCaptureFile != NULL);
  assert(g_savedStderrFd >= 0);
  fflush(stderr);
  TEST_ASSERT_TRUE(dup2(g_savedStderrFd, STDERR_FILENO) >= 0);
  close(g_savedStderrFd);
  g_savedStderrFd = -1;
  rewind(g_stderrCaptureFile);
  size_t length = fread(text, 1, text_size - 1, g_stderrCaptureFile);
  text[length] = '\0';
  fclose(g_stderrCaptureFile);
  g_stderrCaptureFile = NULL;
}
