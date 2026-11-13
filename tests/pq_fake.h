#ifndef PQ_FAKE_H
#define PQ_FAKE_H

#include <stddef.h>
#include <libpq-fe.h>

#define PQFAKE_CONN ((PGconn*)1)

#define PQFAKE_MAX_COLUMNS        3
#define PQFAKE_QUEUE_LEN          8
#define PQFAKE_PARAM_LOG_BUF_SIZE 512
#define PQFAKE_CALL_LOG_BUF_SIZE  256
#define PQFAKE_COMMAND_BUF_SIZE   256

typedef struct
{
  ExecStatusType m_status;
  int            m_columnCount;
  int            m_rowCount;
  const char*    ma_columnNames[PQFAKE_MAX_COLUMNS];
  const char*    ma_cells[PQFAKE_MAX_COLUMNS];
} PqFakeAnswer_t;

extern int g_pqfakeCallCount;

extern char g_pqfakeCallLog[PQFAKE_CALL_LOG_BUF_SIZE];

extern char g_pqfakeLastCommand[PQFAKE_COMMAND_BUF_SIZE];

extern char g_pqfakeLastParamLog[PQFAKE_PARAM_LOG_BUF_SIZE];

void pqfake_reset(void);

void pqfake_queue(const PqFakeAnswer_t* answer);

void pqfake_beginStderrCapture(void);
void pqfake_endStderrCapture(char* text, size_t text_size);

#endif
