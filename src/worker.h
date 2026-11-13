#ifndef WORKER_H
#define WORKER_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <libpq-fe.h>

#define WORKER_QUEUE_CAPACITY 256

typedef struct {
  int  m_fd;
  char ma_clientIp[INET_ADDRSTRLEN];
} WorkerJob_t;

typedef void (*WorkerHandlerFunction_t)(const WorkerJob_t* job, PGconn* conn);

typedef struct WorkerPool WorkerPool_t;


WorkerPool_t* worker_createPool      (int thread_count, const char* db_conninfo, WorkerHandlerFunction_t handler_function);
bool          worker_enqueue         (WorkerPool_t* worker_pool, const WorkerJob_t* job);
void          worker_requestShutdown (WorkerPool_t* worker_pool);
void          worker_destroy         (WorkerPool_t* worker_pool);
void          worker_shutdown        (WorkerPool_t* worker_pool);

#endif
