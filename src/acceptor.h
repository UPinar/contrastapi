#ifndef ACCEPTOR_H
#define ACCEPTOR_H

#include <signal.h>

#include "worker.h"

#define ACCEPTOR_BACKOFF_NSEC 100000000L

typedef struct AcceptorShutdownSignalThread AcceptorShutdownSignalThread_t;

AcceptorShutdownSignalThread_t* acceptor_startShutdownSignalThread (const sigset_t* signals, int wake_fd, WorkerPool_t* worker_pool);
void                            acceptor_stopShutdownSignalThread  (AcceptorShutdownSignalThread_t* signal_thread);
void                            acceptor_acceptUntilShutdown       (int listen_fd, int wake_fd, WorkerPool_t* worker_pool);

#endif
