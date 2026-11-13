#ifndef CONNECTION_H
#define CONNECTION_H

#include <libpq-fe.h>

#define CONNECTION_READ_TIMEOUT_SEC 5
#define CONNECTION_SEND_TIMEOUT_SEC 10

typedef enum {
  CONNECTION_SERVE_HANDLED = 0,
  CONNECTION_SERVE_DROPPED,
} ConnectionServeStatus_t;

ConnectionServeStatus_t connection_serveRequest (int client_fd, const char* client_ip, const char* ip_secret, PGconn* conn);

#endif
