#ifndef NETCONNECT_H
#define NETCONNECT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

bool netconnect_tryBuildSockaddr(const char* address_text, uint16_t port, struct sockaddr_storage* address_out, socklen_t* address_len_out);
int  netconnect_connectUntil    (const struct sockaddr* address, socklen_t address_len, int64_t connect_deadline_ms, int64_t deadline_at);
bool netconnect_waitForSocket   (int fd, short wanted_event, int64_t deadline_at);

#endif
