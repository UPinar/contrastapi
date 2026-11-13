#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netconnect.h"
#include "monotonic.h"

bool netconnect_tryBuildSockaddr(const char* address_text, uint16_t port, struct sockaddr_storage* address_out, socklen_t* address_len_out)
{
  assert(address_text    != NULL);
  assert(address_out     != NULL);
  assert(address_len_out != NULL);

  struct sockaddr_in* ipv4 = (struct sockaddr_in*)address_out;
  if (inet_pton(AF_INET, address_text, &ipv4->sin_addr) == 1)
  {
    ipv4->sin_family = AF_INET;
    ipv4->sin_port   = htons(port);
    *address_len_out = sizeof(*ipv4);
    return true;
  }

  struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)address_out;
  if (inet_pton(AF_INET6, address_text, &ipv6->sin6_addr) == 1)
  {
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port   = htons(port);
    *address_len_out  = sizeof(*ipv6);
    return true;
  }

  return false;
}

int netconnect_connectUntil(const struct sockaddr* address, socklen_t address_len, int64_t connect_deadline_ms, int64_t deadline_at)
{
  assert(address != NULL);

  int fd = socket(address->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  if (connect(fd, address, address_len) == 0)
    return fd;
  int connect_errno = errno;

  int64_t connect_deadline_at = monotonic_nowMs() + connect_deadline_ms;
  if (connect_deadline_at > deadline_at)
    connect_deadline_at = deadline_at;

  int socket_error = 0;
  socklen_t socket_error_len = sizeof(socket_error);
  if (connect_errno != EINPROGRESS                                                ||
      !netconnect_waitForSocket(fd, POLLOUT, connect_deadline_at)                 ||
      getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) != 0 ||
      socket_error != 0)
  {
    close(fd);
    return -1;
  }

  return fd;
}

bool netconnect_waitForSocket(int fd, short wanted_event, int64_t deadline_at)
{
  assert(fd >= 0);

  for (;;)
  {
    int64_t wait_ms = deadline_at - monotonic_nowMs();
    if (wait_ms <= 0)
      return false;

    struct pollfd poll_fd = { .fd = fd, .events = wanted_event };
    int ready_count = poll(&poll_fd, 1, (int)wait_ms);
    if (ready_count > 0)
      return true;
    if (ready_count < 0 && errno != EINTR)
      return false;
  }
}
