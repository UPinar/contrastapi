#ifndef IPGUARD_H
#define IPGUARD_H

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define IPGUARD_GLOBALLY_REACHABLE_IP_REFUSAL_MESSAGE "Provide a public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888."

bool ipguard_isGloballyReachableSockaddr(const struct sockaddr* address, socklen_t address_len);
bool ipguard_isGloballyReachableIp      (const char* ip_text);
bool ipguard_tryWriteCanonicalIp        (const char* ip_text, char ip_address_out[INET6_ADDRSTRLEN]);

#endif
