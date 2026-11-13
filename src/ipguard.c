#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include "ipguard.h"

typedef struct {
  uint32_t     m_prefix;
  unsigned int m_prefixLen;
} IpGuardIpv4Block_t;

typedef struct {
  uint8_t      ma_prefix[16];
  unsigned int m_prefixLen;
} IpGuardIpv6Block_t;

static const IpGuardIpv4Block_t IPV4_ACCEPTED_EXCEPTIONS[] = {
  { 0xC0000009u, 32 },
  { 0xC000000Au, 32 },
};
static const IpGuardIpv4Block_t IPV4_REFUSED_BLOCKS[] = {
  { 0x00000000u,  8 },
  { 0x0A000000u,  8 },
  { 0x64400000u, 10 },
  { 0x7F000000u,  8 },
  { 0xA9FE0000u, 16 },
  { 0xAC100000u, 12 },
  { 0xC0000000u, 24 },
  { 0xC0000200u, 24 },
  { 0xC0586302u, 32 },
  { 0xC0A80000u, 16 },
  { 0xC6120000u, 15 },
  { 0xC6336400u, 24 },
  { 0xCB007100u, 24 },
  { 0xE0000000u,  4 },
  { 0xF0000000u,  4 },
};

static const IpGuardIpv6Block_t IPV6_ACCEPTABLE_BLOCK = { { 0x20 }, 3 };
static const IpGuardIpv6Block_t IPV6_ACCEPTED_EXCEPTIONS[] = {
  { { 0x20, 0x01, 0x00, 0x01, [15] = 0x01 }, 128 },
  { { 0x20, 0x01, 0x00, 0x01, [15] = 0x02 }, 128 },
  { { 0x20, 0x01, 0x00, 0x01, [15] = 0x03 }, 128 },
  { { 0x20, 0x01, 0x00, 0x03 },               32 },
  { { 0x20, 0x01, 0x00, 0x04, 0x01, 0x12 },   48 },
  { { 0x20, 0x01, 0x00, 0x20 },               28 },
  { { 0x20, 0x01, 0x00, 0x30 },               28 },
};
static const IpGuardIpv6Block_t IPV6_REFUSED_BLOCKS[] = {
  { { 0x20, 0x01, 0x00, 0x00 }, 23 },
  { { 0x20, 0x01, 0x0D, 0xB8 }, 32 },
  { { 0x20, 0x02 },             16 },
  { { 0x3F, 0xFF, 0x00, 0x00 }, 20 },
};

static bool static_isInIpv4Block(uint32_t address, const IpGuardIpv4Block_t* block)
{
  uint32_t mask = block->m_prefixLen == 0 ? 0 : 0xFFFFFFFFu << (32 - block->m_prefixLen);
  return (address & mask) == block->m_prefix;
}

static bool static_isInIpv6Block(const uint8_t address[16], const IpGuardIpv6Block_t* block)
{
  unsigned int whole_bytes = block->m_prefixLen / 8;
  unsigned int extra_bits  = block->m_prefixLen % 8;
  if (memcmp(address, block->ma_prefix, whole_bytes) != 0)
    return false;
  if (extra_bits == 0)
    return true;

  uint8_t mask = (uint8_t)(0xFFu << (8 - extra_bits));
  return (address[whole_bytes] & mask) == (block->ma_prefix[whole_bytes] & mask);
}

static bool static_isGloballyReachableIpv4(uint32_t address)
{
  for (size_t i = 0; i < sizeof(IPV4_ACCEPTED_EXCEPTIONS) / sizeof(IPV4_ACCEPTED_EXCEPTIONS[0]); i++)
    if (static_isInIpv4Block(address, &IPV4_ACCEPTED_EXCEPTIONS[i]))
      return true;

  for (size_t i = 0; i < sizeof(IPV4_REFUSED_BLOCKS) / sizeof(IPV4_REFUSED_BLOCKS[0]); i++)
    if (static_isInIpv4Block(address, &IPV4_REFUSED_BLOCKS[i]))
      return false;
    
  return true;
}

static bool static_isGloballyReachableIpv6(const uint8_t address[16])
{
  if (!static_isInIpv6Block(address, &IPV6_ACCEPTABLE_BLOCK))
    return false;

  for (size_t i = 0; i < sizeof(IPV6_ACCEPTED_EXCEPTIONS) / sizeof(IPV6_ACCEPTED_EXCEPTIONS[0]); i++)
    if (static_isInIpv6Block(address, &IPV6_ACCEPTED_EXCEPTIONS[i]))
      return true;

  for (size_t i = 0; i < sizeof(IPV6_REFUSED_BLOCKS) / sizeof(IPV6_REFUSED_BLOCKS[0]); i++)
    if (static_isInIpv6Block(address, &IPV6_REFUSED_BLOCKS[i]))
      return false;
    
  return true;
}

bool ipguard_isGloballyReachableSockaddr(const struct sockaddr* address, socklen_t address_len)
{
  if (address == NULL || address_len < (socklen_t)sizeof(struct sockaddr_in))
    return false;

  if (address->sa_family == AF_INET)
  {
    struct sockaddr_in ipv4_address;
    memcpy(&ipv4_address, address, sizeof(ipv4_address));
    return static_isGloballyReachableIpv4(ntohl(ipv4_address.sin_addr.s_addr));
  }
  else if (address->sa_family == AF_INET6 && address_len >= (socklen_t)sizeof(struct sockaddr_in6))
  {
    struct sockaddr_in6 ipv6_address;
    memcpy(&ipv6_address, address, sizeof(ipv6_address));
    return ipv6_address.sin6_scope_id == 0 && static_isGloballyReachableIpv6(ipv6_address.sin6_addr.s6_addr);
  }
  return false;
}

bool ipguard_isGloballyReachableIp(const char* ip_text)
{
  struct sockaddr_in ipv4_address;
  memset(&ipv4_address, 0, sizeof(ipv4_address));
  if (inet_pton(AF_INET, ip_text, &ipv4_address.sin_addr) == 1)
  {
    ipv4_address.sin_family = AF_INET;
    return ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv4_address, sizeof(ipv4_address));
  }

  struct sockaddr_in6 ipv6_address;
  memset(&ipv6_address, 0, sizeof(ipv6_address));
  if (inet_pton(AF_INET6, ip_text, &ipv6_address.sin6_addr) == 1)
  {
    ipv6_address.sin6_family = AF_INET6;
    return ipguard_isGloballyReachableSockaddr((const struct sockaddr*)&ipv6_address, sizeof(ipv6_address));
  }
  return false;
}

bool ipguard_tryWriteCanonicalIp(const char* ip_text, char ip_address_out[INET6_ADDRSTRLEN])
{
  unsigned char address[sizeof(struct in6_addr)];
  int           family = AF_INET;
  if (inet_pton(AF_INET, ip_text, address) != 1)
  {
    family = AF_INET6;
    if (inet_pton(AF_INET6, ip_text, address) != 1)
      return false;
  }
  return inet_ntop(family, address, ip_address_out, INET6_ADDRSTRLEN) != NULL;
}
