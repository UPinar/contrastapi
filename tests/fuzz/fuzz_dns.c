#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 3)
    return -1;

  size_t message_len     = size - 1;
  unsigned char* message = malloc(message_len);
  if (message == NULL)
    abort();
  memcpy(message, data + 1, message_len);

  DnsQuestion_t question = { .mp_domainName = "example.com", .m_type = (DnsRecordType_t)(data[0] % DNS_RECORD_TYPE_COUNT) };
  uint16_t message_id    = (uint16_t)((message[0] << 8) | message[1]);
  DnsAnswer_t answer;
  memset(&answer, 0, sizeof(answer));
  if (dns_tryReadResponse(message, message_len, &question, message_id, &answer))
    dns_answerFree(&answer);

  free(message);
  return 0;
}
