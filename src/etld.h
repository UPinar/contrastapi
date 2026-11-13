#ifndef ETLD_H
#define ETLD_H

#include <stdint.h>

extern const char     etld_ruleText[];
extern const uint32_t etld_ruleOffsets[];
extern const int      etld_ruleCount;

#define ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE  "domain is a public suffix, such as co.uk; name a domain registered under it"

const char* etld_find        (const char* domain_name);
const char* etld_findPlusOne (const char* domain_name);

#endif
