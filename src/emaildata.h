#ifndef EMAILDATA_H
#define EMAILDATA_H

#include <stddef.h>

#define EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT        3
#define EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT 4

typedef struct {
  const char* mp_name;
  const char* ma_suffixes[EMAILDATA_PROVIDER_MAX_SUFFIX_COUNT];
  const char* ma_dkimSelectors[EMAILDATA_PROVIDER_MAX_DKIM_SELECTOR_COUNT];
} EmailDataProvider_t;

#define EMAILDATA_PROVIDER_COUNT 32

extern const EmailDataProvider_t emaildata_providers[EMAILDATA_PROVIDER_COUNT];

#define EMAILDATA_COMMON_DKIM_SELECTOR_COUNT 13

extern const char* const emaildata_commonDkimSelectors[EMAILDATA_COMMON_DKIM_SELECTOR_COUNT];

const EmailDataProvider_t* emaildata_findProvider(const char* host_name, size_t host_name_len);

#endif
