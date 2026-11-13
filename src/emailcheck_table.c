#include <stddef.h>

#include "emailcheck.h"

static const char* const EMAILCHECK_KIND_IDS[EMAILCHECK_KIND_COUNT] = {
  "spf_record", "spf_syntax", "spf_lookup_limit", "spf_all", "spf_ignored_terms", "spf_ptr",
  "spf_wide_range", "spf_record_size", "dmarc_record", "dmarc_policy", "dmarc_test_mode",
  "dmarc_reporting", "dkim_key_found", "dkim_key_usable", "dkim_key_size", "dkim_key_format",
  "dkim_test_mode", "dkim_key_restricted", "dkim_multiple_keys", "mx", "mta_sts",
};

const char* emailcheck_kindId(EmailCheckKind_t kind)
{
  if ((int)kind < 0 || (int)kind >= EMAILCHECK_KIND_COUNT)
    return NULL;
  return EMAILCHECK_KIND_IDS[kind];
}
