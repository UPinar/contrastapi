#include "tlsprobe.h"

const TlsProbeProblemName_t tlsprobe_problemNames[TLSPROBE_PROBLEM_NAME_COUNT] = {
  { TLSPROBE_PROBLEM_EXPIRED,           "expired"           },
  { TLSPROBE_PROBLEM_NOT_YET_VALID,     "not_yet_valid"     },
  { TLSPROBE_PROBLEM_SELF_SIGNED,       "self_signed"       },
  { TLSPROBE_PROBLEM_UNTRUSTED_ROOT,    "untrusted_root"    },
  { TLSPROBE_PROBLEM_HOSTNAME_MISMATCH, "hostname_mismatch" },
  { TLSPROBE_PROBLEM_CHAIN_INCOMPLETE,  "chain_incomplete"  },
  { TLSPROBE_PROBLEM_OTHER,             "other"             },
  { TLSPROBE_PROBLEM_WEAK_CRYPTO,       "weak_crypto"       },
};
