#include "registryask.h"

static const ThrottleRule_t REGISTRYASK_USER_REQUEST_RDAP_THROTTLE_RULE  = { "rdap",  60, 30 };
static const ThrottleRule_t REGISTRYASK_USER_REQUEST_WHOIS_THROTTLE_RULE = { "whois", 60, 10 };

static const ThrottleRule_t REGISTRYASK_WATCHLIST_SCAN_RDAP_THROTTLE_RULE  = { "rdap",  60, 10 };
static const ThrottleRule_t REGISTRYASK_WATCHLIST_SCAN_WHOIS_THROTTLE_RULE = { "whois", 60, 3 };

const RegistryAskThrottleRules_t registryask_userRequestThrottleRules   = { &REGISTRYASK_USER_REQUEST_RDAP_THROTTLE_RULE,   &REGISTRYASK_USER_REQUEST_WHOIS_THROTTLE_RULE   };
const RegistryAskThrottleRules_t registryask_watchlistScanThrottleRules = { &REGISTRYASK_WATCHLIST_SCAN_RDAP_THROTTLE_RULE, &REGISTRYASK_WATCHLIST_SCAN_WHOIS_THROTTLE_RULE };
