#include "whois.h"

#define WHOIS_KEY_COUNT(keys) ((int)(sizeof(keys) / sizeof((keys)[0])))

static const WhoisKey_t ICANN_KEYS[] = {
  { "Domain Name",          WHOIS_FIELD_DOMAIN_NAME       },
  { "Registrar",            WHOIS_FIELD_REGISTRAR_NAME    },
  { "Sponsoring Registrar", WHOIS_FIELD_REGISTRAR_NAME    },
  { "Registrar IANA ID",    WHOIS_FIELD_REGISTRAR_IANA_ID },
  { "Creation Date",        WHOIS_FIELD_CREATED_AT        },
  { "Updated Date",         WHOIS_FIELD_UPDATED_AT        },
  { "Registry Expiry Date", WHOIS_FIELD_EXPIRES_AT        },
  { "Domain Status",        WHOIS_FIELD_STATUS            },
  { "Name Server",          WHOIS_FIELD_NAME_SERVER       },
  { "DNSSEC",               WHOIS_FIELD_DNSSEC            },
};
static const WhoisKeyMap_t ICANN_KEY_MAP = { ICANN_KEYS, WHOIS_KEY_COUNT(ICANN_KEYS) };

static const WhoisKey_t AM_KEYS[] = {
  { "Domain name",   WHOIS_FIELD_DOMAIN_NAME    },
  { "Registrar",     WHOIS_FIELD_REGISTRAR_NAME },
  { "Status",        WHOIS_FIELD_STATUS         },
  { "Registered",    WHOIS_FIELD_CREATED_AT     },
  { "Last modified", WHOIS_FIELD_UPDATED_AT     },
  { "Expires",       WHOIS_FIELD_EXPIRES_AT     },
  { "DNS servers",   WHOIS_FIELD_NAME_SERVER    },
};
static const WhoisKeyMap_t AM_KEY_MAP = { AM_KEYS, WHOIS_KEY_COUNT(AM_KEYS) };

static const WhoisKey_t DK_KEYS[] = {
  { "Domain",     WHOIS_FIELD_DOMAIN_NAME },
  { "Registered", WHOIS_FIELD_CREATED_AT  },
  { "Expires",    WHOIS_FIELD_EXPIRES_AT  },
  { "DNSSEC",     WHOIS_FIELD_DNSSEC      },
  { "Status",     WHOIS_FIELD_STATUS      },
  { "Hostname",   WHOIS_FIELD_NAME_SERVER },
};
static const WhoisKeyMap_t DK_KEY_MAP = { DK_KEYS, WHOIS_KEY_COUNT(DK_KEYS) };

static const WhoisKey_t IL_KEYS[] = {
  { "domain",         WHOIS_FIELD_DOMAIN_NAME    },
  { "registrar name", WHOIS_FIELD_REGISTRAR_NAME },
  { "assigned",       WHOIS_FIELD_CREATED_AT     },
  { "validity",       WHOIS_FIELD_EXPIRES_AT     },
  { "status",         WHOIS_FIELD_STATUS         },
  { "nserver",        WHOIS_FIELD_NAME_SERVER    },
  { "DNSSEC",         WHOIS_FIELD_DNSSEC         },
};
static const WhoisKeyMap_t IL_KEY_MAP = { IL_KEYS, WHOIS_KEY_COUNT(IL_KEYS) };

static const WhoisKey_t LS_KEYS[] = {
  { "domain",     WHOIS_FIELD_DOMAIN_NAME    },
  { "registrar",  WHOIS_FIELD_REGISTRAR_NAME },
  { "registered", WHOIS_FIELD_CREATED_AT     },
  { "expire",     WHOIS_FIELD_EXPIRES_AT     },
  { "nserver",    WHOIS_FIELD_NAME_SERVER    },
};
static const WhoisKeyMap_t LS_KEY_MAP = { LS_KEYS, WHOIS_KEY_COUNT(LS_KEYS) };

static const WhoisKey_t LT_KEYS[] = {
  { "Domain",     WHOIS_FIELD_DOMAIN_NAME    },
  { "Status",     WHOIS_FIELD_STATUS         },
  { "Registered", WHOIS_FIELD_CREATED_AT     },
  { "Expires",    WHOIS_FIELD_EXPIRES_AT     },
  { "Registrar",  WHOIS_FIELD_REGISTRAR_NAME },
  { "Nameserver", WHOIS_FIELD_NAME_SERVER    },
};
static const WhoisKeyMap_t LT_KEY_MAP = { LT_KEYS, WHOIS_KEY_COUNT(LT_KEYS) };

#define IDENTITY_DIGITAL_NOT_FOUND "Domain not found."
#define TUCOWS_NOT_FOUND           "This name is not available for registration"

const WhoisServer_t whois_servers[] = {
  { "ac",               "whois.nic.ac",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "ag",               "whois.nic.ag",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "am",               "whois.amnic.net",                &AM_KEY_MAP,    "No match" },
  { "dk",               "whois.punktum.dk",               &DK_KEY_MAP,    "No entries found for the selected source." },
  { "dm",               "whois.dmdomains.dm",             &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "gi",               "whois.identitydigital.services", &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "il",               "whois.isoc.org.il",              &IL_KEY_MAP,    NULL },
  { "io",               "whois.nic.io",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "ls",               "whois.nic.ls",                   &LS_KEY_MAP,    "No record found for" },
  { "lt",               "whois.domreg.lt",                &LT_KEY_MAP,    "Status:\t\t\tavailable" },
  { "me",               "whois.nic.me",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "mn",               "whois.nic.mn",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "my",               "whois.mynic.my",                 &ICANN_KEY_MAP, "is available for registration" },
  { "pr",               "whois.afilias-srs.net",          &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "sa",               "whois.nic.net.sa",               &ICANN_KEY_MAP, "No Match for domain" },
  { "sh",               "whois.nic.sh",                   &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "tc",               "whois.nic.tc",                   &ICANN_KEY_MAP, "No Object Found" },
  { "vc",               "whois.identitydigital.services", &ICANN_KEY_MAP, IDENTITY_DIGITAL_NOT_FOUND },
  { "xn--2scrj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--3hcrj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--45br5cyl",     "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--45brj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--4dbrk0ce",     "whois.isoc.org.il",              &IL_KEY_MAP,    NULL },
  { "xn--fpcrj9c3d",    "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--gecrj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--h2breg3eve",   "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--h2brj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--h2brj9c8c",    "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--mgbbh1a",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--mgbbh1a71e",   "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--mgberp4a5d4ar", "whois.nic.net.sa",              &ICANN_KEY_MAP, "No Match for domain" },
  { "xn--mgbgu82a",     "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--mgbx4cd0ab",   "whois.mynic.my",                 &ICANN_KEY_MAP, "is available for registration" },
  { "xn--rvc1e0am3e",   "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--s9brj9c",      "whois.nixiregistry.in",          &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--xkc2dl3a5ee0h", "whois.nixiregistry.in",         &ICANN_KEY_MAP, TUCOWS_NOT_FOUND },
  { "xn--y9a3aq",       "whois.amnic.net",                &AM_KEY_MAP,    "No match" },
};

const int whois_serverCount = (int)(sizeof(whois_servers) / sizeof(whois_servers[0]));
