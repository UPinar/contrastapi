#ifndef VALIDATE_H
#define VALIDATE_H

#include <stdbool.h>

#define VALIDATE_SHA1_HEX_LEN     40
#define VALIDATE_SHA1_HEX_REFUSAL_MESSAGE "Provide the full SHA1 hash (40 hexadecimal characters)."

#define VALIDATE_MD5_HEX_LEN           32
#define VALIDATE_SHA256_HEX_LEN        64
#define VALIDATE_FILE_HASH_HEX_REFUSAL_MESSAGE "Provide an MD5, SHA1 or SHA256 hash (32, 40 or 64 hexadecimal characters)."

#define VALIDATE_DOMAIN_NAME_MAX_LEN  253
#define VALIDATE_DOMAIN_LABEL_MAX_LEN 63

#define VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE "Provide a public domain name, such as example.com."

#define VALIDATE_DKIM_SELECTOR_MAX_LEN (VALIDATE_DOMAIN_NAME_MAX_LEN - 15)

#define VALIDATE_DKIM_SELECTOR_REFUSAL_MESSAGE "dkim_selector must be labels of 1 to 63 letters, digits and hyphens, with dots between them, such as google. A label must not start or end with a hyphen."

#define VALIDATE_ATTACK_TECHNIQUE_ID_REFUSAL_MESSAGE "Provide a MITRE ATT&CK technique id in upper case, such as T1059 or T1059.001."

#define VALIDATE_PACKAGE_ECOSYSTEM_REFUSAL_MESSAGE "ecosystem must be one of npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL"
#define VALIDATE_PACKAGE_NAME_REFUSAL_MESSAGE      "name must not contain a space"
#define VALIDATE_PACKAGE_VERSION_REFUSAL_MESSAGE   "version must hold only visible ASCII characters, with no space"

#define VALIDATE_UUID_LEN 36

#define VALIDATE_ASN_MAX_DIGITS   10

#define VALIDATE_ASN_LOOKUP_TARGET_REFUSAL_MESSAGE "Provide an AS number, such as AS15169, or a public IPv4 or IPv6 address."

#define VALIDATE_EMAIL_ADDRESS_MAX_LEN     254
#define VALIDATE_EMAIL_LOCAL_PART_MAX_LEN  64

#define VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE "Provide an e-mail address with an ASCII local part of at most 64 bytes and a public domain name, such as name@example.com."

bool validate_searchString        (const char* search_string);
bool validate_searchQuery         (const char* search_query);
bool validate_date                (const char* date_str);
bool validate_cveId               (const char* cve_id);
bool validate_cweId               (const char* cwe_id);
bool validate_sha1Hex             (const char* sha1_hex);
bool validate_fileHashHex         (const char* file_hash_hex);
bool validate_domainName          (const char* domain_name);
bool validate_publicDnsName       (const char* domain_name);
bool validate_dkimSelector        (const char* dkim_selector);
bool validate_watchlistCursor     (const char* cursor);
bool validate_attackTechniqueId   (const char* attack_technique_id);
bool validate_packageEcosystem    (const char* ecosystem);
bool validate_packageName         (const char* package_name);
bool validate_packageVersion      (const char* version);
bool validate_packageExactVersion (const char* version);
bool validate_asn                 (const char* asn_text);
bool validate_asnLookupTarget     (const char* target);
bool validate_emailAddress        (const char* email);
bool validate_uuid                (const char* uuid);
bool validate_vendorKeyLink       (const char* link);
bool validate_vendorKey           (const char* vendor_key);

bool validate_publicUnderscoredDnsName(const char* domain_name);

#endif
