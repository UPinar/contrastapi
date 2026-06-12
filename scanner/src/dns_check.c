/*
 * contrastscan — DNS Security Checker
 *
 * resolv.h (libresolv):
 *   res_query(dname, class, type, answer, anslen) — send DNS query
 *   ns_initparse(msg, msglen, handle)             — parse DNS response
 *   ns_parserr(handle, section, rrnum, rr)        — read a single RR
 *   ns_rr_rdata(rr)                               — pointer to RR data
 *   dn_expand(msg, eom, src, dst, dstsiz)         — expand compressed name
 *
 * DNS TXT query:
 *   SPF  → dig TXT example.com        ("v=spf1 ...")
 *   DMARC→ dig TXT _dmarc.example.com ("v=DMARC1; ...")
 *   DKIM → dig TXT selector._domainkey.example.com
 *          selector unknown → we try common ones (google, default, selector1...)
 */

#include <stdio.h>      // printf, fprintf, snprintf
#include <stdlib.h>      // EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>      // strstr, memcpy, strlen
#include <arpa/nameser.h> // ns_initparse, ns_parserr, ns_rr_rdata, NS_PACKETSZ
#include <resolv.h>      // res_query
#include <cjson/cJSON.h> // cJSON_*

#define MAX_SCORE 33

/* common DKIM selectors — we try these for the domain */
static const char *dkim_selectors[] = {
  "google", "default", "selector1", "selector2",
  "k1", "mail", "dkim", "s1", "s2", "smtp", NULL
};

/*
 * query_txt — send TXT query for domain, copy record containing needle to buf
 * return: 1 (found), 0 (not found)
 *
 * Example: query_txt("example.com", "v=spf1", buf, sizeof(buf))
 *          → buf = "v=spf1 include:_spf.google.com ~all"
 */
int query_txt(const char *domain, const char *needle, char *buf, size_t bufsz)
{
  unsigned char answer[4096];
  int len = res_query(domain, ns_c_in, ns_t_txt, answer, sizeof(answer));
  if (len < 0)
    return 0;

  ns_msg handle;
  if (ns_initparse(answer, len, &handle) < 0)
    return 0;

  int count = ns_msg_count(handle, ns_s_an);
  for (int i = 0; i < count; i++)
  {
    ns_rr rr;
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
      continue;
    if (ns_rr_type(rr) != ns_t_txt)
      continue;

    /* TXT RR format: [length_byte][text_data]...
     * there can be multiple chunks, we concatenate them all */
    const unsigned char *rdata = ns_rr_rdata(rr);
    int rdlen = ns_rr_rdlen(rr);
    int pos = 0;
    size_t out = 0;

    while (pos < rdlen && out < bufsz - 1)
    {
      int chunk_len = rdata[pos];
      pos++;
      if (pos + chunk_len > rdlen)
        break;
      int copy = chunk_len;
      if (out + copy >= bufsz - 1)
        copy = bufsz - 1 - out;
      memcpy(buf + out, rdata + pos, copy);
      out += copy;
      pos += chunk_len;
    }
    buf[out] = '\0';

    if (needle == NULL || strstr(buf, needle))
      return 1;
  }

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *domain = argv[1];
  char buf[2048];

  // === 1. SPF ===
  int has_spf = query_txt(domain, "v=spf1", buf, sizeof(buf));
  char spf_record[2048] = "";
  if (has_spf)
    snprintf(spf_record, sizeof(spf_record), "%s", buf);

  // === 2. DMARC ===
  char dmarc_domain[512];
  snprintf(dmarc_domain, sizeof(dmarc_domain), "_dmarc.%s", domain);
  int has_dmarc = query_txt(dmarc_domain, "v=DMARC1", buf, sizeof(buf));
  char dmarc_record[2048] = "";
  if (has_dmarc)
    snprintf(dmarc_record, sizeof(dmarc_record), "%s", buf);

  // === 3. DKIM — try common selectors ===
  int has_dkim = 0;
  char dkim_record[2048] = "";
  char dkim_selector_found[64] = "";

  for (int i = 0; dkim_selectors[i] != NULL; i++)
  {
    char dkim_domain[512];
    snprintf(dkim_domain, sizeof(dkim_domain),
             "%s._domainkey.%s", dkim_selectors[i], domain);
    if (query_txt(dkim_domain, NULL, buf, sizeof(buf)))
    {
      has_dkim = 1;
      snprintf(dkim_record, sizeof(dkim_record), "%s", buf);
      snprintf(dkim_selector_found, sizeof(dkim_selector_found),
               "%s", dkim_selectors[i]);
      break;
    }
  }

  // === Scoring ===
  int spf_score = has_spf ? 11 : 0;
  int dmarc_score = has_dmarc ? 11 : 0;
  int dkim_score = has_dkim ? 11 : 0;
  int score = spf_score + dmarc_score + dkim_score;

  // === JSON output ===
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "domain", domain);
  cJSON_AddNumberToObject(root, "score", score);
  cJSON_AddNumberToObject(root, "max", MAX_SCORE);

  cJSON *details = cJSON_CreateObject();

  cJSON_AddBoolToObject(details, "spf", has_spf);
  cJSON_AddNumberToObject(details, "spf_score", spf_score);
  if (has_spf)
    cJSON_AddStringToObject(details, "spf_record", spf_record);

  cJSON_AddBoolToObject(details, "dmarc", has_dmarc);
  cJSON_AddNumberToObject(details, "dmarc_score", dmarc_score);
  if (has_dmarc)
    cJSON_AddStringToObject(details, "dmarc_record", dmarc_record);

  cJSON_AddBoolToObject(details, "dkim", has_dkim);
  cJSON_AddNumberToObject(details, "dkim_score", dkim_score);
  if (has_dkim)
  {
    cJSON_AddStringToObject(details, "dkim_selector", dkim_selector_found);
    cJSON_AddStringToObject(details, "dkim_record", dkim_record);
  }

  cJSON_AddItemToObject(root, "details", details);

  char *json_str = cJSON_Print(root);
  printf("%s\n", json_str);

  free(json_str);
  cJSON_Delete(root);

  return EXIT_SUCCESS;
}
