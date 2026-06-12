/*
 * csp_util.h — shared helpers for CSP value and HTML <script> analysis.
 *
 * Included by both scanner/src/contrastscan.c (production) and
 * scanner/tests/test_scoring.c (unit tests) so the two never drift.
 *
 * Both helpers are `static inline` so each translation unit gets its own copy
 * (the scanner and the test binary are separate executables, not linked).
 *
 * Caller must `#define _GNU_SOURCE` BEFORE including this header — strcasestr
 * is a GNU extension.
 */

#ifndef CSP_UTIL_H
#define CSP_UTIL_H

#include <ctype.h>
#include <stddef.h>
#include <string.h>

/*
 * csp_has_keyword — word-boundary search for a CSP keyword.
 *
 * Returns 1 if `keyword` appears in `csp` with non-identifier chars on both
 * sides, else 0. Prevents false positives like 'wasm-unsafe-eval' matching
 * 'unsafe-eval'. A char is "non-identifier" if it is not [a-zA-Z0-9] and not
 * '-'. Empty keyword always returns 0.
 */
static inline int csp_has_keyword(const char *csp, const char *keyword)
{
  if (!csp || !keyword) return 0;
  size_t klen = strlen(keyword);
  if (klen == 0) return 0;
  const char *p = csp;
  while ((p = strcasestr(p, keyword)) != NULL)
  {
    char before = (p == csp) ? ' ' : p[-1];
    char after  = p[klen];
    int before_ok = !isalnum((unsigned char)before) && before != '-';
    int after_ok  = !isalnum((unsigned char)after)  && after  != '-';
    if (before_ok && after_ok) return 1;
    p += klen;
    if (*p == '\0') break;
  }
  return 0;
}

/*
 * count_script_data_blocks — count <script> tags whose type attribute marks
 * them as non-executable data blocks (attribute-order agnostic).
 *
 * Per HTML spec, <script type="application/ld+json">, application/json, and
 * text/template are data blocks: browsers do not execute them and CSP does
 * not require 'unsafe-inline' for them. Matches regardless of attribute
 * order, e.g. `<script defer type="application/ld+json">` is counted.
 *
 * Only treats `<script` as a tag when followed by whitespace, '>', or '/'
 * (so `<scripting>` or `<scripts>` are not counted as script tags).
 */
static inline int count_script_data_blocks(const char *html)
{
  if (!html) return 0;
  int count = 0;
  const char *p = html;
  while ((p = strcasestr(p, "<script")) != NULL)
  {
    p += 7; /* past "<script" */
    char nxt = *p;
    if (nxt != ' ' && nxt != '\t' && nxt != '\n' && nxt != '\r' &&
        nxt != '>' && nxt != '/' && nxt != '\0')
    {
      /* e.g. <scripting> — not a script tag, keep scanning */
      continue;
    }
    if (nxt == '\0') break;
    const char *end = strchr(p, '>');
    if (!end) break;
    size_t len = (size_t)(end - p);
    if (len > 512) len = 512; /* clamp: HTML attrs on a single tag rarely exceed this */
    char buf[513];
    memcpy(buf, p, len);
    buf[len] = '\0';
    if (strcasestr(buf, "application/ld+json") ||
        strcasestr(buf, "application/json")    ||
        strcasestr(buf, "text/template"))
    {
      count++;
    }
    p = end + 1;
  }
  return count;
}

#endif /* CSP_UTIL_H */
