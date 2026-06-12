/*
 * contrastscan — HTTP Security Header Checker
 *
 * libcurl:
 *   CURL *curl_easy_init(void)                              — create session
 *   CURLcode curl_easy_setopt(CURL *, CURLoption, ...)      — set option
 *   CURLcode curl_easy_perform(CURL *)                      — send request
 *   void curl_easy_cleanup(CURL *)                          — cleanup
 *
 * Header callback:
 *   size_t cb(char *buffer, size_t size, size_t nitems, void *userdata)
 *   buffer = "X-Frame-Options: DENY\r\n"
 *   return size * nitems
 */

#include <stdio.h>     // printf, fprintf, snprintf
#include <string.h>    // strncasecmp, strlen
#include <stdlib.h>    // EXIT_SUCCESS, EXIT_FAILURE
#include <curl/curl.h> // curl_easy_init, curl_easy_setopt, curl_easy_perform, curl_easy_cleanup
#include <cjson/cJSON.h> // cJSON_CreateObject, cJSON_AddStringToObject, cJSON_Print

// 6 security headers to check
static const char *security_headers[] = {
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy"
};
#define NUM_HEADERS 6
#define MAX_SCORE 33  // header vector total 33 points

// was each header found (0 = no, 1 = yes)
static int found[NUM_HEADERS] = {0};

/*
 * header_callback — libcurl calls this for each header line
 *
 * buffer: "Strict-Transport-Security: max-age=31536000\r\n"
 * We check each line for one of the 6 security headers.
 * strncasecmp: case-insensitive comparison (upper/lower case doesn't matter)
 */
size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
  size_t total = size * nitems;

  for (int i = 0; i < NUM_HEADERS; i++) 
  {
    size_t len = strlen(security_headers[i]);
    // does the header line start with "header-name:"?
    if (total > len + 1 && strncasecmp(buffer, security_headers[i], len) == 0 && buffer[len] == ':') 
    {
      found[i] = 1;
    }
  }

  return total;
}

int main(int argc, char **argv)
{
  if (argc < 2) 
  {
    fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
    return EXIT_FAILURE;
  }

  // build URL: https://domain
  char url[512];
  snprintf(url, sizeof(url), "https://%s", argv[1]);

  // start curl session
  CURL *curl = curl_easy_init();
  if (!curl) 
  {
    fprintf(stderr, "curl_easy_init failed\n");
    return EXIT_FAILURE;
  }

  // settings
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);           // HEAD request
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback); // attach callback
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);   // follow redirects
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);         // 10 second timeout
  curl_easy_setopt(curl, CURLOPT_USERAGENT,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36");

  // send request
  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) 
  {
    fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
    return EXIT_FAILURE;
  }

  // scoring: (found × MAX_SCORE) / total — no full score loss
  int found_count = 0;
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    if (found[i])
      found_count++;
  }
  int score = (found_count * MAX_SCORE) / NUM_HEADERS;

  // build JSON output
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "domain", argv[1]);
  cJSON_AddNumberToObject(root, "score", score);
  cJSON_AddNumberToObject(root, "max", MAX_SCORE);

  // header details
  cJSON *details = cJSON_CreateArray();
  for (int i = 0; i < NUM_HEADERS; i++) 
  {
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "header", security_headers[i]);
    cJSON_AddBoolToObject(item, "present", found[i]);
    cJSON_AddItemToArray(details, item);
  }
  cJSON_AddItemToObject(root, "details", details);

  // print JSON to stdout
  char *json_str = cJSON_Print(root);
  printf("%s\n", json_str);

  // cleanup
  free(json_str);
  cJSON_Delete(root);

  return EXIT_SUCCESS;
}
