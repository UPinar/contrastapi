/*
 * contrastscan — SSL/TLS Security Checker
 *
 * OpenSSL:
 *   SSL_CTX_new(method)             — create SSL context
 *   SSL_new(ctx)                    — create SSL session
 *   SSL_set_fd(ssl, sockfd)         — attach to socket
 *   SSL_set_tlsext_host_name(ssl,h) — set SNI (for virtual hosting)
 *   SSL_connect(ssl)                — initiate TLS handshake
 *   SSL_get_peer_certificate(ssl)   — get server certificate
 *   SSL_get_version(ssl)            — TLS version (TLSv1.2, TLSv1.3)
 *   SSL_get_cipher_name(ssl)        — cipher suite in use
 *   X509_get_notAfter(cert)         — certificate expiry date
 *
 * Socket:
 *   getaddrinfo(host, port, ...)    — DNS resolution
 *   socket(AF_INET, SOCK_STREAM,0)  — create TCP socket
 *   connect(sockfd, addr, len)      — connect to server
 */

#include <stdio.h>      // printf, fprintf, snprintf
#include <stdlib.h>      // EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>      // memset, strcmp
#include <unistd.h>      // close
#include <netdb.h>       // getaddrinfo, freeaddrinfo
#include <sys/socket.h>  // socket, connect
#include <openssl/ssl.h> // SSL_*, TLS_client_method
#include <openssl/x509.h> // X509_*, ASN1_TIME_*
#include <openssl/err.h> // ERR_*
#include <cjson/cJSON.h> // cJSON_*
#include <time.h>        // time, difftime

#define MAX_SCORE 33

/*
 * tcp_connect — open TCP connection to domain:port
 * return: socket fd (success), -1 (error)
 */
int tcp_connect(const char *host, const char *port)
{
  struct addrinfo hints, *res, *p;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;       // IPv4
  hints.ai_socktype = SOCK_STREAM; // TCP

  if (getaddrinfo(host, port, &hints, &res) != 0)
    return -1;

  int sockfd = -1;
  for (p = res; p != NULL; p = p->ai_next)
  {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0)
      continue;
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0)
      break; // connection successful
    close(sockfd);
    sockfd = -1;
  }

  freeaddrinfo(res);
  return sockfd;
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *domain = argv[1];

  // initialize OpenSSL
  SSL_library_init();
  SSL_load_error_strings();

  // TLS context — support all TLS versions, pick the best one
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
  {
    fprintf(stderr, "SSL_CTX_new failed\n");
    return EXIT_FAILURE;
  }

  // open TCP connection (port 443)
  int sockfd = tcp_connect(domain, "443");
  if (sockfd < 0)
  {
    fprintf(stderr, "TCP connection failed\n");
    SSL_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  // create SSL session and attach to socket
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);
  SSL_set_tlsext_host_name(ssl, domain); // SNI — which domain we're connecting to

  // TLS handshake
  if (SSL_connect(ssl) <= 0)
  {
    fprintf(stderr, "TLS handshake failed\n");
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  // === Gather info ===

  // 1. TLS version
  const char *tls_version = SSL_get_version(ssl);

  // 2. Cipher suite
  const char *cipher = SSL_get_cipher_name(ssl);

  // 3. Certificate
  X509 *cert = SSL_get_peer_certificate(ssl);
  int cert_valid = 0;
  int days_remaining = 0;

  if (cert)
  {
    // certificate expiry date
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    // convert ASN1_TIME to seconds
    int day, sec;
    ASN1_TIME_diff(&day, &sec, NULL, not_after); // NULL = now
    days_remaining = day;
    cert_valid = (days_remaining > 0) ? 1 : 0;
    X509_free(cert);
  }

  // === Scoring ===
  int score = 0;

  // TLS version (max 11 points)
  int tls_score = 0;
  if (strcmp(tls_version, "TLSv1.3") == 0)
    tls_score = 11;
  else if (strcmp(tls_version, "TLSv1.2") == 0)
    tls_score = 8;
  else if (strcmp(tls_version, "TLSv1.1") == 0)
    tls_score = 3; // old, insecure
  else
    tls_score = 0; // TLSv1.0 or older

  // certificate validity (max 11 points)
  int cert_score = 0;
  if (cert_valid && days_remaining > 30)
    cert_score = 11;
  else if (cert_valid && days_remaining > 7)
    cert_score = 7; // expiring soon
  else if (cert_valid)
    cert_score = 3; // expiring very soon
  else
    cert_score = 0; // expired

  // cipher strength (max 11 points) — simple check
  int cipher_score = 0;
  if (cipher)
  {
    // strong ciphers contain AES-256 or CHACHA20
    if (strstr(cipher, "AES256") || strstr(cipher, "AES_256") ||
        strstr(cipher, "CHACHA20"))
      cipher_score = 11;
    else if (strstr(cipher, "AES128") || strstr(cipher, "AES_128"))
      cipher_score = 8;
    else
      cipher_score = 3; // weak cipher
  }

  score = tls_score + cert_score + cipher_score;

  // === JSON output ===
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "domain", domain);
  cJSON_AddNumberToObject(root, "score", score);
  cJSON_AddNumberToObject(root, "max", MAX_SCORE);

  cJSON *details = cJSON_CreateObject();
  cJSON_AddStringToObject(details, "tls_version", tls_version);
  cJSON_AddNumberToObject(details, "tls_score", tls_score);
  cJSON_AddStringToObject(details, "cipher", cipher ? cipher : "unknown");
  cJSON_AddNumberToObject(details, "cipher_score", cipher_score);
  cJSON_AddBoolToObject(details, "cert_valid", cert_valid);
  cJSON_AddNumberToObject(details, "days_remaining", days_remaining);
  cJSON_AddNumberToObject(details, "cert_score", cert_score);
  cJSON_AddItemToObject(root, "details", details);

  char *json_str = cJSON_Print(root);
  printf("%s\n", json_str);

  // cleanup
  free(json_str);
  cJSON_Delete(root);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  return EXIT_SUCCESS;
}
