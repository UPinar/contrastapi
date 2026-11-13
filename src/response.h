#ifndef RESPONSE_H
#define RESPONSE_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

void response_send(int client_fd, int status_code, const char* status_text, const char* response_body);

void response_sendMethodNotAllowed405(int client_fd, const char* allow_value, const char* response_body);

void response_sendServiceUnavailable503(int client_fd, unsigned int retry_after_sec, const char* response_body);

void response_sendTooManyRequests429(int client_fd, unsigned int retry_after_sec, const char* response_body);

void response_sendWithRetryAfter(int client_fd, int status_code, const char* status_text, unsigned int retry_after_sec, const char* response_body);

void response_sendContent(int client_fd, const char* content_type, const char* cache_control, const char* extra_headers, const void* body, size_t body_byte_count);

void response_sendWithExtraHeaders(int client_fd, int status_code, const char* status_text, const char* extra_headers, const char* response_body);

void response_setHeadRequest(bool is_head_request);

void response_setRateLimitInfo(unsigned int limit, int remaining_credit_count, time_t reset);
void response_clearRateLimitInfo(void);

#define RESPONSE_RESET_COUNTDOWN_BUF_SIZE 16

void response_formatResetCountdown(time_t reset, time_t now, char* countdown_out, size_t countdown_size);

#endif
