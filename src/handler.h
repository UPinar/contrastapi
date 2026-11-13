#ifndef HANDLER_H
#define HANDLER_H

#include <libpq-fe.h>

#include "endpoint.h"
#include "mcp.h"
#include "request.h"

#define HANDLER_ERROR_JSONBUF_INITIAL_CAP 128


void handler_MCP                              (int client_fd, const char* body, const McpRoutingHeaders_t* routing_headers, PGconn* conn, const RequestCharge_t* charge);
void handler_runRestEndpoint                  (int client_fd, const Endpoint_t* endpoint, const EndpointRestInput_t* input, PGconn* conn, const RequestCharge_t* charge);

void handler_badRequest                       (int client_fd, const char* message);
void handler_uriTooLong                       (int client_fd);
void handler_contentTooLarge                  (int client_fd);
void handler_headerFieldsTooLarge             (int client_fd);
void handler_transferEncodingNotImplemented   (int client_fd);
void handler_endpointNotFound                 (int client_fd);
void handler_httpMethodNotAllowed             (int client_fd, const char* const allowed_methods[]);
void handler_httpQueryParamNameRefused        (int client_fd, const Endpoint_t* endpoint, EndpointGateResult_t gate_result);
void handler_unauthorized                     (int client_fd);
void handler_apiKeyInactive                   (int client_fd);
void handler_rateLimited                      (int client_fd, unsigned int retry_after_sec);
void handler_upstreamBusy                     (int client_fd);
void handler_rawBodyBusy                      (int client_fd);
void handler_internalError                    (int client_fd);

void handler_paymentRequired                  (int client_fd, const Endpoint_t* endpoint, unsigned int credit_count, unsigned int retry_after_sec);
void handler_paymentRefused                   (int client_fd, const Endpoint_t* endpoint, unsigned int credit_count);
void handler_paymentAlreadyUsed               (int client_fd, const Endpoint_t* endpoint, unsigned int credit_count);
void handler_paymentPending                   (int client_fd, unsigned int retry_after_sec);
void handler_paymentInvalid                   (int client_fd);
void handler_paymentNotOffered                (int client_fd);
void handler_paymentBusy                      (int client_fd, unsigned int retry_after_sec);
void handler_paymentLimited                   (int client_fd, unsigned int retry_after_sec);
void handler_paymentUnavailable               (int client_fd, unsigned int retry_after_sec);

void handler_mcpUnauthorized                  (int client_fd, const char* body);
void handler_mcpApiKeyInactive                (int client_fd, const char* body);
void handler_mcpRateLimited                   (int client_fd, const char* body, unsigned int retry_after_sec);
void handler_mcpUpstreamBusy                  (int client_fd, const char* body);
void handler_mcpInternalError                 (int client_fd, const char* body);

void handler_mcpPaymentRequired               (int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, unsigned int retry_after_sec, bool is_modern);
void handler_mcpPaymentRefused                (int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, bool is_modern);
void handler_mcpPaymentAlreadyUsed            (int client_fd, const char* body, const Endpoint_t* tool_endpoint, unsigned int credit_count, bool is_modern);
void handler_mcpPaymentPending                (int client_fd, const char* body, unsigned int retry_after_sec, bool is_modern);
void handler_mcpPaymentInvalid                (int client_fd, const char* body, bool is_modern);
void handler_mcpPaymentNotOffered             (int client_fd, const char* body, bool is_modern);
void handler_mcpPaymentBusy                   (int client_fd, const char* body, unsigned int retry_after_sec);
void handler_mcpPaymentLimited                (int client_fd, const char* body, unsigned int retry_after_sec);
void handler_mcpPaymentUnavailable            (int client_fd, const char* body, unsigned int retry_after_sec);
void handler_mcpLadderRefusal                 (int client_fd, char* json, int status_code);

#endif
