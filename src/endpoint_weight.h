#ifndef ENDPOINT_WEIGHT_H
#define ENDPOINT_WEIGHT_H

#include <libpq-fe.h>

#include "endpoint.h"

EndpointRunStatus_t endpoint_PACKAGECHECKBULKWeigh(PGconn* conn, const EndpointAnyParams_t* params, int weighed_item_count, int* served_item_count_out);

#endif
