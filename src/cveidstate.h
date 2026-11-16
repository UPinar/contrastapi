#ifndef CVEIDSTATE_H
#define CVEIDSTATE_H

#include <libpq-fe.h>

#include "external/cveservices.h"

CveServicesCveIdState_t cveidstate_dbFind(PGconn* conn, const char* cve_id);

#endif
