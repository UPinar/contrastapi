#ifndef MAINTENANCE_H
#define MAINTENANCE_H

#include <stdbool.h>
#include <libpq-fe.h>

#define MAINTENANCE_INTERVAL_SECONDS 900

typedef bool (*MaintenanceJobFunction_t)(PGconn* conn);

typedef struct {
  const char*              mp_name;
  MaintenanceJobFunction_t m_jobFunction;
} MaintenanceJob_t;

typedef struct MaintenanceThread MaintenanceThread_t;

MaintenanceThread_t* maintenance_start (const char* db_conninfo, unsigned int interval_ms, const MaintenanceJob_t* jobs, int job_count);
void                 maintenance_stop  (MaintenanceThread_t* maintenance_thread);

#endif
