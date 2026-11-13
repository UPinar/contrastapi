#include <assert.h>
#include <stdlib.h>

#include "endpoint_weight.h"
#include "db.h"
#include "package.h"

EndpointRunStatus_t endpoint_PACKAGECHECKBULKWeigh(PGconn* conn, const EndpointAnyParams_t* params, int weighed_item_count, int* served_item_count_out)
{
  const PACKAGECHECKBULKParams_t* bulk_params = &params->m_packageCheckBulk;
  assert(weighed_item_count >= 1 && weighed_item_count <= bulk_params->m_itemCount + bulk_params->m_notProcessedItemCount);

  PACKAGECHECKBULKItem_t* items = NULL;
  if (!endpoint_readKeptPackageItems(bulk_params, weighed_item_count, &items))
    return ENDPOINT_RUN_NO_MEMORY;

  DbStatus_t db_status = db_PACKAGECHECKBULKWeigh(conn, items, weighed_item_count, served_item_count_out);
  free(items);
  return db_status == DB_OK ? ENDPOINT_RUN_OK : ENDPOINT_RUN_DB_ERROR;
}
