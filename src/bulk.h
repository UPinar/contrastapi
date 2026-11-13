#ifndef BULK_H
#define BULK_H

#define BULK_MAX_IDS     50

#define BULK_ID_MAX_LEN  64

typedef struct {
  char ma_ids[BULK_MAX_IDS][BULK_ID_MAX_LEN + 1];
  int  m_idCount;
  int  m_skippedIdCount;
  int  m_notProcessedIdCount;
} BulkIdsParams_t;

#endif
