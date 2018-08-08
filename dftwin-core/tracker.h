#ifndef __TRACKER_H__
#define __TRACKER_H__

#include "data_chunk.h"

extern DATA_CHUNK *untainted_chunk;
extern AHASHMAP data_chunk_hashmap;

DATA_CHUNK *alloc_data_chunk();

#endif