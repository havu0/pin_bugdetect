#include "pin.H"
#include "data_chunk.h"
#include "tracker.h"
#include <set>

AHASHMAP data_chunk_hashmap; // hm1 : ptr to tree
DATA_CHUNK *untainted_chunk;

/*
static ADDRINT PIN_FAST_ANALYSIS_CALL return_0() 
{
	return 0;
}

void tracker_thread_init(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	PIN_SetContextReg(ctx, cur_tree, (ADDRINT)untainted_chunk);
}

DATA_CHUNK *alloc_data_chunk() {
	return new DATA_CHUNK;
}


int tracker_init()
{
	if ((cur_tree = PIN_ClaimToolRegister()) == REG_INVALID()) {
		return 1;
	}

	untainted_chunk = new DATA_CHUNK;

	return 0;

}

*/