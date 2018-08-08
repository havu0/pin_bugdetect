#include "bugdetect.h"

AHASHMAP RC_hashmap_mem_accesses;

VOID PIN_FAST_ANALYSIS_CALL RC_Check(UINT32 thread_id, THREADID real_thread_id, ADDRINT *addr) {
	if(M_GET_ADDR_HASHMAP(RC_hashmap_mem_accesses, *addr, ADDRINT, 0) == 0) {
		return;
	}
	return;
}

VOID RaceCondition_INSInst(INS ins) {
	if (INS_IsMemoryWrite(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RC_Check, IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg_thread_identifier, IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);
		return;
	}
	if (INS_IsMemoryRead(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RC_Check, IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg_thread_identifier, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
		return;
	}
}

VOID plugin_RaceCondition() {
	/* THIS IS DFT-INDEPENDENT PLUGIN */
	// INS_AddInstrumentFunction(RaceCondition_INSInst, 0);
	reg_thread_identifier = PIN_ClaimToolRegister();
}

	