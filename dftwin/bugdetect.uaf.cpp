 #include "bugdetect.h"
AHASHMAP UAF_heap_hashmap;
AHASHMAP UAF_heap_hashmap2;
REG UAF_heapInfo;
REG UAF_heapInfo2;
list<HEAP_INFO *>freed_heap_list;

void UAF_freeBefore (ADDRINT addr, ADDRINT eip) {
	PIN_LockClient();
	ADDRINT size, base;
	int i;
	//*out << "free:: " << hex << value << " " << dec;
	HEAP_INFO *heapInfo = M_GET_ADDR_HASHMAP(UAF_heap_hashmap, addr, HEAP_INFO *, 0);
	if(heapInfo == 0) {
		// What the heck? if not exception, it must be pin tool's bug!
		// report_bug(BUG_INVALID_FREE_POINTER, 10, eip, 0);
		PIN_UnlockClient();
		return;
	}
	heapInfo->freed = 1;
	size = heapInfo->size;
	base = heapInfo->base;
	for(i = 0; i < size; i++)
		M_PUT_ADDR_HASHMAP(UAF_heap_hashmap2, i + base, ADDRINT, base);
	char write_buf[5];
	write_buf[0] = 11;
	*(ADDRINT *)write_buf[1] = addr;
	PIN_UnlockClient();
}


ADDRINT UAF_allocAfter(thread_ctx_t *ctx, ADDRINT ret, THREADID tid, HEAP_INFO *heapInfo) {
	PIN_LockClient();
	char write_buf[9];
	ADDRINT size = heapInfo->size;
	write_buf[0] = 10;
	*(unsigned int *)&write_buf[1] = ret;
	*(unsigned int *)&write_buf[5] = size;
	out->write(write_buf, 9);
	heapInfo->base = ret;
	heapInfo->refcount = 0;;
	for(int i = 0; i < size; i++)
		M_PUT_ADDR_HASHMAP(UAF_heap_hashmap2, ret + size, ADDRINT, 0);
	M_PUT_ADDR_HASHMAP(UAF_heap_hashmap, ret, HEAP_INFO *, heapInfo);
	PIN_UnlockClient();
	return 0;
}

VOID *UAF_allocBefore(thread_ctx_t *ctx, ADDRINT size, THREADID tid) {
	auto heapInfo = new HEAP_INFO;
	heapInfo->size = size;
	return heapInfo;
}

VOID UseAfterFree_IMGInst(IMG img, VOID *v) {
	RTN rtn;
	Hook2("HeapAlloc", UAF_allocBefore, IPOINT_BEFORE,
		IARG_REG_VALUE, thread_ctx_ptr,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_REG_VALUE, UAF_heapInfo,
		IARG_RETURN_REGS, UAF_heapInfo,
		IARG_THREAD_ID);
	Hook2("HeapAlloc", UAF_allocAfter, IPOINT_AFTER,
		IARG_REG_VALUE, thread_ctx_ptr,
		IARG_FUNCRET_EXITPOINT_VALUE,
		IARG_RETURN_REGS, UAF_heapInfo,
		IARG_THREAD_ID);
	Hook2("HeapFree", UAF_freeBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2);
}

VOID PIN_FAST_ANALYSIS_CALL UAF_add_refcount(ADDRINT *mem) {
	ADDRINT target_addr = *mem; // don't use safecopy cause of performance
	// *out << "PTR Write : " << hex << target_addr << endl;
	HEAP_INFO *heapInfo = M_GET_ADDR_HASHMAP(UAF_heap_hashmap, target_addr, HEAP_INFO *, 0); // only checks start address
	if(heapInfo == 0) return;
	heapInfo->refcount++;
}

VOID PIN_FAST_ANALYSIS_CALL UAF_sub_refcount(ADDRINT *mem, HEAP_INFO *pre_heapInfo) {
	if(M_GET_ADDR_HASHMAP(UAF_heap_hashmap, *mem, HEAP_INFO *, 0) == 0)
		pre_heapInfo->refcount--;
}

VOID *PIN_FAST_ANALYSIS_CALL UAF_check_exists(ADDRINT *mem) {
	return M_GET_ADDR_HASHMAP(UAF_heap_hashmap, *mem, HEAP_INFO *, 0);
}

ADDRINT PIN_FAST_ANALYSIS_CALL is_freed_heap(ADDRINT ea) {
	return M_GET_ADDR_HASHMAP(UAF_heap_hashmap2, ea, ADDRINT, 0);
}

VOID UseAfterFree_INSInst(INS ins, VOID *v) {
	int memOp = INS_MemoryOperandCount(ins);
	if(memOp) {
		for(int i = 0; i < memOp; i++) {
			INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)is_freed_heap, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYOP_EA, 1, IARG_END);
			INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)report_bug, IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BUG_USE_AFTER_FREE, IARG_UINT32, 10, IARG_INST_PTR, IARG_REG_VALUE, cur_tree, IARG_END);
		}
	}
	if (INS_IsMemoryWrite(ins) && INS_MemoryWriteSize(ins) == sizeof(ADDRINT)) {/*
		INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)UAF_check_exists_and_freed, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, UAF_heapInfo2, IARG_END);
		INS_InsertThenCall(ins, IPOINT_AFTER, (AFUNPTR)UAF_sub_refcount, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, UAF_heapInfo2, IARG_END);
		INS_InsertIfCall(ins, IPOINT_AFTER, (AFUNPTR)UAF_check_exists_and_alloc, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, UAF_heapInfo2, IARG_END);
		INS_InsertThenCall(ins, IPOINT_AFTER, (AFUNPTR)UAF_add_refcount, IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, UAF_heapInfo2, IARG_END);
		*/
	}
}

VOID check_refcount(INT32 code, VOID *v) {
	for(auto i = freed_heap_list.begin(); i != freed_heap_list.end(); i++) {
		HEAP_INFO *heapInfo = *i;
	}
}

VOID plugin_UseAfterFree() {
	IMG_AddInstrumentFunction(UseAfterFree_IMGInst, 0);
	UAF_heapInfo = PIN_ClaimToolRegister();
	UAF_heapInfo2 = PIN_ClaimToolRegister();

	INS_AddInstrumentFunction(UseAfterFree_INSInst, 0);
	UAF_heap_hashmap = create_addr_hashmap(0);

	PIN_AddFiniFunction(check_refcount, 0);
}
