#ifndef __DATA_CHUNK_H__
#define __DATA_CHUNK_H__

// CALL_GET_ADDR_HASHMAP
// CALL_PUT_ADDR_HASHMAP
enum DATA_TYPE {
	heap_chunk,
	freed_heap_chunk,
	stackframe
};

struct DATA_CHUNK {
	DATA_TYPE data_type;
	ADDRINT base;
	ADDRINT size;
};

#define HIWORD(x) (((x) & 0xFFFF0000) >> 16)
#define LOWORD(x) ((x) & 0xFFFF)

#define M_PUT_ADDR_HASHMAP(hm, addr, type, v) \
	if (!hm[HIWORD(addr)]) { hm[HIWORD(addr)] = malloc(sizeof(type) * 0x10000); memset(hm[HIWORD(addr)], 0, sizeof(type) * 0x10000); } \
	((type*)hm[HIWORD(addr)])[LOWORD(addr)] = (type)(v);

#define M_GET_ADDR_HASHMAP(hm, addr, type, fallback) \
	((hm)[HIWORD(addr)] ? ((type*)((hm)[HIWORD(addr)]))[LOWORD(addr)] : (fallback) )

#define HG M_GET_ADDR_HASHMAP // (addr) Hashmap Get
#define HP M_PUT_ADDR_HASHMAP // (addr) Hashmap Put

/*
CALL_GET_ADDR_HASHMAP(ins, hm, addr, type, return_reg)
: add callback for getting value from hashmap
 ins : Instruction handle (INS)
 hm: Hashmap Pointer (HASHMAP?)
 addr: Hashmap Key(ADDRINT)
 type: Value type (any type)
 return_reg: PIN Register that stores value
*/
#define CALL_GET_ADDR_HASHMAP(ins, hm, addr, return_reg) \
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)get_addr_hashmap, IARG_PTR, hm, IARG_PTR, addr, IARG_RETURN_REGS, return_reg, IARG_END);

#define CALL_PUT_ADDR_HASHMAP(ins, hm, addr, v) \
	INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)if_sub_hashmap_exists, IARG_PTR, hm, IARG_PTR, addr, IARG_END); \
	INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)allocate_sub_hashmap, IARG_PTR, hm, IARG_PTR, addr, IARG_PTR, sizeof(ADDRINT), IARG_END); \
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)put_addr_hashmap, IARG_PTR, hm, IARG_PTR,  addr, IARG_PTR, v, IARG_END);

ADDRINT if_sub_hashmap_not_exists(ADDRINT hm, ADDRINT addr);
VOID allocate_sub_hashmap(ADDRINT hm, ADDRINT addr);
ADDRINT get_addr_hashmap(ADDRINT hm, ADDRINT addr, ADDRINT offset);
VOID put_addr_hashmap(ADDRINT hm, ADDRINT addr, ADDRINT offset, ADDRINT value);

typedef void** AHASHMAP;

void** create_addr_hashmap(int sz);

#endif