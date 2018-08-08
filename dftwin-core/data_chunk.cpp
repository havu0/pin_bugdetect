#include "pin.H"
#include "data_chunk.h"

void** create_addr_hashmap(int sz)
{
	void **ret = (void**)calloc(1, 4 * 0x10000);;
	return ret;
}

VOID* if_sub_hashmap_not_exists(VOID **hm, ADDRINT addr) {
	return hm[HIWORD(addr)];
}

VOID allocate_sub_hashmap(VOID **hm, ADDRINT addr, UINT32 type_size) {
	hm[HIWORD(addr)] = malloc(0x10000 * type_size);
}

ADDRINT get_addr_hashmap(ADDRINT **hm, ADDRINT addr, ADDRINT offset) {
	return hm[HIWORD(addr)][LOWORD(addr)];
}

VOID put_addr_hashmap(ADDRINT **hm, ADDRINT addr, ADDRINT offset, ADDRINT value) {
	hm[HIWORD(addr)][LOWORD(addr)] = value;
}