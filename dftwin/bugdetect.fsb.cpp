#include "bugdetect.h"

VOID printfBefore (ADDRINT fmt_ref, ADDRINT eip) {
	int len = strlen((char*)fmt_ref);
	if (len <= 0) return;
	if (tagmap_issetn(fmt_ref, len)) {
		for(int i = 0; i < len; i++) {
			DTree *cur_tree = M_GET_ADDR_HASHMAP(hm1, fmt_ref + i, DTree *, 0);
			if(cur_tree) {
				report_bug(BUG_FORMAT_STRING_BUG, 10, eip, cur_tree);
				break;
			}
		}
	}

}
VOID FormatStringBug(IMG img, VOID *v) {
	RTN rtn;
	Hook2("printf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("fprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
		IARG_RETURN_IP);
	Hook2("snprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("sprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("vprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("vsprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("vsnprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("vfprintf", printfBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
		IARG_RETURN_IP);
}
VOID plugin_FormatStringBug() {
	IMG_AddInstrumentFunction(FormatStringBug, 0);
}
