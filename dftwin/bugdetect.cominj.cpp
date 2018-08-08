#include "bugdetect.h"

VOID cmdBefore (ADDRINT fmt_ref, ADDRINT eip) {
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
VOID CommandInjection_IMGInst(IMG img, VOID *v) {
	RTN rtn;
	Hook2("system", cmdBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("popen", cmdBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
		IARG_RETURN_IP);
	Hook2("ShellExecute", cmdBefore, IPOINT_BEFORE,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_RETURN_IP);
}
VOID plugin_CommandInjection() {
	IMG_AddInstrumentFunction(CommandInjection_IMGInst, 0);
}
