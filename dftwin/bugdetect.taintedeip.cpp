#include "bugdetect.h"

VOID TaintedEIP_INSInst(INS ins) {
	switch(INS_Category(ins)) {
	case XED_CATEGORY_CALL:
	case XED_CATEGORY_UNCOND_BR:
	case XED_CATEGORY_COND_BR:
		INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg_is_tainted, IARG_END);
		INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)report_bug, IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BUG_TAINTED_EIP, IARG_UINT32, 10, IARG_INST_PTR, IARG_REG_VALUE, cur_tree, IARG_END);
		break;
	}
}

VOID plugin_TaintedEIP() {
	ins_set_pre_all(TaintedEIP_INSInst);
}