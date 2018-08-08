#include "bugdetect.h"

static ADDRINT PIN_FAST_ANALYSIS_CALL return_0()
{
	return 0;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL return_arg1(ADDRINT arg1)
{
	return arg1;
}

VOID checkIntegerOverflow(ADDRINT a) {

}

VOID IntegerOverflow_INSInst(INS ins) {
	UINT32 readRegOps = INS_MaxNumRRegs(ins);

	switch(INS_Opcode(ins)) {
		case XED_ICLASS_ADD:
		case XED_ICLASS_ADC:
		case XED_ICLASS_SUB:
		case XED_ICLASS_SBB:
		case XED_ICLASS_SHL:
		case XED_ICLASS_LEA:

		    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)return_arg1, IARG_FAST_ANALYSIS_CALL, 
    				IARG_REG_VALUE, reg_is_tainted, IARG_END);
		    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)report_bug, IARG_FAST_ANALYSIS_CALL, 
				IARG_PTR, BUG_INTEGER_OVERFLOW,
				IARG_PTR, 5,
				IARG_INST_PTR,
				IARG_REG_VALUE, cur_tree,
				IARG_END);
	}

}
VOID plugin_IntegerOverflow() {
	// INS_AddInstrumentFunction(IntegerOverflow_INSInst, 0);
	ins_set_pre_all(IntegerOverflow_INSInst);
}
