#include "etctaint.h"

REG reg_is_tainted;
extern REG thread_ctx_ptr;
extern REG GLOB(counter);
extern ostream *out;
static char *indx_reversed[] = {"EDI", "ESI", "EBP", "ESP", "EBX", "EDX", "ECX", "EAX",
"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
"ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7", "PIN_REG"};

static void etctaint_threadInit(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	PIN_SetContextReg(ctx, reg_is_tainted, 0);
}

// should be inlined
// IARG: IARG_FAST_ANALYSIS_CALL, IARG_RETURN_REGS, reg_is_tainted
ADDRINT PIN_FAST_ANALYSIS_CALL etctaint_init_reg_is_tainted()
{
	return 0;
}

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_ifer(ADDRINT v)
{
	return v;
}

VOID taint_all(ADDRINT instruction, thread_ctx_t *thread_ctx, ADDRINT is_tainted, ADDRINT writeMem, UINT32 szMem, UINT32 n, ...)
{
    va_list vl;
    va_start(vl, n);
	// *out << "TAINT_ALL: " << hex << instruction << " / is_tainted: " << is_tainted << endl;
    //assert(n % 2 == 0);

    if (writeMem) {
		// *out << writeMem << " ";
		if(is_tainted)
			tagmap_setn(writeMem, szMem);
		else
			tagmap_clrn(writeMem, szMem);
	}

    for (UINT i = 0; i < n; i++) {
        ADDRINT dest_val = (ADDRINT)va_arg(vl, ADDRINT);
        UINT32 szor = (UINT32)va_arg(vl, UINT32);
		// if(is_tainted) *out << indx_reversed[dest_val] << " ";
        r_setsz(thread_ctx, dest_val, (size_t)szor & is_tainted);

    }
	// *out << "will be tainted" << endl;

    va_end(vl);

    return;

}

bool
etcTaint_ins_inst_real(INS ins)
{

    int readRegOps = INS_MaxNumRRegs(ins);
	int writeRegOps = INS_MaxNumWRegs(ins);
    int i;
	bool is_etctaint = 0;

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)etctaint_init_reg_is_tainted,
			IARG_FAST_ANALYSIS_CALL, IARG_RETURN_REGS, reg_is_tainted, IARG_END);

	/*
	for(i = 0; i < readRegOps; i++) {
		if(REG_Size(INS_RegR(ins, i)) >= 8)
			is_etctaint = 1;
	}
	for(i = 0; i < writeRegOps; i++) {
		if(REG_Size(INS_RegW(ins, i)) >= 8)
			is_etctaint = 1;
	}
	if(INS_IsMemoryRead(ins) && (INS_MemoryReadSize(ins) >= 8)) {
		is_etctaint = 1;
	}
	if(INS_IsMemoryWrite(ins) && (INS_MemoryWriteSize(ins) >= 8))
		is_etctaint = 1;

	*/
    // if (INS_RepPrefix(ins)) return is_etctaint;
	// if (INS_RepnePrefix(ins)) return is_etctaint;

	bool ismemread = false;
	if (INS_IsMemoryRead(ins) || INS_HasMemoryRead2(ins)) ismemread = true;

	// *out << "what!!! " << INS_Disassemble(ins) << " yoyoyo " << ismemread << endl;
		//if(INS_IsMemoryRead(ins) && INS_Disassemble(ins).find("xmm") != string::npos) {
		
	//}

	for (i = 0; i < readRegOps; i++) {
    	REG reg = INS_RegR(ins, i);
		if (REG_is_seg(reg)) continue;
    	if (reg == REG_ESP || reg == REG_EIP || reg == REG_EFLAGS || reg == REG_X87) continue;
    	// not support more than 4 byte
		switch (REG_Size(reg)) {
    		case 1:
    			if (REG_is_Upper8(reg))
        			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_u_or, IARG_FAST_ANALYSIS_CALL,
        				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
        				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
        		else
        			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_l_or, IARG_FAST_ANALYSIS_CALL,
        				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
        				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
    		case 2:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getw_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG16_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
    		case 4:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getl_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG32_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
			case 8:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getq_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REGFLOAT_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
				break;
			case 16:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_gethex_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REGFLOAT_INDX(reg), IARG_REG_VALUE, reg_is_tainted,
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
				is_etctaint = 1;
    		default:
				is_etctaint = 1;
				break;
    	}
	}

	if (INS_IsMemoryRead(ins)) {
    	switch (INS_MemoryReadSize(ins)) {
    		case 1:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getb_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_MEMORYREAD_EA, IARG_REG_VALUE, reg_is_tainted, 
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
    		case 2:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getw_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_MEMORYREAD_EA, IARG_REG_VALUE, reg_is_tainted, 
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;													
    		case 4:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getl_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_MEMORYREAD_EA, IARG_REG_VALUE, reg_is_tainted, 
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
    		case 8:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getq_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_MEMORYREAD_EA, IARG_REG_VALUE, reg_is_tainted, 
    				IARG_RETURN_REGS, reg_is_tainted, IARG_END);
    			break;
    		case 16:
    		default:
    			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_issetn_or, IARG_FAST_ANALYSIS_CALL,
    				IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_REG_VALUE, reg_is_tainted, IARG_RETURN_REGS, reg_is_tainted,
    				IARG_END);
				is_etctaint = 1;
    			break;
    	}
	}

	return is_etctaint;
		// now writ
}

VOID etcTaint_ins_inst(INS ins) {
	UINT32 writeRegOps = INS_MaxNumWRegs(ins);
    IARGLIST arg_reg_list = IARGLIST_Alloc();
    
    UINT32 inserted_wregops = 0;
    for (UINT32 i = 0; i < writeRegOps; i++) {
    	REG reg = INS_RegW(ins, i);
		if (REG_is_seg(reg)) continue;
		if (reg == REG_ESP || reg == REG_EIP || reg == REG_EFLAGS || reg == REG_X87) continue;
    	UINT32 szor;
    	size_t regval;
    	switch (REG_Size(reg)) {
    		case 1:
    			regval = REG8_INDX(reg);
    			if (REG_is_Upper8(reg)) {
        			szor = VCPU_MASK8 << 1;
        		} else {
        			szor = VCPU_MASK8;
        		}
    			break;
    		case 2:
    			regval = REG16_INDX(reg);
        		szor = VCPU_MASK16;
    			break;
    		case 4:
    			regval = REG32_INDX(reg);
        		szor = VCPU_MASK32;
    			break;
			case 8:
				regval = REGFLOAT_INDX(reg); // user-defined
				szor = VCPU_MASK64;
				break;
			case 16:
				regval = REGFLOAT_INDX(reg);
				szor = VCPU_MASK128;
				break;
    		default:
				regval = 24;
				szor = 0;
				break;
    	}
        IARGLIST_AddArguments(arg_reg_list, IARG_ADDRINT, regval, IARG_UINT32, szor, IARG_END);
        inserted_wregops++;
    }

    if (INS_IsMemoryWrite(ins)) 
    	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taint_all,
			IARG_INST_PTR, IARG_REG_VALUE, thread_ctx_ptr, IARG_REG_VALUE, reg_is_tainted,
        	IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_UINT32, inserted_wregops, IARG_IARGLIST, arg_reg_list, IARG_END);
	else
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taint_all,
			IARG_INST_PTR, IARG_REG_VALUE, thread_ctx_ptr, IARG_REG_VALUE, reg_is_tainted,
        	IARG_ADDRINT, (ADDRINT)0, IARG_UINT32, (UINT32)0, IARG_UINT32, inserted_wregops, IARG_IARGLIST, arg_reg_list, IARG_END);
	
    IARGLIST_Free(arg_reg_list);
}
VOID etctaint_etcTaintInit()
{
	reg_is_tainted = PIN_ClaimToolRegister();

	PIN_AddThreadStartFunction(etctaint_threadInit, 0);
}