/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in October 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * TODO:
 * 	- add support for file descriptor duplication via fcntl(2)
 * 	- add support for non PF_INET* sockets
 * 	- add support for recvmmsg(2)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>
#include <fstream>

#include <set>

#include <assert.h>

#include "bugdetect.h"
#include "filter_.H"
#include "knob.h"
#include "libdft-dta.h"

 extern "C" {
    #include "xed-interface.h"
    #include "xed-flags.h"
    #include "xed-types.h"
    #include "xed-portability.h"
    #include "xed-flag-enum.h"
    #include "xed-flag-action-enum.h"
    #include "xed-gen-table-defs.h"
}
#define WORD_LEN	4	/* size in bytes of a word value */
#define SYS_SOCKET	1	/* socket(2) demux index for socketcall */

/* default path for the log file (audit) */
#define LOGFILE_DFL	"libdft-dta.log"

/* default suffixes for dynamic shared libraries */
#define DLIB_SUFF	".so"
#define DLIB_SUFF_ALT	".so."

#define uint32_t unsigned int

std::ostream * out = &cerr;
std::vector<std::string> trackNames;

/* thread context */
extern REG thread_ctx_ptr;
extern REG reg_is_tainted;

REG reg_thread_identifier;
UINT32 max_thread_identifier = 0;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

extern FILTER GLOB(filter);

extern PIN_LOCK rmInst_Lock;

xed_state_t GLOB(xedstate);



/* set of interesting descriptors (sockets) */
static set<int> fdset;

REG GLOB(counter);
REG GLOB(counter_tmp);
REG GLOB(reg_eachsysc);
REG GLOB(reg_taintstat_readtainted);

bool GLOB(now_tainting) = false;

static UINT64 GLOB(counter_tainted) = 0;
static UINT64 GLOB(tainted_sblock_count) = 0;
static unsigned int GLOB(counter_tainted_mem) = 0;

/*
 * flag variables
 *
 * 0	: feature disabled
 * >= 1	: feature enabled
 */ 

/* track stdin (enabled by default) */
//static KNOB<size_t> sin(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "");

/* track fs (enabled by default) */
static KNOB<size_t> fs(KNOB_MODE_WRITEONCE, "pintool", "f", "1", "");

/* track net (enabled by default) */
//static KNOB<size_t> net(KNOB_MODE_WRITEONCE, "pintool", "n", "1", "");

static KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "l",
		"", "");

static KNOB<string> trackpath(KNOB_MODE_WRITEONCE, "pintool", "T",
		"a.hwp", "");
static char *indx_reversed[] = {"EDI", "ESI", "EBP", "ESP", "EBX", "EDX", "ECX", "EAX",
"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
"ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7", "PIN_REG"};

void PIN_FAST_ANALYSIS_CALL
log_assembly(ADDRINT addr, CHAR *assembly, thread_ctx_t* thread_ctx)  {
	if(1) {
		*out << "Tainted: ";
		for(int i = 0; i <= GRP_NUM; i++) { // includes scratch register
			if(thread_ctx->vcpu.gpr[i]) *out << " [" << indx_reversed[i] << "]";
		}
		*out << "\n";
	}
	*out << " [" << hex << addr << "] " << assembly << endl;
}

/*
 * 32-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg32(thread_ctx_t *thread_ctx, uint32_t reg, uint32_t addr)
{
	/* 
	 * combine the re gister tag along with the tag
	 * markings of the target address
	 */
	return thread_ctx->vcpu.gpr[reg] | tagmap_getl(addr);
}

/*
 * 16-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg16(thread_ctx_t *thread_ctx, uint32_t reg, uint32_t addr)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return (thread_ctx->vcpu.gpr[reg] & VCPU_MASK16)
		| tagmap_getw(addr);
}

/*
 * 32-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem32(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getl(paddr) | tagmap_getl(taddr);
}

/*
 * 16-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem16(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getw(paddr) | tagmap_getw(taddr);
}

/*
 * instrument the jmp/call instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
		}
		else {
		/* call via memory */
			/* size analysis */
				
			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before branch;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before branch;
		 * conditional instrumentation -- then
		 */
	}
}

/*
 * read(2) handler (taint-source)
 */
static void
post_read_hook(void *ctx)
{
        
}

/*
 * readv(2) handler (taint-source)
 */
static void
post_readv_hook(void *ctx)
{
	
}

/*
 * socketcall(2) handler
 *
 * attach taint-sources in the following
 * syscalls:
 * 	socket(2), accept(2), recv(2),
 * 	recvfrom(2), recvmsg(2)
 *
 * everything else is left intact in order
 * to avoid taint-leaks
 */
static void
post_socketcall_hook(void *ctx)
{
	
}

/*
 * auxiliary (helper) function
 *
 * duplicated descriptors are added into
 * the monitored set
 */
static void
post_dup_hook(void *ctx)
{
	
}

/*
 * auxiliary (helper) function
 *
 * whenever close(2) is invoked, check
 * the descriptor and remove if it was
 * inside the monitored set of descriptors
 */
static void
post_close_hook(void *ctx)
{

}

/*
 * auxiliary (helper) function
 *
 * whenever open(2)/creat(2) is invoked,
 * add the descriptor inside the monitored
 * set of descriptors
 *
 * NOTE: it does not track dynamic shared
 * libraries
 */
static void
post_open_hook(void *ctx)
{

}

string disassemble(ADDRINT addrins, UINT32 szinst)
{
    char disbuf[128];
    stringstream strstream;
    xed_decoded_inst_t t;
    xed_decoded_inst_zero_set_mode(&t, &GLOB(xedstate));
    //xed_decoded_inst_zero(&xedd);
    //xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
    xed_error_enum_t e;
    if ((e = xed_decode(&t, XED_STATIC_CAST(const xed_uint8_t*,addrins), szinst)) != XED_ERROR_NONE) {
        strstream << "!!!decode failure: " << xed_error_enum_t2str(e);
    } else {
        if (!xed_format_intel(&t, disbuf, sizeof(disbuf), addrins))
            strstream << "!!!DISASM FAIL, xed_format_intel!";
        else
            strstream << disbuf;
    }
    return strstream.str();
}

static void 
InstrInstruction(INS ins, void *v)
{
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_double_ifer(ADDRINT counter_tmp, ADDRINT reg_es)
{
	return counter_tmp | reg_es;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
inc_sblock_count()
{
	GLOB(tainted_sblock_count)++;
	return 0;
}

static void PIN_FAST_ANALYSIS_CALL
inc_tainted_count()
{
	GLOB(counter_tainted)++;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
not_true(ADDRINT x)
{
	return !x;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
ifer_not_and_true(ADDRINT x, ADDRINT y)
{
	return (!x) | y;
}

static void
custom_trace_inspect(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;
	xed_iclass_enum_t ins_indx;

	if (!GLOB(filter).SelectTrace(trace))
        return;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
			INS_Valid(ins);
			ins = INS_Next(ins)) {
				/*
				* use XED to decode the instruction and
				* extract its opcode
				*/
				ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

				if (INS_IsMemoryWrite(ins)) {
					switch (INS_MemoryWriteSize(ins)) {
						case 1:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 2:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 4:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 8:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;

						case 16:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						default:
							LOG( "non 1/2/4/8 byte memw write found! size : " + decstr(INS_MemoryWriteSize(ins)) + "\n" );
							PIN_WriteErrorMessage("non 1/2/4/8 byte memw write found! size : ", 101, PIN_ERR_FATAL, 0);
					}
					/*INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_last, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter), IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter),
								IARG_END);*/
					/*INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_double_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), IARG_REG_VALUE, GLOB(reg_eachsysc),
								IARG_END);
					// inc GLOB(tainted_sblock_count) only if GLOB(counter_tmp) != 0 AND GLOB(reg_eachsysc) == 1
					INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inc_sblock_count, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_RETURN_REGS, GLOB(reg_eachsysc),
								IARG_END);*/
					INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_double_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), IARG_REG_VALUE, GLOB(reg_eachsysc),
								IARG_END);
					// inc GLOB(tainted_sblock_count) only if GLOB(counter_tmp) != 0 AND GLOB(reg_eachsysc) == 1
					INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inc_sblock_count, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_RETURN_REGS, GLOB(reg_eachsysc),
								IARG_END);
					
				}

		}
	}
}

static void
custom_trace_inspect_chk_if_tainting_eff(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;
	xed_iclass_enum_t ins_indx;

	if (!GLOB(filter).SelectTrace(trace))
        return;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
			INS_Valid(ins);
			ins = INS_Next(ins)) {

	            int readRegOps = INS_MaxNumRRegs(ins);
	            int writeRegOps = INS_MaxNumWRegs(ins);

	            int i;
	            // very slow case?
	            if (INS_RepPrefix(ins)) continue;

	            for (i = 0; i < writeRegOps; i++) {
	            	REG reg = INS_RegW(ins, i);
	            	if (REG_Size(reg) > 4 || reg == REG_ESP) continue;
	        		switch (REG_Size(reg)) {
	            		case 1:
	            			if (REG_is_Upper8(reg))
		            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_u_or, IARG_FAST_ANALYSIS_CALL,
		            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
		            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
		            		else
		            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_l_or, IARG_FAST_ANALYSIS_CALL,
		            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
		            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 2:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getw_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG16_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 4:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getl_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG32_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		default: break;
	            	}
	            }

	            for (i = 0; i < readRegOps; i++) {
	            	REG reg = INS_RegR(ins, i);
	            	if (REG_Size(reg) > 4 || reg == REG_ESP) continue;
	        		switch (REG_Size(reg)) {
	            		case 1:
	            			if (REG_is_Upper8(reg))
		            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_u_or, IARG_FAST_ANALYSIS_CALL,
		            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
		            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
		            		else
		            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getb_l_or, IARG_FAST_ANALYSIS_CALL,
		            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG8_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
		            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 2:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getw_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG16_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 4:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_getl_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, REG32_INDX(reg), IARG_REG_VALUE, GLOB(reg_taintstat_readtainted),
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		default: break;
	            	}
	            }

	            if (INS_IsMemoryWrite(ins) && INS_MemoryWriteSize(ins) <= 8) {
	            	switch (INS_MemoryWriteSize(ins)) {
	            		case 1:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getb_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(reg_taintstat_readtainted), 
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 2:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getw_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(reg_taintstat_readtainted), 
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 4:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getl_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(reg_taintstat_readtainted), 
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		case 8:
	            			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_getq_or, IARG_FAST_ANALYSIS_CALL,
	            				IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(reg_taintstat_readtainted), 
	            				IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            			break;
	            		default: break;
	            		//case 16:
	            		//default:
	            		//	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_issetn, IARG_FAST_ANALYSIS_CALL,
	            		//		IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_RETURN_REGS, GLOB(reg_taintstat_readtainted), IARG_END);
	            		//	break;
	            	}
	            }

		}
	}
}


static void
custom_trace_inspect_dcounting(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;
	xed_iclass_enum_t ins_indx;

	if (!GLOB(filter).SelectTrace(trace))
        return;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
			INS_Valid(ins);
			ins = INS_Next(ins)) {
				/*
				* use XED to decode the instruction and
				* extract its opcode
				*/
				ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

				INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								
								IARG_END);

				if (INS_IsMemoryWrite(ins)) {
					switch (INS_MemoryWriteSize(ins)) {
						case 1:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 2:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 4:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 8:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;

						case 16:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						default:
							LOG( "non 1/2/4/8 byte memw write found! size : " + decstr(INS_MemoryWriteSize(ins)) + "\n" );
							PIN_WriteErrorMessage("non 1/2/4/8 byte memw write found! size : ", 101, PIN_ERR_FATAL, 0);
					}
					/*INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_last, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter), IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter),
								IARG_END);*/
					/*INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_double_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), IARG_REG_VALUE, GLOB(reg_eachsysc),
								IARG_END);
					// inc GLOB(tainted_sblock_count) only if GLOB(counter_tmp) != 0 AND GLOB(reg_eachsysc) == 1
					INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inc_sblock_count, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_RETURN_REGS, GLOB(reg_eachsysc),
								IARG_END);*/
					INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
					// inc GLOB(tainted_sblock_count) only if GLOB(counter_tmp) != 0 AND GLOB(reg_eachsysc) == 1
					INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inc_tainted_count, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_END);
					
				}

		}
	}
}

char *strdup (const char *s) {
    char *d = new char[strlen (s) + 1];   // Allocate memory
    if (d != NULL) strcpy (d,s);         // Copy string if okay
    return d;                            // Return new memory
}

void
custom_trace_inspect_count_tainted_mem(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl; 
	INS ins;
	xed_iclass_enum_t ins_indx;

	if (!GLOB(filter).SelectTrace(trace))
        return;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
			INS_Valid(ins);
			ins = INS_Next(ins)) {

				/*
				INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, reg_is_tainted, IARG_END);
				INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)log_assembly, IARG_FAST_ANALYSIS_CALL,
					IARG_INST_PTR, IARG_PTR, strdup(INS_Disassemble(ins).c_str()), IARG_END);
				*/
				continue;
				/*
				* use XED to decode the instruction and
				* extract its opcode
				*/
				ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

				if (INS_IsMemoryWrite(ins)) {
					switch (INS_MemoryWriteSize(ins)) {
						case 1:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingb_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 2:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingw_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 4:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingl_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						case 8:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;

						case 16:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_before, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_MEMORYWRITE_EA, IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_FIRST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
							INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_countingdq_after, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_MEMORYWRITE_EA, IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter_tmp),
								IARG_END);
							break;
						default:
							LOG( "non 1/2/4/8 byte memw write found! size : " + decstr(INS_MemoryWriteSize(ins)) + "\n" );
							PIN_WriteErrorMessage("non 1/2/4/8 byte memw write found! size : ", 101, PIN_ERR_FATAL, 0);
					}
					/*INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_last, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter), IARG_REG_VALUE, GLOB(counter_tmp), IARG_RETURN_REGS, GLOB(counter),
								IARG_END);*/
					/*INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_double_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), IARG_REG_VALUE, GLOB(reg_eachsysc),
								IARG_END);
					// inc GLOB(tainted_sblock_count) only if GLOB(counter_tmp) != 0 AND GLOB(reg_eachsysc) == 1
					INS_InsertThenCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inc_sblock_count, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_RETURN_REGS, GLOB(reg_eachsysc),
								IARG_END);*/
					INS_InsertIfCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)inst_cb_counting_ifer, IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER, CALL_ORDER_LAST,
								IARG_REG_VALUE, GLOB(counter_tmp), 
								IARG_END);
					
				}

		}
	}
}

VOID init_global_xed()
{
    xed_tables_init();
    xed_state_zero(&GLOB(xedstate));
    xed_state_init2(&GLOB(xedstate), XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
}

static void dta_init()
{
	if (unlikely(
		(GLOB(counter) = PIN_ClaimToolRegister()) == REG_INVALID() /*||
		(GLOB(counter_tmp) = PIN_ClaimToolRegister()) == REG_INVALID() ||
		(GLOB(reg_eachsysc) = PIN_ClaimToolRegister()) == REG_INVALID() ||
		(GLOB(reg_taintstat_readtainted) = PIN_ClaimToolRegister()) == REG_INVALID()*/
		)) {
			/* error message */
			LOG(string(__FUNCTION__) + ": dta register claim failed\n");

			/* failed */
			exit(EXIT_FAILURE);
	}
}

static void
thread_init(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	PIN_SetContextReg(ctx, GLOB(reg_eachsysc), 0);
	PIN_SetContextReg(ctx, GLOB(counter), 0);
    PIN_SetContextReg(ctx, GLOB(counter_tmp), 0);
    PIN_SetContextReg(ctx, GLOB(reg_taintstat_readtainted), 0);
}

VOID
taint_log(INS ins, VOID *v) {
	IMG img;
#define XMM_DEBUG 0
#if XMM_DEBUG != 0
	if(IMG_Valid(img = IMG_FindByAddress(INS_Address(ins)))) {
		if(IMG_IsMainExecutable(img) == true) {
			string additionalInfo = "RR :";
			int readRegOps = INS_MaxNumRRegs(ins);
			int writeRegOps = INS_MaxNumWRegs(ins);
			int i;
			for(i = 0; i < readRegOps; i++) {
				additionalInfo += " ";
				additionalInfo += REG_StringShort(INS_RegR(ins, i));
			}
			additionalInfo += " / WR:";
			for(i = 0; i < writeRegOps; i++) {
				additionalInfo += " ";
				additionalInfo += REG_StringShort(INS_RegW(ins, i));
			}
			if(INS_IsMemoryRead(ins)) {
				additionalInfo += " / READMEM: ";
				additionalInfo += to_string(INS_MemoryReadSize(ins));
			}
			if(INS_IsMemoryWrite(ins)) {
				additionalInfo += " / WRITEMEM: ";
				additionalInfo += to_string(INS_MemoryWriteSize(ins));
			}
			additionalInfo += "\n";
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_assembly, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_PTR, strdup((additionalInfo + INS_Disassemble(ins)).c_str()), IARG_REG_VALUE, thread_ctx_ptr, IARG_END);
		}
	}
	return;
#endif
#define IS_MAIN_EXECUTABLE (1) && IMG_IsMainExecutable(img)
#undef IS_MAIN_EXECUTABLE
#define IS_MAIN_EXECUTABLE 1
	string log("");
	if(IMG_Valid(img=IMG_FindByAddress(INS_Address(ins)))) {
		log += IMG_Name(img) + " :: ";
	};
	log += INS_Disassemble(ins);
	if (!INS_RepPrefix(ins) && IS_MAIN_EXECUTABLE) {
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, reg_is_tainted, IARG_END);
		INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)log_assembly, IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR, IARG_PTR, strdup(log.c_str()), IARG_REG_VALUE, thread_ctx_ptr, IARG_END);
	}
	return;
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

VOID ctx_chg(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
	(*out).flush();
}

VOID thread_start(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	UINT32 cur_thread_identifier = ++max_thread_identifier;
	PIN_SetContextReg(ctxt, reg_thread_identifier, cur_thread_identifier);
	// Thread ID Register Log
	// \x05: magic(1byte)
	// thread identifier for race condition(4byte)
	// real thread id(4byte)
	char write_buf[sizeof(UINT32) + sizeof(THREADID) + 1];
	write_buf[0] = 6;
	*(UINT32 *)&write_buf[1] = cur_thread_identifier;
	*(THREADID *)&write_buf[1 + sizeof(UINT32)] = threadid;
	out->write(write_buf, sizeof(write_buf));
}


/* 
 * DTA
 *
 * used for demonstrating how to implement
 * a practical dynamic taint analysis (DTA)
 * tool using libdft
 */
int
main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();

	string fileName;
	string trackName;
	char delim = ':';
	
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;

	fileName = logpath.Value();
	trackName = trackpath.Value();
	init_global_xed();
	GLOB(filter).Activate();
	
	if (!fileName.empty()) { out = new std::ofstream(fileName.c_str(), ofstream::binary);}
	if (!trackName.empty()) { trackNames = split(trackName, delim); };

	IMG_AddInstrumentFunction(Image, 0); // for os_win_apihook.cpp
	PIN_AddContextChangeFunction(ctx_chg, 0);
	init_bugdetect();
	reg_thread_identifier = PIN_ClaimToolRegister();

	PIN_InitLock(&rmInst_Lock);


	PIN_AddThreadStartFunction(thread_start, 0);
	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
