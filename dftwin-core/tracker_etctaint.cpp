#include "pin.H"
#include "tagmap.h"
#include "libdft_core.h"
#include "libdft_api.h"
#include "tracker_etctaint.h"
#include <set>
#include <iostream>

AHASHMAP data_chunk_hashmap;

REG cur_tree;
REG scratch_grp;
extern REG thread_ctx_ptr;
extern REG reg_is_tainted;
extern ostream *out;

extern ADDRINT cur_dtree_id;

char *dt_type_reversed[] = {"MEMORY", "REGISTER"};

AHASHMAP hm1; // hm1 : ptr to tree

static ADDRINT PIN_FAST_ANALYSIS_CALL return_0() 
{
    return 0;
}

VOID tracker_file_read(ADDRINT addr, USIZE len, ADDRINT start_offset)
{
    PIN_LockClient();
	char write_buf[17];
	write_buf[0] = 0xD;
	*(ADDRINT *)&write_buf[1] = addr;
	*(ADDRINT *)&write_buf[1 + sizeof(ADDRINT)] = len;
	*(ADDRINT *)&write_buf[1 + sizeof(ADDRINT) * 2] = cur_dtree_id + 1;
	*(ADDRINT *)&write_buf[1 + sizeof(ADDRINT) * 3] = start_offset;
	out->write(write_buf, 17);
    for (int i = 0; i < len; i++) {
        DTree *dt = new struct DTree;
		dt->magic = 2;
        dt->parent[0] = 0;
        dt->parent_id[0] = 0;
		dt->parents = 0;
        dt->type = DT_MEMORY;
        dt->id = ++cur_dtree_id;
        dt->eip = -1;
        out->write((char*)dt, sizeof(*dt));
        M_PUT_ADDR_HASHMAP(hm1, addr+i, ADDRINT, (ADDRINT)dt);
    }
    PIN_UnlockClient();
}

ADDRINT PIN_FAST_ANALYSIS_CALL memread(ADDRINT addr, UINT32 len, ADDRINT cur_tree, ADDRINT eip, THREADID tid)
{
    int i = 0;
    PIN_LockClient();

    DTree *p;
    while (i < len) {
        if (tagmap_getb(addr+i) && (p = M_GET_ADDR_HASHMAP(hm1, addr+i, DTree*, 0)) != 0) {
            DTree *dt = new DTree;
            /* it's not necessary.. */
            //dt->foffset = p->foffset;
            dt->type = DT_MEMORY;
            dt->parent[0] = (DTree*)cur_tree; dt->parent[1] = (DTree*)p;
            if (cur_tree) 
                dt->parent_id[0] = ((DTree*)cur_tree)->id;
            else
                dt->parent_id[0] = 0;
            dt->parent_id[1] = p->id; // p는 저 위에서 이미 체크됬음
            dt->id = ++cur_dtree_id;
            dt->eip = eip;

            out->write("\x0C", 1);
            out->write((const char*)&tid, sizeof(THREADID)); // typedef UINT32 THREADID

            cur_tree = (ADDRINT)dt;
        }
        i++;
    } 
    PIN_UnlockClient();
    return cur_tree;
}

VOID PIN_FAST_ANALYSIS_CALL memwrite(ADDRINT addr, USIZE len, ADDRINT cur_tree)
{
    int i = 0;
    PIN_LockClient();
    // 구현 개념 : 1. 해시맵에 addr을 key로 하는 DATA_CHUNK 구조체를 넣는다.
    //             2. 끝

    for(i = 0; i < len; i++) {
        M_PUT_ADDR_HASHMAP(hm1, addr + i, ADDRINT, cur_tree);
    }
    PIN_UnlockClient();
    // 뒷부분

    // 쓰기.
    
}

REG regindx32_to_reg(UINT32 indx)
{
	if(indx > 24) {
		// *out << "Unknown Register " << REG_StringShort(reg) << " " << reg << endl;
		return scratch_grp;
	} else if(indx > 16) {
		return (REG)(indx + REG_ST0 - 16);
	} else if(indx > 8) {
		return (REG)(indx + REG_XMM0 - 8);
	} else 
		return (REG)(indx + R32_ALIGN);
}

ADDRINT PIN_FAST_ANALYSIS_CALL regread(UINT32 reg, ADDRINT cur_tree, thread_ctx_t *ctx, ADDRINT eip, THREADID tid)
{
    PIN_LockClient();
    DTree *p;
    if (p = ctx->vcpu.gpr_chunk[reg]) {
        DTree *dt = new DTree;
        dt->type = DT_REGISTER;
        //dt->foffset = ctx->vcpu.gpr_chunk[reg]->foffset;
        dt->parent[0] = (DTree*)cur_tree; dt->parent[1] = (DTree*)p;
        if (cur_tree) 
            dt->parent_id[0] = ((DTree*)cur_tree)->id; 
        else
            dt->parent_id[0] = 0;
        dt->parent_id[1] = p->id; // p는 위에서 이미 체크됬음 
        dt->id = ++cur_dtree_id;
        dt->eip = eip;

        out->write("\x0C", 1);
        out->write((const char*)&tid, sizeof(THREADID)); // typedef UINT32 THREADID

        log_dtree(dt);

        cur_tree = (ADDRINT)dt;
    }
    PIN_UnlockClient();
    return cur_tree;
}

VOID PIN_FAST_ANALYSIS_CALL regwrite(UINT32 reg, DTree *cur_tree, thread_ctx_t *ctx)
{
    PIN_LockClient();
    ctx->vcpu.gpr_chunk[reg] = cur_tree;
    PIN_UnlockClient();
}

VOID log_memreg(thread_ctx_t *ctx, ADDRINT mem0, UINT32 mem0_len, ADDRINT mem1, UINT32 mem1_len, ADDRINT mem2, UINT32 mem2_len, THREADID tid, const CONTEXT *ctxt, UINT32 readRegs, ...)
{
    PIN_LockClient();
	DTree *mem0_tree, *mem1_tree, *mem2_tree;
	UINT32 reg;

    out->write("\x0C", 1);
    out->write((const char*)&tid, sizeof(THREADID)); // typedef UINT32 THREADID

	UINT32 eflags;
	PIN_GetContextRegval(ctxt, REG_EFLAGS, (UINT8*)&eflags);
	out->write("\x04", 1);
	out->write("\xAF", 1);
	out->write((char *)&eflags, 4);

	va_list regs;
	va_start(regs, readRegs);

    // log reg
    for (int reg = 0; reg < 24; reg++) {
		// reg = va_arg(regs, UINT32);
		CHAR size = REG_Size(regindx32_to_reg(reg));
        out->write("\x04", 1);
        out->write("\xAA", 1);
        out->write((const char*)&reg, 4); // assertion: sizeof(ADDRINT) == 4
        out->write((const char*)&size, 1);
		char *t = (char*)malloc(size);
        PIN_GetContextRegval(ctxt, regindx32_to_reg(reg), (UINT8 *)t);
        out->write((const char*)t, size);
		free(t);
        if (ctx->vcpu.gpr_chunk[reg]) {
			out->write("\x04", 1);
            out->write("\xAC", 1);
            out->write((const char*)&reg, 4); // assertion: sizeof(ADDRINT) == 4
            out->write((const char*)&ctx->vcpu.gpr_chunk[reg]->id, 4);
        }
    }
	if (mem0_len) {
		while(mem0_len--) {
			UINT32 tmp = 1;
			if (mem0_tree = M_GET_ADDR_HASHMAP(hm1, mem0, DTree *, 0)) {
				out->write("\x04", 1);
				out->write("\xAB", 1);
				out->write((char*)&mem0, 4);
				out->write((char*)&mem0_tree->id, 4);
			} else {
				char mem0_val[256];
				UINT32 mem0_real_len = PIN_SafeCopy(mem0_val, (void *)mem0, 1);
				out->write("\x04", 1);
				out->write("\xAD", 1);
				out->write((const char*)&mem0, 4); // assertion: sizeof(ADDRINT) == 4
				out->write((const char*)mem0_val, 1);
			}
			mem0++;
		}
	}
	if (mem1_len) {
		while(mem1_len--) {
			if (mem1_tree = M_GET_ADDR_HASHMAP(hm1, mem1, DTree *, 0)) {
				out->write("\x04", 1);
				out->write("\xAB", 1);
				out->write((char*)&mem1, 4);
				out->write((char*)&mem1_tree->id, 4);
			} else {
				char mem1_val[256];
				UINT32 mem1_real_len = PIN_SafeCopy(mem1_val, (void *)mem1, 1);
				out->write("\x04", 1);
				out->write("\xAD", 1);
				out->write((const char*)&mem1, 4); // assertion: sizeof(ADDRINT) == 4
				out->write((const char*)mem1_val, 1);
			}
			mem1++;
		}
	}

	if (mem2_len) {
		while(mem2_len--) {
			if (mem2_tree = M_GET_ADDR_HASHMAP(hm1, mem2, DTree *, 0)) {
				out->write("\x04", 1);
				out->write("\xAE", 1);
				out->write((char*)&mem2, 4);
				out->write((char*)&mem2_tree->id, 4);
			} else {
				char mem2_val[256];
				UINT32 mem2_real_len = PIN_SafeCopy(mem2_val, (void *)mem2, 1);
				out->write("\x04", 1);
				out->write("\xAD", 1);
				out->write((const char*)&mem2, 4); // assertion: sizeof(ADDRINT) == 4
				out->write((const char*)mem2_val, 1);
			}
			mem2++;
		}
	}

    PIN_UnlockClient();
}

VOID PIN_FAST_ANALYSIS_CALL 
log_branch(BOOL taken, THREADID tid)
{
	PIN_LockClient();
	char write_buf[6];
	write_buf[0] = 5;
	*(ADDRINT *)&write_buf[1] = tid;
	write_buf[5] = taken;
	out->write(write_buf, 6);
	PIN_UnlockClient();
}

ADDRINT inst_cb_ifer(ADDRINT arg) {
    return arg;
}

static void tracker_thread_init(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
    PIN_LockClient();
    PIN_SetContextReg(ctx, cur_tree, 0);
	/*
    out->write("\x06", 1);
    out->write((const char*)&tid, 4);
    OS_THREAD_ID os_tid = PIN_GetTid();
    out->write((const char*)&os_tid, 4);*/
    PIN_UnlockClient();
}


UINT32 REG_INDX(REG reg) {
    switch(REG_Size(reg)) {
    case 1: return REG8_INDX(reg);
    case 2: return REG16_INDX(reg);
    case 4: return REG32_INDX(reg);
    default: return REGFLOAT_INDX(reg);
    }
}

VOID PIN_FAST_ANALYSIS_CALL process_info(THREADID tid, ADDRINT eip) {
	char write_buf[5];
	write_buf[0] = 0x0E;
	*(ADDRINT *)&write_buf[1] = tid;
	*(ADDRINT *)&write_buf[5] = eip;
	PIN_LockClient();
	out->write(write_buf,9);
	PIN_UnlockClient();
}

VOID tracker_ins_inst(INS ins, VOID *v)
{
	return;
    /*
        first of all, zero cur_tree. if tainted mem/reg is available, cur_tree = (ptr to tree)
    */
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)return_0, 
        IARG_FAST_ANALYSIS_CALL, IARG_RETURN_REGS, cur_tree,
        IARG_END);
    // read (mem/reg)

    if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memread, 
            IARG_FAST_ANALYSIS_CALL, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_REG_VALUE, cur_tree, IARG_INST_PTR, IARG_THREAD_ID, IARG_RETURN_REGS, cur_tree,
            IARG_END);
    }
    
    int readRegOps = INS_MaxNumRRegs(ins);
    int writeRegOps = INS_MaxNumWRegs(ins);
    UINT i;

    
    for (i = 0; i < readRegOps; i++) {
        REG reg = INS_RegR(ins, i);
        UINT32 reg_indx;
        if (REG_is_seg(reg)) continue;
        if (reg == REG_ESP || reg == REG_EIP || reg == REG_EFLAGS || reg == REG_X87) continue;
        reg_indx = REG_INDX(reg);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)regread, 
            IARG_FAST_ANALYSIS_CALL, IARG_UINT32, reg_indx, IARG_REG_VALUE, cur_tree, IARG_RETURN_REGS, cur_tree, IARG_REG_VALUE, thread_ctx_ptr, IARG_INST_PTR, IARG_THREAD_ID,
            IARG_END);
    }
    // write (mem/reg)


    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memwrite, 
            IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_REG_VALUE, cur_tree, 
            IARG_END);
    }
    for (i = 0; i < writeRegOps; i++) {
        REG reg = INS_RegW(ins, i);
        UINT32 reg_indx;
        if (REG_is_seg(reg)) continue;
        if (reg == REG_ESP || reg == REG_EIP || reg == REG_EFLAGS || reg == REG_X87) continue;
        reg_indx = REG_INDX(reg);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)regwrite, 
            IARG_FAST_ANALYSIS_CALL, IARG_UINT32, reg_indx, IARG_REG_VALUE, cur_tree, IARG_REG_VALUE, thread_ctx_ptr, 
            IARG_END);
    }
}

void tracker_ins_logger(INS ins) {

	if(INS_SegmentPrefix(ins) && INS_SegmentRegPrefix(ins) >= REG_SEG_FS) return;

	
	//INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_REG_VALUE, cur_tree, IARG_END);
    //INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)print_offset_tree, IARG_REG_VALUE, cur_tree, IARG_END);
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_REG_VALUE, reg_is_tainted, IARG_END);
    IARGLIST iarglist = IARGLIST_Alloc();
    if (INS_IsMemoryRead(ins)) {
        IARGLIST_AddArguments(iarglist, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    } else {
        IARGLIST_AddArguments(iarglist, IARG_ADDRINT, (ADDRINT)0, IARG_UINT32, (UINT32)0, IARG_END);
    }
    if (INS_HasMemoryRead2(ins)) {
        IARGLIST_AddArguments(iarglist, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    } else {
        IARGLIST_AddArguments(iarglist, IARG_ADDRINT, (ADDRINT)0, IARG_UINT32, (UINT32)0, IARG_END);
    }

	if (INS_IsMemoryWrite(ins)) {
		IARGLIST_AddArguments(iarglist, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
	} else {
		IARGLIST_AddArguments(iarglist, IARG_ADDRINT, (ADDRINT)0, IARG_UINT32, (UINT32)0, IARG_END);
	}

	UINT32 readRegs = INS_MaxNumRRegs(ins);

	for(int i = 0; i < readRegs; i++) {
		REG reg = INS_RegR(ins, i);
		if(!(reg != REG_X87 && !REG_is_seg(reg) && reg != REG_EIP && REG_INDX(reg) != GRP_NUM)) {
			readRegs--;
			i--;
		}
	}

	IARGLIST_AddArguments(iarglist, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);;
	IARGLIST_AddArguments(iarglist, IARG_UINT32, readRegs, IARG_END);
	readRegs = INS_MaxNumRRegs(ins);
	for(int i = 0; i < readRegs; i++) {
		REG reg = INS_RegR(ins, i);
		if(reg != REG_X87 && !REG_is_seg(reg) && reg != REG_EIP && REG_INDX(reg) != GRP_NUM)
			IARGLIST_AddArguments(iarglist, IARG_UINT32, REG_INDX(reg), IARG_END);
	}

    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)log_memreg,
        IARG_REG_VALUE, thread_ctx_ptr, IARG_IARGLIST, iarglist, IARG_END);
    IARGLIST_Free(iarglist);

    // branch
    if (INS_IsBranchOrCall(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_branch, IARG_FAST_ANALYSIS_CALL, IARG_BRANCH_TAKEN, IARG_THREAD_ID, IARG_END);

	INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_REG_VALUE, reg_is_tainted, IARG_END);
	INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)process_info, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);

}

int tracker_init()
{

    if ((cur_tree = PIN_ClaimToolRegister()) == REG_INVALID() ||
        (scratch_grp = PIN_ClaimToolRegister()) == REG_INVALID()) {
        exit(1);
    }
    hm1 = create_addr_hashmap(0);
    PIN_AddThreadStartFunction(tracker_thread_init, 0);
    return 0;
}


