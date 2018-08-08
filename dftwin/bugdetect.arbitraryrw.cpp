#include "pin.H"
#include "bugdetect.h"
#include "libdft_api.h"
#include <iostream>

//extern REG thread_ctx_ptr;

#define push_reg(reg) INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_tree, \
   IARG_FAST_ANALYSIS_CALL, \
   IARG_REG_VALUE, thread_ctx_ptr, \
   IARG_UINT32, REG32_INDX(REG_FullRegName(reg)), \
   IARG_REG_VALUE, reg_thread_identifier, \
   IARG_UINT32, reg, \
   IARG_REG_VALUE, reg, \
   IARG_END); \
   cout << " " << REG_StringShort(reg);

#define check_it() INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_check_it, \
   IARG_FAST_ANALYSIS_CALL, \
   IARG_REG_VALUE, reg_thread_identifier, \
   IARG_INST_PTR, \
   IARG_END); \
   cout << endl;

VOID PIN_FAST_ANALYSIS_CALL
log_tree(thread_ctx_t *ctx, UINT32 indx, UINT32 thread_identifier, REG reg, ADDRINT value) {
   char write_buf[1 + sizeof(ADDRINT) * (3) + sizeof(UINT32) * (1)];
   PIN_LockClient();
   DTree *dt = ctx->vcpu.gpr_chunk[indx];
   write_buf[0] = 9;
   if(dt != 0)
      *(ADDRINT *)&write_buf[1] = dt->id;
   else
      *(ADDRINT *)&write_buf[1] = 0;
   *(UINT32 *)&write_buf[1 + sizeof(ADDRINT) * (1)] = thread_identifier;
   *(UINT32 *)&write_buf[1 + sizeof(ADDRINT) * (2)] = reg;
   *(ADDRINT *)&write_buf[1 + sizeof(ADDRINT) * (3)] = value;
   out->write(write_buf, sizeof(write_buf));
   PIN_UnlockClient();
}

VOID PIN_FAST_ANALYSIS_CALL
log_check_it(UINT32 thread_identifier, ADDRINT eip) {
   char write_buf[1 + sizeof(UINT32) + sizeof(ADDRINT)];
   PIN_LockClient();
   write_buf[0] = 8;
   *(UINT32 *)&write_buf[1] = thread_identifier;
   *(ADDRINT *)&write_buf[1 + sizeof(UINT32)] = eip;
   out->write(write_buf, sizeof(write_buf));
   PIN_UnlockClient();
}

namespace OSDEP {
    namespace W {
    #include <Windows.h>
    }
}

bool memory_readable(void *ptr, size_t byteCount)
{
  OSDEP::W::MEMORY_BASIC_INFORMATION mbi;
  if (OSDEP::W::VirtualQuery(ptr, &mbi, sizeof(OSDEP::W::MEMORY_BASIC_INFORMATION)) == 0)
    return false;

  if (mbi.State != MEM_COMMIT)
    return false;

  if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
    return false;

  // This checks that the start of memory block is in the same "region" as the
  // end. If it isn't you "simplify" the problem into checking that the rest of 
  // the memory is readable.
  size_t blockOffset = (size_t)((char *)ptr - (char *)mbi.AllocationBase);
  size_t blockBytesPostPtr = mbi.RegionSize - blockOffset;

  if (blockBytesPostPtr < byteCount)
    return memory_readable((char *)ptr + blockBytesPostPtr,
                           byteCount - blockBytesPostPtr);

  return true;
}

VOID PIN_FAST_ANALYSIS_CALL
memop(thread_ctx_t *ctx, UINT32 reg0, ADDRINT eip, ADDRINT access_addr, UINT32 sz)
{
	PIN_LockClient();
	if (ctx->vcpu.gpr_chunk[reg0] && !memory_readable((void *)access_addr, sz)) {
		report_bug(BUG_ARBITRARY_RW, 1, eip, ctx->vcpu.gpr_chunk[reg0]);
	}
	PIN_UnlockClient();
}

UINT32 REG_INDX_bugdetect(REG reg) {
    switch(REG_Size(reg)) {
    case 1: return REG8_INDX(reg);
    case 2: return REG16_INDX(reg);
    case 4: return REG32_INDX(reg);
    default: return REGFLOAT_INDX(reg);
    }
}

/* this logs memread/memwrite operations

ex)
mov [eax+ebx], ecx => log(eax, ebx, addressof "mov [eax+ebx], ecx")
add ecx, [eax+ebx*4], ecx => log(eax, ebx, addressof "add ecx, [eax+ebx*4]")
*/
VOID ARW_INSInst(INS ins) {
   UINT32 memopcount = INS_MemoryOperandCount(ins);
   /*for (int i = 0; i < opcount; i++) {
   	if (INS_OperandIsMemory(ins, i)) {
   		REG reg = INS_OperandMemoryBaseReg(ins, i);
   		if (reg != REG_INVALID()) push_reg(reg);
   		reg = INS_OperandMemoryIndexReg(ins, i);
   		if (reg != REG_INVALID()) push_reg(reg);
   	}
   }
   check_it();*/
   return;
   for (int memopindex = 0; memopindex < memopcount; memopindex++) {
 		REG reg;
    UINT32 opindex = INS_MemoryOperandIndexToOperandIndex(ins, memopindex);
 		if ((reg = INS_OperandMemoryBaseReg(ins, opindex)) != REG_INVALID())
   		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memop, IARG_FAST_ANALYSIS_CALL,
		   	IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, (UINT32)REG_INDX_bugdetect(reg), IARG_INST_PTR, IARG_MEMORYOP_EA, memopindex, IARG_UINT32, INS_MemoryOperandSize(ins, memopindex),
		   	IARG_END);
   	if ((reg = INS_OperandMemoryIndexReg(ins, opindex)) != REG_INVALID())
   		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memop, IARG_FAST_ANALYSIS_CALL,
		   	IARG_REG_VALUE, thread_ctx_ptr, IARG_UINT32, (UINT32)REG_INDX_bugdetect(reg), IARG_INST_PTR, IARG_MEMORYOP_EA, memopindex, IARG_UINT32, INS_MemoryOperandSize(ins, memopindex),
		   	IARG_END);
   }
   
}

VOID plugin_ArbitraryRW() {
   // ins_set_pre_all(ARW_INSInst);
}