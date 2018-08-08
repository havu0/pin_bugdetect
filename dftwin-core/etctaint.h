#ifndef __ETCTAINT_H__
#define __ETCTAINT_H__

#include "pin.H"
#include "libdft_core.h"
#include "tagmap.h"
#include "libdft_api.h"
#include "data_chunk.h"
#include "tracker.h"

VOID etctaint_etcTaintInit();
void
etcTaint_ins_inst(INS ins);
bool
etcTaint_ins_inst_real(INS ins);

static void etctaint_threadInit(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v);
ADDRINT PIN_FAST_ANALYSIS_CALL etctaint_init_reg_is_tainted();
ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_ifer(ADDRINT v);

extern REG reg_is_tainted;

#endif /* __ETCTAINT_H__ */