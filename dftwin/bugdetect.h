#ifndef __BUGDETECT_H__
#define __BUGDETECT_H__

#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "tagmap.h"
#include "tracker_etctaint.h"
#include "etctaint.h"
#include "libdft-dta.h"
#include <list>
#include <set>
VOID init_bugdetect();
extern REG thread_ctx_ptr;
extern REG GLOB(counter);
extern std::ostream *out;
extern bool GLOB(now_tainting);

extern AHASHMAP hm1;

typedef enum {
   BUG_FORMAT_STRING_BUG,
   BUG_USE_AFTER_FREE,
   BUG_TAINTED_EIP,
   BUG_INVALID_FREE_POINTER,
   BUG_POTENTIAL_USE_AFTER_FREE,
   BUG_INTEGER_OVERFLOW,
   BUG_POTENTIAL_BUFFER_OVERFLOW,
   BUG_BUFFER_OVERFLOW,
   BUG_RACE_CONDITION,
   BUG_COMMAND_INJECTION,
   BUG_ARBITRARY_RW,
} BUG_CLASSES;

VOID plugin_IntegerOverflow();
VOID plugin_FormatStringBug();
VOID plugin_BufferOverflow();
VOID plugin_TaintedEIP();
VOID plugin_RaceCondition();
VOID plugin_CommandInjection();
VOID plugin_ArbitraryRW();
VOID PIN_FAST_ANALYSIS_CALL report_bug(ADDRINT msg, UINT32 level, ADDRINT eip, DTree *cur_tree);

#define Hooker(name, when) name##when
#define QUOTE(a) #a
#define Hook2(name, cb, when, ...) \
	rtn = RTN_FindByName(img, name); \
if (RTN_Valid(rtn)) {\
 RTN_Open(rtn); \
    RTN_InsertCall(rtn, when, (AFUNPTR)cb, __VA_ARGS__, IARG_END); \
    RTN_Close(rtn); \
}

struct HEAP_INFO {
	bool freed;
	ADDRINT base;
	ADDRINT size;
	INT64 refcount;
};

extern REG reg_is_tainted_bugdetect;

extern AHASHMAP UAF_heap_hashmap;

#endif /* __BUGDETECT_H__ */