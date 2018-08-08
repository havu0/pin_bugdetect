#include "bugdetect.h"

UINT32 total_score = 0;

VOID PIN_FAST_ANALYSIS_CALL report_bug(ADDRINT msg, UINT32 level, ADDRINT eip, DTree *cur_tree) {
	struct {
		ADDRINT bug_class;
		ADDRINT level;
		ADDRINT eip;
		ADDRINT cur_tree_id;
	} bugdetect_struct;
	bugdetect_struct.bug_class = msg;
	bugdetect_struct.level = level;
	bugdetect_struct.eip = eip;
	if(cur_tree)
		bugdetect_struct.cur_tree_id = cur_tree->id;
	else
		bugdetect_struct.cur_tree_id = 0;
	out->write("\x03", 1);
	out->write((char*)(&bugdetect_struct), sizeof(bugdetect_struct));
	// *out << "** BUG FOUND\n" << msg << "\nLevel: " << level << "\nThread ID : " << PIN_ThreadId() << "\naddr : " << hex << eip << dec << '\n';
	total_score += level;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_ifer_bugdetect(ADDRINT v)
{
	return v;
}

VOID init_bugdetect()
{
	// 구현된건 주석 풀고, 구현 안된건 주석처리합니다.
	//plugin_IntegerOverflow();
	plugin_FormatStringBug();
	//plugin_UseAfterFree();
	plugin_TaintedEIP();
	plugin_RaceCondition();
	//plugin_BufferOverflow();
	plugin_CommandInjection();
	plugin_ArbitraryRW();

}