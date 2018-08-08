#ifndef __TRACKER_ETCTAINT_H__
#define __TRACKER_ETCTAINT_H__
VOID tracker_ins_inst(INS, VOID*);
void tracker_ins_logger(INS);
VOID tracker_file_read(ADDRINT addr, USIZE len, ADDRINT start_offset);
int tracker_init();

typedef enum DT_TYPE {
	DT_MEMORY,
	DT_REGISTER
};

typedef struct DTree {
	ADDRINT magic;
	ADDRINT id;
	DT_TYPE type;
	ADDRINT parents;
    DTree *parent[5];
	ADDRINT parent_id[5];
	ADDRINT eip;
	UINT32 reg_indx;
	/*
	// these are not implemented yet
	// uncomment if implemented, and modify ui_parser.py

	ADDRINT min, max; // min, max
	*/
} DTree;

extern REG cur_tree;
extern AHASHMAP hm1;

#endif