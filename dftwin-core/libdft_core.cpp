/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
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

/* 01/10/2013:
 * 	_xchg_m2r_op{b_u, b_l, w, l} and _xadd_r2m_op{b_u, b_l, w, l} did
 * 	not propagate the tags correctly; proposed fix by Remco Vermeulen
 * 	(r.vermeulen@vu.nl)
 * 09/10/2010:
 * 	r2r_xfer_oplb() was erroneously invoked without a third argument in
 *	MOVSX and MOVZX; proposed fix by Kangkook Jee (jikk@cs.columbia.edu)
 */

/*
 * TODO:
 * 	- optimize rep prefixed MOVS{B, W, D}
 */

#include <errno.h>
#include <string.h>

#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "tagmap.h"
#include "branch_pred.h"
#include "etctaint.h"
#include "data_chunk.h"
#include "tracker.h"
#include "tracker_etctaint.h"

 #include <stdint.h>

#define MAX_CALLBACK_COUNT 256

UINT32 pre_callback_count = 0;
void (*pre_callback[MAX_CALLBACK_COUNT])(INS);
/* thread context */
extern REG	thread_ctx_ptr;
extern std::ostream * out;

ADDRINT cur_dtree_id = 1;

/* tagmap */
extern unsigned char	*bitmap;

/* fast tag extension (helper); [0] -> 0, [1] -> VCPU_MASK16 */
static unsigned int	MAP_8L_16[] = {0, VCPU_MASK16};

/* fast tag extension (helper); [0] -> 0, [2] -> VCPU_MASK16 */
static unsigned int	MAP_8H_16[] = {0, 0, VCPU_MASK16};

/* fast tag extension (he1lper); [0] -> 0, [1] -> VCPU_MASK32 */
static unsigned int	MAP_8L_32[] = {0, VCPU_MASK32};

/* fast tag extension (helper); [0] -> 0, [2] -> VCPU_MASK32 */
static unsigned int	MAP_8H_32[] = {0, 0, VCPU_MASK32};

#define transfer_reg_to_reg(src, dst) \
	if(thread_ctx->vcpu.gpr_chunk[src]) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src]; \
		new_dtree->parents = 1; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree->reg_indx = dst; \
		thread_ctx->vcpu.gpr_chunk[dst] = new_dtree; \
		log_dtree(new_dtree);; \
	} else thread_ctx->vcpu.gpr_chunk[dst] = 0;

#define transfer_reg2_to_reg(src_1, src_2, dst) \
	if(thread_ctx->vcpu.gpr_chunk[src_1] || thread_ctx->vcpu.gpr_chunk[src_2]) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src_1]; \
		new_dtree->parent[1] = thread_ctx->vcpu.gpr_chunk[src_2]; \
		new_dtree->parents = 2; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree->reg_indx = dst; \
		thread_ctx->vcpu.gpr_chunk[dst] = new_dtree; \
		log_dtree(new_dtree);; \
	} else thread_ctx->vcpu.gpr_chunk[dst] = 0;

#define transfer_reg3_to_reg(src_1, src_2, src_3, dst) \
	if(thread_ctx->vcpu.gpr_chunk[src_1] || thread_ctx->vcpu.gpr_chunk[src_2] || thread_ctx->vcpu.gpr_chunk[src_3]) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src_1]; \
		new_dtree->parent[1] = thread_ctx->vcpu.gpr_chunk[src_2]; \
		new_dtree->parent[2] = thread_ctx->vcpu.gpr_chunk[src_3]; \
		new_dtree->parents = 3; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree->reg_indx = dst; \
		thread_ctx->vcpu.gpr_chunk[dst] = new_dtree; \
		log_dtree(new_dtree);; \
	} else thread_ctx->vcpu.gpr_chunk[dst] = 0;

#define transfer_memreg_to_reg(src_1, src_2, dst, size) \
	do { \
		DTree *new_dtree = new DTree; \
		bool create_new = 0; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src_2]; \
		for(int i = 1; i <= size; i++) { \
			new_dtree->parent[i] = M_GET_ADDR_HASHMAP(hm1, src_1 + i - 1, DTree *, 0); \
			if(new_dtree->parent[i]) create_new = 1; \
		} \
		if (create_new) { \
			new_dtree->parents = 1 + size; \
			new_dtree->id = ++cur_dtree_id; \
			new_dtree->reg_indx = dst; \
			thread_ctx->vcpu.gpr_chunk[dst] = new_dtree; \
			log_dtree(new_dtree); \
		} else delete new_dtree; \
	} while (0);

#define transfer_regmem_to_mem(src_1, src_2, dst, size) \
	for(int i = 0; i < size; i++) { \
	if(thread_ctx->vcpu.gpr_chunk[src_1] && M_GET_ADDR_HASHMAP(hm1, src_2 + i, DTree *, 0)) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_MEMORY; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src_1]; \
		new_dtree->parent[1] = M_GET_ADDR_HASHMAP(hm1, src_2 + i, DTree *, 0); \
		new_dtree->parents = 2; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree->reg_indx = dst; \
		M_PUT_ADDR_HASHMAP(hm1, dst, DTree *, new_dtree); \
		log_dtree(new_dtree);; \
	} \
	}

#define transfer_mem_to_reg(src, dst, size) \
	do { \
		DTree *new_dtree = new DTree; \
		bool create_new = 0; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		for(int i = 0; i < size; i++) { \
			new_dtree->parent[i] = M_GET_ADDR_HASHMAP(hm1, src + i, DTree *, 0); \
			if(new_dtree->parent[i]) create_new = 1; \
		} \
		if(create_new) { \
			new_dtree->parents = size; \
			new_dtree->id = ++cur_dtree_id; \
			new_dtree->reg_indx = dst; \
			thread_ctx->vcpu.gpr_chunk[dst] = new_dtree; \
			log_dtree(new_dtree); \
		} else delete new_dtree; \
	} while (0);
#define transfer_reg_to_mem(src, dst, size) \
	if(thread_ctx->vcpu.gpr_chunk[src]) \
	for(int i = 0; i < size; i++) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_MEMORY; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[src]; \
		new_dtree->parents = 1; \
		new_dtree->id = ++cur_dtree_id; \
		M_PUT_ADDR_HASHMAP(hm1, dst + i, DTree *, new_dtree); \
		log_dtree(new_dtree);; \
	}

#define transfer_mem_to_mem(src, dst, size) \
	for(int i = 0; i < size; i++) { \
		DTree *new_dtree = new DTree; \
		new_dtree->magic = 2; \
		new_dtree->type = DT_MEMORY; \
		new_dtree->eip = eip; \
		new_dtree->parent[0] = M_GET_ADDR_HASHMAP(hm1, src + i, DTree *, 0); \
		if(new_dtree->parent[0]) { \
			new_dtree->parents = 1; \
			new_dtree->id = ++cur_dtree_id; \
			M_PUT_ADDR_HASHMAP(hm1, dst + i, DTree *, new_dtree); \
			log_dtree(new_dtree);; \
		} else delete new_dtree; \
	}

#define swap_reg_to_reg(src, dst) \
	do { \
		DTree *new_dtree = new DTree; \
		DTree *new_dtree2 = new DTree; \
		new_dtree->magic = 2; \
		new_dtree2->magic = 2; \
		new_dtree->type = DT_REGISTER; \
		new_dtree2->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree2->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[dst]; \
		new_dtree->parents = 1; \
		new_dtree2->parent[0] = thread_ctx->vcpu.gpr_chunk[src]; \
		new_dtree2->parents = 1; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree2->id = ++cur_dtree_id; \
		thread_ctx->vcpu.gpr_chunk[dst] = new_dtree2; \
		thread_ctx->vcpu.gpr_chunk[src] = new_dtree; \
		log_dtree(new_dtree);; \
		log_dtree(new_dtree2);; \
	} while (0);

#define swap_mem_to_reg(src, dst, size) \
	do { \
		DTree *new_dtree = new DTree; \
		DTree *new_dtree2 = new DTree; \
		new_dtree->magic = 2; \
		new_dtree2->magic = 2; \
		new_dtree->type = DT_MEMORY; \
		new_dtree2->type = DT_REGISTER; \
		new_dtree->eip = eip; \
		new_dtree2->eip = eip; \
		new_dtree->parent[0] = thread_ctx->vcpu.gpr_chunk[dst]; \
		new_dtree->parents = 1; \
		for(int i = 0; i < size; i++) { \
			new_dtree2->parent[i] = M_GET_ADDR_HASHMAP(hm1, src + i, DTree *, 0); \
		} \
		new_dtree2->parents = size; \
		new_dtree->id = ++cur_dtree_id; \
		new_dtree2->id = ++cur_dtree_id; \
		thread_ctx->vcpu.gpr_chunk[dst] = new_dtree2; \
		for(int i = 0; i < size; i++) { \
			M_PUT_ADDR_HASHMAP(hm1, src, DTree *, new_dtree); \
		} \
		log_dtree(new_dtree);; \
		log_dtree(new_dtree2);; \
	} while (0);


#define xadd_reg_to_reg swap_reg_to_reg
#define xadd_mem_to_reg swap_mem_to_reg
#define xadd_reg_to_mem xadd_mem_to_reg


/*
 * tag propagation (analysis function)
 *
 * extend the tag as follows: t[upper(eax)] = t[ax]
 *
 * NOTE: special case for the CWDE instruction
 *
 * @thread_ctx:	the thread context
 */
static void PIN_FAST_ANALYSIS_CALL
_cwde(thread_ctx_t *thread_ctx, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[7] & VCPU_MASK16;

	/* extension; 16-bit to 32-bit */
	src_tag |= (src_tag << 2);

	/* update the destination */
	thread_ctx->vcpu.gpr[7] = src_tag;
	transfer_reg_to_reg(7, 7);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1);

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | MAP_8H_16[src_tag];
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		thread_ctx->vcpu.gpr[src] & VCPU_MASK8;
	
	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | MAP_8L_16[src_tag];
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and an upper 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1);

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = MAP_8H_32[src_tag]; 
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a lower 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK8;

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = MAP_8L_32[src_tag]; 
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK16;

	/* extension; 16-bit to 32-bit */
	src_tag |= (src_tag << 2);

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag;
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opwb(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* update the destination (xfer) */ 
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | MAP_8L_16[src_tag];
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplb(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = MAP_8L_32[src_tag];
	transfer_mem_to_reg(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	/* extension; 16-bit to 32-bit */
	src_tag |= (src_tag << 2);

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag;
	transfer_mem_to_reg(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag =
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1;

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | src_tag;
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		thread_ctx->vcpu.gpr[src] & VCPU_MASK8;
	
	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | src_tag;
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and an upper 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag =
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1;

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag; 
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a lower 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK8;

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag; 
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK16;

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag;
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opwb(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* update the destination (xfer) */ 
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) | src_tag;
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplb(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag;
	transfer_mem_to_reg(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t src_tag = 
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	/* update the destination (xfer) */
	thread_ctx->vcpu.gpr[dst] = src_tag;
	transfer_mem_to_reg(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit
 * registers as t[EAX] = t[src]; return
 * the result of EAX == src and also
 * store the original tag value of
 * EAX in the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst_val:	EAX register value
 * @src:	source register index (VCPU)
 * @src_val:	source register value
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_fast(thread_ctx_t *thread_ctx, unsigned int dst_val, unsigned int src,
							unsigned int src_val, ADDRINT eip)
{
	/* save the tag value of dst in the scratch register */
	thread_ctx->vcpu.gpr[8] = 
		thread_ctx->vcpu.gpr[7];
	transfer_reg_to_reg(7, 8);
	
	/* update */
	thread_ctx->vcpu.gpr[7] =
		thread_ctx->vcpu.gpr[src];
	transfer_reg_to_reg(src, 7);

	/* compare the dst and src values */
	return (dst_val == src_val);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] = t[src]; restore the
 * value of EAX from the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_slow(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* restore the tag value from the scratch register */
	thread_ctx->vcpu.gpr[7] = 
		thread_ctx->vcpu.gpr[8];
	
	/* update */
	thread_ctx->vcpu.gpr[dst] =
		thread_ctx->vcpu.gpr[src];
	transfer_reg_to_reg(8, 7);
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit
 * registers as t[AX] = t[src]; return
 * the result of AX == src and also
 * store the original tag value of
 * AX in the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst_val:	AX register value
 * @src:	source register index (VCPU)
 * @src_val:	source register value
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_fast(thread_ctx_t *thread_ctx, unsigned short dst_val, unsigned int src,
						unsigned short src_val, ADDRINT eip)
{
	/* save the tag value of dst in the scratch register */
	thread_ctx->vcpu.gpr[8] = 
		thread_ctx->vcpu.gpr[7];
	transfer_reg_to_reg(7, 8);
	
	/* update */
	thread_ctx->vcpu.gpr[7] =
		(thread_ctx->vcpu.gpr[7] & ~VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16);
	transfer_reg_to_reg(7, 7);

	/* compare the dst and src values */
	return (dst_val == src_val);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] = t[src]; restore the
 * value of AX from the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_slow(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* restore the tag value from the scratch register */
	thread_ctx->vcpu.gpr[7] = 
		thread_ctx->vcpu.gpr[8];
	
	/* update */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16);

	transfer_reg_to_reg(8, 7);
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit
 * register and a memory location
 * as t[EAX] = t[src]; return the result
 * of EAX == src and also store the
 * original tag value of EAX in
 * the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst_val:	destination register value
 * @src:	source memory address
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opl_fast(thread_ctx_t *thread_ctx, unsigned int dst_val, ADDRINT src, ADDRINT eip)
{
	/* save the tag value of dst in the scratch register */
	thread_ctx->vcpu.gpr[8] = 
		thread_ctx->vcpu.gpr[7];
	
	/* update */
	thread_ctx->vcpu.gpr[7] =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;

	transfer_reg2_to_reg(7, 8, 8);
	transfer_mem_to_reg(src, 7, 4);
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(unsigned int *)src);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location
 * as t[dst] = t[src]; restore the value
 * of EAX from the scratch register
 *1
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opl_slow(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	/* restore the tag value from the scratch register */
	thread_ctx->vcpu.gpr[7] = 
		thread_ctx->vcpu.gpr[8];
	
	/* update */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[src] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	transfer_reg_to_reg(8, 7);
	transfer_regmem_to_mem(src, dst, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit
 * register and a memory location
 * as t[AX] = t[src]; return the result
 * of AX == src and also store the
 * original tag value of AX in
 * the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @dst_val:	destination register value
 * @src:	source memory address
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opw_fast(thread_ctx_t *thread_ctx, unsigned short dst_val, ADDRINT src, ADDRINT eip)
{
	/* save the tag value of dst in the scratch register */
	thread_ctx->vcpu.gpr[8] = 
		thread_ctx->vcpu.gpr[7];
	
	/* update */
	thread_ctx->vcpu.gpr[7] =
		(thread_ctx->vcpu.gpr[7] & ~VCPU_MASK16) |
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	transfer_reg_to_reg(7, 8);
	transfer_memreg_to_reg(src, 7, 7, 2);
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(unsigned short *)src);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location
 * as t[dst] = t[src]; restore the value
 * of AX from the scratch register
 *
 * NOTE: special case for the CMPXCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @res:	restore register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opw_slow(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	/* restore the tag value from the scratch register */
	thread_ctx->vcpu.gpr[7] = 
		thread_ctx->vcpu.gpr[8];
	
	/* update */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[src] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_reg(8, 7);
	transfer_regmem_to_mem(src, dst, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] = t[lower(src)]
 * and t[lower(src)] = t[upper(dst)]
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_ul(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		 (thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		 ((thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << 1);
	
	thread_ctx->vcpu.gpr[src] =
		 (thread_ctx->vcpu.gpr[src] & ~VCPU_MASK8) | (tmp_tag >> 1);

}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] = t[upper(src)]
 * and t[upper(src)] = t[lower(dst)]
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_lu(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8;

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) | 
		((thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1);
	
	thread_ctx->vcpu.gpr[src] =
	 (thread_ctx->vcpu.gpr[src] & ~(VCPU_MASK8 << 1)) | (tmp_tag << 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] = t[upper(src)]
 * and t[upper(src)] = t[upper(dst)]
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1));
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~(VCPU_MASK8 << 1)) | tmp_tag;

	swap_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] = t[lower(src)]
 * and t[lower(src)] = t[lower(dst)]
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8; 

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK8);
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~VCPU_MASK8) | tmp_tag;
	swap_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] = t[src]
 * and t[src] = t[dst]
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK16; 

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16);
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~VCPU_MASK16) | tmp_tag;

	swap_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an upper 8-bit 
 * register and a memory location as
 * t[dst] = t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		(((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) << 1) &
		(VCPU_MASK8 << 1));

	bitmap[VIRT2BYTE(src)] =
		(bitmap[VIRT2BYTE(src)] & ~(BYTE_MASK << VIRT2BIT(src))) |
		((tmp_tag >> 1) << VIRT2BIT(src));

	swap_mem_to_reg(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a lower 8-bit 
 * register and a memory location as
 * t[dst] = t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8;
	
	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) |
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8);
	
	bitmap[VIRT2BYTE(src)] =
		(bitmap[VIRT2BYTE(src)] & ~(BYTE_MASK << VIRT2BIT(src))) |
		(tmp_tag << VIRT2BIT(src));

	swap_mem_to_reg(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] = t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opw(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK16;

	/* swap */	
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	*((unsigned short *)(bitmap + VIRT2BYTE(src))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) & ~(WORD_MASK <<
							      VIRT2BIT(src))) |
		((unsigned short)(tmp_tag) << VIRT2BIT(src));

	swap_mem_to_reg(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XCHG instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opl(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst];
	
	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	*((unsigned short *)(bitmap + VIRT2BYTE(src))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) & ~(LONG_MASK <<
							      VIRT2BIT(src))) |
		((unsigned short)(tmp_tag) << VIRT2BIT(src));
	xadd_mem_to_reg(src, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] |= t[lower(src)]
 * and t[lower(src)] = t[upper(dst)]
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_ul(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		 (thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1)) |
		 ((thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << 1);
	
	thread_ctx->vcpu.gpr[src] =
		 (thread_ctx->vcpu.gpr[src] & ~VCPU_MASK8) | (tmp_tag >> 1);
	xadd_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] |= t[upper(src)]
 * and t[upper(src)] = t[lower(dst)]
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_lu(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8;

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & VCPU_MASK8) | 
		((thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1);
	
	thread_ctx->vcpu.gpr[src] =
	 (thread_ctx->vcpu.gpr[src] & ~(VCPU_MASK8 << 1)) | (tmp_tag << 1);
	xadd_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] |= t[upper(src)]
 * and t[upper(src)] = t[upper(dst)]
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1)) |
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1));
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~(VCPU_MASK8 << 1)) | tmp_tag;
	xadd_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] |= t[lower(src)]
 * and t[lower(src)] = t[lower(dst)]
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8; 

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & VCPU_MASK8) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK8);
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~VCPU_MASK8) | tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] |= t[src]
 * and t[src] = t[dst]
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK16; 

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16);
	
	thread_ctx->vcpu.gpr[src] =
		(thread_ctx->vcpu.gpr[src] & ~VCPU_MASK16) | tmp_tag;
	xadd_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an upper 8-bit 
 * register and a memory location as
 * t[dst] |= t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1);

	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & (VCPU_MASK8 << 1)) |
		(((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) << 1) &
		(VCPU_MASK8 << 1));

	bitmap[VIRT2BYTE(src)] =
		(bitmap[VIRT2BYTE(src)] & ~(BYTE_MASK << VIRT2BIT(src))) |
		((tmp_tag >> 1) << VIRT2BIT(src));
	xadd_reg_to_mem(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a lower 8-bit 
 * register and a memory location as
 * t[dst] |= t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK8;
	
	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & VCPU_MASK8) |
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8);
	
	bitmap[VIRT2BYTE(src)] =
		(bitmap[VIRT2BYTE(src)] & ~(BYTE_MASK << VIRT2BIT(src))) |
		(tmp_tag << VIRT2BIT(src));
	xadd_reg_to_mem(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] |= t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opw(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst] & VCPU_MASK16;

	/* swap */	
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & VCPU_MASK16) |
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	*((unsigned short *)(bitmap + VIRT2BYTE(src))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) & ~(WORD_MASK <<
							      VIRT2BIT(src))) |
		((unsigned short)(tmp_tag) < VIRT2BIT(src));
	xadd_reg_to_mem(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] and t[src] = t[dst]
 * (dst is a register)
 *
 * NOTE: special case for the XADD instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opl(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[dst];
	
	/* swap */
	thread_ctx->vcpu.gpr[dst] =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	*((unsigned short *)(bitmap + VIRT2BYTE(src))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) & (LONG_MASK <<
							      VIRT2BIT(src))) |
		((unsigned short)(tmp_tag) << VIRT2BIT(src));
	xadd_reg_to_mem(src, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between three 16-bit 
 * registers as t[dst] = t[base] | t[index]
 *
 * NOTE: special case for the LEA instruction
 *
 * @thread_ctx: the thread context
 * @dst:        destination register
 * @base:       base register
 * @index:      index register
 */
static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opw(thread_ctx_t *thread_ctx,
		unsigned int dst,
		unsigned int base,
		unsigned int index,
		ADDRINT eip)
{
	/* update the destination */
	thread_ctx->vcpu.gpr[dst] =
		((thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[base] & VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[index] & VCPU_MASK16));
	transfer_reg3_to_reg(dst, base, index, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between three 32-bit 
 * registers as t[dst] = t[base] | t[index]
 *
 * NOTE: special case for the LEA instruction
 *
 * @thread_ctx: the thread context
 * @dst:        destination register
 * @base:       base register
 * @index:      index register
 */
static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opl(thread_ctx_t *thread_ctx,
		unsigned int dst,
		unsigned int base,
		unsigned int index,
		ADDRINT eip)
{
	/* update the destination */
	thread_ctx->vcpu.gpr[dst] =
		thread_ctx->vcpu.gpr[base] | thread_ctx->vcpu.gpr[index];
	transfer_reg2_to_reg(base, index, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among three 8-bit registers as t[dst] |= t[upper(src)];
 * dst is AX, whereas src is an upper 8-bit register (e.g., CH, BH, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_u(thread_ctx_t *thread_ctx, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1);
	
	/* update the destination (ternary) */
	thread_ctx->vcpu.gpr[7] |= MAP_8H_16[tmp_tag];
	transfer_reg2_to_reg(src, 7, 7);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among three 8-bit registers as t[dst] |= t[lower(src)];
 * dst is AX, whereas src is a lower 8-bit register (e.g., CL, BL, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_l(thread_ctx_t *thread_ctx, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK8;

	/* update the destination (ternary) */
	thread_ctx->vcpu.gpr[7] |= MAP_8L_16[tmp_tag];
	transfer_reg2_to_reg(src, 7, 7);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 16-bit 
 * registers as t[dst1] |= t[src] and t[dst2] |= t[src];
 * dst1 is DX, dst2 is AX, and src is a 16-bit register 
 * (e.g., CX, BX, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw(thread_ctx_t *thread_ctx, unsigned int src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = thread_ctx->vcpu.gpr[src] & VCPU_MASK16;
	
	/* update the destinations */
	thread_ctx->vcpu.gpr[5] |= tmp_tag;
	thread_ctx->vcpu.gpr[7] |= tmp_tag;
	transfer_reg2_to_reg(src, 5, 5);
	transfer_reg2_to_reg(src, 7, 7);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 32-bit 
 * registers as t[dst1] |= t[src] and t[dst2] |= t[src];
 * dst1 is EDX, dst2 is EAX, and src is a 32-bit register
 * (e.g., ECX, EBX, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl(thread_ctx_t *thread_ctx, unsigned int src, ADDRINT eip)
{ 
	/* update the destinations */
	thread_ctx->vcpu.gpr[5] |= thread_ctx->vcpu.gpr[src];
	thread_ctx->vcpu.gpr[7] |= thread_ctx->vcpu.gpr[src];
	transfer_reg2_to_reg(src, 5, 5);
	transfer_reg2_to_reg(src, 7, 7);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 8-bit registers
 * and an 8-bit memory location as t[dst] |= t[src];
 * dst is AX, whereas src is an 8-bit memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opb(thread_ctx_t *thread_ctx, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* update the destination (ternary) */
	thread_ctx->vcpu.gpr[7] |= MAP_8L_16[tmp_tag];
	transfer_memreg_to_reg(src, 7, 7, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 16-bit registers
 * and a 16-bit memory address as
 * t[dst1] |= t[src] and t[dst1] |= t[src];
 *
 * dst1 is DX, dst2 is AX, and src is a 16-bit
 * memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw(thread_ctx_t *thread_ctx, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16;
	
	/* update the destinations */
	thread_ctx->vcpu.gpr[5] |= tmp_tag; 
	thread_ctx->vcpu.gpr[7] |= tmp_tag; 
	transfer_memreg_to_reg(src, 5, 5, 2);
	transfer_memreg_to_reg(src, 7, 7, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 32-bit 
 * registers and a 32-bit memory as
 * t[dst1] |= t[src] and t[dst2] |= t[src];
 * dst1 is EDX, dst2 is EAX, and src is a 32-bit
 * memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @thread_ctx:	the thread context
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl(thread_ctx_t *thread_ctx, ADDRINT src, ADDRINT eip)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;

	/* update the destinations */
	thread_ctx->vcpu.gpr[5] |= tmp_tag;
	thread_ctx->vcpu.gpr[7] |= tmp_tag;
	transfer_memreg_to_reg(src, 5, 5, 4);
	transfer_memreg_to_reg(src, 7, 7, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] |= t[lower(src)];
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_ul(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << 1;
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] |= t[upper(src)];
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_lu(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1;
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] |= t[upper(src)]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1);
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] |= t[lower(src)]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		thread_ctx->vcpu.gpr[src] & VCPU_MASK8;
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit registers
 * as t[dst] |= t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		thread_ctx->vcpu.gpr[src] & VCPU_MASK16;
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] |= t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opl(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |= thread_ctx->vcpu.gpr[src];
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] |= t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opq(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |= thread_ctx->vcpu.gpr[src];
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[upper(dst)] |= t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8) << 1;
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[lower(dst)] |= t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opw(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16;
	transfer_memreg_to_reg(src, dst, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opl(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	transfer_memreg_to_reg(src, dst, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opq(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] |=
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK64;
	// transfer_memreg_to_reg(src, dst);
// #error "TODO"
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] |= t[upper(src)] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_u(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	bitmap[VIRT2BYTE(dst)] |=
		((thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1)
		<< VIRT2BIT(dst);
	transfer_regmem_to_mem(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] |= t[lower(src)] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_l(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	bitmap[VIRT2BYTE(dst)] |=
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << VIRT2BIT(dst);
	transfer_regmem_to_mem(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opw(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) |=
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16) <<
		VIRT2BIT(dst);
	transfer_regmem_to_mem(src, dst, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opl(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) |=
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK32) <<
		VIRT2BIT(dst);
	transfer_regmem_to_mem(src, dst, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opq(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) |=
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK64) <<
		VIRT2BIT(dst);
	// transfer_regmem_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of EAX, EBX, ECX, EDX
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl4(thread_ctx_t *thread_ctx, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[4] = 0;
	thread_ctx->vcpu.gpr[5] = 0;
	thread_ctx->vcpu.gpr[6] = 0;
	thread_ctx->vcpu.gpr[7] = 0;
	thread_ctx->vcpu.gpr_chunk[4] = (DTree *)0;
	thread_ctx->vcpu.gpr_chunk[5] = (DTree *)0;
	thread_ctx->vcpu.gpr_chunk[6] = (DTree *)0;
	thread_ctx->vcpu.gpr_chunk[7] = (DTree *)0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of EAX, EDX
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl2(thread_ctx_t *thread_ctx, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[5] = 0;
	thread_ctx->vcpu.gpr[7] = 0;
	thread_ctx->vcpu.gpr_chunk[5] = (DTree *)0;
	thread_ctx->vcpu.gpr_chunk[7] = (DTree *)0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a 32-bit register
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrq(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[reg] = 0;
	thread_ctx->vcpu.gpr_chunk[reg] = (DTree *)0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a 32-bit register
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[reg] = 0;
	thread_ctx->vcpu.gpr_chunk[reg] = (DTree*)0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a 16-bit register
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrw(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[reg] &= ~VCPU_MASK16;
	transfer_reg_to_reg(reg, reg);
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of an upper 8-bit register
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrb_u(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[reg] &= ~(VCPU_MASK8 << 1);
	transfer_reg_to_reg(reg, reg);
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a lower 8-bit register
 *
 * @thread_ctx:	the thread context
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrb_l(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[reg] &= ~VCPU_MASK8;
	transfer_reg_to_reg(reg, reg);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_l_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & VCPU_MASK8);
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_u_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & (VCPU_MASK8 << 1));
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getw_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & VCPU_MASK16);
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getl_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & VCPU_MASK32);
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getq_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & VCPU_MASK64);
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_gethex_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop)
{
	return orop | (thread_ctx->vcpu.gpr[reg] & VCPU_MASK128);
}

static void PIN_FAST_ANALYSIS_CALL
r_setb_l(thread_ctx_t *thread_ctx, unsigned int reg)
{
	thread_ctx->vcpu.gpr[reg] |= VCPU_MASK8;
}
static void PIN_FAST_ANALYSIS_CALL
r_setb_u(thread_ctx_t *thread_ctx, unsigned int reg)
{
	thread_ctx->vcpu.gpr[reg] |= VCPU_MASK8 << 1;
}
static void PIN_FAST_ANALYSIS_CALL
r_setw(thread_ctx_t *thread_ctx, unsigned int reg)
{
	thread_ctx->vcpu.gpr[reg] |= VCPU_MASK16;
}
static void PIN_FAST_ANALYSIS_CALL
r_setl(thread_ctx_t *thread_ctx, unsigned int reg)
{
	thread_ctx->vcpu.gpr[reg] |= VCPU_MASK32;
}
void PIN_FAST_ANALYSIS_CALL
r_setszor(thread_ctx_t *thread_ctx, unsigned int reg, size_t szor)
{
	thread_ctx->vcpu.gpr[reg] |= szor;
}
void PIN_FAST_ANALYSIS_CALL
r_setsz(thread_ctx_t *thread_ctx, unsigned int reg, size_t szor)
{
	thread_ctx->vcpu.gpr[reg] |= szor;
}
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getl(thread_ctx_t *thread_ctx, unsigned int reg)
{
	return thread_ctx->vcpu.gpr[reg] & VCPU_MASK32;
}


/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] = t[lower(src)]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_ul(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	 thread_ctx->vcpu.gpr[dst] =
		 (thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		 ((thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << 1);
	 transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] = t[upper(src)];
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_lu(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) | 
		((thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1);
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] = t[upper(src)]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		(thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1));
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] = t[lower(src)]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK8);
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] = t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		(thread_ctx->vcpu.gpr[src] & VCPU_MASK16);
	transfer_reg2_to_reg(src, dst, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] = t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		thread_ctx->vcpu.gpr[src];
	transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 64-bit 
 * registers as t[dst] = t[src]
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opq(thread_ctx_t *thread_ctx, unsigned int dst, unsigned int src)
{
	thread_ctx->vcpu.gpr[dst] =
		thread_ctx->vcpu.gpr[src];
	// transfer_reg_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an upper 8-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_u(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
		(((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) << 1) &
		(VCPU_MASK8 << 1));
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a lower 8-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_l(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK8) |
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8);
	transfer_memreg_to_reg(src, dst, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opw(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(thread_ctx->vcpu.gpr[dst] & ~VCPU_MASK16) |
		((*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	transfer_memreg_to_reg(src, dst, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opl(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src, ADDRINT eip)
{
	thread_ctx->vcpu.gpr[dst] =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	transfer_mem_to_reg(src, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 64-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opq(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT src)
{
	thread_ctx->vcpu.gpr[dst] =
		(*((unsigned short *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK64;
	// transfer_mem_to_reg(src, dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is AL
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @count:	memory bytes
 * @eflags:	the value of the EFLAGS register
 *
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opbn(thread_ctx_t *thread_ctx,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags,
		ADDRINT eip)
{

	if (likely(EFLAGS_DF(eflags) == 0)) {

		transfer_reg_to_mem(7, dst, count);
		/* EFLAGS.DF = 0 */

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7] & VCPU_MASK8)
			tagmap_setn(dst, count);
		/* the source register is clear */
		else
			tagmap_clrn(dst, count);
	}
	else {

		transfer_reg_to_mem(7, dst - count + 1, count);
		/* EFLAGS.DF = 1 */

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7] & VCPU_MASK8)
			tagmap_setn(dst - count + 1, count);
		/* the source register is clear */
		else
			tagmap_clrn(dst - count + 1, count);
	
	}
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] = t[upper(src)] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_u(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	bitmap[VIRT2BYTE(dst)] =
		(bitmap[VIRT2BYTE(dst)] & ~(BYTE_MASK << VIRT2BIT(dst))) |
		(((thread_ctx->vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1)
		<< VIRT2BIT(dst));

	transfer_reg_to_mem(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] = t[lower(src)] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_l(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	bitmap[VIRT2BYTE(dst)] =
		(bitmap[VIRT2BYTE(dst)] & ~(BYTE_MASK << VIRT2BIT(dst))) |
		((thread_ctx->vcpu.gpr[src] & VCPU_MASK8) << VIRT2BIT(dst));

	transfer_reg_to_mem(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is AX
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @count:	memory words
 * @eflags:	the value of the EFLAGS register
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opwn(thread_ctx_t *thread_ctx,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags, ADDRINT eip)
{

	if (likely(EFLAGS_DF(eflags) == 0)) {

		transfer_reg_to_mem(7, dst, count << 1);
		/* EFLAGS.DF = 0 */

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7] & VCPU_MASK16)
			tagmap_setn(dst, (count << 1));
		/* the source register is clear */
		else
			tagmap_clrn(dst, (count << 1));
	}
	else {
		/* EFLAGS.DF = 1 */

		transfer_reg_to_mem(7, dst - (count << 1) + 1, count << 1);

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7] & VCPU_MASK16)
			tagmap_setn(dst - (count << 1) + 1, (count << 1));
		/* the source register is clear */
		else
			tagmap_clrn(dst - (count << 1) + 1, (count << 1));
	}
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[src] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is EAX
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @count:	memory double words
 * @eflags:	the value of the EFLAGS register
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opln(thread_ctx_t *thread_ctx,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags,
		ADDRINT eip)
{

	if (likely(EFLAGS_DF(eflags) == 0)) {
		transfer_reg_to_mem(7, dst, count << 2);
		/* EFLAGS.DF = 0 */

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7])
			tagmap_setn(dst, (count << 2));
		/* the source register is clear */
		else
			tagmap_clrn(dst, (count << 2));
	}
	else {
		transfer_reg_to_mem(7, dst - (count << 2) + 1, count << 2);
		/* EFLAGS.DF = 1 */

		/* the source register is taged */
		if (thread_ctx->vcpu.gpr[7])
			tagmap_setn(dst - (count << 2) + 1, (count << 2));
		/* the source register is clear */
		else
			tagmap_clrn(dst - (count << 2) + 1, (count << 2));
	}
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[src] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(src, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opq(thread_ctx_t *thread_ctx, ADDRINT dst, unsigned int src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(QUAD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[src] & VCPU_MASK64) <<
		VIRT2BIT(dst));
	transfer_reg_to_mem(src, dst, 8);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opw(ADDRINT dst, ADDRINT src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		(((*((unsigned short *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& WORD_MASK) << VIRT2BIT(dst);
	transfer_mem_to_mem(src, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opb(ADDRINT dst, ADDRINT src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(BYTE_MASK <<
							      VIRT2BIT(dst))) |
		(((*((unsigned short *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& BYTE_MASK) << VIRT2BIT(dst);
	transfer_mem_to_mem(src, dst, 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opl(ADDRINT dst, ADDRINT src, ADDRINT eip)
{
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		(((*((unsigned short *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& LONG_MASK) << VIRT2BIT(dst);
	transfer_mem_to_mem(src, dst, 4);
}

/*
 * tag propagation (analysis function)
 *
 * instrumentation helper; returns the flag that
 * takes as argument -- seems lame, but it is
 * necessary for aiding conditional analysis to
 * be inlined. Typically used with INS_InsertIfCall()
 * in order to return true (i.e., allow the execution
 * of the function that has been instrumented with
 * INS_InsertThenCall()) only once
 *
 * first_iteration:	flag; indicates whether the rep-prefixed instruction is
 * 			executed for the first time or not
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
rep_predicate(BOOL first_iteration)
{
	/* return the flag; typically this is true only once */
	return first_iteration; 
}

/*
 * tag propagation (analysis function)
 *
 * restore the tag values for all the
 * 16-bit general purpose registers from
 * the memory
 *
 * NOTE: special case for POPA instruction 
 *
 * @thread_ctx:	the thread context
 * @src:	the source memory address	
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opw(thread_ctx_t *thread_ctx, ADDRINT src, ADDRINT eip)
{
	/* tagmap value */
	unsigned short src_val = *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore DI */
	thread_ctx->vcpu.gpr[0] =
		(thread_ctx->vcpu.gpr[0] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src)) & VCPU_MASK16);

	transfer_mem_to_reg(src, 0, 2);
	
	/* restore SI */
	thread_ctx->vcpu.gpr[1] =
		(thread_ctx->vcpu.gpr[1] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src + 2)) & VCPU_MASK16);
	transfer_mem_to_reg(src + 2, 1, 2);
	
	/* restore BP */
	thread_ctx->vcpu.gpr[2] =
		(thread_ctx->vcpu.gpr[2] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src + 4)) & VCPU_MASK16);

	transfer_mem_to_reg(src + 4, 2, 2);
	
	/* update the tagmap value */
	src	+= 8;
	src_val	= *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore BX */
	thread_ctx->vcpu.gpr[4] =
		(thread_ctx->vcpu.gpr[4] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src)) & VCPU_MASK16);

	transfer_mem_to_reg(src, 4, 2);
	
	/* restore DX */
	thread_ctx->vcpu.gpr[5] =
		(thread_ctx->vcpu.gpr[5] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src + 2)) & VCPU_MASK16);

	transfer_mem_to_reg(src + 2, 5, 2);
	
	/* restore CX */
	thread_ctx->vcpu.gpr[6] =
		(thread_ctx->vcpu.gpr[6] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src + 4)) & VCPU_MASK16);
	transfer_mem_to_reg(src + 4, 6, 2);
	
	/* restore AX */
	thread_ctx->vcpu.gpr[7] =
		(thread_ctx->vcpu.gpr[7] & ~VCPU_MASK16) |
		((src_val >> VIRT2BIT(src + 6)) & VCPU_MASK16);
	transfer_mem_to_reg(src + 6, 7, 2);
}

/*
 * tag propagation (analysis function)
 *
 * restore the tag values for all the
 * 32-bit general purpose registers from
 * the memory
 *
 * NOTE: special case for POPAD instruction 
 *
 * @thread_ctx:	the thread context
 * @src:	the source memory address	
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opl(thread_ctx_t *thread_ctx, ADDRINT src, ADDRINT eip)
{
	/* tagmap value */
	unsigned short src_val = *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore EDI */
	thread_ctx->vcpu.gpr[0] =
		(src_val >> VIRT2BIT(src)) & VCPU_MASK32;

	transfer_mem_to_reg(src, 0, 4);

	/* restore ESI */
	thread_ctx->vcpu.gpr[1] =
		(src_val >> VIRT2BIT(src + 4)) & VCPU_MASK32;

	transfer_mem_to_reg(src + 4, 1, 4);
	
	/* update the tagmap value */
	src	+= 8;
	src_val	= *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore EBP */
	thread_ctx->vcpu.gpr[2] =
		(src_val >> VIRT2BIT(src)) & VCPU_MASK32;

	transfer_mem_to_reg(src, 2, 4);
	
	/* update the tagmap value */
	src	+= 8;
	src_val	= *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore EBX */
	thread_ctx->vcpu.gpr[4] =
		(src_val >> VIRT2BIT(src)) & VCPU_MASK32;

	transfer_mem_to_reg(src, 4, 4);
	
	/* restore EDX */
	thread_ctx->vcpu.gpr[5] =
		(src_val >> VIRT2BIT(src + 4)) & VCPU_MASK32;

	transfer_mem_to_reg(src + 4, 5, 4);
	
	/* update the tagmap value */
	src	+= 8;
	src_val	= *(unsigned short *)(bitmap + VIRT2BYTE(src));

	/* restore ECX */
	thread_ctx->vcpu.gpr[6] =
		(src_val >> VIRT2BIT(src)) & VCPU_MASK32;

	transfer_mem_to_reg(src, 6, 4);
	
	/* restore EAX */
	thread_ctx->vcpu.gpr[7] =
		(src_val >> VIRT2BIT(src + 4)) & VCPU_MASK32;
	transfer_mem_to_reg(src + 4, 7, 4);
}

/*
 * tag propagation (analysis function)
 *
 * save the tag values for all the 16-bit
 * general purpose registers into the memory
 *
 * NOTE: special case for PUSHA instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	the destination memory address
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_save_opw(thread_ctx_t *thread_ctx, ADDRINT dst, ADDRINT eip)
{
	/* save DI */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[0] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(0, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save SI */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[1] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(1, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save BP */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[2] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(2, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save SP */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[3] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(3, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save BX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[4] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(4, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save DX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[5] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(5, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save CX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[6] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(6, dst, 2);
	/* update the destination memory */
	dst += 2;

	/* save AX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[7] & VCPU_MASK16) <<
		VIRT2BIT(dst));
	transfer_reg_to_mem(7, dst, 2);
}

/*
 * tag propagation (analysis function)
 *
 * save the tag values for all the 32-bit
 * general purpose registers into the memory
 *
 * NOTE: special case for PUSHAD instruction 
 *
 * @thread_ctx:	the thread context
 * @dst:	the destination memory address
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_save_opl(thread_ctx_t *thread_ctx, ADDRINT dst, ADDRINT eip)
{
	/* save EDI */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[0] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(0, dst, 4);

	/* update the destination memory address */
	dst += 4;

	/* save ESI */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[1] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(1, dst, 4);
	
	/* update the destination memory address */
	dst += 4;

	/* save EBP */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[2] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(2, dst, 4);
	
	/* update the destination memory address */
	dst += 4;

	/* save ESP */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[3] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(3, dst, 4);

	/* update the destination memory address */
	dst += 4;

	/* save EBX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[4] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(4, dst, 4);
	
	/* update the destination memory address */
	dst += 4;

	/* save EDX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[5] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(5, dst, 4);
	
	/* update the destination memory address */
	dst += 4;

	/* save ECX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[6] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(6, dst, 4);
	
	/* update the destination memory address */
	dst += 4;
	
	/* save EAX */
	*((unsigned short *)(bitmap + VIRT2BYTE(dst))) =
		(*((unsigned short *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((unsigned short)(thread_ctx->vcpu.gpr[7] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	transfer_reg_to_mem(7, dst, 4);
}

ADDRINT is_true_reg(ADDRINT x)
{
	return x;
}

/*
 * special case for inc/dec
 */
VOID PIN_FAST_ANALYSIS_CALL
reg_incdec(thread_ctx_t *thread_ctx, unsigned int dst, ADDRINT eip) {
	transfer_reg_to_reg(dst, dst);
}

/*
 * special case for inc/dec
 */
VOID PIN_FAST_ANALYSIS_CALL
mem_incdec(ADDRINT dst, ADDRINT eip) {
	transfer_mem_to_mem(dst, dst, 4);
}

/*
 * instruction inspection (instrumentation function)
 *
 * analyze every instruction and instrument it
 * for propagating the tag bits accordingly
 *
 * @ins:	the instruction to be instrumented
 */
void
ins_inspect(INS ins)
{
	bool is_etctaint = 0;

	if((is_etctaint = etcTaint_ins_inst_real(ins)) == 1) {
		// *out << "Taint:" << endl;
		// *out << " " << INS_Disassemble(ins) << endl;
		/*
		INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg_is_tainted, IARG_INST_PTR, IARG_END);
		INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)alloc_data_chunk, IARG_RETURN_REGS, cur_tree, IARG_INST_PTR, IARG_END);
		*/
		etcTaint_ins_inst(ins);
		return;
	}
	/*
	INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_cb_ifer, IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg_is_tainted, IARG_INST_PTR, IARG_END);
	INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)alloc_data_chunk, IARG_RETURN_REGS, cur_tree, IARG_INST_PTR, IARG_END);
	*/
	/* 
	 * temporaries;
	 * source, destination, base, and index registers
	 */
	REG reg_dst, reg_src, reg_base, reg_indx;

	/* use XED to decode the instruction and extract its opcode */
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

	/* sanity check */
	if (unlikely(ins_indx <= XED_ICLASS_INVALID || 
				ins_indx >= XED_ICLASS_LAST)) {
		LOG(string(__FUNCTION__) + ": unknown opcode (opcode=" +
				decstr(ins_indx) + ")\n");

		/* done */
		return;
	}

	/* analyze the instruction */
	switch (ins_indx) {
		/* adc */
		case XED_ICLASS_ADC:
		/* add */
		case XED_ICLASS_ADD:
		/* and */
		case XED_ICLASS_AND:
		/* or */
		case XED_ICLASS_OR:
		/* xor */
		case XED_ICLASS_XOR:
		/* sbb */
		case XED_ICLASS_SBB:
		/* sub */
		case XED_ICLASS_SUB:
			/*
			 * the general format of these instructions
			 * is the following: dst {op}= src, where
			 * op can be +, -, &, |, etc. We tag the
			 * destination if the source is also taged
			 * (i.e., t[dst] |= t[src])
			 */
			/* 2nd operand is immediate; do nothing */
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 64-bit operands */
				if(REG_is_gr64(reg_dst)) {
					switch(ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrq,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE, 
								thread_ctx_ptr,
								IARG_UINT32,
							REGFLOAT_INDX(reg_dst),
								IARG_INST_PTR, IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
							/* 
							 * propagate the tag
							 * markings accordingly
							 */
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_REG_VALUE,
							thread_ctx_ptr,
							IARG_UINT32,
							REGFLOAT_INDX(reg_dst),
							IARG_UINT32,
							REGFLOAT_INDX(reg_src),
							IARG_INST_PTR, IARG_END);
					}
				}
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrl,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE, 
								thread_ctx_ptr,
								IARG_UINT32,
							REG32_INDX(reg_dst),
								IARG_INST_PTR, IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
							/* 
							 * propagate the tag
							 * markings accordingly
							 */
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_REG_VALUE,
							thread_ctx_ptr,
							IARG_UINT32,
							REG32_INDX(reg_dst),
							IARG_UINT32,
							REG32_INDX(reg_src),
							IARG_INST_PTR, IARG_END);
					}
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrw,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE, 
								thread_ctx_ptr,
								IARG_UINT32,
							REG16_INDX(reg_dst),
								IARG_INST_PTR, IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
						/* propagate tags accordingly */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE, 
								thread_ctx_ptr,
								IARG_UINT32,
							REG16_INDX(reg_dst),
								IARG_UINT32,
							REG16_INDX(reg_src),
								IARG_INST_PTR, IARG_END);
					}
				}
				/* 8-bit operands */
				else {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
							/* 8-bit upper */
						if (REG_is_Upper8(reg_dst))
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
							(AFUNPTR)r_clrb_u,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE,
								thread_ctx_ptr,
								IARG_UINT32,
							REG8_INDX(reg_dst),
								IARG_INST_PTR, IARG_END);
							/* 8-bit lower */
						else 
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
							(AFUNPTR)r_clrb_l,
							IARG_FAST_ANALYSIS_CALL,
								IARG_REG_VALUE,
								thread_ctx_ptr,
								IARG_UINT32,
							REG8_INDX(reg_dst),
								IARG_INST_PTR, IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
						/* propagate tags accordingly */
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					}
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 64-bit operands */
				if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (upper) */
				else if (REG_is_Upper8(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else 
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 64-bit operands */
				if (REG_is_gr64(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REGFLOAT_INDX(reg_src),
						IARG_INST_PTR, IARG_END);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* bsf */
		case XED_ICLASS_BSF:
		/* bsr */
		case XED_ICLASS_BSR:
		/* mov */
		case XED_ICLASS_MOV:
			/*
			 * the general format of these instructions
			 * is the following: dst = src. We move the
			 * tag of the source to the destination
			 * (i.e., t[dst] = t[src])
			 */
			/* 
			 * 2nd operand is immediate or segment register;
			 * clear the destination
			 *
			 * NOTE: When the processor moves a segment register
			 * into a 32-bit general-purpose register, it assumes
			 * that the 16 least-significant bits of the
			 * general-purpose register are the destination or
			 * source operand. If the register is a destination
			 * operand, the resulting value in the two high-order
			 * bytes of the register is implementation dependent.
			 * For the Pentium 4, Intel Xeon, and P6 family
			 * processors, the two high-order bytes are filled with
			 * zeros; for earlier 32-bit IA-32 processors, the two
			 * high order bytes are undefined.
			 */
			if (INS_OperandIsImmediate(ins, OP_1) ||
				(INS_OperandIsReg(ins, OP_1) &&
				REG_is_seg(INS_OperandReg(ins, OP_1)))) {
				/* destination operand is a memory address */
				if (INS_OperandIsMemory(ins, OP_0)) {
					/* clear n-bytes */
					switch (INS_OperandWidth(ins, OP_0)) {
						/* 8 bytes */
						case MEM_QUAD_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)tagmap_clrq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);
							
							break;
						/* 4 bytes */
						case MEM_LONG_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)tagmap_clrl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* 2 bytes */
						case MEM_WORD_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)tagmap_clrw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* 1 byte */
						case MEM_BYTE_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)tagmap_clrb,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* make the compiler happy */
						default:
						LOG(string(__FUNCTION__) +
						": unhandled operand width (" +
						INS_Disassemble(ins) + ")\n");

							/* done */
							return;
					}
				}
				/* destination operand is a register */
				else if (INS_OperandIsReg(ins, OP_0)) {
					/* extract the operand */
					reg_dst = INS_OperandReg(ins, OP_0);

					/* 64-bit operand */
					if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrq,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
							IARG_INST_PTR, IARG_END);
					/* 32-bit operand */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrl,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
							IARG_INST_PTR, IARG_END);
					/* 16-bit operand */
					else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrw,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
							IARG_INST_PTR, IARG_END);
					/* 8-bit operand (upper) */
					else if (REG_is_Upper8(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_u,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
							IARG_INST_PTR, IARG_END);
					/* 8-bit operand (lower) */
					else
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_l,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
							IARG_INST_PTR, IARG_END);
				}
			}
			/* both operands are registers */
			else if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 64-bit operands */
				if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
					IARG_UINT32, REGFLOAT_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 64-bit operands */
				if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (upper) */
				else if (REG_is_Upper8(reg_dst)) 
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 64-bit operands */
				if (REG_is_gr64(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REGFLOAT_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (lower) */
				else 
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* conditional movs */
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
			/*
			 * the general format of these instructions
			 * is the following: dst = src iff cond. We
			 * move the tag of the source to the destination
			 * iff the corresponding condition is met
			 * (i.e., t[dst] = t[src])
			 */
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				/* 64-bit operands */
				if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
					IARG_UINT32, REGFLOAT_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else 
					/* propagate tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 64-bit opreands */
				if (REG_is_gr64(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REGFLOAT_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* 
		 * cbw;
		 * move the tag associated with AL to AH
		 *
		 * NOTE: sign extension generates data that
		 * are dependent to the source operand
		 */
		case XED_ICLASS_CBW:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opb_ul,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(REG_AH),
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/*
		 * cwd;
		 * move the tag associated with AX to DX
		 *
		 * NOTE: sign extension generates data that
		 * are dependent to the source operand
		 */
		case XED_ICLASS_CWD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG16_INDX(REG_DX),
				IARG_UINT32, REG16_INDX(REG_AX),
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * cwde;
		 * move the tag associated with AX to EAX
		 *
		 * NOTE: sign extension generates data that
		 * are dependent to the source operand
		 */
		case XED_ICLASS_CWDE:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)_cwde,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/*
		 * cdq;
		 * move the tag associated with EAX to EDX
		 *
		 * NOTE: sign extension generates data that
		 * are dependent to the source operand
		 */
		case XED_ICLASS_CDQ:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG32_INDX(REG_EDX),
				IARG_UINT32, REG32_INDX(REG_EAX),
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * movsx;
		 *
		 * NOTE: sign extension generates data that
		 * are dependent to the source operand
		 */
		case XED_ICLASS_MOVSX:
			/*
			 * the general format of these instructions
			 * is the following: dst = src. We move the
			 * tag of the source to the destination
			 * (i.e., t[dst] = t[src]) and we extend the
			 * tag bits accordingly
			 */
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst)) {
					/* upper 8-bit */
					if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 32-bit & 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands (upper 8-bit) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands (lower 8-bit) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}
			/* 2nd operand is memory */
			else {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 16-bit operands */
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/*
		 * movzx;
		 *
		 * NOTE: zero extension always results in
		 * clearing the tags associated with the
		 * higher bytes of the destination operand
		 */
		case XED_ICLASS_MOVZX:
			/*
			 * the general format of these instructions
			 * is the following: dst = src. We move the
			 * tag of the source to the destination
			 * (i.e., t[dst] = t[src]) and we extend the
			 * tag bits accordingly
			 */
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst)) {
					/* upper 8-bit */
					if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 32-bit & 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands (upper 8-bit) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands (lower 8-bit) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}
			/* 2nd operand is memory */
			else {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 16-bit operands */
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 32-bit & 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* div */
		case XED_ICLASS_DIV:
		/* idiv */
		case XED_ICLASS_IDIV:
		/* mul */
		case XED_ICLASS_MUL:
			/*
			 * the general format of these brain-dead and
			 * totally corrupted instructions is the following:
			 * dst1:dst2 {*, /}= src. We tag the destination
			 * operands if the source is also taged
			 * (i.e., t[dst1]:t[dst2] |= t[src])
			 */
			/* memory operand */
			if (INS_OperandIsMemory(ins, OP_0))
				/* differentiate based on the memory size */
				switch (INS_MemoryWriteSize(ins)) {
					/* 4 bytes */
					case BIT2BYTE(MEM_LONG_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case BIT2BYTE(MEM_WORD_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
					/* 1 byte */
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
				}
			/* register operand */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else 
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/*
		 * imul;
		 * I'm still wondering how brain-damaged the
		 * ISA architect should be in order to come
		 * up with something so ugly as the IMUL 
		 * instruction
		 */
		case XED_ICLASS_IMUL:
			/* one-operand form */
			if (INS_OperandIsImplicit(ins, OP_1)) {
				/* memory operand */
				if (INS_OperandIsMemory(ins, OP_0))
				/* differentiate based on the memory size */
				switch (INS_MemoryWriteSize(ins)) {
					/* 4 bytes */
					case BIT2BYTE(MEM_LONG_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case BIT2BYTE(MEM_WORD_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
					/* 1 byte */
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);

						/* done */
						break;
				}
			/* register operand */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
			}
			/* two/three-operands form */
			else {
				/* 2nd operand is immediate; do nothing */
				if (INS_OperandIsImmediate(ins, OP_1))
					break;

				/* both operands are registers */
				if (INS_MemoryOperandCount(ins) == 0) {
					/* extract the operands */
					reg_dst = INS_OperandReg(ins, OP_0);
					reg_src = INS_OperandReg(ins, OP_1);
				
					/* 32-bit operands */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
							IARG_INST_PTR, IARG_END);
					/* 16-bit operands */
					else
					/* propagate tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
							IARG_INST_PTR, IARG_END);
				}
				/* 
				 * 2nd operand is memory;
				 * we optimize for that case, since most
				 * instructions will have a register as
				 * the first operand -- leave the result
				 * into the reg and use it later
				 */
				else {
					/* extract the register operand */
					reg_dst = INS_OperandReg(ins, OP_0);

					/* 32-bit operands */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);
					/* 16-bit operands */
					else
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_INST_PTR, IARG_END);
				}
			}

			/* done */
			break;
		/* conditional sets */
		case XED_ICLASS_SETB:
		case XED_ICLASS_SETBE:
		case XED_ICLASS_SETL:
		case XED_ICLASS_SETLE:
		case XED_ICLASS_SETNB:
		case XED_ICLASS_SETNBE:
		case XED_ICLASS_SETNL:
		case XED_ICLASS_SETNLE:
		case XED_ICLASS_SETNO:
		case XED_ICLASS_SETNP:
		case XED_ICLASS_SETNS:
		case XED_ICLASS_SETNZ:
		case XED_ICLASS_SETO:
		case XED_ICLASS_SETP:
		case XED_ICLASS_SETS:
		case XED_ICLASS_SETZ:
			/*
			 * clear the tag information associated with the
			 * destination operand
			 */
			/* register operand */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 8-bit operand (upper) */
				if (REG_is_Upper8(reg_dst))	
					/* propagate tag accordingly */
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else 
					/* propagate tag accordingly */
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
			}
			/* memory operand */
			else
				/* propagate the tag accordingly */
				INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);

			/* done */
			break;
		/* 
		 * stmxcsr;
		 * clear the destination operand (register only)
		 */
		case XED_ICLASS_STMXCSR:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)tagmap_clrl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		
			/* done */
			break;
		/* smsw */
		case XED_ICLASS_SMSW:
		/* str */
		case XED_ICLASS_STR:
			/*
			 * clear the tag information associated with
			 * the destination operand
			 */
			/* register operand */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 16-bit register */
				if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
				/* 32-bit register */
				else 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
			}
			/* memory operand */
			else
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);

			/* done */
			break;
		/* 
		 * lar;
		 * clear the destination operand (register only)
		 */
		case XED_ICLASS_LAR:
			/* extract the 1st operand */
			reg_dst = INS_OperandReg(ins, OP_0);

			/* 16-bit register */
			if (REG_is_gr16(reg_dst))
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_INST_PTR, IARG_END);
			/* 32-bit register */
			else
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* rdpmc */
		case XED_ICLASS_RDPMC:
		/* rdtsc */
		case XED_ICLASS_RDTSC:
			/*
			 * clear the tag information associated with
			 * EAX and EDX
			 */
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl2,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * cpuid;
		 * clear the tag information associated with
		 * EAX, EBX, ECX, and EDX 
		 */
		case XED_ICLASS_CPUID:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl4,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
			/* yogiyo */
		/* 
		 * lahf;
		 * clear the tag information of AH
		 */
		case XED_ICLASS_LAHF:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_u,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(REG_AH),
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * cmpxchg;
		 * t[dst] = t[src] iff EAX/AX/AL == dst, else
		 * t[EAX/AX/AL] = t[dst] -- yes late-night coding again
		 * and I'm really tired to comment this crap...
		 */
		case XED_ICLASS_CMPXCHG:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_REG_VALUE, REG_EAX,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_INST_PTR, IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_REG_VALUE, REG_AX,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_INST_PTR, IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 8-bit operands */
				//else
				//LOG(string(__FUNCTION__) +
				//	": unhandled opcode (opcode=" +
				//	decstr(ins_indx) + ")\n");
			}
			/* 1st operand is memory */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_REG_VALUE, REG_AX,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 8-bit operands */
				//else
				//LOG(string(__FUNCTION__) +
				//	": unhandled opcode (opcode=" +
				//	decstr(ins_indx) + ")\n");
			}

			/* done */
			break;
		/* 
		 * xchg;
		 * exchange the tag information of the two operands
		 */
		case XED_ICLASS_XCHG:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_UINT32, 8,
						IARG_INST_PTR, IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (upper) */
				else if (REG_is_Upper8(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG8_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG8_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* 
		 * xadd;
		 * xchg + add. We instrument this instruction  using the tag
		 * logic of xchg and add (see above)
		 */
		case XED_ICLASS_XADD:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_INST_PTR, IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				}
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2m_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2m_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (upper) */
				else if (REG_is_Upper8(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2m_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
				/* 8-bit operand (lower) */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2m_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* xlat; similar to a mov between a memory location and AL */
		case XED_ICLASS_XLAT:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* lodsb; similar to a mov between a memory location and AL */
		case XED_ICLASS_LODSB:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* lodsw; similar to a mov between a memory location and AX */
		case XED_ICLASS_LODSW:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG16_INDX(REG_AX),
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* lodsd; similar to a mov between a memory location and EAX */
		case XED_ICLASS_LODSD:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG32_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * stosb;
		 * the opposite of lodsb; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSB:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opbn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_INST_PTR, IARG_END);
			}
			/* no rep prefix */
			else 
				/* the instruction is not rep prefixed */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opb_l,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(REG_AL),
					IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * stosw; 
		 * the opposite of lodsw; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSW:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opwn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_INST_PTR, IARG_END);
			}
			/* no rep prefix */
			else
				/* the instruction is not rep prefixed */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(REG_AX),
					IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* 
		 * stosd;
		 * the opposite of lodsd; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSD:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opln,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_INST_PTR, IARG_END);
			}
			/* no rep prefix */
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(REG_EAX),
					IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* movsd */
		case XED_ICLASS_MOVSD:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* movsw */
		case XED_ICLASS_MOVSW:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* movsb */
		case XED_ICLASS_MOVSB:
			/* propagate the tag accordingly */
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* sal */
		case XED_ICLASS_SALC:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* TODO: shifts are not handled (yet) */
		/* rcl */
		case XED_ICLASS_RCL:
		/* rcr */        
		case XED_ICLASS_RCR:
		/* rol */        
		case XED_ICLASS_ROL:
		/* ror */        
		case XED_ICLASS_ROR:
		/* sal/shl */
		case XED_ICLASS_SHL:
		/* sar */
		case XED_ICLASS_SAR:
		/* shr */
		case XED_ICLASS_SHR:
		/* shld */
		case XED_ICLASS_SHLD:
		case XED_ICLASS_SHRD:

			/* done */
			break;
		/* pop; mov equivalent (see above) */
		case XED_ICLASS_POP:
			/* register operand */
			if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}
			/* memory operand */
			else if (INS_OperandIsMemory(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* push; mov equivalent (see above) */
		case XED_ICLASS_PUSH:
			/* register operand */
			if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_INST_PTR, IARG_END);
			}
			/* memory operand */
			else if (INS_OperandIsMemory(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR, IARG_END);
			}
			/* immediate or segment operand; clean */
			else {
				/* clear n-bytes */
				switch (INS_OperandWidth(ins, OP_0)) {
					/* 4 bytes */
					case MEM_LONG_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case MEM_WORD_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* 1 byte */
					case MEM_BYTE_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* make the compiler happy */
					default:
						/* done */
						break;
				}
			}

			/* done */
			break;
		/* popa;
		 * similar to pop but for all the 16-bit
		 * general purpose registers
		 */
		case XED_ICLASS_POPA:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* popad; 
		 * similar to pop but for all the 32-bit
		 * general purpose registers
		 */
		case XED_ICLASS_POPAD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_MEMORYREAD_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* pusha; 
		 * similar to push but for all the 16-bit
		 * general purpose registers
		 */
		case XED_ICLASS_PUSHA:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_MEMORYWRITE_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* pushad; 
		 * similar to push but for all the 32-bit
		 * general purpose registers
		 */
		case XED_ICLASS_PUSHAD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_MEMORYWRITE_EA,
				IARG_INST_PTR, IARG_END);

			/* done */
			break;
		/* pushf; clear a memory word (i.e., 16-bits) */
		case XED_ICLASS_PUSHF:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)tagmap_clrw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* pushfd; clear a double memory word (i.e., 32-bits) */
		case XED_ICLASS_PUSHFD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)tagmap_clrl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* call (near); similar to push (see above) */
		case XED_ICLASS_CALL_NEAR:
			/* relative target */
			if (INS_OperandIsImmediate(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}
			/* absolute target; register */
			else if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the source register */
				reg_src = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}
			/* absolute target; memory */
			else {
				/* 32-bit operand */
				if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			/* done */
			break;
		/* 
		 * leave;
		 * similar to a mov between ESP/SP and EBP/BP, and a pop
		 */
		case XED_ICLASS_LEAVE:
			/* extract the operands */
			reg_dst = INS_OperandReg(ins, OP_3);
			reg_src = INS_OperandReg(ins, OP_2);

			/* 32-bit operands */	
			if (REG_is_gr32(reg_dst)) {
				/* propagate the tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_INST_PTR, IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_INST_PTR, IARG_END);
			}
			/* 16-bit operands */
			else {
				/* propagate the tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_INST_PTR, IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_INST_PTR, IARG_END);
			}

			/* done */
			break;
		/* lea */
		case XED_ICLASS_LEA:
			/*
			 * the general format of this instruction
			 * is the following: dst = src_base | src_indx.
			 * We move the tags of the source base and index
			 * registers to the destination
			 * (i.e., t[dst] = t[src_base] | t[src_indx])
			 */

			/* extract the operands */
			reg_base	= INS_MemoryBaseReg(ins);
			reg_indx	= INS_MemoryIndexReg(ins);
			reg_dst		= INS_OperandReg(ins, OP_0);
			
			/* no base or index register; clear the destination */
			if (reg_base == REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* clear */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32,
						REG32_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else 
					/* clear */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_UINT32,
						REG16_INDX(reg_dst),
						IARG_INST_PTR, IARG_END);
			}
			/* base register exists; no index register */
			if (reg_base != REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_base),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_base),
						IARG_INST_PTR, IARG_END);
			}
			/* index register exists; no base register */
			if (reg_base == REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_indx),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_indx),
						IARG_INST_PTR, IARG_END);
			}
			/* base and index registers exist */
			if (reg_base != REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_base),
					IARG_UINT32, REG32_INDX(reg_indx),
						IARG_INST_PTR, IARG_END);
				/* 16-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_base),
					IARG_UINT32, REG16_INDX(reg_indx),
						IARG_INST_PTR, IARG_END);
			}
			
			/* done */
			break;
		/* cmpxchg */
		case XED_ICLASS_CMPXCHG8B:
		/* enter */
		case XED_ICLASS_ENTER:
			//LOG(string(__FUNCTION__) +
			//	": unhandled opcode (opcode=" +
			//	decstr(ins_indx) + ")\n");

			/* done */
			break;
		/* 
		 * default handler
		 */
		case XED_ICLASS_INC:
		case XED_ICLASS_DEC:
			if(INS_OperandIsReg(ins, 0))
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)reg_incdec,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_UINT32, REG8_INDX(INS_RegR(ins, 0)),
				IARG_INST_PTR,
				IARG_END);
			else if (INS_OperandIsMemory(ins, 0))
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mem_incdec,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYOP_EA, 0,
				IARG_INST_PTR,
				IARG_END);
		case XED_ICLASS_TEST:
		case XED_ICLASS_CMP:
			break;
		default:
			tracker_ins_inst(ins, 0);
			etcTaint_ins_inst(ins);
			break;
	}
}




ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingl_before(ADDRINT addr)
{
	return M_TAGMAP_NUML(addr);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingl_after(ADDRINT addr, ADDRINT counter)
{
	//*out << "inst_cb_countingl_after : " << M_TAGMAP_NUMDQ(addr) << ' ' << counter << '\n';
	return M_TAGMAP_NUML(addr) - counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingw_before(ADDRINT addr)
{
	return M_TAGMAP_NUMW(addr);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingw_after(ADDRINT addr, ADDRINT counter)
{
	//*out << "inst_cb_countingw_after : " << M_TAGMAP_NUMDQ(addr) << ' ' << counter << '\n';
	return M_TAGMAP_NUMW(addr) - counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingb_before(ADDRINT addr)
{
	return M_TAGMAP_NUMB(addr);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingb_after(ADDRINT addr, ADDRINT counter)
{
	//*out << "inst_cb_countingb_after : " << M_TAGMAP_NUMDQ(addr) << ' ' << counter << '\n';
	return M_TAGMAP_NUMB(addr) - counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingq_before(ADDRINT addr)
{
	return M_TAGMAP_NUMQ(addr);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingq_after(ADDRINT addr, ADDRINT counter)
{
	//*out << "inst_cb_countingq_after : " << M_TAGMAP_NUMDQ(addr) << ' ' << counter << '\n';
	return M_TAGMAP_NUMQ(addr) - counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingdq_before(ADDRINT addr)
{
	return M_TAGMAP_NUMDQ(addr);
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_countingdq_after(ADDRINT addr, ADDRINT counter)
{
	//*out << "inst_cb_countingdq_after : " << M_TAGMAP_NUMDQ(addr) << ' ' << counter << '\n';
	return M_TAGMAP_NUMDQ(addr) - counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_counting_ifer(ADDRINT counter)
{
	return counter;
}

ADDRINT PIN_FAST_ANALYSIS_CALL
inst_cb_counting_last(ADDRINT counter, ADDRINT counter_tmp)
{
	counter += counter_tmp;
	return counter;
}