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

#ifndef __LIBDFT_CORE_H__
#define __LIBDFT_CORE_H__

#include "pin.H"
#include "filter_.H"

#define R32_ALIGN	REG_EDI			/* alignment offset for 
						   mapping 32-bit PIN registers
						   to VCPU registers */
#define VCPU_MASK128 0xFFFF
#define VCPU_MASK64 0xFF
#define VCPU_MASK32	0x0F			/* 32-bit VCPU mask */
#define VCPU_MASK16	0x03			/* 16-bit VCPU mask */
#define VCPU_MASK8	0x01			/* 8-bit VCPU mask */
#define MEM_QUAD_LEN    64          /* float size (64-bit) */
#define MEM_LONG_LEN	32			/* long size (32-bit) */
#define MEM_WORD_LEN	16			/* word size (16-bit) */
#define MEM_BYTE_LEN	8			/* byte size (8-bit) */
#define BIT2BYTE(len)	((len) >> 3)		/* scale change; macro */

/* extract the EFLAGS.DF bit by applying the corresponding mask */
#define EFLAGS_DF(eflags)	((eflags & 0x0400))

enum {
/* #define */ OP_0 = 0,			/* 0th (1st) operand index */
/* #define */ OP_1 = 1,			/* 1st (2nd) operand index */
/* #define */ OP_2 = 2,			/* 2nd (3rd) operand index */
/* #define */ OP_3 = 3,			/* 3rd (4th) operand index */
/* #define */ OP_4 = 4			/* 4rd (5th) operand index */
};


/* core API */
void ins_inspect(INS);
void ins_inspect_test(INS);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingl_before(ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingl_after(ADDRINT, ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingw_before(ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingw_after(ADDRINT, ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingb_before(ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingb_after(ADDRINT, ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingq_before(ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingq_after(ADDRINT, ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingdq_before(ADDRINT addr);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_countingdq_after(ADDRINT addr, ADDRINT counter);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_counting_ifer(ADDRINT);

ADDRINT PIN_FAST_ANALYSIS_CALL inst_cb_counting_last(ADDRINT, ADDRINT);

#include "libdft_api.h"
ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_l_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_u_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getw_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getl_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getq_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_gethex_or(thread_ctx_t *thread_ctx, unsigned int reg, ADDRINT orop);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_l(thread_ctx_t *thread_ctx, unsigned int reg);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getb_u(thread_ctx_t *thread_ctx, unsigned int reg);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getw(thread_ctx_t *thread_ctx, unsigned int reg);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getl(thread_ctx_t *thread_ctx, unsigned int reg);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_getq(thread_ctx_t *thread_ctx, unsigned int reg);

ADDRINT PIN_FAST_ANALYSIS_CALL
r_gethex(thread_ctx_t *thread_ctx, unsigned int reg);

void PIN_FAST_ANALYSIS_CALL
r_setszor(thread_ctx_t *thread_ctx, unsigned int reg, size_t szor);
void PIN_FAST_ANALYSIS_CALL
r_setsz(thread_ctx_t *thread_ctx, unsigned int reg, size_t szor);

extern ADDRINT cur_dtree_id;

#endif /* __LIBDFT_CORE_H__ */
