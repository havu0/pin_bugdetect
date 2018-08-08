/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Georgios Portokalidis <porto@cs.columbia.edu> contributed to the
 * optimized implementation of tagmap_setn() and tagmap_clrn()
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

//#include <sys/mman.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <intrin.h>

#include "tagmap.h"
#include "branch_pred.h"
#include "data_chunk.h"
#include "tracker_etctaint.h"

#ifdef	HUGE_TLB
#ifndef	MAP_HUGETLB
#define	MAP_HUGETLB	0x40000	/* architecture specific */
#endif
#define MAP_FLAGS	MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB
#else
#define MAP_FLAGS	MAP_PRIVATE | MAP_ANONYMOUS
#endif


/*
 * tagmap
 *
 * the tagmap is the core data structure in libdft.
 * It keeps the tag information for the virtual address space
 * of a process. For the 32-bit x86 architecture, it is implemented
 * using a BITMAP_SZ MB bitmap.
 *
 * Every byte that is addressable in the 32-bit virtual address
 * space is represented using one bit on the tagmap.
 */
uint8_t *bitmap = NULL;

/*
 * initialize the tagmap; allocate space
 *
 * returns:	0 on success, 1 on error 
 */
int
tagmap_alloc(void)
{
	/*
	 * allocate space for the bitmap by invoking mmap(2);
	 * if HUGE_TLB is defined, then the mapping is done
	 * using ``huge pages''
	 */
	//if (unlikely((bitmap = (uint8_t *)mmap(NULL,
	//					BITMAP_SZ,
	//					PROT_READ | PROT_WRITE,
	//					MAP_FLAGS,
	//					-1, 0)) == MAP_FAILED))
	    if((bitmap = (uint8_t *)malloc(BITMAP_SZ)) == NULL )
		/* return with failure */
		return 1;
	memset(bitmap, 0, BITMAP_SZ);
	/* return with success */
	return 0;
}

/*
 * dispose the tagmap; deallocate its space
 */
void
tagmap_free(void)
{
	/* deallocate the bitmap space */
	//(void)munmap(bitmap, BITMAP_SZ);
	free(bitmap);
}

/*
 * tag a byte on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setb(size_t addr)
{
	/* assert the bit that corresponds to the given address */
	bitmap[VIRT2BYTE(addr)] |= (BYTE_MASK << VIRT2BIT(addr));
}

/*
 * untag a byte on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrb(size_t addr)
{
	/* clear the bit that corresponds to the given address */
	bitmap[VIRT2BYTE(addr)] &= ~(BYTE_MASK << VIRT2BIT(addr));
	M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
}

/*
 * get the tag value of a byte from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
size_t PIN_FAST_ANALYSIS_CALL
tagmap_getb(size_t addr)
{
	/* get the bit that corresponds to the address */
	return bitmap[VIRT2BYTE(addr)] & (BYTE_MASK << VIRT2BIT(addr));
}

size_t PIN_FAST_ANALYSIS_CALL
tagmap_getb_or(size_t addr, ADDRINT orop)
{
	/* get the bit that corresponds to the address */
	return orop | (bitmap[VIRT2BYTE(addr)] & (BYTE_MASK << VIRT2BIT(addr)));
}

/*
 * tag a word (i.e., 2 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setw(size_t addr)
{
	/*
	 * assert the bits that correspond to the addresses of the word
	 *
	 * NOTE: we use 16-bit words for referring to the bitmap in order
	 * to avoid checking for cases where we need to set cross-byte bits
	 * (e.g., 2 bits starting from address 0x00000007)
	 */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
			(WORD_MASK << VIRT2BIT(addr));
}

/*
 * untag a word (i.e., 2 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrw(size_t addr)
{
	/* clear the bits that correspond to the addresses of the word */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
			~(WORD_MASK << VIRT2BIT(addr));
	M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
	M_PUT_ADDR_HASHMAP(hm1, addr + 1, DTree *, 0);
}

/*
 * get the tag value of a word (i.e., 2 bytes) from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
size_t PIN_FAST_ANALYSIS_CALL
tagmap_getw(size_t addr)
{
	/* get the bits that correspond to the addresses of the word */
	return *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(WORD_MASK << VIRT2BIT(addr));
}

size_t PIN_FAST_ANALYSIS_CALL
tagmap_getw_or(size_t addr, ADDRINT orop)
{
	/* get the bits that correspond to the addresses of the word */
	return orop | (*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(WORD_MASK << VIRT2BIT(addr)));
}

/*
 * tag a long word (i.e., 4 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setl(size_t addr)
{
	/*
	 * assert the bits that correspond to the addresses of the long word
	 *
	 * NOTE: we use 16-bit words for referring to the bitmap in order
	 * to avoid checking for cases where we need to set cross-byte bits
	 * (e.g., 4 bits starting from address 0x00000006)
	 */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
			(LONG_MASK << VIRT2BIT(addr));
}

/*
 * untag a long word (i.e., 4 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrl(size_t addr)
{
	/* clear the bits that correspond to the addresses of the long word */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
			~(LONG_MASK << VIRT2BIT(addr));
	M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
	M_PUT_ADDR_HASHMAP(hm1, addr + 1, DTree *, 0);
	M_PUT_ADDR_HASHMAP(hm1, addr + 2, DTree *, 0);
	M_PUT_ADDR_HASHMAP(hm1, addr + 3, DTree *, 0);
}

/*
 * get the tag value of a long word (i.e., 4 bytes) from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
size_t PIN_FAST_ANALYSIS_CALL
tagmap_getl(size_t addr)
{
	/* get the bits that correspond to the addresses of the long word */
	return *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(LONG_MASK << VIRT2BIT(addr));
}

size_t PIN_FAST_ANALYSIS_CALL
tagmap_getl_or(size_t addr, ADDRINT orop)
{
	/* get the bits that correspond to the addresses of the long word */
	return orop | (*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(LONG_MASK << VIRT2BIT(addr)));
}

/*
 * tag a quad word (i.e., 8 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setq(size_t addr)
{
	/*
	 * assert the bits that correspond to the addresses of the quad word
	 *
	 * NOTE: we use 16-bit words for referring to the bitmap in order
	 * to avoid checking for cases where we need to set cross-byte bits
	 * (e.g., 8 bits starting from address 0x00000002)
	 */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
			(QUAD_MASK << VIRT2BIT(addr));
}

/*
 * untag a quad word (i.e., 8 bytes) on the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrq(size_t addr)
{
	/* assert the bits that correspond to the addresses of the quad word */
	*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
			~(QUAD_MASK << VIRT2BIT(addr));
	for(int i = 0; i < 8; i++) {
		M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
	}
}

/*
 * get the tag value of a quad word (i.e., 8 bytes) from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
size_t PIN_FAST_ANALYSIS_CALL
tagmap_getq(size_t addr)
{
	/* get the bits that correspond to the addresses of the quad word */
	return *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(QUAD_MASK << VIRT2BIT(addr));
}

size_t PIN_FAST_ANALYSIS_CALL
tagmap_getq_or(size_t addr, ADDRINT orop)
{
	/* get the bits that correspond to the addresses of the quad word */
	return orop | (*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(QUAD_MASK << VIRT2BIT(addr)));
}

/*
 * check if an arbitrary number of bytes on the virtual address space are set
 *
 * in case the number of bytes can be handled efficiently (e.g.,
 * tag a byte, word, long, or quad) then we use one the previous
 * functions. In all other cases, we try to align the number of
 * bits that needs to be checked for reusing the get{b, w, l ,q}()
 * functions as much as possible 
 *
 * @addr:	the virtual address
 * @num:	the number of bytes to check
 *
 * returns:	0 if clean, non-zero otherwise
 */
size_t
tagmap_issetn(size_t addr, size_t num)
{
	/* alignment offset */
	int alg_off;
	size_t tag;

	/* fast path for small writes (i.e., ~8 bytes) */
	if (num <= ALIGN_OFF_MAX) {
		switch (num) {
			/* tag 1 byte; similar to tagmap_setb() */
			case 1:
				tag = tagmap_getb(addr);
				break;
			/* tag 2 bytes; similar to tagmap_setw() */
			case 2:
				tag = tagmap_getw(addr);
				break;
			/* tag 3 bytes */
			case 3:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
					(_3BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 4 bytes; similar to tagmap_setl() */
			case 4:
				tag = tagmap_getl(addr);
				break;
			/* tag 5 bytes */
			case 5:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
					(_5BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 6 bytes */
			case 6:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
					(_6BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 7 bytes */
			case 7:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
					(_7BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 8 bytes; similar to tagmap_setq() */
			case 8:
				tag = tagmap_getq(addr);
				break;
			default:
				/* nothing to do */
				tag = 0;
				break;
		}

		/* done */
		return tag;
	}

	/* 
	 * estimate the address alignment offset;
	 * how many bits we need to check in 
	 * order to align the address
	 */
	alg_off = ALIGN_OFF_MAX - VIRT2BIT(addr);

	/* 
	 * check the appropriate number of bits
	 * in order to align the address
	 */
	switch (alg_off) {
		/* tag 1 byte; similar to tagmap_setb() */
		case 1:
			tag = tagmap_getb(addr);
			break;
		/* tag 2 bytes; similar to tagmap_setw() */
		case 2:
			tag = tagmap_getw(addr);
			break;
		/* tag 3 bytes */
		case 3:
			/* 
			 * check the bits that correspond to
			 * the addresses of the 3 bytes
			 */
			tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
				(_3BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 4 bytes; similar to tagmap_setl() */
		case 4:
			tag = tagmap_getl(addr);
			break;
		/* tag 5 bytes */
		case 5:
			/* 
			 * check the bits that correspond to
			 * the addresses of the 5 bytes
			 */
			tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
				(_5BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 6 bytes */
		case 6:
			/* 
			 * check the bits that correspond to
			 * the addresses of the 6 bytes
			 */
			tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
				(_6BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 7 bytes */
		case 7:
			/* 
			 * check the bits that correspond to
			 * the addresses of the 7 bytes
			 */
			tag = *((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
				(_7BYTE_MASK << VIRT2BIT(addr));
			break;
		/* the address is already aligned */
		case 8:
			/* fix the alg_offset */
			alg_off = 0;
		default:
			/* nothing to do */
			tag = 0;
			break;
	}

	if (tag)
		return tag;

	/* patch the address and bytes left */
	addr	+= alg_off;
	num	-= alg_off;
	
	/* 
	 * fast path; check a 32 bits chunk at a time
	 * we assume that in most cases the tags are going to be clear, so we
	 * only check the tag after the loop
	 */
	for (tag = 0; num >= ASSERT_FAST; num -= ASSERT_FAST, 
			addr += ASSERT_FAST)
		tag |= *((uint32_t *)(bitmap + VIRT2BYTE(addr)));
	if (tag)
		return tag;
	
	/* slow path; check whatever is left */
	while (num > 0) {
		switch (num) {
			/* tag 1 byte; similar to tagmap_setb() */
			case 1:
				tag |= tagmap_getb(addr);
				num--; addr++;
				break;
			/* tag 2 bytes; similar to tagmap_setw() */
			case 2:
				tag |= tagmap_getw(addr);
				num -= 2; addr += 2;
				break;
			/* tag 3 bytes */
			case 3:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				tag |= *((uint16_t *)(bitmap + VIRT2BYTE(addr)))
					& (_3BYTE_MASK << VIRT2BIT(addr));
				num -= 3; addr += 3;
				break;
			/* tag 4 bytes; similar to tagmap_setl() */
			case 4:
				tag |= tagmap_getl(addr);
				num -= 4; addr += 4;
				break;
			/* tag 5 bytes */
			case 5:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				tag |= *((uint16_t *)(bitmap + VIRT2BYTE(addr)))
					& (_5BYTE_MASK << VIRT2BIT(addr));
				num -= 5; addr += 5;
				break;
			/* tag 6 bytes */
			case 6:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				tag |= *((uint16_t *)(bitmap + VIRT2BYTE(addr)))
					& (_6BYTE_MASK << VIRT2BIT(addr));
				num -= 6; addr += 6;
				break;
			/* tag 7 bytes */
			case 7:
				/* 
				 * check the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				tag |= *((uint16_t *)(bitmap + VIRT2BYTE(addr)))
					& (_7BYTE_MASK << VIRT2BIT(addr));
				num -= 7; addr += 7;
				break;
			/* tag 8 bytes; similar to tagmap_setq() */
			default:
				tag |= tagmap_getq(addr);
				num -= 8; addr += 8;
				break;
		}
	}

	return tag;
}

size_t PIN_FAST_ANALYSIS_CALL
tagmap_issetn_or(size_t addr, size_t num, ADDRINT orop)
{
	return orop | tagmap_issetn(addr, num);
}

/*
 * tag an arbitrary number of bytes on the virtual address space
 *
 * in case the number of bytes can be handled efficiently (e.g.,
 * tag a byte, word, long, or quad) then we use one the previous
 * functions. In all other cases, we try to align the number of
 * bits that needs to be asserted for reusing the set{b, w, l ,q}()
 * functions as much as possible 
 *
 * @addr:	the virtual address
 * @num:	the number of bytes to tag
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setn(size_t addr, size_t num)
{
	/* alignment offset */
	int alg_off;

	/* fast path for small writes (i.e., ~8 bytes) */
	if (num <= ALIGN_OFF_MAX) {
		switch (num) {
			/* tag 1 byte; similar to tagmap_setb() */
			case 1:
				tagmap_setb(addr);
				break;
			/* tag 2 bytes; similar to tagmap_setw() */
			case 2:
				tagmap_setw(addr);
				break;
			/* tag 3 bytes */
			case 3:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_3BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 4 bytes; similar to tagmap_setl() */
			case 4:
				tagmap_setl(addr);
				break;
			/* tag 5 bytes */
			case 5:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_5BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 6 bytes */
			case 6:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_6BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 7 bytes */
			case 7:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_7BYTE_MASK << VIRT2BIT(addr));
				break;
			/* tag 8 bytes; similar to tagmap_setq() */
			case 8:
				tagmap_setq(addr);
				break;
			default:
				/* nothing to do */
				break;
		}

		/* done */
		return;
	}

	/* 
	 * estimate the address alignment offset;
	 * how many bits we need to assert in 
	 * order to align the address
	 */
	alg_off = ALIGN_OFF_MAX - VIRT2BIT(addr);

	/* 
	 * assert the appropriate number of bits
	 * in order to align the address
	 */
	switch (alg_off) {
		/* tag 1 byte; similar to tagmap_setb() */
		case 1:
			tagmap_setb(addr);
			break;
		/* tag 2 bytes; similar to tagmap_setw() */
		case 2:
			tagmap_setw(addr);
			break;
		/* tag 3 bytes */
		case 3:
			/* 
			 * assert the bits that correspond to
			 * the addresses of the 3 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
				(_3BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 4 bytes; similar to tagmap_setl() */
		case 4:
			tagmap_setl(addr);
			break;
		/* tag 5 bytes */
		case 5:
			/* 
			 * assert the bits that correspond to
			 * the addresses of the 5 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
				(_5BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 6 bytes */
		case 6:
			/* 
			 * assert the bits that correspond to
			 * the addresses of the 6 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
				(_6BYTE_MASK << VIRT2BIT(addr));
			break;
		/* tag 7 bytes */
		case 7:
			/* 
			 * assert the bits that correspond to
			 * the addresses of the 7 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
				(_7BYTE_MASK << VIRT2BIT(addr));
			break;
		/* the address is already aligned */
		case 8:
			/* fix the alg_offset */
			alg_off = 0;
		default:
			/* nothing to do */
			break;
	}

	/* patch the address and bytes left */
	addr	+= alg_off;
	num	-= alg_off;
	
	/* 
	 * fast path; assert a 32 bits chunk at a time
	 */
	for (; num >= ASSERT_FAST; num -= ASSERT_FAST, addr += ASSERT_FAST)
		*((uint32_t *)(bitmap + VIRT2BYTE(addr))) = ~0x0U;
	
	/* slow path; assert whatever is left */
	while (num > 0) {
		switch (num) {
			/* tag 1 byte; similar to tagmap_setb() */
			case 1:
				tagmap_setb(addr);
				num--; addr++;
				break;
			/* tag 2 bytes; similar to tagmap_setw() */
			case 2:
				tagmap_setw(addr);
				num -= 2; addr += 2;
				break;
			/* tag 3 bytes */
			case 3:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_3BYTE_MASK << VIRT2BIT(addr));
				num -= 3; addr += 3;
				break;
			/* tag 4 bytes; similar to tagmap_setl() */
			case 4:
				tagmap_setl(addr);
				num -= 4; addr += 4;
				break;
			/* tag 5 bytes */
			case 5:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_5BYTE_MASK << VIRT2BIT(addr));
				num -= 5; addr += 5;
				break;
			/* tag 6 bytes */
			case 6:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_6BYTE_MASK << VIRT2BIT(addr));
				num -= 6; addr += 6;
				break;
			/* tag 7 bytes */
			case 7:
				/* 
				 * assert the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) |=
					(_7BYTE_MASK << VIRT2BIT(addr));
				num -= 7; addr += 7;
				break;
			/* tag 8 bytes; similar to tagmap_setq() */
			default:
				tagmap_setq(addr);
				num -= 8; addr += 8;
				break;
		}
	}
}

/*
 * untag an arbitrary number of bytes on the virtual address space
 *
 * @addr:	the virtual address
 * @num:	the number of bytes to untag
 */
void
tagmap_clrn(size_t addr, size_t num)
{
	/* alignment offset */
	int alg_off;

	/* fast path for small writes (i.e., ~8 bytes) */
	if (num <= ALIGN_OFF_MAX) {
		switch (num) {
			/* untag 1 byte; similar to tagmap_clrb() */
			case 1:
				tagmap_clrb(addr);
				break;
			/* untag 2 bytes; similar to tagmap_clrw() */
			case 2:
				tagmap_clrw(addr);
				break;
			/* untag 3 bytes */
			case 3:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_3BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 3; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
				}
				break;
			/* untag 4 bytes; similar to tagmap_clrl() */
			case 4:
				tagmap_clrl(addr);
				break;
			/* untag 5 bytes */
			case 5:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_5BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 5; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
				}
				break;
			/* untag 6 bytes */
			case 6:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_6BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 6; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
				}
				break;
			/* untag 7 bytes */
			case 7:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_7BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 7; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
				}
				break;
			/* untag 8 bytes; similar to tagmap_clrq() */
			case 8:
				tagmap_clrq(addr);
				break;
			default:
				/* nothing to do */
				break;
		}

		/* done */
		return;
	}

	/* 
	 * estimate the address alignment offset;
	 * how many bits we need to assert in 
	 * order to align the address
	 */
	alg_off = ALIGN_OFF_MAX - VIRT2BIT(addr);

	/* 
	 * clear the appropriate number of bits
	 * in order to align the address
	 */
	switch (alg_off) {
		/* untag 1 byte; similar to tagmap_crlb() */
		case 1:
			tagmap_clrb(addr);
			break;
		/* untag 2 bytes; similar to tagmap_clrw() */
		case 2:
			tagmap_clrw(addr);
			break;
		/* untag 3 bytes */
		case 3:
			/* 
			 * clear the bits that correspond to
			 * the addresses of the 3 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
				~(_3BYTE_MASK << VIRT2BIT(addr));
			for(int i = 0; i < 3; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
			}
			break;
		/* untag 4 bytes; similar to tagmap_clrl() */
		case 4:
			tagmap_clrl(addr);
			break;
		/* untag 5 bytes */
		case 5:
			/* 
			 * clear the bits that correspond to
			 * the addresses of the 5 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
				~(_5BYTE_MASK << VIRT2BIT(addr));
			for(int i = 0; i < 5; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
			}
			break;
		/* untag 6 bytes */
		case 6:
			/* 
			 * clear the bits that correspond to
			 * the addresses of the 6 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
				~(_6BYTE_MASK << VIRT2BIT(addr));
			for(int i = 0; i < 6; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
			}
			break;
		/* untag 7 bytes */
		case 7:
			/* 
			 * clear the bits that correspond to
			 * the addresses of the 7 bytes
			 */
			*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
				~(_7BYTE_MASK << VIRT2BIT(addr));
			for(int i = 0; i < 7; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr + i, DTree *, 0);
			}
			break;
		/* the address is already aligned */
		case 8:
			/* fix the alg_offset */
			alg_off = 0;
		default:
			/* nothing to do */
			break;
	}

	/* patch the address and bytes left */
	addr	+= alg_off;
	num	-= alg_off;
	
	/* 
	 * fast path; clear a 32 bits chunk at a time
	 */
	for (; num >= ASSERT_FAST; num -= ASSERT_FAST, addr += ASSERT_FAST) {
		*((uint32_t *)(bitmap + VIRT2BYTE(addr))) = 0x0U;
		for(int i = 0; i < 8; i++) {
			M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
		}
	}
	
	/* slow path; clear whatever is left */
	while (num > 0) {
		switch (num) {
			/* untag 1 byte; similar to tagmap_clrb() */
			case 1:
				tagmap_clrb(addr);
				num--;
				break;
			/* untag 2 bytes; similar to tagmap_clrw() */
			case 2:
				tagmap_clrw(addr);
				num -= 2;
				break;
			/* untag 3 bytes */
			case 3:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 3 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_3BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 3; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
				}
				num -= 3;
				break;
			/* untag 4 bytes; similar to tagmap_clrl() */
			case 4:
				tagmap_clrl(addr);
				num -= 4;
				break;
			/* untag 5 bytes */
			case 5:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 5 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_5BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 5; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
				}
				num -= 5;
				break;
			/* untag 6 bytes */
			case 6:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 6 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &=
					~(_6BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 6; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
				}
				num -= 6;
				break;
			/* untag 7 bytes */
			case 7:
				/* 
				 * clear the bits that correspond to
				 * the addresses of the 7 bytes
				 */
				*((uint16_t *)(bitmap + VIRT2BYTE(addr))) *=
					~(_7BYTE_MASK << VIRT2BIT(addr));
				for(int i = 0; i < 7; i++) {
					M_PUT_ADDR_HASHMAP(hm1, addr, DTree *, 0);
				}
				num -= 7;
				break;
			/* untag 8 bytes; similar to tagmap_clrq() */
			default:
				tagmap_clrq(addr);
				num -= 8; 
				break;
		}
	}
}

size_t __forceinline 
tagmap_numb(size_t addr)
{
	return __popcnt(bitmap[VIRT2BYTE(addr)] & (BYTE_MASK << VIRT2BIT(addr)));
}

size_t __forceinline 
tagmap_numw(size_t addr)
{
	return __popcnt16(*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(WORD_MASK << VIRT2BIT(addr)));
}

size_t __forceinline 
tagmap_numl(size_t addr)
{
	return __popcnt(*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(LONG_MASK << VIRT2BIT(addr)));
}

size_t __forceinline 
tagmap_numq(size_t addr)
{
	return __popcnt(*((uint16_t *)(bitmap + VIRT2BYTE(addr))) &
			(LONG_MASK << VIRT2BIT(addr))) + 
			__popcnt(*((uint16_t *)(bitmap + VIRT2BYTE(addr + 4))) &
			(LONG_MASK << (VIRT2BIT(addr + 4))));
}

