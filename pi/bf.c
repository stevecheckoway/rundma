#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "dma.h"
#include "uart.h"

#define UART0_DR 0x7e201000
#define UART0_FR 0x7e201018

static void setup_cb(volatile struct control_block *cb,
			 volatile void *dest, volatile void *src, size_t size,
			 volatile struct control_block *next)
{
	cb->ti = TI_SRC_INC | TI_DEST_INC;
	cb->source_ad = src? virtual_to_bus(src):0;
	cb->dest_ad = dest? virtual_to_bus(dest):0;
	cb->txfr_len = size;
	cb->stride = 0;
	cb->nextconbk = next? virtual_to_bus(next):0;
}

static size_t copy_program(volatile uint8_t *program, const char *program_path)
{
	FILE *fp = fopen(program_path, "r");
	if (!fp)
	{
		perror(program_path);
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	long program_size = ftell(fp);
	if (program_size < 0)
	{
		perror("ftell");
		exit(1);
	}
	rewind(fp);
	if (fread((void *)program, program_size, 1, fp) != 1)
	{
		perror(program_path);
		exit(1);
	}
	program[program_size] = 0;
	return program_size + 1;
}

typedef volatile struct control_block *cb_t;
typedef volatile uint8_t vuint8_t;
typedef volatile uint32_t vuint32_t;

typedef struct
{
	vuint32_t quit;
	vuint32_t nop;
	vuint32_t inc;
	vuint32_t dec;
	vuint32_t right;
	vuint32_t left;
	vuint32_t lcond;
	vuint32_t rcond;
	vuint32_t input;
	vuint32_t output;
} insn_table_t;

typedef struct
{
	cb_t next_cb;

	// Tables
	vuint8_t *dispatch_table;
	vuint8_t *inc_table;
	vuint8_t *dec_table;
	vuint8_t *boolean_inc_table;
        vuint8_t *boolean_dec_table;
	insn_table_t *insn_table;
	vuint32_t *conditional_table;
	vuint8_t *bracket_table;
	vuint32_t *scanleft_table;
	vuint32_t *scanright_table;
	vuint8_t *boolean_read_table;
	vuint8_t *boolean_write_table;

	// Data
	vuint32_t *pc;
	vuint32_t *lc;
	vuint32_t *head;
	
	// Helper gadgets
	cb_t dispatch;
	cb_t tramp;
	cb_t tramp2;
	cb_t inc_4;
	cb_t dec_4;
	cb_t next_insn;

	// Instruction gadgets +-><[],.
	cb_t inc;
	cb_t dec;
	cb_t right;
	cb_t left;
	cb_t lcond;
	cb_t rcond;
	cb_t input;
	cb_t output;

} bf_t;

/* Offsets into the conditional table. */
enum
{
	INC_4_INDEX = 0x0,
	// INC_4_INDEX_1 = 0x1,
	// INC_4_INDEX_2 = 0x2,
	DEC_4_INDEX = 0x3,
	// DEC_4_INDEX_1 = 0x4,
	// DEC_4_INDEX_2 = 0x5,
	LCOND_INDEX = 0x6,
	LCOND_LC_INDEX_0 = 0x7,
	LCOND_LC_INDEX_1 = 0x8,
	LCOND_LC_INDEX_2 = 0x9,
	LCOND_LC_INDEX_3 = 0xa,
	RCOND_INDEX = 0xb,
	RCOND_LC_INDEX_0 = 0xc,
	RCOND_LC_INDEX_1 = 0xd,
	RCOND_LC_INDEX_2 = 0xe,
	RCOND_LC_INDEX_3 = 0xf,
	INPUT_INDEX = 0x10,
	OUTPUT_INDEX = 0x11,
};

static void build_dispatch(bf_t *bf)
{
	// Build the dispatch table.
	memset((void *)bf->dispatch_table, offsetof(insn_table_t, nop), 0x100);
	bf->dispatch_table['\0'] = offsetof(insn_table_t, quit);
	bf->dispatch_table['+'] = offsetof(insn_table_t, inc);
	bf->dispatch_table['-'] = offsetof(insn_table_t, dec);
	bf->dispatch_table['>'] = offsetof(insn_table_t, right);
	bf->dispatch_table['<'] = offsetof(insn_table_t, left);
	bf->dispatch_table['['] = offsetof(insn_table_t, lcond);
	bf->dispatch_table[']'] = offsetof(insn_table_t, rcond);
	bf->dispatch_table[','] = offsetof(insn_table_t, input);
	bf->dispatch_table['.'] = offsetof(insn_table_t, output);

	cb_t cb = bf->next_cb;
	// To dispatch an instruction:
	// 0. Load the pc into the source of cb[1]
	// 1. Load the byte at the pc to use as an offset into the
	//	diapatch_table.
	// 2. Load 1 byte from the dispatch_table to use as an offset
	//	into the insn_table.
	// 3. Load 4 bytes from the insn_table to write into the next
	//	control block of tramp
	// 4. Do nothing in tramp.
	setup_cb(cb + 0, &cb[1].source_ad, bf->pc, 4, cb + 1);
	setup_cb(cb + 1, &cb[2].source_ad, NULL, 1, cb + 2);
	setup_cb(cb + 2, &cb[3].source_ad, bf->dispatch_table, 1, cb + 3);
	setup_cb(cb + 3, &cb[4].nextconbk, bf->insn_table, 4, cb + 4);
	setup_cb(cb + 4, cb + 4, cb + 4, 1, NULL);
	setup_cb(cb + 5, cb + 5, cb + 5, 1, NULL);

	bf->dispatch = cb;
	bf->tramp = cb + 4;
	bf->tramp2 = cb + 5;
	bf->next_cb = cb + 6;
}

/* This is a generic 4-byte increment gadget. The source address of
 * the first control block contains the address of the 4-byte aligned
 * uint32_t to increment. After the gadget is finished, it executes
 * the trampoline gadget tramp. */
static void build_inc_4(bf_t *bf)
{
	assert(bf->tramp);
	assert(bf->tramp2);
	cb_t cb = bf->next_cb;

	/* The basic algorithm is
	 *	 if (++*input)
	 *		 goto tramp;
	 *	 ++input;
	 *	 if (++*input)
	 *		 goto tramp;
	 *	 ++input;
	 *	 if (++*input)
	 *		 goto tramp;
	 *	 ++*input;
	 * tramp:
	 */
	
	bf->inc_4 = cb;
	for (int i = 0; ; ++i)
	{	
		// 0. Copy 1 byte of the input into cb[2]'s source. This
		//	LSB is used as an offset into the inc_table.
		// 1. Copy the input into cb[2]'s destination.
		// 2. Load from the inc_table into the destination. 
		vuint32_t *input = &cb[0].source_ad;
		setup_cb(cb + 0, &cb[2].source_ad, NULL, 1, cb + 1);
		setup_cb(cb + 1, &cb[2].dest_ad, input, 4, cb + 2);
		if (i == 3)
		{
			// Once we perform the increment, we're done
			// so goto tramp.
			setup_cb(cb + 2, NULL, bf->inc_table, 1, bf->tramp);
			cb = cb + 3;
			break;
		}
		// Perform the increment and continue.
		setup_cb(cb + 2, NULL, bf->inc_table, 1, cb + 3);

		// 3. Copy the input address into cb[3]'s source.
		// 4. Load the LSB (which we just wrote) and use as an index
		//	into the boolean_inc_table.
		// 5. Load from the boolean_inc_table and use as the 2nd LSB into
		//	the conditional_table.
		// 6. Load the offset from the conditional_table into tramp2
		//	and execute tramp2.
		setup_cb(cb + 3, &cb[4].source_ad, input, 4, cb + 4);
		setup_cb(cb + 4, &cb[5].source_ad, NULL, 1, cb + 5);
		setup_cb(cb + 5, (vuint8_t *)&cb[6].source_ad + 1, bf->boolean_inc_table, 1, cb + 6);
		setup_cb(cb + 6, &bf->tramp2->nextconbk, bf->conditional_table + INC_4_INDEX + i, 4, bf->tramp2);

		// If the value is 0, then we need to increment the next byte;
		// otherwise, goto tramp.
		bf->conditional_table[INC_4_INDEX + i] = virtual_to_bus(cb + 7);
		bf->conditional_table[INC_4_INDEX + i + 0x40] = virtual_to_bus(bf->tramp);

		// Now we need to repeat the above, but we need to increment
		// the input address so that we operate on the next byte of
		// the word.
		
		// 7. Copy the input address into cb[7]'s source.
		// 8. Load the LSB of the address and use as an offset into
		//	inc_table.
		// 9. Load the incremented address and store it in
		//	cb[10]'s LSB.
		setup_cb(cb + 7, &cb[10].source_ad, input, 4, cb + 8);
		setup_cb(cb + 8, &cb[9].source_ad, input, 1, cb + 9);
		setup_cb(cb + 9, &cb[10].source_ad, bf->inc_table, 1, cb + 10);
		
		// At this point, we can simply repeat
		cb = cb + 10;
	}

	bf->next_cb = cb;
}

/* This is a generic 4-byte decrement gadget. The source address of
 * the first control block contains the address of the 4-byte aligned
 * uint32_t to decrement. After the gadget is finished, it executes
 * the trampoline gadget tramp. */
static void build_dec_4(bf_t *bf)
{
	assert(bf->tramp);
	assert(bf->tramp2);
	cb_t cb = bf->next_cb;

	/* The basic algorithm is
	 *	 if (--*input)
	 *		 goto tramp;
	 *	 ++input;
	 *	 if (--*input)
	 *		 goto tramp;
	 *	 ++input;
	 *	 if (--*input)
	 *		 goto tramp;
	 *	 --*input;
	 *
	 * tramp:
	 */
	
	bf->dec_4 = cb;
	for (int i = 0; ; ++i)
	{
		// 0. Copy 1 byte of the input into cb[2]'s source. This
		//      LSB is used as an offset into the inc_table.
		// 1. Copy the input into cb[2]'s destination.
		// 2. Load from the dec_table into the destination. 
		vuint32_t *input = &cb[0].source_ad;
		setup_cb(cb + 0, &cb[2].source_ad, NULL, 1, cb + 1);
		setup_cb(cb + 1, &cb[2].dest_ad, input, 4, cb + 2);
		if (i == 3)
		{
			// Once we perform the decrement, we're done
			// so goto tramp.
			setup_cb(cb + 2, NULL, bf->dec_table, 1, bf->tramp);
			cb = cb + 3;
			break;
		}
		// Perform the decrement and continue.
		setup_cb(cb + 2, NULL, bf->dec_table, 1, cb + 3);

		// 4. Copy the input address into cb[3]'s source
		// 5. Load the LSB (which we just wrote) and use as an index
		//	into the boolean_dec_table.
		// 6. Load from the boolean_dec_table and use as the 2nd LSB
		//	into the conditional_table.
		// 7. Load the offset from the conditional_table into tramp2
		//	and execute tramp2.
		setup_cb(cb + 3, &cb[4].source_ad, input, 4, cb + 4);
		setup_cb(cb + 4, &cb[5].source_ad, NULL, 1, cb + 5);
		setup_cb(cb + 5, (vuint8_t *)&cb[6].source_ad + 1, bf->boolean_dec_table, 1, cb + 6);
		setup_cb(cb + 6, &bf->tramp2->nextconbk, bf->conditional_table + DEC_4_INDEX + i, 4, bf->tramp2);

		// If the value is 255, then we need to decrement the next byte;
		// otherwise, goto tramp.
		bf->conditional_table[DEC_4_INDEX + i] = virtual_to_bus(cb + 7);
		bf->conditional_table[DEC_4_INDEX + i + 0x40] = virtual_to_bus(bf->tramp);

		// Now we need to repeat the above, but we need to increment
		// the input address so that we operate on the next byte of
		// the word.
		
		// 8. Copy the input address into cb[7]'s source.
		// 9. Load the LSB of the address and use as an offset into
		//	inc_table.
		// 10. Load the incremented address and store it in
		//	 cb[11]'s LSB.
		setup_cb(cb + 7, &cb[10].source_ad, input, 4, cb + 8);
		setup_cb(cb + 8, &cb[9].source_ad, input, 1, cb + 9);
		setup_cb(cb + 9, &cb[10].source_ad, bf->inc_table, 1, cb + 10);
		
		// At this point, we can simply repeat
		cb = cb + 10;
	}	

	bf->next_cb = cb;
}

static void build_next_insn(bf_t *bf)
{
	assert(bf->dispatch);
	assert(bf->inc_4);
	assert(bf->tramp);

	cb_t cb = bf->next_cb;
	// To execute the next instruction, increment the pc by 1 and
	// then goto dispatch by using the trampoline 
	setup_cb(cb + 0, &bf->inc_4->source_ad, &cb[0].stride, 4, cb + 1);	
	cb[0].stride = virtual_to_bus(bf->pc);
	setup_cb(cb + 1, &bf->tramp->nextconbk, &cb[1].stride, 4, bf->inc_4);
	cb[1].stride = virtual_to_bus(bf->dispatch);

	bf->next_insn = cb;
	bf->next_cb = cb + 2;
}

static void build_incdec(bf_t *bf)
{
	assert(bf->next_insn);

	// Build the inc/dec tables.
	for (int i = 0; i < 256; ++i)
	{
		bf->inc_table[i] = i + 1;
		bf->dec_table[i] = i - 1;
	}

	cb_t cb = bf->next_cb;
	// Set up the control blocks for inc.
	bf->inc = cb;
	// 0. Copy from the head into cb[2]'s source
	setup_cb(cb + 0, &cb[2].source_ad, bf->head, 4, cb + 1);
	// 1. Copy from the head into cb[3]'s destination
	setup_cb(cb + 1, &cb[3].dest_ad, bf->head, 4, cb + 2);
	// 2. Copy from the tape into the LSB of cb[3]'s source
	setup_cb(cb + 2, &cb[3].source_ad, NULL, 1, cb + 3);
	// 3. Copy from the increment table into the tape
	setup_cb(cb + 3, NULL, bf->inc_table, 1, bf->next_insn);
	cb += 4;

	// Set up the control blocks for dec which is identical to inc
	// except for the table.
	bf->dec = cb;
	// 0. Copy from the head into cb[2]'s source
	setup_cb(cb + 0, &cb[2].source_ad, bf->head, 4, cb + 1);
	// 1. Copy from the head into cb[3]'s destination
	setup_cb(cb + 1, &cb[3].dest_ad, bf->head, 4, cb + 2);
	// 2. Copy from the tape into the LSB of cb[3]'s source
	setup_cb(cb + 2, &cb[3].source_ad, NULL, 1, cb + 3);
	// 3. Copy from the decrement table into the tape
	setup_cb(cb + 3, NULL, bf->dec_table, 1, bf->next_insn);
	cb += 4;

	bf->next_cb = cb;
}

static void build_rightleft(bf_t *bf)
{
	assert(bf->next_insn);
	assert(bf->inc_4);
	assert(bf->dec_4);

	cb_t cb = bf->next_cb;
	// To move right, increment the head by 1 and then goto
	// next_insn via the trampoline.
	setup_cb(cb + 0, &bf->inc_4->source_ad, &cb[0].stride, 4, cb + 1);
	cb[0].stride = virtual_to_bus(bf->head);
	setup_cb(cb + 1, &bf->tramp->nextconbk, &cb[1].stride, 4, bf->inc_4);
	cb[1].stride = virtual_to_bus(bf->next_insn);
	bf->right = cb;
	cb += 2;

	// To move left, decrement the head by 1 and then goto
	// next_insn via the trampoline.
	setup_cb(cb + 0, &bf->dec_4->source_ad, &cb[0].stride, 4, cb + 1);
	cb[0].stride = virtual_to_bus(bf->head);
	setup_cb(cb + 1, &bf->tramp->nextconbk, &cb[1].stride, 4, bf->dec_4);
	cb[1].stride = virtual_to_bus(bf->next_insn);
	bf->left = cb;
	bf->next_cb = cb + 2;
}

static void build_cond(bf_t *bf)
{
	assert(bf->next_insn);
	assert(bf->inc_4);
	assert(bf->dec_4);

	// Build bracket table with offsets into scan(right||left)_table.
	memset((void *)bf->bracket_table, 0, 0x100);
	bf->bracket_table['['] = 0x4;
	bf->bracket_table[']'] = 0x8;
	bf->bracket_table[0] = 0xc;  

	cb_t cb = bf->next_cb;
	// Set up the control blocks for lcond.
	bf->lcond = cb;

	//
	// LCOND: 
	//
	// 0/3. If !*head goto next_insn, else increment lc and scan right.
	setup_cb(cb + 0, &cb[1].source_ad, bf->head, 4, cb + 1);
	setup_cb(cb + 1, &cb[2].source_ad, NULL, 1, cb + 2);
	setup_cb(cb + 2, (vuint8_t *)&cb[3].source_ad + 1, bf->boolean_inc_table, 1, cb + 3);
	setup_cb(cb + 3, &bf->tramp->nextconbk, bf->conditional_table + LCOND_INDEX, 4, bf->tramp);
	bf->conditional_table[LCOND_INDEX] = virtual_to_bus(cb + 4); // Increment lc, scan right. 
	bf->conditional_table[LCOND_INDEX + 0x40] = virtual_to_bus(bf->next_insn); // Goto next_insn. 

	// 4/5. Increment the loop counter (lc).
	setup_cb(cb + 4, &bf->inc_4->source_ad, &cb[4].stride, 4, cb + 5);	
	cb[4].stride = virtual_to_bus(bf->lc);
	setup_cb(cb + 5, &bf->tramp->nextconbk, &cb[5].stride, 4, bf->inc_4);
	cb[5].stride = virtual_to_bus(cb + 6);

	// SCAN RIGHT:
	// 6/7. Increment the program counter (pc).
	setup_cb(cb + 6, &bf->inc_4->source_ad, &cb[6].stride, 4, cb + 7);	
	cb[6].stride = virtual_to_bus(bf->pc);
	setup_cb(cb + 7, &bf->tramp->nextconbk, &cb[7].stride, 4, bf->inc_4);
	cb[7].stride = virtual_to_bus(cb + 8);

	// 8. Copy the pc into cb[9]'s source. 
	setup_cb(cb + 8, &cb[9].source_ad, bf->pc, 4, cb + 9);
	// 9. Load the LSB and use as index into the bracket_table.
	setup_cb(cb + 9, &cb[10].source_ad, NULL, 1, cb + 10);
	// 10. Load from the bracket_table and use as index into scanright table.
	setup_cb(cb + 10, &cb[11].source_ad, bf->bracket_table, 1, cb + 11);
	// 11. Load the offset from scanright_table into tramp and execute tramp.
	setup_cb(cb + 11, &bf->tramp->nextconbk, bf->scanright_table, 4, bf->tramp);

	// Build scanright table after we setup the control blocks.
	memset((void *)bf->scanright_table, 0, 0xc);
	bf->scanright_table[0] = virtual_to_bus(cb + 6); // Scan right.
	bf->scanright_table[1] = virtual_to_bus(cb + 4); // If *pc = '['; ++lc.
	bf->scanright_table[2] = virtual_to_bus(cb + 12); // If *pc = ']'; --lc.
	bf->scanright_table[3] = 0; // No matching ']' quit.

	// 12/13. Decrement the loop counter (lc). 
	setup_cb(cb + 12, &bf->dec_4->source_ad, &cb[12].stride, 4, cb + 13);	
	cb[12].stride = virtual_to_bus(bf->lc);
	setup_cb(cb + 13, &bf->tramp->nextconbk, &cb[13].stride, 4, bf->dec_4);
	cb[13].stride = virtual_to_bus(cb + 14);

	// 14/16. If the LSB of lc is 0 then check next byte, else scan right. 
	setup_cb(cb + 14, &cb[15].source_ad, bf->lc, 1, cb + 15);
	setup_cb(cb + 15, (vuint8_t *)&cb[16].source_ad + 1, bf->boolean_inc_table, 1, cb + 16);
	setup_cb(cb + 16, &bf->tramp->nextconbk, bf->conditional_table + LCOND_LC_INDEX_0, 4, bf->tramp);
	bf->conditional_table[LCOND_LC_INDEX_0] = virtual_to_bus(cb + 17); // Check next byte.
	bf->conditional_table[LCOND_LC_INDEX_0 + 0x40] = virtual_to_bus(cb + 6); // Scan right.

	// 17/19. 2nd LSB.
	setup_cb(cb + 17, &cb[18].source_ad, (vuint8_t *)bf->lc + 1, 1, cb + 18);
	setup_cb(cb + 18, (vuint8_t *)&cb[19].source_ad + 1, bf->boolean_inc_table, 1, cb + 19);
	setup_cb(cb + 19, &bf->tramp->nextconbk, bf->conditional_table + LCOND_LC_INDEX_1, 4, bf->tramp);
	bf->conditional_table[LCOND_LC_INDEX_1] = virtual_to_bus(cb + 20); // Check next byte.
	bf->conditional_table[LCOND_LC_INDEX_1 + 0x40] = virtual_to_bus(cb + 6); // Scan right.   

	// 20/22. 3rd LSB.
	setup_cb(cb + 20, &cb[21].source_ad, (vuint8_t *)bf->lc + 2, 1, cb + 21);
	setup_cb(cb + 21, (vuint8_t *)&cb[22].source_ad + 1, bf->boolean_inc_table, 1, cb + 22);
	setup_cb(cb + 22, &bf->tramp->nextconbk, bf->conditional_table + LCOND_LC_INDEX_2, 4, bf->tramp);
	bf->conditional_table[LCOND_LC_INDEX_2] = virtual_to_bus(cb + 23); // Check next byte.
	bf->conditional_table[LCOND_LC_INDEX_2 + 0x40] = virtual_to_bus(cb + 6); // Scan right.   

	// 23/25. 4th LSB. 
	setup_cb(cb + 23, &cb[24].source_ad, (vuint8_t *)bf->lc + 3, 1, cb + 24);
	setup_cb(cb + 24, (vuint8_t *)&cb[25].source_ad + 1, bf->boolean_inc_table, 1, cb + 25);
	setup_cb(cb + 25, &bf->tramp->nextconbk, bf->conditional_table + LCOND_LC_INDEX_3, 4, bf->tramp); 
	bf->conditional_table[LCOND_LC_INDEX_3] = virtual_to_bus(bf->next_insn); // Goto next_insn.
	bf->conditional_table[LCOND_LC_INDEX_3 + 0x40] = virtual_to_bus(cb + 6); // Scan right.		   

	cb += 26;
	// Set up the control blocks for rcond.
	bf->rcond = cb;

	//
	// RCOND: 
	//
	// 0/3. If !*head goto next_insn, else increment lc and scan left.
	setup_cb(cb + 0, &cb[1].source_ad, bf->head, 4, cb + 1);
	setup_cb(cb + 1, &cb[2].source_ad, NULL, 1, cb + 2);
	setup_cb(cb + 2, (vuint8_t *)&cb[3].source_ad + 1, bf->boolean_inc_table, 1, cb + 3);
	setup_cb(cb + 3, &bf->tramp->nextconbk, bf->conditional_table + RCOND_INDEX, 4, bf->tramp);
	bf->conditional_table[RCOND_INDEX] = virtual_to_bus(bf->next_insn); // Goto next_insn. 
	bf->conditional_table[RCOND_INDEX + 0x40] = virtual_to_bus(cb + 4); // Increment lc, scan left.

	// 4/5. Increment the loop counter (lc).
	setup_cb(cb + 4, &bf->inc_4->source_ad, &cb[4].stride, 4, cb + 5);	
	cb[4].stride = virtual_to_bus(bf->lc);
	setup_cb(cb + 5, &bf->tramp->nextconbk, &cb[5].stride, 4, bf->inc_4);
	cb[5].stride = virtual_to_bus(cb + 6);

	// SCAN LEFT: 
	// 6/7. Decrement the program counter (pc).
	setup_cb(cb + 6, &bf->dec_4->source_ad, &cb[6].stride, 4, cb + 7);	
	cb[6].stride = virtual_to_bus(bf->pc);
	setup_cb(cb + 7, &bf->tramp->nextconbk, &cb[7].stride, 4, bf->dec_4);
	cb[7].stride = virtual_to_bus(cb + 8);

	// 8. Copy the pc into cb[9]'s source. 
	setup_cb(cb + 8, &cb[9].source_ad, bf->pc, 4, cb + 9);
	// 9. Load the LSB and use as index into the bracket_table.
	setup_cb(cb + 9, &cb[10].source_ad, NULL, 1, cb + 10);
	// 10. Load from the bracket_table and use as index into scanleft table.
	setup_cb(cb + 10, &cb[11].source_ad, bf->bracket_table, 1, cb + 11);
	// 11. Load the offset from scanleft_table into tramp2 and execute tramp.
	setup_cb(cb + 11, &bf->tramp->nextconbk, bf->scanleft_table, 4, bf->tramp);

	// 12/13. Decrement the loop counter (lc). 
	setup_cb(cb + 12, &bf->dec_4->source_ad, &cb[12].stride, 4, cb + 13);	
	cb[12].stride = virtual_to_bus(bf->lc);
	setup_cb(cb + 13, &bf->tramp->nextconbk, &cb[13].stride, 4, bf->dec_4);
	cb[13].stride = virtual_to_bus(cb + 14);

	// Build scanleft table after we setup the control blocks.
	memset((void *)bf->scanleft_table, 0, 0xc);
	bf->scanleft_table[0] = virtual_to_bus(cb + 6); // Scan left.
	bf->scanleft_table[1] = virtual_to_bus(cb + 12); // If *pc = '['.
	bf->scanleft_table[2] = virtual_to_bus(cb + 4); // If *pc = ']'.
	bf->scanleft_table[3] = 0; // No matching ']' quit.

	// 15/19. If !*lc goto dispatch, else goto scan left.
	setup_cb(cb + 14, &cb[15].source_ad, bf->lc, 1, cb + 15);
	setup_cb(cb + 15, (vuint8_t *)&cb[16].source_ad + 1, bf->boolean_inc_table, 1, cb + 16);
	setup_cb(cb + 16, &bf->tramp->nextconbk, bf->conditional_table + RCOND_LC_INDEX_0, 4, bf->tramp);
	bf->conditional_table[RCOND_LC_INDEX_0] = virtual_to_bus(cb + 17); // Check next byte.
	bf->conditional_table[RCOND_LC_INDEX_0 + 0x40] = virtual_to_bus(cb + 6); // Scan left.

	// 2nd LSB.
	setup_cb(cb + 17, &cb[18].source_ad, (vuint8_t *)bf->lc + 1, 1, cb + 18);
	setup_cb(cb + 18, (vuint8_t *)&cb[19].source_ad + 1, bf->boolean_inc_table, 1, cb + 19);
	setup_cb(cb + 19, &bf->tramp->nextconbk, bf->conditional_table + RCOND_LC_INDEX_1, 4, bf->tramp);
	bf->conditional_table[RCOND_LC_INDEX_1] = virtual_to_bus(cb + 20); // Check next byte.
	bf->conditional_table[RCOND_LC_INDEX_1 + 0x40] = virtual_to_bus(cb + 6); // Scan left.   

	// 3rd LSB.
	setup_cb(cb + 20, &cb[21].source_ad, (vuint8_t *)bf->lc + 2, 1, cb + 21);
	setup_cb(cb + 21, (vuint8_t *)&cb[22].source_ad + 1, bf->boolean_inc_table, 1, cb + 22);
	setup_cb(cb + 22, &bf->tramp->nextconbk, bf->conditional_table + RCOND_LC_INDEX_2, 4, bf->tramp);
	bf->conditional_table[RCOND_LC_INDEX_2] = virtual_to_bus(cb + 23); // Check next byte.
	bf->conditional_table[RCOND_LC_INDEX_2 + 0x40] = virtual_to_bus(cb + 6); // Scan left.   

	// 4th LSB. 
	setup_cb(cb + 23, &cb[24].source_ad, (vuint8_t *)bf->lc + 3, 1, cb + 24);
	setup_cb(cb + 24, (vuint8_t *)&cb[25].source_ad + 1, bf->boolean_inc_table, 1, cb + 25);
	setup_cb(cb + 25, &bf->tramp->nextconbk, bf->conditional_table + RCOND_LC_INDEX_3, 4, bf->tramp); 
	bf->conditional_table[RCOND_LC_INDEX_3] = virtual_to_bus(bf->next_insn); // Goto next_insn.
	bf->conditional_table[RCOND_LC_INDEX_3 + 0x40] = virtual_to_bus(cb + 6); // Scan left.	  

	cb += 26;
	bf->next_cb = cb;
}


static void build_io(bf_t *bf)
{
	assert(bf->next_insn);
	assert(bf->tramp);

        cb_t cb = bf->next_cb;
        // Set up the control blocks for input.
        bf->input = cb;

	//
	// INPUT:
	//
	// Loop.
        setup_cb(cb + 0, &cb[1].source_ad, NULL, 1, cb + 1);
        cb[0].source_ad = UART0_FR;
        setup_cb(cb + 1, (vuint8_t *)&cb[2].source_ad + 1, bf->boolean_read_table, 1, cb + 2);
        setup_cb(cb + 2, &bf->tramp->nextconbk, bf->conditional_table + INPUT_INDEX, 4, bf->tramp);

	// If the uart0 flag register has RXFE, bit 4, set we take input. 
	// Otherwise, we loop.
	bf->conditional_table[INPUT_INDEX] = virtual_to_bus(cb + 3);
	bf->conditional_table[INPUT_INDEX + 0x40] = virtual_to_bus(cb + 0);

	// Set head to input. 
	setup_cb(cb + 3, &cb[4].dest_ad, bf->head, 4, cb + 4);
	setup_cb(cb + 4, NULL, NULL, 1, bf->next_insn);
	cb[4].source_ad = UART0_DR;

	cb += 5;
	// Set up the control blocks for output.
	bf->output = cb;

	//
	// OUTPUT
	//
	// Loop.
        //setup_cb(cb + 0, &cb[1].source_ad, &cb[0].stride, 4, cb + 1);
        setup_cb(cb + 0, &cb[1].source_ad, NULL, 1, cb + 1);
        cb[0].source_ad = UART0_FR;
        setup_cb(cb + 1, (vuint8_t *)&cb[2].source_ad + 1, bf->boolean_write_table, 1, cb + 2);
        setup_cb(cb + 2, &bf->tramp->nextconbk, bf->conditional_table + OUTPUT_INDEX, 4, bf->tramp);

        // If the uart0 flag register has TXFF, bit 5, set we take input.
        // Otherwise, we loop.
        bf->conditional_table[OUTPUT_INDEX] = virtual_to_bus(cb + 3);
        bf->conditional_table[OUTPUT_INDEX + 0x40] = virtual_to_bus(cb + 0);

	// Set head to output. 
	setup_cb(cb + 3, &cb[4].source_ad, bf->head, 4, cb + 4);
	setup_cb(cb + 4, NULL, NULL, 4, bf->next_insn);
	cb[4].dest_ad = UART0_DR;
 
	cb += 5;
	bf->next_cb = cb;
}

static void build_insn_table(bf_t *bf)
{
	assert(bf->next_insn);
	assert(bf->inc);
	assert(bf->dec);
	assert(bf->right);
	assert(bf->left);
	assert(bf->lcond);
	assert(bf->rcond);
	assert(bf->input);
	assert(bf->output);
	assert(bf->dispatch);

	bf->insn_table->quit = 0;
	bf->insn_table->nop = virtual_to_bus(bf->next_insn);
	bf->insn_table->inc = virtual_to_bus(bf->inc); 
	bf->insn_table->dec = virtual_to_bus(bf->dec);
	bf->insn_table->right = virtual_to_bus(bf->right);
	bf->insn_table->left = virtual_to_bus(bf->left);
	bf->insn_table->lcond = virtual_to_bus(bf->lcond);
	bf->insn_table->rcond = virtual_to_bus(bf->rcond);
	bf->insn_table->input = virtual_to_bus(bf->input);
	bf->insn_table->output = virtual_to_bus(bf->output);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s program.bf\n", argv[0]);
		exit(1);
	}
	setup();

	/* The memory is arranged as
	 * 1. DMA control blocks
	 * 2. Tables
	 * 3. Program counter
	 * 4. Loop counter
	 * 5. Tape head
	 * 6. Brainfuck program
	 * 7. Tape
	 */

	bf_t bf;
	memset(&bf, 0, sizeof bf);

	// Control blocks
	const cb_t cb_base = bus_to_virtual(BUS_ADDRESS);
	bf.next_cb = cb_base;

	// Tables
#define TABLE_ADDRESS (BUS_ADDRESS + 0x2000)
	bf.dispatch_table = bus_to_virtual(TABLE_ADDRESS);
	bf.inc_table = bus_to_virtual(TABLE_ADDRESS + 0x100);
	bf.dec_table = bus_to_virtual(TABLE_ADDRESS + 0x200);
	bf.insn_table = bus_to_virtual(TABLE_ADDRESS + 0x300);
	bf.boolean_inc_table = bus_to_virtual(TABLE_ADDRESS + 0x400);
	bf.boolean_dec_table = bus_to_virtual(TABLE_ADDRESS + 0x500);
	bf.bracket_table = bus_to_virtual(TABLE_ADDRESS + 0x600);
	bf.scanright_table = bus_to_virtual(TABLE_ADDRESS + 0x700);
	bf.scanleft_table = bus_to_virtual(TABLE_ADDRESS + 0x800);
	bf.boolean_read_table = bus_to_virtual(TABLE_ADDRESS + 0x900);
	bf.boolean_write_table = bus_to_virtual(TABLE_ADDRESS + 0xa00);
	bf.conditional_table = bus_to_virtual(TABLE_ADDRESS + 0xb00);
	
	// Data
	bf.pc = bus_to_virtual(BUS_ADDRESS + 0x3000);
	bf.lc = bf.pc + 1;
	bf.head = bf.lc + 1;

	// Program
	vuint8_t *program = (vuint8_t *)(bf.head + 1);
	size_t program_size = copy_program(program, argv[1]);

	// Tape
	vuint8_t *tape = program + program_size;

	// 1. Set the pc, lc, and head. Clear the tape.
	*bf.pc = virtual_to_bus(program);
	*bf.lc = 0;
	*bf.head = virtual_to_bus(tape);
	memset((void *)tape, 0, 0x200000); // 2MB.

	// 2. Build the boolean tables.
	{
		uint8_t second_LSB = virtual_to_bus(bf.conditional_table) >> 8;
		assert(second_LSB != 0xff);

		memset((void *)bf.boolean_inc_table, second_LSB + 1, 0x100);
		bf.boolean_inc_table[0] = second_LSB;

		memset((void *)bf.boolean_dec_table, second_LSB + 1, 0x100);
		bf.boolean_dec_table[255] = second_LSB;

		memset((void *)bf.boolean_read_table, second_LSB, 0x100);
		for(int i=0; i < 256; i++) 
		{
			// RXFE bit 4.
			if(i & (1 << 4))
				bf.boolean_read_table[i] = second_LSB + 1;	
		}

		memset((void *)bf.boolean_write_table, second_LSB, 0x100);
		for(int i=0; i < 256; i++)
		{
			// TXFF bit 5.
			if(i & (1 << 5))
				bf.boolean_write_table[i] = second_LSB + 1;
		}
	}

	// 3. Build the interpreter.
	build_dispatch(&bf);
	build_inc_4(&bf);
	build_dec_4(&bf);
	build_next_insn(&bf);
	build_rightleft(&bf);	
	build_incdec(&bf);
	build_cond(&bf);
	build_io(&bf);
	build_insn_table(&bf);

#if 0
	for (cb_t cb = cb_base; cb < bf.next_cb; ++cb)
	{
		printf("cb %08lx\n", (unsigned long int)virtual_to_bus(cb));
		print_control_block(cb);
		puts("");
	}
#endif

#if 0 
	printf("dispatch:\t%08x\n", (unsigned)virtual_to_bus(bf.dispatch));
	printf("tramp:\t%08x\n", (unsigned)virtual_to_bus(bf.tramp));
	printf("tramp2:\t%08x\n", (unsigned)virtual_to_bus(bf.tramp2));
	printf("inc_4:\t%08x\n", (unsigned)virtual_to_bus(bf.inc_4));
	printf("dec_4:\t%08x\n", (unsigned)virtual_to_bus(bf.dec_4));
	printf("next_insn:\t%08x\n", (unsigned)virtual_to_bus(bf.next_insn));
	printf("inc:\t%08x\n", (unsigned)virtual_to_bus(bf.inc));
	printf("dec:\t%08x\n", (unsigned)virtual_to_bus(bf.dec));
	printf("right:\t%08x\n", (unsigned)virtual_to_bus(bf.right));
	printf("left:\t%08x\n", (unsigned)virtual_to_bus(bf.left));
	printf("lcond:\t%08x\n", (unsigned)virtual_to_bus(bf.lcond));
	printf("rcond:\t%08x\n", (unsigned)virtual_to_bus(bf.rcond));
	printf("input:\t%08x\n", (unsigned)virtual_to_bus(bf.input));
	printf("output:\t%08x\n", (unsigned)virtual_to_bus(bf.output));
	printf("pc:\t%08x\n", (unsigned)virtual_to_bus(bf.pc));
	printf("lc:\t%08x\n", (unsigned)virtual_to_bus(bf.lc));
	printf("head:\t%08x\n", (unsigned)virtual_to_bus(bf.head));		

	trace_dma(bf.dispatch);
#else
	run_dma(bf.dispatch);
#endif
	printf("Output: %s\n", (char *)tape);

	cleanup();
	return 0;
}
