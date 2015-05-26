#ifndef DMA_H
#define DMA_H

#include <stdint.h>

struct control_block
{
	uint32_t ti;		// transfer information
	uint32_t source_ad;	// source address
	uint32_t dest_ad;	// destination address
	uint32_t txfr_len;	// transfer length
	uint32_t stride;	// 2D mode stride
	uint32_t nextconbk;	// next control block address;
	uint32_t reserved[2];
};

struct dma_registers
{
	volatile uint32_t cs;		// control and status
	volatile uint32_t conblk_ad;	// control block address
	volatile struct control_block cb;// control block
};

int map_dma_registers(void);
int unmap_dma_registers(void);

int reserve_dma_channel(void);
int unreserve_dma_channel(int channel);
struct dma_registers *get_dma_channel(int channel);

enum
{
	CS_RESET			= 1 << 31, // W1SC
	CS_ABORT			= 1 << 30, // W1SC
	CS_DISDEBUG			= 1 << 29, // RW
	CS_WAIT_FOR_OUTSTANDING_WRITES	= 1 << 28, // RW
	CS_PANIC_PRIORITY_SHIFT		= 20,
	CS_PANIC_PRIORITY_MASK		= 0xf << 20, // RW
	CS_PRIORITY_SHIFT		= 16,
	CS_PRIORITY_MASK		= 0xf << 16, // RW
	CS_ERROR			= 1 << 8, // RO
	CS_WAITING_FOR_OUTSTANDING_WRITES = 1 << 6, // RO
	CS_DREQ_STOPS_DMA		= 1 << 5, // RO
	CS_PAUSED			= 1 << 4, // RO
	CS_DREQ				= 1 << 3, // RO
	CS_INT				= 1 << 2, // W1C
	CS_END				= 1 << 1, // W1C
	CS_ACTIVE			= 1 << 0, // RW
};

#define DMA_CS_PRIORITY(n) ((n) << CS_PRIORITY_SHIFT)
#define DMA_CS_PANIC_PRIORITY(n) ((n) << CS_PANIC_PRIORITY_SHIFT)

enum
{
	TI_NO_WIDE_BURSTS		= 1 << 26,
	TI_WAITS_MASK			= 0x1f << 21,
	TI_PERMAP_MASK			= 0x1f << 16,
	TI_BURST_LENGTH_MASK		= 0xf << 12,
	TI_SRC_IGNORE			= 1 << 11,
	TI_SRC_DREQ			= 1 << 10,
	TI_SRC_WIDTH			= 1 << 9,
	TI_SRC_INC			= 1 << 8,
	TI_DEST_IGNORE			= 1 << 7,
	TI_DEST_DREQ			= 1 << 6,
	TI_DEST_WIDTH			= 1 << 5,
	TI_DEST_INC			= 1 << 4,
	TI_WAIT_RESP			= 1 << 3,
	TI_TDMODE			= 1 << 1,
	TI_INTEN			= 1 << 0,
};

#endif
