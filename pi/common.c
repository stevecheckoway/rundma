#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "common.h"
#include "dma.h"
#include "uart.h"
#include "mem.h"

#define SDRAM_BASE 0x3b000000
#define DEBUG 0

static int dma_channel = -1;
struct dma_registers *dma;
struct gpio_registers *gpio;
struct uart0_registers *uart0;
void *physical_memory;

static void cleanup_dma(void)
{
	if (dma_channel != -1)
	{
		if (unreserve_dma_channel(dma_channel))
			perror("failed to unreserve DMA channel");
	}
}

static void handler(int sig)
{
	exit(1);
}

void setup(void)
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

	if (map_gpio_registers())
	{
		perror("map gpio registers");
		exit(1);
	}
    
	if (map_uart0_registers())
	{
		perror("map uart0 registers");
		exit(1);
	}    
    
	dma_channel = reserve_dma_channel();

	if (dma_channel == -1)
	{
		if (errno)
			perror("reserve dma channel");
		else
			fputs("out of DMA channels\n", stderr);
		exit(1);
	}

	atexit(cleanup_dma);
	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
    
	gpio = get_gpio();
	uart0 = get_uart0();
	init_uart(gpio, uart0);
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

void cleanup(void)
{
	if (sdram_unmap(physical_memory, MEMORY_SIZE))
	{
		perror("sdram_unmap");
		exit(1);
	}

	if (unmap_dma_registers())
	{
		perror("unmap dma registers");
		exit(1);
	}

	if (unmap_gpio_registers())
	{
		perror("unmap gpio registers");
		exit(1);
	}
    
	if (unmap_uart0_registers())
	{
		perror("unmap uart0 registers");
		exit(1);
	}

	physical_memory = NULL;
	dma = NULL;
	gpio = NULL;
	uart0 = NULL;
}

void print_control_block(volatile struct control_block *cb)
{
	printf("TI:  %08x\n"
	       "Src: %08x\n"
	       "Dst: %08x\n"
	       "Len: %08x\n"
	       "Std: %08x\n"
	       "Nxt: %08x\n",
	       cb->ti, cb->source_ad, cb->dest_ad, cb->txfr_len,
	       cb->stride, cb->nextconbk);
}

static void reset_dma(void)
{
	#if DEBUG
	puts("Resetting the DMA");
	#endif
	// Reset the DMA
	dma->cs = CS_RESET;

	#if DEBUG
	puts("Waiting for the DMA to reset");
	#endif
	// Wait for the DMA to complete
	while (dma->cs & CS_ACTIVE)
		;

	//print_dma_regs(dma);
}

void run_dma(volatile struct control_block *cb)
{
	reset_dma();
	#if DEBUG
	puts("Starting the DMA");
	#endif
	dma->conblk_ad = virtual_to_bus(cb);
	dma->cs = DMA_CS_PANIC_PRIORITY(7) | DMA_CS_PRIORITY(7) | CS_DISDEBUG | CS_ACTIVE;
	#if DEBUG
	puts("Waiting for the DMA to complete");
	#endif
	//print_dma_regs(dma);
	// Wait for the DMA to complete
	while (dma->cs & CS_ACTIVE)
		;
	
	// Clear the END flag. I don't know if this is needed or not.
	dma->cs = CS_END;
}

void trace_dma(volatile struct control_block *cb)
{
	reset_dma();
	while (1)
	{
		unsigned bus_addr = virtual_to_bus(cb);
		unsigned src = cb->source_ad;
		unsigned next = cb->nextconbk;
		unsigned len = cb->txfr_len;
		if (src >= BUS_ADDRESS)
		{
			switch (len)
			{
			case 1:
				printf("%8x: src=%8x  dest=%8x  %02x        next=%8x\n",
				       bus_addr, src, cb->dest_ad, *(volatile uint8_t *)bus_to_virtual(src), next);
				break;
			case 4:
				printf("%8x: src=%8x  dest=%8x  %08x  next=%8x\n",
				       bus_addr, src, cb->dest_ad, *(volatile uint32_t *)bus_to_virtual(src), next);
				break;
			default:
				printf("%8x: src=%8x  dest=%8x  len=%d     next=%8x\n",
				       bus_addr, src, cb->dest_ad, len, next);
			}
		}
		else
		{
			// Break if src < BUS_ADDRESS unless src is UART0 FR/DR addr.
			if(src == 0x7e201000 || src == 0x7e201018)
			{
                        	switch (len)
                        	{
                        	case 1:
                                	printf("%8x: src=%8x  dest=%8x  %02x        next=%8x\n",
                                       		bus_addr, src, cb->dest_ad, src, next);
                                	break;
                        	case 4:
                                	printf("%8x: src=%8x  dest=%8x  %08x  next=%8x\n",
                                       		bus_addr, src, cb->dest_ad, src, next);
                                	break;
                        	default:
                                	printf("%8x: src=%8x  dest=%8x  len=%d     next=%8x\n",
                                       		bus_addr, src, cb->dest_ad, len, next);
                        	}
			} 
			else 
			{ 
				printf("%8x: src=%8x  dest=%8x  len=%d     next=%8x\n",
			       		bus_addr, src, cb->dest_ad, len, next);
				printf("src (%08x) < BUS_ADDRESS\n", src);
				break;
			}
		}
		cb->nextconbk = 0;
		dma->conblk_ad = bus_addr;
		dma->cs = DMA_CS_PANIC_PRIORITY(7) | DMA_CS_PRIORITY(7) | CS_DISDEBUG | CS_ACTIVE;
		while (dma->cs & CS_ACTIVE)
			;
		dma->cs = CS_END;
		cb->nextconbk = next;
		if (!next)
			break;
		if (next < BUS_ADDRESS)
		{
			// Break if next < BUS_ADDRESS unless next is UART0 FR/DR addr.
			if(next != 0x7e201000)
			{
				if(next != 0x7e201018)
				{
					puts("next < BUS_ADDRESS");
					break;
				}
			}
		}
		cb = bus_to_virtual(next);
	}
}
