#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/* 64 MB to play with */
#define BUS_ADDRESS 0xfb000000
#define MEMORY_SIZE 0x04000000

struct control_block;
extern void *physical_memory;

extern void setup(void);
extern void cleanup(void);
extern void run_dma(volatile struct control_block *cb);
extern void trace_dma(volatile struct control_block *cb);
extern void print_control_block(volatile struct control_block *cb);

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

#endif
