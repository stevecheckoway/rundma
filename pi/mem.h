#ifndef MEM_H
#define MEM_H

#include <stdint.h>

int open_dev_mem(void);
int close_dev_mem(void);
void *io_map(uintptr_t bus_address, size_t size);
int io_unmap(void *p, size_t size);

void *sdram_map(uintptr_t address, size_t size);
int sdram_unmap(void *p, size_t size);

#endif
