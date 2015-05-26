#include <stdio.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>

#include "mem.h"

#define PAGE_SIZE 4096

static int dev_mem_fd = -1;

int open_dev_mem(void)
{
	if (dev_mem_fd != -1)
		return 0;
	dev_mem_fd = open("/dev/mem", O_RDWR|O_SYNC);
	return dev_mem_fd == -1? -1:0;
}

int close_dev_mem(void)
{
	if (dev_mem_fd == -1)
		return 0;
	int ret = close(dev_mem_fd);
	dev_mem_fd = -1;
	return ret;
}

static inline uintptr_t round_down(uintptr_t addr)
{
	return addr & -PAGE_SIZE;
}

static inline size_t round_up(size_t size)
{
	return (size + PAGE_SIZE-1) & -PAGE_SIZE;
}

static void *physical_map(uintptr_t physical_address, size_t size)
{
	if (dev_mem_fd == -1)
		return NULL;
	uintptr_t addr = round_down(physical_address);
	ptrdiff_t delta = physical_address - addr;
	size = round_up(size + delta);
	uint8_t *p = mmap(NULL, size, PROT_READ|PROT_WRITE,
			  MAP_SHARED, dev_mem_fd, addr);
	if (p == MAP_FAILED)
		return NULL;
	return p + delta;
}

static int physical_unmap(void *p, size_t size)
{
	uintptr_t addr = round_down((uintptr_t)p);
	ptrdiff_t delta = (uintptr_t)p - addr;
	size = round_up(size + delta);
	return munmap((void *)addr, size);
}

static inline uintptr_t bus_to_physical(uintptr_t p)
{
	return p - 0x7e000000 + 0x3f000000;
}

void *io_map(uintptr_t bus_address, size_t size)
{
	return physical_map(bus_to_physical(bus_address), size);
}

int io_unmap(void *p, size_t size)
{
	return physical_unmap(p, size);
}

void *sdram_map(uintptr_t address, size_t size)
{
	return physical_map(address, size);
}

int sdram_unmap(void *p, size_t size)
{
	return physical_unmap(p, size);
}
