#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dma.h"
#include "mem.h"

#define DMA0_BASE 0x7e007000
#define DMA0_14_SIZE (0x100 * 15)

static volatile uint8_t *dma;

int map_dma_registers(void)
{
	if (dma)
		return 0;
	dma = io_map(DMA0_BASE, DMA0_14_SIZE);
	return dma? 0:-1;
}

int unmap_dma_registers(void)
{
	if (!dma)
		return 0;
	return io_unmap((void *)dma, DMA0_14_SIZE);
}

static int get_dma_channel_fd(void)
{
	static int dma_channel_fd = -1;
	if (dma_channel_fd == -1)
		dma_channel_fd = open("/sys/module/dma/parameters/dmachans", O_RDWR);
	else
		lseek(dma_channel_fd, 0, SEEK_SET);
	return dma_channel_fd;
}

int reserve_dma_channel(void)
{
	int dma_channel_fd = get_dma_channel_fd();

	if (dma_channel_fd == -1)
		return -1;
	int channel = -1;
	char buf[10];
	ssize_t amount = read(dma_channel_fd, buf, sizeof buf - 1);
	if (amount <= 0)
		return -1;
	if (buf[amount-1] != '\n')
	{
		fputs("This shouldn't happen!\n", stderr);
		return -1;
	}
	buf[amount-1] = 0;
	int mask = atoi(buf);
	static const char channels[] = {4, 5, 8, 9, 10, 11, 12, 13, 14};
	for (int i = 0; i < sizeof channels; ++i)
	{
		if (mask & (1 << channels[i]))
		{
			// Channel is not reserved by the GPU at
			// least!
			channel = channels[i];
			break;
		}
	}
	if (channel == -1)
		return -1;
	// Clear the corresponding bit and write the mask back.
	mask &= ~(1 << channel);
	sprintf(buf, "%d\n", mask);
	lseek(dma_channel_fd, 0, SEEK_SET);
	size_t len = strlen(buf);
	amount = write(dma_channel_fd, buf, len);

	if (amount != len)
		channel = -1;
	return channel;
}

int unreserve_dma_channel(int channel)
{
	if (channel < 0 || channel > 14)
		return -1;

	int dma_channel_fd = get_dma_channel_fd();
	if (dma_channel_fd == -1)
		return -1;
	int ret = -1;
	char buf[10];
	ssize_t amount = read(dma_channel_fd, buf, sizeof buf - 1);
	if (amount <= 0)
		return -1;
	if (buf[amount-1] != '\n')
	{
		fputs("This shouldn't happen!\n", stderr);
		return -1;
	}
	buf[amount-1] = 0;
	int mask = atoi(buf);

	if (mask & (1 << channel))
		return -1;

	mask |= 1 << channel;

	sprintf(buf, "%d\n", mask);
	lseek(dma_channel_fd, 0, SEEK_SET);
	size_t len = strlen(buf);
	amount = write(dma_channel_fd, buf, len);

	if (amount == len)
		ret = 0;

	return ret;
}

struct dma_registers *get_dma_channel(int channel)
{
	if (!dma || channel < 0 || channel > 14)
		return NULL;

	// Make sure the DMA channel is enabled.
	volatile uint32_t *enable = (volatile uint32_t *)(dma + 0xff0);
	*enable |= (1 << channel);
	return (struct dma_registers *)(dma + channel * 0x100);
}
