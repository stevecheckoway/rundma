#ifndef UART_H
#define UART_H

#include <stdint.h>

struct gpio_registers
{
	uint32_t gpfsel0; // GPIO Function Select 0.
	uint32_t gpfsel1; // GPIO Function Select 1.
	uint32_t gpfsel2; // GPIO Function Select 2.
	uint32_t gpfsel3; // GPIO Function Select 3.
	uint32_t gpfsel4; // GPIO Function Select 4.
	uint32_t gpfsel5; // GPIO Function Select 5.
	uint32_t reserved1; 
	uint32_t gpset0; // GPIO Pin Output Set 0.
	uint32_t gpset1; // GPIO Pin Output Set 1.
	uint32_t reserved2;
	uint32_t gpclr0; // GPIO Pin Output Clear 0.
	uint32_t gpclr1; // GPIO Pin Output Clear 1.
	uint32_t reserved3;
	uint32_t gplev0; // GPIO Pin Level 0.
	uint32_t gplev1; // GPIO Pin Level 1.
	uint32_t reserved4;
	uint32_t gpeds0; // GPIO Pin Event Detect Status 0.
	uint32_t gpeds1; // GPIO Pin Event Detect Status 1.
	uint32_t reserved5;
	uint32_t gpren0; // GPIO Pin Rising Edge Detect Enable 0.
	uint32_t gpren1; // GPIO Pin Rising Edge Detect Enable 1.
	uint32_t reserved6;
	uint32_t gpfen0; // GPIO Pin Falling Edge Detect Enable 0.
	uint32_t gpfen1; // GPIO Pin Falling Edge Detect Enable 1.
	uint32_t reserved7;
	uint32_t gphen0; // GPIO Pin High Detect Enable 0.
	uint32_t gphen1; // GPIO Pin High Detect Enable 1.
	uint32_t reserved8;
	uint32_t gplen0; // GPIO Pin Low Detect Enable 0.
	uint32_t gplen1; // GPIO Pin Low Detect Enable 1.
	uint32_t reserved9;
	uint32_t gparen0; // GPIO Pin Async. Rising Edge Detect 0.
	uint32_t gparen1; // GPIO Pin Async. Falling Edge Detect 1.
	uint32_t reserved10; 
	uint32_t gppud; // GPIO Pin Pull-up/down Enable.
	uint32_t gppudclk0; // GPIO Pin Pull-up/down Enable Clock 0.
	uint32_t gppudclk1; // GPIO Pin Pull-up/down Enable Clock 1.
};

struct uart0_registers
{
	uint32_t dr;	// Data register.
	uint32_t rsrecr;
	uint32_t reserved[4];
	uint32_t fr;	// Flag register.
	uint32_t reserved2;
	uint32_t ilpr;	// Not in use.
	uint32_t ibrd;	// Integer baud rate divisor.
	uint32_t fbrd;	// Fractional baud rate divisor.
	uint32_t lcrh;	// Line control register.
	uint32_t cr;	// Control register.
	uint32_t ifls;	// Interrupt FIFO level select register.
	uint32_t imsc;	// Interrupt mask set clear register.
	uint32_t ris;	// Raw interrupt status register.
	uint32_t mis;	// Masked interrupt status register.
	uint32_t icr;	// Interrupt clear register.
	uint32_t dmacr;	// DMA control register.
	uint32_t reserved3[13];
	uint32_t itcr;	// Test control register.
	uint32_t itip;	// Integration test input register.
	uint32_t itop;	// Integration test output register.
	uint32_t tdr;	// Test data register.
};

enum
{
	GPPUDCLK0_PUDCLK14 = 1 << 14, // Assert clock on line 14.
	GPPUDCLK0_PUDCLK15 = 1 << 15, // Assert clock on line 15.
};

enum
{
	GPFSEL1_FSEL14_ALT0 = 4 << 12, // GPIO Pin 14 takes alt func 0.
	GPFSEL1_FSEL15_ALT0 = 4 << 15, // GPIO Pin 15 takes alt func 0.
};

enum
{
	FR_BUSY		= 1 << 3, // UART busy.
	FR_RXFE		= 1 << 4, // Receive FIFO empty.
	FR_TXFF		= 1 << 5, // Transmit FIFO full.
};

enum
{
	LCRH_FEN	= 1 << 4, // Transmit/Receive FIFO buffers.
	LCRH_WLEN1	= 1 << 5, // Data bits Tx/Rx'd. 11 = 8bits.
	LCRH_WLEN2	= 1 << 6, //
};

enum
{
	IMSC_CTSMIM	= 1 << 1, // nUARTCTS modem interrupt.
	IMSC_RXIM	= 1 << 4, // Receive interrupt mask.
	IMSC_TXIM	= 1 << 5, // Transmit interrupt mask.
	IMSC_RTIM	= 1 << 6, // Receive timout interrupt mask.
	IMSC_FEIM	= 1 << 7, // Framing error interrupt mask.
	IMSC_PEIM	= 1 << 8, // Parity error interrupt mask.
	IMSC_BEIM	= 1 << 9, // Break error interrupt mask.
	IMSC_OEIM	= 1 << 10, // Overrun error interrupt mask.
};

enum
{
	CR_UARTEN 	= 1 << 0, // Uart enable. 
	CR_TXE		= 1 << 8, // Transmit enable.
	CR_RXE		= 1 << 9, // Receive enable.
};

int map_gpio_registers(void);
int map_uart0_registers(void);
int unmap_gpio_registers(void);
int unmap_uart0_registers(void);
void init_uart(struct gpio_registers *gpio, struct uart0_registers *uart0);
struct gpio_registers *get_gpio(void);
struct uart0_registers *get_uart0(void);

// Unoptimized delay count in cycles.
static inline void delay(int32_t count)
{
	asm volatile("__delay_%=: subs %[count], %[count], #1; bne __delay_%=\n"
		: : [count]"r"(count) : "cc");
}

#endif
