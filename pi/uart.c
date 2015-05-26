#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "uart.h"
#include "mem.h"

#define GPIO_BASE 0x7e200000
#define GPIO_SIZE 0xa4
#define UART0_BASE 0x7e201000
#define UART0_SIZE 0x48

static volatile uint32_t *uart0;
static volatile uint32_t *gpio;

int map_gpio_registers(void)
{
	if (gpio)
		return 0;
	gpio = io_map(GPIO_BASE, GPIO_SIZE);
	return gpio? 0:-1;
}

int map_uart0_registers(void)
{
	if (uart0)
		return 0;
	uart0 = io_map(UART0_BASE, UART0_SIZE);
	return uart0? 0:-1;
}

int unmap_gpio_registers(void)
{
	if (!gpio)
		return 0;
	return io_unmap((void *)gpio, GPIO_SIZE);
}

int unmap_uart0_registers(void)
{
	if (!uart0)
		return 0;
	return io_unmap((void *)uart0, UART0_SIZE);
}

void init_uart(struct gpio_registers *gpio, struct uart0_registers *uart0)
{
	// Disable the UART0.
	uart0->cr = 0x0;

	// Wait for the end of transmission.
	while (uart0->fr & FR_BUSY) { }

	// Flush the transmit FIFO.
	uart0->lcrh = LCRH_WLEN1 | LCRH_WLEN2;

	// Define operation of GPIO pins 14 and 15. GPFSEL1 register
	// determines pin 10-19 functionality. FSEL14 = bits 14-12, 
	// FSEL15 = bits 17-15. 100 takes alternative function 0.
	gpio->gpfsel1 &= ~(7 << 12); // Clear FSEL14.
	gpio->gpfsel1 &= ~(7 << 15); // Clear FSEL15.
	gpio->gpfsel1 |= GPFSEL1_FSEL14_ALT0 | GPFSEL1_FSEL15_ALT0;	

	// Setup GPIO pins 14, 15.
	gpio->gppud = 0x0;
	delay(150); // delay 150 cycles.

	// Disable Pun Pull-up/down for all GPIO.
	gpio->gppudclk0 = GPPUDCLK0_PUDCLK14 | GPPUDCLK0_PUDCLK15;
	delay(150);

	// Write 0 to GPPUDCLK0.
	gpio->gppudclk0 = 0x0;	

	// Clear all UART0 interrupt status.
	uart0->icr = 0x7ff;

	// Set UART0 baud rate (3MHz clock).
	// Integer = UART_CLOCK=3000000 / (16 * baud=115200)
	// Fractional = (Remainder * 64) + 0.5
	uart0->ibrd = 0x1;
	uart0->fbrd = 0x28;

	// Enable FIFO, 8-bit data transmission, 1 stop bit, no parity.
	uart0->lcrh = LCRH_FEN | LCRH_WLEN1 | LCRH_WLEN2;

	// Mask all UART0 interrupts.
	uart0->imsc = IMSC_CTSMIM | IMSC_RXIM | IMSC_TXIM | IMSC_RTIM | 
		IMSC_FEIM | IMSC_PEIM | IMSC_BEIM | IMSC_OEIM;

	// Enable UART0.
	uart0->cr = CR_UARTEN | CR_TXE | CR_RXE;
}

struct gpio_registers *get_gpio(void)
{
	return (struct gpio_registers *)(gpio);
}

struct uart0_registers *get_uart0(void)
{
	return (struct uart0_registers *)(uart0);
}
