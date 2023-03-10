#include <string.h>
#include "serial_api.h"
#include "serial_ex_api.h"
#include "task.h"

#define DMA_MODE   0    // 0: interrupt mode, 1: DMA mode

#define UART_TX    PE_1
#define UART_RX    PE_2

#define SRX_BUF_SZ 100

char rx_buf[SRX_BUF_SZ] = {0};
volatile uint32_t tx_busy = 0;
volatile uint32_t rx_done = 0;

void uart_send_string_done(uint32_t id)
{
	serial_t    *sobj = (void *)id;
	tx_busy = 0;
}

static void uart_send_string(serial_t *sobj, char *pstr)
{
	int32_t ret = 0;

	if (tx_busy) {
		return;
	}

	tx_busy = 1;
	ret = serial_send_stream(sobj, pstr, strlen(pstr));
	if (ret != 0) {
		dbg_printf("%s Error(%d)\n\r", __FUNCTION__, ret);
		tx_busy = 0;
	}
}

void Release_CPU(void)
{
	// while waitting UART transfer done, try to wakeup other task
#if 1
	// make this task to sleep, so other task can wakeup
	vTaskDelay(10 / portTICK_RATE_MS);
#else
	// force the OS scheduler to do a context switch, but if the
	// priority of this task is the highest then no other task can wake up
	taskYIELD();
#endif
}

void uart_test_demo(void *param)
{
	serial_t    sobj;
	int ret;
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	serial_init(&sobj, UART_TX, UART_RX);
	serial_baud(&sobj, 38400);
	serial_format(&sobj, 8, ParityNone, 1);

	serial_send_comp_handler(&sobj, (void *)uart_send_string_done, (uint32_t) &sobj);

	while (1) {
		// expect to receive maximum 13 bytes with timeout 1000ms
#if DMA_MODE
#if 0
		// If you don't know what is Task Yield or no RTOS, then just keep the last argument is NULL
		ret = serial_recv_stream_dma_timeout(&sobj, rx_buf, 13, 5000, NULL);
#else
		// Do Task Yield while waitting UART RX done
		ret = serial_recv_stream_dma_timeout(&sobj, rx_buf, 13, 5000, (void *)Release_CPU);
#endif
#else
#if 1
		// If you don't know what is Task Yield or no RTOS, then just keep the last argument is NULL
		ret = serial_recv_stream_timeout(&sobj, rx_buf, 13, 1000, NULL);
#else
		// Do Task Yield while waitting UART RX done
		ret = serial_recv_stream_timeout(&sobj, rx_buf, 13, 1000, Release_CPU);
#endif
#endif
		if (ret < 100) {
			dbg_printf("Serial Rcv Timeout, Got %d bytes\n\r", ret);
		}

		if (ret > 0) {
			rx_buf[ret] = 0x00; // end of string
			uart_send_string(&sobj, rx_buf);
		}
	}
}

int main(void)
{
	// create demo Task
	if (xTaskCreate((TaskFunction_t)uart_test_demo, "uart test demo", (2048 / 2), (void *)NULL, (tskIDLE_PRIORITY + 1), NULL) != pdPASS) {
		dbg_printf("Cannot create uart test demo task\n\r");
		goto end_demo;
	}

	vTaskStartScheduler();

end_demo:
	while (1);
}
