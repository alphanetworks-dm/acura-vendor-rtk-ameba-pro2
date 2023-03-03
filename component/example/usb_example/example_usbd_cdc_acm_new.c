/**
  ******************************************************************************
  * @file    example_usbd_cdc_acm_new.c
  * @author  Realsil WLAN5 Team
  * @version V1.0.0
  * @date    2021-6-18
  * @brief   This file is example of usbd cdc acm class
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and
  * possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2021, Realtek Semiconductor Corporation. All rights reserved.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------ */

#include <platform_opts.h>
#include "usbd.h"
#include "usbd_cdc_acm.h"
#include "osdep_service.h"
#include "log_service.h"
/* Private defines -----------------------------------------------------------*/

// This configuration is used to enable a thread to check hotplug event
// and reset USB stack to avoid memory leak, only for example.
#define CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS	1

// Echo asynchronously
#define CONFIG_USBD_CDC_ACM_ASYNC_XFER			0

#define CDC_ACM_TX_BUF_SIZE						1024U
#define CDC_ACM_RX_BUF_SIZE						1024U

#define CDC_ACM_ASYNC_XFER_SIZE					4096U

#define USB_CONSOLE_LOG

/* Private types -------------------------------------------------------------*/

/* Private macros ------------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/

static u8 cdc_acm_cb_init(void);
static u8 cdc_acm_cb_deinit(void);
static u8 cdc_acm_cb_setup(u8 cmd, u8 *pbuf, u16 length, u16 value);
static u8 cdc_acm_cb_receive(u8 *pbuf, u32 Len);

/* Private variables ---------------------------------------------------------*/

static usbd_cdc_acm_cb_t cdc_acm_cb = {
	cdc_acm_cb_init,
	cdc_acm_cb_deinit,
	cdc_acm_cb_setup,
	cdc_acm_cb_receive
};

static usbd_cdc_acm_line_coding_t cdc_acm_line_coding;

static u16 cdc_acm_ctrl_line_state;

static usbd_config_t cdc_acm_cfg = {
	.speed = USB_SPEED_HIGH,
	.max_ep_num = 4U,
	.rx_fifo_size = 512U,
	.nptx_fifo_size = 256U,
	.ptx_fifo_size = 64U,
	.dma_enable = FALSE,
	.self_powered = CDC_ACM_SELF_POWERED,
	.isr_priority = 4U,
};

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
static u8 cdc_acm_async_xfer_buf[CDC_ACM_ASYNC_XFER_SIZE];
static u16 cdc_acm_async_xfer_buf_pos = 0;
static volatile int cdc_acm_async_xfer_busy = 0;
static _sema cdc_acm_async_xfer_sema;
#endif

#ifdef USB_CONSOLE_LOG
extern void remote_stdio_init(void *read_cb, void *write_cb);
static char cdc_buffer[2][256];
static int cdc_buffer_idx[2] = {0};
static int cdc_buffer_slot = 0;
extern int cdc_acm_get_status(void);
static _mutex cdc_mutex;
static char cdc_buf[16] = {0};
extern int cdc_acm_get_status(void);

static int usb_status = 0;
static int cdc_status = 0;
static int cdc_setup_status = 0;
static int cdc_force_close = 0;
static int cdc_procedure = 0;

int get_cdc_procedure_status(void)
{
	return cdc_procedure;
}

static unsigned cdc_acm_write_buffer(unsigned fd, const void *buf, unsigned len)
{

	int ret = 0;
	if (usbd_get_status() == USBD_ATTACH_STATUS_ATTACHED && len > 0) {
		ret = usbd_cdc_new_acm_transmit((void *)buf, len);
		if (ret != 0) {
			vTaskDelay(10);
			ret = usbd_cdc_new_acm_transmit((void *)buf, len); //Try again
		}
		return len;
	} else {
		return len;
	}
}

static unsigned cdc_acm_read_buffer(unsigned fd, void *buf, unsigned len)
{
	if (usbd_get_status() == USBD_ATTACH_STATUS_ATTACHED) {
		int curr_slot;
		unsigned cnt;
		__disable_irq();
		curr_slot = cdc_buffer_slot;
		cdc_buffer_slot ^= 1;
		__enable_irq();
		cnt = (unsigned)cdc_buffer_idx[curr_slot];
		memcpy(buf, cdc_buffer[curr_slot], cdc_buffer_idx[curr_slot]);
		cdc_buffer_idx[curr_slot] = 0;
		return cnt;
	} else {
		return 0;
	}
}
#endif

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes the CDC media layer
  * @param  None
  * @retval Status
  */
static u8 cdc_acm_cb_init(void)
{
	usbd_cdc_acm_line_coding_t *lc = &cdc_acm_line_coding;

	lc->bitrate = 150000;
	lc->format = 0x00;
	lc->parity_type = 0x00;
	lc->data_type = 0x08;

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	cdc_acm_async_xfer_buf_pos = 0;
	cdc_acm_async_xfer_busy = 0;
#endif

	return HAL_OK;
}

/**
  * @brief  DeInitializes the CDC media layer
  * @param  None
  * @retval Status
  */
static u8 cdc_acm_cb_deinit(void)
{
#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	cdc_acm_async_xfer_buf_pos = 0;
	cdc_acm_async_xfer_busy = 0;
#endif
	return HAL_OK;
}

/**
  * @brief  Data received over USB OUT endpoint are sent over CDC interface through this function.
  * @param  Buf: RX buffer
  * @param  Len: RX data length (in bytes)
  * @retval Status
  */
static u8 cdc_acm_cb_receive(u8 *buf, u32 len)
{
#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	u8 ret = HAL_OK;
	if (0 == cdc_acm_async_xfer_busy) {
		if ((cdc_acm_async_xfer_buf_pos + len) > CDC_ACM_ASYNC_XFER_SIZE) {
			len = CDC_ACM_ASYNC_XFER_SIZE - cdc_acm_async_xfer_buf_pos;  // extra data discarded
		}

		rtw_memcpy((void *)((u32)cdc_acm_async_xfer_buf + cdc_acm_async_xfer_buf_pos), buf, len);
		cdc_acm_async_xfer_buf_pos += len;
		if (cdc_acm_async_xfer_buf_pos >= CDC_ACM_ASYNC_XFER_SIZE) {
			cdc_acm_async_xfer_buf_pos = 0;
			rtw_up_sema(&cdc_acm_async_xfer_sema);
		}
	} else {
		printf("\n[CDC] Busy, discarded %d bytes\n", len);
		ret = HAL_BUSY;
	}

	usbd_cdc_new_acm_receive();
	return ret;
#else
#ifdef USB_CONSOLE_LOG
	int i = 0;
	int *idx = &cdc_buffer_idx[cdc_buffer_slot];
	char *ptr = (char *)buf;
	for (i = 0; i < len; i++) {
		idx = &cdc_buffer_idx[cdc_buffer_slot];
		if ((*idx) < 255) {
			cdc_buffer[cdc_buffer_slot][*idx] = ptr[i];
			(*idx)++;
		}
	}
	usbd_cdc_new_acm_receive();
	return 0;
#else
	usbd_cdc_new_acm_transmit(buf, len);
	return usbd_cdc_new_acm_receive();
#endif
#endif
}

/**
  * @brief  Handle the CDC class control requests
  * @param  cmd: Command code
  * @param  buf: Buffer containing command data (request parameters)
  * @param  len: Number of data to be sent (in bytes)
  * @retval Status
  */
static u8 cdc_acm_cb_setup(u8 cmd, u8 *pbuf, u16 len, u16 value)
{
	usbd_cdc_acm_line_coding_t *lc = &cdc_acm_line_coding;
	cdc_setup_status = 1;
	switch (cmd) {
	case CDC_SEND_ENCAPSULATED_COMMAND:
		/* Do nothing */
		break;

	case CDC_GET_ENCAPSULATED_RESPONSE:
		/* Do nothing */
		break;

	case CDC_SET_COMM_FEATURE:
		/* Do nothing */
		break;

	case CDC_GET_COMM_FEATURE:
		/* Do nothing */
		break;

	case CDC_CLEAR_COMM_FEATURE:
		/* Do nothing */
		break;

	case CDC_SET_LINE_CODING:
		if (len == CDC_ACM_LINE_CODING_SIZE) {
			lc->bitrate = (u32)(pbuf[0] | (pbuf[1] << 8) | (pbuf[2] << 16) | (pbuf[3] << 24));
			lc->format = pbuf[4];
			lc->parity_type = pbuf[5];
			lc->data_type = pbuf[6];
		}
		break;

	case CDC_GET_LINE_CODING:
		pbuf[0] = (u8)(lc->bitrate & 0xFF);
		pbuf[1] = (u8)((lc->bitrate >> 8) & 0xFF);
		pbuf[2] = (u8)((lc->bitrate >> 16) & 0xFF);
		pbuf[3] = (u8)((lc->bitrate >> 24) & 0xFF);
		pbuf[4] = lc->format;
		pbuf[5] = lc->parity_type;
		pbuf[6] = lc->data_type;
		break;

	case CDC_SET_CONTROL_LINE_STATE:
		/*
		wValue:	wValue, Control Signal Bitmap
				D2-15:	Reserved, 0
				D1:	RTS, 0 - Deactivate, 1 - Activate
				D0:	DTR, 0 - Not Present, 1 - Present
		*/
		if (cdc_acm_ctrl_line_state != value) {
			cdc_acm_ctrl_line_state = value;
			if (value & 0x02) {
				printf("\n[CDC] VCOM port activated/deactivated\n");
#if CONFIG_CDC_ACM_NOTIFY
				usbd_cdc_acm_notify_serial_state(CDC_ACM_CTRL_DSR | CDC_ACM_CTRL_DCD);
#endif
			}
		}

		break;

	case CDC_SEND_BREAK:
		/* Do nothing */
		break;

	default:
		break;
	}

	return HAL_OK;
}

/* 	USBD_ATTACH_STATUS_INIT     = 0U
	USBD_ATTACH_STATUS_ATTACHED = 1U
	USBD_ATTACH_STATUS_DETACHED = 2U */

int usbd_get_device_status(void)
{
	while (1) {
		if (usb_status == USBD_ATTACH_STATUS_ATTACHED) {
			goto EXIT;
		} else if (cdc_status == 1) {
			goto EXIT;
		} else {
			vTaskDelay(100);
		}
	}
EXIT:
	printf("%s %d\r\n", __FUNCTION__, usb_status);
	return usb_status;
}

#if CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS
static void cdc_acm_check_usb_status_thread(void *param)
{
	int ret = 0;
	usb_status = USBD_ATTACH_STATUS_INIT;
	int old_usb_status = USBD_ATTACH_STATUS_INIT;
	int count = 0;
	UNUSED(param);
	printf("%s\r\n", __FUNCTION__);
	for (;;) {
		rtw_mdelay_os(100);
		usb_status = usbd_get_status();
		if (cdc_force_close) {
			remote_stdio_init(NULL, NULL);
			vTaskDelay(50);
			usbd_cdc_new_acm_deinit();
			ret = usbd_deinit();
			if (ret != 0) {
				printf("\n[CDC] Fail to de-init USBD driver\n");
				break;
			}
			rtw_mdelay_os(100);
			printf("\n[CDC] Free heap size: 0x%lx\n", rtw_getFreeHeapSize());
			break;
		}
		if (old_usb_status != usb_status) {
			old_usb_status = usb_status;
			if (usb_status == USBD_ATTACH_STATUS_DETACHED) {
				printf("\n[CDC] USB DETACHED\n");
				remote_stdio_init(NULL, NULL);
				vTaskDelay(50);
				usbd_cdc_new_acm_deinit();
				ret = usbd_deinit();
				if (ret != 0) {
					printf("\n[CDC] Fail to de-init USBD driver\n");
					break;
				}
				rtw_mdelay_os(100);
				printf("\n[CDC] Free heap size: 0x%lx\n", rtw_getFreeHeapSize());
				break;
				/* ret = usbd_init(&cdc_acm_cfg);
				if (ret != 0) {
					printf("\n[CDC] Fail to re-init USBD driver\n");
					break;
				}
				ret = usbd_cdc_acm_init(CDC_ACM_RX_BUF_SIZE, CDC_ACM_TX_BUF_SIZE, &cdc_acm_cb);
				if (ret != 0) {
					printf("\n[CDC] Fail to re-init CDC ACM class\n");
					usbd_deinit();
					break;
				} */
			} else if (usb_status == USBD_ATTACH_STATUS_ATTACHED) {
				printf("\n[CDC] USB ATTACHED\n");
			} else {
				printf("\n[CDC] USB INIT\n");
			}
		} else if (usb_status == USBD_ATTACH_STATUS_INIT) {
			count++;
			if (count >= 10) {
				count = 0;
				remote_stdio_init(NULL, NULL);
				vTaskDelay(50);
				usbd_cdc_new_acm_deinit();
				ret = usbd_deinit();
				if (ret != 0) {
					printf("\n[CDC] Fail to de-init USBD driver\n");
					break;
				}
				rtw_mdelay_os(100);
				printf("The same status\r\n");
				printf("\n[CDC] Free heap size: 0x%lx\n", rtw_getFreeHeapSize());
				break;
			}
		}
	}
	usb_status = USBD_ATTACH_STATUS_INIT;
	remote_stdio_init(NULL, NULL);
	printf("Disable the Remote log\r\n");
	printf("usbd cdc acm disconnect\r\n");
	cdc_status = 1;
	cdc_procedure = 0;
	rtw_thread_exit();
}
#endif // CONFIG_USDB_MSC_CHECK_USB_STATUS

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
static void cdc_acm_xfer_thread(void *param)
{
	u8 ret;
	u8 *xfer_buf;
	u32 xfer_len;

	for (;;) {
		if (rtw_down_sema(&cdc_acm_async_xfer_sema)) {
			xfer_len = CDC_ACM_ASYNC_XFER_SIZE;
			xfer_buf = cdc_acm_async_xfer_buf;
			cdc_acm_async_xfer_busy = 1;
			printf("\n[CDC] Start transfer %d bytes\n", CDC_ACM_ASYNC_XFER_SIZE);
			while (xfer_len > 0) {
				if (xfer_len > CDC_ACM_TX_BUF_SIZE) {
					ret = usbd_cdc_new_acm_transmit(xfer_buf, CDC_ACM_TX_BUF_SIZE);
					if (ret == HAL_OK) {
						xfer_len -= CDC_ACM_TX_BUF_SIZE;
						xfer_buf += CDC_ACM_TX_BUF_SIZE;
					} else { // HAL_BUSY
						printf("\n[CDC] Busy to transmit data, retry\n");
						rtw_udelay_os(200);
					}
				} else {
					ret = usbd_cdc_new_acm_transmit(xfer_buf, xfer_len);
					if (ret == HAL_OK) {
						xfer_len = 0;
						cdc_acm_async_xfer_busy = 0;
						printf("\n[CDC] Transmit done\n");
						break;
					} else { // HAL_BUSY
						printf("\n[CDC] Busy to transmit data, retry\n");
						rtw_udelay_os(200);
					}
				}
			}
		}
	}
}
#endif
void atcmd_cdc_init(void);

static void example_usbd_cdc_acm_thread(void *param)
{
	int ret = 0;

	atcmd_cdc_init();

#if CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS
	struct task_struct check_task;
#endif
#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	struct task_struct xfer_task;
#endif
#ifdef USB_CONSOLE_LOG
	remote_stdio_init(NULL, NULL);

	cdc_procedure = 1;

	usb_status = 0;

	cdc_status = 0;

	cdc_setup_status = 0;//It don't enter the setup procedrue.

	cdc_force_close = 0;
#endif
	UNUSED(param);

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	rtw_init_sema(&cdc_acm_async_xfer_sema, 0);
#endif
	extern int otg_select_usb_mode(int value);
	otg_select_usb_mode(0);
	ret = usbd_init(&cdc_acm_cfg);
	if (ret != HAL_OK) {
		printf("\n[CDC] Fail to init USB device driver\n");
		goto exit_usbd_init_fail;
	}

	ret = usbd_cdc_new_acm_init(CDC_ACM_RX_BUF_SIZE, CDC_ACM_TX_BUF_SIZE, &cdc_acm_cb);
	if (ret != HAL_OK) {
		printf("\n[CDC] Fail to init CDC ACM class\n");
		goto exit_usbd_cdc_acm_init_fail;
	}

#if CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS
	ret = rtw_create_task(&check_task, "cdc_check_usb_status_thread", 512, tskIDLE_PRIORITY + 2, cdc_acm_check_usb_status_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[CDC] Fail to create CDC ACM status check thread\n");
		goto exit_create_check_task_fail;
	}
#endif

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	// The priority of transfer thread shall be lower than USB isr priority
	ret = rtw_create_task(&xfer_task, "cdc_acm_xfer_thread", 512, tskIDLE_PRIORITY + 2, cdc_acm_xfer_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[CDC] Fail to create CDC ACM transfer thread\n");
		goto exit_create_xfer_task_fail;
	}
#endif

	rtw_mdelay_os(100);

	printf("\n[CDC] CDC ACM demo started\n");

#ifdef USB_CONSOLE_LOG
	//rtw_mutex_init(&cdc_mutex);
	vTaskDelay(1500);
	if (cdc_setup_status) {
		printf("Enalbe the log service\r\n");
		vTaskDelay(50);
		remote_stdio_init((void *)cdc_acm_read_buffer, (void *)cdc_acm_write_buffer);
	} else {
		cdc_force_close = 1;
		printf("The cdc is not setup procedure, force close\r\n");
		for (int i = 0; i < 10; i++) {
			if (cdc_status == 1) {
				printf("Exit cdc procedure without setup\r\n");
				break;
			} else {
				vTaskDelay(50);
			}
		}
	}
#endif

	rtw_thread_exit();

	return;

#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
exit_create_xfer_task_fail:
#if CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS
	rtw_delete_task(&check_task);
#endif
#endif

#if CONFIG_USDB_CDC_ACM_CHECK_USB_STATUS
exit_create_check_task_fail:
	usbd_cdc_new_acm_deinit();
#endif

exit_usbd_cdc_acm_init_fail:
	usbd_deinit();

exit_usbd_init_fail:
#if CONFIG_USBD_CDC_ACM_ASYNC_XFER
	rtw_free_sema(&cdc_acm_async_xfer_sema);
#endif

	rtw_thread_exit();
}

/**
  * @brief  USB download de-initialize
  * @param  None
  * @retval Result of the operation: 0 if success else fail
  */
void example_usbd_cdc_acm(void)
{
	int ret;
	struct task_struct task;

	ret = rtw_create_task(&task, "example_usbd_cdc_acm_thread", 1024, tskIDLE_PRIORITY + 5, example_usbd_cdc_acm_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[CDC] Fail to create CDC ACM thread\n");
	}
}

void ACDFU(void *arg)
{
	printf("Switch from cdc to dfu mode\r\n");
	cdc_force_close = 1;
	for (int i = 0; i < 10; i++) {
		vTaskDelay(100);
		if (usb_status == USBD_ATTACH_STATUS_INIT) {
			printf("switch to dfu mode\r\n");
			extern void example_usb_dfu_ota(void);
			example_usb_dfu_ota();
			break;
		}
	}
}

log_item_t usb_cdc_items[] = {
	{"CDFU", ACDFU,},
};

void atcmd_cdc_init(void)
{
	printf("cdc command\r\n");
	log_service_add_table(usb_cdc_items, sizeof(usb_cdc_items) / sizeof(usb_cdc_items[0]));
}
