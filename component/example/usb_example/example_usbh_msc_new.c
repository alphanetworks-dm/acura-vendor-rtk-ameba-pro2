/**
  ******************************************************************************
  * @file    example_usbh_msc_new.c
  * @author  Realsil WLAN5 Team
  * @version V1.0.0
  * @date    2020-11-23
  * @brief   This file provides the demo code for USB MSC host class
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and
  * possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2020, Realtek Semiconductor Corporation. All rights reserved.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------ */

#include <platform_opts.h>
#include <platform_stdlib.h>
#include "usbh.h"
#include "osdep_service.h"
#include "ff.h"
#include "fatfs_ext/inc/ff_driver.h"
#include "disk_if/inc/usbdisk.h"
#include "usbh_msc.h"

/* Private defines -----------------------------------------------------------*/

#define USBH_MSC_THREAD_STACK_SIZE  20480
#define USBH_MSC_TEST_BUF_SIZE      4096
#define USBH_MSC_TEST_ROUNDS        20
#define USBH_MSC_TEST_SEED          0xA5

/* Private types -------------------------------------------------------------*/

/* Private macros ------------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/

static u8 msc_cb_attach(void);
static u8 msc_cb_setup(void);
static u8 msc_cb_process(usb_host_t *host, u8 id);

/* Private variables ---------------------------------------------------------*/

static _sema msc_attach_sema;
static __IO int msc_is_ready = 0;
static u32 filenum = 0;

static usbh_config_t usbh_cfg = {
	.host_channels = 5U,
	.speed = USB_SPEED_HIGH,
	.dma_enable = FALSE,
	.main_task_priority = 3U,
	.isr_task_priority = 4U,
	.rx_fifo_size = 0x200U,
	.nptx_fifo_size = 0x100U,
	.ptx_fifo_size = 0x100U,
};

static usbh_msc_cb_t msc_usr_cb = {
	.attach = msc_cb_attach,
	.setup = msc_cb_setup,
};

static usbh_user_cb_t usbh_usr_cb = {
	.process = msc_cb_process
};

/* Private functions ---------------------------------------------------------*/

static u8 msc_cb_attach(void)
{
	printf("[MSC] ATTACH\n");
	rtw_up_sema(&msc_attach_sema);
	return HAL_OK;
}

static u8 msc_cb_setup(void)
{
	printf("[MSC] SETUP\n");
	msc_is_ready = 1;
	return HAL_OK;
}

int mass_storage_status = 0;

int get_mass_storage_procedure_status(void)
{
	return mass_storage_status;
}

static u8 msc_cb_process(usb_host_t *host, u8 id)
{
	UNUSED(host);

	switch (id) {
	case USBH_MSG_DISCONNECTED:
		msc_is_ready = 0;
		break;
	case USBH_MSG_CONNECTED:
		break;
	default:
		break;
	}

	return HAL_OK;
}

void example_usbh_msc_thread(void *param)
{
	FATFS fs;
	FIL f;
	int drv_num = 0;
	FRESULT res;
	char logical_drv[4];
	char path[64];
	int ret = 0;
	u32 br;
	u32 bw;
	u32 round = 0;
	u32 start;
	u32 elapse;
	u32 perf = 0;
	u32 test_sizes[] = {512, 1024, 2048, 4096, 8192};
	u32 test_size;
	u32 i;
	u8 *buf = NULL;
	int time_count = 0;
	UNUSED(param);

	mass_storage_status = 1;

	rtw_init_sema(&msc_attach_sema, 0);

	buf = (u8 *)rtw_malloc(USBH_MSC_TEST_BUF_SIZE);
	if (buf == NULL) {
		printf("[MSC] \nFail to allocate USBH MSC test buffer\n");
		goto exit;
	}

	extern int otg_select_usb_mode(int value);
	otg_select_usb_mode(1);
	ret = usbh_init(&usbh_cfg, &usbh_usr_cb);
	if (ret != HAL_OK) {
		printf("[MSC] Fail to init USB\n");
		goto exit_free;
	}

	usbh_msc_init(&msc_usr_cb);

	// Register USB disk driver to fatfs
	printf("\nRegister USB disk driver\n");
	drv_num = FATFS_RegisterDiskDriver(&USB_disk_Driver);
	if (drv_num < 0) {
		printf("[MSC] Fail to register USB disk driver\n");
		goto exit_deinit;
	}

	logical_drv[0] = drv_num + '0';
	logical_drv[1] = ':';
	logical_drv[2] = '/';
	logical_drv[3] = 0;

	printf("FatFS USB Write/Read performance test started...\n");

	while (1) {
		time_count++;
		if (msc_is_ready) {
			rtw_mdelay_os(10);
			break;
		} else {
			//For test
			if (time_count >= 10) {
				printf("Timeout to get the sd host\r\n");
				goto exit_unregister;
			} else {
				vTaskDelay(100);
			}
		}
	}

	if (f_mount(&fs, logical_drv, 1) != FR_OK) {
		printf("[MSC] Fail to mount logical drive\n");
		goto exit_unregister;
	}

	strcpy(path, logical_drv);

	while (1) {
		rtw_down_sema(&msc_attach_sema);

		while (1) {
			if (msc_is_ready) {
				rtw_mdelay_os(10);
				break;
			}
		}
#if 0
		sprintf(&path[3], "TEST%ld.DAT", filenum);
		printf("[MSC] open file path: %s\n", path);
		// open test file
		res = f_open(&f, path, FA_OPEN_ALWAYS | FA_READ | FA_WRITE);
		if (res) {
			printf("[MSC] Fail to open file: TEST%ld.DAT\n", filenum);
			goto exit_unmount;
		}
		// clean write and read buffer
		memset(buf, USBH_MSC_TEST_SEED, USBH_MSC_TEST_BUF_SIZE);

		for (i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); ++i) {
			test_size = test_sizes[i];
			if (test_size > USBH_MSC_TEST_BUF_SIZE) {
				break;
			}

			printf("[MSC] Write test: size = %ld round = %d...\n", test_size, USBH_MSC_TEST_ROUNDS);
			//start = SYSTIMER_TickGet();

			for (round = 0; round < USBH_MSC_TEST_ROUNDS; ++round) {
				res = f_write(&f, (void *)buf, test_size, (UINT *)&bw);
				if (res || (bw < test_size)) {
					f_lseek(&f, 0);
					printf("[MSC] Write error bw=%ld, rc=%d\n", bw, res);
					ret = 1;
					break;
				}
			}

			//elapse = SYSTIMER_GetPassTime(start);
			//perf = (round * test_size * 10000 / 1024) / elapse;
			//printf("[MSC] Write rate %ld.%ld KB/s for %ld round @ %ld ms\n", perf / 10, perf % 10, round, elapse);

			/* move the file pointer to the file head*/
			res = f_lseek(&f, 0);

			printf("[MSC] Read test: size = %ld round = %d...\n", test_size, USBH_MSC_TEST_ROUNDS);
			//start = SYSTIMER_TickGet();

			for (round = 0; round < USBH_MSC_TEST_ROUNDS; ++round) {
				res = f_read(&f, (void *)buf, test_size, (UINT *)&br);
				if (res || (br < test_size)) {
					f_lseek(&f, 0);
					printf("[MSC] Read error br=%ld, rc=%d\n", br, res);
					ret = 1;
					break;
				}
			}

			//elapse = SYSTIMER_GetPassTime(start);
			//perf = (round * test_size * 10000 / 1024) / elapse;
			//printf("[MSC] Read rate %ld.%ld KB/s for %ld round @ %ld ms\n", perf / 10, perf % 10, round, elapse);

			/* move the file pointer to the file head*/
			res = f_lseek(&f, 0);
		}

		printf("[MSC] FatFS USB Write/Read performance test %s\n", (ret == 0) ? "done" : "aborted");
#else
		static int num = 0;
		sprintf(&path[3], "hello_%d.txt", num);
		num++;
		printf("[MSC] open file path: %s\n", path);
		// open test file
		res = f_open(&f, path, FA_OPEN_ALWAYS | FA_READ | FA_WRITE);
		if (res) {
			printf("[MSC] Fail to open file: TEST%ld.DAT\n", filenum);
			goto exit_unmount;
		}
		const char *str = "hello_world\r\n";
		res = f_write(&f, (void *)str, strlen(str), (UINT *)&bw);
		if (res) {
			f_lseek(&f, 0);
			printf("[MSC] Write error bw=%ld, rc=%d\n", bw, res);
			ret = 1;
		}
		printf("Write hello_world\r\n");
#endif
		// close source file
		res = f_close(&f);
		if (res) {
			printf("[MSC] File close fail \n");
			ret = 1;
		} else {
			printf("[MSC] File close success \n");
		}

		if (!ret) {
			filenum++;
		}
		ret = 0;
		goto exit_unmount;
	}
exit_unmount:
	if (f_mount(NULL, logical_drv, 1) != FR_OK) {
		printf("[MSC] Fail to unmount logical drive\n");
	}
exit_unregister:
	if (FATFS_UnRegisterDiskDriver(drv_num)) {
		printf("[MSC] Fail to unregister disk driver from FATFS\n");
	}
exit_deinit:
	usbh_msc_deinit();
	usbh_deinit();
exit_free:
	if (buf) {
		rtw_free(buf);
	}
exit:
	mass_storage_status = 0;
	msc_is_ready = 0;
	rtw_free_sema(&msc_attach_sema);
	rtw_thread_exit();
}

/* Exported functions --------------------------------------------------------*/

void example_usbh_msc(void)
{
	int ret;
	struct task_struct task;

	printf("\n[MSC] USB host MSC demo started...\n");

	ret = rtw_create_task(&task, "example_usbh_msc_thread", USBH_MSC_THREAD_STACK_SIZE, tskIDLE_PRIORITY + 2, example_usbh_msc_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[MSC] Fail to create USB host MSC thread\n");
	}
}

