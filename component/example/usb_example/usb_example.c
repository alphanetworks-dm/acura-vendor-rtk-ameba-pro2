#include "FreeRTOS.h"
#include "task.h"
#include "diag.h"
#include "hal.h"
#include "log_service.h"
#include <platform_opts.h>
#include "freertos_service.h"
#include "osdep_service.h"


_sema usb_detect_sema;

#include "gpio_api.h"
#include "gpio_irq_api.h"
#include "wdt_api.h"

#define GPIO_IRQ_PIN       PA_3

extern int usbd_get_device_status(void);

gpio_irq_t gpio_btn;
void gpio_demo_irq_handler(uint32_t id, gpio_irq_event event)
{
	gpio_t *gpio_led;

	dbg_printf("%s==> \r\n", __FUNCTION__);

	rtw_up_sema_from_isr(&usb_detect_sema);
}

int usb_gpio_init(void)
{

	dbg_printf("\r\n   usb gpio init   \r\n");

	// Initial Push Button pin as interrupt source
	gpio_irq_init(&gpio_btn, GPIO_IRQ_PIN, gpio_demo_irq_handler, 10);
	gpio_irq_set(&gpio_btn, IRQ_FALL, 1);    // Falling Edge Trigger
	gpio_irq_enable(&gpio_btn);
	return 0;
}

void AUSBH(void *arg)
{
	extern void example_usbh_msc(void);
	example_usbh_msc();
	printf("USBH\r\n");
}

void AUSBD(void *arg)
{
	extern void example_usbd_cdc_acm(void);
	example_usbd_cdc_acm();
	printf("USBD\r\n");
}

extern int usbd_new_uvc_init(void);
static void example_usbd_new_uvc_thread(void *param)
{
	extern void example_media_uvcd(void);
	example_media_uvcd();
	vTaskDelete(NULL);
}

void example_usbd_new_uvc(void)
{
	int ret;
	struct task_struct task;

	ret = rtw_create_task(&task, "example_usbd_new_uvc_thread", 10240, tskIDLE_PRIORITY + 5, example_usbd_new_uvc_thread, NULL);
	if (ret != pdPASS) {
		printf("\n\rUSBD uvc create thread fail\n\r");
	}
}

void AUDFU(void *arg)
{
	//example_usbd_new_dfu();
	printf("Enter dfu mode\r\n");
	extern void example_usb_dfu_ota(void);
	example_usb_dfu_ota();
	printf("UDFU\r\n");
}

void AUCDC(void *arg)
{
	extern void example_usbd_cdc_acm(void);
	//usbd_new_uvc_init();
	example_usbd_cdc_acm();
	printf("UUVC\r\n");
}

static void example_watchdog_task(void *param)
{
	while (1) {
		vTaskDelay(1000);
		watchdog_refresh();
	}
	vTaskDelete(NULL);
}
extern int get_cdc_procedure_status(void);
extern int get_mass_storage_procedure_status(void);
static void example_usb_demo(void *param)
{
	printf("Start the USB switch demo\r\n");
	usb_gpio_init();
	watchdog_init(5000); // setup 5s watchdog
	watchdog_start();

	int demo_status = 0;

	rtw_init_sema(&usb_detect_sema, 0);
	extern void example_usbd_cdc_acm(void);
	extern void example_usbh_msc(void);

	if (xTaskCreate(example_watchdog_task, ((const char *)"example_watchdog_task"), 2048, NULL, 1 + 1, NULL) != pdPASS) {
		printf("\n\r%s xTaskCreate(init_thread) failed", __FUNCTION__);
	}

	while (1) {
		rtw_down_sema(&usb_detect_sema);
		if (get_cdc_procedure_status() || get_mass_storage_procedure_status()) {
			printf("The procedure is running\r\n");
			continue;
		}
		if (demo_status == 1) {
			printf("The procedure is running\r\n");
			continue;
		}
		demo_status = 1;
		printf("Enter device mode\r\n");
		example_usbd_cdc_acm();
		vTaskDelay(2000);
		usbd_get_device_status();
		if (usbd_get_device_status() != 1) {
			printf("usb status %d\r\n", usbd_get_device_status());
			printf("No device connect, Enter host mode\r\n");
			example_usbh_msc();
		}
		demo_status = 0;
	}
}

void AUDEM(void *arg)
{
	if (xTaskCreate(example_usb_demo, ((const char *)"example_usb_demo"), 2048, NULL, 1 + 1, NULL) != pdPASS) {
		printf("\n\r%s xTaskCreate(init_thread) failed", __FUNCTION__);
	}
}

void AUMSD(void *arg)
{
	extern void example_usbd_msc(void);
	example_usbd_msc();
	printf("Enter usb mass storage device mode\r\n");
}
#if(CONFIG_ETHERNET == 1 && ETHERNET_INTERFACE == USB_INTERFACE)
void AUECM(void *arg)
{
	/* extern void example_usbh_ecm(void);
	example_usbh_ecm(); */
	extern void ethernet_usb_init(void);
	ethernet_usb_init();
	printf("Enter USB Ethernet host mode\r\n");
}
#endif
int ecm_log = 0;
void AUTES(void *arg)
{
	ecm_log = 1;
	extern int hcd_measure_flag;
	hcd_measure_flag = 1;
	printf("Enter USB Ethernet log\r\n");

	/* extern void example_arp_test(void);
	example_arp_test(); */
}

void AUVID(void *arg)
{
	printf("Enable the video streaming test from ethernet\r\n");
	extern void example_media_rtsp_ethernet(void);
	example_media_rtsp_ethernet();
}

log_item_t usb_items[] = {
	{"USBH", AUSBH,},
	{"USBD", AUSBD,},
	{"UDFU", AUDFU,},
	{"UCDC", AUCDC,},
	{"UMSD", AUMSD,},
	{"UDEM", AUDEM,},
#if(CONFIG_ETHERNET == 1 && ETHERNET_INTERFACE == USB_INTERFACE)
	{"UECM", AUECM,},
#endif
	{"UTES", AUTES,},
	{"UVID", AUVID,},
};

void atcmd_usb_init(void)
{
	log_service_add_table(usb_items, sizeof(usb_items) / sizeof(usb_items[0]));
}

void usb_switch_demo(void)
{
	if (xTaskCreate(example_usb_demo, ((const char *)"example_usb_demo"), 2048, NULL, 1 + 1, NULL) != pdPASS) {
		printf("\n\r%s xTaskCreate(init_thread) failed", __FUNCTION__);
	}
}
