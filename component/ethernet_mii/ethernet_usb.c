#include <platform_opts.h>
#include <platform_stdlib.h>
#include "usbh.h"
#include "osdep_service.h"
#include "usbh_cdc_ecm.h"
#include "usbh_cdc_ecm_hal.h"

#ifdef PLATFORM_FREERTOS
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#endif
#include "osdep_service.h"
#include "lwip_netconf.h"
#include "lwip_intf.h"
#include "platform_opts.h"

#if(CONFIG_ETHERNET == 1 && ETHERNET_INTERFACE == USB_INTERFACE)

#define ETHERNET_IDX (NET_IF_NUM - 1)

extern struct netif  xnetif[NET_IF_NUM];

static u8 TX_BUFFER[1536];
static u8 RX_BUFFER[1536];

static _mutex mii_tx_mutex;

extern int lwip_init_done;

#define USBH_ECM_THREAD_STACK_SIZE 2048

#define ENABLE_LWIP

/* typedef void (*usb_report_usbdata)(u8 *buf, u32 len); */
extern void pfw_dump_mem(uint8_t *buf, int size);
extern int ecm_log;
void usb_cdc_ecm_usbdata(u8 *buf, u32 len)
{
	printf("usb_cdc_ecm_usbdata len %d\r\n", len);
	if (ecm_log && len < 100) {
		pfw_dump_mem(buf, len);
	}
}

static u32 rx_buffer_saved_data = 0;
static u32 ip_total_len = 0;
u8 multi_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//should parse the data to get the ip header
u8 rltk_mii_recv_data(u8 *buf, u32 total_len, u32 *frame_length)
{
	u8 *pbuf ;

	if (0 == ip_total_len) { //first packet
		pbuf = RX_BUFFER;
		rtw_memcpy((void *)pbuf, buf, total_len);
		if (total_len != 512) { //should finish
			*frame_length = total_len;
			return 1;
		} else { //get the total length
			rx_buffer_saved_data = total_len;
			//should check the vlan header
			//should check it is IP packet 0x0800
			ip_total_len = buf[14 + 2] * 256 + buf[14 + 2 + 1];
			//printf("ip packet len = %d\n", ip_total_len);
			if (512 - 14 == ip_total_len) { //the total length is 512
				*frame_length = total_len;
				ip_total_len = 0;
				return 1;
			}
		}
	} else {
		pbuf = RX_BUFFER + rx_buffer_saved_data;
		rtw_memcpy((void *)pbuf, buf, total_len);
		rx_buffer_saved_data += total_len;
		if (total_len != 512) {
			//should finish
			*frame_length = rx_buffer_saved_data;
			ip_total_len = 0;
			return 1;
		} else {
			//should check the vlan header
			//should check it is IP packet 0x0800
			if (rx_buffer_saved_data - 14 == ip_total_len) {
				//should finish
				*frame_length = rx_buffer_saved_data;
				ip_total_len = 0;
				return 1;
			}
		}
	}

	return 0;
}
u8 rltk_mii_recv_data_check(u8 *mac, u32 frame_length)
{
	u8 *pbuf = RX_BUFFER;
	u8 checklen = 0;
	u8 multi[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	//printf("[usb]get framelen=%d\n",frame_length);

	if (memcmp(mac, pbuf, 6) == 0 || memcmp(multi, pbuf, 6) == 0) {
		checklen = 7 ;
		//printf("\n[rx data header]");
	} else {
		checklen = 6;
		//printf("\n[rx data header][exit]");
	}

	if (1) {
		u32 index = 0 ;
		u32 max = frame_length;

		if (frame_length >= checklen) {
			max = checklen;
		}
		/* for(index=0; index<max; index++)
			printf("0x%x ",pbuf[index]);
		printf("\n\n"); */
	}

	return (checklen == 6) ? (0) : (1);
}

void usb_ethernet_ecm_cb(u8 *buf, u32 len)
{
	u8 *pbuf = RX_BUFFER;
	//memcpy(pbuf, buf, len);
	u32 frame_len = 0;

	if (ecm_log) {
		printf("len %d\r\n", len);
	}

	if (0 == rltk_mii_recv_data(buf, len, &frame_len)) {
		return;
	}

	if (0 == rltk_mii_recv_data_check(multi_mac, frame_len)) {
		return;
	}
	if (frame_len > 512) {
		if (ecm_log) {
			pfw_dump_mem(pbuf, frame_len);
		}
	}
	ethernetif_mii_recv(&xnetif[ETHERNET_IDX], frame_len);
	/* 	printf("recv len %d\r\n", len);
		if (ecm_log && len < 100) {
			pfw_dump_mem(buf, len);
		} */
}

void rltk_mii_recv(struct eth_drv_sg *sg_list, int sg_len)
{
	struct eth_drv_sg *last_sg;
	u8 *pbuf = RX_BUFFER;

	for (last_sg = &sg_list[sg_len]; sg_list < last_sg; ++sg_list) {
		if (sg_list->buf != 0) {
			rtw_memcpy((void *)(sg_list->buf), pbuf, sg_list->len);
			pbuf += sg_list->len;
		}
	}
}

s8 rltk_mii_send(struct eth_drv_sg *sg_list, int sg_len, int total_len)
{
	int ret = 0;
	struct eth_drv_sg *last_sg;
	u8 *pdata = TX_BUFFER;
	u8	retry_cnt = 0;
	u32 size = 0;
	for (last_sg = &sg_list[sg_len]; sg_list < last_sg; ++sg_list) {
		rtw_memcpy(pdata, (void *)(sg_list->buf), sg_list->len);
		pdata += sg_list->len;
		size += sg_list->len;
	}
	pdata = TX_BUFFER;
	//DBG_8195A("mii_send len= %d\n\r", size);
	if (NULL == mii_tx_mutex) {
		rtw_mutex_init(&mii_tx_mutex);
	}
	rtw_mutex_get(&mii_tx_mutex);
	while (1) {
		ret = usbh_cdc_ecm_senddata(pdata, size);
		if (ret == 0) {
			//ethernet_send();
			//ret = 0;
			break;
		}
		if (++retry_cnt > 3) {
			printf("TX drop\n\r");
			ret = -1;
			break;
		} else {
			rtw_udelay_os(1);
		}
	}
	rtw_mutex_put(&mii_tx_mutex);

	//wait reply success,wait signal
	while (!usbh_cdc_ecm_get_sendflag()) {
		rtw_msleep_os(1);
	}
	return ret;
}


void example_usbh_ecm_thread(void *param)
{
	int ret = 0;
	extern int otg_select_usb_mode(int value);
	otg_select_usb_mode(1);
#ifdef ENABLE_LWIP
	usbh_cdc_ecm_do_init((void *)usb_ethernet_ecm_cb);
#else
	usbh_cdc_ecm_do_init((void *)usb_cdc_ecm_usbdata);
#endif
	rtw_mutex_init(&mii_tx_mutex);
	vTaskDelay(1000);

	u8 *mac;
	mac = (unsigned char *)usbh_cdc_ecm_process_mac_str();
	//If no mac address that we will set the fake mac address
	if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
		mac[0] = 0x00;
		mac[1] = 0xe0;
		mac[2] = 0x4c;
		mac[3] = 0x36;
		mac[4] = 0x00;
		mac[5] = 0x02;
	}

	usbh_cdc_ecm_set_ethernet_packetfilter(CDC_ECM_ETH_PACKET_TYPE_DIRECTED | CDC_ECM_ETH_PACKET_TYPE_BROADCAST);
#ifdef ENABLE_LWIP
	if (!lwip_init_done) {
		LwIP_Init();
	}
	printf("mac[%02x %02x %02x %02x %02x %02x]\r\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	memcpy((void *)xnetif[ETHERNET_IDX].hwaddr, (void *)mac, 6);
	int i = 0;
	for (i = 0; i < 6; i++) {
		multi_mac[i] = mac[i];
	}
	printf("mac[%02x %02x %02x %02x %02x %02x]\r\n", xnetif[ETHERNET_IDX].hwaddr[0], xnetif[ETHERNET_IDX].hwaddr[1], xnetif[ETHERNET_IDX].hwaddr[2],
		   xnetif[ETHERNET_IDX].hwaddr[3], xnetif[ETHERNET_IDX].hwaddr[4], xnetif[ETHERNET_IDX].hwaddr[5]);
#if LWIP_VERSION_MAJOR >= 2
	netif_set_up(&xnetif[ETHERNET_IDX]);
	netif_set_link_up(&xnetif[ETHERNET_IDX]);
#endif
	LwIP_DHCP(ETHERNET_IDX, DHCP_START);
	netif_set_default(&xnetif[ETHERNET_IDX]);  //Set default gw to ether netif
#endif
	vTaskDelete(NULL);
}

void ethernet_usb_init(void)
{
	int ret;
	struct task_struct task;

	printf("\n[MSC] USB host ECM demo started...\n");

	ret = rtw_create_task(&task, "example_usbh_ecm_thread", USBH_ECM_THREAD_STACK_SIZE, tskIDLE_PRIORITY + 2, example_usbh_ecm_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[MSC] Fail to create USB host MSC thread\n");
	}
}

unsigned char arp_packet[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xe0, 0x4c, 0x36, 0x00, 0x02, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0xe0, 0x4c, 0x36, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x1f, 0xC5};
void example_usbh_send_thread(void *param)
{
	vTaskDelay(2000);
	while (1) {
		vTaskDelay(500);
		usbh_cdc_ecm_bulk_send(arp_packet, sizeof(arp_packet));
	}
}

void example_arp_test(void)
{
	int ret;
	struct task_struct task;
	ret = rtw_create_task(&task, "example_usbh_send_thread", USBH_ECM_THREAD_STACK_SIZE, tskIDLE_PRIORITY + 2, example_usbh_send_thread, NULL);
	if (ret != pdPASS) {
		printf("\n[MSC] Fail to create USB host MSC thread\n");
	}
}
#endif