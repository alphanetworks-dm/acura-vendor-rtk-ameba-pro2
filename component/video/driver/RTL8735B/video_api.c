/******************************************************************************
*
* Copyright(c) 2021 - 2025 Realtek Corporation. All rights reserved.
*
******************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>
#include <semphr.h>
#include <osdep_service.h>
#include <math.h>
#include "platform_stdlib.h"
#include <unistd.h>
#include <sys/wait.h>
#include "base_type.h"
#include "cmsis.h"
#include "error.h"
#include "hal.h"
#include "hal_video.h"
#include "video_api.h"
#include "platform_opts.h"
#include "hal_voe_nsc.h"

static isp_info_t isp_info;
static voe_info_t voe_info = {0};
static int voe_info_init = 0;

volatile video_peri_info_t g_video_peri_info = {0};

hal_gpio_adapter_t sensor_en_gpio;
int sensor_en_pin_delay_init = 0;

//Video boot config//
#include "fw_img_export.h"
#include "video_boot.h"
#include "ftl_common_api.h"
#include "../fwfs/fwfs.h"
extern BL4VOE_INFO_T bl4voe_shared;
extern uint8_t __eram_heap_start__[];
extern uint8_t __eram_bss_end__[];
extern uint8_t __eram_end__[];
extern void *pvPortInsertPreAlloc(void *addr, size_t xWantedSize);
video_boot_stream_t *isp_boot = (video_boot_stream_t *)bl4voe_shared.data;

static mult_sensor_info_t multi_sensor_info = {0};
int video_isp_memcpy(void *dst, const void *src, u32 size);
int video_voe_memcpy(void *dst, const void *src, u32 size);
int video_load(int sensor_index);
void *video_fw_deinit(void);
void video_set_isp_info(isp_info_t *info);
int video_reset_fw(int ch, int id);
const unsigned int crc32_result[10] = {0xd202ef8d, 0xa505df1b, 0x3c0c8ea1, 0x4b0bbe37, 0xd56f2b94, 0xa2681b02, 0x3b614ab8, 0x4c667a2e, 0xdcd967bf, 0xabde5729};
#define FCS_ID  0x04
#define FCS_CRC 0x08
extern int __voe_code_start__[];
int voe_fw_reload = 0;
int video_load_fw(unsigned int sensor_start_addr);
unsigned char *video_load_sensor(unsigned int sensor_start_addr);
unsigned char *video_load_iq(unsigned int iq_start_addr);
/////////////////////////////////
#include "section_config.h"
SDRAM_DATA_SECTION unsigned char sensor_buf[4096];
SDRAM_DATA_SECTION unsigned char iq_buf[64 * 1024];

int video_dbg_level = VIDEO_LOG_MSG;

#define video_dprintf(level, ...) if(level >= video_dbg_level) printf(__VA_ARGS__)

char *fmt_table[] = {"hevc", "h264", "jpeg", "nv12", "rgb", "nv16", "hevc", "h264"};
char *paramter_table[] = {
	"-l 1 --gopSize=1 -U1 -u1 -q-1 --roiMapDeltaQpBlockUnit 0 --roiMapDeltaQpEnable 1",	// HEVC
	"-l 1 --gopSize=3 -U1 -u1 -q-1 -I6 -A-8 --smoothPsnrInGOP=1 --rcQpDeltaRange=15 --picQpDeltaRange=-4:6 --blockRCSize=1",
	"-g 1 -b 1",			// JPEG
	"",						// NV12
	"",						// RGB
	"",						// NV16
};

int isp_ch_buf_num[5] = {2, 2, 2, 2, 2};

void video_set_debug_level(int value)
{
	if (value <= VIDEO_LOG_OFF) {
		video_dbg_level = value;
	} else {
		video_dprintf(VIDEO_LOG_ERR, "The maximu is %d\r\n", VIDEO_LOG_OFF);
	}
}

// Output stream callback function
static void temp_output_cb(void *param1, void  *param2, uint32_t arg)
{
	enc2out_t *enc2out = (enc2out_t *)param1;
	hal_video_adapter_t  *v_adp = (hal_video_adapter_t *)param2;
	commandLine_s *cml = &v_adp->cmd[enc2out->ch];

	video_dprintf(VIDEO_LOG_INF, "ch = %d, type = %d\r\n", enc2out->ch, enc2out->codec);

	// VOE status check
	if (enc2out->cmd_status != VOE_OK) {
		switch (enc2out->cmd_status) {
		case VOE_ENC_BUF_OVERFLOW:
		case VOE_ENC_QUEUE_OVERFLOW:
		case VOE_JPG_BUF_OVERFLOW:
		case VOE_JPG_QUEUE_OVERFLOW:
			video_dprintf(VIDEO_LOG_MSG, "VOE CH%d ENC/BUF overflow\n", enc2out->ch);
			break;
		default:
			video_dprintf(VIDEO_LOG_MSG, "Error CH%d VOE status %x\n", enc2out->ch, enc2out->cmd_status);
			break;
		}
		return;
	}


	if ((enc2out->codec & (CODEC_H264 | CODEC_HEVC)) != 0) {
		hal_video_release(enc2out->ch, (enc2out->codec & (CODEC_H264 | CODEC_HEVC)), 0);
	}

	if ((enc2out->codec & CODEC_JPEG) != 0) {
		hal_video_release(enc2out->ch, (enc2out->codec & CODEC_JPEG), 0);
	}

	if ((enc2out->codec & (CODEC_NV12 | CODEC_RGB | CODEC_NV16)) != 0) {
		hal_video_isp_buf_release(enc2out->ch, (uint32_t)enc2out->isp_addr);
	}


	if (enc2out->finish == LAST_FRAME) {

	}

}

int isp_ctrl_cmd(int argc, char **argv)
{
	int id;
	int set_flag;
	int set_value;
	int read_value;
	int ret;
	if (argc >= 2) {
		set_flag = atoi(argv[0]);
		id = atoi(argv[1]);
		if (set_flag == 0) {
			ret = hal_video_isp_ctrl(id, set_flag, &read_value);
			if (ret == 0) {
				video_dprintf(VIDEO_LOG_INF, "result 0x%08x %d \r\n", read_value, read_value);
			} else {
				video_dprintf(VIDEO_LOG_ERR, "isp_ctrl get error\r\n");
			}
		} else {

			if (argc >= 3) {
				set_value = atoi(argv[2]);

				ret = hal_video_isp_ctrl(id, set_flag, &set_value);
				if (ret != 0) {
					video_dprintf(VIDEO_LOG_ERR, "isp_ctrl set error\r\n");
				}
			} else {
				video_dprintf(VIDEO_LOG_ERR, "isp_ctrl set error : need 3 argument: set_flag id  set_value\r\n");
			}
		}

	} else {
		video_dprintf(VIDEO_LOG_ERR, "isp_ctrl  error : need 2~3 argument: set_flag id  [set_value] \r\n");
	}
	return OK;
}

int iq_tuning_cmd(int argc, char **argv)
{
	int ccmd;
	uint32_t cmd_data;
	struct isp_tuning_cmd *iq_cmd;
	if (argc < 1) {	// usage
		video_dprintf(VIDEO_LOG_INF, "iqtun cmd\r\n");
		video_dprintf(VIDEO_LOG_INF, "      0: rts_isp_tuning_get_iq\n");
		video_dprintf(VIDEO_LOG_INF, "      1 : rts_isp_tuning_set_iq\r\n");
		video_dprintf(VIDEO_LOG_INF, "      2 : rts_isp_tuning_get_statis\r\n");
		video_dprintf(VIDEO_LOG_INF, "      3 : rts_isp_tuning_get_param\r\n");
		video_dprintf(VIDEO_LOG_INF, "      4 : rts_isp_tuning_set_param\r\n");
		video_dprintf(VIDEO_LOG_INF, "      5 offset lens : rts_isp_tuning_read_vreg \r\n");
		video_dprintf(VIDEO_LOG_INF, "      6 offset lens value1 value2: rts_isp_tuning_write_vreg\r\n");
		return NOK;
	}
	ccmd = atoi(argv[0]);

	cmd_data = malloc(IQ_CMD_DATA_SIZE + 32); // for cache alignment
	if (cmd_data == NULL) {
		video_dprintf(VIDEO_LOG_ERR, "malloc cmd buf fail\r\n");
		return NOK;
	}
	iq_cmd = (struct isp_tuning_cmd *)((cmd_data + 31) & ~31); // for cache alignment

	if (ccmd == 0) {
		iq_cmd->addr = ISP_TUNING_IQ_TABLE_ALL;
		hal_video_isp_tuning(VOE_ISP_TUNING_GET_IQ, iq_cmd);
	} else if (ccmd == 1) {
		iq_cmd->addr = ISP_TUNING_IQ_TABLE_ALL;
		hal_video_isp_tuning(VOE_ISP_TUNING_SET_IQ, iq_cmd);
	} else if (ccmd == 2) {
		iq_cmd->addr = ISP_TUNING_STATIS_ALL;
		hal_video_isp_tuning(VOE_ISP_TUNING_GET_STATIS, iq_cmd);
	} else if (ccmd == 3) {
		iq_cmd->addr = ISP_TUNING_PARAM_ALL;
		hal_video_isp_tuning(VOE_ISP_TUNING_GET_PARAM, iq_cmd);
	} else if (ccmd == 4) {
		iq_cmd->addr = ISP_TUNING_PARAM_ALL;
		hal_video_isp_tuning(VOE_ISP_TUNING_SET_PARAM, iq_cmd);
	} else if (ccmd == 5) {

		iq_cmd->addr = atoi(argv[1]);
		iq_cmd->len = atoi(argv[2]);
		hal_video_isp_tuning(VOE_ISP_TUNING_READ_VREG, iq_cmd);
		uint32_t *r_data = (uint32_t *)iq_cmd->data;
		for (int i = 0; i < (iq_cmd->len / 4); i++) {
			video_dprintf(VIDEO_LOG_INF, "vreg 0x%08x = 0x%08x \n", iq_cmd->addr + i * 4, r_data[i]);
		}

	} else if (ccmd == 6) {
		if (argc < 4) {
			video_dprintf(VIDEO_LOG_ERR, "      6 offset lens value1 [value2]: rts_isp_tuning_write_vreg\r\n");
		} else {
			iq_cmd->addr = atoi(argv[1]);
			iq_cmd->len = atoi(argv[2]);

			uint32_t *w_data = (uint32_t *)iq_cmd->data;
			w_data[0] = atoi(argv[3]);
			if (argc > 4) {
				for (int i = 0; i < (argc - 4); i++) {
					w_data[i + 1] = atoi(argv[4 + i]);
				}
			}
			hal_video_isp_tuning(VOE_ISP_TUNING_WRITE_VREG, iq_cmd);
		}
	}

	if (cmd_data) {
		free(cmd_data);
	}
	return OK;
}

int video_i2c_cmd(int argc, char **argv)
{
	int rd = 0;
	struct rts_isp_i2c_reg reg = {0};
	if (argc < 1) {	// usage
		video_dprintf(VIDEO_LOG_INF, "i2cs r/w reg data  \r\n");
		video_dprintf(VIDEO_LOG_INF, "      r/w: r/w function 0:write 1:read\n");
		video_dprintf(VIDEO_LOG_INF, "      reg  : sensor reg\r\n");
		video_dprintf(VIDEO_LOG_INF, "      data : sensor data\r\n");
		return 0;
	}
	if (argc > 0) {
		rd = atoi(argv[0]);
		reg.addr = atoi(argv[1]);
		reg.data = atoi(argv[2]);
		if (rd == 0) {
			hal_video_i2c_write(&reg);
		} else {
			hal_video_i2c_read(&reg);
		}
		video_dprintf(VIDEO_LOG_INF, "i2c reg[%x] = %x\n\r", reg.addr, reg.data);
	}
	return 0;
}

int video_encbuf_clean(int ch, int codec)
{
	int ret = 0;
	ret = hal_video_release(ch, codec, 1);
	return ret;
}

int video_encbuf_release(int ch, int codec, int mode)
{
	int ret = 0;
	//printf("hevc/h264/jpeg release = %d\r\n",mode);
	ret = hal_video_release(ch, codec, 0);
	if (ret == NOK) {
		//retry release again
		ret = hal_video_release(ch, codec, 0);
	}
	return ret;
}

int video_ispbuf_release(int ch, int addr)
{
	int ret = 0;
	//printf("nv12/nv16/rgb release = 0x%X\r\n",addr);
	ret = hal_video_isp_buf_release(ch, addr);
	if (ret == NOK) {
		//retry release again
		ret = hal_video_isp_buf_release(ch, addr);
	}
	return ret;
}

int video_ctrl(int ch, int cmd, int arg)
{
	switch (cmd) {
	case VIDEO_SET_RCPARAM: {
		rate_ctrl_s rc_ctrl;
		encode_rc_parm_t *rc_param = (encode_rc_parm_t *)arg;
		memset(&rc_ctrl, 0x0, sizeof(rate_ctrl_s));

		rc_ctrl.maxqp = rc_param->maxQp;
		rc_ctrl.minqp = rc_param->minQp;
		hal_video_set_rc(&rc_ctrl, ch);
	}
	break;
	case VIDEO_FORCE_IFRAME: {
		hal_video_froce_i(ch);
	}
	break;
	case VIDEO_BPS: {
		rate_ctrl_s rc_ctrl;
		memset(&rc_ctrl, 0x0, sizeof(rate_ctrl_s));
		rc_ctrl.bps = arg;
		hal_video_set_rc(&rc_ctrl, ch);
	}
	break;
	case VIDEO_GOP: {
		rate_ctrl_s rc_ctrl;
		memset(&rc_ctrl, 0x0, sizeof(rate_ctrl_s));
		rc_ctrl.gop = arg;
		hal_video_set_rc(&rc_ctrl, ch);
	}
	break;
	//type 0:HEVC 1:H264 2:JPEG 3:NV12 4:RGB 5:NV16
	case VIDEO_HEVC_OUTPUT: {
		hal_video_out_mode(ch, 0, arg);
	}
	break;
	case VIDEO_H264_OUTPUT: {
		hal_video_out_mode(ch, 1, arg);
	}
	break;
	case VIDEO_JPEG_OUTPUT: {
		hal_video_out_mode(ch, 2, arg);
	}
	break;
	case VIDEO_NV12_OUTPUT: {
		hal_video_out_mode(ch, 3, arg);
	}
	break;
	case VIDEO_RGB_OUTPUT: {
		hal_video_out_mode(ch, 4, arg);
	}
	break;
	case VIDEO_NV16_OUTPUT: {
		hal_video_out_mode(ch, 5, arg);
	}
	break;
	case VIDEO_ISP_SET_RAWFMT: {
		hal_video_isp_set_rawfmt(ch, arg);
	}
	break;
	case VIDEO_PRINT_INFO: {
		hal_video_mem_info();
		hal_video_buf_info();
	}
	break;
	case VIDEO_DEBUG: {
		hal_video_print(arg);
	}
	break;
	}

	return 0;
}

int video_set_roi_region(int ch, int x, int y, int width, int height, int value)
{
	int result = 0;
	result = hal_video_roi_region(ch, x, y, width, height, value);
	return result;
}

void video_set_isp_info(isp_info_t *info)
{
	isp_info.sensor_width = info->sensor_width;
	isp_info.sensor_height = info->sensor_height;
	isp_info.sensor_fps = info->sensor_fps;
	isp_info.osd_enable = info->osd_enable;
	isp_info.md_enable = info->md_enable;
	isp_info.hdr_enable = info->hdr_enable;
}

static int video_set_voe_heap(int heap_addr, int heap_size, int use_malloc)
{
#if 0
	if (use_malloc) {
		voe_info.voe_heap_addr = malloc(heap_size);
	} else {
		voe_info.voe_heap_addr = heap_addr;
	}

	if (voe_info.voe_heap_addr) {
		voe_info.voe_heap_size = heap_size;
		return 0;
	} else {
		video_dprintf(VIDEO_LOG_ERR, "malloc voe buffer fail\r\n");
		return -1;
	}
#else
	voe_info.voe_heap_size = heap_size;
	return 0;
#endif
}

#define ISP_COMMON_BUF  900*1024
#define ENC_COMMON_BUF  500*1024
#define ENABLE_OSD_BUF  900*1024
#define ENABLE_MD_BUF   500*1024
#define ENABLE_HDR_BUF  500*1024

#define ISP_CREATE_BUF 200*1024
#define ENC_CREATE_BUF 420*1024
#define SNAPSHOT_BUF   300*1024

int video_buf_calc(int v1_enable, int v1_w, int v1_h, int v1_bps, int v1_shapshot,
				   int v2_enable, int v2_w, int v2_h, int v2_bps, int v2_shapshot,
				   int v3_enable, int v3_w, int v3_h, int v3_bps, int v3_shapshot,
				   int v4_enable, int v4_w, int v4_h)
{
	int voe_heap_size = 0;
	int v3dnr_w = 2560;
	int v3dnr_h = 1440;

	if (isp_info.sensor_width && isp_info.sensor_height) {
		v3dnr_w = isp_info.sensor_width;
		v3dnr_h = isp_info.sensor_height;
	}

	//3dnr
	voe_heap_size += ((v3dnr_w * v3dnr_h * 3) / 2);
	video_dprintf(VIDEO_LOG_INF, "3dnr = %d,%d,%d\r\n", v3dnr_w, v3dnr_h, voe_heap_size);

	//common buffer
	voe_heap_size += ISP_COMMON_BUF;
	voe_heap_size += ENC_COMMON_BUF;
	if (isp_info.osd_enable) {
		if (isp_info.osd_buf_size) {
			voe_heap_size += isp_info.osd_buf_size;
		} else {
			voe_heap_size += ENABLE_OSD_BUF;
		}
	}

	if (isp_info.md_enable) {
		if (isp_info.md_buf_size) {
			voe_heap_size += isp_info.md_buf_size;
		} else {
			voe_heap_size += ENABLE_MD_BUF;
		}
	}

	if (isp_info.hdr_enable) {
		voe_heap_size += ENABLE_HDR_BUF;
	}

	if (v1_enable) {
		//ISP buffer
		voe_heap_size += ((v1_w * v1_h * 3) / 2) * isp_ch_buf_num[0];
		//ISP common
		voe_heap_size += ISP_CREATE_BUF;
		//enc ref
		voe_heap_size += ((v1_w * v1_h * 3) / 2) * 2;
		//enc common
		voe_heap_size += ENC_CREATE_BUF;
		//enc buffer
		voe_heap_size += ((v1_w * v1_h) / 2 +  v1_bps * 2);
		//shapshot
		if (v1_shapshot) {
			voe_heap_size += ((v1_w * v1_h * 3) / 2) + SNAPSHOT_BUF;
		}
	}

	video_dprintf(VIDEO_LOG_INF, "v1 = %d,%d,%d\r\n", v1_w, v1_h, voe_heap_size);

	if (v2_enable) {
		//ISP buffer
		voe_heap_size += ((v2_w * v2_h * 3) / 2) * isp_ch_buf_num[1];
		//ISP common
		voe_heap_size += ISP_CREATE_BUF;
		//enc ref
		voe_heap_size += ((v2_w * v2_h * 3) / 2) * 2;
		//enc common
		voe_heap_size += ENC_CREATE_BUF;
		//enc buffer
		voe_heap_size += ((v2_w * v2_h) / 2 +  v2_bps * 2);
		//shapshot
		if (v2_shapshot) {
			voe_heap_size += ((v2_w * v2_h * 3) / 2) + SNAPSHOT_BUF;
		}
	}

	video_dprintf(VIDEO_LOG_INF, "v2 = %d,%d,%d\r\n", v2_w, v2_h, voe_heap_size);

	if (v3_enable) {
		//ISP buffer
		voe_heap_size += ((v3_w * v3_h * 3) / 2) * isp_ch_buf_num[2];
		//ISP common
		voe_heap_size += ISP_CREATE_BUF;
		//enc ref
		voe_heap_size += ((v3_w * v3_h * 3) / 2) * 2;
		//enc common
		voe_heap_size += ENC_CREATE_BUF;
		//enc buffer
		voe_heap_size += ((v3_w * v3_h) / 2 +  v3_bps * 2);
		//shapshot
		if (v3_shapshot) {
			voe_heap_size += ((v3_w * v3_h * 3) / 2) + SNAPSHOT_BUF;
		}
	}

	video_dprintf(VIDEO_LOG_INF, "v3 = %d,%d,%d\r\n", v3_w, v3_h, voe_heap_size);

	if (v4_enable) {
		//ISP buffer
		voe_heap_size += v4_w * v4_h * 3 * isp_ch_buf_num[4];
		//ISP common
		voe_heap_size += ISP_CREATE_BUF;
	}

	video_dprintf(VIDEO_LOG_INF, "v4 = %d,%d,%d\r\n", v4_w, v4_h, voe_heap_size);

	video_set_voe_heap(NULL, voe_heap_size, 1);

	return voe_heap_size;
}

void video_buf_release(void)
{
	if ((voe_info.voe_heap_addr) != NULL) {
		free(voe_info.voe_heap_addr);
		voe_info.voe_heap_addr = NULL;
	}
}

void video_init_peri(void)
{
	int peri_update_with_fcs = 0;


	volatile hal_i2c_adapter_t  i2c_master_video;


	g_video_peri_info.scl_pin = PIN_D12;
	g_video_peri_info.sda_pin = PIN_D10;
	g_video_peri_info.i2c_id = 3;

	g_video_peri_info.rst_pin = PIN_E0;
	g_video_peri_info.pwdn_pin = PIN_D11;
	g_video_peri_info.pwr_ctrl_pin = PIN_A5;
	g_video_peri_info.snr_clk_pin = PIN_D13;

	peri_update_with_fcs = hal_video_peri_update_with_fcs(&g_video_peri_info);

	if (!hal_video_check_fcs_OK()) {

		if (peri_update_with_fcs) {
			hal_pinmux_unregister(g_video_peri_info.pwr_ctrl_pin, PID_GPIO); //sensor clock
			hal_pinmux_unregister(g_video_peri_info.rst_pin, PID_GPIO); //reset pin
			hal_pinmux_unregister(g_video_peri_info.pwdn_pin, PID_GPIO); //power down pin
			hal_pinmux_unregister(g_video_peri_info.snr_clk_pin, PID_SENSOR); //sensor clock

			i2c_master_video.pltf_dat.scl_pin = g_video_peri_info.scl_pin;
			i2c_master_video.pltf_dat.sda_pin = g_video_peri_info.sda_pin;
			i2c_master_video.init_dat.index = g_video_peri_info.i2c_id;
			hal_i2c_pin_unregister_simple(&i2c_master_video);
		}


		if (IS_CUT_TEST(hal_sys_get_rom_ver())) {
			g_video_peri_info.pwr_ctrl_pin = PIN_A5;
			g_video_peri_info.scl_pin	= PIN_D14;
			g_video_peri_info.sda_pin	= PIN_D12;
			g_video_peri_info.rst_pin	= PIN_D13;
			g_video_peri_info.pwdn_pin = PIN_D11;
			g_video_peri_info.snr_clk_pin = PIN_D10;
			g_video_peri_info.i2c_id = 3;
		} else {
			g_video_peri_info.pwr_ctrl_pin = PIN_A5;
			g_video_peri_info.scl_pin	= PIN_D12;
			g_video_peri_info.sda_pin	= PIN_D10;
			g_video_peri_info.rst_pin	= PIN_E0;
			g_video_peri_info.pwdn_pin = PIN_D11;
			g_video_peri_info.snr_clk_pin = PIN_D13;
			g_video_peri_info.i2c_id = 3;
		}

		// Enable Sensor PWR
		hal_gpio_init(&sensor_en_gpio, g_video_peri_info.pwr_ctrl_pin);
		hal_gpio_set_dir(&sensor_en_gpio, GPIO_OUT);
		hal_gpio_write(&sensor_en_gpio, 1);
		video_dprintf(VIDEO_LOG_INF, "set sensor pwr 0x%02x \n", g_video_peri_info.pwr_ctrl_pin);
		// Enable GPIO
		hal_sys_peripheral_en(GPIO_SYS, ENABLE);
		hal_pinmux_register(g_video_peri_info.rst_pin, PID_GPIO); //reset pin
		hal_pinmux_register(g_video_peri_info.pwdn_pin, PID_GPIO); //power down pin
		hal_pinmux_register(g_video_peri_info.snr_clk_pin, PID_SENSOR); //sensor clock
		video_dprintf(VIDEO_LOG_INF, "register pin rst 0x%02x pwdn 0x%02x snr_clk 0x%02x \n", g_video_peri_info.rst_pin, g_video_peri_info.pwdn_pin,
					  g_video_peri_info.snr_clk_pin);

		// Enable I2C
		i2c_master_video.pltf_dat.scl_pin = g_video_peri_info.scl_pin;
		i2c_master_video.pltf_dat.sda_pin = g_video_peri_info.sda_pin;
		i2c_master_video.init_dat.index = g_video_peri_info.i2c_id;//1;
		hal_i2c_pin_register_simple(&i2c_master_video);
		video_dprintf(VIDEO_LOG_INF, "i2c init scl 0x%02x sda 0x%02x id %d \n", g_video_peri_info.scl_pin, g_video_peri_info.sda_pin, g_video_peri_info.i2c_id);

	} else {
		sensor_en_pin_delay_init = 0x1;  // set flag for reset during de-init
		hal_video_reset_fcs_OK();
	}

}

void video_deinit_peri(void)
{
	volatile hal_i2c_adapter_t	i2c_master_video;

	// Disable I2C
	i2c_master_video.pltf_dat.scl_pin = g_video_peri_info.scl_pin;
	i2c_master_video.pltf_dat.sda_pin = g_video_peri_info.sda_pin;
	i2c_master_video.init_dat.index = g_video_peri_info.i2c_id;
	hal_i2c_pin_unregister_simple(&i2c_master_video);

	if (sensor_en_pin_delay_init) {    // for fcs OK flow, unregister and re-init
		sensor_en_pin_delay_init = 0;
		hal_pinmux_unregister(g_video_peri_info.pwr_ctrl_pin, PID_GPIO);
		video_dprintf(VIDEO_LOG_INF, "unregister sensor pwr 0x%02x \n", g_video_peri_info.pwr_ctrl_pin);
		hal_gpio_init(&sensor_en_gpio, g_video_peri_info.pwr_ctrl_pin);
		hal_gpio_set_dir(&sensor_en_gpio, GPIO_OUT);
	}
	hal_gpio_write(&sensor_en_gpio, 0);
	hal_gpio_deinit(&sensor_en_gpio);
	//unregister GPIO

	hal_pinmux_unregister(g_video_peri_info.rst_pin, PID_GPIO);//reset pin
	hal_pinmux_unregister(g_video_peri_info.pwdn_pin, PID_GPIO);//power down pin
	hal_pinmux_unregister(g_video_peri_info.snr_clk_pin, PID_SENSOR);//reset pin

}


int video_open(video_params_t *v_stream, output_callback_t output_cb, void *ctx)
{
	int ch = v_stream->stream_id;
	int fcs_v = v_stream->fcs;
	int fps = 30;
	int gop = 30;
	int rcMode = 2;
	int bps = 1024 * 1024;
	int minQp = 0;
	int maxQP = 51;
	int rotation = 0;
	int jpeg_qlevel = 5;

	char cmd1[256];
	char cmd2[256];
	char cmd3[256];
	char fps_cmd1[48];
	char fps_cmd2[48];
	char fps_cmd3[48];
	int type;
	int res = 0;
	int codec = 0;
	int out_rsvd_size = (v_stream->width * v_stream->height) / 2;
	int out_buf_size = v_stream->bps * 2 + out_rsvd_size;
	int jpeg_out_buf_size = out_rsvd_size * 3;

	video_dprintf(VIDEO_LOG_INF, "video w = %d, video h = %d\r\n", v_stream->width, v_stream->height);

	memset(fps_cmd1, 0x0, 48);
	memset(fps_cmd2, 0x0, 48);
	memset(fps_cmd3, 0x0, 48);
	memset(cmd1, 0x0, 256);
	memset(cmd2, 0x0, 256);
	memset(cmd3, 0x0, 256);

	type = v_stream->type;

	res = v_stream->resolution;

	if (v_stream->fps) {
		fps = v_stream->fps;
	}

	if (v_stream->bps) {
		bps = v_stream->bps;
	}

	if (v_stream->gop) {
		gop = v_stream->gop;
	}

	if (v_stream->rc_mode) {
		rcMode = v_stream->rc_mode - 1;
		if (rcMode) {
			minQp = 20;
			maxQP = 45;
		}
	}

	if (v_stream->rotation) {
		rotation = v_stream->rotation;
	}

	if (v_stream->jpeg_qlevel) {
		jpeg_qlevel = v_stream->jpeg_qlevel;
	}


	switch (type) {
	case 0:
		codec = CODEC_HEVC;
		break;
	case 1:
		codec = CODEC_H264;
		break;
	case 2:
		codec = CODEC_JPEG;
		break;
	case 3:
		codec = CODEC_NV12;
		break;
	case 4:
		codec = CODEC_RGB;
		break;
	case 5:
		codec = CODEC_NV16;
		break;
	case 6:
		codec = CODEC_HEVC | CODEC_JPEG;
		break;
	case 7:
		codec = CODEC_H264 | CODEC_JPEG;
		break;
	}

	//if (fcs_v) {
	if (isp_boot->fcs_status == 1 && isp_boot->fcs_setting_done == 0 && isp_boot->video_params[ch].fcs == 1) {

		if (hal_video_out_cb(output_cb, 4096, (uint32_t)ctx, ch) != OK) {
			video_dprintf(VIDEO_LOG_ERR, "hal_video_cb_register fail\n");
			return NULL;
		}
		static int count = 0;
		count++;
		video_dprintf(VIDEO_LOG_INF, "start fcs video\r\n");
		if (codec & CODEC_H264) {
			hal_video_out_mode(ch, TYPE_H264, 2);
		} else if (codec & CODEC_HEVC) {
			hal_video_out_mode(ch, TYPE_HEVC, 2);
		}
		hal_video_fcs_ch(count);
		if (count == isp_boot->fcs_channel) {
			isp_boot->fcs_setting_done = 1;
			video_dprintf(VIDEO_LOG_MSG, "The fcs setup is finished\r\n");
		}
		voe_info.stream_is_open[ch] = 1;

		if (voe_info_init == 0) {
			memset(voe_info.stream_is_open, 0, sizeof(uint32_t)*MAX_CHANNEL);
			voe_info_init = 1;
		}
		voe_info.stream_is_open[ch] = 1;
		return OK;
	}

	if ((codec & (CODEC_HEVC | CODEC_H264)) != 0) {
		sprintf(fps_cmd1, "-f %d -j %d -R %d -B %d --vbr %d -n %d -m %d", fps, fps, gop, bps, rcMode, minQp, maxQP);
		sprintf(cmd1, "%s %d %s -w %d -h %d -r %d --mode %d --codecFormat %d %s --dbg 1 -i isp"
				, fmt_table[(codec & (CODEC_HEVC | CODEC_H264)) - 1]
				, ch
				, fps_cmd1
				, v_stream->width
				, v_stream->height
				, rotation
				, 2
				, (codec & (CODEC_HEVC | CODEC_H264)) - 1
				, paramter_table[(codec & (CODEC_HEVC | CODEC_H264)) - 1]);
	}

	if ((codec & CODEC_JPEG) != 0) {
		sprintf(fps_cmd2, "-n %d", fps);
		sprintf(cmd2, "%s %d %s -w %d -h %d -r %d -q %d --mode %d --codecFormat %d %s --dbg 1 -i isp"
				, fmt_table[2]
				, ch
				, fps_cmd2
				, v_stream->width
				, v_stream->height
				, rotation
				, jpeg_qlevel
				, 0
				, 2
				, paramter_table[2]);
	}

	if ((codec & (CODEC_NV12 | CODEC_RGB | CODEC_NV16)) != 0) {
		int value;
		if ((codec & CODEC_NV12) != 0) {
			value = 3;
		} else if ((codec & CODEC_RGB) != 0) {
			value = 4;
		} else {
			value = 5;
		}
		sprintf(fps_cmd3, "-j %d", fps);
		sprintf(cmd3, "%s %d %s -w %d -h %d --mode %d --codecFormat %d %s --dbg 1 -i isp"
				, fmt_table[value]
				, ch
				, fps_cmd3
				, v_stream->width
				, v_stream->height
				, 0
				, 3
				, paramter_table[value]);
		video_dprintf(VIDEO_LOG_INF, "str3 %s\n", cmd3);

	}


	video_dprintf(VIDEO_LOG_INF, "%s\n", cmd1);
	video_dprintf(VIDEO_LOG_INF, "%s\n", cmd2);
	video_dprintf(VIDEO_LOG_INF, "%s\n", cmd3);

	video_dprintf(VIDEO_LOG_INF, "hal_video_str2cmd\r\n");
	//string to command
	if (hal_video_str2cmd(cmd1, cmd2, cmd3) == NOK) {
		video_dprintf(VIDEO_LOG_ERR, "hal_video_str2cmd fail\n");
		return NULL;
	}

	hal_video_isp_set_sensor_gpio(ch, g_video_peri_info.rst_pin, g_video_peri_info.pwdn_pin, g_video_peri_info.pwr_ctrl_pin);
	hal_video_isp_set_i2c_id(ch, g_video_peri_info.i2c_id);

	video_dprintf(VIDEO_LOG_INF, "set video callback\r\n");
	if (output_cb != NULL) {
		if (hal_video_out_cb(output_cb, 1024, (uint32_t)ctx, ch) != OK) {
			video_dprintf(VIDEO_LOG_ERR, "hal_video_cb_register fail\n");
		}
	} else {
		if (hal_video_out_cb(temp_output_cb, 1024, (uint32_t)ctx, ch) != OK) {
			video_dprintf(VIDEO_LOG_ERR, "hal_video_cb_register fail\n");
		}
	}

	video_dprintf(VIDEO_LOG_INF, "hal_video_isp_buf_num\r\n");
	hal_video_isp_buf_num(ch, isp_ch_buf_num[ch]);

	if (codec & (CODEC_HEVC | CODEC_H264)) {
		hal_video_enc_buf(ch, out_buf_size, out_rsvd_size);
	} else if (codec & CODEC_JPEG) {
		hal_video_jpg_buf(ch, jpeg_out_buf_size, out_rsvd_size);
	}

	hal_video_adapter_t *v_adp = hal_video_get_adp();
	/* Encoder initialization */
	if (v_adp) {
		if (isp_info.osd_enable) {
			v_adp->cmd[ch]->osd	= 1;
		}
	}

	if (v_stream->use_roi == 1) {
		video_dprintf(VIDEO_LOG_INF, "set v%d roi \r\n", ch);
		hal_video_isp_set_roi(ch, v_stream->roi.xmin, v_stream->roi.ymin, v_stream->roi.xmax - v_stream->roi.xmin, v_stream->roi.ymax - v_stream->roi.ymin);
	}

	video_dprintf(VIDEO_LOG_INF, "hal_video_open\r\n");
	if (hal_video_open(ch) != OK) {
		video_dprintf(VIDEO_LOG_ERR, "hal_video_open fail\n");
		return -1;
	}

	if (voe_info_init == 0) {
		memset(voe_info.stream_is_open, 0, sizeof(uint32_t)*MAX_CHANNEL);
		voe_info_init = 1;
	}
	voe_info.stream_is_open[ch] = 1;

	return OK;
}



int video_close(int ch)
{
	voe_info.stream_is_open[ch] = 0;
	video_dprintf(VIDEO_LOG_INF, "hal_video_close\r\n");
	if (hal_video_close(ch) != OK) {
		video_dprintf(VIDEO_LOG_ERR, "hal_video_close fail\n");
		return NULL;
	}

	osDelay(10); 				// To idle task clean task usage memory

	return OK;
}

int video_get_stream_info(int id)
{
	return voe_info.stream_is_open[id];
}

hal_video_adapter_t *video_init(int iq_start_addr, int sensor_start_addr)
{
	// HW enable & allocation adapter memory
	int res = 0;

	if (hal_voe_ready() != OK) {
		extern int __voe_code_start__[];
		if (!hal_voe_fcs_check_OK()) {
			unsigned char *iq_addr = NULL;
			unsigned char *sensor_addr = NULL;
			iq_addr = video_load_iq(iq_start_addr);
			sensor_addr = video_load_sensor(sensor_start_addr);
			video_dprintf(VIDEO_LOG_MSG, "iq timestamp: %04d/%02d/%02d %02d:%02d:%02d\r\n", *(unsigned short *)(iq_addr + 12), iq_addr[14], iq_addr[15], iq_addr[16],
						  iq_addr[17], *(unsigned short *)(iq_addr + 18));
			hal_video_load_iq((voe_cpy_t)hal_voe_cpy, iq_addr, __voe_code_start__);
			hal_video_load_sensor((voe_cpy_t)hal_voe_cpy, sensor_addr, __voe_code_start__);
		}

		if (voe_fw_reload == 1) {
			video_load_fw(isp_boot->fcs_voe_fw_addr);
			voe_fw_reload = 0;
		}

		video_init_peri();

		voe_info.voe_heap_addr = malloc(voe_info.voe_heap_size);
		dcache_clean_invalidate_by_addr((uint32_t *)voe_info.voe_heap_addr, voe_info.voe_heap_size);
		res = hal_video_init(voe_info.voe_heap_addr, voe_info.voe_heap_size);
		if (res != OK) {
			video_dprintf(VIDEO_LOG_ERR, "hal_video_init fail\n");
			return NULL;
		}

		video_dprintf(VIDEO_LOG_INF, "!hal_voe_ready\r\n");

	}
	if (isp_boot->fcs_status == 1 && isp_boot->fcs_setting_done == 0) {
		voe_info.voe_heap_addr = isp_boot->voe_heap_addr;
		voe_info.voe_heap_size = isp_boot->voe_heap_size;
		video_dprintf(VIDEO_LOG_INF, "voe_info.voe_heap_addr %x voe_info.voe_heap_size %x\r\n", voe_info.voe_heap_addr, voe_info.voe_heap_size);
	}

	hal_video_adapter_t *v_adp = hal_video_get_adp();

	return 	v_adp;
}

void *video_deinit(void)
{
	if (hal_voe_ready() == OK) {
		if ((voe_info.voe_heap_addr) != NULL) {
			free(voe_info.voe_heap_addr);
		}

		video_deinit_peri();

		video_dprintf(VIDEO_LOG_INF, "video_deinit\r\n");
		hal_video_deinit();

		rtw_mdelay_os(50);
		voe_fw_reload = 1;
	}

	return NULL;
}


//////////////////////////////////////////////
void voe_set_iq_sensor_fw(int id)
{
	extern int __voe_code_start__[];
	unsigned int p_fcs_data, p_iq_data, p_sensor_data = 0;
	p_fcs_data    = (uint8_t *)(isp_boot->p_fcs_ld_info.fcs_hdr_start + (isp_boot->p_fcs_ld_info.sensor_set[id].fcs_data_offset));
	p_iq_data     = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[id].iq_start_addr));
	p_sensor_data = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[id].sensor_start_addr));
	video_dprintf(VIDEO_LOG_INF, "ch %d p_fcs_data %x p_sensor_data %x\r\n", id, p_iq_data, p_sensor_data);

	unsigned char *iq_addr = NULL;
	unsigned char *sensor_addr = NULL;
	iq_addr = video_load_iq(p_iq_data);
	sensor_addr = video_load_sensor(p_sensor_data);
	if (iq_addr == NULL || sensor_addr == NULL) {
		video_dprintf(VIDEO_LOG_ERR, "It can't allocate the buffer\r\n");
		return NULL;
	}
	video_dprintf(VIDEO_LOG_MSG, "iq timestamp: %04d/%02d/%02d %02d:%02d:%02d\r\n", *(unsigned short *)(iq_addr + 12), iq_addr[14], iq_addr[15], iq_addr[16],
				  iq_addr[17], *(unsigned short *)(iq_addr + 18));
	hal_video_load_iq((voe_cpy_t)hal_voe_cpy, iq_addr, __voe_code_start__);
	hal_video_load_sensor((voe_cpy_t)hal_voe_cpy, sensor_addr, __voe_code_start__);
}

int voe_get_sensor_info(int id, int *iq_data, int *sensor_data)
{
	int ret = 0;
	unsigned int p_fcs_data, p_iq_data, p_sensor_data = 0;
	if (id >= isp_boot->p_fcs_ld_info.multi_fcs_cnt) {
		ret = -1;
		video_dprintf(VIDEO_LOG_ERR, "sensor id is bigger than isp_boot->p_fcs_ld_info.multi_fcs_cnt\r\n");
	} else {
		p_fcs_data    = (uint8_t *)(isp_boot->p_fcs_ld_info.fcs_hdr_start + (isp_boot->p_fcs_ld_info.sensor_set[id].fcs_data_offset));
		p_iq_data     = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[id].iq_start_addr));
		p_sensor_data = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[id].sensor_start_addr));
		video_dprintf(VIDEO_LOG_INF, "ch %d p_fcs_data %x p_sensor_data %x\r\n", id, p_iq_data, p_sensor_data);
		*iq_data = p_iq_data;
		*sensor_data = p_sensor_data;
	}
	return ret;
}

void voe_dump_isp_info(void)
{
	//video_boot_stream_t *isp_boot = (video_boot_stream_t *)bl4voe_shared.data;
	int i = 0;
	unsigned int p_fcs_data, p_iq_data, p_sensor_data = 0;
	video_dprintf(VIDEO_LOG_INF, "isp_boot->fcs_voe_fw_addr %x\r\n", isp_boot->fcs_voe_fw_addr);
	video_dprintf(VIDEO_LOG_INF, "fcs_id %d\r\n", isp_boot->p_fcs_ld_info.fcs_id);
	video_dprintf(VIDEO_LOG_INF, "multi_fcs_cnt %d\r\n", isp_boot->p_fcs_ld_info.multi_fcs_cnt);
	video_dprintf(VIDEO_LOG_INF, "magic %x\r\n", isp_boot->p_fcs_ld_info.magic);
	video_dprintf(VIDEO_LOG_INF, "version %d\r\n", isp_boot->p_fcs_ld_info.version);
	video_dprintf(VIDEO_LOG_INF, "wait_km_init_timeout_us %d\r\n", isp_boot->p_fcs_ld_info.wait_km_init_timeout_us);
	video_dprintf(VIDEO_LOG_INF, "fcs_hdr_start %x\r\n", isp_boot->p_fcs_ld_info.fcs_hdr_start);
	for (i = 0; i < isp_boot->p_fcs_ld_info.multi_fcs_cnt; i++) {
		video_dprintf(VIDEO_LOG_INF, "sesnor %d fcs_data_size %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].fcs_data_size);
		video_dprintf(VIDEO_LOG_INF, "sesnor %d fcs_data_offset %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].fcs_data_offset);
		video_dprintf(VIDEO_LOG_INF, "sesnor %d iq_start_addr %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].iq_start_addr);
		video_dprintf(VIDEO_LOG_INF, "sesnor %d iq_data_size %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].iq_data_size);
		video_dprintf(VIDEO_LOG_INF, "sesnor %d sensor_start_addr %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].sensor_start_addr);
		video_dprintf(VIDEO_LOG_INF, "sesnor %d sensor_data_size %x\r\n", i, isp_boot->p_fcs_ld_info.sensor_set[i].sensor_data_size);
		p_fcs_data    = (uint8_t *)(isp_boot->p_fcs_ld_info.fcs_hdr_start + (isp_boot->p_fcs_ld_info.sensor_set[i].fcs_data_offset));
		p_iq_data     = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[i].iq_start_addr));
		p_sensor_data = (uint8_t *)(p_fcs_data + (isp_boot->p_fcs_ld_info.sensor_set[i].sensor_start_addr));
		video_dprintf(VIDEO_LOG_INF, "sensor %d p_fcs_data %x p_iq_data %x p_sensor_data %x\r\n", i, p_fcs_data, p_iq_data, p_sensor_data);
	}
	video_dprintf(VIDEO_LOG_INF, "isp_boot->fcs_voe_fw_addr %x\r\n", isp_boot->fcs_voe_fw_addr);
}

void voe_t2ff_prealloc(void)
{
	//video_boot_stream_t *isp_boot = (video_boot_stream_t *)bl4voe_shared.data;
	unsigned char *ptr = NULL;
	if (isp_boot->fcs_status) {
		//printf("isp_boot %d %d %d\r\n",isp_boot->video_params[0].width,isp_boot->video_params[0].height,isp_boot->fcs_status);
		video_dprintf(VIDEO_LOG_INF, "heap addr %x heap size %x\r\n", isp_boot->voe_heap_addr, isp_boot->voe_heap_size);
		if (isp_boot->voe_heap_size > (__eram_end__ - __eram_heap_start__)) {
			video_dprintf(VIDEO_LOG_ERR, "The voe buffer is not enough\r\n");
			while (1);
		} else {
			ptr = (char *) pvPortInsertPreAlloc((void *)isp_boot->voe_heap_addr, isp_boot->voe_heap_size);
			if (ptr == NULL) {
				video_dprintf(VIDEO_LOG_ERR, "It can't be allocate buffer\r\n");
				while (1);
			}
		}
	}
	//voe_dump_isp_info();
}

int voe_boot_fsc_status(void)// 1 : Inited 0: Non-Inited
{
	video_dprintf(VIDEO_LOG_INF, "isp_boot->fcs_status %d\r\n", isp_boot->fcs_status);
	return isp_boot->fcs_status;
}

int voe_boot_fsc_id(void)//
{
	video_dprintf(VIDEO_LOG_INF, "isp_boot->fcs_id %d\r\n", isp_boot->p_fcs_ld_info.fcs_id);
	return isp_boot->p_fcs_ld_info.fcs_id;
}

uint8_t isp_i2c_read_byte(int addr)
{
	struct rts_isp_i2c_reg reg;
	int ret = 0;
	reg.addr = addr;
	reg.data = 0;
	ret = hal_video_i2c_read(&reg);
	return reg.data;
}

void video_set_fcs_id(int SensorName)
{
	unsigned int crc32_result[10] = {0xd202ef8d, 0xa505df1b, 0x3c0c8ea1, 0x4b0bbe37, 0xd56f2b94, 0xa2681b02, 0x3b614ab8, 0x4c667a2e, 0xdcd967bf, 0xabde5729};
	pfw_init();

	void *fp = pfw_open_by_typeid(0x89CE, M_MANI_UNPT);

	uint8_t *ref = malloc(32);
	uint8_t *tmp = malloc(32);
	if (ref == NULL || tmp == NULL) {
		video_dprintf(VIDEO_LOG_ERR, "It can't get the memory\r\n");
		while (1);
	}
	pfw_read_unpt(fp, ref, 12);

	ref[4] = SensorName;
	*(uint32_t *)&ref[8] = crc32_result[ref[4]];

	pfw_write_unpt(fp, ref, 12);

	pfw_read_unpt(fp, tmp, 12);

	pfw_close(fp);
	if (ref) {
		free(ref);
	}
	if (tmp) {
		free(tmp);
	}
}

int video_fcs_write_sensor_id(int SensorName)
{
	if (isp_boot->p_fcs_ld_info.fcs_id == 0) {
		return -1;
	} else {
		if (SensorName != isp_boot->p_fcs_ld_info.fcs_id) {
			video_set_fcs_id(SensorName);
		}
		return 0;
	}
}

void video_get_video_snesor_info(mult_sensor_info_t *info)
{
	info->sensor_index = multi_sensor_info.sensor_index;
	info->sensor_finish =  multi_sensor_info.sensor_finish;
}

void video_set_video_snesor_info(mult_sensor_info_t *info)
{
	multi_sensor_info.sensor_index = info->sensor_index;
	multi_sensor_info.sensor_finish = info->sensor_finish;
}

int video_get_video_sensor_status(void)
{
	return multi_sensor_info.sensor_finish;
}

int video_get_video_sensor_index(void)
{
	return multi_sensor_info.sensor_index;
}

int video_load(int sensor_index)
{


	if (!hal_voe_fcs_check_OK()) {
		// Enable ISP PWR
		hal_gpio_init(&sensor_en_gpio, PIN_A5);
		hal_gpio_set_dir(&sensor_en_gpio, GPIO_OUT);
		hal_gpio_write(&sensor_en_gpio, 1);
	}
	video_dprintf(VIDEO_LOG_INF, "sensor_index %d\r\n", sensor_index);
	voe_set_iq_sensor_fw(sensor_index);
	// extern int _binary_voe_bin_start[];			// VOE binary address
	// extern int __voe_code_start__[];
	// int *voe_bin_addr = (int *)isp_boot->fcs_voe_fw_addr;
	video_load_fw(isp_boot->fcs_voe_fw_addr);
	//hal_video_load_fw((voe_cpy_t)hal_voe_cpy, _binary_voe_bin_start, __voe_code_start__);
	video_dprintf(VIDEO_LOG_INF, "voe_info.voe_heap_addr %x voe_heap_size %x\r\n", voe_info.voe_heap_addr, voe_info.voe_heap_size);
	if (hal_video_init(voe_info.voe_heap_addr, voe_info.voe_heap_size) != OK) {
		video_dprintf(VIDEO_LOG_ERR, "hal_video_init fail\n");
		return -1;
	}

	return OK;
}

void *video_fw_deinit(void)
{
	if (hal_voe_ready() == OK) {
		video_dprintf(VIDEO_LOG_INF, "video_deinit\r\n");
		hal_gpio_write(&sensor_en_gpio, 0);
		hal_video_deinit();
		// Disable ISP PWR
		//hal_gpio_write(&sensor_en_gpio, 0);
		hal_gpio_deinit(&sensor_en_gpio);
		rtw_mdelay_os(50);
	}
	return NULL;
}

int video_reset_fw(int ch, int id)
{
	int ret = 0;
	video_close(ch);
	video_fw_deinit();
	video_load(id);
	return ret;
}

unsigned char *video_load_iq(unsigned int iq_start_addr)
{
	int offset = 0;
	void *fp = NULL;
	unsigned int iq_full_size;

	fp = pfw_open("ISP_IQ", 0);
	if (!fp) {
		video_dprintf(VIDEO_LOG_ERR, "It cannot open file ISP_IQ\n\r");
		goto EXIT;
	}
	if (sys_get_boot_sel() == 0) { // NOR
		offset = (u32)iq_start_addr - isp_boot->p_fcs_ld_info.fcs_hdr_start;
	} else if (sys_get_boot_sel() == 1) { // NAND
		offset = (u32)iq_start_addr - VOE_NAND_FLASH_OFFSET;
	}

	iq_full_size = 65536;//default iq size
	pfw_seek(fp, offset, SEEK_SET);
	pfw_read(fp, iq_buf, iq_full_size);
	pfw_close(fp);
	return iq_buf;
EXIT:
	if (fp) {
		pfw_close(fp);
	}
	return NULL;
}

unsigned char *video_load_sensor(unsigned int sensor_start_addr)
{
	int offset = 0;
	void *fp = NULL;
	unsigned int sensor_size;

	fp = pfw_open("ISP_IQ", 0);
	if (!fp) {
		video_dprintf(VIDEO_LOG_ERR, "It cannot open file ISP_IQ\n\r");
		goto EXIT;
	}
	if (sys_get_boot_sel() == 0) { // NOR
		offset = (u32)sensor_start_addr - isp_boot->p_fcs_ld_info.fcs_hdr_start;
	} else if (sys_get_boot_sel() == 1) { // NAND
		offset = (u32)sensor_start_addr - VOE_NAND_FLASH_OFFSET;
	}
	sensor_size = 4096;//Default size for sensor fw
	pfw_seek(fp, offset, SEEK_SET);
	pfw_read(fp, sensor_buf, sensor_size);
	pfw_close(fp);
	return sensor_buf;
EXIT:
	if (fp) {
		pfw_close(fp);
	}
	return NULL;
}

int video_load_fw(unsigned int sensor_start_addr)
{
	int offset = 0;
	unsigned int fw_size = 0;
	void *fp = NULL;
	if (hal_sys_get_ld_fw_idx() == FW_1) {
		fp = pfw_open("FW1", 0);
		if (!fp) {
			video_dprintf(VIDEO_LOG_ERR, "cannot open file FW1\n\r");
			return -1;
		}
	} else if (hal_sys_get_ld_fw_idx() == FW_2) {
		fp = pfw_open("FW2", 0);
		if (!fp) {
			video_dprintf(VIDEO_LOG_ERR, "cannot open file FW2\n\r");
			return -1;
		}
	} else {
		return -1;
	}
	if (sys_get_boot_sel() == 0) { // NOR;
		offset = (u32)sensor_start_addr - hal_sys_get_ld_fw_img_dev_nor_offset() - 0x1080;
	} else if (sys_get_boot_sel() == 1) { // NAND
		offset = (u32)sensor_start_addr - VOE_NAND_FLASH_OFFSET;
	}
	fw_size = 600 * 1024; //Default voe fw size
	unsigned char *buf = malloc(fw_size);
	if (buf == NULL) {
		video_dprintf(VIDEO_LOG_ERR, "It don't the enough memory %s\r\n", __FUNCTION__);
		return -1;
	}
	pfw_seek(fp, offset, SEEK_SET);
	pfw_read(fp, buf, fw_size);
	pfw_close(fp);
	dcache_clean_invalidate_by_addr((uint32_t *)buf, (int32_t)fw_size);
	hal_video_load_fw((voe_cpy_t)hal_voe_cpy, buf, __voe_code_start__);
	if (buf) {
		free(buf);
	}
	return 0;
}

void video_get_fcs_info(video_boot_stream_t **isp_fcs_info)
{
	*isp_fcs_info = isp_boot;
}
