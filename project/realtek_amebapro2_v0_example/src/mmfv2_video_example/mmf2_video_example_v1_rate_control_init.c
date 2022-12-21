/******************************************************************************
*
* Copyright(c) 2007 - 2021 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "module_video.h"
#include "module_rtsp2.h"
#include "mmf2_pro2_video_config.h"
#include "video_example_media_framework.h"
#include "log_service.h"
#include "wifi_structures.h"
#include "wifi_conf.h"

#define AUTO_RATE_CONTROL
#ifndef AUTO_RATE_CONTROL
#define QUEUE_LENGTH_MODE	1
#define BANDWIDTH_MODE	0
#define HIGH_THRESHOLD  8
#define LOW_THRESHOLD   2
#endif

/*****************************************************************************
* ISP channel : 0
* Video type  : H264/HEVC
*****************************************************************************/

#define V1_CHANNEL 0
#if USE_SENSOR == SENSOR_GC4653
#define V1_RESOLUTION VIDEO_2K
#define V1_FPS 15
#define V1_GOP 15
#else
#define V1_RESOLUTION VIDEO_FHD
#define V1_FPS 30
#define V1_GOP 30
#endif
#define V1_BPS 2*1024*1024
#define V1_RCMODE 2 // 1: CBR, 2: VBR

#define USE_H265 0

#if USE_H265
#include "sample_h265.h"
#define VIDEO_TYPE VIDEO_HEVC
#define VIDEO_CODEC AV_CODEC_ID_H265
#else
#include "sample_h264.h"
#define VIDEO_TYPE VIDEO_H264
#define VIDEO_CODEC AV_CODEC_ID_H264
#endif

#if V1_RESOLUTION == VIDEO_VGA
#define V1_WIDTH	640
#define V1_HEIGHT	480
#elif V1_RESOLUTION == VIDEO_HD
#define V1_WIDTH	1280
#define V1_HEIGHT	720
#elif V1_RESOLUTION == VIDEO_FHD
#define V1_WIDTH	1920
#define V1_HEIGHT	1080
#elif V1_RESOLUTION == VIDEO_2K
#define V1_WIDTH	2560
#define V1_HEIGHT	1440
#endif

static void atcmd_userctrl_init(void);
static mm_context_t *video_v1_ctx			= NULL;
static mm_context_t *rtsp2_v1_ctx			= NULL;
static mm_siso_t *siso_video_rtsp_v1			= NULL;

static video_params_t video_v1_params = {
	.stream_id = V1_CHANNEL,
	.type = VIDEO_TYPE,
	.resolution = V1_RESOLUTION,
	.width = V1_WIDTH,
	.height = V1_HEIGHT,
	.bps = V1_BPS,
	.fps = V1_FPS,
	.gop = V1_GOP,
	.rc_mode = V1_RCMODE,
	.use_static_addr = 1
};


static rtsp2_params_t rtsp2_v1_params = {
	.type = AVMEDIA_TYPE_VIDEO,
	.u = {
		.v = {
			.codec_id = VIDEO_CODEC,
			.fps      = V1_FPS,
			.bps      = V1_BPS
		}
	}
};

#ifdef AUTO_RATE_CONTROL
static rate_ctrl_t rate_ctrl_v1_params = {
	.sampling_time = V1_GOP,
	.maximun_bitrate = V1_BPS * 1.2,
	.target_bitrate = V1_BPS
};
#else
static struct user_bitrate_control {
	uint32_t enable;
	uint32_t cur_bps;
	uint32_t remain_queue_length;
	uint32_t bandwidth_level;
	uint32_t cur_maxqp;
	uint32_t ori_maxqp;
	uint32_t switch_flag;
	struct bitrate_ctrl_params {
		uint32_t bw_level_h;
		uint32_t bw_level_l;
		uint32_t ql_threshold;
		uint32_t qp_scale;
		uint32_t max_bitrate;
		uint32_t min_bitrate;
		uint32_t max_framerate;
		uint32_t min_framerate;
	} bpsc_params;
} user_bps_ctrl;

static uint32_t mgn_dr_table[8] = {
	6656, 13312, 19968, 26624, 39936, 53248, 59904, 66560
};

static TaskHandle_t bitrate_control_handler = NULL;
extern int wifi_get_sta_max_data_rate(OUT unsigned char *inidata_rate);

static void bitrate_control_task(void *param)
{
	user_bps_ctrl.switch_flag = 1;
	//set parameters
	user_bps_ctrl.bpsc_params.bw_level_h = HIGH_THRESHOLD;
	user_bps_ctrl.bpsc_params.bw_level_l = LOW_THRESHOLD;
	user_bps_ctrl.bpsc_params.ql_threshold = V1_FPS * 3 / 2;
	user_bps_ctrl.bpsc_params.qp_scale = 3;
	user_bps_ctrl.bpsc_params.max_bitrate = V1_BPS;
	user_bps_ctrl.bpsc_params.min_bitrate = V1_BPS / 2;
	user_bps_ctrl.bpsc_params.max_framerate = V1_FPS;
	user_bps_ctrl.bpsc_params.min_framerate = V1_FPS / 2;
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_GET_MAX_QP, (int)&user_bps_ctrl.ori_maxqp);
	vTaskDelay(2000);
	while (user_bps_ctrl.enable) {
		//queue length mode with max qp adjustment
#if	QUEUE_LENGTH_MODE
		//get remain queue length
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_GET_REMAIN_QUEUE_LENGTH, (int)&user_bps_ctrl.remain_queue_length);
		if (user_bps_ctrl.remain_queue_length < user_bps_ctrl.bpsc_params.ql_threshold) {
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_GET_MAX_QP, (int)&user_bps_ctrl.cur_maxqp);
			if (user_bps_ctrl.cur_maxqp < 51) {
				if ((user_bps_ctrl.cur_maxqp + user_bps_ctrl.bpsc_params.qp_scale) <= 51) {
					user_bps_ctrl.cur_maxqp += user_bps_ctrl.bpsc_params.qp_scale;
				} else {
					user_bps_ctrl.cur_maxqp = 51;
				}
				mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_MAX_QP, (int)&user_bps_ctrl.cur_maxqp);
			}
		} else {
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_GET_MAX_QP, (int)&user_bps_ctrl.cur_maxqp);
			if (user_bps_ctrl.cur_maxqp > user_bps_ctrl.ori_maxqp) {
				if ((user_bps_ctrl.cur_maxqp - user_bps_ctrl.bpsc_params.qp_scale) >= user_bps_ctrl.ori_maxqp) {
					user_bps_ctrl.cur_maxqp -= user_bps_ctrl.bpsc_params.qp_scale;
				} else {
					user_bps_ctrl.cur_maxqp = user_bps_ctrl.ori_maxqp;
				}
				mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_MAX_QP, (int)&user_bps_ctrl.cur_maxqp);
			}
		}
		//bandwidth mode with adjustment fps and bps
#elif BANDWIDTH_MODE
		//count bandwidth
		rtw_phy_statistics_t phy_statistics;
		wifi_fetch_phy_statistic(&phy_statistics);
		uint32_t curr_dr = mgn_dr_table[0];
		uint32_t rate = 0;
		wifi_get_sta_max_data_rate((unsigned char *)&rate);
		if (rate > 127 && rate < 136) {
			curr_dr = mgn_dr_table[rate - 128] * 1024;
		} else {
			continue;
		}
		user_bps_ctrl.bandwidth_level = ((curr_dr / 2) * (100 - (40 + phy_statistics.rssi)) / 100) / (V1_BPS * 3);

		if (user_bps_ctrl.bandwidth_level < user_bps_ctrl.bpsc_params.bw_level_l && user_bps_ctrl.switch_flag == 1) {
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_BPS, (int)user_bps_ctrl.bpsc_params.min_bitrate);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_FPS, (int)user_bps_ctrl.bpsc_params.min_framerate);
			printf("\r\n***set min br %ld set fps %d\r\n", user_bps_ctrl.bpsc_params.min_bitrate, user_bps_ctrl.bpsc_params.min_framerate);
			user_bps_ctrl.switch_flag ^= 1;
		} else if (user_bps_ctrl.bandwidth_level > user_bps_ctrl.bpsc_params.bw_level_h && user_bps_ctrl.switch_flag == 0) {
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_BPS, (int)user_bps_ctrl.bpsc_params.max_bitrate);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_FPS, (int)user_bps_ctrl.bpsc_params.max_framerate);
			printf("\r\n***set max br %ld set fps %d\r\n", user_bps_ctrl.bpsc_params.max_bitrate, user_bps_ctrl.bpsc_params.max_framerate);
			user_bps_ctrl.switch_flag ^= 1;
		}
#endif

		vTaskDelay(1000);
		//get current bitrate
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_GET_CURRENT_BITRATE, (int)&user_bps_ctrl.cur_bps);
		printf("\r\ncurrent bitrate = %ld\r\n", user_bps_ctrl.cur_bps);
	};
	vTaskDelete(NULL);
}
#endif

void mmf2_video_example_v1_rate_control_init(void)
{
	atcmd_userctrl_init();

	int voe_heap_size = video_voe_presetting(1, V1_WIDTH, V1_HEIGHT, V1_BPS, 0,
						0, 0, 0, 0, 0,
						0, 0, 0, 0, 0,
						0, 0, 0);

	printf("\r\n voe heap size = %d\r\n", voe_heap_size);
	video_v1_ctx = mm_module_open(&video_module);
	if (video_v1_ctx) {
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v1_params);
		mm_module_ctrl(video_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_FPS * 3);
		mm_module_ctrl(video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
	} else {
		rt_printf("video open fail\n\r");
		goto mmf2_video_exmaple_v1_fail;
	}

	rtsp2_v1_ctx = mm_module_open(&rtsp2_module);
	if (rtsp2_v1_ctx) {
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SELECT_STREAM, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_PARAMS, (int)&rtsp2_v1_params);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_APPLY, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_STREAMMING, ON);
	} else {
		rt_printf("RTSP2 open fail\n\r");
		goto mmf2_video_exmaple_v1_fail;
	}

	siso_video_rtsp_v1 = siso_create();
	if (siso_video_rtsp_v1) {
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_SET_SECURE_CONTEXT, 1, 0);
#endif
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_ADD_INPUT, (uint32_t)video_v1_ctx, 0);
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_ADD_OUTPUT, (uint32_t)rtsp2_v1_ctx, 0);
		siso_start(siso_video_rtsp_v1);
	} else {
		rt_printf("siso2 open fail\n\r");
		goto mmf2_video_exmaple_v1_fail;
	}

	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_APPLY, V1_CHANNEL);	// start channel 0
#ifdef AUTO_RATE_CONTROL
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_RATE_CONTROL, (int)&rate_ctrl_v1_params);
#else
	user_bps_ctrl.enable = 1;
	/*user can start their own task here*/
	if (xTaskCreate(bitrate_control_task, ((const char *)"bps_ctrl_example"), 1024, NULL, tskIDLE_PRIORITY + 1, &bitrate_control_handler) != pdPASS) {
		printf("\r\n video_example_main: Create Task Error\n");
	}
#endif

	return;
mmf2_video_exmaple_v1_fail:

	return;
}

static const char *example = "mmf2_video_example_v1_rate_control_init";
static void example_deinit(void)
{
#ifndef AUTO_RATE_CONTROL
	if (user_bps_ctrl.enable) {
		user_bps_ctrl.enable = 0;
		vTaskDelete(bitrate_control_handler);
	}
#endif
	//Pause Linker
	siso_pause(siso_video_rtsp_v1);

	//Stop module
	mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_STREAMMING, OFF);
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_STREAM_STOP, V1_CHANNEL);

	//Delete linker
	siso_delete(siso_video_rtsp_v1);

	//Close module
	mm_module_close(rtsp2_v1_ctx);
	mm_module_close(video_v1_ctx);

	//Video Deinit
	video_deinit();
}

static void fUC(void *arg)
{
	static uint32_t user_cmd = 0;

	if (!strcmp(arg, "TD")) {
		if (user_cmd & USR_CMD_EXAMPLE_DEINIT) {
			printf("invalid state, can not do %s deinit!\r\n", example);
		} else {
			example_deinit();
			user_cmd = USR_CMD_EXAMPLE_DEINIT;
			printf("deinit %s\r\n", example);
		}
	} else if (!strcmp(arg, "TSR")) {
		if (user_cmd & USR_CMD_EXAMPLE_DEINIT) {
			printf("reinit %s\r\n", example);
			sys_reset();
		} else {
			printf("invalid state, can not do %s reinit!\r\n", example);
		}
	} else {
		printf("invalid cmd");
	}

	printf("user command 0x%lx\r\n", user_cmd);
}

static log_item_t userctrl_items[] = {
	{"UC", fUC, },
};

static void atcmd_userctrl_init(void)
{
	log_service_add_table(userctrl_items, sizeof(userctrl_items) / sizeof(userctrl_items[0]));
}
