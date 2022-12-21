/******************************************************************************
*
* Copyright(c) 2007 - 2021 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "module_video.h"
#include "mmf2_pro2_video_config.h"
#include "video_example_media_framework.h"

#include "module_md.h"
#include "module_rtsp2.h"
#include "log_service.h"

#undef printf // undefine hal_vidoe.h printf 
#include <stdio.h>

/*****************************************************************************
* ISP channel : 4
* Video type  : RGB
*****************************************************************************/
#define RTSP_CHANNEL 0
#define RTSP_RESOLUTION VIDEO_FHD
#define RTSP_FPS 30
#define RTSP_GOP 30
#define RTSP_BPS 2*1024*1024
#define VIDEO_RCMODE 2 // 1: CBR, 2: VBR

#define USE_H265 0

#if USE_H265
#include "sample_h265.h"
#define RTSP_TYPE VIDEO_HEVC
#define RTSP_CODEC AV_CODEC_ID_H265
#else
#include "sample_h264.h"
#define RTSP_TYPE VIDEO_H264
#define RTSP_CODEC AV_CODEC_ID_H264
#endif

#if RTSP_RESOLUTION == VIDEO_VGA
#define RTSP_WIDTH	640
#define RTSP_HEIGHT	480
#elif RTSP_RESOLUTION == VIDEO_HD
#define RTSP_WIDTH	1280
#define RTSP_HEIGHT	720
#elif RTSP_RESOLUTION == VIDEO_FHD
#define RTSP_WIDTH	1920
#define RTSP_HEIGHT	1080
#endif

static video_params_t video_v1_params = {
	.stream_id 		= RTSP_CHANNEL,
	.type 			= RTSP_TYPE,
	.resolution 	= RTSP_RESOLUTION,
	.width 			= RTSP_WIDTH,
	.height 		= RTSP_HEIGHT,
	.bps            = RTSP_BPS,
	.fps 			= RTSP_FPS,
	.gop 			= RTSP_GOP,
	.rc_mode        = VIDEO_RCMODE,
	.use_static_addr = 1
};


static rtsp2_params_t rtsp2_v1_params = {
	.type = AVMEDIA_TYPE_VIDEO,
	.u = {
		.v = {
			.codec_id = RTSP_CODEC,
			.fps      = RTSP_FPS,
			.bps      = RTSP_BPS
		}
	}
};

#define MD_CHANNEL 4
#define MD_RESOLUTION VIDEO_VGA //VIDEO_WVGA
#define MD_FPS 10
#define MD_GOP 10
#define MD_BPS 1024*1024
#define MD_COL 16
#define MD_ROW 16

#define MD_TYPE VIDEO_RGB

#if MD_RESOLUTION == VIDEO_VGA
#define MD_WIDTH	640
#define MD_HEIGHT	480
#elif MD_RESOLUTION == VIDEO_WVGA
#define MD_WIDTH	640
#define MD_HEIGHT	360
#endif

#if USE_SENSOR == SENSOR_GC4653
#define SENSOR_MAX_WIDTH 2560
#define SENSOR_MAX_HEIGHT 1440
#elif USE_SENSOR == SENSOR_SC301
#define SENSOR_MAX_WIDTH 2048
#define SENSOR_MAX_HEIGHT 1536
#elif USE_SENSOR == SENSOR_JXF51
#define SENSOR_MAX_WIDTH 1536
#define SENSOR_MAX_HEIGHT 1536
#else
#define SENSOR_MAX_WIDTH 1920
#define SENSOR_MAX_HEIGHT 1080
#endif

static video_params_t video_v4_params = {
	.stream_id 		= MD_CHANNEL,
	.type 			= MD_TYPE,
	.resolution	 	= MD_RESOLUTION,
	.width 			= MD_WIDTH,
	.height 		= MD_HEIGHT,
	.bps 			= MD_BPS,
	.fps 			= MD_FPS,
	.gop 			= MD_GOP,
	.direct_output 	= 0,
	.use_static_addr = 1,
	.use_roi = 1,
	.roi = {
		.xmin = 0,
		.ymin = 0,
		.xmax = SENSOR_MAX_WIDTH,
		.ymax = SENSOR_MAX_HEIGHT,
	}
};

static md_param_t md_param = {
	.image_width = MD_WIDTH,
	.image_height = MD_HEIGHT,
	.md_row = MD_ROW,
	.md_col = MD_COL
};

static void atcmd_userctrl_init(void);
static mm_context_t *video_v1_ctx			= NULL;
static mm_context_t *rtsp2_v1_ctx			= NULL;
static mm_siso_t *siso_video_rtsp_v1			= NULL;

static mm_context_t *video_rgb_ctx			= NULL;
static mm_context_t *md_ctx            = NULL;
static mm_siso_t *siso_rgb_md         = NULL;

//--------------------------------------------
// Draw Rect
//--------------------------------------------
#define MD_DRAW 1

#if MD_DRAW
#include "osd_render.h"

#endif
static void md_process(void *md_result)
{

	char *md_res = (char *) md_result;
	//draw md rect
	int motion = 0, j, k;
	int jmin = MD_ROW - 1, jmax = 0;
	int kmin = MD_COL - 1, kmax = 0;
	for (j = 0; j < MD_ROW; j++) {
		for (k = 0; k < MD_COL; k++) {
			printf("%d ", md_res[j * MD_COL + k]);
			if (md_res[j * MD_COL + k]) {
				motion = 1;
				if (j < jmin) {
					jmin = j;
				}
				if (k < kmin) {
					kmin = k;
				}
				if (j > jmax) {
					jmax = j;
				}
				if (k > kmax) {
					kmax = k;
				}
			}
		}
		printf("\r\n");
	}
	printf("\r\n\r\n");
#if MD_DRAW
	//draw md region
	canvas_clean_all(RTSP_CHANNEL, 0);
	if (motion) {
		int xmin = (int)(kmin * RTSP_WIDTH / MD_COL) + 1;
		int ymin = (int)(jmin * RTSP_HEIGHT / MD_ROW) + 1;
		int xmax = (int)((kmax + 1) * RTSP_WIDTH / MD_COL) - 1;
		int ymax = (int)((jmax + 1) * RTSP_HEIGHT / MD_ROW) - 1;
		canvas_set_rect(RTSP_CHANNEL, 0, xmin, ymin, xmax, ymax, 3, COLOR_GREEN);
	}
	canvas_update(RTSP_CHANNEL, 0);
#endif
}

void mmf2_video_example_md_rtsp_init(void)
{

	int voe_heap_size = video_voe_presetting(1, RTSP_WIDTH, RTSP_HEIGHT, RTSP_BPS, 0,
						0, 0, 0, 0, 0,
						0, 0, 0, 0, 0,
						1, MD_WIDTH, MD_HEIGHT);

	printf("\r\n voe heap size = %d\r\n", voe_heap_size);

	video_v1_ctx = mm_module_open(&video_module);
	if (video_v1_ctx) {
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_VOE_HEAP, voe_heap_size);
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v1_params);
		mm_module_ctrl(video_v1_ctx, MM_CMD_SET_QUEUE_LEN, RTSP_FPS * 3);
		mm_module_ctrl(video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
	} else {
		printf("video open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}

	rtsp2_v1_ctx = mm_module_open(&rtsp2_module);
	if (rtsp2_v1_ctx) {
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SELECT_STREAM, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_PARAMS, (int)&rtsp2_v1_params);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_APPLY, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_STREAMMING, ON);
	} else {
		printf("RTSP2 open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}
	video_rgb_ctx = mm_module_open(&video_module);
	if (video_rgb_ctx) {
		//mm_module_ctrl(video_rgb_ctx, CMD_VIDEO_SET_VOE_HEAP, voe_heap_size);
		mm_module_ctrl(video_rgb_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v4_params);
		mm_module_ctrl(video_rgb_ctx, MM_CMD_SET_QUEUE_LEN, 2);
		mm_module_ctrl(video_rgb_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
	} else {
		printf("video open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}


	motion_detect_threshold_t md_thr = {
		.Tbase = 2,
		.Tlum = 3
	};
	char md_mask [MD_COL * MD_ROW] = {0};
	for (int i = 0; i < MD_COL * MD_ROW; i++) {
		md_mask[i] = 1;
	}

	md_ctx  = mm_module_open(&md_module);
	if (md_ctx) {
		mm_module_ctrl(md_ctx, CMD_MD_SET_PARAMS, (int)&md_param);
		mm_module_ctrl(md_ctx, CMD_MD_SET_MD_THRESHOLD, (int)&md_thr);
		mm_module_ctrl(md_ctx, CMD_MD_SET_MD_MASK, (int)&md_mask);
		mm_module_ctrl(md_ctx, CMD_MD_SET_DISPPOST, (int)md_process);
		//mm_module_ctrl(md_ctx, CMD_MD_GET_MD_RESULT, (int)&md_mask);
	} else {
		printf("md_ctx open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}

	//--------------Link---------------------------
	siso_video_rtsp_v1 = siso_create();
	if (siso_video_rtsp_v1) {
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_SET_SECURE_CONTEXT, 1, 0);
#endif
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_ADD_INPUT, (uint32_t)video_v1_ctx, 0);
		siso_ctrl(siso_video_rtsp_v1, MMIC_CMD_ADD_OUTPUT, (uint32_t)rtsp2_v1_ctx, 0);
		siso_start(siso_video_rtsp_v1);
	} else {
		printf("siso2 open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_APPLY, RTSP_CHANNEL);	// start channel 0

	siso_rgb_md = siso_create();
	if (siso_rgb_md) {
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
		siso_ctrl(siso_rgb_md, MMIC_CMD_SET_SECURE_CONTEXT, 1, 0);
#endif
		siso_ctrl(siso_rgb_md, MMIC_CMD_ADD_INPUT, (uint32_t)video_rgb_ctx, 0);
		siso_ctrl(siso_rgb_md, MMIC_CMD_SET_STACKSIZE, (uint32_t)1024 * 64, 0);
		//siso_ctrl(siso_rgb_md, MMIC_CMD_SET_STACKSIZE, (uint32_t)1024 * 1024, 0);
		//siso_ctrl(siso_rgb_md, MMIC_CMD_SET_TASKPRIORITY, 3, 0);
		siso_ctrl(siso_rgb_md, MMIC_CMD_ADD_OUTPUT, (uint32_t)md_ctx, 0);
		siso_start(siso_rgb_md);
	} else {
		printf("siso_rgb_md open fail\n\r");
		goto mmf2_example_md_rtsp_fail;
	}
	printf("siso_rgb_md started\n\r");
	mm_module_ctrl(video_rgb_ctx, CMD_VIDEO_APPLY, MD_CHANNEL);	// start channel 4
	mm_module_ctrl(video_rgb_ctx, CMD_VIDEO_YUV, 2);

#if MD_DRAW
	int ch_enable[3] = {1, 0, 0};
	int char_resize_w[3] = {16, 0, 0}, char_resize_h[3] = {32, 0, 0};
	int ch_width[3] = {RTSP_WIDTH, 0, 0}, ch_height[3] = {RTSP_HEIGHT, 0, 0};
	osd_render_dev_init(ch_enable, char_resize_w, char_resize_h);
	osd_render_task_start(ch_enable, ch_width, ch_height);
#endif

	atcmd_userctrl_init();
	return;
mmf2_example_md_rtsp_fail:

	return;
}

static const char *example = "mmf2_video_example_md_rtsp_init";
static void example_deinit(void)
{
	//Pause Linker
	siso_pause(siso_rgb_md);
	siso_pause(siso_video_rtsp_v1);

	//Stop module
	mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_STREAMMING, OFF);
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_STREAM_STOP, 0);
	mm_module_ctrl(video_rgb_ctx, CMD_VIDEO_STREAM_STOP, 0);

	//Delete linker
	siso_delete(siso_rgb_md);
	siso_delete(siso_video_rtsp_v1);

	//Close module
	rtsp2_v1_ctx = mm_module_close(rtsp2_v1_ctx);
	md_ctx = mm_module_close(md_ctx);
	video_rgb_ctx = mm_module_close(video_rgb_ctx);
	video_v1_ctx = mm_module_close(video_v1_ctx);

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
			printf("invalid state, can not do %s init!\r\n", example);
		}
	} else {
		printf("invalid cmd");
	}

	printf("user command 0x%x\r\n", user_cmd);
}

static log_item_t userctrl_items[] = {
	{"UC", fUC, },
};

static void atcmd_userctrl_init(void)
{
	log_service_add_table(userctrl_items, sizeof(userctrl_items) / sizeof(userctrl_items[0]));
}