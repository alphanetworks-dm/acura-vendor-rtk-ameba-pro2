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
#include "video_snapshot.h"
/*****************************************************************************
* ISP channel : 0
* Video type  : H264/HEVC + SNAPSHOT
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
#define SHAPSHOT_TYPE VIDEO_HEVC_JPEG
#else
#include "sample_h264.h"
#define VIDEO_TYPE VIDEO_H264
#define VIDEO_CODEC AV_CODEC_ID_H264
#define SHAPSHOT_TYPE VIDEO_H264_JPEG
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

//#define ENABLE_META_INFO  //Enable the marco to wirte the META data to frame
//#define ENABLE_SD_SNAPSHOT //Enable the snapshot to sd card
static void atcmd_userctrl_init(void);
static mm_context_t *video_v1_ctx			= NULL;
static mm_context_t *rtsp2_v1_ctx			= NULL;
static mm_siso_t *siso_video_rtsp_v1			= NULL;

static video_params_t video_v1_params = {
	.stream_id = V1_CHANNEL,
	.type = SHAPSHOT_TYPE,
	.resolution = V1_RESOLUTION,
	.width = V1_WIDTH,
	.height = V1_HEIGHT,
	.bps = V1_BPS,
	.fps = V1_FPS,
	.gop = V1_GOP,
	.rc_mode = V1_RCMODE,
	.use_static_addr = 1,
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

TaskHandle_t snapshot_thread = NULL;

int v1_snapshot_cb(uint32_t jpeg_addr, uint32_t jpeg_len)
{
	printf("snapshot size=%d\n\r", jpeg_len);
	return 0;
}
#if defined(ENABLE_META_INFO)
static void video_meta_cb(void *parm)
{
	video_meta_t *m_parm = (video_meta_t *)parm;
	unsigned char *ptr = (unsigned char *)m_parm->video_addr;
	if (m_parm->type == AV_CODEC_ID_MJPEG) {
		memcpy(ptr + m_parm->meta_offset + VIDEO_JPEG_META_OFFSET, m_parm->isp_meta_data, sizeof(isp_meta_t));
		memcpy(ptr + m_parm->meta_offset + VIDEO_JPEG_META_OFFSET + sizeof(isp_meta_t), m_parm->isp_statis_meta, sizeof(isp_statis_meta_t));
	} else if (m_parm->type == AV_CODEC_ID_H264) {
		memcpy(ptr + m_parm->meta_offset + VIDEO_H264_META_OFFSET, m_parm->isp_meta_data, sizeof(isp_meta_t));
		memcpy(ptr + m_parm->meta_offset + VIDEO_H264_META_OFFSET + sizeof(isp_meta_t), m_parm->isp_statis_meta, sizeof(isp_statis_meta_t));
	} else if (m_parm->type == AV_CODEC_ID_H265) {
		//printf("The type is %d\r\n",m_parm->type);
	} else {
		//printf("It don't support %d\r\n",m_parm->type);
	}
}
#endif

void snapshot_control_thread(void *param)
{
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(2048);
#endif
	while (1) {
		vTaskDelay(10000);
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SNAPSHOT, 1);
	}
}


void mmf2_video_example_v1_shapshot_init(void)
{
	atcmd_userctrl_init();
#if defined(ENABLE_META_INFO)
	video_v1_params.meta_size = sizeof(isp_meta_t) + sizeof(isp_statis_meta_t) + VIDEO_META_USER_SIZE; //It add the size of user info to video frame
#endif

	int voe_heap_size = video_voe_presetting(1, V1_WIDTH, V1_HEIGHT, V1_BPS, 1,
						0, 0, 0, 0, 0,
						0, 0, 0, 0, 0,
						0, 0, 0);

	printf("\r\n voe heap size = %d\r\n", voe_heap_size);

	video_v1_ctx = mm_module_open(&video_module);
	if (video_v1_ctx) {
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v1_params);
		mm_module_ctrl(video_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_FPS * 3);
		mm_module_ctrl(video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SNAPSHOT, 0);
	} else {
		rt_printf("video open fail\n\r");
		goto mmf2_video_exmaple_v1_shapshot_fail;
	}

	rtsp2_v1_ctx = mm_module_open(&rtsp2_module);
	if (rtsp2_v1_ctx) {
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SELECT_STREAM, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_PARAMS, (int)&rtsp2_v1_params);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_APPLY, 0);
		mm_module_ctrl(rtsp2_v1_ctx, CMD_RTSP2_SET_STREAMMING, ON);
	} else {
		rt_printf("RTSP2 open fail\n\r");
		goto mmf2_video_exmaple_v1_shapshot_fail;
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
		goto mmf2_video_exmaple_v1_shapshot_fail;
	}

	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_APPLY, V1_CHANNEL);

	//--------------snapshot setting---------------------------
#if defined(ENABLE_SD_SNAPSHOT)
	extern snapshot_user_config_t snap_config;
	memset(&snap_config, 0x00, sizeof(snap_config));
	snapshot_vfs_init();
	snap_config.video_snapshot_ctx = video_v1_ctx;
	snap_config.snapshot_write = snapshot_write_picture;
	video_snapshot_init_with_streaming(&snap_config);
	atcmd_snapshot_init();//ATCMD => SNAP=SNAPS (Take picture to sdcard)
#else
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SNAPSHOT_CB, (int)v1_snapshot_cb);

	if (xTaskCreate(snapshot_control_thread, ((const char *)"snapshot_store"), 512, NULL, tskIDLE_PRIORITY + 1, &snapshot_thread) != pdPASS) {
		printf("\n\r%s xTaskCreate failed", __FUNCTION__);
	}
#endif
#if defined(ENABLE_META_INFO)
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_META_CB, (int)video_meta_cb);
#endif

	return;
mmf2_video_exmaple_v1_shapshot_fail:

	return;
}

static const char *example = "mmf2_video_example_v1_shapshot";
static void example_deinit(void)
{
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
	} else if (!strcmp(arg, "TSS")) {
		if (!(user_cmd & USR_CMD_EXAMPLE_DEINIT)) {
			printf("snapshot %s\r\n", example);
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
			rtw_create_secure_context(2048);
#endif
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SNAPSHOT, 1);
		} else {
			printf("invalid state, can not do %s snapshot!\r\n", example);
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
