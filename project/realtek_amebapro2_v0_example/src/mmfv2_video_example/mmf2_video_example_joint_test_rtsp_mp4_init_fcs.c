/******************************************************************************
*
* Copyright(c) 2007 - 2021 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "mmf2_mimo.h"

#include "module_video.h"
#include "module_rtsp2.h"
#include "module_audio.h"
#include "module_aac.h"
#include "module_aad.h"
#include "module_rtp.h"
#include "module_mp4.h"
#include "mmf2_pro2_video_config.h"
#include "video_example_media_framework.h"
#include "log_service.h"
#include "fwfs.h"

/*****************************************************************************
* ISP channel : 0,1
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

#define V2_CHANNEL 1
#define V2_RESOLUTION VIDEO_HD
#if USE_SENSOR == SENSOR_GC4653
#define V2_FPS 15
#define V2_GOP 15
#else
#define V2_FPS 30
#define V2_GOP 30
#endif
#define V2_BPS 1024*1024
#define V2_RCMODE 2 // 1: CBR, 2: VBR

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

#if V2_RESOLUTION == VIDEO_VGA
#define V2_WIDTH	640
#define V2_HEIGHT	480
#elif V2_RESOLUTION == VIDEO_HD
#define V2_WIDTH	1280
#define V2_HEIGHT	720
#elif V2_RESOLUTION == VIDEO_FHD
#define V2_WIDTH	1920
#define V2_HEIGHT	1080
#endif

static void atcmd_userctrl_init(void);
static void atcmd_fcs_init(void);
static mm_context_t *video_v1_ctx			= NULL;
static mm_context_t *video_v2_ctx			= NULL;
static mm_context_t *rtsp2_v2_ctx			= NULL;
static mm_context_t *audio_ctx				= NULL;
static mm_context_t *aac_ctx				= NULL;
static mm_context_t *rtp_ctx				= NULL;
static mm_context_t *aad_ctx				= NULL;
static mm_context_t *mp4_ctx				= NULL;


static mm_siso_t *siso_audio_aac			= NULL;
static mm_mimo_t *mimo_2v_1a_rtsp_mp4		= NULL;
static mm_siso_t *siso_rtp_aad				= NULL;
static mm_siso_t *siso_aad_audio			= NULL;

#include "video_boot.h"
#include "ftl_common_api.h"

#if USE_SENSOR == SENSOR_GC4653
#define USE_2K_SENSOR
#endif

//#define FCS_PARTITION //Use the FCS data to change the parameter from bootloader.If mark the marco, it will use the FTL config.

static video_boot_stream_t video_boot_stream = {
	.video_params[STREAM_V1].stream_id = STREAM_V1,
	.video_params[STREAM_V1].type = CODEC_H264,
	.video_params[STREAM_V1].resolution = 0,
#ifdef USE_2K_SENSOR
	.video_params[STREAM_V1].width = 2560,
	.video_params[STREAM_V1].height = 1440,
#else
	.video_params[STREAM_V1].width = 1920,
	.video_params[STREAM_V1].height = 1080,
#endif
	.video_params[STREAM_V1].bps = 2 * 1024 * 1024,
	.video_params[STREAM_V1].fps = 15,
	.video_params[STREAM_V1].gop = 15,
	.video_params[STREAM_V1].rc_mode = 2,
	.video_params[STREAM_V1].jpeg_qlevel = 0,
	.video_params[STREAM_V1].rotation = 0,
	.video_params[STREAM_V1].out_buf_size = V1_ENC_BUF_SIZE,
	.video_params[STREAM_V1].out_rsvd_size = 0,
	.video_params[STREAM_V1].direct_output = 0,
	.video_params[STREAM_V1].use_static_addr = 0,
	.video_snapshot[STREAM_V1] = 0,
	.video_drop_frame[STREAM_V1] = 0,
	.video_params[STREAM_V1].fcs = 1,//Enable the fcs for channel 1
	.video_params[STREAM_V2].stream_id = STREAM_V2,
	.video_params[STREAM_V2].type = CODEC_H264,
	.video_params[STREAM_V2].resolution = 0,
	.video_params[STREAM_V2].width = 1280,
	.video_params[STREAM_V2].height = 720,
	.video_params[STREAM_V2].bps = 1 * 1024 * 1024,
	.video_params[STREAM_V2].fps = 15,
	.video_params[STREAM_V2].gop = 15,
	.video_params[STREAM_V2].rc_mode = 0,
	.video_params[STREAM_V2].jpeg_qlevel = 0,
	.video_params[STREAM_V2].rotation = 0,
	.video_params[STREAM_V2].out_buf_size = V2_ENC_BUF_SIZE,
	.video_params[STREAM_V2].out_rsvd_size = 0,
	.video_params[STREAM_V2].direct_output = 0,
	.video_params[STREAM_V2].use_static_addr = 0,
	.video_params[STREAM_V2].fcs = 0,
	.video_snapshot[STREAM_V2] = 0,
	.video_drop_frame[STREAM_V2] = 0,
	.video_params[STREAM_V3].stream_id = STREAM_V3,
	.video_params[STREAM_V3].type = CODEC_H264,
	.video_params[STREAM_V3].resolution = 0,
	.video_params[STREAM_V3].width = 0,
	.video_params[STREAM_V3].height = 0,
	.video_params[STREAM_V3].bps = 0,
	.video_params[STREAM_V3].fps = 0,
	.video_params[STREAM_V3].gop = 0,
	.video_params[STREAM_V3].rc_mode = 0,
	.video_params[STREAM_V3].jpeg_qlevel = 0,
	.video_params[STREAM_V3].rotation = 0,
	.video_params[STREAM_V3].out_buf_size = V3_ENC_BUF_SIZE,
	.video_params[STREAM_V3].out_rsvd_size = 0,
	.video_params[STREAM_V3].direct_output = 0,
	.video_params[STREAM_V3].use_static_addr = 0,
	.video_params[STREAM_V3].fcs = 0,
	.video_snapshot[STREAM_V3] = 0,
	.video_drop_frame[STREAM_V3] = 0,
	.video_params[STREAM_V4].stream_id = STREAM_V4,
	.video_params[STREAM_V4].type = 0,
	.video_params[STREAM_V4].resolution = 0,
	.video_params[STREAM_V4].width = 640,
	.video_params[STREAM_V4].height = 480,
	.video_params[STREAM_V4].bps = 0,
	.video_params[STREAM_V4].fps = 0,
	.video_params[STREAM_V4].gop = 0,
	.video_params[STREAM_V4].rc_mode = 0,
	.video_params[STREAM_V4].jpeg_qlevel = 0,
	.video_params[STREAM_V4].rotation = 0,
	.video_params[STREAM_V4].out_buf_size = 0,
	.video_params[STREAM_V4].out_rsvd_size = 0,
	.video_params[STREAM_V4].direct_output = 0,
	.video_params[STREAM_V4].use_static_addr = 0,
	.video_params[STREAM_V4].fcs = 0,
	.video_enable[STREAM_V1] = 1,
	.video_enable[STREAM_V2] = 1,
	.video_enable[STREAM_V3] = 0,
	.video_enable[STREAM_V4] = 1,
	.fcs_isp_ae_enable = 0,
	.fcs_isp_ae_init_exposure = 0,
	.fcs_isp_ae_init_gain = 0,
	.fcs_isp_awb_enable = 0,
	.fcs_isp_awb_init_rgain = 0,
	.fcs_isp_awb_init_bgain = 0,
	.fcs_isp_init_daynight_mode = 0,
	.voe_heap_size = 0,
	.voe_heap_addr = 0,
#ifdef USE_2K_SENSOR
	.isp_info.sensor_width = 2560,
	.isp_info.sensor_height = 1440,
#else
	.isp_info.sensor_width = 1920,
	.isp_info.sensor_height = 1080,
#endif
	.isp_info.md_enable = 1,
	.isp_info.hdr_enable = 1,
	.isp_info.osd_enable = 1,
	.fcs_channel = 1,//FCS_TOTAL_NUMBER
	.fcs_status = 0,
	.fcs_setting_done = 0,
	.fcs_isp_iq_id = 0,
};

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

static video_params_t video_v2_params = {
	.stream_id = V2_CHANNEL,
	.type = VIDEO_TYPE,
	.resolution = V2_RESOLUTION,
	.width = V2_WIDTH,
	.height = V2_HEIGHT,
	.bps = V2_BPS,
	.fps = V2_FPS,
	.gop = V2_GOP,
	.rc_mode = V2_RCMODE,
	.use_static_addr = 1
};

static audio_params_t audio_params;

static aac_params_t aac_params = {
	.sample_rate = 8000,
	.channel = 1,
	.bit_length = FAAC_INPUT_16BIT,
	.output_format = 1,
	.mpeg_version = MPEG4,
	.mem_total_size = 10 * 1024,
	.mem_block_size = 128,
	.mem_frame_size = 1024
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

static rtsp2_params_t rtsp2_v2_params = {
	.type = AVMEDIA_TYPE_VIDEO,
	.u = {
		.v = {
			.codec_id = VIDEO_CODEC,
			.fps      = V2_FPS,
			.bps      = V2_BPS
		}
	}
};

static rtsp2_params_t rtsp2_a_params = {
	.type = AVMEDIA_TYPE_AUDIO,
	.u = {
		.a = {
			.codec_id   = AV_CODEC_ID_MP4A_LATM,
			.channel    = 1,
			.samplerate = 8000
		}
	}
};

static aad_params_t aad_rtp_params = {
	.sample_rate = 8000,
	.channel = 1,
	.type = TYPE_RTP_RAW
};

static rtp_params_t rtp_aad_params = {
	.valid_pt = 0xFFFFFFFF,
	.port = 16384,
	.frame_size = 1500,
	.cache_depth = 6
};

static mp4_params_t mp4_v1_params = {
	.fps            = V1_FPS,
	.gop            = V1_GOP,
	.width = V1_WIDTH,
	.height = V1_HEIGHT,
	.sample_rate = 8000,
	.channel = 1,

	.record_length = 10, //seconds
	.record_type = STORAGE_ALL,
	.record_file_num = 2,
	.record_file_name = "AmebaPro_recording",
	.fatfs_buf_size = 224 * 1024, /* 32kb multiple */
};
#ifdef FCS_PARTITION
void voe_fcs_change_parameters(int ch, int width, int height, int iq_id)
{
	pfw_init();

	void *fp = pfw_open("FCSDATA", M_RAW | M_CREATE);
	unsigned char *ptr = (unsigned char *)&video_boot_stream;
	unsigned char *fcs_buf = malloc(4096);
	unsigned char *fcs_verify = malloc(4096);
	unsigned int checksum_tag = 0;
	int i = 0;
	if (fcs_buf == NULL || fcs_verify == NULL) {
		printf("It can't allocate buffer\r\n");
		return;
	}
	video_boot_stream.video_params[ch].width  = width;
	video_boot_stream.video_params[ch].height = height;
	video_boot_stream.fcs_isp_iq_id = iq_id;
	printf("ch %d width %d height %d iq_id %d\r\n", ch, width, height, iq_id);
	memset(fcs_buf, 0x00, 4096);
	memset(fcs_verify, 0x00, 4096);
	fcs_buf[0] = 'F';
	fcs_buf[1] = 'C';
	fcs_buf[2] = 'S';
	fcs_buf[3] = 'D';
	for (i = 0; i < sizeof(video_boot_stream_t); i++) {
		checksum_tag += ptr[i];
	}
	fcs_buf[4] = (checksum_tag) & 0xff;
	fcs_buf[5] = (checksum_tag >> 8) & 0xff;
	fcs_buf[6] = (checksum_tag >> 16) & 0xff;
	fcs_buf[7] = (checksum_tag >> 24) & 0xff;
	memcpy(fcs_buf + 8, &video_boot_stream, sizeof(video_boot_stream_t));
	pfw_seek(fp, 0, SEEK_SET);
	pfw_write(fp, fcs_buf, 4096);
	pfw_seek(fp, 0, SEEK_SET);
	pfw_read(fp, fcs_verify, 4096);
	for (i = 0; i < 4096; i++) {
		if (fcs_buf[i] != fcs_verify[i]) {
			printf("wrong %d %x %x\r\n", i, fcs_buf[i], fcs_verify[i]);
		}
	}
	pfw_seek(fp, 0, SEEK_SET);
	pfw_close(fp);
	if (fcs_buf) {
		free(fcs_buf);
	}
	if (fcs_verify) {
		free(fcs_verify);
	}
}
#else
void voe_fcs_change_parameters(int ch, int width, int height, int iq_id) //Setup the tag and modify the parameters.
{
	video_boot_stream_t *fcs_data = NULL;// = (video_boot_stream_t *)malloc(sizeof(video_boot_stream_t));
	unsigned char *fcs_buf = malloc(2048);
	int i = 0;
	unsigned int checksum_tag = 0;
	unsigned char *ptr = (unsigned char *)&video_boot_stream;
	unsigned int flash_addr = 0;
	if (sys_get_boot_sel() == 0) {
		flash_addr = NOR_FLASH_FCS;
	} else {
		flash_addr = NAND_FLASH_FCS;
	}
	if (fcs_buf == NULL) {
		printf("It can't get the buffer\r\n");
		return;
	}
	video_boot_stream.video_params[ch].width  = width;
	video_boot_stream.video_params[ch].height = height;
	video_boot_stream.fcs_isp_iq_id = iq_id;
	printf("ch %d width %d height %d iq_id %d\r\n", ch, width, height, iq_id);
	memset(fcs_buf, 0x00, 2048);
	fcs_buf[0] = 'F';
	fcs_buf[1] = 'C';
	fcs_buf[2] = 'S';
	fcs_buf[3] = 'D';
	for (i = 0; i < sizeof(video_boot_stream_t); i++) {
		checksum_tag += ptr[i];
	}
	fcs_buf[4] = (checksum_tag) & 0xff;
	fcs_buf[5] = (checksum_tag >> 8) & 0xff;
	fcs_buf[6] = (checksum_tag >> 16) & 0xff;
	fcs_buf[7] = (checksum_tag >> 24) & 0xff;
	memcpy(fcs_buf + 8, &video_boot_stream, sizeof(video_boot_stream_t));
	ftl_common_write(flash_addr, fcs_buf, 2048);
	memset(fcs_buf, 0xff, 2048);
	ftl_common_read(flash_addr, fcs_buf, 2048);
	fcs_data = (video_boot_stream_t *)(fcs_buf + 8);
	printf("ch %d ->width %d ->height %d iq_id %d\r\n", ch, fcs_data->video_params[ch].width, fcs_data->video_params[ch].height, fcs_data->fcs_isp_iq_id);
	if (fcs_buf) {
		free(fcs_buf);
	}
}
#endif

static inline unsigned int str_to_value(const unsigned char *str)
{
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		return strtol((char const *)str, NULL, 16);
	} else {
		return atoi((char const *)str);
	}
}

void fcs_change(void *arg)
{
	int argc;
	int ret = 0;
	char *argv[MAX_ARGC] = {0};
	unsigned char *ptr = NULL;
	int type = 0;
	int page_size = 0;
	int block_size = 0;
	int block_cnt = 0;
	int ch, width, height, iq_id = 0;

	argc = parse_param(arg, argv);

	ftl_common_info(&type, &page_size, &block_size, &block_cnt);
	printf("type %d page_size %d block_size %d block_cnt %d\r\n", type, page_size, block_size, block_cnt);
	if (argc != 5) {
		printf("FCST=ch,width,height,iq_id\r\n");//FCST=0,1280,720,IQ_ID
		return;
	}
	ch = str_to_value((unsigned char const *)argv[1]);
	width = str_to_value((unsigned char const *)argv[2]);
	height = str_to_value((unsigned char const *)argv[3]);
	iq_id = str_to_value((unsigned char const *)argv[4]);
	printf("ch %d width %d height %d iq_id %d\r\n", ch, width, height, iq_id);
	if (type == 1) {
		voe_fcs_change_parameters(ch, width, height, iq_id);
	} else {
		voe_fcs_change_parameters(ch, width, height, iq_id);
	}
}

void fcs_info(void *arg)
{
	video_boot_stream_t *isp_fcs_info;
	video_get_fcs_info(&isp_fcs_info);
	printf("ch 0 -> width %d height %d\r\n", isp_fcs_info->video_params[STREAM_V1].width, isp_fcs_info->video_params[STREAM_V1].height);
	printf("ch 1 -> width %d height %d\r\n", isp_fcs_info->video_params[STREAM_V2].width, isp_fcs_info->video_params[STREAM_V2].height);
}

int fcs_snapshot_cb(uint32_t jpeg_addr, uint32_t jpeg_len)
{
	printf("snapshot size=%d\n\r", jpeg_len);
	return 0;
}

#define FCS_AV_SYNC 1
void fcs_avsync(bool enable)
{
	if (enable) {
		//get the fcs time need to what video first frame
		int fcs_video_starttime = 0;
		int fcs_video_endtime = 0;
		int audio_framesize_ms = 0;
		while (!fcs_video_starttime) {
			vTaskDelay(1);
			video_get_fcs_queue_info(&fcs_video_starttime, &fcs_video_endtime);
		}

		audio_params.fcs_avsync_en = 1;
		audio_params.fcs_avsync_vtime = fcs_video_starttime;
	}
}

#define MODULE_TIMESTAMP_OFFSET 2000
void mmf2_video_example_joint_test_rtsp_mp4_init_fcs(void)
{
	int voe_heap_size = video_voe_presetting(1, V1_WIDTH, V1_HEIGHT, V1_BPS, 1,
						1, V2_WIDTH, V2_HEIGHT, V2_BPS, 1,
						0, 0, 0, 0, 0,
						0, 0, 0);

	//printf("\r\n voe heap size = %d\r\n", voe_heap_size);
	video_boot_stream_t *isp_fcs_info;
	video_get_fcs_info(&isp_fcs_info);//Get the fcs info
	int fcs_start_ch = -1;//Get the first start fcs channel
	if (isp_fcs_info->fcs_status) {
		for (int i = 0; i < 2; i++) { //Maximum two channel
			if (fcs_start_ch == -1 && isp_fcs_info->video_params[i].fcs == 1) {
				fcs_start_ch = i;
				printf("fcs_start_ch %d\r\n", fcs_start_ch);
			}
		}
		if ((video_boot_stream.isp_info.sensor_width == isp_fcs_info->isp_info.sensor_width) &&
			(video_boot_stream.isp_info.sensor_height == isp_fcs_info->isp_info.sensor_height)) {
			if (isp_fcs_info->video_params[STREAM_V1].fcs) {
				video_v1_params.width = isp_fcs_info->video_params[STREAM_V1].width;
				video_v1_params.height = isp_fcs_info->video_params[STREAM_V1].height;
				mp4_v1_params.width = video_v1_params.width;
				mp4_v1_params.height = video_v1_params.height;
				//printf("ch 0 w %d h %d\r\n",mp4_v1_params.width,mp4_v1_params.height);
			}
			if (isp_fcs_info->video_params[STREAM_V2].fcs) {
				video_v2_params.width = isp_fcs_info->video_params[STREAM_V2].width;
				video_v2_params.height = isp_fcs_info->video_params[STREAM_V2].height;
				//printf("ch 1 w %d h %d\r\n",video_v2_params.width,video_v2_params.height);
			}
		}
	}
	if (isp_fcs_info->fcs_status == 1 && fcs_start_ch == 1) { //It need to change the order if the fcs channel is not zero
		// ------ Channel 2--------------
		video_v2_ctx = mm_module_open(&video_module);
		if (video_v2_ctx) {
			video_v2_params.type = SHAPSHOT_TYPE;
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_SET_TIMESTAMP_OFFSET, MODULE_TIMESTAMP_OFFSET);
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v2_params);
			mm_module_ctrl(video_v2_ctx, MM_CMD_SET_QUEUE_LEN, V2_FPS * 10); //Add the queue buffer to avoid to lost data.
			mm_module_ctrl(video_v2_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_SNAPSHOT_CB, (int)fcs_snapshot_cb);
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_APPLY, V2_CHANNEL);	// start channel 1
		} else {
			rt_printf("video open fail\n\r");
			goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
		}
		// ------ Channel 1--------------
		video_v1_ctx = mm_module_open(&video_module);
		if (video_v1_ctx) {
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_TIMESTAMP_OFFSET, MODULE_TIMESTAMP_OFFSET);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v1_params);
			mm_module_ctrl(video_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_FPS * 10); //Add the queue buffer to avoid to lost data.
			mm_module_ctrl(video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_APPLY, V1_CHANNEL);	// start channel 0
		} else {
			rt_printf("video open fail\n\r");
			goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
		}
	} else {
		// ------ Channel 1--------------
		video_v1_ctx = mm_module_open(&video_module);
		if (video_v1_ctx) {
			video_v1_params.type = SHAPSHOT_TYPE;
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_TIMESTAMP_OFFSET, MODULE_TIMESTAMP_OFFSET);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v1_params);
			mm_module_ctrl(video_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_FPS * 10); //Add the queue buffer to avoid to lost data.
			mm_module_ctrl(video_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_SNAPSHOT_CB, (int)fcs_snapshot_cb);
			mm_module_ctrl(video_v1_ctx, CMD_VIDEO_APPLY, V1_CHANNEL);	// start channel 0
		} else {
			rt_printf("video open fail\n\r");
			goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
		}
		// ------ Channel 2--------------
		video_v2_ctx = mm_module_open(&video_module);
		if (video_v2_ctx) {
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_SET_TIMESTAMP_OFFSET, MODULE_TIMESTAMP_OFFSET);
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_SET_PARAMS, (int)&video_v2_params);
			mm_module_ctrl(video_v2_ctx, MM_CMD_SET_QUEUE_LEN, V2_FPS * 10); //Add the queue buffer to avoid to lost data.
			mm_module_ctrl(video_v2_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
			mm_module_ctrl(video_v2_ctx, CMD_VIDEO_APPLY, V2_CHANNEL);	// start channel 1
		} else {
			rt_printf("video open fail\n\r");
			goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
		}
	}

	memcpy((void *)&audio_params, (void *)&default_audio_params, sizeof(audio_params_t));

	if (isp_fcs_info->fcs_status) {
		//enable the setting of fcs avsync
		fcs_avsync(FCS_AV_SYNC);
	}

	//--------------Audio --------------
	audio_ctx = mm_module_open(&audio_module);
	if (audio_ctx) {
		mm_module_ctrl(audio_ctx, CMD_AUDIO_SET_TIMESTAMP_OFFSET, MODULE_TIMESTAMP_OFFSET);
#if FCS_AV_SYNC
		mm_module_ctrl(audio_ctx, MM_CMD_SET_QUEUE_LEN, 30); //Add the queue buffer to avoid to lost data.
#else
		mm_module_ctrl(audio_ctx, MM_CMD_SET_QUEUE_LEN, 6); //queue size can be smaller
#endif
		mm_module_ctrl(audio_ctx, CMD_AUDIO_SET_PARAMS, (int)&audio_params);
		mm_module_ctrl(audio_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(audio_ctx, CMD_AUDIO_APPLY, 0);
	} else {
		rt_printf("audio open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	aac_ctx = mm_module_open(&aac_module);
	if (aac_ctx) {
		mm_module_ctrl(aac_ctx, CMD_AAC_SET_PARAMS, (int)&aac_params);
		mm_module_ctrl(aac_ctx, MM_CMD_SET_QUEUE_LEN, 30);
		mm_module_ctrl(aac_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(aac_ctx, CMD_AAC_INIT_MEM_POOL, 0);
		mm_module_ctrl(aac_ctx, CMD_AAC_APPLY, 0);
	} else {
		rt_printf("AAC open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	//--------------MP4---------------
	mp4_ctx = mm_module_open(&mp4_module);
	if (mp4_ctx) {
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_PARAMS, (int)&mp4_v1_params);
		mm_module_ctrl(mp4_ctx, CMD_MP4_LOOP_MODE, 0);
		mm_module_ctrl(mp4_ctx, CMD_MP4_START, mp4_v1_params.record_file_num);
	} else {
		rt_printf("MP4 open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	//--------------RTSP---------------
	rtsp2_v2_ctx = mm_module_open(&rtsp2_module);
	if (rtsp2_v2_ctx) {
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SELECT_STREAM, 0);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_PARAMS, (int)&rtsp2_v2_params);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_CMD_RTSP2_SET_TIME_OFFSET, MODULE_TIMESTAMP_OFFSET);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_APPLY, 0);

		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SELECT_STREAM, 1);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_PARAMS, (int)&rtsp2_a_params);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_CMD_RTSP2_SET_TIME_OFFSET, MODULE_TIMESTAMP_OFFSET);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_APPLY, 0);
		mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_STREAMMING, ON);
	} else {
		rt_printf("RTSP2 open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	//--------------Link---------------------------
	siso_audio_aac = siso_create();
	if (siso_audio_aac) {
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_INPUT, (uint32_t)audio_ctx, 0);
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_OUTPUT, (uint32_t)aac_ctx, 0);
		siso_start(siso_audio_aac);
	} else {
		rt_printf("siso1 open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}
	//vTaskDelay(300);
	//rt_printf("siso started\n\r");

	mimo_2v_1a_rtsp_mp4 = mimo_create();
	if (mimo_2v_1a_rtsp_mp4) {
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_SET_SECURE_CONTEXT, 1, 0);
#endif
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_ADD_INPUT0, (uint32_t)video_v1_ctx, 0);
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_ADD_INPUT1, (uint32_t)video_v2_ctx, 0);
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_ADD_INPUT2, (uint32_t)aac_ctx, 0);
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_ADD_OUTPUT0, (uint32_t)mp4_ctx, MMIC_DEP_INPUT0 | MMIC_DEP_INPUT2);
		mimo_ctrl(mimo_2v_1a_rtsp_mp4, MMIC_CMD_ADD_OUTPUT1, (uint32_t)rtsp2_v2_ctx, MMIC_DEP_INPUT1 | MMIC_DEP_INPUT2);
		mimo_start(mimo_2v_1a_rtsp_mp4);
	} else {
		rt_printf("mimo open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}
	//rt_printf("mimo started\n\r");

	// RTP audio

	rtp_ctx = mm_module_open(&rtp_module);
	if (rtp_ctx) {
		mm_module_ctrl(rtp_ctx, CMD_RTP_SET_PARAMS, (int)&rtp_aad_params);
		mm_module_ctrl(rtp_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(rtp_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(rtp_ctx, CMD_RTP_APPLY, 0);
		mm_module_ctrl(rtp_ctx, CMD_RTP_STREAMING, 1);	// streamming on
	} else {
		rt_printf("RTP open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	aad_ctx = mm_module_open(&aad_module);
	if (aad_ctx) {
		mm_module_ctrl(aad_ctx, CMD_AAD_SET_PARAMS, (int)&aad_rtp_params);
		mm_module_ctrl(aad_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(aad_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(aad_ctx, CMD_AAD_APPLY, 0);
	} else {
		rt_printf("AAD open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	siso_rtp_aad = siso_create();
	if (siso_rtp_aad) {
		siso_ctrl(siso_rtp_aad, MMIC_CMD_ADD_INPUT, (uint32_t)rtp_ctx, 0);
		siso_ctrl(siso_rtp_aad, MMIC_CMD_ADD_OUTPUT, (uint32_t)aad_ctx, 0);
		siso_start(siso_rtp_aad);
	} else {
		rt_printf("siso1 open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}

	//rt_printf("siso3 started\n\r");

	siso_aad_audio = siso_create();
	if (siso_aad_audio) {
		siso_ctrl(siso_aad_audio, MMIC_CMD_ADD_INPUT, (uint32_t)aad_ctx, 0);
		siso_ctrl(siso_aad_audio, MMIC_CMD_ADD_OUTPUT, (uint32_t)audio_ctx, 0);
		siso_start(siso_aad_audio);
	} else {
		rt_printf("siso2 open fail\n\r");
		goto mmf2_video_exmaple_joint_test_rtsp_mp4_fail;
	}
	atcmd_fcs_init();
	atcmd_userctrl_init();
	return;
mmf2_video_exmaple_joint_test_rtsp_mp4_fail:

	return;
}

static const char *example = "mmf2_video_example_joint_test_rtsp_mp4_init_fcs";
static void example_deinit(int need_pause)
{
	//Pause Linker
	siso_pause(siso_audio_aac);
	mimo_pause(mimo_2v_1a_rtsp_mp4, MM_OUTPUT0 | MM_OUTPUT1);
	siso_pause(siso_rtp_aad);
	siso_pause(siso_aad_audio);

	//Stop module
	mm_module_ctrl(rtp_ctx, CMD_RTP_STREAMING, 0);
	mm_module_ctrl(rtsp2_v2_ctx, CMD_RTSP2_SET_STREAMMING, OFF);
	mm_module_ctrl(aac_ctx, CMD_AAC_STOP, 0);
	mm_module_ctrl(audio_ctx, CMD_AUDIO_SET_TRX, 0);
	mm_module_ctrl(mp4_ctx, CMD_MP4_STOP, 0);
	mm_module_ctrl(video_v1_ctx, CMD_VIDEO_STREAM_STOP, 0);
	mm_module_ctrl(video_v2_ctx, CMD_VIDEO_STREAM_STOP, 0);

	//Delete linker
	siso_delete(siso_aad_audio);
	siso_delete(siso_rtp_aad);
	mimo_delete(mimo_2v_1a_rtsp_mp4);
	siso_delete(siso_audio_aac);


	//Close module
	aad_ctx = mm_module_close(aad_ctx);
	rtp_ctx = mm_module_close(rtp_ctx);
	rtsp2_v2_ctx = mm_module_close(rtsp2_v2_ctx);
	aac_ctx = mm_module_close(aac_ctx);
	audio_ctx = mm_module_close(audio_ctx);
	mp4_ctx = mm_module_close(mp4_ctx);
	video_v1_ctx = mm_module_close(video_v1_ctx);
	video_v2_ctx = mm_module_close(video_v2_ctx);

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
			example_deinit(user_cmd);
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

static log_item_t at_fcs_change_items[ ] = {
	{"FCST", fcs_change,},
	{"FCSG", fcs_info,},
};

static void atcmd_userctrl_init(void)
{
	log_service_add_table(userctrl_items, sizeof(userctrl_items) / sizeof(userctrl_items[0]));
}
static void atcmd_fcs_init(void)
{
	log_service_add_table(at_fcs_change_items, sizeof(at_fcs_change_items) / sizeof(at_fcs_change_items[0]));
	printf("FCST=ch,width,height -> change the fcs resolution; FCSG get the fcs resolution info\r\n");
}