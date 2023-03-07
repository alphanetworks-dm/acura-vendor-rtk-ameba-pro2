/******************************************************************************
*
* Copyright(c) 2007 - 2018 Realtek Corporation. All rights reserved.
*
******************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include "module_md.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "hal_video.h"//draw rect
#include "avcodec.h"

static float sw_ALS_lite(void)
{
	int iAECGain, iAEExp;
	float fAECGain;
	hal_video_isp_ctrl(0x0011, 0, &iAEExp);
	hal_video_isp_ctrl(0x0013, 0, &iAECGain);
	fAECGain = iAEExp * iAECGain / 25600;
	//printf("Exp:%.6d, AEC Gain: %.4f, fAECGain : %.6f\r\n", iAEExp, (float)iAECGain / 256, fAECGain);
	return fAECGain;
}

static char check_AE_stable(void)
{
	float ETGain1, ETGain2;
	ETGain1 = sw_ALS_lite();
	vTaskDelay(100);
	ETGain2 = sw_ALS_lite();
	//printf("ETGain1 = %.5f, ETGain2 = %.5f", ETGain1, ETGain2);
	if (ETGain1 == ETGain2) {
		return 1;
	} else {
		return 0;
	}
}

int md_handle(void *p, void *input, void *output)
{
	md_ctx_t *ctx = (md_ctx_t *)p;
	mm_queue_item_t *input_item = (mm_queue_item_t *)input;
	mm_queue_item_t *output_item = (mm_queue_item_t *)output;
	int i, j, k, l;

	//printf("width = %d,height = %d\n",ctx->params->image_width, ctx->params->image_height);
	//printf("image size = %d\n",input_item->size);

	if (ctx->motion_detect_ctx->en_AE_stable) {
		if (ctx->motion_detect_ctx->AE_stable == 0) {
			printf("AE not sable\n\r");
			ctx->motion_detect_ctx->AE_stable = check_AE_stable();
			return 0;
		}
	}

	if (ctx->motion_detect_ctx->count % ctx->motion_detect_ctx->detect_interval == 0) {
		unsigned long tick1 = xTaskGetTickCount();
		md_get_YRGB_value(ctx->motion_detect_ctx, ctx->params, (unsigned char *)input_item->data_addr);
		//printf("\r\nCalculate YRGB after %dms.\n", (xTaskGetTickCount() - tick1));
	}
	if (ctx->motion_detect_ctx->count == 0) {
		printf("md initial\n\r");
		md_initial(ctx->motion_detect_ctx, ctx->params);
		if (ctx->motion_detect_ctx->md_adapt.mode) {
			md_initial_adaptive_threshold(ctx->motion_detect_ctx, ctx->params, 3, 96);
		}
	}
	if (ctx->motion_detect_ctx->count % ctx->motion_detect_ctx->detect_interval == 0) {
		motion_detect(ctx->motion_detect_ctx, ctx->params);
		if (ctx->motion_detect_ctx->count == ctx->motion_detect_ctx->detect_interval * 1000) {
			ctx->motion_detect_ctx->count = ctx->motion_detect_ctx->detect_interval;
		}
		if (ctx->disp_postproc) {
			ctx->disp_postproc(&ctx->motion_detect_ctx->md_result);
		}
	}
	ctx->motion_detect_ctx->count ++;

	if (ctx->md_out_en) {
		int motion = ctx->motion_detect_ctx->md_trigger_block;
		if (motion > ctx->motion_detect_ctx->md_trigger_block_threshold) {
			//printf("Motion Detected!\r\n");
			output_item->timestamp = input_item->timestamp;
			output_item->size = input_item->size;
			output_item->type = AV_CODEC_ID_MD_RAW;
			memcpy((unsigned char *)output_item->data_addr, (unsigned char *) input_item->data_addr, input_item->size);
			return output_item->size;
		}
	}

	return 0;
}

int md_control(void *p, int cmd, int arg)
{
	int ret = 0;
	md_ctx_t *ctx = (md_ctx_t *)p;

	switch (cmd) {
	case CMD_MD_SET_PARAMS:
		ctx->params = (md_param_t *)arg;
		break;
	case CMD_MD_SET_MD_MASK:
		memcpy(ctx->motion_detect_ctx->md_mask, (char *)arg, sizeof(ctx->motion_detect_ctx->md_mask));
		printf("Set MD Mask: \r\n");
		for (int j = 0; j < ctx->params->md_row; j++) {
			for (int k = 0; k < ctx->params->md_col; k++) {
				printf("%d ", ctx->motion_detect_ctx->md_mask[j * ctx->params->md_col + k]);
			}
			printf("\r\n");
		}
		printf("\r\n");
		printf("\r\n");
		break;
	case CMD_MD_GET_MD_MASK:
		memcpy((int *)arg, ctx->motion_detect_ctx->md_mask, sizeof(ctx->motion_detect_ctx->md_mask));
		break;
	case CMD_MD_GET_MD_RESULT:
		memcpy((int *)arg, &ctx->motion_detect_ctx->md_result, sizeof(ctx->motion_detect_ctx->md_result));
		break;
	case CMD_MD_SET_OUTPUT:
		ctx->md_out_en = (bool)arg;
		((mm_context_t *)ctx->parent)->module->output_type = MM_TYPE_VSINK;
		break;
	case CMD_MD_SET_DISPPOST:
		ctx->disp_postproc = (md_disp_postprcess)arg;
		break;
	case CMD_MD_SET_TRIG_BLK:
		ctx->motion_detect_ctx->md_trigger_block_threshold = arg;
		break;
	case CMD_MD_EN_AE_STABLE:
		ctx->motion_detect_ctx->en_AE_stable = arg;
		break;
	case CMD_MD_SET_DETECT_INTERVAL:
		ctx->motion_detect_ctx->detect_interval = arg;
		break;
	case CMD_MD_SET_ADAPT_THR_MODE:
		ctx->motion_detect_ctx->md_adapt.mode = arg;
		break;
	case CMD_MD_SET_BGMODE:
		if (arg >= 0 && arg <= 1) {
			ctx->motion_detect_ctx->md_bgmodel.bg_mode = arg;
		} else {
			printf("MD: md bgmode set out of range (0-1).\r\n");
		}
		break;
	case CMD_MD_SET_MD_SENSITIVITY:
		if (arg >= 0 && arg <= 100) {
			ctx->motion_detect_ctx->md_obj_sensitivity = arg;
		} else {
			printf("MD: md sensitivity set out of range (0-100).\r\n");
		}
		break;
	case CMD_MD_GET_MD_SENSITIVITY:
		*(int *)arg = ctx->motion_detect_ctx->md_obj_sensitivity;
		break;
	}

	return ret;
}

void *md_destroy(void *p)
{
	md_ctx_t *ctx = (md_ctx_t *)p;

	if (ctx) {
		if (ctx->motion_detect_ctx) {
			if (ctx->motion_detect_ctx->md_threshold) {
				free(ctx->motion_detect_ctx->md_threshold);
			}
			free(ctx->motion_detect_ctx);
		}
		free(ctx);
	}
	return NULL;
}

void *md_create(void *parent)
{
	md_ctx_t *ctx = (md_ctx_t *)malloc(sizeof(md_ctx_t));
	memset(ctx, 0, sizeof(md_ctx_t));

	ctx->motion_detect_ctx = NULL;
	ctx->motion_detect_ctx = (md_context_t *) malloc(sizeof(md_context_t));
	if (ctx->motion_detect_ctx == NULL) {
		printf("[Error] Allocate motion_detect_ctx fail\n\r");
		goto md_error;
	}
	memset(ctx->motion_detect_ctx, 0, sizeof(md_context_t));
	ctx->motion_detect_ctx->max_threshold_shift = 0.7;
	ctx->motion_detect_ctx->max_turn_off = 15;
	ctx->motion_detect_ctx->md_trigger_block_threshold = 1;

	ctx->motion_detect_ctx->en_AE_stable = 1;
	ctx->motion_detect_ctx->detect_interval = 1;

	ctx->motion_detect_ctx->md_bgmodel.bg_mode = 0;

	ctx->motion_detect_ctx->md_threshold = (motion_detect_threshold_t *) malloc(sizeof(motion_detect_threshold_t));
	ctx->motion_detect_ctx->md_threshold->Tbase = 1;
	ctx->motion_detect_ctx->md_threshold->Tlum = 3;
	ctx->motion_detect_ctx->md_obj_sensitivity = 100;
	ctx->disp_postproc = NULL;

	for (int i = 0; i < MD_MAX_COL * MD_MAX_ROW; i++) {
		ctx->motion_detect_ctx->md_mask[i] = 1;
	}

	ctx->parent = parent;

	return ctx;

md_error:
	return NULL;
}

void *md_new_item(void *p)
{
	md_ctx_t *ctx = (md_ctx_t *)p;

	return (void *)malloc(ctx->params->image_width * ctx->params->image_height * 3);
}

void *md_del_item(void *p, void *d)
{
	(void)p;
	if (d) {
		free(d);
	}
	return NULL;
}

mm_module_t md_module = {
	.create = md_create,
	.destroy = md_destroy,
	.control = md_control,
	.handle = md_handle,

	.new_item = md_new_item,
	.del_item = md_del_item,

	.output_type = MM_TYPE_NONE,
	.module_type = MM_TYPE_VDSP,
	.name = "md"
};
