/******************************************************************************
*
* Copyright(c) 2007 - 2023 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include <string.h>

#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "module_video.h"
#include "avcodec.h"

#include "module_vipnn.h"
#include "module_fileloader.h"
#include "module_filesaver.h"

#include "avcodec.h"
#include "vfs.h"
#include "cJSON.h"
#include "model_yolo.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#define STBI_ONLY_BMP
#define STBI_ONLY_JPEG
#include "../image/3rdparty/stb/stb_image.h"

static char coco_name[80][20] =
{ "person",    "bicycle",    "car",    "motorbike",    "aeroplane",    "bus",    "train",    "truck",    "boat",    "traffic light",    "fire hydrant",    "stop sign",    "parking meter",    "bench",    "bird",    "cat",    "dog",    "horse",    "sheep",    "cow",    "elephant",    "bear",    "zebra",    "giraffe",    "backpack",    "umbrella",    "handbag",    "tie",    "suitcase",    "frisbee",    "skis",    "snowboard",    "sports ball",    "kite",    "baseball bat",    "baseball glove",    "skateboard",    "surfboard",    "tennis racket",    "bottle",    "wine glass",    "cup",    "fork",    "knife",    "spoon",    "bowl",    "banana",    "apple",    "sandwich",    "orange",    "broccoli",    "carrot",    "hot dog",    "pizza",    "donut",    "cake",    "chair",    "sofa",    "pottedplant",    "bed",    "diningtable",    "toilet",    "tvmonitor",    "laptop",    "mouse",    "remote",    "keyboard",    "cell phone",    "microwave",    "oven",    "toaster",    "sink",    "refrigerator",    "book",    "clock",    "vase",    "scissors",    "teddy bear",    "hair drier",    "toothbrush" };

// NN tester config
#define NN_MODEL_OBJ        yolov4_tiny     /* fix here to choose model: yolov4_tiny, yolov7_tiny */
#define NN_DATASET_LABEL    coco_name       /* fix here to define label */
#define TEST_IMAGE_WIDTH	416             /* fix here to match model input size */
#define TEST_IMAGE_HEIGHT	416             /* fix here to match model input size */
static float nn_confidence_thresh = 0.2;    /* fix here to set score threshold */
static float nn_nms_thresh = 0.3;           /* fix here to set nms threshold */

#define SAVE_COCO_FORMAT    1

nn_data_param_t roi_tester = {
	.img = {
		.width = TEST_IMAGE_WIDTH,
		.height = TEST_IMAGE_HEIGHT,
		.roi = {
			.xmin = 0,
			.ymin = 0,
			.xmax = TEST_IMAGE_WIDTH,
			.ymax = TEST_IMAGE_HEIGHT,
		}
	}
};

static fileloader_params_t test_image_params = {
	.codec_id = AV_CODEC_ID_JPEG       /* Fix me (AV_CODEC_ID_BMP or AV_CODEC_ID_JPEG) */
};

static int ImageDecodeToRGB888planar_ConvertInPlace(void *pbuffer, void *pbuffer_size);
static char *nn_get_json_format(void *p, int frame_id, char *file_name);
static void nn_save_handler_for_evaluate(char *file_name, uint32_t data_addr, uint32_t data_size);
static int sd_save_file(char *file_name, char *data_buf, int data_buf_size);

static mm_context_t *fileloader_ctx			= NULL;
static mm_context_t *filesaver_ctx			= NULL;
static mm_context_t *vipnn_ctx              = NULL;

static mm_siso_t *siso_fileloader_vipnn     = NULL;
static mm_siso_t *siso_vipnn_filesaver      = NULL;

#define FILELIST_NAME           "coco_val2017_list.txt"       /* Fix me */

static int get_line_num_in_sdfile(char *file_name)
{
	char line[128];
	memset(line, 0, sizeof(line));
	char file_path[64];
	memset(file_path, 0, sizeof(file_path));
	snprintf(file_path, sizeof(file_path), "%s%s", "sd:/", file_name);
	int count = 0;
	FILE *f = fopen(file_path, "r");
	while (fgets(line, sizeof(line), f)) {
		count++;
		//printf("[line %d] %s\r\n", count, line);
		memset(line, 0, sizeof(line));
	}
	fclose(f);

	return count;
}

void mmf2_example_vipnn_objectdet_test_init(void)
{
	// init virtual file system
	vfs_init(NULL);
	vfs_user_register("sd", VFS_FATFS, VFS_INF_SD);
	// get test file num on list
	printf("Getting data set image number in list......\r\n");
	uint32_t t0 = xTaskGetTickCount();
	int file_count = get_line_num_in_sdfile((char *)FILELIST_NAME);
	printf("The file has %d lines, it take %ld ms\r\n", file_count, xTaskGetTickCount() - t0);

	// file loader
	fileloader_ctx = mm_module_open(&fileloader_module);
	if (fileloader_ctx) {
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_SET_PARAMS, (int)&test_image_params);
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_SET_READ_MODE, (int)FILELIST_MODE);
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_SET_FILELIST_NAME, (int)FILELIST_NAME);
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_SET_FILE_NUM, (int)file_count);
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_SET_DECODE_PROCESS, (int)ImageDecodeToRGB888planar_ConvertInPlace);

		mm_module_ctrl(fileloader_ctx, MM_CMD_SET_QUEUE_LEN, 1);  //set to 1 when using NN file tester
		mm_module_ctrl(fileloader_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(fileloader_ctx, CMD_FILELOADER_APPLY, 0);
	} else {
		printf("fileloader open fail\n\r");
		goto mmf2_example_file_vipnn_tester_fail;
	}
	printf("fileloader opened\n\r");

	// VIPNN
	vipnn_ctx = mm_module_open(&vipnn_module);
	if (vipnn_ctx) {
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_MODEL, (int)&NN_MODEL_OBJ);
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_IN_PARAMS, (int)&roi_tester);
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_CONFIDENCE_THRES, (int)&nn_confidence_thresh);
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_NMS_THRES, (int)&nn_nms_thresh);
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_OUTPUT, 1);  //enable module output
		mm_module_ctrl(vipnn_ctx, MM_CMD_SET_QUEUE_LEN, 1);  //set to 1 when using NN file tester
		mm_module_ctrl(vipnn_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(vipnn_ctx, CMD_VIPNN_APPLY, 0);
	} else {
		printf("VIPNN open fail\n\r");
		goto mmf2_example_file_vipnn_tester_fail;
	}
	printf("VIPNN opened\n\r");

	// file saver
	filesaver_ctx = mm_module_open(&filesaver_module);
	if (filesaver_ctx) {
		mm_module_ctrl(filesaver_ctx, CMD_FILESAVER_SET_TYPE_HANDLER, (int)nn_save_handler_for_evaluate);
		mm_module_ctrl(filesaver_ctx, CMD_FILESAVER_APPLY, 0);
	} else {
		printf("filesaver open fail\n\r");
		goto mmf2_example_file_vipnn_tester_fail;
	}
	printf("filesaver opened\n\r");

	//--------------Link---------------------------

	siso_fileloader_vipnn = siso_create();
	if (siso_fileloader_vipnn) {
		siso_ctrl(siso_fileloader_vipnn, MMIC_CMD_ADD_INPUT, (uint32_t)fileloader_ctx, 0);
		siso_ctrl(siso_fileloader_vipnn, MMIC_CMD_ADD_OUTPUT, (uint32_t)vipnn_ctx, 0);
		siso_ctrl(siso_fileloader_vipnn, MMIC_CMD_SET_STACKSIZE, (uint32_t)1024 * 128, 0);
		siso_start(siso_fileloader_vipnn);
	} else {
		printf("siso_fileloader_vipnn open fail\n\r");
		goto mmf2_example_file_vipnn_tester_fail;
	}
	printf("siso_fileloader_vipnn started\n\r");

	siso_vipnn_filesaver = siso_create();
	if (siso_vipnn_filesaver) {
		siso_ctrl(siso_vipnn_filesaver, MMIC_CMD_ADD_INPUT, (uint32_t)vipnn_ctx, 0);
		siso_ctrl(siso_vipnn_filesaver, MMIC_CMD_ADD_OUTPUT, (uint32_t)filesaver_ctx, 0);
		siso_ctrl(siso_vipnn_filesaver, MMIC_CMD_SET_STACKSIZE, (uint32_t)1024 * 128, 0);
		siso_start(siso_vipnn_filesaver);
	} else {
		printf("siso_vipnn_filesaver open fail\n\r");
		goto mmf2_example_file_vipnn_tester_fail;
	}
	printf("siso_vipnn_filesaver started\n\r");

	return;
mmf2_example_file_vipnn_tester_fail:

	return;
}

/*-----------------------------------------------------------------------------------*/

static void set_nn_roi(int w, int h)
{
	roi_tester.img.width = w;
	roi_tester.img.height = h;
	roi_tester.img.roi.xmax = w;
	roi_tester.img.roi.ymax = h;
	mm_module_ctrl(vipnn_ctx, CMD_VIPNN_SET_IN_PARAMS, (int)&roi_tester);
}

static int ImageDecodeToRGB888planar_ConvertInPlace(void *pbuffer, void *pbuffer_size)
{
	uint8_t *pImageBuf = (uint8_t *)pbuffer;
	uint32_t *pImageSize = (uint32_t *)pbuffer_size;

	int w, h, c;
	int channels = 3;
	uint8_t *im_data = stbi_load_from_memory(pImageBuf, *pImageSize, &w, &h, &c, channels);
	printf("\r\nimage data size: w:%d, h:%d, c:%d\r\n", w, h, c);

	if (c != 1 && c != 3) {
		printf("error: it's not an image file\r\n");
		return -1;
	}

	/* set nn roi according to image size */
	set_nn_roi(w, h);

	/* rgb packed to rgb planar */
	int data_size = w * h * c;
	uint8_t *rgb_planar_buf = (uint8_t *)malloc(data_size);
	for (int k = 0; k < c; k++) {
		for (int j = 0; j < h; j++) {
			for (int i = 0; i < w; i++) {
				int dst_i = i + w * j + w * h * k;
				int src_i = k + c * i + c * w * j;
				rgb_planar_buf[dst_i] = im_data[src_i];
			}
		}
	}
	memcpy(pImageBuf, rgb_planar_buf, data_size);
	*pImageSize = (uint32_t) data_size;

	free(rgb_planar_buf);
	stbi_image_free(im_data);

	return 0;
}

static char *nn_get_json_format(void *p, int frame_id, char *file_name)
{
	objdetect_res_t *res = (objdetect_res_t *)p;

	/**** cJSON ****/
	cJSON_Hooks memoryHook;
	memoryHook.malloc_fn = malloc;
	memoryHook.free_fn = free;
	cJSON_InitHooks(&memoryHook);

	cJSON *nnJSObject = NULL, *nn_obj_JSObject = NULL;
	cJSON *nn_coor_JSObject = NULL, *nn_obj_JSArray = NULL;
	cJSON *nnJSArray = NULL, *nn_coor_JSArray = NULL;
	char *nn_json_string = NULL;
#if SAVE_COCO_FORMAT
	nnJSArray = cJSON_CreateArray();
#else
	nnJSObject = cJSON_CreateObject();
	cJSON_AddItemToObject(nnJSObject, "frame_id", cJSON_CreateNumber(frame_id));
	cJSON_AddItemToObject(nnJSObject, "filename", cJSON_CreateString(file_name));
	cJSON_AddItemToObject(nnJSObject, "objects", nn_obj_JSArray = cJSON_CreateArray());
#endif

	int im_w = roi_tester.img.width;
	int im_h = roi_tester.img.height;

	printf("object num = %d\r\n", res->obj_num);
	if (res->obj_num > 0) {
		for (int i = 0; i < res->obj_num; i++) {

			int top_x = (int)(res->result[6 * i + 2] * im_w) < 0 ? 0 : (int)(res->result[6 * i + 2] * im_w);
			int top_y = (int)(res->result[6 * i + 3] * im_h) < 0 ? 0 : (int)(res->result[6 * i + 3] * im_h);
			int bottom_x = (int)(res->result[6 * i + 4] * im_w) > im_w ? im_w : (int)(res->result[6 * i + 4] * im_w);
			int bottom_y = (int)(res->result[6 * i + 5] * im_h) > im_h ? im_h : (int)(res->result[6 * i + 5] * im_h);

			printf("%d,c%d,s%lf:(x0 y0 w h)%d %d %d %d\n\r", i, (int)(res->result[6 * i]), (float)res->result[6 * i + 1], top_x, top_y, bottom_x, bottom_y);
#if SAVE_COCO_FORMAT
			int w = bottom_x - top_x;
			int h = bottom_y - top_y;

			cJSON_AddItemToArray(nnJSArray, nn_obj_JSObject = cJSON_CreateObject());

			cJSON_AddItemToObject(nn_obj_JSObject, "image_id", cJSON_CreateNumber(frame_id));
			cJSON_AddItemToObject(nn_obj_JSObject, "category_id", cJSON_CreateNumber((int)res->result[6 * i ]));
			cJSON_AddItemToObject(nn_obj_JSObject, "bbox", nn_coor_JSArray = cJSON_CreateArray());
			cJSON_AddItemToObject(nn_obj_JSObject, "score", cJSON_CreateNumber((float)res->result[6 * i + 1]));
			cJSON_AddItemToArray(nn_coor_JSArray, cJSON_CreateNumber(top_x));
			cJSON_AddItemToArray(nn_coor_JSArray, cJSON_CreateNumber(top_y));
			cJSON_AddItemToArray(nn_coor_JSArray, cJSON_CreateNumber(w));
			cJSON_AddItemToArray(nn_coor_JSArray, cJSON_CreateNumber(h));
#else
			cJSON_AddItemToArray(nn_obj_JSArray, nn_obj_JSObject = cJSON_CreateObject());
			cJSON_AddItemToObject(nn_obj_JSObject, "class_id", cJSON_CreateNumber((int)res->result[6 * i ]));
			cJSON_AddItemToObject(nn_obj_JSObject, "name", cJSON_CreateString(NN_DATASET_LABEL[(int)res->result[6 * i ]]));
			cJSON_AddItemToObject(nn_obj_JSObject, "relative_coordinates", nn_coor_JSObject = cJSON_CreateObject());
			cJSON_AddItemToObject(nn_coor_JSObject, "top_x", cJSON_CreateNumber(top_x));
			cJSON_AddItemToObject(nn_coor_JSObject, "top_y", cJSON_CreateNumber(top_y));
			cJSON_AddItemToObject(nn_coor_JSObject, "bottom_x", cJSON_CreateNumber(bottom_x));
			cJSON_AddItemToObject(nn_coor_JSObject, "bottom_y", cJSON_CreateNumber(bottom_y));

			cJSON_AddItemToObject(nn_obj_JSObject, "probability", cJSON_CreateNumber((float)res->result[6 * i + 1]));
#endif
		}
	}
#if SAVE_COCO_FORMAT
	nn_json_string = cJSON_Print(nnJSArray);
	cJSON_Delete(nnJSArray);
#else
	nn_json_string = cJSON_Print(nnJSObject);
	cJSON_Delete(nnJSObject);
#endif
	return nn_json_string;
}

static int saver_count = 0;
static int (*media_save_file)(char *file_name, char *data_buf, int data_buf_size) = sd_save_file;

//char *str1 = "coco_val2017_pro2/image-0001.jpg";  --> return 1
//char *str2 = "coco_val2017_pro2/000000425131.jpg";  --> return 425131
static int get_id_in_filename(char *str)
{
	int pos_slash = strrchr(str, '/') - str;
	int pos_dash = strrchr(str, '-') - str;
	int start_pos = pos_dash > pos_slash ? pos_dash + 1 : pos_slash + 1;

	int pos_dot = strrchr(str, '.') - str;
	int len = pos_dot - start_pos;

	char image_id[32];
	memset(&image_id[0], 0x00, sizeof(image_id));
	strncpy(image_id, &str[start_pos], len);

	printf("image_id = %s\n", image_id);

	return (int)strtol(image_id, NULL, 10);
}

//char *str1 = "coco_val2017_pro2/000000425131.jpg";  --> return "coco_val2017_pro2/000000425131"
static char *strip_filename_extention(char *filename)
{
	char *end = filename + strlen(filename);

	while (end > filename && *end != '.') {
		--end;
	}

	if (end > filename) {
		*end = '\0';
	}
	return filename;
}

static void nn_save_handler_for_evaluate(char *file_name, uint32_t data_addr, uint32_t data_size)
{
	vipnn_out_buf_t pre_tensor_out;
	memcpy(&pre_tensor_out, (vipnn_out_buf_t *)data_addr, data_size);

	char nn_fn[128];
	memset(&nn_fn[0], 0x00, sizeof(nn_fn));

	int image_id = get_id_in_filename(file_name);

	/* save yolo json result */
	snprintf(nn_fn, sizeof(nn_fn), "%s.json", strip_filename_extention(file_name));
	char *json_format_out = nn_get_json_format(&pre_tensor_out.vipnn_res, image_id, nn_fn);
	//printf("\r\njson_format_out: %s\r\n", json_format_out);
	media_save_file(nn_fn, json_format_out, strlen(json_format_out));

	/* save tensor */
#if 0
	for (int i = 0; i < pre_tensor_out.vipnn_out_tensor_num; i++) {

		/* save raw tensor */
		memset(&nn_fn[0], 0x00, sizeof(nn_fn));
		snprintf(nn_fn, sizeof(nn_fn), "%s/nn_result/nn_out_tensor%d_uint8_%d.bin", folder_name, i, image_id);
		media_save_file(nn_fn, (char *)pre_tensor_out.vipnn_out_tensor[i], pre_tensor_out.vipnn_out_tensor_size[i]); /* raw tensor*/

		/* save float32 tensor */
		memset(&nn_fn[0], 0x00, sizeof(nn_fn));
		snprintf(nn_fn, sizeof(nn_fn), "%s/nn_result/nn_out_tensor%d_float32_%d.bin", folder_name, i, image_id);
		float *float_tensor;
		switch (pre_tensor_out.quant_format[i]) {
		case VIP_BUFFER_QUANTIZE_TF_ASYMM:   /* uint8 --> float32 */
			float_tensor = (float *)malloc((int)(pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float)));
			for (int k = 0; k < pre_tensor_out.vipnn_out_tensor_size[i]; k++) {
				float_tensor[k] = (*((uint8_t *)pre_tensor_out.vipnn_out_tensor[i] + k) - pre_tensor_out.quant_data[i].affine.zeroPoint) *
								  pre_tensor_out.quant_data[i].affine.scale;
			}
			media_save_file(nn_fn, (char *)float_tensor, pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float));
			break;
		case VIP_BUFFER_QUANTIZE_DYNAMIC_FIXED_POINT:   /* int16 --> float32 */
			float_tensor = (float *)malloc((int)(pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float) / sizeof(int16_t)));
			for (int k = 0; k < (pre_tensor_out.vipnn_out_tensor_size[i] / sizeof(int16_t)); k++) {
				float_tensor[k] = (float)(*((int16_t *)pre_tensor_out.vipnn_out_tensor[i] + k)) / ((float)(1 << pre_tensor_out.quant_data[i].dfp.fixed_point_pos));
			}
			media_save_file(nn_fn, (char *)float_tensor, pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float) / sizeof(int16_t));
			break;
		default:   /* float16 --> float32 */
			float_tensor = (float *)malloc(pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float) / sizeof(__fp16));
			for (int k = 0; k < (pre_tensor_out.vipnn_out_tensor_size[i] / sizeof(__fp16)); k++) {
				float_tensor[k] = (float)(*((__fp16 *)pre_tensor_out.vipnn_out_tensor[i] + k));
			}
			media_save_file(nn_fn, (char *)float_tensor, pre_tensor_out.vipnn_out_tensor_size[i] * sizeof(float) / sizeof(__fp16));
		}
		free(float_tensor);
	}
#endif

	saver_count++;
}

/*-----------------------------------------------------------------------------------*/

static int sd_save_file(char *file_name, char *data_buf, int data_buf_size)
{
	char fn[128];
	snprintf(fn, sizeof(fn), "%s%s", "sd:/", file_name);

	FILE *fp;
	fp = fopen(fn, "wb+");
	if (fp == NULL) {
		printf("fail to open file.\r\n");
		return -1;
	}
	fwrite(data_buf, data_buf_size, 1, fp);
	fclose(fp);

	printf("save file to %s\r\n", fn);

	return 0;
}
