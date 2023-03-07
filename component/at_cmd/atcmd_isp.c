#include <platform_stdlib.h>
#include <platform_opts.h>
#include <build_info.h>
#include "log_service.h"
#include "atcmd_isp.h"
#include "main.h"
#include "flash_api.h"
#include "hal_osd_util.h"
#include "hal_md_util.h"
#include "hal_video.h"
#include "osd/osd_custom.h"
#include "osd/osd_api.h"
#include "video_api.h"

#if CONFIG_TUNING
#include "../example/media_uvcd/example_media_uvcd.h"
#include "isp_ctrl_api.h"
#include "module_video.h"
#include "../../usb/usb_class/device/class/uvc/tuning-server.h"
#endif

#define ENABLE_OSD_CMD 0

//-------- AT SYS commands ---------------------------------------------------------------
#define CMD_DATA_SIZE 65536

void myTaskDelay(uint32_t delay_ms)
{
	//vTaskDelay(delay_ms);
}
void fATIT(void *arg)
{
#if 1
	int i;
	int ccmd;
	int value;
	char *cmd_data;
	struct isp_tuning_cmd *iq_cmd;
	int argc = 0;
	char *argv[MAX_ARGC] = {0};

	if (!arg) {
		return;
	}


	argc = parse_param(arg, argv);
	if (argc < 1) {	// usage
		printf("iqtun cmd\r\n");
		printf("      0: rts_isp_tuning_get_iq\n");
		printf("      1 : rts_isp_tuning_set_iq\r\n");
		printf("      2 : rts_isp_tuning_get_statis\r\n");
		printf("      3 : rts_isp_tuning_get_param\r\n");
		printf("      4 : rts_isp_tuning_set_param\r\n");
		return;
	}
	ccmd = atoi(argv[1]);

	cmd_data = malloc(CMD_DATA_SIZE);
	if (cmd_data == NULL) {
		printf("malloc cmd buf fail\r\n");
		return;
	}
	iq_cmd = (struct isp_tuning_cmd *)cmd_data;

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
	} else if (ccmd == 11) {
		iq_cmd->addr = atoi(argv[1]);
		iq_cmd->len  = atoi(argv[2]);
		hal_video_isp_tuning(VOE_ISP_TUNING_READ_VREG, iq_cmd);
		for (i = 0; i < iq_cmd->len; i++) {
			printf("virtual reg[%d]: 0x02%X.\r\n", i, iq_cmd->data[i]);
		}
		iq_cmd->data[i] = atoi(argv[3 + i]);
	} else if (ccmd == 12) {
		iq_cmd->addr = atoi(argv[1]);
		iq_cmd->len  = atoi(argv[2]);
		for (i = 0; i < iq_cmd->len; i++) {
			iq_cmd->data[i] = atoi(argv[3 + i]);
		}
		hal_video_isp_tuning(VOE_ISP_TUNING_WRITE_VREG, iq_cmd);
	}

	if (ccmd >= 0 && ccmd <= 4) {
		myTaskDelay(300);
		printf("len = %d.\r\n", iq_cmd->len);
	}

	if (cmd_data) {
		free(cmd_data);
	}

#else
	int type;
	int set_flag;
	int table_type;
	int set_value;
	int print_addr;
	int ret;
	int i;
	struct isp_tuning_cmd *cmd = (struct isp_tuning_cmd *)malloc(65536);
	int argc = 0;
	char *argv[MAX_ARGC] = {0};

	if (!arg) {
		return;
	}

	argc = parse_param(arg, argv);

	table_type = atoi(argv[1]);
	set_flag = atoi(argv[2]);
	type = atoi(argv[3]);
	print_addr = atoi(argv[4]);
	cmd->addr = type;
	printf("print_addr:%d  table_type:%d  set_flag:%d  cmd->addr=%d.\r\n", print_addr, table_type, set_flag, cmd->addr);
	if (argc >= 3) {
		if (table_type == 0) {
			//ISP_TUNING_IQ_TABLE_ALL
			if (set_flag == 0) {
				hal_video_isp_tuning(VOE_ISP_TUNING_GET_IQ, cmd);
			} else {
				hal_video_isp_tuning(VOE_ISP_TUNING_SET_IQ, cmd);
			}
		} else if (table_type == 1) {
			//ISP_TUNING_STATIS_ALL
			if (set_flag == 0) {
				hal_video_isp_tuning(VOE_ISP_TUNING_GET_STATIS, cmd);
			}
		} else if (table_type == 2) {
			//ISP_TUNING_PARAM_ALL
			if (set_flag == 0) {
				hal_video_isp_tuning(VOE_ISP_TUNING_GET_PARAM, cmd);
			} else {
				hal_video_isp_tuning(VOE_ISP_TUNING_SET_PARAM, cmd);
			}
		}
		myTaskDelay(50);
		printf("len = %d.\r\n", cmd->len);
		if (print_addr) {
			for (i = 0; i < cmd->len; i++) {
				if (i > 0 && i % 16 == 0) {
					printf("\r\n");
				}
				printf("0x%02X,", cmd->data[i]);
			}
		}
	}
	free(cmd);
#endif
}
void fATIC(void *arg)
{
	int i;
	int set_flag;
	int ret;
#if 1
	int id;
	int set_value;
	int argc = 0;
	char *argv[MAX_ARGC] = {0};

	if (!arg) {
		return;
	}

	argc = parse_param(arg, argv);

	if (argc >= 2) {
		set_flag = atoi(argv[1]);
		id = atoi(argv[2]);
		printf("[isp ctrl] set_flag:%d  id:%d.\r\n", set_flag, id);
		if (set_flag == 0) {
			hal_video_isp_ctrl(id, set_flag, &ret);
			if (ret != -1) {
				printf("result 0x%08x %d \r\n", ret, ret);
			} else {
				printf("isp_ctrl get error\r\n");
			}
		} else {

			if (argc >= 3) {
				hal_video_isp_ctrl(id, 0, &ret);
				if (ret != -1) {
					printf("before set result 0x%08x %d \r\n", ret, ret);
					myTaskDelay(20);
					set_value = atoi(argv[3]);
					printf("[isp ctrl] set_value:%d.\r\n", set_value);

					ret = hal_video_isp_ctrl(id, set_flag, &set_value);
					if (ret != 0) {
						printf("isp_ctrl set error\r\n");
					} else {
						myTaskDelay(20);
						hal_video_isp_ctrl(id, 0, &ret);
						if (ret != -1) {
							printf("check result 0x%08x %d \r\n", ret, ret);
						} else {
							printf("isp_ctrl get error\r\n");
						}
					}
				} else {
					printf("isp_ctrl get error\r\n");
				}

			} else {
				printf("isp_ctrl set error : need 3 argument: set_flag id  set_value\r\n");
			}
		}

	} else {
		printf("isp_ctrl  error : need 2~3 argument: set_flag id  [set_value] \r\n");
	}
#else
	printf("\r\n[ISP_CTRL_TEST GET]\r\n");
	set_flag = 0;
	int aRet[64];
	int test_value;
	for (i = 0; i < 44; i++) {
		aRet[i] = hal_video_isp_ctrl(i, set_flag, NULL);
		myTaskDelay(50);
	}
	myTaskDelay(1000);
	for (i = 0; i < 44; i++) {
		if (aRet[i] != -1) {
			printf("\r\n[RESULT ID %d]: 0x%08x %d ", i, aRet[i], aRet[i]);
		} else {
			printf("\r\n[RESULT ID %d]: GET_ERROR", i);
		}
	}
	myTaskDelay(1000);
	printf("\r\n\r\n[ISP_CTRL_TEST SET]\r\n");
	set_flag = 1;
	for (i = 0; i < 44; i++) {
		if (aRet[i] == 0) {
			test_value = 1;
		} else if (aRet[i] == 1) {
			test_value = 0;
		} else {
			test_value = aRet[i] + 1;
		}
		aRet[i] = hal_video_isp_ctrl(i, set_flag, test_value);
		myTaskDelay(50);
	}
	myTaskDelay(1000);
	for (i = 0; i < 44; i++) {
		if (aRet[i] != 0) {
			printf("\r\n[RESULT ID %d]: SET_ERROR", i);
		} else {
			printf("\r\n[RESULT ID %d]: SET_SUCCESS", i);
		}
	}










	myTaskDelay(1000);
	printf("\r\n[ISP_CTRL_TEST GET]\r\n");
	set_flag = 0;
	for (i = 0; i < 28; i++) {
		aRet[i] = hal_video_isp_ctrl(i + 0xF000, set_flag, NULL);
		myTaskDelay(50);
	}
	myTaskDelay(1000);
	for (i = 0; i < 28; i++) {
		if (aRet[i] != -1) {
			printf("\r\n[RESULT ID %d]: 0x%08x %d ", i, aRet[i], aRet[i]);
		} else {
			printf("\r\n[RESULT ID %d]: GET_ERROR", i);
		}
	}


	myTaskDelay(1000);
	printf("\r\n\r\n[ISP_CTRL_TEST SET]\r\n");
	set_flag = 1;
	for (i = 0; i < 28; i++) {
		if (aRet[i] == 0) {
			test_value = 1;
		} else if (aRet[i] == 1) {
			test_value = 0;
		} else {
			test_value = aRet[i] + 1;
		}
		aRet[i] = hal_video_isp_ctrl(i + 61440, set_flag, test_value);
		myTaskDelay(50);
	}
	myTaskDelay(1000);
	for (i = 0; i < 28; i++) {
		if (aRet[i] != 0) {
			printf("\r\n[RESULT ID %d]: SET_ERROR", i);
		} else {
			printf("\r\n[RESULT ID %d]: SET_SUCCESS", i);
		}
	}
#endif
}
void fATIX(void *arg)
{
	int i;
	int argc = 0;
	int addr = 0;
	int num = 0;
	int value32 = 0;
	short value16 = 0;
	char value8  = 0;
	char *argv[MAX_ARGC] = {0};

	if (!arg) {
		return;
	}

	argc = parse_param(arg, argv);
	if (strcmp(argv[1], "help") == 0) {
		printf("[ATIX] Usage: ATIX=FUNCTION,ADDRESS,NUMBER,VALUE1,VALUE2...\r\n");
		printf("--FUNCTION: read32,write32,read16,write16,read8,write8.\r\n");
		printf("--ADDRESS : register address.(2 bytes,exclude base-address)\r\n");
		printf("--NUMBER  : number of value.\r\n");
		printf("--VALUE#  : necessary if FUNCTION=write32, write16 or write8.\r\n");
	}

	num  = atoi(argv[3]);
	if (num <= 0) {
		return;
	}

	addr = atoi(argv[2]);
	if (strcmp(argv[1], "read32") == 0) {

		printf("[ISP]register read addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			printf("0x%X \r\n", HAL_READ32(0x40300000, addr + 4 * i));
		}
		printf("\r\n");
	} else if (strcmp(argv[1], "write32") == 0) {

		printf("[ISP]register write addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			value32 = atoi(argv[4 + i]);
			if ((addr + 4 * i) == 0x05bf4) {
				if (value32 == 1) {
					printf("Enter TNR Debug Mode.\r\n");
					HAL_WRITE32(0x40300000, 0x00004, 0x1f3bf);
					myTaskDelay(5);
					HAL_WRITE32(0x40300000, 0x05800, 0x4f);
					myTaskDelay(5);
					HAL_WRITE32(0x40300000, 0x05bf4, 0x0e);
					myTaskDelay(5);
					HAL_WRITE32(0x40300000, 0x00004, 0x3f3bf);
					myTaskDelay(5);
					HAL_WRITE32(0x40300000, 0x05800, 0x5f);
				} else {
					HAL_WRITE32(0x40300000, (addr + 4 * i), value32);
				}
			}
			printf("0x%X \r\n", value32);
		}
		printf("\r\n");
	} else if (strcmp(argv[1], "read16") == 0) {

		printf("[ISP]register read addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			printf("0x%X \r\n", HAL_READ16(0x40300000, addr + 2 * i));
		}
		printf("\r\n");
	} else if (strcmp(argv[1], "write16") == 0) {

		printf("[ISP]register write addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			value16 = (short)atoi(argv[4 + i]);
			HAL_WRITE16(0x40300000, (addr + 2 * i), value16);
			printf("0x%X \r\n", value16);
		}
		printf("\r\n");
	} else if (strcmp(argv[1], "read8") == 0) {

		printf("[ISP]register read addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			printf("0x%X \r\n", HAL_READ8(0x40300000, addr + 1 * i));
		}
		printf("\r\n");
	} else if (strcmp(argv[1], "write8") == 0) {

		printf("[ISP]register write addr from 0x%X:\r\n", 0x40300000 | addr);
		for (i = 0; i < num; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\r\n");
			}
			value8 = (char)atoi(argv[4 + i]);
			HAL_WRITE8(0x40300000, (addr + 1 * i), value8);
			printf("0x%X \r\n", value8);
		}
		printf("\r\n");
	}
}

#include "isp_ctrl_api.h"
#include "ftl_common_api.h"
void fATII(void *arg)
{
	int i;
	int argc = 0;
	char *argv[MAX_ARGC] = {0};
	int stream_id = 0;
	int bayer_index = 0;

	if (!arg) {
		return;
	}

	argc = parse_param(arg, argv);

	if (argc < 1) {
		return;
	}

	if (strcmp(argv[1], "bayer") == 0) {
		stream_id = atoi(argv[2]);
		bayer_index = atoi(argv[3]);
		if (bayer_index < 0 || bayer_index > 9) {
			return;
		}
		if (bayer_index == 7 || bayer_index == 8 || bayer_index == 9) {
			HAL_WRITE32(0x50000000, 0x0918, 0x3733);
		}
		hal_video_isp_set_rawfmt(stream_id, bayer_index);
	} else if (strcmp(argv[1], "gray") == 0) {
		int mode = -1;
		isp_set_gray_mode(atoi(argv[2]));
		isp_get_gray_mode(&mode);
		printf("isp gray mode: %d.\r\n", mode);
#if CONFIG_TUNING
	} else if (strcmp(argv[1], "log") == 0) {
		extern void tuning_set_log_level(int level);
		if (strcmp(argv[2], "all") == 0) {
			hal_video_print(atoi(argv[3]));
			isp_ctrl_enable_log(atoi(argv[3]));
			printf("log-all: %d.\r\n", atoi(argv[3]));
		} else if (strcmp(argv[2], "voe") == 0) {
			hal_video_print(atoi(argv[3]));
			printf("log-voe: %d.\r\n", atoi(argv[3]));
		} else if (strcmp(argv[2], "ispctrl") == 0) {
			isp_ctrl_enable_log(atoi(argv[3]));
			printf("log-ispctrl: %d.\r\n", atoi(argv[3]));
		} else if (strcmp(argv[2], "tuning") == 0) {
			tuning_set_log_level(atoi(argv[3]));
			printf("log-tuning: %d.\r\n", atoi(argv[3]));
		}
	} else if (strcmp(argv[1], "delay") == 0) {
		int is_tuning_delay;
		extern void tuning_command_delay(int enable);
		is_tuning_delay = atoi(argv[2]);
		tuning_command_delay(is_tuning_delay);
		printf("is_tuning_delay: %d.\r\n", is_tuning_delay);
	} else if (strcmp(argv[1], "v2") == 0) {
		example_tuning_rtsp_video_v2_init();
	} else if (strcmp(argv[1], "fps") == 0) {
		if (strcmp(argv[2], "show") == 0) {
			video_show_fps(1);
		} else if (strcmp(argv[2], "hide") == 0) {
			video_show_fps(0);
		}
	} else if (strcmp(argv[1], "flash") == 0) {
		int fw_size = 0;
		unsigned char iq_header[28] = {0};
		if (strcmp(argv[2], "read") == 0) {
			ftl_common_read(TUNING_IQ_FW, (u8 *) &fw_size, sizeof(int));
			printf("IQ FW size: 0x%04X.\r\n", fw_size);
		} else if (strcmp(argv[2], "timestamp") == 0) {
			ftl_common_read(TUNING_IQ_FW, (u8 *) iq_header, 28);
			int *diq_header = (int *)(iq_header + 8);
			printf("IQ header: 0x%08X 0x%08X 0x%08X 0x%08X.\r\n", diq_header[0], diq_header[1], diq_header[2], diq_header[3]);
			printf("iq timestamp: %04d/%02d/%02d %02d:%02d:%02d\r\n", *(unsigned short *)(iq_header + 12), iq_header[14], iq_header[15], iq_header[16],
				   iq_header[17], *(unsigned short *)(iq_header + 18));
		} else if (strcmp(argv[2], "erase") == 0) {
			if (strcmp(argv[3], "ap") == 0) {
				extern int Erase_Fastconnect_data(void);
				Erase_Fastconnect_data();
				printf("[ATII] erase AP info.\r\n");
			} else {
				int *iq_tmp = malloc(CMD_DATA_SIZE * 4);
				if (iq_tmp) {
					memset(iq_tmp, 0, CMD_DATA_SIZE * 4);
					ftl_common_write(TUNING_IQ_FW, (u8 *)iq_tmp, CMD_DATA_SIZE * 4);
					printf("[ATII] erase 256K..Done.\r\n");
					free(iq_tmp);
				}
			}
		}
		printf("[atcmd_isp] not CONFIG_TUNING.\r\n");
	} else if (strcmp(argv[1], "meta") == 0) {
		extern isp_statis_meta_t _meta;
		isp_statis_meta_t jmeta = _meta;
		printf("[%s]exposure_h:%d exposure_l:%d\r\n", __FUNCTION__, jmeta.exposure_h, jmeta.exposure_l);
		printf("[%s]gain_h:%d gain_l:%d\r\n", __FUNCTION__, jmeta.gain_h, jmeta.gain_l);
		printf("[%s]wb_r_gain:%d wb_b_gain:%d wb_g_gain:%d\r\n", __FUNCTION__, jmeta.wb_r_gain, jmeta.wb_b_gain, jmeta.wb_g_gain);
		printf("[%s]colot_temperature:%d\r\n", __FUNCTION__, jmeta.colot_temperature);
		printf("[%s]y_average:%d\r\n", __FUNCTION__, jmeta.y_average);
		printf("[%s]white_num:%d\r\n", __FUNCTION__, jmeta.white_num);
		printf("[%s]rg_sum:%d bg_sum:%d\r\n", __FUNCTION__, jmeta.rg_sum, jmeta.bg_sum);
		printf("[%s]hdr_mode:%d\r\n", __FUNCTION__, jmeta.hdr_mode);
		printf("[%s]sensor_fps:%d max_fps:%d\r\n", __FUNCTION__, jmeta.sensor_fps, jmeta.max_fps);
		printf("[%s]frame_count:%d\r\n", __FUNCTION__, jmeta.frame_count);
		printf("[%s]time_stamp:%d\r\n", __FUNCTION__, jmeta.time_stamp);
		printf("[%s]rmean:%d gmean:%d bmean:%d\r\n", __FUNCTION__, jmeta.rmean, jmeta.gmean, jmeta.bmean);
#endif
	} else if (strcmp(argv[1], "i2c") == 0) {
		struct rts_isp_i2c_reg reg;
		int ret;
		reg.addr = atoi(argv[3]);
		if (strcmp(argv[2], "read") == 0) {
			reg.data = 0;
			ret = hal_video_i2c_read(&reg);
			printf("ret: %d, read addr:0x%04X, data:0x%04X.\r\n", ret, reg.addr, reg.data);
		} else if (strcmp(argv[2], "write") == 0) {
			reg.data = atoi(argv[4]);
			printf("write addr:0x%04X, data:0x%04X.\r\n", reg.addr, reg.data);
			ret = hal_video_i2c_write(&reg);
			printf("ret: %d, .\r\n", ret);

			reg.data = 0;
			ret = hal_video_i2c_read(&reg);
			printf("ret: %d, read addr:0x%04X, data:0x%04X.\r\n", ret, reg.addr, reg.data);
		}
	} else if (strcmp(argv[1], "info") == 0) {
		if (strcmp(argv[2], "af") == 0) {
			af_statis_t af_result;
			int ret = hal_video_get_AF_statis(&af_result);
			if (!ret) {
				printf("fr %d af0 %d %d af1 %d %d\n", af_result.frame_count, af_result.sum0, af_result.num0, af_result.sum1, af_result.num1);
			} else {
				printf("get info fail hal_video_get_AF_statis.\r\n");
			}
		} else if (strcmp(argv[2], "ae") == 0) {
			ae_statis_t ae_result;
			int ret = hal_video_get_AE_statis(&ae_result);
			if (!ret) {
#if 0
				printf("fr %d ae win %d #0 %d #15 %d #119 %d #136 %d #240 %d #255 %d\n", \
					   ae_result.frame_count, ae_result.win_cnt, ae_result.y_mean[0], ae_result.y_mean[15], \
					   ae_result.y_mean[119], ae_result.y_mean[136], ae_result.y_mean[240], ae_result.y_mean[255]);
#else
				printf("fr %d ae win %d \n", ae_result.frame_count, ae_result.win_cnt);
				for (int j = 0; j < 16; j += 3) {
					for (int k = 0; k < 16; k += 3) {
						dbg_printf("%d ", ae_result.y_mean[j * 16 + k]);
					}
					dbg_printf("\n");
				}
#endif
			} else {
				printf("get info fail hal_video_get_AE_statis.\r\n");
			}
		} else if (strcmp(argv[2], "awb") == 0) {
			awb_statis_t awb_result;
			int ret = hal_video_get_AWB_statis(&awb_result);
			if (!ret) {
#if 0
				printf("r %d %d g %d %d n %d %d \n", \
					   awb_result.r_mean[119], awb_result.r_mean[136], awb_result.g_mean[119], awb_result.g_mean[136], awb_result.b_mean[119], awb_result.b_mean[136]);
#else
				printf("awb r \n");
				for (int j = 0; j < 16; j += 3) {
					for (int k = 0; k < 16; k += 3) {
						dbg_printf("%d ", awb_result.r_mean[j * 16 + k]);
					}
					dbg_printf("\n");
				}
				printf("awb g \n");
				for (int j = 0; j < 16; j += 3) {
					for (int k = 0; k < 16; k += 3) {
						dbg_printf("%d ", awb_result.g_mean[j * 16 + k]);
					}
					dbg_printf("\n");
				}
				printf("awb b \n");
				for (int j = 0; j < 16; j += 3) {
					for (int k = 0; k < 16; k += 3) {
						dbg_printf("%d ", awb_result.b_mean[j * 16 + k]);
					}
					dbg_printf("\n");
				}

#endif
			} else {
				printf("get info fail hal_video_get_AWB_statis.\r\n");
			}
		}
	} else {

	}

}


#include "../video/osd2/isp_osd_example.h"
#include "osd_api.h"
#include <sntp/sntp.h>
void fATIO(void *arg)
{
#if ENABLE_OSD_CMD
	int argc = 0;
	char *argv[MAX_ARGC] = {0};
	argc = parse_param(arg, argv);
	if (strcmp(argv[1], "size") == 0) {
		rts_set_char_size(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
	} else if (strcmp(argv[1], "block") == 0) {
		if (atoi(argv[4]) == 1) {
			rts_osd_block_show(atoi(argv[2]), atoi(argv[3]));
		} else {
			rts_osd_block_hide(atoi(argv[2]), atoi(argv[3]));
		}
	} else if (strcmp(argv[1], "task") == 0) {
		example_isp_osd(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
	} else if (strcmp(argv[1], "timezone") == 0) {
		rts_osd_set_timezone(atoi(argv[2]));
		printf("Current time-zone:%d.\r\n", rts_osd_get_timezone());
	} else if (strcmp(argv[1], "close") == 0) {
		rts_osd_deinit(atoi(argv[2]));
	}
#endif
}

#include "sensor_service.h"
void fATIR(void *arg)
{
	volatile int argc, error_no = 0;
	char *argv[MAX_ARGC] = {0};
	int mode;

	if (!arg) {
		AT_DBG_MSG(AT_FLAG_WIFI, AT_DBG_ERROR,
				   "\r\n[ATPW] Usage : ATPW=<mode>");
		error_no = 1;
		goto EXIT;
	}

	argc = parse_param(arg, argv);


	// Init LED control pin
	if (strcmp(argv[1], "init") == 0) {
		ir_cut_init(NULL);
		ir_ctrl_init(NULL);
		ambient_light_sensor_init(NULL);
		ambient_light_sensor_power(1);
		printf("ir_cut_init/ir_ctrl_init/ambient_light_sensor_init.\r\n");
	} else if (strcmp(argv[1], "enable") == 0) {
		mode = atoi(argv[2]);
		if (mode == 1) {
			ir_cut_enable(0);
			vTaskDelay(1000);
			ir_cut_enable(1);
			printf("IR Cut On\r\n");
		} else if (mode == 0) {
			ir_cut_enable(1);
			vTaskDelay(1000);
			ir_cut_enable(0);
			printf("IR Cut Off\r\n");
		}
	} else if (strcmp(argv[1], "getlight") == 0) {
		int lux = ambient_light_sensor_get_lux(0);
		printf("light_sensor: %d \r\n", lux);
	} else if (strcmp(argv[1], "setlight") == 0) {
		int dValue1 = atoi(argv[2]);
		float fBright = (float)dValue1 / 100.0f;
		if (dValue1 > 100) {
			dValue1 = 100;
		}
		if (dValue1 < 0) {
			dValue1 = 0;
		}

		printf("led_brightness: %f \r\n", fBright);
		ir_ctrl_set_brightness(fBright);
		ir_ctrl_set_brightness_d(dValue1);
	} else if (strcmp(argv[1], "service") == 0) {
		init_sensor_service();
	}

	return;
EXIT:
	printf("error at command format\r\n");
}

void fATIM(void *arg)
{
	volatile int argc, error_no = 0;
	char *argv[MAX_ARGC] = {0};
	int mode;

	if (!arg) {
		AT_DBG_MSG(AT_FLAG_WIFI, AT_DBG_ERROR,
				   "\r\n[ATPW] Usage : ATPW=<mode>");
		error_no = 1;
		goto EXIT;
	}

	argc = parse_param(arg, argv);

	struct private_mask_s pr_mask;
	//=ch,en,grid_mode,id,startx,starty,w,h,color,cols,rows  0,1,1,1,100,100,960,540,0x00FF00,32,18
	printf("[%s] ATIM=ch,en,grid_mode,id,startx,starty,w,h,color,cols,rows \r\n");
	pr_mask.en = atoi(argv[2]);
	pr_mask.grid_mode = atoi(argv[3]);
	pr_mask.id = atoi(argv[4]);//0~3 only for rect-mode
	pr_mask.color = atoi(argv[9]);//BBGGRR
	pr_mask.start_x = atoi(argv[5]);//2-align
	pr_mask.start_y = atoi(argv[6]);//2-align
	pr_mask.w = atoi(argv[7]);//16-align when grid-mode
	pr_mask.h = atoi(argv[8]);
	pr_mask.cols = atoi(argv[10]);//8 align
	pr_mask.rows = atoi(argv[11]);
	memset(pr_mask.bitmap, 0xAA, 160);
	video_set_private_mask(atoi(argv[1]), &pr_mask);

	return;
EXIT:
	printf("error at command format\r\n");
}

void ISP_Enable(unsigned char Value)
{
	if(Value == 0)
	{
		HAL_WRITE32(0x40300000, 0x00004, 0x00382);	//23a2
		HAL_WRITE32(0x40300000, 0x00008, 0x03);
		printf("ISP:Off\r\n");
	}
	else if(Value == 1)
	{
		HAL_WRITE32(0x40300000, 0x00004, 0x3F3BF);
		HAL_WRITE32(0x40300000, 0x00008, 0x07);
		printf("ISP:On\r\n");
	}
}

void fATIE(void *arg)
{
	volatile int argc;
	char *argv[MAX_ARGC] = {0};
	int mode;
	argc = parse_param(arg, argv);
	mode = atoi(argv[1]);
	ISP_Enable(mode);
}

log_item_t at_isp_items[] = {
	{"ATIT", fATIT,},
	{"ATIC", fATIC,},
	{"ATIX", fATIX,},
	{"ATII", fATII,},
	{"ATIO", fATIO,},
	{"ATIR", fATIR,},
	{"ATIM", fATIM,},
	{"ATIE", fATIE,},
};

void at_isp_init(void)
{
	log_service_add_table(at_isp_items, sizeof(at_isp_items) / sizeof(at_isp_items[0]));
}

#if SUPPORT_LOG_SERVICE
log_module_init(at_isp_init);
#endif
