/******************************************************************************
*
* Copyright(c) 2007 - 2018 Realtek Corporation. All rights reserved.
*
******************************************************************************/
#include <FreeRTOS.h>
#include <task.h>
#include "platform_opts.h"

#ifndef CONFIG_PLATFORM_8735B
#include "platform_autoconf.h"
#endif

#include "usb.h"
#include "msc/inc/usbd_msc_config.h"
#include "msc/inc/usbd_msc.h"
#include "fatfs_ramdisk_api.h"

#if SAVE_AUDIO_DATA
#include "audio_tool_command.h"
#endif
#include "audio_tool_init.h"

#define AUDIO_TRANSFER_FUNC 0

#if AUDIO_TRANSFER_FUNC
void audio_data_transfer(void *param)
{
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	char raw_path[64];
	char txt_path[64];
	uint8_t rBufferr;
	char tBufferr[10];
	FILE  *raw_record_file;
	FILE  *txt_record_file;
	char raw_record_filen[32] = "std1ktone_8kHz.raw";
	char txt_record_filen[32] = "std1ktone_8kHz.txt";
	int record_flag = 1;
	int total_read_count = 0;
	int total_write_count = 0;
	int br, bw;

	snprintf(raw_path, sizeof(raw_path), "audio_sd:/%s", raw_record_filen);
	printf("read file %s\r\n", raw_path);
	raw_record_file = fopen(raw_path, "r");
	if (!raw_record_file) {
		printf("Open SD file failed\r\n");
		goto exit;
	}
	snprintf(txt_path, sizeof(txt_path), "audio_sd:/%s", txt_record_filen);
	printf("txt file %s\r\n", txt_path);
	txt_record_file = fopen(txt_path, "w");
	if (!txt_record_file) {
		printf("Open SD file failed\r\n");
		fclose(raw_record_file);
		goto exit;
	}

	while (record_flag) {
		for (int i = 0; i < 160; i++) {

			br = fread(&rBufferr, 1, 1, raw_record_file);

			if (br <= 0) {
				printf("Read END\r\n");
				fclose(raw_record_file);
				fclose(txt_record_file);
				record_flag = 0;
				break;
			} else {
				int buffer_len = 0;
				total_read_count += br;
				memset(tBufferr, 0x0, 10);
				buffer_len = snprintf(tBufferr, 10, "0x%02x, ", rBufferr);
				if (i % 16 == 15) {
					printf("buffer_len = %d\r\n", buffer_len);
					tBufferr[buffer_len] = '\r';
					tBufferr[buffer_len + 1] = '\n';
					tBufferr[buffer_len + 2] = '\0';
				}
				bw = fwrite(tBufferr, 1, strlen(tBufferr), txt_record_file);

				if (bw <= 0) {
					printf("Write END\r\n");
					fclose(raw_record_file);
					fclose(txt_record_file);
					record_flag = 0;
					break;
				}
				total_write_count += bw;
			}
		}
		printf("total_read_count = %d, br = %d\r\n", total_read_count, br);
		printf("total_write_count = %d, bw = %d\r\n", total_write_count, bw);
		vTaskDelay(1);
	}
exit:
	vTaskDelete(NULL);
}
#endif

void audio_save_mass_storage_thread(void *param)
{
	int status = 0;
	struct msc_opts *disk_operation = NULL;
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	_usb_init();

	status = wait_usb_ready();
	if (status != USB_INIT_OK) {
		if (status == USB_NOT_ATTACHED) {
			printf("\r\n NO USB device attached\n");
		} else {
			printf("\r\n USB init fail\n");
		}
		goto exit;
	}

	disk_operation = malloc(sizeof(struct msc_opts));
	if (disk_operation == NULL) {
		printf("\r\n disk_operation malloc fail\n");
		goto exit;
	}

	disk_operation->disk_init = usb_ram_init;
	disk_operation->disk_deinit = usb_ram_deinit;
	disk_operation->disk_getcapacity = usb_ram_getcapacity;
	disk_operation->disk_read = usb_ram_readblocks;
	disk_operation->disk_write = usb_ram_writeblocks;

	// load usb mass storage driver
	status = usbd_msc_init(MSC_NBR_BUFHD, MSC_BUFLEN, disk_operation);

	if (status) {
		printf("USB MSC driver load fail.\n");
	} else {
		printf("USB MSC driver load done, Available heap [0x%x]\n", xPortGetFreeHeapSize());
	}

exit:
	vTaskDelete(NULL);
}

void audio_ram_sd_thread(void *param)
{
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	FILE  *m_ram_file;
	FILE  *m_sd_file;
	char ram_path[64];
	char sd_path[64];
	char ram_r_file[64];
	char sd_r_file[64];
	int br, bw;
	int16_t ramBufferr[RECORD_WORDS];
	int record_flag = 0;
	int total_read_count = 0;
	int total_write_count = 0;
	int transformcount = 0;
	int record_percent = 0;
	int type_select = 0;

	while (1) {
		if ((xSemaphoreTake(ram_dump_sd_sema, portMAX_DELAY) == pdTRUE) && (audiocopy_status & SD_SAVE_START)) {
			printf("Start trans data from ram to sd card\r\n");
			type_select = RECORD_MIN;

			while (type_select <= RECORD_MAX) {
				record_flag = 0;
				switch (type_select) {
				case RECORD_RX_DATA: {
					if (record_type & RECORD_RX_DATA) {
						record_flag = 1;
						//ram disk data
						snprintf(ram_r_file, 63, "%s_RX%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", ram_r_file);

						snprintf(ram_path, sizeof(ram_path), "audio_ram:/%s", ram_r_file);
						printf("RAM record file name: %s\n\r", ram_path);

						m_ram_file = fopen(ram_path, "r");
						if (!m_ram_file) {
							audiocopy_status &= ~SD_SAVE_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						//sd card data
						snprintf(sd_r_file, 63, "%s_RX%03d.wav", file_name, recored_count);
						printf("SD record file name: %s\n\r", sd_r_file);

						snprintf(sd_path, sizeof(sd_path), "audio_sd:/%s", sd_r_file);
						printf("SD record file name: %s\n\r", sd_path);

						m_sd_file = fopen(sd_path, "w");
						if (!m_sd_file) {
							printf("Open SD file failed\r\n");
							audiocopy_status &= ~SD_SAVE_START;
							fclose(m_ram_file);
							goto open_file_fail;
						}
					}
					break;
				}
				case RECORD_TX_DATA:
					if (record_type & RECORD_TX_DATA) {
						record_flag = 1;
						//ram disk data
						snprintf(ram_r_file, 63, "%s_TX%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", ram_r_file);

						snprintf(ram_path, sizeof(ram_path), "audio_ram:/%s", ram_r_file);
						printf("RAM record file name: %s\n\r", ram_path);

						m_ram_file = fopen(ram_path, "r");
						if (!m_ram_file) {
							audiocopy_status &= ~SD_SAVE_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						//sd card data
						snprintf(sd_r_file, 63, "%s_TX%03d.wav", file_name, recored_count);
						printf("SD record file name: %s\n\r", sd_r_file);

						snprintf(sd_path, sizeof(sd_path), "audio_sd:/%s", sd_r_file);
						printf("SD record file name: %s\n\r", sd_path);

						m_sd_file = fopen(sd_path, "w");
						if (!m_sd_file) {
							printf("Open SD file failed\r\n");
							audiocopy_status &= ~SD_SAVE_START;
							fclose(m_ram_file);
							goto open_file_fail;
						}
					}
					break;
				case RECORD_ASP_DATA:
					if (record_type & RECORD_ASP_DATA) {
						record_flag = 1;
						//ram disk data
						snprintf(ram_r_file, 63, "%s_ASP%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", ram_r_file);

						snprintf(ram_path, sizeof(ram_path), "audio_ram:/%s", ram_r_file);
						printf("RAM record file name: %s\n\r", ram_path);

						m_ram_file = fopen(ram_path, "r");
						if (!m_ram_file) {
							audiocopy_status &= ~SD_SAVE_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						//sd card data
						snprintf(sd_r_file, 63, "%s_ASP%03d.wav", file_name, recored_count);
						printf("SD record file name: %s\n\r", sd_r_file);

						snprintf(sd_path, sizeof(sd_path), "audio_sd:/%s", sd_r_file);
						printf("SD record file name: %s\n\r", sd_path);

						m_sd_file = fopen(sd_path, "w");
						if (!m_sd_file) {
							printf("Open SD file failed\r\n");
							audiocopy_status &= ~SD_SAVE_START;
							fclose(m_ram_file);
							goto open_file_fail;
						}
					}
					break;
				case RECORD_TXASP_DATA:
					if (record_type & RECORD_TXASP_DATA) {
						record_flag = 1;
						//ram disk data
						snprintf(ram_r_file, 63, "%s_TXASP%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", ram_r_file);

						snprintf(ram_path, sizeof(ram_path), "audio_ram:/%s", ram_r_file);
						printf("RAM record file name: %s\n\r", ram_path);

						m_ram_file = fopen(ram_path, "r");
						if (!m_ram_file) {
							audiocopy_status &= ~SD_SAVE_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						//sd card data
						snprintf(sd_r_file, 63, "%s_TXASP%03d.wav", file_name, recored_count);
						printf("SD record file name: %s\n\r", sd_r_file);

						snprintf(sd_path, sizeof(sd_path), "audio_sd:/%s", sd_r_file);
						printf("SD record file name: %s\n\r", sd_path);

						m_sd_file = fopen(sd_path, "w");
						if (!m_sd_file) {
							printf("Open SD file failed\r\n");
							audiocopy_status &= ~SD_SAVE_START;
							fclose(m_ram_file);
							goto open_file_fail;
						}
					}
					break;
				}

				total_write_count = 0;
				total_read_count = 0;
				transformcount = 0;
				record_percent = 0;
				printf("Transforming\r\n");
				//record loop
				while (record_flag) {
					if (((FRAME_LEN / RECORD_WORDS) * (record_frame_count)) >= 100) {
						if ((transformcount / (((FRAME_LEN / RECORD_WORDS) * (record_frame_count)) / 100)) >= (record_percent + 1)) {
							record_percent = (transformcount / (((FRAME_LEN / RECORD_WORDS) * (record_frame_count)) / 100));
							printf("*");
							if ((record_percent % 10) == 0) {
								printf(" %d%% is done!\n\r", record_percent);
							}
						}
					}
					transformcount ++;
					memset(ramBufferr, 0x0, RECORD_WORDS * 2);
					br = fread(ramBufferr, 1, RECORD_WORDS * 2, m_ram_file);
					if (br <= 0) {
						printf("\r\nRead END\r\n");
						printf("READ %d, WRITE: %d\r\n", total_read_count, total_write_count);
						fclose(m_ram_file);
						fclose(m_sd_file);
						record_flag = 0;
						break;
					} else {
						total_read_count += br;
						bw = fwrite(ramBufferr, 1, br, m_sd_file);

						if (bw <= 0) {
							printf("\r\nWrite END\r\n");
							printf("READ %d, WRITE: %d\r\n", total_read_count, total_write_count);
							fclose(m_ram_file);
							fclose(m_sd_file);
							record_flag = 0;
							break;
						}
						total_write_count += bw;
					}

					vTaskDelay(1);
				}
				type_select = type_select << 1;
			}
open_file_fail:
			printf("Start trans data from ram to sd card END\r\n");
			audiocopy_status &= ~SD_SAVE_START;
		}
	}
	vTaskDelete(NULL);
}

FILE  *tftp_ram_file;
char tftp_ram_path[64];
char tftp_ram_r_file[64];
void tftp_audio_send_handler(unsigned char *buffer, int *len, unsigned int index)
{
	int br;
	memset(buffer, 0x0, BLOCK_SIZE - 4);
	br = fread(buffer, 1, BLOCK_SIZE - 4, tftp_ram_file);
	if (br <= 0) {
		printf("\r\nRead ERROR\r\n");
		*len = 0;
	} else {
		*len = br;
	}
	vTaskDelay(30);
}

void audio_ram_tftp_thread(void *param)
{
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	int type_select = 0;
	tftp tftp_info;

	while (1) {
		if ((xSemaphoreTake(ram_upload_tftp_sema, portMAX_DELAY) == pdTRUE) && (audiocopy_status & TFTP_UPLOAD_START)) {
			printf("Start upload data by TFTP\r\n");
			type_select = RECORD_MIN;

			//setting tftp information
			tftp_info.send_handle = tftp_audio_send_handler;
			tftp_info.tftp_mode = AUDIO_TFTP_MODE;
			tftp_info.tftp_host = audio_tftp_ip;
			tftp_info.tftp_port = audio_tftp_port;
			tftp_info.tftp_op = WRQ;//FOR READ OPERATION
			tftp_info.tftp_retry_num = 5;
			tftp_info.tftp_timeout = 10;//second
			printf("tftp retry time = %d timeout = %d seconds\r\n", tftp_info.tftp_retry_num, tftp_info.tftp_timeout);

			while (type_select <= RECORD_MAX) {
				switch (type_select) {
				case RECORD_RX_DATA: {
					if (record_type & RECORD_RX_DATA) {
						//ram disk data
						snprintf(tftp_ram_r_file, 63, "%s_RX%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", tftp_ram_r_file);

						snprintf(tftp_ram_path, sizeof(tftp_ram_path), "audio_ram:/%s", tftp_ram_r_file);
						printf("RAM record file name: %s\n\r", tftp_ram_path);

						tftp_ram_file = fopen(tftp_ram_path, "r");
						if (!tftp_ram_file) {
							audiocopy_status &= ~TFTP_UPLOAD_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);
						if (tftp_client_start(&tftp_info) == 0) {
							printf("Send file successful\r\n");
						} else {
							printf("Send file fail\r\n");
						}
						fclose(tftp_ram_file);
					}
					break;
				}
				case RECORD_TX_DATA:
					if (record_type & RECORD_TX_DATA) {
						//ram disk data
						snprintf(tftp_ram_r_file, 63, "%s_TX%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", tftp_ram_r_file);

						snprintf(tftp_ram_path, sizeof(tftp_ram_path), "audio_ram:/%s", tftp_ram_r_file);
						printf("RAM record file name: %s\n\r", tftp_ram_path);

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);

						tftp_ram_file = fopen(tftp_ram_path, "r");
						if (!tftp_ram_file) {
							audiocopy_status &= ~TFTP_UPLOAD_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);
						if (tftp_client_start(&tftp_info) == 0) {
							printf("Send file successful\r\n");
						} else {
							printf("Send file fail\r\n");
						}
						fclose(tftp_ram_file);
					}
					break;
				case RECORD_ASP_DATA:
					if (record_type & RECORD_ASP_DATA) {
						//ram disk data
						snprintf(tftp_ram_r_file, 63, "%s_ASP%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", tftp_ram_r_file);

						snprintf(tftp_ram_path, sizeof(tftp_ram_path), "audio_ram:/%s", tftp_ram_r_file);
						printf("RAM record file name: %s\n\r", tftp_ram_path);

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);

						tftp_ram_file = fopen(tftp_ram_path, "r");
						if (!tftp_ram_file) {
							audiocopy_status &= ~TFTP_UPLOAD_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);
						if (tftp_client_start(&tftp_info) == 0) {
							printf("Send file successful\r\n");
						} else {
							printf("Send file fail\r\n");
						}
						fclose(tftp_ram_file);
					}
					break;
				case RECORD_TXASP_DATA:
					if (record_type & RECORD_TXASP_DATA) {
						//ram disk data
						snprintf(tftp_ram_r_file, 63, "%s_TXASP%03d.wav", file_name, recored_count);
						printf("RAM record file name: %s\n\r", tftp_ram_r_file);

						snprintf(tftp_ram_path, sizeof(tftp_ram_path), "audio_ram:/%s", tftp_ram_r_file);
						printf("RAM record file name: %s\n\r", tftp_ram_path);

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);

						tftp_ram_file = fopen(tftp_ram_path, "r");
						if (!tftp_ram_file) {
							audiocopy_status &= ~TFTP_UPLOAD_START;
							printf("Open RAM file failed\r\n");
							goto open_file_fail;
						}

						tftp_info.tftp_file_name = tftp_ram_r_file;
						printf("TFTP File name = %s\r\n", tftp_info.tftp_file_name);
						if (tftp_client_start(&tftp_info) == 0) {
							printf("Send file successful\r\n");
						} else {
							printf("Send file fail\r\n");
						}
						fclose(tftp_ram_file);
					}
					break;
				}
				vTaskDelay(10);
				type_select = type_select << 1;
			}
open_file_fail:
			printf("Start upload data by TFTP END\r\n");
			audiocopy_status &= ~TFTP_UPLOAD_START;
		}
	}
	vTaskDelete(NULL);
}

void audio_tool_flow_init(void *param)
{
#if defined(configENABLE_TRUSTZONE) && (configENABLE_TRUSTZONE == 1)
	rtw_create_secure_context(configMINIMAL_SECURE_STACK_SIZE);
#endif
	ram_dump_sd_sema = xSemaphoreCreateBinary();
	ram_upload_tftp_sema = xSemaphoreCreateBinary();

	audio_fatfs_drv_open();
	audio_save_ctx = mm_module_open(&audio_module);
	if (audio_save_ctx) {
		mm_module_ctrl(audio_save_ctx, CMD_AUDIO_SET_PARAMS, (int)&audio_save_params);
		mm_module_ctrl(audio_save_ctx, CMD_AUDIO_SET_TXASP_PARAM, (int)&tx_asp_params);
		mm_module_ctrl(audio_save_ctx, CMD_AUDIO_SET_RXASP_PARAM, (int)&rx_asp_params);
		mm_module_ctrl(audio_save_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(audio_save_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(audio_save_ctx, CMD_AUDIO_APPLY, 0);
		mm_module_ctrl(audio_save_ctx, CMD_AUDIO_SET_MIC_RECORD_FUN, (int)(audio_mic_record));
	} else {
		printf("audio open fail\n\r");
		goto audio_save_init_fail;
	}

	afft_test_ctx = mm_module_open(&afft_module);
	if (afft_test_ctx) {
		mm_module_ctrl(afft_test_ctx, CMD_AFFT_SET_PARAMS, (int)&afft_test_params);
		mm_module_ctrl(afft_test_ctx, CMD_AFFT_SET_OUTPUT, 1);
		mm_module_ctrl(afft_test_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(afft_test_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(afft_test_ctx, CMD_AFFT_APPLY, 0);
		mm_module_ctrl(afft_test_ctx, CMD_AFFT_SHOWN, 0);
	} else {
		printf("AFFT open fail\n\r");
		goto audio_save_init_fail;
	}

	printf("AFFT MODULE opened\n\r");

	pcm_tone_ctx = mm_module_open(&tone_module);
	if (pcm_tone_ctx) {
		mm_module_ctrl(pcm_tone_ctx, CMD_TONE_SET_PARAMS, (int)&pcm_tone_params);
		mm_module_ctrl(pcm_tone_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(pcm_tone_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(pcm_tone_ctx, CMD_TONE_APPLY, 0);
		//mm_module_ctrl(pcm_tone_ctx, CMD_TONE_STREAMING, 1);	// streamming on
	} else {
		printf("TONE open fail\n\r");
		goto audio_save_init_fail;
	}

	array_t array;
	array.data_addr = (uint32_t) music_sr16k;
	array.data_len = (uint32_t) music_sr16k_pcm_len;
	array_pcm_ctx = mm_module_open(&array_module);
	if (array_pcm_ctx) {
		mm_module_ctrl(array_pcm_ctx, CMD_ARRAY_SET_PARAMS, (int)&pcm16k_array_params);
		mm_module_ctrl(array_pcm_ctx, CMD_ARRAY_SET_ARRAY, (int)&array);
		mm_module_ctrl(array_pcm_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(array_pcm_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(array_pcm_ctx, CMD_ARRAY_APPLY, 0);
		//mm_module_ctrl(array_pcm_ctx, CMD_ARRAY_STREAMING, 1);	// streamming on
	} else {
		printf("ARRAY open fail\n\r");
		goto audio_save_init_fail;
	}

	p2p_audio_ctx = mm_module_open(&p2p_audio_module);
	if (p2p_audio_ctx) {
		mm_module_ctrl(p2p_audio_ctx, CMD_P2P_AUDIO_SET_PARAMS, (int)&p2p_audio_params);
		mm_module_ctrl(p2p_audio_ctx, CMD_P2P_AUDIO_APPLY, 1);
		mm_module_ctrl(p2p_audio_ctx, CMD_P2P_AUDIO_STREAMING, 0);

	} else {
		printf("P2P AUDIO open fail\n\r");
		goto audio_save_init_fail;
	}

	printf("\r\n   siso_audio_afft create  \r\n");
	siso_audio_afft = siso_create();
	if (siso_audio_afft) {
		siso_ctrl(siso_audio_afft, MMIC_CMD_ADD_INPUT, (uint32_t)audio_save_ctx, 0);
		siso_ctrl(siso_audio_afft, MMIC_CMD_ADD_OUTPUT, (uint32_t)afft_test_ctx, 0);
		siso_ctrl(siso_audio_afft, MMIC_CMD_SET_TASKPRIORITY, 2, 0);
		printf("siso_start siso_audio_afft\n\r");
	} else {
		printf("siso2 open fail\n\r");
		goto audio_save_init_fail;
	}

	printf("\r\n   mimo_array_audio create  \r\n");
	mimo_aarray_audio = mimo_create();
	if (mimo_aarray_audio) {
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_INPUT0, (uint32_t)afft_test_ctx, 0);
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_INPUT1, (uint32_t)array_pcm_ctx, 0);
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_INPUT2, (uint32_t)pcm_tone_ctx, 0);
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_OUTPUT0, (uint32_t)p2p_audio_ctx, MMIC_DEP_INPUT0);//for audio record and streaming
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_OUTPUT1, (uint32_t)audio_save_ctx, MMIC_DEP_INPUT0);//for audio playback
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_OUTPUT2, (uint32_t)audio_save_ctx, MMIC_DEP_INPUT1);//for audio playmusic
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_ADD_OUTPUT3, (uint32_t)audio_save_ctx, MMIC_DEP_INPUT2);//for audio playtone
		mimo_ctrl(mimo_aarray_audio, MMIC_CMD_SET_TASKPRIORITY, 2, 0);
		mimo_start(mimo_aarray_audio);
		printf("mimo_start mimo_aarray_audio\n\r");
		mimo_pause(mimo_aarray_audio, MM_OUTPUT1 | MM_OUTPUT2 | MM_OUTPUT3); //disable audio playback and disable audio playtone
		printf("mimo_pause mimo_aarray_audio MM_OUTPUT1, MM_OUTPUT2 and MM_OUTPUT3\n\r");
	} else {
		printf("siso2 open fail\n\r");
		goto audio_save_init_fail;
	}
	siso_start(siso_audio_afft);
	printf("audio_set_done~~~~~\r\n");

	if (xTaskCreate(audio_save_mass_storage_thread, ((const char *)"mass_stor"), 2048, NULL, tskIDLE_PRIORITY + 5, NULL) != pdPASS) {
		printf("\r\n audio_save_mass_storage_thread: Create Task Error\n");
	}

	if (xTaskCreate(audio_ram_sd_thread, ((const char *)"ram_sd"), 1024 * 8, NULL, tskIDLE_PRIORITY + 5, NULL) != pdPASS) {
		printf("\r\n audio_ram_sd_thread: Create Task Error\n");
	}

	if (xTaskCreate(audio_ram_tftp_thread, ((const char *)"ram_tftp"), 1024 * 8, NULL, tskIDLE_PRIORITY + 5, NULL) != pdPASS) {
		printf("\r\n audio_ram_tftp_thread: Create Task Error\n");
	}

	audio_save_log_init();

#if AUDIO_TRANSFER_FUNC
	if (xTaskCreate(audio_data_transfer, ((const char *)"au_trans"), 1024 * 8, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
		printf("\r\n audio_data_transfer: Create Task Error\n");
	}
#endif
	vTaskDelay(5000);
#if P2P_ENABLE
	//skynet_device_run();
#endif
	while (1) {
		vTaskDelay(1000);
	}

audio_save_init_fail:
	printf("MODULE OPEN FAILED\r\n");
	vTaskDelete(NULL);
}

void audio_tool_init(void)
{
	/*user can start their own task here*/
	if (xTaskCreate(audio_tool_flow_init, ((const char *)"au_test"), 1024 * 16, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
		printf("\r\n audio_tool_flow_init: Create Task Error\n");
	}
}
