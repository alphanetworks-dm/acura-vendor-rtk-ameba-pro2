/******************************************************************************
*
* Copyright(c) 2007 - 2018 Realtek Corporation. All rights reserved.
*
******************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>
#include <semphr.h>

#include "mmf2_module.h"
#include "audio_api.h"
#include "module_audio.h"
#include "avcodec.h"


//------------------------------------------------------------------------------
#if defined(CONFIG_PLATFORM_8735B)
#if IS_CUT_TEST(CONFIG_CHIP_VER)
#define DMIC_CLK_PIN    PE_2 //PE_0
#define DMIC_DATA_PIN   PE_4
#else
#define DMIC_CLK_PIN    PD_16 //PD_14
#define DMIC_DATA_PIN   PD_18
#endif
#define AUDIO_DMA_PAGE_NUM 4
#define TX_CACHE_DEPTH	16
#define RX_CACHE_DEPTH	(AUDIO_DMA_PAGE_NUM*2)
#define AUDIO_DMA_PAGE_SIZE (640)	// 8KHz 40ms 16KHz 20ms
#else
#define AUDIO_DMA_PAGE_NUM 2
#define RX_CACHE_DEPTH	(AUDIO_DMA_PAGE_NUM*2)
#define AUDIO_DMA_PAGE_SIZE (320)	// 8KHz 20ms 16KHz 10ms   
#endif

#if defined(CONFIG_PLATFORM_8735B) && (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
#define AUDIO_AEC_PAGE_SIZE (640)
#else
#define AUDIO_AEC_PAGE_SIZE (320)
#endif

#define TX_PAGE_SIZE 	AUDIO_DMA_PAGE_SIZE //64*N bytes, max: 4095. 128, 4032 
#define TX_PAGE_NUM 	AUDIO_DMA_PAGE_NUM
#define RX_PAGE_SIZE 	AUDIO_DMA_PAGE_SIZE //64*N bytes, max: 4095. 128, 4032
#define RX_PAGE_NUM 	AUDIO_DMA_PAGE_NUM
#define FRAME_LENGTH_MS(samplerate, wordlength)    ((AUDIO_DMA_PAGE_SIZE / wordlength) / (samplerate / 1000)) // 1 sample = wordlength(bytes)

static uint8_t dma_txdata[TX_PAGE_SIZE * TX_PAGE_NUM]__attribute__((aligned(0x20)));
static uint8_t dma_rxdata[RX_PAGE_SIZE * RX_PAGE_NUM]__attribute__((aligned(0x20)));
static uint8_t dma_rxdata_buf_lr[RX_PAGE_SIZE * 2];	//save the mic audio data (16bits left, 16bits right)

#define AUDIO_TX_PCM_QUEUE_LENGTH (20)

typedef struct pcm_tx_cache_s {
	xQueueHandle queue;
	uint16_t idx;
	uint8_t  buffer[AUDIO_DMA_PAGE_SIZE];	// for sw output cache handler
	uint8_t  txbuf[AUDIO_DMA_PAGE_SIZE];	// for interrupt
} pcm_tx_cache_t;

static pcm_tx_cache_t	*pcm_tx_cache = NULL;
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
static pcm_tx_cache_t	*pcm_pretx_cache = NULL;
xQueueHandle pretx_record_queue;
static uint8_t last_pretx_buf[AUDIO_DMA_PAGE_SIZE];
#endif

#define LOGIC_INPUT_NUM	4
static int logic_input_num = 1;		// for non-mix mode

#if LOGIC_INPUT_NUM==2
#warning ****VERY IMPORTANT : AUDIO must connect to MIMO/MISO INPUT 0 and 1 ****
// TODO : remove this limitation
#endif

#if LOGIC_INPUT_NUM!=4 && LOGIC_INPUT_NUM!=2
#error ONLY SUPPORT 4 and 2
#endif

#if !defined(ENABLE_ASP)
#define ENABLE_ASP 0
#endif

//-------------AEC interrupt handler ------------------------------------------
#if ENABLE_ASP==1

static uint8_t last_tx_buf[AUDIO_DMA_PAGE_SIZE];

int last_tx_ts, proc_tx_ts;
int last_rx_ts, proc_rx_ts;

static uint8_t proc_tx_buf[AUDIO_DMA_PAGE_SIZE];
static uint8_t proc_pretx_buf[AUDIO_DMA_PAGE_SIZE];

typedef struct pcm_rx_s {
	uint32_t timestamp;
	uint32_t hw_timestamp;
	uint8_t  pcm_data[AUDIO_DMA_PAGE_SIZE * 2];	//reserve for stereo buffer
} pcm_rx_t;

static xQueueHandle pcm_rx_cache = NULL;
static pcm_rx_t rx_irq_buf;
static pcm_rx_t proc_rx_buf;

#define M 8
#define FRAMESIZE (AUDIO_AEC_PAGE_SIZE/2)
#define TAIL_LENGTH_IN_MILISECONDS (20*M)
#define TAIL(tail_ms, rate) (tail_ms * (rate / 1000) )

#if defined(CONFIG_PLATFORM_8195BHP)
#include "AEC.h"
#elif defined(CONFIG_PLATFORM_8735B)
#include "ASP.h"
#endif
#endif //ENABLE_ASP

#if CONFIG_MMF_AUDIO_DEBUG
#include <audio_debug.h>
int audio_tx_debug_cnt = 0x7fffffff;
int audio_rx_debug_cnt = 0x7fffffff;
int audio_rx_aec_cnt = 0x7fffffff;
int audio_rx_debug_mode = 0;
#endif

#if CONFIG_MMF_AUDIO_ATAF
/* for ATCMD control
 * use ATAF=[aec,vad],[0 or 1]
 *     ATAF=[ns,agc],[0 ~ 3]
 * Here default all on to prevent turn on in parameter but still feature off
 */
int module_audio_aec = 1;
int module_audio_vad = 1;
int module_audio_agc = 3;
int module_audio_ns = 3;


#define ATAF_AEC_CTRL module_audio_aec
#define ATAF_AGC_CTRL module_audio_agc
#define ATAF_VAD_CTRL module_audio_vad
#define ATAF_NS_CTRL module_audio_ns
#else
#define ATAF_AEC_CTRL 1
#define ATAF_AGC_CTRL 3
#define ATAF_VAD_CTRL 1
#define ATAF_NS_CTRL 3
#endif

#if !(defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
static int NS_MODE = 3;			// 0~3 ns aggressive level
static int VAD_MODE = 1;		// 0 : normal 1:low rate 2: aggrasive 3: very aggrasive
#endif

static int audio_get_samplerate(audio_sr rate)
{
	switch (rate) {
	case ASR_8KHZ:
		return 8000;
	case ASR_16KHZ:
		return 16000;
	case ASR_32KHZ:
		return 32000;
	case ASR_44p1KHZ:
		return 44100;
	case ASR_48KHZ:
		return 48000;
	case ASR_88p2KHZ:
		return 88200;
	case ASR_96KHZ:
		return 96000;
	default:
		AUDIO_DBG_INFO("wrong rate index %d\n\r", rate);
		while (1);
	}
}

#if defined(CONFIG_PLATFORM_8735B)
static void audio_err_callback(uint32_t arg, uint8_t *pbuf)
{
	audio_ctx_t *ctx = (audio_ctx_t *)arg;
	audio_t *obj = (audio_t *)ctx->audio;

	//get audio error for debug
	uint8_t *err_buf = pbuf;
	uint32_t err_status = err_buf[3] << 24 | err_buf[2] << 16 | err_buf[1] << 8 | err_buf[0];

	printf("The audio Test err call back = 0x%x\r\n", err_status);
}
#endif

static void audio_tx_complete(uint32_t arg, uint8_t *pbuf)
{
	audio_ctx_t *ctx = (audio_ctx_t *)arg;
	audio_t *obj = (audio_t *)ctx->audio;
	uint8_t *ptx_buf;
#if ENABLE_ASP==1
	last_tx_ts = xTaskGetTickCountFromISR() + ctx->audio_timestamp_offset;
	memcpy(last_tx_buf, pbuf, AUDIO_DMA_PAGE_SIZE);
#endif

	ptx_buf = (uint8_t *)audio_get_tx_page_adr(obj);
#if LOGIC_INPUT_NUM==4 || LOGIC_INPUT_NUM==2
	if (ctx->params.mix_mode) {
		for (int i = 0; i < logic_input_num; i++) {
			if (xQueueReceiveFromISR(pcm_tx_cache[i].queue, pcm_tx_cache[i].txbuf, NULL) != pdPASS) {
				memset(pcm_tx_cache[i].txbuf, 0, AUDIO_DMA_PAGE_SIZE);
			}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
			if (xQueueReceiveFromISR(pcm_pretx_cache[i].queue, pcm_pretx_cache[i].txbuf, NULL) != pdPASS) {
				memset(pcm_pretx_cache[i].txbuf, 0, AUDIO_DMA_PAGE_SIZE);
			}
#endif
		}
		if (ctx->params.word_length == WL_16BIT) {
			int16_t *ptx_tmp = (int16_t *)ptx_buf;
			int16_t *cache_txbuf0 = (int16_t *)pcm_tx_cache[0].txbuf;
			int16_t *cache_txbuf1 = (int16_t *)pcm_tx_cache[1].txbuf;
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
			int16_t *cache_pretxbuf0 = (int16_t *)pcm_pretx_cache[0].txbuf;
			int16_t *cache_pretxbuf1 = (int16_t *)pcm_pretx_cache[1].txbuf;
#endif
#if LOGIC_INPUT_NUM==4
			int16_t *cache_txbuf2 = (int16_t *)pcm_tx_cache[2].txbuf;
			int16_t *cache_txbuf3 = (int16_t *)pcm_tx_cache[3].txbuf;
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
			int16_t *cache_pretxbuf2 = (int16_t *)pcm_pretx_cache[2].txbuf;
			int16_t *cache_pretxbuf3 = (int16_t *)pcm_pretx_cache[3].txbuf;
#endif
#endif
			for (int i = 0; i < AUDIO_DMA_PAGE_SIZE / 2; i++) {
				ptx_tmp[i] = cache_txbuf0[i] / LOGIC_INPUT_NUM + cache_txbuf1[i] / LOGIC_INPUT_NUM
#if LOGIC_INPUT_NUM==4
							 + cache_txbuf2[i] / LOGIC_INPUT_NUM + cache_txbuf3[i] / LOGIC_INPUT_NUM
#endif
							 ;
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
				cache_pretxbuf0[i] = cache_pretxbuf0[i] / LOGIC_INPUT_NUM + cache_pretxbuf1[i] / LOGIC_INPUT_NUM
#if LOGIC_INPUT_NUM==4
									 + cache_pretxbuf2[i] / LOGIC_INPUT_NUM + cache_pretxbuf3[i] / LOGIC_INPUT_NUM
#endif
									 ;
#endif
			}
		} else {
			for (int i = 0; i < AUDIO_DMA_PAGE_SIZE; i++) {
				ptx_buf[i] = (int8_t)pcm_tx_cache[0].txbuf[i] / LOGIC_INPUT_NUM + (int8_t)pcm_tx_cache[1].txbuf[i] / LOGIC_INPUT_NUM
#if LOGIC_INPUT_NUM==4
							 + (int8_t)pcm_tx_cache[2].txbuf[i] / LOGIC_INPUT_NUM + (int8_t)pcm_tx_cache[3].txbuf[i] / LOGIC_INPUT_NUM
#endif
							 ;
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
				int8_t tmp_value = (int8_t)pcm_pretx_cache[0].txbuf[i];
				tmp_value = (int8_t)pcm_pretx_cache[0].txbuf[i] / LOGIC_INPUT_NUM + (int8_t)pcm_pretx_cache[1].txbuf[i] / LOGIC_INPUT_NUM
#if LOGIC_INPUT_NUM==4
							+ (int8_t)pcm_pretx_cache[2].txbuf[i] / LOGIC_INPUT_NUM + (int8_t)pcm_pretx_cache[3].txbuf[i] / LOGIC_INPUT_NUM
#endif
							;
#endif
			}
		}
	} else
#endif
	{
		if (xQueueReceiveFromISR(pcm_tx_cache[0].queue, ptx_buf, NULL) != pdPASS) {
			memset(ptx_buf, 0, AUDIO_DMA_PAGE_SIZE);
		}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
		if (xQueueReceiveFromISR(pcm_pretx_cache[0].queue, pcm_pretx_cache[0].txbuf, NULL) != pdPASS) {
			memset(pcm_pretx_cache[0].txbuf, 0, AUDIO_DMA_PAGE_SIZE);
		}
#endif
	}

#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
	BaseType_t xHigherPriorityTaskWoken_TX = pdFALSE;
	int pretx_queue_ready = 0;
	pretx_queue_ready = xQueueSendFromISR(pretx_record_queue, (void *) & (pcm_pretx_cache[0].txbuf), &xHigherPriorityTaskWoken_TX);
	if (xQueueIsQueueFullFromISR(pretx_record_queue) == pdTRUE) {
		if (xQueueReceiveFromISR(pretx_record_queue, last_pretx_buf, NULL) != pdPASS) {
			memset(last_pretx_buf, 0, AUDIO_DMA_PAGE_SIZE);
		}
	} else {
		memset(last_pretx_buf, 0, AUDIO_DMA_PAGE_SIZE);
	}
#endif

#if defined(AUDIO_DEBUG_H)
	if (audio_tx_debug_ena == 1) {
		AUDIO_DBG_INFO("start tx playback debug\n\r");
		audio_tx_debug_cnt = 0;
		audio_tx_debug_ena = 0;
	}

	if (audio_tx_debug_cnt < audio_tx_debug_len) {
		memcpy(ptx_buf, &audio_tx_debug_buffer[audio_tx_debug_cnt], AUDIO_DMA_PAGE_SIZE);
		audio_tx_debug_cnt += AUDIO_DMA_PAGE_SIZE;
		if (audio_tx_debug_cnt >= audio_tx_debug_len) {
			AUDIO_DBG_INFO("done for tx playback debug\n\r");
		}

	}
#endif

	audio_set_tx_page(obj, (uint8_t *)ptx_buf);
}

static void audio_rx_complete(uint32_t arg, uint8_t *pbuf)
{
	audio_ctx_t *ctx = (audio_ctx_t *)arg;
	audio_t *obj = (audio_t *)ctx->audio;
	uint32_t rx_ts = xTaskGetTickCountFromISR();
	static int rx_index = 0;
	int is_output_ready = 0;
	// set timestamp to 1st sample
	// AUDIO_DBG_INFO("rx timestamp = %d\r\n", audio_rx_ts);
	rx_ts -= 1000 * (AUDIO_DMA_PAGE_SIZE / ctx->word_length) / ctx->sample_rate;
	uint32_t audio_rx_ts = rx_ts + ctx->audio_timestamp_offset;

	// disable the first frame to prevent "pop" sound
	if (ctx->rx_first_frame) {
		memset(pbuf, 0, AUDIO_DMA_PAGE_SIZE);
		ctx->rx_first_frame = 0;
	}

#if defined(AUDIO_LOOPBACK) && AUDIO_LOOPBACK
	uint8_t *ptx_addre;
	ptx_addre = audio_get_tx_page_adr(obj);
	memcpy((void *)ptx_addre, (void *)pbuf, TX_PAGE_SIZE);
	audio_set_tx_page(obj, ptx_addre);
	if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
		memcpy((void *)(dma_rxdata_buf_lr + rx_index), (void *)pbuf, RX_PAGE_SIZE);
		rx_index += RX_PAGE_SIZE;
		if (rx_index == RX_PAGE_SIZE * 2) {
			int16_t *stereo_loop_ptx_addre;
			int16_t *stereo_loop_data_lr;
			stereo_loop_ptx_addre = (int16_t *) ptx_addre;
			stereo_loop_data_lr = (int16_t *) dma_rxdata_buf_lr;
			//use merge the two channel data
			for (int j = 0; j < TX_PAGE_SIZE / sizeof(int16_t); j++) {
				stereo_loop_ptx_addre[j] = stereo_loop_data_lr[2 * j] / 2 + stereo_loop_data_lr[2 * j + 1] / 2;
			}
			audio_set_tx_page(obj, ptx_addre);
			rx_index = 0;
		}
	} else {
		memcpy((void *)ptx_addre, (void *)pbuf, TX_PAGE_SIZE);
		audio_set_tx_page(obj, ptx_addre);
	}
#endif

	//count the audio send/drop frame
	if (ctx->timer_2 == 0) {
		ctx->timer_1 = xTaskGetTickCountFromISR();
		ctx->timer_2 = ctx->timer_1;
	} else {
		ctx->timer_2 = xTaskGetTickCountFromISR();
		//print every 1 min
		if ((ctx->timer_2 - ctx->timer_1) >= 60000) {
			AUDIO_DBG_WARNING("audio:%ld drop:%ld audio_total:%ld drop_total:%ld\r\n", ctx->audio_frame, ctx->drop_frame, ctx->audio_frame_total, ctx->drop_frame_total);
			ctx->timer_2 = 0;
			ctx->drop_frame = 0;
			ctx->audio_frame = 0;
		}
	}

#if defined(CONFIG_PLATFORM_8735B) //on;y test on 8735
	if (ctx->params.fcs_avsync_en && !ctx->fcs_avsync_done) {
		ctx->fcs_avsync_done = 1;
		if (audio_rx_ts > ctx->params.fcs_avsync_vtime) {
			BaseType_t xTaskWokenByReceive = pdFALSE;
			BaseType_t xHigherPriorityTaskWoken = pdFALSE;
			mm_context_t *dummy_mctx = (mm_context_t *)ctx->parent;
			mm_queue_item_t *dummy_output_item;
			int audio_frame_ms = 1000 * (RX_PAGE_SIZE / ctx->word_length) / ctx->sample_rate;

			int dummy_length = (audio_rx_ts - ctx->params.fcs_avsync_vtime) / audio_frame_ms;
			int audio_dummy_ts = audio_rx_ts - dummy_length * audio_frame_ms;
			AUDIO_DBG_INFO("avsync_vtime = %d, audio_rx_ts = %d, dummy_length = %d\r\n",  ctx->params.fcs_avsync_vtime, audio_rx_ts, dummy_length);
			while (audio_dummy_ts < audio_rx_ts) {
				if (dummy_mctx->output_recycle && (xQueueReceiveFromISR(dummy_mctx->output_recycle, &dummy_output_item, &xTaskWokenByReceive) == pdTRUE)) {
					memset((void *)dummy_output_item->data_addr, 0, RX_PAGE_SIZE);
					dummy_output_item->size = RX_PAGE_SIZE;
					dummy_output_item->timestamp = audio_dummy_ts;
					dummy_output_item->hw_timestamp = rx_ts;
					dummy_output_item->type = AV_CODEC_ID_PCM_RAW;
					xQueueSendFromISR(dummy_mctx->output_ready, (void *)&dummy_output_item, &xHigherPriorityTaskWoken);
				}
				//AUDIO_DBG_INFO("audio_dummy_ts = %d\r\n",  audio_dummy_ts);
				audio_dummy_ts += audio_frame_ms;
			}
		}
	}
#endif

#if ENABLE_ASP==1
	if (pcm_rx_cache && (ctx->enable_rxasp || ctx->params.enable_record)) {
		BaseType_t xHigherPriorityTaskWoken_AEC = pdFALSE;
#if defined(CONFIG_PLATFORM_8735B) // only 8735 support stereo dmic 
		if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			int16_t *stereo_rx_data_l = (int16_t *)(rx_irq_buf.pcm_data + rx_index);
			int16_t *stereo_rx_data_r = (int16_t *)(rx_irq_buf.pcm_data + AUDIO_DMA_PAGE_SIZE + rx_index);
			int16_t *stereo_rx_data_lr = (int16_t *) pbuf;
			for (int j = 0; j < AUDIO_DMA_PAGE_SIZE / sizeof(int16_t); j++) {
				stereo_rx_data_l[j] = stereo_rx_data_lr[2 * j];
				stereo_rx_data_r[j] = stereo_rx_data_lr[2 * j + 1];
			}
			rx_index += RX_PAGE_SIZE;
			if (rx_index == RX_PAGE_SIZE * 2) {
				//send the 20ms l_r data to rx buf
				is_output_ready = xQueueSendFromISR(pcm_rx_cache, (void *)&rx_irq_buf, &xHigherPriorityTaskWoken_AEC);
				rx_index = 0;
				if (is_output_ready != pdTRUE) {
					ctx->drop_frame++;
					ctx->drop_frame_total++;
				} else {
					ctx->audio_frame++;
					ctx->audio_frame_total++;
				}
			} else {
				last_rx_ts = audio_rx_ts;
				rx_irq_buf.timestamp = audio_rx_ts;
				rx_irq_buf.hw_timestamp = rx_ts;
			}
		} else
#endif
		{
			last_rx_ts = audio_rx_ts;
			rx_irq_buf.timestamp = audio_rx_ts;
			rx_irq_buf.hw_timestamp = rx_ts;
			if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) {
				memcpy((void *)(rx_irq_buf.pcm_data + AUDIO_DMA_PAGE_SIZE), (void *)pbuf, RX_PAGE_SIZE);
			} else {
				memcpy((void *)rx_irq_buf.pcm_data, (void *)pbuf, RX_PAGE_SIZE);
			}
			is_output_ready = xQueueSendFromISR(pcm_rx_cache, (void *)&rx_irq_buf, &xHigherPriorityTaskWoken_AEC);
			if (is_output_ready != pdTRUE) {
				ctx->drop_frame++;
				ctx->drop_frame_total++;
			} else {
				ctx->audio_frame++;
				ctx->audio_frame_total++;
			}
		}
		audio_set_rx_page(obj);

	} else
#endif
	{
		BaseType_t xTaskWokenByReceive = pdFALSE;
		BaseType_t xHigherPriorityTaskWoken = pdFALSE;

		mm_context_t *mctx = (mm_context_t *)ctx->parent;
		mm_queue_item_t *output_item;
#if defined(CONFIG_PLATFORM_8735B) // only 8735 support stereo dmic 
		if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			memcpy((void *)(dma_rxdata_buf_lr + rx_index), (void *)pbuf, RX_PAGE_SIZE);
			rx_index += RX_PAGE_SIZE;
			if (rx_index == RX_PAGE_SIZE * 2) {
				//send the 20ms l_r data to rx buf
				memcpy((void *)dma_rxdata_buf_lr, (void *)pbuf, RX_PAGE_SIZE);
				if (mctx->output_recycle && (xQueueReceiveFromISR(mctx->output_recycle, &output_item, &xTaskWokenByReceive) == pdTRUE)) {
					//memcpy((void *)output_item->data_addr, (void *)dma_rxdata_buf_lr, RX_PAGE_SIZE * 2);
					int16_t *ptx_addre = (int16_t *)output_item->data_addr;
					int16_t *rx_data_lr = (int16_t *)dma_rxdata_buf_lr;
					//use merge the two channel data
					for (int j = 0; j < TX_PAGE_SIZE / sizeof(int16_t); j++) {
						ptx_addre[j] = rx_data_lr[2 * j] / 2 + rx_data_lr[2 * j + 1] / 2;
					}
					output_item->size = RX_PAGE_SIZE;
					output_item->timestamp = audio_rx_ts;
					output_item->hw_timestamp = rx_ts;
					output_item->type = AV_CODEC_ID_PCM_RAW;

					//count the audio send/drop frame
					ctx->audio_frame++;
					ctx->audio_frame_total++;
					xQueueSendFromISR(mctx->output_ready, (void *)&output_item, &xHigherPriorityTaskWoken);
				} else {
					//count the audio send/drop frame
					ctx->drop_frame++;
					ctx->drop_frame_total++;
				}
				rx_index = 0;
			}
		} else
#endif
		{
			memcpy((void *)dma_rxdata_buf_lr, (void *)pbuf, RX_PAGE_SIZE);
			if (mctx->output_recycle && (xQueueReceiveFromISR(mctx->output_recycle, &output_item, &xTaskWokenByReceive) == pdTRUE)) {
				memcpy((void *)output_item->data_addr, (void *)dma_rxdata_buf_lr, RX_PAGE_SIZE);
				output_item->size = RX_PAGE_SIZE;
				output_item->timestamp = audio_rx_ts;
				output_item->hw_timestamp = rx_ts;
				output_item->type = AV_CODEC_ID_PCM_RAW;
				//count the audio send/drop frame
				ctx->audio_frame++;
				ctx->audio_frame_total++;

				xQueueSendFromISR(mctx->output_ready, (void *)&output_item, &xHigherPriorityTaskWoken);
			} else {
				//count the audio send/drop frame
				ctx->drop_frame++;
				ctx->drop_frame_total++;
			}
		}
		audio_set_rx_page(obj);

		if (xHigherPriorityTaskWoken || xTaskWokenByReceive) {
			taskYIELD();
		}
	}
}

#if !(defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
static int fade_level = 0;
#define FADE_IN 1
#define FADE_OUT 0

#define FADE_RATIO	16
#define FADE_LEVEL(curr_level) (curr_level/FADE_RATIO)
#define FADE_SILENCE_LEVEL	16*FADE_RATIO

#define MODE_INSTANT 0
#define MODE_SLOPE 1
#define FADE_IN_MODE MODE_SLOPE

/* zero -> 16*FADE_RATIO, suppress  x*FADE_RATIO = 3*x dB */
#define FADE_MAX_LEVEL 16*FADE_RATIO	// 16, silence

#if FADE_IN_MODE==MODE_INSTANT
static int last_fade_state = 0;
#endif

static int FADE_OUT_SPEED = 8;
static void audio_fade_signal(int fade_state, int16_t *data, int num)
{
	if (fade_state == FADE_OUT) {	// fade out
		if (fade_level < FADE_MAX_LEVEL) {
			int __level = FADE_LEVEL(fade_level);
			for (int i = 0; i < num; i++) {
				data[i] >>= __level;
			}

			fade_level += FADE_OUT_SPEED;
		} else {
			fade_level = FADE_MAX_LEVEL;
			if (FADE_MAX_LEVEL == FADE_SILENCE_LEVEL) {
				memset((int16_t *)data, 0, num * sizeof(int16_t));
			} else {
				int __level = FADE_LEVEL(FADE_MAX_LEVEL);
				for (int i = 0; i < num; i++) {
					data[i] >>= __level;
				}
			}
		}
	} else {	// fade in
#if FADE_IN_MODE==MODE_INSTANT
		int __level = FADE_LEVEL(fade_level);
		int step = 16 - __level > 0 ? num / (16 - __level) : num / 16;

		if (last_fade_state == 0) {
			for (int i = 0; i < (16 - __level); i++) {
				for (int j = 0; j < step; j++) {
					data[i * step + j] >>= (16 - __level - i);
				}
			}
		}
		fade_level = 0;
#else // SLOPE
		if (fade_level > 0) {
			int __level = FADE_LEVEL(fade_level);
			for (int i = 0; i < num; i++) {
				data[i] >>= __level;
			}

			// 8 times speed to fade in
			fade_level -= 8;
		} else {
			// do nothing
			fade_level = 0;
		}
#endif
	}
#if FADE_IN_MODE==MODE_INSTANT
	last_fade_state = fade_state;
#endif
}
#endif

#if ENABLE_ASP==1
#define PRINT_ASP_PROCESS_TIME

#if defined(PRINT_ASP_PROCESS_TIME)
uint32_t total_AEC_process = 0;
uint32_t max_AEC_process = 0;
uint32_t AEC_times = 0;
uint32_t this_AEC_times = 0;
uint32_t the_max_AEC_process = 0;
uint32_t thisAEC_process = 0;
#endif
static void audio_rx_handle_thread(void *param)
{
	audio_ctx_t *ctx = (audio_ctx_t *)param;
	mm_context_t *mctx = (mm_context_t *)ctx->parent;
	mm_queue_item_t *output_item;

	if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
		int sampleRate = audio_get_samplerate(ctx->params.sample_rate);

		AUDIO_DBG_INFO("sample rate: %d \r\n", sampleRate);
		AUDIO_DBG_INFO("frame size = %d, DMAsize = %d\r\n", AUDIO_AEC_PAGE_SIZE, AUDIO_DMA_PAGE_SIZE);
#if defined(CONFIG_PLATFORM_8735B) && (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
		if (ctx->rxcfg.aec_cfg.AEC_EN || ctx->rxcfg.agc_cfg.AGC_EN || ctx->rxcfg.ns_cfg.NS_EN) {
			AEC_init(FRAMESIZE, sampleRate, &(ctx->rxcfg.aec_cfg), &(ctx->rxcfg.agc_cfg), &(ctx->rxcfg.ns_cfg), 1.0f);
			AUDIO_DBG_INFO("set AEC level = %d, sdelay = %d\r\n", ctx->rxcfg.aec_cfg.PPLevel, ctx->rxcfg.aec_cfg.EchoTailLen);
			ctx->inited_aec = 1;
			ctx->run_aec = 1;
		}
#else
		if (ctx->rxcfg.aec_cfg.AEC_EN) {
			AEC_init(FRAMESIZE, sampleRate, &(ctx->rxcfg.aec_cfg), 1.0f);
			AUDIO_DBG_INFO("set AEC level = %d, sdelay = %d\r\n", ctx->rxcfg.aec_cfg.AECLevel, ctx->rxcfg.aec_cfg.FilterLength);
			AUDIO_DBG_INFO("Inintial AEC \r\n");
			ctx->inited_aec = 1;
			ctx->run_aec = 1;
		}

		if (ctx->rxcfg.ns_cfg.NS_EN) {
			NS2_init(sampleRate, &(ctx->rxcfg.ns_cfg));
			ctx->inited_ns |= 0x2;
			ctx->run_ns |= 0x2;
			AUDIO_DBG_INFO("Set MIC NS level %d\r\n", ctx->rxcfg.ns_cfg.NSLevel);
		}

		if (ctx->rxcfg.agc_cfg.AGC_EN) {
			AGC2_init(sampleRate, &(ctx->rxcfg.agc_cfg));
			AUDIO_DBG_INFO("mic AGC %d,%d,%d,%d\r\n", ctx->rxcfg.agc_cfg.AGCMode, ctx->rxcfg.agc_cfg.TargetLevelDbfs, ctx->rxcfg.agc_cfg.CompressionGaindB,
						   ctx->rxcfg.agc_cfg.LimiterEnable);
			ctx->inited_agc |= 0x2;
			ctx->run_agc |= 0x2;
		}

		if (ctx->rxcfg.vad_cfg.VAD_EN) {
			VAD_init(sampleRate, &(ctx->rxcfg.vad_cfg));
			ctx->inited_vad = 1;
			ctx->run_vad = 1;
		}
#endif
	}
	while (1) {
		if (!mctx->output_recycle || !pcm_rx_cache) {
			// drop current frame
			// NOT SEND
			AUDIO_DBG_ERROR("[Audio AEC] NO audio output_recycle queue block here for debug\r\n");
			while (1);
		}
		if (xQueueReceive(pcm_rx_cache, &proc_rx_buf, 0xFFFFFFFF) != pdTRUE) {
			AUDIO_DBG_WARNING("[Audio AEC] Can not get audio buffer\r\n");
			continue;
		}

		uint8_t *dma_rxdata_buf_l = (uint8_t *)proc_rx_buf.pcm_data;
		uint8_t *dma_rxdata_buf_r = (uint8_t *)(proc_rx_buf.pcm_data + AUDIO_DMA_PAGE_SIZE);
		uint8_t *dma_rxdata_proc_buf;
		// use left mic data to do process in stereo mic signal, will modify after stereo signal process is ready
		if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			dma_rxdata_proc_buf = dma_rxdata_buf_l;
		} else if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) {
			dma_rxdata_proc_buf = dma_rxdata_buf_r;
		} else { //USE_AUDIO_LEFT_DMIC or USE_AUDIO_AMIC
			dma_rxdata_proc_buf = dma_rxdata_buf_l;
		}
		//uint32_t audio_rx_ts = proc_rx_buf.timestamp;
		//uint32_t audio_rx_ts = xTaskGetTickCount();
		memcpy(proc_tx_buf, last_tx_buf, AUDIO_DMA_PAGE_SIZE);
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
		memcpy(proc_pretx_buf, last_pretx_buf, AUDIO_DMA_PAGE_SIZE);
#endif
		//memcpy(pre_proc_tx_buf, pre_tx_buf, AUDIO_DMA_PAGE_SIZE);
		// last tx rx buffer may be corrupted by interrupt, backup processing data first
		proc_tx_ts = last_tx_ts;
		proc_rx_ts = last_rx_ts;
		if (xQueueReceive(mctx->output_recycle, &output_item, 0xFFFFFFFF) == pdTRUE) {
#if defined(AUDIO_DEBUG_H)
			if (audio_rx_debug_ena != 0) {
#if defined(AUDIO_DEBUG_ENABLE)
				AUDIO_DBG_INFO("start rx recording\n\r");
#endif
				audio_rx_debug_cnt = 0;
				audio_rx_debug_ena = 0;
			}
			if (audio_rx_debug_cnt < audio_rx_debug_len) {
				memcpy(&audio_rx_debug_buffer[audio_rx_debug_cnt], last_rx_buf, AUDIO_DMA_PAGE_SIZE);
				audio_rx_debug_cnt += AUDIO_DMA_PAGE_SIZE;
				if (audio_rx_debug_cnt >= audio_rx_debug_len) {
#if defined(AUDIO_DEBUG_ENABLE)
					AUDIO_DBG_INFO("done for rx (mic) recording\n\r");
#endif
				}
			}
#endif

			int aec_proc_time = xTaskGetTickCount();
#if defined(PRINT_ASP_PROCESS_TIME)
			uint32_t this_aec_proc_time = xTaskGetTickCount();
#endif


			if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
				int i = 0;
#if defined(CONFIG_PLATFORM_8735B) && defined(CONFIG_NEWAEC) && CONFIG_NEWAEC
				if (ctx->inited_aec && ctx->run_aec && ATAF_AEC_CTRL) {
					for (i = 0; i < AUDIO_DMA_PAGE_SIZE; i += AUDIO_AEC_PAGE_SIZE) {
						AEC_process((int16_t *)(proc_tx_buf + i), (int16_t *)(dma_rxdata_proc_buf + i), (int16_t *)(output_item->data_addr + i));
					}
				} else {
					memcpy((int16_t *)output_item->data_addr, (int16_t *)(dma_rxdata_proc_buf), AUDIO_DMA_PAGE_SIZE);
				}
#else
				if (ctx->inited_aec && ctx->run_aec && ATAF_AEC_CTRL) {
					for (i = 0; i < AUDIO_DMA_PAGE_SIZE; i += AUDIO_AEC_PAGE_SIZE) {
						AEC_process((int16_t *)(proc_tx_buf + i), (int16_t *)(dma_rxdata_proc_buf + i), (int16_t *)(output_item->data_addr + i));
					}
				} else {
					memcpy((int16_t *)output_item->data_addr, (int16_t *)(dma_rxdata_proc_buf), AUDIO_DMA_PAGE_SIZE);
				}
				if ((ctx->inited_ns & 0x2) && (ctx->run_ns & 0x2) && (ATAF_NS_CTRL & 0x2)) {
					NS2_process(AUDIO_DMA_PAGE_SIZE / sizeof(int16_t), (int16_t *)output_item->data_addr);
				}

				if ((ctx->inited_agc & 0x2) && (ctx->run_agc & 0x2) && (ATAF_AGC_CTRL & 0x2)) {
					AGC2_process(AUDIO_DMA_PAGE_SIZE / sizeof(int16_t), (int16_t *)(output_item->data_addr));
				}
				if (ctx->inited_vad && ctx->run_vad && (ATAF_VAD_CTRL)) {
					int vad_state = VAD_process(AUDIO_DMA_PAGE_SIZE / sizeof(int16_t), (int16_t *)output_item->data_addr);
					if (vad_state == 0) {
						audio_fade_signal(FADE_OUT, (int16_t *)output_item->data_addr, AUDIO_DMA_PAGE_SIZE / sizeof(int16_t));
					} else {
						audio_fade_signal(FADE_IN, (int16_t *)output_item->data_addr, AUDIO_DMA_PAGE_SIZE / sizeof(int16_t));
					}
				}
#endif
#if defined(PRINT_ASP_PROCESS_TIME)
				this_aec_proc_time = xTaskGetTickCount() - this_aec_proc_time;
				this_AEC_times ++;
				thisAEC_process += this_aec_proc_time;
				if (max_AEC_process < this_aec_proc_time) {
					max_AEC_process = this_aec_proc_time;
				}
				if (this_AEC_times == 3000) {
					AEC_times += this_AEC_times;
					total_AEC_process += thisAEC_process;
					AUDIO_DBG_INFO("AEC this avg time = %ld, this max time %ld, total avg time %ld\r\n", thisAEC_process / this_AEC_times, max_AEC_process,
								   total_AEC_process / AEC_times);
					max_AEC_process = 0;
					this_AEC_times = 0;
					thisAEC_process = 0;
				}
#endif
			} else {
				memcpy((int16_t *)output_item->data_addr, (int16_t *)(dma_rxdata_proc_buf), AUDIO_DMA_PAGE_SIZE);
			}
#if defined(CONFIG_PLATFORM_8735B)
			if (ctx->mic_record_file) {
				ctx->mic_record_file((int16_t *)(proc_pretx_buf), (int16_t *)(proc_tx_buf), (int16_t *)(dma_rxdata_proc_buf),
									 (int16_t *)(output_item->data_addr)); //record left channel data
			}
#endif
			aec_proc_time = xTaskGetTickCount() - aec_proc_time;
			if (aec_proc_time > 20) {
				AUDIO_DBG_WARNING("AEC proc execution too long %dms\n\r", aec_proc_time);
			}
#if defined(AUDIO_DEBUG_H)
			if (audio_rx_aec_ena != 0) {
				AUDIO_DBG_INFO("start rx aec recording\n\r");
				audio_rx_aec_cnt = 0;
				audio_rx_aec_ena = 0;
			}
			if (audio_rx_aec_cnt < audio_rx_aec_len) {
				memcpy(&audio_rx_aec_buffer[audio_rx_aec_cnt], (void *)output_item->data_addr, AUDIO_DMA_PAGE_SIZE);
				audio_rx_aec_cnt += AUDIO_DMA_PAGE_SIZE;
				if (audio_rx_aec_cnt >= audio_rx_aec_len) {
#if defined(AUDIO_DEBUG_ENABLE)
					AUDIO_DBG_INFO("done for rx (aec) recording\n\r");
#endif
				}
			}
#endif
			if (proc_tx_ts != last_tx_ts) {
#if defined(AUDIO_DEBUG_ENABLE)
				AUDIO_DBG_INFO("TX buffer update when AEC processing\n\r");
#endif
				if (last_tx_ts - proc_tx_ts > 20) {
#if defined(AUDIO_DEBUG_ENABLE)
					AUDIO_DBG_INFO("last_tx_ts, proc_tx_ts diff %d > 20ms\n\r", last_tx_ts - proc_tx_ts);
#endif
				}
			}
			if (proc_rx_ts != last_rx_ts) {
#if defined(AUDIO_DEBUG_ENABLE)
				AUDIO_DBG_INFO("RX buffer update when AEC processing\n\r");
#endif
				if (last_rx_ts - proc_rx_ts > 20) {
#if defined(AUDIO_DEBUG_ENABLE)
					AUDIO_DBG_INFO("last_rx_ts, proc_rx_ts diff %d > 20ms\n\r", last_rx_ts - proc_rx_ts);
#endif
				}
			}
			output_item->size = RX_PAGE_SIZE;
			output_item->timestamp = proc_rx_buf.timestamp;
			output_item->hw_timestamp = proc_rx_buf.hw_timestamp;
			output_item->type = AV_CODEC_ID_PCM_RAW;
			xQueueSend(mctx->output_ready, (void *)&output_item, 0xFFFFFFFF);
		}
	}
}
#endif

int audio_control(void *p, int cmd, int arg)
{
	audio_ctx_t *ctx = (audio_ctx_t *)p;
	int sample_rate = 8000;
	switch (cmd) {
	case CMD_AUDIO_SET_ADC_GAIN:
		audio_adc_digital_vol(ctx->audio, arg);
		AUDIO_DBG_INFO("ADC Gain: 0x%x.\r\n", arg);
		break;
	case CMD_AUDIO_SET_DAC_GAIN:
		audio_dac_digital_vol(ctx->audio, arg);
		AUDIO_DBG_INFO("DAC Gain: 0x%x.\r\n", arg);
		break;
	case CMD_AUDIO_SET_MESSAGE_LEVEL: {
		if (arg == 0) { //level 0 no MESSAGE will be shown
			DBG_MMF_ERR_MSG_OFF(_MMF_DBG_AUDIO_);
			DBG_MMF_WARN_MSG_OFF(_MMF_DBG_AUDIO_);
			DBG_MMF_INFO_MSG_OFF(_MMF_DBG_AUDIO_);
		} else if (arg == 1) { //level 1 support INF, WARN and ERROR MESSAGE
			DBG_MMF_ERR_MSG_ON(_MMF_DBG_AUDIO_);
			DBG_MMF_WARN_MSG_ON(_MMF_DBG_AUDIO_);
			DBG_MMF_INFO_MSG_ON(_MMF_DBG_AUDIO_);
		} else if (arg == 2) { //level 2 support WARN and ERROR MESSAGE
			DBG_MMF_ERR_MSG_ON(_MMF_DBG_AUDIO_);
			DBG_MMF_WARN_MSG_ON(_MMF_DBG_AUDIO_);
			DBG_MMF_INFO_MSG_OFF(_MMF_DBG_AUDIO_);
		} else { //level 3 on;y support ERROR MESSAGE
			DBG_MMF_ERR_MSG_ON(_MMF_DBG_AUDIO_);
			DBG_MMF_WARN_MSG_OFF(_MMF_DBG_AUDIO_);
			DBG_MMF_INFO_MSG_OFF(_MMF_DBG_AUDIO_);
		}
	}
	break;
	case CMD_AUDIO_SET_PARAMS:
		memcpy(&ctx->params, (void *)arg, sizeof(audio_params_t));
		break;
	case CMD_AUDIO_GET_PARAMS:
		memcpy((void *)arg, &ctx->params, sizeof(audio_params_t));
		break;
#if defined(CONFIG_PLATFORM_8195BHP) || defined(CONFIG_PLATFORM_8735B)
#if ENABLE_ASP==1
	case CMD_AUDIO_SET_NS_ENABLE:
		if (arg > 3 || arg < 0)	{
			arg = 0;
		}
		ctx->rxcfg.ns_cfg.NS_EN = arg | 0x02;
		ctx->txcfg.ns_cfg.NS_EN = arg | 0x01;
		break;
	case CMD_AUDIO_SET_AEC_ENABLE:
		if (arg > 1 || arg < 0)	{
			arg = 0;
		}
		AUDIO_DBG_INFO("AEC Enable: %d.\r\n", arg);
		ctx->rxcfg.aec_cfg.AEC_EN = 1;
		break;
	case CMD_AUDIO_SET_AGC_ENABLE:
		if (arg > 3 || arg < 0)	{
			arg = 0;
		}
		ctx->rxcfg.agc_cfg.AGC_EN = arg | 0x02;
		ctx->txcfg.agc_cfg.AGC_EN = arg | 0x01;
		break;
#if !(defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
	case CMD_AUDIO_SET_VAD_ENABLE:
		if (arg > 1 || arg < 0)	{
			arg = 0;
		}
		ctx->rxcfg.vad_cfg.VAD_EN = arg;
		break;
#endif
	case CMD_AUDIO_SET_MIC_ENABLE:
		if (arg == 0) {
			audio_adc_digital_mute(ctx->audio, 1);
			AUDIO_DBG_INFO("MIC Disable\r\n");
		} else {
			audio_adc_digital_mute(ctx->audio, 0);
			AUDIO_DBG_INFO("MIC Enable\r\n");
		}
		break;
	case CMD_AUDIO_SET_SPK_ENABLE:
		if (arg == 0) {
			audio_dac_digital_mute(ctx->audio, 1);
			AUDIO_DBG_INFO("Speaker Disable\r\n");
		} else {
			audio_dac_digital_mute(ctx->audio, 0);
			AUDIO_DBG_INFO("Speaker Enable\r\n");
		}
		break;
	case CMD_AUDIO_RUN_NS:
		if (arg > 3 || arg < 0)	{
			arg = 0;
		}
		ctx->run_ns = arg;
		break;
	case CMD_AUDIO_RUN_AEC:
		if (arg > 1 || arg < 0)	{
			arg = 0;
		}
		ctx->run_aec = arg;
		break;
	case CMD_AUDIO_RUN_AGC:
		if (arg > 3 || arg < 0)	{
			arg = 0;
		}
		ctx->run_agc = arg;
		break;
	case CMD_AUDIO_RUN_VAD:
		if (arg > 1 || arg < 0)	{
			arg = 0;
		}
		ctx->run_vad = arg;
		break;
	case CMD_AUDIO_SET_AEC_LEVEL:
		sample_rate = audio_get_samplerate(ctx->params.sample_rate);
		ctx->run_aec = 0;
		vTaskDelay(FRAME_LENGTH_MS(sample_rate, ctx->word_length));     // wait for the AEC process of previous frames
		AEC_destory();
#if defined(CONFIG_PLATFORM_8735B) && (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
		ctx->rxcfg.aec_cfg.PPLevel = arg;
		AEC_init(FRAMESIZE, sample_rate, &(ctx->rxcfg.aec_cfg), &(ctx->rxcfg.agc_cfg), &(ctx->rxcfg.ns_cfg), 1.0f);
#else
		AEC_init(FRAMESIZE, sample_rate, &(ctx->rxcfg.aec_cfg), 1.0f);
		if (AEC_set_level(arg, &(ctx->rxcfg.aec_cfg)) != 0) {
			AUDIO_DBG_WARNING("Set AEC level fail.\r\n");
		}
#endif
		break;
#if defined(CONFIG_PLATFORM_8195BHP) || defined(CONFIG_PLATFORM_8735B)
	case CMD_AUDIO_SET_RXASP_PARAM:
		memcpy((void *) & (ctx->rxcfg), (void *) arg, sizeof(RX_cfg_t));
		break;
	case CMD_AUDIO_SET_TXASP_PARAM:
		memcpy((void *) & (ctx->txcfg), (void *) arg, sizeof(TX_cfg_t));
		break;
	case CMD_AUDIO_GET_RXASP_PARAM:
		memcpy((void *) arg, (void *) & (ctx->rxcfg), sizeof(RX_cfg_t));
		break;
	case CMD_AUDIO_GET_TXASP_PARAM:
		memcpy((void *) arg, (void *) & (ctx->txcfg), sizeof(TX_cfg_t));
		break;
#endif
#endif
	case CMD_AUDIO_SET_SAMPLERATE:
		ctx->params.sample_rate = (audio_sr)arg;
		break;
	case CMD_AUDIO_SET_TRX:
		if (arg == TRUE) {
			audio_trx_start(ctx->audio);
			AUDIO_DBG_INFO("START TRX\r\n");
			for (int i = 0; i < logic_input_num; i++) {
				xQueueReset(pcm_tx_cache[i].queue);
			}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
			for (int i = 0; i < logic_input_num; i++) {
				xQueueReset(pcm_pretx_cache[i].queue);
			}
			xQueueReset(pretx_record_queue);
#endif
		} else {
			audio_trx_stop(ctx->audio);
			AUDIO_DBG_INFO("STOP TRX\r\n");
		}
		break;
	case CMD_AUDIO_SET_MIC_RECORD_FUN:
		ctx->mic_record_file = (void (*)(void *, void *, void *, void *))arg;
		break;
	case CMD_AUDIO_SET_TIMESTAMP_OFFSET:
		ctx->audio_timestamp_offset = arg;
		break;
	case CMD_AUDIO_GET_FRAMESIZE_MS:
		sample_rate = audio_get_samplerate(ctx->params.sample_rate);
		do {
			int *framesize = (int *)arg;
			if (ctx->params.word_length == WL_16BIT) {
				*framesize = 1000 * (AUDIO_DMA_PAGE_SIZE / 2) / sample_rate;
			} else if (ctx->params.word_length == WL_24BIT) {
				*framesize = 1000 * (AUDIO_DMA_PAGE_SIZE / 3) / sample_rate;
			}
		} while (0);
		break;
	case CMD_AUDIO_SET_RESET:
		sample_rate = audio_get_samplerate(ctx->params.sample_rate);
#if ENABLE_ASP==1
		ctx->run_ns = 0;
		ctx->run_agc = 0;
		ctx->run_aec = 0;
		vTaskDelay(FRAME_LENGTH_MS(sample_rate, ctx->word_length));     // wait for the AEC process of previous frames
		if (pcm_rx_cache && (ctx->enable_rxasp || ctx->params.enable_record)) {
			xQueueReset(pcm_rx_cache);
		}
		audio_tx_stop(ctx->audio);
		audio_rx_stop(ctx->audio);
		audio_deinit(ctx->audio);

		if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
#if defined(CONFIG_PLATFORM_8735B) && (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
			ctx->enable_rxasp = 0;
			/* reset all voice algorithm */
			if (ctx->inited_ns & 0x1) {
				NS_destory();
			}
			ctx->inited_ns = 0;

			if (ctx->txcfg.ns_cfg.NS_EN) {
				NS_init(sample_rate, &(ctx->txcfg.ns_cfg));
				AUDIO_DBG_INFO("Inintial NS \r\n");
				ctx->inited_ns |= 0x1;
				ctx->run_ns |= 0x1;
				AUDIO_DBG_INFO("Set Speaker NS level %d\r\n", ctx->txcfg.ns_cfg.NSLevel);
			}

			if (ctx->inited_agc & 0x1) {
				AGC_destory();
			}
			ctx->inited_agc = 0;
			if (ctx->txcfg.agc_cfg.AGC_EN) {
				AGC_init(sample_rate, &(ctx->txcfg.agc_cfg));
				AUDIO_DBG_INFO("speaker AGC %d,%d,%d,%d\r\n", ctx->txcfg.agc_cfg.ReferenceLvl, ctx->txcfg.agc_cfg.RefThreshold, ctx->txcfg.agc_cfg.AttackTime,
							   ctx->txcfg.agc_cfg.ReleaseTime);
				ctx->inited_agc |= 0x1;
				ctx->run_agc |= 0x1;
			}

			if (ctx->inited_aec) {
				AEC_destory();
			}
			ctx->inited_aec = 0;


			if ((ctx->rxcfg.aec_cfg.AEC_EN) || (ctx->rxcfg.agc_cfg.AGC_EN) || (ctx->rxcfg.ns_cfg.NS_EN)) {
				AUDIO_DBG_INFO("Inintial RX ASP\r\n");
				AEC_init(FRAMESIZE, sample_rate, &(ctx->rxcfg.aec_cfg), &(ctx->rxcfg.agc_cfg), &(ctx->rxcfg.ns_cfg), 1.0f);
				ctx->inited_aec = 1;
				ctx->run_aec = 1;
				ctx->enable_rxasp = 1;
			}
			AUDIO_DBG_INFO("[16k_noise_issue]reset ns=%d agc=%d aec=%d.\r\n", ctx->rxcfg.ns_cfg.NS_EN, ctx->rxcfg.agc_cfg.AGC_EN, ctx->rxcfg.aec_cfg.AEC_EN);
#else
			ctx->enable_rxasp = 0;
			/* reset all voice algorithm */
			if (ctx->inited_ns & 0x1) {
				NS_destory();
			}
			if (ctx->inited_ns & 0x2) {
				NS2_destory();
			}
			ctx->inited_ns = 0;
			if (ctx->txcfg.ns_cfg.NS_EN) {
				NS_init(sample_rate, &(ctx->txcfg.ns_cfg));
				AUDIO_DBG_INFO("Inintial NS \r\n");
				ctx->inited_ns |= 0x1;
				ctx->run_ns |= 0x1;
				AUDIO_DBG_INFO("Set Speaker NS level %d\r\n", ctx->txcfg.ns_cfg.NSLevel);
			}
			if (ctx->rxcfg.ns_cfg.NS_EN) {
				NS2_init(sample_rate, &(ctx->rxcfg.ns_cfg));
				ctx->inited_ns |= 0x2;
				ctx->run_ns |= 0x2;
				AUDIO_DBG_INFO("Set MIC NS level %d\r\n", ctx->rxcfg.ns_cfg.NSLevel);
			}
			if (ctx->inited_agc & 0x1) {
				AGC_destory();
			}
			if (ctx->inited_agc & 0x2) {
				AGC2_destory();
			}
			ctx->inited_agc = 0;

			if (ctx->txcfg.agc_cfg.AGC_EN) {
				AGC_init(sample_rate, &(ctx->txcfg.agc_cfg));
				AUDIO_DBG_INFO("speaker AGC %d,%d,%d,%d\r\n", ctx->txcfg.agc_cfg.AGCMode, ctx->txcfg.agc_cfg.TargetLevelDbfs, ctx->txcfg.agc_cfg.CompressionGaindB,
							   ctx->txcfg.agc_cfg.LimiterEnable);
				ctx->inited_agc |= 0x1;
				ctx->run_agc |= 0x1;
			}
			if (ctx->rxcfg.agc_cfg.AGC_EN) {
				AGC2_init(sample_rate, &(ctx->rxcfg.agc_cfg));
				AUDIO_DBG_INFO("mic AGC %d,%d,%d,%d\r\n", ctx->rxcfg.agc_cfg.AGCMode, ctx->rxcfg.agc_cfg.TargetLevelDbfs, ctx->rxcfg.agc_cfg.CompressionGaindB,
							   ctx->rxcfg.agc_cfg.LimiterEnable);
				ctx->inited_agc |= 0x2;
				ctx->run_agc |= 0x2;
			}
			if (ctx->inited_aec) {
				AEC_destory();
			}
			ctx->inited_aec = 0;
			if (ctx->rxcfg.aec_cfg.AEC_EN) {
				AEC_init(FRAMESIZE, sample_rate, &(ctx->rxcfg.aec_cfg), 1.0f);
				AUDIO_DBG_INFO("set AEC level = %d, sdelay = %d\r\n", ctx->rxcfg.aec_cfg.AECLevel, ctx->rxcfg.aec_cfg.FilterLength);
				AUDIO_DBG_INFO("Inintial AEC \r\n");
				ctx->inited_aec = 1;
				ctx->run_aec = 1;
			}
			if (ctx->inited_vad) {
				VAD_destory();
			}
			ctx->inited_vad = 0;
			ctx->run_vad = 0;
			if (ctx->rxcfg.vad_cfg.VAD_EN) {
				VAD_init(sample_rate, &(ctx->rxcfg.vad_cfg));
				ctx->inited_vad = 0x1;
				ctx->run_vad = 0x1;
			}
			if (ctx->rxcfg.aec_cfg.AEC_EN || ctx->rxcfg.ns_cfg.NS_EN || ctx->rxcfg.vad_cfg.VAD_EN || ctx->rxcfg.agc_cfg.AGC_EN) {
				ctx->enable_rxasp = 1;
			}
#endif
		}
#endif

#if defined(CONFIG_PLATFORM_8735B)
		if (ctx->dmic_pin_set == 1) {
			AUDIO_DBG_INFO("demux audio dmic pin\r\n");
			audio_dmic_depinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);

			ctx->dmic_pin_set = 0;
		}
		if (ctx->params.use_mic_type == USE_AUDIO_AMIC) {
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, MIC_SINGLE_EDNED, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init AMIC \r\n");
		} else if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC) {
			audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
			ctx->dmic_pin_set = 1;
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_LEFT_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init Left DMIC \r\n");
		} else if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) {
			audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
			ctx->dmic_pin_set = 1;
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_RIGHT_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init Right DMIC \r\n");
		} else if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
			ctx->dmic_pin_set = 1;
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_STEREO_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init Stereo DMIC \r\n");
		} else {
			AUDIO_DBG_ERROR("unsupported MIC type \r\n");
			goto audio_control_fail;
		}
		audio_adc_digital_vol(ctx->audio, ctx->params.ADC_gain);
		audio_dac_digital_vol(ctx->audio, ctx->params.DAC_gain);
		//Init RX dma
		audio_rx_irq_handler(ctx->audio, audio_rx_complete, (uint32_t *)ctx);
		//Init TX dma
		audio_tx_irq_handler(ctx->audio, audio_tx_complete, (uint32_t *)ctx);
		//Init Err callback
		audio_err_irq_handler(ctx->audio, audio_err_callback, (uint32_t *)ctx);

		//audio_headphone_analog_mute(ctx->audio, 1);
		audio_set_dma_buffer(ctx->audio, dma_txdata, dma_rxdata, AUDIO_DMA_PAGE_SIZE, AUDIO_DMA_PAGE_NUM);

		if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			audio_set_param_adv(ctx->audio, ctx->params.sample_rate, ctx->params.word_length, A_MONO, A_STEREO);
		} else {
			audio_set_param_adv(ctx->audio, ctx->params.sample_rate, ctx->params.word_length, A_MONO, A_MONO);
		}

		for (int i = 0; i < (AUDIO_DMA_PAGE_NUM - 1); i++) {
			uint8_t *ptx_buf_reset = audio_get_tx_page_adr(ctx->audio);
			if (ptx_buf_reset) {
				memset(ptx_buf_reset, 0x0, TX_PAGE_SIZE);
				audio_set_tx_page(ctx->audio, ptx_buf_reset);
			}
			audio_set_rx_page(ctx->audio);
		}

		//Set up hpf for mic
		audio_adc_l_hpf(ctx->audio, 1, ctx->params.hpf_set);
		audio_adc_r_hpf(ctx->audio, 1, ctx->params.hpf_set);
		AUDIO_DBG_INFO("hpf_set = %d\r\n", ctx->params.hpf_set);


		if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC || ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC || ctx->params.use_mic_type == USE_AUDIO_AMIC) {
			AUDIO_DBG_INFO("left digital mic or analog mic set\r\n");
			for (uint32_t j = 0; j < 5; j++) {
				if (ctx->params.mic_l_eq[j].eq_enable) {
					audio_input_l_eq(ctx->audio, j, 1, ctx->params.mic_l_eq[j].eq_h0, ctx->params.mic_l_eq[j].eq_b1, ctx->params.mic_l_eq[j].eq_b2, ctx->params.mic_l_eq[j].eq_a1,
									 ctx->params.mic_l_eq[j].eq_a2);
					AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.mic_l_eq[j].eq_h0, ctx->params.mic_l_eq[j].eq_b1,
								   ctx->params.mic_l_eq[j].eq_b2, ctx->params.mic_l_eq[j].eq_a1, ctx->params.mic_l_eq[j].eq_a2);
				} else {
					audio_input_l_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
					AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
				}
			}
		}

		if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC || ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			AUDIO_DBG_INFO("right digital dmic set\r\n");
			for (uint32_t j = 0; j < 5; j++) {
				if (ctx->params.mic_r_eq[j].eq_enable) {
					audio_input_r_eq(ctx->audio, j, 1, ctx->params.mic_r_eq[j].eq_h0, ctx->params.mic_r_eq[j].eq_b1, ctx->params.mic_r_eq[j].eq_b2, ctx->params.mic_r_eq[j].eq_a1,
									 ctx->params.mic_r_eq[j].eq_a2);
					AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.mic_r_eq[j].eq_h0, ctx->params.mic_r_eq[j].eq_b1,
								   ctx->params.mic_r_eq[j].eq_b2, ctx->params.mic_r_eq[j].eq_a1, ctx->params.mic_r_eq[j].eq_a2);
				} else {
					audio_input_r_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
					AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
				}
			}
		}

		AUDIO_DBG_INFO("speaker set\r\n");
		for (uint32_t j = 0; j < 5; j++) {
			if (ctx->params.spk_l_eq[j].eq_enable) {
				audio_output_l_eq(ctx->audio, j, 1, ctx->params.spk_l_eq[j].eq_h0, ctx->params.spk_l_eq[j].eq_b1, ctx->params.spk_l_eq[j].eq_b2, ctx->params.spk_l_eq[j].eq_a1,
								  ctx->params.spk_l_eq[j].eq_a2);
				AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.spk_l_eq[j].eq_h0, ctx->params.spk_l_eq[j].eq_b1,
							   ctx->params.spk_l_eq[j].eq_b2, ctx->params.spk_l_eq[j].eq_a1, ctx->params.spk_l_eq[j].eq_a2);
			} else {
				audio_output_l_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
				AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
			}
		}

		if (ctx->params.use_mic_type == USE_AUDIO_AMIC) { // AMIC
			audio_mic_bias_ctrl(ctx->audio, 1, ctx->params.mic_bias);
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			AUDIO_DBG_INFO("set AMIC bias = %d, gain = %d\r\n", ctx->params.mic_bias, ctx->params.mic_gain);

		} else if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC) { // LEFT DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_l_dmic_gain(ctx->audio, ctx->params.dmic_l_gain);
			AUDIO_DBG_INFO("set LEFT DMIC gain = %d\r\n", ctx->params.dmic_l_gain);
		} else if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) { // RIGHT DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_r_dmic_gain(ctx->audio, ctx->params.dmic_r_gain);
			AUDIO_DBG_INFO("set RIGHT DMIC gain = %d\r\n", ctx->params.dmic_r_gain);
		} else if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) { // STEREO DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_l_dmic_gain(ctx->audio, ctx->params.dmic_l_gain);
			audio_r_dmic_gain(ctx->audio, ctx->params.dmic_r_gain);
			AUDIO_DBG_INFO("set LEFT/RIGHT DMIC gain = %d/%d\r\n", ctx->params.dmic_l_gain, ctx->params.dmic_r_gain);
		}
#else
		audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, MIC_SINGLE_EDNED, AUDIO_CODEC_2p8V);
		//audio_mic_analog_gain(ctx->audio, 1, AUDIO_MIC_40DB);
		//audio_adc_digital_vol(ctx->audio, 0x7F);
		audio_dac_digital_vol(ctx->audio, 0xAF);
		//audio_headphone_analog_mute(ctx->audio, 1);

		//Init RX dma
		audio_set_rx_dma_buffer(ctx->audio, dma_rxdata, RX_PAGE_SIZE);
		audio_rx_irq_handler(ctx->audio, audio_rx_complete, (uint32_t)ctx);
		//Init TX dma
		audio_set_tx_dma_buffer(ctx->audio, dma_txdata, TX_PAGE_SIZE);
		audio_tx_irq_handler(ctx->audio, audio_tx_complete, (uint32_t)ctx);
		audio_set_param(ctx->audio, ctx->params.sample_rate, ctx->params.word_length);  // ASR_8KHZ, ASR_16KHZ //ASR_48KHZ
		AUDIO_DBG_INFO("sample rate = %d, %d\r\n", ctx->params.sample_rate, audio_get_samplerate(ctx->params.sample_rate));
		audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain); // default 0DB
#endif
		audio_trx_start(ctx->audio);
		ctx->rx_first_frame = 1;
		for (int i = 0; i < logic_input_num; i++) {
			xQueueReset(pcm_tx_cache[i].queue);
		}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
		for (int i = 0; i < logic_input_num; i++) {
			xQueueReset(pcm_pretx_cache[i].queue);
		}
		xQueueReset(pretx_record_queue);
#endif
		break;
#endif
	case CMD_AUDIO_APPLY:
#if defined(CONFIG_PLATFORM_8735B)
		if (ctx->params.fcs_avsync_en) {
			ctx->fcs_avsync_done = 0;
		}
		if (ctx->params.use_mic_type == USE_AUDIO_AMIC) { // AMIC
			AUDIO_DBG_INFO("Init AMIC \r\n");
			//Audio Init
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, MIC_SINGLE_EDNED, AUDIO_CODEC_2p8V);
		} else if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC) {
			if (ctx->dmic_pin_set == 0) {
				audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
				ctx->dmic_pin_set = 1;
			}
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_LEFT_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init LEFT DMIC \r\n");
		} else if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) {
			if (ctx->dmic_pin_set == 0) {
				audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
				ctx->dmic_pin_set = 1;
			}
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_RIGHT_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init RIGHT DMIC \r\n");
		} else if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			if (ctx->dmic_pin_set == 0) {
				audio_dmic_pinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
				ctx->dmic_pin_set = 1;
			}
			audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, AUDIO_STEREO_DMIC, AUDIO_CODEC_2p8V);
			AUDIO_DBG_INFO("Init STEREO DMIC \r\n");
		} else {
			AUDIO_DBG_ERROR("unsupported MIC type \r\n");
			goto audio_control_fail;
		}
		audio_set_dma_buffer(ctx->audio, dma_txdata, dma_rxdata, AUDIO_DMA_PAGE_SIZE, AUDIO_DMA_PAGE_NUM);
		audio_adc_digital_vol(ctx->audio, ctx->params.ADC_gain);
		audio_dac_digital_vol(ctx->audio, ctx->params.DAC_gain);

		//Init RX dma
		audio_rx_irq_handler(ctx->audio, audio_rx_complete, (uint32_t *)ctx);
		//Init TX dma
		audio_tx_irq_handler(ctx->audio, audio_tx_complete, (uint32_t *)ctx);
		//Init Err callback
		audio_err_irq_handler(ctx->audio, audio_err_callback, (uint32_t *)ctx);

		ctx->sample_rate = audio_get_samplerate(ctx->params.sample_rate);

		AUDIO_DBG_INFO("sample rate = %d, %d\r\n", ctx->params.sample_rate, audio_get_samplerate(ctx->params.sample_rate));
		if (ctx->params.word_length == WL_16BIT) {
			ctx->word_length = 2;
		} else if (ctx->params.word_length == WL_24BIT) {
			ctx->word_length = 3;
		}
		if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			audio_set_param_adv(ctx->audio, ctx->params.sample_rate, ctx->params.word_length, A_MONO, A_STEREO); // ASR_8KHZ, ASR_16KHZ //ASR_48KHZ
		} else {
			audio_set_param_adv(ctx->audio, ctx->params.sample_rate, ctx->params.word_length, A_MONO, A_MONO);
		}
		// Use (DMA page count -1) because occur RX interrupt in first //
		for (int i = 0; i < (AUDIO_DMA_PAGE_NUM - 1); i++) {
			uint8_t *ptx_buf = audio_get_tx_page_adr(ctx->audio);
			if (ptx_buf) {
				memset(ptx_buf, 0x0, TX_PAGE_SIZE);
				audio_set_tx_page(ctx->audio, ptx_buf);
			}
			audio_set_rx_page(ctx->audio);
		}

		//Set up hpf for mic
		audio_adc_l_hpf(ctx->audio, 1, ctx->params.hpf_set);
		audio_adc_r_hpf(ctx->audio, 1, ctx->params.hpf_set);
		AUDIO_DBG_INFO("hpf_set = %d\r\n", ctx->params.hpf_set);

		if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC || ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC || ctx->params.use_mic_type == USE_AUDIO_AMIC) {
			AUDIO_DBG_INFO("left digital mic or analog mic set\r\n");
			for (uint32_t j = 0; j < 5; j++) {
				if (ctx->params.mic_l_eq[j].eq_enable) {
					audio_input_l_eq(ctx->audio, j, 1, ctx->params.mic_l_eq[j].eq_h0, ctx->params.mic_l_eq[j].eq_b1, ctx->params.mic_l_eq[j].eq_b2, ctx->params.mic_l_eq[j].eq_a1,
									 ctx->params.mic_l_eq[j].eq_a2);
					AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.mic_l_eq[j].eq_h0, ctx->params.mic_l_eq[j].eq_b1,
								   ctx->params.mic_l_eq[j].eq_b2, ctx->params.mic_l_eq[j].eq_a1, ctx->params.mic_l_eq[j].eq_a2);
				} else {
					audio_input_l_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
					AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
				}
			}
		}

		if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC || ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
			AUDIO_DBG_INFO("right digital dmic set\r\n");
			for (uint32_t j = 0; j < 5; j++) {
				if (ctx->params.mic_r_eq[j].eq_enable) {
					audio_input_r_eq(ctx->audio, j, 1, ctx->params.mic_r_eq[j].eq_h0, ctx->params.mic_r_eq[j].eq_b1, ctx->params.mic_r_eq[j].eq_b2, ctx->params.mic_r_eq[j].eq_a1,
									 ctx->params.mic_r_eq[j].eq_a2);
					AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.mic_r_eq[j].eq_h0, ctx->params.mic_r_eq[j].eq_b1,
								   ctx->params.mic_r_eq[j].eq_b2, ctx->params.mic_r_eq[j].eq_a1, ctx->params.mic_r_eq[j].eq_a2);
				} else {
					audio_input_r_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
					AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
				}
			}
		}

		AUDIO_DBG_INFO("speaker set\r\n");
		for (uint32_t j = 0; j < 5; j++) {
			if (ctx->params.spk_l_eq[j].eq_enable) {
				audio_output_l_eq(ctx->audio, j, 1, ctx->params.spk_l_eq[j].eq_h0, ctx->params.spk_l_eq[j].eq_b1, ctx->params.spk_l_eq[j].eq_b2, ctx->params.spk_l_eq[j].eq_a1,
								  ctx->params.spk_l_eq[j].eq_a2);
				AUDIO_DBG_INFO("OPEN EQ:0x%lx\r\nh0:0x%lx\r\nb1:0x%lx\r\nb2:0x%lx\r\na1:0x%lx\r\na2:0x%lx\r\n", j, ctx->params.spk_l_eq[j].eq_h0, ctx->params.spk_l_eq[j].eq_b1,
							   ctx->params.spk_l_eq[j].eq_b2, ctx->params.spk_l_eq[j].eq_a1, ctx->params.spk_l_eq[j].eq_a2);
			} else {
				audio_output_l_eq(ctx->audio, j, 0, 0, 0, 0, 0, 0);
				AUDIO_DBG_INFO("CLOSE EQ:0x%lx\r\n", j);
			}
		}

		if (ctx->params.use_mic_type == USE_AUDIO_AMIC) { // AMIC
			audio_mic_bias_ctrl(ctx->audio, 1, ctx->params.mic_bias);
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			AUDIO_DBG_INFO("set AMIC bias = %d, gain = %d\r\n", ctx->params.mic_bias, ctx->params.mic_gain);

		} else if (ctx->params.use_mic_type == USE_AUDIO_LEFT_DMIC) { // LEFT DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_l_dmic_gain(ctx->audio, ctx->params.dmic_l_gain);
			AUDIO_DBG_INFO("set LEFT DMIC gain = %d\r\n", ctx->params.dmic_l_gain);
		} else if (ctx->params.use_mic_type == USE_AUDIO_RIGHT_DMIC) { // RIGHT DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_r_dmic_gain(ctx->audio, ctx->params.dmic_r_gain);
			AUDIO_DBG_INFO("set RIGHT DMIC gain = %d\r\n", ctx->params.dmic_r_gain);
		} else if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) { // STEREO DMIC
			audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain);
			audio_l_dmic_gain(ctx->audio, ctx->params.dmic_l_gain);
			audio_r_dmic_gain(ctx->audio, ctx->params.dmic_r_gain);
			AUDIO_DBG_INFO("set LEFT/RIGHT DMIC gain = %d/%d\r\n", ctx->params.dmic_l_gain, ctx->params.dmic_r_gain);
		}

		audio_trx_start(ctx->audio);
		ctx->rx_first_frame = 1;
#else
		audio_init(ctx->audio, OUTPUT_SINGLE_EDNED, MIC_SINGLE_EDNED, AUDIO_CODEC_2p8V);
		//audio_mic_analog_gain(ctx->audio, 1, AUDIO_MIC_40DB);
		audio_adc_digital_vol(ctx->audio, 0x7F);
		audio_dac_digital_vol(ctx->audio, 0xAF);

		//audio_headphone_analog_mute(ctx->audio, 1);
		//Init RX dma
		audio_set_rx_dma_buffer(ctx->audio, dma_rxdata, RX_PAGE_SIZE);
		audio_rx_irq_handler(ctx->audio, audio_rx_complete, (uint32_t)ctx);
		//Init TX dma
		audio_set_tx_dma_buffer(ctx->audio, dma_txdata, TX_PAGE_SIZE);
		audio_tx_irq_handler(ctx->audio, audio_tx_complete, (uint32_t)ctx);

		if (ctx->params.sample_rate == ASR_8KHZ) {
			ctx->sample_rate = 8000;
		} else if (ctx->params.sample_rate == AUDIO_SR_16KHZ) {
			ctx->sample_rate = 16000;
		} else if (ctx->params.sample_rate == AUDIO_SR_32KHZ) {
			ctx->sample_rate = 32000;
		} else if (ctx->params.sample_rate == AUDIO_SR_44p1KHZ) {
			ctx->sample_rate = 44100;
		} else if (ctx->params.sample_rate == AUDIO_SR_48KHZ) {
			ctx->sample_rate = 48000;
		} else if (ctx->params.sample_rate == AUDIO_SR_88p2KHZ) {
			ctx->sample_rate = 88200;
		} else if (ctx->params.sample_rate == AUDIO_SR_96KHZ) {
			ctx->sample_rate = 96000;
		}


		if (ctx->params.word_length == WL_8BIT) {
			ctx->word_length = 1;
		} else if (ctx->params.word_length == WL_16BIT) {
			ctx->word_length = 2;
		} else if (ctx->params.word_length == WL_24BIT) {
			ctx->word_length = 3;
		}
		audio_set_param(ctx->audio, ctx->params.sample_rate, ctx->params.word_length);  // ASR_8KHZ, ASR_16KHZ //ASR_48KHZ
		audio_mic_analog_gain(ctx->audio, 1, ctx->params.mic_gain); // default 0DB

		audio_trx_start(ctx->audio);
		ctx->rx_first_frame = 1;
#endif
		// mix mode --> LOGIC_INPUT_NUM input, non-mix mode 1 input
		if (ctx->params.mix_mode) {
			logic_input_num = LOGIC_INPUT_NUM;
		}
		pcm_tx_cache = malloc(logic_input_num * sizeof(pcm_tx_cache_t));
		if (!pcm_tx_cache) {
			AUDIO_DBG_ERROR("\r\n pcm tx cache: Create Error\n");
			goto audio_control_fail;
		}
		memset(pcm_tx_cache, 0, logic_input_num * sizeof(pcm_tx_cache_t));
		for (int i = 0; i < logic_input_num; i++) {
			memset(pcm_tx_cache[i].txbuf, 0x80, AUDIO_DMA_PAGE_SIZE);	// set to audio level 0;
			pcm_tx_cache[i].queue = xQueueCreate(AUDIO_TX_PCM_QUEUE_LENGTH, AUDIO_DMA_PAGE_SIZE);
			if (!pcm_tx_cache[i].queue) {
				goto audio_control_fail;
			}
		}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
		pcm_pretx_cache = malloc(logic_input_num * sizeof(pcm_tx_cache_t));
		if (!pcm_pretx_cache) {
			AUDIO_DBG_ERROR("\r\n pcm tx cache: Create Error\n");
			goto audio_control_fail;
		}
		memset(pcm_pretx_cache, 0, logic_input_num * sizeof(pcm_tx_cache_t));
		for (int i = 0; i < logic_input_num; i++) {
			memset(pcm_pretx_cache[i].txbuf, 0x80, AUDIO_DMA_PAGE_SIZE);	// set to audio level 0;
			pcm_pretx_cache[i].queue = xQueueCreate(AUDIO_TX_PCM_QUEUE_LENGTH, AUDIO_DMA_PAGE_SIZE);
			if (!pcm_pretx_cache[i].queue) {
				goto audio_control_fail;
			}
		}
		pretx_record_queue = xQueueCreate(TX_PAGE_NUM, AUDIO_DMA_PAGE_SIZE);
#endif
#if ENABLE_ASP==1
#if defined(CONFIG_PLATFORM_8735B) && defined(CONFIG_NEWAEC) && CONFIG_NEWAEC
		if ((ctx->rxcfg.aec_cfg.AEC_EN) || (ctx->rxcfg.agc_cfg.AGC_EN) || (ctx->rxcfg.ns_cfg.NS_EN)) {
			ctx->enable_rxasp = 1;
		}
#else
		if ((ctx->rxcfg.aec_cfg.AEC_EN) || (ctx->rxcfg.agc_cfg.AGC_EN) || (ctx->rxcfg.ns_cfg.NS_EN) || (ctx->rxcfg.vad_cfg.VAD_EN)) {
			ctx->enable_rxasp = 1;
		}
#endif
		if (ctx->enable_rxasp || ctx->params.enable_record) {
			ctx->aec_rx_done_sema = xSemaphoreCreateBinary();
			if (!ctx->aec_rx_done_sema) {
				goto audio_control_fail;
			}
			pcm_rx_cache = xQueueCreate(RX_CACHE_DEPTH, sizeof(pcm_rx_t));
			if (!pcm_rx_cache) {
				goto audio_control_fail;
			}
			if (xTaskCreate(audio_rx_handle_thread, ((const char *)"audio_rx"), 24 * 1024, (void *)ctx, tskIDLE_PRIORITY + 5, &ctx->aec_rx_task) != pdPASS) {
				AUDIO_DBG_ERROR("\r\n audio_rx_handle_thread: Create Task Error\n");
				goto audio_control_fail;
			}
		}
		if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
			sample_rate = audio_get_samplerate(ctx->params.sample_rate);
#if defined(CONFIG_PLATFORM_8735B) && (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
			if (ctx->txcfg.ns_cfg.NS_EN) {
				NS_init(sample_rate, &(ctx->txcfg.ns_cfg));
				AUDIO_DBG_INFO("Set Speaker NS level %d\r\n", ctx->txcfg.ns_cfg.NSLevel);
				ctx->inited_ns |= 0x1;
				ctx->run_ns |= 0x1;
			}
			if (ctx->txcfg.agc_cfg.AGC_EN) {
				AGC_init(sample_rate, &(ctx->txcfg.agc_cfg));
				AUDIO_DBG_INFO("speaker AGC %d,%d,%d,%d\r\n", ctx->txcfg.agc_cfg.ReferenceLvl, ctx->txcfg.agc_cfg.RefThreshold, ctx->txcfg.agc_cfg.AttackTime,
							   ctx->txcfg.agc_cfg.ReleaseTime);

				ctx->inited_agc |= 0x1;
				ctx->run_agc |= 0x1;
			}
#else
			if (ctx->txcfg.ns_cfg.NS_EN) {
				NS_init(sample_rate, &(ctx->txcfg.ns_cfg));
				AUDIO_DBG_INFO("Set Speaker NS level %d\r\n", ctx->txcfg.ns_cfg.NSLevel);
				ctx->inited_ns |= 0x1;
				ctx->run_ns |= 0x1;
			}
			if (ctx->txcfg.agc_cfg.AGC_EN) {
				AGC_init(sample_rate, &(ctx->txcfg.agc_cfg));
				AUDIO_DBG_INFO("speaker AGC %d,%d,%d,%d\r\n", ctx->txcfg.agc_cfg.AGCMode, ctx->txcfg.agc_cfg.TargetLevelDbfs, ctx->txcfg.agc_cfg.CompressionGaindB,
							   ctx->txcfg.agc_cfg.LimiterEnable);
				ctx->inited_agc |= 0x1;
				ctx->run_agc |= 0x1;
			}
#endif
#endif
		}
		break;
	}
	return 0;
audio_control_fail:
	AUDIO_DBG_ERROR("audio_control fail\n\r");
	if (ctx->aec_rx_done_sema) {
		vSemaphoreDelete(ctx->aec_rx_done_sema);
		ctx->aec_rx_done_sema = NULL;
	}
#if ENABLE_ASP==1
	if (pcm_rx_cache) {
		vQueueDelete(pcm_rx_cache);
		pcm_rx_cache = NULL;
	}
#endif
	if (ctx->aec_rx_task) {
		vTaskDelete(ctx->aec_rx_task);
		ctx->aec_rx_task = NULL;
	}
	if (pcm_tx_cache) {
		for (int i = 0; i < logic_input_num; i++)
			if (pcm_tx_cache[i].queue) {
				vQueueDelete(pcm_tx_cache[i].queue);
			}
		free(pcm_tx_cache);
		pcm_tx_cache = NULL;
	}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
	if (pcm_pretx_cache) {
		for (int i = 0; i < logic_input_num; i++)
			if (pcm_pretx_cache[i].queue) {
				vQueueDelete(pcm_pretx_cache[i].queue);
			}
		free(pcm_pretx_cache);
		pcm_pretx_cache = NULL;
	}
	if (pretx_record_queue) {
		vQueueDelete(pretx_record_queue);
		pretx_record_queue = NULL;
	}
#endif
	return -1;
}

int audio_handle(void *p, void *input, void *output)
{
	audio_ctx_t *ctx = (audio_ctx_t *)p;
	mm_queue_item_t *input_item = (mm_queue_item_t *)input;
	uint8_t *input_data = (uint8_t *)input_item->data_addr;
	(void)output;
	int cache_idx = input_item->in_idx > (logic_input_num - 1) ? 0 : input_item->in_idx;
	pcm_tx_cache_t *cache = &pcm_tx_cache[cache_idx];
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
	pcm_tx_cache_t *pretx_cache = &pcm_pretx_cache[cache_idx];
#endif

	for (int i = 0; i < input_item->size; i++) {
		cache->buffer[cache->idx++] = input_data[i];
		if (cache->idx == AUDIO_DMA_PAGE_SIZE) {
#if ENABLE_ASP==1
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
			if (xQueueSend(pretx_cache->queue, cache->buffer, 1000) != pdTRUE) {
				AUDIO_DBG_WARNING("fail to send tx queue\r\n");
			}
#endif
			if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
				if ((ctx->inited_ns & 0x1) && (ctx->run_ns & 0x1) && (ATAF_NS_CTRL & 0x1)) {
					NS_process(AUDIO_DMA_PAGE_SIZE / sizeof(int16_t), (int16_t *)cache->buffer);
				}
				if ((ctx->inited_agc & 0x1) && (ctx->run_agc & 0x1) && (ATAF_AGC_CTRL & 0x1)) {
					AGC_process(AUDIO_DMA_PAGE_SIZE / sizeof(int16_t), (int16_t *)(cache->buffer));
				}
			}
#endif
			if (xQueueSend(cache->queue, cache->buffer, 1000) != pdTRUE) {
				AUDIO_DBG_WARNING("fail to send tx queue\r\n");
			}
			cache->idx = 0;
		}
	}
	//
	return 0;
}

void *audio_destroy(void *p)
{
	audio_ctx_t *ctx = (audio_ctx_t *)p;

	//stop the audio
	if (ctx) {
		audio_tx_stop(ctx->audio);
		audio_rx_stop(ctx->audio);
		audio_deinit(ctx->audio);
		if (ctx->dmic_pin_set == 1) {
			audio_dmic_depinmux(ctx->audio, DMIC_CLK_PIN, DMIC_DATA_PIN);
			ctx->dmic_pin_set = 0;
		}
	}
	if (pcm_tx_cache) {
		for (int i = 0; i < logic_input_num; i++)
			if (pcm_tx_cache[i].queue) {
				vQueueDelete(pcm_tx_cache[i].queue);
			}
		free(pcm_tx_cache);
		pcm_tx_cache = NULL;
	}
#if defined(SAVE_AUDIO_DATA) && SAVE_AUDIO_DATA
	if (pcm_pretx_cache) {
		for (int i = 0; i < logic_input_num; i++)
			if (pcm_pretx_cache[i].queue) {
				vQueueDelete(pcm_pretx_cache[i].queue);
			}
		free(pcm_pretx_cache);
		pcm_pretx_cache = NULL;
	}
	if (pretx_record_queue) {
		vQueueDelete(pretx_record_queue);
		pretx_record_queue = NULL;
	}
#endif
#if ENABLE_ASP==1
	if (pcm_rx_cache) {
		vQueueDelete(pcm_rx_cache);
		pcm_rx_cache = NULL;
	}
#endif

	if (ctx) {
		if (ctx->aec_rx_done_sema) {
			vSemaphoreDelete(ctx->aec_rx_done_sema);
		}
		if (ctx->aec_rx_task) {
			vTaskDelete(ctx->aec_rx_task);
		}
		if (ctx->audio) {
			free(ctx->audio);
		}

#if ENABLE_ASP==1
		if (ctx->params.sample_rate == ASR_8KHZ || ctx->params.sample_rate == ASR_16KHZ) {
			if (ctx->inited_ns & 0x1) {
				NS_destory();
			}
			if (ctx->inited_agc & 0x1) {
				AGC_destory();
			}
			if (ctx->inited_aec) {
				AEC_destory();
			}
#if !(defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
			if (ctx->inited_ns & 0x2) {
				NS2_destory();
			}
			if (ctx->inited_agc & 0x2) {
				AGC2_destory();
			}
			if (ctx->inited_vad) {
				VAD_destory();
			}
#endif
		}
#endif

		free(ctx);
		ctx = NULL;
	}
	return NULL;
}

void *audio_create(void *parent)
{
	audio_ctx_t *ctx = malloc(sizeof(audio_ctx_t));
	if (!ctx) {
		return NULL;
	}

	memset(ctx, 0, sizeof(audio_ctx_t));
	ctx->parent = parent;
	ctx->audio = malloc(sizeof(audio_t));
	if (!ctx->audio) {
		goto audio_create_fail;
	}
	memset(ctx->audio, 0, sizeof(audio_t));
	mm_module_ctrl(ctx->parent, CMD_AUDIO_SET_MESSAGE_LEVEL, AUDIO_LOG_LEVEL);
#if defined(CONFIG_PLATFORM_8735B) //only test on 8735
	//audio default setting
	memcpy((void *)&ctx->params, (void *)&default_audio_params, sizeof(audio_params_t));
#endif
	//audio signal processing default setting
	memcpy((void *)&ctx->rxcfg, (void *)&default_rx_asp_params, sizeof(RX_cfg_t));
	memcpy((void *)&ctx->txcfg, (void *)&default_tx_asp_params, sizeof(TX_cfg_t));


#if ENABLE_ASP==1
#if (defined(CONFIG_NEWAEC) && CONFIG_NEWAEC)
	AEC_set_print(AEC_LOG_EN);
#endif
	memset(last_tx_buf, 0, AUDIO_DMA_PAGE_SIZE);	//MIC_SINGLE_EDNED
	//ctx->run_aec = 0;
	ctx->run_ns = 0;
	ctx->run_agc = 0;
	ctx->run_vad = 0;
	//ctx->inited_aec = 0;
	ctx->inited_ns = 0;
	ctx->inited_agc = 0;
	ctx->inited_vad = 0;
#endif
#if defined(CONFIG_PLATFORM_8735B)
	ctx->dmic_pin_set = 0;
#endif
	return ctx;
audio_create_fail:
	audio_destroy((void *)ctx);
	return NULL;
}

void *audio_new_item(void *p)
{
	audio_ctx_t *ctx = (audio_ctx_t *)p;
	// get parameter
	void *ptr;
	if (ctx->params.use_mic_type == USE_AUDIO_STEREO_DMIC) {
		ptr = malloc(AUDIO_DMA_PAGE_SIZE * 2);
		memset(ptr, 0x0,  AUDIO_DMA_PAGE_SIZE * 2);
	} else {
		ptr = malloc(AUDIO_DMA_PAGE_SIZE);
		memset(ptr, 0x0,  AUDIO_DMA_PAGE_SIZE);
	}
	return ptr;
}

void *audio_del_item(void *p, void *d)
{
	if (d) {
		free(d);
	}
	return NULL;
}

mm_module_t audio_module = {
	.create = audio_create,
	.destroy = audio_destroy,
	.control = audio_control,
	.handle = audio_handle,

	.new_item = audio_new_item,
	.del_item = audio_del_item,

	.output_type = MM_TYPE_ADSP | MM_TYPE_ASINK,   // no output
	.module_type = MM_TYPE_ASRC | MM_TYPE_ASINK,
	.name = "AUDIO"
};

#if defined(CONFIG_PLATFORM_8735B)
audio_params_t default_audio_params = {
	.sample_rate        = ASR_8KHZ, //when modify please also check the EQ setting
	.word_length        = WL_16BIT,
	.mic_gain           = MIC_0DB,
	.dmic_l_gain        = DMIC_BOOST_0DB,
	.dmic_r_gain        = DMIC_BOOST_0DB,
	.use_mic_type       = USE_AUDIO_AMIC,
	.channel            = 1,
	.mix_mode           = 0,
	.mic_bias           = 0,
	.hpf_set            = 0,
	.ADC_gain           = 0x66,	//ADC path Dgain about 20dB
	.DAC_gain           = 0xAF,
	.enable_record      = 0,
	.mic_l_eq[0]        = {1, 0x1ca2925, 0x1c000000, 0x2000000, 0x38ea551, 0x1e6600bf}, //USE EQ for HPF 200Hz @ sample rate 8kHz
	.mic_r_eq[0]        = {1, 0x1ca2925, 0x1c000000, 0x2000000, 0x38ea551, 0x1e6600bf}, //USE EQ for HPF 200Hz @ sample rate 8kHz
	.spk_l_eq[0]        = {1, 0x1ca2925, 0x1c000000, 0x2000000, 0x38ea551, 0x1e6600bf}, //USE EQ for HPF 200Hz @ sample rate 8kHz
	//.mic_l_eq[0]      = {1, 0x1e45618, 0x1c000000, 0x2000000, 0x3c72d61, 0x1e35d500}, //USE EQ for HPF 200Hz @ sample rate 16kHz
	//.mic_r_eq[0]      = {1, 0x1e45618, 0x1c000000, 0x2000000, 0x3c72d61, 0x1e35d500}, //USE EQ for HPF 200Hz @ sample rate 16kHz
	//.spk_l_eq[0]      = {1, 0x1e45618, 0x1c000000, 0x2000000, 0x3c72d61, 0x1e35d500}, //USE EQ for HPF 200Hz @ sample rate 16kHz
};
#endif

//here are the setting for the audio signal processing (AEC/AGC/NS)
#if defined(CONFIG_PLATFORM_8735B) && defined(CONFIG_NEWAEC) && CONFIG_NEWAEC
RX_cfg_t default_rx_asp_params = {
	.aec_cfg = {
		.AEC_EN = 0,
		.EchoTailLen = 64,
		.CNGEnable = 1,
		.PPLevel = 6,
		.DTControl = 1,
	},
	.agc_cfg = {
		.AGC_EN = 0,
		.AGCMode = CT_ALC,
		.ReferenceLvl = 6,
		.RefThreshold = 6,
		.AttackTime = 20,
		.ReleaseTime = 20,
		.Ratio = {50, 50, 50},
		.Threshold = {20, 30, 40},
		.KneeWidth = 0,
		.NoiseFloorAdaptEnable = 0,
	},
	.ns_cfg = {
		.NS_EN = 0,
		.NSLevel = 5,
		.HPFEnable = 0,
	}
};

TX_cfg_t default_tx_asp_params = {
	.agc_cfg = {
		.AGC_EN = 0,
		.AGCMode = CT_ALC,
		.ReferenceLvl = 6,
		.RefThreshold = 6,
		.AttackTime = 20,
		.ReleaseTime = 20,
		.Ratio = {50, 50, 50},
		.Threshold = {20, 30, 40},
		.KneeWidth = 0,
		.NoiseFloorAdaptEnable = 0,
	},
	.ns_cfg = {
		.NS_EN = 0,
		.NSLevel = 5,
		.HPFEnable = 0,
	},
};
#else
RX_cfg_t default_rx_asp_params = {
	.aec_cfg = {
		.AEC_EN = 0,
		.aec_core = WEBRTC_AECM,
		.FilterLength = 30,
		.CNGEnable = 1,
		.AECLevel = 3,

		//for the AGC embedded in AEC
		.AGC_EN = 0,
		.AGCMode = 2,
		.TargetLevelDbfs = 0,
		.CompressionGaindB = 18,
		.LimiterEnable = 1,

		//for the NS embedded in AEC
		.NS_EN = 0,
		.NSLevel = 3,

		//howling suppression only used in webrtc
		.HOWL_EN = 0,
		.HOWL_AGC_EN = 0,
		.HOWL_AGCMode = 2,
		.HOWL_TargetLevelDbfs = 0,
		.HOWL_CompressionGaindB = 18,
		.HOWL_LimiterEnable = 1,

		.HOWL_NS_EN = 0,
		.HOWL_NSLevel = 3,
	},
	.agc_cfg = {
		.AGC_EN = 0,
		.AGCMode = 2,
		.TargetLevelDbfs = 0,
		.CompressionGaindB = 18,
		.LimiterEnable = 1,
	},
	.ns_cfg = {
		.NS_EN = 0,
		.NSLevel = 5,
	}
};

TX_cfg_t default_tx_asp_params = {
	.agc_cfg = {
		.AGC_EN = 0,
		.AGCMode = 2,
		.TargetLevelDbfs = 0,
		.CompressionGaindB = 18,
		.LimiterEnable = 1,
	},
	.ns_cfg = {
		.NS_EN = 0,
		.NSLevel = 5,
	},
};
#endif