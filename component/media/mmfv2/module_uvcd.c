/******************************************************************************
*
* Copyright(c) 2007 - 2018 Realtek Corporation. All rights reserved.
*
******************************************************************************/

#include <stdint.h>
#include "mmf2_module.h"
#include "module_uvcd.h"
#include "uvc/inc/usbd_uvc_desc.h"
//------------------------------------------------------------------------------
#define num 1

struct uvc_format *uvc_format_ptr = NULL;

static struct usbd_uvc_buffer uvc_payload[num];



void uvcd_change_format_resolution(void *ctx)
{
	//struct uvc_format *uvc_forma_ctx = (struct uvc_format *)ctx;
	//rtw_up_senma_from_isr(&uvc_format_ptr->uvcd_change_sema);
	rtw_up_sema_from_isr(&uvc_format_ptr->uvcd_change_sema);
}

void *uvcd_create(void *parent)
{
	struct uvc_dev *uvc_ctx = get_private_usbd_uvc();
	int i = 0;
	int status = 0;
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
	if (!uvc_ctx)	{
		return NULL;
	}

	if (usbd_uvc_init() < 0) {
		uvc_ctx = NULL;
		printf("usbd uvc init error\r\n");
	}


	for (i = 0; i < num; i++) {
		uvc_video_put_out_stream_queue(&uvc_payload[i], uvc_ctx);
	}
	uvc_ctx->change_parm_cb = uvcd_change_format_resolution;
	return (void *)uvc_ctx;
exit:
	return NULL;
}

int uvcd_handle(void *p, void *input, void *output)
{
	int ret = 0;
	//uvcd_ctx *ctx = (uvcd_ctx *) p;
	struct uvc_dev *uvc_ctx = (struct uvc_dev *)p;
	mm_queue_item_t *input_item = (mm_queue_item_t *)input;
	struct usbd_uvc_buffer *payload = NULL;//&rtp_payload;
	//printf("input address = %x\r\n\r\n",input_item->data_addr);


	//printf("uvcd_mod_handle\r\n");
	if (uvc_ctx->common->running == 0) {
		goto end;
	}

	do {
		payload = uvc_video_out_stream_queue(uvc_ctx);
		if (payload == NULL) {
			printf("NULL\r\n");
			vTaskDelay(1);
		}
	} while (payload == NULL);


	payload->mem = (unsigned char *) input_item->data_addr;
	payload->bytesused = input_item->size;
	uvc_video_put_in_stream_queue(payload, uvc_ctx);
	rtw_down_sema(&uvc_ctx->video.output_queue_sema);
end:
	return ret;
}

int uvcd_control(void *p, int cmd, int arg)
{
	// struct uvc_dev *uvc_ctx = (struct uvc_dev *)p;
	return 0;
}

void *uvcd_destroy(void *p)
{
	// struct uvc_dev *uvc_ctx = (struct uvc_dev *)p;

	//if(ctx)	free(ctx);
	return NULL;
}

mm_module_t uvcd_module = {
	.create = uvcd_create,
	.destroy = uvcd_destroy,
	.control = uvcd_control,
	.handle = uvcd_handle,

	.new_item = NULL,
	.del_item = NULL,

	.output_type = MM_TYPE_NONE,     // no output
	.module_type = MM_TYPE_VSINK,    // module type is video algorithm
	.name = "UVCD"
};