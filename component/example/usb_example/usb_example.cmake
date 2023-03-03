### add lib ###
list(
	APPEND app_example_lib
)

### add flags ###
list(
	APPEND app_example_flags
)

### add header files ###
list (
	APPEND app_example_inc_path
)

### add source file ###
list(
	APPEND app_example_sources
	app_example.c
	usb_example.c
	#example_media_uvc.c
	example_usb_dfu_ota.c
	example_usbd_cdc_acm_new.c
	example_usbh_msc_new.c
	example_usbd_msc_new.c
	#example_usbh_ecm_new.c
	example_media_rtsp_ethernet.c
)
list(TRANSFORM app_example_sources PREPEND ${CMAKE_CURRENT_LIST_DIR}/)
