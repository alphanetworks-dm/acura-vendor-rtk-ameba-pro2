#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "platform_stdlib.h"
#include <unistd.h>
#include <sys/wait.h>
#include "base_type.h"
#include "cmsis.h"
#include "error.h"
#include "hal.h"
#include "hal_snand.h"
#include "diag.h"
#include "hal_spic.h"
#include "hal_flash.h"
#include "fw_img_export.h"
#include "hal_spic.h"
extern hal_spic_adaptor_t _hal_spic_adaptor;
static void user_boot_hexdump(void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char *)addr;
	if (len == 0) {
		dbg_printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		dbg_printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}
	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).
		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0) {
				dbg_printf("  %s\n", buff);
			}

			// Output the offset.
			dbg_printf("  %04x ", i);
		}
		// Now the hex code for the specific character.
		dbg_printf(" %02x", pc[i]);
		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		} else {
			buff[i % 16] = pc[i];
		}
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		dbg_printf("   ");
		i++;
	}
	// And print the final ASCII bit.
	dbg_printf("  %s\n", buff);
}

#define NOR_FLASH_BASE		0x08000000
#define BOOT_FLAG_ADDR		0xF0000
#define USER_BOOT_VER		"0.1"

int user_boot_read_flash_data(unsigned int address, unsigned char *buf, int length)
{
	/* dcache_invalidate_by_addr((uint32_t *)NOR_FLASH_BASE + address, 2048);
	memcpy(buf, (void *)(NOR_FLASH_BASE + address), length); */
	dcache_invalidate_by_addr((uint32_t *)(NOR_FLASH_BASE + address), length);
	hal_flash_stream_read(&_hal_spic_adaptor, length, address, buf);
}

int check_fw_boot_index(fw_img_user_export_info_type_t *pfw_img_user_export_info)
{
	uint8_t data[2048] __attribute__((aligned(32)));
	unsigned int address = BOOT_FLAG_ADDR;

	memset(data, 0, sizeof(data));
	user_boot_read_flash_data(address, data, sizeof(data));
	//user_boot_hexdump(data, 128);
	dbg_printf("BOOT IDX = 0x%02x\n", data[0]);

	if (data[0] == 0x01 && pfw_img_user_export_info->fw1_ld_sel_info.valid == 0x01) {
		dbg_printf("BOOT IDX = 0x%02x, and FW1 is valid\n", data[0]);
		return USER_LOAD_FW1;
	} else if (data[0] == 0x02 && pfw_img_user_export_info->fw2_ld_sel_info.valid == 0x01) {
		dbg_printf("BOOT IDX = 0x%02x, and FW2 is valid\n", data[0]);
		return USER_LOAD_FW2;
	} else
		return USER_LOAD_FW_FOLLOW_DEFAULT;
}

uint8_t user_boot_fw_selection(fw_img_user_export_info_type_t *pfw_img_user_export_info)
{
	dbg_printf("USER_BOOT_VER = %s\n", USER_BOOT_VER);
	dbg_printf("fw1 valid = 0x%x\n", pfw_img_user_export_info->fw1_ld_sel_info.valid);
	dbg_printf("fw2 valid = 0x%x\n", pfw_img_user_export_info->fw2_ld_sel_info.valid);
	//return USER_LOAD_FW_FOLLOW_DEFAULT;
	return check_fw_boot_index(pfw_img_user_export_info);
}


void spic_user_select(uint8_t *pspic_bit_mode)
{
	*pspic_bit_mode = SPIC_BIT_MODE_SETTING;
}

