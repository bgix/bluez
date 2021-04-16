// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/mesh-config.h"
#include "mesh/ob-msg.h"

static uint8_t ob_msg[MAX_MSG_LEN];
static uint8_t *cur_end;

uint8_t *mesh_ob_buf(uint16_t *available)
{
	if (cur_end < ob_msg || cur_end >= &ob_msg[sizeof(ob_msg)])
		cur_end = ob_msg;

	*available = sizeof(ob_msg) - (uint16_t) (cur_end - ob_msg);
	return cur_end;
}

uint16_t mesh_ob_opcode_set(uint32_t opcode, uint8_t *buf)
{
	uint16_t n = 0;

	if (buf > ob_msg && buf <= &ob_msg[sizeof(ob_msg)]) {
		*buf++ = 0;
		n++;
	}

	if (opcode <= 0x7e) {
		buf[0] = opcode;
		return n + 1;
	}

	if (opcode >= 0x8000 && opcode <= 0xbfff) {
		l_put_be16(opcode, buf);
		return n + 2;
	}

	if (opcode >= 0xc00000 && opcode <= 0xffffff) {
		buf[0] = (opcode >> 16) & 0xff;
		l_put_be16(opcode, buf + 1);
		return n + 3;
	}

	l_debug("Illegal Opcode %x", opcode);
	return 0;
}

uint16_t mesh_ob_finalize(uint8_t *buf, uint16_t len)
{
	if (!len || buf < ob_msg || buf >= &ob_msg[sizeof(ob_msg)])
		return 0;

	if (ob_msg == buf) {
		cur_end = ob_msg + len;
		return len;
	}

	if (len <= 0x80) {
		*buf = (uint8_t) (len - 1);
		cur_end += len;
		return len;
	} else if (len <= 0x8000) {
		/* If this is a rare aggregation larger than 127, adjust
		 * length parameter to LE16.
		 */

		/* Check for overflow */
		if (&buf[len + 1] >= &ob_msg[sizeof(ob_msg)])
			return 0;

		memmove(buf, buf + 1, len);
		l_put_le16((len - 1) | 0x8000, buf);
		cur_end += len + 1;
		return len + 1;
	} else
		return 0;
}

bool mesh_ob_ready_to_send(uint8_t *buf)
{
	return buf == ob_msg;
}

void mesh_ob_reset(void)
{
	cur_end = ob_msg;
}
