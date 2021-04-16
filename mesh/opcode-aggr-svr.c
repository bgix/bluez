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
#include "mesh/ob-msg.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/mesh-config.h"
#include "mesh/opcode-aggr.h"

static bool opcode_aggr_srv_pkt(uint16_t src, uint16_t dst, uint16_t app_idx,
				uint16_t net_idx, const uint8_t *data,
				uint16_t size, const void *user_data)
{
	struct mesh_node *node = (struct mesh_node *) user_data;
	const uint8_t *pkt = data;
	uint8_t *msg, *rsp_status;
	uint32_t opcode;
	uint16_t n;
	uint16_t item_len;
	uint16_t dst_addr;
	ssize_t pkt_size = size;


	if (app_idx != APP_IDX_DEV_LOCAL)
		return false;

	if (mesh_model_opcode_get(pkt, size, &opcode, &n)) {
		pkt_size -= n;
		pkt += n;
	} else
		return false;

	l_debug("OPCODE-AGGR-opcode 0x%x size %u idx %3.3x", opcode, size,
								net_idx);

	n = 0;

	switch (opcode) {
	default:
		return false;

	case OP_AGGREGATOR_SEQ:
		if (pkt_size < 2)
			return true;

		dst_addr = l_get_le16(pkt);
		/* TODO: Test that it is *my* address */
		if (!IS_UNICAST(dst_addr))
			return true;

		msg = mesh_ob_buf(&n);

		/* We don't allow nested Aggregations */
		if (n != MAX_MSG_LEN)
			return true;

		n = mesh_ob_opcode_set(OP_AGGREGATOR_STATUS, msg);
		rsp_status = msg + n;
		n++;
		l_put_le16(dst_addr, msg + n);
		n += 2;

		/* Finalizing at this point sets subsequent outbound message
		 * requests to return the remaining part of the shared OB buf.
		 */
		mesh_ob_finalize(msg, n);

		while (pkt_size >= 2 && n < MAX_MSG_LEN) {
			if (pkt[0] & 0x80) {
				item_len = l_get_le16(pkt) & 0x7fff;
				pkt += 2;
				pkt_size -= 2;
			} else {
				item_len = pkt[0];
				pkt++;
				pkt_size--;
			}

			/* Empty Item */
			if (!item_len)
				continue;

			if (item_len > pkt_size)
				/* Fail */
				goto done;

			mesh_model_opcode_get(pkt, item_len, &opcode, &n);

			/* Disallow nested aggregations */
			if (opcode == OP_AGGREGATOR_SEQ ||
						opcode == OP_AGGREGATOR_STATUS)
				/* Fail */
				goto done;

			mesh_model_clear_rx(node, src, dst_addr,
					net_idx, app_idx, pkt, item_len);
		}

		*rsp_status = MESH_STATUS_SUCCESS;

		break;
	}

	/* Find out how much total space was used */
	n = (uint16_t) (mesh_ob_buf(&n) - msg);

	/* Always send aggregation responses with Segmented ACKs */
	mesh_model_send(node, dst, src, app_idx, net_idx, DEFAULT_TTL, true,
								n, msg);

done:
	mesh_ob_reset();
	return true;
}

static void opcode_aggr_srv_unregister(void *user_data)
{
}

static const struct mesh_model_ops ops = {
	.unregister = opcode_aggr_srv_unregister,
	.recv = opcode_aggr_srv_pkt,
	.bind = NULL,
	.sub = NULL,
	.pub = NULL
};

void opcode_aggr_server_init(struct mesh_node *node, uint8_t ele_idx)
{
	l_debug("%2.2x", ele_idx);
	mesh_model_register(node, ele_idx, OPCODE_AGGR_SRV_MODEL, &ops, node);
}
