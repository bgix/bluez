/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
 *
 *
 */

#define OPCODE_AGGR_SRV_MODEL	SET_ID(SIG_VENDOR, 0x3000)
#define OPCODE_AGGR_CLI_MODEL	SET_ID(SIG_VENDOR, 0x3001)

/* New List */
#define OP_AGGREGATOR_SEQ			0x8300
#define OP_AGGREGATOR_STATUS			0x8301

void opcode_aggr_server_init(struct mesh_node *node, uint8_t ele_idx);
