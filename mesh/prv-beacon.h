/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

/* TODO:  These const values are all place holders */
struct mesh_node;

#define PRV_BEACON_SRV_MODEL	SET_ID(SIG_VENDOR, 0x0008)
#define PRV_BEACON_CLI_MODEL	SET_ID(SIG_VENDOR, 0x0009)

/* Private Beacon opcodes */
#define OP_PRIVATE_BEACON_GET			0x8100
#define OP_PRIVATE_BEACON_SET			0x8101
#define OP_PRIVATE_BEACON_STATUS		0x8102
#define OP_PRIVATE_GATT_PROXY_GET		0x8103
#define OP_PRIVATE_GATT_PROXY_SET		0x8104
#define OP_PRIVATE_GATT_PROXY_STATUS		0x8105
#define OP_PRIVATE_NODE_ID_SET			0x8106
#define OP_PRIVATE_NODE_ID_GET			0x8107
#define OP_PRIVATE_NODE_ID_STATUS		0x8108

void prv_beacon_server_init(struct mesh_node *node, uint8_t ele_idx);
