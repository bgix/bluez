/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

uint8_t *mesh_ob_buf(uint16_t *available);
uint16_t mesh_ob_opcode_set(uint32_t opcode, uint8_t *buf);
uint16_t mesh_ob_finalize(uint8_t *buf, uint16_t len);
bool mesh_ob_ready_to_send(uint8_t *buf);
void mesh_ob_reset(void);
