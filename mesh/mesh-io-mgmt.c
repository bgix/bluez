// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "monitor/bt.h"
#include "lib/bluetooth.h"
#include "src/shared/hci.h"
#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/util.h"
#include "mesh/mesh-mgmt.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-generic.h"

struct mesh_io_private {
	struct bt_hci *hci;
	struct mgmt *mgmt;
	void *user_data;
	mesh_io_ready_func_t ready_callback;
	struct l_timeout *tx_timeout;
	struct l_queue *dup_filters;
	struct l_queue *rx_regs;
	struct l_queue *tx_pkts;
	struct tx_pkt *tx;
	uint32_t controllers;
	uint16_t send_idx;
	uint16_t interval;
	uint8_t instance;
	bool sending;
	bool active;
	bool multicontroller;
};

struct pvt_rx_reg {
	mesh_io_recv_func_t cb;
	struct l_queue *seen;
	void *user_data;
	uint8_t len;
	uint8_t filter[0];
};

struct process_data {
	struct mesh_io_private		*pvt;
	const uint8_t			*data;
	uint8_t				len;
	struct mesh_io_recv_info	info;
};

struct tx_pkt {
	struct mesh_io_send_info	info;
	bool				delete;
	uint8_t				len;
	uint8_t				pkt[30];
};

struct tx_pattern {
	const uint8_t			*data;
	uint8_t				len;
};

#define DUP_FILTER_TIME        1000
/* Accept one instance of unique message a second */
struct dup_filter {
	uint64_t data;
	uint32_t instant;
	uint8_t addr[6];
} __packed;

static struct mesh_io_private *pvt;

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data);

static uint32_t get_instant(void)
{
	struct timeval tm;
	uint32_t instant;

	gettimeofday(&tm, NULL);
	instant = tm.tv_sec * 1000;
	instant += tm.tv_usec / 1000;

	return instant;
}

static uint32_t instant_remaining_ms(uint32_t instant)
{
	instant -= get_instant();
	return instant;
}

static bool find_by_addr(const void *a, const void *b)
{
	const struct dup_filter *filter = a;
	return !memcmp(filter->addr, b, 6);
}

static void filter_timeout (struct l_timeout *timeout, void *user_data)
{
	struct dup_filter *filter;
	uint32_t instant, delta;

	if (!pvt)
		goto done;

	instant = get_instant();

	filter = l_queue_peek_tail(pvt->dup_filters);
	while (filter) {
		delta = instant - filter->instant;
		if (delta >= DUP_FILTER_TIME) {
			l_queue_remove(pvt->dup_filters, filter);
			l_free(filter);
		} else {
			l_timeout_modify(timeout, 1);
			return;
		}

		filter = l_queue_peek_tail(pvt->dup_filters);
	}

done:
	l_timeout_remove(timeout);
}

/* Ignore consequtive duplicate advertisements within timeout period */
static bool filter_dups(const uint8_t *addr, const uint8_t *adv,
                                                       uint32_t instant)
{
	struct dup_filter *filter;
	uint32_t instant_delta;
	uint64_t data = l_get_be64(adv);

	filter = l_queue_remove_if(pvt->dup_filters, find_by_addr, addr);
	if (!filter) {
		filter = l_new(struct dup_filter, 1);
		memcpy(filter->addr, addr, 6);
	}

	/* Start filter expiration timer */
	if (!l_queue_length(pvt->dup_filters))
		l_timeout_create(1, filter_timeout, NULL, NULL);

	l_queue_push_head(pvt->dup_filters, filter);
	instant_delta = instant - filter->instant;

	if (instant_delta >= DUP_FILTER_TIME || data != filter->data) {
		filter->instant = instant;
		filter->data = data;
		//l_debug("pass - %lx", data);
		return false;
	}

	//l_debug("filter - %lx", data);
	return true;
}

static void process_rx_callbacks(void *v_reg, void *v_rx)
{
	struct pvt_rx_reg *rx_reg = v_reg;
	struct process_data *rx = v_rx;

	if (!memcmp(rx->data, rx_reg->filter, rx_reg->len))
		rx_reg->cb(rx_reg->user_data, &rx->info, rx->data, rx->len);
}

static void process_rx(struct mesh_io_private *pvt, int8_t rssi,
					uint32_t instant, const uint8_t *addr,
					const uint8_t *data, uint8_t len)
{
	struct process_data rx = {
		.pvt = pvt,
		.data = data,
		.len = len,
		.info.instant = instant,
		.info.addr = addr,
		.info.chan = 7,
		.info.rssi = rssi,
	};

	l_queue_foreach(pvt->rx_regs, process_rx_callbacks, &rx);
}

static void event_device_found(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_device_found *ev = param;
	struct mesh_io *io = user_data;
	const uint8_t *adv;
	const uint8_t *addr;
	uint32_t instant;
	uint16_t adv_len;
	uint16_t len = 0;

	if (ev->addr.type < 1 || ev->addr.type > 2)
		return;

	instant = get_instant();
	adv = ev->eir;
	adv_len = ev->eir_len;
	addr = ev->addr.bdaddr.b;

	if (filter_dups(addr, adv, instant))
		return;

	while (len < adv_len - 1) {
		uint8_t field_len = adv[0];

		/* Check for the end of advertising data */
		if (field_len == 0)
			break;

		len += field_len + 1;

		/* Do not continue data parsing if got incorrect length */
		if (len > adv_len)
			break;

		/* TODO: Create an Instant to use */
		process_rx(io->pvt, ev->rssi, instant, addr, adv + 1, adv[0]);

		adv += field_len + 1;
	}
}

static void close_hci(void *hci)
{
	bt_hci_unref(hci);
}

static void hci_init_cb(const void *data, uint8_t size, void *user_data)
{
	struct bt_hci *hci = user_data;
	uint8_t status = l_get_u8(data);

	if (status)
		l_error("Failed to initialize HCI (0x%2.2x)", status);

	if (pvt && pvt->ready_callback) {
		pvt->ready_callback(pvt->user_data, !status);
		pvt->ready_callback = NULL;
	}

	/* We no longer need user channel when using MGMT */
	if (!pvt || pvt->hci != hci)
		l_idle_oneshot(close_hci, hci, NULL);
}

static void local_commands_callback(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_local_commands *rsp = data;

	if (rsp->status) {
		l_error("Failed to read local commands");
		hci_init_cb(data, size, user_data);
	}
}

static void local_features_callback(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_local_features *rsp = data;

	if (rsp->status) {
		l_error("Failed to read local features");
		hci_init_cb(data, size, user_data);
	}
}

static void hci_generic_callback(const void *data, uint8_t size,
								void *user_data)
{
	uint8_t status = l_get_u8(data);

	if (status)
		hci_init_cb(data, size, user_data);
}

static void configure_hci(struct bt_hci *hci)
{
	struct bt_hci_cmd_le_set_scan_parameters cmd_sp;
	struct bt_hci_cmd_set_event_mask cmd_sem;
	struct bt_hci_cmd_le_set_event_mask cmd_slem;
	struct bt_hci_cmd_le_set_random_address cmd_raddr;
	struct bt_hci_cmd_le_set_scan_enable cmd_se;

	/* Set scan parameters */
	cmd_sp.type = 0x00; /* Passive Scanning */
	cmd_sp.interval = L_CPU_TO_LE16(0x0010);	/* 10 ms */
	cmd_sp.window = L_CPU_TO_LE16(0x0010);	/* 10 ms */
	cmd_sp.own_addr_type = 0x01; /* Public Device Address */
	/* Accept all advertising packets except directed advertising packets
	 * not addressed to this device (default).
	 */
	cmd_sp.filter_policy = 0x00;

	/* Scan Enable parameters */
	cmd_se.enable = 0x01;	/* Enable scanning */
	cmd_se.filter_dup = 0x00;	/* Report duplicates */

	/* Set event mask
	 *
	 * Mask: 0x2000800002008890
	 *   Disconnection Complete
	 *   Encryption Change
	 *   Read Remote Version Information Complete
	 *   Hardware Error
	 *   Data Buffer Overflow
	 *   Encryption Key Refresh Complete
	 *   LE Meta
	 */
	cmd_sem.mask[0] = 0x90;
	cmd_sem.mask[1] = 0x88;
	cmd_sem.mask[2] = 0x00;
	cmd_sem.mask[3] = 0x02;
	cmd_sem.mask[4] = 0x00;
	cmd_sem.mask[5] = 0x80;
	cmd_sem.mask[6] = 0x00;
	cmd_sem.mask[7] = 0x20;

	/* Set LE event mask
	 *
	 * Mask: 0x000000000000087f
	 *   LE Connection Complete
	 *   LE Advertising Report
	 *   LE Connection Update Complete
	 *   LE Read Remote Used Features Complete
	 *   LE Long Term Key Request
	 *   LE Remote Connection Parameter Request
	 *   LE Data Length Change
	 *   LE PHY Update Complete
	 */
	cmd_slem.mask[0] = 0x7f;
	cmd_slem.mask[1] = 0x08;
	cmd_slem.mask[2] = 0x00;
	cmd_slem.mask[3] = 0x00;
	cmd_slem.mask[4] = 0x00;
	cmd_slem.mask[5] = 0x00;
	cmd_slem.mask[6] = 0x00;
	cmd_slem.mask[7] = 0x00;

	/* Set LE random address */
	l_getrandom(cmd_raddr.addr, 6);
	cmd_raddr.addr[5] |= 0xc0;

	/* Reset Command */
	bt_hci_send(hci, BT_HCI_CMD_RESET, NULL, 0, hci_generic_callback,
								hci, NULL);

	/* Read local supported commands */
	bt_hci_send(hci, BT_HCI_CMD_READ_LOCAL_COMMANDS, NULL, 0,
					local_commands_callback, hci, NULL);

	/* Read local supported features */
	bt_hci_send(hci, BT_HCI_CMD_READ_LOCAL_FEATURES, NULL, 0,
					local_features_callback, hci, NULL);

	/* Set event mask */
	bt_hci_send(hci, BT_HCI_CMD_SET_EVENT_MASK, &cmd_sem,
			sizeof(cmd_sem), hci_generic_callback, hci, NULL);

	/* Set LE event mask */
	bt_hci_send(hci, BT_HCI_CMD_LE_SET_EVENT_MASK, &cmd_slem,
			sizeof(cmd_slem), hci_generic_callback, hci, NULL);

	/* Set LE random address */
	bt_hci_send(hci, BT_HCI_CMD_LE_SET_RANDOM_ADDRESS, &cmd_raddr,
			sizeof(cmd_raddr), hci_generic_callback, hci, NULL);

	/* Scan Params */
	bt_hci_send(hci, BT_HCI_CMD_LE_SET_SCAN_PARAMETERS, &cmd_sp,
			sizeof(cmd_sp), hci_generic_callback, hci, NULL);

	/* Scan Enable */
	bt_hci_send(hci, BT_HCI_CMD_LE_SET_SCAN_ENABLE, &cmd_se,
				sizeof(cmd_se), hci_init_cb, hci, NULL);
}

#if 0
static void scan_enable_rsp(const void *buf, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) buf);

	if (status)
		l_error("LE Scan enable failed (0x%02x)", status);
}

static void set_recv_scan_enable(const void *buf, uint8_t size,
							void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct bt_hci_cmd_le_set_scan_enable cmd;

	cmd.enable = 0x01;	/* Enable scanning */
	cmd.filter_dup = 0x00;	/* Report duplicates */
	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_SCAN_ENABLE,
			&cmd, sizeof(cmd), scan_enable_rsp, pvt, NULL);
}

static void scan_disable_rsp(const void *buf, uint8_t size,
							void *user_data)
{
	struct bt_hci_cmd_le_set_scan_parameters cmd;
	struct mesh_io_private *pvt = user_data;
	uint8_t status = *((uint8_t *) buf);

	if (status)
		l_error("LE Scan disable failed (0x%02x)", status);

	cmd.type = pvt->active ? 0x01 : 0x00;	/* Passive/Active scanning */
	cmd.interval = L_CPU_TO_LE16(0x0010);	/* 10 ms */
	cmd.window = L_CPU_TO_LE16(0x0010);	/* 10 ms */
	cmd.own_addr_type = 0x01;		/* ADDR_TYPE_RANDOM */
	cmd.filter_policy = 0x00;		/* Accept all */

	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_SCAN_PARAMETERS,
			&cmd, sizeof(cmd),
			set_recv_scan_enable, pvt, NULL);
}
#endif

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static bool find_by_ad_type(const void *a, const void *b)
{
	const struct tx_pkt *tx = a;
	uint8_t ad_type = L_PTR_TO_UINT(b);

	return !ad_type || ad_type == tx->pkt[0];
}

static bool find_by_pattern(const void *a, const void *b)
{
	const struct tx_pkt *tx = a;
	const struct tx_pattern *pattern = b;

	if (tx->len < pattern->len)
		return false;

	return (!memcmp(tx->pkt, pattern->data, pattern->len));
}

static bool find_active(const void *a, const void *b)
{
	const struct pvt_rx_reg *rx_reg = a;

	/* Mesh specific AD types do *not* require active scanning,
	 * so do not turn on Active Scanning on their account.
	 */
	if (rx_reg->filter[0] < MESH_AD_TYPE_PROVISION ||
			rx_reg->filter[0] > MESH_AD_TYPE_BEACON)
		return true;

	return false;
}

static void hci_init(uint16_t index)
{
	struct bt_hci *hci;
	bool result = true;

	if (!pvt)
		return;

	hci = bt_hci_new_user_channel(index);
	if (!hci) {
		l_error("Failed to start mesh io (hci %u): %s", index,
							strerror(errno));
		result = false;
	}

	if (result) {
		if (!pvt->hci) {
			pvt->send_idx = index;
			pvt->hci = hci;
		}

		configure_hci(hci);

		l_debug("Started controller hci%u", index);

	}

	if (!result && pvt->ready_callback)
		pvt->ready_callback(pvt->user_data, result);
}

#if 0
#define MGMT_OP_READ_ADV_MONITOR_FEATURES	0x0051
struct mgmt_rp_read_adv_monitor_features {
	uint32_t supported_features;
	uint32_t enabled_features;
	uint16_t max_num_handles;
	uint8_t max_num_patterns;
	uint16_t num_handles;
	uint16_t handles[0];
}  __packed;

#define MGMT_OP_START_DISCOVERY		0x0023
struct mgmt_cp_start_discovery {
	uint8_t type;
} __packed;


#endif

static void disco_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("Disco Status hci%d: %d", index, status);
	print_packet("Disco params", param, length);
}

static void mon_feat(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	char disco[] = { 6 };

	l_debug("Mon Feat Status hci%d: %d", index, status);
	print_packet("Monitor Features", param, length);

	mgmt_send(pvt->mgmt, MGMT_OP_START_DISCOVERY, index,
				sizeof(disco), disco, disco_cb, NULL, NULL);
}

static void adv_unset(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("Adv Set Status hci%d: %d", index, status);
	print_packet("Adv Params", param, length);

        if (status == MGMT_STATUS_SUCCESS) {
		pvt->send_idx = index;
		mgmt_send(pvt->mgmt, MGMT_OP_READ_ADV_MONITOR_FEATURES, index,
			0, NULL, mon_feat, L_UINT_TO_PTR(index), NULL);
	}
}

static void con_set(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	char advertisable[] = { 0 };

	l_debug("Con Set Status hci%d: %d", index, status);
	print_packet("Con Params", param, length);
	mgmt_send(pvt->mgmt, MGMT_OP_SET_ADVERTISING, index,
				sizeof(advertisable), advertisable,
				adv_unset, L_UINT_TO_PTR(index), NULL);
}

static void adv_set(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	char advertisable[] = { 1 };

	l_debug("Adv Set Status hci%d: %d", index, status);
	print_packet("Adv Params", param, length);

        if (status == MGMT_STATUS_BUSY)
		mgmt_send(pvt->mgmt, MGMT_OP_SET_ADVERTISING, index,
				sizeof(advertisable), advertisable,
				adv_set, L_UINT_TO_PTR(index), NULL);
}

static void mesh_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("HCI%d Mesh up status: %d", index, status);
}

static void le_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("HCI%d LE up status: %d", index, status);

}

static void ctl_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	uint16_t len;
	struct mgmt_cp_set_mesh *mesh;
	uint8_t mesh_ad_types[] = { MESH_AD_TYPE_NETWORK,
				MESH_AD_TYPE_BEACON, MESH_AD_TYPE_PROVISION };

	l_debug("HCI%d is up status: %d", index, status);
	if (status)
		return;

	pvt->controllers |= 1 << index;

	len = sizeof(struct mgmt_cp_set_mesh) + sizeof(mesh_ad_types);
	mesh = l_malloc(len);

	mesh->enable = 1;
	mesh->window = L_CPU_TO_LE16(0x1000);
	mesh->period = L_CPU_TO_LE16(0x1000);
	mesh->num_ad_types = sizeof(mesh_ad_types);
	memcpy(mesh->ad_types, mesh_ad_types, sizeof(mesh_ad_types));

	mgmt_send(pvt->mgmt, MGMT_OP_SET_MESH_RECEIVER, index, len, mesh,
			mesh_up, L_UINT_TO_PTR(index), NULL);

	l_free(mesh);

	if (pvt->send_idx == MGMT_INDEX_NONE) {
		if (pvt && pvt->ready_callback) {
			pvt->ready_callback(pvt->user_data, true);
			pvt->ready_callback = NULL;
		}
	}
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	unsigned char le[] = { 0x01 };
	int index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	l_debug("hci %u status 0x%02x", index, status);

	if (!pvt)
		return;

	if (index > 31) {
		l_debug("controllers > 31 not supported");
		return;
	}

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
				index, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	if (!(supported_settings & MGMT_SETTING_LE)) {
		l_info("Controller hci %u does not support LE", index);
		return;
	}

	l_debug("Existing Controllers: %x", pvt->controllers);
	if (pvt->controllers & (1 << index))
		return;

	if (!(current_settings & MGMT_SETTING_POWERED)) {
		char connectable[] = { 0 };

		/* TODO: Initialize this HCI controller */
		l_info("Controller hci %u not in use", index);
		if (0)
			hci_init(index);
		else {
			unsigned char power[] = { 0x01 };

			mgmt_send(pvt->mgmt, MGMT_OP_SET_LE, index,
						sizeof(le), &le,
					le_up, L_UINT_TO_PTR(index), NULL);

			mgmt_send(pvt->mgmt, MGMT_OP_SET_POWERED, index,
					sizeof(power), &power,
					ctl_up, L_UINT_TO_PTR(index), NULL);

			mgmt_send(pvt->mgmt, MGMT_OP_SET_CONNECTABLE, index,
				sizeof(connectable), connectable,
				con_set, L_UINT_TO_PTR(index), NULL);

		}
	} else {
		char disco[] = { 6 };

		l_info("Controller hci %u already in use (%x)",
						index, current_settings);

		/* Share this controller with bluetoothd */
		mgmt_send(pvt->mgmt, MGMT_OP_SET_LE, index,
				sizeof(le), &le,
				ctl_up, L_UINT_TO_PTR(index), NULL);

		mgmt_send(pvt->mgmt, MGMT_OP_START_DISCOVERY, index,
				sizeof(disco), disco, disco_cb, NULL, NULL);

	}
}

static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("Found hci %u", index);
	mgmt_send(pvt->mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_cb, L_UINT_TO_PTR(index), NULL);
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("Hci dev %4.4x removed", index);

	if (pvt && pvt->send_idx == index)
		pvt->send_idx = MGMT_INDEX_NONE;

#if 0
	if (pvt)
		pvt->controllers &= ~(1 << index);

	if (pvt && pvt->send_idx == index) {
		bt_hci_unref(pvt->hci);
		pvt->hci = NULL;
		pvt->send_idx = MGMT_INDEX_NONE;

		if (pvt->controllers)
			mgmt_send(pvt->mgmt, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					read_index_list_cb, NULL, NULL);
	}
#endif
}

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read index list: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read index list response sixe too short");
		return;
	}

	num = btohs(rp->num_controllers);

	l_debug("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		l_error("Incorrect packet size for index list response");
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);
		index_added(index, 0, NULL, user_data);
	}
}

static bool dev_init(struct mesh_io *io, void *opts,
				mesh_io_ready_func_t cb, void *user_data)
{
	uint16_t index = *(int *)opts;

	if (!io || pvt)
		return false;

	pvt = l_new(struct mesh_io_private, 1);

	pvt->mgmt = mgmt_new_default();
	pvt->send_idx = MGMT_INDEX_NONE;

	if (!pvt->mgmt) {
		l_free(pvt);
		pvt = NULL;
		return false;
	}

	if (index <= 31)
		pvt->controllers = 1 << index;
	else
		pvt->multicontroller = true;


	l_debug("Register MGMT");
	if (mgmt_send(pvt->mgmt, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					read_index_list_cb, NULL, NULL) <= 0)
		return false;

	mgmt_register(pvt->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
						index_added, io, NULL);
	mgmt_register(pvt->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
						index_removed, io, NULL);
	mgmt_register(pvt->mgmt, MGMT_EV_DEVICE_FOUND, MGMT_INDEX_NONE,
						event_device_found, io, NULL);

	pvt->dup_filters = l_queue_new();
	pvt->rx_regs = l_queue_new();
	pvt->tx_pkts = l_queue_new();

	pvt->ready_callback = cb;
	pvt->user_data = user_data;
	io->pvt = pvt;

	//l_idle_oneshot(mgmt_init, io, NULL);

	return true;
}

static void ctl_dn(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{

	l_debug("Terminated Mesh IO");

	if (pvt) {
		mgmt_unref(pvt->mgmt);
		l_free(pvt);
		pvt = NULL;
	}
}

static bool dev_destroy(struct mesh_io *io)
{
	uint16_t index = 0;
	uint32_t mask = pvt->controllers;
	unsigned char param[] = { 0x00 };
	bool pd = false;

	if (io->pvt != pvt)
		return true;

	while (mask) {
		if (mask == 1)
			mgmt_send(pvt->mgmt, MGMT_OP_SET_POWERED, index,
					sizeof(param), &param,
					ctl_dn, NULL, NULL);
		else if (mask & 1)
			mgmt_send(pvt->mgmt, MGMT_OP_SET_POWERED, index,
					sizeof(param), &param,
					NULL, NULL, NULL);

		pd = true;
		index++;
		mask >>= 1;
	}

	bt_hci_unref(pvt->hci);
	l_timeout_remove(pvt->tx_timeout);
	l_queue_destroy(pvt->dup_filters, l_free);
	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	io->pvt = NULL;
	if (!pd) {
		mgmt_unref(pvt->mgmt);
		l_free(pvt);
		pvt = NULL;
	}

	return true;
}

static bool dev_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = 255;
	caps->window_accuracy = 50;

	return true;
}

#if 0
static void send_cancel_done(const void *buf, uint8_t size,
							void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct bt_hci_cmd_le_set_random_address cmd;

	if (!pvt)
		return;

	pvt->sending = false;

	/* At end of any burst of ADVs, change random address */
	/* TODO:  Add MGMT command to set Random Address */
	l_getrandom(cmd.addr, 6);
	cmd.addr[5] |= 0xc0;
	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_RANDOM_ADDRESS,
				&cmd, sizeof(cmd), NULL, NULL, NULL);
}
#endif

static void send_cancel(struct mesh_io_private *pvt)
{
	struct mgmt_cp_remove_advertising remove;

	if (!pvt)
		return;

	if (pvt->instance) {
		char adv_off[] = { 0 };
		mgmt_send(pvt->mgmt, MGMT_OP_SET_ADVERTISING, pvt->send_idx,
				sizeof(adv_off), adv_off,
				NULL, NULL, NULL);

		remove.instance = pvt->instance;
		//if (0)
		l_debug("Cancel TX");
		mgmt_send(pvt->mgmt, MGMT_OP_REMOVE_ADVERTISING, pvt->send_idx,
						sizeof(remove), &remove,
						NULL, NULL, NULL);
	}

	/* TODO:  Add MGMT command to set Random Address */
}

#if 0
static void set_send_adv_enable(const void *buf, uint8_t size,
							void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct bt_hci_cmd_le_set_adv_enable cmd;

	if (!pvt)
		return;

	pvt->sending = true;
	cmd.enable = 0x01;	/* Enable advertising */
	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_ADV_ENABLE,
				&cmd, sizeof(cmd), NULL, NULL, NULL);
}

static void set_send_adv_data(const void *buf, uint8_t size,
							void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct tx_pkt *tx;
	struct bt_hci_cmd_le_set_adv_data cmd;

	if (!pvt || !pvt->tx)
		return;

	tx = pvt->tx;
	if (tx->len >= sizeof(cmd.data))
		goto done;

	memset(&cmd, 0, sizeof(cmd));

	cmd.len = tx->len + 1;
	cmd.data[0] = tx->len;
	memcpy(cmd.data + 1, tx->pkt, tx->len);

	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_ADV_DATA,
					&cmd, sizeof(cmd),
					set_send_adv_enable, pvt, NULL);
done:
	if (tx->delete) {
		l_queue_remove_if(pvt->tx_pkts, simple_match, tx);
		l_free(tx);
	}

	pvt->tx = NULL;
}

static void set_send_adv_params(const void *buf, uint8_t size,
							void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct bt_hci_cmd_le_set_adv_parameters cmd;
	uint16_t hci_interval;

	if (!pvt)
		return;

	hci_interval = (pvt->interval * 16) / 10;
	cmd.min_interval = L_CPU_TO_LE16(hci_interval);
	cmd.max_interval = L_CPU_TO_LE16(hci_interval);
	cmd.type = 0x03; /* ADV_NONCONN_IND */
	cmd.own_addr_type = 0x01; /* ADDR_TYPE_RANDOM */
	cmd.direct_addr_type = 0x00;
	memset(cmd.direct_addr, 0, 6);
	cmd.channel_map = 0x07;
	cmd.filter_policy = 0x03;

	bt_hci_send(pvt->hci, BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
				&cmd, sizeof(cmd),
				set_send_adv_data, pvt, NULL);
}
#endif

static void next_instance(struct mesh_io_private *pvt)
{
	//uint8_t instance = pvt->instance + 1;

	//if (!instance || instance == 255)
		pvt->instance = 1;
	//else
		//pvt->instance++;
}

#if 0
#define MGMT_OP_SET_STATIC_ADDRESS	0x002B
struct mgmt_cp_set_static_address {
	bdaddr_t bdaddr;
} __packed;
#endif

static void add_adv_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	//l_debug("Add_Adv Status: %d", status);
	//print_packet("Add_Adv params", param, length);
}

static void adv_halt(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	l_debug("Adv Halt Status: %d", status);
	print_packet("Halt params", param, length);
}

static void send_pkt(struct mesh_io_private *pvt, struct tx_pkt *tx,
							uint16_t interval)
{
	//struct mgmt_cp_set_static_address set_addr;
	struct mgmt_cp_remove_advertising remove;
	struct mgmt_cp_add_advertising *add;
	char advertisable[] = { 1 };
	uint8_t instance;
	uint16_t index;
	size_t len;

	if (!pvt)
		return;

	instance = pvt->instance;
	index = pvt->send_idx;

	if (instance) {
		char adv_off[] = { 0 };
		mgmt_send(pvt->mgmt, MGMT_OP_SET_ADVERTISING, index,
				sizeof(adv_off), adv_off,
				adv_halt, L_UINT_TO_PTR(index), NULL);

		remove.instance = instance;
		//if (0)
		mgmt_send(pvt->mgmt, MGMT_OP_REMOVE_ADVERTISING, index,
						sizeof(remove), &remove,
						NULL, NULL, NULL);

#if 0
		l_getrandom(&set_addr, sizeof(set_addr));
		set_addr.bdaddr.b[5] |= 0xc0;
		mgmt_send(pvt->mgmt, MGMT_OP_SET_STATIC_ADDRESS, index,
				sizeof(set_addr), &set_addr, NULL, NULL, NULL);
#endif
	} else
		l_debug("Adv-Idle");

	next_instance(pvt);

	/* Delete superseded packet in favor of new packet */
	if (pvt->tx && pvt->tx != tx && pvt->tx->delete) {
		l_queue_remove_if(pvt->tx_pkts, simple_match, pvt->tx);
		l_free(pvt->tx);
	}

	pvt->tx = tx;
	pvt->interval = interval;

	len = sizeof(struct mgmt_cp_add_advertising) + tx->len + 1;
	add = (struct mgmt_cp_add_advertising *) l_new(char, len);

	add->instance = pvt->instance;
	add->duration = 1;
	add->timeout = 1;
	add->adv_data_len = tx->len + 1;
	add->data[0] = tx->len;
	memcpy(add->data + 1, tx->pkt, tx->len);
	mgmt_send(pvt->mgmt, MGMT_OP_ADD_ADVERTISING, index, len, add,
							add_adv_cb, NULL, NULL);
	l_free(add);
	mgmt_send(pvt->mgmt, MGMT_OP_SET_ADVERTISING, index,
				sizeof(advertisable), advertisable,
				adv_set, L_UINT_TO_PTR(index), NULL);


	if (tx->delete) {
		l_queue_remove_if(pvt->tx_pkts, simple_match, tx);
		l_free(tx);
	}
}

static void tx_to(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct tx_pkt *tx;
	uint16_t ms;
	uint8_t count;

	if (!pvt)
		return;

	tx = l_queue_pop_head(pvt->tx_pkts);
	if (!tx) {
		l_timeout_remove(timeout);
		pvt->tx_timeout = NULL;
		send_cancel(pvt);
		pvt->tx = NULL;
		return;
	}

	if (tx->info.type == MESH_IO_TIMING_TYPE_GENERAL) {
		ms = tx->info.u.gen.interval;
		count = tx->info.u.gen.cnt;
		if (count != MESH_IO_TX_COUNT_UNLIMITED)
			tx->info.u.gen.cnt--;
	} else {
		ms = 25;
		count = 1;
	}

	tx->delete = !!(count == 1);

	send_pkt(pvt, tx, ms);

	if (count == 1) {
		/* Recalculate wakeup if we are responding to POLL */
		tx = l_queue_peek_head(pvt->tx_pkts);

		if (tx && tx->info.type == MESH_IO_TIMING_TYPE_POLL_RSP) {
			ms = instant_remaining_ms(tx->info.u.poll_rsp.instant +
						tx->info.u.poll_rsp.delay);
		}
	} else
		l_queue_push_tail(pvt->tx_pkts, tx);

	if (timeout) {
		pvt->tx_timeout = timeout;
		l_timeout_modify_ms(timeout, ms);
	} else
		pvt->tx_timeout = l_timeout_create_ms(ms, tx_to, pvt, NULL);
}

static void tx_worker(void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct tx_pkt *tx;
	uint32_t delay;

	tx = l_queue_peek_head(pvt->tx_pkts);
	if (!tx)
		return;

	switch (tx->info.type) {
	case MESH_IO_TIMING_TYPE_GENERAL:
		if (tx->info.u.gen.min_delay == tx->info.u.gen.max_delay)
			delay = tx->info.u.gen.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= tx->info.u.gen.max_delay -
						tx->info.u.gen.min_delay;
			delay += tx->info.u.gen.min_delay;
		}
		break;

	case MESH_IO_TIMING_TYPE_POLL:
		if (tx->info.u.poll.min_delay == tx->info.u.poll.max_delay)
			delay = tx->info.u.poll.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= tx->info.u.poll.max_delay -
						tx->info.u.poll.min_delay;
			delay += tx->info.u.poll.min_delay;
		}
		break;

	case MESH_IO_TIMING_TYPE_POLL_RSP:
		/* Delay until Instant + Delay */
		delay = instant_remaining_ms(tx->info.u.poll_rsp.instant +
						tx->info.u.poll_rsp.delay);
		if (delay > 255)
			delay = 0;
		break;

	default:
		return;
	}

	if (!delay)
		tx_to(pvt->tx_timeout, pvt);
	else if (pvt->tx_timeout)
		l_timeout_modify_ms(pvt->tx_timeout, delay);
	else
		pvt->tx_timeout = l_timeout_create_ms(delay, tx_to, pvt, NULL);
}

static bool send_tx(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	struct tx_pkt *tx;
	bool sending = false;

	if (!info || !data || !len || len > sizeof(tx->pkt))
		return false;

	tx = l_new(struct tx_pkt, 1);

	memcpy(&tx->info, info, sizeof(tx->info));
	memcpy(&tx->pkt, data, len);
	tx->len = len;

	l_debug("q: %p tx: %p", pvt->tx_pkts, tx);
	if (info->type == MESH_IO_TIMING_TYPE_POLL_RSP)
		l_queue_push_head(pvt->tx_pkts, tx);
	else {
		if (pvt->tx)
			sending = true;
		else
			sending = !l_queue_isempty(pvt->tx_pkts);

		l_queue_push_tail(pvt->tx_pkts, tx);
	}

	if (!sending) {
		l_timeout_remove(pvt->tx_timeout);
		pvt->tx_timeout = NULL;
		l_idle_oneshot(tx_worker, pvt, NULL);
	}

	return true;
}

static bool tx_cancel(struct mesh_io *io, const uint8_t *data, uint8_t len)
{
	struct mesh_io_private *pvt = io->pvt;
	struct tx_pkt *tx;

	if (!data)
		return false;

	if (len == 1) {
		do {
			tx = l_queue_remove_if(pvt->tx_pkts, find_by_ad_type,
							L_UINT_TO_PTR(data[0]));
			l_free(tx);

			if (tx == pvt->tx)
				pvt->tx = NULL;

		} while (tx);
	} else {
		struct tx_pattern pattern = {
			.data = data,
			.len = len
		};

		do {
			tx = l_queue_remove_if(pvt->tx_pkts, find_by_pattern,
								&pattern);
			l_free(tx);

			if (tx == pvt->tx)
				pvt->tx = NULL;

		} while (tx);
	}

	if (l_queue_isempty(pvt->tx_pkts)) {
		send_cancel(pvt);
		l_timeout_remove(pvt->tx_timeout);
		pvt->tx_timeout = NULL;
	}

	return true;
}

static bool find_by_filter(const void *a, const void *b)
{
	const struct pvt_rx_reg *rx_reg = a;
	const uint8_t *filter = b;

	return !memcmp(rx_reg->filter, filter, rx_reg->len);
}

static void free_rx_reg(void *user_data)
{
	struct pvt_rx_reg *rx_reg = user_data;

	if (rx_reg) {
		l_queue_destroy(rx_reg->seen, l_free);
		//l_timout_cancel(rx_reg->flush_to);
	}

	l_free(rx_reg);
}

static bool recv_register(struct mesh_io *io, const uint8_t *filter,
			uint8_t len, mesh_io_recv_func_t cb, void *user_data)
{
	//struct bt_hci_cmd_le_set_scan_enable cmd;
	struct pvt_rx_reg *rx_reg;
	bool active = false;

	if (!cb || !filter || !len || io->pvt != pvt)
		return false;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter, filter);

	free_rx_reg(rx_reg);
	rx_reg = l_malloc(sizeof(*rx_reg) + len);

	memcpy(rx_reg->filter, filter, len);
	rx_reg->len = len;
	rx_reg->cb = cb;
	rx_reg->user_data = user_data;

	l_queue_push_head(pvt->rx_regs, rx_reg);

	/* Look for any AD types requiring Active Scanning */
	if (l_queue_find(pvt->rx_regs, find_active, NULL))
		active = true;

	if (pvt->active != active) {
		pvt->active = active;
		/* TODO: Request active or passive scanning */
	}

	return true;
}

static bool recv_deregister(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	struct pvt_rx_reg *rx_reg;
	bool active = false;

	if (io->pvt != pvt)
		return false;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter, filter);

	free_rx_reg(rx_reg);

	/* Look for any AD types requiring Active Scanning */
	if (l_queue_find(pvt->rx_regs, find_active, NULL))
		active = true;

	if (active != pvt->active) {
		pvt->active = active;
		/* TODO: Request active or passive scanning */
	}

	return true;
}

const struct mesh_io_api mesh_io_mgmt = {
	.init = dev_init,
	.destroy = dev_destroy,
	.caps = dev_caps,
	.send = send_tx,
	.reg = recv_register,
	.dereg = recv_deregister,
	.cancel = tx_cancel,
};
