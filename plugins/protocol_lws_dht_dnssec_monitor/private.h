/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * Shared between the monitor's translation units.  Include
 * <libwebsockets.h> (with the plugin DLL dance) before this.
 */

#if !defined(__LWS_DHT_DNSSEC_MONITOR_PRIVATE_H__)
#define __LWS_DHT_DNSSEC_MONITOR_PRIVATE_H__

#include <sys/types.h>

#define PSS_MAGIC 0x50535301
#define MONITOR_IPC_BUF_SIZE 65536

/*
 * Smallest amount of room in the shared IPC tx buffer worth starting a new
 * response into: comfortably larger than any fixed response envelope in this
 * plugin, so a response either fits or is not begun at all
 */
#define MONITOR_TX_MIN_ROOM 1024

struct pss {
	uint32_t magic;
	struct lws *wsi;
	struct lws *cwsi;

	lws_sorted_usec_list_t sul;
	int retry_count;

	/* TX (proxy -> root) buffer */
	uint8_t tx[LWS_PRE + MONITOR_IPC_BUF_SIZE];
	size_t tx_len;

	/*
	 * RX buffer: on the proxy side it holds the root's responses waiting
	 * to go out on the browser ws; on the root side it is the line
	 * reassembly buffer for this one UDS client's requests.  It has to be
	 * per-connection either way, since UDS clients do not trust each
	 * other and a request can span several reads
	 */
	uint8_t rx[LWS_PRE + MONITOR_IPC_BUF_SIZE];
	size_t rx_len;

	lws_dll2_t list;
	int send_ext_ips;
};

struct pub_state {
	struct lws_dll2 list;
	char domain[64];
	time_t mtime;
};

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_dht_dnssec_ops *ops;

	char *base_dir;
	const char *uds_path;
	uint32_t signature_duration;

	lws_sorted_usec_list_t sul_timer;
	lws_sorted_usec_list_t sul_fast_timer;
	struct lws_dir_notify *dn;

	struct lws_spawn_piped *lsp;
	int root_process_active;

	char cookie_name[64];
	char jwk_path[256];
	struct lws_jwk jwk;

	char auth_token[129];
	struct lws_jwk auth_jwk;

	lws_dll2_owner_t ui_clients;
	struct lws_smd_peer *smd_peer;
	char ext_ips[256];

	/* ACME client configuration state */
	int acme_production;
	char acme_email[128];
	char acme_profile[128];

	uid_t proxy_uid;
	gid_t proxy_gid;

	/* UDS Proxy clients queue */
	lws_dll2_owner_t clients;

	lws_dll2_owner_t pub_states;
	int initial_parent_scan_done;
};

struct monitor_req_args {
	char req[32];
	char domain[128];
	char subdomain[128];
	char email[128];
	char organization[128];
	char directory_url[256];
	char *zone_buf;
	int zone_len;
	int zone_alloc;
	char jwt[2048];
	char suffix[64];
	int port;
	int enabled;
	int production;
	char country[128];
	char state[128];
	char locality[128];
	char profile[128];
	char key_type[32];
	int sign_validity_days;
	int cursor;

	/*
	 * Currently DHT-detected external addresses, as IPv4 / IPv6 literal
	 * hints from the UI.  They resolve ${MHWC_DYNAMIC} /
	 * ${MHWC6_DYNAMIC} records in zonefiles to real addresses for the
	 * inventory; empty strings when the client does not know them yet
	 */
	char ip4[64];
	char ip6[64];
};

typedef void (*monitor_req_handler_t)(struct vhd *vhd, struct pss *root_pss,
				      struct monitor_req_args *a);

/*
 * Any string interpolated into composed JSON, whether it came from an IPC
 * request or was read off storage, must be escaped first: lws_json_purify()
 * produces the \t / \n / \r / \\ / \uXXXX forms so quotes and control chars
 * cannot break out of the string and inject arbitrary JSON members.
 *
 * esc must be sized for 6x expansion of the worst-case input plus the NUL.
 */
static inline const char *
json_escape(char *esc, size_t esc_len, const char *s)
{
	return lws_json_purify(esc, s, (int)esc_len, NULL);
}

/*
 * Buffer sizes for escaping each kind of interpolated string: the largest
 * expansion lws_json_purify() can apply is 6x, plus the NUL.
 */
#define MON_ESC_DOMAIN_SZ	(6 * 256 + 8)
#define MON_ESC_FIELD_SZ	(6 * 128 + 8)

/* monitor-inventory.c */

void
handle_req_get_ip_inventory(struct vhd *vhd, struct pss *root_pss,
			     struct monitor_req_args *a);

#endif
