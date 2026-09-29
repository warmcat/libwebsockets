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
 * External addresses for the zone signer
 *
 * Zonefiles write ${EXTIP4} / ${EXTIP6} where the DHT-detected external
 * addresses belong.  The DHT, and so the ext-ips SMD, lives in the
 * unprivileged proxy process, but zones are signed by the root monitor
 * process, which runs no DHT.  The proxy owns the root process' stdin
 * pipe as a private control channel: its first line is the UDS IPC auth
 * token, generated at spawn, and after that the proxy forwards each ext-ips
 * SMD payload down it as one line.  The root process adopts it into its
 * event loop at init, so nothing waits on it.
 *
 * The root process applies the configured IPv6 suffix (one hex group that
 * replaces the low 16 bits of the detected address, exactly as the UI
 * previews ${EXTIP6}) and hands the pair to the signer.  Next to each
 * signed zone that uses the macros it records which addresses it was
 * signed with, so a change of address (or of suffix), including across
 * restarts, re-signs exactly the zones it affects.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <arpa/inet.h>
#endif

#include "private.h"

/* refuse to consider zonefiles larger than the signer is willing to read */
#define EXTIP_ZONE_MAX_BYTES	(1024 * 1024)

void
monitor_extip_suffix(struct vhd *vhd, char *out, size_t outlen)
{
	char path[1024];
	ssize_t n;
	int fd;

	out[0] = '\0';

	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt",
		     vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	n = read(fd, out, outlen - 1);
	close(fd);
	if (n <= 0) {
		out[0] = '\0';
		return;
	}
	out[n] = '\0';

	while (n && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
		     out[n - 1] == ' '))
		out[--n] = '\0';
}

int
monitor_extip_apply_suffix(char *out, size_t outlen, const char *ip6,
			   const char *suffix)
{
	unsigned char ad[16], iid[2];
	size_t sl = strlen(suffix), n;
	char grp[5];

	out[0] = '\0';

	if (!ip6[0] || inet_pton(AF_INET6, ip6, ad) != 1)
		return 1;

	if (sl) {
		/*
		 * one hex group, as the UI's suffix field takes it: pad it to
		 * four digits with leading '0's
		 */
		if (sl <= 4) {
			for (n = 0; n < 4; n++)
				grp[n] = n < 4 - sl ? '0' : suffix[n - (4 - sl)];
			grp[4] = '\0';
		}
		if (sl <= 4 && lws_hex_len_to_byte_array(grp, 4, iid, 2) == 2)
			memcpy(&ad[14], iid, sizeof(iid));
		else
			lwsl_err("%s: ignoring malformed ipv6 suffix '%s'\n",
				 __func__, suffix);
	}

	if (!inet_ntop(AF_INET6, ad, out, (socklen_t)outlen)) {
		out[0] = '\0';
		return 1;
	}

	return 0;
}

int
monitor_extip_zone_uses(const char *zone_path)
{
	struct stat st;
	char *buf;
	int fd, uses = 0;

	fd = open(zone_path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) || st.st_size <= 0 ||
	    st.st_size > EXTIP_ZONE_MAX_BYTES) {
		close(fd);
		return -1;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (read(fd, buf, (size_t)st.st_size) != (ssize_t)st.st_size) {
		free(buf);
		close(fd);
		return -1;
	}
	close(fd);
	buf[st.st_size] = '\0';

	/* a mention in a comment only costs a spurious re-sign */
	if (strstr(buf, "${EXTIP4}"))
		uses |= MON_EXTIP_USES_4;
	if (strstr(buf, "${EXTIP6}"))
		uses |= MON_EXTIP_USES_6;

	free(buf);

	return uses;
}

void
monitor_extip_for_zone(struct vhd *vhd, int uses, char *ip4, size_t ip4_len,
		       char *ip6, size_t ip6_len)
{
	char suffix[64];

	ip4[0] = '\0';
	ip6[0] = '\0';

	if (uses & MON_EXTIP_USES_4)
		lws_strncpy(ip4, vhd->extip4, ip4_len);

	if ((uses & MON_EXTIP_USES_6) && vhd->extip6[0]) {
		monitor_extip_suffix(vhd, suffix, sizeof(suffix));
		monitor_extip_apply_suffix(ip6, ip6_len, vhd->extip6, suffix);
	}
}

/*
 * The record of what a zone was signed with is one line per macro, so an
 * empty value (family unused by the zone, or not detected) still compares
 */

static int
monitor_extip_state_fmt(char *buf, size_t len, const char *ip4,
			const char *ip6)
{
	return lws_snprintf(buf, len, "EXTIP4=%s\nEXTIP6=%s\n", ip4, ip6);
}

int
monitor_extip_signed_matches(const char *state_path, const char *ip4,
			     const char *ip6)
{
	char want[160], have[160];
	ssize_t n;
	int fd, wl;

	wl = monitor_extip_state_fmt(want, sizeof(want), ip4, ip6);

	fd = open(state_path, O_RDONLY);
	if (fd < 0)
		return 0;

	n = read(fd, have, sizeof(have));
	close(fd);

	return n == wl && !memcmp(have, want, (size_t)wl);
}

int
monitor_extip_record(const char *state_path, const char *ip4, const char *ip6)
{
	char buf[160];
	int fd, n;

	n = monitor_extip_state_fmt(buf, sizeof(buf), ip4, ip6);

	fd = open(state_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, state_path);
		return 1;
	}

	if (write(fd, buf, (size_t)n) != (ssize_t)n) {
		lwsl_err("%s: unable to write %s\n", __func__, state_path);
		close(fd);
		unlink(state_path);
		return 1;
	}
	close(fd);

	return 0;
}

/*
 * One forwarded ext-ips line, eg, {"ext-ips": ["192.0.2.1", "2001:db8::1"]}.
 * It came from our own proxy over a private pipe, but it is still only
 * taken as literal addresses of the right family.
 */

static const char * const extip_paths[] = {
	"ext-ips[]",
};

struct extip_parse {
	char ip4[64];
	char ip6[64];
};

static signed char
extip_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct extip_parse *ep = (struct extip_parse *)ctx->user;
	unsigned char ad[16];

	if (reason != LEJPCB_VAL_STR_END || ctx->path_match != 1)
		return 0;

	if (!ep->ip4[0] && inet_pton(AF_INET, ctx->buf, ad) == 1)
		inet_ntop(AF_INET, ad, ep->ip4, sizeof(ep->ip4));
	else if (!ep->ip6[0] && inet_pton(AF_INET6, ctx->buf, ad) == 1)
		inet_ntop(AF_INET6, ad, ep->ip6, sizeof(ep->ip6));

	return 0;
}

int
monitor_extip_ctl_line(struct vhd *vhd, const char *line, size_t len)
{
	struct extip_parse ep;
	struct lejp_ctx ctx;
	int m;

	memset(&ep, 0, sizeof(ep));
	lejp_construct(&ctx, extip_lejp_cb, &ep, extip_paths,
		       LWS_ARRAY_SIZE(extip_paths));
	m = lejp_parse(&ctx, (const uint8_t *)line, (int)len);
	lejp_destruct(&ctx);

	if (m < 0) {
		lwsl_err("%s: rejecting malformed ext-ips line\n", __func__);
		return 1;
	}

	if (!strcmp(ep.ip4, vhd->extip4) && !strcmp(ep.ip6, vhd->extip6))
		return 0;

	if (!vhd->extip4[0] && !vhd->extip6[0])
		vhd->extip_since = lws_now_usecs();

	lws_strncpy(vhd->extip4, ep.ip4, sizeof(vhd->extip4));
	lws_strncpy(vhd->extip6, ep.ip6, sizeof(vhd->extip6));
	vhd->extip_gen++;

	lwsl_user("%s: external addresses now v4 '%s', v6 '%s'\n", __func__,
		  vhd->extip4, vhd->extip6);

	return 0;
}

/*
 * The proxy generates the UDS IPC key at spawn and hands it to the root
 * process as the first control line.  Until it is installed, the root
 * process rejects every UDS request.
 */

int
monitor_auth_key_set(struct vhd *vhd, const uint8_t *key)
{
	lws_jwk_destroy(&vhd->auth_jwk);
	memset(&vhd->auth_jwk, 0, sizeof(vhd->auth_jwk));

	if (lws_jwk_dup_oct(&vhd->auth_jwk, key, MON_AUTH_KEY_LEN)) {
		/* it set kty before failing: stay unbootstrapped */
		memset(&vhd->auth_jwk, 0, sizeof(vhd->auth_jwk));
		return 1;
	}

	lws_hex_from_byte_array(key, MON_AUTH_KEY_LEN, vhd->auth_token,
				sizeof(vhd->auth_token));

	return 0;
}

/*
 * The first control line is the UDS IPC key, as 128 hex chars.  Anything
 * else leaves us unbootstrapped, rejecting every UDS request.
 */

static void
monitor_ctl_token_line(struct vhd *vhd, const char *line, size_t len)
{
	uint8_t key[MON_AUTH_KEY_LEN];
	char hex[(MON_AUTH_KEY_LEN * 2) + 1];

	if (len && line[len - 1] == '\r')
		len--;

	if (len != sizeof(hex) - 1) {
		lwsl_err("%s: bad IPC auth token length\n", __func__);
		return;
	}

	memcpy(hex, line, len);
	hex[len] = '\0';

	if (lws_hex_to_byte_array(hex, key, (int)sizeof(key)) !=
							(int)sizeof(key)) {
		lwsl_err("%s: malformed IPC auth token\n", __func__);
		goto bail;
	}

	if (monitor_auth_key_set(vhd, key))
		lwsl_err("%s: unable to install IPC auth token\n", __func__);
	else
		lwsl_notice("%s: IPC auth token installed\n", __func__);

bail:
	lws_explicit_bzero(key, sizeof(key));
	lws_explicit_bzero(hex, sizeof(hex));
}

void
monitor_extip_ctl_rx(struct vhd *vhd, const char *in, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++) {
		if (in[n] != '\n') {
			if (vhd->ctl_rx_len == sizeof(vhd->ctl_rx)) {
				/* no line of ours is this long: resync */
				lwsl_err("%s: overlong control line\n",
					 __func__);
				vhd->ctl_rx_discard = 1;
				vhd->ctl_rx_len = 0;
			}
			if (!vhd->ctl_rx_discard)
				vhd->ctl_rx[vhd->ctl_rx_len++] = in[n];
			continue;
		}

		if (!vhd->ctl_rx_token_done) {
			if (!vhd->ctl_rx_discard)
				monitor_ctl_token_line(vhd, vhd->ctl_rx,
						       vhd->ctl_rx_len);
			lws_explicit_bzero(vhd->ctl_rx, vhd->ctl_rx_len);
			vhd->ctl_rx_token_done = 1;
		} else
			if (!vhd->ctl_rx_discard && vhd->ctl_rx_len)
				monitor_extip_ctl_line(vhd, vhd->ctl_rx,
						       vhd->ctl_rx_len);
		vhd->ctl_rx_len = 0;
		vhd->ctl_rx_discard = 0;
	}
}

int
callback_monitor_ctl(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)lws_get_opaque_user_data(wsi);
	char buf[512];
	ssize_t n;
	int fd;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX_FILE:
		fd = (int)(intptr_t)lws_get_socket_fd(wsi);
		if (!vhd || fd < 0)
			return -1;

		n = read(fd, buf, sizeof(buf));
		if (n <= 0) {
			/* the proxy end is gone */
			lwsl_notice("%s: proxy control channel closed\n",
				    __func__);
			return -1;
		}

		monitor_extip_ctl_rx(vhd, buf, (size_t)n);
		/* the first read carries the IPC auth token */
		lws_explicit_bzero(buf, (size_t)n);
		break;

	default:
		break;
	}

	return 0;
}
