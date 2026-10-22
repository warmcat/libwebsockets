/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <time.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#include <gettimeofday.h>
#endif


/*
 * The peer's User-Agent is untrusted: it's sent JSON-escaped, and truncated at
 * a character boundary if its escaped form doesn't fit in STATUS_ESC_UA_LEN.
 */
#define STATUS_ESC_IP_LEN	96
#define STATUS_ESC_UA_LEN	384

/*
 * One "conns" entry: the leading ',', the JSON text around the fields, the
 * time as a decimal number, and the escaped strings, which purify always
 * leaves NUL-terminated within their buffer.  The entry buffer is sized for
 * that worst case, so an entry is never cut short partway through.
 */
#define STATUS_ENTRY_LEN	(1 + sizeof("{\"peer\":\"\",\"time\":\"\"," \
					    "\"ua\":\"\"}") + 20 + \
				 STATUS_ESC_IP_LEN + STATUS_ESC_UA_LEN)

typedef enum {
	WALK_NONE,
	WALK_INITIAL,
	WALK_LIST,
	WALK_FINAL
} e_walk;

struct per_session_data__lws_status {
	lws_dll2_t list;	/* membership of vhd->live_pss_list */
	struct lws *wsi;
	time_t time_est;
	char user_agent[256];

	e_walk walk;
	lws_dll2_t *walk_next;
	unsigned char subsequent:1;
	unsigned char changed_partway:1;
	unsigned char wss_over_h2:1;
};

struct per_vhost_data__lws_status {
	lws_dll2_owner_t live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
};

static void
trigger_resend(struct per_vhost_data__lws_status *vhd)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->live_pss_list)) {
		struct per_session_data__lws_status *pss =
			lws_container_of(d, struct per_session_data__lws_status,
					 list);

		if (pss->walk == WALK_NONE) {
			pss->subsequent = 0;
			pss->walk_next = lws_dll2_get_head(&vhd->live_pss_list);
			pss->walk = WALK_INITIAL;
		} else
			pss->changed_partway = 1;
	} lws_end_foreach_dll(d);

	lws_callback_on_writable_all_protocol(vhd->context, vhd->protocol);
}

/*
 * Header values may contain any bytes >= 0x80, but we send the UA to other
 * people's browsers inside a ws TEXT message, which they must reject if it is
 * not valid UTF-8.  If it isn't valid UTF-8, replace every non-ASCII byte.
 */
static void
sanitize_utf8(char *s)
{
	unsigned char st = 0;

	if (!lws_check_utf8(&st, (const unsigned char *)s, strlen(s)) && !st)
		return;

	for (; *s; s++)
		if ((unsigned char)*s >= 0x80)
			*s = '?';
}

/* lws-status protocol */

static int
callback_lws_status(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_status *pss =
			(struct per_session_data__lws_status *)user;
	struct per_vhost_data__lws_status *vhd =
			(struct per_vhost_data__lws_status *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	char buf[LWS_PRE + STATUS_ENTRY_LEN], ip[24], *start = buf + LWS_PRE,
	     *p = start,
	     *end = buf + sizeof(buf) - 1;
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;

		/*
		 * We take no pvos of our own, so `in` (which is the pvo's
		 * child options, not the pvo itself) may well be NULL... we
		 * must still create the vhd, since every per-connection
		 * callback below needs it.
		 */

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_status));
		if (!vhd) {
			lwsl_vhost_err(lws_get_vhost(wsi), "%s: PROTOCOL_INIT failed", __func__);
			return 1;
		}
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED:

		/*
		 * This shows how to stage sending a single ws message in
		 * multiple fragments.  In this case, it lets us trade off
		 * memory needed to make the data vs time to send it.
		 */

		if (!vhd)
			/* we never got inited on this vhost... refuse him */
			return -1;

		lws_dll2_add_head(&pss->list, &vhd->live_pss_list);

		pss->wss_over_h2 = !!len;

		time(&pss->time_est);
		pss->wsi = wsi;

#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
		if (lws_hdr_copy(wsi, pss->user_agent, sizeof(pss->user_agent),
			     WSI_TOKEN_HTTP_USER_AGENT) < 0) /* too big */
#endif
			strcpy(pss->user_agent, "unknown");
		sanitize_utf8(pss->user_agent);
		trigger_resend(vhd);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd)
			return -1;

		switch (pss->walk) {
		case WALK_INITIAL:
			n = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				      "{ \"version\":\"%s\","
				      " \"wss_over_h2\":\"%d\","
				      " \"hostname\":\"%s\","
				      " \"wsi\":\"%d\", \"conns\":[",
				      lws_get_library_version(),
				      pss->wss_over_h2,
				      lws_canonical_hostname(vhd->context),
				      (int)lws_dll2_count(&vhd->live_pss_list));
			pss->walk = WALK_LIST;
			pss->walk_next = lws_dll2_get_head(&vhd->live_pss_list);
			break;
		case WALK_LIST:
			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			if (!pss->walk_next)
				goto walk_final;

			if (pss->subsequent)
				*p++ = ',';
			pss->subsequent = 1;

			/*
			 * our cached next guy may have gone away... the check
			 * only compares pointers against the live list, it
			 * never dereferences the possibly-freed candidate
			 */

			if (!lws_dll2_is_in_list(&vhd->live_pss_list,
						 pss->walk_next)) {
				/* our next guy went away */
				pss->walk = WALK_FINAL;
				pss->changed_partway = 1;
				break;
			}

			{
				struct per_session_data__lws_status *walk_pss =
					lws_container_of(pss->walk_next,
							 struct per_session_data__lws_status,
							 list);
				char esc_ip[STATUS_ESC_IP_LEN];
				char esc_ua[STATUS_ESC_UA_LEN];

				strcpy(ip, "unknown");
				lws_get_peer_simple(walk_pss->wsi, ip, sizeof(ip));
				lws_json_purify(esc_ip, ip, sizeof(esc_ip), NULL);
				lws_json_purify(esc_ua, walk_pss->user_agent,
						sizeof(esc_ua), NULL);

				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
						"{\"peer\":\"%s\",\"time\":\"%lu\","
						"\"ua\":\"%s\"}",
						esc_ip, (unsigned long)walk_pss->time_est,
						esc_ua);
			}

			pss->walk_next = lws_dll2_get_next(pss->walk_next);
			if (!pss->walk_next)
				pss->walk = WALK_FINAL;
			break;
		case WALK_FINAL:
walk_final:
			n = LWS_WRITE_CONTINUATION;
			p += lws_snprintf(p, 4, "]}");
			if (pss->changed_partway) {
				pss->changed_partway = 0;
				pss->subsequent = 0;
				pss->walk_next = lws_dll2_get_head(&vhd->live_pss_list);
				pss->walk = WALK_INITIAL;
			} else
				pss->walk = WALK_NONE;
			break;
		default:
			return 0;
		}

		m = lws_write(wsi, (unsigned char *)start, lws_ptr_diff_size_t(p, start), (unsigned int)n);
		if (m < 0) {
			lwsl_err("ERROR %d writing to di socket\n", m);
			return -1;
		}

		if (pss->walk != WALK_NONE)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_info("pmd test: RX len %d\n", (int)len);
		break;

	case LWS_CALLBACK_CLOSED:
		// lwsl_debug("****** LWS_CALLBACK_CLOSED\n");
		if (!vhd)
			break;

		lws_dll2_remove(&pss->list);

		trigger_resend(vhd);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_STATUS \
	{ \
		"lws-status", \
		callback_lws_status, \
		sizeof(struct per_session_data__lws_status), \
		512, /* rx buf size must be >= permessage-deflate rx size */ \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_status_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_STATUS
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_status = {
	.hdr = {
		.name = "lws status",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_status_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_status_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
