/*
 * xip relay - libwebsockets protocol plugin
 *
 * Serves the "xip" ws subprotocol from any lwsws vhost.  Authenticates
 * clients with a shared token, relays clipboard updates between every
 * other authenticated session, optionally caches the last clip for late
 * joiners, and drops over-size or malformed traffic.
 *
 * The ws URL path is the group key: the URI of the connection (read at
 * ESTABLISHED time; normally ignored for ws) selects a clipboard-sharing
 * group.  Sessions on the same path see each other, different paths are
 * fully isolated, each with its own late-joiner cache.
 *
 * Load it from your lwsws vhost JSON:
 *
 *   "ws-protocols": [ { "xip": {
 *        "token-file": "/etc/xip/token",
 *        "max-bytes":  "4194304",
 *        "cache":      "on"
 *   } } ]
 *
 * The plugin contains no clipboard code: every participating machine
 * (including the one running lwsws) runs the `xip` client binary.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#ifndef LWS_BUILD_HASH
#define LWS_BUILD_HASH "xip-external"
#endif

/*
 * This lws version defines LWS_VISIBLE as empty for out-of-tree
 * builds; with -fvisibility=hidden the single required export would
 * become a local symbol and lwsws dlsym() would fail.
 */
#if defined(__GNUC__)
#define XIP_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define XIP_PLUGIN_EXPORT
#endif

#include <stdlib.h>
#include <string.h>

#include "chunk.h"
#include "proto.h"
#include "txq.h"
#include "xip.h"

/* per-vhost state */
struct vhd__xip {
	struct lws_vhost	*vh;
	struct lws_context	*cx;

	char			 token[XIP_TOKEN_MAX + 1];
	size_t			 token_len;
	int			 have_token;

	size_t			 max_bytes;
	int			 cache;

	struct grp__xip		*groups;	/* path-keyed groups */
	unsigned int		 next_id;
};

/*
 * per-path group: sessions that connected with the same URL path share
 * clipboard and late-joiner cache.  A cached group outlives its last
 * session (push -> later pull must work per group); an empty group with
 * nothing cached is freed when its last session leaves, so random-path
 * connections cannot pin memory.
 */
struct grp__xip {
	struct grp__xip		*next, *prev;	/* vhd's group list */
	struct vhd__xip		*vhd;
	char			 path[XIP_PATH_MAX + 1];

	struct pss__xip		*sessions;

	/* cached last clip */
	uint8_t		       *clip_data;
	size_t			 clip_len;
	char			 clip_hash[XIP_HASH_HEX];
	char			 clip_mime[XIP_MIME_MAX + 1];
	unsigned		 clip_seq;
	int			 have_clip;
};

/* per-session state */
struct pss__xip {
	struct pss__xip	*next, *prev;	/* group session list */
	struct lws		*wsi;
	struct vhd__xip	*vhd;
	struct grp__xip	*grp;

	unsigned int		 id;
	int			 authed;
	int			 auth_fail;	/* flush error frame, then close */
	char			 name[XIP_NAME_MAX + 1];

	struct xip_txq_node	*txq;
	struct xip_reasm	 reasm;
	struct xip_parser	 parser;
};

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int
pss_queue(struct pss__xip *pss, const char *frame, size_t len)
{
	if (xip_txq_append(&pss->txq, frame, len))
		return -1;
	lws_callback_on_writable(pss->wsi);

	return 0;
}

/* queue a full chunked clip to one session */
static int
queue_clip_to(struct pss__xip *t, const uint8_t *data, size_t len,
	      const char *mime, const char *hash, unsigned seq)
{
	struct xip_chunker ch;
	static char frame[XIP_FRAME_MAX]; /* single-threaded service loop */
	size_t fl;

	if (xip_chunker_init(&ch, data, len, mime, seq))
		return -1;
	while (xip_chunker_next(&ch, frame, sizeof(frame), &fl) == 1)
		if (pss_queue(t, frame, fl))
			return -1;

	return 0;
}

/* relay a completed clip to every other authenticated session */
static int
broadcast_clip(struct grp__xip *grp, struct pss__xip *sender,
	       const uint8_t *data, size_t len, const char *mime,
	       const char *hash, unsigned seq)
{
	struct xip_chunker ch;
	static char frame[XIP_FRAME_MAX];
	struct pss__xip *t;
	size_t fl;
	int sent = 0;

	if (xip_chunker_init(&ch, data, len, mime, seq))
		return -1;
	while (xip_chunker_next(&ch, frame, sizeof(frame), &fl) == 1)
		for (t = grp->sessions; t; t = t->next) {
			if (t != sender && t->authed) {
				if (!xip_txq_append(&t->txq, frame, fl))
					lws_callback_on_writable(t->wsi);
				sent++;
			}
		}

	return sent;
}

static void
session_link(struct grp__xip *grp, struct pss__xip *pss)
{
	pss->prev = NULL;
	pss->next = grp->sessions;
	if (grp->sessions)
		grp->sessions->prev = pss;
	grp->sessions = pss;
}

static void
session_unlink(struct grp__xip *grp, struct pss__xip *pss)
{
	if (pss->prev)
		pss->prev->next = pss->next;
	else
		grp->sessions = pss->next;
	if (pss->next)
		pss->next->prev = pss->prev;
	pss->next = pss->prev = NULL;
}

static int
group_session_count(const struct grp__xip *grp)
{
	const struct pss__xip *t;
	int n = 0;

	for (t = grp->sessions; t; t = t->next)
		n++;

	return n;
}

static struct grp__xip *
group_find(struct vhd__xip *vhd, const char *path)
{
	struct grp__xip *g;

	for (g = vhd->groups; g; g = g->next)
		if (!strcmp(g->path, path))
			return g;

	return NULL;
}

static struct grp__xip *
group_get(struct vhd__xip *vhd, const char *path)
{
	struct grp__xip *g = group_find(vhd, path);

	if (g)
		return g;

	g = (struct grp__xip *)calloc(1, sizeof(*g));
	if (!g)
		return NULL;

	lws_strncpy(g->path, path, sizeof(g->path));
	g->vhd = vhd;
	g->next = vhd->groups;
	if (vhd->groups)
		vhd->groups->prev = g;
	vhd->groups = g;
	lwsl_notice("xip: new group '%s'\n", g->path);

	return g;
}

/* release a group ref from a closing session; may free it */
static void
group_put(struct vhd__xip *vhd, struct grp__xip *grp)
{
	if (grp->sessions)
		return;
	if (vhd->cache && grp->have_clip)
		return;		/* keep the late-joiner cache warm */

	if (grp->prev)
		grp->prev->next = grp->next;
	else
		vhd->groups = grp->next;
	if (grp->next)
		grp->next->prev = grp->prev;

	free(grp->clip_data);
	free(grp);
}

/* constant-time token compare; length mismatch is allowed to leak */
static int
ct_token_eq(const char *a, size_t alen, const char *b, size_t blen)
{
	volatile unsigned char d = 0;
	size_t i, n = alen > blen ? alen : blen;

	if (alen != blen)
		d = 1;
	for (i = 0; i < n; i++) {
		d |= (unsigned char)(i < alen ? a[i] : 0) ^
		     (unsigned char)(i < blen ? b[i] : 0);
	}

	return d == 0;
}

static void
replace_cache(struct grp__xip *grp, const uint8_t *data, size_t len,
	      const char *mime, const char *hash)
{
	uint8_t *nd = NULL;

	if (len) {
		nd = (uint8_t *)malloc(len);
		if (!nd)
			return;
		memcpy(nd, data, len);
	}
	free(grp->clip_data);
	grp->clip_data = nd;
	grp->clip_len = len;
	lws_strncpy(grp->clip_hash, hash, sizeof(grp->clip_hash));
	lws_strncpy(grp->clip_mime, mime, sizeof(grp->clip_mime));
	grp->clip_seq = (unsigned)lws_now_secs();
	grp->have_clip = 1;
}

static char *
read_token_file(const char *path, char *buf, size_t cap, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return NULL;
	n = fread(buf, 1, cap - 1, f);
	fclose(f);
	if (!n)
		return NULL;
	buf[n] = '\0';
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
		     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
		buf[--n] = '\0';
	if (!n)
		return NULL;
	*out_len = n;

	return buf;
}

/* ------------------------------------------------------------------ */
/* message dispatch                                                    */
/* ------------------------------------------------------------------ */

static int
handle_hello(struct vhd__xip *vhd, struct pss__xip *pss,
	     const struct xip_msg *m)
{
	char frame[256];
	int n;

	if (pss->authed) {
		n = xip_build_error(frame, sizeof(frame), "auth");
		pss_queue(pss, frame, (size_t)n);
		pss->auth_fail = 1;

		return 0;
	}

	if (!vhd->have_token ||
	    !ct_token_eq(vhd->token, vhd->token_len,
			 m->token, strlen(m->token))) {
		lwsl_notice("xip: auth failed for new connection\n");
		n = xip_build_error(frame, sizeof(frame), "auth");
		pss_queue(pss, frame, (size_t)n);
		pss->auth_fail = 1;

		return 0;
	}

	pss->authed = 1;
	pss->id = ++vhd->next_id;
	lws_strncpy(pss->name, m->name[0] ? m->name : "anon",
		    sizeof(pss->name));
	session_link(pss->grp, pss);
	{
		int cnt = group_session_count(pss->grp);

		lwsl_notice("xip: session %u '%s' joined group '%s' "
			    "(%d in group)\n", pss->id, pss->name,
			    pss->grp->path, cnt);
	}

	n = xip_build_welcome(frame, sizeof(frame), pss->id,
			      (vhd->cache && pss->grp->have_clip) ?
					pss->grp->clip_hash : NULL);
	pss_queue(pss, frame, (size_t)n);

	return 0;
}

static int
handle_msg(struct pss__xip *pss, const struct xip_msg *m)
{
	struct vhd__xip *vhd = pss->vhd;
	struct grp__xip *grp = pss->grp;
	char frame[256];
	int n, r;


	switch (m->type) {
	case XIP_MSG_HELLO:
		return handle_hello(vhd, pss, m);

	case XIP_MSG_FETCH:
		if (!pss->authed) {
			n = xip_build_error(frame, sizeof(frame), "auth");
			pss_queue(pss, frame, (size_t)n);
			pss->auth_fail = 1;
			break;
		}
		if (vhd->cache && grp->have_clip)
			queue_clip_to(pss, grp->clip_data, grp->clip_len,
				      grp->clip_mime, grp->clip_hash,
				      grp->clip_seq);
		break;

	case XIP_MSG_CLIP:
		if (!pss->authed) {
			n = xip_build_error(frame, sizeof(frame), "auth");
			pss_queue(pss, frame, (size_t)n);
			pss->auth_fail = 1;
			break;
		}
		r = xip_reasm_add(&pss->reasm, m, vhd->max_bytes);
		if (r < 0) {
			lwsl_notice("xip: bad/oversize chunk from session "
				    "%u\n", pss->id);
			n = xip_build_error(frame, sizeof(frame),
					    "too-large");
			pss_queue(pss, frame, (size_t)n);
			break;
		}
		if (r == 1) {
			int peers;

			if (grp->have_clip &&
			    !strcmp(grp->clip_hash, pss->reasm.hash)) {
				lwsl_debug("xip: dedup clip from %u\n",
					   pss->id);
				break;	/* identical consecutive clip */
			}
			if (vhd->cache)
				replace_cache(grp, pss->reasm.data,
					      pss->reasm.len,
					      pss->reasm.mime,
					      pss->reasm.hash);
			/*
			 * NB: never put calls with side effects inside
			 * lwsl_*() args; INFO-level logs compile away
			 * with default _LWS_ENABLED_LOGS.
			 */
			peers = broadcast_clip(grp, pss, pss->reasm.data,
					       pss->reasm.len,
					       pss->reasm.mime,
					       pss->reasm.hash,
					       pss->reasm.seq);
			lwsl_notice("xip: clip from '%s' (%zu bytes, "
				    "hash %s) relayed to %d peer(s) in "
				    "group '%s'\n",
				    pss->name, pss->reasm.len,
				    pss->reasm.hash, peers, grp->path);
		}
		break;

	case XIP_MSG_BYE:
		lwsl_info("xip: session %u '%s' said bye\n",
			   pss->id, pss->name);
		return -1;

	case XIP_MSG_ERROR:
		lwsl_info("xip: client '%s' reported: %s\n",
			   pss->name, m->reason);
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* protocol callback                                                   */
/* ------------------------------------------------------------------ */

static int
callback_xip(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss__xip *pss = (struct pss__xip *)user;
	struct vhd__xip *vhd = (struct vhd__xip *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	char frame[256];
	int n, budget;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(*vhd));
		if (!vhd)
			return 0;

		vhd->vh = lws_get_vhost(wsi);
		vhd->cx = lws_get_context(wsi);
		vhd->max_bytes = XIP_MAX_BYTES_DEFAULT;
		vhd->cache = 1;

		{
			const char *s;

			if (lws_pvo_get_str(in, "token-file", &s) == 0) {
				if (read_token_file(s, vhd->token,
						    sizeof(vhd->token),
						    &vhd->token_len))
					vhd->have_token = 1;
				else
					lwsl_err("xip: cannot read "
						 "token-file '%s'\n", s);
			}
			if (lws_pvo_get_str(in, "token", &s) == 0) {
				lws_strncpy(vhd->token, s,
					    sizeof(vhd->token));
				vhd->token_len = strlen(vhd->token);
				vhd->have_token = 1;
			}
			if (lws_pvo_get_str(in, "max-bytes", &s) == 0)
				vhd->max_bytes = (size_t)atoll(s);
			if (lws_pvo_get_str(in, "cache", &s) == 0)
				vhd->cache = strcmp(s, "off") &&
					     strcmp(s, "0");
		}

		if (!vhd->have_token)
			lwsl_err("xip: no token configured; all clients "
				 "will be refused (set 'token' or "
				 "'token-file' pvo)\n");
		else
			lwsl_notice("xip: relay ready on vhost (max %zu "
				    "bytes, cache %s)\n", vhd->max_bytes,
				    vhd->cache ? "on" : "off");
		break;

	case LWS_CALLBACK_ESTABLISHED: {
		char path[XIP_PATH_MAX + 1];
		int pl;

		if (!vhd) {
			/* protocol not instantiated on this vhost */
			lwsl_err("xip: no vhost state; is the 'xip' pvo "
				 "configured on this vhost?\n");

			return -1;
		}

		/*
		 * The URL path is normally ignored for ws; we use it as
		 * the clipboard-group key.  The ah is still attached here
		 * (it is detached after ESTABLISHED returns), and lws
		 * seals WSI_TOKEN_GET_URI at the '?', so the query string
		 * is not part of the key.
		 */
		pl = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
		if (pl <= 0) {
			lws_strncpy(path, "/", sizeof(path));
		} else if (pl > XIP_PATH_MAX ||
			   lws_hdr_copy(wsi, path, sizeof(path),
					WSI_TOKEN_GET_URI) < 1) {
			lwsl_notice("xip: refusing connection with "
				    "oversized path (%d bytes)\n", pl);

			return -1;
		}

		memset(pss, 0, sizeof(*pss));
		pss->wsi = wsi;
		pss->vhd = vhd;
		pss->grp = group_get(vhd, path);
		if (!pss->grp) {
			lwsl_err("xip: OOM creating group\n");

			return -1;
		}
		xip_parser_init(&pss->parser);
		break;
	}

	case LWS_CALLBACK_SERVER_WRITEABLE:
		budget = 8;			/* frames per service pass */
		while (budget-- && pss->txq) {
			struct xip_txq_node *tn = xip_txq_pop(&pss->txq);
			int m = lws_write(wsi, tn->buf + LWS_PRE + tn->off,
					  (unsigned int)(tn->len - tn->off),
					  LWS_WRITE_TEXT);

			if (m < 0) {
				xip_txq_free_node(tn);
				return -1;
			}
			if ((size_t)m < tn->len - tn->off) {
				/* defensive partial handling: push back */
				tn->off += (size_t)m;
				tn->next = pss->txq;
				pss->txq = tn;
				lws_callback_on_writable(wsi);
				break;
			}
			xip_txq_free_node(tn);
		}
		if (pss->txq)
			lws_callback_on_writable(wsi);
		else if (pss->auth_fail) {
			/* error flushed: close cleanly (explicit kill is
			 * version-stable where -1 returns stopped
			 * closing in newer lws) */
			lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_SEND,
					LWS_TO_KILL_ASYNC);
		}
		break;

	case LWS_CALLBACK_RECEIVE: {
		int r;

		r = xip_parser_feed(&pss->parser, in, len);
		if (r < 0) {
			lwsl_info("xip: protocol parse error\n");
			n = xip_build_error(frame, sizeof(frame), "bad-json");
			pss_queue(pss, frame, (size_t)n);
			pss->auth_fail = 1;
			break;
		}
		if (r == 1) {
			n = handle_msg(pss, &pss->parser.msg);
			xip_parser_reset(&pss->parser);
			if (n)
				return -1;
		}
		break;
	}

	case LWS_CALLBACK_CLOSED:
		if (pss->vhd && pss->authed && pss->grp) {
			session_unlink(pss->grp, pss);
			lwsl_notice("xip: session %u '%s' left group '%s'\n",
				    pss->id, pss->name, pss->grp->path);
		}
		if (pss->vhd && pss->grp) {
			group_put(pss->vhd, pss->grp);	/* may free it */
			pss->grp = NULL;
		}
		xip_txq_destroy(&pss->txq);
		xip_reasm_destroy(&pss->reasm);
		xip_parser_reset(&pss->parser);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			while (vhd->groups) {
				struct grp__xip *g = vhd->groups;

				vhd->groups = g->next;
				free(g->clip_data);
				free(g);
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* plugin packaging                                                    */
/* ------------------------------------------------------------------ */

#define XIP_PLUGIN_PROTOCOL_XIP \
	{ \
		XIP_WS_PROTOCOL, \
		callback_xip, \
		sizeof(struct pss__xip), \
		XIP_FRAME_MAX, /* rx buf covers one full b64 chunk */ \
		0, NULL, 0 \
	}

#if !defined(LWS_PLUGIN_STATIC)

static const struct lws_protocols xip_protocols[] = {
	XIP_PLUGIN_PROTOCOL_XIP
};

/*
 * Must be named exactly like the .so suffix after removing
 * "libprotocol_", i.e. libprotocol_xip_clipboard.so exports
 * xip_clipboard.  Note the base name must be >= 6 chars or
 * lws_plat_dlopen() silently rejects the plugin.
 */
XIP_PLUGIN_EXPORT const lws_plugin_protocol_t xip_clipboard = {
	.hdr = {
		.name			= "xip relay",
		._class			= "lws_protocol_plugin",
		.lws_build_hash		= LWS_BUILD_HASH,
		.api_magic		= LWS_PLUGIN_API_MAGIC
	},
	.protocols		= xip_protocols,
	.count_protocols	= LWS_ARRAY_SIZE(xip_protocols),
	.extensions		= NULL,
	.count_extensions	= 0,
};

#endif
