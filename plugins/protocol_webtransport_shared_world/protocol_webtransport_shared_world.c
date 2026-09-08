/*
 * WebTransport + WebSocket shared world test plugin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
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
#include <libwebsockets/lws-webtransport.h>
#include <string.h>
#include <stdlib.h>

struct msg {
	char payload[LWS_PRE + 256];
	size_t len;
	uint32_t sender_id;
};

struct vhd__shared_world {
	lws_dll2_owner_t sessions;
	struct lws_ring *ring;
	uint32_t seed;
	uint32_t next_player_id;
};

struct pss__shared_world {
	lws_dll2_t list;
	struct lws *wsi;
	uint32_t player_id;
	uint32_t tail;
	double x;
	double z;
	double angle;
	double speed;
	int seed_sent;
	int is_moving;
};

/*
 * The world is nominally +/- this much on each axis.  Peer-provided
 * coordinates outside it (or a nan / inf out of strtod) are dropped, since
 * they are only useful for corrupting the JSON we compose for everybody else.
 */

#define SW_COORD_LIMIT		1000000.0
#define SW_ANGLE_LIMIT		10000.0

/* worst case length of one player object in the welcome JSON, plus slack */

#define SW_PLAYER_JSON_MAX	128u

/*
 * The rx is not NUL-terminated on the WebTransport / QUIC path, and
 * lws_json_simple_find() does not terminate anything either, it only returns
 * the bounded extent of the value.  So copy the extent out to a scratch buffer
 * before letting strtod() near it, and only accept a finite, in-range result.
 */

static int
sw_json_double(const char *buf, size_t len, const char *name, double *result,
	       double limit)
{
	char scratch[32], *ep;
	const char *val;
	size_t alen;
	double d;

	val = lws_json_simple_find(buf, len, name, &alen);
	if (!val || !alen || alen >= sizeof(scratch))
		return 0;

	memcpy(scratch, val, alen);
	scratch[alen] = '\0';

	d = strtod(scratch, &ep);
	if (ep == scratch)
		return 0;

	while (*ep == ' ' || *ep == '\t')
		ep++;

	if (*ep)
		return 0;

	/* written this way so nan, which compares false either way, is out */

	if (!(d >= -limit && d <= limit))
		return 0;

	*result = d;

	return 1;
}

static int
sw_json_bool(const char *buf, size_t len, const char *name, int *result)
{
	const char *val;
	size_t alen;

	val = lws_json_simple_find(buf, len, name, &alen);
	if (!val)
		return 0;

	/* the length matters, the value is not NUL-terminated */

	*result = alen == 4 && !strncmp(val, "true", 4);

	return 1;
}

/*
 * Move the ring's oldest tail up to wherever the furthest-behind live session
 * is.  This has to happen after every service and after any session leaves:
 * if we only did it when the session we just serviced happened to be holding
 * the oldest tail, then a session leaving while holding it pins the tail there
 * forever, the ring fills, and every subsequent broadcast is silently dropped.
 */

static void
sw_recompute_oldest_tail(struct vhd__shared_world *vhd)
{
	size_t max_waiting = 0;
	uint32_t oldest = 0;
	int any = 0;

	if (!vhd || !vhd->ring)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->sessions)) {
		struct pss__shared_world *other = lws_container_of(d,
					struct pss__shared_world, list);
		size_t waiting = lws_ring_get_count_waiting_elements(vhd->ring,
								&other->tail);

		if (!any || waiting > max_waiting) {
			max_waiting = waiting;
			oldest = other->tail;
			any = 1;
		}
	} lws_end_foreach_dll(d);

	if (!any) {
		/* nobody left to serve, the ring can be emptied */

		lws_ring_consume(vhd->ring, NULL, NULL,
			lws_ring_get_count_waiting_elements(vhd->ring, NULL));

		return;
	}

	lws_ring_update_oldest_tail(vhd->ring, oldest);
}

/*
 * Take the session out of the player list and tell the others it left.
 *
 * This must be idempotent and it must be called from every path that can
 * destroy or replace the pss, since the list node lives inside the pss.
 */

static void
sw_unregister(struct vhd__shared_world *vhd, struct pss__shared_world *pss,
	      struct lws *wsi)
{
	struct msg lmsg;

	if (!pss || !pss->wsi)
		return;

	pss->wsi = NULL;
	lws_dll2_remove(&pss->list);

	if (!vhd || !vhd->ring)
		return;

	/* Broadcast leave message */

	lmsg.sender_id = pss->player_id;
	lmsg.len = (size_t)lws_snprintf(lmsg.payload + LWS_PRE,
					sizeof(lmsg.payload) - LWS_PRE,
					"{\"leave\":%u}", pss->player_id);
	if (lws_ring_insert(vhd->ring, &lmsg, 1) != 1)
		lwsl_wsi_warn(wsi, "Failed to insert leave message to ring");

	sw_recompute_oldest_tail(vhd);

	lws_callback_on_writable_all_protocol(lws_get_context(wsi),
					      lws_get_protocol(wsi));
}

static int
callback_shared_world(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	struct pss__shared_world *pss = (struct pss__shared_world *)user;
	struct vhd__shared_world *vhd = (struct vhd__shared_world *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 4096];

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd__shared_world));
		if (!vhd)
			return -1;

		vhd->ring = lws_ring_create(sizeof(struct msg), 32, NULL);
		if (!vhd->ring)
			return -1;

		lws_dll2_owner_clear(&vhd->sessions);
		vhd->next_player_id = 0;
		{
			struct lws_xos xos;
			lws_xos_init(&xos, 0x12345678);
			vhd->seed = (uint32_t)lws_xos(&xos);
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			if (vhd->ring) {
				lws_ring_destroy(vhd->ring);
				vhd->ring = NULL;
			}
		}
		break;

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
#if defined(LWS_ROLE_WT)
		/*
		 * The session wsi is only the transport for the streams, it is
		 * not itself a player
		 */

		if (lws_wt_is_session(wsi)) {
			lwsl_user("WT Session established\n");
			break;
		}

		if (lws_wt_get_session_wsi(wsi) != NULL)
			goto init_session;
#endif
		break;

	case LWS_CALLBACK_ESTABLISHED:
#if defined(LWS_ROLE_WT)
	init_session:
#endif
		if (!pss)
			break;
		if (pss->wsi) {
			lwsl_user("Session already initialized\n");
			break;
		}
		/*
		 * We cannot play without the vhost priv, eg, if the vhost
		 * never issued PROTOCOL_INIT for us
		 */
		if (!vhd || !vhd->ring) {
			lwsl_wsi_warn(wsi, "protocol not initialized on vhost");
			return -1;
		}
		{
			const char *tt = "WebSocket";
#if defined(LWS_ROLE_WT)
			if (lws_wt_get_session_wsi(wsi) != NULL)
				tt = "WebTransport";
#endif
			lwsl_user("Connection/Stream established (protocol: %s, transport: %s)\n",
				  lws_get_protocol(wsi)->name, tt);
		}
		pss->wsi = wsi;
		pss->player_id = ++vhd->next_player_id;
		pss->x = 0.0;
		pss->z = 0.0;
		pss->angle = 0.0;
		pss->speed = 0.0;
		pss->is_moving = 0;
		pss->seed_sent = 0;

		lws_dll2_add_tail(&pss->list, &vhd->sessions);

		/*
		 * Start from the head... anything still in the ring belongs to
		 * exchanges that happened before we existed
		 */

		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		lws_ring_consume(vhd->ring, &pss->tail, NULL,
			lws_ring_get_count_waiting_elements(vhd->ring,
							    &pss->tail));

		/* Broadcast join message */
		{
			struct msg jmsg;
			jmsg.sender_id = pss->player_id;
			jmsg.len = (size_t)lws_snprintf(jmsg.payload + LWS_PRE, sizeof(jmsg.payload) - LWS_PRE,
							"{\"join\":%u}", pss->player_id);
			if (lws_ring_insert(vhd->ring, &jmsg, 1) != 1) {
				lwsl_wsi_warn(wsi, "Failed to insert join message to ring");
			}
		}

		lws_callback_on_writable(wsi);
		lws_callback_on_writable_all_protocol(lws_get_context(wsi), lws_get_protocol(wsi));
		break;

	/*
	 * A stream we adopted as a player may be closed, or have its pss freed
	 * and replaced under it, by any of these depending on the role it ended
	 * up in... a QUIC stream that never became a WebTransport one closes as
	 * h3, and lws_bind_protocol() frees the pss on the unbind reasons even
	 * when the protocol is unchanged.  Unregistering on all of them is what
	 * stops the player list keeping a node that lives in freed heap.
	 */

	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	case LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL:
#if defined(LWS_ROLE_WT)
	case LWS_CALLBACK_WT_DROP_PROTOCOL:
#endif
		if (!pss || !pss->wsi)
			break;

		lwsl_user("Connection/Stream closed (player %u)\n",
			  pss->player_id);

		sw_unregister(vhd, pss, wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			break;
		}
#endif
		if (!pss || !pss->wsi || !vhd || !vhd->ring) {
			break;
		}
		{
			sw_json_double(in, len, "\"x\":", &pss->x,
				       SW_COORD_LIMIT);
			sw_json_double(in, len, "\"z\":", &pss->z,
				       SW_COORD_LIMIT);
			sw_json_double(in, len, "\"angle\":", &pss->angle,
				       SW_ANGLE_LIMIT);
			sw_json_double(in, len, "\"speed\":", &pss->speed,
				       SW_COORD_LIMIT);
			sw_json_bool(in, len, "\"isMoving\":", &pss->is_moving);

			/* Broadcast update */
			{
				struct msg umsg;
				umsg.sender_id = pss->player_id;
				umsg.len = (size_t)lws_snprintf(umsg.payload + LWS_PRE, sizeof(umsg.payload) - LWS_PRE,
								"{\"player_id\":%u,\"x\":%.2f,\"z\":%.2f,\"angle\":%.2f,\"isMoving\":%s}",
								pss->player_id, pss->x, pss->z, pss->angle, pss->is_moving ? "true" : "false");
				if (lws_ring_insert(vhd->ring, &umsg, 1) != 1) {
					lwsl_wsi_warn(wsi, "Failed to insert update message to ring");
				}
			}

			lws_callback_on_writable_all_protocol(lws_get_context(wsi), lws_get_protocol(wsi));
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			break;
		}
#endif
		if (!pss || !pss->wsi || !vhd || !vhd->ring) {
			break;
		}
		if (!pss->seed_sent) {
			char *p = (char *)buf + LWS_PRE;
			/*
			 * hold back enough for the "]}" terminator, so that
			 * however many players there are, what we send is
			 * always parseable JSON
			 */
			char *lim = (char *)buf + sizeof(buf) - 3;
			char *end = (char *)buf + sizeof(buf);
			size_t slen;
			int first = 1;

			p += lws_snprintf(p, lws_ptr_diff_size_t(lim, p),
					  "{\"seed\":%u,\"player_id\":%u,\"players\":[",
					  vhd->seed, pss->player_id);

			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct pss__shared_world *other = lws_container_of(d, struct pss__shared_world, list);

				if (lws_ptr_diff_size_t(lim, p) < SW_PLAYER_JSON_MAX)
					break;

				if (other != pss) {
					if (!first)
						p += lws_snprintf(p, lws_ptr_diff_size_t(lim, p), ",");
					first = 0;
					p += lws_snprintf(p, lws_ptr_diff_size_t(lim, p), "{\"id\":%u,\"x\":%.2f,\"z\":%.2f,\"angle\":%.2f,\"isMoving\":%s}",
							  other->player_id, other->x, other->z, other->angle, other->is_moving ? "true" : "false");
				}
			} lws_end_foreach_dll(d);

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

			slen = lws_ptr_diff_size_t(p, (char *)buf + LWS_PRE);
			lwsl_user("Sending initial welcome JSON: %s\n", (char *)buf + LWS_PRE);
			if (lws_write(wsi, buf + LWS_PRE, (unsigned int)slen, LWS_WRITE_TEXT) < (int)slen)
				return -1;

			pss->seed_sent = 1;
		}

		{
			const struct msg *pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
			if (pmsg) {
				if (lws_write(wsi, (unsigned char *)pmsg->payload + LWS_PRE, pmsg->len, LWS_WRITE_TEXT) < (int)pmsg->len)
					return -1;

				lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);

				sw_recompute_oldest_tail(vhd);

				if (lws_ring_get_element(vhd->ring, &pss->tail))
					lws_callback_on_writable(wsi);
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_SHARED_WORLD \
	{ \
		"webtransport-shared-world", \
		callback_shared_world, \
		sizeof(struct pss__shared_world), \
		4096, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
LWS_VISIBLE const struct lws_protocols shared_world_protocols[] = {
	LWS_PLUGIN_PROTOCOL_SHARED_WORLD,
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

LWS_VISIBLE const lws_plugin_protocol_t webtransport_shared_world = {
	.hdr = {
		.name = "webtransport shared world",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = shared_world_protocols,
	.count_protocols = 1,
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
