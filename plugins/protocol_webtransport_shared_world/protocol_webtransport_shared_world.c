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
		if (!in)
			return 0;

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
		if (!lws_wt_is_session(wsi) && lws_wt_get_session_wsi(wsi) != NULL) {
			goto init_session;
		}
#endif
		break;

	case LWS_CALLBACK_ESTABLISHED:
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			lwsl_user("WT Session established\n");
			break;
		}
#endif
#if defined(LWS_ROLE_WT)
	init_session:
#endif
		if (pss->wsi) {
			lwsl_user("Session already initialized\n");
			break;
		}
		{
			const char *tt = "WebSocket";
#if defined(LWS_ROLE_WT)
			if (lws_wt_is_session(wsi) || lws_wt_get_session_wsi(wsi) != NULL) {
				tt = "WebTransport";
			}
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
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);

		/* Broadcast join message */
		{
			struct msg jmsg;
			jmsg.sender_id = pss->player_id;
			jmsg.len = (size_t)lws_snprintf(jmsg.payload + LWS_PRE, sizeof(jmsg.payload) - LWS_PRE,
							"{\"join\":%u}", pss->player_id);
			lws_ring_insert(vhd->ring, &jmsg, 1);
		}

		lws_callback_on_writable(wsi);
		lws_callback_on_writable_all_protocol(lws_get_context(wsi), lws_get_protocol(wsi));
		break;

	case LWS_CALLBACK_CLOSED:
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			break;
		}
#endif
		if (!pss->wsi) {
			break;
		}
		{
			const char *tt = "WebSocket";
#if defined(LWS_ROLE_WT)
			if (lws_wt_is_session(wsi) || lws_wt_get_session_wsi(wsi) != NULL) {
				tt = "WebTransport";
			}
#endif
			lwsl_user("Connection/Stream closed (transport: %s)\n", tt);
		}
		lws_dll2_remove(&pss->list);

		/* Broadcast leave message */
		{
			struct msg lmsg;
			lmsg.sender_id = pss->player_id;
			lmsg.len = (size_t)lws_snprintf(lmsg.payload + LWS_PRE, sizeof(lmsg.payload) - LWS_PRE,
							"{\"leave\":%u}", pss->player_id);
			lws_ring_insert(vhd->ring, &lmsg, 1);
		}

		lws_callback_on_writable_all_protocol(lws_get_context(wsi), lws_get_protocol(wsi));
		break;

	case LWS_CALLBACK_RECEIVE:
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			break;
		}
#endif
		if (!pss->wsi) {
			break;
		}
		{
			size_t alen;
			const char *val;

			val = lws_json_simple_find(in, len, "\"x\":", &alen);
			if (val) pss->x = atof(val);

			val = lws_json_simple_find(in, len, "\"z\":", &alen);
			if (val) pss->z = atof(val);

			val = lws_json_simple_find(in, len, "\"angle\":", &alen);
			if (val) pss->angle = atof(val);

			val = lws_json_simple_find(in, len, "\"speed\":", &alen);
			if (val) pss->speed = atof(val);

			val = lws_json_simple_find(in, len, "\"isMoving\":", &alen);
			if (val) pss->is_moving = (!strncmp(val, "true", 4)) ? 1 : 0;

			/* Broadcast update */
			{
				struct msg umsg;
				umsg.sender_id = pss->player_id;
				umsg.len = (size_t)lws_snprintf(umsg.payload + LWS_PRE, sizeof(umsg.payload) - LWS_PRE,
								"{\"player_id\":%u,\"x\":%.2f,\"z\":%.2f,\"angle\":%.2f,\"isMoving\":%s}",
								pss->player_id, pss->x, pss->z, pss->angle, pss->is_moving ? "true" : "false");
				lws_ring_insert(vhd->ring, &umsg, 1);
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
		if (!pss->wsi) {
			break;
		}
		if (!pss->seed_sent) {
			char *p = (char *)buf + LWS_PRE;
			char *end = (char *)buf + sizeof(buf);

			p += lws_snprintf(p, (size_t)(end - p), "{\"seed\":%u,\"player_id\":%u,\"players\":[",
					  vhd->seed, pss->player_id);

			int first = 1;
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
				struct pss__shared_world *other = lws_container_of(d, struct pss__shared_world, list);
				if (other != pss) {
					if (!first)
						p += lws_snprintf(p, (size_t)(end - p), ",");
					first = 0;
					p += lws_snprintf(p, (size_t)(end - p), "{\"id\":%u,\"x\":%.2f,\"z\":%.2f,\"angle\":%.2f,\"isMoving\":%s}",
							  other->player_id, other->x, other->z, other->angle, other->is_moving ? "true" : "false");
				}
			} lws_end_foreach_dll(d);

			p += lws_snprintf(p, (size_t)(end - p), "]}");

			size_t slen = (size_t)(p - ((char *)buf + LWS_PRE));
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
				
				int oldest_consumed = (lws_ring_get_oldest_tail(vhd->ring) == pss->tail);
				lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);
				
				if (oldest_consumed) {
					uint32_t oldest = pss->tail;
					size_t max_waiting = 0;
					
					lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
						struct pss__shared_world *other = lws_container_of(d, struct pss__shared_world, list);
						size_t waiting = lws_ring_get_count_waiting_elements(vhd->ring, &other->tail);
						if (waiting >= max_waiting) {
							max_waiting = waiting;
							oldest = other->tail;
						}
					} lws_end_foreach_dll(d);
					
					lws_ring_update_oldest_tail(vhd->ring, oldest);
				}

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
	LWS_PLUGIN_PROTOCOL_SHARED_WORLD
};

LWS_VISIBLE const lws_plugin_protocol_t webtransport_shared_world = {
	.hdr = {
		.name = "webtransport shared world",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = shared_world_protocols,
	.count_protocols = LWS_ARRAY_SIZE(shared_world_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
