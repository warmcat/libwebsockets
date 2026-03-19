/*
 * Sai common utils
 *
 * Copyright (C) 2025 Andy Green <andy@warmcat.com>
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
 */

#include <libwebsockets.h>

#include <assert.h>

#include "include/private.h"

#if defined(WIN32)
#define write _write
#endif

int
sai_uuid16_create(struct lws_context *context, char *dest33)
{
	uint8_t uuid[16];
	int n;

	if (lws_get_random(context, uuid, sizeof(uuid)) != sizeof(uuid))
		return -1;

	for (n = 0; n < 16; n++)
		lws_snprintf(dest33 + (n * 2), 3, "%02X", uuid[n]);

	return 0;
}

int
sai_metrics_hash(uint8_t *key, size_t key_len, const char *sp_name,
		 const char *spawn, const char *project_name,
		 const char *ref)
{
	struct lws_genhash_ctx ctx;
	uint8_t hash[32];

//	lwsl_notice("%s: }}}}}}}}}}}}}}}}}}}}} '%s' '%s' '%s' '%s'\n", __func__,
//	sp_name, spawn, project_name, ref);

	if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256)		 ||
	    lws_genhash_update(&ctx, sp_name,	   strlen(sp_name))	 ||
	    lws_genhash_update(&ctx, spawn,	   strlen(spawn))	 ||
	    lws_genhash_update(&ctx, project_name, strlen(project_name)) ||
	    lws_genhash_update(&ctx, ref,	   strlen(ref))		 ||
	    lws_genhash_destroy(&ctx, hash))
		return 1;

	lws_hex_from_byte_array(hash, sizeof(hash), (char *)key, sizeof(key_len));
	key[key_len - 1] = '\0';

	return 0;
}

const char *
sai_get_ref(const char *fullref)
{
	if (!strncmp(fullref, "refs/heads/", 11))
		return fullref + 11;

	if (!strncmp(fullref, "refs/tags/", 10))
		return fullref + 10;

	return fullref;
}

const char *
sai_task_describe(sai_task_t *task, char *buf, size_t len)
{
	lws_snprintf(buf, len, "[%s(step %d/%d)]",
		     task->uuid, task->build_step, task->build_step_count);

	return buf;
}

void
sai_dump_stderr(const uint8_t *buf, size_t w)
{
	if ((ssize_t)write(2, "\n", 1) != (ssize_t)1 ||
	    (ssize_t)write(2, buf, LWS_POSIX_LENGTH_CAST(w)) != (ssize_t)w ||
	    (ssize_t)write(2, "\n", 1) != (ssize_t)1)
		lwsl_err("%s: failed to log to stderr\n", __func__);
}


int
sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(struct lws_ss_handle *h,
					      struct lws_buflist **buflist,
					      void *buf, size_t len,
					      unsigned int ss_flags)
{
	unsigned int *pi = (unsigned int *)((const char *)buf - sizeof(int));

	*pi = ss_flags;

	if (lws_buflist_append_segment(buflist, (uint8_t *)buf - sizeof(int),
				       len + sizeof(int)) < 0)
		lwsl_ss_err(h, "failed to append"); /* still ask to drain */

	if (lws_ss_request_tx(h))
		lwsl_ss_err(h, "failed to request tx");

	return 0;
}

int
sai_ss_serialize_queue_helper(struct lws_ss_handle *h,
			      struct lws_buflist **buflist,
			      const lws_struct_map_t *map,
			      size_t map_len, void *root)
{
	lws_struct_json_serialize_result_t r = 0;
	uint8_t buf[1100 + LWS_PRE], fi = 1;
	lws_struct_serialize_t *js;

	js = lws_struct_json_serialize_create(map, map_len, 0, root);
	if (!js) {
		lwsl_ss_warn(h, "Failed to serialize state update");
		return 1;
	}

	do {
		size_t w;

		r = lws_struct_json_serialize(js, buf + LWS_PRE,
					      sizeof(buf) - LWS_PRE, &w);

		// lwsl_hexdump_err(buf + LWS_PRE, w);

		sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(h, buflist,
				   buf + LWS_PRE, w, (unsigned int)((fi ? LWSSS_FLAG_SOM : 0) |
				   (r == LSJS_RESULT_FINISH ? LWSSS_FLAG_EOM : 0)));
		fi = 0;
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);

	return 0;
}

lws_ss_state_return_t
sai_ss_tx_from_buflist_helper(struct lws_ss_handle *ss, struct lws_buflist **buflist,
			      uint8_t *buf, size_t *len, int *flags)
{
	int *pi = (int *)lws_buflist_get_frag_start_or_NULL(buflist), depi, fl;
	char som, som1, eom, final = 1;
	size_t fsl, used;

	if (!*buflist)
		return LWSSSSRET_TX_DONT_SEND;

	depi = *pi;

	fsl = lws_buflist_next_segment_len(buflist, NULL);

	lws_buflist_fragment_use(buflist, NULL, 0, &som, &eom);
	if (som) {
		fsl -= sizeof(int);
		lws_buflist_fragment_use(buflist, buf, sizeof(int), &som1, &eom);
	}
	if (!(depi & LWSSS_FLAG_SOM))
		som = 0;

	if (*len > fsl)
		*len = fsl;

	used = (size_t)lws_buflist_fragment_use(buflist, (uint8_t *)buf, *len, &som1, &eom);
	if (!used)
		return LWSSSSRET_TX_DONT_SEND;

	if (used < fsl || !(depi & LWSSS_FLAG_EOM)) /* we saved SS flags at the start of the buf */
		final = 0;

	*len = used;
	fl = (som ? LWSSS_FLAG_SOM : 0) | (final ? LWSSS_FLAG_EOM : 0);

	if ((fl & LWSSS_FLAG_SOM) && (((*flags) & 3) == 2)) {
		lwsl_ss_err(ss, "TX: Illegal LWSSS_FLAG_SOM after previous frame without LWSSS_FLAG_EOM");
		assert(0);
	}
	if (!(fl & LWSSS_FLAG_SOM) && ((*flags) & 3) == 3) {
		lwsl_ss_err(ss, "TX: Missing LWSSS_FLAG_SOM after previous frame with LWSSS_FLAG_EOM");
		assert(0);
	}
	if (!(fl & LWSSS_FLAG_SOM) && !((*flags) & 2)) {
		lwsl_ss_err(ss, "TX: Missing LWSSS_FLAG_SOM on first frame");
		assert(0);
	}

	*flags = fl;

	/* If there are more to send, request another writable callback */
	if (*buflist && lws_ss_request_tx(ss))
		lwsl_ss_warn(ss, "tx request failed");

	return LWSSSSRET_OK;
}

