/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Secure Streams / OTA
 *
 * In the interests of minimizing heap usage, OTA SS is only existing during
 * update checks, update bulk data download, and OTA storage.  Checks are
 * initiated by cx->sul_ota_periodic which is triggered at OPERATIONAL and then
 * periodically as set in system_ops->ota_ops->ota_periodic_check_secs.
 */

#include "private-lib-core.h"

static const char * const ota_pub_jwk = LWS_OTA_PUBLIC_JWK;
/* This is a string that is unique to the build type / application... we use
 * it to make sure that we are updating to the same kind of build... */
const char *lws_ota_variant = LWS_OTA_VARIANT;

/*
 * Lifecycle
 *
 * An lws_ota_t lives for one check, and if it finds an update it likes, for
 * one download, flash and finalize.  Two things outside it must be put back
 * however it ends:
 *
 *  - the system state, once we started to negotiate MODAL_UPDATING, and the
 *    periodic check we suspend meanwhile (g->modal), and
 *
 *  - the platform OTA op, which holds g from a successful ota_start() until
 *    we have taken its ABORT or FINALIZE completion (g->plat_active).  Only
 *    one op may be in flight on the platform at a time.
 *
 * Every way of giving up goes through ota_give_up().  While the platform
 * holds g, it queues ABORT (when nothing else is in flight) and g must stay
 * alive until the ABORT completion: only then is the stream destroyed.  The
 * only destroy we can't defer is a forced one, eg the context going down; for
 * that, DESTROYING has the platform let go of g synchronously via
 * ota_detach().
 */

static void
ota_queue(lws_ota_t *g, lws_ota_async_t a)
{
	if (a == LWS_OTA_ASYNC_ABORT || a == LWS_OTA_ASYNC_FINALIZE)
		g->final_queued = 1;

	/* we use this to know an op is in flight, so don't rely on the
	 * platform to set it */
	*((volatile lws_ota_async_t *)&g->async_last) = a;
	g->cx->system_ops->ota_ops.ota_queue(g, a);
}

static void
ota_queue_abort_if_idle(lws_ota_t *g)
{
	if (!g->abort_wanted || g->final_queued ||
	    *((volatile lws_ota_async_t *)&g->async_last))
		/* not wanted, too late, or the completion of the op in flight
		 * will come back here */
		return;

	lwsl_ss_notice(g->ss, "aborting platform ota");
	ota_queue(g, LWS_OTA_ASYNC_ABORT);
}

/*
 * Put the system back how we found it, if we changed it: leave the update
 * mode, and resume the periodic checks.  Idempotent.
 */

static void
ota_release_system(lws_ota_t *g)
{
	struct lws_context *cx = g->cx;
	int secs = 0;

	if (!g->modal)
		return;

	g->modal = 0;

	if (cx->being_destroyed)
		/* nothing to come back to */
		return;

	if (cx->mgr_system.state == LWS_SYSTATE_AWAITING_MODAL_UPDATING ||
	    cx->mgr_system.state == LWS_SYSTATE_MODAL_UPDATING)
		lws_state_transition(&cx->mgr_system, LWS_SYSTATE_OPERATIONAL);

	/*
	 * Reaching OPERATIONAL schedules a check after a short jitter (see
	 * context.c), but we just did one: come back after the full period
	 */

	if (cx->system_ops && cx->system_ops->ota_ops.ota_periodic_check_secs)
		secs = cx->system_ops->ota_ops.ota_periodic_check_secs;

	lws_sul_schedule(cx, 0, &cx->sul_ota_periodic, lws_ota_periodic_cb,
			 secs ? secs * LWS_US_PER_SEC : 24 * 3600 * LWS_US_PER_SEC);
}

/*
 * Give up on this check or update, whatever stage it reached.
 *
 * Returns 0 if the platform no longer holds g, so it may be destroyed now, or
 * 1 if it does: then ABORT has been queued (or will be, when the op in flight
 * completes) and g must live until its completion, which finishes the job.
 */

static int
ota_give_up(lws_ota_t *g)
{
	g->state = LWSOS_FAILED;
	g->flow.state = LWSDLOFLOW_STATE_READ_FAILED;
	lws_sul_cancel(&g->sul_drain);

	if (g->plat_active) {
		g->abort_wanted = 1;
		ota_queue_abort_if_idle(g);

		return 1;
	}

	ota_release_system(g);

	return 0;
}

/*
 * For failures outside of a stream callback: give up, and destroy the stream
 * from its timeout as soon as the platform has let go of g
 */

static void
ota_fail(lws_ota_t *g)
{
	if (!ota_give_up(g))
		lws_ss_start_timeout(g->ss, 1);
}

static void
ota_write_sul_cb(lws_sorted_usec_list_t *sul)
{
	lws_ota_t *g = lws_container_of(sul, lws_ota_t, sul_drain);

	/* we use this to retry entering modal */

	if (g->state == LWSOS_AWAITING_MODAL) {
		const lws_ota_ops_t *ota_ops = &g->cx->system_ops->ota_ops;

		if (!g->modal) {
			/*
			 * From here, however we end, we must put the system
			 * state back, and resume the periodic checks that we
			 * don't want to create a dupe of ourselves meanwhile
			 */
			g->modal = 1;
			lws_sul_cancel(&g->cx->sul_ota_periodic);
		}

		/*
		 * Ask the user code to move to AWAITING_MODAL_UPDATING which it
		 * should agree to... and then MODAL_UPDATING whereit may choose
		 * to indicate it can't stop what it's doing right now.
		 */

		lws_state_transition(&g->cx->mgr_system,
				LWS_SYSTATE_AWAITING_MODAL_UPDATING);
		lws_state_transition(&g->cx->mgr_system,
				     LWS_SYSTATE_MODAL_UPDATING);

		if (g->cx->mgr_system.state != LWS_SYSTATE_MODAL_UPDATING) {

			/*
			 * Something decided we can't do the update right now, eg,
			 * he's busy rendering something that would exhause the heap
			 * if we also tried to get on with the update.
			 *
			 * Let's try again in 1s, up to a timeout.
			 */

			lwsl_ss_warn(g->ss, "Scheduling update mode retry");

			lws_sul_schedule(g->cx, 0, &g->sul_drain,
					 ota_write_sul_cb, LWS_US_PER_SEC);
			return;
		}

		/* we can go ahead now, the system is in the update mode */

		g->state = LWSOS_FETCHING;

		/* prep the gzip stream decompression */

		g->inflate = lws_upng_inflator_create(&g->outring,
					&g->outringlen, &g->opl, &g->cl);
		if (!g->inflate) {
			lwsl_err("%s: zlib init failed\n", __func__);
			goto update_impossible;
		}

		g->state = LWSOS_FETCHING_INITED_GZ;

		/* prep the hash computation of the decompressed data */

		if (lws_genhash_init(&g->ctx, LWS_GENHASH_TYPE_SHA512)) {
			lwsl_err("%s: hash init failed\n", __func__);
			goto update_impossible;
		}

		g->state = LWSOS_FETCHING_INITED_GZ_HASH;
		g->hash_inited = 1;

		lwsl_warn("%s: platform ota start\n", __func__);
		/* continues asynchronously */
		*((volatile lws_ota_async_t *)&g->async_last) =
							LWS_OTA_ASYNC_START;
		if (ota_ops->ota_start(g)) {
			/* the platform did not take g */
			*((volatile lws_ota_async_t *)&g->async_last) = 0;
			lwsl_err("%s: ota_start failed\n", __func__);
			goto update_impossible;
		}

		g->plat_active = 1;

		return;

update_impossible:
		ota_fail(g);

		return;
	}

	if (*((volatile lws_ota_async_t *)&g->async_last)) {
		/*
		 * The task is busy, we can't start anything atm.  When it
		 * is finished, the write completion will come back here.
		 */
		// lwsl_notice("%s: async_last busy\n", __func__);
		return;
	}

	/*
	 * We have a chance to write the next chunk... let's stage g->buf with
	 * as much inflated data as we can with what we have to hand, and set it
	 * writing
	 */

	g->buf_len = 0;
	while (g->buf_len < sizeof(g->buf) - 8 &&
	       g->seen + g->buf_len < g->expected_size) {
		lws_stateful_ret_t sr = 0;
		size_t os, part;

		/* inflator pauses for WANT_OUTPUT after this many bytes out */
		g->inflate->bypl = sizeof(g->buf) - g->buf_len - 1;

		if (*g->opl == *g->cl) {

			/* No output pending.. do we have unused input left? */

			if (g->flow.len) {

				/*
				 * There's some input already available,
				 * let's process that and see if it helped
				 */

				sr = lws_upng_inflate_data(g->inflate, NULL, 0);
				if (sr & LWS_SRET_FATAL) {
					lwsl_ss_err(g->ss, "inflate error 1");

					goto fail;
				}
				g->flow.len = g->inflate->inlen - (g->inflate->bp >> 3);
			}

			if (*g->opl == *g->cl) {

				/*
				 * Still no output available... let's
				 * attempt to move to the next
				 */

				lws_flow_req(&g->flow);
				if (!g->flow.len)
					break;

				sr = lws_upng_inflate_data(g->inflate,
						g->flow.data, g->flow.len);

				g->flow.len = g->inflate->inlen -
						(g->inflate->bp >> 3);
			}
		} /* there is already output pending */

		if (sr & LWS_SRET_FATAL) {
			lwsl_ss_err(g->ss, "inflate error %d", sr & 0xff);

			goto fail;
		}

		os = ((*g->opl - g->old_op) % g->outringlen);
		if (os > sizeof(g->buf) - g->buf_len)
			os = sizeof(g->buf) - g->buf_len;

		if (!os) {
			lwsl_err("%s: Nothing to compose in\n", __func__);
			break;
		}

		part = os;
		if (*g->opl % g->outringlen < g->old_op)
			part = g->outringlen - g->old_op;

		memcpy(g->buf + g->buf_len, g->outring + g->old_op, part);
		g->buf_len += part;
		if (part != os) {
			memcpy(g->buf + g->buf_len, g->outring, os - part);
			g->buf_len += os - part;
		}

		g->old_op = *g->opl % g->outringlen;
		*g->cl += os;

	} /* while try to fill the staging buffer */

	if (!g->buf_len) {
		if (g->net_done && g->seen < g->expected_size) {
			/*
			 * The image connection is gone and everything it
			 * brought is used up: the rest is never coming
			 */
			lwsl_ss_err(g->ss, "image ended short, %llu / %llu",
				    (unsigned long long)g->seen,
				    (unsigned long long)g->expected_size);

			goto fail;
		}

		/* no ammo to work with... we will come back next time we
		 * get some rx */
		return;
	}

	g->seen += g->buf_len;
	if (g->seen > g->expected_size) {
		lwsl_ss_err(g->ss, "oversize payload");

		goto fail;
	}

	/* let's track the hash as we get it */

	if (lws_genhash_update(&g->ctx, g->buf, g->buf_len)) {
		lwsl_ss_err(g->ss, "hash update failed");

		goto fail;
	}

	if (g->seen == g->expected_size) {
		char temp[64];

		lws_upng_inflator_destroy(&g->inflate);
		lws_genhash_destroy(&g->ctx, temp);
		g->hash_inited = 0;

		if (memcmp(temp, g->sha512, sizeof(temp))) {
			lwsl_err("%s: payload hash differs\n", __func__);

			goto fail;
		}
	}

	/*
	 * Never hand image data to the platform writer unless the platform
	 * actually acknowledged ota_start() (eg, it may have declined for want
	 * of a free partition)
	 */

	if (!g->ota_start_done) {
		lwsl_ss_err(g->ss, "write without successful ota_start");

		goto fail;
	}

	ota_queue(g, LWS_OTA_ASYNC_WRITE);

	return;

fail:
	ota_fail(g);
}

static void
ota_completion_start(lws_ota_t *g)
{
	if (g->async_r != LWSOTARET_OK) {
		lwsl_ss_err(g->ss, "OTA START FAILED r %d", g->async_r);
		ota_fail(g);

		return;
	}

	/* we can start writing now */
	g->ota_start_done = 1;
	g->state = LWSOS_STARTED;

	if (lws_ss_client_connect(lws_ss_from_user(g))) {
		lwsl_ss_warn(g->ss, "image connect failed");
		ota_fail(g);

		return;
	}

	lws_sul_schedule(g->cx, 0, &g->sul_drain, ota_write_sul_cb, 1);
}

static void
ota_completion_write(lws_ota_t *g)
{
	const lws_ota_ops_t *ota_ops = &g->cx->system_ops->ota_ops;
	uint8_t pc;

	if (g->async_r != LWSOTARET_OK) {
		lwsl_ss_err(g->ss, "r %d", g->async_r);
		ota_fail(g);

		return;
	}

	g->written += g->buf_len;

	pc = (uint8_t)((g->written * 100) / g->expected_size);
	if (pc != g->last_pc) {
		g->last_pc = pc;
		lwsl_notice("%s: %u%%\n", __func__, pc);
		if (ota_ops->ota_progress)
			g->cx->system_ops->ota_ops.ota_progress(LWSOTARET_PROGRESS, pc);
	}

	if (g->written != g->expected_size) {
		lws_sul_schedule(g->cx, 0, &g->sul_drain, ota_write_sul_cb, 1);

		return;
	}

	/* We have completed writing the last part */

	lwsl_warn("%s: finalizing good ota\n", __func__);
	g->state = LWSOS_FINALIZING;

	ota_queue(g, LWS_OTA_ASYNC_FINALIZE);
}

static void
ota_completion_finalize(lws_ota_t *g)
{
	lwsl_notice("%s: %d\n", __func__, g->async_r);

	if (g->async_r) {
		ota_fail(g);

		return;
	}

	/*
	 * If we are still around after a while, the reboot didn't happen:
	 * the timeout puts the system back and destroys us then
	 */
	g->state = LWSOS_REPORTED;
	lws_ss_start_timeout(g->ss, 5000);

	if (g->cx->system_ops->reboot)
		g->cx->system_ops->reboot();
}


static lws_ss_state_return_t
ota_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	lws_ss_state_return_t r = LWSSSSRET_DISCONNECT_ME;
	lws_ota_t *g = (lws_ota_t *)userobj;
	const lws_ota_ops_t *ota_ops = &lws_ss_cx_from_user(g)->system_ops->ota_ops;
	struct lws_jws_map map;
	struct lws_jwk jwk;
	uint64_t fw_last;
	char *temp = NULL;
	int temp_len;
	const char *p;
	size_t alen;
	int n;

	/*
	 * LWSOS_FAILED sorts above LWSOS_FETCHING in lws_ota_state_t, so it
	 * must be excluded explicitly here: otherwise rx arriving after we
	 * gave up (eg, in the ~1ms before the abort timeout fires) is treated
	 * as an in-progress download and resets the state to LWSOS_WRITING,
	 * resuming with a NULL inflator or an uninitialized hash context.
	 */

	if (g->state == LWSOS_FAILED)
		/* we gave up, nothing more is wanted from this connection */
		return LWSSSSRET_DISCONNECT_ME;

	if (g->state >= LWSOS_FETCHING) {

		lwsl_info("%s: fetching %u, fl 0x%02X\n", __func__, (unsigned int)len, flags);

		/*
		 * We are decompressing, checking and flashing the image.
		 *
		 * g->flow and its buflist is managing COMPRESSED data from the
		 * network according to g->flow.window limit.  Rx events are
		 * tiggered by tx credit manipulation from, and coming to
		 * service g->flow / buflist state ONLY and do not know or care
		 * about direct inflator state (it makes itself felt by using
		 * g->flow data in the write completion).
		 *
		 * The inflator may not need any g->flow data to produce output,
		 * or it may need all of it and more before it can produce
		 * output, or somewhere in the middle.  At the output side, we
		 * have a fixed-size staging buffer so we may need to come back
		 * to issue more inflated data without any network event
		 * triggering it.
		 */

		if (flags & LWSSS_FLAG_SOM) {
			if (g->state == LWSOS_WRITING) {
				/*
				 * The image started again from the beginning
				 * (eg, a retry): it can't be spliced onto
				 * what we already decompressed and flashed
				 */
				lwsl_ss_err(g->ss, "image restarted");

				goto fetch_fail;
			}
			g->state = LWSOS_WRITING;
			g->flow.state = LWSDLOFLOW_STATE_READ;
			g->flow.h = g->ss;
			g->flow.window = 4096;
			if (ota_ops->ota_progress)
				ota_ops->ota_progress(LWSOTARET_PROGRESS, 0);
		}

		if (len &&
		    lws_buflist_append_segment(&g->flow.bl, in, len) < 0) {
			lwsl_ss_err(g->ss, "OOM");

			goto fetch_fail;
		}

		lws_sul_schedule(g->cx, 0, &g->sul_drain, ota_write_sul_cb, 1);

		if (flags & LWSSS_FLAG_EOM)
			/*
			 * This was the last part, so there is no more new data
			 * in flight
			 */
			g->flow.state = (uint8_t)LWSDLOFLOW_STATE_READ_COMPLETED;

		return LWSSSSRET_OK;

fetch_fail:
		ota_fail(g);

		return LWSSSSRET_DISCONNECT_ME;
	}

	/* we are collecting the manifest... */

	if (g->pos + len > sizeof(g->buf))
		return LWSSSSRET_DISCONNECT_ME;

	if (len) /* the EOM may come alone, with in NULL */
		memcpy(g->buf + g->pos, in, len);
	g->pos += len;

	if ((flags & LWSSS_FLAG_EOM) != LWSSS_FLAG_EOM)
		return LWSSSSRET_OK;

	/*
	 * We want to validate the JWS manifest against our public JWK.
	 *
	 * The decoded manifest blocks go in temp, which map points into until
	 * we are done with the manifest.  The b64 decoder emits 3 bytes per 4
	 * chars, but wants 3 bytes free before the last, possibly partial,
	 * group of at least 2 chars, and a byte spare at the end.  It's sized
	 * for this manifest on the heap, since small targets' stacks are
	 * already busy with the signature check.
	 */

	temp_len = (int)((3 * (g->pos + 2)) / 4) + 1;
	temp = lws_malloc((size_t)temp_len, __func__);
	if (!temp)
		return LWSSSSRET_DISCONNECT_ME;

	if (lws_jwk_import(&jwk, NULL, NULL, ota_pub_jwk, strlen(ota_pub_jwk))) {
		lwsl_err("%s: unable to import jwk\n", __func__);
		goto bail1;
	}

	/* Step 1... is the JWS signed by the required key? */

	if (lws_jws_sig_confirm_compact_b64(g->buf, g->pos, &map, &jwk,
					    lws_ss_cx_from_user(g), temp,
					    &temp_len)) {
		lwsl_err("%s: manifest failed sig check\n", __func__);
		goto bail;
	}

	/* finished with the jwk */
	lws_jwk_destroy(&jwk);

	/* Step 2... the JOSE and payload sections are there, right? */

	if (!map.buf[LJWS_JOSE] || !map.buf[LJWS_PYLD]) {
		lwsl_err("%s: no JOSE block\n", __func__);
		goto bail1;
	}

	/* Step 3... do we agree the signing alg is secure enough? */

	p = lws_json_simple_find(map.buf[LJWS_JOSE], map.len[LJWS_JOSE],
				 "\"alg\":", &alen);
	if (!p) {
		lwsl_err("%s: no alg\n", __func__);
		goto bail1;
	}

	/*
	 * Compare the whole value, not just the manifest's alen bytes of it:
	 * a length-blind strncmp() accepts any strict prefix of the string we
	 * are checking against.
	 */
	if (alen != strlen("ES512") || memcmp("ES512", p, alen)) {
		lwsl_err("%s: bad alg %.*s %d\n", __func__, (int)alen, p, (int)alen);
		goto bail1;
	}

	/*
	 * We trust that the manifest was robustly signed by the key we like,
	 * let's parse out the pieces we care about and validate the firmware is
	 * the same variant build as we're currently running, and, eg, we're not
	 * being given a validly-signed real firmware from the wrong variant,
	 * that will brick us.
	 */

	lwsl_hexdump_notice(map.buf[LJWS_PYLD], map.len[LJWS_PYLD]);

	lwsl_notice("%s: JWS validated okay\n", __func__);

	p = lws_json_simple_find(map.buf[LJWS_PYLD], map.len[LJWS_PYLD],
					 "\"variant\":", &alen);
	if (!p) {
		lwsl_err("%s: no variant\n", __func__);
		goto bail1;
	}

	/*
	 * This is the anti-brick gate: a manifest that is validly signed but
	 * for a different product variant must be refused.  It has to be an
	 * exact match, since a strncmp() limited to the manifest's length
	 * would accept any variant name that is a strict prefix of ours
	 * ("myproduct" for a "myproduct2" build).
	 */
	if (alen != strlen(lws_ota_variant) ||
	    memcmp(lws_ota_variant, p, alen)) {
		lwsl_err("%s: wrong variant %.*s\n", __func__, (int)alen, p);
		goto bail1;
	}

	/*
	 * We liked the manifest, prepare to go again targeting the payload
	 * that the manifest described to us.
	 */

	p = lws_json_simple_find(map.buf[LJWS_PYLD], map.len[LJWS_PYLD],
					 "\"path\":", &alen);
	if (!p) {
		lwsl_err("%s: no path\n", __func__);
		goto bail1;
	}

	/*
	 * lws_strnncpy() truncates to fit g->file, but the metadata below
	 * is described by alen, so alen must fit too: refuse a path that
	 * would not fit rather than describe bytes g->file does not hold.
	 */
	if (alen >= sizeof(g->file)) {
		lwsl_err("%s: path too long (%u)\n", __func__,
			 (unsigned int)alen);
		goto bail1;
	}

	lws_strnncpy(g->file, p, alen, sizeof(g->file));
	if (lws_ss_set_metadata(lws_ss_from_user(g), "file", g->file, alen)) {
		lwsl_err("%s: failed to set firmware file %s\n", __func__,
				LWS_OTA_VARIANT);
		goto bail1;
	}

	p = lws_json_simple_find(map.buf[LJWS_PYLD], map.len[LJWS_PYLD],
					 "\"size\":", &alen);
	if (!p) {
		lwsl_err("%s: no size\n", __func__);
		goto bail1;
	}
	g->expected_size = (size_t)atoll(p);

	p = lws_json_simple_find(map.buf[LJWS_PYLD], map.len[LJWS_PYLD],
					 "\"unixtime\":", &alen);
	if (!p) {
		lwsl_err("%s: no unxitime\n", __func__);
		goto bail1;
	}
	g->unixtime = (uint64_t)atoll(p);

	p = lws_json_simple_find(map.buf[LJWS_PYLD], map.len[LJWS_PYLD],
					 "\"sha512\":", &alen);
	if (!p) {
		lwsl_err("%s: no hash\n", __func__);
		goto bail1;
	}
	n = lws_hex_len_to_byte_array(p, alen, g->sha512, sizeof(g->sha512));
	if (n != sizeof(g->sha512)) {
		lwsl_err("%s: bad hash %d %u %s\n", __func__, n, (unsigned int)alen, p);
		goto bail1;
	}

	/*
	 * So... is it newer?
	 */

	if (!ota_ops->ota_get_last_fw_unixtime(&fw_last) &&
	    g->unixtime <= fw_last) {

		/*
		 * We don't actually want this...
		 */

		lwsl_ss_warn(g->ss, "Latest update is not newer");

		goto bail1;
	}

	/* ... this is something that we like the look of... schedule trying
	 * to enter LWS_SYSTATE_MODAL_UPDATING state after this, and retry if
	 * we don't get there immediately */

	g->state = LWSOS_AWAITING_MODAL;
	lws_sul_schedule(g->cx, 0, &g->sul_drain, ota_write_sul_cb, 1);
	/* on the other hand, don't let it keep trying forever */
	lws_ss_start_timeout(g->ss, 30000);

	/*
	 * We will DISCONNECT shortly, we won't proceed to the update image
	 * download unless we can agree with the user code to enter MODAL_
	 * UPDATING within a timeout.  Otherwise we will give up and retry
	 * after 24h or whatever.
	 */

	r = LWSSSSRET_OK;
	goto bail1;

bail:
	lws_jwk_destroy(&jwk);

bail1:
	lws_free(temp);

	return r;
}

static lws_ss_state_return_t
ota_state(void *userobj, void *h_src, lws_ss_constate_t state,
		  lws_ss_tx_ordinal_t ack)
{
	lws_ota_t *g = (lws_ota_t *)userobj;
	int n;

	switch ((int)state) {
	case LWSSSCS_CREATING: /* start the transaction as soon as we exist */

		g->cx = lws_ss_cx_from_user(g);
		g->cx->ota_ss = g->ss;
		g->state = LWSOS_CHECKING;

		if (lws_ss_set_metadata(lws_ss_from_user(g),
					"ota_variant", LWS_OTA_VARIANT,
					strlen(LWS_OTA_VARIANT))) {
			lwsl_err("%s: failed to set ota_variant %s\n", __func__,
					LWS_OTA_VARIANT);
			return LWSSSSRET_DISCONNECT_ME;
		}

		if (lws_ss_set_metadata(lws_ss_from_user(g),
					"file", "manifest.jws", 12)) {
			lwsl_err("%s: failed to set ota_variant %s\n", __func__,
					LWS_OTA_VARIANT);
			return LWSSSSRET_DISCONNECT_ME;
		}

		return lws_ss_client_connect(lws_ss_from_user(g));

	case LWSSSCS_DISCONNECTED:

		/*
		 * We have two kinds of connection that may disconnect, the
		 * manifest fetch, and the firmware fetch.
		 */

		switch (g->state) {
		case LWSOS_FETCHING_INITED_GZ_HASH:
		case LWSOS_FETCHING:
			return LWSSSSRET_OK;

		case LWSOS_WRITING:
			/*
			 * The network part of fetching the update image is
			 * over.  We need to stick around and let it either
			 * finish writing and finalizing, or, if the transfer
			 * was cut short, find that it has run out of data and
			 * give up.  The drain may be stalled waiting for rx
			 * that won't come now, so kick it.
			 */
			lwsl_notice("%s: draining\n", __func__);

			g->net_done = 1;
			lws_ss_start_timeout(g->ss, 45000);
			lws_sul_schedule(g->cx, 0, &g->sul_drain,
					 ota_write_sul_cb, 1);

			return LWSSSSRET_OK;

		case LWSOS_FINALIZING:
		case LWSOS_REPORTED:
			/*
			 * We have the whole image already, the FINALIZE
			 * completion, or the timeout after it, ends us
			 */
			return LWSSSSRET_OK;

		case LWSOS_AWAITING_MODAL:
			/*
			 * We might have to wait a bit to find a good moment to
			 * enter the update mode.  If we disconnect
			 * inbetweentimes, it's OK.
			 */
			return LWSSSSRET_OK;

		default:
			if (ota_give_up(g))
				/* the ABORT completion destroys us */
				return LWSSSSRET_OK;

			lwsl_notice("%s: state %d, DESTROYING\n", __func__, g->state);

			return LWSSSSRET_DESTROY_ME;
		}

	case LWSSSCS_DESTROYING:

		/* we only live for one ota check / fetch */
		lws_ss_cx_from_user(g)->ota_ss = NULL;
		lws_sul_cancel(&g->sul_drain);

		if (g->plat_active) {
			const lws_ota_ops_t *ota_ops =
				&lws_ss_cx_from_user(g)->system_ops->ota_ops;

			/*
			 * We are being destroyed from outside (eg, the context
			 * is going down) while the platform still holds g, and
			 * maybe is using g->buf right now.  It must let go of
			 * g before we return and it is freed.
			 */

			lwsl_ss_warn(g->ss, "destroyed while platform active");

			if (ota_ops->ota_detach)
				ota_ops->ota_detach(g);
			else {
				lwsl_ss_err(g->ss, "platform has no ota_detach");
				/* the best we can do for a synchronous one */
				g->abort_wanted = 1;
				ota_queue_abort_if_idle(g);
			}
			g->plat_active = 0;
		}

		ota_release_system(g);
		lws_buflist_destroy_all_segments(&g->flow.bl);

		/*
		 * Free whatever we still own, judged by ownership rather than
		 * by g->state: the update_impossible path sets LWSOS_FAILED,
		 * which sorts after LWSOS_FINALIZING, and the normal
		 * completion path destroys both while still in the fetching
		 * states, so state-range gates both leak and double-free.
		 */
		if (g->hash_inited) {
			lws_genhash_destroy(&g->ctx, NULL);
			g->hash_inited = 0;
		}
		if (g->inflate)
			lws_upng_inflator_destroy(&g->inflate);

		return LWSSSSRET_OK;

	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_TIMEOUT:
		/*
		 * This is also how we destroy ourselves after giving up
		 * elsewhere, once the platform let go of g
		 */
		lwsl_ss_notice(g->ss, "%s, state %d", lws_ss_state_name(state),
			       g->state);

		if (ota_give_up(g))
			/* the ABORT completion destroys us */
			return LWSSSSRET_OK;

		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_EVENT_WAIT_CANCELLED:
		/* We may have a completion */
		if (g->async_completed) {
			g->async_completed = 0;
			n = g->async_last;
			*((volatile lws_ota_async_t *)&g->async_last) = 0;

			/* EVENT_WAIT_CANCELLED doesn't deal with returns */

			switch (n) {
			case LWS_OTA_ASYNC_START:
			case LWS_OTA_ASYNC_WRITE:
				if (g->abort_wanted) {
					/* we gave up while it was in flight */
					ota_queue_abort_if_idle(g);
					break;
				}
				if (n == LWS_OTA_ASYNC_START)
					ota_completion_start(g);
				else
					ota_completion_write(g);
				break;

			case LWS_OTA_ASYNC_ABORT:
				/* the platform let go of g, we've had it */
				g->plat_active = 0;
				ota_fail(g);
				break;

			case LWS_OTA_ASYNC_FINALIZE:
				/* the platform let go of g */
				g->plat_active = 0;
				ota_completion_finalize(g);
				break;
			}
		}
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("ota", lws_ota_t)
	.rx				= ota_rx,
	.state				= ota_state,
	.manual_initial_tx_credit	= sizeof(((lws_ota_t *)NULL)->buf),
};

/*
 * Creates the SS and kicks off the manifest check
 */

void
lws_ota_periodic_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context *cx = lws_container_of(sul, struct lws_context,
						  sul_ota_periodic);
	int secs = 0;

	if (cx->system_ops && cx->system_ops->ota_ops.ota_periodic_check_secs)
		secs = cx->system_ops->ota_ops.ota_periodic_check_secs;

	lwsl_notice("%s\n", __func__);

	if (cx->ota_ss)
		/* the last one is still finishing up */
		lwsl_cx_notice(cx, "previous ota check still active");
	else
		if (lws_ss_create(cx, 0, &ssi_lws_ota_t, NULL, NULL, NULL, NULL))
			lwsl_cx_warn(cx, "failed to create ota SS");

	/* set up coming back again at (usually long) periods */

	lws_sul_schedule(cx, 0, sul, lws_ota_periodic_cb,
			 secs ? secs * LWS_US_PER_SEC : 24 * 3600 * LWS_US_PER_SEC);
}

const char *
lws_ota_variant_name(void)
{
	return lws_ota_variant;
}
