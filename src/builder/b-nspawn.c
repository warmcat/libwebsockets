/*
 * sai-builder
 *
 * Copyright (C) 2019 - 2025 Andy Green <andy@warmcat.com>
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
 * Generic unix spawn and stdxxx pipe to wsi mapping
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#if !defined(WIN32)
#include <unistd.h>
#else
#include <process.h>
#endif
#include <fcntl.h>
#include <assert.h>

#include "b-private.h"

extern struct lws_vhost *builder_vhost;

/*
 * Build and queue one log chunk.  \p task_uuid identifies the task it belongs
 * to; \p ns may be NULL, in which case there is no retcode to attach and no
 * spew accounting to do.
 */

static int
saib_log_chunk(struct sai_plat_server *spm, struct sai_nspawn *ns,
	       const char *task_uuid, const void *buf, size_t len, int channel)
{
	char lj[2600 + LWS_PRE];
	lws_usec_t us;
	int n = 0;

	if (!spm || !task_uuid || !task_uuid[0])
		return 1;

	/*
	 * The web pages a task's logs 50 rows at a time with a strictly
	 * greater-than timestamp cursor, so chunks sharing the timestamp of
	 * the last row on a page are never delivered.  On Windows the clock
	 * ticks at a millisecond or coarser, so a burst of chunks readily
	 * shares one: issue strictly increasing timestamps.  The latch is
	 * builder-wide rather than per-nspawn, since a task's steps are each
	 * their own nspawn and must not reissue timestamps an earlier step
	 * already used.
	 */
	us = lws_now_usecs();
	if (us <= builder.last_log_us)
		us = builder.last_log_us + 1;
	builder.last_log_us = us;

	n = lws_snprintf(lj + LWS_PRE, sizeof(lj) - LWS_PRE,
		"{\"schema\":\"com-warmcat-sai-logs\","
		 "\"task_uuid\":\"%s\", \"timestamp\": %llu,"
		 "\"channel\": %d, \"len\": %d, ",
		 task_uuid, (unsigned long long)us,
		 channel, (int)len);

	if (ns && ns->retcode_set) {
		n += lws_snprintf(lj + LWS_PRE + n,
				  sizeof(lj) - LWS_PRE - (unsigned int)n,
				  "\"finished\":%d,", ns->retcode);
		n += lws_snprintf(lj + LWS_PRE + n,
				  sizeof(lj) - LWS_PRE - (unsigned int)n,
			"\"avail_mem_kib\":%u,\"avail_sto_kib\":%u,",
			saib_get_free_ram_kib(),
			saib_get_free_disk_kib(builder.home));
		ns->retcode_set = 0;
	}

	n += lws_snprintf(lj + LWS_PRE + n,
			  sizeof(lj) - LWS_PRE - (unsigned int)n,
			  "\"log\":\"");

	n += lws_b64_encode_string(buf, (int)len, (char *)&lj[LWS_PRE + n],
				   (int)sizeof(lj) - LWS_PRE - n - 5);

	lj[LWS_PRE + n++] = '"';
	lj[LWS_PRE + n++] = '}';
	lj[LWS_PRE + n] = '\0';

	return saib_srv_queue_tx(spm->ss, lj + LWS_PRE, (size_t)n,
				 LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
}

int
saib_log_chunk_create_uuid(struct sai_plat_server *spm, const char *task_uuid,
			   const void *buf, size_t len, int channel)
{
	return saib_log_chunk(spm, NULL, task_uuid, buf, len, channel);
}

int
saib_log_chunk_create(struct sai_nspawn *ns, void *buf, size_t len, int channel)
{
	if (!ns || !ns->spm)
		return 1;

	if (!ns->task)
		return 0;

	{
		unsigned int limit = ns->task->task_log_limit ? ns->task->task_log_limit : 30000;

		ns->log_count++;

		if (ns->log_count > limit) {
			if (!ns->killed_for_spew) {
				const char *msg = ">saib> <=== Killed by Sai due to log spew limit exceeded\n";

				ns->killed_for_spew = 1;

				/*
				 * Say so directly rather than recursively:
				 * re-entering here would find the limit
				 * already exceeded and silently drop the one
				 * message that explains the kill.
				 */
				saib_log_chunk(ns->spm, ns, ns->task->uuid,
					       msg, strlen(msg), 3);

				if (ns->op && ns->op->lsp)
					lws_spawn_piped_kill_child_process(ns->op->lsp);
			}
			return 0;
		}
	}

	return saib_log_chunk(ns->spm, ns, ns->task->uuid, buf, len, channel);
}

/*
 * Report a builder-side problem with a task in the task's own log, as well as
 * in our local log.  The builders are often transient VMs whose local logs are
 * gone by the time anybody looks, so anything that decides a task's fate has to
 * say why in the stream that goes to the server.
 */

int
saib_task_logf(struct sai_plat_server *spm, struct sai_nspawn *ns,
	       const char *task_uuid, const char *fmt, ...)
{
	char s[512];
	va_list ap;
	int n;

	n = lws_snprintf(s, sizeof(s), ">saib> ");

	va_start(ap, fmt);
	n += vsnprintf(s + n, sizeof(s) - (unsigned int)n - 2, fmt, ap);
	va_end(ap);

	if (n > (int)sizeof(s) - 2)
		n = (int)sizeof(s) - 2;
	s[n++] = '\n';
	s[n] = '\0';

	lwsl_warn("%s", s);

	if (ns)
		return saib_log_chunk_create(ns, s, (size_t)n, 3);

	return saib_log_chunk_create_uuid(spm, task_uuid, s, (size_t)n, 3);
}

/*
 * One piece of the child's stdout / stderr: at most sizeof(buf) - 1 bytes
 * of what the callback below has, so that the base64 log chunk it becomes
 * still fits saib_log_chunk_create()'s buffer.
 */
static int
saib_stdwsi_rx_piece(struct lws *wsi, struct saib_opaque_spawn *op,
		     uint8_t *buf, size_t len)
{
	buf[len] = '\0';

	if (!op || !op->ns || !op->ns->spm) {
		lwsl_notice("%s: (%d) [orphaned] %s\n", __func__,
		       (int)lws_spawn_get_stdfd(wsi), (const char *)buf);
		return 0;
	}

	{
		int ch = lws_spawn_get_stdfd(wsi);
		if (ch == 0)
			ch = 1;
			
		if (ch < 3)
			op->ns->stdwsi[ch] = wsi;

		if (saib_log_chunk_create(op->ns, buf, len, ch)) {
			lwsl_user("%s: saib_log_chunk_create failed (ch %d, len %d)\n", __func__, ch, (int)len);
			return -1;
		}

		if (lws_buflist2_total_len(&op->ns->spm->bl_to_srv) > (LWS_BUFLIST_OOM_LIMIT - (256 * 1024))) {
			/* buflist is getting full, backpressure ALL active stdwsi for this connection */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, builder.sai_plat_owner.head) {
				sai_plat_t *sp = lws_container_of(d, sai_plat_t, sai_plat_list);
				lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, sp->nspawn_owner.head) {
					struct sai_nspawn *ns = lws_container_of(d2, struct sai_nspawn, list);
					if (ns->spm == op->ns->spm) {
						for (int i = 0; i < 3; i++) {
							if (!ns->stdwsi_paused[i] && ns->stdwsi[i]) {
								ns->stdwsi_paused[i] = 1;
								lws_rx_flow_control(ns->stdwsi[i], 0); /* 0 disables RX */
								lwsl_notice("%s: Backpressure applied to ch %d (tot %zu)\n",
									__func__, i, lws_buflist2_total_len(&op->ns->spm->bl_to_srv));
							}
						}
					}
				} lws_end_foreach_dll_safe(d2, d3);
			} lws_end_foreach_dll_safe(d, d1);
		}
	}


	return lws_ss_request_tx(op->ns->spm->ss) ? -1 : 0;
}

static int
callback_sai_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct saib_opaque_spawn *op =
		(struct saib_opaque_spawn *)lws_get_opaque_user_data(wsi);
	struct sai_nspawn *ns = op ? op->ns : NULL;
	uint8_t buf[600];
	int ilen;

	switch (reason) {

#if defined(WIN32)
	case LWS_CALLBACK_RAW_ADOPT_FILE:
		break;
#endif

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		{
			int ch = lws_spawn_get_stdfd(wsi);
			if (ch == 0) ch = 1;
			if (op && op->ns && ch < 3)
				op->ns->stdwsi[ch] = NULL;
		}
		if (op && op->lsp) {
			/*
			 * ns is op->ns, which saib_sub_cleaner_cb() clears
			 * when it gives up on a child that refused to die, so
			 * it can legitimately be NULL here
			 */
			if (lws_spawn_stdwsi_closed(op->lsp, wsi) &&
			    ns && ns->reap_cb_called) {
				lwsl_notice("%s: freeing op from stdwsi_cb\n", __func__);
				free(op);
			}
			if (ns)
				lws_cancel_service(ns->builder->context);
		}
		break;

	case LWS_CALLBACK_RAW_RX_FILE:
#if defined(WIN32)
		/*
		 * lws spawn reads the pipe itself on windows, up to 4KB at a
		 * time, and delivers the data in in / len; the wsi has no
		 * readable fd for us.  Walk the whole delivery in the same
		 * sized pieces the read() below produces: keeping only the
		 * first piece used to lose the rest of every larger read.
		 */
		while (len) {
			ilen = (int)len;
			if (ilen > (int)sizeof(buf) - 1)
				ilen = (int)sizeof(buf) - 1;
			memcpy(buf, in, (size_t)ilen);
			in = (uint8_t *)in + ilen;
			len -= (size_t)ilen;

			if (saib_stdwsi_rx_piece(wsi, op, buf, (size_t)ilen))
				return -1;
		}
		break;
#else
		ilen = (int)read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
		if (ilen < 1) {
			lwsl_debug("%s: read on stdwsi failed\n", __func__);
			return -1;
		}

		return saib_stdwsi_rx_piece(wsi, op, buf, (size_t)ilen);
#endif

	default:
		break;
	}

	return 0;
}

struct lws_protocols protocol_stdxxx = {
	.name			= "sai-stdxxx",
	.callback		= callback_sai_stdwsi,
	.per_session_data_size	= 0,
	.rx_buffer_size		= 0,
};

/*
 * We are called when the process completed and has been reaped at
 * lsp level, and we know that all the stdwsi related to the process
 * are closed.
 */

static void
sai_lsp_reap_cb(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
		int we_killed_him)
{
	struct saib_opaque_spawn *op = (struct saib_opaque_spawn *)opaque;
	struct sai_nspawn *ns = op ? op->ns : NULL;
	uint64_t us_wallclock = op ? (uint64_t)(lws_now_usecs() - op->start_time) : 0;
	char h5[40], h6[40], h7[40], h8[40], h9[40];
	sai_build_metric_t m;
	int exit_code = -1;
	char s[256];
	int n;

	if (!ns) {
		if (op) {
			lwsl_warn("%s: op %p has no ns (orphaned), freeing op\n", __func__, op);
			if (op->spawn)
				free(op->spawn);
			free(op);
		}
		return;
	}

	saib_log_chunk_create(ns, ">saib> <=== Reaping build process\n", 34, 3);

	if (ns->user_killed) {
		lwsl_notice("%s: Process killed manually by user\n", __func__);
		exit_code = -1;
		ns->retcode = SAISPRF_EXIT | 1;
		ns->retcode_set = 1;
		goto fail;
	}

	if (ns->idle_yield) {
		/* we stopped this idle task to make way for real work */
		saib_task_logf(ns->spm, ns, NULL,
			       "Idle task stopped to make way for real work");
		exit_code = -1;
		ns->retcode = SAISPRF_TERMINATED;
		ns->retcode_set = 1;
		goto fail;
	}

#if !defined(WIN32)

	if ((we_killed_him & 1) && ns->task->idle) {
		/*
		 * An idle task that ran over its slice: it's not a failure,
		 * the slice is just over
		 */
		saib_task_logf(ns->spm, ns, NULL,
			       "Idle task step ran past its %us slice, stopping it",
			       ns->sp->idle_slice_secs);
		ns->idle_yield = 1;
		exit_code = -1;
		ns->retcode = SAISPRF_TERMINATED;
		ns->retcode_set = 1;
		goto fail;
	}

	if (we_killed_him & 1) {
		lwsl_notice("%s: Process TIMED OUT by Sai\n", __func__);
		exit_code = -1;
		ns->retcode = SAISPRF_TIMEDOUT;
		ns->retcode_set = 1;
		goto fail;
	}

	if ((we_killed_him & 2) || ns->killed_for_spew) {
		lwsl_notice("%s: Process killed by Sai due to spew\n", __func__);
		exit_code = -1;
		ns->retcode = SAISPRF_TERMINATED;
		ns->retcode_set = 1;
		goto fail;
	}

	/*
	 * lws reports the disposition as CLD_EXITED + si_status for a clean
	 * exit, and si_code 0 for anything else, with si_status carrying
	 * 128 + signal the way a shell does (or -1 if the child was reaped
	 * elsewhere and we never learned).  si_signo is not filled in, so the
	 * signal has to come out of si_status.
	 *
	 * Every branch must set retcode / retcode_set: leaving them alone
	 * reports ecode 0 to the server, which it reads as a failure with no
	 * explanation anywhere.
	 */

	if (si->si_code == CLD_EXITED) {
		lwsl_notice("%s: Process Exited with exit code %d\n",
			    __func__, si->si_status);
		exit_code = si->si_status;
		ns->retcode_set = 1;
		ns->retcode = SAISPRF_EXIT | si->si_status;
		if (ns->user_cancel)
			ns->retcode = SAISPRF_TERMINATED;
	} else {
		int sig = si->si_status > 128 ? si->si_status - 128 : 0;

		exit_code = -1;

		if (sig) {
			saib_task_logf(ns->spm, ns, NULL,
				       "Build process terminated by signal %d",
				       sig);
			ns->retcode = SAISPRF_SIGNALLED | sig;
		} else {
			/*
			 * We know he's gone but not how... don't let it look
			 * like a clean exit
			 */
			saib_task_logf(ns->spm, ns, NULL,
				       "Build process disappeared without a "
				       "usable exit status (si_code %d, "
				       "si_status %d)", si->si_code,
				       si->si_status);
			ns->retcode = SAISPRF_TERMINATED;
		}

		ns->retcode_set = 1;
	}
#else
	exit_code = si->retcode & 0xff;
	ns->retcode = SAISPRF_EXIT | exit_code;
	ns->retcode_set = 1;
#endif

	if (exit_code)
		goto fail;

	/* step succeeded */

	lws_dir_du_t du;
	uint64_t peak_mem_bytes;

	memset(&du, 0, sizeof(du));
	lws_dir(ns->inp, &du, lws_dir_du_cb);

	peak_mem_bytes = res->peak_mem_rss;
#if defined(__APPLE__)
	/*
	 * lws seems to be multiplying OSX ru_maxrss by 1024 when it's already
	 * in bytes. Let's divide it back to bytes.
	 */
	peak_mem_bytes /= 1024;
#endif

	ns->us_cpu_user		+= res->us_cpu_user;
	ns->us_cpu_sys		+= res->us_cpu_sys;
	ns->us_wallclock	+= us_wallclock;

	if (du.size_in_bytes > ns->worst_stg)
		ns->worst_stg	= du.size_in_bytes;
	if (peak_mem_bytes > ns->worst_mem)
		ns->worst_mem	= peak_mem_bytes;

	lws_humanize_pad(h5, sizeof(h5), res->us_cpu_user, humanize_schema_us);
	lws_humanize_pad(h6, sizeof(h6), res->us_cpu_sys,  humanize_schema_us);
	lws_humanize_pad(h7, sizeof(h7), peak_mem_bytes,   humanize_schema_si);
	lws_humanize_pad(h8, sizeof(h8), du.size_in_bytes, humanize_schema_si);
	lws_humanize_pad(h9, sizeof(h9), us_wallclock,     humanize_schema_us);

	n = lws_snprintf(s, sizeof(s),
		 ">saib> Step %d: [ %s (%s U / %s S), Mem: %sB, Stg: %sB ]\n",
		 ns->task->build_step + 1, h9, h5, h6, h7, h8);
	saib_log_chunk_create(ns, s, (size_t)n, 3);

	/*
	 * Let's send the metrics about the step build back to the
	 * server so it can store them.
	 */

	if (!op->spawn || !ns->spm || !ns->spm->ss)
		goto skip;

	memset(&m, 0, sizeof(m));

	/*
	 * Not being able to key the metrics is not a reason to fail a step
	 * that exited 0... the metrics are just bookkeeping
	 */
	if (sai_metrics_hash((uint8_t *)m.key, sizeof(m.key),
			     ns->sp->name, ns->task->build, ns->project_name, ns->ref)) {
		lwsl_notice("%s: unable to hash metrics key\n", __func__);
		goto skip;
	}

	lws_strncpy(m.builder_name, ns->sp->name,	sizeof(m.builder_name));
	lws_strncpy(m.project_name, ns->project_name,	sizeof(m.project_name));
	lws_strncpy(m.ref,	    ns->ref,		sizeof(m.ref));
	lws_strncpy(m.task_uuid,    ns->task->uuid,	sizeof(m.task_uuid));

	m.unix_time	= (uint64_t)time(NULL);
	m.us_cpu_user	= res->us_cpu_user;
	m.us_cpu_sys	= res->us_cpu_sys;
	m.wallclock_us	= us_wallclock;
	m.peak_mem_rss	= peak_mem_bytes;
	m.stg_bytes	= du.size_in_bytes;
	m.parallel	= ns->task->parallel;
	m.step		= ns->task->build_step + 1;

	/*
	 * Likewise: if we can't get the metrics away, complete the step
	 * anyway.  Returning here used to leave the ns in EXECUTING_STEPS with
	 * a dead child, no grace timer and no status update, so the task hung
	 * on the server until something else knocked it over.
	 */
	if (saib_srv_queue_json_fragments_helper(ns->spm->ss,
					lsm_schema_map_build_metric,
					LWS_ARRAY_SIZE(lsm_schema_map_build_metric), &m))
		lwsl_notice("%s: unable to queue step metrics\n", __func__);

skip:

	/* step succeeded, wait for next instruction */
	lwsl_notice("%s: step succeeded\n", __func__);

	if (op->spawn) {
		free(op->spawn);
		op->spawn = NULL;
	}

	/*
	 * add a final zero-length log with the retcode to the list of pending
	 * logs
	 */

	saib_log_chunk_create(ns, NULL, 0, 2);

	lwsl_notice("%s: ns finished\n", __func__);

	ns->reap_cb_called = 1;

	if (ns)
		ns->op = NULL;

	saib_task_grace(ns);
	saib_set_ns_state(ns, NSSTATE_DONE);
	if (ns->state != NSSTATE_FAILED)
		saib_set_ns_state(ns, NSSTATE_UPLOADING_ARTIFACTS);

	if (!op->lsp || lws_spawn_get_stdwsi_open_count(op->lsp) == 0) {
		lwsl_notice("%s: freeing op from reap_cb\n", __func__);
		free(op);
	}

	return;

fail:
	if (!ns->idle_yield) {
		n = lws_snprintf(s, sizeof(s), "Build step %d FAILED, exit code: %d\n",
				 ns->task->build_step + 1, exit_code);
		saib_log_chunk_create(ns, s, (size_t)n, 3);
	}

	saib_task_grace(ns);
	saib_set_ns_state(ns, NSSTATE_FAILED);

	saib_log_chunk_create(ns, NULL, 0, 2);

	if (op->spawn)
		free(op->spawn);

	if (ns)
		ns->op = NULL;
	free(op);
}

#if defined(WIN32)

static const char * const runscript_win_first =
	"set SAI_INSTANCE_IDX=%d\n"
	"set SAI_WRAP14=%d\n"
	"set SAI_PARALLEL=%d\n"
	"set SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"set SAI_LOGPROXY=%s\n"
	"set SAI_LOGPROXY_TTY0=%s\n"
	"set SAI_LOGPROXY_TTY1=%s\n"
	"%s%s"
	"set HOME=%s\n"
	"set CI=true\n"
	"set BUILDKIT_PROGRESS=plain\n"
	"cd %s%s &&"
	" rmdir /s /q src & "
	"%s < NUL"
;

static const char * const runscript_win_next =
	"set SAI_INSTANCE_IDX=%d\n"
	"set SAI_WRAP14=%d\n"
	"set SAI_PARALLEL=%d\n"
	"set SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"set SAI_LOGPROXY=%s\n"
	"set SAI_LOGPROXY_TTY0=%s\n"
	"set SAI_LOGPROXY_TTY1=%s\n"
	"%s%s"
	"set HOME=%s\n"
	"set CI=true\n"
	"set BUILDKIT_PROGRESS=plain\n"
	"cd %s%s &&"
	"%s < NUL"
;

#else

static const char * const runscript_first =
	"#!/usr/bin/env bash\n" /* use -x to see what it does for these */
	/* PATH comes from saib_env_build(), with any conf "env" applied */
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_WRAP14=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
	"%s%s"
	"export CI=true\n"
	"export BUILDKIT_PROGRESS=plain\n"
	"set -e\n"
	"cd %s/jobs/$SAI_VN\n"
	"rm -rf src\n"
	"%s < /dev/null\n"
	"exit $?\n"
;

static const char * const runscript_next =
	"#!/usr/bin/env bash\n" /* use -x to see what it does for these */
	/* PATH comes from saib_env_build(), with any conf "env" applied */
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_WRAP14=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
	"%s%s"
	"export CI=true\n"
	"export BUILDKIT_PROGRESS=plain\n"
	"set -e\n"
	"cd %s/jobs/$SAI_VN\n"
	"%s < /dev/null\n"
	"exit $?\n"
;

static const char * const runscript_build =
	"#!/usr/bin/env bash\n" /* use -x to see what it does for these */
	/* PATH comes from saib_env_build(), with any conf "env" applied */
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_WRAP14=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
	"%s%s"
	"export CI=true\n"
	"export BUILDKIT_PROGRESS=plain\n"
	"set -e\n"
	"cd %s/jobs/$SAI_VN/src\n"
	"%s < /dev/null\n"
	"exit $?\n"
;

#endif

int
saib_spawn_script(struct sai_nspawn *ns)
{
	struct lws_spawn_piped_info info;
	struct saib_opaque_spawn *op;
	struct lwsac *ac_env = NULL;
#if !defined(WIN32)
	const char *script_template;
#endif
	const char *respath = "unk";
	const char * cmd[] = {
		"/bin/ps",
		NULL
	};
	char one_step[4096], idle_env[64], pool_env[1024];
	char st[8192];
	unsigned int timeout_secs;
	int fd, n;
#if defined(__linux__)
	int in_cgroup = 1;
	char cgroup[128];
#endif

#if defined(WIN32)
	lws_snprintf(ns->script_path, sizeof(ns->script_path),
		     "%s\\sai-build-script.bat",
		     ns->inp);
#else
	lws_snprintf(ns->script_path, sizeof(ns->script_path),
		     "%s/sai-build-script.sh",
		     ns->inp);
#endif

	n = lws_snprintf(one_step, sizeof(one_step), "%s\n", ns->task->script);
	if (n < 1)
		return -1;

	if (saib_log_chunk_create(ns, one_step, strlen(one_step), 3))
		return -1;

	one_step[n - 1] = '\0'; /* trim off the CR; n is always at least 1 */

#if defined(WIN32)
	if (_sopen_s(&fd, ns->script_path, _O_CREAT | _O_TRUNC | _O_WRONLY,
		     _SH_DENYNO, _S_IWRITE))
		fd = -1;
#else
	fd = open(ns->script_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
#endif
	if (fd < 0) {
		saib_task_logf(ns->spm, ns, NULL,
			       "Unable to create the step script %s: errno %d (%s)",
			       ns->script_path, errno, strerror(errno));
		return 1;
	}

	if (builder.sai_plat_server_owner.head) {
		struct sai_plat_server *cm = lws_container_of(
				builder.sai_plat_server_owner.head,
				sai_plat_server_t, list);

		respath = cm->resproxy_path;
	}
	builder.wrap14 = (builder.wrap14 + 8) & 0x3fff;

	/*
	 * An idle task is told how long its slice is, so it can aim to fit
	 * whatever it does in the time.  We stop it anyway if it goes on much
	 * longer than that.
	 */
	/* where the task's pool is, if it has one, see b-pool.c */
	saib_pool_env(ns, pool_env, sizeof(pool_env));

	idle_env[0] = '\0';
	timeout_secs = builder.build_timeout_secs;
	if (ns->task->idle) {
		lws_snprintf(idle_env, sizeof(idle_env),
#if defined(WIN32)
			     "set SAI_IDLE_SECS=%u\n",
#else
			     "export SAI_IDLE_SECS=%u\n",
#endif
			     ns->sp->idle_slice_secs);
		if (ns->sp->idle_slice_secs + SAIB_IDLE_SLICE_GRACE_SECS <
								timeout_secs)
			timeout_secs = ns->sp->idle_slice_secs +
						SAIB_IDLE_SLICE_GRACE_SECS;
	}

#if defined(WIN32)
	n = lws_snprintf(st, sizeof(st),
			 ns->task->build_step ? runscript_win_next : runscript_win_first,
			 ns->instance_ordinal + 1, builder.wrap14,
			 ns->task->parallel ? ns->task->parallel : 1,
			 respath, ns->slp_control.sockpath,
			 ns->slp[0].sockpath, ns->slp[1].sockpath, idle_env,
			 pool_env, builder.home,
                        ns->inp, ns->task->build_step > 1 ? "\\src" : "",
                        one_step);
#else

	switch (ns->task->build_step) {
	case 0:
		script_template = runscript_first;
		break;
	case 1:
		script_template = runscript_next;
		break;
	default:
		script_template = runscript_build;
		break;
	}

	n = lws_snprintf(st, sizeof(st), script_template,
			 builder.home, ns->fsm.ovname, ns->inp_vn,
			 ns->project_name, ns->ref, ns->instance_ordinal + 1,
			 builder.wrap14,
			 ns->task->parallel ? ns->task->parallel : 1,
			 respath, ns->slp_control.sockpath,
			 ns->slp[0].sockpath, ns->slp[1].sockpath, idle_env,
			 pool_env, builder.home, one_step);
#endif

	/* but from the script's pov, it's chrooted at /home/sai */

	if (write(fd, st, (unsigned int)n) != n) {
		int en = errno;

		close(fd);
		saib_task_logf(ns->spm, ns, NULL,
			       "Unable to write the step script %s: errno %d (%s)",
			       ns->script_path, en, strerror(en));
		return 1;
	}

	close(fd);

	cmd[0] = ns->script_path;

#if defined(__linux__)
	lws_snprintf(cgroup, sizeof(cgroup), "inst-%s", ns->task->uuid);
#endif

	memset(&info, 0, sizeof(info));
	info.vh			= builder.vhost;
	info.exec_array		= cmd;
	info.protocol_name	= "sai-stdxxx";
	info.max_log_lines	= 10000;
	info.timeout_us		= (lws_usec_t)((uint64_t)timeout_secs * LWS_US_PER_SEC);
	info.reap_cb		= sai_lsp_reap_cb;
#if defined(WIN32)
	info.pty_mode		= 0;
#else
	info.pty_mode		= 1;
#endif
	info.disable_ctrlc	= 1;
	memset(&ns->res, 0, sizeof(ns->res));
	info.res		= &ns->res;
#if defined(__linux__)
	info.cgroup_name_suffix = cgroup;
	info.p_cgroup_ret	= &in_cgroup;
#endif

	/* the base set plus the platform's conf "env", see b-env.c */
	info.env_array		= saib_env_build(ns->sp, &ac_env);
	if (!info.env_array) {
		saib_task_logf(ns->spm, ns, NULL,
			       "Unable to prepare the step environment: OOM");
		return 1;
	}

	op			= malloc(sizeof(*op));
	if (!op) {
		lwsac_free(&ac_env);
		return 1;
	}
	memset(op, 0, sizeof(*op));

	op->ns			= ns;
	ns->reap_cb_called	= 0;
	ns->op			= op;
#if defined(WIN32)
	op->spawn		= _strdup(one_step);
#else
	op->spawn		= strdup(one_step);
#endif
	op->start_time		= lws_now_usecs();

	info.opaque		= op;
	info.owner		= &builder.lsp_owner;
	info.plsp		= &op->lsp;

	lwsl_user("%s: calling lws_spawn_piped for task uuid %s\n", __func__, ns->task->uuid);
	lws_spawn_piped(&info);
	lwsac_free(&ac_env); /* the child has its copy by now */
	if (!op->lsp) {
		saib_task_logf(ns->spm, ns, NULL,
			       "Unable to spawn the step process (errno %d (%s)): "
			       "the builder could not fork, allocate a pty or "
			       "exec %s", errno, strerror(errno), ns->script_path);
		/*
		 * op is attached to wsi and will be freed in reap cb,
		 * we can't free it here
		 */
		ns->op = NULL;

		return 1;
	}
	lwsl_user("%s: lws_spawn_piped success, op->lsp %p\n", __func__, op->lsp);

	return 0;
}

static void
sai_shell_reap_cb(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
		  int we_killed_him)
{
	struct sai_shell *sh = (struct sai_shell *)opaque;

	lwsl_notice("%s: shell exited\n", __func__);

	if (sh) {
		lws_dll2_remove(&sh->list);
		free(sh);
	}
	saib_reassess_idle_situation();
}

static int
callback_sai_shell_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct sai_shell *sh = (struct sai_shell *)lws_get_opaque_user_data(wsi);
	uint8_t buf[1024];
	int ilen;

	switch (reason) {

#if defined(WIN32)
	case LWS_CALLBACK_RAW_ADOPT_FILE:
		lwsl_user("%s: wsi %p, reason %d, sh %p, fd %d\n", __func__,
			    wsi, reason, sh, lws_spawn_get_stdfd(wsi));
		break;
#endif

	case LWS_CALLBACK_RAW_CLOSE_FILE:
#if defined(WIN32)
		lwsl_user("%s: wsi %p, CLOSE_FILE, sh %p, fd %d\n", __func__,
			    wsi, sh, lws_spawn_get_stdfd(wsi));
#endif
	{
		int ch = lws_spawn_get_stdfd(wsi);
		if (ch == 0) ch = 1;
		if (sh && ch < 3)
			sh->stdwsi[ch] = NULL;
		break;
	}

	case LWS_CALLBACK_RAW_RX_FILE:
#if defined(WIN32)
		/* lws spawn reads the pipe itself on windows and delivers the
		 * data in in / len; the wsi has no readable fd for us
		 */
		ilen = (int)len;
		if (ilen > (int)sizeof(buf) - 1)
			ilen = (int)sizeof(buf) - 1;
		if (ilen > 0)
			memcpy(buf, in, (size_t)ilen);
#else
		ilen = (int)read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
		if (ilen < 1)
			return -1;
#endif
		if (!sh || !sh->spm)
			return -1;

		len = (size_t)ilen;
		int ch = lws_spawn_get_stdfd(wsi);
		if (ch == 0) ch = 1;

		lwsl_notice("%s: read %d bytes from shell %s (ch %d)\n", __func__, ilen, sh->task_uuid, ch);

		if (ch < 3)
			sh->stdwsi[ch] = wsi;

		char lj[4000 + LWS_PRE];
		int n = lws_snprintf(lj + LWS_PRE, sizeof(lj) - LWS_PRE,
			"{\"schema\":\"com.warmcat.sai.ptydata\","
			 "\"task_uuid\":\"%s\", \"channel\": %d, \"len\": %d, \"data\":\"",
			 sh->task_uuid, ch, (int)len);
		
		n += lws_b64_encode_string((char *)buf, (int)len, lj + LWS_PRE + n,
					   (int)sizeof(lj) - LWS_PRE - n - 5);
		lj[LWS_PRE + n++] = '\"';
		lj[LWS_PRE + n++] = '}';
		lj[LWS_PRE + n] = '\0';

		lwsl_notice("%s: PTYDATA queueing %d bytes from shell %s to server\n", __func__, (int)len, sh->task_uuid);

		saib_srv_queue_tx(sh->spm->ss, lj + LWS_PRE, (size_t)n, LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);

		if (lws_buflist2_total_len(&sh->spm->bl_to_srv) > (LWS_BUFLIST_OOM_LIMIT - (256 * 1024))) {
			/* buflist is getting full, backpressure ALL active shell stdwsi for this connection */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, builder.shell_owner.head) {
				struct sai_shell *s = lws_container_of(d, struct sai_shell, list);
				if (s->spm == sh->spm) {
					for (int i = 0; i < 3; i++) {
						if (!s->stdwsi_paused[i] && s->stdwsi[i]) {
							s->stdwsi_paused[i] = 1;
							lws_rx_flow_control(s->stdwsi[i], 0); /* 0 disables RX */
							lwsl_notice("%s: Backpressure applied to shell %s ch %d (tot %zu)\n",
								__func__, s->task_uuid, i, lws_buflist2_total_len(&sh->spm->bl_to_srv));
						}
					}
				}
			} lws_end_foreach_dll_safe(d, d1);
		}
		break;

	default:
		break;
	}
	return 0;
}

struct lws_protocols protocol_saishell = {
	.name			= "sai-saishell",
	.callback		= callback_sai_shell_stdwsi,
	.per_session_data_size	= 0,
	.rx_buffer_size		= 0,
};

int
saib_shell_spawn(struct sai_plat_server *spm, const char *task_uuid)
{
	struct lws_spawn_piped_info info;
	const sai_plat_t *tsp = NULL;
	struct lwsac *ac_env = NULL;
	struct sai_shell *sh;
	const char *cmd[] = { "/bin/bash", "-i", NULL };

	/* the shell sees the same env as the task's platform gives its steps */

	lws_start_foreach_dll(struct lws_dll2 *, d, builder.sai_plat_owner.head) {
		const sai_plat_t *sp = lws_container_of(d, sai_plat_t,
							sai_plat_list);

		lws_start_foreach_dll(struct lws_dll2 *, d1, sp->nspawn_owner.head) {
			const struct sai_nspawn *ns = lws_container_of(d1,
						struct sai_nspawn, list);

			if (ns->task && !strcmp(ns->task->uuid, task_uuid))
				tsp = sp;
		} lws_end_foreach_dll(d1);
	} lws_end_foreach_dll(d);

	sh = malloc(sizeof(*sh));
	if (!sh)
		return 1;
	memset(sh, 0, sizeof(*sh));

	lws_strncpy(sh->task_uuid, task_uuid, sizeof(sh->task_uuid));
	sh->spm = spm;

	memset(&info, 0, sizeof(info));
	info.vh			= builder.vhost;
	info.exec_array		= cmd;
	info.protocol_name	= "sai-saishell";
	info.max_log_lines	= 10000;
	info.timeout_us		= (lws_usec_t)((uint64_t)builder.build_timeout_secs * LWS_US_PER_SEC);
	info.reap_cb		= sai_shell_reap_cb;
	info.pty_mode		= 1;
	info.disable_ctrlc	= 0;
	info.opaque		= sh;
	info.owner		= &builder.lsp_owner;
	info.plsp		= &sh->lsp;
	info.env_array		= saib_env_build(tsp, &ac_env);
	if (!info.env_array) {
		free(sh);
		return 1;
	}

	lws_dll2_add_tail(&sh->list, &builder.shell_owner);

	lws_spawn_piped(&info);
	lwsac_free(&ac_env);
	if (!sh->lsp) {
		lwsl_err("%s: Failed to spawn shell for %s\n", __func__, task_uuid);
		lws_dll2_remove(&sh->list);
		free(sh);
		return 1;
	}

	lwsl_notice("%s: Spawned shell successfully for %s\n", __func__, task_uuid);
	saib_reassess_idle_situation();
	return 0;
}
