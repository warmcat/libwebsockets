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

int
saib_log_chunk_create(struct sai_nspawn *ns, void *buf, size_t len, int channel)
{
	char lj[2600 + LWS_PRE];
	int n = 0;

	if (!ns || !ns->spm)
		return 1;

	if (!ns->task)
		return 0;

	n = lws_snprintf(lj + LWS_PRE, sizeof(lj) - LWS_PRE,
		"{\"schema\":\"com-warmcat-sai-logs\","
		 "\"task_uuid\":\"%s\", \"timestamp\": %llu,"
		 "\"channel\": %d, \"len\": %d, ",
		 ns->task->uuid, (unsigned long long)lws_now_usecs(),
		 channel, (int)len);

	if (ns->retcode_set) {
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

	// puts((const char *)&chunk[1]);
	// puts((const char *)start);

	n += lws_b64_encode_string(buf, (int)len, (char *)&lj[LWS_PRE + n],
				   (int)sizeof(lj) - LWS_PRE - n - 5);

	lj[LWS_PRE + n++] = '\"';
	lj[LWS_PRE + n++] = '}';
	lj[LWS_PRE + n] = '\0';

	return saib_srv_queue_tx(ns->spm->ss, lj + LWS_PRE, (size_t)n, LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
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

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		if (op && op->lsp) {
			if (lws_spawn_stdwsi_closed(op->lsp, wsi) &&
			    ns->reap_cb_called) {
				lwsl_notice("%s: freeing op from stdwsi_cb\n", __func__);
				free(op);
			}
			if (ns)
				lws_cancel_service(ns->builder->context);
		}
		break;

	case LWS_CALLBACK_RAW_RX_FILE:
#if defined(WIN32)
	{
		DWORD rb;
		if (!ReadFile((HANDLE)lws_get_socket_fd(wsi), buf, sizeof(buf), &rb, NULL)) {
			lwsl_debug("%s: read on stdwsi failed\n", __func__);
			return -1;
		}
		ilen = (int)rb;
	}
#else
		ilen = (int)read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf));
		if (ilen < 1) {
			lwsl_debug("%s: read on stdwsi failed\n", __func__);
			return -1;
		}
#endif

		len = (unsigned int)ilen;

		if (!op || !op->ns || !op->ns->spm) {
			printf("%s: (%d) %.*s\n", __func__,
			       (int)lws_spawn_get_stdfd(wsi), (int)len, buf);
			return -1;
		}

		if (saib_log_chunk_create(op->ns, buf, len, lws_spawn_get_stdfd(wsi)))
			return -1;

		return lws_ss_request_tx(op->ns->spm->ss) ? -1 : 0;

	default:
		break;
	}

	return 0;
}

struct lws_protocols protocol_stdxxx =
		{ "sai-stdxxx", callback_sai_stdwsi, 0, 0 };

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

#if !defined(WIN32)

	if (we_killed_him & 1) {
		lwsl_notice("%s: Process TIMED OUT by Sai\n", __func__);
		exit_code = -1;
		ns->retcode = SAISPRF_TIMEDOUT;
		ns->retcode_set = 1;
		goto fail;
	}

	if (we_killed_him & 2) {
		lwsl_notice("%s: Process killed by Sai due to spew\n", __func__);
		exit_code = -1;
		ns->retcode = SAISPRF_TERMINATED;
		ns->retcode_set = 1;
		goto fail;
	}

	switch (si->si_code) {
	case CLD_EXITED:
		lwsl_notice("%s: Process Exited with exit code %d\n",
			    __func__, si->si_status);
		exit_code = si->si_status;
		ns->retcode_set = 1;
		ns->retcode = SAISPRF_EXIT | si->si_status;
		if (ns->user_cancel)
			ns->retcode = SAISPRF_TERMINATED;
		break;
	case CLD_KILLED:
	case CLD_DUMPED:
		lwsl_notice("%s: Process Terminated by signal %d / %d\n",
			    __func__, si->si_status, si->si_signo);
		ns->retcode = SAISPRF_SIGNALLED | si->si_signo;
		ns->retcode_set = 1;
		break;
	default:
		lwsl_notice("%s: SI code %d\n", __func__, si->si_code);
		break;
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

	if (!op->spawn || !ns->spm)
		goto skip;

	memset(&m, 0, sizeof(m));

	if (sai_metrics_hash((uint8_t *)m.key, sizeof(m.key),
			     ns->sp->name, ns->task->build, ns->project_name, ns->ref))
		goto fail;

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

	if (saib_srv_queue_json_fragments_helper(ns->spm->ss,
					lsm_schema_map_build_metric,
					LWS_ARRAY_SIZE(lsm_schema_build_metric), &m))
		return;

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

	saib_task_grace(ns);
	saib_set_ns_state(ns, NSSTATE_DONE);
	if (ns->state != NSSTATE_FAILED)
		saib_set_ns_state(ns, NSSTATE_UPLOADING_ARTIFACTS);

	ns->reap_cb_called = 1;

	if (ns)
		ns->op = NULL;

	if (!op->lsp || lws_spawn_get_stdwsi_open_count(op->lsp) == 0) {
		lwsl_notice("%s: freeing op from reap_cb\n", __func__);
		free(op);
	}

	if (ns->task) {
		saib_queue_task_status_update(ns->sp, ns->spm, ns->task->uuid,
					      (unsigned int)ns->retcode,
					      SAI_TASK_REASON_DESTROYED);
		saib_reassess_idle_situation();

		builder.ram_reserved_kib	-= ns->task->est_peak_mem_kib;
		builder.disk_reserved_kib	-= ns->task->est_disk_kib;
		if (ns->spm)
			lws_sul_schedule(builder.context, 0,
					 &ns->spm->sul_load_report,
					 saib_sul_load_report_cb, 1);
	}

	return;

fail:
	n = lws_snprintf(s, sizeof(s), "Build step %d FAILED, exit code: %d\n",
			 ns->task->build_step, exit_code);
	saib_log_chunk_create(ns, s, (size_t)n, 3);

	saib_task_grace(ns);
	saib_set_ns_state(ns, NSSTATE_FAILED);

	saib_log_chunk_create(ns, NULL, 0, 2);

	if (ns->task) {
		saib_queue_task_status_update(ns->sp, ns->spm, ns->task->uuid,
					      (unsigned int)ns->retcode,
					      SAI_TASK_REASON_DESTROYED);
		saib_reassess_idle_situation();

		builder.ram_reserved_kib	-= ns->task->est_peak_mem_kib;
		builder.disk_reserved_kib	-= ns->task->est_disk_kib;
		if (ns->spm)
			lws_sul_schedule(builder.context, 0,
					 &ns->spm->sul_load_report,
					 saib_sul_load_report_cb, 1);
	}

	if (op->spawn)
		free(op->spawn);

	if (ns)
		ns->op = NULL;
	free(op);
}

#if defined(WIN32)

static const char * const runscript_win_first =
	"set SAI_INSTANCE_IDX=%d\n"
	"set SAI_PARALLEL=%d\n"
	"set SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"set SAI_LOGPROXY=%s\n"
	"set SAI_LOGPROXY_TTY0=%s\n"
	"set SAI_LOGPROXY_TTY1=%s\n"
	"set HOME=%s\n"
	"cd %s%s &&"
	" rmdir /s /q src & "
	"%s < NUL"
;

static const char * const runscript_win_next =
	"set SAI_INSTANCE_IDX=%d\n"
	"set SAI_PARALLEL=%d\n"
	"set SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"set SAI_LOGPROXY=%s\n"
	"set SAI_LOGPROXY_TTY0=%s\n"
	"set SAI_LOGPROXY_TTY1=%s\n"
	"set HOME=%s\n"
	"cd %s%s &&"
	"%s < NUL"
;

#else

static const char * const runscript_first =
	"#!/bin/bash\n" /* use -x to see what it does for these */
#if defined(__APPLE__)
	"export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin\n"
#else
	"export PATH=/usr/local/bin:$PATH\n"
#endif
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
	"set -e\n"
	"cd %s/jobs/$SAI_VN\n"
	"rm -rf src\n"
	"%s < /dev/null\n"
	"exit $?\n"
;

static const char * const runscript_next =
	"#!/bin/bash\n" /* use -x to see what it does for these */
#if defined(__APPLE__)
	"export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin\n"
#else
	"export PATH=/usr/local/bin:$PATH\n"
#endif
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
	"set -e\n"
	"cd %s/jobs/$SAI_VN\n"
	"%s < /dev/null\n"
	"exit $?\n"
;

static const char * const runscript_build =
	"#!/bin/bash\n" /* use -x to see what it does for these */
#if defined(__APPLE__)
	"export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin\n"
#else
	"export PATH=/usr/local/bin:$PATH\n"
#endif
	"export HOME=%s\n"
	"export SAI_OVN=%s\n"
	"export SAI_VN=%s\n"
	"export SAI_PROJECT=%s\n"
	"export SAI_REMOTE_REF=%s\n"
	"export SAI_INSTANCE_IDX=%d\n"
	"export SAI_PARALLEL=%d\n"
	"export SAI_BUILDER_RESOURCE_PROXY=%s\n"
	"export SAI_LOGPROXY=%s\n"
	"export SAI_LOGPROXY_TTY0=%s\n"
	"export SAI_LOGPROXY_TTY1=%s\n"
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
#if !defined(WIN32)
	const char *script_template;
#endif
	const char *respath = "unk";
	const char * cmd[] = {
		"/bin/ps",
		NULL
	};
	const char *env[] = {
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=en_US.UTF-8",
		NULL
	};
	char one_step[4096];
	char st[2048];
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

	lws_strncpy(one_step, ns->task->script, sizeof(one_step));

#if defined(WIN32)
	if (_sopen_s(&fd, ns->script_path, _O_CREAT | _O_TRUNC | _O_WRONLY,
		     _SH_DENYNO, _S_IWRITE))
		fd = -1;
#else
	fd = open(ns->script_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
#endif
	if (fd < 0) {
		lwsl_err("%s: unable to open %s for write\n", __func__, ns->script_path);
		return 1;
	}

	if (builder.sai_plat_server_owner.head) {
		struct sai_plat_server *cm = lws_container_of(
				builder.sai_plat_server_owner.head,
				sai_plat_server_t, list);

		respath = cm->resproxy_path;
	}

#if defined(WIN32)
	n = lws_snprintf(st, sizeof(st),
			 ns->task->build_step ? runscript_win_next : runscript_win_first,
			 ns->instance_ordinal + 1,
			 ns->task->parallel ? ns->task->parallel : 1,
			 respath, ns->slp_control.sockpath,
			 ns->slp[0].sockpath, ns->slp[1].sockpath, builder.home,
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
			 ns->task->parallel ? ns->task->parallel : 1,
			 respath, ns->slp_control.sockpath,
			 ns->slp[0].sockpath, ns->slp[1].sockpath,
			 builder.home, one_step);
#endif

	/* but from the script's pov, it's chrooted at /home/sai */

	if (write(fd, st, (unsigned int)n) != n) {
		close(fd);
		lwsl_err("%s: failed to write runscript to %s\n", __func__, ns->script_path);
		return 1;
	}

	close(fd);

	cmd[0] = ns->script_path;

#if defined(__linux__)
	lws_snprintf(cgroup, sizeof(cgroup), "inst-%s", ns->task->uuid);
#endif

	memset(&info, 0, sizeof(info));
	info.vh			= builder.vhost;
	info.env_array		= (const char **)env;
	info.exec_array		= cmd;
	info.protocol_name	= "sai-stdxxx";
	info.max_log_lines	= 10000;
	info.timeout_us		= 30 * 60 * LWS_US_PER_SEC;
	info.reap_cb		= sai_lsp_reap_cb;
	memset(&ns->res, 0, sizeof(ns->res));
	info.res		= &ns->res;
#if defined(__linux__)
	info.cgroup_name_suffix = cgroup;
	info.p_cgroup_ret	= &in_cgroup;
#endif

	op			= malloc(sizeof(*op));
	if (!op)
		return 1;
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

	lws_spawn_piped(&info);
	if (!op->lsp) {
		/*
		 * op is attached to wsi and will be freed in reap cb,
		 * we can't free it here
		 */
		ns->op = NULL;

		return 1;
	}

	return 0;
}

