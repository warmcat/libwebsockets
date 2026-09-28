/*
 * Sai push - src/push/pu-git.c
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
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
 * Promotions run as a series of git commands on a bare repo per project in
 * the repo cache, one command at a time, one promotion at a time: jobs are
 * rare, and this way nothing else ever touches a cache repo while git is.
 *
 *  - git init --bare (does nothing if it's already there)
 *  - fetch all the primary remote's branches
 *  - the hash must still be on the feed branch, or it was rewritten since:
 *    then it's not what the feed branch says is good any more
 *
 * then for the primary remote, and each mirror in turn:
 *
 *  - fetch the remote's target branch (the primary's came with the rest)
 *  - if the remote's target branch already has the hash, skip it: this also
 *    stops an older success rewinding a target that moved on
 *  - push the hash to the remote's target branch, forced if the rule says
 *
 * If the primary fails, the mirrors are left alone.  If a mirror fails, the
 * others are still done, and it's tried again later.
 *
 * The commands are given argv directly, without a shell, and everything in
 * them from the feed was checked in saip_feed_process().  A remote with a
 * token file gets it by git running us as its GIT_ASKPASS, so the token is
 * never in an argv, a url or a log.
 */

#include <libwebsockets.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pu-private.h"

static const char * const step_names[] = {
	"init", "fetch", "check feed branch", "fetch target branch",
	"check target branch", "push", "done"
};

static void
saip_job_run(lws_sorted_usec_list_t *sul);

static void
saip_job_kick(void)
{
	lws_sul_schedule(saip.cx, 0, &saip.sul_job, saip_job_run, 1);
}

/*
 * Remote 0 is the watch's primary, 1.. its mirrors in conf order
 */
static const char *
saip_job_remote(saip_job_t *j, int idx, const char **token_file)
{
	int n = 1;

	*token_file = NULL;
	if (!idx)
		return j->w->remote;

	lws_start_foreach_dll(struct lws_dll2 *, p, j->w->mirrors.head) {
		saip_mirror_t *m = lws_container_of(p, saip_mirror_t, list);

		if (n++ == idx) {
			*token_file = m->token_file;
			return m->url;
		}
	} lws_end_foreach_dll(p);

	return NULL;
}

void
saip_job_queue(saip_watch_t *w, saip_target_t *t, const sai_feed_item_t *it,
	       int force)
{
	saip_job_t *j;

	lws_start_foreach_dll(struct lws_dll2 *, p, saip.jobs.head) {
		j = lws_container_of(p, saip_job_t, list);
		if (j->t == t && !strcmp(j->hash, it->hash))
			return; /* already on it */
	} lws_end_foreach_dll(p);

	j = malloc(sizeof(*j));
	if (!j) {
		lwsl_err("%s: OOM\n", __func__);
		return;
	}
	memset(j, 0, sizeof(*j));

	j->w		= w;
	j->t		= t;
	j->force	= force;
	j->received	= it->received;
	lws_strncpy(j->project, it->project, sizeof(j->project));
	lws_strncpy(j->src, it->branch, sizeof(j->src));
	lws_strncpy(j->dst, t->branch, sizeof(j->dst));
	lws_strncpy(j->hash, it->hash, sizeof(j->hash));
	lws_strncpy(j->uuid, it->uuid, sizeof(j->uuid));
	lws_snprintf(j->repo, sizeof(j->repo), "%s/%s.git",
		     saip.conf->repo_cache, j->project);

	lwsl_user("%s: %s: %.12s succeeded on %s, promoting to %s%s\n",
		  __func__, j->project, j->hash, j->src, j->dst,
		  j->force ? " (force)" : "");

	lws_dll2_add_tail(&j->list, &saip.jobs);
	if (saip.jobs.count == 1)
		saip_job_kick();
}

static void
saip_job_log_line(saip_job_t *j)
{
	const char *tf, *r;

	j->line[j->line_len] = '\0';
	if (j->line_len) {
		r = j->step >= SAIP_STEP_R_FETCH_DST ?
				saip_job_remote(j, j->remote, &tf) : NULL;
		lwsl_notice("%s: %s %s%s%s: git: %s\n", __func__, j->project,
			    step_names[j->step], r ? " " : "", r ? r : "",
			    j->line);
	}
	j->line_len = 0;
}

/*
 * The primary has the hash on the target now, whether we pushed it or it was
 * already there: remember this event as the last one promoted, so no event
 * older than it is ever promoted over it
 */
static void
saip_job_promoted(saip_job_t *j)
{
	saip_target_t *t = j->t;

	if (j->received < t->promoted_received)
		return;

	t->promoted_received = j->received;
	lws_strncpy(t->promoted_hash, j->hash, sizeof(t->promoted_hash));
	lws_strncpy(t->promoted_uuid, j->uuid, sizeof(t->promoted_uuid));
	saip_state_save();
}

/* on to the next remote, or finished */

static void
saip_job_next_remote(saip_job_t *j)
{
	const char *tf;

	j->remote++;
	j->dst_fetched = 0;

	if (!saip_job_remote(j, j->remote, &tf)) {
		if (!j->failed)
			lws_strncpy(j->t->pushed, j->hash,
				    sizeof(j->t->pushed));
		j->step = SAIP_STEP_DONE;

		return;
	}

	j->step = SAIP_STEP_R_FETCH_DST;
}

static void
saip_git_reap(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
	      int we_killed_him)
{
	saip_job_t *j = (saip_job_t *)opaque;
	const char *tf, *r;
	int code = -1;

	if (!j)
		return;

	saip_job_log_line(j);

	if (si && si->si_code == CLD_EXITED)
		code = si->si_status;

	if (we_killed_him)
		lwsl_err("%s: %s: git %s timed out\n", __func__, j->project,
			 step_names[j->step]);

	r = saip_job_remote(j, j->remote, &tf);

	switch (j->step) {
	case SAIP_STEP_ON_SRC:
		if (code == 1) {
			lwsl_user("%s: %s: %.12s is no longer on %s, not "
				  "promoting it\n", __func__, j->project,
				  j->hash, j->src);
			j->step = SAIP_STEP_DONE;
			goto next;
		}
		if (!code) {
			/* remote 0's target came with the primary's fetch */
			j->remote = 0;
			j->dst_fetched = 1;
			j->step = SAIP_STEP_R_IN_DST;
			goto next;
		}
		break;

	case SAIP_STEP_R_FETCH_DST:
		/*
		 * Failing here is usually the target branch not existing on
		 * the remote yet.  Either way, don't check against a stale
		 * copy from before: the push will say if there's a problem.
		 */
		j->dst_fetched = !code;
		j->step = j->dst_fetched ? SAIP_STEP_R_IN_DST :
					   SAIP_STEP_R_PUSH;
		goto next;

	case SAIP_STEP_R_IN_DST:
		if (!code) {
			lwsl_user("%s: %s: %s on %s already has %.12s\n",
				  __func__, j->project, j->dst, r, j->hash);
			if (!j->remote)
				saip_job_promoted(j);
			saip_job_next_remote(j);
			goto next;
		}
		/*
		 * Anything else, including the target branch not existing
		 * yet, means pushing it is up to us
		 */
		j->step = SAIP_STEP_R_PUSH;
		goto next;

	case SAIP_STEP_R_PUSH:
		if (!code) {
			lwsl_user("%s: %s: pushed %.12s to %s on %s%s\n",
				  __func__, j->project, j->hash, j->dst, r,
				  j->force ? " (force)" : "");
			if (!j->remote)
				saip_job_promoted(j);
			saip_job_next_remote(j);
			goto next;
		}

		if (j->remote) {
			/* a mirror failed: still do the others */
			lwsl_err("%s: %s: pushing %.12s to %s on mirror %s "
				 "failed (exit %d)\n", __func__, j->project,
				 j->hash, j->dst, r, code);
			j->failed = 1;
			saip_job_next_remote(j);
			goto next;
		}
		break;

	default:
		break;
	}

	if (code) {
		/*
		 * We'll try again when the feed next changes or the long poll
		 * times out, after SAIP_RETRY_S
		 */
		lwsl_err("%s: %s: promoting %.12s to %s failed at git %s "
			 "(exit %d)\n", __func__, j->project, j->hash, j->dst,
			 step_names[j->step], code);
		j->step = SAIP_STEP_DONE;
		goto next;
	}

	j->step++;

next:
	/* we're inside lws spawn's reap here, start the next one after */
	saip_job_kick();
}

static int
saip_job_spawn(saip_job_t *j)
{
	char home[300], askpass[300], tokenfile[300], url[512], refspec[160],
	     tracking[160];
	const char *env[8], *argv[16], *prefix, *tf;
	struct lws_spawn_piped_info info;
	int n = 0, e = 0;

	prefix = saip_job_remote(j, j->step >= SAIP_STEP_R_FETCH_DST ?
					j->remote : 0, &tf);
	if (!prefix)
		return 1;
	lws_snprintf(url, sizeof(url), "%s%s", prefix, j->project);

	lws_snprintf(home, sizeof(home), "HOME=%s", saip.home);
	env[e++] = home;
	env[e++] = "PATH=/usr/local/bin:/usr/bin:/bin";
	env[e++] = "LANG=C";
	/* never wait for someone to type anything */
	env[e++] = "GIT_TERMINAL_PROMPT=0";
	env[e++] = "GIT_SSH_COMMAND=ssh -o BatchMode=yes";

	argv[n++] = "git";

	if (tf) {
		/*
		 * git runs us to answer its username / password prompts, and
		 * we answer from the token file, see saip_askpass().  Clear
		 * any credential helpers the user's git config names, so
		 * nothing but that is asked, and nothing is stored.
		 */
		lws_snprintf(askpass, sizeof(askpass), "GIT_ASKPASS=%s",
			     saip.self);
		lws_snprintf(tokenfile, sizeof(tokenfile),
			     "SAI_PUSH_TOKEN_FILE=%s", tf);
		env[e++] = askpass;
		env[e++] = tokenfile;
		argv[n++] = "-c";
		argv[n++] = "credential.helper=";
	}
	env[e] = NULL;

	switch (j->step) {
	case SAIP_STEP_INIT:
		argv[n++] = "init";
		argv[n++] = "--bare";
		argv[n++] = "-q";
		argv[n++] = j->repo;
		break;

	case SAIP_STEP_FETCH:
		argv[n++] = "-C";
		argv[n++] = j->repo;
		argv[n++] = "fetch";
		argv[n++] = "-q";
		argv[n++] = "--prune";
		argv[n++] = "--no-tags";
		argv[n++] = url;
		argv[n++] = "+refs/heads/*:refs/sai-push/heads/*";
		break;

	case SAIP_STEP_R_FETCH_DST:
		lws_snprintf(refspec, sizeof(refspec),
			     "+refs/heads/%s:refs/sai-push/mirror%d/%s",
			     j->dst, j->remote, j->dst);
		argv[n++] = "-C";
		argv[n++] = j->repo;
		argv[n++] = "fetch";
		argv[n++] = "-q";
		argv[n++] = "--no-tags";
		argv[n++] = url;
		argv[n++] = refspec;
		break;

	case SAIP_STEP_ON_SRC:
	case SAIP_STEP_R_IN_DST:
		if (j->step == SAIP_STEP_ON_SRC)
			lws_snprintf(tracking, sizeof(tracking),
				     "refs/sai-push/heads/%s", j->src);
		else if (!j->remote)
			lws_snprintf(tracking, sizeof(tracking),
				     "refs/sai-push/heads/%s", j->dst);
		else
			lws_snprintf(tracking, sizeof(tracking),
				     "refs/sai-push/mirror%d/%s", j->remote,
				     j->dst);
		argv[n++] = "-C";
		argv[n++] = j->repo;
		argv[n++] = "merge-base";
		argv[n++] = "--is-ancestor";
		argv[n++] = j->hash;
		argv[n++] = tracking;
		break;

	case SAIP_STEP_R_PUSH:
		lws_snprintf(refspec, sizeof(refspec), "%s%s:refs/heads/%s",
			     j->force ? "+" : "", j->hash, j->dst);
		argv[n++] = "-C";
		argv[n++] = j->repo;
		argv[n++] = "push";
		argv[n++] = "-q";
		argv[n++] = url;
		argv[n++] = refspec;
		break;

	default:
		return 1;
	}

	argv[n] = NULL;

	memset(&info, 0, sizeof(info));
	info.vh			= saip.vh;
	info.exec_array		= argv;
	info.env_array		= env;
	info.protocol_name	= protocol_saip_git.name;
	info.max_log_lines	= 100;
	info.timeout_us		= (lws_usec_t)SAIP_GIT_TIMEOUT_S *
								LWS_US_PER_SEC;
	info.reap_cb		= saip_git_reap;
	info.opaque		= j;
	info.plsp		= &saip.lsp;

	lwsl_info("%s: %s: git %s (%s)\n", __func__, j->project,
		  step_names[j->step], prefix);

	/* lws_spawn_piped() copies what it needs before returning */
	if (!lws_spawn_piped(&info)) {
		lwsl_err("%s: %s: unable to spawn git\n", __func__, j->project);
		return 1;
	}

	return 0;
}

static void
saip_job_run(lws_sorted_usec_list_t *sul)
{
	saip_job_t *j;

	while (saip.jobs.head) {
		j = lws_container_of(saip.jobs.head, saip_job_t, list);

		if (j->step != SAIP_STEP_DONE) {
			if (!saip_job_spawn(j))
				return;
			/* couldn't even start it, give up on this one */
		}

		lws_dll2_remove(&j->list);
		free(j);
	}
}

static int
callback_saip_git(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	saip_job_t *j = (saip_job_t *)lws_get_opaque_user_data(wsi);
	char buf[512];
	ssize_t n, m;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX_FILE:
		n = read((int)(intptr_t)lws_get_socket_fd(wsi), buf,
			 sizeof(buf));
		if (n < 1)
			return -1;
		if (!j)
			break;

		/* log what git says a line at a time */
		for (m = 0; m < n; m++) {
			if (buf[m] == '\n' || buf[m] == '\r' ||
			    j->line_len == sizeof(j->line) - 1) {
				saip_job_log_line(j);
				if (buf[m] == '\n' || buf[m] == '\r')
					continue;
			}
			j->line[j->line_len++] = buf[m];
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		if (j)
			saip_job_log_line(j);
		/*
		 * lws spawn reaps the child when its last stdwsi closes, which
		 * calls saip_git_reap() and destroys the lsp
		 */
		if (saip.lsp)
			lws_spawn_stdwsi_closed(saip.lsp, wsi);
		break;

	default:
		break;
	}

	return 0;
}

const struct lws_protocols protocol_saip_git = {
	.name			= "sai-push-git",
	.callback		= callback_saip_git,
};
