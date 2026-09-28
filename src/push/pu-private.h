/*
 * Sai push definitions src/push/pu-private.h
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
 */

#include "../common/include/private.h"

/*
 * How long we ask sai-web to hold a request for (it caps it at 600 anyway)
 */
#define SAIP_WAIT_S		600

/*
 * sai-web sends a keepalive newline every 10s on a held request, so this long
 * without anything arriving means the connection is dead
 */
#define SAIP_RX_TIMEOUT_S	45

/* don't retry pushing the same hash to the same branch sooner than this */
#define SAIP_RETRY_S		600

/* longest one git step may take before it's killed */
#define SAIP_GIT_TIMEOUT_S	600

/*
 * One promotion rule: a feed branch matching "match" (an lws_strcmp_wildcard
 * pattern, default "*") and ending in branch_suffix is promoted to the
 * branch named without the suffix, with a force push if force.  The first
 * matching rule in the watch decides.
 */

typedef struct saip_rule {
	lws_dll2_t		list;
	const char		*match;
	const char		*branch_suffix;
	int			force;
} saip_rule_t;

/*
 * A mirror of the watched repo: whatever we push to the primary remote, we
 * also push to the same branch here.  The project name is appended to url.
 * If token_file is given, it holds a token git gives as the password when
 * the (https) remote asks, eg, a github fine-grained access token.
 */

typedef struct saip_mirror {
	lws_dll2_t		list;
	const char		*url;
	const char		*token_file;
} saip_mirror_t;

/*
 * What we know about promoting to one target branch of a watch
 */

typedef struct saip_target {
	lws_dll2_t		list;
	char			branch[65];
	char			pushed[65];	/* hash we last pushed everywhere */
	char			tried[65];	/* hash we last tried */
	lws_usec_t		tried_at;

	/*
	 * The last event promoted to this branch on the primary, kept in the
	 * state file across restarts: an event whose notification arrived
	 * before this one's is never promoted over it
	 */
	uint64_t		promoted_received;
	char			promoted_hash[65];
	char			promoted_uuid[65];
} saip_target_t;

typedef struct saip_watch {
	lws_dll2_t		list;

	/* from the conf */

	const char		*feed;		/* sai rss.xml or rss.json url */
	const char		*fetchurl;	/* events must have this */
	const char		*remote;	/* project name is appended */
	lws_dll2_owner_t	rules;		/* saip_rule_t */
	lws_dll2_owner_t	mirrors;	/* saip_mirror_t */

	/* runtime */

	char			host[128];
	char			path[256];	/* rss.json path, from '/' */
	int			port;
	int			tls;

	struct lws		*wsi;
	lws_sorted_usec_list_t	sul;		/* next feed request */
	uint16_t		retry_count;

	struct lejp_ctx		ctx;
	lws_struct_args_t	a;		/* the feed being parsed */
	int			http_status;
	char			index[33];	/* from the last feed */

	lws_dll2_owner_t	targets;	/* saip_target_t */

	uint8_t			parse_done:1;
	uint8_t			parse_failed:1;
	uint8_t			handled:1;
} saip_watch_t;

enum {
	SAIP_STEP_INIT,		/* git init --bare, idempotent */
	SAIP_STEP_FETCH,	/* fetch the primary remote's branches */
	SAIP_STEP_ON_SRC,	/* the hash must be on the feed branch */

	/* then these for the primary, and each mirror in turn */

	SAIP_STEP_R_FETCH_DST,	/* fetch the remote's target branch */
	SAIP_STEP_R_IN_DST,	/* if the remote's target has it, skip it */
	SAIP_STEP_R_PUSH,	/* push the hash to the remote's target */

	SAIP_STEP_DONE
};

/*
 * One promotion, run as a series of git commands, one at a time.  Remote 0
 * is the watch's primary remote, 1.. are its mirrors in order.
 */

typedef struct saip_job {
	lws_dll2_t		list;
	saip_watch_t		*w;
	saip_target_t		*t;
	char			project[65];
	char			src[65];	/* feed branch, eg main-dev */
	char			dst[65];	/* target branch, eg main */
	char			hash[65];
	char			uuid[65];	/* the event */
	uint64_t		received;	/* the event's notification */
	char			repo[512];	/* bare repo in the cache */
	int			force;
	int			step;
	int			remote;		/* 0 primary, 1.. mirrors */
	uint8_t			dst_fetched:1;	/* remote's target is fetched */
	uint8_t			failed:1;	/* a mirror failed */
	char			line[256];	/* partial output line */
	size_t			line_len;
} saip_job_t;

/* the conf, as parsed into its lwsac */

typedef struct saip_conf {
	const char		*user;
	const char		*repo_cache;
	lws_dll2_owner_t	watches;	/* saip_watch_t */
} saip_conf_t;

typedef struct saip {
	struct lws_context	*cx;
	struct lws_vhost	*vh;
	struct lwsac		*ac_conf;
	saip_conf_t		*conf;

	char			home[256];	/* for the git child env */
	char			self[256];	/* our own path, for GIT_ASKPASS */
	lws_dll2_owner_t	jobs;		/* saip_job_t, head is running */
	struct lws_spawn_piped	*lsp;
	lws_sorted_usec_list_t	sul_job;
} saip_t;

extern saip_t saip;
extern const struct lws_protocols protocol_saip_feed, protocol_saip_git;

int
saip_conf_load(const char *path);

void
saip_feed_start(saip_watch_t *w);

void
saip_feed_process(saip_watch_t *w, sai_feed_t *f);

void
saip_job_queue(saip_watch_t *w, saip_target_t *t, const sai_feed_item_t *it,
	       int force);

saip_target_t *
saip_target_get(saip_watch_t *w, const char *branch);

int
saip_state_load(void);

void
saip_state_save(void);

int
saip_askpass(const char *prompt);
