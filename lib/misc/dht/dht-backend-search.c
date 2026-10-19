/*
 * Copyright (c) 2009-2011 by Juliusz Chroboczek
 * Minor changes (c) 2018 Gwiz <gwiz2009@gmail.com>
 *   Added handler for implied port & hook for dhtdigg
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *   Adaptation for lws, cleaning, modernization
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "private-lib-misc-dht.h"

struct search *
find_search(struct lws_dht_ctx *ctx, unsigned short tid, int af)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->searches)) {
		struct search *sr = lws_container_of(d, struct search, list);

		if (sr->tid == tid && sr->af == af)
			return sr;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * Did we actually send a request to this address as part of this search?
 *
 * A search tid is only 16 bits and find_search() matches on (tid, af) alone,
 * so without this an off-path peer that guesses or observes a tid can inject
 * nodes, a token and search *results* into somebody else's lookup, and end it
 * early.  The search node list is our pending-request table: it holds the
 * addresses we sent get_peers / announce_peer to, along with the time, so we
 * require the reply to come from one of those with a request outstanding.
 * Returns that candidate, or NULL.
 */

struct search_node *
search_awaiting_reply_from(struct lws_dht_ctx *ctx, struct search *sr,
			   const struct sockaddr *sa)
{
	int i;

	for (i = 0; i < sr->numnodes; i++) {
		struct search_node *n = &sr->nodes[i];

		/*
		 * Accept either a node with a request outstanding, or one that
		 * already passed this test and replied, so that a late
		 * duplicate or a second reply datagram from a node we really
		 * did query still counts.  ->replied is only ever set from
		 * this path, and the reuse path in lws_dht_search() clears it.
		 */
		if (!n->replied && (!n->request_time || n->request_time <
			    ctx->now - LWS_DHT_PING_TIMEOUT_SECS))
			continue;

		if (dht_sa_same_peer((const struct sockaddr *)&n->ss, sa))
			return n;
	}

	return NULL;
}

void
search_free_nodes(struct search *sr)
{
	int i;

	for (i = 0; i < sr->numnodes; i++)
		lws_dht_hash_destroy(&sr->nodes[i].id);
	for (i = 0; i < sr->numbacklog; i++)
		lws_dht_hash_destroy(&sr->backlog[i].id);

	sr->numnodes = 0;
	sr->numbacklog = 0;
	sr->numdead = 0;
	sr->nextdead = 0;
}

/* a candidate we asked LWS_DHT_MAX_PING_FAILURES times without an answer */

static int
search_node_dead(const struct search_node *n)
{
	return !n->replied && n->pinged >= LWS_DHT_MAX_PING_FAILURES;
}

/* record who introduced a candidate; family 0 if nobody (our own table) */

static void
search_intro_set(lws_sockaddr46 *intro, const struct sockaddr *sa)
{
	size_t cl = 0;

	memset(intro, 0, sizeof(*intro));
	if (!sa)
		return;

	switch (sa->sa_family) {
	case AF_INET:
		cl = sizeof(struct sockaddr_in);
		break;
#if defined(LWS_WITH_IPV6)
	case AF_INET6:
		cl = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		return;
	}

	if (cl <= sizeof(*intro))
		memcpy(intro, sa, cl);
}

/*
 * Is intro the same introducer as sa?  A public introducer is its host
 * (dht_source_key()), the same unit the per-host caps use, so one host gets
 * one share however many of its endpoints we query.  Private addresses are
 * never collapsed into one host by the caps (on a LAN or loopback several
 * real nodes share an address), so there the introducer is the endpoint.
 */

static int
search_intro_same(const lws_sockaddr46 *intro, const struct sockaddr *sa)
{
	const struct sockaddr *i = (const struct sockaddr *)intro;

	if (!intro->sa4.sin_family || i->sa_family != sa->sa_family)
		return 0;

	if (lws_dht_ads_is_private(sa) || lws_dht_ads_is_private(i))
		return dht_sa_same_peer(i, sa);

	return lws_dht_same_host(i, sa);
}

/*
 * Remember an endpoint that never answered this search: a nodes list naming
 * it again must not bring it back as a fresh candidate, or one that is gone
 * (routing tables keep listing those for a long time) would be asked again
 * and again, and hold the search open (G-211)
 */

static void
search_dead_add(struct search *sr, const struct search_node *n)
{
	search_intro_set(&sr->dead[sr->nextdead],
			 (const struct sockaddr *)&n->ss);
	sr->nextdead = (sr->nextdead + 1) % LWS_DHT_SEARCH_DEAD;
	if (sr->numdead < LWS_DHT_SEARCH_DEAD)
		sr->numdead++;
}

static int
search_dead(const struct search *sr, const struct sockaddr *sa)
{
	int i;

	for (i = 0; i < sr->numdead; i++)
		if (dht_sa_same_peer((const struct sockaddr *)&sr->dead[i], sa))
			return 1;

	return 0;
}

/*
 * Has the search run for as long as any may?  Then it asks nobody more, and
 * completes on the candidates that answered it.
 */

static int
search_expired(const struct lws_dht_ctx *ctx, const struct search *sr)
{
	return ctx->now - sr->start_time >= LWS_DHT_SEARCH_MAX_SECS;
}

/*
 * Keep a candidate back for later, taking ownership of id: in distance order,
 * and when full the farthest one is dropped (perhaps the one offered).  It
 * keeps how often it was asked without answering, so the backlog does not
 * make a candidate that fails to answer fresh again.
 */

static void
search_backlog_add(struct search *sr, lws_dht_hash_t *id,
		   const struct sockaddr_storage *ss, size_t sslen,
		   const lws_sockaddr46 *intro, int pinged, time_t request_time)
{
	struct search_cand *c;
	int i, j;

	for (i = 0; i < sr->numbacklog; i++)
		if (xorcmp(id, sr->backlog[i].id, sr->id) < 0)
			break;

	if (i >= LWS_DHT_SEARCH_BACKLOG) {
		lws_dht_hash_destroy(&id);
		return;
	}

	if (sr->numbacklog >= LWS_DHT_SEARCH_BACKLOG)
		lws_dht_hash_destroy(&sr->backlog[LWS_DHT_SEARCH_BACKLOG - 1].id);
	else
		sr->numbacklog++;

	for (j = sr->numbacklog - 1; j > i; j--)
		sr->backlog[j] = sr->backlog[j - 1];

	c		= &sr->backlog[i];
	c->id		= id;
	c->ss		= *ss;
	c->sslen	= sslen;
	c->intro	= *intro;
	c->pinged	= pinged;
	c->request_time	= request_time;
}

/*
 * Take a candidate out of the node list.  One that failed to answer is
 * remembered as dead.  If keep, one still waiting to be asked or to answer
 * goes to the backlog; one that answered never does, since the backlog keeps
 * no answers: it is only pushed out when the search has enough closer ones.
 */

static void
search_node_retire(struct search *sr, int i, int keep)
{
	struct search_node *n = &sr->nodes[i];
	int j;

	if (search_node_dead(n))
		search_dead_add(sr, n);

	if (!keep || n->replied || search_node_dead(n))
		lws_dht_hash_destroy(&n->id);
	else
		/* the backlog owns the id now */
		search_backlog_add(sr, n->id, &n->ss, n->sslen, &n->intro,
				   n->pinged, n->request_time);

	for (j = i; j < sr->numnodes - 1; j++)
		sr->nodes[j] = sr->nodes[j + 1];
	sr->numnodes--;
}

/*
 * A search contains a list of nodes, sorted by decreasing distance to the
 * target.  We just got a new candidate, insert it at the right spot or
 * discard it.
 *
 * Candidates mostly come from the nodes lists in replies, which name any
 * endpoint and any id their sender likes, so the list applies the same
 * admission the routing table does (maybe_new_node()): no martian or
 * blacklisted endpoints, and no more than a couple of entries from one host
 * (dht_source_key()) however many ids it presents.  Otherwise one host
 * answering us can list a dozen ids of its own next to the target, which
 * sort ahead of every honest node, and own the lookup and where its
 * announce goes; or have us send requests to internal addresses.
 *
 * The ids and endpoints a reply lists need not answer either, so one host
 * could still list decoys at many hosts that sort ahead of every honest
 * candidate and push them all out, and once the decoys time out the search
 * would complete on whatever that host left in it (G-158).  So
 *
 *  - intro is who listed the candidate (NULL for our routing table and for
 *    the replier itself), and the candidates one introducer listed that have
 *    not answered yet are capped, across the list and the backlog: a closer
 *    newcomer from it may take the place of its own farthest one only
 *
 *  - the LWS_DHT_SEARCH_RESULT_NODES closest candidates that replied, the
 *    ones the search completes on, are never pushed out; farther ones that
 *    replied only take slots from closer candidates and may be dropped
 *
 *  - unverified candidates pushed out, or that sort after a full list, go to
 *    a small backlog that search_step() refills the list from when candidates
 *    it asked fail to answer.  They keep their failures there, and endpoints
 *    that failed are remembered, so neither comes back fresh (G-211)
 *
 * An entry also keeps the endpoint it was admitted with: a nodes list
 * naming a known candidate's id somewhere else, or a reply from another
 * endpoint claiming it, does not move it there.
 */

/* the index after the candidates the search completes on, if it has them */

static int
search_result_end(const struct search *sr)
{
	int i, n = 0;

	for (i = 0; i < sr->numnodes; i++)
		if (sr->nodes[i].replied && ++n == LWS_DHT_SEARCH_RESULT_NODES)
			return i + 1;

	return sr->numnodes;
}

/*
 * In a full list, the entry a newcomer sorting at i may take the place of:
 * the farthest that sorts after it and either has not replied, or is not one
 * the search would complete on.  -1 if there is none.
 */

static int
search_victim(const struct search *sr, int i)
{
	int end = search_result_end(sr), j;

	for (j = sr->numnodes - 1; j >= i; j--)
		if (!sr->nodes[j].replied || j >= end)
			return j;

	return -1;
}

/* where id sorts in the list */

static int
search_sorts_at(const struct search *sr, const lws_dht_hash_t *id)
{
	int i;

	for (i = 0; i < sr->numnodes; i++)
		if (xorcmp(id, sr->nodes[i].id, sr->id) < 0)
			break;

	return i;
}

static int
search_insert(struct lws_dht_ctx *ctx, lws_dht_hash_t *id,
	      const struct sockaddr *sa, size_t salen, struct search *sr,
	      int replied, const uint8_t *token, size_t token_len,
	      const struct sockaddr *intro, int pinged, time_t request_time)
{
	struct sockaddr_storage ss;
	int i, j, same = 0, introduced = 0, intro_far = -1, victim = -1;
	lws_dht_hash_t *nid;
	struct search_node *n;

	if (sa->sa_family != sr->af) {
		lwsl_dht_warn("Attempted to insert node in the wrong family.\n");
		return 0;
	}

	if (salen > sizeof(ss) || dht_endpoint_refused(ctx, sa, salen))
		return 0;

	/*
	 * a candidate we already have, what its host already holds, and what
	 * its introducer already put in that has not answered
	 */

	for (i = 0; i < sr->numnodes; i++) {
		if (id_cmp(id, sr->nodes[i].id) == 0) {
			n = &sr->nodes[i];
			if (!dht_sa_same_peer((const struct sockaddr *)&n->ss,
					      sa))
				return 0;
			goto found;
		}
		if (!lws_dht_ads_is_private(sa) &&
		    lws_dht_same_host((const struct sockaddr *)&sr->nodes[i].ss,
				     sa))
			same++;
		if (intro && !sr->nodes[i].replied &&
		    search_intro_same(&sr->nodes[i].intro, intro)) {
			introduced++;
			intro_far = i;
		}
	}

	for (i = 0; i < sr->numbacklog; i++) {
		if (id_cmp(id, sr->backlog[i].id))
			continue;
		/*
		 * Held back already: only the node itself answering us (a
		 * candidate pushed out while our request to it was
		 * outstanding) brings it back, and at the endpoint it had
		 */
		if (!replied || !dht_sa_same_peer(
				(const struct sockaddr *)&sr->backlog[i].ss, sa))
			return 0;
		lws_dht_hash_destroy(&sr->backlog[i].id);
		for (j = i; j < sr->numbacklog - 1; j++)
			sr->backlog[j] = sr->backlog[j + 1];
		sr->numbacklog--;
		break;
	}

	/* proof it is alive is the only way back for an endpoint that failed */
	if (!replied && search_dead(sr, sa))
		return 0;

	for (i = 0; i < sr->numbacklog; i++)
		if (intro && search_intro_same(&sr->backlog[i].intro, intro))
			introduced++;

	/* a newcomer: where it sorts */

	i = search_sorts_at(sr, id);

	if (same >= LWS_DHT_MAX_SAME_ADS_PER_SEARCH) {
		lwsl_dht_info("%s: host already has %d search candidates\n",
			      __func__, same);
		return 0;
	}

	if (introduced >= LWS_DHT_MAX_INTRODUCED_PER_SEARCH) {
		/*
		 * Its introducer's share is used up: it may only replace the
		 * farthest of that introducer's own unanswered candidates in
		 * the list, and only if it is closer
		 */
		if (intro_far < i) {
			lwsl_dht_info("%s: introducer already has %d unverified "
				      "candidates\n", __func__, introduced);
			return 0;
		}
		victim = intro_far;
	} else if (sr->numnodes >= SEARCH_NODES)
		victim = search_victim(sr, i);

	/*
	 * Take the copy of the id before disturbing the list, so a failure here
	 * cannot leave a counted entry behind with a NULL ->id.
	 */
	nid = lws_dht_hash_dup(id);
	if (!nid)
		return 0;

	if (sr->numnodes >= SEARCH_NODES && victim < 0) {
		/* it sorts after everything, or only after ones we need */
		lws_sockaddr46 i46;

		if (replied) {
			/* the backlog cannot keep its reply */
			lws_dht_hash_destroy(&nid);

			return 0;
		}

		memset(&ss, 0, sizeof(ss));
		memcpy(&ss, sa, salen);
		search_intro_set(&i46, intro);
		search_backlog_add(sr, nid, &ss, salen, &i46, pinged,
				   request_time);

		return 0;
	}

	if (victim >= 0)
		/*
		 * Removing an entry at or after i leaves where the newcomer
		 * sorts unchanged.  One replaced inside its introducer's share
		 * is dropped, not kept back, or the share would not bound it.
		 */
		search_node_retire(sr, victim,
			introduced < LWS_DHT_MAX_INTRODUCED_PER_SEARCH);

	for (j = sr->numnodes; j > i; j--)
		sr->nodes[j] = sr->nodes[j - 1];
	sr->numnodes++;

	n = &sr->nodes[i];

	memset(n, 0, sizeof(struct search_node));
	n->id		= nid;
	n->pinged	= pinged;
	n->request_time	= request_time;
	search_intro_set(&n->intro, intro);

found:
	memcpy(&n->ss, sa, (size_t)salen);
	n->sslen = salen;

	if (replied) {
		n->replied = 1;
		n->reply_time = ctx->now;
		n->request_time = 0;
		n->pinged = 0;
	}
	if (token) {
		if (token_len >= 40) {
			lwsl_dht_warn("%s: Eek!  Overlong token.\n", __func__);
		} else {
			memcpy(n->token, token, (size_t)token_len);
			n->token_len = token_len;
		}
	}

	return 1;
}

int
insert_search_node(struct lws_dht_ctx *ctx, lws_dht_hash_t *id,
		   const struct sockaddr *sa, size_t salen, struct search *sr,
		   int replied, const uint8_t *token, size_t token_len,
		   const struct sockaddr *intro)
{
	return search_insert(ctx, id, sa, salen, sr, replied, token,
			     token_len, intro, 0, 0);
}

/* has an entry at this endpoint answered the search already? */

static int
search_endpoint_replied(const struct search *sr, const struct sockaddr *sa)
{
	int i;

	for (i = 0; i < sr->numnodes; i++)
		if (sr->nodes[i].replied &&
		    dht_sa_same_peer((const struct sockaddr *)&sr->nodes[i].ss,
				     sa))
			return 1;

	return 0;
}

/*
 * Record a get_peers reply from sa, claiming id, against sn, the candidate
 * search_awaiting_reply_from() found we asked at that endpoint.  Returns 1 if
 * this reply may add the candidates it lists to the search, 0 if not.
 *
 * An endpoint introduces once per search, on its first reply (G-158).  That
 * is decided by the endpoint, not by the id the reply claims: entries match
 * by id, so a reply under another id than the one the endpoint was listed and
 * asked as used to leave the asked entry unanswered, and the next ask of it
 * introduced again, each time with fresh decoys replacing the last (G-216).
 *
 * So a reply under another id answers for the entry we asked: that entry
 * goes, since nothing answers as that id there, and the reply is recorded
 * under the id it claims, as an entry for that endpoint that replied.  An
 * honest node that restarted with a new id at its old endpoint is then
 * counted under its new id, rather than asked again under the old one until
 * it looked dead.  An id another endpoint holds in the search is not taken
 * over, and that reply introduces nothing.
 */

int
search_record_reply(struct lws_dht_ctx *ctx, struct search *sr,
		    struct search_node *sn, lws_dht_hash_t *id,
		    const struct sockaddr *sa, size_t salen,
		    const uint8_t *token, size_t token_len)
{
	int first = !sn->replied && !search_endpoint_replied(sr, sa);

	if (id_cmp(sn->id, id)) {
		if (sn->replied) {
			/*
			 * It answered already as the id we have it under: the
			 * entry stays as it was, and is not doubled
			 */
			lwsl_dht_info("%s: replier changed its id\n", __func__);

			return 0;
		}

		/* sn is not used after this */
		flush_search_node(sn, sr);
	}

	return search_insert(ctx, id, sa, salen, sr, 1, token, token_len,
			     NULL, 0, 0) && first;
}

/*
 * Give the backlog's candidates the slots of ones we asked that never
 * answered, so a search pushed off course by candidates that do not exist
 * returns to the ones that do instead of completing on what is left; and
 * the places of entries a newcomer could take, so a closer candidate held
 * back while the list was full is asked before the search completes without
 * it.  Each move brings in a closer candidate than it puts out, and it is
 * bounded besides.
 */

static void
search_refill(struct lws_dht_ctx *ctx, struct search *sr)
{
	struct search_cand c;
	int i, n;

	if (!sr->numbacklog)
		return;

	for (i = sr->numnodes - 1; i >= 0; i--)
		if (search_node_dead(&sr->nodes[i]))
			search_node_retire(sr, i, 0);

	for (n = 0; sr->numbacklog &&
		    n < LWS_DHT_SEARCH_BACKLOG + SEARCH_NODES; n++) {
		if (sr->numnodes >= SEARCH_NODES &&
		    search_victim(sr, search_sorts_at(sr,
						sr->backlog[0].id)) < 0)
			break;

		c = sr->backlog[0];
		for (i = 0; i < sr->numbacklog - 1; i++)
			sr->backlog[i] = sr->backlog[i + 1];
		sr->numbacklog--;

		/*
		 * admitted again as from the start, so the caps still hold,
		 * with the failures it had
		 */
		search_insert(ctx, c.id, (const struct sockaddr *)&c.ss,
			      c.sslen, sr, 0, NULL, 0, c.intro.sa4.sin_family ?
				(const struct sockaddr *)&c.intro : NULL,
			      c.pinged, c.request_time);
		lws_dht_hash_destroy(&c.id);
	}
}

/*
 * The search has run out of time: nobody is asked again, the candidates that
 * have not answered count as failed and the backlog is dropped, so it
 * completes now on what answered
 */

static void
search_give_up(struct search *sr)
{
	int i;

	for (i = 0; i < sr->numnodes; i++)
		if (!sr->nodes[i].replied &&
		    sr->nodes[i].pinged < LWS_DHT_MAX_PING_FAILURES)
			sr->nodes[i].pinged = LWS_DHT_MAX_PING_FAILURES;

	for (i = 0; i < sr->numbacklog; i++)
		lws_dht_hash_destroy(&sr->backlog[i].id);
	sr->numbacklog = 0;
}

void
expire_searches(struct lws_dht_ctx *ctx)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&ctx->searches)) {
		struct search *sr = lws_container_of(d, struct search, list);

		if (sr->step_time < ctx->now - DHT_SEARCH_EXPIRE_TIME) {
			lws_dll2_remove(d);
			lws_dht_hash_destroy(&sr->id);
			search_free_nodes(sr);
			lws_free(sr);
		}
	} lws_end_foreach_dll_safe(d, d1);
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
int
search_send_get_peers(struct lws_dht_ctx *ctx, struct search *sr, struct search_node *n)
{
	struct node *node;
	uint8_t tid[4];

	if (search_expired(ctx, sr))
		return 0;

	if (n == NULL) {
		int i;
		for (i = 0; i < sr->numnodes; i++) {
			if (sr->nodes[i].pinged < LWS_DHT_MAX_PING_FAILURES && !sr->nodes[i].replied &&
					sr->nodes[i].request_time < ctx->now - LWS_DHT_PING_TIMEOUT_SECS)
				n = &sr->nodes[i];
		}
	}

	if (!n || n->pinged >= LWS_DHT_MAX_PING_FAILURES || n->replied ||
			n->request_time >= ctx->now - LWS_DHT_PING_TIMEOUT_SECS)
		return 0;

	lwsl_dht_info("Sending get_peers.\n");
	make_tid(tid, "gp", sr->tid);
	send_get_peers(ctx, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
			n->reply_time >= ctx->now - LWS_DHT_PING_TIMEOUT_SECS);
	n->pinged++;
	n->request_time = ctx->now;

	/* If the node happens to be in our main routing table, mark it
	   as pinged. */

	node = find_node(ctx, n->id, n->ss.ss_family);
	if (node) mark_as_pinged(ctx, node, NULL);

	return 1;
}

/*
 * When a search is in progress, we periodically call search_step to send
 * further requests.
 */
void
search_step(struct lws_dht_ctx *ctx, struct search *sr, lws_dht_callback_t *callback, void *closure)
{
	int i, j;
	int all_done = 1;

	/*
	 * A search can only take so long: candidates keep arriving while ones
	 * it asks fail, and ->step_time, renewed at each step, never lets
	 * expire_searches() retire one still in progress (G-211)
	 */
	if (search_expired(ctx, sr))
		search_give_up(sr);
	else
		search_refill(ctx, sr);

	/* Check if the first live nodes have replied. */
	j = 0;
	for (i = 0; i < sr->numnodes && j < LWS_DHT_SEARCH_RESULT_NODES; i++) {
		struct search_node *n = &sr->nodes[i];
		if (n->pinged >= LWS_DHT_MAX_PING_FAILURES)
			continue;
		if (!n->replied) {
			all_done = 0;
			break;
		}
		j++;
	}

	if (all_done) {
		if (!sr->port)
			goto done;

		int all_acked = 1;

		j = 0;
		for (i = 0; i < sr->numnodes && j < LWS_DHT_SEARCH_RESULT_NODES;
		     i++) {
			struct search_node *n = &sr->nodes[i];
			struct node *node;
			uint8_t tid[4];

			if (n->pinged >= LWS_DHT_MAX_PING_FAILURES)
				continue;
			/*
			 * A proposed extension to the protocol consists in
			 * omitting the token when storage tables are full.  While
			 * I don't think this makes a lot of sense -- just sending
			 * a positive reply is just as good --, let's deal with it.
			 */
			if (!n->token_len)
				n->acked = 1;

			if (!n->acked) {
				all_acked = 0;
				lwsl_dht_info("Sending announce_peer.\n");
				make_tid(tid, "ap", sr->tid);
				send_announce_peer(ctx, (struct sockaddr*)&n->ss,
						n->sslen,
						tid, 4, sr->id, sr->port,
						n->token, n->token_len,
						n->reply_time >= ctx->now - LWS_DHT_PING_TIMEOUT_SECS);
				n->pinged++;
				n->request_time = ctx->now;

				node = find_node(ctx, n->id, n->ss.ss_family);
				if (node) mark_as_pinged(ctx, node, NULL);
			}
			j++;
		}
		if (all_acked)
			goto done;

		sr->step_time = ctx->now;
		return;
	}

	if (sr->step_time + LWS_DHT_PING_TIMEOUT_SECS >= ctx->now)
		return;

	j = 0;
	for (i = 0; i < sr->numnodes; i++) {
		j += search_send_get_peers(ctx, sr, &sr->nodes[i]);
		if (j >= LWS_DHT_MAX_PING_FAILURES)
			break;
	}
	sr->step_time = ctx->now;
	return;

done:
	sr->done = 1;
	/*
	 * Update ->step_time *before* dispatching: the app may start another
	 * search from its SEARCH_DONE handler, and new_search() then sees this
	 * one as the oldest done search and may free or recycle it.  Writing
	 * ->step_time after the callback returned would be a write into freed
	 * or reused memory.
	 */
	sr->step_time = ctx->now;

	if (callback)
		(*callback)(closure, sr->af == AF_INET ?
				LWS_DHT_EVENT_SEARCH_DONE : LWS_DHT_EVENT_SEARCH_DONE6,
				sr->id, NULL, 0, NULL, 0);
}

static struct search *
new_search(struct lws_dht_ctx *ctx)
{
	struct search *oldest = NULL;

	/* Find the oldest done search */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->searches)) {
		struct search *sr = lws_container_of(d, struct search, list);

		if (sr->done &&
		    (oldest == NULL || oldest->step_time > sr->step_time))
			oldest = sr;
	} lws_end_foreach_dll(d);

	/* The oldest slot is expired, drop it and allocate a fresh one. */
	if (oldest && oldest->step_time < ctx->now - DHT_SEARCH_EXPIRE_TIME) {
		lws_dll2_remove(&oldest->list);
		lws_dht_hash_destroy(&oldest->id);
		search_free_nodes(oldest);
		lws_free(oldest);
		oldest = NULL;
	}

	/* Allocate a new slot. */
	if (lws_dll2_count(&ctx->searches) < DHT_MAX_SEARCHES) {
		struct search *sr = lws_zalloc(sizeof(struct search), __func__);

		if (sr != NULL) {
			lws_dll2_add_head(&sr->list, &ctx->searches);
			return sr;
		}
	}

	/* Oh, well, never mind.  Re-use the oldest slot. */
	if (oldest) {
		lws_dll2_t list = oldest->list;

		lws_dht_hash_destroy(&oldest->id);
		search_free_nodes(oldest);
		memset(oldest, 0, sizeof(*oldest)); /* Clear old data */
		oldest->list = list; /* ... but stay on the searches list */
	}
	return oldest;
}

int
lws_dht_foreach_search_node(struct lws_dht_ctx *ctx,
			    const lws_dht_hash_t *target, int af,
			    lws_dht_node_cb_t cb, void *user)
{
	lws_dht_node_info_t ni;
	int i;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ctx->searches)) {
		struct search *sr = lws_container_of(d, struct search, list);

		if (sr->af != af || id_cmp(sr->id, target))
			continue;

		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n = &sr->nodes[i];
			const struct sockaddr *sa =
					(const struct sockaddr *)&n->ss;

			memset(&ni, 0, sizeof(ni));
			ni.id		= n->id;
			ni.sa		= sa;
			ni.salen	= n->sslen;
			ni.replied	= n->replied ?
					  (long)(ctx->now - n->reply_time) : -1;
			ni.heard	= ni.replied;
			ni.pinged	= n->pinged;
			ni.good		= !!n->replied;
			ni.bep42_ok	= lws_dht_ads_is_private(sa) ||
					  lws_dht_bep42_check(n->id, sa);

			if (cb(user, &ni))
				return i + 1;
		}

		return sr->numnodes;
	} lws_end_foreach_dll(d);

	return -1;
}

/* Insert the contents of a bucket into a search structure. */
static void
insert_search_bucket(struct lws_dht_ctx *ctx, struct bucket *b, struct search *sr)
{
	if (!b)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
		struct node *n = lws_container_of(d, struct node, list);

		insert_search_node(ctx, n->id, (struct sockaddr*)&n->ss, n->sslen,
				sr, 0, NULL, 0, NULL);
	} lws_end_foreach_dll(d);
}

/*
 * Start a search.  If port is non-zero, perform an announce when the
 * search is complete.
 */
LWS_VISIBLE int
lws_dht_search(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int port, int af,
		lws_dht_callback_t *callback, void *closure)
{
	struct search *sr;
	struct storage *st;
	struct bucket *b = find_bucket(ctx, id, af);

	/* the app may call between our events: the search starts now */
	ctx->now = (time_t)lws_now_secs();

	if (port) {
		/* We are announcing.  Store ourselves. */
		struct sockaddr_in sin;

		if (af == AF_INET) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			/*
			 * In the test case, we are on loopback.
			 * Generally determining our own public IP is hard.
			 * But here we want to store what we are listening on so others can find us.
			 * For the test, Node A is on 10001.
			 */
			sin.sin_port = 0; /* Unused by storage_store, it uses the port arg */
			sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			/* If we have a bound wsi, maybe use its address? */
			/* But effectively we just want to put "us" in the storage. */

			storage_store(ctx, id, (struct sockaddr *)&sin, (unsigned short)port, 1);
		}
	}

	if (b == NULL) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/*
	 * Try to answer this search locally.  In a fully grown DHT this
	 * is very unlikely, but people are running modified versions of
	 * this code in private DHTs with very few nodes.  What's wrong
	 * with flooding?
	 */
	if (callback) {
		st = find_storage(ctx, id);
		if (st) {
			unsigned short swapped;
			uint8_t buf[18];
			int i;

			lwsl_dht_info("Found local data (%d peers).\n", st->numpeers);

			for (i = 0; i < st->numpeers; i++) {
				swapped = htons(st->peers[i].port);
				if (st->peers[i].len == 4) {
					memcpy(buf, st->peers[i].ip, 4);
					memcpy(buf + 4, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES, id,
								(void*)buf, 6, NULL, 0);
				} else if (st->peers[i].len == 16) {
					memcpy(buf, st->peers[i].ip, 16);
					memcpy(buf + 16, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES6, id,
								(void*)buf, 18, NULL, 0);
				}
			}
		}
	}

	sr = NULL;
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->searches)) {
		struct search *sr1 = lws_container_of(d, struct search, list);

		if (sr1->af == af && id_cmp(sr1->id, id) == 0) {
			sr = sr1;
			break;
		}
	} lws_end_foreach_dll(d);

	if (sr) {
		/*
		 * We're reusing data from an old search.  Reusing the same tid
		 * means that we can merge replies for both searches.
		 */
		int i;
		sr->done = 0;
		i = 0;
		while (i < sr->numnodes) {
			struct search_node *n = &sr->nodes[i];

			/* Discard any doubtful nodes. */
			if (n->pinged >= LWS_DHT_MAX_PING_FAILURES || n->reply_time < ctx->now - LWS_DHT_NODE_EXPIRE_SECS) {
				flush_search_node(n, sr);
				continue;
			}
			n->pinged	= 0;
			n->token_len	= 0;
			n->replied	= 0;
			n->acked	= 0;
			i++;
		}
		/* a new lookup: what failed the last one may answer this one */
		for (i = 0; i < sr->numbacklog; i++) {
			sr->backlog[i].pinged		= 0;
			sr->backlog[i].request_time	= 0;
		}
		sr->numdead	= 0;
		sr->nextdead	= 0;
	} else {
		sr = new_search(ctx);
		if (sr == NULL) {
			errno = ENOSPC;
			return -1;
		}
		sr->af		= af;
		sr->tid		= ctx->search_id++;
		/*
		 * Never stepped: the search_step() below sends the first
		 * round of requests at once and sets ->step_time itself.
		 * Starting it at ->now held those back for the retransmit
		 * interval, so a new lookup sat idle for 15 - 25s.
		 */
		sr->step_time	= 0;
		sr->id		= lws_dht_hash_dup(id);

		if (!sr->id) {
			/*
			 * If we fail to dup the ID, free the search struct and
			 * take it back off the list again.
			 */
			lws_dll2_remove(&sr->list);
			lws_free(sr);
			errno = ENOMEM;
			return -1;
		}
		sr->done = 0;
		sr->numnodes = 0;
	}

	sr->port	= (unsigned short)port;
	sr->start_time	= ctx->now;

	insert_search_bucket(ctx, b, sr);

	if (sr->numnodes < SEARCH_NODES) {
		struct bucket *p = previous_bucket(b);
		struct bucket *nb = bucket_next(b);

		if (nb)
			insert_search_bucket(ctx, nb, sr);
		if (p)
			insert_search_bucket(ctx, p, sr);
	}
	if (sr->numnodes < SEARCH_NODES)
		insert_search_bucket(ctx, find_bucket(ctx, ctx->myid, af), sr);

	search_step(ctx, sr, callback, closure);
	ctx->search_time = ctx->now;
	return 1;
}
