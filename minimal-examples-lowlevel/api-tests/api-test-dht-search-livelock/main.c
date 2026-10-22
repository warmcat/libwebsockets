/*
 * lws-api-test-dht-search-livelock
 *
 * A DHT search keeps up to 14 candidates, sorted by distance to the target,
 * and completes once the 8 closest that are not known to be dead have
 * answered.  Candidates that answered are kept against unverified newcomers
 * (G-158), and the rest pushed out go to a small backlog.  This checks a
 * search with a node that is gone still completes (G-211):
 *
 *  - plain UDP sockets play 14 honest nodes and one that is gone.  Eight
 *    seeds S ping DHT A so A knows them, and A searches for a target.  Two
 *    seeds answer listing five more nodes E and a node L, closer to the
 *    target than all of them; the others list nothing
 *
 *  - L waits until the other 13 have answered, so the search's 14 slots are
 *    full, then answers every request listing D, closer still, which never
 *    answers anything, as an honest node whose table still holds a node that
 *    went away would
 *
 * L's answer must be recorded, with its token: before, its own list was
 * inserted first, D pushed L, still unanswered, into the backlog, and L's
 * answer went there too, which keeps no answers.  D must be asked no more
 * than the 3 times a candidate is asked before it counts as failed: before,
 * once D failed it was flushed, L came back from the backlog fresh, was
 * asked again, listed D again, and D was a fresh candidate again, so the
 * search never completed.  It must complete with L among its candidates.
 *
 * With --case id-switch, it checks a node answering under another id than
 * the one it was listed and asked as only adds candidates to the search once
 * (G-216):
 *
 *  - eight seeds S and a node X ping A, X as an id next to the target.  X
 *    answers every get_peers under another id, farther away, listing three
 *    nodes V that never answer, closer each time than the last three
 *
 *  - before, the entry A asked never became answered, since the answer was
 *    recorded under the id it claimed: A asked it again, up to 3 times, and
 *    each answer put fresh Vs in place of the last ones.  Now X's answer
 *    stands for the entry A asked, which is recorded under the id X claims:
 *    X must be asked once, only its first three Vs may be asked, and the
 *    search must complete with X, under its new id, as a candidate that
 *    answered, as for an honest node that restarted with a new id
 *
 * D, or the Vs, only fail after A has asked them 3 times, 15 to 25s apart,
 * so this takes a minute or more.
 *
 * The UDP port of A is allocated uniquely at build time and passed in on the
 * command line, so parallel ctest instances do not collide; the raw nodes
 * bind ephemeral ports.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SL_POLL_US	(100 * LWS_US_PER_MS)
#define SL_DEADLINE_US	(150 * LWS_US_PER_SEC)

/* what A asks a candidate before counting it as failed */
#define SL_MAX_ASKS	3

#define SL_TARGET	0x40	/* fill byte of the target's id */
#define SL_ID_A		0xc0	/* ...and of A's, far from it */

enum {
	SL_D,			/* gone: never answers */
	SL_L,			/* lists D */
	SL_S0, SL_S1, SL_S2, SL_S3, SL_S4, SL_S5, SL_S6, SL_S7,
	SL_E0, SL_E1, SL_E2, SL_E3, SL_E4,

	SL_COUNT
};
#define SL_SEEDS	8

/* --case id-switch */

enum {
	SW_X,			/* answers as another id */
	SW_S0, SW_S1, SW_S2, SW_S3, SW_S4, SW_S5, SW_S6, SW_S7,
	SW_V0,			/* three per answer of X, nine in all */

	SW_COUNT = SW_V0 + 9
};

#define SW_X_AS		0x30	/* distance of the id X answers as */
#define SW_ANSWERS	3	/* X's answers that have Vs of their own */

#define SL_MAX		((int)SW_COUNT > (int)SL_COUNT ? (int)SW_COUNT : \
							 (int)SL_COUNT)

/*
 * Each node's id is the target's with the last byte replaced, so its XOR
 * distance to the target is that byte: D (1) is closest, then L (2), the
 * seeds and the Es.  S0 lists E0 - E2, S1 lists E3, E4 and L: as many as one
 * introducer may put into the search unverified.
 */

static const struct {
	uint8_t		dist;
	uint8_t		lists[3];
	uint8_t		nlists;
} sl_node[SL_COUNT] = {
	[SL_D]	= { 1,  { 0 }, 0 },
	[SL_L]	= { 2,  { SL_D }, 1 },
	[SL_S0]	= { 3,  { SL_E0, SL_E1, SL_E2 }, 3 },
	[SL_S1]	= { 4,  { SL_E3, SL_E4, SL_L }, 3 },
	[SL_S2]	= { 5,  { 0 }, 0 },
	[SL_S3]	= { 6,  { 0 }, 0 },
	[SL_S4]	= { 7,  { 0 }, 0 },
	[SL_S5]	= { 8,  { 0 }, 0 },
	[SL_S6]	= { 9,  { 0 }, 0 },
	[SL_S7]	= { 10, { 0 }, 0 },
	[SL_E0]	= { 11, { 0 }, 0 },
	[SL_E1]	= { 12, { 0 }, 0 },
	[SL_E2]	= { 13, { 0 }, 0 },
	[SL_E3]	= { 14, { 0 }, 0 },
	[SL_E4]	= { 15, { 0 }, 0 },
};

/*
 * In the id-switch case X is the closest, the Vs its three answers list next,
 * each three closer than the last, then the seeds.  Everything but the Vs
 * pings A.
 */

static const uint8_t sw_dist[SW_COUNT] = {
	[SW_X]	= 1,
	[SW_S0]	= 0x10, [SW_S1] = 0x11, [SW_S2] = 0x12, [SW_S3] = 0x13,
	[SW_S4]	= 0x14, [SW_S5] = 0x15, [SW_S6] = 0x16, [SW_S7] = 0x17,
	[SW_V0]	= 0x0b, 0x0a, 0x09,	/* listed in X's first answer */
		  0x08, 0x07, 0x06,	/* ...its second */
		  0x05, 0x04, 0x03,	/* ...its third */
};

static int sw;			/* the id-switch case */
static int sl_count;		/* nodes in the case */

static struct lws_context *cx;
static struct lws_dht_ctx *dht_a;
static lws_dht_hash_t *target;
static struct sockaddr_in sa_a;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int retcode = 1;

static struct {
	struct lws	*wsi;
	uint16_t	port;		/* network order */
	int		asked;		/* get_peers A sent it */
} peer[SL_MAX];

static struct {
	int		state;
	int		polls;
	uint8_t		l_tid[4];	/* of A's first get_peers to L */
	unsigned int	l_asked:1;
	unsigned int	l_answered:1;	/* L sent its first answer */
	unsigned int	l_kept:1;	/* ...and A kept it as answered */
	unsigned int	l_lost:1;	/* ...or not */
	unsigned int	done:1;		/* A's SEARCH_DONE for the target */
	int		done_l;		/* L was a candidate when it completed */
	int		done_x;		/* X, as its new id, was, answered */
	int		done_x_old;	/* ...X as the id it was asked as was */
	int		x_answers;	/* answers X sent */
} sl;

static uint8_t
sl_dist(int n)
{
	return sw ? sw_dist[n] : sl_node[n].dist;
}

static void
sl_id_dist(uint8_t *id20, uint8_t dist)
{
	memset(id20, SL_TARGET, 20);
	id20[19] = SL_TARGET ^ dist;
}

static void
sl_id(uint8_t *id20, int n)
{
	sl_id_dist(id20, sl_dist(n));
}

static int
sl_peer_of(const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
	int n;

	if (sa->sa_family != AF_INET ||
	    sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
		return -1;

	for (n = 0; n < sl_count; n++)
		if (sin->sin_port == peer[n].port)
			return n;

	return -1;
}

static ssize_t
sl_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), m;

	for (m = 0; m + nl <= len; m++)
		if (!memcmp(buf + m, needle, nl))
			return (ssize_t)m;

	return -1;
}

static void
sl_sendto(int n, const void *buf, size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(peer[n].wsi);
	ssize_t r;

	if (fd == LWS_SOCK_INVALID)
		return;

	r = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   buf,
#if defined(WIN32)
		   (int)
#endif
		   len, 0, (const struct sockaddr *)&sa_a, sizeof(sa_a));
	if (r != (ssize_t)len)
		lwsl_err("%s: sendto returned %d\n", __func__, (int)r);
}

/*
 * node n's answer to the get_peers with tid, as the id at distance dist,
 * listing the nlists nodes in lists
 */

static void
sl_answer_as(int n, uint8_t dist, const uint8_t *tid, const uint8_t *lists,
	     int nlists)
{
	uint8_t q[256], *p = q;
	int k;

	memcpy(p, "d1:rd2:id20:", 12);
	p += 12;
	sl_id_dist(p, dist);
	p += 20;

	if (nlists) {
		p += lws_snprintf((char *)p, 16, "5:nodes%u:",
				  (unsigned int)nlists * 28);
		for (k = 0; k < nlists; k++) {
			int m = lists[k];

			/* lws nodes list entry: type, len, id, ip, port */
			*p++ = LWS_DHT_HASH_TYPE_SHA1;
			*p++ = 20;
			sl_id(p, m);
			p += 20;
			memcpy(p, &sa_a.sin_addr, 4);
			p += 4;
			memcpy(p, &peer[m].port, 2);
			p += 2;
		}
	}

	memcpy(p, "5:token8:TTTTTTTTe1:t4:", 23);
	p += 23;
	memcpy(p, tid, 4);
	p += 4;
	memcpy(p, "1:y1:re", 7);
	p += 7;

	sl_sendto(n, q, lws_ptr_diff_size_t(p, q));
}

/* node n's answer to the get_peers with tid, listing what it lists */

static void
sl_answer(int n, const uint8_t *tid)
{
	sl_answer_as(n, sl_node[n].dist, tid, sl_node[n].lists,
		     sl_node[n].nlists);
}

/*
 * X answers every get_peers as an id other than the one A has it as, with Vs
 * of its own for each of its first SW_ANSWERS answers
 */

static void
sw_answer(int n, const uint8_t *tid)
{
	uint8_t lists[3];
	int k;

	if (n != SW_X) {
		if (n < SW_V0)
			/* the seeds answer, listing nothing */
			sl_answer_as(n, sw_dist[n], tid, NULL, 0);
		return;
	}

	if (sl.x_answers >= SW_ANSWERS)
		sl_answer_as(n, SW_X_AS, tid, NULL, 0);
	else {
		for (k = 0; k < 3; k++)
			lists[k] = (uint8_t)(SW_V0 + sl.x_answers * 3 + k);
		sl_answer_as(n, SW_X_AS, tid, lists, 3);
	}
	sl.x_answers++;
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	void *in, size_t len)
{
	const uint8_t *buf = (const uint8_t *)in;
	const struct lws_udp *udp;
	ssize_t at;
	int n;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_a.sin_port)
		return 0;

	for (n = 0; n < sl_count; n++)
		if (peer[n].wsi == wsi)
			break;
	if (n == sl_count)
		return 0;

	/* only A's get_peers are answered: its pings and find_nodes are not */
	at = sl_find(buf, len, "1:q9:get_peers1:t4:");
	if (at < 0 || (size_t)at + 23 > len)
		return 0;

	peer[n].asked++;

	if (sw) {
		sw_answer(n, buf + at + 19);
		return 0;
	}

	if (n == SL_D)
		return 0;

	if (n == SL_L && !sl.l_answered) {
		/* L holds its first answer until the list is full */
		memcpy(sl.l_tid, buf + at + 19, 4);
		sl.l_asked = 1;
		return 0;
	}

	sl_answer(n, buf + at + 19);

	return 0;
}

struct sl_tally {
	int		replied;	/* candidates but L that answered */
	int		l_present, l_replied, d_present;
	int		x_replied, x_old_replied; /* id-switch */
};

static int
sl_node_cb(void *user, const lws_dht_node_info_t *ni)
{
	struct sl_tally *t = (struct sl_tally *)user;
	int n = sl_peer_of(ni->sa);

	if (sw) {
		if (n == SW_X && ni->replied >= 0 && ni->id &&
		    ni->id->len == 20) {
			if (ni->id->id[19] == (SL_TARGET ^ SW_X_AS))
				t->x_replied = 1;
			else
				t->x_old_replied = 1;
		}
		return 0;
	}

	if (n == SL_L) {
		t->l_present = 1;
		t->l_replied = ni->replied >= 0;
	} else if (n == SL_D)
		t->d_present = 1;
	else if (n >= 0 && ni->replied >= 0)
		t->replied++;

	return 0;
}

static int
sl_tally(struct sl_tally *t)
{
	memset(t, 0, sizeof(*t));

	return lws_dht_foreach_search_node(dht_a, target, AF_INET, sl_node_cb,
					   t);
}

static void
cb_a(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	struct sl_tally t;

	if (event != LWS_DHT_EVENT_SEARCH_DONE || !info_hash || !target ||
	    info_hash->len != target->len ||
	    memcmp(info_hash->id, target->id, target->len))
		return;

	sl.done = 1;
	if (sl_tally(&t) >= 0) {
		sl.done_l = t.l_present && t.l_replied;
		sl.done_x = t.x_replied;
		sl.done_x_old = t.x_old_replied;
	}
}

/* how many of X's Vs A asked */

static int
sw_vs_asked(void)
{
	int n, c = 0;

	for (n = SW_V0; n < SW_COUNT; n++)
		if (peer[n].asked)
			c++;

	return c;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	static const char ping_head[] = "d1:ad2:id20:",
			  ping_tail[] = "e1:q4:ping1:t2:pp1:y1:qe";
	struct sl_tally t;
	uint8_t q[64];
	int n;

	switch (sl.state) {
	case 0: /* the seeds make themselves known to A, as any node can */
		for (n = sw ? SW_X : SL_S0;
		     n < (sw ? SW_V0 : SL_S0 + SL_SEEDS); n++) {
			memcpy(q, ping_head, sizeof(ping_head) - 1);
			sl_id(q + sizeof(ping_head) - 1, n);
			memcpy(q + sizeof(ping_head) - 1 + 20, ping_tail,
			       sizeof(ping_tail) - 1);
			sl_sendto(n, q, sizeof(ping_head) - 1 + 20 +
					sizeof(ping_tail) - 1);
		}
		sl.state++;
		break;

	case 1: /* give A a moment to have taken them into its table */
		if (++sl.polls < 5)
			break;
		if (lws_dht_search(dht_a, target, 0, AF_INET, cb_a, NULL) < 0) {
			lwsl_err("%s: lws_dht_search failed\n", __func__);
			goto finish;
		}
		sl.state = sw ? 10 : sl.state + 1;
		break;

	case 2: /* L answers once the 13 others did */
		if (sl_tally(&t) < 0) {
			lwsl_err("%s: A has no search for the target\n",
				 __func__);
			goto finish;
		}
		if (!sl.l_asked || t.replied != SL_COUNT - 2 || t.l_replied)
			break;

		lwsl_user("%s: search full, %d answered, L answers listing "
			  "D\n", __func__, t.replied);
		sl.l_answered = 1;
		sl_answer(SL_L, sl.l_tid);
		sl.polls = 0;
		sl.state++;
		break;

	case 3: /* L's answer must have been kept */
		if (++sl.polls < 3)
			break;
		if (sl_tally(&t) < 0)
			goto finish;
		if (t.l_present && t.l_replied)
			sl.l_kept = 1;
		else
			sl.l_lost = 1;
		lwsl_user("%s: after L's answer: L present %d, answered %d, "
			  "D present %d\n", __func__, t.l_present, t.l_replied,
			  t.d_present);
		sl.state++;
		break;

	case 4: /* the search must complete, without asking D again */
		if (peer[SL_D].asked > SL_MAX_ASKS) {
			lwsl_err("%s: D asked %d times\n", __func__,
				 peer[SL_D].asked);
			goto finish;
		}
		if (sl.done) {
			retcode = 0;
			goto finish;
		}
		break;

	case 10: /* id-switch: X must introduce once, the search complete */
		if (sw_vs_asked() > 3) {
			lwsl_err("%s: %d of X's Vs asked\n", __func__,
				 sw_vs_asked());
			goto finish;
		}
		if (sl.done) {
			retcode = 0;
			goto finish;
		}
		break;
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SL_POLL_US);

	return;

finish:
	lws_default_loop_exit(cx);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: the search did not complete\n", __func__);
	retcode = 1;
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "sl-peer", cb_peer, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	struct sockaddr_in sin;
#if defined(WIN32)
	int slen;
#else
	socklen_t slen;
#endif
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	int port_a = 0, n = 0;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-a")))
		port_a = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "--case"))) {
		if (strcmp(p, "id-switch")) {
			lwsl_err("unknown --case %s\n", p);
			return 1;
		}
		sw = 1;
	}
	sl_count = sw ? SW_COUNT : SL_COUNT;

	if (port_a < 1 || port_a > 65535) {
		lwsl_err("usage: --port-a <udp port> [--case id-switch]\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht search with %s\n", sw ?
		  "a node answering as another id" : "a node that is gone");

	signal(SIGINT, sigint_handler);

	memset(&sa_a, 0, sizeof(sa_a));
	sa_a.sin_family = AF_INET;
	sa_a.sin_port = htons((uint16_t)port_a);
	sa_a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	memset(idb, SL_TARGET, sizeof(idb));
	target = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idb);
	if (!target)
		return 1;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	/* the raw nodes and the DHT need more than the defaults' fds */
	info.fd_limit_per_thread = 0;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		goto bail1;
	}

	info.vhost_name = "dht-sl-a";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(idb, SL_ID_A, sizeof(idb));
	memset(&di, 0, sizeof(di));
	di.allow_private_ads	= 1; /* everything is on loopback */
	di.vhost		= vh;
	di.cb			= cb_a;
	di.name			= "sl-a";
	di.port			= port_a;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_a = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht_a) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	/*
	 * each node on a port of its own, which it learns from the kernel:
	 * without LWS_CAUDP_RANDOM_PORT the socket sets SO_REUSEADDR, and two
	 * of them can be given the same port (G-626)
	 */
	for (n = 0; n < sl_count; n++) {
		peer[n].wsi = lws_create_adopt_udp(vh, "127.0.0.1", 0,
						   LWS_CAUDP_BIND |
						   LWS_CAUDP_RANDOM_PORT,
						   protocols[1].name, NULL,
						   NULL, NULL, NULL, "sl-peer");
		slen = sizeof(sin);
		if (!peer[n].wsi ||
		    getsockname(lws_get_socket_fd(peer[n].wsi),
				(struct sockaddr *)&sin, &slen) ||
		    sin.sin_family != AF_INET || !sin.sin_port) {
			lwsl_err("raw udp socket creation failed\n");
			goto bail;
		}
		peer[n].port = sin.sin_port;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, SL_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SL_POLL_US);

	n = 0;
	while (n >= 0)
		n = lws_service(cx, 0);

	if (sw) {
		lwsl_user("X asked %d times, %d of its Vs asked, search "
			  "completed %d with X as its new id %d (old id %d)\n",
			  peer[SW_X].asked, sw_vs_asked(), sl.done, sl.done_x,
			  sl.done_x_old);

		if (peer[SW_X].asked != 1) {
			lwsl_err("X was asked again after it answered\n");
			retcode = 1;
		}
		if (sw_vs_asked() > 3) {
			lwsl_err("X put in more than its first answer's Vs\n");
			retcode = 1;
		}
		if (!sl.done || !sl.done_x || sl.done_x_old) {
			lwsl_err("the search did not complete on X as its "
				 "new id\n");
			retcode = 1;
		}
	} else {
		lwsl_user("L's answer kept %d (lost %d), D asked %d times, "
			  "search completed %d with L %d\n", sl.l_kept,
			  sl.l_lost, peer[SL_D].asked, sl.done, sl.done_l);

		if (!sl.l_kept) {
			lwsl_err("L's answer was not kept\n");
			retcode = 1;
		}
		if (peer[SL_D].asked > SL_MAX_ASKS) {
			lwsl_err("D was asked again after it failed\n");
			retcode = 1;
		}
		if (!sl.done || !sl.done_l) {
			lwsl_err("the search did not complete on L\n");
			retcode = 1;
		}
	}

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);
bail1:
	lws_dht_hash_destroy(&target);

	return retcode;
}
