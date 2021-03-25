/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 * The lsquic bits of this are modified from lsquic http_client example,
 * originally
 *
 *    Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.
 *
 * lsquic license is also MIT same as lws.
 */

#if __GNUC__
#undef _GNU_SOURCE
#define _GNU_SOURCE     /* For struct in6_pktinfo */
#undef __USE_GNU
#define __USE_GNU
#endif

#include <sys/queue.h>

#include <private-lib-core.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define LITESPEED_ID "lsquic" "/" TOSTRING(LSQUIC_MAJOR_VERSION) "." \
		TOSTRING(LSQUIC_MINOR_VERSION) "." TOSTRING(LSQUIC_PATCH_VERSION)

/* TODO: presumably it's the same on FreeBSD, test it.
 * See https://github.com/quicwg/base-drafts/wiki/ECN-in-QUIC
 */
#if __linux__ || defined(__FreeBSD__)
#define ECN_SUPPORTED 1
#else
#define ECN_SUPPORTED 0
#endif

#if __linux__
#   define NDROPPED_SZ CMSG_SPACE(sizeof(uint32_t))  /* SO_RXQ_OVFL */
#else
#   define NDROPPED_SZ 0
#endif

#if __linux__ && defined(IP_RECVORIGDSTADDR)
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#elif WIN32
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#elif __linux__
#   define DST_MSG_SZ sizeof(struct in_pktinfo)
#else
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#endif

#if ECN_SUPPORTED
#define ECN_SZ CMSG_SPACE(sizeof(int))
#else
#define ECN_SZ 0
#endif
#define MAX_PACKET_SZ 0xffff
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, \
		sizeof(struct in6_pktinfo))) + NDROPPED_SZ + ECN_SZ)

enum ctl_what
{
	CW_SENDADDR     = 1 << 0,
#if defined(ECN_SUPPORTED)
	CW_ECN          = 1 << 1,
#endif
};

struct packets_in
{
	unsigned char           *packet_data;
	unsigned char           *ctlmsg_data;
#ifndef WIN32
	struct iovec            *vecs;
#else
	WSABUF                  *vecs;
#endif
#if ECN_SUPPORTED
	int                     *ecn;
#endif
	struct sockaddr_storage *local_addresses,
	*peer_addresses;
	unsigned                 n_alloc;
	unsigned                 data_sz;
};


struct read_iter
{
	struct service_port     *ri_sport;
	unsigned                 ri_idx;    /* Current element */
	unsigned                 ri_off;    /* Offset into packet_data */
};


extern struct lsquic_stream_if http_client_if, http_server_if;
extern struct priority_spec *priority_specs;

enum rop { ROP_OK, ROP_NOROOM, ROP_ERROR, };

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif


/* Replace IP address part of `sa' with that provided in ancillary messages
 * in `msg'.
 */
static void
proc_ancillary (
#ifndef WIN32
		struct msghdr
#else
		WSAMSG
#endif
		*msg, struct sockaddr_storage *storage
#if __linux__
		, uint32_t *n_dropped
#endif
#if ECN_SUPPORTED
		, int *ecn
#endif
)
{
	const struct in6_pktinfo *in6_pkt;
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
				cmsg->cmsg_type  ==
#if __linux__ && defined(IP_RECVORIGDSTADDR)
						IP_ORIGDSTADDR
#elif __linux__ || WIN32 || __APPLE__
						IP_PKTINFO
#else
						IP_RECVDSTADDR
#endif
		) {
#if __linux__ && defined(IP_RECVORIGDSTADDR)
			memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
#elif WIN32
			const struct in_pktinfo *in_pkt;
			in_pkt = (void *) WSA_CMSG_DATA(cmsg);
			((struct sockaddr_in *) storage)->sin_addr = in_pkt->ipi_addr;
#elif __linux__ || __APPLE__
			const struct in_pktinfo *in_pkt;
			in_pkt = (void *) CMSG_DATA(cmsg);
			((struct sockaddr_in *) storage)->sin_addr = in_pkt->ipi_addr;
#else
			memcpy(&((struct sockaddr_in *) storage)->sin_addr,
					CMSG_DATA(cmsg), sizeof(struct in_addr));
#endif
		}
		else if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type  == IPV6_PKTINFO)
		{
#ifndef WIN32
			in6_pkt = (void *) CMSG_DATA(cmsg);
#else
			in6_pkt = (void *) WSA_CMSG_DATA(cmsg);
#endif
			((struct sockaddr_in6 *) storage)->sin6_addr =
					in6_pkt->ipi6_addr;
		}
#if __linux__
		else if (cmsg->cmsg_level == SOL_SOCKET &&
				cmsg->cmsg_type  == SO_RXQ_OVFL)
			memcpy(n_dropped, CMSG_DATA(cmsg), sizeof(*n_dropped));
#endif
#if ECN_SUPPORTED
		else if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
				|| (cmsg->cmsg_level == IPPROTO_IPV6
						&& cmsg->cmsg_type == IPV6_TCLASS))
		{
			memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
			*ecn &= IPTOS_ECN_MASK;
		}
#ifdef __FreeBSD__
else if (cmsg->cmsg_level == IPPROTO_IP
		&& cmsg->cmsg_type == IP_RECVTOS)
{
	unsigned char tos;
	memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
	*ecn = tos & IPTOS_ECN_MASK;
}
#endif
#endif
	}
}

/* Sometimes it is useful to impose an artificial limit for testing */
static unsigned
packet_out_limit (void)
{
	const char *env = getenv("LSQUIC_PACKET_OUT_LIMIT");
	if (env)
		return (unsigned int)atoi(env);
	else
		return 0;
}

void
prog_sport_cant_send (struct lws_context_role_lsq *prog, int fd)
{
	//	assert(!prog->prog_send);
	lwsl_warn("%s: cannot send: register on_write event\n", __func__);
	//	prog->prog_send = event_new(prog->prog_eb, fd, EV_WRITE, send_unsent, prog);
	//	event_add(prog->prog_send, NULL);
}

static void
setup_control_msg (
#ifndef WIN32
		struct msghdr
#else
		WSAMSG
#endif
		*msg, enum ctl_what cw,
		const struct lsquic_out_spec *spec, unsigned char *buf, size_t bufsz)
{
	struct cmsghdr *cmsg;
	struct sockaddr_in *local_sa;
	struct sockaddr_in6 *local_sa6;
#if defined(__linux__) || defined(__APPLE__) || defined(WIN32)
	struct in_pktinfo info;
#endif
	struct in6_pktinfo info6;
	size_t ctl_len;

#ifndef WIN32
	msg->msg_control    = buf;
	msg->msg_controllen = bufsz;
#else
	msg->Control.buf    = (char*)buf;
	msg->Control.len = bufsz;
#endif

	/* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
	 * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
	 */
	memset(buf, 0, bufsz);

	ctl_len = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cw & CW_SENDADDR) {
			if (AF_INET == spec->dest_sa->sa_family) {
				local_sa = (struct sockaddr_in *) spec->local_sa;
#if defined(__linux__) || defined(__APPLE__)
				memset(&info, 0, sizeof(info));
				info.ipi_spec_dst = local_sa->sin_addr;
				cmsg->cmsg_level    = IPPROTO_IP;
				cmsg->cmsg_type     = IP_PKTINFO;
				cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
#elif defined(WIN32)
				memset(&info, 0, sizeof(info));
				info.ipi_addr = local_sa->sin_addr;
				cmsg->cmsg_level    = IPPROTO_IP;
				cmsg->cmsg_type     = IP_PKTINFO;
				cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
				#else
					cmsg->cmsg_level    = IPPROTO_IP;
				cmsg->cmsg_type     = IP_SENDSRCADDR;
				cmsg->cmsg_len      = CMSG_LEN(sizeof(local_sa->sin_addr));
				ctl_len += CMSG_SPACE(sizeof(local_sa->sin_addr));
				memcpy(CMSG_DATA(cmsg), &local_sa->sin_addr,
						sizeof(local_sa->sin_addr));
#endif
			} else {
				local_sa6 = (struct sockaddr_in6 *) spec->local_sa;
				memset(&info6, 0, sizeof(info6));
				info6.ipi6_addr = local_sa6->sin6_addr;
				cmsg->cmsg_level    = IPPROTO_IPV6;
				cmsg->cmsg_type     = IPV6_PKTINFO;
				cmsg->cmsg_len      = CMSG_LEN(sizeof(info6));
#ifndef WIN32
memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
#else
memcpy(WSA_CMSG_DATA(cmsg), &info6, sizeof(info6));
#endif
ctl_len += CMSG_SPACE(sizeof(info6));
			}
			cw = cw & (unsigned int)(~CW_SENDADDR);
		}
#if defined(ECN_SUPPORTED)
		else if (cw & CW_ECN)
		{
			if (AF_INET == spec->dest_sa->sa_family)
			{
				const
#if defined(__FreeBSD__)
			unsigned char
#else
			int
#endif
					tos = spec->ecn;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type  = IP_TOS;
				cmsg->cmsg_len   = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			} else {
				const int tos = spec->ecn;

				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type  = IPV6_TCLASS;
				cmsg->cmsg_len   = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			}
			cw = cw & (unsigned int)(~CW_ECN);
		}
#endif
		else
			assert(0);
	}

#ifndef WIN32
	msg->msg_controllen = ctl_len;
#else
	msg->Control.len = ctl_len;
#endif
}

static int
send_packets_one_by_one (const struct lsquic_out_spec *specs, unsigned count)
{
	const struct service_port *sport;
	enum ctl_what cw;
	unsigned n;
	int s = 0;
#ifndef WIN32
	struct msghdr msg;
#else
	DWORD bytes;
	WSAMSG msg;
	LPWSABUF pWsaBuf = NULL;
#endif
	union {
		/* cmsg(3) recommends union for proper alignment */
#if __linux__ || WIN32
#	define SIZE1 sizeof(struct in_pktinfo)
#else
#	define SIZE1 sizeof(struct in_addr)
#endif
	unsigned char buf[CMSG_SPACE(MAX(SIZE1, sizeof(struct in6_pktinfo)))
#if ECN_SUPPORTED
		                  + CMSG_SPACE(sizeof(int))
#endif
		                  ];
		struct cmsghdr cmsg;
	} ancil;
	uintptr_t ancil_key, prev_ancil_key;

	if (!count)
		return 0;

	const unsigned orig_count = count;
	const unsigned out_limit = packet_out_limit();
	if (out_limit && count > out_limit)
		count = out_limit;

	n = 0;
	prev_ancil_key = 0;
#ifdef WIN32
#define MAX_OUT_BATCH_SIZE 1024
	pWsaBuf = malloc(sizeof(*pWsaBuf)*MAX_OUT_BATCH_SIZE*2);
	if (NULL == pWsaBuf) {
		return -1;
	}
#endif

	do
	{
		sport = specs[n].peer_ctx;
#if defined(LSQUIC_PREFERRED_ADDR)
		if (sport->sp_prog->prog_flags & PROG_SEARCH_ADDRS)
			sport = find_sport(sport->sp_prog, specs[n].local_sa);
#endif
#ifndef WIN32
		msg.msg_name       = (void *) specs[n].dest_sa;
		msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
				sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6)),
						msg.msg_iov        = specs[n].iov;
		msg.msg_iovlen     = specs[n].iovlen;
		msg.msg_flags      = 0;
#else
		for (int i = 0; i < specs[n].iovlen; i++) {
			pWsaBuf[i].buf = specs[n].iov[i].iov_base;
			pWsaBuf[i].len = specs[n].iov[i].iov_len;
		}

		msg.name           = (void *) specs[n].dest_sa;
		msg.namelen        = (AF_INET == specs[n].dest_sa->sa_family ?
				sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6));
		msg.dwBufferCount  = specs[n].iovlen;
		msg.lpBuffers      = pWsaBuf;
		msg.dwFlags        = 0;
#endif
		if ((sport->sp_flags & SPORT_SERVER) && specs[n].local_sa->sa_family) {
			cw = CW_SENDADDR;
			ancil_key = (uintptr_t) specs[n].local_sa;
			assert(0 == (ancil_key & 3));
		} else {
			cw = 0;
			ancil_key = 0;
		}
#if defined(ECN_SUPPORTED)
		if (sport->context->lsq.api.ea_settings->es_ecn && specs[n].ecn) {
			cw |= CW_ECN;
			ancil_key = ancil_key | (unsigned int)specs[n].ecn;
		}
	#endif
		if (cw && prev_ancil_key == ancil_key)
		{
			/* Reuse previous ancillary message */
			;
		}
		else if (cw)
		{
			prev_ancil_key = ancil_key;
			setup_control_msg(&msg, cw, &specs[n], ancil.buf, sizeof(ancil.buf));
		}
		else
		{
			prev_ancil_key = 0;
	#ifndef WIN32
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
	#else
			msg.Control.buf = NULL;
			msg.Control.len = 0;
	#endif
		}
	#ifndef WIN32
		s = (int)sendmsg(sport->fd, &msg, 0);
	#else
		s = pfnWSASendMsg(sport->fd, &msg, 0, &bytes, NULL, NULL);
	#endif
		if (s < 0)
		{
	#ifndef WIN32
			printf("sendto failed: %s", strerror(errno));
	#else
			printf("sendto failed: %s", WSAGetLastError());
	#endif
			break;
		}
		++n;
	} while (n < count);

	if (n < orig_count)
		prog_sport_cant_send(&sport->context->lsq, sport->fd);

#ifdef WIN32
	if (NULL != pWsaBuf) {
		free(pWsaBuf);
		pWsaBuf = NULL;
	}
#endif

	if (n > 0)
	{
		if (n < orig_count && out_limit)
			errno = EAGAIN;
		return (int)n;
	}


	assert(s < 0);

	return -1;
}

static enum rop
read_one_packet (struct read_iter *iter)
{
	unsigned char *ctl_buf;
	struct packets_in *packs_in;
#if __linux__
	uint32_t n_dropped;
#endif
#ifndef WIN32
	ssize_t nread;
#else
	DWORD nread;
	int socket_ret;
#endif
	struct sockaddr_storage *local_addr;
	struct service_port *sport;

	sport = iter->ri_sport;
	packs_in = sport->packs_in;

	if (iter->ri_idx >= packs_in->n_alloc ||
			iter->ri_off + MAX_PACKET_SZ > packs_in->data_sz)
	{
		lwsl_notice("%s: out of room in packets_in\n", __func__);
		return ROP_NOROOM;
	}

#ifndef WIN32
	packs_in->vecs[iter->ri_idx].iov_base = packs_in->packet_data + iter->ri_off;
	packs_in->vecs[iter->ri_idx].iov_len  = MAX_PACKET_SZ;
#else
	packs_in->vecs[iter->ri_idx].buf = (char*)packs_in->packet_data + iter->ri_off;
	packs_in->vecs[iter->ri_idx].len = MAX_PACKET_SZ;
#endif

#ifndef WIN32
	top:
#endif
	ctl_buf = packs_in->ctlmsg_data + iter->ri_idx * CTL_SZ;

#ifndef WIN32
	struct msghdr msg = {
			.msg_name       = &packs_in->peer_addresses[iter->ri_idx],
			.msg_namelen    = sizeof(packs_in->peer_addresses[iter->ri_idx]),
			.msg_iov        = &packs_in->vecs[iter->ri_idx],
			.msg_iovlen     = 1,
			.msg_control    = ctl_buf,
			.msg_controllen = CTL_SZ,
	};
	nread = recvmsg(sport->fd, &msg, 0);
	if (-1 == nread) {
		if (!(EAGAIN == errno || EWOULDBLOCK == errno)) {
			//            printf("recvmsg: %s", strerror(errno));
			lwsl_notice("%s: B: errno %d, sport->fd %d\n", __func__, errno, sport->fd);
		}
		return ROP_ERROR;
	}

	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))
	{
		if (msg.msg_flags & MSG_TRUNC)
			printf("packet truncated - drop it");
		if (msg.msg_flags & MSG_CTRUNC)
			printf("packet's auxilicary data truncated - drop it");
		goto top;
	}
#else
	WSAMSG msg = {
			.name       = (LPSOCKADDR)&packs_in->peer_addresses[iter->ri_idx],
			.namelen    = sizeof(packs_in->peer_addresses[iter->ri_idx]),
			.lpBuffers        = &packs_in->vecs[iter->ri_idx],
			.dwBufferCount     = 1,
			.Control = {CTL_SZ,(char*)ctl_buf}
	};
	socket_ret = pfnWSARecvMsg(sport->fd, &msg, &nread, NULL, NULL);
	if (SOCKET_ERROR == socket_ret) {
		if (WSAEWOULDBLOCK != WSAGetLastError())
			printf("recvmsg: %d", WSAGetLastError());
		return ROP_ERROR;
	}
#endif

	local_addr = &packs_in->local_addresses[iter->ri_idx];
	memcpy(local_addr, &sport->sp_local_addr, sizeof(*local_addr));
#if __linux__
	n_dropped = 0;
#endif
#if ECN_SUPPORTED
	packs_in->ecn[iter->ri_idx] = 0;
#endif
	proc_ancillary(&msg, local_addr
#if __linux__
			, &n_dropped
#endif
#if ECN_SUPPORTED
			, &packs_in->ecn[iter->ri_idx]
#endif
	);
#if defined(LSQUIC_ECN_BLACK_HOLE) && defined(ECN_SUPPORTED)
	{
		const char *s;
		s = getenv("LSQUIC_ECN_BLACK_HOLE");
		if (s && atoi(s) && packs_in->ecn[iter->ri_idx])
		{
			LSQ_NOTICE("ECN blackhole: drop packet");
			return ROP_OK;
		}
	}
#endif
#if defined(__linux__)
	if (sport->drop_init)
	{
		if (sport->n_dropped < n_dropped)
			printf("dropped %u packets", n_dropped - sport->n_dropped);
	}
	else
		sport->drop_init = 1;
	sport->n_dropped = n_dropped;
#endif

#if !defined(WIN32)
	packs_in->vecs[iter->ri_idx].iov_len = (size_t)nread;
#else
	packs_in->vecs[iter->ri_idx].len = nread;
#endif
	iter->ri_off += (unsigned int)nread;
	iter->ri_idx += 1;

	return ROP_OK;
}


#if defined(HAVE_RECVMMSG)
static enum rop
read_using_recvmmsg (struct read_iter *iter)
{
#if __linux__
	uint32_t n_dropped;
#endif
	int s;
	unsigned n;
	struct sockaddr_storage *local_addr;
	struct service_port *const sport = iter->ri_sport;
	struct packets_in *const packs_in = sport->packs_in;
	/* XXX TODO We allocate this array on the stack and initialize the
	 * headers each time the function is invoked.  This is suboptimal.
	 * What we should really be doing is allocate mmsghdrs as part of
	 * packs_in and initialize it there.  While we are at it, we should
	 * make packs_in shared between all service ports.
	 */
	struct mmsghdr mmsghdrs[ packs_in->n_alloc  ];

	/* Sanity check: we assume that the iterator is reset */
	assert(iter->ri_off == 0 && iter->ri_idx == 0);

	/* Initialize mmsghdrs */
	for (n = 0; n < sizeof(mmsghdrs) / sizeof(mmsghdrs[0]); ++n)
	{
		packs_in->vecs[n].iov_base = packs_in->packet_data + MAX_PACKET_SZ * n;
		packs_in->vecs[n].iov_len  = MAX_PACKET_SZ;
		mmsghdrs[n].msg_hdr = (struct msghdr) {
			.msg_name       = &packs_in->peer_addresses[n],
					.msg_namelen    = sizeof(packs_in->peer_addresses[n]),
					.msg_iov        = &packs_in->vecs[n],
					.msg_iovlen     = 1,
					.msg_control    = packs_in->ctlmsg_data + CTL_SZ * n,
					.msg_controllen = CTL_SZ,
		};
	}

	/* Read packets */
	s = recvmmsg(sport->fd, mmsghdrs, n, 0, NULL);
	if (s < 0)
	{
		if (!(EAGAIN == errno || EWOULDBLOCK == errno))
			printf("recvmmsg: %s", strerror(errno));
		return ROP_ERROR;
	}

	/* Process ancillary data and update vecs */
	for (n = 0; n < (unsigned) s; ++n)
	{
		local_addr = &packs_in->local_addresses[n];
		memcpy(local_addr, &sport->sp_local_addr, sizeof(*local_addr));
#if __linux__
		n_dropped = 0;
#endif
#if ECN_SUPPORTED
		packs_in->ecn[n] = 0;
#endif
		proc_ancillary(&mmsghdrs[n].msg_hdr, local_addr
#if __linux__
				, &n_dropped
#endif
#if ECN_SUPPORTED
				, &packs_in->ecn[n]
#endif
		);
#if __linux__
		if (sport->drop_init)
		{
			if (sport->n_dropped < n_dropped)
				printf("dropped %u packets", n_dropped - sport->n_dropped);
		}
		else
			sport->drop_init = 1;
		sport->n_dropped = n_dropped;
#endif
		packs_in->vecs[n].iov_len = mmsghdrs[n].msg_len;
	}

	iter->ri_idx = n;

	return n == sizeof(mmsghdrs) / sizeof(mmsghdrs[0]) ? ROP_NOROOM : ROP_OK;
}


#endif

void
prog_process_conns (struct lws_context *cx);

static void
prog_timer_handler (lws_sorted_usec_list_t *sul)
{
	struct lws_context_role_lsq *lsq = lws_container_of(sul,
					struct lws_context_role_lsq, sul_timer);

	//if (!prog_is_stopped())
	prog_process_conns(lsq->context);
}

void
prog_process_conns (struct lws_context *cx)
{
	int diff;

	lsquic_engine_process_conns(cx->lsq.engine);

	if (!lsquic_engine_earliest_adv_tick(cx->lsq.engine, &diff))
		return;

	if (diff < 0 ||
	    (unsigned)diff < cx->lsq.settings.es_clock_granularity)
		diff = (int)cx->lsq.settings.es_clock_granularity;

	//if (!prog_is_stopped())
	lws_sul_schedule(cx, 0, &cx->lsq.sul_timer,
			 prog_timer_handler, (lws_usec_t)diff);
}

static void
read_handler (int fd, short flags, void *ctx)
{
	struct service_port *sport = ctx;
	lsquic_engine_t *const engine = sport->engine;
	struct packets_in *packs_in = sport->packs_in;
	struct read_iter iter;
	unsigned n, n_batches;
	/* Save the value in case program is stopped packs_in is freed: */
	const unsigned n_alloc = packs_in->n_alloc;
	enum rop rop;

	n_batches = 0;
	iter.ri_sport = sport;

	sport->context->lsq.read_count += 1;
	do
	{
		iter.ri_off = 0;
		iter.ri_idx = 0;

		//     lwsl_notice("%s: do\n", __func__);

#if HAVE_RECVMMSG
		if (sport->context->lsq.use_recvmmsg)
			rop = read_using_recvmmsg(&iter);
		else
#endif
			do
				rop = read_one_packet(&iter);
			while (ROP_OK == rop);

		if (UNLIKELY(ROP_ERROR == rop && (sport->sp_flags & SPORT_CONNECT)
				&& errno == ECONNREFUSED))
		{
			printf("connection refused: exit program\n");
			// prog_cleanup(sport->sp_prog);
			exit(1);
		}

		n_batches += iter.ri_idx > 0;

		for (n = 0; n < iter.ri_idx; ++n)
			if (0 > lsquic_engine_packet_in(engine,
#ifndef WIN32
				packs_in->vecs[n].iov_base,
				packs_in->vecs[n].iov_len,
#else
				(const unsigned char *) packs_in->vecs[n].buf,
				packs_in->vecs[n].len,
#endif
				(struct sockaddr *) &packs_in->local_addresses[n],
				(struct sockaddr *) &packs_in->peer_addresses[n],
				sport,
#if ECN_SUPPORTED
				packs_in->ecn[n]
#else
					      0
#endif
			))
				break;

		if (n > 0)
			prog_process_conns(sport->context);
	}
	while (ROP_NOROOM == rop);

	if (n_batches)
		n += n_alloc * (n_batches - 1);

	lwsl_info("read %u packet%.*s in %u batch%s\n", n, n != 1,
			"s", n_batches, n_batches != 1 ? "es" : "");
}

static int
rops_handle_POLLIN_lsq(struct lws_context_per_thread *pt, struct lws *wsi,
		struct lws_pollfd *pollfd)
{
	if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
		return LWS_HPI_RET_HANDLED;

	read_handler(wsi->desc.sockfd, 0, wsi->lsq_sport);

	return LWS_HPI_RET_HANDLED;
}

#if defined(LWS_WITH_SERVER)
static int
rops_adoption_bind_lsq(struct lws *wsi, int type, const char *vh_prot_name)
{

	// lwsl_notice("%s: bind type %d\n", __func__, type);

	/* no http but socket... must be raw skt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
			((type & _LWS_ADOPT_FINISH) && (!(type & LWS_ADOPT_FLAG_UDP))))
		return 0; /* no match */

#if defined(LWS_WITH_UDP)
	if ((type & (LWS_ADOPT_FLAG_UDP |LWS_ADOPT_FLAG_QUIC)) && !wsi->udp) {
		/*
		 * these can be >128 bytes, so just alloc for UDP
		 */
		wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");
		if (!wsi->udp)
			return 0;
		memset(wsi->udp, 0, sizeof(*wsi->udp));
	}
#endif

	lws_role_transition(wsi, 0, (type & LWS_ADOPT_ALLOW_SSL) ? LRS_SSL_INIT :
			LRS_ESTABLISHED, &role_ops_lsq);

	lwsl_err("%s: vh prot name %s\n", __func__, vh_prot_name);
	if (vh_prot_name)
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);
	else
		/* this is the only time he will transition */
		lws_bind_protocol(wsi,
				&wsi->a.vhost->protocols[wsi->a.vhost->raw_protocol_index],
				__func__);

	return 1; /* bound */
}
#endif



void
pba_init (struct packout_buf_allocator *pba, unsigned max)
{
	SLIST_INIT(&pba->free_packout_bufs);
	pba->max   = max;
	pba->n_out = 0;
}


void *
pba_allocate (void *packout_buf_allocator, void *peer_ctx,
		lsquic_conn_ctx_t *conn_ctx, unsigned short size, char is_ipv6)
{
	struct packout_buf_allocator *const pba = packout_buf_allocator;
	struct packout_buf *pb;

	if (pba->max && pba->n_out >= pba->max)
	{
		printf("# outstanding packout bufs reached the limit of %u, "
				"returning NULL\n", pba->max);
		return NULL;
	}

#if LSQUIC_USE_POOLS
	pb = SLIST_FIRST(&pba->free_packout_bufs);
	if (pb && size <= PBA_SIZE_THRESH)
		SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
	else if (size <= PBA_SIZE_THRESH)
		pb = malloc(PBA_SIZE_MAX);
	else
		pb = malloc(sizeof(uintptr_t) + size);
#else
	pb = malloc(sizeof(uintptr_t) + size);
#endif

	if (pb)
	{
		* (uintptr_t *) pb = size;
		++pba->n_out;
		return (uintptr_t *) pb + 1;
	}
	else
		return NULL;
}

#if HAVE_SENDMMSG
static int
send_packets_using_sendmmsg (const struct lsquic_out_spec *specs,
		unsigned count)
{
#ifndef NDEBUG
	{
		/* This only works for a single port!  If the specs contain more
		 * than one socket, this function does *NOT* work.  We check it
		 * here just in case:
		 */
		void *ctx;
		unsigned i;
		for (i = 1, ctx = specs[i].peer_ctx;
				i < count;
				ctx = specs[i].peer_ctx, ++i)
			assert(ctx == specs[i - 1].peer_ctx);
	}
#endif

	const struct service_port *const sport = specs[0].peer_ctx;
	const int fd = sport->fd;
	enum ctl_what cw;
	unsigned i;
	int s, saved_errno;
	uintptr_t ancil_key, prev_ancil_key;
	struct mmsghdr mmsgs[1024];
	union {
		/* cmsg(3) recommends union for proper alignment */
		unsigned char buf[ CMSG_SPACE(
				MAX(
#if defined(__linux__)
						sizeof(struct in_pktinfo)
#else
						sizeof(struct in_addr)
#endif
						, sizeof(struct in6_pktinfo))
		)
#if defined(ECN_SUPPORTED)
		                   + CMSG_SPACE(sizeof(int))
#endif
		                   ];
		struct cmsghdr cmsg;
	} ancil [ sizeof(mmsgs) / sizeof(mmsgs[0]) ];

	prev_ancil_key = 0;
	for (i = 0; i < count && i < sizeof(mmsgs) / sizeof(mmsgs[0]); ++i)
	{
		mmsgs[i].msg_hdr.msg_name       = (void *) specs[i].dest_sa;
		mmsgs[i].msg_hdr.msg_namelen    = (AF_INET == specs[i].dest_sa->sa_family ?
				sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6)),
				mmsgs[i].msg_hdr.msg_iov        = specs[i].iov;
		mmsgs[i].msg_hdr.msg_iovlen     = specs[i].iovlen;
		mmsgs[i].msg_hdr.msg_flags      = 0;
		if ((sport->sp_flags & SPORT_SERVER) && specs[i].local_sa->sa_family)
		{
			cw = CW_SENDADDR;
			ancil_key = (uintptr_t) specs[i].local_sa;
			assert(0 == (ancil_key & 3));
		}
		else
		{
			cw = 0;
			ancil_key = 0;
		}
#if ECN_SUPPORTED
if (sport->context->lsq.api.ea_settings->es_ecn && specs[i].ecn)
{
	cw |= CW_ECN;
	ancil_key = ancil_key | (unsigned int)specs[i].ecn;
}
#endif
if (cw && prev_ancil_key == ancil_key)
{
	/* Reuse previous ancillary message */
	assert(i > 0);
#ifndef WIN32
	mmsgs[i].msg_hdr.msg_control    = mmsgs[i - 1].msg_hdr.msg_control;
	mmsgs[i].msg_hdr.msg_controllen = mmsgs[i - 1].msg_hdr.msg_controllen;
#else
	mmsgs[i].msg_hdr.Control.buf    = mmsgs[i - 1].msg_hdr.Control.buf;
	mmsgs[i].msg_hdr.Control.len    = mmsgs[i - 1].msg_hdr.Control.len;
#endif
}
else if (cw)
{
	prev_ancil_key = ancil_key;
	setup_control_msg(&mmsgs[i].msg_hdr, cw, &specs[i], ancil[i].buf,
			sizeof(ancil[i].buf));
}
else
{
	prev_ancil_key = 0;
#ifndef WIN32
mmsgs[i].msg_hdr.msg_control    = NULL;
mmsgs[i].msg_hdr.msg_controllen = 0;
#else
	mmsgs[i].msg_hdr.Control.buf    = NULL;
	mmsgs[i].msg_hdr.Control.len    = 0;
#endif
}
	}

	s = sendmmsg(fd, mmsgs, count, 0);
	if (s < (int) count)
	{
		saved_errno = errno;
		prog_sport_cant_send(&sport->context->lsq, sport->fd);
		if (s < 0)
		{
			printf("sendmmsg failed: %s", strerror(saved_errno));
			errno = saved_errno;
		}
		else if (s > 0)
			errno = EAGAIN;
		else
			errno = saved_errno;
	}

	return s;
}


#endif


int
sport_packets_out (void *ctx, const struct lsquic_out_spec *specs,
		unsigned count)
{
#if defined(HAVE_SENDMMSG)
	const struct lws_context_role_lsq *prog = ctx;
	if (prog->use_sendmmsg)
		return send_packets_using_sendmmsg(specs, count);
	else
#endif
		return send_packets_one_by_one(specs, count);
}


static struct packets_in *
allocate_packets_in (SOCKET_TYPE fd)
{
	struct packets_in *packs_in;
	size_t n_alloc;
	socklen_t opt_len;
	int recvsz;

	opt_len = sizeof(recvsz);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*)&recvsz, &opt_len)) {
		lwsl_warn("%s: getsockopt failed: %s", __func__, strerror(errno));
		return NULL;
	}

	n_alloc = (unsigned) recvsz / 1370;
	lwsl_info("%s: socket buffer size: %d bytes; max # packets is set to %u\n",
			__func__, recvsz, (unsigned int)n_alloc);
	recvsz += MAX_PACKET_SZ;

	packs_in = malloc(sizeof(*packs_in));
	packs_in->data_sz = (unsigned int)recvsz;
	packs_in->n_alloc = (unsigned int)n_alloc;
	packs_in->packet_data = malloc((size_t)recvsz);
	packs_in->ctlmsg_data = malloc((size_t)(n_alloc * CTL_SZ));
	packs_in->vecs = malloc(n_alloc * sizeof(packs_in->vecs[0]));
	packs_in->local_addresses = malloc(n_alloc * sizeof(packs_in->local_addresses[0]));
	packs_in->peer_addresses = malloc(n_alloc * sizeof(packs_in->peer_addresses[0]));
#if ECN_SUPPORTED
	packs_in->ecn = malloc(n_alloc * sizeof(packs_in->ecn[0]));
#endif

	return packs_in;
}

int
sport_init_client (struct service_port *sport, struct lsquic_engine *engine,
		struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct http_client_ctx * cc = (struct http_client_ctx *)context->lsq.api.ea_stream_if_ctx;
	const struct sockaddr *sa_peer = (struct sockaddr *) &sport->sas;
	//    lws_sock_file_fd_type desc;
	int saved_errno, s;
#ifndef WIN32
	int flags;
#endif
	SOCKET_TYPE sockfd;
	socklen_t socklen, peer_socklen;
	union {
		struct sockaddr_in  sin;
		struct sockaddr_in6 sin6;
	} u;
	struct sockaddr *sa_local = (struct sockaddr *) &u;
	char addr_str[0x20];
	struct path_elem *pe;

	lwsl_info("%s\n", __func__);

	if (!wsi->udp) {
		wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");
		if (!wsi->udp)
			return 0;
		memset(wsi->udp, 0, sizeof(*wsi->udp));
	}


	pe = calloc(1, sizeof(*pe));
	pe->path = "/"; // optarg;
	TAILQ_INSERT_TAIL(&cc->hcc_path_elems, pe, next_pe);

	switch (sa_peer->sa_family) {
	case AF_INET:
		socklen = sizeof(struct sockaddr_in);
		u.sin.sin_family      = AF_INET;
		u.sin.sin_addr.s_addr = INADDR_ANY;
		u.sin.sin_port        = 0;
		break;
	case AF_INET6:
		socklen = sizeof(struct sockaddr_in6);
		memset(&u.sin6, 0, sizeof(u.sin6));
		u.sin6.sin6_family = AF_INET6;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

#if defined(WIN32)
	getExtensionPtrs();
#endif
	sockfd = socket(sa_peer->sa_family, SOCK_DGRAM, 0);
	if (-1 == sockfd)
		return -1;

	if (0 != bind(sockfd, sa_local, socklen)) {
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}


	if (sport->sp_flags & SPORT_CONNECT)
	{
		peer_socklen = AF_INET == sa_peer->sa_family
				? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
		if (0 != connect(sockfd, sa_peer, peer_socklen))
		{
			saved_errno = errno;
			CLOSE_SOCKET(sockfd);
			errno = saved_errno;
			return -1;
		}
	}

	/* Make socket non-blocking */
	#ifndef WIN32
	flags = fcntl(sockfd, F_GETFL);
	if (-1 == flags) {
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}
	flags |= O_NONBLOCK;
	if (0 != fcntl(sockfd, F_SETFL, flags)) {
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}
	#else
	{
		u_long on = 1;
		ioctlsocket(sockfd, FIONBIO, &on);
	}
	#endif

	#if defined(LSQUIC_DONTFRAG_SUPPORTED)
	if (!(sport->sp_flags & SPORT_FRAGMENT_OK))
	{
		if (AF_INET == sa_local->sa_family)
		{
			int on;
	#if defined(__linux__)
			on = IP_PMTUDISC_PROBE;
			s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
					sizeof(on));
	#elif defined(WIN32)
	on = 1;
	s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, CHAR_CAST &on, sizeof(on));
	#else
	on = 1;
	s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on));
	#endif
	if (0 != s)
	{
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}
		}
	}
	#endif

	#if defined(ECN_SUPPORTED)
	{
		int on = 1;
		if (AF_INET == sa_local->sa_family)
			s = setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS,
					CHAR_CAST &on, sizeof(on));
		else
			s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS,
					CHAR_CAST &on, sizeof(on));
		if (0 != s)
		{
			saved_errno = errno;
			close(sockfd);
			errno = saved_errno;
			return -1;
		}
	}
	#endif

	if (sport->sp_flags & SPORT_SET_SNDBUF)
	{
		s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
				CHAR_CAST &sport->sp_sndbuf,
				sizeof(sport->sp_sndbuf));
		if (0 != s)
		{
			saved_errno = errno;
			CLOSE_SOCKET(sockfd);
			errno = saved_errno;
			return -1;
		}
	}

	if (sport->sp_flags & SPORT_SET_RCVBUF)
	{
		s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
				CHAR_CAST &sport->sp_rcvbuf,
				sizeof(sport->sp_rcvbuf));
		if (0 != s)
		{
			saved_errno = errno;
			CLOSE_SOCKET(sockfd);
			errno = saved_errno;
			return -1;
		}
	}

	if (0 != getsockname(sockfd, sa_local, &socklen))
	{
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}

	sport->packs_in = allocate_packets_in(sockfd);
	if (!sport->packs_in)
	{
		saved_errno = errno;
		CLOSE_SOCKET(sockfd);
		errno = saved_errno;
		return -1;
	}

	memcpy((void *) &sport->sp_local_addr, sa_local,
			sa_local->sa_family == AF_INET ?
					sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	switch (sa_local->sa_family) {
	case AF_INET:
		lwsl_info("%s: local address: %s:%d\n", __func__,
				inet_ntop(AF_INET, &u.sin.sin_addr, addr_str, sizeof(addr_str)),
				ntohs(u.sin.sin_port));
		break;
	}

	sport->engine = engine;
	sport->fd = sockfd;

	//    desc.sockfd = sockfd;

	wsi->desc.sockfd = sockfd;
	cc->wsi = wsi;

	lwsl_info("%s: %s: WAITING_CONNECT: fd %d\n", __func__, wsi->lc.gutag, (int)sockfd);
	lwsi_set_state(wsi, LRS_WAITING_CONNECT);

	if (wsi->a.context->event_loop_ops->sock_accept)
		if (wsi->a.context->event_loop_ops->sock_accept(wsi))
			goto bail;

	lws_pt_lock(pt, __func__);
	if (__insert_wsi_socket_into_fds(wsi->a.context, wsi)) {
		lws_pt_unlock(pt);
		goto bail;
	}
	lws_pt_unlock(pt);

	/*
	 * The fd + wsi combination is entered into the wsi tables
	 * at this point, with a pollfd
	 *
	 * Past here, we can't simply free the structs as error
	 * handling as oom4 does.
	 *
	 * We can run the whole close flow, or unpick the fds inclusion
	 * and anything else we have done.
	 */

	if (lws_change_pollfd(wsi, 0, LWS_POLLIN))
		goto bail;


	#if 0
	lws_adopt_descriptor_vhost(lws_get_vhost_by_name(context, "default"),
			LWS_ADOPT_FLAG_UDP | LWS_ADOPT_SOCKET | LWS_ADOPT_FLAG_QUIC,
			desc, NULL, // "quic-h3", /* protocols[0].name, */
			NULL);
	#endif
	if (!cc->wsi)
		goto bail;

	/* the wsi lsquic object */
	cc->wsi->lsq_sport = sport;

	return 0;

	bail:
	saved_errno = errno;
	CLOSE_SOCKET(sockfd);
	errno = saved_errno;
	return -1;
}



static SSL_CTX *
get_ssl_ctx (void *peer_ctx, const struct sockaddr *unused)
{
	const struct service_port *const sport = peer_ctx;
	return sport->context->lsq.ssl_ctx;
}






void
pba_release (void *packout_buf_allocator, void *peer_ctx, void *obj, char ipv6)
{
	struct packout_buf_allocator *const pba = packout_buf_allocator;
	obj = (uintptr_t *) obj - 1;
#if LSQUIC_USE_POOLS
	if (* (uintptr_t *) obj <= PBA_SIZE_THRESH)
	{
		struct packout_buf *const pb = obj;
		SLIST_INSERT_HEAD(&pba->free_packout_bufs, pb, next_free_pb);
	}
	else
#endif
	free(obj);
	--pba->n_out;
}


void
pba_cleanup (struct packout_buf_allocator *pba)
{
#if LSQUIC_USE_POOLS
	unsigned n = 0;
	struct packout_buf *pb;
#endif

	if (pba->n_out)
		lwsl_info("%u packout bufs outstanding at deinit\n", pba->n_out);

#if LSQUIC_USE_POOLS
	while ((pb = SLIST_FIRST(&pba->free_packout_bufs)))
	{
		SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
		free(pb);
		++n;
	}

	lwsl_info("pba deinitialized, freed %u packout bufs\n", n);
#endif
}

static const struct lsquic_packout_mem_if pmi = {
		.pmi_allocate = pba_allocate,
		.pmi_release  = pba_release,
		.pmi_return   = pba_release,
};


struct service_port *
sport_new(const char *optarg, struct lws_context *cx)
{
	struct service_port *const sport = lws_zalloc(sizeof(*sport), __func__);
	struct lws_context_role_lsq *prog = &cx->lsq;
	char *port_str;
	int port, e;
	const char *host;
	struct addrinfo hints, *res = NULL;
#if __linux__
	sport->n_dropped = 0;
	sport->drop_init = 0;
#endif
	sport->wsi = NULL;
	sport->packs_in = NULL;
	sport->fd = -1;
	char *const addr = strdup(optarg);
#if __linux__
	char *if_name;
	if_name = strrchr(addr, ',');
	if (if_name)
	{
		strncpy(sport->if_name, if_name + 1, sizeof(sport->if_name) - 1);
		sport->if_name[ sizeof(sport->if_name) - 1 ] = '\0';
		*if_name = '\0';
	}
	else
		sport->if_name[0] = '\0';
#endif

	host = addr;
	port_str = strrchr(addr, ':');
	if (port_str)
	{
		*port_str++ = '\0';
		port = atoi(port_str);
	}
	else
	{
		port_str = "443";
		port = 443;
	}

	assert(host);
	lwsl_info("%s: host: %s; port: %d\n", __func__, host, port);
	if (strlen(host) > sizeof(sport->host) - 1)
	{
		printf("argument `%s' too long", host);
		goto err;
	}
	strcpy(sport->host, host);

	struct sockaddr_in  *const sa4 = (void *) &sport->sas;
	struct sockaddr_in6 *const sa6 = (void *) &sport->sas;
	if        (inet_pton(AF_INET, host, &sa4->sin_addr)) {
		sa4->sin_family = AF_INET;
		sa4->sin_port   = htons((uint16_t)port);
	} else if (memset(sa6, 0, sizeof(*sa6)),
			inet_pton(AF_INET6, host, &sa6->sin6_addr)) {
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port   = htons((uint16_t)port);
	} else
	{
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICSERV;
		if (prog->ipver == 4)
			hints.ai_family = AF_INET;
		else if (prog->ipver == 6)
			hints.ai_family = AF_INET6;
		e = getaddrinfo(host, port_str, &hints, &res);
		if (e != 0)
		{
			lwsl_warn("could not resolve %s:%s: %s\n", host, port_str,
					gai_strerror(e));
			goto err;
		}
		if (res->ai_addrlen > sizeof(sport->sas))
		{
			lwsl_warn("resolved socket length is too long\n");
			goto err;
		}
		memcpy(&sport->sas, res->ai_addr, res->ai_addrlen);
		if (!prog->hostname)
			prog->hostname = sport->host;
	}


	if (res)
		freeaddrinfo(res);
	free(addr);
	sport->context = cx;
	return sport;

err:

	if (res)
		freeaddrinfo(res);
	lws_free(sport);
	free(addr);
	return NULL;
}

static void
free_packets_in (struct packets_in *packs_in)
{
#if ECN_SUPPORTED
	free(packs_in->ecn);
#endif
	free(packs_in->peer_addresses);
	free(packs_in->local_addresses);
	free(packs_in->ctlmsg_data);
	free(packs_in->vecs);
	free(packs_in->packet_data);
	free(packs_in);
}


void
sport_destroy (struct service_port *sport)
{
	if (sport->wsi) {
		lws_wsi_close(sport->wsi, LWS_TO_KILL_ASYNC);
		sport->wsi = NULL;
	}
	//    if (sport->fd >= 0)
	//      (void) CLOSE_SOCKET(sport->fd);
	if (sport->packs_in)
		free_packets_in(sport->packs_in);
	free(sport->sp_token_buf);
	lws_free(sport);
}

int
prog_connect(struct lws_context_role_lsq *prog, unsigned char *sess_resume,
	     size_t sess_resume_len)
{
	struct service_port *sport;

	sport = TAILQ_FIRST(&prog->sports);

	if (!lsquic_engine_connect(prog->engine, N_LSQVER,
			(struct sockaddr *) &sport->sp_local_addr,
			(struct sockaddr *) &sport->sas, sport, NULL,
			prog->hostname ? prog->hostname
			/* SNI is required for HTTP */
			: prog->engine_flags & LSENG_HTTP ? sport->host
					: NULL,
					  LWS_LSQ_MAX_MTU,
					  sess_resume, sess_resume_len,
					  sport->sp_token_buf, sport->sp_token_sz))
		return -1;

	prog_process_conns(prog->context);
	return 0;
}

static void
create_connections (struct http_client_ctx *ccx)
{
	size_t len;
	FILE *file;
	unsigned char sess_resume[0x2000];

	if (!(ccx->hcc_flags & HCC_SKIP_SESS_RESUME) &&
	    ccx->hcc_sess_resume_file_name)
	{
		file = fopen(ccx->hcc_sess_resume_file_name, "rb");
		if (!file)
		{
			lwsl_debug("%s: cannot open %s for reading: %s", __func__,
				   ccx->hcc_sess_resume_file_name,
				   strerror(errno));
			goto no_file;
		}
		len = fread(sess_resume, 1, sizeof(sess_resume), file);
		if (0 == len && !feof(file))
			lwsl_warn("%s: error reading %s: %s", __func__,
				  ccx->hcc_sess_resume_file_name,
				  strerror(errno));
		fclose(file);
		lwsl_info("create connection sess_resume %zu bytes", len);
	} else
no_file:
		len = 0;

	while (ccx->hcc_n_open_conns < ccx->hcc_concurrency &&
	       ccx->hcc_total_n_reqs > 0)
		if (prog_connect(&ccx->context->lsq, len ? sess_resume : NULL, len)) {
			lwsl_err("connection failed");
			exit(EXIT_FAILURE);
		}
}


#if defined(LWS_WITH_CLIENT)
static int
rops_client_bind_lsq(struct lws *wsi, const struct lws_client_connect_info *i)
{
	if (!i) {

		struct service_port *sport;
		struct lws_context *cx = wsi->a.context;
		struct http_client_ctx * cc = (struct http_client_ctx *)
					cx->lsq.api.ea_stream_if_ctx;

		/* finalize */

		if (!wsi->user_space && wsi->stash->cis[CIS_METHOD])
			if (lws_ensure_user_space(wsi))
				return 1;

		sport = sport_new(wsi->stash->cis[CIS_ADDRESS], cx);
		if (!sport)
			return -1;

		/* Default settings: */
		sport->sp_flags = cx->lsq.dummy_sport.sp_flags;
		sport->sp_sndbuf = cx->lsq.dummy_sport.sp_sndbuf;
		sport->sp_rcvbuf = cx->lsq.dummy_sport.sp_rcvbuf;
		TAILQ_INSERT_TAIL(&cx->lsq.sports, sport, next_sport);

		sport = TAILQ_FIRST(&cx->lsq.sports);
		if (sport_init_client(sport, cx->lsq.engine, cx->lsq.context, wsi))
			return -1;

		create_connections(cc);

		return 0;
	}

	/*
	 *
	 */

	if (i->ssl_connection & LCCSCF_LSQUIC)
		lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED,
				&role_ops_lsq);

	return 1; /* matched */
}
#endif

static int
rops_close_kill_connection_lsq(struct lws *wsi, enum lws_close_status reason)
{
	struct service_port *sport = wsi->lsq_sport;

	TAILQ_REMOVE(&wsi->a.context->lsq.sports, sport, next_sport);
	sport_destroy(sport);
/*
	if (lwsi_role_client(wsi)) {
		struct http_client_ctx * cc = (struct http_client_ctx *)context->lsq.api.ea_stream_if_ctx;

		cc->
	}
*/
	return 0;
}

static int
prog_init_ssl_ctx (struct lws_context_role_lsq *prog)
{
	unsigned char ticket_keys[48];

	prog->ssl_ctx = SSL_CTX_new(TLS_method());
	if (!prog->ssl_ctx)
	{
		lwsl_err("cannot allocate SSL context");
		return -1;
	}

	SSL_CTX_set_min_proto_version(prog->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(prog->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(prog->ssl_ctx);

	/* This is obviously test code: the key is just an array of NUL bytes */
	memset(ticket_keys, 0, sizeof(ticket_keys));
	if (1 != SSL_CTX_set_tlsext_ticket_keys(prog->ssl_ctx,
			ticket_keys, sizeof(ticket_keys)))
	{
		lwsl_err("SSL_CTX_set_tlsext_ticket_keys failed\n");
		return -1;
	}

	return 0;
}


static struct ssl_ctx_st *
no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
	return NULL;
}

static int
lwsl_log_buf (void *ctx, const char *buf, size_t len)
{
	lwsl_lsq("%s", buf);
	return 0;
	//   return (int)fwrite(buf, sizeof(char), len, (FILE *) ctx);
}

static const struct lsquic_logger_if lwsl_logger_if = {
		.log_buf    = lwsl_log_buf,
};

// !!!

static 		struct http_client_ctx ccx;

int
rops_pt_init_destroy_lsq(struct lws_context *context,
		const struct lws_context_creation_info *info,
		struct lws_context_per_thread *pt, int destroy)
{
	if (pt != &context->pt[0])
		return 0;

	if (!destroy) {

		lsquic_logger_init(&lwsl_logger_if, NULL, LLTS_NONE);
		lsquic_set_log_level("debug");

		memset(&ccx, 0, sizeof(ccx));
		TAILQ_INIT(&ccx.hcc_path_elems);
		ccx.method			= "GET";
		ccx.hcc_concurrency		= 1;
		ccx.hcc_cc_reqs_per_conn		= 1;
		ccx.hcc_reqs_per_conn		= 1;
		ccx.hcc_total_n_reqs		= 1;
		ccx.hcc_reset_after_nbytes	= 0;
		ccx.hcc_retire_cid_after_nbytes	= 0;
		ccx.context			= context;

		TAILQ_INIT(&context->lsq.sports);

		context->lsq.context = context;

		context->lsq.engine_flags = LSENG_HTTP;
		lsquic_engine_init_settings(&context->lsq.settings, LSENG_HTTP);
#if defined(ECN_SUPPORTED)
		context->lsq.settings.es_ecn      = LSQUIC_DF_ECN;
#else
		context->lsq.settings.es_ecn      = 0;
#endif

		context->lsq.api.ea_settings      = &context->lsq.settings;
		context->lsq.api.ea_stream_if     = &http_client_if;
		context->lsq.api.ea_stream_if_ctx = &ccx;
		context->lsq.api.ea_packets_out   = sport_packets_out;
		context->lsq.api.ea_packets_out_ctx = &context->lsq;
		context->lsq.api.ea_pmi           = &pmi;
		context->lsq.api.ea_pmi_ctx       = &context->lsq.pba;
		context->lsq.api.ea_get_ssl_ctx   = get_ssl_ctx;

#if defined(LSQUIC_PREFERRED_ADDR)
		if (getenv("LSQUIC_PREFERRED_ADDR4") || getenv("LSQUIC_PREFERRED_ADDR6"))
			context->lsq.prog_flags |= PROG_SEARCH_ADDRS;
#endif

		context->lsq.settings.es_ua = LITESPEED_ID;

		lsquic_global_init(LSENG_HTTP & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER :
				LSQUIC_GLOBAL_CLIENT);

		context->lsq.settings.es_versions = 1u << lsquic_str2ver("Q046", 4);


		//	was_empty = TAILQ_EMPTY(&context->lsq.sports);

		{
			char err_buf[100];

			if (0 != lsquic_engine_check_settings(context->lsq.api.ea_settings,
					context->lsq.engine_flags, err_buf, sizeof(err_buf)))
			{
				lwsl_err("Error in settings: %s", err_buf);
				return -1;
			}

			if (!context->lsq.use_stock_pmi)
				pba_init(&context->lsq.pba, context->lsq.packout_max);
			else
			{
				context->lsq.api.ea_pmi = NULL;
				context->lsq.api.ea_pmi_ctx = NULL;
			}

			// !!!
#if 0
			if (prog.certs)
			{
				prog.api.ea_lookup_cert = lookup_cert;
				prog.api.ea_cert_lu_ctx = prog.certs;
			}
			else
#endif
			{
				if (context->lsq.engine_flags & LSENG_SERVER)
					lwsl_warn("Not a single service specified.  Use -c option.");
				context->lsq.api.ea_lookup_cert = no_cert;
			}

			/*
			 * Create the lsq engine
			 */

			context->lsq.engine = lsquic_engine_new(
					context->lsq.engine_flags,
					&context->lsq.api);
			if (!context->lsq.engine) {
				lwsl_err("%s: engine new failed\n", __func__);
				return -1;
			}

			if (prog_init_ssl_ctx(&context->lsq)) {
				lwsl_err("%s: ssl_ctx init fail\n", __func__);
				return -1;
			}

#if 0
			if (context->lsq.engine_flags & LSENG_SERVER)
				s = prog_init_server(context->lsq);
			else
#endif

		}

		return 0;
	}

	if (context->lsq.destroyed)
		return 0;

	context->lsq.destroyed = 1;

	free(priority_specs);

	{
		struct service_port *sport;
		while ((sport = TAILQ_FIRST(&context->lsq.sports)))
		{
			TAILQ_REMOVE(&context->lsq.sports, sport, next_sport);
			sport_destroy(sport);
		}
	}

	lsquic_engine_destroy(context->lsq.engine);

	if (!context->lsq.use_stock_pmi)
		pba_cleanup(&context->lsq.pba);
	if (context->lsq.ssl_ctx) {
		SSL_CTX_free(context->lsq.ssl_ctx);
		context->lsq.ssl_ctx = NULL;
	}
	//    if (prog->certs)
	//        delete_certs(prog->certs);

	lsquic_global_cleanup();

	return 0;
}


static const lws_rops_t rops_table_lsq[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_lsq },
#if defined(LWS_WITH_SERVER)
	/*  2 */ { .adoption_bind	  = rops_adoption_bind_lsq },
#else
	/*  2 */ { .adoption_bind	  = NULL },
#endif
#if defined(LWS_WITH_CLIENT)
	/*  3 */ { .client_bind		  = rops_client_bind_lsq },
#endif
	/*  4 */ { .pt_init_destroy	  = rops_pt_init_destroy_lsq },
	/*  5 */ { .close_kill_connection = rops_close_kill_connection_lsq },
};

const struct lws_role_ops role_ops_lsq = {
	/* role name */			"lsq",
	/* alpn id */			NULL,

	/* rops_table */		rops_table_lsq,
	/* rops_idx */			{
		/* LWS_ROPS_check_upgrades */
		/* LWS_ROPS_pt_init_destroy */			0x04,
		/* LWS_ROPS_init_vhost */
		/* LWS_ROPS_destroy_vhost */			0x00,
		/* LWS_ROPS_service_flag_pending */
		/* LWS_ROPS_handle_POLLIN */			0x01,
		/* LWS_ROPS_handle_POLLOUT */
		/* LWS_ROPS_perform_user_POLLOUT */		0x00,
		/* LWS_ROPS_callback_on_writable */
		/* LWS_ROPS_tx_credit */			0x00,
		/* LWS_ROPS_write_role_protocol */
		/* LWS_ROPS_encapsulation_parent */		0x00,
		/* LWS_ROPS_alpn_negotiated */
		/* LWS_ROPS_close_via_role_protocol */		0x00,
		/* LWS_ROPS_close_role */
		/* LWS_ROPS_close_kill_connection */		0x05,
		/* LWS_ROPS_destroy_role */
#if defined(LWS_WITH_SERVER)
		/* LWS_ROPS_adoption_bind */			0x02,
#else
		/* LWS_ROPS_adoption_bind */			0x00,
#endif
#if defined(LWS_WITH_CLIENT)
		/* LWS_ROPS_client_bind */
		/* LWS_ROPS_issue_keepalive */			0x30,
#else
		/* LWS_ROPS_client_bind */
		/* LWS_ROPS_issue_keepalive */			0x00,
#endif
	},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_RAW_CONNECTED,
					  LWS_CALLBACK_RAW_ADOPT },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RAW_RX,
					  LWS_CALLBACK_RAW_RX },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_WRITEABLE,
					  LWS_CALLBACK_RAW_WRITEABLE},
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_CLOSE,
					  LWS_CALLBACK_RAW_CLOSE },
	/* protocol_bind cb c, srv */	{ LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL,
					  LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL },
	/* protocol_unbind cb c, srv */	{ LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL,
					  LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL },
	/* file_handle */		0,
};
