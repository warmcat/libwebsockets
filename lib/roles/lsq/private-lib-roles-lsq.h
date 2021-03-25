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
 *  This is included from private-lib-core.h if LWS_WITH_LSQUIC
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


extern const struct lws_role_ops role_ops_lsq;

#define lwsi_role_lsq(wsi) (wsi->role_ops == &role_ops_lsq)

#include <sys/queue.h>

#if defined(LWS_NEED_LINUX_IPV6)
#include <linux/ipv6.h>
#endif


#ifndef WIN32
#   define SOCKOPT_VAL int
#   define SOCKET_TYPE int
#   define CLOSE_SOCKET close
#   define CHAR_CAST
#else
#   define SOCKOPT_VAL DWORD
#   define SOCKET_TYPE SOCKET
#   define CLOSE_SOCKET closesocket
#   define CHAR_CAST (char *)
#endif

#define HAVE_SENDMMSG 1
#define HAVE_RECVMMSG 1
#define HAVE_OPEN_MEMSTREAM 1
/* #undef HAVE_IP_DONTFRAG */
#define HAVE_IP_MTU_DISCOVER 1
#define HAVE_REGEX 1
#define HAVE_PREADV 1

#define LWS_LSQ_MAX_MTU 1340

#ifndef WIN32
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include<io.h>
#pragma warning(disable:4996)//posix name deprecated
#define close closesocket
#endif
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>

/* When more than `nread' bytes are read from stream `stream_id', apply
 * priority in `ehp'.
 */
struct priority_spec
{
	enum {
		PRIORITY_SPEC_ACTIVE    = 1 << 0,
	}                                       flags;
	lsquic_stream_id_t                      stream_id;
	size_t                                  nread;
	struct lsquic_ext_http_prio             ehp;
};

struct lsquic_conn_ctx;

struct path_elem {
	TAILQ_ENTRY(path_elem)			next_pe;
	const char				*path;
};

/*
 *
 *
 * lsquic_conn_ctx_t *
 * lsquic_conn_get_ctx (const lsquic_conn_t *);
 *
 * void
 * lsquic_conn_set_ctx (lsquic_conn_t *, lsquic_conn_ctx_t *);
 *
 * (lsquic_conn_t *conn)
 * 	lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
 * 	struct http_client_ctx *hcc = conn_h->ccx;
 */

struct http_client_ctx {
	const char				*hostname;
	const char				*method;
	const char				*payload;
	char					payload_size[20];

	/* hcc_path_elems holds a list of paths which are to be requested from
	 * the server.  Each new request gets the next path from the list (the
	 * iterator is stored in hcc_cur_pe); when the end is reached, the
	 * iterator wraps around.
	 */
	TAILQ_HEAD(, path_elem)			hcc_path_elems;
	struct path_elem			*hcc_cur_pe;

	unsigned				hcc_total_n_reqs;
	unsigned				hcc_reqs_per_conn;
	unsigned				hcc_concurrency;
	unsigned				hcc_cc_reqs_per_conn;
	unsigned				hcc_n_open_conns;
	unsigned				hcc_reset_after_nbytes;
	unsigned				hcc_retire_cid_after_nbytes;
	const char				*hcc_download_dir;

	char					*hcc_sess_resume_file_name;

	enum {
		HCC_SKIP_SESS_RESUME    = (1 << 0),
		HCC_SEEN_FIN            = (1 << 1),
		HCC_ABORT_ON_INCOMPLETE = (1 << 2),
	}                            hcc_flags;

	struct lws_context			*context;
	struct lws				*wsi;

	unsigned int				notified_http_hdr_sent:1;
	unsigned int				subsequent:1;
};

struct hset_elem
{
	STAILQ_ENTRY(hset_elem)			next;
	size_t					nalloc;
	struct lsxpack_header			xhdr;
};

STAILQ_HEAD(hset, hset_elem);

struct header_buf
{
	unsigned				off;
	char					buf[UINT16_MAX];
};

#ifndef LSQUIC_USE_POOLS
#define LSQUIC_USE_POOLS 1
#endif

/* So that largest allocation in PBA fits in 4KB */
#define PBA_SIZE_MAX 0x1000
#define PBA_SIZE_THRESH (PBA_SIZE_MAX - sizeof(uintptr_t))

struct packout_buf
{
    SLIST_ENTRY(packout_buf)    next_free_pb;
};

enum sport_flags
{
#if defined(LSQUIC_DONTFRAG_SUPPORTED)
    SPORT_FRAGMENT_OK				= (1 << 0),
#endif
    SPORT_SET_SNDBUF				= (1 << 1), /* SO_SNDBUF */
    SPORT_SET_RCVBUF				= (1 << 2), /* SO_RCVBUF */
    SPORT_SERVER				= (1 << 3),
    SPORT_CONNECT				= (1 << 4),
};

struct service_port {
    TAILQ_ENTRY(service_port)			next_sport;
#ifndef WIN32
    int						fd;
#else
    SOCKET					fd;
#endif
#if __linux__
    uint32_t					n_dropped;
    int						drop_init;
    char					if_name[IFNAMSIZ];
#endif
    struct lws_context				*context;
    struct lws					*wsi;
    struct lsquic_engine			*engine;
    char					host[80];
    struct sockaddr_storage			sas;
    struct sockaddr_storage 			sp_local_addr;
    struct packets_in				*packs_in;
    enum sport_flags				sp_flags;
    SOCKOPT_VAL					sp_sndbuf;   /* If SPORT_SET_SNDBUF is set */
    SOCKOPT_VAL					sp_rcvbuf;   /* If SPORT_SET_RCVBUF is set */
    unsigned char				*sp_token_buf;
    size_t					sp_token_sz;
};

TAILQ_HEAD(sport_head, service_port);

struct server_ctx {
	struct lsquic_conn_ctx			*conn_h;
	lsquic_engine_t				*engine;
	const char				*document_root;
	const char				*push_path;
	struct sport_head			sports;
	struct lws_context			*context;
	struct lws				*wsi;
	unsigned				max_conn;
	unsigned				n_conn;
	unsigned				n_current_conns;
	unsigned				delay_resp_sec;
};


struct lsquic_conn_ctx {
	TAILQ_ENTRY(lsquic_conn_ctx)		next_ch;
	lsquic_conn_t				*conn;
	struct http_client_ctx			*ccx;
	struct server_ctx			*server_ctx;
	//    lws_usec_t        ch_created;
	unsigned				ch_n_reqs;    /* This number gets decremented as streams are closed and
	 * incremented as push promises are accepted.
	 */
	unsigned				ch_n_cc_streams;   /* This number is incremented as streams are opened
	 * and decremented as streams are closed. It should
	 * never exceed hcc_cc_reqs_per_conn in ccx.
	 */
	enum {
		CH_SESSION_RESUME_SAVED		 = 1 << 0,
	}                    ch_flags;

	enum {
		RECEIVED_GOAWAY			= 1 << 0,
	}                    flags;
};

struct resp
{
	const char				*buf;
	size_t					sz;
	size_t					off;
};


struct lsquic_stream_ctx {
	lsquic_stream_t				*stream;
	struct http_client_ctx			*ccx;
	struct server_ctx			*server_ctx;

	const char				*path;
	enum {
		HEADERS_SENT			= (1 << 0),
		PROCESSED_HEADERS		= 1 << 1,
		ABANDON				= 1 << 2,
		/* Abandon reading from stream after sh_stop bytes
		 * have been read.
		 */
	} sh_flags;
	lws_usec_t				sh_created;
	lws_usec_t				sh_ttfb;
	size_t					sh_stop;   /* Stop after reading this many bytes if ABANDON is set */
	size_t					sh_nread;  /* Number of bytes read from stream using one of
	 * lsquic_stream_read* functions.
	 */
	unsigned				count;

	/* server bits */

	FILE					*req_fh;
	char					*req_buf;
	char					*req_filename;
	char					*req_path;
	size_t					req_sz;
	enum {
		SH_HEADERS_SENT = (1 << 0),
		SH_DELAYED      = (1 << 1),
		SH_HEADERS_READ = (1 << 2),
	} flags;

	/* Fields below are used by interop callbacks: */
	enum interop_handler {
		IOH_ERROR,
		IOH_INDEX_HTML,
		IOH_MD5SUM,
		IOH_VER_HEAD,
		IOH_GEN_FILE,
		IOH_ECHO,
	} interop_handler;
	struct req				*req;
	const char				*resp_status;
	union {
		struct {
			char buf[0x100];
			struct resp resp;
		} err;
	} interop_u;
	struct event				*resume_resp;
	size_t					written;
};

struct packout_buf;

struct packout_buf_allocator
{
	unsigned				n_out,      /* Number of buffers outstanding */
						max;        /* Maximum outstanding.  Zero mean no limit */
	SLIST_HEAD(, packout_buf)		free_packout_bufs;
};

struct lws_context_role_lsq
{
	struct packout_buf_allocator		pba;
	struct lsquic_engine_settings		settings;
	struct lsquic_engine_api		api;
	unsigned				engine_flags;
	struct service_port			dummy_sport;   /* Use for options */
	unsigned				packout_max;
	unsigned short				max_packet_size;

	unsigned long				read_count;
#if defined(HAVE_SENDMMSG)
	int					use_sendmmsg;
#endif
#if defined(HAVE_RECVMMSG)
	int					use_recvmmsg;
#endif
	int					use_stock_pmi;

	struct lws_context			*context;
	lws_sorted_usec_list_t			sul_timer;
	struct sport_head			sports;

	struct ssl_ctx_st			*ssl_ctx;
	struct lsquic_hash			*certs;
	//    char				*prog_susp_sni;
	struct lsquic_engine			*engine;
	const char				*hostname;
	int					ipver;     /* 0, 4, or 6 */
	enum {
		PROG_FLAG_COOLDOWN 		= 1 << 0,
#if defined(LSQUIC_PREFERRED_ADDR)
		PROG_SEARCH_ADDRS		= 1 << 1,
#endif
	} prog_flags;

	char					destroyed;
};
