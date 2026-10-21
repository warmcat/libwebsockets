/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 */

/** \defgroup log_ship Log shipping
 * ##Log shipping
 *
 * Mirrors the lws log lines this process emits to a log ingestor, eg, the
 * lws-log-ingest plugin, which keeps the lines of many processes on many
 * machines in one place, in UTC, so they can be looked at together.  See
 * READMEs/README.log-ship.md.
 *
 * Every line lws emits, whichever log context it went through and wherever
 * it went (stderr, syslog / the journal, a file), is also kept in a bounded
 * backlog in memory with its UTC time.  Nothing is sent by default: the
 * process keeps a ws connection open to the ingestor, authenticated by a
 * shared secret, and the ingestor tells it when to send.  It names a window,
 * from a UTC time that may be a little in the past, which the backlog
 * provides, until a UTC time a limited time ahead; while the window is open
 * it may also raise the process' log level, and when it closes the level goes
 * back to what it was.
 *
 * There is one log shipper per process, since the lines it sees are the whole
 * process'.
 *
 * Besides lws_log_ship_create(), a vhost makes one when it's given pvos for
 * the "lws-log-ship" protocol, which every vhost has: "url" and "secret", and
 * optionally "kind" ("lws" by default), "host" and "backlog-kb".  That's how
 * lwsws makes one, from a vhost's "ws-protocols" config.
 */
///@{

struct lws_log_ship;

/**
 * lws_log_ship_line_t - a log line, as given to a local store
 */
typedef struct lws_log_ship_line {
	uint64_t		seq;	/**< per-shipper sequence, from 1 */
	uint64_t		t_us;	/**< UTC us when it was logged */
	const char		*text;	/**< printable ASCII, NUL terminated */
	const char		*tag;	/**< NULL, or its tag, see
					 * lws_log_ship_set_tagger() */
	size_t			len;	/**< strlen(text) */
	int			level;	/**< its single LLL_ bit */
} lws_log_ship_line_t;

/**
 * lws_log_ship_tagger_t - find a line's tag
 *
 * \param line: the line, printable ASCII
 * \param len: its length
 * \param tag: where to put the tag, NUL terminated
 * \param tag_len: the room at tag, 33
 *
 * Returns 0 if the line has a tag, else nonzero.  A tag is 1 to 32 of
 * [A-Za-z0-9._/-], anything else is ignored.  It's called with the backlog
 * locked, so it must be quick, and mustn't log.
 */
typedef int (*lws_log_ship_tagger_t)(const char *line, size_t len, char *tag,
				     size_t tag_len);

/**
 * lws_log_ship_store_cb_t - a local store takes some lines
 *
 * \param opaque: the info's .opaque
 * \param kind: the shipper's kind, eg "lwsws"
 * \param host: the shipper's host name
 * \param inst: the shipper's instance, 16 lowercase hex
 * \param lines: the lines, in seq order
 * \param count: how many lines
 *
 * For a shipper in the ingestor's own process, which stores its lines without
 * a connection.  It's called from the event loop, and must not hold on to the
 * lines after it returns.
 */
typedef void (*lws_log_ship_store_cb_t)(void *opaque, const char *kind,
					const char *host, const char *inst,
					const lws_log_ship_line_t *lines,
					size_t count);

/**
 * struct lws_log_ship_info - how to ship our logs
 */
struct lws_log_ship_info {
	struct lws_vhost		*vhost;
	/**< the vhost the connection to the ingestor is made on, its client
	 * tls settings apply.  The shipper is destroyed with the vhost, if
	 * lws_log_ship_destroy() wasn't called before. */
	const char			*url;
	/**< the ingestor, "wss://host[:port]/path"; ws:// is only allowed to
	 * a loopback address.  NULL with .store set for a local store, or
	 * NULL with no .store to only keep lines until lws_log_ship_link()
	 * says where they go, eg, when that's only known later. */
	const char			*secret;
	/**< shared with the ingestor, it's sent inside the tls tunnel */
	const char			*kind;
	/**< what kind of process we are, eg "lwsws", up to 32 of
	 * [A-Za-z0-9._-] */
	const char			*host;
	/**< our name, up to 64 of [A-Za-z0-9._-], NULL means the hostname */
	size_t				backlog_max;
	/**< bytes of lines kept for windows that start in the past, and while
	 * they're waiting to be sent; 0 means 4MiB.  Past it, the oldest go */
	lws_log_ship_store_cb_t		store;
	/**< NULL, or a local store, used instead of a connection */
	void				*opaque;
	/**< passed to .store */
	int				client_ssl_flags;
	/**< extra LCCSCF_ flags for the connection, eg, to allow a selfsigned
	 * ingestor in a test */
	char				no_sysinfo;
	/**< the first window starts with lines describing the system, see
	 * lws_sysinfo_create(), unless this is set, eg, because the
	 * application logs them itself */
};

/**
 * lws_log_ship_create() - start keeping our log lines, and connect to the
 *			   ingestor
 *
 * \param info: how to ship our logs, its strings are copied
 *
 * Returns the shipper, or NULL if it couldn't be made, or there already is
 * one in this process.
 */
LWS_VISIBLE LWS_EXTERN struct lws_log_ship *
lws_log_ship_create(const struct lws_log_ship_info *info);

/**
 * lws_log_ship_link() - say where the lines of a shipper made without a url go
 *
 * \param ls: the shipper
 * \param url: the ingestor, as for lws_log_ship_info .url
 * \param secret: shared with the ingestor
 *
 * Returns 0 if it's connecting, or nonzero if it already has somewhere to
 * go, or the url or secret can't be used.
 */
LWS_VISIBLE LWS_EXTERN int
lws_log_ship_link(struct lws_log_ship *ls, const char *url,
		  const char *secret);

/**
 * lws_log_ship_set_host() - ship as a different host name from now on
 *
 * \param ls: the shipper
 * \param host: the new name, up to 64 of [A-Za-z0-9._-]
 *
 * Eg, a process that only learns its name some time after it started.  The
 * ingestor renames the source, with what it already has from it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_log_ship_set_host(struct lws_log_ship *ls, const char *host);

/**
 * lws_log_ship_set_tagger() - tag lines as they're sent
 *
 * \param tagger: NULL, or the tagger
 *
 * An application can tag lines with something they're about, eg, a job, by
 * what's in them, so the ingestor can find them by it.  It's processwide,
 * and can be set before the shipper is made.
 */
LWS_VISIBLE LWS_EXTERN void
lws_log_ship_set_tagger(lws_log_ship_tagger_t tagger);

/**
 * lws_log_ship_destroy() - stop keeping and shipping our log lines
 *
 * \param pls: the shipper, set to NULL
 *
 * Lines not yet stored by the ingestor are lost.  A raised log level goes back
 * to what it was.
 */
LWS_VISIBLE LWS_EXTERN void
lws_log_ship_destroy(struct lws_log_ship **pls);

/**
 * lws_log_ship_window() - open, change or close the window of lines to send
 *
 * \param ls: the shipper
 * \param from_us: UTC us of the earliest line wanted
 * \param until_us: UTC us when the window closes, 0 closes it now
 * \param lvl: LLL_ bits to log as well as the usual ones while it's open
 *
 * The ingestor does this for a connected shipper; this is for a local store,
 * or an application that decides the window itself.  The lines in the
 * backlog logged from from_us on, and every line logged until until_us, are
 * sent, each once.  A new window replaces the last one.  Whoever asks, a
 * window closes at most 24h from when it was given.
 */
LWS_VISIBLE LWS_EXTERN void
lws_log_ship_window(struct lws_log_ship *ls, uint64_t from_us,
		    uint64_t until_us, int lvl);

/**
 * lws_log_ship_get() - the process' shipper, if it has one
 *
 * Returns the shipper, or NULL.  There can only be one, so something that
 * would make one, eg, from config, can see first that the process' lines
 * already go somewhere.
 */
LWS_VISIBLE LWS_EXTERN struct lws_log_ship *
lws_log_ship_get(void);

/**
 * lws_log_ship_inst() - our instance name, 16 lowercase hex
 *
 * \param ls: the shipper
 *
 * It's chosen at random when the shipper is created, so lines from a restarted
 * process, or a reused host name, can be told apart.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_log_ship_inst(struct lws_log_ship *ls);

/**
 * lws_log_ship_host() - the host name we ship as
 *
 * \param ls: the shipper
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_log_ship_host(struct lws_log_ship *ls);

/**
 * lws_log_ship_utc_us() - the UTC time now, in us, as the shipper takes it
 */
LWS_VISIBLE LWS_EXTERN uint64_t
lws_log_ship_utc_us(void);

/* the protocol names on the wire */
#define LWS_LOG_SHIP_WS_PROTOCOL	"lws-log-ingest"
#define LWS_LOG_SHIP_LINE_MAX		1024

///@}
