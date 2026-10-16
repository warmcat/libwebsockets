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

/** \defgroup sysinfo System information snapshot
 * ##System information snapshot
 *
 * A snapshot of what the system we are running on looks like, for logging
 * at startup so the logs say where they came from, and for debugging: the
 * lws build and version, what the system calls itself, its OS and
 * architecture, the time, how long it has been up, its cpus and RAM, every
 * address on every network interface, and the resolver's nameservers and
 * search list.
 *
 * lws_sysinfo_create() takes the snapshot, lws_sysinfo_next() walks its
 * items, lws_sysinfo_describe() renders one as a line of text, and
 * lws_sysinfo_destroy() frees it.  What is in it depends on the platform:
 * an item a platform can't provide is simply not there.
 */
///@{

#if defined(LWS_WITH_SYS_INFO)

typedef enum lws_sysinfo_type {
	LWS_SYSINFO_LWS_VERSION,	/**< s: the lws library version */
	LWS_SYSINFO_LWS_BUILD,		/**< s: the lws build's git hash */
	LWS_SYSINFO_HOSTNAME,		/**< s: what the system calls itself */
	LWS_SYSINFO_OS,			/**< s: the OS and its version */
	LWS_SYSINFO_ARCH,		/**< s: the machine architecture */
	LWS_SYSINFO_PID,		/**< u: our process id */
	LWS_SYSINFO_TIME,		/**< u: unix time in s; s: ISO 8601 UTC */
	LWS_SYSINFO_UPTIME,		/**< u: seconds since the system booted */
	LWS_SYSINFO_CPUS,		/**< u: cpus we may run on */
	LWS_SYSINFO_RAM_TOTAL,		/**< u: bytes of RAM in the system */
	LWS_SYSINFO_RAM_FREE,		/**< u: bytes of RAM not in use */
	LWS_SYSINFO_IFACE_ADDR,		/**< name: the interface; sa46: an
					 *   address on it; u: the prefix length;
					 *   flags: LWS_SYSINFO_IF_ bits */
	LWS_SYSINFO_DNS_SERVER,		/**< sa46: a nameserver the resolver uses */
	LWS_SYSINFO_DNS_SEARCH,		/**< s: a domain in the resolver's search
					 *   list */

	LWS_SYSINFO_TYPE_COUNT
} lws_sysinfo_type_t;

/* the state of an interface an LWS_SYSINFO_IFACE_ADDR address is on */

enum {
	LWS_SYSINFO_IF_UP		= (1 << 0),
	LWS_SYSINFO_IF_RUNNING		= (1 << 1),
	LWS_SYSINFO_IF_LOOPBACK		= (1 << 2),
	LWS_SYSINFO_IF_P2P		= (1 << 3),
};

typedef struct lws_sysinfo_item {
	lws_dll2_t		list;
	const char		*name;	/**< the interface's name, or NULL */
	const char		*s;	/**< the string value, or NULL */
	uint64_t		u;	/**< the numeric value, or 0 */
	lws_sockaddr46		sa46;	/**< the address, for the address types */
	uint32_t		flags;	/**< LWS_SYSINFO_IF_ bits, or 0 */
	lws_sysinfo_type_t	type;
} lws_sysinfo_item_t;

struct lws_sysinfo;

/**
 * lws_sysinfo_create() - take a snapshot of the system
 *
 * \param cx: the lws context
 *
 * Returns the snapshot, to walk with lws_sysinfo_next() and free with
 * lws_sysinfo_destroy(), or NULL if it couldn't be allocated.  The items are
 * in a fixed order by type, and the interface addresses in the order the
 * platform lists them.
 */
LWS_VISIBLE LWS_EXTERN struct lws_sysinfo *
lws_sysinfo_create(struct lws_context *cx);

/**
 * lws_sysinfo_next() - the next item of a snapshot
 *
 * \param si: the snapshot
 * \param prev: the item before it, or NULL for the first
 *
 * Returns the item, or NULL after the last
 */
LWS_VISIBLE LWS_EXTERN const lws_sysinfo_item_t *
lws_sysinfo_next(struct lws_sysinfo *si, const lws_sysinfo_item_t *prev);

/**
 * lws_sysinfo_describe() - render an item as a line of text
 *
 * \param it: the item
 * \param buf: where to write it
 * \param len: the size of buf
 *
 * Writes a NUL-terminated line like "iface eth0: 10.0.0.2/24 up running" or
 * "ram total: 16384 MiB", without a newline, and returns its length.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sysinfo_describe(const lws_sysinfo_item_t *it, char *buf, size_t len);

/**
 * lws_sysinfo_type_name() - the name of an item type, eg, "hostname"
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_sysinfo_type_name(lws_sysinfo_type_t type);

/**
 * lws_sysinfo_destroy() - free a snapshot, and NULL the pointer to it
 */
LWS_VISIBLE LWS_EXTERN void
lws_sysinfo_destroy(struct lws_sysinfo **psi);

#endif
///@}
