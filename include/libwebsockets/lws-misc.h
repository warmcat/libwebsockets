/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/** \defgroup misc Miscellaneous APIs
* ##Miscellaneous APIs
*
* Various APIs outside of other categories
*/
///@{

struct lws_buflist;

/**
 * lws_buflist_append_segment(): add buffer to buflist at head
 *
 * \param head: list head
 * \param buf: buffer to stash
 * \param len: length of buffer to stash
 *
 * Returns -1 on OOM, 1 if this was the first segment on the list, and 0 if
 * it was a subsequent segment.
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_buflist_append_segment(struct lws_buflist **head, const uint8_t *buf,
			   size_t len);
/**
 * lws_buflist_next_segment_len(): number of bytes left in current segment
 *
 * \param head: list head
 * \param buf: if non-NULL, *buf is written with the address of the start of
 *		the remaining data in the segment
 *
 * Returns the number of bytes left in the current segment.  0 indicates
 * that the buflist is empty (there are no segments on the buflist).
 */
LWS_VISIBLE LWS_EXTERN size_t
lws_buflist_next_segment_len(struct lws_buflist **head, uint8_t **buf);

/**
 * lws_buflist_use_segment(): remove len bytes from the current segment
 *
 * \param head: list head
 * \param len: number of bytes to mark as used
 *
 * If len is less than the remaining length of the current segment, the position
 * in the current segment is simply advanced and it returns.
 *
 * If len uses up the remaining length of the current segment, then the segment
 * is deleted and the list head moves to the next segment if any.
 *
 * Returns the number of bytes left in the current segment.  0 indicates
 * that the buflist is empty (there are no segments on the buflist).
 */
LWS_VISIBLE LWS_EXTERN int
lws_buflist_use_segment(struct lws_buflist **head, size_t len);

/**
 * lws_buflist_destroy_all_segments(): free all segments on the list
 *
 * \param head: list head
 *
 * This frees everything on the list unconditionally.  *head is always
 * NULL after this.
 */
LWS_VISIBLE LWS_EXTERN void
lws_buflist_destroy_all_segments(struct lws_buflist **head);

/**
 * lws_buflist_describe(): debug helper logging buflist status
 *
 * \param head: list head
 * \param id: pointer shown in debug list
 * \param reason: reason string show in debug list
 *
 * Iterates through the buflist segments showing position and size.
 * This only exists when lws was built in debug mode
 */
LWS_VISIBLE LWS_EXTERN void
lws_buflist_describe(struct lws_buflist **head, void *id, const char *reason);

/**
 * lws_ptr_diff(): helper to report distance between pointers as an int
 *
 * \param head: the pointer with the larger address
 * \param tail: the pointer with the smaller address
 *
 * This helper gives you an int representing the number of bytes further
 * forward the first pointer is compared to the second pointer.
 */
#define lws_ptr_diff(head, tail) \
			((int)((char *)(head) - (char *)(tail)))

/**
 * lws_snprintf(): snprintf that truncates the returned length too
 *
 * \param str: destination buffer
 * \param size: bytes left in destination buffer
 * \param format: format string
 * \param ...: args for format
 *
 * This lets you correctly truncate buffers by concatenating lengths, if you
 * reach the limit the reported length doesn't exceed the limit.
 */
LWS_VISIBLE LWS_EXTERN int
lws_snprintf(char *str, size_t size, const char *format, ...) LWS_FORMAT(3);

/**
 * lws_strncpy(): strncpy that guarantees NUL on truncated copy
 *
 * \param dest: destination buffer
 * \param src: source buffer
 * \param size: bytes left in destination buffer
 *
 * This lets you correctly truncate buffers by concatenating lengths, if you
 * reach the limit the reported length doesn't exceed the limit.
 */
LWS_VISIBLE LWS_EXTERN char *
lws_strncpy(char *dest, const char *src, size_t size);

/**
 * lws_hex_to_byte_array(): convert hex string like 0123456789ab into byte data
 *
 * \param h: incoming NUL-terminated hex string
 * \param dest: array to fill with binary decodes of hex pairs from h
 * \param max: maximum number of bytes dest can hold, must be at least half
 *		the size of strlen(h)
 *
 * This converts hex strings into an array of 8-bit representations, ie the
 * input "abcd" produces two bytes of value 0xab and 0xcd.
 *
 * Returns number of bytes produced into \p dest, or -1 on error.
 *
 * Errors include non-hex chars and an odd count of hex chars in the input
 * string.
 */
LWS_VISIBLE LWS_EXTERN int
lws_hex_to_byte_array(const char *h, uint8_t *dest, int max);

/*
 * lws_timingsafe_bcmp(): constant time memcmp
 *
 * \param a: first buffer
 * \param b: second buffer
 * \param len: count of bytes to compare
 *
 * Return 0 if the two buffers are the same, else nonzero.
 *
 * Always compares all of the buffer before returning, so it can't be used as
 * a timing oracle.
 */

LWS_VISIBLE LWS_EXTERN int
lws_timingsafe_bcmp(const void *a, const void *b, uint32_t len);

/**
 * lws_get_random(): fill a buffer with platform random data
 *
 * \param context: the lws context
 * \param buf: buffer to fill
 * \param len: how much to fill
 *
 * Fills buf with len bytes of random.  Returns the number of bytes set, if
 * not equal to len, then getting the random failed.
 */
LWS_VISIBLE LWS_EXTERN int
lws_get_random(struct lws_context *context, void *buf, int len);
/**
 * lws_daemonize(): make current process run in the background
 *
 * \param _lock_path: the filepath to write the lock file
 *
 * Spawn lws as a background process, taking care of various things
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_daemonize(const char *_lock_path);
/**
 * lws_get_library_version(): return string describing the version of lws
 *
 * On unix, also includes the git describe
 */
LWS_VISIBLE LWS_EXTERN const char * LWS_WARN_UNUSED_RESULT
lws_get_library_version(void);

/**
 * lws_wsi_user() - get the user data associated with the connection
 * \param wsi: lws connection
 *
 * Not normally needed since it's passed into the callback
 */
LWS_VISIBLE LWS_EXTERN void *
lws_wsi_user(struct lws *wsi);

/**
 * lws_set_wsi_user() - set the user data associated with the client connection
 * \param wsi: lws connection
 * \param user: user data
 *
 * By default lws allocates this and it's not legal to externally set it
 * yourself.  However client connections may have it set externally when the
 * connection is created... if so, this api can be used to modify it at
 * runtime additionally.
 */
LWS_VISIBLE LWS_EXTERN void
lws_set_wsi_user(struct lws *wsi, void *user);

/**
 * lws_parse_uri:	cut up prot:/ads:port/path into pieces
 *			Notice it does so by dropping '\0' into input string
 *			and the leading / on the path is consequently lost
 *
 * \param p:			incoming uri string.. will get written to
 * \param prot:		result pointer for protocol part (https://)
 * \param ads:		result pointer for address part
 * \param port:		result pointer for port part
 * \param path:		result pointer for path part
 *
 * You may also refer to unix socket addresses, using a '+' at the start of
 * the address.  In this case, the address should end with ':', which is
 * treated as the separator between the address and path (the normal separator
 * '/' is a valid part of the socket path).  Eg,
 *
 * http://+/var/run/mysocket:/my/path
 *
 * If the first character after the + is '@', it's interpreted by lws client
 * processing as meaning to use linux abstract namespace sockets, the @ is
 * replaced with a '\0' before use.
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_parse_uri(char *p, const char **prot, const char **ads, int *port,
	      const char **path);
/**
 * lws_cmdline_option():	simple commandline parser
 *
 * \param argc:		count of argument strings
 * \param argv:		argument strings
 * \param val:		string to find
 *
 * Returns NULL if the string \p val is not found in the arguments.
 *
 * If it is found, then it returns a pointer to the next character after \p val.
 * So if \p val is "-d", then for the commandlines "myapp -d15" and
 * "myapp -d 15", in both cases the return will point to the "15".
 *
 * In the case there is no argument, like "myapp -d", the return will
 * either point to the '\\0' at the end of -d, or to the start of the
 * next argument, ie, will be non-NULL.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_cmdline_option(int argc, const char **argv, const char *val);

/**
 * lws_now_secs(): return seconds since 1970-1-1
 */
LWS_VISIBLE LWS_EXTERN unsigned long
lws_now_secs(void);

/**
 * lws_now_usecs(): return useconds since 1970-1-1
 */
LWS_VISIBLE LWS_EXTERN lws_usec_t
lws_now_usecs(void);

/**
 * lws_get_context - Allow getting lws_context from a Websocket connection
 * instance
 *
 * With this function, users can access context in the callback function.
 * Otherwise users may have to declare context as a global variable.
 *
 * \param wsi:	Websocket connection instance
 */
LWS_VISIBLE LWS_EXTERN struct lws_context * LWS_WARN_UNUSED_RESULT
lws_get_context(const struct lws *wsi);

/**
 * lws_get_vhost_listen_port - Find out the port number a vhost is listening on
 *
 * In the case you passed 0 for the port number at context creation time, you
 * can discover the port number that was actually chosen for the vhost using
 * this api.
 *
 * \param vhost:	Vhost to get listen port from
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_get_vhost_listen_port(struct lws_vhost *vhost);

/**
 * lws_get_count_threads(): how many service threads the context uses
 *
 * \param context: the lws context
 *
 * By default this is always 1, if you asked for more than lws can handle it
 * will clip the number of threads.  So you can use this to find out how many
 * threads are actually in use.
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_get_count_threads(struct lws_context *context);

/**
 * lws_get_parent() - get parent wsi or NULL
 * \param wsi: lws connection
 *
 * Specialized wsi like cgi stdin/out/err are associated to a parent wsi,
 * this allows you to get their parent.
 */
LWS_VISIBLE LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_get_parent(const struct lws *wsi);

/**
 * lws_get_child() - get child wsi or NULL
 * \param wsi: lws connection
 *
 * Allows you to find a related wsi from the parent wsi.
 */
LWS_VISIBLE LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_get_child(const struct lws *wsi);

/**
 * lws_get_effective_uid_gid() - find out eventual uid and gid while still root
 *
 * \param context: lws context
 * \param uid: pointer to uid result
 * \param gid: pointer to gid result
 *
 * This helper allows you to find out what the uid and gid for the process will
 * be set to after the privileges are dropped, beforehand.  So while still root,
 * eg in LWS_CALLBACK_PROTOCOL_INIT, you can arrange things like cache dir
 * and subdir creation / permissions down /var/cache dynamically.
 */
LWS_VISIBLE LWS_EXTERN void
lws_get_effective_uid_gid(struct lws_context *context, int *uid, int *gid);

/**
 * lws_get_udp() - get wsi's udp struct
 *
 * \param wsi: lws connection
 *
 * Returns NULL or pointer to the wsi's UDP-specific information
 */
LWS_VISIBLE LWS_EXTERN const struct lws_udp * LWS_WARN_UNUSED_RESULT
lws_get_udp(const struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void *
lws_get_opaque_parent_data(const struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void
lws_set_opaque_parent_data(struct lws *wsi, void *data);

LWS_VISIBLE LWS_EXTERN void *
lws_get_opaque_user_data(const struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void
lws_set_opaque_user_data(struct lws *wsi, void *data);

LWS_VISIBLE LWS_EXTERN int
lws_get_child_pending_on_writable(const struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void
lws_clear_child_pending_on_writable(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_get_close_length(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN unsigned char *
lws_get_close_payload(struct lws *wsi);

/**
 * lws_get_network_wsi() - Returns wsi that has the tcp connection for this wsi
 *
 * \param wsi: wsi you have
 *
 * Returns wsi that has the tcp connection (which may be the incoming wsi)
 *
 * HTTP/1 connections will always return the incoming wsi
 * HTTP/2 connections may return a different wsi that has the tcp connection
 */
LWS_VISIBLE LWS_EXTERN
struct lws *lws_get_network_wsi(struct lws *wsi);

/**
 * lws_set_allocator() - custom allocator support
 *
 * \param realloc
 *
 * Allows you to replace the allocator (and deallocator) used by lws
 */
LWS_VISIBLE LWS_EXTERN void
lws_set_allocator(void *(*realloc)(void *ptr, size_t size, const char *reason));

enum {
	/*
	 * Flags for enable and disable rxflow with reason bitmap and with
	 * backwards-compatible single bool
	 */
	LWS_RXFLOW_REASON_USER_BOOL		= (1 << 0),
	LWS_RXFLOW_REASON_HTTP_RXBUFFER		= (1 << 6),
	LWS_RXFLOW_REASON_H2_PPS_PENDING	= (1 << 7),

	LWS_RXFLOW_REASON_APPLIES		= (1 << 14),
	LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT	= (1 << 13),
	LWS_RXFLOW_REASON_APPLIES_ENABLE	= LWS_RXFLOW_REASON_APPLIES |
						  LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT,
	LWS_RXFLOW_REASON_APPLIES_DISABLE	= LWS_RXFLOW_REASON_APPLIES,
	LWS_RXFLOW_REASON_FLAG_PROCESS_NOW	= (1 << 12),

};

/**
 * lws_rx_flow_control() - Enable and disable socket servicing for
 *				received packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * \param wsi:	Websocket connection instance to get callback for
 * \param enable:	0 = disable read servicing for this connection, 1 = enable
 *
 * If you need more than one additive reason for rxflow control, you can give
 * iLWS_RXFLOW_REASON_APPLIES_ENABLE or _DISABLE together with one or more of
 * b5..b0 set to idicate which bits to enable or disable.  If any bits are
 * enabled, rx on the connection is suppressed.
 *
 * LWS_RXFLOW_REASON_FLAG_PROCESS_NOW  flag may also be given to force any change
 * in rxflowbstatus to benapplied immediately, this should be used when you are
 * changing a wsi flow control state from outside a callback on that wsi.
 */
LWS_VISIBLE LWS_EXTERN int
lws_rx_flow_control(struct lws *wsi, int enable);

/**
 * lws_rx_flow_allow_all_protocol() - Allow all connections with this protocol to receive
 *
 * When the user server code realizes it can accept more input, it can
 * call this to have the RX flow restriction removed from all connections using
 * the given protocol.
 * \param context:	lws_context
 * \param protocol:	all connections using this protocol will be allowed to receive
 */
LWS_VISIBLE LWS_EXTERN void
lws_rx_flow_allow_all_protocol(const struct lws_context *context,
			       const struct lws_protocols *protocol);

/**
 * lws_remaining_packet_payload() - Bytes to come before "overall"
 *					      rx fragment is complete
 * \param wsi:		Websocket instance (available from user callback)
 *
 * This tracks how many bytes are left in the current ws fragment, according
 * to the ws length given in the fragment header.
 *
 * If the message was in a single fragment, and there is no compression, this
 * is the same as "how much data is left to read for this message".
 *
 * However, if the message is being sent in multiple fragments, this will
 * reflect the unread amount of the current **fragment**, not the message.  With
 * ws, it is legal to not know the length of the message before it completes.
 *
 * Additionally if the message is sent via the negotiated permessage-deflate
 * extension, this number only tells the amount of **compressed** data left to
 * be read, since that is the only information available at the ws layer.
 */
LWS_VISIBLE LWS_EXTERN size_t
lws_remaining_packet_payload(struct lws *wsi);

#if defined(LWS_WITH_DIR)

typedef enum {
	LDOT_UNKNOWN,
	LDOT_FILE,
	LDOT_DIR,
	LDOT_LINK,
	LDOT_FIFO,
	LDOTT_SOCKET,
	LDOT_CHAR,
	LDOT_BLOCK
} lws_dir_obj_type_t;

struct lws_dir_entry {
	const char *name;
	lws_dir_obj_type_t type;
};

typedef int
lws_dir_callback_function(const char *dirpath, void *user,
			  struct lws_dir_entry *lde);

/**
 * lws_dir() - get a callback for everything in a directory
 *
 * \param dirpath: the directory to scan
 * \param user: pointer to give to callback
 * \param cb: callback to receive information on each file or dir
 *
 * Calls \p cb (with \p user) for every object in dirpath.
 *
 * This wraps whether it's using POSIX apis, or libuv (as needed for windows,
 * since it refuses to support POSIX apis for this).
 */
LWS_VISIBLE LWS_EXTERN int
lws_dir(const char *dirpath, void *user, lws_dir_callback_function cb);
#endif

/**
 * lws_get_allocated_heap() - if the platform supports it, returns amount of
 *				heap allocated by lws itself
 *
 * On glibc currently, this reports the total amount of current logical heap
 * allocation, found by tracking the amount allocated by lws_malloc() and
 * friends and accounting for freed allocations via lws_free().
 *
 * This is useful for confirming where processwide heap allocations actually
 * come from... this number represents all lws internal allocations, for
 * fd tables, wsi allocations, ah, etc combined.  It doesn't include allocations
 * from user code, since lws_malloc() etc are not exported from the library.
 *
 * On other platforms, it always returns 0.
 */
size_t lws_get_allocated_heap(void);

/**
 * lws_is_ssl() - Find out if connection is using SSL
 * \param wsi:	websocket connection to check
 *
 *	Returns 0 if the connection is not using SSL, 1 if using SSL and
 *	using verified cert, and 2 if using SSL but the cert was not
 *	checked (appears for client wsi told to skip check on connection)
 */
LWS_VISIBLE LWS_EXTERN int
lws_is_ssl(struct lws *wsi);
/**
 * lws_is_cgi() - find out if this wsi is running a cgi process
 *
 * \param wsi: lws connection
 */
LWS_VISIBLE LWS_EXTERN int
lws_is_cgi(struct lws *wsi);

/**
 * lws_open() - platform-specific wrapper for open that prepares the fd
 *
 * \param __file: the filepath to open
 * \param __oflag: option flags
 *
 * This is a wrapper around platform open() that sets options on the fd
 * according to lws policy.  Currently that is FD_CLOEXEC to stop the opened
 * fd being available to any child process forked by user code.
 */
LWS_VISIBLE LWS_EXTERN int
lws_open(const char *__file, int __oflag, ...);

struct lws_wifi_scan { /* generic wlan scan item */
	struct lws_wifi_scan *next;
	char ssid[32];
	int32_t rssi; /* divide by .count to get db */
	uint8_t bssid[6];
	uint8_t count;
	uint8_t channel;
	uint8_t authmode;
};

#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS)
/**
 * lws_get_ssl() - Return wsi's SSL context structure
 * \param wsi:	websocket connection
 *
 * Returns pointer to the SSL library's context structure
 */
LWS_VISIBLE LWS_EXTERN SSL*
lws_get_ssl(struct lws *wsi);
#endif

LWS_VISIBLE LWS_EXTERN void
lws_explicit_bzero(void *p, size_t len);

typedef struct lws_humanize_unit {
	const char *name; /* array ends with NULL name */
	uint64_t factor;
} lws_humanize_unit_t;

LWS_VISIBLE LWS_EXTERN const lws_humanize_unit_t humanize_schema_si[];
LWS_VISIBLE LWS_EXTERN const lws_humanize_unit_t humanize_schema_si_bytes[];
LWS_VISIBLE LWS_EXTERN const lws_humanize_unit_t humanize_schema_us[];

/**
 * lws_humanize() - Convert possibly large number to himan-readable uints
 *
 * \param buf: result string buffer
 * \param len: remaining length in \p buf
 * \param value: the uint64_t value to represent
 * \param schema: and array of scaling factors and units
 *
 * This produces a concise string representation of \p value, referening the
 * schema \p schema of scaling factors and units to find the smallest way to
 * render it.
 *
 * Three schema are exported from lws for general use, humanize_schema_si, which
 * represents as, eg, "  22.130Gi" or " 128      "; humanize_schema_si_bytes
 * which is the same but shows, eg, "  22.130GiB", and humanize_schema_us,
 * which represents a count of us as a human-readable time like "  14.350min",
 * or "  1.500d".
 *
 * You can produce your own schema.
 */

LWS_VISIBLE LWS_EXTERN int
lws_humanize(char *buf, int len, uint64_t value,
	     const lws_humanize_unit_t *schema);


LWS_VISIBLE LWS_EXTERN void
lws_ser_wu16be(uint8_t *b, uint16_t u);

LWS_VISIBLE LWS_EXTERN void
lws_ser_wu32be(uint8_t *b, uint32_t u32);

LWS_VISIBLE LWS_EXTERN void
lws_ser_wu64be(uint8_t *b, uint64_t u64);

LWS_VISIBLE LWS_EXTERN uint16_t
lws_ser_ru16be(const uint8_t *b);

LWS_VISIBLE LWS_EXTERN uint32_t
lws_ser_ru32be(const uint8_t *b);

LWS_VISIBLE LWS_EXTERN uint64_t
lws_ser_ru64be(const uint8_t *b);

int
lws_vbi_encode(uint64_t value, void *buf);

int
lws_vbi_decode(const void *buf, uint64_t *value, size_t len);

///@}
