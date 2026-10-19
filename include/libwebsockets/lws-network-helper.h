/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2023 Andy Green <andy@warmcat.com>
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

/** \defgroup net Network related helper APIs
 * ##Network related helper APIs
 *
 * These wrap miscellaneous useful network-related functions
 */
LWS_VISIBLE LWS_EXTERN struct lws_dll2_owner *
lws_routing_table_get(struct lws_context *cx);

///@{

#if defined(LWS_ESP_PLATFORM)
#include <lwip/sockets.h>
#endif

/* cope with large amounts of route information */
typedef uint16_t lws_route_uidx_t;

typedef struct lws_dns_score {
	uint8_t precedence;
	uint8_t label;
} lws_dns_score_t;

/*
 * This represents an entry in the system routing table
 */

typedef struct lws_route {
	lws_dll2_t		list;

	lws_sockaddr46		src; /* lws_dns_sort_t: the source route's src */
	lws_sockaddr46		dest;
	lws_sockaddr46		gateway;

	lws_dns_score_t		score; /* when used as lws_dns_sort_t */

	int			if_idx;
	int			priority;
	int			ifa_flags; /* if source_ads */

	lws_route_uidx_t	uidx; /* unique index for this route */

	uint8_t			proto;
	uint8_t			dest_len;
	uint8_t			src_len;
	uint8_t			scope; /* if source_ads */
	uint8_t			af; /* if source_ads */

	uint8_t			source_ads:1;
	uint8_t			has_source:1; /* lws_dns_sort_t: src is set */
} lws_route_t;

/*
 * We reuse the route object as the dns sort granule, so there's only one
 * struct needs to know all the gnarly ipv6 details
 */

typedef lws_route_t lws_dns_sort_t;

/**
 * lws_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * \param context:	Websocket context
 */
LWS_VISIBLE LWS_EXTERN const char * LWS_WARN_UNUSED_RESULT
lws_canonical_hostname(struct lws_context *context);

/**
 * lws_get_peer_addresses() - Get client address information
 * \param wsi:	Local struct lws associated with
 * \param fd:		Connection socket descriptor
 * \param name:	Buffer to take client address name
 * \param name_len:	Length of client address name buffer
 * \param rip:	Buffer to take client address IP dotted quad
 * \param rip_len:	Length of client address IP buffer
 *
 *	This function fills in name and rip with the name and IP of
 *	the client connected with socket descriptor fd.  Names may be
 *	truncated if there is not enough room.  If either cannot be
 *	determined, they will be returned as valid zero-length strings.
 */
LWS_VISIBLE LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_get_peer_addresses(struct lws *wsi, lws_sockfd_type fd, char *name,
		       int name_len, char *rip, int rip_len);

/**
 * lws_get_peer_simple() - Get client address information without RDNS
 *
 * \param wsi:	Local struct lws associated with
 * \param name:	Buffer to take client address name
 * \param namelen:	Length of client address name buffer
 *
 * This provides a 123.123.123.123 type IP address in name from the
 * peer that has connected to wsi
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_get_peer_simple(struct lws *wsi, char *name, size_t namelen);

LWS_VISIBLE LWS_EXTERN const char *
lws_get_peer_simple_fd(lws_sockfd_type fd, char *name, size_t namelen);

#define LWS_ITOSA_USABLE	0
#define LWS_ITOSA_NOT_EXIST	-1
#define LWS_ITOSA_NOT_USABLE	-2
#define LWS_ITOSA_BUSY		-3 /* only returned by lws_socket_bind() on
					EADDRINUSE */

#if !defined(LWS_PLAT_FREERTOS) && !defined(LWS_PLAT_OPTEE)
/**
 * lws_interface_to_sa() - Convert interface name or IP to sockaddr struct
 *
 * \param ipv6:		Allow IPV6 addresses
 * \param ifname:	Interface name or IP
 * \param addr:		struct sockaddr_in * to be written
 * \param addrlen:	Length of addr
 *
 * This converts a textual network interface name to a sockaddr usable by
 * other network functions.
 *
 * If the network interface doesn't exist, it will return LWS_ITOSA_NOT_EXIST.
 *
 * If the network interface is not usable, eg ethernet cable is removed, it
 * may logically exist but not have any IP address.  As such it will return
 * LWS_ITOSA_NOT_USABLE.
 *
 * If the network interface exists and is usable, it will return
 * LWS_ITOSA_USABLE.
 */
LWS_VISIBLE LWS_EXTERN int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen);
#endif

/**
 * lws_sa46_compare_ads() - checks if two sa46 have the same address
 *
 * \param sa46a: first
 * \param sa46b: second
 *
 * Returns 0 if the address family is INET or INET6 and the address is the same,
 * or if the AF is the same but not INET or INET6, otherwise nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_compare_ads(const lws_sockaddr46 *sa46a, const lws_sockaddr46 *sa46b);

/**
 * lws_sa46_compare_sin6_addr() - compare two sin6_addr objects safely
 *
 * \param a: first
 * \param b: second
 *
 * Returns 0 if equal, else non-zero.  Operates directly on the s6_addr
 * array to avoid static analysis warnings about padding in the struct.
 */
#if defined(LWS_WITH_IPV6)
#define lws_sa46_compare_sin6_addr(a, b) memcmp((a)->s6_addr, (b)->s6_addr, 16)
#endif

/**
 * lws_sa46_on_net() - checks if an sa46 is on the subnet represented by another
 *
 * \param sa46a: first
 * \param sa46_net: network
 * \param net_len: length of network non-mask
 *
 * Returns 0 if sa46a belongs on network sa46_net/net_len
 *
 * If there is an ipv4 / v6 mismatch between the ip and the net, the ipv4
 * address is promoted to ::ffff:x.x.x.x before the comparison.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_on_net(const lws_sockaddr46 *sa46a, const lws_sockaddr46 *sa46_net,
			int net_len);

/*
 * lws_parse_numeric_address() - converts numeric ipv4 or ipv6 to byte address
 *
 * \param ads: the numeric ipv4 or ipv6 address string
 * \param result: result array
 * \param max_len: max length of result array
 *
 * Converts a 1.2.3.4 or 2001:abcd:123:: or ::ffff:1.2.3.4 formatted numeric
 * address into an array of network ordered byte address elements.
 *
 * The parse is as strict as inet_pton(): the string must contain nothing but
 * the address, and an ipv4 octet may not have a leading zero, since libc's
 * resolver reads one as octal (to it "012.0.0.1" is 10.0.0.1).
 *
 * Returns < 0 on error, else length of result set, either 4 or 16 for ipv4 /
 * ipv6.
 */
LWS_VISIBLE LWS_EXTERN int
lws_parse_numeric_address(const char *ads, uint8_t *result, size_t max_len);

/**
 * lws_host_is_ambiguous_numeric() - a host libc would take as ipv4 but we don't
 *
 * \param host: the host name or address string
 *
 * libc's getaddrinfo() also takes a host whose last label is a number as an
 * ipv4 address, in the inet_aton() forms lws_parse_numeric_address() refuses:
 * octets with a leading zero are octal, 0x is hex, and fewer than four parts
 * are allowed ("012.0.0.1", "10.1" and "167772161" are all 10.0.0.1 to it).
 * Such a host means different things to different resolvers, so lws refuses
 * to resolve it for a client connection; a filter deciding whether a host is
 * acceptable should refuse it too.
 *
 * Returns 1 if \p host is not a strict numeric address, but its last label
 * (ignoring one trailing '.') is all decimal digits, or "0x" and hex digits;
 * else 0.
 */
LWS_VISIBLE LWS_EXTERN int
lws_host_is_ambiguous_numeric(const char *host);

/*
 * lws_sa46_parse_numeric_address() - converts numeric ipv4 or ipv6 to sa46
 *
 * \param ads: the numeric ipv4 or ipv6 address string
 * \param sa46: pointer to sa46 to set
 *
 * Converts a 1.2.3.4 or 2001:abcd:123:: or ::ffff:1.2.3.4 formatted numeric
 * address into an sa46, a union of sockaddr_in or sockaddr_in6 depending on
 * what kind of address was found.  sa46->sa4.sin_fmaily will be AF_INET if
 * ipv4, or AF_INET6 if ipv6.
 *
 * Returns 0 if the sa46 was set, else < 0 on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_parse_numeric_address(const char *ads, lws_sockaddr46 *sa46);

/**
 * lws_sa46_is_ipv4_mapped() - is an AF_INET6 sa46 an IPv4-mapped address?
 *
 * \param sa46: the sa46 to test
 *
 * Returns 1 if \p sa46 is AF_INET6 and holds an IPv4-mapped IPv6 address
 * (::ffff:a.b.c.d), else 0.  Useful for deciding that an AF_INET6 socket
 * targeting this address must be dual-stack (IPV6_V6ONLY = 0) to actually
 * reach the IPv4 peer through the mapping.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_is_ipv4_mapped(const lws_sockaddr46 *sa46);

/*
 * Room for any key lws_sa46_host_key() / lws_get_peer_host_key() writes,
 * including the terminating NUL
 */
#define LWS_HOST_KEY_LEN	32
/* the one key every peer whose address is not IPv4 or IPv6 shares */
#define LWS_HOST_KEY_UNKNOWN	"unknown"

/**
 * lws_sa46_host_key() - the key a peer's host is accounted under
 *
 * \param sa46: the peer address
 * \param key: buffer for the key, at least LWS_HOST_KEY_LEN
 * \param len: size of \p key
 *
 * Per-peer admission caps, strikes and rate limits must count one host as
 * one peer.  For IPv4 that is the address, but an IPv6 host commands its
 * whole /64 (2^64 source addresses), so counting per address does not bound
 * it at all.  The key is therefore:
 *
 *  - IPv4, or IPv4-mapped IPv6: the dotted quad, eg "192.0.2.1"
 *  - other IPv6: the /64, eg "2001:db8:1:2::/64"
 *  - anything else (eg, an unset sa46): LWS_HOST_KEY_UNKNOWN, one bucket
 *    shared by every such peer, so they are counted together rather than
 *    not at all
 *
 * Keys compare equal with strcmp() exactly when the hosts are the same.
 *
 * Returns 0 if the key is a host's, or 1 if it is LWS_HOST_KEY_UNKNOWN.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_host_key(const lws_sockaddr46 *sa46, char *key, size_t len);

/**
 * lws_get_peer_host_key() - the host key of the client connected to wsi
 *
 * \param wsi: the connection
 * \param key: buffer for the key, at least LWS_HOST_KEY_LEN
 * \param len: size of \p key
 *
 * lws_sa46_host_key() of the address lws_get_peer_simple() gives, ie, the
 * client a trusted PROXY v2 proxy named where there is one.  A peer whose
 * address can't be determined or parsed gets LWS_HOST_KEY_UNKNOWN.
 *
 * Use this to key per-client admission decisions, so they all agree on who
 * the client is.
 *
 * Returns \p key.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_get_peer_host_key(struct lws *wsi, char *key, size_t len);

/**
 * lws_write_numeric_address() - convert network byte order ads to text
 *
 * \param ads: network byte order address array
 * \param size: number of bytes valid in ads
 * \param buf: result buffer to take text format
 * \param len: max size of text buffer
 *
 * Converts an array of network-ordered byte address elements to a textual
 * representation of the numeric address, like "1.2.3.4" or "::1".  Returns the
 * number of chars written into buf, else < 0.  ipv6 only supported with
 * LWS_IPV6=1 at cmake.
 */
LWS_VISIBLE LWS_EXTERN int
lws_write_numeric_address(const uint8_t *ads, int size, char *buf, size_t len);

/**
 * lws_sa46_write_numeric_address() - convert sa46 ads to textual numeric ads
 *
 * \param sa46: the sa46 whose address to show
 * \param buf: result buffer to take text format
 * \param len: max size of text buffer
 *
 * Converts the ipv4 or ipv6 address in an lws_sockaddr46 to a textual
 * representation of the numeric address, like "1.2.3.4" or "::1".  Returns the
 * number of chars written into buf, else < 0.  ipv6 only supported with
 * LWS_IPV6=1 at cmake.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_write_numeric_address(lws_sockaddr46 *sa46, char *buf, size_t len);

/**
 * lws_parse_mac() - convert XX:XX:XX:XX:XX:XX to 6-byte MAC address
 *
 * \param ads: mac address as XX:XX:XX:XX:XX:XX string
 * \param result_6_bytes: result buffer to take 6 bytes
 *
 * Converts a string representation of a 6-byte hex mac address to a 6-byte
 * array.
 */
LWS_VISIBLE LWS_EXTERN int
lws_parse_mac(const char *ads, uint8_t *result_6_bytes);

LWS_VISIBLE LWS_EXTERN int
lws_parse_cidr(const char *cidr, lws_sockaddr46 *sa46, int *len);

/**
 * lws_is_lan_address() - checks if the given string represents a LAN address
 *
 * \param ads: The address string
 *
 * Returns 1 if the address is a local/LAN unroutable address
 */
LWS_VISIBLE LWS_EXTERN int
lws_is_lan_address(const char *ads);

/*
 * lws_is_local_address() - checks if the given string represents a local address
 *
 * \param ads: the address string to check
 *
 * Returns 1 if the address is a recognized local address like "localhost" or "127.0.0.1",
 * else 0.
 */
LWS_VISIBLE LWS_EXTERN int
lws_is_local_address(const char *ads);

/**
 * lws_is_lan_address() - checks if the given string represents a LAN address
 *
 * \param ads: The address string
 *
 * Returns 1 if the address is a local/LAN unroutable address
 */
LWS_VISIBLE LWS_EXTERN int
lws_is_lan_address(const char *ads);

///@}
