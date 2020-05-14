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

/** \defgroup net Network related helper APIs
 * ##Network related helper APIs
 *
 * These wrap miscellaneous useful network-related functions
 */
///@{

#if defined(LWS_ESP_PLATFORM)
#include <lwip/sockets.h>
#endif

typedef union {
#if defined(LWS_WITH_IPV6)
	struct sockaddr_in6 sa6;
#endif
	struct sockaddr_in sa4;
} lws_sockaddr46;

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
LWS_VISIBLE LWS_EXTERN void
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
 * Returns 0 if the address family and address are the same, otherwise nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_compare_ads(const lws_sockaddr46 *sa46a, const lws_sockaddr46 *sa46b);

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
 * Returns < 0 on error, else length of result set, either 4 or 16 for ipv4 /
 * ipv6.
 */
LWS_VISIBLE LWS_EXTERN int
lws_parse_numeric_address(const char *ads, uint8_t *result, size_t max_len);

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
 * lws_write_numeric_address() - convert network byte order ads to text
 *
 * \param ads: network byte order address array
 * \param size: number of bytes valid in ads
 * \param buf: result buffer to take text format
 * \param len: max size of text buffer
 *
 * Converts an array of network-ordered byte address elements to a textual
 * representation of the numeric address, like "1.2.3.4" or "::1".  Return 0
 * if OK else < 0.  ipv6 only supported with LWS_IPV6=1 at cmake.
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
 * representation of the numeric address, like "1.2.3.4" or "::1".  Return 0
 * if OK else < 0.  ipv6 only supported with LWS_IPV6=1 at cmake.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sa46_write_numeric_address(lws_sockaddr46 *sa46, char *buf, size_t len);

///@}
