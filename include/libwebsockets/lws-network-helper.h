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
lws_get_peer_simple(struct lws *wsi, char *name, int namelen);

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
///@}
