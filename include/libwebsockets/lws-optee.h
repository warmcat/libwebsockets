/*
 * libwebsockets - small server side websockets and web server implementation
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2019 Akira Tsukamoto <akira.tsukamoto@gmail.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

#ifndef __LWS_OPTEE_H
#define __LWS_OPTEE_H

/* 128-bit IP6 address */
struct in6_addr {
	union {
		uint8_t	  u6_addr8[16];
		uint16_t  u6_addr16[8];
		uint32_t  u6_addr32[4];
	};
};

#define		_SS_MAXSIZE	128U
#define		_SS_ALIGNSIZE	(sizeof(int64_t))
#define		_SS_PAD1SIZE	(_SS_ALIGNSIZE - \
			sizeof(sa_family_t))
#define		_SS_PAD2SIZE	(_SS_MAXSIZE - \
			sizeof(sa_family_t) - _SS_PAD1SIZE - _SS_ALIGNSIZE)

struct sockaddr_storage {
	sa_family_t	ss_family;	/* address family */
	char		__ss_pad1[_SS_PAD1SIZE];
	int64_t		__ss_align;	/* force desired struct alignment */
	char		__ss_pad2[_SS_PAD2SIZE];
};

#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)      */
struct sockaddr {
	sa_family_t	sa_family;	/* address family */
	uint8_t		sa_data[__SOCK_SIZE__	/* address value */
				- sizeof(sa_family_t)];
};

/* 16 bytes */
struct sockaddr_in {
	sa_family_t	sin_family;
	in_port_t	sin_port;
	struct in_addr	sin_addr;
	uint8_t		sin_zero[__SOCK_SIZE__	/* padding until 16 bytes */
				- sizeof(sa_family_t)
				- sizeof(in_port_t)
				- sizeof(struct  in_addr)];
};

struct sockaddr_in6 {
	sa_family_t	sin6_family;	/* AF_INET6 */
	in_port_t	sin6_port;	/* Transport layer port # */
	uint32_t	sin6_flowinfo;	/* IP6 flow information */
	struct in6_addr	sin6_addr;	/* IP6 address */
	uint32_t	sin6_scope_id;	/* scope zone index */
};

#endif /* __LWS_OPTEE_H */
