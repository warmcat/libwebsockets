/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 Andy Green <andy@warmcat.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <poll.h>
#include <sys/mman.h>

#ifdef LWS_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "libwebsockets.h"

/* #define DEBUG  */


#ifdef DEBUG
#define debug(  \
      fprintf(stderr, 
#else
static void inline debug(const char *format, ...) { }
#endif

#ifdef LWS_OPENSSL_SUPPORT
extern SSL_CTX *ssl_ctx;
extern int use_ssl;
#endif


#define MAX_CLIENTS 100
#define LWS_MAX_HEADER_NAME_LENGTH 64
#define LWS_MAX_HEADER_LEN 4096
#define LWS_INITIAL_HDR_ALLOC 256
#define LWS_ADDITIONAL_HDR_ALLOC 64
#define MAX_USER_RX_BUFFER 512
#define MAX_BROADCAST_PAYLOAD 1024
#define LWS_MAX_PROTOCOLS 10

enum lws_connection_states {
	WSI_STATE_HTTP,
	WSI_STATE_HTTP_HEADERS,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED
};

enum lws_token_indexes {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_HOST,
	WSI_TOKEN_CONNECTION,
	WSI_TOKEN_KEY1,
	WSI_TOKEN_KEY2,
	WSI_TOKEN_PROTOCOL,
	WSI_TOKEN_UPGRADE,
	WSI_TOKEN_ORIGIN,
	WSI_TOKEN_DRAFT,
	WSI_TOKEN_CHALLENGE,

	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE
};

enum lws_rx_parse_state {
	LWS_RXPS_NEW,

	LWS_RXPS_SEEN_76_FF,
	LWS_RXPS_PULLING_76_LENGTH,
	LWS_RXPS_EAT_UNTIL_76_FF,

	LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED
};


struct lws_tokens {
	char *token;
	int token_len;
};

struct libwebsocket_context {
	struct libwebsocket *wsi[MAX_CLIENTS + 1];
	struct pollfd fds[MAX_CLIENTS + 1];
	int fds_count;
#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
#endif
	int count_protocols;
};


/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration; the user can use the pointer with
 * other APIs to get information out of it.
 */

struct libwebsocket {
	const struct libwebsocket_protocols *protocol;

	enum lws_connection_states state;

	char name_buffer[LWS_MAX_HEADER_NAME_LENGTH];
	int name_buffer_pos;
	int current_alloc_len;
	enum lws_token_indexes parser_state;
	struct lws_tokens utf8_token[WSI_TOKEN_COUNT];
	int ietf_spec_revision;
	char rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING + MAX_USER_RX_BUFFER +
						  LWS_SEND_BUFFER_POST_PADDING];
	int rx_user_buffer_head;

	int sock;

	enum lws_rx_parse_state lws_rx_parse_state;
	size_t rx_packet_length;

#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
#endif

	void *user_space;
};

extern void
libwebsocket_close_and_free_session(struct libwebsocket *wsi);

extern void
libwebsockets_md5(const unsigned char *input, int ilen, unsigned char *output);

extern int
libwebsocket_parse(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);
