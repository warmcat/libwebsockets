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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifndef LWS_NO_FORK
#include <sys/prctl.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

#include <poll.h>
#include <sys/mman.h>

#ifdef LWS_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include <openssl/md5.h>
#include <openssl/sha.h>
#include "libwebsockets.h"

#if 0
#define DEBUG
#endif

#ifdef DEBUG
static inline void debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap);
}
#else
static inline void debug(const char *format, ...)
{
}
#endif


#define MAX_CLIENTS 100
#define LWS_MAX_HEADER_NAME_LENGTH 64
#define LWS_MAX_HEADER_LEN 4096
#define LWS_INITIAL_HDR_ALLOC 256
#define LWS_ADDITIONAL_HDR_ALLOC 64
#define MAX_USER_RX_BUFFER 4096
#define MAX_BROADCAST_PAYLOAD 2048
#define LWS_MAX_PROTOCOLS 10

#define MAX_WEBSOCKET_04_KEY_LEN 128
#define SYSTEM_RANDOM_FILEPATH "/dev/urandom"

enum lws_websocket_opcodes_04 {
	LWS_WS_OPCODE_04__CONTINUATION = 0,
	LWS_WS_OPCODE_04__CLOSE = 1,
	LWS_WS_OPCODE_04__PING = 2,
	LWS_WS_OPCODE_04__PONG = 3,
	LWS_WS_OPCODE_04__TEXT_FRAME = 4,
	LWS_WS_OPCODE_04__BINARY_FRAME = 5,
};

enum lws_connection_states {
	WSI_STATE_HTTP,
	WSI_STATE_HTTP_HEADERS,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED,
	WSI_STATE_CLIENT_UNCONNECTED
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

	/* new for 04 */
	WSI_TOKEN_KEY,
	WSI_TOKEN_VERSION,
	WSI_TOKEN_SWORIGIN,

	/* client receives these */
	WSI_TOKEN_ACCEPT,
	WSI_TOKEN_NONCE,
	WSI_TOKEN_HTTP,

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

	LWS_RXPS_04_MASK_NONCE_1,
	LWS_RXPS_04_MASK_NONCE_2,
	LWS_RXPS_04_MASK_NONCE_3,

	LWS_RXPS_04_FRAME_HDR_1,
	LWS_RXPS_04_FRAME_HDR_LEN,
	LWS_RXPS_04_FRAME_HDR_LEN16_2,
	LWS_RXPS_04_FRAME_HDR_LEN16_1,
	LWS_RXPS_04_FRAME_HDR_LEN64_8,
	LWS_RXPS_04_FRAME_HDR_LEN64_7,
	LWS_RXPS_04_FRAME_HDR_LEN64_6,
	LWS_RXPS_04_FRAME_HDR_LEN64_5,
	LWS_RXPS_04_FRAME_HDR_LEN64_4,
	LWS_RXPS_04_FRAME_HDR_LEN64_3,
	LWS_RXPS_04_FRAME_HDR_LEN64_2,
	LWS_RXPS_04_FRAME_HDR_LEN64_1,

	LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED
};


struct lws_tokens {
	char *token;
	int token_len;
};

struct libwebsocket_protocols;

struct libwebsocket_context {
	struct libwebsocket *wsi[MAX_CLIENTS + 1];
	struct pollfd fds[MAX_CLIENTS + 1];
	int fds_count;
	int listen_port;
	char http_proxy_address[256];
	char canonical_hostname[1024];
	unsigned int http_proxy_port;
	unsigned int options;
#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_client_ctx;
#endif
	struct libwebsocket_protocols *protocols;
	int count_protocols;
};

enum connection_mode {
	LWS_CONNMODE_WS_SERVING,
	LWS_CONNMODE_WS_CLIENT,
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

	/* 04 protocol specific */

	unsigned char masking_key_04[20];
	unsigned char frame_masking_nonce_04[4];
	unsigned char frame_mask_04[20];
	unsigned char frame_mask_index;
	size_t rx_packet_length;
	unsigned char opcode;
	unsigned char final;

	int pings_vs_pongs;

	/* client support */
	char initial_handshake_hash_base64[30];
	enum connection_mode mode;

#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
	BIO *client_bio;
#endif

	void *user_space;
};

extern int
libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c);

extern void
libwebsocket_close_and_free_session(struct libwebsocket *wsi);

extern int
libwebsocket_parse(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);

extern int
libwebsocket_read(struct libwebsocket *wsi, unsigned char * buf, size_t len);

extern int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size);

extern int
lws_b64_decode_string(const char *in, char *out, int out_size);

extern int
lws_b64_selftest(void);
