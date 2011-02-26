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
#include <sys/time.h>

#ifdef LWS_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif


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


/*
 * Mac OSX as well as iOS do not define the MSG_NOSIGNAL flag,
 * but happily have something equivalent in the SO_NOSIGPIPE flag.
 */
#ifdef __APPLE__
#define MSG_NOSIGNAL SO_NOSIGPIPE 
#endif


#define FD_HASHTABLE_MODULUS 32
#define MAX_CLIENTS 100
#define LWS_MAX_HEADER_NAME_LENGTH 64
#define LWS_MAX_HEADER_LEN 4096
#define LWS_INITIAL_HDR_ALLOC 256
#define LWS_ADDITIONAL_HDR_ALLOC 64
#define MAX_USER_RX_BUFFER 4096
#define MAX_BROADCAST_PAYLOAD 2048
#define LWS_MAX_PROTOCOLS 10
#define SPEC_LATEST_SUPPORTED 6

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
	WSI_STATE_CLIENT_UNCONNECTED,
	WSI_STATE_RETURNED_CLOSE_ALREADY,
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


enum connection_mode {
	LWS_CONNMODE_WS_SERVING,
	LWS_CONNMODE_WS_CLIENT,

	/* transient modes */
	LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY,
	LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE,
	LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY,

	/* special internal types */
	LWS_CONNMODE_SERVER_LISTENER,
	LWS_CONNMODE_BROADCAST_PROXY_LISTENER,
	LWS_CONNMODE_BROADCAST_PROXY
};


#define LWS_FD_HASH(fd) ((fd ^ (fd >> 8) ^ (fd >> 16)) % FD_HASHTABLE_MODULUS)

struct libwebsocket_fd_hashtable {
	struct libwebsocket *wsi[MAX_CLIENTS + 1];
	int length;
};

struct libwebsocket_protocols;

struct libwebsocket_context {
	struct libwebsocket_fd_hashtable fd_hashtable[FD_HASHTABLE_MODULUS];
	struct pollfd fds[MAX_CLIENTS * FD_HASHTABLE_MODULUS + 1];
	int fds_count;
	int listen_port;
	char http_proxy_address[256];
	char canonical_hostname[1024];
	unsigned int http_proxy_port;
	unsigned int options;
	unsigned long last_timeout_check_s;

	int fd_random;
	
#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_client_ctx;
	int openssl_websocket_private_data_index;
#endif
	struct libwebsocket_protocols *protocols;
	int count_protocols;
};


enum pending_timeout {
	NO_PENDING_TIMEOUT = 0,
	PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
	PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
	PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
	PENDING_TIMEOUT_AWAITING_PING,
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
	int protocol_index_for_broadcast_proxy;
	enum pending_timeout pending_timeout;
	unsigned long pending_timeout_limit;

	int sock;

	enum lws_rx_parse_state lws_rx_parse_state;

	/* 04 protocol specific */

	char key_b64[150];
	unsigned char masking_key_04[20];
	unsigned char frame_masking_nonce_04[4];
	unsigned char frame_mask_04[20];
	unsigned char frame_mask_index;
	size_t rx_packet_length;
	unsigned char opcode;
	unsigned char final;

	int pings_vs_pongs;
	unsigned char (*xor_mask)(struct libwebsocket *, unsigned char);
	char all_zero_nonce;

	enum lws_close_status close_reason;

	/* client support */
	char initial_handshake_hash_base64[30];
	enum connection_mode mode;
	char *c_path;
	char *c_host;
	char *c_origin;
	char *c_protocol;

#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
	BIO *client_bio;
	int use_ssl;
#endif

	void *user_space;
};

extern int
libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_parse(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);

extern int
libwebsocket_read(struct libwebsocket_context *this, struct libwebsocket *wsi,
					       unsigned char * buf, size_t len);

extern int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size);

extern int
lws_b64_decode_string(const char *in, char *out, int out_size);

extern int
lws_b64_selftest(void);

extern unsigned char
xor_no_mask(struct libwebsocket *wsi, unsigned char c);

extern unsigned char
xor_mask_04(struct libwebsocket *wsi, unsigned char c);

extern unsigned char
xor_mask_05(struct libwebsocket *wsi, unsigned char c);

extern struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *this, int fd);

extern int
insert_wsi(struct libwebsocket_context *this, struct libwebsocket *wsi);

extern int
delete_from_fd(struct libwebsocket_context *this, int fd);

extern void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					 enum pending_timeout reason, int secs);

#ifndef LWS_OPENSSL_SUPPORT

unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md);

void
MD5(const unsigned char *input, int ilen, unsigned char *output);

#endif
