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

#include "private-libwebsockets.h"

#ifdef WIN32

#else
#include <ifaddrs.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef LWS_OPENSSL_SUPPORT
int openssl_websocket_private_data_index;
#endif

#ifdef __MINGW32__
#include "../win32port/win32helpers/websock-w32.c"
#else
#ifdef __MINGW64__
#include "../win32port/win32helpers/websock-w32.c"
#endif
#endif

/*
 * In-place str to lower case
 */

static void
strtolower(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

/* file descriptor hash management */

struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *context, int fd)
{
	int h = LWS_FD_HASH(fd);
	int n = 0;

	for (n = 0; n < context->fd_hashtable[h].length; n++)
		if (context->fd_hashtable[h].wsi[n]->sock == fd)
			return context->fd_hashtable[h].wsi[n];

	return NULL;
}

int
insert_wsi(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	int h = LWS_FD_HASH(wsi->sock);

	if (context->fd_hashtable[h].length == MAX_CLIENTS - 1) {
		fprintf(stderr, "hash table overflow\n");
		return 1;
	}

	context->fd_hashtable[h].wsi[context->fd_hashtable[h].length++] = wsi;

	return 0;
}

int
delete_from_fd(struct libwebsocket_context *context, int fd)
{
	int h = LWS_FD_HASH(fd);
	int n = 0;

	for (n = 0; n < context->fd_hashtable[h].length; n++)
		if (context->fd_hashtable[h].wsi[n]->sock == fd) {
			while (n < context->fd_hashtable[h].length) {
				context->fd_hashtable[h].wsi[n] =
					    context->fd_hashtable[h].wsi[n + 1];
				n++;
			}
			context->fd_hashtable[h].length--;

			return 0;
		}

	fprintf(stderr, "Failed to find fd %d requested for "
						   "delete in hashtable\n", fd);
	return 1;
}

#ifdef LWS_OPENSSL_SUPPORT
static void
libwebsockets_decode_ssl_error(void)
{
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		fprintf(stderr, "*** %s\n", buf);
	}
}
#endif


static int
interface_to_sa(const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;
#ifdef WIN32
	/* TODO */
#else
	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
	struct sockaddr_in *sin;

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL; ifc = ifc->ifa_next) {
		if (strcmp(ifc->ifa_name, ifname))
			continue;
		if (ifc->ifa_addr == NULL)
			continue;
		sin = (struct sockaddr_in *)ifc->ifa_addr;
		if (sin->sin_family != AF_INET)
			continue;
		memcpy(addr, sin, addrlen);
		rc = 0;
	}

	freeifaddrs(ifr);
#endif
	return rc;
}

void
libwebsocket_close_and_free_session(struct libwebsocket_context *context,
			 struct libwebsocket *wsi, enum lws_close_status reason)
{
	int n;
	int old_state;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 2 +
						  LWS_SEND_BUFFER_POST_PADDING];
	int ret;
	int m;
	struct lws_tokens eff_buf;
	struct libwebsocket_extension *ext;

	if (!wsi)
		return;

	old_state = wsi->state;

	if (old_state == WSI_STATE_DEAD_SOCKET)
		return;

	wsi->close_reason = reason;

	/*
	 * are his extensions okay with him closing?  Eg he might be a mux
	 * parent and just his ch1 aspect is closing?
	 */


	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		m = wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_CHECK_OK_TO_REALLY_CLOSE,
				       wsi->active_extensions_user[n], NULL, 0);

		/*
		 * if somebody vetoed actually closing him at this time....
		 * up to the extension to track the attempted close, let's
		 * just bail
		 */

		if (m) {
			debug("extension vetoed close\n");
			return;
		}
	}



	/*
	 * flush any tx pending from extensions, since we may send close packet
	 * if there are problems with send, just nuke the connection
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* show every extension the new incoming data */

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
					wsi->protocol->owning_server,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_FLUSH_PENDING_TX,
				   wsi->active_extensions_user[n], &eff_buf, 0);
			if (m < 0) {
				fprintf(stderr, "Extension reports "
							       "fatal error\n");
				goto just_kill_connection;
			}
			if (m)
				/*
				 * at least one extension told us he has more
				 * to spill, so we will go around again after
				 */
				ret = 1;
		}

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len)
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							     eff_buf.token_len))
				goto just_kill_connection;
	}

	/*
	 * signal we are closing, libsocket_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * WSI_STATE_RETURNED_CLOSE_ALREADY and we will skip this.
	 *
	 * Likewise if it's a second call to close this connection after we
	 * sent the close indication to the peer already, we are in state
	 * WSI_STATE_AWAITING_CLOSE_ACK and will skip doing this a second time.
	 */

	if (old_state == WSI_STATE_ESTABLISHED &&
					  reason != LWS_CLOSE_STATUS_NOSTATUS) {

		debug("sending close indication...\n");

		n = libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING],
							    0, LWS_WRITE_CLOSE);
		if (!n) {
			/*
			 * we have sent a nice protocol level indication we
			 * now wish to close, we should not send anything more
			 */

			wsi->state = WSI_STATE_AWAITING_CLOSE_ACK;

			/* and we should wait for a reply for a bit */

			libwebsocket_set_timeout(wsi,
						  PENDING_TIMEOUT_CLOSE_ACK, 5);

			debug("sent close indication, awaiting ack\n");

			return;
		}

		/* else, the send failed and we should just hang up */
	}

just_kill_connection:

	debug("libwebsocket_close_and_free_session: just_kill_connection\n");

	/*
	 * we won't be servicing or receiving anything further from this guy
	 * remove this fd from wsi mapping hashtable
	 */

	if (wsi->sock)
		delete_from_fd(context, wsi->sock);

	/* delete it from the internal poll list if still present */

	for (n = 0; n < context->fds_count; n++) {
		if (context->fds[n].fd != wsi->sock)
			continue;
		while (n < context->fds_count - 1) {
			context->fds[n] = context->fds[n + 1];
			n++;
		}
		context->fds_count--;
		/* we only have to deal with one */
		n = context->fds_count;
	}

	/* remove also from external POLL support via protocol 0 */
	if (wsi->sock)
		context->protocols[0].callback(context, wsi,
		    LWS_CALLBACK_DEL_POLL_FD, (void *)(long)wsi->sock, NULL, 0);

	wsi->state = WSI_STATE_DEAD_SOCKET;

	/* tell the user it's all over for this guy */

	if (wsi->protocol && wsi->protocol->callback &&
			((old_state == WSI_STATE_ESTABLISHED) ||
			 (old_state == WSI_STATE_RETURNED_CLOSE_ALREADY) ||
			 (old_state == WSI_STATE_AWAITING_CLOSE_ACK))) {
		debug("calling back CLOSED\n");
		wsi->protocol->callback(context, wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);
	} else
		debug("not calling back closed, old_state=%d\n", old_state);

	/* deallocate any active extension contexts */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
				LWS_EXT_CALLBACK_DESTROY,
				       wsi->active_extensions_user[n], NULL, 0);

		free(wsi->active_extensions_user[n]);
	}

	/*
	 * inform all extensions in case they tracked this guy out of band
	 * even though not active on him specifically
	 */

	ext = context->extensions;
	while (ext && ext->callback) {
		ext->callback(context, ext, wsi,
				LWS_EXT_CALLBACK_DESTROY_ANY_WSI_CLOSING,
				       NULL, NULL, 0);
		ext++;
	}

	/* free up his parsing allocations */

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);

	if (wsi->c_address)
		free(wsi->c_address);

/*	fprintf(stderr, "closing fd=%d\n", wsi->sock); */

#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		n = SSL_get_fd(wsi->ssl);
		SSL_shutdown(wsi->ssl);
#ifdef WIN32
		closesocket(n);
#else
		close(n);
#endif
		SSL_free(wsi->ssl);
	} else {
#endif
		shutdown(wsi->sock, SHUT_RDWR);
#ifdef WIN32
		if (wsi->sock)
			closesocket(wsi->sock);
#else
		if (wsi->sock)
			close(wsi->sock);
#endif
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif
	if (wsi->protocol && wsi->protocol->per_session_data_size && wsi->user_space) /* user code may own */
		free(wsi->user_space);

	free(wsi);
}

/**
 * libwebsockets_hangup_on_client() - Server calls to terminate client
 *					connection
 * @context:	libwebsockets context
 * @fd:		Connection socket descriptor
 */

void
libwebsockets_hangup_on_client(struct libwebsocket_context *context, int fd)
{
	struct libwebsocket *wsi = wsi_from_fd(context, fd);

	if (wsi == NULL)
		return;

	libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
}


/**
 * libwebsockets_get_peer_addresses() - Get client address information
 * @fd:		Connection socket descriptor
 * @name:	Buffer to take client address name
 * @name_len:	Length of client address name buffer
 * @rip:	Buffer to take client address IP qotted quad
 * @rip_len:	Length of client address IP buffer
 *
 *	This function fills in @name and @rip with the name and IP of
 *	the client connected with socket descriptor @fd.  Names may be
 *	truncated if there is not enough room.  If either cannot be
 *	determined, they will be returned as valid zero-length strings.
 */

void
libwebsockets_get_peer_addresses(int fd, char *name, int name_len,
					char *rip, int rip_len)
{
	unsigned int len;
	struct sockaddr_in sin;
	struct hostent *host;
	struct hostent *host1;
	char ip[128];
	unsigned char *p;
	int n;
	struct sockaddr_un *un;

	rip[0] = '\0';
	name[0] = '\0';

	len = sizeof sin;
	if (getpeername(fd, (struct sockaddr *) &sin, &len) < 0) {
		perror("getpeername");
		return;
	}

	host = gethostbyaddr((char *) &sin.sin_addr, sizeof sin.sin_addr,
								       AF_INET);
	if (host == NULL) {
		perror("gethostbyaddr");
		return;
	}

	strncpy(name, host->h_name, name_len);
	name[name_len - 1] = '\0';

	host1 = gethostbyname(host->h_name);
	if (host1 == NULL)
		return;
	p = (unsigned char *)host1;
	n = 0;
	while (p != NULL) {
		p = (unsigned char *)host1->h_addr_list[n++];
		if (p == NULL)
			continue;
		if ((host1->h_addrtype != AF_INET)
#ifdef AF_LOCAL
			&& (host1->h_addrtype != AF_LOCAL)
#endif
			)
			continue;

		if (host1->h_addrtype == AF_INET)
			sprintf(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
#ifdef AF_LOCAL
		else {
			un = (struct sockaddr_un *)p;
			strncpy(ip, un->sun_path, sizeof(ip) - 1);
			ip[sizeof(ip) - 1] = '\0';
		}
#endif
		p = NULL;
		strncpy(rip, ip, rip_len);
		rip[rip_len - 1] = '\0';
	}
}

int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	int n;
	char *p = buf;

#ifdef WIN32
	for (n = 0; n < len; n++)
		p[n] = (unsigned char)rand();
#else
	n = read(context->fd_random, p, len);
#endif

	return n;
}

unsigned char *
libwebsockets_SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
	return SHA1(d, n, md);
}

void libwebsockets_00_spaceout(char *key, int spaces, int seed)
{
	char *p;

	key++;
	while (spaces--) {
		if (*key && (seed & 1))
			key++;
		seed >>= 1;

		p = key + strlen(key);
		while (p >= key) {
			p[1] = p[0];
			p--;
		}
		*key++ = ' ';
	}
}

void libwebsockets_00_spam(char *key, int count, int seed)
{
	char *p;

	key++;
	while (count--) {

		if (*key && (seed & 1))
			key++;
		seed >>= 1;

		p = key + strlen(key);
		while (p >= key) {
			p[1] = p[0];
			p--;
		}
		*key++ = 0x21 + ((seed & 0xffff) % 15);
		/* 4 would use it up too fast.. not like it matters */
		seed >>= 1;
	}
}

int lws_send_pipe_choked(struct libwebsocket *wsi)
{
	struct pollfd fds;

	fds.fd = wsi->sock;
	fds.events = POLLOUT;
	fds.revents = 0;

	if (poll(&fds, 1, 0) != 1)
		return 1;

	if ((fds.revents & POLLOUT) == 0)
		return 1;

	/* okay to send another packet without blocking */

	return 0;
}

int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
				struct libwebsocket *wsi, struct pollfd *pollfd)
{
	struct lws_tokens eff_buf;
	int n;
	int ret;
	int m;
	int handled = 0;

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		m = wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_IS_WRITEABLE,
				       wsi->active_extensions_user[n], NULL, 0);
		if (m > handled)
			handled = m;
	}

	if (handled == 1)
		goto notify_action;

	if (!wsi->extension_data_pending || handled == 2)
		goto user_service;

	/*
	 * check in on the active extensions, see if they
	 * had pending stuff to spill... they need to get the
	 * first look-in otherwise sequence will be disordered
	 *
	 * NULL, zero-length eff_buf means just spill pending
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* give every extension a chance to spill */

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
				wsi->protocol->owning_server,
				wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
				   wsi->active_extensions_user[n], &eff_buf, 0);
			if (m < 0) {
				fprintf(stderr, "ext reports fatal error\n");
				return -1;
			}
			if (m)
				/*
				 * at least one extension told us he has more
				 * to spill, so we will go around again after
				 */
				ret = 1;
		}

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							     eff_buf.token_len))
				return -1;
		} else
			continue;

		/* no extension has more to spill */

		if (!ret)
			continue;

		/*
		 * There's more to spill from an extension, but we just sent
		 * something... did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		debug("choked in POLLOUT service\n");

		/*
		 * Yes, he's choked.  Leave the POLLOUT masked on so we will
		 * come back here when he is unchoked.  Don't call the user
		 * callback to enforce ordering of spilling, he'll get called
		 * when we come back here and there's nothing more to spill.
		 */

		return 0;
	}

	wsi->extension_data_pending = 0;

user_service:
	/* one shot */

	if (pollfd) {
		pollfd->events &= ~POLLOUT;

		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLEAR_MODE_POLL_FD,
			(void *)(long)wsi->sock, NULL, POLLOUT);
	}

notify_action:

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT)
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
	else
		n = LWS_CALLBACK_SERVER_WRITEABLE;

	wsi->protocol->callback(context, wsi, n, wsi->user_space, NULL, 0);

	return 0;
}



void
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				     struct libwebsocket *wsi, unsigned int sec)
{
	int n;

	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */

	for (n = 0; n < wsi->count_active_extensions; n++)
		wsi->active_extensions[n]->callback(
				    context, wsi->active_extensions[n],
				    wsi, LWS_EXT_CALLBACK_1HZ,
				    wsi->active_extensions_user[n], NULL, sec);

	if (!wsi->pending_timeout)
		return;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */

	if (sec > wsi->pending_timeout_limit) {
		debug("TIMEDOUT WAITING\n");
		libwebsocket_close_and_free_session(context,
				wsi, LWS_CLOSE_STATUS_NOSTATUS);
	}
}

struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context)
{
	struct libwebsocket *new_wsi;
	int n;

	new_wsi = malloc(sizeof(struct libwebsocket));
	if (new_wsi == NULL) {
		fprintf(stderr, "Out of memory for new connection\n");
		return NULL;
	}

	memset(new_wsi, 0, sizeof(struct libwebsocket));
	new_wsi->count_active_extensions = 0;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;

	/* intialize the instance struct */

	new_wsi->state = WSI_STATE_HTTP;
	new_wsi->name_buffer_pos = 0;
	new_wsi->mode = LWS_CONNMODE_WS_SERVING;

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		new_wsi->utf8_token[n].token = NULL;
		new_wsi->utf8_token[n].token_len = 0;
	}

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;

	/*
	 * Default protocol is 76 / 00
	 * After 76, there's a header specified to inform which
	 * draft the client wants, when that's seen we modify
	 * the individual connection's spec revision accordingly
	 */
	new_wsi->ietf_spec_revision = 0;

	return new_wsi;
}

char *
libwebsockets_generate_client_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi, char *pkt)
{
	char hash[20];
	char *p = pkt;
	int n;
	struct libwebsocket_extension *ext;
	struct libwebsocket_extension *ext1;
	int ext_count = 0;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1 +
			 MAX_BROADCAST_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
	static const char magic_websocket_guid[] =
					 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	/*
	 * create the random key
	 */

	n = libwebsockets_get_random(context, hash, 16);
	if (n != 16) {
		fprintf(stderr, "Unable to read from random dev %s\n",
						SYSTEM_RANDOM_FILEPATH);
		free(wsi->c_path);
		free(wsi->c_host);
		if (wsi->c_origin)
			free(wsi->c_origin);
		if (wsi->c_protocol)
			free(wsi->c_protocol);
		libwebsocket_close_and_free_session(context, wsi,
					     LWS_CLOSE_STATUS_NOSTATUS);
		return NULL;
	}

	lws_b64_encode_string(hash, 16, wsi->key_b64,
						   sizeof wsi->key_b64);

	/*
	 * 00 example client handshake
	 *
	 * GET /socket.io/websocket HTTP/1.1
	 * Upgrade: WebSocket
	 * Connection: Upgrade
	 * Host: 127.0.0.1:9999
	 * Origin: http://127.0.0.1
	 * Sec-WebSocket-Key1: 1 0 2#0W 9 89 7  92 ^
	 * Sec-WebSocket-Key2: 7 7Y 4328 B2v[8(z1
	 * Cookie: socketio=websocket
	 *
	 * (Á®Ä0¶†≥
	 *
	 * 04 example client handshake
	 *
	 * GET /chat HTTP/1.1
	 * Host: server.example.com
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	 * Sec-WebSocket-Origin: http://example.com
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 4
	 */

	p += sprintf(p, "GET %s HTTP/1.1\x0d\x0a", wsi->c_path);

	if (wsi->ietf_spec_revision == 0) {
		unsigned char spaces_1, spaces_2;
		unsigned int max_1, max_2;
		unsigned int num_1, num_2;
		unsigned long product_1, product_2;
		char key_1[40];
		char key_2[40];
		unsigned int seed;
		unsigned int count;
		char challenge[16];

		libwebsockets_get_random(context, &spaces_1, sizeof(char));
		libwebsockets_get_random(context, &spaces_2, sizeof(char));

		spaces_1 = (spaces_1 % 12) + 1;
		spaces_2 = (spaces_2 % 12) + 1;

		max_1 = 4294967295 / spaces_1;
		max_2 = 4294967295 / spaces_2;

		libwebsockets_get_random(context, &num_1, sizeof(int));
		libwebsockets_get_random(context, &num_2, sizeof(int));

		num_1 = (num_1 % max_1);
		num_2 = (num_2 % max_2);

		challenge[0] = num_1 >> 24;
		challenge[1] = num_1 >> 16;
		challenge[2] = num_1 >> 8;
		challenge[3] = num_1;
		challenge[4] = num_2 >> 24;
		challenge[5] = num_2 >> 16;
		challenge[6] = num_2 >> 8;
		challenge[7] = num_2;

		product_1 = num_1 * spaces_1;
		product_2 = num_2 * spaces_2;

		sprintf(key_1, "%lu", product_1);
		sprintf(key_2, "%lu", product_2);

		libwebsockets_get_random(context, &seed, sizeof(int));
		libwebsockets_get_random(context, &count, sizeof(int));

		libwebsockets_00_spam(key_1, (count % 12) + 1, seed);

		libwebsockets_get_random(context, &seed, sizeof(int));
		libwebsockets_get_random(context, &count, sizeof(int));

		libwebsockets_00_spam(key_2, (count % 12) + 1, seed);

		libwebsockets_get_random(context, &seed, sizeof(int));

		libwebsockets_00_spaceout(key_1, spaces_1, seed);
		libwebsockets_00_spaceout(key_2, spaces_2, seed >> 16);

		p += sprintf(p, "Upgrade: WebSocket\x0d\x0a"
			"Connection: Upgrade\x0d\x0aHost: %s\x0d\x0a",
			wsi->c_host);
		if (wsi->c_origin)
			p += sprintf(p, "Origin: %s\x0d\x0a", wsi->c_origin);

		if (wsi->c_protocol)
			p += sprintf(p, "Sec-WebSocket-Protocol: %s"
					 "\x0d\x0a", wsi->c_protocol);

		p += sprintf(p, "Sec-WebSocket-Key1: %s\x0d\x0a", key_1);
		p += sprintf(p, "Sec-WebSocket-Key2: %s\x0d\x0a", key_2);

		/* give userland a chance to append, eg, cookies */

		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
				NULL, &p, (pkt + sizeof(pkt)) - p - 12);

		p += sprintf(p, "\x0d\x0a");

		if (libwebsockets_get_random(context, p, 8) != 8)
			return NULL;
		memcpy(&challenge[8], p, 8);
		p += 8;

		/* precompute what we want to see from the server */

		MD5((unsigned char *)challenge, 16,
		   (unsigned char *)wsi->initial_handshake_hash_base64);

		goto issue_hdr;
	}

	p += sprintf(p, "Host: %s\x0d\x0a", wsi->c_host);
	p += sprintf(p, "Upgrade: websocket\x0d\x0a");
	p += sprintf(p, "Connection: Upgrade\x0d\x0a"
				"Sec-WebSocket-Key: ");
	strcpy(p, wsi->key_b64);
	p += strlen(wsi->key_b64);
	p += sprintf(p, "\x0d\x0a");
	if (wsi->c_origin)
		p += sprintf(p, "Sec-WebSocket-Origin: %s\x0d\x0a",
							 wsi->c_origin);
	if (wsi->c_protocol)
		p += sprintf(p, "Sec-WebSocket-Protocol: %s\x0d\x0a",
						       wsi->c_protocol);

	/* tell the server what extensions we could support */

	p += sprintf(p, "Sec-WebSocket-Extensions: ");

	ext = context->extensions;
	while (ext && ext->callback) {

		n = 0;
		ext1 = context->extensions;

		while (ext1 && ext1->callback) {
			n |= ext1->callback(context, ext1, wsi,
				LWS_EXT_CALLBACK_CHECK_OK_TO_PROPOSE_EXTENSION,
					NULL, (char *)ext->name, 0);

			ext1++;
		}

		if (n) { /* an extension vetos us */
			debug("ext %s vetoed\n", (char *)ext->name);
			ext++;
			continue;
		}

		n = context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED,
				wsi->user_space, (char *)ext->name, 0);

		/*
		 * zero return from callback means
		 * go ahead and allow the extension,
		 * it's what we get if the callback is
		 * unhandled
		 */

		if (n) {
			ext++;
			continue;
		}

		/* apply it */

		if (ext_count)
			*p++ = ',';
		p += sprintf(p, "%s", ext->name);
		ext_count++;

		ext++;
	}

	p += sprintf(p, "\x0d\x0a");

	if (wsi->ietf_spec_revision)
		p += sprintf(p, "Sec-WebSocket-Version: %d\x0d\x0a",
					       wsi->ietf_spec_revision);

	/* give userland a chance to append, eg, cookies */

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
		NULL, &p, (pkt + sizeof(pkt)) - p - 12);

	p += sprintf(p, "\x0d\x0a");

	/* prepare the expected server accept response */

	strcpy((char *)buf, wsi->key_b64);
	strcpy((char *)&buf[strlen((char *)buf)], magic_websocket_guid);

	SHA1(buf, strlen((char *)buf), (unsigned char *)hash);

	lws_b64_encode_string(hash, 20,
			wsi->initial_handshake_hash_base64,
			     sizeof wsi->initial_handshake_hash_base64);

issue_hdr:

#if 0
	puts(pkt);
#endif

	/* done with these now */

	free(wsi->c_path);
	free(wsi->c_host);
	if (wsi->c_origin)
		free(wsi->c_origin);

	return p;
}

int
lws_client_interpret_server_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi)
{
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1 +
			MAX_BROADCAST_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
	char pkt[1024];
	char *p = &pkt[0];
	const char *pc;
	const char *c;
	int more = 1;
	int okay = 0;
	char ext_name[128];
	struct libwebsocket_extension *ext;
	void *v;
	int len = 0;
	int n;
	static const char magic_websocket_04_masking_guid[] =
					 "61AC5F19-FBBA-4540-B96F-6561F1AB40A8";

	/*
	 * 00 / 76 -->
	 *
	 * HTTP/1.1 101 WebSocket Protocol Handshake
	 * Upgrade: WebSocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Origin: http://127.0.0.1
	 * Sec-WebSocket-Location: ws://127.0.0.1:9999/socket.io/websocket
	 *
	 * xxxxxxxxxxxxxxxx
	 */

	if (wsi->ietf_spec_revision == 0) {
		if (!wsi->utf8_token[WSI_TOKEN_HTTP].token_len ||
			!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len ||
			(!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len &&
			wsi->c_protocol != NULL)) {
			debug("libwebsocket_client_handshake "
					"missing required header(s)\n");
			pkt[len] = '\0';
			debug("%s", pkt);
			goto bail3;
		}

		strtolower(wsi->utf8_token[WSI_TOKEN_HTTP].token);
		if (strncmp(wsi->utf8_token[WSI_TOKEN_HTTP].token, "101", 3)) {
			fprintf(stderr, "libwebsocket_client_handshake "
				"server sent bad HTTP response '%s'\n",
				wsi->utf8_token[WSI_TOKEN_HTTP].token);
			goto bail3;
		}

		if (wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len < 16) {
			fprintf(stderr, "libwebsocket_client_handshake "
				"challenge reply too short %d\n",
				wsi->utf8_token[
					WSI_TOKEN_CHALLENGE].token_len);
			pkt[len] = '\0';
			debug("%s", pkt);
			goto bail3;

		}

		goto select_protocol;
	}

	/*
	 * well, what the server sent looked reasonable for syntax.
	 * Now let's confirm it sent all the necessary headers
	 */
#if 0
	fprintf(stderr, "WSI_TOKEN_HTTP: %d\n",
				    wsi->utf8_token[WSI_TOKEN_HTTP].token_len);
	fprintf(stderr, "WSI_TOKEN_UPGRADE: %d\n",
				 wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len);
	fprintf(stderr, "WSI_TOKEN_CONNECTION: %d\n",
			      wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len);
	fprintf(stderr, "WSI_TOKEN_ACCEPT: %d\n",
				  wsi->utf8_token[WSI_TOKEN_ACCEPT].token_len);
	fprintf(stderr, "WSI_TOKEN_NONCE: %d\n",
				   wsi->utf8_token[WSI_TOKEN_NONCE].token_len);
	fprintf(stderr, "WSI_TOKEN_PROTOCOL: %d\n",
				wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len);
#endif
	if (!wsi->utf8_token[WSI_TOKEN_HTTP].token_len ||
	    !wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
	    !wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len ||
	    !wsi->utf8_token[WSI_TOKEN_ACCEPT].token_len ||
	    (!wsi->utf8_token[WSI_TOKEN_NONCE].token_len &&
				   wsi->ietf_spec_revision == 4) ||
	    (!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len &&
						    wsi->c_protocol != NULL)) {
		debug("libwebsocket_client_handshake "
					"missing required header(s)\n");
		pkt[len] = '\0';
		debug("%s", pkt);
		goto bail3;
	}

	/*
	 * Everything seems to be there, now take a closer look at what
	 * is in each header
	 */

	strtolower(wsi->utf8_token[WSI_TOKEN_HTTP].token);
	if (strncmp(wsi->utf8_token[WSI_TOKEN_HTTP].token, "101", 3)) {
		fprintf(stderr, "libwebsocket_client_handshake "
				"server sent bad HTTP response '%s'\n",
				 wsi->utf8_token[WSI_TOKEN_HTTP].token);
		goto bail3;
	}

	strtolower(wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
	if (strcmp(wsi->utf8_token[WSI_TOKEN_UPGRADE].token,
							 "websocket")) {
		fprintf(stderr, "libwebsocket_client_handshake server "
				"sent bad Upgrade header '%s'\n",
				  wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
		goto bail3;
	}

	strtolower(wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
	if (strcmp(wsi->utf8_token[WSI_TOKEN_CONNECTION].token,
							   "upgrade")) {
		fprintf(stderr, "libwebsocket_client_handshake server "
				"sent bad Connection hdr '%s'\n",
			   wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
		goto bail3;
	}

select_protocol:
	pc = wsi->c_protocol;
	if (pc == NULL)
		fprintf(stderr, "lws_client_interpret_server_handshake: "
							  "NULL c_protocol\n");
	else
		debug("lws_client_interpret_server_handshake: "
						      "cPprotocol='%s'\n", pc);

	/*
	 * confirm the protocol the server wants to talk was in the list
	 * of protocols we offered
	 */

	if (!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len) {

		fprintf(stderr, "lws_client_interpret_server_handshake "
					       "WSI_TOKEN_PROTOCOL is null\n");
		/*
		 * no protocol name to work from,
		 * default to first protocol
		 */
		wsi->protocol = &context->protocols[0];
		wsi->c_callback = wsi->protocol->callback;
		free(wsi->c_protocol);

		goto check_accept;
	}

	while (*pc && !okay) {
		if ((!strncmp(pc, wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
		 wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len)) &&
		 (pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == ',' ||
		  pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == '\0')) {
			okay = 1;
			continue;
		}
		while (*pc && *pc != ',')
			pc++;
		while (*pc && *pc != ' ')
			pc++;
	}

	/* done with him now */

	if (wsi->c_protocol)
		free(wsi->c_protocol);

	if (!okay) {
		fprintf(stderr, "libwebsocket_client_handshake server "
					"sent bad protocol '%s'\n",
				 wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
		goto bail2;
	}

	/*
	 * identify the selected protocol struct and set it
	 */
	n = 0;
	wsi->protocol = NULL;
	while (context->protocols[n].callback && !wsi->protocol) {  /* Stop after finding first one?? */
		if (strcmp(wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
					   context->protocols[n].name) == 0) {
			wsi->protocol = &context->protocols[n];
			wsi->c_callback = wsi->protocol->callback;
		}
		n++;
	}

	if (wsi->protocol == NULL) {
		fprintf(stderr, "libwebsocket_client_handshake server "
				"requested protocol '%s', which we "
				"said we supported but we don't!\n",
				 wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
		goto bail2;
	}


	/* instantiate the accepted extensions */

	if (!wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token_len) {
		debug("no client extenstions allowed by server\n");
		goto check_accept;
	}

	/*
	 * break down the list of server accepted extensions
	 * and go through matching them or identifying bogons
	 */

	c = wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token;
	n = 0;
	while (more) {

		if (*c && (*c != ',' && *c != ' ' && *c != '\t')) {
			ext_name[n] = *c++;
			if (n < sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		/* check we actually support it */

		debug("checking client ext %s\n", ext_name);

		n = 0;
		ext = wsi->protocol->owning_server->extensions;
		while (ext && ext->callback) {

			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			n = 1;

			debug("instantiating client ext %s\n", ext_name);

			/* instantiate the extension on this conn */

			wsi->active_extensions_user[
				wsi->count_active_extensions] =
					 malloc(ext->per_session_data_size);
			memset(wsi->active_extensions_user[
				wsi->count_active_extensions], 0,
						    ext->per_session_data_size);
			wsi->active_extensions[
				  wsi->count_active_extensions] = ext;

			/* allow him to construct his context */

			ext->callback(wsi->protocol->owning_server,
				ext, wsi,
				   LWS_EXT_CALLBACK_CLIENT_CONSTRUCT,
					wsi->active_extensions_user[
					 wsi->count_active_extensions],
								   NULL, 0);

			wsi->count_active_extensions++;

			ext++;
		}

		if (n == 0) {
			fprintf(stderr, "Server said we should use"
				  "an unknown extension '%s'!\n", ext_name);
			goto bail2;
		}

		n = 0;
	}


check_accept:

	if (wsi->ietf_spec_revision == 0) {

		if (memcmp(wsi->initial_handshake_hash_base64,
			  wsi->utf8_token[WSI_TOKEN_CHALLENGE].token, 16)) {
			fprintf(stderr, "libwebsocket_client_handshake "
					   "failed 00 challenge compare\n");
				pkt[len] = '\0';
				fprintf(stderr, "%s", pkt);
				goto bail2;
		}

		goto accept_ok;
	}

	/*
	 * Confirm his accept token is the one we precomputed
	 */

	if (strcmp(wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
				  wsi->initial_handshake_hash_base64)) {
		fprintf(stderr, "libwebsocket_client_handshake server "
			"sent bad ACCEPT '%s' vs computed '%s'\n",
			wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
					wsi->initial_handshake_hash_base64);
		goto bail2;
	}

	if (wsi->ietf_spec_revision == 4) {
		/*
		 * Calculate the 04 masking key to use when
		 * sending data to server
		 */

		strcpy((char *)buf, wsi->key_b64);
		p = (char *)buf + strlen(wsi->key_b64);
		strcpy(p, wsi->utf8_token[WSI_TOKEN_NONCE].token);
		p += wsi->utf8_token[WSI_TOKEN_NONCE].token_len;
		strcpy(p, magic_websocket_04_masking_guid);
		SHA1(buf, strlen((char *)buf), wsi->masking_key_04);
	}
accept_ok:

	/* allocate the per-connection user memory (if any) */
	if (wsi->protocol->per_session_data_size &&
					  !libwebsocket_ensure_user_space(wsi))
		goto bail2;

	/* clear his proxy connection timeout */

	libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/* mark him as being alive */

	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->mode = LWS_CONNMODE_WS_CLIENT;

	debug("handshake OK for protocol %s\n", wsi->protocol->name);

	/* call him back to inform him he is up */

	wsi->protocol->callback(context, wsi,
				LWS_CALLBACK_CLIENT_ESTABLISHED,
						     wsi->user_space, NULL, 0);

	/*
	 * inform all extensions, not just active ones since they
	 * already know
	 */

	ext = context->extensions;

	while (ext && ext->callback) {
		v = NULL;
		for (n = 0; n < wsi->count_active_extensions; n++)
			if (wsi->active_extensions[n] == ext)
				v = wsi->active_extensions_user[n];

		ext->callback(context, ext, wsi,
			  LWS_EXT_CALLBACK_ANY_WSI_ESTABLISHED, v, NULL, 0);
		ext++;
	}

	return 0;

bail3:
	if (wsi->c_protocol)
		free(wsi->c_protocol);

bail2:
	if (wsi->c_callback) wsi->c_callback(context, wsi,
       LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
			 wsi->user_space,
			 NULL, 0);
	libwebsocket_close_and_free_session(context, wsi,
						 LWS_CLOSE_STATUS_NOSTATUS);  // But this should be LWS_CLOSE_STATUS_PROTOCOL_ERR

	return 1;
}



/**
 * libwebsocket_service_fd() - Service polled socket with something waiting
 * @context:	Websocket context
 * @pollfd:	The pollfd entry describing the socket fd and which events
 *		happened.
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */

int
libwebsocket_service_fd(struct libwebsocket_context *context,
							  struct pollfd *pollfd)
{
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1 +
			 MAX_BROADCAST_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
	struct libwebsocket *wsi;
	struct libwebsocket *new_wsi;
	int n;
	int m;
	ssize_t len;
	int accept_fd;
	unsigned int clilen;
	struct sockaddr_in cli_addr;
	struct timeval tv;
	char pkt[1024];
	char *p = &pkt[0];
	int more = 1;
	struct lws_tokens eff_buf;
	int opt = 1;
	char c;

#ifdef LWS_OPENSSL_SUPPORT
	char ssl_err_buf[512];
#endif
	/*
	 * you can call us with pollfd = NULL to just allow the once-per-second
	 * global timeout checks; if less than a second since the last check
	 * it returns immediately then.
	 */

	gettimeofday(&tv, NULL);

	if (context->last_timeout_check_s != tv.tv_sec) {
		context->last_timeout_check_s = tv.tv_sec;

		/* global timeout check once per second */

		for (n = 0; n < context->fds_count; n++) {
			wsi = wsi_from_fd(context, context->fds[n].fd);

			libwebsocket_service_timeout_check(context, wsi,
								     tv.tv_sec);
		}
	}

	/* just here for timeout management? */

	if (pollfd == NULL)
		return 0;

	/* no, here to service a socket descriptor */

	wsi = wsi_from_fd(context, pollfd->fd);

	if (wsi == NULL)
		return 1;

	switch (wsi->mode) {
	case LWS_CONNMODE_SERVER_LISTENER:

		/* pollin means a client has connected to us then */

		if (!pollfd->revents & POLLIN)
			break;

		if (context->fds_count >= MAX_CLIENTS) {
			fprintf(stderr, "too busy to accept new client\n");
			break;
		}

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			debug("ERROR on accept\n");
			return -1;
		}

		/* Disable Nagle */
		opt = 1;
		setsockopt(accept_fd, IPPROTO_TCP, TCP_NODELAY,
					      (const void *)&opt, sizeof(opt));

		/*
		 * look at who we connected to and give user code a chance
		 * to reject based on client IP.  There's no protocol selected
		 * yet so we issue this to protocols[0]
		 */

		if ((context->protocols[0].callback)(context, wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					   (void *)(long)accept_fd, NULL, 0)) {
			debug("Callback denied network connection\n");
#ifdef WIN32
			closesocket(accept_fd);
#else
			close(accept_fd);
#endif
			break;
		}

		/* accepting connection to main listener */

		new_wsi = libwebsocket_create_new_server_wsi(context);
		if (new_wsi == NULL)
			break;

		new_wsi->sock = accept_fd;


#ifdef LWS_OPENSSL_SUPPORT
		new_wsi->ssl = NULL;

		if (context->use_ssl) {

			new_wsi->ssl = SSL_new(context->ssl_ctx);
			if (new_wsi->ssl == NULL) {
				fprintf(stderr, "SSL_new failed: %s\n",
				    ERR_error_string(SSL_get_error(
				    new_wsi->ssl, 0), NULL));
				    libwebsockets_decode_ssl_error();
				free(new_wsi);
				break;
			}

			SSL_set_fd(new_wsi->ssl, accept_fd);

			n = SSL_accept(new_wsi->ssl);
			if (n != 1) {
				/*
				 * browsers seem to probe with various
				 * ssl params which fail then retry
				 * and succeed
				 */
				debug("SSL_accept failed skt %u: %s\n",
				      pollfd->fd,
				      ERR_error_string(SSL_get_error(
				      new_wsi->ssl, n), NULL));
				SSL_free(
				       new_wsi->ssl);
				free(new_wsi);
				break;
			}

			debug("accepted new SSL conn  "
			      "port %u on fd=%d SSL ver %s\n",
				ntohs(cli_addr.sin_port), accept_fd,
				  SSL_get_version(new_wsi->ssl));

		} else
#endif
			debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

		insert_wsi(context, new_wsi);

		/*
		 * make sure NO events are seen yet on this new socket
		 * (otherwise we inherit old fds[client].revents from
		 * previous socket there and die mysteriously! )
		 */
		context->fds[context->fds_count].revents = 0;

		context->fds[context->fds_count].events = POLLIN;
		context->fds[context->fds_count++].fd = accept_fd;

		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, new_wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)accept_fd, NULL, POLLIN);

		break;

	case LWS_CONNMODE_BROADCAST_PROXY_LISTENER:

		/* as we are listening, POLLIN means accept() is needed */

		if (!pollfd->revents & POLLIN)
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			debug("ERROR on accept\n");
			return -1;
		}

		if (context->fds_count >= MAX_CLIENTS) {
			fprintf(stderr, "too busy to accept new broadcast "
							      "proxy client\n");
#ifdef WIN32
			closesocket(accept_fd);
#else
			close(accept_fd);
#endif
			break;
		}

		/* create a dummy wsi for the connection and add it */

		new_wsi = malloc(sizeof(struct libwebsocket));
		memset(new_wsi, 0, sizeof(struct libwebsocket));
		new_wsi->sock = accept_fd;
		new_wsi->mode = LWS_CONNMODE_BROADCAST_PROXY;
		new_wsi->state = WSI_STATE_ESTABLISHED;
		new_wsi->count_active_extensions = 0;
		/* note which protocol we are proxying */
		new_wsi->protocol_index_for_broadcast_proxy =
					wsi->protocol_index_for_broadcast_proxy;
		insert_wsi(context, new_wsi);

		/* add connected socket to internal poll array */

		context->fds[context->fds_count].revents = 0;
		context->fds[context->fds_count].events = POLLIN;
		context->fds[context->fds_count++].fd = accept_fd;

		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, new_wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)accept_fd, NULL, POLLIN);

		break;

	case LWS_CONNMODE_BROADCAST_PROXY:

		/* handle session socket closed */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			debug("Session Socket %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(context, wsi,
						       LWS_CLOSE_STATUS_NORMAL);
			return 1;
		}

		/*
		 * either extension code with stuff to spill, or the user code,
		 * requested a callback when it was OK to write
		 */

		if (pollfd->revents & POLLOUT)
			if (lws_handle_POLLOUT_event(context, wsi,
								 pollfd) < 0) {
				libwebsocket_close_and_free_session(
					context, wsi, LWS_CLOSE_STATUS_NORMAL);
				return 1;
			}

		/* any incoming data ready? */

		if (!(pollfd->revents & POLLIN))
			break;

		/* get the issued broadcast payload from the socket */

		len = read(pollfd->fd, buf + LWS_SEND_BUFFER_PRE_PADDING,
							 MAX_BROADCAST_PAYLOAD);
		if (len < 0) {
			fprintf(stderr, "Error reading broadcast payload\n");
			break;
		}

		/* broadcast it to all guys with this protocol index */

		for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

			for (m = 0; m < context->fd_hashtable[n].length; m++) {

				new_wsi = context->fd_hashtable[n].wsi[m];

				/* only to clients we are serving to */

				if (new_wsi->mode != LWS_CONNMODE_WS_SERVING)
					continue;

				/*
				 * never broadcast to non-established
				 * connection
				 */

				if (new_wsi->state != WSI_STATE_ESTABLISHED)
					continue;

				/*
				 * only broadcast to connections using
				 * the requested protocol
				 */

				if (new_wsi->protocol->protocol_index !=
					wsi->protocol_index_for_broadcast_proxy)
					continue;

				/* broadcast it to this connection */

				new_wsi->protocol->callback(context, new_wsi,
					LWS_CALLBACK_BROADCAST,
					new_wsi->user_space,
					buf + LWS_SEND_BUFFER_PRE_PADDING, len);
			}
		}
		break;

	case LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY:

		/* handle proxy hung up on us */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Proxy connection %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		n = recv(wsi->sock, pkt, sizeof pkt, 0);
		if (n < 0) {
			libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			fprintf(stderr, "ERROR reading from proxy socket\n");
			return 1;
		}

		pkt[13] = '\0';
		if (strcmp(pkt, "HTTP/1.0 200 ") != 0) {
			libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			fprintf(stderr, "ERROR from proxy: %s\n", pkt);
			return 1;
		}

		/* clear his proxy connection timeout */

		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* fallthru */

	case LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE:

	#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->use_ssl && !wsi->ssl) {

			wsi->ssl = SSL_new(context->ssl_client_ctx);
			wsi->client_bio = BIO_new_socket(wsi->sock,
								   BIO_NOCLOSE);
			SSL_set_bio(wsi->ssl, wsi->client_bio, wsi->client_bio);

			SSL_set_ex_data(wsi->ssl,
					openssl_websocket_private_data_index,
								       context);
		}		

		if (wsi->use_ssl) {
			if (SSL_connect(wsi->ssl) <= 0) {

				/*
				 * retry if new data comes until we
				 * run into the connection timeout or win
				 */

				fprintf(stderr, "SSL connect error %s\n",
					ERR_error_string(ERR_get_error(),
								  ssl_err_buf));
				return 0;
			}

			n = SSL_get_verify_result(wsi->ssl);
			if ((n != X509_V_OK) && (
				n != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
							   wsi->use_ssl != 2)) {

				fprintf(stderr, "server's cert didn't "
							   "look good %d\n", n);
				libwebsocket_close_and_free_session(context,
						wsi, LWS_CLOSE_STATUS_NOSTATUS);
				return 1;
			}
		} else
			wsi->ssl = NULL;
	#endif

		p = libwebsockets_generate_client_handshake(context, wsi, p);
		if (p == NULL)
			return 1;

		/* send our request to the server */

	#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->use_ssl)
			n = SSL_write(wsi->ssl, pkt, p - pkt);
		else
	#endif
			n = send(wsi->sock, pkt, p - pkt, 0);

		if (n < 0) {
			fprintf(stderr, "ERROR writing to client socket\n");
			libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		wsi->parser_state = WSI_TOKEN_NAME_PART;
		wsi->mode = LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY;
		libwebsocket_set_timeout(wsi,
				PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE, 5);

		break;

	case LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY:

		/* handle server hung up on us */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Server connection %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			goto bail3;
		}


		/* interpret the server response */

		/*
		 *  HTTP/1.1 101 Switching Protocols
		 *  Upgrade: websocket
		 *  Connection: Upgrade
		 *  Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
		 *  Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
		 *  Sec-WebSocket-Protocol: chat
		 */

		/*
		 * we have to take some care here to only take from the
		 * socket bytewise.  The browser may (and has been seen to
		 * in the case that onopen() performs websocket traffic)
		 * coalesce both handshake response and websocket traffic
		 * in one packet, since at that point the connection is
		 * definitively ready from browser pov.
		 */

		len = 1;
		while (wsi->parser_state != WSI_PARSING_COMPLETE && len > 0) {
#ifdef LWS_OPENSSL_SUPPORT
			if (wsi->use_ssl)
				len = SSL_read(wsi->ssl, &c, 1);
			 else
#endif
				len = recv(wsi->sock, &c, 1, 0);

			libwebsocket_parse(wsi, c);
		}

		/*
		 * hs may also be coming in multiple packets, there is a 5-sec
		 * libwebsocket timeout still active here too, so if parsing did
		 * not complete just wait for next packet coming in this state
		 */

		if (wsi->parser_state != WSI_PARSING_COMPLETE)
			break;

		/*
		 * otherwise deal with the handshake.  If there's any
		 * packet traffic already arrived we'll trigger poll() again
		 * right away and deal with it that way
		 */

		return lws_client_interpret_server_handshake(context, wsi);

bail3:
		if (wsi->c_protocol)
			free(wsi->c_protocol);
		libwebsocket_close_and_free_session(context, wsi,
						    LWS_CLOSE_STATUS_NOSTATUS);
		return 1;

	case LWS_CONNMODE_WS_CLIENT_WAITING_EXTENSION_CONNECT:
		fprintf(stderr,
			 "LWS_CONNMODE_WS_CLIENT_WAITING_EXTENSION_CONNECT\n");
		break;

	case LWS_CONNMODE_WS_CLIENT_PENDING_CANDIDATE_CHILD:
		fprintf(stderr,
			   "LWS_CONNMODE_WS_CLIENT_PENDING_CANDIDATE_CHILD\n");
		break;


	case LWS_CONNMODE_WS_SERVING:
	case LWS_CONNMODE_WS_CLIENT:

		/* handle session socket closed */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Session Socket %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		/* the guy requested a callback when it was OK to write */

		if ((pollfd->revents & POLLOUT) &&
					    wsi->state == WSI_STATE_ESTABLISHED)
			if (lws_handle_POLLOUT_event(context, wsi,
								  pollfd) < 0) {
				libwebsocket_close_and_free_session(
					 context, wsi, LWS_CLOSE_STATUS_NORMAL);
				return 1;
			}


		/* any incoming data ready? */

		if (!(pollfd->revents & POLLIN))
			break;

#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->ssl)
			eff_buf.token_len = SSL_read(wsi->ssl, buf, sizeof buf);
		else
#endif
			eff_buf.token_len =
					   recv(pollfd->fd, buf, sizeof buf, 0);

		if (eff_buf.token_len < 0) {
			fprintf(stderr, "Socket read returned %d\n",
							    eff_buf.token_len);
			if (errno != EINTR)
				libwebsocket_close_and_free_session(context,
					       wsi, LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}
		if (!eff_buf.token_len) {
			libwebsocket_close_and_free_session(context, wsi,
						    LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		/*
		 * give any active extensions a chance to munge the buffer
		 * before parse.  We pass in a pointer to an lws_tokens struct
		 * prepared with the default buffer and content length that's in
		 * there.  Rather than rewrite the default buffer, extensions
		 * that expect to grow the buffer can adapt .token to
		 * point to their own per-connection buffer in the extension
		 * user allocation.  By default with no extensions or no
		 * extension callback handling, just the normal input buffer is
		 * used then so it is efficient.
		 */

		eff_buf.token = (char *)buf;

		more = 1;
		while (more) {

			more = 0;

			for (n = 0; n < wsi->count_active_extensions; n++) {
				m = wsi->active_extensions[n]->callback(context,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_PACKET_RX_PREPARSE,
					wsi->active_extensions_user[n],
								   &eff_buf, 0);
				if (m < 0) {
					fprintf(stderr,
					    "Extension reports fatal error\n");
					libwebsocket_close_and_free_session(
						context, wsi,
						    LWS_CLOSE_STATUS_NOSTATUS);
					return 1;
				}
				if (m)
					more = 1;
			}

			/* service incoming data */

			if (eff_buf.token_len) {
				n = libwebsocket_read(context, wsi,
					(unsigned char *)eff_buf.token,
							    eff_buf.token_len);
				if (n < 0)
					/* we closed wsi */
					return 1;
			}

			eff_buf.token = NULL;
			eff_buf.token_len = 0;
		}
		break;
	}

	return 0;
}


/**
 * libwebsocket_context_destroy() - Destroy the websocket context
 * @context:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
void
libwebsocket_context_destroy(struct libwebsocket_context *context)
{
	int n;
	int m;
	struct libwebsocket *wsi;
	struct libwebsocket_extension *ext;

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++)
		for (m = 0; m < context->fd_hashtable[n].length; m++) {
			wsi = context->fd_hashtable[n].wsi[m];
			libwebsocket_close_and_free_session(context, wsi,
						    LWS_CLOSE_STATUS_GOINGAWAY);
		}

	/*
	 * give all extensions a chance to clean up any per-context
	 * allocations they might have made
	 */

	ext = context->extensions;
	m = LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT;
	if (context->listen_port)
		m = LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT;
	while (ext && ext->callback) {
		ext->callback(context, ext, NULL, m, NULL, NULL, 0);
		ext++;
	}

#ifdef WIN32
#else
	close(context->fd_random);
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);
#endif

	free(context);

#ifdef WIN32
	WSACleanup();
#endif
}

/**
 * libwebsocket_service() - Service any pending websocket activity
 * @context:	Websocket context
 * @timeout_ms:	Timeout for poll; 0 means return immediately if nothing needed
 *		service otherwise block and service immediately, returning
 *		after the timeout if nothing needed service.
 *
 *	This function deals with any pending websocket traffic, for three
 *	kinds of event.  It handles these events on both server and client
 *	types of connection the same.
 *
 *	1) Accept new connections to our context's server
 *
 *	2) Perform pending broadcast writes initiated from other forked
 *	   processes (effectively serializing asynchronous broadcasts)
 *
 *	3) Call the receive callback for incoming frame data received by
 *	    server or client connections.
 *
 *	You need to call this service function periodically to all the above
 *	functions to happen; if your application is single-threaded you can
 *	just call it in your main event loop.
 *
 *	Alternatively you can fork a new process that asynchronously handles
 *	calling this service in a loop.  In that case you are happy if this
 *	call blocks your thread until it needs to take care of something and
 *	would call it with a large nonzero timeout.  Your loop then takes no
 *	CPU while there is nothing happening.
 *
 *	If you are calling it in a single-threaded app, you don't want it to
 *	wait around blocking other things in your loop from happening, so you
 *	would call it with a timeout_ms of 0, so it returns immediately if
 *	nothing is pending, or as soon as it services whatever was pending.
 */


int
libwebsocket_service(struct libwebsocket_context *context, int timeout_ms)
{
	int n;

	/* stay dead once we are dead */

	if (context == NULL)
		return 1;

	/* wait for something to need service */

	n = poll(context->fds, context->fds_count, timeout_ms);
	if (n == 0) /* poll timeout */
		return 0;

	if (n < 0) {
		/*
		fprintf(stderr, "Listen Socket dead\n");
		*/
		return -1;
	}

	/* handle accept on listening socket? */

	for (n = 0; n < context->fds_count; n++)
		if (context->fds[n].revents)
			if (libwebsocket_service_fd(context,
							&context->fds[n]) < 0)
				return -1;
	return 0;
}

int
lws_any_extension_handled(struct libwebsocket_context *context,
			  struct libwebsocket *wsi,
			  enum libwebsocket_extension_callback_reasons r,
						       void *v, size_t len)
{
	int n;
	int handled = 0;

	/* maybe an extension will take care of it for us */

	for (n = 0; n < wsi->count_active_extensions && !handled; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		handled |= wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			r, wsi->active_extensions_user[n], v, len);
	}

	return handled;
}


void *
lws_get_extension_user_matching_ext(struct libwebsocket *wsi,
					   struct libwebsocket_extension *ext)
{
	int n = 0;

	if (wsi == NULL)
		return NULL;

	while (n < wsi->count_active_extensions) {
		if (wsi->active_extensions[n] != ext) {
			n++;
			continue;
		}
		return wsi->active_extensions_user[n];
	}

	return NULL;
}

/**
 * libwebsocket_callback_on_writable() - Request a callback when this socket
 *					 becomes able to be written to without
 *					 blocking
 *
 * @context:	libwebsockets context
 * @wsi:	Websocket connection instance to get callback for
 */

int
libwebsocket_callback_on_writable(struct libwebsocket_context *context,
						      struct libwebsocket *wsi)
{
	int n;
	int handled = 0;

	/* maybe an extension will take care of it for us */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		handled |= wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_REQUEST_ON_WRITEABLE,
				       wsi->active_extensions_user[n], NULL, 0);
	}

	if (handled)
		return 1;

	for (n = 0; n < context->fds_count; n++)
		if (context->fds[n].fd == wsi->sock) {
			context->fds[n].events |= POLLOUT;
			n = context->fds_count + 1;
		}

	if (n == context->fds_count)
		fprintf(stderr, "libwebsocket_callback_on_writable: "
				      "failed to find socket %d\n", wsi->sock);

	/* external POLL support via protocol 0 */
	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_SET_MODE_POLL_FD,
		(void *)(long)wsi->sock, NULL, POLLOUT);

	return 1;
}

/**
 * libwebsocket_callback_on_writable_all_protocol() - Request a callback for
 *			all connections using the given protocol when it
 *			becomes possible to write to each socket without
 *			blocking in turn.
 *
 * @protocol:	Protocol whose connections will get callbacks
 */

int
libwebsocket_callback_on_writable_all_protocol(
				  const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	int m;
	struct libwebsocket *wsi;

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

		for (m = 0; m < context->fd_hashtable[n].length; m++) {

			wsi = context->fd_hashtable[n].wsi[m];

			if (wsi->protocol == protocol)
				libwebsocket_callback_on_writable(context, wsi);
		}
	}

	return 0;
}

/**
 * libwebsocket_set_timeout() - marks the wsi as subject to a timeout
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 * @reason:	timeout reason
 * @secs:	how many seconds
 */

void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					  enum pending_timeout reason, int secs)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	wsi->pending_timeout_limit = tv.tv_sec + secs;
	wsi->pending_timeout = reason;
}


/**
 * libwebsocket_get_socket_fd() - returns the socket file descriptor
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 */

int
libwebsocket_get_socket_fd(struct libwebsocket *wsi)
{
	return wsi->sock;
}

/**
 * libwebsocket_rx_flow_control() - Enable and disable socket servicing for
 *				receieved packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * @wsi:	Websocket connection instance to get callback for
 * @enable:	0 = disable read servicing for this connection, 1 = enable
 */

int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;
	int n;

	for (n = 0; n < context->fds_count; n++)
		if (context->fds[n].fd == wsi->sock) {
			if (enable)
				context->fds[n].events |= POLLIN;
			else
				context->fds[n].events &= ~POLLIN;

			return 0;
		}

	if (enable)
		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_SET_MODE_POLL_FD,
			(void *)(long)wsi->sock, NULL, POLLIN);
	else
		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLEAR_MODE_POLL_FD,
			(void *)(long)wsi->sock, NULL, POLLIN);

#if 0
	fprintf(stderr, "libwebsocket_rx_flow_control "
						     "unable to find socket\n");
#endif
	return 1;
}

/**
 * libwebsocket_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * @context:	Websocket context
 */


extern const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *context)
{
	return (const char *)context->canonical_hostname;
}


static void sigpipe_handler(int x)
{
}

#ifdef LWS_OPENSSL_SUPPORT
static int
OpenSSL_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{

	SSL *ssl;
	int n;
	struct libwebsocket_context *context;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	/*
	 * !!! nasty openssl requires the index to come as a library-scope
	 * static
	 */
	context = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

	n = context->protocols[0].callback(NULL, NULL,
		LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
						   x509_ctx, ssl, preverify_ok);

	/* convert return code from 0 = OK to 1 = OK */

	if (!n)
		n = 1;
	else
		n = 0;

	return n;
}
#endif


/**
 * libwebsocket_create_context() - Create the websocket handler
 * @port:	Port to listen on... you can use 0 to suppress listening on
 *		any port, that's what you want if you are not running a
 *		websocket server at all but just using it as a client
 * @interf:  NULL to bind the listen socket to all interfaces, or the
 *		interface name, eg, "eth2"
 * @protocols:	Array of structures listing supported protocols and a protocol-
 *		specific callback for each one.  The list is ended with an
 *		entry that has a NULL callback pointer.
 *		It's not const because we write the owning_server member
 * @extensions: NULL or array of libwebsocket_extension structs listing the
 *		extensions this context supports
 * @ssl_cert_filepath:	If libwebsockets was compiled to use ssl, and you want
 *			to listen using SSL, set to the filepath to fetch the
 *			server cert from, otherwise NULL for unencrypted
 * @ssl_private_key_filepath: filepath to private key if wanting SSL mode,
 *			else ignored
 * @gid:	group id to change to after setting listen socket, or -1.
 * @uid:	user id to change to after setting listen socket, or -1.
 * @options:	0, or LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK
 *
 *	This function creates the listening socket and takes care
 *	of all initialization in one step.
 *
 *	After initialization, it returns a struct libwebsocket_context * that
 *	represents this server.  After calling, user code needs to take care
 *	of calling libwebsocket_service() with the context pointer to get the
 *	server's sockets serviced.  This can be done in the same process context
 *	or a forked process, or another thread,
 *
 *	The protocol callback functions are called for a handful of events
 *	including http requests coming in, websocket connections becoming
 *	established, and data arriving; it's also called periodically to allow
 *	async transmission.
 *
 *	HTTP requests are sent always to the FIRST protocol in @protocol, since
 *	at that time websocket protocol has not been negotiated.  Other
 *	protocols after the first one never see any HTTP callack activity.
 *
 *	The server created is a simple http server by default; part of the
 *	websocket standard is upgrading this http connection to a websocket one.
 *
 *	This allows the same server to provide files like scripts and favicon /
 *	images or whatever over http and dynamic data over websockets all in
 *	one place; they're all handled in the user callback.
 */

struct libwebsocket_context *
libwebsocket_create_context(int port, const char *interf,
			       struct libwebsocket_protocols *protocols,
			       struct libwebsocket_extension *extensions,
			       const char *ssl_cert_filepath,
			       const char *ssl_private_key_filepath,
			       int gid, int uid, unsigned int options)
{
	int n;
	int m;
	int sockfd = 0;
	int fd;
	struct sockaddr_in serv_addr, cli_addr;
	int opt = 1;
	struct libwebsocket_context *context = NULL;
	unsigned int slen;
	char *p;
	char hostname[1024] = "";
//	struct hostent *he;
	struct libwebsocket *wsi;
	struct sockaddr sa;

#ifdef LWS_OPENSSL_SUPPORT
	SSL_METHOD *method;
	char ssl_err_buf[512];
#endif

#ifdef _WIN32
	{
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;
		HMODULE wsdll;

		/* Use the MAKEWORD(lowbyte, highbyte) macro from Windef.h */
		wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0) {
			/* Tell the user that we could not find a usable */
			/* Winsock DLL.                                  */
			fprintf(stderr, "WSAStartup failed with error: %d\n",
									   err);
			return NULL;
		}

		/* default to a poll() made out of select() */
		poll = emulated_poll;

		/* if windows socket lib available, use his WSAPoll */
		wsdll = GetModuleHandle("Ws2_32.dll");
		if (wsdll)
			poll = (PFNWSAPOLL)GetProcAddress(wsdll, "WSAPoll");
	}
#endif


	context = malloc(sizeof(struct libwebsocket_context));
	if (!context) {
		fprintf(stderr, "No memory for websocket context\n");
		return NULL;
	}
	context->protocols = protocols;
	context->listen_port = port;
	context->http_proxy_port = 0;
	context->http_proxy_address[0] = '\0';
	context->options = options;
	context->fds_count = 0;
	context->extensions = extensions;
	context->last_timeout_check_s = 0;

#ifdef WIN32
	context->fd_random = 0;
#else
	context->fd_random = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
	if (context->fd_random < 0) {
		fprintf(stderr, "Unable to open random device %s %d\n",
				    SYSTEM_RANDOM_FILEPATH, context->fd_random);
		return NULL;
	}
#endif

#ifdef LWS_OPENSSL_SUPPORT
	context->use_ssl = 0;
	context->ssl_ctx = NULL;
	context->ssl_client_ctx = NULL;
	openssl_websocket_private_data_index = 0;
#endif
	/* find canonical hostname */

	hostname[(sizeof hostname) - 1] = '\0';
	memset(&sa, 0, sizeof(sa));
	sa.sa_family = AF_INET;
	sa.sa_data[(sizeof sa.sa_data) - 1] = '\0';
	gethostname(hostname, (sizeof hostname) - 1);

	n = 0;

	if (strlen(hostname) < sizeof(sa.sa_data) - 1) {	
		strcpy(sa.sa_data, hostname);
//		fprintf(stderr, "my host name is %s\n", sa.sa_data);
		n = getnameinfo(&sa, sizeof(sa), hostname,
			(sizeof hostname) - 1, NULL, 0, 0);
	}

	if (!n) {
		strncpy(context->canonical_hostname, hostname,
					sizeof context->canonical_hostname - 1);
		context->canonical_hostname[
				sizeof context->canonical_hostname - 1] = '\0';
	} else
		strncpy(context->canonical_hostname, hostname,
					sizeof context->canonical_hostname - 1);

//	fprintf(stderr, "context->canonical_hostname = %s\n",
//						context->canonical_hostname);

	/* split the proxy ads:port if given */

	p = getenv("http_proxy");
	if (p) {
		strncpy(context->http_proxy_address, p,
				       sizeof context->http_proxy_address - 1);
		context->http_proxy_address[
				 sizeof context->http_proxy_address - 1] = '\0';

		p = strchr(context->http_proxy_address, ':');
		if (p == NULL) {
			fprintf(stderr, "http_proxy needs to be ads:port\n");
			return NULL;
		}
		*p = '\0';
		context->http_proxy_port = atoi(p + 1);

		fprintf(stderr, "Using proxy %s:%u\n",
				context->http_proxy_address,
						      context->http_proxy_port);
	}

	if (port) {

#ifdef LWS_OPENSSL_SUPPORT
		context->use_ssl = ssl_cert_filepath != NULL &&
					       ssl_private_key_filepath != NULL;
		if (context->use_ssl)
			fprintf(stderr, " Compiled with SSL support, "
								  "using it\n");
		else
			fprintf(stderr, " Compiled with SSL support, "
							      "not using it\n");

#else
		if (ssl_cert_filepath != NULL &&
					     ssl_private_key_filepath != NULL) {
			fprintf(stderr, " Not compiled for OpenSSl support!\n");
			return NULL;
		}
		fprintf(stderr, " Compiled without SSL support, "
						       "serving unencrypted\n");
#endif
	}

	/* ignore SIGPIPE */
#ifdef WIN32
#else
	signal(SIGPIPE, sigpipe_handler);
#endif


#ifdef LWS_OPENSSL_SUPPORT

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "libwebsockets", NULL, NULL, NULL);

	/*
	 * Firefox insists on SSLv23 not SSLv3
	 * Konq disables SSLv2 by default now, SSLv23 works
	 */

	method = (SSL_METHOD *)SSLv23_server_method();
	if (!method) {
		fprintf(stderr, "problem creating ssl method: %s\n",
			ERR_error_string(ERR_get_error(), ssl_err_buf));
		return NULL;
	}
	context->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!context->ssl_ctx) {
		fprintf(stderr, "problem creating ssl context: %s\n",
			ERR_error_string(ERR_get_error(), ssl_err_buf));
		return NULL;
	}

	/* client context */

	if (port == CONTEXT_PORT_NO_LISTEN) {
		method = (SSL_METHOD *)SSLv23_client_method();
		if (!method) {
			fprintf(stderr, "problem creating ssl method: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* create context */
		context->ssl_client_ctx = SSL_CTX_new(method);
		if (!context->ssl_client_ctx) {
			fprintf(stderr, "problem creating ssl context: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}

		/* openssl init for cert verification (for client sockets) */

		if (!SSL_CTX_load_verify_locations(
					context->ssl_client_ctx, NULL,
						      LWS_OPENSSL_CLIENT_CERTS))
			fprintf(stderr,
			    "Unable to load SSL Client certs from %s "
			    "(set by --with-client-cert-dir= in configure) -- "
				" client ssl isn't going to work",
						      LWS_OPENSSL_CLIENT_CERTS);

		/*
		 * callback allowing user code to load extra verification certs
		 * helping the client to verify server identity
		 */

		context->protocols[0].callback(context, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
			context->ssl_client_ctx, NULL, 0);
	}

	/* as a server, are we requiring clients to identify themselves? */

	if (options & LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) {

		/* absolutely require the client cert */

		SSL_CTX_set_verify(context->ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						       OpenSSL_verify_callback);

		/*
		 * give user code a chance to load certs into the server
		 * allowing it to verify incoming client certs
		 */

		context->protocols[0].callback(context, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
						     context->ssl_ctx, NULL, 0);
	}

	if (context->use_ssl) {

		/* openssl init for server sockets */

		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_file(context->ssl_ctx,
					ssl_cert_filepath, SSL_FILETYPE_PEM);
		if (n != 1) {
			fprintf(stderr, "problem getting cert '%s': %s\n",
				ssl_cert_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(context->ssl_ctx,
			     ssl_private_key_filepath, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "ssl problem getting key '%s': %s\n",
						ssl_private_key_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(context->ssl_ctx)) {
			fprintf(stderr, "Private SSL key doesn't match cert\n");
			return NULL;
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif

	/* selftest */

	if (lws_b64_selftest())
		return NULL;

	/* fd hashtable init */

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++)
		context->fd_hashtable[n].length = 0;

	/* set up our external listening socket we serve on */

	if (port) {

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			fprintf(stderr, "ERROR opening socket");
			return NULL;
		}

		/* allow us to restart even if old sockets in TIME_WAIT */
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
					      (const void *)&opt, sizeof(opt));

		/* Disable Nagle */
		opt = 1;
		setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,
					      (const void *)&opt, sizeof(opt));

		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		if (interf == NULL)
			serv_addr.sin_addr.s_addr = INADDR_ANY;
		else
			interface_to_sa(interf, &serv_addr,
						sizeof(serv_addr));
		serv_addr.sin_port = htons(port);

		n = bind(sockfd, (struct sockaddr *) &serv_addr,
							     sizeof(serv_addr));
		if (n < 0) {
			fprintf(stderr, "ERROR on binding to port %d (%d %d)\n",
								port, n, errno);
			return NULL;
		}

		wsi = malloc(sizeof(struct libwebsocket));
		memset(wsi, 0, sizeof(struct libwebsocket));
		wsi->sock = sockfd;
		wsi->count_active_extensions = 0;
		wsi->mode = LWS_CONNMODE_SERVER_LISTENER;
		insert_wsi(context, wsi);

		listen(sockfd, 5);
		fprintf(stderr, " Listening on port %d\n", port);

		/* list in the internal poll array */

		context->fds[context->fds_count].fd = sockfd;
		context->fds[context->fds_count++].events = POLLIN;

		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)sockfd, NULL, POLLIN);

	}

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
#ifdef WIN32
#else
	if (gid != -1)
		if (setgid(gid))
			fprintf(stderr, "setgid: %s\n", strerror(errno));
	if (uid != -1)
		if (setuid(uid))
			fprintf(stderr, "setuid: %s\n", strerror(errno));
#endif

	/* set up our internal broadcast trigger sockets per-protocol */

	for (context->count_protocols = 0;
			protocols[context->count_protocols].callback;
						   context->count_protocols++) {

		debug("  Protocol: %s\n", protocols[context->count_protocols].name);

		protocols[context->count_protocols].owning_server = context;
		protocols[context->count_protocols].protocol_index =
						       context->count_protocols;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			fprintf(stderr, "ERROR opening socket");
			return NULL;
		}

		/* allow us to restart even if old sockets in TIME_WAIT */
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
								  sizeof(opt));

		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serv_addr.sin_port = 0; /* pick the port for us */

		n = bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
		if (n < 0) {
			fprintf(stderr, "ERROR on binding to port %d (%d %d)\n",
								port, n, errno);
			return NULL;
		}

		slen = sizeof cli_addr;
		n = getsockname(fd, (struct sockaddr *)&cli_addr, &slen);
		if (n < 0) {
			fprintf(stderr, "getsockname failed\n");
			return NULL;
		}
		protocols[context->count_protocols].broadcast_socket_port =
						       ntohs(cli_addr.sin_port);
		listen(fd, 5);

		debug("  Protocol %s broadcast socket %d\n",
				protocols[context->count_protocols].name,
						      ntohs(cli_addr.sin_port));

		/* dummy wsi per broadcast proxy socket */

		wsi = malloc(sizeof(struct libwebsocket));
		memset(wsi, 0, sizeof(struct libwebsocket));
		wsi->sock = fd;
		wsi->mode = LWS_CONNMODE_BROADCAST_PROXY_LISTENER;
		wsi->count_active_extensions = 0;
		/* note which protocol we are proxying */
		wsi->protocol_index_for_broadcast_proxy =
						       context->count_protocols;
		insert_wsi(context, wsi);

		/* list in internal poll array */

		context->fds[context->fds_count].fd = fd;
		context->fds[context->fds_count].events = POLLIN;
		context->fds[context->fds_count].revents = 0;
		context->fds_count++;

		/* external POLL support via protocol 0 */
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)fd, NULL, POLLIN);
	}

	/*
	 * give all extensions a chance to create any per-context
	 * allocations they need
	 */

	m = LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT;
	if (port)
		m = LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT;
	
	if (extensions) {
	    while (extensions->callback) {
		    debug("  Extension: %s\n", extensions->name);
		    extensions->callback(context, extensions,
						NULL, m, NULL, NULL, 0);
		    extensions++;
	    }
	}

	return context;
}


#ifndef LWS_NO_FORK

/**
 * libwebsockets_fork_service_loop() - Optional helper function forks off
 *				  a process for the websocket server loop.
 *				You don't have to use this but if not, you
 *				have to make sure you are calling
 *				libwebsocket_service periodically to service
 *				the websocket traffic
 * @context:	server context returned by creation function
 */

int
libwebsockets_fork_service_loop(struct libwebsocket_context *context)
{
	int fd;
	struct sockaddr_in cli_addr;
	int n;
	int p;

	n = fork();
	if (n < 0)
		return n;

	if (!n) {

		/* main process context */

		/*
		 * set up the proxy sockets to allow broadcast from
		 * service process context
		 */

		for (p = 0; p < context->count_protocols; p++) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd < 0) {
				fprintf(stderr, "Unable to create socket\n");
				return -1;
			}
			cli_addr.sin_family = AF_INET;
			cli_addr.sin_port = htons(
			     context->protocols[p].broadcast_socket_port);
			cli_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			n = connect(fd, (struct sockaddr *)&cli_addr,
							       sizeof cli_addr);
			if (n < 0) {
				fprintf(stderr, "Unable to connect to "
						"broadcast socket %d, %s\n",
						n, strerror(errno));
				return -1;
			}

			context->protocols[p].broadcast_socket_user_fd = fd;
		}

		return 0;
	}

#ifdef HAVE_SYS_PRCTL_H
	/* we want a SIGHUP when our parent goes down */
	prctl(PR_SET_PDEATHSIG, SIGHUP);
#endif

	/* in this forked process, sit and service websocket connections */

	while (1) {
		if (libwebsocket_service(context, 1000))
			break;
#ifndef HAVE_SYS_PRCTL_H
/*
 * on systems without prctl() (i.e. anything but linux) we can notice that our
 * parent is dead if getppid() returns 1. FIXME apparently this is not true for
 * solaris, could remember ppid right after fork and wait for it to change.
 */

        if (getppid() == 1)
            break;
#endif
    }


	return 1;
}

#endif

/**
 * libwebsockets_get_protocol() - Returns a protocol pointer from a websocket
 *				  connection.
 * @wsi:	pointer to struct websocket you want to know the protocol of
 *
 *
 *	This is useful to get the protocol to broadcast back to from inside
 * the callback.
 */

const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi)
{
	return wsi->protocol;
}

/**
 * libwebsockets_broadcast() - Sends a buffer to the callback for all active
 *				  connections of the given protocol.
 * @protocol:	pointer to the protocol you will broadcast to all members of
 * @buf:  buffer containing the data to be broadcase.  NOTE: this has to be
 *		allocated with LWS_SEND_BUFFER_PRE_PADDING valid bytes before
 *		the pointer and LWS_SEND_BUFFER_POST_PADDING afterwards in the
 *		case you are calling this function from callback context.
 * @len:	length of payload data in buf, starting from buf.
 *
 *	This function allows bulk sending of a packet to every connection using
 * the given protocol.  It does not send the data directly; instead it calls
 * the callback with a reason type of LWS_CALLBACK_BROADCAST.  If the callback
 * wants to actually send the data for that connection, the callback itself
 * should call libwebsocket_write().
 *
 * libwebsockets_broadcast() can be called from another fork context without
 * having to take any care about data visibility between the processes, it'll
 * "just work".
 */


int
libwebsockets_broadcast(const struct libwebsocket_protocols *protocol,
						 unsigned char *buf, size_t len)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	int m;
	struct libwebsocket *wsi;

	if (!protocol->broadcast_socket_user_fd) {
		/*
		 * We are either running unforked / flat, or we are being
		 * called from poll thread context
		 * eg, from a callback.  In that case don't use sockets for
		 * broadcast IPC (since we can't open a socket connection to
		 * a socket listening on our own thread) but directly do the
		 * send action.
		 *
		 * Locking is not needed because we are by definition being
		 * called in the poll thread context and are serialized.
		 */

		for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

			for (m = 0; m < context->fd_hashtable[n].length; m++) {

				wsi = context->fd_hashtable[n].wsi[m];

				if (wsi->mode != LWS_CONNMODE_WS_SERVING)
					continue;

				/*
				 * never broadcast to
				 * non-established connections
				 */
				if (wsi->state != WSI_STATE_ESTABLISHED)
					continue;

				/* only broadcast to guys using
				 * requested protocol
				 */
				if (wsi->protocol != protocol)
					continue;

				wsi->protocol->callback(context, wsi,
					 LWS_CALLBACK_BROADCAST,
					 wsi->user_space,
					 buf, len);
			}
		}

		return 0;
	}

	/*
	 * We're being called from a different process context than the server
	 * loop.  Instead of broadcasting directly, we send our
	 * payload on a socket to do the IPC; the server process will serialize
	 * the broadcast action in its main poll() loop.
	 *
	 * There's one broadcast socket listening for each protocol supported
	 * set up when the websocket server initializes
	 */

	n = send(protocol->broadcast_socket_user_fd, buf, len, MSG_NOSIGNAL);

	return n;
}

int
libwebsocket_is_final_fragment(struct libwebsocket *wsi)
{
	return wsi->final;
}

void *
libwebsocket_ensure_user_space(struct libwebsocket *wsi)
{
	/* allocate the per-connection user memory (if any) */

	if (wsi->protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = malloc(
				  wsi->protocol->per_session_data_size);
		if (wsi->user_space  == NULL) {
			fprintf(stderr, "Out of memory for "
						   "conn user space\n");
			return NULL;
		}
		memset(wsi->user_space, 0,
					 wsi->protocol->per_session_data_size);
	}
	return wsi->user_space;
}
