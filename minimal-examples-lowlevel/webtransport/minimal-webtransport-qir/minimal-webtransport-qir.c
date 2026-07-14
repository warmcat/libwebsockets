/*
 * lws-minimal-webtransport-qir
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * WebTransport Interop Runner shim implementation.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#if defined(_WIN32)
#include <io.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
static void usleep(unsigned long l) { Sleep(l / 1000); }
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <errno.h>



static int interrupted;
static int is_server;
static char testcase[64] = "";
static struct lws_context *context;
static struct lws *first_session_wsi;
static char global_endpoint[128] = "";



struct request_item {
	char url[512];
	char host[128];
	int port;
	char endpoint[128];
	char filename[128];
	struct lws *session_wsi;
	int started;
	int completed;
};

static struct request_item client_requests[256];
static int client_requests_count;

struct server_request_item {
	char endpoint[128];
	char filename[128];
	int started;
	int completed;
};

static struct server_request_item server_requests[256];
static int server_requests_count;

struct pending_datagram {
	char filename[256];
	int is_push; /* 1 for PUSH, 0 for GET */
};

static struct pending_datagram dg_queue[512];
static int dg_queue_head;
static int dg_queue_tail;

static void enqueue_datagram(const char *filename, int is_push)
{
	if ((dg_queue_tail + 1) % 512 == dg_queue_head) {
		lwsl_err("Datagram queue overflow!\n");
		return;
	}
	struct pending_datagram *dg = &dg_queue[dg_queue_tail];
	lws_strncpy(dg->filename, filename, sizeof(dg->filename));
	dg->is_push = is_push;
	dg_queue_tail = (dg_queue_tail + 1) % 512;
}

static struct pending_datagram *dequeue_datagram(void)
{
	if (dg_queue_head == dg_queue_tail)
		return NULL;
	struct pending_datagram *dg = &dg_queue[dg_queue_head];
	dg_queue_head = (dg_queue_head + 1) % 512;
	return dg;
}

struct pss_qir {
	struct lws *wsi;
	int is_session;
	char endpoint[128];

	/* For child streams */
	int is_unidi;
	int is_initiator; /* 1 if we sent GET, 0 if we received GET */
	char filename[256];
	int request_index;

	/* Send state */
	int fd_in;
	size_t file_len;
	size_t sent_len;
	int header_sent;

	/* Receive state */
	int fd_out;
	char push_hdr[512];
	size_t push_hdr_len;
	size_t push_hdr_read;
	int push_hdr_done;
	int initialized;
	int write_completed;
};

static void init_pss(struct pss_qir *pss)
{
	if (pss && !pss->initialized) {
		pss->fd_in = -1;
		pss->fd_out = -1;
		pss->request_index = -1;
		pss->write_completed = 0;
		pss->initialized = 1;
	}
}

static int pss_is_file_sender(struct pss_qir *pss)
{
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	if (pss->is_unidi)
		return local_is_sender && !pss->is_initiator;
	return local_is_sender;
}

static int pss_is_file_receiver(struct pss_qir *pss)
{
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');
	if (pss->is_unidi)
		return local_is_receiver && !pss->is_initiator;
	return local_is_receiver;
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
static void print_custom_header_cb(const char *name, int nlen, void *custom)
{
	struct lws *wsi = (struct lws *)custom;
	char val[128];
	int vl = lws_hdr_custom_copy(wsi, val, sizeof(val) - 1, name, nlen);
	if (vl >= 0) {
		val[vl] = '\0';
		lwsl_user("  Custom Header: %.*s = %s\n", nlen, name, val);
	}
}
#endif


static void sigint_handler(int sig)
{
	interrupted = 1;
}
static void trim_trailing_whitespace(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == '\t')) {
		str[len - 1] = '\0';
		len--;
	}
}

static int parse_client_requests(void)
{
	const char *reqs = getenv("REQUESTS_CLIENT");
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char token[512];

	if (!reqs)
		reqs = getenv("REQUESTS");
	if (!reqs)
		return 0;

	lws_tokenize_init(&ts, reqs, LWS_TOKENIZE_F_MINUS_NONTERM |
				      LWS_TOKENIZE_F_SLASH_NONTERM |
				      LWS_TOKENIZE_F_DOT_NONTERM |
				      LWS_TOKENIZE_F_COLON_NONTERM |
				      LWS_TOKENIZE_F_NO_INTEGERS |
				      LWS_TOKENIZE_F_NO_FLOATS);

	while ((e = lws_tokenize(&ts)) > 0) {
		if (e != LWS_TOKZE_TOKEN)
			continue;

		if (lws_tokenize_cstr(&ts, token, sizeof(token))) {
			lwsl_err("Client request URL too long\n");
			continue;
		}

		struct request_item *item = &client_requests[client_requests_count];
		lws_strncpy(item->url, token, sizeof(item->url));
		trim_trailing_whitespace(item->url);

		/* Parse URL: https://<host>:<port>/<endpoint>/<filename> */
		char *p = item->url;
		if (strncmp(p, "https://", 8) == 0)
			p += 8;

		char *host_start = p;
		char *slash = strchr(p, '/');
		if (!slash)
			continue;

		*slash = '\0';
		char *port_colon = strchr(host_start, ':');
		if (port_colon) {
			*port_colon = '\0';
			item->port = atoi(port_colon + 1);
		} else {
			item->port = 443;
		}
		lws_strncpy(item->host, host_start, sizeof(item->host));
		*slash = '/';

		p = slash + 1;
		char *next_slash = strchr(p, '/');
		if (next_slash) {
			*next_slash = '\0';
			lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", p);
			*next_slash = '/';
			lws_strncpy(item->filename, next_slash + 1, sizeof(item->filename));
			trim_trailing_whitespace(item->filename);
		} else {
			lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", p);
			item->filename[0] = '\0';
		}

		client_requests_count++;
		if (client_requests_count >= (int)LWS_ARRAY_SIZE(client_requests))
			break;
	}

	/* If we are the client and acting as the sender, we also need to parse files from REQUESTS_SERVER */
	const char *sreqs = getenv("REQUESTS_SERVER");
	if (sreqs && client_requests_count == 1 && client_requests[0].filename[0] == '\0') {
		struct lws_tokenize sts;
		lws_tokenize_elem se;
		char stoken[256];
		int first = 1;

		lws_tokenize_init(&sts, sreqs, LWS_TOKENIZE_F_MINUS_NONTERM |
					       LWS_TOKENIZE_F_SLASH_NONTERM |
					       LWS_TOKENIZE_F_DOT_NONTERM |
					       LWS_TOKENIZE_F_NO_INTEGERS |
					       LWS_TOKENIZE_F_NO_FLOATS);

		while ((se = lws_tokenize(&sts)) > 0) {
			if (se != LWS_TOKZE_TOKEN)
				continue;

			if (lws_tokenize_cstr(&sts, stoken, sizeof(stoken)))
				continue;

			/* format: <endpoint>/<filename> */
			char *slash = strchr(stoken, '/');
			if (!slash)
				continue;

			*slash = '\0';
			char filename[256];
			lws_strncpy(filename, slash + 1, sizeof(filename));
			trim_trailing_whitespace(filename);
			*slash = '/';

			if (first) {
				lws_strncpy(client_requests[0].filename, filename, sizeof(client_requests[0].filename));
				first = 0;
			} else {
				struct request_item *item = &client_requests[client_requests_count];
				item->port = client_requests[0].port;
				lws_strncpy(item->host, client_requests[0].host, sizeof(item->host));
				lws_strncpy(item->endpoint, client_requests[0].endpoint, sizeof(item->endpoint));
				lws_strncpy(item->filename, filename, sizeof(item->filename));
				client_requests_count++;
				if (client_requests_count >= (int)LWS_ARRAY_SIZE(client_requests))
					break;
			}
		}
	}

	return client_requests_count;
}

static int parse_server_requests(void)
{
	const char *reqs = getenv("REQUESTS_SERVER");
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char token[256];

	if (!reqs)
		reqs = getenv("REQUESTS");
	if (!reqs)
		return 0;

	lws_tokenize_init(&ts, reqs, LWS_TOKENIZE_F_MINUS_NONTERM |
				      LWS_TOKENIZE_F_SLASH_NONTERM |
				      LWS_TOKENIZE_F_DOT_NONTERM |
				      LWS_TOKENIZE_F_NO_INTEGERS |
				      LWS_TOKENIZE_F_NO_FLOATS);

	while ((e = lws_tokenize(&ts)) > 0) {
		if (e != LWS_TOKZE_TOKEN)
			continue;

		if (lws_tokenize_cstr(&ts, token, sizeof(token)))
			continue;

		struct server_request_item *item = &server_requests[server_requests_count];

		/* format: <endpoint>/<filename> */
		char *slash = strchr(token, '/');
		if (!slash)
			continue;

		*slash = '\0';
		lws_snprintf(item->endpoint, sizeof(item->endpoint), "/%s", token);
		*slash = '/';
		lws_strncpy(item->filename, slash + 1, sizeof(item->filename));
		trim_trailing_whitespace(item->filename);

		server_requests_count++;
		if (server_requests_count >= (int)LWS_ARRAY_SIZE(server_requests))
			break;
	}

	return server_requests_count;
}

static void trigger_client_transfers(struct lws *wsi_session, const char *endpoint)
{
	int i;
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');

	lwsl_user("trigger_client_transfers called for endpoint %s, client_requests_count=%d\n", endpoint, client_requests_count);
	if (local_is_sender) {
		lwsl_user("  Local node is sender, not initiating client transfers.\n");
		return;
	}

	for (i = 0; i < client_requests_count; i++) {
		struct request_item *item = &client_requests[i];
		lwsl_user("  Client Request %d: url=%s endpoint=%s started=%d filename=%s\n", i, item->url, item->endpoint, item->started, item->filename);
		if (strcmp(item->endpoint, endpoint) == 0 && !item->started && item->filename[0]) {
			/* Start the transfer according to the testcase */
			item->started = 1;
			lwsl_user("  Triggering request %d (%s) on testcase %s\n", i, item->filename, testcase);
			if (strstr(testcase, "unidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 1);
				lwsl_user("  lws_wt_create_stream(unidi=1) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 1;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for client stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "bidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 0);
				lwsl_user("  lws_wt_create_stream(unidi=0) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 0;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for client stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "datagram")) {
				if (local_is_receiver) {
					enqueue_datagram(item->filename, 0); /* 0 for GET */
					lws_callback_on_writable(wsi_session);
				}
			}
		}
	}
}

static void trigger_server_transfers(struct lws *wsi_session, const char *endpoint)
{
	int i;
	int local_is_sender = (strstr(testcase, "-receive") && is_server) ||
			      (strstr(testcase, "-send") && !is_server) ||
			      (strcmp(testcase, "transfer") == 0 && (is_server || !client_requests_count || client_requests[0].filename[0] == '\0'));
	int local_is_receiver = (strstr(testcase, "-receive") && !is_server) ||
				(strstr(testcase, "-send") && is_server) ||
				(strcmp(testcase, "transfer") == 0 && !is_server && client_requests_count && client_requests[0].filename[0] != '\0');

	lwsl_user("trigger_server_transfers called for endpoint %s, server_requests_count=%d\n", endpoint, server_requests_count);
	if (local_is_sender) {
		lwsl_user("  Local node is sender, not initiating server transfers.\n");
		return;
	}

	for (i = 0; i < server_requests_count; i++) {
		struct server_request_item *item = &server_requests[i];
		lwsl_user("  Server Request %d: endpoint=%s started=%d filename=%s\n", i, item->endpoint, item->started, item->filename);
		if (strcmp(item->endpoint, endpoint) == 0 && !item->started) {
			item->started = 1;
			lwsl_user("  Triggering server request %d (%s) on testcase %s\n", i, item->filename, testcase);
			if (strstr(testcase, "unidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 1);
				lwsl_user("  lws_wt_create_stream(unidi=1) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 1;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for server stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "bidirectional")) {
				struct lws *cwsi = lws_wt_create_stream(wsi_session, 0);
				lwsl_user("  lws_wt_create_stream(unidi=0) returned wsi %p\n", cwsi);
				if (cwsi) {
					int err = lws_ensure_user_space(cwsi);
					lwsl_user("  lws_ensure_user_space returned %d\n", err);
					if (!err) {
						struct pss_qir *pss = (struct pss_qir *)lws_wsi_user(cwsi);
						lwsl_user("  pss user space: %p\n", pss);
						if (pss) {
							init_pss(pss);
							pss->is_unidi = 0;
							pss->is_initiator = 1;
							pss->request_index = i;
							lws_strncpy(pss->endpoint, item->endpoint, sizeof(pss->endpoint));
							lws_strncpy(pss->filename, item->filename, sizeof(pss->filename));
							lws_callback_on_writable(cwsi);
							lwsl_user("  Requested writable callback for server stream wsi %p\n", cwsi);
						}
					}
				}
			} else if (strstr(testcase, "datagram")) {
				if (local_is_receiver) {
					enqueue_datagram(item->filename, 0); /* 0 for GET */
					lws_callback_on_writable(wsi_session);
				}
			}
		}
	}
}

static int callback_qir(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss_qir *pss = (struct pss_qir *)user;
	uint8_t buf[LWS_PRE + 4096], *p;
	int n, m;

	if (pss) {
		init_pss(pss);
	}

	if (!pss && reason != LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER)
		return 0;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	{
		unsigned char **hp = (unsigned char **)in, *end = (*hp) + len;

		/* Add sec-webtransport-http3-draft header */
		if (lws_add_http_header_by_name(wsi,
				(const unsigned char *)"sec-webtransport-http3-draft:",
				(const unsigned char *)"draft02", 7, hp, end))
			return -1;

		/* Format and send PROTOCOLS as custom headers */
		const char *env_protocols = getenv("PROTOCOLS_CLIENT");
		if (!env_protocols)
			env_protocols = getenv("PROTOCOLS");

		if (env_protocols) {
			char av_buf[512] = "";
			struct lws_tokenize ts;
			lws_tokenize_elem e;
			char tok[128];
			int first = 1;

			lws_tokenize_init(&ts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM |
							      LWS_TOKENIZE_F_NO_INTEGERS |
							      LWS_TOKENIZE_F_NO_FLOATS);

			while ((e = lws_tokenize(&ts)) > 0) {
				if (e != LWS_TOKZE_TOKEN)
					continue;

				if (lws_tokenize_cstr(&ts, tok, sizeof(tok)))
					continue;

				if (sizeof(av_buf) - strlen(av_buf) > strlen(tok) + 5) {
					if (!first)
						strcat(av_buf, ", ");
					strcat(av_buf, "\"");
					strcat(av_buf, tok);
					strcat(av_buf, "\"");
					first = 0;
				}
			}

			if (lws_add_http_header_by_name(wsi,
					(const unsigned char *)"wt-available-protocols:",
					(const unsigned char *)av_buf, (int)strlen(av_buf), hp, end))
				return -1;
		}
		break;
	}

	case LWS_CALLBACK_ESTABLISHED:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		pss->wsi = wsi;
		pss->request_index = -1;
		if (lws_wt_is_session(wsi)) {
			if (!is_server)
				break;
			pss->is_session = 1;
			/* Extract endpoint path */
			char path[128];
			int path_len = lws_hdr_copy(wsi, path, sizeof(path) - 1, WSI_TOKEN_HTTP_COLON_PATH);
			if (path_len > 0) {
				path[path_len] = '\0';
				lws_strncpy(pss->endpoint, path, sizeof(pss->endpoint));
				lws_strncpy(global_endpoint, path, sizeof(global_endpoint));
			}
			lwsl_user("Server WebTransport session established on %s\n", pss->endpoint);

			/* Save negotiated protocol to /downloads/negotiated_protocol.txt */
			{
				char client_protos[256];
				char negotiated[64] = "";
				int cp_len = lws_hdr_custom_copy(wsi, client_protos, sizeof(client_protos) - 1,
								 "wt-available-protocols", 22);
				if (cp_len > 0) {
					const char *env_protocols = getenv("PROTOCOLS_SERVER");
					client_protos[cp_len] = '\0';
					if (!env_protocols)
						env_protocols = getenv("PROTOCOLS");

					if (env_protocols) {
						/* client_protos format: '"proto1", "proto2"' */
						struct lws_tokenize ts;
						lws_tokenize_elem e;
						char token[64];

						lws_tokenize_init(&ts, client_protos, LWS_TOKENIZE_F_COMMA_SEP_LIST |
											      LWS_TOKENIZE_F_MINUS_NONTERM |
											      LWS_TOKENIZE_F_NO_INTEGERS |
											      LWS_TOKENIZE_F_NO_FLOATS);

						while ((e = lws_tokenize(&ts)) > 0) {
							if (e != LWS_TOKZE_TOKEN && e != LWS_TOKZE_QUOTED_STRING)
								continue;

							if (lws_tokenize_cstr(&ts, token, sizeof(token)))
								continue;

							struct lws_tokenize sts;
							lws_tokenize_elem se;
							char sp_tok[64];

							lws_tokenize_init(&sts, env_protocols, LWS_TOKENIZE_F_MINUS_NONTERM |
													       LWS_TOKENIZE_F_NO_INTEGERS |
													       LWS_TOKENIZE_F_NO_FLOATS);

							while ((se = lws_tokenize(&sts)) > 0) {
								if (se != LWS_TOKZE_TOKEN)
									continue;

								if (lws_tokenize_cstr(&sts, sp_tok, sizeof(sp_tok)))
									continue;

								if (strcmp(token, sp_tok) == 0) {
									lws_strncpy(negotiated, token, sizeof(negotiated));
									break;
								}
							}
							if (negotiated[0])
								break;
						}
					}
				}

				if (negotiated[0]) {
					if (mkdir("/downloads", 0777) < 0 && errno != EEXIST) { // NOSONAR
						lwsl_err("Failed to create /downloads: %d\n", errno);
					}
					int nfd = open("/downloads/negotiated_protocol.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
					if (nfd >= 0) {
						if (write(nfd, negotiated, LWS_POSIX_LENGTH_CAST(strlen(negotiated))) < 0) {
							lwsl_err("Failed to write negotiated protocol\n");
						}
						close(nfd);
					}
				}
			}

			/* If server needs to request files, trigger them now */
			trigger_server_transfers(wsi, pss->endpoint);
		} else {
			pss->is_session = 0;
			pss->is_unidi = lws_wt_is_unidi(wsi);
			lws_strncpy(pss->endpoint, global_endpoint, sizeof(pss->endpoint));
			lwsl_user("%s stream established (unidi=%d)\n", is_server ? "Server" : "Client", pss->is_unidi);

			if (is_server && !pss->is_unidi &&
			    lws_get_parent(wsi) && lws_wt_is_session(lws_get_parent(wsi))) {
				/* Server receives files over client-initiated bidi streams.
				 * Find first unstarted server request, assign it to this stream,
				 * and trigger writable callback to send GET <filename>. */
				int i;
				for (i = 0; i < server_requests_count; i++) {
					if (!server_requests[i].started) {
						server_requests[i].started = 1;
						pss->request_index = i;
						pss->is_initiator = 1;
						lws_strncpy(pss->filename, server_requests[i].filename, sizeof(pss->filename));
						lws_callback_on_writable(wsi);
						lwsl_user("Server assigned request %d (%s) to bidi stream %p\n", i, pss->filename, wsi);
						break;
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (is_server)
			break;
		pss->wsi = wsi;
		pss->request_index = -1;
		if (lws_wt_is_session(wsi)) {
			pss->is_session = 1;
			
			/* Match the endpoint from client_requests */
			int i;
			for (i = 0; i < client_requests_count; i++) {
				if (!client_requests[i].session_wsi) {
					lws_strncpy(pss->endpoint, client_requests[i].endpoint, sizeof(pss->endpoint));
					client_requests[i].session_wsi = wsi;
					lws_strncpy(global_endpoint, pss->endpoint, sizeof(global_endpoint));
					break;
				}
			}
			lwsl_user("Client WebTransport session established on %s. Listing all custom headers:\n", pss->endpoint);
#if defined(LWS_WITH_CUSTOM_HEADERS)
			lws_hdr_custom_name_foreach(wsi, print_custom_header_cb, wsi);
#endif

			/* Parse and save negotiated protocol to /downloads/negotiated_protocol.txt */
			char negotiated[64];
			int nl = lws_hdr_custom_copy(wsi, negotiated, sizeof(negotiated) - 1, "wt-protocol", 11);
			lwsl_user("wt-protocol header lookup result: %d\n", nl);
			if (nl > 0) {
				negotiated[nl] = '\0';
				/* Remove quotes */
				char *n_ptr = negotiated;
				while (*n_ptr == '"') n_ptr++;
				char *ne = n_ptr + strlen(n_ptr);
				while (ne > n_ptr && (ne[-1] == '"' || ne[-1] == '\r' || ne[-1] == '\n')) {
					ne[-1] = '\0';
					ne--;
				}
				if (mkdir("/downloads", 0777) < 0 && errno != EEXIST) { // NOSONAR
					lwsl_err("Failed to create /downloads: %d\n", errno);
				}
				int nfd = open("/downloads/negotiated_protocol.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
				if (nfd >= 0) {
					if (write(nfd, n_ptr, LWS_POSIX_LENGTH_CAST(strlen(n_ptr))) < 0) {
						lwsl_err("Failed to write negotiated protocol\n");
					}
					close(nfd);
				}
			}

			/* If client needs to request files, trigger them now */
			trigger_client_transfers(wsi, pss->endpoint);
		} else {
			pss->is_session = 0;
			pss->is_unidi = lws_wt_is_unidi(wsi);
			lws_strncpy(pss->endpoint, global_endpoint, sizeof(pss->endpoint));
			lwsl_user("Client stream established (unidi=%d)\n", pss->is_unidi);
		}
		break;

		case LWS_CALLBACK_SERVER_WRITEABLE:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (pss->is_session) {
			struct pending_datagram *dg = dequeue_datagram();
			if (dg) {
				if (dg->is_push) {
					/* Send PUSH <filename>\n<contents> as a datagram */
					char filepath[512];
					const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
					lws_snprintf(filepath, sizeof(filepath), "/www%s/%s", endpoint, dg->filename);
					int fd = open(filepath, O_RDONLY);
					if (fd >= 0) {
						struct stat st;
						if (fstat(fd, &st) == 0) {
							uint8_t dgbuf[LWS_PRE + 65536];
							int hn = lws_snprintf((char *)&dgbuf[LWS_PRE], sizeof(dgbuf) - LWS_PRE, "PUSH %s\n", dg->filename);
							if (hn > 0 && (size_t)hn < sizeof(dgbuf) - LWS_PRE) {
								int rn = (int)read(fd, &dgbuf[LWS_PRE + hn], sizeof(dgbuf) - LWS_PRE - (size_t)hn);
								if (rn >= 0) {
									size_t total_len = (size_t)hn + (size_t)rn;
									if (total_len <= sizeof(dgbuf) - LWS_PRE) {
										enum lws_write_protocol wp = LWS_WRITE_QUIC_DATAGRAM;
										lws_write(wsi, &dgbuf[LWS_PRE], total_len, wp);
										lwsl_user("Session WSI sent datagram PUSH: %s (%zu bytes)\n", dg->filename, total_len);
										usleep(5000); /* Pace datagram sends to prevent queue overflow */

										/* Mark completed on client side (if we are the client sending PUSH) */
										if (!is_server) {
											int r_idx = -1;
											int i;
											for (i = 0; i < client_requests_count; i++) {
												if (strcmp(client_requests[i].filename, dg->filename) == 0) {
													r_idx = i;
													break;
												}
											}
											if (r_idx >= 0) {
												client_requests[r_idx].completed = 1;
												lwsl_user("Client datagram transfer completed: %s\n", dg->filename);
											}
										}
									}
								}
							}
						}
						close(fd);
					} else {
						lwsl_err("Failed to open file %s for datagram PUSH\n", filepath);
					}
				} else {
					/* Send GET <filename> as a datagram */
					uint8_t buf[LWS_PRE + 512];
					size_t len = (size_t)lws_snprintf((char *)&buf[LWS_PRE], 512, "GET %s", dg->filename);
					enum lws_write_protocol wp = LWS_WRITE_QUIC_DATAGRAM;
					lws_write(wsi, &buf[LWS_PRE], len, wp);
					lwsl_user("Session WSI sent datagram GET: %s\n", dg->filename);
					usleep(5000); /* Pace datagram sends to prevent queue overflow */
				}
				/* Request next writable callback to process remaining queue items */
				lws_callback_on_writable(wsi);
			}
			break;
		}

		if (pss_is_file_sender(pss)) {
			/* Sender: write file data */
			if (!pss->filename[0] || pss->write_completed)
				break;
			if (pss->fd_in < 0) {
				char filepath[512];
				const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
				lws_snprintf(filepath, sizeof(filepath), "/www%s/%s", endpoint, pss->filename);
				pss->fd_in = open(filepath, O_RDONLY);
				if (pss->fd_in >= 0) {
					struct stat st;
					if (fstat(pss->fd_in, &st) == 0) {
						pss->file_len = (size_t)st.st_size;
					}
					pss->sent_len = 0;
					pss->header_sent = 0;
					lwsl_user("Sender opened file %s (%zu bytes) for transmission\n", filepath, pss->file_len);
				} else {
					lwsl_err("Sender failed to open file %s\n", filepath);
					return -1;
				}
			}

			if (pss->fd_in >= 0) {
				if (!pss->is_unidi || pss->header_sent) {
					/* Read and send file chunk */
					p = &buf[LWS_PRE];
					n = (int)read(pss->fd_in, p, sizeof(buf) - LWS_PRE);
					if (n > 0) {
						pss->sent_len += (size_t)n;
						int is_final = (pss->sent_len == pss->file_len);
						m = lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY | (is_final ? LWS_WRITE_H2_STREAM_END : LWS_WRITE_NO_FIN));
						if (m < 0)
							return -1;
						if (m < n) {
							/* Seek back the unwritten bytes and retry */
							off_t diff = (off_t)(n - m);
							if (lseek(pss->fd_in, -diff, SEEK_CUR) == (off_t)-1) {
								lwsl_err("lseek failed: %d\n", errno);
								return -1;
							}
							pss->sent_len -= (size_t)diff;
							lws_callback_on_writable(wsi);
						} else {
							if (!is_final)
								lws_callback_on_writable(wsi);
							else {
								close(pss->fd_in);
								pss->fd_in = -1;
								pss->write_completed = 1;
								lwsl_user("Sender completed file write: %zu bytes\n", pss->sent_len);
								return 0;
							}
						}
					} else {
						/* EOF or error */
						close(pss->fd_in);
						pss->fd_in = -1;
						pss->write_completed = 1;
						lws_write(wsi, NULL, 0, LWS_WRITE_BINARY | LWS_WRITE_H2_STREAM_END);
						return 0;
					}
				} else {
					/* Unidirectional stream requires PUSH <filename>\n first */
					p = &buf[LWS_PRE];
					n = lws_snprintf((char *)p, sizeof(buf) - LWS_PRE, "PUSH %s\n", pss->filename);
					m = lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
					if (m < 0)
						return -1;
					if (m < n) {
						/* Throttled or partial, retry header next time */
						lws_callback_on_writable(wsi);
					} else {
						pss->header_sent = 1;
						lws_callback_on_writable(wsi);
						lwsl_user("Sender sent PUSH %s\\n\n", pss->filename);
					}
				}
			}
		} else {
			if (pss->is_initiator) {
				/* Initiator: write GET <filename> */
				if (!pss->header_sent) {
					p = &buf[LWS_PRE];
					n = lws_snprintf((char *)p, sizeof(buf) - LWS_PRE, "GET %s", pss->filename);
					m = lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY | LWS_WRITE_H2_STREAM_END);
					if (m < 0)
						return -1;
					pss->header_sent = 1;
					lwsl_user("Initiator sent GET %s\n", pss->filename);
				}
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (pss->is_session) {
			/* Datagram received! format: GET <filename> or PUSH <filename>\n<data> */
			char *payload = (char *)in;
			size_t payload_len = len;

			if (payload_len > 4 && strncmp(payload, "GET ", 4) == 0) {
				/* GET <filename> */
				char filename[256];
				size_t fn_len = payload_len - 4;
				if (fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
				memcpy(filename, payload + 4, fn_len);
				filename[fn_len] = '\0';

				lwsl_user("Session WSI received datagram GET: %s\n", filename);

				/* Respond by sending PUSH <filename>\n<contents> as a datagram */
				enqueue_datagram(filename, 1); /* 1 for PUSH */
				lws_callback_on_writable(wsi);
			} else if (payload_len > 5 && strncmp(payload, "PUSH ", 5) == 0) {
				/* PUSH <filename>\n<data> */
				char *newline = memchr(payload, '\n', payload_len);
				if (newline) {
					char filename[256];
					size_t fn_len = (size_t)(newline - (payload + 5));
					if (fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
					memcpy(filename, payload + 5, fn_len);
					filename[fn_len] = '\0';

					char *data_start = newline + 1;
					size_t data_len = payload_len - (size_t)(data_start - payload);

					lwsl_user("Session WSI received datagram PUSH: %s (%zu bytes)\n", filename, data_len);

					char dirpath[512], filepath[512];
					lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s", pss->endpoint);
					if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
						lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
					}
					lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, filename);

					int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
					if (fd >= 0) {
						if (write(fd, data_start, LWS_POSIX_LENGTH_CAST(data_len)) < 0) {
							lwsl_err("Failed to write datagram content\n");
						}
						close(fd);

						/* Mark request completed for datagram-receive */
						if (!is_server) {
							int r_idx = -1;
							int i;
							for (i = 0; i < client_requests_count; i++) {
								if (strcmp(client_requests[i].filename, filename) == 0) {
									r_idx = i;
									break;
								}
							}
							if (r_idx >= 0) {
								client_requests[r_idx].completed = 1;
								lwsl_user("Client datagram request index %d (%s) completed (datagram received)\n", r_idx, filename);
							}
						} else {
							int r_idx = -1;
							int i;
							for (i = 0; i < server_requests_count; i++) {
								if (strcmp(server_requests[i].filename, filename) == 0) {
									r_idx = i;
									break;
								}
							}
							if (r_idx >= 0) {
								server_requests[r_idx].completed = 1;
								lwsl_user("Server datagram request index %d (%s) completed (datagram received)\n", r_idx, filename);
								
								int all_done = 1;
								for (i = 0; i < server_requests_count; i++) {
									if (!server_requests[i].completed) {
										all_done = 0;
										break;
									}
								}
								if (all_done) {
									lwsl_user("All server requests completed. Setting interrupted = 1 to exit.\n");
									interrupted = 1;
								}
							}
						}
					}
				}
			}
			break;
		}

		/* Child Stream Data Received */
		{
			char *data = (char *)in;
			size_t data_len = len;
			int is_file_rec = pss_is_file_receiver(pss);

			lwsl_user("RECEIVE: wsi=%p, len=%zu, is_unidi=%d, is_initiator=%d, push_hdr_done=%d, is_file_rec=%d\n",
				wsi, data_len, pss->is_unidi, pss->is_initiator, pss->push_hdr_done, is_file_rec);

			if (is_file_rec) {
				/* Receiver of file */
				if (pss->is_unidi) {
					/* Unidirectional: parse PUSH <filename>\n first */
					if (!pss->push_hdr_done) {
						size_t i;
						for (i = 0; i < data_len; i++) {
							if (pss->push_hdr_len < sizeof(pss->push_hdr) - 1) {
								pss->push_hdr[pss->push_hdr_len++] = data[i];
								if (data[i] == '\n') {
									pss->push_hdr[pss->push_hdr_len] = '\0';
									pss->push_hdr_done = 1;
									/* Parse filename */
									if (strncmp(pss->push_hdr, "PUSH ", 5) == 0) {
										char *nl = strchr(pss->push_hdr, '\n');
										if (nl) *nl = '\0';
										lws_strncpy(pss->filename, pss->push_hdr + 5, sizeof(pss->filename));
										lwsl_user("RECEIVE: Parsed filename '%s'\n", pss->filename);
									}
									/* Open file regardless of rem */
									char dirpath[512], filepath[512];
									const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
									lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s", endpoint);
									if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
										lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
									}
									lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, pss->filename);
									pss->fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
									
									size_t rem = data_len - i - 1;
									lwsl_user("RECEIVE: Opened file '%s' -> fd %d (rem=%zu bytes written)\n", filepath, pss->fd_out, rem);
									if (pss->fd_out >= 0 && rem > 0) {
										if (write(pss->fd_out, data + i + 1, LWS_POSIX_LENGTH_CAST(rem)) < 0) {
											lwsl_err("Failed to write stream chunk\n");
										}
									}
									break;
								}
							}
						}
					} else {
						if (pss->fd_out >= 0) {
							if (write(pss->fd_out, data, LWS_POSIX_LENGTH_CAST(data_len)) < 0) {
								lwsl_err("Failed to write stream data\n");
							}
						} else {
							lwsl_user("RECEIVE: fd_out is closed/invalid (%d) while trying to write %zu bytes\n", pss->fd_out, data_len);
						}
					}
				} else {
					/* Bidirectional: no header, just raw file contents */
					if (pss->fd_out < 0) {
						char dirpath[512], filepath[512];
						const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
						lws_snprintf(dirpath, sizeof(dirpath), "/downloads%s", endpoint);
						if (mkdir(dirpath, 0777) < 0 && errno != EEXIST) { // NOSONAR
							lwsl_err("Failed to create directory %s: %d\n", dirpath, errno);
						}
						lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, pss->filename);
						pss->fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666); // NOSONAR
						lwsl_user("RECEIVE (bidi): Opened file '%s' -> fd %d\n", filepath, pss->fd_out);
					}
					if (pss->fd_out >= 0) {
						if (write(pss->fd_out, data, LWS_POSIX_LENGTH_CAST(data_len)) < 0) {
							lwsl_err("Failed to write stream data\n");
						}
					}
				}
			} else {
				/* Sender (received GET <filename>) */
				if (data_len > 4 && strncmp(data, "GET ", 4) == 0) {
					char filename[256];
					size_t fn_len = data_len - 4;
					/* Remove trailing spaces or newlines if any */
					while (fn_len > 0 && (data[4 + fn_len - 1] == ' ' || data[4 + fn_len - 1] == '\r' || data[4 + fn_len - 1] == '\n'))
						fn_len--;
					if (fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
					memcpy(filename, data + 4, fn_len);
					filename[fn_len] = '\0';

					lws_strncpy(pss->filename, filename, sizeof(pss->filename));
					lwsl_user("Sender WSI received GET %s\n", pss->filename);

					/* Open local file from /www/<endpoint>/<filename> */
					char filepath[512];
					const char *endpoint = pss->endpoint[0] ? pss->endpoint : global_endpoint;
					lws_snprintf(filepath, sizeof(filepath), "/www%s/%s", endpoint, pss->filename);
					pss->fd_in = open(filepath, O_RDONLY);
					if (pss->fd_in >= 0) {
						struct stat st;
						if (fstat(pss->fd_in, &st) == 0) {
							pss->file_len = (size_t)st.st_size;
						}
						
						if (lws_wt_is_unidi(wsi)) {
							struct lws *cwsi = lws_wt_create_stream_from_child(wsi, 1);
							if (cwsi) {
								if (!lws_ensure_user_space(cwsi)) {
									struct pss_qir *cpss = (struct pss_qir *)lws_wsi_user(cwsi);
									if (cpss) {
										cpss->is_unidi = 1;
										cpss->is_initiator = 0;
										lws_strncpy(cpss->endpoint, endpoint, sizeof(cpss->endpoint));
										lws_strncpy(cpss->filename, filename, sizeof(cpss->filename));
										cpss->fd_in = pss->fd_in;
										pss->fd_in = -1;
										cpss->file_len = pss->file_len;
										lws_callback_on_writable(cwsi);
										lwsl_user("Created server-initiated stream %p for unidirectional file response\n", cwsi);
									} else {
										lwsl_err("Child stream user space is NULL\n");
										close(pss->fd_in);
										pss->fd_in = -1;
									}
								} else {
									lwsl_err("Failed to ensure user space for child stream\n");
									close(pss->fd_in);
									pss->fd_in = -1;
								}
							} else {
								lwsl_err("Failed to create server-initiated stream for response\n");
								close(pss->fd_in);
								pss->fd_in = -1;
							}
						} else {
							lws_callback_on_writable(wsi);
						}
					} else {
						lwsl_err("Sender WSI failed to open file %s\n", filepath);
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (pss->fd_in >= 0) {
			close(pss->fd_in);
			pss->fd_in = -1;
		}
		if (pss->fd_out >= 0) {
			close(pss->fd_out);
			pss->fd_out = -1;
		}
		if (!pss->is_session) {
			if (pss->is_unidi && pss->is_initiator) {
				lwsl_user("Initiator unidirectional GET stream closed (not marking request completed yet)\n");
				break;
			}
			if (!is_server) {
				int r_idx = -1;
				int i;
				for (i = 0; i < client_requests_count; i++) {
					if (strcmp(client_requests[i].filename, pss->filename) == 0) {
						r_idx = i;
						break;
					}
				}
				if (r_idx >= 0) {
					client_requests[r_idx].completed = 1;
					lwsl_user("Client transfer request index %d (%s) completed (stream closed)\n", r_idx, pss->filename);
				}
			} else {
				int r_idx = -1;
				int i;
				for (i = 0; i < server_requests_count; i++) {
					if (strcmp(server_requests[i].filename, pss->filename) == 0) {
						r_idx = i;
						break;
					}
				}
				if (r_idx >= 0) {
					server_requests[r_idx].completed = 1;
					lwsl_user("Server transfer request index %d (%s) completed (stream closed)\n", r_idx, pss->filename);
					
					int all_done = 1;
					for (i = 0; i < server_requests_count; i++) {
						if (!server_requests[i].completed) {
							all_done = 0;
							break;
						}
					}
					if (all_done) {
						lwsl_user("All server requests completed. Setting interrupted = 1 to exit.\n");
						interrupted = 1;
					}
				}
			}
		} else {
			lwsl_user("%s session closed. Setting interrupted = 1 to exit.\n", is_server ? "Server" : "Client");
			interrupted = 1;
		}
		lwsl_user("WSI closed\n");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "webtransport", callback_qir, sizeof(struct pss_qir), 65536, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	signal(SIGINT, sigint_handler);

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	/* Determine role */
	if (argc > 1 && strcmp(argv[1], "server") == 0)
		is_server = 1;
	else
		is_server = 0;

	/* Read testcase env */
	const char *tc = getenv("TESTCASE_NAME");
	if (!tc)
		tc = getenv("TESTCASE");
	if (tc)
		lws_strncpy(testcase, tc, sizeof(testcase));

	lwsl_user("LWS WebTransport QIR Tool | Role: %s | Testcase: %s\n",
		  is_server ? "server" : "client", testcase);

	/* Determine port */
	int port = 443;
	const char *port_env = getenv("PORT");
	if (port_env)
		port = atoi(port_env);

	memset(&info, 0, sizeof info);
	info.port = is_server ? port : CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols = protocols;
	info.alpn = "h3";

	if (is_server) {
		static char cert_path[512];
		static char key_path[512];
		int fd_check;

		/* The interop runner mounts host certificates at /certs inside the container */
		fd_check = open("/certs/cert.pem", O_RDONLY);
		if (fd_check >= 0) {
			close(fd_check);
			lws_strncpy(cert_path, "/certs/cert.pem", sizeof(cert_path));
			lws_strncpy(key_path, "/certs/priv.key", sizeof(key_path));
		} else {
			/* Fallback to local files if running outside QIR simulation */
			lws_strncpy(cert_path, "localhost-100y.cert", sizeof(cert_path));
			lws_strncpy(key_path, "localhost-100y.key", sizeof(key_path));
		}

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
		parse_server_requests();
	} else {
		parse_client_requests();
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* Client connection triggering */
	if (!is_server && client_requests_count > 0) {
		int i;
		for (i = 0; i < client_requests_count; i++) {
			struct request_item *item = &client_requests[i];

			/* Connect only once per unique host/port/endpoint */
			int already_triggered = 0;
			int j;
			for (j = 0; j < i; j++) {
				if (strcmp(client_requests[j].endpoint, item->endpoint) == 0 &&
				    strcmp(client_requests[j].host, item->host) == 0 &&
				    client_requests[j].port == item->port) {
					already_triggered = 1;
					break;
				}
			}
			if (already_triggered)
				continue;

			struct lws_client_connect_info cinfo;

			memset(&cinfo, 0, sizeof(cinfo));
			cinfo.context = context;
			cinfo.address = item->host;
			cinfo.port = item->port;
			cinfo.path = item->endpoint;
			cinfo.host = item->host;
			cinfo.origin = item->host;
			cinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
			cinfo.protocol = "webtransport";
			cinfo.alpn = "h3";

			if (first_session_wsi) {
				/* Force multiplexing on the same QUIC network connection */
				cinfo.parent_wsi = first_session_wsi;
			}

			struct lws *wsi = lws_client_connect_via_info(&cinfo);
			if (!wsi) {
				lwsl_err("Failed to initiate WebTransport client connection to %s\n", item->url);
			} else {
				if (!first_session_wsi) {
					first_session_wsi = wsi;
				}
			}
		}
	}

	while (n >= 0 && !interrupted) {
		n = lws_service(context, 0);

		/* Check if all client requests are done and exit */
		if (!is_server && client_requests_count > 0) {
			int all_done = 1;
			int i;
			for (i = 0; i < client_requests_count; i++) {
				if (!client_requests[i].completed)
					all_done = 0;
			}
			if (all_done && strcmp(testcase, "handshake") != 0) {
				lwsl_user("All client requests completed. Waiting 500ms before exiting.\n");
				usleep(500000);
				break;
			}
			/* Handshake testcase does not download files, just wait a bit and exit */
			if (strcmp(testcase, "handshake") == 0) {
				char client_proto_path[512];
				lws_snprintf(client_proto_path, sizeof(client_proto_path), "/downloads/negotiated_protocol.txt");
				int fd = open(client_proto_path, O_RDONLY);
				if (fd >= 0) {
					close(fd);
					lwsl_user("Handshake verification file found, client exiting successfully.\n");
					break;
				}
			}
		}
	}

	lws_context_destroy(context);
	return 0;
}
