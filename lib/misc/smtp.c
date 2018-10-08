/*
 * SMTP support for libwebsockets
 *
 * Copyright (C) 2016-2017 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#include "core/private.h"

static unsigned int
lwsgs_now_secs(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec;
}

static void
ccb(uv_handle_t* handle)
{

}

static void
alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	struct lws_email *email = (struct lws_email *)handle->data;

	*buf = uv_buf_init(email->email_buf, sizeof(email->email_buf) - 1);
}

static void
on_write_end(uv_write_t *req, int status) {
	lwsl_notice("%s\n", __func__);
	if (status == -1) {
		fprintf(stderr, "error on_write_end");
		return;
	}
}

static void
lwsgs_email_read(struct uv_stream_s *s, ssize_t nread, const uv_buf_t *buf)
{
	struct lws_email *email = (struct lws_email *)s->data;
	static const short retcodes[] = {
		0,	/* idle */
		0,	/* connecting */
		220,	/* connected */
		250,	/* helo */
		250,	/* from */
		250,	/* to */
		354,	/* data */
		250,	/* body */
		221,	/* quit */
	};
	uv_write_t write_req;
	uv_buf_t wbuf;
	int n;

	if (nread >= 0)
		email->email_buf[nread] = '\0';
	lwsl_notice("%s: %s\n", __func__, buf->base);
	if (nread == -1) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	n = atoi(buf->base);
	if (n != retcodes[email->estate]) {
		lwsl_err("%s: bad response from server\n", __func__);
		goto close_conn;
	}

	switch (email->estate) {
	case LGSSMTP_CONNECTED:
		n = sprintf(email->content, "HELO %s\n", email->email_helo);
		email->estate = LGSSMTP_SENT_HELO;
		break;
	case LGSSMTP_SENT_HELO:
		n = sprintf(email->content, "MAIL FROM: <%s>\n",
			    email->email_from);
		email->estate = LGSSMTP_SENT_FROM;
		break;
	case LGSSMTP_SENT_FROM:
		n = sprintf(email->content, "RCPT TO: <%s>\n", email->email_to);
		email->estate = LGSSMTP_SENT_TO;
		break;
	case LGSSMTP_SENT_TO:
		n = sprintf(email->content, "DATA\n");
		email->estate = LGSSMTP_SENT_DATA;
		break;
	case LGSSMTP_SENT_DATA:
		if (email->on_get_body(email, email->content,
				       email->max_content_size))
			return;
		n = strlen(email->content);
		email->estate = LGSSMTP_SENT_BODY;
		break;
	case LGSSMTP_SENT_BODY:
		n = sprintf(email->content, "quit\n");
		email->estate = LGSSMTP_SENT_QUIT;
		break;
	case LGSSMTP_SENT_QUIT:
		lwsl_notice("%s: done\n", __func__);
		email->on_sent(email);
		email->estate = LGSSMTP_IDLE;
		goto close_conn;
	default:
		return;
	}

	puts(email->content);
	wbuf = uv_buf_init(email->content, n);
	uv_write(&write_req, s, &wbuf, 1, on_write_end);

	return;

close_conn:

	uv_close((uv_handle_t *)s, ccb);
}

static void
lwsgs_email_on_connect(uv_connect_t *req, int status)
{
	struct lws_email *email = (struct lws_email *)req->data;

	lwsl_notice("%s\n", __func__);

	if (status == -1) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	uv_read_start(req->handle, alloc_buffer, lwsgs_email_read);
	email->estate = LGSSMTP_CONNECTED;
}


static void
uv_timeout_cb_email(uv_timer_t *w
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct lws_email *email = lws_container_of(w, struct lws_email,
						   timeout_email);
	time_t now = lwsgs_now_secs();
	struct sockaddr_in req_addr;

	switch (email->estate) {
	case LGSSMTP_IDLE:

		if (email->on_next(email))
			break;

		email->estate = LGSSMTP_CONNECTING;

		uv_tcp_init(email->loop, &email->email_client);
		if (uv_ip4_addr(email->email_smtp_ip, 25, &req_addr)) {
			lwsl_err("Unable to convert mailserver ads\n");
			return;
		}

		lwsl_notice("LGSSMTP_IDLE: connecting\n");

		email->email_connect_started = now;
		email->email_connect_req.data = email;
		email->email_client.data = email;
		uv_tcp_connect(&email->email_connect_req, &email->email_client,
			       (struct sockaddr *)&req_addr,
			       lwsgs_email_on_connect);

		uv_timer_start(&email->timeout_email,
			       uv_timeout_cb_email, 5000, 0);

		break;

	case LGSSMTP_CONNECTING:
		if (email->email_connect_started - now > 5) {
			lwsl_err("mail session timed out\n");
			/* !!! kill the connection */
			uv_close((uv_handle_t *) &email->email_connect_req, ccb);
			email->estate = LGSSMTP_IDLE;
		}
		break;

	default:
		break;
	}
}

LWS_VISIBLE LWS_EXTERN int
lws_email_init(struct lws_email *email, uv_loop_t *loop, int max_content)
{
	email->content = lws_malloc(max_content, "email content");
	if (!email->content)
		return 1;

	email->max_content_size = max_content;
	uv_timer_init(loop, &email->timeout_email);

	email->loop = loop;

	/* trigger him one time in a bit */
	uv_timer_start(&email->timeout_email, uv_timeout_cb_email, 2000, 0);

	return 0;
}

LWS_VISIBLE LWS_EXTERN void
lws_email_check(struct lws_email *email)
{
	uv_timer_start(&email->timeout_email, uv_timeout_cb_email, 1000, 0);
}

LWS_VISIBLE LWS_EXTERN void
lws_email_destroy(struct lws_email *email)
{
	if (email->content)
		lws_free_set_NULL(email->content);

	uv_timer_stop(&email->timeout_email);
	uv_close((uv_handle_t *)&email->timeout_email, NULL);
}
