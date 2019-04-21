/*
 * Abstract SMTP support for libwebsockets
 *
 * Copyright (C) 2016-2019 Andy Green <andy@warmcat.com>
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
#include "abstract/smtp/private.h"

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

static void
lws_smtp_client_state_transition(lws_smtp_client_t *c, lwsgs_smtp_states_t s)
{
	lwsl_debug("%s: cli %p: state %d -> %d\n", __func__, c, c->estate, s);
	c->estate = s;
}

void
lws_smtp_client_kick(lws_smtp_client_t *c)
{
	lws_smtp_email_t *e;
	lws_dll2_t *d;
	char buf[64];
	int n;

	if (c->estate != LGSSMTP_IDLE)
		return;

	/* is there something to do? */

again:
	d = lws_dll2_get_head(&c->pending_owner);
	if (!d)
		return;

	e = lws_container_of(d, lws_smtp_email_t, list);

	/* do we need to time out this guy? */

	if ((time_t)lws_now_secs() - e->added > (time_t)c->i.delivery_timeout) {
		lwsl_err("%s: timing out email\n", __func__);
		lws_dll2_remove(&e->list);
		n = lws_snprintf(buf, sizeof(buf), "0 Timed out retrying send");
		e->done(e, buf, n);

		if (lws_dll2_get_head(&c->pending_owner))
			goto again;

		return;
	}

	/* is it time for his retry yet? */

	if (e->last_try &&
	    (time_t)lws_now_secs() - e->last_try < (time_t)c->i.retry_interval) {
		/* no... send him to the tail */
		lws_dll2_remove(&e->list);
		lws_dll2_add_tail(&e->list, &c->pending_owner);
		return;
	}

	/* check if we have a connection to the server ongoing */

	if (c->abs.state(c->abs_conn)) {
		/*
		 * there's a connection, it could be still trying to connect
		 * or established
		 */
		c->abs.ask_for_writeable(c->abs_conn);

		return;
	}

	/* there's no existing connection */

	lws_smtp_client_state_transition(c, LGSSMTP_CONNECTING);
	lwsl_notice("LGSSMTP_IDLE: connecting to %s:25\n", c->i.ip);

	if (c->abs.client_conn(c->abs_conn, c->i.vh, c->i.ip, 25, 0)) {
		lwsl_err("%s: failed to connect to %s:25\n",
			__func__, c->i.ip);

		return;
	}

	e->tries++;
	e->last_try = lws_now_secs();
}

/*
 * we became connected
 */

static int
lws_smtp_client_abs_accept(lws_abs_user_t *abs_priv)
{
	lws_smtp_client_t *c = (lws_smtp_client_t *)abs_priv;

	lws_smtp_client_state_transition(c, LGSSMTP_CONNECTED);

	return 0;
}

static int
lws_smtp_client_abs_rx(lws_abs_user_t *abs_priv, uint8_t *buf, size_t len)
{
	lws_smtp_client_t *c = (lws_smtp_client_t *)abs_priv;
	lws_smtp_email_t *e;
	lws_dll2_t *pd2;
	int n;

	pd2 = lws_dll2_get_head(&c->pending_owner);
	if (!pd2)
		return 0;

	e = lws_container_of(pd2, lws_smtp_email_t, list);
	if (!e)
		return 0;

	lwsl_debug("%s: rx: '%.*s'\n", __func__, (int)len, (const char *)buf);

	n = atoi((char *)buf);
	if (n != retcodes[c->estate]) {
		lwsl_notice("%s: bad response from server: %d (state %d) %.*s\n",
				__func__, n, c->estate, (int)len, buf);

		lws_dll2_remove(&e->list);
		lws_dll2_add_tail(&e->list, &c->pending_owner);
		lws_smtp_client_state_transition(c, LGSSMTP_IDLE);
		lws_smtp_client_kick(c);

		return 0;
	}

	if (c->estate == LGSSMTP_SENT_QUIT) {
		lwsl_debug("%s: done\n", __func__);
		lws_smtp_client_state_transition(c, LGSSMTP_IDLE);

		lws_dll2_remove(&e->list);
		if (e->done && e->done(e, "sent OK", 7))
			return 1;

		return 1;
	}

	c->send_pending = 1;
	c->abs.ask_for_writeable(c->abs_conn);

	return 0;
}

static int
lws_smtp_client_abs_writeable(lws_abs_user_t *abs_priv, size_t budget)
{
	lws_smtp_client_t *c = (lws_smtp_client_t *)abs_priv;
	char b[256 + LWS_PRE], *p = b + LWS_PRE;
	lws_smtp_email_t *e;
	lws_dll2_t *pd2;
	int n;

	pd2 = lws_dll2_get_head(&c->pending_owner);
	if (!pd2)
		return 0;

	e = lws_container_of(pd2, lws_smtp_email_t, list);
	if (!e)
		return 0;


	if (!c->send_pending)
		return 0;

	c->send_pending = 0;

	lwsl_debug("%s: writing response for state %d\n", __func__, c->estate);

	switch (c->estate) {
	case LGSSMTP_CONNECTED:
		n = lws_snprintf(p, sizeof(b) - LWS_PRE, "HELO %s\n", c->i.helo);
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_HELO);
		break;
	case LGSSMTP_SENT_HELO:
		n = lws_snprintf(p, sizeof(b) - LWS_PRE, "MAIL FROM: <%s>\n",
				 e->email_from);
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_FROM);
		break;
	case LGSSMTP_SENT_FROM:
		n = lws_snprintf(p, sizeof(b) - LWS_PRE,
				 "RCPT TO: <%s>\n", e->email_to);
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_TO);
		break;
	case LGSSMTP_SENT_TO:
		n = lws_snprintf(p, sizeof(b) - LWS_PRE, "DATA\n");
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_DATA);
		break;
	case LGSSMTP_SENT_DATA:
		p = (char *)e->payload;
		n = strlen(e->payload);
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_BODY);
		break;
	case LGSSMTP_SENT_BODY:
		n = lws_snprintf(p, sizeof(b) - LWS_PRE, "quit\n");
		lws_smtp_client_state_transition(c, LGSSMTP_SENT_QUIT);
		break;
	case LGSSMTP_SENT_QUIT:
		return 0;

	default:
		return 0;
	}

	//puts(p);
	c->abs.tx(c->abs_conn, (uint8_t *)p, n);

	return 0;
}

static int
lws_smtp_client_abs_closed(lws_abs_user_t *abs_priv)
{
	lws_smtp_client_t *c = (lws_smtp_client_t *)abs_priv;

	c->abs_conn = NULL;

	return 0;
}

static int
lws_smtp_client_abs_heartbeat(lws_abs_user_t *abs_priv)
{
	lws_smtp_client_t *c = (lws_smtp_client_t *)abs_priv;

	lws_smtp_client_kick(c);

	return 0;
}

lws_smtp_email_t *
lws_smtp_client_alloc_email_helper(const char *payload, size_t payload_len,
				   const char *sender, const char *recipient,
				   const char *extra, size_t extra_len, void *data,
				   int (*done)(struct lws_smtp_email *e,
					       void *buf, size_t len))
{
	size_t ls = strlen(sender), lr = strlen(recipient);
	lws_smtp_email_t *em;
	char *p;

	em = malloc(sizeof(*em) + payload_len + ls + lr + extra_len + 4);
	if (!em) {
		lwsl_err("OOM\n");
		return NULL;
	}

	p = (char *)&em[1];

	memset(em, 0, sizeof(*em));

	em->data = data;
	em->done = done;

	em->email_from = p;
	memcpy(p, sender, ls + 1);
	p += ls + 1;
	em->email_to = p;
	memcpy(p, recipient, lr + 1);
	p += lr + 1;
	em->payload = p;
	memcpy(p, payload, payload_len + 1);
	p += payload_len + 1;

	if (extra) {
		em->extra = p;
		memcpy(p, extra, extra_len + 1);
	}

	return em;
}

int
lws_smtp_client_add_email(lws_smtp_client_t *c, lws_smtp_email_t *e)
{
	if (c->pending_owner.count > c->i.email_queue_max) {
		lwsl_err("%s: email queue at limit of %d\n", __func__,
				(int)c->i.email_queue_max);

		return 1;
	}

	e->added = lws_now_secs();
	e->last_try = 0;
	e->tries = 0;

	lws_dll2_clear(&e->list);
	lws_dll2_add_tail(&e->list, &c->pending_owner);

	lws_smtp_client_kick(c);

	return 0;
}

lws_smtp_client_t *
lws_smtp_client_create(const lws_smtp_client_info_t *ci)
{
	lws_smtp_client_t *c;

	c = lws_zalloc(sizeof(*c), "email client");
	if (!c)
		return NULL;

	c->i = *ci;
	c->abs = *ci->abs;

	/* fill in the additional abstract callbacks we fulfil */

	c->abs.accept = lws_smtp_client_abs_accept;
	c->abs.rx = lws_smtp_client_abs_rx;
	c->abs.writeable = lws_smtp_client_abs_writeable;
	c->abs.closed = lws_smtp_client_abs_closed;
	c->abs.heartbeat = lws_smtp_client_abs_heartbeat;

	if (!c->i.email_queue_max)
		c->i.email_queue_max = 8;

	if (!c->i.retry_interval)
		c->i.retry_interval = 15 * 60;

	if (!c->i.delivery_timeout)
		c->i.delivery_timeout = 12 * 60 * 60;

	c->abs_conn = c->abs.create(&c->abs, c);
	if (!c->abs_conn) {
		lws_free(c);

		return NULL;
	}

	lws_smtp_client_state_transition(c, LGSSMTP_IDLE);

	return c;
}

static int
cleanup(struct lws_dll2 *d, void *user)
{
	lws_smtp_email_t *e;

	e = lws_container_of(d, lws_smtp_email_t, list);
	if (e->done && e->done(e, "destroying", 10))
		return 1;

	return 0;
}

void
lws_smtp_client_destroy(lws_smtp_client_t **c)
{
	if (!*c)
		return;

	lws_dll2_foreach_safe(&(*c)->pending_owner, NULL, cleanup);

	if ((*c)->abs_conn) {
		(*c)->abs.close((*c)->abs_conn);
		(*c)->abs.destroy(&(*c)->abs_conn);
	}

	lws_free_set_NULL(*c);
}
