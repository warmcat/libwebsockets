/*
 * sai-builder - src/builder/b-whoami.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * A builder in a VM sai-virt spawned (-O / -E) is a clone of a basis image,
 * so its conf can't say which VM it is.  sai-virt can tell, from the address
 * our requests come from, so before we connect to anything else we ask it at
 * our sai-power url, and take the name it knows the VM by as our host name.
 * Our /stay and /auto-power-off requests only mean anything to sai-virt under
 * that name.
 *
 * Until it tells us, we hold the system state short of OPERATIONAL, so we
 * don't connect to any server or take any task.  If sai-virt doesn't know us,
 * eg, the basis VM was booted by hand to maintain it, we never start, we just
 * keep asking: otherwise we'd build real tasks into the basis image.
 */

#include <libwebsockets.h>
#include <string.h>

#include "b-private.h"

#define SAIB_WHOAMI_RETRY_MIN_US	(2 * LWS_US_PER_SEC)
#define SAIB_WHOAMI_RETRY_MAX_US	(60 * LWS_US_PER_SEC)

LWS_SS_USER_TYPEDEF
	char			reply[96];
	size_t			len;
	char			replied;
} saib_whoami_t;

static struct lws_ss_handle *ss_whoami;
static lws_sorted_usec_list_t sul_whoami;
static lws_usec_t whoami_retry_us = SAIB_WHOAMI_RETRY_MIN_US;
static char whoami_done;

static void
sul_whoami_cb(lws_sorted_usec_list_t *sul);

/*
 * sai-virt names its VMs "sai-vm-<platform>-<n>", but anything we take as
 * our host name ends up in urls and logs, so be strict about what we accept
 */

static int
saib_whoami_name_ok(const char *p, size_t len)
{
	size_t n;

	if (!len || len > 64)
		return 0;

	for (n = 0; n < len; n++)
		if (!((p[n] >= 'a' && p[n] <= 'z') ||
		      (p[n] >= 'A' && p[n] <= 'Z') ||
		      (p[n] >= '0' && p[n] <= '9') ||
		      p[n] == '-' || p[n] == '_' || p[n] == '.'))
			return 0;

	return 1;
}

static void
saib_whoami_reply(saib_whoami_t *g)
{
	char *host;
	size_t n;

	if (g->len < 5 || memcmp(g->reply, "ACK: ", 5)) {
		lwsl_warn("%s: sai-virt doesn't know this VM: '%.*s', asking "
			  "again in %ds\n", __func__, (int)g->len, g->reply,
			  (int)(whoami_retry_us / LWS_US_PER_SEC));
		return;
	}

	n = g->len - 5;
	while (n && (g->reply[5 + n - 1] == '\n' ||
		     g->reply[5 + n - 1] == '\r'))
		n--;

	if (!saib_whoami_name_ok(g->reply + 5, n)) {
		lwsl_err("%s: unusable name from sai-virt: '%.*s'\n", __func__,
			 (int)g->len, g->reply);
		return;
	}

	host = lwsac_use(&builder.conf_head, n + 1, 512);
	if (!host)
		return;

	memcpy(host, g->reply + 5, n);
	host[n] = '\0';

	lwsl_notice("%s: sai-virt knows this VM as %s (conf had %s)\n",
		    __func__, host, builder.host ? builder.host : "none");

	builder.host = host;
	whoami_done = 1;

	/* move on from outside this callback */
	lws_sul_schedule(builder.context, 0, &sul_whoami,
			 sul_whoami_cb, 1);
}

static lws_ss_state_return_t
saib_whoami_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	saib_whoami_t *g = (saib_whoami_t *)userobj;
	size_t n;

	if (flags & LWSSS_FLAG_SOM)
		g->len = 0;

	n = sizeof(g->reply) - g->len;
	if (len < n)
		n = len;
	memcpy(g->reply + g->len, buf, n);
	g->len += n;

	if (flags & LWSSS_FLAG_EOM) {
		g->replied = 1;
		saib_whoami_reply(g);
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_whoami_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
	       size_t *len, int *flags)
{
	*len = 0;
	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_whoami_state(void *userobj, void *sh, lws_ss_constate_t state,
		  lws_ss_tx_ordinal_t ack)
{
	saib_whoami_t *g = (saib_whoami_t *)userobj;

	switch (state) {
	case LWSSSCS_CONNECTING:
		g->replied = 0;
		break;

	case LWSSSCS_DISCONNECTED:
		/*
		 * Failing to connect is retried by the stream's own policy:
		 * we only have to ask again if sai-virt answered, but didn't
		 * know us
		 */
		if (!g->replied)
			break;
		/* fallthru */
	case LWSSSCS_ALL_RETRIES_FAILED:
		if (!whoami_done)
			lws_sul_schedule(builder.context, 0, &sul_whoami,
					 sul_whoami_cb, whoami_retry_us);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power", saib_whoami_t)
	.rx				= saib_whoami_rx,
	.tx				= saib_whoami_tx,
	.state				= saib_whoami_state,
};

static void
sul_whoami_cb(lws_sorted_usec_list_t *sul)
{
	if (whoami_done || !ss_whoami) {
		/*
		 * Either we know who we are, or we couldn't create the stream
		 * yet, and going through the transition again retries that
		 */
		lws_ss_destroy(&ss_whoami);
		lws_state_transition_steps(
			lws_system_get_state_manager(builder.context),
			LWS_SYSTATE_OPERATIONAL);
		return;
	}

	if (lws_ss_client_connect(ss_whoami))
		lwsl_ss_err(ss_whoami, "unable to connect");

	if (lws_ss_request_tx(ss_whoami))
		lwsl_ss_warn(ss_whoami, "unable to request tx");

	whoami_retry_us *= 2;
	if (whoami_retry_us > SAIB_WHOAMI_RETRY_MAX_US)
		whoami_retry_us = SAIB_WHOAMI_RETRY_MAX_US;
}

/*
 * Called from the system state notifier as we try to go OPERATIONAL: returns
 * nonzero while we have to hold off, having started asking if we weren't
 * already.
 */

int
saib_whoami_pending(void)
{
	char url[256];

	if (!saib_is_ephemeral() || whoami_done)
		return 0;

	if (ss_whoami)
		return 1; /* still asking */

	if (!builder.url_sai_power) {
		lwsl_err("%s: in a sai-virt VM, but no sai-power url in conf "
			 "to ask sai-virt which VM we are: carrying on as %s, "
			 "sai-virt won't recognize us\n", __func__,
			 builder.host ? builder.host : "unknown");
		whoami_done = 1;

		return 0;
	}

	if (lws_ss_create(builder.context, 0, &ssi_saib_whoami_t, NULL,
			  &ss_whoami, NULL, NULL)) {
		lwsl_err("%s: unable to create whoami stream\n", __func__);
		lws_sul_schedule(builder.context, 0, &sul_whoami,
				 sul_whoami_cb, SAIB_WHOAMI_RETRY_MIN_US);

		return 1;
	}

	lws_snprintf(url, sizeof(url), "%s/whoami", builder.url_sai_power);
	if (lws_ss_set_metadata(ss_whoami, "url", url, strlen(url)))
		lwsl_err("%s: unable to set url\n", __func__);

	lwsl_notice("%s: asking sai-virt which VM we are: %s\n", __func__, url);

	lws_sul_schedule(builder.context, 0, &sul_whoami, sul_whoami_cb, 1);

	return 1;
}
