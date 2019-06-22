/*
 * libwebsockets lib/abstract/transports/unit-test.c
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
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
 * An abstract transport that is useful for unit testing an abstract protocol.
 * It doesn't actually connect to anything, but checks the protocol's response
 * to various canned packets.
 *
 * Although it doesn't use any socket itself, it still needs to respect the
 * event loop so it can reflect the associated behaviours correctly.  So it
 * creates a wsi for these purposes, which is a RAW FILE open on /dev/null.
 */

#include "core/private.h"
#include "abstract/private.h"

typedef struct lws_abstxp_unit_test_priv {
	char note[128];
	struct lws_abs *abs;

	struct lws *wsi;
	lws_expect_test_t *current_test;
	lws_expect_t *expect;
	lws_expect_disposition disposition;
	int filefd;

	lws_dll2_t same_abs_transport_list;

	uint8_t established:1;
	uint8_t connecting:1;
} abs_unit_test_priv_t;

struct vhd {
	lws_dll2_owner_t owner;
};

/*
 * A definitive result has appeared for the current test
 */

static lws_expect_disposition
lws_expect_dispose(abs_unit_test_priv_t *priv, lws_expect_disposition disp,
		   const char *note)
{
	assert(priv->disposition == LPE_CONTINUE);

	if (note)
		lws_strncpy(priv->note, note, sizeof(priv->note));

	priv->disposition = disp;

	lwsl_user("%s: %s: test %d: %s\n", priv->abs->ap->name,
		  priv->current_test->name,
		  (int)(priv->expect - priv->current_test->expect),
		  disp == LPE_SUCCEEDED ? "OK" : "FAIL");

	return disp;
}

/*
 * start on the next step of the test
 */

lws_expect_disposition
process_expect(abs_unit_test_priv_t *priv)
{
	assert(priv->disposition == LPE_CONTINUE);

	while (priv->expect->flags & LWS_AUT_EXPECT_RX) {
		int f = priv->expect->flags & LWS_AUT_EXPECT_LOCAL_CLOSE,
		    s = priv->abs->ap->rx(priv->abs->api, priv->expect->buffer,
					priv->expect->len);
		if (!!f != !!s) {
			lwsl_notice("%s: expected rx return %d, got %d\n",
					__func__, !!f, s);

			return lws_expect_dispose(priv, LPE_FAILED,
						  "rx unexpected return");
		}

		if (priv->expect->flags & LWS_AUT_EXPECT_TEST_END)
			return lws_expect_dispose(priv, LPE_SUCCEEDED, NULL);

		priv->expect++;
	}

	return LPE_CONTINUE;
}

static int
heartbeat_cb(struct lws_dll2 *d, void *user)
{
	abs_unit_test_priv_t *priv = lws_container_of(d, abs_unit_test_priv_t,
						      same_abs_transport_list);

	if (priv->abs->ap->heartbeat)
		priv->abs->ap->heartbeat(priv->abs->api);

	return 0;
}

static int
callback_abs_client_unit_test(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)user;
	struct vhd *vhd = (struct vhd *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					 lws_get_protocol(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd));
		if (!vhd)
			return 1;

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_USER:
		/*
		 * This comes at 1Hz without a wsi context, so there is no
		 * valid priv.  We need to track the live abstract objects that
		 * are using our abstract protocol, and pass the heartbeat
		 * through to the ones that care.
		 */
		if (!vhd)
			break;

		lws_dll2_foreach_safe(&vhd->owner, NULL, heartbeat_cb);

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 1);
		break;

        case LWS_CALLBACK_RAW_ADOPT_FILE:
		lwsl_debug("LWS_CALLBACK_RAW_ADOPT_FILE\n");
		priv->connecting = 0;
		priv->established = 1;
		if (priv->abs->ap->accept)
			priv->abs->ap->accept(priv->abs->api);
                break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		if (!user)
			break;
		lwsl_debug("LWS_CALLBACK_RAW_CLOSE_FILE\n");
		priv->established = 0;
		priv->connecting = 0;
		if (priv->abs && priv->abs->ap->closed)
			priv->abs->ap->closed(priv->abs->api);
		if (priv->filefd != -1)
			close(priv->filefd);
		priv->filefd = -1;
		lws_set_wsi_user(wsi, NULL);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE_FILE:
		lwsl_debug("LWS_CALLBACK_RAW_WRITEABLE_FILE\n");
		priv->abs->ap->writeable(priv->abs->api,
				lws_get_peer_write_allowance(priv->wsi));
		break;

	case LWS_CALLBACK_RAW_FILE_BIND_PROTOCOL:
		lws_dll2_add_tail(&priv->same_abs_transport_list, &vhd->owner);
		break;

	case LWS_CALLBACK_RAW_FILE_DROP_PROTOCOL:
		lws_dll2_remove(&priv->same_abs_transport_list);
		break;

	default:
		break;
	}

	return 0;
}

const struct lws_protocols protocol_abs_client_unit_test = {
	"lws-abs-cli-unit-test", callback_abs_client_unit_test,
	0, 1024, 1024, NULL, 0
};

static int
lws_atcut_close(lws_abs_transport_inst_t *ati)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)ati;

	lws_set_timeout(priv->wsi, 1, LWS_TO_KILL_SYNC);

	/* priv is destroyed in the CLOSE callback */

	return 0;
}

static int
lws_atcut_tx(lws_abs_transport_inst_t *ati, uint8_t *buf, size_t len)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)ati;

	assert(priv->disposition == LPE_CONTINUE);

	if (!(priv->expect->flags & LWS_AUT_EXPECT_TX)) {
		lwsl_notice("%s: unexpected tx\n", __func__);
		lwsl_hexdump_notice(buf, len);
		lws_expect_dispose(priv, LPE_FAILED, "unexpected tx");

		return 1;
	}

	if (len != priv->expect->len) {
		lwsl_notice("%s: unexpected tx len %zu, expected %zu\n",
				__func__, len, priv->expect->len);
		lws_expect_dispose(priv, LPE_FAILED, "tx len mismatch");

		return 1;
	}

	if (memcmp(buf, priv->expect->buffer, len)) {
		lwsl_notice("%s: tx mismatch (exp / actual)\n", __func__);
		lwsl_hexdump_notice(priv->expect->buffer, len);
		lwsl_hexdump_notice(buf, len);
		lws_expect_dispose(priv, LPE_FAILED, "tx data mismatch");

		return 1;
	}

	if (priv->expect->flags & LWS_AUT_EXPECT_TEST_END) {
		lws_expect_dispose(priv, LPE_SUCCEEDED, NULL);

		return 1;
	}

	priv->expect++;

	return 0;
}

#if !defined(LWS_WITHOUT_CLIENT)
static int
lws_atcut_client_conn(const lws_abs_t *abs)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)abs->ati;
	const lws_token_map_t *tm;
	lws_sock_file_fd_type u;

	/*
	 * we do this fresh for each test
	 */

	if (priv->connecting || priv->established)
		return 0;

	priv->filefd = lws_open("/dev/null", O_RDWR);
	if (priv->filefd == -1) {
		lwsl_err("%s: Unable to open /dev/null\n", __func__);

		return 1;
	}
	u.filefd = (lws_filefd_type)(long long)priv->filefd;
	if (!lws_adopt_descriptor_vhost(priv->abs->vh, LWS_ADOPT_RAW_FILE_DESC,
					u, "unit-test", NULL)) {
		lwsl_err("Failed to adopt file descriptor\n");
		close(priv->filefd);
		priv->filefd = -1;

		return 1;
	}

	/* set up the test start pieces */

	tm = lws_abs_get_token(abs->at_tokens, LTMI_PEER_V_EXPECT_TEST);
	if (!tm) {
		lwsl_notice("%s: unit_test needs LTMI_PEER_V_EXPECT_TEST\n",
			    __func__);

		return 1;
	}
	priv->current_test = (lws_expect_test_t *)tm->u.value;
	priv->expect = priv->current_test->expect;
	priv->disposition = LPE_CONTINUE;
	priv->note[0] = '\0';

	lwsl_notice("%s: %s: %s: start\n", __func__, abs->ap->name,
		    priv->current_test->name);

	process_expect(priv);

	priv->connecting = 1;

	return 0;
}
#endif

static int
lws_atcut_ask_for_writeable(lws_abs_transport_inst_t *ati)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)ati;

	if (!priv->established)
		return 1;

	lws_callback_on_writable(priv->wsi);

	return 0;
}

static int
lws_atcut_create(struct lws_abs *ai)
{
	abs_unit_test_priv_t *at = (abs_unit_test_priv_t *)ai->ati;

	memset(at, 0, sizeof(*at));
	at->abs = ai;

	return 0;
}

static void
lws_atcut_destroy(lws_abs_transport_inst_t **pati)
{
	/*
	 * We don't free anything because the abstract layer combined our
	 * allocation with that of the instance, and it will free the whole
	 * thing after this.
	 */
	*pati = NULL;
}

static int
lws_atcut_set_timeout(lws_abs_transport_inst_t *ati, int reason, int secs)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)ati;

	lws_set_timeout(priv->wsi, reason, secs);

	return 0;
}

static int
lws_atcut_state(lws_abs_transport_inst_t *ati)
{
	abs_unit_test_priv_t *priv = (abs_unit_test_priv_t *)ati;

	if (!priv || (!priv->established && !priv->connecting))
		return 0;

	return 1;
}


const lws_abs_transport_t lws_abs_transport_cli_unit_test = {
	.name			= "unit_test",
	.alloc			= sizeof(abs_unit_test_priv_t),

	.create			= lws_atcut_create,
	.destroy		= lws_atcut_destroy,

	.tx			= lws_atcut_tx,
#if defined(LWS_WITHOUT_CLIENT)
	.client_conn		= NULL,
#else
	.client_conn		= lws_atcut_client_conn,
#endif
	.close			= lws_atcut_close,
	.ask_for_writeable	= lws_atcut_ask_for_writeable,
	.set_timeout		= lws_atcut_set_timeout,
	.state			= lws_atcut_state,
};

/*
 * This goes through the test array instantiating a new protocol + transport
 * for each test and keeping track of the results
 */

int
lws_abs_transport_unit_test_helper(lws_abs_t *abs)
{
	lws_abs_t *instance;
	const lws_token_map_t *tm;

	tm = lws_abs_get_token(abs->at_tokens, LTMI_PEER_V_EXPECT_TEST_ARRAY);
	if (!tm) {
		lwsl_err("%s: LTMI_PEER_V_EXPECT_TEST_ARRAY is required\n",
			 __func__);

		return 1;
	}

	//wh

	instance = lws_abs_bind_and_create_instance(abs);
	if (!instance) {
		lwsl_err("%s: failed to create SMTP client\n", __func__);
		return 1;
	}

	return 0;
}
