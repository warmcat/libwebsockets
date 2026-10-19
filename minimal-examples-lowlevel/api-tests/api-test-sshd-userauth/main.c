/*
 * lws-api-test-sshd-userauth
 *
 * Fences the F-056 fixes in the sshd plugin's USERAUTH pubkey blob and
 * signature blob handling: both walks advance by attacker-chosen inner
 * lengths and must be bounded against, and exactly consume, the outer
 * blob they walk, or the RSA verify is fed data from wild pointers.  The
 * "scp " exec prefix check is also bounded by the exec command length.
 *
 * An sshd vhost and a raw client run in one process.  The client skips
 * KEX (the USERAUTH states are reachable on the plaintext transport, the
 * session_id is all-zeroes until KEX completes) and drives the USERAUTH
 * states directly:
 *
 *  - with ops that accept any blob structure (a consumer without the
 *    demo's whole-blob byte-compare fence), a pubkey blob with a huge
 *    inner length, and one with an off-by-one mpint length, must each
 *    draw USERAUTH_FAILURE rather than be walked out of bounds,
 *  - the genuine authorized pubkey blob (which passes
 *    is_pubkey_authorized) with a malformed signature blob (huge inner
 *    algo name length / signature length one past the end of the blob /
 *    trailing junk so the blob is not exactly consumed) must likewise
 *    draw USERAUTH_FAILURE rather than read past the sig allocation,
 *  - a genuinely signed USERAUTH request (signed with a runtime-made
 *    keypair over the plaintext the server reconstructs) must still
 *    authenticate and open a session channel, and a 1-byte "exec"
 *    command must be refused with CHANNEL_FAILURE without reading past
 *    the 1-byte command allocation looking for an "scp " prefix.
 *
 * Further scenarios, each on a fresh connection, fence the pre-auth
 * transport parser (G-284, G-285):
 *
 *  - a second KEXINIT while the first one's key exchange is in progress
 *    must close the connection (it used to orphan the first KEXINIT's
 *    copy, up to 256KB a time),
 *  - a DISCONNECT with a long description and a language tag, followed
 *    by another packet in the same write, must reach the disconnect_reason
 *    op exactly once with intact strings, and the server must close the
 *    connection without parsing what follows (the parser used to stay in
 *    the DISCONNECT lang state and pass the freed description to the op
 *    for every later byte),
 *  - zero-length strings must complete: a SERVICE_REQUEST for "" must be
 *    accepted, and a DISCONNECT with empty description and language tag
 *    must reach the op once and close (empty strings used to swallow the
 *    following bytes until the parser bailed).
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/* import the whole of the sshd-base plugin statically, like test-sshd */
#include <lws-plugin-sshd-static-build-includes.h>

#define RXBUF_LEN		8192

enum scenario {
	SC_USERAUTH,		/* the USERAUTH blob walk phases */
	SC_KEXINIT_REPEAT,	/* second KEXINIT during the kex */
	SC_DISCONNECT_LONG,	/* DISCONNECT, then more bytes */
	SC_DISCONNECT_EMPTY,	/* zero-length strings */

	SC_COUNT
};

enum cli_state {
	ST_CLI_VERSION,		/* skipping the server's id string */
	ST_CLI_SVC_ACCEPT,	/* waiting for SERVICE_ACCEPT */
	ST_CLI_UAF_PUB_HUGE,	/* lax ops, huge inner length in pubkey blob */
	ST_CLI_UAF_PUB_OFF1,	/* lax ops, pubkey mpint len off-by-one */
	ST_CLI_UAF_SIG_HUGE,	/* genuine pubkey, huge inner sig length */
	ST_CLI_UAF_SIG_OFF1,	/* genuine pubkey, sig length overruns blob */
	ST_CLI_UAF_SIG_JUNK,	/* genuine pubkey, trailing junk in sig blob */
	ST_CLI_UA_SUCCESS,	/* genuine sig, expecting success */
	ST_CLI_CH_CONFIRM,	/* expecting CHANNEL_OPEN_CONFIRMATION */
	ST_CLI_CH_FAIL,		/* expecting CHANNEL_FAILURE for exec "x" */
	ST_CLI_KEXR_SVC_ACCEPT,	/* first KEXINIT taken, SERVICE_ACCEPT */
	ST_CLI_EMPTY_SVC_ACCEPT,/* SERVICE_ACCEPT for the empty service name */
	ST_CLI_EXPECT_CLOSE,	/* the server must close us now */
	ST_CLI_DONE,		/* scenario passed, we are closing */
};

static struct lws_context *context;
static struct lws *cli_wsi;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_next;
static struct lws_vhost *vh_cli;
static enum scenario scenario = SC_USERAUTH;
static enum cli_state cli_state = ST_CLI_VERSION;
static int result = 1, failed;
static uint16_t port_tcp = 21046;

static uint8_t rxbuf[RXBUF_LEN];
static uint32_t rxlen;

static uint8_t txbuf[LWS_PRE + 2048];
static uint32_t txlen;

static uint8_t pay[1600];	/* ssh packet payload under construction */
static uint32_t paylen;

/* the runtime-generated authorized key material */

static uint8_t keyblob[768];	/* string "ssh-rsa" + mpint e + mpint n */
static uint32_t keyblob_len;
static uint32_t keyblob_n_len_off, keyblob_n_len;
static uint8_t rsasig[512];	/* signature of the USERAUTH plaintext */
static uint32_t rsasig_len;
static uint8_t dummysig[4 + 12 + 4 + 16];	/* well-formed, wrong, never
						 * expected to verify */

static uint32_t server_ch;	/* server's number for the session channel */

static char ops_lax;		/* is_pubkey_authorized accepts any blob */

/* what the disconnect_reason op was told */

#define DISC_DESC_LONG		1000

static int disc_count;
static uint32_t disc_reason;
static size_t disc_desc_len;
static char disc_desc_head[16], disc_lang[16];

/* the sshd side's ops */

static int
ops_is_pubkey_authorized(const char *username, const char *type,
			 const uint8_t *peer, int peer_len)
{
	if (ops_lax)
		/*
		 * The library code itself has to survive consumers that
		 * don't structurally validate the blob: accept anything
		 */
		return 0;

	if (peer_len < 0 || (uint32_t)peer_len != keyblob_len ||
	    lws_timingsafe_bcmp(peer, keyblob, (unsigned int)peer_len))
		return 1;

	return 0;
}

static int
ops_exec(void *priv, struct lws *wsi, const char *command,
	 lws_ssh_finish_exec finish, void *finish_handle)
{
	/* we refuse to exec anything, the "scp " fallback path is next */
	return 1;
}

static int
ops_tx_waiting(void *priv)
{
	return 0;
}

static void
ops_disconnect_reason(uint32_t reason, const char *desc, const char *desc_lang)
{
	/*
	 * Read all of both strings, so a stale pointer is a sanitizer
	 * report rather than a quiet pass
	 */
	disc_count++;
	disc_reason = reason;
	disc_desc_len = strlen(desc);
	lws_strncpy(disc_desc_head, desc, sizeof(disc_desc_head));
	lws_strncpy(disc_lang, desc_lang, sizeof(disc_lang));
}

/* in-memory store for the generated server host key */

static uint8_t ops_hostkey[256];
static size_t ops_hostkey_len;

static size_t
ops_get_server_key(struct lws *wsi, uint8_t *buf, size_t len)
{
	if (len < ops_hostkey_len)
		return 0;

	memcpy(buf, ops_hostkey, ops_hostkey_len);

	return ops_hostkey_len;
}

static size_t
ops_set_server_key(struct lws *wsi, uint8_t *buf, size_t len)
{
	if (len > sizeof(ops_hostkey))
		return 0;

	memcpy(ops_hostkey, buf, len);
	ops_hostkey_len = len;

	return len;
}

static const struct lws_ssh_ops ops = {
	.tx_waiting			= ops_tx_waiting,
	.get_server_key			= ops_get_server_key,
	.set_server_key			= ops_set_server_key,
	.exec				= ops_exec,
	.is_pubkey_authorized		= ops_is_pubkey_authorized,
	.disconnect_reason		= ops_disconnect_reason,
	.server_string			= "SSH-2.0-LibwebsocketsAPITest",
	.api_version			= LWS_SSH_OPS_VERSION,
};

static const struct lws_protocols protocols_sshd[] = {
	LWS_PLUGIN_PROTOCOL_LWS_RAW_SSHD,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocol_vhost_options pvo_ops = {
	NULL,
	NULL,
	"ops",
	(void *)&ops
}, pvo_sshd = {
	NULL,
	&pvo_ops,
	"lws-ssh-base",
	""
};

/* ssh wire format helpers for the client side */

static void
pay_u8(uint8_t b)
{
	pay[paylen++] = b;
}

static void
pay_u32(uint32_t v)
{
	pay[paylen++] = (uint8_t)(v >> 24);
	pay[paylen++] = (uint8_t)(v >> 16);
	pay[paylen++] = (uint8_t)(v >> 8);
	pay[paylen++] = (uint8_t)v;
}

static void
pay_str(const void *p, uint32_t len)
{
	pay_u32(len);
	memcpy(pay + paylen, p, len);
	paylen += len;
}

static void
pay_cstr(const char *s)
{
	pay_str(s, (uint32_t)strlen(s));
}

static uint32_t
peek_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
poke_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/*
 * Wrap the assembled payload in pay[] into an SSH binary packet appended
 * to any unsent tx in txbuf, ready to write
 */
static int
pac_done(void)
{
	uint8_t *o = txbuf + LWS_PRE + txlen;
	uint32_t pad, msg_len;

	if (paylen + 64 > sizeof(txbuf) - LWS_PRE - txlen)
		return 1;

	msg_len = 1 + paylen;		/* padding length byte + payload */

	pad = 8 - ((4 + msg_len) & 7);	/* whole packet stays 8-aligned */
	if (pad < 4)			/* RFC4253 wants >= 4 */
		pad += 8;
	msg_len += pad;

	poke_u32(o, msg_len);
	o[4] = (uint8_t)pad;
	memcpy(o + 5, pay, paylen);
	memset(o + 5 + paylen, 0, pad);
	txlen += 4 + msg_len;

	return 0;
}

static int
cli_send_next(void)
{
	if (!cli_wsi)
		return 1;
	lws_callback_on_writable(cli_wsi);

	return 0;
}

static int
msg_service_request(const char *service)
{
	paylen = 0;
	pay_u8(SSH_MSG_SERVICE_REQUEST);
	pay_cstr(service);

	return pac_done();
}

/* a KEXINIT offering exactly what the sshd plugin supports */

static int
msg_kexinit(void)
{
	paylen = 0;
	pay_u8(SSH_MSG_KEXINIT);
	memset(pay + paylen, 0x5a, 16);		/* cookie */
	paylen += 16;
	pay_cstr("curve25519-sha256@libssh.org");
	pay_cstr("ssh-ed25519");
	pay_cstr("chacha20-poly1305@openssh.com");
	pay_cstr("chacha20-poly1305@openssh.com");
	pay_cstr("hmac-sha2-256");
	pay_cstr("hmac-sha2-256");
	pay_cstr("none");
	pay_cstr("none");
	pay_cstr("");				/* languages cts */
	pay_cstr("");				/* languages stc */
	pay_u8(0);				/* first_kex_packet_follows */
	pay_u32(0);				/* reserved */

	return pac_done();
}

static int
msg_disconnect(uint32_t reason, uint32_t desc_len, const char *lang)
{
	paylen = 0;
	pay_u8(SSH_MSG_DISCONNECT);
	pay_u32(reason);
	pay_u32(desc_len);
	memset(pay + paylen, 'D', desc_len);
	paylen += desc_len;
	pay_cstr(lang);

	return pac_done();
}

static int
msg_userauth(const uint8_t *pub, uint32_t pub_len,
	     const uint8_t *sig, uint32_t sig_len)
{
	paylen = 0;
	pay_u8(SSH_MSG_USERAUTH_REQUEST);
	pay_cstr("jtest");		/* username */
	pay_cstr("ssh-connection");	/* service */
	pay_cstr("publickey");		/* method */
	pay_u8(1);			/* TRUE: signature follows */
	pay_cstr("rsa-sha2-256");	/* public key alg */
	pay_str(pub, pub_len);		/* public key blob */
	pay_str(sig, sig_len);		/* signature blob */

	return pac_done();
}

static int
msg_channel_open(void)
{
	paylen = 0;
	pay_u8(SSH_MSG_CHANNEL_OPEN);
	pay_cstr("session");
	pay_u32(0x5a5a1234);		/* our channel number */
	pay_u32(0x100000);		/* initial window */
	pay_u32(0x4000);		/* max packet */

	return pac_done();
}

static int
msg_channel_exec(const char *cmd, uint32_t cmd_len)
{
	paylen = 0;
	pay_u8(SSH_MSG_CHANNEL_REQUEST);
	pay_u32(server_ch);
	pay_cstr("exec");
	pay_u8(1);			/* want reply */
	pay_str(cmd, cmd_len);

	return pac_done();
}

static int
test_fail(const char *why)
{
	lwsl_err("%s: %s (scenario %d, state %d)\n", __func__, why,
		 scenario, cli_state);
	failed = 1;
	lws_default_loop_exit(context);
	lws_cancel_service(context);

	return 1;
}

/*
 * This is where the expectations for each phase of the script are
 * asserted, and the next message to send is prepared
 */
static int
handle_msg(uint8_t msg, const uint8_t *pl, uint32_t pl_len)
{
	switch (msg) {
	case SSH_MSG_KEXINIT:
		/* the server's unsolicited kex offer; we don't do kex */
		return 0;
	default:
		break;
	}

	switch (cli_state) {
	case ST_CLI_SVC_ACCEPT:
		if (msg != SSH_MSG_SERVICE_ACCEPT)
			return test_fail("expected SERVICE_ACCEPT");

		/*
		 * phase 1: ops that don't structurally validate the blob,
		 * pubkey blob with a huge inner length.  Post-fix the walk
		 * is bounded and this draws USERAUTH_FAILURE.
		 */
		ops_lax = 1;
		{
			uint8_t m[15];

			poke_u32(m, 7);
			memcpy(m + 4, "ssh-rsa", 7);
			poke_u32(m + 11, 0x7fffff00);
			if (msg_userauth(m, sizeof(m), dummysig,
					 (uint32_t)sizeof(dummysig)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UAF_PUB_HUGE;
		return cli_send_next();

	case ST_CLI_UAF_PUB_HUGE:
		if (msg != SSH_MSG_USERAUTH_FAILURE)
			return test_fail("expected USERAUTH_FAILURE (pub huge)");

		/* phase 2: pubkey blob with mpint n length one too big */
		{
			uint8_t m[768];

			memcpy(m, keyblob, keyblob_len);
			poke_u32(m + keyblob_n_len_off, keyblob_n_len + 1);
			if (msg_userauth(m, keyblob_len, dummysig,
					 (uint32_t)sizeof(dummysig)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UAF_PUB_OFF1;
		return cli_send_next();

	case ST_CLI_UAF_PUB_OFF1:
		if (msg != SSH_MSG_USERAUTH_FAILURE)
			return test_fail("expected USERAUTH_FAILURE (pub off1)");

		/*
		 * phase 3: the F-056 attack itself.  The genuine authorized
		 * pubkey blob passes is_pubkey_authorized, the sig blob
		 * inner algo name length is huge so the unbounded walk
		 * steps past the sig allocation
		 */
		ops_lax = 0;
		{
			uint8_t m[4 + 12];

			poke_u32(m, 0x7fffff00);
			memcpy(m + 4, "junkjunkjunk", 12);
			if (msg_userauth(keyblob, keyblob_len, m, sizeof(m)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UAF_SIG_HUGE;
		return cli_send_next();

	case ST_CLI_UAF_SIG_HUGE:
		if (msg != SSH_MSG_USERAUTH_FAILURE)
			return test_fail("expected USERAUTH_FAILURE (sig huge)");

		/* phase 4: sig length one byte past the end of the sig blob */
		{
			uint8_t m[4 + 12 + 4 + 512];
			uint8_t *o = m;

			poke_u32(o, 12);
			o += 4;
			memcpy(o, "rsa-sha2-256", 12);
			o += 12;
			poke_u32(o, rsasig_len + 1);
			o += 4;
			memcpy(o, rsasig, rsasig_len);
			if (msg_userauth(keyblob, keyblob_len, m,
					 (uint32_t)(4 + 12 + 4 + rsasig_len)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UAF_SIG_OFF1;
		return cli_send_next();

	case ST_CLI_UAF_SIG_OFF1:
		if (msg != SSH_MSG_USERAUTH_FAILURE)
			return test_fail("expected USERAUTH_FAILURE (sig off1)");

		/* phase 5: trailing junk, so the blob is not consumed exactly */
		{
			uint8_t m[4 + 12 + 4 + 512 + 1];
			uint8_t *o = m;

			poke_u32(o, 12);
			o += 4;
			memcpy(o, "rsa-sha2-256", 12);
			o += 12;
			poke_u32(o, rsasig_len);
			o += 4;
			memcpy(o, rsasig, rsasig_len);
			o += rsasig_len;
			*o = 0x5a;
			if (msg_userauth(keyblob, keyblob_len, m,
					 (uint32_t)(4 + 12 + 4 + rsasig_len + 1)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UAF_SIG_JUNK;
		return cli_send_next();

	case ST_CLI_UAF_SIG_JUNK:
		if (msg != SSH_MSG_USERAUTH_FAILURE)
			return test_fail("expected USERAUTH_FAILURE (sig junk)");

		/*
		 * phase 6: genuine blob and genuine signature.  The server
		 * reconstructs and hashes the plaintext with the (still
		 * all-zero) session_id and verifies against the pubkey we
		 * generated.  This must still authenticate.
		 */
		{
			uint8_t m[4 + 12 + 4 + 512];
			uint8_t *o = m;

			poke_u32(o, 12);
			o += 4;
			memcpy(o, "rsa-sha2-256", 12);
			o += 12;
			poke_u32(o, rsasig_len);
			o += 4;
			memcpy(o, rsasig, rsasig_len);
			if (msg_userauth(keyblob, keyblob_len, m,
					 (uint32_t)(4 + 12 + 4 + rsasig_len)))
				return test_fail("tx prep");
		}
		cli_state = ST_CLI_UA_SUCCESS;
		return cli_send_next();

	case ST_CLI_UA_SUCCESS:
		if (msg != SSH_MSG_USERAUTH_SUCCESS)
			return test_fail("expected USERAUTH_SUCCESS");

		if (msg_channel_open())
			return test_fail("tx prep");
		cli_state = ST_CLI_CH_CONFIRM;
		return cli_send_next();

	case ST_CLI_CH_CONFIRM:
		if (msg != SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
			return test_fail("expected CHANNEL_OPEN_CONFIRMATION");

		if (pl_len < 8 || peek_u32(pl) != 0x5a5a1234)
			return test_fail("bad CHANNEL_OPEN_CONFIRMATION");
		server_ch = peek_u32(pl + 4);

		/*
		 * phase 7: a 1-byte exec command.  ops.exec refuses it, and
		 * looking for the "scp " prefix must not read past the
		 * 1-byte command allocation.
		 */
		if (msg_channel_exec("x", 1))
			return test_fail("tx prep");
		cli_state = ST_CLI_CH_FAIL;
		return cli_send_next();

	case ST_CLI_CH_FAIL:
		if (msg != SSH_MSG_CHANNEL_FAILURE)
			return test_fail("expected CHANNEL_FAILURE");

		/* all phases of this scenario completed, close and move on */

		cli_state = ST_CLI_DONE;
		return 1;

	case ST_CLI_KEXR_SVC_ACCEPT:
		/*
		 * The connection survived our first KEXINIT.  A second one
		 * while that key exchange is in progress is a protocol
		 * error the server must close us for.
		 */
		if (msg != SSH_MSG_SERVICE_ACCEPT)
			return test_fail("expected SERVICE_ACCEPT (kexinit)");

		if (msg_kexinit())
			return test_fail("tx prep");
		cli_state = ST_CLI_EXPECT_CLOSE;
		return cli_send_next();

	case ST_CLI_EMPTY_SVC_ACCEPT:
		/* the empty service name completed as a string */
		if (msg != SSH_MSG_SERVICE_ACCEPT || pl_len != 1 + 4 ||
		    peek_u32(pl))
			return test_fail("expected SERVICE_ACCEPT for \"\"");

		if (msg_disconnect(SSH_DISCONNECT_BY_APPLICATION, 0, ""))
			return test_fail("tx prep");
		cli_state = ST_CLI_EXPECT_CLOSE;
		return cli_send_next();

	default:
		return test_fail("unexpected message");
	}
}

/* the state the server's reply moves us to once its id string arrived */

static const enum cli_state scenario_first_state[] = {
	[SC_USERAUTH]		= ST_CLI_SVC_ACCEPT,
	[SC_KEXINIT_REPEAT]	= ST_CLI_KEXR_SVC_ACCEPT,
	[SC_DISCONNECT_LONG]	= ST_CLI_EXPECT_CLOSE,
	[SC_DISCONNECT_EMPTY]	= ST_CLI_EMPTY_SVC_ACCEPT,
};

static int
cli_rx(const void *in, size_t len)
{
	const uint8_t *p = (const uint8_t *)in;
	uint32_t plen, pad, n, remain;

	while (len--) {
		if (rxlen >= sizeof(rxbuf))
			return test_fail("rx overflow");
		rxbuf[rxlen++] = *p++;
	}

	for (;;) {
		if (cli_state == ST_CLI_VERSION) {
			for (n = 0; n < rxlen; n++)
				if (rxbuf[n] == '\n')
					break;
			if (n == rxlen) {
				/* id string fragment only, discard it */
				rxlen = 0;
				return 0;
			}
			/* n -> length of the id string including the '\n' */
			if (++n == sizeof(rxbuf)) {
				/* the '\n' was the last buffered byte */
				rxlen = 0;
			} else {
				/* keep anything already buffered after it */
				rxlen -= n;
				if (rxlen)
					memmove(rxbuf, rxbuf + n, rxlen);
			}
			cli_state = scenario_first_state[scenario];
			continue;
		}

		if (rxlen < 5)
			return 0;

		plen = peek_u32(rxbuf);
		pad = rxbuf[4];

		if (plen < 6 || plen >= sizeof(rxbuf) - 4)
			return test_fail("bad rx packet length");
		if (pad + 2 > plen)	/* payload must have >= 1 byte */
			return test_fail("bad rx padding");
		if (rxlen < 4 + plen)
			return 0;	/* wait for the rest of it */

		/*
		 * Snapshot the post-packet rxbuf length now, from the
		 * validated plen and rxlen, so it stays provably in range
		 * across the handle_msg() call below
		 */
		remain = rxlen - 4 - plen;

		if (handle_msg(rxbuf[5], rxbuf + 6, plen - 1 - pad))
			return 1;

		/* keep any further whole packets already buffered */
		memmove(rxbuf, rxbuf + 4 + plen, remain);
		rxlen = remain;
	}
}

/* what each scenario sends straight after our id string */
static int
cli_connected(void)
{
	memcpy(txbuf + LWS_PRE, "SSH-2.0-lwsApiTest\r\n", 20);
	txlen = 20;

	switch (scenario) {
	case SC_USERAUTH:
		/* a service request for the service we want to auth into */
		return msg_service_request("ssh-connection");

	case SC_KEXINIT_REPEAT:
		/* start a kex, and show the connection is still up after */
		return msg_kexinit() ||
		       msg_service_request("ssh-connection");

	case SC_DISCONNECT_LONG:
		/* the server must not act on the packet after DISCONNECT */
		return msg_disconnect(SSH_DISCONNECT_BY_APPLICATION,
				      DISC_DESC_LONG, "en") ||
		       msg_service_request("ssh-connection");

	case SC_DISCONNECT_EMPTY:
		return msg_service_request("");

	default:
		return 1;
	}
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("test timed out in scenario %d state %d\n", scenario,
		 cli_state);
	test_fail("timeout");
}

static void
cli_connect(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	cli_state = ST_CLI_VERSION;
	rxlen = 0;
	txlen = 0;
	disc_count = 0;
	disc_desc_len = 0;
	disc_desc_head[0] = '\0';
	disc_lang[0] = '\0';

	lwsl_user("%s: scenario %d\n", __func__, scenario);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = "127.0.0.1";
	i.port = port_tcp;
	i.host = i.address;
	i.origin = i.address;
	i.method = "RAW";
	i.local_protocol_name = "sshd-userauth-cli";

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 15 * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i))
		test_fail("client connect failed");
}

/* our connection closed: was that the expected end of the scenario? */

static void
cli_closed(void)
{
	switch (cli_state) {
	case ST_CLI_DONE:
		/* we closed it after the scenario's last expectation held */
		break;

	case ST_CLI_EXPECT_CLOSE:
		switch (scenario) {
		case SC_KEXINIT_REPEAT:
			if (disc_count) {
				test_fail("unexpected disconnect_reason");
				return;
			}
			break;
		case SC_DISCONNECT_LONG:
			if (disc_count != 1 ||
			    disc_reason != SSH_DISCONNECT_BY_APPLICATION ||
			    disc_desc_len != DISC_DESC_LONG ||
			    strcmp(disc_desc_head, "DDDDDDDDDDDDDDD") ||
			    strcmp(disc_lang, "en")) {
				lwsl_err("disconnect_reason x%d: %u, %u, '%s'\n",
					 disc_count, (unsigned int)disc_reason,
					 (unsigned int)disc_desc_len,
					 disc_lang);
				test_fail("bad disconnect_reason (long)");
				return;
			}
			break;
		case SC_DISCONNECT_EMPTY:
			if (disc_count != 1 || disc_desc_len || disc_lang[0]) {
				test_fail("bad disconnect_reason (empty)");
				return;
			}
			break;
		default:
			test_fail("unexpected close");
			return;
		}
		break;

	default:
		test_fail("server closed us early");
		return;
	}

	lwsl_user("%s: scenario %d passed\n", __func__, scenario);

	if (++scenario == SC_COUNT) {
		lws_sul_cancel(&sul_timeout);
		result = 0;
		lws_default_loop_exit(context);
		lws_cancel_service(context);
		lwsl_user("Completed: ALL OK\n");
		return;
	}

	/* the next scenario on a fresh connection, outside this callback */
	lws_sul_schedule(context, 0, &sul_next, cli_connect, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		cli_wsi = wsi;
		if (cli_connected())
			return -1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (cli_rx(in, len))
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!txlen)
			break;
		if (lws_write(wsi, txbuf + LWS_PRE, txlen,
			      LWS_WRITE_RAW) != (int)txlen) {
			lwsl_err("%s: raw write failed\n", __func__);
			return -1;
		}
		txlen = 0;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		cli_wsi = NULL;
		if (!failed)
			cli_closed();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		test_fail("client connection error");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "sshd-userauth-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Generate the authorized keypair at runtime, and produce the signature
 * of the USERAUTH plaintext the server will reconstruct and verify
 */
static int
gen_keypair(void)
{
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	struct lws_genrsa_ctx ctx;
	uint8_t pt[768 + 128], hash[32], *o;
	/* pt is built piece by piece; the session_id stretch is all-zeroes
	 * pre-KEX, everything else is written over zeroed space anyway */

	struct lws_genhash_ctx gh;
	size_t pt_len;
	uint32_t elen;
	int n;

	memset(el, 0, sizeof(el));
	memset(&ctx, 0, sizeof(ctx));
	/* the session_id stretch of pt stays zeroes, pre-KEX */
	memset(pt, 0, sizeof(pt));

	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_1_5, el, 2048)) {
		lwsl_err("keygen failed\n");
		return 1;
	}

	/* public key blob: string "ssh-rsa" + mpint e + mpint n */

	o = keyblob;
	poke_u32(o, 7);
	o += 4;
	memcpy(o, "ssh-rsa", 7);
	o += 7;
	elen = el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	poke_u32(o, elen);
	o += 4;
	memcpy(o, el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, elen);
	o += elen;
	keyblob_n_len_off = (uint32_t)(o - keyblob);
	keyblob_n_len = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	poke_u32(o, keyblob_n_len);
	o += 4;
	memcpy(o, el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, keyblob_n_len);
	o += keyblob_n_len;
	keyblob_len = (uint32_t)(o - keyblob);

	/* the USERAUTH plaintext the server reconstructs for verifying */

	o = pt;
	poke_u32(o, 32);			/* session_id, all zeroes pre-kex */
	o += 4;
	o += 32;
	*o++ = SSH_MSG_USERAUTH_REQUEST;
	poke_u32(o, 5);  o += 4; memcpy(o, "jtest", 5);           o += 5;
	poke_u32(o, 14); o += 4; memcpy(o, "ssh-connection", 14); o += 14;
	poke_u32(o, 9);  o += 4; memcpy(o, "publickey", 9);       o += 9;
	*o++ = 1;				/* sig_present = TRUE */
	poke_u32(o, 12); o += 4; memcpy(o, "rsa-sha2-256", 12);   o += 12;
	poke_u32(o, keyblob_len);
	o += 4;
	memcpy(o, keyblob, keyblob_len);
	o += keyblob_len;
	pt_len = (size_t)(o - pt);

	if (lws_genhash_init(&gh, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&gh, pt, pt_len) ||
	    lws_genhash_destroy(&gh, hash)) {
		lwsl_err("hash failed\n");
		goto bail;
	}

	n = lws_genrsa_hash_sign(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
				 rsasig, sizeof(rsasig));
	if (n < 0) {
		lwsl_err("sign failed\n");
		goto bail;
	}
	rsasig_len = (uint32_t)n;

bail:
	lws_genrsa_destroy_elements(el);
	lws_genrsa_destroy(&ctx);

	/*
	 * a well-formed-but-wrong sig blob for the phases that don't reach
	 * the sig walk
	 */
	o = dummysig;
	poke_u32(o, 12);
	o += 4;
	memcpy(o, "rsa-sha2-256", 12);
	o += 12;
	poke_u32(o, 16);
	o += 4;
	memset(o, 0xa5, 16);

	return keyblob_len && rsasig_len ? 0 : 1;
}

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p"))) {
		int __pt = atoi(p);
		if (__pt < 0 || __pt > 65535) {
			lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
			return 1;
		}
		port_tcp = (uint16_t)__pt;
	}

	lwsl_user("LWS API selftest: sshd userauth and transport parser\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (gen_keypair()) {
		lwsl_err("keypair setup failed\n");
		goto bail;
	}

	/* the sshd vhost: raw plaintext ssh (no kex is done by this test) */

	info.port = port_tcp;
	info.options = LWS_SERVER_OPTION_ONLY_RAW;
	info.vhost_name = "sshd";
	info.protocols = protocols_sshd;
	info.pvo = &pvo_sshd;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create sshd vhost\n");
		goto bail;
	}

	/* the client vhost */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = 0;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.pvo = NULL;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	cli_connect(&sul_next);
	if (failed)
		goto bail;

	while (n >= 0 && !failed)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
