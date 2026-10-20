/*
 * lws-api-test-sshd-userauth
 *
 * Fences the F-056 fixes in the sshd plugin's USERAUTH pubkey blob and
 * signature blob handling: both walks advance by attacker-chosen inner
 * lengths and must be bounded against, and exactly consume, the outer
 * blob they walk, or the RSA verify is fed data from wild pointers.  The
 * "scp " exec prefix check is also bounded by the exec command length.
 *
 * An sshd vhost and a raw client run in one process.  The client does a
 * real curve25519-sha256 key exchange using the plugin's own primitives,
 * verifies the server's signature over the exchange hash, and then drives
 * the USERAUTH states over chacha20-poly1305:
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
 *    keypair over the plaintext the server reconstructs, including the
 *    session id from the key exchange) must still
 *    authenticate and open a session channel, and a 1-byte "exec"
 *    command must be refused with CHANNEL_FAILURE without reading past
 *    the 1-byte command allocation looking for an "scp " prefix,
 *  - two more signed USERAUTH requests after the success are silently
 *    ignored, and must not leak their signature allocations (G-303; LSan
 *    reports them otherwise).
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
 * And the services run only on the transport the key exchange set up
 * (G-286): a SERVICE_REQUEST or a USERAUTH_REQUEST before the key exchange,
 * or a USERAUTH_REQUEST after it without the "ssh-userauth" service having
 * been requested, must close the connection without a reply (they used to
 * be served in plaintext, with an all-zero session id signed by userauth).
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
	SC_PREKEX_SERVICE,	/* SERVICE_REQUEST before the kex */
	SC_PREKEX_USERAUTH,	/* USERAUTH_REQUEST before the kex */
	SC_USERAUTH_WRONG_SVC,	/* USERAUTH_REQUEST, no ssh-userauth service */

	SC_COUNT
};

enum cli_state {
	ST_CLI_VERSION,		/* skipping the server's id string */
	ST_CLI_KEX_KEXINIT,	/* waiting for the server's KEXINIT */
	ST_CLI_KEX_REPLY,	/* waiting for KEX_ECDH_REPLY */
	ST_CLI_KEX_NEWKEYS,	/* waiting for the server's NEWKEYS */
	ST_CLI_SVC_ACCEPT,	/* waiting for SERVICE_ACCEPT */
	ST_CLI_UAF_PUB_HUGE,	/* lax ops, huge inner length in pubkey blob */
	ST_CLI_UAF_PUB_OFF1,	/* lax ops, pubkey mpint len off-by-one */
	ST_CLI_UAF_SIG_HUGE,	/* genuine pubkey, huge inner sig length */
	ST_CLI_UAF_SIG_OFF1,	/* genuine pubkey, sig length overruns blob */
	ST_CLI_UAF_SIG_JUNK,	/* genuine pubkey, trailing junk in sig blob */
	ST_CLI_UA_SUCCESS,	/* genuine sig, expecting success */
	ST_CLI_CH_CONFIRM,	/* expecting CHANNEL_OPEN_CONFIRMATION */
	ST_CLI_CH_FAIL,		/* expecting CHANNEL_FAILURE for exec "x" */
	ST_CLI_EMPTY_SVC_ACCEPT,/* SERVICE_ACCEPT for the empty service name */
	ST_CLI_WRONG_SVC_ACCEPT,/* SERVICE_ACCEPT for "ssh-connection" */
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

static uint8_t rxpt[RXBUF_LEN];	/* decrypted rx packet */

/* the client's side of the key exchange and transport */

#define CLI_ID_STRING		"SSH-2.0-lwsApiTest"

static struct lws_ssh_keys cli_keys_cts;	/* we encrypt with these */
static struct lws_ssh_keys cli_keys_stc;	/* we decrypt with these */
static uint32_t cli_seq_tx, cli_seq_rx;
static uint8_t cli_eph_pri[LWS_SIZE_EC25519];
static uint8_t cli_Q_C[LWS_SIZE_EC25519];
static uint8_t cli_I_C[256];		/* our KEXINIT payload */
static uint32_t cli_I_C_len;
static uint8_t cli_I_S[1024];		/* the server's KEXINIT payload */
static uint32_t cli_I_S_len;
static uint8_t session_id[LWS_SIZE_SHA256];

/* the runtime-generated authorized key material */

static struct lws_gencrypto_keyelem rsa_el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
static struct lws_genrsa_ctx rsa_ctx;
static char rsa_ctx_valid;

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
 * to any unsent tx in txbuf, ready to write.  Once our NEWKEYS is sent, it
 * is encrypted with chacha20-poly1305@openssh.com.
 */
static int
pac_done(void)
{
	uint8_t pkt[sizeof(pay) + 32], *o = txbuf + LWS_PRE + txlen;
	uint32_t pad, msg_len, aligned;

	msg_len = 1 + paylen;		/* padding length byte + payload */

	/*
	 * RFC4253 6 wants the packet a multiple of 8, and >= 4 bytes of
	 * padding; with chacha20-poly1305 the encrypted length field is not
	 * counted
	 */
	aligned = cli_keys_cts.valid ? msg_len : 4 + msg_len;
	pad = 8 - (aligned & 7);
	if (pad < 4)
		pad += 8;
	msg_len += pad;

	if (4 + msg_len + POLY1305_TAGLEN > sizeof(pkt) ||
	    4 + msg_len + POLY1305_TAGLEN > sizeof(txbuf) - LWS_PRE - txlen)
		return 1;

	poke_u32(pkt, msg_len);
	pkt[4] = (uint8_t)pad;
	memcpy(pkt + 5, pay, paylen);
	memset(pkt + 5 + paylen, 0, pad);

	if (cli_keys_cts.valid) {
		if (lws_chacha_encrypt(&cli_keys_cts, cli_seq_tx, pkt,
				       4 + msg_len, o))
			return 1;
		txlen += 4 + msg_len + cli_keys_cts.MAC_length;
	} else {
		memcpy(o, pkt, 4 + msg_len);
		txlen += 4 + msg_len;
	}

	cli_seq_tx++;

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

	/* I_C, for the exchange hash */
	memcpy(cli_I_C, pay, paylen);
	cli_I_C_len = paylen;

	return pac_done();
}

/* our ephemeral curve25519 key, and the KEX_ECDH_INIT carrying it */

static int
msg_ecdh_init(void)
{
	lws_get_random(context, cli_eph_pri, sizeof(cli_eph_pri));
	cli_eph_pri[0] &= 248;
	cli_eph_pri[31] &= 127;
	cli_eph_pri[31] |= 64;
	crypto_scalarmult_curve25519(cli_Q_C, cli_eph_pri, basepoint);

	paylen = 0;
	pay_u8(SSH_MSG_KEX_ECDH_INIT);
	pay_str(cli_Q_C, sizeof(cli_Q_C));

	return pac_done();
}

static int
msg_newkeys(void)
{
	paylen = 0;
	pay_u8(SSH_MSG_NEWKEYS);

	return pac_done();
}

static int
msg_ignore(void)
{
	paylen = 0;
	pay_u8(SSH_MSG_IGNORE);
	pay_cstr("ignore me");

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

/* the authorized key, with a genuine signature of this session's request */

static int
msg_userauth_genuine(void)
{
	uint8_t m[4 + 12 + 4 + sizeof(rsasig)], *o = m;

	poke_u32(o, 12);
	o += 4;
	memcpy(o, "rsa-sha2-256", 12);
	o += 12;
	poke_u32(o, rsasig_len);
	o += 4;
	memcpy(o, rsasig, rsasig_len);

	return msg_userauth(keyblob, keyblob_len, m,
			    (uint32_t)(4 + 12 + 4 + rsasig_len));
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

/* take one bounded RFC4251 string out of a received payload */

static int
get_str(const uint8_t **p, const uint8_t *end, const uint8_t **s,
	uint32_t *len)
{
	if (end - *p < 4)
		return 1;

	*len = peek_u32(*p);
	*p += 4;
	if (*len > (uint32_t)(end - *p))
		return 1;

	*s = *p;
	*p += *len;

	return 0;
}

/*
 * The server's KEX_ECDH_REPLY: compute the shared secret and the exchange
 * hash H, check the server signed H with the host key it sent, and derive
 * the keys for both directions (RFC4253 7.2, RFC8731)
 */
static int
cli_kex_reply(const uint8_t *pl, uint32_t pl_len)
{
	const uint8_t *p = pl, *end = pl + pl_len, *ks, *qs, *sb, *q, *n,
		      *hostpub, *sig;
	uint8_t K[LWS_SIZE_EC25519], kbi[LWS_SIZE_EC25519 + 5],
		sm[64 + LWS_SIZE_SHA256], m[64 + LWS_SIZE_SHA256];
	uint32_t ks_len, qs_len, sb_len, l, hp_len, sig_len;
	struct lws_genhash_ctx gh;
	unsigned long long mlen;
	int c, ret = 1, kbi_len;
	uint8_t a = 0;

	if (get_str(&p, end, &ks, &ks_len) ||	/* K_S, host key blob */
	    get_str(&p, end, &qs, &qs_len) ||	/* Q_S */
	    get_str(&p, end, &sb, &sb_len) ||	/* signature of H */
	    p != end || qs_len != LWS_SIZE_EC25519)
		return 1;

	/* K_S: string "ssh-ed25519", string 32-byte public key */

	q = ks;
	if (get_str(&q, ks + ks_len, &n, &l) || l != 11 ||
	    memcmp(n, "ssh-ed25519", 11) ||
	    get_str(&q, ks + ks_len, &hostpub, &hp_len) ||
	    hp_len != LWS_SIZE_EC25519_PUBKEY || q != ks + ks_len)
		return 1;

	/* signature: string "ssh-ed25519", string 64-byte signature */

	q = sb;
	if (get_str(&q, sb + sb_len, &n, &l) || l != 11 ||
	    memcmp(n, "ssh-ed25519", 11) ||
	    get_str(&q, sb + sb_len, &sig, &sig_len) || sig_len != 64 ||
	    q != sb + sb_len)
		return 1;

	crypto_scalarmult_curve25519(K, cli_eph_pri, qs);
	lws_explicit_bzero(cli_eph_pri, sizeof(cli_eph_pri));
	for (c = 0; c < (int)sizeof(K); c++)
		a |= K[c];
	if (!a)
		goto bail;

	kbi_len = lws_mpint_rfc4251(kbi, K, LWS_SIZE_EC25519, 1);

	if (lws_genhash_init(&gh, LWS_GENHASH_TYPE_SHA256))
		goto bail;
	if (_genhash_update_len(&gh, CLI_ID_STRING, strlen(CLI_ID_STRING)) ||
	    _genhash_update_len(&gh, ops.server_string,
				strlen(ops.server_string)) ||
	    _genhash_update_len(&gh, cli_I_C, cli_I_C_len) ||
	    _genhash_update_len(&gh, cli_I_S, cli_I_S_len) ||
	    _genhash_update_len(&gh, ks, ks_len) ||
	    _genhash_update_len(&gh, cli_Q_C, sizeof(cli_Q_C)) ||
	    _genhash_update_len(&gh, qs, qs_len) ||
	    lws_genhash_update(&gh, kbi, (size_t)kbi_len)) {
		lws_genhash_destroy(&gh, NULL);
		goto bail;
	}
	if (lws_genhash_destroy(&gh, session_id))
		goto bail;

	/* the server must have signed H with the host key it sent us */

	memcpy(sm, sig, 64);
	memcpy(sm + 64, session_id, LWS_SIZE_SHA256);
	if (crypto_sign_ed25519_open(m, &mlen, sm, sizeof(sm), hostpub)) {
		lwsl_err("%s: bad host signature of H\n", __func__);
		goto bail;
	}

	/* H is also the session id, since this is the first exchange */

	for (c = 0; c < 3; c++)
		if (kex_ecdh_dv(cli_keys_cts.key[c], LWS_SIZE_CHACHA256_KEY,
				kbi, kbi_len, session_id, (char)('A' + (c * 2)),
				session_id) ||
		    kex_ecdh_dv(cli_keys_stc.key[c], LWS_SIZE_CHACHA256_KEY,
				kbi, kbi_len, session_id, (char)('B' + (c * 2)),
				session_id))
			goto bail;

	ret = 0;

bail:
	lws_explicit_bzero(K, sizeof(K));
	lws_explicit_bzero(kbi, sizeof(kbi));

	return ret;
}

/* drop the client's transport state, between scenarios and at exit */

static void
cli_transport_reset(void)
{
	lws_chacha_destroy(&cli_keys_cts);
	lws_chacha_destroy(&cli_keys_stc);
	lws_explicit_bzero(&cli_keys_cts, sizeof(cli_keys_cts));
	lws_explicit_bzero(&cli_keys_stc, sizeof(cli_keys_stc));
	lws_explicit_bzero(cli_eph_pri, sizeof(cli_eph_pri));
	cli_seq_tx = cli_seq_rx = 0;
	cli_I_C_len = cli_I_S_len = 0;
	memset(session_id, 0, sizeof(session_id));
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

static int sign_userauth(void);

/*
 * The key exchange is complete in both directions: send the scenario's
 * first message on the encrypted transport
 */
static int
cli_kex_done(void)
{
	switch (scenario) {
	case SC_USERAUTH:
		/* the signature covers the session id we now have */
		if (sign_userauth() ||
		    msg_service_request("ssh-userauth"))
			return test_fail("tx prep");
		cli_state = ST_CLI_SVC_ACCEPT;
		break;

	case SC_DISCONNECT_EMPTY:
		if (msg_service_request(""))
			return test_fail("tx prep");
		cli_state = ST_CLI_EMPTY_SVC_ACCEPT;
		break;

	case SC_USERAUTH_WRONG_SVC:
		/* a service that is not the one USERAUTH_REQUEST belongs to */
		if (msg_service_request("ssh-connection"))
			return test_fail("tx prep");
		cli_state = ST_CLI_WRONG_SVC_ACCEPT;
		break;

	default:
		return test_fail("no kex in this scenario");
	}

	return cli_send_next();
}

/*
 * This is where the expectations for each phase of the script are
 * asserted, and the next message to send is prepared
 */
static int
handle_msg(uint8_t msg, const uint8_t *pl, uint32_t pl_len)
{
	if (msg == SSH_MSG_KEXINIT) {
		/*
		 * The server's offer is unsolicited and comes on every
		 * connection; the scenarios with no key exchange ignore it
		 */
		if (cli_state != ST_CLI_KEX_KEXINIT)
			return 0;

		/* I_S, for the exchange hash: the payload from the msg id */
		if (pl_len + 1 > sizeof(cli_I_S))
			return test_fail("server KEXINIT too large");
		memcpy(cli_I_S, pl - 1, pl_len + 1);
		cli_I_S_len = pl_len + 1;

		if (msg_ecdh_init())
			return test_fail("tx prep");
		cli_state = ST_CLI_KEX_REPLY;
		return cli_send_next();
	}

	switch (cli_state) {
	case ST_CLI_KEX_REPLY:
		if (msg != SSH_MSG_KEX_ECDH_REPLY)
			return test_fail("expected KEX_ECDH_REPLY");
		if (cli_kex_reply(pl, pl_len))
			return test_fail("key exchange failed");

		/* our NEWKEYS goes in plaintext, then our keys are active */
		if (msg_newkeys() || lws_chacha_activate(&cli_keys_cts))
			return test_fail("tx prep");
		cli_state = ST_CLI_KEX_NEWKEYS;
		return cli_send_next();

	case ST_CLI_KEX_NEWKEYS:
		if (msg != SSH_MSG_NEWKEYS)
			return test_fail("expected NEWKEYS");

		/* everything the server sends after this is encrypted */
		if (lws_chacha_activate(&cli_keys_stc))
			return test_fail("activating rx keys");

		return cli_kex_done();

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
		 * reconstructs and hashes the plaintext with the session_id
		 * from the key exchange and verifies against the pubkey we
		 * generated.  This must still authenticate.
		 */
		if (msg_userauth_genuine())
			return test_fail("tx prep");
		cli_state = ST_CLI_UA_SUCCESS;
		return cli_send_next();

	case ST_CLI_UA_SUCCESS:
		if (msg != SSH_MSG_USERAUTH_SUCCESS)
			return test_fail("expected USERAUTH_SUCCESS");

		/*
		 * Signed requests after the success are silently ignored
		 * (RFC4252 5.1), and must not leak their signature: the
		 * next string the server allocates (the exec command
		 * below) used to orphan it
		 */
		if (msg_userauth_genuine() || msg_userauth_genuine() ||
		    msg_channel_open())
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

	case ST_CLI_EMPTY_SVC_ACCEPT:
		/* the empty service name completed as a string */
		if (msg != SSH_MSG_SERVICE_ACCEPT || pl_len != 4 ||
		    peek_u32(pl))
			return test_fail("expected SERVICE_ACCEPT for \"\"");

		if (msg_disconnect(SSH_DISCONNECT_BY_APPLICATION, 0, ""))
			return test_fail("tx prep");
		cli_state = ST_CLI_EXPECT_CLOSE;
		return cli_send_next();

	case ST_CLI_WRONG_SVC_ACCEPT:
		/*
		 * The service was accepted, but without "ssh-userauth" a
		 * USERAUTH_REQUEST must close us
		 */
		if (msg != SSH_MSG_SERVICE_ACCEPT)
			return test_fail("expected SERVICE_ACCEPT (wrong svc)");

		if (msg_userauth(keyblob, keyblob_len, dummysig,
				 (uint32_t)sizeof(dummysig)))
			return test_fail("tx prep");
		cli_state = ST_CLI_EXPECT_CLOSE;
		return cli_send_next();

	default:
		return test_fail("unexpected message");
	}
}

/* the state the server's reply moves us to once its id string arrived */

static const enum cli_state scenario_first_state[] = {
	[SC_USERAUTH]		= ST_CLI_KEX_KEXINIT,
	[SC_KEXINIT_REPEAT]	= ST_CLI_EXPECT_CLOSE,
	[SC_DISCONNECT_LONG]	= ST_CLI_EXPECT_CLOSE,
	[SC_DISCONNECT_EMPTY]	= ST_CLI_KEX_KEXINIT,
	[SC_PREKEX_SERVICE]	= ST_CLI_EXPECT_CLOSE,
	[SC_PREKEX_USERAUTH]	= ST_CLI_EXPECT_CLOSE,
	[SC_USERAUTH_WRONG_SVC]	= ST_CLI_KEX_KEXINIT,
};

/*
 * What each scenario sends once the server's id string arrived.  It is held
 * until then because the server may close on it: sent with our id string, it
 * may reach the server before it wrote its own id string, which is then never
 * sent, and the close would come in ST_CLI_VERSION, looking early.
 */
static int
cli_first_msgs(void)
{
	switch (scenario) {
	case SC_USERAUTH:
	case SC_DISCONNECT_EMPTY:
	case SC_USERAUTH_WRONG_SVC:
		/* these scenarios start once the key exchange completes */
		return msg_kexinit();

	case SC_KEXINIT_REPEAT:
		/*
		 * A second KEXINIT while the first one's exchange is in
		 * progress.  That one KEXINIT is accepted is shown by the
		 * scenarios that complete a key exchange.
		 */
		return msg_kexinit() || msg_kexinit();

	case SC_DISCONNECT_LONG:
		/* the server must not act on the packet after DISCONNECT */
		return msg_disconnect(SSH_DISCONNECT_BY_APPLICATION,
				      DISC_DESC_LONG, "en") ||
		       msg_ignore();

	case SC_PREKEX_SERVICE:
		/* the userauth service, before any key exchange */
		return msg_service_request("ssh-userauth");

	case SC_PREKEX_USERAUTH:
		/*
		 * a USERAUTH_REQUEST in plaintext before any key exchange,
		 * which used to be judged (and signed over an all-zero
		 * session id), even with no service requested
		 */
		return msg_userauth(keyblob, keyblob_len, dummysig,
				    (uint32_t)sizeof(dummysig));

	default:
		return 1;
	}
}

static int
cli_rx(const void *in, size_t len)
{
	const uint8_t *p = (const uint8_t *)in, *pkt;
	uint32_t plen, pad, n, remain, mac;

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
			if (cli_first_msgs())
				return test_fail("tx prep");
			if (cli_send_next())
				return 1;
			continue;
		}

		if (rxlen < 5)
			return 0;

		/* after the server's NEWKEYS, packets are encrypted */

		mac = 0;
		if (cli_keys_stc.valid) {
			plen = lws_chachapoly_get_length(&cli_keys_stc,
							 cli_seq_rx, rxbuf);
			mac = cli_keys_stc.MAC_length;
		} else
			plen = peek_u32(rxbuf);

		if (plen < 6 || plen >= sizeof(rxbuf) - 4 - mac)
			return test_fail("bad rx packet length");
		if (rxlen < 4 + plen + mac)
			return 0;	/* wait for the rest of it */

		pkt = rxbuf;
		if (cli_keys_stc.valid) {
			if (lws_chacha_decrypt(&cli_keys_stc, cli_seq_rx,
					       rxbuf, 4 + plen + mac, rxpt))
				return test_fail("rx decryption failed");
			pkt = rxpt;
		}
		cli_seq_rx++;

		pad = pkt[4];
		if (pad + 2 > plen)	/* payload must have >= 1 byte */
			return test_fail("bad rx padding");

		/*
		 * Snapshot the post-packet rxbuf length now, from the
		 * validated plen and rxlen, so it stays provably in range
		 * across the handle_msg() call below
		 */
		remain = rxlen - 4 - plen - mac;

		/* the payload after the msg id, without the padding */
		if (handle_msg(pkt[5], pkt + 6, plen - 2 - pad))
			return 1;

		/* keep any further whole packets already buffered */
		memmove(rxbuf, rxbuf + 4 + plen + mac, remain);
		rxlen = remain;
	}
}

/* we connected: our id string goes first */
static void
cli_connected(void)
{
	memcpy(txbuf + LWS_PRE, CLI_ID_STRING "\r\n",
	       sizeof(CLI_ID_STRING) + 1);
	txlen = sizeof(CLI_ID_STRING) + 1;
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
	cli_transport_reset();
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
		case SC_PREKEX_SERVICE:
		case SC_PREKEX_USERAUTH:
		case SC_USERAUTH_WRONG_SVC:
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
		cli_connected();
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
 * Generate the authorized keypair at runtime, and the public key blob for it
 */
static int
gen_keypair(void)
{
	uint32_t elen;
	uint8_t *o;

	memset(rsa_el, 0, sizeof(rsa_el));
	memset(&rsa_ctx, 0, sizeof(rsa_ctx));

	if (lws_genrsa_new_keypair(context, &rsa_ctx, LGRSAM_PKCS1_1_5,
				   rsa_el, 2048)) {
		lwsl_err("keygen failed\n");
		return 1;
	}
	rsa_ctx_valid = 1;

	/* public key blob: string "ssh-rsa" + mpint e + mpint n */

	elen = rsa_el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	keyblob_n_len = rsa_el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	if (4 + 7 + 4 + elen + 4 + keyblob_n_len > sizeof(keyblob))
		return 1;

	o = keyblob;
	poke_u32(o, 7);
	o += 4;
	memcpy(o, "ssh-rsa", 7);
	o += 7;
	poke_u32(o, elen);
	o += 4;
	memcpy(o, rsa_el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, elen);
	o += elen;
	keyblob_n_len_off = (uint32_t)(o - keyblob);
	poke_u32(o, keyblob_n_len);
	o += 4;
	memcpy(o, rsa_el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, keyblob_n_len);
	o += keyblob_n_len;
	keyblob_len = (uint32_t)(o - keyblob);

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

	return 0;
}

/*
 * Sign the USERAUTH plaintext the server will reconstruct and verify
 * (RFC4252 7), which starts with the session id from the key exchange
 */
static int
sign_userauth(void)
{
	uint8_t pt[768 + 128], hash[32], *o = pt;
	struct lws_genhash_ctx gh;
	int n;

	if (keyblob_len > sizeof(keyblob) ||
	    4 + LWS_SIZE_SHA256 + 1 + 4 + 5 + 4 + 14 + 4 + 9 + 1 + 4 + 12 +
	    4 + keyblob_len > sizeof(pt))
		return 1;

	poke_u32(o, LWS_SIZE_SHA256);
	o += 4;
	memcpy(o, session_id, LWS_SIZE_SHA256);
	o += LWS_SIZE_SHA256;
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

	if (lws_genhash_init(&gh, LWS_GENHASH_TYPE_SHA256))
		return 1;
	if (lws_genhash_update(&gh, pt, (size_t)(o - pt))) {
		lws_genhash_destroy(&gh, NULL);
		return 1;
	}
	if (lws_genhash_destroy(&gh, hash))
		return 1;

	n = lws_genrsa_hash_sign(&rsa_ctx, hash, LWS_GENHASH_TYPE_SHA256,
				 rsasig, sizeof(rsasig));
	if (n <= 0) {
		lwsl_err("sign failed\n");
		return 1;
	}
	rsasig_len = (uint32_t)n;

	return 0;
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

	/* the sshd vhost: raw ssh */

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
	cli_transport_reset();
	if (rsa_ctx_valid) {
		lws_genrsa_destroy_elements(rsa_el);
		lws_genrsa_destroy(&rsa_ctx);
	}
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
