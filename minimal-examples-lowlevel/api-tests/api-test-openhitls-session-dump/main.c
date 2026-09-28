/*
 * lws-api-test-openhitls-session-dump
 *
 * Focused tests for openHiTLS session dump/load cold-storage blobs, using
 * only the public session dump apis on a real context and vhost.
 *
 * The vhost's session cache can only be populated from outside the library
 * by a handshake or by lws_tls_session_dump_load(), so the tests start from
 * a blob the test encodes itself from a known session, load it, and check
 * what lws_tls_session_dump_save() gives back.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_TLS_SESSIONS)

#include <string.h>
#include <stdlib.h>

#include <hitls_config.h>
#include <hitls_error.h>
#include <hitls_session.h>

#define TEST_HOST	"example.com"
#define TEST_PORT	443

struct blob_store {
	uint8_t *blob;
	size_t len;
	int loads;
};

/* not const: openHiTLS' session id setters take non-const buffers */
static uint8_t expected_master_key[] = { 0x01, 0x03, 0x05, 0x07,
					 0x09, 0x0b, 0x0d, 0x0f },
	       expected_session_id[] = { 0x11, 0x22, 0x33, 0x44 },
	       expected_session_id_ctx[] = { 0x55, 0x66, 0x77, 0x88 };

static struct lws_context *
create_context(struct lws_vhost **pvh)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;

	lws_context_info_defaults(&info, NULL);
	info.vhost_name = "default";

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return NULL;
	}

	*pvh = lws_create_vhost(cx, &info);
	if (!*pvh) {
		lwsl_err("%s: vhost creation failed\n", __func__);
		lws_context_destroy(cx);
		return NULL;
	}

	return cx;
}

static int
init_session(HITLS_Session *session)
{
	return HITLS_SESS_SetProtocolVersion(session, HITLS_VERSION_TLS12) ||
	       HITLS_SESS_SetCipherSuite(session,
					 HITLS_RSA_WITH_AES_128_GCM_SHA256) ||
	       HITLS_SESS_SetMasterKey(session, expected_master_key,
				       sizeof(expected_master_key)) ||
	       HITLS_SESS_SetSessionId(session, expected_session_id,
				       sizeof(expected_session_id)) ||
	       HITLS_SESS_SetSessionIdCtx(session, expected_session_id_ctx,
					  sizeof(expected_session_id_ctx)) ||
	       HITLS_SESS_SetHaveExtMasterSecret(session, 1) ||
	       HITLS_SESS_SetTimeout(session, 12345);
}

static int
check_session(const HITLS_Session *session)
{
	uint8_t master_key[8], session_id[4], session_id_ctx[4];
	uint32_t master_key_len = sizeof(master_key);
	uint32_t session_id_len = sizeof(session_id);
	uint32_t session_id_ctx_len = sizeof(session_id_ctx);
	uint16_t version = 0, cipher_suite = 0;
	bool have_ext_master_secret = false;

	if (HITLS_SESS_GetProtocolVersion(session, &version) ||
	    version != HITLS_VERSION_TLS12 ||
	    HITLS_SESS_GetCipherSuite(session, &cipher_suite) ||
	    cipher_suite != HITLS_RSA_WITH_AES_128_GCM_SHA256 ||
	    HITLS_SESS_GetMasterKey(session, master_key, &master_key_len) ||
	    master_key_len != sizeof(expected_master_key) ||
	    memcmp(master_key, expected_master_key, sizeof(master_key)) ||
	    HITLS_SESS_GetSessionId(session, session_id, &session_id_len) ||
	    session_id_len != sizeof(expected_session_id) ||
	    memcmp(session_id, expected_session_id, sizeof(session_id)) ||
	    HITLS_SESS_GetSessionIdCtx(session, session_id_ctx,
				       &session_id_ctx_len) ||
	    session_id_ctx_len != sizeof(expected_session_id_ctx) ||
	    memcmp(session_id_ctx, expected_session_id_ctx,
		   sizeof(session_id_ctx)) ||
	    HITLS_SESS_GetHaveExtMasterSecret((HITLS_Session *)session,
					      &have_ext_master_secret) ||
	    !have_ext_master_secret ||
	    HITLS_SESS_GetTimeout((HITLS_Session *)session) != 12345)
		return 1;

	return 0;
}

/*
 * The cold-storage blob is openHiTLS' own session encoding, so the test can
 * make the first one itself from a session with known contents
 */

static int
encode_known_session(struct blob_store *store)
{
	HITLS_Session *session = HITLS_SESS_New();
	uint32_t len = 0, used = 0;
	int ret = 1;

	if (!session || init_session(session) ||
	    HITLS_SESS_Encode(session, NULL, 0, &len) != HITLS_SUCCESS || !len)
		goto bail;

	store->blob = malloc(len);
	if (!store->blob)
		goto bail;

	if (HITLS_SESS_Encode(session, store->blob, len, &used) !=
							HITLS_SUCCESS ||
	    !used || used > len)
		goto bail;

	store->len = used;
	ret = 0;

bail:
	HITLS_SESS_Free(session);

	return ret;
}

static int
save_cb(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	struct blob_store *store = (struct blob_store *)info->opaque;

	(void)cx;

	free(store->blob);
	store->len = 0;
	store->blob = malloc(info->blob_len);
	if (!store->blob)
		return 1;

	memcpy(store->blob, info->blob, info->blob_len);
	store->len = info->blob_len;

	return 0;
}

static int
load_cb(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	struct blob_store *store = (struct blob_store *)info->opaque;

	(void)cx;

	store->loads++;
	if (!store->blob || !store->len)
		return 1;

	/* lws frees the loaded blob with free() */
	info->blob = malloc(store->len);
	if (!info->blob)
		return 1;

	memcpy(info->blob, store->blob, store->len);
	info->blob_len = store->len;

	return 0;
}

static int
decode_and_check(const struct blob_store *store)
{
	HITLS_Session *session = NULL;
	int ret = 1;

	if (store->blob && store->len &&
	    store->len <= UINT32_MAX &&
	    HITLS_SESS_Decode(&session, store->blob, (uint32_t)store->len) ==
								HITLS_SUCCESS)
		ret = check_session(session);

	if (session)
		HITLS_SESS_Free(session);

	return ret;
}

/*
 * A known session goes into cold storage and comes back out of it, in one
 * context and then in a fresh one, as it would across a restart
 */

static int
test_dump_roundtrip(void)
{
	struct blob_store known = { 0 }, saved = { 0 }, resaved = { 0 };
	struct lws_context *cx;
	struct lws_vhost *vh;
	int ret = 1;

	if (encode_known_session(&known)) {
		lwsl_err("%s: unable to encode test session\n", __func__);
		goto bail;
	}

	cx = create_context(&vh);
	if (!cx)
		goto bail;

	if (lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				      &known) ||
	    lws_tls_session_dump_save(vh, TEST_HOST, TEST_PORT, save_cb,
				      &saved) ||
	    decode_and_check(&saved)) {
		lwsl_err("%s: first context roundtrip failed\n", __func__);
		lws_context_destroy(cx);
		goto bail;
	}

	lws_context_destroy(cx);

	cx = create_context(&vh);
	if (!cx)
		goto bail;

	if (lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				      &saved) ||
	    lws_tls_session_dump_save(vh, TEST_HOST, TEST_PORT, save_cb,
				      &resaved) ||
	    decode_and_check(&resaved)) {
		lwsl_err("%s: second context roundtrip failed\n", __func__);
		lws_context_destroy(cx);
		goto bail;
	}

	lws_context_destroy(cx);
	ret = 0;

bail:
	free(known.blob);
	free(saved.blob);
	free(resaved.blob);

	return ret;
}

static int
test_failure_paths(void)
{
	struct blob_store empty = { 0 }, corrupt = { 0 }, known = { 0 },
			  saved = { 0 };
	static const uint8_t bad_blob[] = { 1, 2, 3, 4, 5 };
	struct lws_context *cx = NULL;
	struct lws_vhost *vh;
	int ret = 1;

	if (encode_known_session(&known)) {
		lwsl_err("%s: unable to encode test session\n", __func__);
		goto bail;
	}

	cx = create_context(&vh);
	if (!cx)
		goto bail;

	if (!lws_tls_session_dump_save(vh, TEST_HOST, TEST_PORT, save_cb,
				       &saved)) {
		lwsl_err("%s: save without cache entry succeeded\n", __func__);
		goto bail;
	}

	if (!lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				       &empty)) {
		lwsl_err("%s: empty blob load succeeded\n", __func__);
		goto bail;
	}

	corrupt.blob = malloc(sizeof(bad_blob));
	if (!corrupt.blob)
		goto bail;
	memcpy(corrupt.blob, bad_blob, sizeof(bad_blob));
	corrupt.len = sizeof(bad_blob);

	if (!lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				       &corrupt)) {
		lwsl_err("%s: corrupt blob load succeeded\n", __func__);
		goto bail;
	}

	/* ... and neither failed load may have left a cache entry behind */

	if (!lws_tls_session_dump_save(vh, TEST_HOST, TEST_PORT, save_cb,
				       &saved)) {
		lwsl_err("%s: failed load left a cache entry\n", __func__);
		goto bail;
	}

	if (lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				      &known)) {
		lwsl_err("%s: valid blob load failed\n", __func__);
		goto bail;
	}

	/*
	 * With a session cached for the tag, cold storage must not even be
	 * asked, since what is cached is likely newer
	 */

	corrupt.loads = 0;
	if (!lws_tls_session_dump_load(vh, TEST_HOST, TEST_PORT, load_cb,
				       &corrupt) || corrupt.loads) {
		lwsl_err("%s: existing session was overwritten\n", __func__);
		goto bail;
	}

	if (lws_tls_session_dump_save(vh, TEST_HOST, TEST_PORT, save_cb,
				      &saved) ||
	    decode_and_check(&saved)) {
		lwsl_err("%s: cached session was disturbed\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	lws_context_destroy(cx);
	free(corrupt.blob);
	free(known.blob);
	free(saved.blob);

	return ret;
}

int
main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: openHiTLS session dump\n");

	e |= test_dump_roundtrip();
	e |= test_failure_paths();

	if (e)
		lwsl_err("%s: failed\n", __func__);
	else
		lwsl_user("%s: pass\n", __func__);

	return e;
}

#else

int
main(void)
{
	return 0;
}

#endif
