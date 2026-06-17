/*
 * lws-api-test-openhitls-session-dump
 *
 * Focused tests for openHiTLS session dump/load cold-storage blobs.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_TLS_SESSIONS)

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

#include <crypt_eal_init.h>
#include <hitls_cert_init.h>
#include <hitls_crypt_init.h>
#include <hitls_session.h>

struct test_sco {
	lws_dll2_t list;
	HITLS_Session *session;
	lws_sorted_usec_list_t sul_ttl;
	/* tag is overallocated here */
};

struct blob_store {
	uint8_t *blob;
	size_t len;
	int loads;
};

static int
init_openhitls(void)
{
	int32_t ret;

	ret = BSL_ERR_Init();
	if (ret != BSL_SUCCESS)
		return 1;

	ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
	if (ret != CRYPT_SUCCESS)
		return 1;

	ret = HITLS_CertMethodInit();
	if (ret != HITLS_SUCCESS)
		return 1;
	HITLS_CryptMethodInit();

	return 0;
}

static void
cleanup_vhost_sessions(struct lws_vhost *vh)
{
	while (vh->tls_sessions.head) {
		struct test_sco *ts = lws_container_of(vh->tls_sessions.head,
						       struct test_sco, list);

		lws_dll2_remove(&ts->list);
		HITLS_SESS_Free(ts->session);
		free(ts);
	}
}

static void
init_vhost(struct lws_context *cx, struct lws_vhost *vh)
{
	memset(cx, 0, sizeof(*cx));
	memset(vh, 0, sizeof(*vh));
	vh->context = cx;
	vh->name = "default";
}

static int
init_session(HITLS_Session *session)
{
	uint8_t master_key[] = { 0x01, 0x03, 0x05, 0x07,
				 0x09, 0x0b, 0x0d, 0x0f };
	uint8_t session_id[] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t session_id_ctx[] = { 0x55, 0x66, 0x77, 0x88 };

	return HITLS_SESS_SetProtocolVersion(session, HITLS_VERSION_TLS12) ||
	       HITLS_SESS_SetCipherSuite(session,
					 HITLS_RSA_WITH_AES_128_GCM_SHA256) ||
	       HITLS_SESS_SetMasterKey(session, master_key,
				       sizeof(master_key)) ||
	       HITLS_SESS_SetSessionId(session, session_id,
				       sizeof(session_id)) ||
	       HITLS_SESS_SetSessionIdCtx(session, session_id_ctx,
					  sizeof(session_id_ctx)) ||
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
	uint8_t expected_master_key[] = { 0x01, 0x03, 0x05, 0x07,
					  0x09, 0x0b, 0x0d, 0x0f };
	uint8_t expected_session_id[] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t expected_session_id_ctx[] = { 0x55, 0x66, 0x77, 0x88 };
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

static int
seed_session(struct lws_vhost *vh)
{
	static const char tag[] = "default_example.com_443";
	struct test_sco *ts;

	ts = calloc(1, sizeof(*ts) + sizeof(tag));
	if (!ts)
		return 1;

	memcpy(&ts[1], tag, sizeof(tag));
	ts->session = HITLS_SESS_New();
	if (!ts->session || init_session(ts->session)) {
		HITLS_SESS_Free(ts->session);
		free(ts);
		return 1;
	}

	lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

	return 0;
}

static int
save_cb(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	struct blob_store *store = (struct blob_store *)info->opaque;

	(void)cx;

	free(store->blob);
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

static int
test_dump_roundtrip(void)
{
	struct lws_context cx1, cx2;
	struct lws_vhost vh1, vh2;
	struct blob_store saved = { 0 }, loaded = { 0 };
	int ret = 1;

	init_vhost(&cx1, &vh1);
	init_vhost(&cx2, &vh2);

	if (seed_session(&vh1) ||
	    lws_tls_session_dump_save(&vh1, "example.com", 443, save_cb,
				      &saved) ||
	    decode_and_check(&saved)) {
		lwsl_err("%s: save path failed\n", __func__);
		goto bail;
	}

	if (lws_tls_session_dump_load(&vh2, "example.com", 443, load_cb,
				      &saved) ||
	    lws_tls_session_dump_save(&vh2, "example.com", 443, save_cb,
				      &loaded) ||
	    decode_and_check(&loaded)) {
		lwsl_err("%s: load path failed\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	cleanup_vhost_sessions(&vh1);
	cleanup_vhost_sessions(&vh2);
	free(saved.blob);
	free(loaded.blob);

	return ret;
}

static int
test_failure_paths(void)
{
	struct lws_context cx;
	struct lws_vhost vh;
	struct blob_store empty = { 0 }, corrupt = { 0 }, valid = { 0 };
	uint8_t bad_blob[] = { 1, 2, 3, 4, 5 };
	int ret = 1;

	init_vhost(&cx, &vh);

	if (!lws_tls_session_dump_save(&vh, "example.com", 443, save_cb,
				       &valid)) {
		lwsl_err("%s: save without cache entry succeeded\n", __func__);
		goto bail;
	}

	if (!lws_tls_session_dump_load(&vh, "example.com", 443, load_cb,
				       &empty)) {
		lwsl_err("%s: empty blob load succeeded\n", __func__);
		goto bail;
	}

	corrupt.blob = malloc(sizeof(bad_blob));
	if (!corrupt.blob)
		goto bail;
	memcpy(corrupt.blob, bad_blob, sizeof(bad_blob));
	corrupt.len = sizeof(bad_blob);
	if (!lws_tls_session_dump_load(&vh, "example.com", 443, load_cb,
				       &corrupt)) {
		lwsl_err("%s: corrupt blob load succeeded\n", __func__);
		goto bail;
	}

	if (seed_session(&vh))
		goto bail;

	corrupt.loads = 0;
	if (!lws_tls_session_dump_load(&vh, "example.com", 443, load_cb,
				       &corrupt) || corrupt.loads) {
		lwsl_err("%s: existing session was overwritten\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	cleanup_vhost_sessions(&vh);
	free(corrupt.blob);
	free(valid.blob);

	return ret;
}

int
main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: openHiTLS session dump\n");

	if (init_openhitls())
		e = 1;
	else {
		e |= test_dump_roundtrip();
		e |= test_failure_paths();
	}

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
