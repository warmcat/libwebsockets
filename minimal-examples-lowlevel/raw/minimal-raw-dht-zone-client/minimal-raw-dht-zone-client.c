/*
 * lws-minimal-raw-dht
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal DHT node that can store and retrieve data/files
 * using the lws-dht UDP data transport, by instantiating the
 * lws-dht-dnssec plugin.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/stat.h>
#if defined(WIN32)
#include <direct.h>
#define mkdir(a, b) _mkdir(a)
#endif

static lws_state_notify_link_t nl;
int retcode = 1;
int interrupted;
int use_stdin;
char port_buf[16];
const char *storage_path = "./dht-store";
static struct lws_context *cx;

static lws_state_notify_link_t *const app_notifier_list[] = {&nl, NULL};
extern const struct lws_protocols lws_dht_dnssec_protocols[];

static void
dht_completion_cb(void *closure, int result)
{
	int *p_interrupted = (int *)closure;

	*p_interrupted = 1;

	lwsl_user("dht_completion_cb called! result: %d\n", result);

	if (!result)
		retcode = 0;

	lws_cancel_service(cx);
}

struct lws_protocol_vhost_options pvos[] = {
	{
		.options	= &pvos[1],
		.next		= NULL,
		.name		= "lws-dht-dnssec",
		.value		= "ok"
	},
	{
		.options	= NULL,
		.next		= &pvos[2],
		.name		= "dht-storage-path",
		.value		= "./dht-store"
	},
	{
		.options	= NULL,
		.next		= &pvos[3],
		.name		= "dht-port",
		.value		= port_buf
	},
	{
		.options	= NULL,
		.next		= &pvos[4],
		.name		= "completion-cb",
		.value		= (const char *)dht_completion_cb
	},
	{
		.options	= NULL,
		.next		= &pvos[5],
		.name		= "completion-cb-arg",
		.value		= (const char *)&interrupted
	},
	{
		.options	= NULL,
		.next		= &pvos[6],
		.name		= "target-ip",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[7],
		.name		= "target-port",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[8],
		.name		= "put-file",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[9],
		.name		= "get-hash",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[10],
		.name		= "bulk",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[11],
		.name		= "gen-manifest",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[12],
		.name		= "receiver",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[13],
		.name		= "dht-iface",
		.value		= "127.0.0.1"
	},
	{
		.options	= NULL,
		.next		= &pvos[14],
		.name		= "dht-jwk",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[15],
		.name		= "dht-policy-allow",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[16],
		.name		= "dht-policy-deny",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[17],
		.name		= "dht-test-handshake",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= NULL,
		.name		= "domain",
		.value		= ""
	},
};

static int
create_signed_jws(struct lws_context *cx, const char *in_path, const char *jwk_path, const char *out_path)
{
	char temp[4096 * 4], *in_buf;
	int temp_len = sizeof(temp);
	struct lws_jws jws;
	struct lws_jwk jwk;
	struct lws_jose jose;
	int fd, n, r = 1;
	struct stat st;

	lws_jose_init(&jose);
	lws_jws_init(&jws, &jwk, cx);

	if (lws_jwk_load(&jwk, jwk_path, NULL, NULL)) {
		lwsl_err("%s: failed to load %s\n", __func__, jwk_path);
		goto bail;
	}

	if (lws_gencrypto_jws_alg_to_definition("ES256", &jose.alg)) {
		lwsl_err("%s: alg unknown\n", __func__);
		goto bail;
	}

	fd = open(in_path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		lwsl_err("%s: failed to open %s\n", __func__, in_path);
		goto bail;
	}

	in_buf = malloc((size_t)st.st_size + 1);
	if (!in_buf) {
		close(fd);
		goto bail;
	}
	n = (int)read(fd, in_buf, (size_t)st.st_size);
	close(fd);

	if (n != st.st_size) {
		free(in_buf);
		goto bail;
	}

	if (lws_jws_alloc_element(&jws.map, LJWS_JOSE, lws_concat_temp(temp, temp_len),
				  &temp_len, 20, 0)) goto bail2;
	
	jws.map.len[LJWS_JOSE] = (uint32_t)lws_snprintf((char *)jws.map.buf[LJWS_JOSE],
							(unsigned int)temp_len, "{\"alg\":\"ES256\"}");

	jws.map.buf[LJWS_PYLD] = in_buf;
	jws.map.len[LJWS_PYLD] = (unsigned int)n;

	if (lws_jws_encode_b64_element(&jws.map_b64, LJWS_PYLD, lws_concat_temp(temp, temp_len),
				       &temp_len, jws.map.buf[LJWS_PYLD], jws.map.len[LJWS_PYLD])) goto bail2;

	if (lws_jws_encode_b64_element(&jws.map_b64, LJWS_JOSE, lws_concat_temp(temp, temp_len),
				       &temp_len, jws.map.buf[LJWS_JOSE], jws.map.len[LJWS_JOSE])) goto bail2;

	if (lws_jws_alloc_element(&jws.map_b64, LJWS_SIG, lws_concat_temp(temp, temp_len),
				  &temp_len, (unsigned int)lws_base64_size(LWS_JWE_LIMIT_KEY_ELEMENT_BYTES), 0)) goto bail2;

	n = lws_jws_sign_from_b64(&jose, &jws, (char *)jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);
	if (n < 0) {
		lwsl_err("%s: sign failed\n", __func__);
		goto bail2;
	}
	jws.map_b64.len[LJWS_SIG] = (uint32_t)n;

	char *compact = malloc((size_t)st.st_size + 4096);
	if (!compact) goto bail2;

	n = lws_jws_write_flattened_json(&jws, compact, (size_t)st.st_size + 4096);
	if (n < 0) {
		free(compact);
		goto bail2;
	}

	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(compact);
		goto bail2;
	}
	if (write(fd, compact, (size_t)n) != n) {
		close(fd);
		free(compact);
		goto bail2;
	}
	close(fd);
	free(compact);

	r = 0;
bail2:
	free(in_buf);
bail:
	lws_jws_destroy(&jws);
	lws_jwk_destroy(&jwk);
	lws_jose_destroy(&jose);
	return r;
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
                    int current, int target)
{
        struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
        struct lws_context_creation_info info;
        struct lws_vhost *vh;

        switch (target) {
        case LWS_SYSTATE_OPERATIONAL:
                if (current == LWS_SYSTATE_OPERATIONAL)
                        break;

		lwsl_user("%s: OPERATIONAL->creating vhost\n", __func__);

		memset(&info, 0, sizeof(info));
                info.vhost_name = "dht";
                info.pvo = pvos;
                info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
                vh = lws_create_vhost(cx, &info);
                if (!vh) {
			lwsl_err("vhost creation failed\n");
			return 0;
		}

                lws_finalize_startup(cx, __func__);
		break;
        }
	return 0;
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int dht_port = 5000;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal raw DHT DNSSEC client\n");

	if ((p = lws_cmdline_option(argc, argv, "-s")))
		storage_path = p;

	mkdir(storage_path, 0700);
	pvos[1].value = storage_path;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		dht_port = atoi(p);

	lws_snprintf(port_buf, sizeof(port_buf), "%d", dht_port);

	if ((p = lws_cmdline_option(argc, argv, "--target-ip")))
		pvos[5].value = p;

	if ((p = lws_cmdline_option(argc, argv, "--target-port")))
		pvos[6].value = p;

	if ((p = lws_cmdline_option(argc, argv, "--put"))) {
		pvos[7].value = p;
		use_stdin = 1;
	}

	if ((p = lws_cmdline_option(argc, argv, "--get"))) {
		pvos[8].value = p;
		use_stdin = 1;
	}

	if (lws_cmdline_option(argc, argv, "--bulk")) {
		pvos[9].value = "1";
		use_stdin = 1;
	}

	if (lws_cmdline_option(argc, argv, "--gen-manifest"))
		pvos[10].value = "1";

	if (lws_cmdline_option(argc, argv, "--receiver"))
		pvos[11].value = "1";

	if ((p = lws_cmdline_option(argc, argv, "--jwk")))
		pvos[13].value = p;

	if ((p = lws_cmdline_option(argc, argv, "--policy-allow")))
		pvos[14].value = p;

	if ((p = lws_cmdline_option(argc, argv, "--policy-deny")))
		pvos[15].value = p;

	if (lws_cmdline_option(argc, argv, "--test-handshake"))
		pvos[16].value = "1";

	if ((p = lws_cmdline_option(argc, argv, "--domain")))
		pvos[17].value = p;


	info.port				= CONTEXT_PORT_NO_LISTEN;
	info.options				= LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.pvo				= pvos;
	info.protocols				= lws_dht_dnssec_protocols;
	info.fd_limit_per_thread		= 100;

        nl.name					= "app";
        nl.notify_cb				= app_system_state_nf;
        info.register_notifier_list		= app_notifier_list;

        cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (pvos[7].value && pvos[7].value[0]) {
		const char *jwk_path = pvos[13].value;
		if (!jwk_path[0]) jwk_path = "dht.jwk";

		lwsl_user("Loading %s, signing, and preparing upload...\n", pvos[7].value);
		if (create_signed_jws(cx, pvos[7].value, jwk_path, "/tmp/signed-zone.jws.tmp")) {
			lwsl_err("Failed to sign JWS\n");
			return 1;
		}
		pvos[7].value = "/tmp/signed-zone.jws.tmp";
	}

	while (n >= 0 && !interrupted)
		n = lws_service(cx, 0);

	lws_context_destroy(cx);

        return lws_cmdline_passfail(argc, argv, retcode);
}
