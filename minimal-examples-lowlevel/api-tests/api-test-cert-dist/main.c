/*
 * lws-api-test-cert-dist
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * End to end test of certificate distribution: the lws-cert-dist-server and
 * lws-cert-dist-client plugins, composed into this executable, are brought up
 * on two vhosts from a lejp-conf (lwsws-style JSON) config, and the client
 * fetches a (fake) cert and key from the server over mTLS, installing them via
 * its privileged stub.
 *
 * The trust is all fake and all local:
 *
 *  - the server vhost presents the usual self-signed localhost-100y cert,
 *    which the client is told to trust as its CA with its "ca-filepath" pvo;
 *
 *  - the server vhost requires a client cert signed by ca.crt, a throwaway
 *    test CA whose key is not kept.  node1.crt and node2.crt are signed by it,
 *    for CN node1.example.com and node2.example.com.
 *
 * The client has three certs[] entries, and so three mTLS links:
 *
 *  - node1: trusted, and provisioned on the server to receive example.com.
 *    It must get the cert and key installed, and then get the update when
 *    the server's copy changes on disk;
 *
 *  - node2: trusted by the mTLS CA, but not provisioned.  The server must
 *    not hand it anything;
 *
 *  - node3: presents the localhost-100y cert, which ca.crt did not sign.  The
 *    TLS handshake must fail, so it gets nothing either.
 *
 * Both plugins spawn privilege-separated stub children, which are this same
 * executable re-run with --lws-stub=; main() then does nothing but host the
 * plugins for them.  Their sockets go in a private dir of ours, given to the
 * plugins with their "stub-dir" pvo, rather than the default /var/run.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* the plugins are composed into us, see compose-cert-dist-*.c */
extern const lws_plugin_protocol_t * const composed_cds, * const composed_cdc;

/*
 * lws runs the .init and .deinit of the plugins we list here, and ignores any
 * copy of them built into lws or found to dlopen.  Their protocols go on the
 * vhosts the config makes through pprotocols, and a vhost instantiates the
 * ones its "ws-protocols" names.
 */
static const lws_plugin_protocol_t *composed_plugins[3];
static const struct lws_protocols *pprotocols[3];

static void
compose_plugins(void)
{
	composed_plugins[0]	= composed_cds;
	composed_plugins[1]	= composed_cdc;
	pprotocols[0]		= &composed_cds->protocols[0];
	pprotocols[1]		= &composed_cdc->protocols[0];
}

enum {
	LWS_SW_PORT,
	LWS_SW_SERVER,
	LWS_SW_CERTS,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the distribution server "
					"(default 7681)" },
	[LWS_SW_SERVER]	= { "-s",	"Address the client uses for the server "
					"(default localhost)" },
	[LWS_SW_CERTS]	= { "--certs",	"Dir holding the test certs and keys "
					"(default .)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

#define PHASE_TIMEOUT_SECS	20

/* what the server is distributing for example.com, before and after */

static const char * const fake_crt[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"ZmFrZSBjZXJ0aWZpY2F0ZSBmb3IgZXhhbXBsZS5jb20sIHZlcnNpb24gMQ==\n"
	"-----END CERTIFICATE-----\n",
	"-----BEGIN CERTIFICATE-----\n"
	"ZmFrZSBjZXJ0aWZpY2F0ZSBmb3IgZXhhbXBsZS5jb20sIHZlcnNpb24gMg==\n"
	"-----END CERTIFICATE-----\n",
};

static const char * const fake_key[] = {
	"-----BEGIN PRIVATE KEY-----\n"
	"ZmFrZSBwcml2YXRlIGtleSBmb3IgZXhhbXBsZS5jb20sIHZlcnNpb24gMQ==\n"
	"-----END PRIVATE KEY-----\n",
	"-----BEGIN PRIVATE KEY-----\n"
	"ZmFrZSBwcml2YXRlIGtleSBmb3IgZXhhbXBsZS5jb20sIHZlcnNpb24gMg==\n"
	"-----END PRIVATE KEY-----\n",
};

/* the server picks the newest by name */
static const char * const fake_stem[] = {
	"2026-01-01", "2026-06-01"
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_check;
static char work[64];
static int phase, tests, fail, done;
static lws_usec_t phase_deadline;

static void
expect(const char *what, int ok)
{
	tests++;
	if (!ok)
		fail++;
	lwsl_user("  %s: %s\n", ok ? "PASS" : "FAIL", what);
}

static int
write_file(const char *path, const char *content)
{
	size_t len = strlen(content);
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

	if (fd < 0) {
		lwsl_err("%s: unable to create %s: %s\n", __func__, path,
			 strerror(errno));
		return 1;
	}

	if (write(fd, content, len) != (ssize_t)len) {
		close(fd);
		return 1;
	}

	return close(fd);
}

/* 1 if the file at path holds exactly content */
static int
file_is(const char *path, const char *content)
{
	size_t len = strlen(content);
	char buf[256];
	ssize_t n;
	int fd;

	if (len >= sizeof(buf))
		return 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf));
	close(fd);

	return n == (ssize_t)len && !memcmp(buf, content, len);
}

static int
exists(const char *path)
{
	struct stat s;

	return !lstat(path, &s);
}

static int
mkdirs(const char * const *dirs)
{
	char path[256];

	while (*dirs) {
		lws_snprintf(path, sizeof(path), "%s/%s", work, *dirs);
		if (mkdir(path, 0700)) {
			lwsl_err("%s: unable to create %s: %s\n", __func__,
				 path, strerror(errno));
			return 1;
		}
		dirs++;
	}

	return 0;
}

/*
 * Put version v of example.com's cert and key where the server looks for
 * them.  Each is written under a name the server ignores and renamed into
 * place, so it never sees one half-written; the key goes first, so a cert is
 * never offered without its key.
 */
static int
publish(int v)
{
	static const char * const sub[] = { "key", "crt" };
	char tmp[256], path[256];
	int n;

	for (n = 0; n < 2; n++) {
		lws_snprintf(tmp, sizeof(tmp), "%s/pki/domains/example.com/"
			     "certs/production/%s/.incoming", work, sub[n]);
		lws_snprintf(path, sizeof(path), "%s/pki/domains/example.com/"
			     "certs/production/%s/%s.%s", work, sub[n],
			     fake_stem[v], sub[n]);

		if (write_file(tmp, n ? fake_crt[v] : fake_key[v]) ||
		    rename(tmp, path)) {
			lwsl_err("%s: unable to publish %s\n", __func__, path);
			return 1;
		}
	}

	return 0;
}

/* 1 if node1 has version v of the cert and key installed */
static int
node1_has(int v)
{
	char fc[256], pk[256];

	lws_snprintf(fc, sizeof(fc), "%s/install/node1/fullchain.pem", work);
	lws_snprintf(pk, sizeof(pk), "%s/install/node1/privkey.pem", work);

	return file_is(fc, fake_crt[v]) && file_is(pk, fake_key[v]);
}

/*
 * How the stub installs: fullchain.pem and privkey.pem are symlinks to
 * timestamped siblings, and nobody but us can read the key
 */
static void
check_install_layout(void)
{
	char path[256], target[128];
	struct stat s;
	ssize_t n;

	lws_snprintf(path, sizeof(path), "%s/install/node1/privkey.pem", work);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0)
		target[n] = '\0';
	expect("privkey.pem is a symlink to a timestamped sibling",
	       n > 0 && !strncmp(target, "privkey.pem.", 12) &&
	       !strchr(target, '/'));
	expect("installed private key is private",
	       !stat(path, &s) && !(s.st_mode & 077));

	lws_snprintf(path, sizeof(path), "%s/install/node1/fullchain.pem",
		     work);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0)
		target[n] = '\0';
	expect("fullchain.pem is a symlink to a timestamped sibling",
	       n > 0 && !strncmp(target, "fullchain.pem.", 14) &&
	       !strchr(target, '/'));

	lws_snprintf(path, sizeof(path), "%s/install/node1", work);
	expect("install dir is private",
	       !stat(path, &s) && S_ISDIR(s.st_mode) && !(s.st_mode & 077));
}

static void
arm_phase_deadline(void)
{
	phase_deadline = lws_now_usecs() +
			 (lws_usec_t)PHASE_TIMEOUT_SECS * LWS_US_PER_SEC;
}

static void
sul_check_cb(lws_sorted_usec_list_t *sul)
{
	switch (phase) {
	case 0:
		/* the initial distribution of version 0 */
		if (!node1_has(0))
			break;

		expect("node1 got the cert and key over mTLS", 1);
		check_install_layout();

		/* the server's copy is renewed on disk */
		if (publish(1)) {
			expect("publish the renewed cert", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		phase++;
		arm_phase_deadline();
		break;

	case 1:
		/* the renewal is pushed on the link that is already up */
		if (!node1_has(1))
			break;

		expect("node1 got the renewed cert and key", 1);
		phase++;
		done = 1;
		lws_cancel_service(context);
		return;
	}

	if (lws_now_usecs() > phase_deadline) {
		expect(phase ? "node1 got the renewed cert and key" :
			       "node1 got the cert and key over mTLS", 0);
		done = 1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_check, sul_check_cb,
			 100 * LWS_US_PER_MS);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

/*
 * Compose the lejp-conf config dir: the globals in <work>/conf, the vhosts
 * in <work>/conf.d/cert-dist
 */
static int
write_config(const char *certs, const char *server, int port)
{
	char ew[sizeof(work) * 6], ec[256 * 6], url[128], path[256];
	char *conf;
	size_t len = 8192;
	int r;

	if (strlen(certs) >= 256)
		return 1;

	lws_json_purify(ew, work, (int)sizeof(ew), NULL);
	lws_json_purify(ec, certs, (int)sizeof(ec), NULL);

	/* an IPv6 literal needs brackets in the URL */
	lws_snprintf(url, sizeof(url), strchr(server, ':') ?
			"wss://[%s]:%d" : "wss://%s:%d", server, port);

	lws_snprintf(path, sizeof(path), "%s/conf", work);
	if (write_file(path, "{\"global\": {\"init-ssl\": \"yes\"}}\n"))
		return 1;

	conf = malloc(len);
	if (!conf)
		return 1;

	lws_snprintf(conf, len,
		"{\"vhosts\": [{\n"
		"  \"name\": \"cds\",\n"
		"  \"port\": \"%d\",\n"
		"  \"host-ssl-cert\": \"%s/localhost-100y.cert\",\n"
		"  \"host-ssl-key\": \"%s/localhost-100y.key\",\n"
		"  \"host-ssl-ca\": \"%s/ca.crt\",\n"
		"  \"client-cert-required\": \"1\",\n"
		"  \"ws-protocols\": [{\n"
		"    \"lws-cert-dist-server\": {\n"
		"      \"status\": \"ok\",\n"
		"      \"pki-root\": \"%s/pki\",\n"
		"      \"stub-dir\": \"%s/run\"\n"
		"    }\n"
		"  }]\n"
		"}, {\n"
		"  \"name\": \"cdc\",\n"
		"  \"port\": \"-1\",\n"
		"  \"ws-protocols\": [{\n"
		"    \"lws-cert-dist-client\": {\n"
		"      \"status\": \"ok\",\n"
		"      \"base-dir\": \"%s/install\",\n"
		"      \"stub-dir\": \"%s/run\",\n"
		"      \"server-url\": \"%s\",\n"
		"      \"ca-filepath\": \"%s/localhost-100y.cert\",\n"
		"      \"certs\": {\n"
		"        \"node1\": {\n"
		"          \"cert\": \"%s/node1.crt\",\n"
		"          \"key\": \"%s/node1.key\"\n"
		"        },\n"
		"        \"node2\": {\n"
		"          \"cert\": \"%s/node2.crt\",\n"
		"          \"key\": \"%s/node2.key\"\n"
		"        },\n"
		"        \"node3\": {\n"
		"          \"cert\": \"%s/localhost-100y.cert\",\n"
		"          \"key\": \"%s/localhost-100y.key\"\n"
		"        }\n"
		"      }\n"
		"    }\n"
		"  }]\n"
		"}]}\n",
		port, ec, ec, ec, ew, ew, ew, ew, url, ec, ec, ec, ec, ec,
		ec, ec);

	lws_snprintf(path, sizeof(path), "%s/conf.d/cert-dist", work);
	r = write_file(path, conf);
	free(conf);

	return r;
}

/*
 * The server side PKI: example.com's cert and key, and the provisioning of
 * node1.example.com (only) to receive them
 */
static int
write_pki(void)
{
	static const char * const dirs[] = {
		"conf.d", "run", "install", "pki", "pki/domains",
		"pki/domains/example.com",
		"pki/domains/example.com/dist-client",
		"pki/domains/example.com/certs",
		"pki/domains/example.com/certs/production",
		"pki/domains/example.com/certs/production/crt",
		"pki/domains/example.com/certs/production/key",
		NULL
	};
	char path[256];

	if (mkdirs(dirs))
		return 1;

	/* only its existence is looked at */
	lws_snprintf(path, sizeof(path), "%s/pki/domains/example.com/"
		     "dist-client/distribution-client-node1.example.com.crt",
		     work);
	if (write_file(path, "provisioned\n"))
		return 1;

	return publish(0);
}

/*
 * We are one of the plugins' stub children: the plugin in the parent re-ran
 * this executable with --lws-stub=<name> --lws-uds=<path>.  All we have to do
 * is create a context with the plugins in it: the plugin whose stub it is sees
 * the option in its init and sets up the stub side.  The stub layer exits the
 * process when the parent goes away.
 */
static int
run_stub(struct lws_context_creation_info *info)
{
	int n = 0;

	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info->plugins = composed_plugins;

	context = lws_create_context(info);
	if (!context)
		return 1;

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *certs = ".", *server = "localhost";
	static char arena[16384];
	char *cs = arena, path[256];
	int n = 0, port = 7681, len = (int)sizeof(arena), have_work = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	compose_plugins();

	if (lws_cmdline_option(argc, argv, "--lws-stub="))
		return run_stub(&info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CERTS].sw)))
		certs = p;

	lwsl_user("LWS API selftest: cert distribution over mTLS\n");

	/*
	 * Everything we make lives in a private dir of our own, short enough
	 * for the stub socket paths in it to fit in a sockaddr_un
	 */
	lws_strncpy(work, "/tmp/lws-cd-XXXXXX", sizeof(work));
	if (!mkdtemp(work)) {
		lwsl_err("unable to create work dir\n");
		goto bail;
	}
	have_work = 1;

	if (write_pki() || write_config(certs, server, port)) {
		lwsl_err("unable to create the fixture\n");
		goto bail;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	if (lwsws_get_config_globals(&info, work, &cs, &len)) {
		lwsl_err("unable to parse the globals config\n");
		goto bail;
	}

	/* the globals parse starts info over, so after it */
	info.plugins = composed_plugins;
	info.pprotocols = pprotocols;
	info.argc = argc;
	info.argv = argv;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		goto bail;
	}

	if (lwsws_get_config_vhosts(context, &info, work, &cs, &len)) {
		lwsl_err("unable to create the vhosts from the config\n");
		goto bail;
	}

	arm_phase_deadline();
	lws_sul_schedule(context, 0, &sul_check, sul_check_cb,
			 100 * LWS_US_PER_MS);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	expect("every phase ran", done && phase == 2);

	/*
	 * The refused links had as long as the whole run to get something
	 * installed
	 */
	lws_snprintf(path, sizeof(path), "%s/install/node2", work);
	expect("unprovisioned node2 got nothing", !exists(path));
	lws_snprintf(path, sizeof(path), "%s/install/node3", work);
	expect("node3 with an untrusted client cert got nothing",
	       !exists(path));

bail:
	lws_context_destroy(context);
	if (have_work)
		lws_dir(work, NULL, lws_dir_rm_rf_cb);

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  !tests || fail ? "FAIL" : "PASS", tests, fail);

	return !tests || fail;
}
