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
 *  - node1: trusted, and provisioned on the server, which holds the client
 *    cert it issued node1.  It must get the cert and key for its own name,
 *    node1.example.com, installed, never the example.com ones beside them,
 *    and then get the update when the server's copy changes on disk.  An
 *    update it fails to install must be fetched again, and while the client
 *    cert the server holds for it is not the one it presents, it must get
 *    nothing;
 *
 *  - node2: trusted by the mTLS CA, but not provisioned.  The server must
 *    not hand it anything;
 *
 *  - node3: presents the localhost-100y cert, which ca.crt did not sign.  The
 *    TLS handshake must fail, so it gets nothing either.
 *
 * A tls server vhost, node1-svc, serves node1's installed fullchain.pem and
 * privkey.pem.  The stub writes those as files the vhost may not be able to
 * read, eg, after lwsws dropped its privileges, so once a pair is installed
 * the client must hand the vhost copies of it.  Here we can read them
 * ourselves, so to see that only the copies are used, the install dir is
 * moved out of the way as soon as a new pair turns up in it, until the vhost
 * serves the new cert: the vhost watching its files would only look a couple
 * of seconds later, and find them gone.
 *
 * Both plugins spawn privilege-separated stub children, which are this same
 * executable re-run with --lws-stub=; main() then does nothing but host the
 * plugins for them.  The client's stub is told to run as its "stub-user",
 * which here is us: we are not root, so it can only be who we are already,
 * but it is passed down and checked as it would be.  Their sockets go in a private dir of ours, given to the
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
#include <pwd.h>

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
/*
 * The client holds back refetching a cert it failed to install for 10s, with
 * 20% jitter, before it reconnects
 */
#define RETRY_TIMEOUT_SECS	35

/*
 * What the server distributes for example.com, before and after a renewal:
 * real cert + key pairs, since the server only sends a key that belongs to
 * its cert.  They are just certs we have to hand, read from --certs.
 *
 * The third is the first pair again, sent while node1's install dir is not
 * one the client's stub will write a key into: the install fails, and the
 * client must retry it once the dir is fixed.
 *
 * The fourth is the second pair again, renewed while the server's record of
 * the client cert it issued node1 is a different cert: node1 must get nothing.
 *
 * The fifth "renewal" is the third pair with a line that is not PEM on the
 * end of its fullchain (see ver_junk below): the server's copy of a cert is
 * no more trustworthy than the server, and the client must not install it.
 */

#define VERSIONS	5
#define VER_UNAUTH	3
#define VER_JUNK	4

static const char * const ver_cert_file[VERSIONS] = {
	"localhost-100y.cert", "node2.crt", "localhost-100y.cert", "node2.crt",
	"node1.crt"
};
static const char * const ver_key_file[VERSIONS] = {
	"localhost-100y.key", "node2.key", "localhost-100y.key", "node2.key",
	"node1.key"
};
/* the timestamps the acme client names each renewal's files with */
static const char * const ver_stem[VERSIONS] = {
	"20260101-000000", "20260601-000000", "20261101-000000",
	"20270101-000000", "20270601-000000"
};

/*
 * node1's client cert is for node1.example.com, so that is the name of the
 * cert it must be given.  The domain's own cert sits beside it, a different
 * pair, which node1 must never be given.
 */
#define NODE1_NAME	"node1.example.com"
#define APEX_NAME	"example.com"
#define APEX_VER	1

/* where the server keeps the client cert it issued node1 */
#define NODE1_ISSUED	"pki/domains/example.com/dist-client/" \
			"distribution-client-node1.example.com.crt"

/*
 * A PEM body never contains a double quote.  One that does would, if the
 * client passed it on as it stands, end the string it is carried in inside
 * the request to the client's privileged stub, and what follows would be
 * taken as further members of that request: here, a second "subdomain"
 * naming a sibling of the cert's own install dir.  The client has to refuse
 * the body, and whatever happens nothing may appear under that name.
 */
#define VER_JUNK_NAME "victim"
static const char * const ver_junk =
		"\",\"subdomain\":\"" VER_JUNK_NAME "\",\"x\":\"\n";

#define PEM_MAX 8192

static char ver_cert[VERSIONS][PEM_MAX], ver_key[VERSIONS][PEM_MAX];
static const char *certs = ".";

/* the CN of each version's cert, what node1-svc must serve */
static const char * const ver_cn[VERSIONS] = {
	"localhost", "node2.example.com", "localhost", "node2.example.com",
	"node1.example.com"
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_check;
static char work[64];
static int phase, tests, fail, done, hidden;
static lws_usec_t phase_deadline, hold_until;

/* how long a half-done renewal is watched for being (wrongly) sent */
#define HOLD_US		(2 * LWS_US_PER_SEC)

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
	char buf[PEM_MAX];
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
 * Renew the cert for name in example.com to version v, the way the acme
 * client does with the dnssec monitor storing it: a timestamped leaf cert,
 * key and fullchain are written, and the -latest links moved onto each in
 * turn, the outgoing ones kept as -previous.  So the dirs hold several certs
 * and keys besides the ones the server must send, and for a moment the links
 * point to the new key and the old fullchain, which the server must not
 * offer.
 *
 * Files [from, to) of the renewal are stored, so a test can stop it halfway.
 */
#define PUB_KEY_DONE	2	/* leaf and key stored, the fullchain not yet */
#define PUB_ALL		3

static int
publish_as(const char *name, int v, size_t from, size_t to)
{
	static const struct {
		const char *sub, *suffix;
		char key;
	} f[] = {	/* in the order the monitor stores them */
		{ "crt", ".crt", 0 },
		{ "key", ".key", 1 },
		{ "crt", "-fullchain.crt", 0 },
	};
	char dir[192], target[96], path[256], link[256];
	size_t n;

	for (n = from; n < to && n < LWS_ARRAY_SIZE(f); n++) {
		lws_snprintf(dir, sizeof(dir), "%s/pki/domains/example.com/"
			     "certs/production/%s", work, f[n].sub);
		lws_snprintf(target, sizeof(target), "%s-%s%s", name,
			     ver_stem[v], f[n].suffix);
		lws_snprintf(path, sizeof(path), "%s/%s", dir, target);
		lws_snprintf(link, sizeof(link), "%s/%s-latest%s", dir, name,
			     f[n].suffix);

		if (write_file(path, f[n].key ? ver_key[v] : ver_cert[v])) {
			lwsl_err("%s: unable to write %s\n", __func__, path);
			return 1;
		}
		if (lws_dir_symlink_rotate(link, target, "-latest",
					   "-previous")) {
			lwsl_err("%s: unable to link %s\n", __func__, link);
			return 1;
		}
	}

	return 0;
}

/* renew node1's own cert */
static int
publish(int v, size_t from, size_t to)
{
	return publish_as(NODE1_NAME, v, from, to);
}

/*
 * Set the server's record of the client cert it issued node1 to the cert in
 * file, in the --certs dir
 */
static int
set_node1_issued(const char *file)
{
	char path[256], pem[PEM_MAX];
	int n;

	lws_snprintf(path, sizeof(path), "%s/%s", certs, file);
	n = lws_plat_read_file(path, pem, sizeof(pem) - 1);
	if (n <= 0 || n >= (int)sizeof(pem) - 1)
		return 1;
	pem[n] = '\0';

	lws_snprintf(path, sizeof(path), "%s/" NODE1_ISSUED, work);

	return write_file(path, pem);
}

/* read the pairs we distribute from the --certs dir */
static int
load_versions(void)
{
	char path[256];
	int v, n;

	for (v = 0; v < VERSIONS; v++) {
		lws_snprintf(path, sizeof(path), "%s/%s", certs,
			     ver_cert_file[v]);
		n = lws_plat_read_file(path, ver_cert[v], PEM_MAX - 1);
		if (n <= 0 || n >= PEM_MAX - 1)
			goto bail;
		ver_cert[v][n] = '\0';

		if (v == VER_JUNK) {
			/* the last version's fullchain is not plain PEM */
			if ((size_t)n + strlen(ver_junk) >= PEM_MAX)
				goto bail;
			lws_strncpy(ver_cert[v] + n, ver_junk,
				    PEM_MAX - (size_t)n);
		}

		lws_snprintf(path, sizeof(path), "%s/%s", certs,
			     ver_key_file[v]);
		n = lws_plat_read_file(path, ver_key[v], PEM_MAX - 1);
		if (n <= 0 || n >= PEM_MAX - 1)
			goto bail;
		ver_key[v][n] = '\0';
	}

	return 0;

bail:
	lwsl_err("%s: can't read %s\n", __func__, path);

	return 1;
}

/* 1 if node1 has version v of the cert and key installed */
static int
node1_has(int v)
{
	char fc[256], pk[256];

	lws_snprintf(fc, sizeof(fc), "%s/install/node1/fullchain.pem", work);
	lws_snprintf(pk, sizeof(pk), "%s/install/node1/privkey.pem", work);

	return file_is(fc, ver_cert[v]) && file_is(pk, ver_key[v]);
}

/* 1 if node1-svc serves the cert of version v */
static int
svc_serves(int v)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "node1-svc");
	union lws_tls_cert_info_results ir;

	return vh && !lws_tls_vhost_cert_info(vh, LWS_TLS_CERT_INFO_COMMON_NAME,
					      &ir, sizeof(ir.ns.name)) &&
	       !strcmp(ir.ns.name, ver_cn[v]);
}

/* move node1's install dir out of the way, or back */
static int
node1_dir_hide(int hide)
{
	char dir[256], away[256];

	lws_snprintf(dir, sizeof(dir), "%s/install/node1", work);
	lws_snprintf(away, sizeof(away), "%s/install/node1-away", work);

	if (hide ? rename(dir, away) : rename(away, dir))
		return 1;
	hidden = hide;

	return 0;
}

/*
 * 1 once node1 has version v installed, and node1-svc serves it.  As soon as
 * the files are there, they are moved out of the way until the vhost serves
 * the new cert, so it can only have had it from the copies the client hands
 * it.  -1 if the dir can't be moved.
 */
static int
node1_installed_and_served(int v)
{
	if (!hidden) {
		if (!node1_has(v))
			return 0;
		if (node1_dir_hide(1))
			return -1;
	}

	if (!svc_serves(v))
		return 0;

	return node1_dir_hide(0) ? -1 : 1;
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
arm_deadline(int secs)
{
	phase_deadline = lws_now_usecs() + (lws_usec_t)secs * LWS_US_PER_SEC;
}

static void
arm_phase_deadline(void)
{
	arm_deadline(PHASE_TIMEOUT_SECS);
}

/* node1's install dir, made writable by others or private again */
static int
node1_dir_mode(mode_t mode)
{
	char path[256];

	lws_snprintf(path, sizeof(path), "%s/install/node1", work);

	return chmod(path, mode);
}

static void
sul_check_cb(lws_sorted_usec_list_t *sul)
{
	char path[256];

	switch (phase) {
	case 0:
		/* the initial distribution of version 0 */
		if (node1_installed_and_served(0) <= 0)
			break;

		expect("node1 got the cert and key over mTLS", 1);
		expect("the vhost serving it was handed the pair", 1);
		check_install_layout();

		/*
		 * The server's copy is renewed on disk, stopping where the
		 * links point to the new key and the old fullchain.  Without
		 * JOSE the server can't tell the pair doesn't match, so we
		 * don't ask it to.
		 */
#if defined(LWS_WITH_JOSE)
		if (publish(1, 0, PUB_KEY_DONE)) {
#else
		if (publish(1, 0, PUB_ALL)) {
#endif
			expect("publish the renewed cert", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		hold_until = lws_now_usecs() + HOLD_US;
		phase++;
		arm_phase_deadline();
		break;

	case 1:
#if defined(LWS_WITH_JOSE)
		/* node1 must keep the pair it has, not get a mismatched one */
		if (!node1_has(0)) {
			expect("half-done renewal not sent", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		if (lws_now_usecs() < hold_until)
			break;

		expect("half-done renewal not sent", 1);

		/* the renewal completes */
		if (publish(1, PUB_KEY_DONE, PUB_ALL)) {
			expect("complete the renewal", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
#endif
		phase++;
		arm_phase_deadline();
		break;

	case 2:
		/* the renewal is pushed on the link that is already up */
		if (node1_installed_and_served(1) <= 0)
			break;

		expect("node1 got the renewed cert and key", 1);
		expect("the vhost serving it was handed the renewal", 1);

		/*
		 * The next renewal arrives while node1's install dir is
		 * writable by its group, so the stub refuses to write a key
		 * into it
		 */
		if (node1_dir_mode(0770) || publish(2, 0, PUB_ALL)) {
			expect("publish a renewal node1 can't install", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		hold_until = lws_now_usecs() + HOLD_US;
		phase++;
		arm_phase_deadline();
		break;

	case 3:
		/* the install fails: node1 keeps the pair it has */
		if (!node1_has(1)) {
			expect("renewal not installed in an unsafe dir", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		if (lws_now_usecs() < hold_until)
			break;

		expect("renewal not installed in an unsafe dir", 1);

		/*
		 * The dir is put right.  Nothing changes on the server now,
		 * so only the client retrying can get the renewal installed
		 */
		if (node1_dir_mode(0700)) {
			expect("make node1's install dir private again", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		phase++;
		arm_deadline(RETRY_TIMEOUT_SECS);
		break;

	case 4:
		if (node1_installed_and_served(2) <= 0)
			break;

		expect("failed install retried and completed", 1);
		expect("the vhost serving it was handed the retried pair", 1);

		/*
		 * The server's record of the client cert it issued node1
		 * becomes another cert, as if node1's provisioning had been
		 * reset and reissued.  The cert node1 presents is still signed
		 * by the CA and still names node1.example.com, but it is not
		 * the one issued, so a renewal must not reach it
		 */
		if (set_node1_issued("node2.crt") ||
		    publish(VER_UNAUTH, 0, PUB_ALL)) {
			expect("publish a renewal for a node1 no longer issued "
			       "that cert", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		hold_until = lws_now_usecs() + HOLD_US;
		phase++;
		arm_phase_deadline();
		break;

	case 5:
		if (!node1_has(2)) {
			expect("client cert that is not the one issued gets "
			       "nothing", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		if (lws_now_usecs() < hold_until)
			break;

		expect("client cert that is not the one issued gets nothing",
		       1);

		/*
		 * node1 is provisioned again, and the server's copy is
		 * "renewed" again, to a fullchain that is not plain PEM, and
		 * pushed down the link the same way
		 */
		if (set_node1_issued("node1.crt") ||
		    publish(VER_JUNK, 0, PUB_ALL)) {
			expect("publish the junk renewal", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		hold_until = lws_now_usecs() + HOLD_US;
		phase++;
		arm_phase_deadline();
		break;

	case 6:
		/*
		 * node1 must keep a pair it was given, and nothing may turn
		 * up under the name the junk carries.  Being provisioned
		 * again, it may first get the renewal it was refused.
		 */
		lws_snprintf(path, sizeof(path), "%s/install/%s", work,
			     VER_JUNK_NAME);
		if (exists(path) || !(node1_has(2) || node1_has(VER_UNAUTH))) {
			expect("junk renewal refused, nothing installed under "
			       "its name", 0);
			done = 1;
			lws_cancel_service(context);
			return;
		}
		if (lws_now_usecs() < hold_until)
			break;

		expect("junk renewal refused, nothing installed under its name",
		       1);
		phase++;
		done = 1;
		lws_cancel_service(context);
		return;
	}

	if (lws_now_usecs() > phase_deadline) {
		static const char * const waited_for[] = {
			"node1 got the cert and key over mTLS, and the vhost "
				"serving it was handed the pair",
			"half-done renewal not sent",
			"node1 got the renewed cert and key, and the vhost "
				"serving it was handed it",
			"renewal not installed in an unsafe dir",
			"failed install retried and completed, and the vhost "
				"serving it was handed it",
			"client cert that is not the one issued gets nothing",
			"junk renewal refused, nothing installed under its name",
		};

		expect(phase >= 0 && phase < (int)LWS_ARRAY_SIZE(waited_for) ?
					waited_for[phase] : "phase in range", 0);
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
write_config(const char *certs_dir, const char *server, int port)
{
	char ew[sizeof(work) * 6], ec[256 * 6], url[128], path[256];
	struct passwd *pw;
	char *conf;
	size_t len = 8192;
	int r;
#if defined(LWS_HAVE_GETPWUID_R)
	struct passwd pwd;
	char pstrs[512];

	if (getpwuid_r(getuid(), &pwd, pstrs, sizeof(pstrs), &pw))
		return 1;
#else
	pw = getpwuid(getuid());
#endif

	if (strlen(certs_dir) >= 256 || !pw)
		return 1;

	lws_json_purify(ew, work, (int)sizeof(ew), NULL);
	lws_json_purify(ec, certs_dir, (int)sizeof(ec), NULL);

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
		"      \"stub-user\": \"%s\",\n"
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
		"}, {\n"
		"  \"name\": \"node1-svc\",\n"
		"  \"port\": \"-2\",\n"
		"  \"host-ssl-cert\": \"%s/install/node1/fullchain.pem\",\n"
		"  \"host-ssl-key\": \"%s/install/node1/privkey.pem\",\n"
		"  \"ignore-missing-cert\": \"1\"\n"
		"}]}\n",
		port, ec, ec, ec, ew, ew, ew, ew, pw->pw_name, url, ec, ec, ec,
		ec, ec, ec, ec, ew, ew);

	lws_snprintf(path, sizeof(path), "%s/conf.d/cert-dist", work);
	r = write_file(path, conf);
	free(conf);

	return r;
}

/*
 * The server side PKI: certs and keys for example.com and node1.example.com,
 * and the provisioning of node1.example.com (only) to receive its own
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

	if (mkdirs(dirs))
		return 1;

	/*
	 * Provision node1, by the server holding the very client cert it
	 * issued node1, and give the domain a cert of its own besides
	 * node1's
	 */
	return set_node1_issued("node1.crt") ||
	       publish_as(APEX_NAME, APEX_VER, 0, PUB_ALL) ||
	       publish(0, 0, PUB_ALL);
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
	const char *p, *server = "localhost";
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
	 * for the stub socket paths in it to fit in a sockaddr_un; mkdtemp
	 * makes it unique and 0700, so the shared /tmp it sits in is safe
	 */
	lws_strncpy(work, "/tmp/lws-cd-XXXXXX", sizeof(work)); // NOSONAR
	if (!mkdtemp(work)) {
		lwsl_err("unable to create work dir\n");
		goto bail;
	}
	have_work = 1;

	if (load_versions() || write_pki() ||
	    write_config(certs, server, port)) {
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

	expect("every phase ran", done && phase == 7);

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
