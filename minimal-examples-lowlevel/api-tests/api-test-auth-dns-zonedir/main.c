/*
 * lws-api-test-auth-dns-zonedir
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain
 *
 * F-055 fence: the local zone-dir trust policy in protocol-lws-auth-dns.
 *
 * Everything the plugin loads from its zone dir is served as authoritative
 * data and its filename drives later unlinks in that dir, so the dir must
 * be exclusively controlled by the service uid.  The test plants zones the
 * pre-fix plugin happily served, and asserts they are now refused:
 *
 * | phase | arrangement | pre-fix behavior | post-fix behavior |
 * |-------|-------------|------------------|-------------------|
 * | 1 | service-owned dir + properly decorated zone file | served | served (control) |
 * | 2 | no "zone-dir" pvo at all | defaults to shared /tmp/lws-auth-dns and starts | protocol init refused, no listener |
 * | 3 | world-writable zone dir with planted zone | planted zone served | protocol init refused, no listener |
 * | 4 | zone-dir that is a symlink to a valid dir | followed, zone served | protocol init refused, no listener |
 * | 5 | good dir, but undecorated / short-suffix / group-writable / symlinked zone files | all loaded and served | only the properly shaped file loads, the rest answer REFUSED |
 * | 6 | (root only) zone file or dir owned by another uid | loaded / started | file ignored (REFUSED) / init refused |
 *
 * "No listener" is observed two ways: queries stay unanswered, and the UDP
 * port is bindable by the test itself afterwards (the plugin only creates
 * its UDP listeners once protocol init succeeded).
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TICK_US			(50 * LWS_US_PER_MS)
#define RESP_US			(2 * LWS_US_PER_SEC)  /* wait for expected replies */
#define QUIET_US		(700 * LWS_US_PER_MS)  /* prove silence */
#define DEADLINE_US		(8 * LWS_US_PER_SEC)

#define BASE_DIR		"zones-f055"

/* decorated filename fields: far-future ttl / sig expiry (2033), serial 1 */
#define DECOR			"_2000000000_2000000000_1.zone"

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;
static volatile int interrupted;

static int ports[2];
static int cli_fd = -1;
static struct sockaddr_in auth_sa;

static int test_ok = 1;
static int phase_idx, phase_done, phase_failed;

/* per-phase state */

struct qexp {
	const char	*name;
	uint16_t	id;
	int		expect_rcode;	/* -1: no response at all */
	int		expect_anc;
	int		got_rcode;
	int		got_anc;
	int		sent;
};

#define MAX_Q		5

struct phase {
	const char	*name;
	const char	*zdir;		/* NULL: no zone-dir pvo */
	int		check_port_free;
	struct qexp	q[MAX_Q];
};

static struct phase *cur;

static lws_sorted_usec_list_t sul_drive;
static lws_usec_t t0;

/* build a DNS query for "name" into buf, returning the packet length */

static size_t
mk_query(uint8_t *buf, size_t bufsize, uint16_t id, const char *name,
	 uint16_t qtype)
{
	const char *p = name;
	size_t o = 12;

	memset(buf, 0, bufsize >= 12 ? 12 : bufsize);
	buf[0] = (uint8_t)(id >> 8);
	buf[1] = (uint8_t)(id & 0xff);
	buf[2] = 0x01;			/* RD */
	buf[5] = 1;			/* QDCOUNT = 1 */

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		if (!l || l > 63 || o + 1 + l + 4 > bufsize)
			return 0;

		buf[o++] = (uint8_t)l;
		memcpy(&buf[o], p, l);
		o += l;

		p = dot ? dot + 1 : p + l;
	}
	buf[o++] = 0;			/* root */

	buf[o++] = (uint8_t)(qtype >> 8);
	buf[o++] = (uint8_t)(qtype & 0xff);
	buf[o++] = 0;			/* IN */
	buf[o++] = 1;

	return o;
}

/*
 * Fixture creation.  Everything lives under a per-run scratch dir so runs
 * as different uids cannot trip over each other's leftovers, and every
 * created object is chmod'd explicitly so the arrangement does not depend
 * on the process umask.
 */

static char run_dir[512];

static int
mk_zone_dir(const char *path, mode_t mode)
{
	struct stat st;

	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		lwsl_err("%s: mkdir %s failed errno %d\n", __func__, path,
				errno);
		return 1;
	}

	if (chmod(path, mode) == 0)
		return 0;

	/*
	 * chmod can fail on something another uid left behind; what matters
	 * is the effective mode is the one this phase needs
	 */
	if (stat(path, &st) == 0 && (st.st_mode & 07777) == mode)
		return 0;

	lwsl_err("%s: chmod %s to %o failed\n", __func__, path,
			(unsigned int)mode);

	return 1;
}

static int
write_zone(const char *dir, const char *fname, const char *origin,
	   const char *ip, mode_t mode)
{
	char path[1024], buf[2048];
	int fd, n;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, fname);
	n = lws_snprintf(buf, sizeof(buf),
			"$ORIGIN %s.\n"
			"$TTL 86400\n"
			"@	IN	SOA	ns1.%s. hostmaster.%s. (\n"
			"			2026090101 ; serial\n"
			"			3600 1800 604800 86400 )\n"
			"@	IN	NS	ns1.%s.\n"
			"www	IN	A	%s\n",
			origin, origin, origin, origin, ip);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		lwsl_err("%s: open %s failed\n", __func__, path);
		return 1;
	}
	n = (write(fd, buf, (size_t)n) == n);
	close(fd);

	if (!n || chmod(path, mode)) {
		lwsl_err("%s: write/chmod %s failed\n", __func__, path);
		return 1;
	}

	return 0;
}

static int
plant_fixtures(void)
{
	char dir[512], target[512], link[512];

	if (mk_zone_dir(BASE_DIR, 0755))
		return 1;

	/* the per-run scratch dir */

	if (mk_zone_dir(run_dir, 0755))
		return 1;

	/* phase 1: a clean, service-owned arrangement */

	lws_snprintf(dir, sizeof(dir), "%s/good", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "ok.example" DECOR, "ok.example", "127.0.0.77", 0644))
		return 1;

	/* phase 3: world-writable dir with a planted zone */

	lws_snprintf(dir, sizeof(dir), "%s/ww", run_dir);
	if (mk_zone_dir(dir, 0777) ||
	    write_zone(dir, "pwn.example" DECOR, "pwn.example", "127.0.0.66", 0644))
		return 1;

	/*
	 * phase 4: a valid arrangement reached through a symlinked zone-dir
	 * path
	 */

	lws_snprintf(dir, sizeof(dir), "%s/real", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "via.example" DECOR, "via.example", "127.0.0.65", 0644))
		return 1;

	lws_snprintf(link, sizeof(link), "%s/symlink", run_dir);
	unlink(link);
	if (symlink(dir, link)) {
		lwsl_err("%s: symlink %s failed errno %d\n", __func__, link,
				errno);
		return 1;
	}

	/*
	 * phase 5: good dir, but only one file of the lot is admissible
	 */

	lws_snprintf(dir, sizeof(dir), "%s/files", run_dir);
	if (mk_zone_dir(dir, 0700))
		return 1;

	if (write_zone(dir, "ok2.example" DECOR, "ok2.example", "127.0.0.77", 0644))
		return 1;

	/* undecorated name: valid content, foreign shape */
	if (write_zone(dir, "plain.example.zone", "plain.example", "127.0.0.66", 0644))
		return 1;

	/* only two numeric suffix fields */
	if (write_zone(dir, "short.example_2000000000_2000000000.zone",
			"short.example", "127.0.0.66", 0644))
		return 1;

	/* right shape and content, but group-writable */
	if (write_zone(dir, "badmode.example" DECOR, "badmode.example",
			"127.0.0.66", 0666))
		return 1;

	/* right shape, but a symlink to a valid zone file */
	lws_snprintf(target, sizeof(target), "%s/%s", dir, "ok2.example" DECOR);
	lws_snprintf(link, sizeof(link), "%s/linked.example" DECOR, dir);
	unlink(link);
	if (symlink(target, link)) {
		lwsl_err("%s: symlink %s failed errno %d\n", __func__, link,
				errno);
		return 1;
	}

	/*
	 * phases 6+7 (root only): another uid's file in an otherwise good
	 * dir, and another uid's dir
	 */

	lws_snprintf(dir, sizeof(dir), "%s/rootfile", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "okroot.example" DECOR, "okroot.example", "127.0.0.77", 0644) ||
	    write_zone(dir, "foreign.example" DECOR, "foreign.example", "127.0.0.66", 0644))
		return 1;

	lws_snprintf(dir, sizeof(dir), "%s/rootdir", run_dir);
	if (mk_zone_dir(dir, 0755) ||
	    write_zone(dir, "another.example" DECOR, "another.example", "127.0.0.66", 0644))
		return 1;

	if (!geteuid()) {
		char path[512];

		lws_snprintf(path, sizeof(path), "%s/rootfile/foreign.example" DECOR, run_dir);
		if (chown(path, 1, (gid_t)-1)) {
			lwsl_err("%s: chown %s failed\n", __func__, path);
			return 1;
		}

		if (chown(dir, 1, (gid_t)-1)) {
			lwsl_err("%s: chown rootdir failed\n", __func__);
			return 1;
		}
	}

	return 0;
}

/* best-effort removal of this run's scratch dir (known contents) */

static void
unplant_fixtures(void)
{
	static const char *const subdirs[] = {
		"good", "ww", "real", "files", "rootfile", "rootdir"
	};
	size_t i;

	for (i = 0; i < LWS_ARRAY_SIZE(subdirs); i++) {
		char dpath[600], fpath[768];

		lws_snprintf(dpath, sizeof(dpath), "%s/%s", run_dir, subdirs[i]);

		lws_snprintf(fpath, sizeof(fpath), "%s/symlink", run_dir);
		unlink(fpath);

		lws_snprintf(fpath, sizeof(fpath), "%s/ok.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/pwn.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/via.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/ok2.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/plain.example.zone", dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath),
				"%s/short.example_2000000000_2000000000.zone", dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/badmode.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/linked.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/okroot.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/foreign.example" DECOR, dpath);
		unlink(fpath);
		lws_snprintf(fpath, sizeof(fpath), "%s/another.example" DECOR, dpath);
		unlink(fpath);

		rmdir(dpath);
	}

	rmdir(run_dir);
}

static int
udp_port_free(int port)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return 0;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		close(fd);
		return 0;
	}

	close(fd);

	return 1;
}

static void
drive_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t now = lws_now_usecs();
	int n, still_waiting = 0, window;
	ssize_t r;
	uint8_t buf[2048];

	(void)sul;

	/* harvest any responses */

	do {
		struct qexp *q = NULL;
		int i;

		r = recv(cli_fd, buf, sizeof(buf), 0);
		if (r < 12)
			break;
		n = (int)r;

		for (i = 0; i < MAX_Q; i++) {
			if (!cur->q[i].name)
				break;
			if (cur->q[i].id == (uint16_t)((buf[0] << 8) | buf[1])) {
				q = &cur->q[i];
				break;
			}
		}

		if (!q) {
			lwsl_err("%s: stray packet id %02x%02x\n", __func__,
					buf[0], buf[1]);
			phase_failed = 1;
			phase_done = 1;
			return;
		}

		if (!(buf[2] & 0x80)) {
			lwsl_err("%s: not a response\n", __func__);
			phase_failed = 1;
			phase_done = 1;
			return;
		}

		q->got_rcode = buf[3] & 0xf;
		q->got_anc = (buf[6] << 8) | buf[7];
	} while (1);

	/* first tick after the listeners should be up: send the queries */

	if (!phase_failed && !cur->q[0].sent) {
		for (n = 0; n < MAX_Q && cur->q[n].name; n++) {
			size_t ql = mk_query(buf, sizeof(buf), cur->q[n].id,
					     cur->q[n].name,
					     LWS_ADNS_RECORD_A);

			if (!ql ||
			    sendto(cli_fd, buf, ql, 0,
				   (struct sockaddr *)&auth_sa,
				   sizeof(auth_sa)) < 0) {
				lwsl_err("%s: query %d sendto failed errno %d\n",
						__func__, n, errno);
				phase_failed = 1;
				break;
			}
			cur->q[n].sent = 1;
		}
		if (phase_failed) {
			phase_done = 1;
			return;
		}

		lwsl_user("phase '%s': %d queries sent\n", cur->name, n);
	}

	for (n = 0; n < MAX_Q && cur->q[n].name; n++) {
		if (cur->q[n].expect_rcode < 0) {
			/* no response must ever arrive for this one */
			if (cur->q[n].got_rcode != -1)
				continue; /* handled as failure below */
		} else if (cur->q[n].got_rcode != cur->q[n].expect_rcode ||
			   cur->q[n].got_anc < cur->q[n].expect_anc)
			still_waiting++;
	}

	window = still_waiting ? RESP_US : QUIET_US;

	if (now - t0 >= (lws_usec_t)window || now - t0 >= DEADLINE_US) {
		int i;

		for (i = 0; i < MAX_Q && cur->q[i].name; i++) {
			if (cur->q[i].expect_rcode < 0) {
				if (cur->q[i].got_rcode != -1) {
					lwsl_err("phase '%s': FAIL %s was "
						 "answered (rcode %d)\n",
						 cur->name, cur->q[i].name,
						 cur->q[i].got_rcode);
					phase_failed = 1;
				} else
					lwsl_user("phase '%s': %s stayed "
						  "unanswered\n", cur->name,
						  cur->q[i].name);
				continue;
			}
			if (cur->q[i].got_rcode != cur->q[i].expect_rcode ||
			    cur->q[i].got_anc < cur->q[i].expect_anc) {
				lwsl_err("phase '%s': FAIL %s rcode %d/%d "
					 "anc %d/%d\n", cur->name,
					 cur->q[i].name,
					 cur->q[i].got_rcode,
					 cur->q[i].expect_rcode,
					 cur->q[i].got_anc,
					 cur->q[i].expect_anc);
				phase_failed = 1;
			} else
				lwsl_user("phase '%s': %s rcode %d anc %d "
					  "ok\n", cur->name,
					  cur->q[i].name,
					  cur->q[i].got_rcode,
					  cur->q[i].got_anc);
		}

		if (cur->check_port_free && !udp_port_free(ports[phase_idx & 1])) {
			lwsl_err("phase '%s': FAIL udp port %d is still bound, "
				 "protocol init did not refuse\n", cur->name,
				 ports[phase_idx & 1]);
			phase_failed = 1;
		}

		phase_done = 1;

		return;
	}

	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);
}

static void
sigint_handler(int sig)
{
	(void)sig;

	interrupted = 1;
}

static int
run_phase(struct phase *p, int idx)
{
	struct lws_context_creation_info info;
	const struct lws_protocols my_protocols[] = {
		lws_auth_dns_protocols[0],
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
	struct lws_protocol_vhost_options pvo_extra = {
		NULL, NULL, "cache-max-zones", "499"
	};
	struct lws_protocol_vhost_options pvo_zonedir = {
		NULL, NULL, "zone-dir", ""
	};
	struct lws_protocol_vhost_options pvo = {
		NULL, NULL, "protocol-lws-auth-dns", ""
	};
	char zd[512];
	int n = 0;

	cur = p;
	phase_idx = idx;
	phase_done = phase_failed = 0;
	t0 = lws_now_usecs();

	/* discard anything left over from the previous phase */

	{
		uint8_t dbuf[2048];

		while (recv(cli_fd, dbuf, sizeof(dbuf), 0) >= 0)
			;
	}

	lws_context_info_defaults(&info, NULL);
	info.port = ports[idx & 1];
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";
	info.protocols = my_protocols;

	if (p->zdir) {
		lws_snprintf(zd, sizeof(zd), "%s/%s", run_dir, p->zdir);
		pvo_zonedir.value = zd;
		pvo.options = &pvo_zonedir;
	} else
		/*
		 * some pvo content is needed so the plugin actually runs its
		 * init refusal path rather than the !in early exit
		 */
		pvo.options = &pvo_extra;
	info.pvo = &pvo;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("phase '%s': lws init failed\n", p->name);
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);

	while (n >= 0 && !phase_done && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	context = NULL;

	if (phase_failed)
		test_ok = 0;

	return phase_failed;
}

int
main(int argc, const char **argv)
{
	struct phase tbl[] = {
		{
			.name		= "good dir serves decorated zone",
			.zdir		= "good",
			.q		= {
				{ "www.ok.example", 0x1101, 0, 1, -1, -1, 0 },
			}
		}, {
			.name		= "missing zone-dir pvo refused",
			.zdir		= NULL,
			.check_port_free = 1,
			.q		= {
				{ "www.any.example", 0x1102, -1, 0, -1, -1, 0 },
			}
		}, {
			.name		= "world-writable zone dir refused",
			.zdir		= "ww",
			.check_port_free = 1,
			.q		= {
				{ "www.pwn.example", 0x1103, -1, 0, -1, -1, 0 },
			}
		}, {
			.name		= "symlinked zone dir refused",
			.zdir		= "symlink",
			.check_port_free = 1,
			.q		= {
				{ "www.via.example", 0x1104, -1, 0, -1, -1, 0 },
			}
		}, {
			.name		= "foreign files in good dir ignored",
			.zdir		= "files",
			.q		= {
				{ "www.ok2.example", 0x1105, 0, 1, -1, -1, 0 },
				{ "www.plain.example", 0x2105, 5, 0, -1, -1, 0 },
				{ "www.short.example", 0x3105, 5, 0, -1, -1, 0 },
				{ "www.badmode.example", 0x4105, 5, 0, -1, -1, 0 },
				{ "www.linked.example", 0x5105, 5, 0, -1, -1, 0 },
			}
		}, {
			.name		= "another uid's file ignored",
			.zdir		= "rootfile",
			.q		= {
				{ "www.okroot.example", 0x1106, 0, 1, -1, -1, 0 },
				{ "www.foreign.example", 0x2106, 5, 0, -1, -1, 0 },
			}
		}, {
			.name		= "another uid's zone dir refused",
			.zdir		= "rootdir",
			.check_port_free = 1,
			.q		= {
				{ "www.another.example", 0x1107, -1, 0, -1, -1, 0 },
			}
		},
	};
	int nph = 5, i, ret;
	const char *p;

	signal(SIGINT, sigint_handler);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-p"))) {
		ports[0] = atoi(p);
		if (ports[0] <= 0 || ports[0] > 65535) {
			lwsl_err("Bad port %s\n", p);
			return 1;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, "-b"))) {
		ports[1] = atoi(p);
		if (ports[1] <= 0 || ports[1] > 65535) {
			lwsl_err("Bad port %s\n", p);
			return 1;
		}
	}

	if (!ports[0] || !ports[1]) {
		lwsl_err("usage: %s -p <auth dns port a> -b <auth dns port b>\n",
				argv[0]);
		return 1;
	}

	if (geteuid())
		lwsl_user("not running as root: uid-based phases skipped\n");
	else
		nph = (int)LWS_ARRAY_SIZE(tbl);

	lws_snprintf(run_dir, sizeof(run_dir), "%s/%d", BASE_DIR,
			(int)getpid());

	if (plant_fixtures()) {
		lwsl_err("fixture planting failed\n");
		return 1;
	}

	cli_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cli_fd < 0) {
		lwsl_err("client socket failed\n");
		unplant_fixtures();
		return 1;
	}
	fcntl(cli_fd, F_SETFL, O_NONBLOCK);

	lwsl_user("LWS API selftest: auth dns zone dir trust (F-055)\n");

	for (i = 0; i < nph && !interrupted; i++) {
		lwsl_user("--- phase %d: %s\n", i + 1, tbl[i].name);

		memset(&auth_sa, 0, sizeof(auth_sa));
		auth_sa.sin_family = AF_INET;
		auth_sa.sin_port = htons((uint16_t)ports[i & 1]);
		auth_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (run_phase(&tbl[i], i)) {
			lwsl_err("phase %d (%s) FAILED\n", i + 1, tbl[i].name);
			break;
		}
	}

	ret = i != nph || interrupted;

	lwsl_user("Completed: %s\n", test_ok && !ret ? "PASS" : "FAIL");

	close(cli_fd);
	unplant_fixtures();

	return !test_ok || ret;
}
