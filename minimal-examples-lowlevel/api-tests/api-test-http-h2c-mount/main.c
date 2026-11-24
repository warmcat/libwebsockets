/*
 * lws-api-test-http-h2c-mount
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A mount with "no_ws_upgrades" is passed over for a websocket upgrade, so
 * that the upgrade lands in a mount that serves it.  An h1 request that
 * upgrades to h2c is not a websocket upgrade: it is an http request, served
 * on h2 stream 1, and it must land in the mount its path does, meeting that
 * mount's gates, as it would without the upgrade.
 *
 * The server has a public file mount at /, and inside its origin the origin
 * of a file mount at /private, behind a basic auth login file, and with
 * no_ws_upgrades.  If the h2c request were not given to /private, / would
 * serve the private file from its own origin, without asking for any
 * credentials.  A raw client in the same process makes the requests:
 *
 *  - /private/index.html, as plain h1 without credentials: 401
 *
 *  - the same, upgrading to h2c: 401, and the upgrade is not done
 *
 *  - the same, upgrading to h2c, with credentials: the private file, on
 *    stream 1, so h2c works here and the files are where we think
 *
 *  - /index.html, upgrading to h2c: the public file, on stream 1
 *
 *  - /index.html, upgrading to h2c, and once stream 1 has answered, on
 *    stream 3, /private/index.html without credentials, carrying
 *    "upgrade: websocket".  h2 has no such
 *    header (an h2 ws upgrade is an extended CONNECT), and it once made the
 *    request pass /private over as if it were a ws upgrade, so / served the
 *    private file with no credentials.  The request is malformed: the
 *    connection goes away, with no answer on stream 3.
 *
 * The files and the login file are made in the cwd, named with the process
 * id, and removed afterwards.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define PRIVATE_MARK	"lws-h2c-mount-private"
#define PUBLIC_MARK	"lws-h2c-mount-public"

/* test-user:test-password */
#define AUTH_HDR	"Authorization: Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=\r\n"
/* base64url of one setting, SETTINGS_MAX_CONCURRENT_STREAMS 100 */
#define H2C_HDRS	"Connection: Upgrade, HTTP2-Settings\r\n" \
			"Upgrade: h2c\r\n" \
			"HTTP2-Settings: AAMAAABk\r\n"

enum expect {
	EX_401,		/* refused 401, as h1 */
	EX_PRIVATE,	/* upgraded, and stream 1 is the private file */
	EX_PUBLIC,	/* upgraded, and stream 1 is the public file */
	EX_GOAWAY,	/* upgraded, and the connection ends with no answer
			 * on stream 3 */
};

static const struct hcase {
	const char	*name;
	const char	*path;
	const char	*extra;		/* more request headers */
	enum expect	expect;
} cases[] = {
	{ "h1, no credentials",	  "/private/index.html", "",	   EX_401 },
	{ "h2c, no credentials",  "/private/index.html", H2C_HDRS, EX_401 },
	{ "h2c, credentials",	  "/private/index.html", H2C_HDRS AUTH_HDR,
								   EX_PRIVATE },
	{ "h2c, public",	  "/index.html",	 H2C_HDRS, EX_PUBLIC },
	{ "h2, upgrade header",	  "/index.html",	 H2C_HDRS, EX_GOAWAY },
};

/*
 * HEADERS on stream 3, END_STREAM | END_HEADERS: GET /private/index.html,
 * with an "upgrade: websocket" field, in hpack literals without indexing
 */
static const uint8_t hdrs_upgrade[] = {
	0x00, 0x00, 53, 0x01, 0x05, 0x00, 0x00, 0x00, 0x03,
	0x82,					/* :method GET */
	0x86,					/* :scheme http */
	0x04, 19, '/', 'p', 'r', 'i', 'v', 'a', 't', 'e', '/',
		  'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
	0x01, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
	0x00, 7, 'u', 'p', 'g', 'r', 'a', 'd', 'e',
		 9, 'w', 'e', 'b', 's', 'o', 'c', 'k', 'e', 't',
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_timeout;
static const char *server_addr = "127.0.0.1";
static char dir[64], dir_private[80], login_file[64], origin_private[96],
	    file_pub[96], file_priv[96];
static int port, cur = -1, failed;

/* what the client heard for the current case */
static struct {
	uint8_t		rx[8192];
	char		body[256];
	size_t		rx_len, pos, body_len;
	int		status;		/* the h1 status line's */
	int		upgraded;	/* sent the h2 preface */
	int		ended;		/* stream 1 ended */
	int		goaway;		/* 1 + the GOAWAY's error code */
	int		s3;		/* stream 3 had an answer */
	struct lws	*wsi;
	int		done;
} cli;

static struct lws_http_mount mount_private = {
	.mountpoint		= "/private",
	.def			= "index.html",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 8,
	.no_ws_upgrades		= 1,
};

static struct lws_http_mount mount = {
	.mount_next		= &mount_private,
	.mountpoint		= "/",
	.def			= "index.html",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

static void
next_case(lws_sorted_usec_list_t *sul);

/* the current case's connection has told us all it will */

static void
case_judge(void)
{
	const struct hcase *c = &cases[cur];
	int priv, pub, ok = 0;

	if (cli.done)
		return;
	cli.done = 1;

	priv = !!strstr(cli.body, PRIVATE_MARK);
	pub = !!strstr(cli.body, PUBLIC_MARK);

	switch (c->expect) {
	case EX_GOAWAY:
		/*
		 * If the GOAWAY made it before the close, it says
		 * PROTOCOL_ERROR; either way, nothing on stream 3
		 */
		ok = cli.upgraded == 3 && !cli.s3 && !priv &&
		     (!cli.goaway || cli.goaway == 1 + 1);
		break;
	case EX_401:
		ok = !cli.upgraded && cli.status == 401;
		break;
	case EX_PRIVATE:
		ok = cli.upgraded && cli.ended && priv;
		break;
	case EX_PUBLIC:
		ok = cli.upgraded && cli.ended && pub && !priv;
		break;
	}

	lwsl_user("--- case %d \"%s\" %s: %s (status %d, upgraded %d, "
		  "stream 1 %s, goaway %d, stream 3 %s, %s) ---\n", cur,
		  c->name, c->path, ok ? "PASS" : "FAIL", cli.status,
		  cli.upgraded, cli.ended ? "ended" : "did not end",
		  cli.goaway - 1, cli.s3 ? "answered" : "not answered",
		  priv ? "PRIVATE FILE SERVED" : (pub ? "public file" :
							"no file"));
	if (!ok)
		failed = 1;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

/*
 * Until the upgrade, the response is h1: anything but a 101 is the answer.
 * After it, we only follow stream 1's frames, keeping its DATA.
 */

static void
cli_parse(void)
{
	const uint8_t *f;
	size_t flen;
	uint32_t sid;
	char *e;

	if (!cli.pos) {
		cli.rx[cli.rx_len] = '\0';
		e = strstr((char *)cli.rx, "\r\n\r\n");
		if (!e)
			return; /* the rest of the response headers to come */
		if (strncmp((char *)cli.rx, "HTTP/1.1 ", 9)) {
			case_judge();
			return;
		}
		cli.status = atoi((char *)cli.rx + 9);
		if (cli.status != 101) {
			case_judge();
			return;
		}
		cli.pos = lws_ptr_diff_size_t(e + 4, (char *)cli.rx);
	}

	while (cli.rx_len - cli.pos >= 9) {
		f = cli.rx + cli.pos;
		flen = ((size_t)f[0] << 16) | ((size_t)f[1] << 8) | f[2];
		if (cli.rx_len - cli.pos < 9 + flen)
			return; /* the rest of the frame to come */
		sid = lws_ser_ru32be(f + 5) & 0x7fffffff;

		if ((sid == 1 || sid == 3) && !f[3] && flen) { /* DATA */
			if (flen > sizeof(cli.body) - 1 - cli.body_len)
				flen = sizeof(cli.body) - 1 - cli.body_len;
			memcpy(cli.body + cli.body_len, f + 9, flen);
			cli.body_len += flen;
			cli.body[cli.body_len] = '\0';
		}
		cli.pos += 9 + (((size_t)f[0] << 16) | ((size_t)f[1] << 8) |
				f[2]);

		if (f[3] == 7 && flen >= 8) {
			cli.goaway = 1 + (int)lws_ser_ru32be(f + 9 + 4);
			case_judge();
			return;
		}

		if (cases[cur].expect == EX_GOAWAY) {
			/* stream 1 answered: now ask on stream 3 */
			if (sid == 1 && f[3] <= 1 && (f[4] & 1)) {
				cli.ended = 1;
				lws_callback_on_writable(cli.wsi);
			}
			/* stream 3 is what is judged: any answer is a FAIL */
			if (sid == 3 && f[3] <= 1)
				cli.s3 = 1;
			if (sid == 3 && ((f[3] <= 1 && (f[4] & 1)) ||
					 f[3] == 3)) {
				case_judge();
				return;
			}
			continue;
		}

		/* DATA or HEADERS with END_STREAM, or RST_STREAM */
		if ((sid == 1 && f[3] <= 1 && (f[4] & 1)) ||
		    (sid == 1 && f[3] == 3)) {
			cli.ended = sid == 1 && f[3] <= 1;
			case_judge();
			return;
		}
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	/* the h2 preface, and our SETTINGS, with none in it */
	static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
				      "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
	uint8_t buf[LWS_PRE + 1024];
	char *start = (char *)buf + LWS_PRE;
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error\n", __func__);
		case_judge();
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		cli.wsi = wsi;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (cli.upgraded == 1) {
			/* after the 101, the h2 connection starts with us */
			if (lws_write(wsi, (uint8_t *)preface,
				      sizeof(preface) - 1, LWS_WRITE_RAW) !=
						(int)sizeof(preface) - 1)
				return -1;
			cli.upgraded = 2;
			break;
		}

		if (cli.upgraded == 2) {
			if (!cli.ended)
				break;
			memcpy(start, hdrs_upgrade, sizeof(hdrs_upgrade));
			if (lws_write(wsi, (uint8_t *)start,
				      sizeof(hdrs_upgrade), LWS_WRITE_RAW) !=
						(int)sizeof(hdrs_upgrade))
				return -1;
			cli.upgraded = 3;
			break;
		}

		n = lws_snprintf(start, sizeof(buf) - LWS_PRE,
				 "GET %s HTTP/1.1\r\n"
				 "Host: localhost\r\n"
				 "%s\r\n", cases[cur].path, cases[cur].extra);
		if (lws_write(wsi, (uint8_t *)start, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (cli.done)
			break;
		if (len > sizeof(cli.rx) - 1 - cli.rx_len) {
			lwsl_err("%s: too much rx\n", __func__);
			case_judge();
			return -1;
		}
		memcpy(cli.rx + cli.rx_len, in, len);
		cli.rx_len += len;
		cli_parse();
		if (!cli.done && cli.status == 101 && !cli.upgraded) {
			cli.upgraded = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		case_judge();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "h2cm-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		lws_default_loop_exit(context);
		return;
	}

	memset(&cli, 0, sizeof(cli));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= "h2cm-cli";

	if (!lws_client_connect_via_info(&i))
		/* it told us with CLIENT_CONNECTION_ERROR */
		case_judge();
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in case %d ---\n", cur);
	failed = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_default_loop_exit(context);
}

static int
write_file(const char *path, const char *content)
{
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600), r;

	if (fd < 0)
		return 1;
	r = write(fd, content, strlen(content)) != (ssize_t)strlen(content);
	close(fd);

	return r;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: an h2c upgrade lands in its path's mount\n");

	/* the files and the login file, in the cwd, named for us */

	lws_snprintf(dir, sizeof(dir), "h2cm-%d", (int)getpid());
	lws_snprintf(dir_private, sizeof(dir_private), "%s/private", dir);
	lws_snprintf(origin_private, sizeof(origin_private), "./%s",
		     dir_private);
	lws_snprintf(file_pub, sizeof(file_pub), "%s/index.html", dir);
	lws_snprintf(file_priv, sizeof(file_priv), "%s/index.html",
		     dir_private);
	lws_snprintf(login_file, sizeof(login_file), "h2cm-%d.txt",
		     (int)getpid());

	if (mkdir(dir, 0700) || mkdir(dir_private, 0700) ||
	    write_file(file_pub, PUBLIC_MARK "\n") ||
	    write_file(file_priv, PRIVATE_MARK "\n") ||
	    write_file(login_file, "test-user:test-password\n")) {
		lwsl_err("can't make the test files\n");
		failed = 1;
		goto bail_files;
	}

	mount.origin			= dir;
	mount_private.origin		= origin_private;
	mount_private.basic_auth_login_file = login_file;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		failed = 1;
		goto bail_files;
	}

	/* the server, plaintext h1, which may upgrade to h2c */

	info.port		= 0;
	info.vhost_name		= "srv";
	info.protocols		= protocols_srv;
	info.mounts		= &mount;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}
	port = lws_get_vhost_listen_port(vh);

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;
	info.mounts		= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	if (cur != (int)LWS_ARRAY_SIZE(cases))
		failed = 1;

	goto bail_files;

bail:
	failed = 1;
	lws_context_destroy(context);
bail_files:
	unlink(login_file);
	unlink(file_priv);
	unlink(file_pub);
	rmdir(dir_private);
	rmdir(dir);

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
