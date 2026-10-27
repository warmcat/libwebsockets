/*
 * lws-api-test-iface-bind
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A server vhost given an iface listens only there, or not at all: never on
 * the wildcard address, even when the process is out of fds while the vhost
 * comes up.  Looking up an interface (getifaddrs()) needs an fd itself, so
 * running out of them at the wrong moment must not read as "the interface is
 * usable" with no address filled in.
 *
 *  - numeric: iface "127.0.0.1" with exactly one fd free, which the listen
 *    socket takes, so looking up the interfaces at bind time fails.  A
 *    numeric address needs no interface list: it must listen on 127.0.0.1.
 *
 *  - name (linux): iface "lo" the same way.  Without the interface list
 *    there's no address for it: the vhost must either not come up, or listen
 *    on 127.0.0.1, never on 0.0.0.0.
 *
 *  - deferred: iface "127.0.0.1" with no fd free at all, so its listen
 *    socket() fails.  The vhost must be retried by the periodic check, and
 *    still be retried after its first retry's socket() fails too (by fault
 *    injection), listening once an fd is available.
 *
 * Fault injection shortens the periodic check from 30s to 200ms.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IFB_NOFILE		128	/* soft fd limit while we exhaust them */
#define IFB_TIMEOUT_S		5
#define IFB_POLL_US		(50 * LWS_US_PER_MS)

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_poll;
static struct lws_vhost *vh_deferred;
static int fill[IFB_NOFILE], fill_count, deferred_port, timed_out, failed;

static const struct lws_protocols protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Open fds until we hit the (lowered) limit, then give back \p spare of them,
 * the most recent first.  Returns the lowest fd given back, or -1 if none
 * were, or -2 on error.
 */

static int
ifb_exhaust_fds(int spare)
{
	int fd, last = -1;

	fill_count = 0;
	while (fill_count < (int)LWS_ARRAY_SIZE(fill)) {
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0) {
			if (errno == EMFILE)
				break;
			lwsl_err("%s: open: errno %d\n", __func__, errno);
			return -2;
		}
		fill[fill_count++] = fd;
	}

	if (fill_count == (int)LWS_ARRAY_SIZE(fill)) {
		lwsl_err("%s: never reached the fd limit\n", __func__);
		return -2;
	}

	while (spare-- && fill_count) {
		last = fill[--fill_count];
		close(last);
	}

	return last;
}

static void
ifb_release_fds(void)
{
	while (fill_count)
		close(fill[--fill_count]);
}

/*
 * What address the listen socket \p fd was bound to, checking it really is
 * the vhost's listen socket.  Returns 0 if it's on 127.0.0.1, 1 if anywhere
 * else, -1 if we can't tell.
 */

static int
ifb_check_bound(struct lws_vhost *vh, int fd)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	char ads[32];

	memset(&sin, 0, sizeof(sin));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) ||
	    sin.sin_family != AF_INET ||
	    ntohs(sin.sin_port) != lws_get_vhost_listen_port(vh)) {
		lwsl_err("%s: fd %d is not the vhost's listen socket\n",
			 __func__, fd);
		return -1;
	}

	inet_ntop(AF_INET, &sin.sin_addr, ads, sizeof(ads));
	lwsl_user("%s: listening on %s:%d\n", __func__, ads,
		  ntohs(sin.sin_port));

	return sin.sin_addr.s_addr != htonl(INADDR_LOOPBACK);
}

/* create a vhost for iface, port 0, with exactly one fd free */

static int
ifb_case_one_free(struct lws_context_creation_info *info, const char *name,
		  const char *iface, int may_fail)
{
	struct lws_vhost *vh;
	int fd, r;

	lwsl_user("=== %s: iface %s with one fd free ===\n", name, iface);

	info->vhost_name	= name;
	info->iface		= iface;
	info->port		= 0;

	fd = ifb_exhaust_fds(1);
	if (fd < 0) {
		ifb_release_fds();
		return 1;
	}

	vh = lws_create_vhost(context, info);
	if (!vh) {
		ifb_release_fds();
		if (may_fail) {
			lwsl_user("%s: PASS (the vhost did not come up)\n",
				  name);
			return 0;
		}
		lwsl_err("%s: FAIL: the vhost did not come up\n", name);
		return 1;
	}

	/* the only free fd was the one the listen socket took */
	r = ifb_check_bound(vh, fd);
	ifb_release_fds();

	lwsl_user("%s: %s\n", name, r ? "FAIL" : "PASS");

	return !!r;
}

/*
 * The deferred case listens once the periodic check retried it enough:
 * confirm a client can connect to it on 127.0.0.1
 */

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	struct sockaddr_in sin;
	int fd;

	if (lws_get_vhost_listen_port(vh_deferred) <= 0) {
		lws_sul_schedule(context, 0, &sul_poll, poll_cb, IFB_POLL_US);
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	sin.sin_port		= htons((uint16_t)
				lws_get_vhost_listen_port(vh_deferred));

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd >= 0 && !connect(fd, (struct sockaddr *)&sin, sizeof(sin)))
		deferred_port = lws_get_vhost_listen_port(vh_deferred);
	else
		lwsl_err("%s: can't connect to the deferred vhost\n", __func__);
	if (fd >= 0)
		close(fd);

	lws_default_loop_exit(context);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int result = 1, fd;
	struct rlimit rl;
	lws_fi_t fi;

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: a vhost iface out of fds\n");

	/* no captive portal detection: it'd use fds while we count them */
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_CPD_BYPASS;

	/* retry vhosts waiting on their iface every 200ms, not 30s */
	memset(&fi, 0, sizeof(fi));
	fi.name			= "plat_periodic_ms";
	fi.type			= LWSFI_RANGE;
	fi.pre			= 200;
	fi.count		= 201;
	if (lws_fi_add(&info.fic, &fi)) {
		lwsl_err("can't add the fault\n");
		return 1;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols		= protocols;

	/* a vhost with no listener first, so later ones aren't the first */
	info.vhost_name		= "cli";
	info.port		= CONTEXT_PORT_NO_LISTEN;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	/* let the context do what it does on its first service pass */
	lws_service(context, 0);

	/* few enough fds that we can use them all up */
	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		lwsl_err("getrlimit failed\n");
		goto bail;
	}
	if (rl.rlim_cur > IFB_NOFILE) {
		rl.rlim_cur = IFB_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &rl)) {
			lwsl_err("setrlimit failed\n");
			goto bail;
		}
	}

	/* the cases go on after a failure, so each can be seen */
	failed |= ifb_case_one_free(&info, "numeric", "127.0.0.1", 0);
#if defined(__linux__)
	failed |= ifb_case_one_free(&info, "name", "lo", 1);
#endif

	/*
	 * deferred: no fd free, so the listen socket() fails, then the first
	 * retry's socket() fails too (the second call to it, by the fault)
	 */

	lwsl_user("=== deferred: iface 127.0.0.1 with no fd free ===\n");

	memset(&fi, 0, sizeof(fi));
	fi.name			= "listenskt";
	fi.type			= LWSFI_DETERMINISTIC;
	fi.pre			= 1;
	fi.count		= 1;
	if (lws_fi_add(&info.fic, &fi)) {
		lwsl_err("can't add the fault\n");
		goto bail;
	}

	info.vhost_name		= "deferred";
	info.iface		= "127.0.0.1";
	info.port		= 0;

	fd = ifb_exhaust_fds(0);
	if (fd < -1) {
		ifb_release_fds();
		goto bail;
	}
	vh_deferred = lws_create_vhost(context, &info);
	ifb_release_fds();

	if (!vh_deferred) {
		lwsl_err("deferred: FAIL: the vhost was not created\n");
		goto bail;
	}
	if (lws_get_vhost_listen_port(vh_deferred) > 0) {
		lwsl_err("deferred: FAIL: listening with no fd for it\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 IFB_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_poll, poll_cb, IFB_POLL_US);

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out || !deferred_port) {
		lwsl_err("deferred: FAIL: no listener %s\n",
			 timed_out ? "inside the timeout" : "to connect to");
		goto bail;
	}
	lwsl_user("deferred: PASS (listening on port %d)\n", deferred_port);

	result = failed;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_poll);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", !result ? "PASS" : "FAIL");

	return result;
}
