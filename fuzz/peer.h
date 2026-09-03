/*
 * lws fuzzing peer helper
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Creates a real, adopted server-side connection over a socketpair so the
 * wsi-bound protocol parsers (h1, h2 + hpack, ws, ...) can be fuzzed through
 * their production state machines, without any event loop or network.
 *
 * A canned prelude is delivered first to get the connection into the target
 * protocol state (eg, a ws upgrade handshake, or an h2c upgrade plus the
 * h2 connection preface), then the fuzz input is delivered as if received
 * from the peer in two chunks.  Anything lws sends back is drained and
 * discarded, and the peer hangs up at the end so the close paths are
 * exercised as well.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

/* bounded service rounds per pump, so a wedged parser cannot spin forever */

#define FUZZ_PEER_ROUNDS 64

static struct lws_context *fuzz_peer_cx;
static struct lws_vhost  *fuzz_peer_vh;

/* used to make the final lws_service() pass non-blocking, see below */

static lws_sorted_usec_list_t fuzz_peer_sul;

static void
fuzz_peer_sul_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
}

static int
fuzz_peer_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	(void)wsi;
	(void)reason;
	(void)user;
	(void)in;
	(void)len;

	return 0;
}

static const struct lws_protocols fuzz_peer_protocols[] = {
	{ "lws-fuzz", fuzz_peer_cb, 0, 0, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static int
fuzz_peer_init(void)
{
	struct lws_context_creation_info info;

	signal(SIGPIPE, SIG_IGN);

	memset(&info, 0, sizeof(info));
	info.port      = CONTEXT_PORT_NO_LISTEN;
	info.protocols = fuzz_peer_protocols;

	fuzz_peer_cx = lws_create_context(&info);
	if (!fuzz_peer_cx)
		return 1;

	fuzz_peer_vh = lws_get_vhost_by_name(fuzz_peer_cx, "default");

	return fuzz_peer_vh ? 0 : 1;
}

static void
fuzz_peer_write_all(int fd, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = write(fd, buf, len);

		if (n > 0) {
			buf += n;
			len -= (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EAGAIN) {
			struct pollfd p = { .fd = fd, .events = POLLOUT };

			poll(&p, 1, 10);
			continue;
		}
		return;
	}
}

/*
 * Give lws service opportunities against the adopted socket and throw away
 * anything it sends, until it stops making progress or the round budget is
 * used up
 */

static void
fuzz_peer_pump(int lws_fd, int peer_fd)
{
	uint8_t scratch[4096];
	int n;

	for (n = 0; n < FUZZ_PEER_ROUNDS; n++) {
		struct pollfd p = { .fd = lws_fd, .events = POLLIN | POLLOUT };
		struct lws_pollfd lpfd;
		short r;

		if (poll(&p, 1, 0) <= 0)
			break;

		r = (short)(p.revents & (POLLIN | POLLOUT | POLLHUP));
		if (!r)
			break;

		lpfd.fd      = lws_fd;
		lpfd.events  = r;
		lpfd.revents = r;
		lws_service_fd(fuzz_peer_cx, &lpfd);

		/* discard any response bytes */

		while (read(peer_fd, scratch, sizeof(scratch)) > 0)
			;
	}
}

/*
 * One peer connection lifetime: adopt, prelude, fuzz input in two chunks,
 * then hang up and drive the lws close paths
 */

static void
fuzz_peer_session(const uint8_t *prelude, size_t prelude_len,
		  const uint8_t *in, size_t in_len)
{
	int fd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
		return;

	(void)fcntl(fd[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(fd[1], F_SETFL, O_NONBLOCK);

	if (!lws_adopt_socket_vhost(fuzz_peer_vh, fd[1])) {
		close(fd[0]);
		close(fd[1]);

		return;
	}

	/* from here lws owns fd[1] */

	if (prelude_len) {
		fuzz_peer_write_all(fd[0], prelude, prelude_len);
		fuzz_peer_pump(fd[1], fd[0]);
	}

	fuzz_peer_write_all(fd[0], in, in_len / 2);
	fuzz_peer_pump(fd[1], fd[0]);

	fuzz_peer_write_all(fd[0], in + in_len / 2, in_len - in_len / 2);
	fuzz_peer_pump(fd[1], fd[0]);

	/* the peer hangs up: drive the lws close path */

	close(fd[0]);
	fuzz_peer_pump(fd[1], fd[0]);

	/*
	 * Run any now-ripe suls (deferred closes etc) without waiting on
	 * later timers: our own immediately-due sul bounds lws_service()'s
	 * internal poll wait to ~zero
	 */

	lws_sul_schedule(fuzz_peer_cx, 0, &fuzz_peer_sul, fuzz_peer_sul_cb, 1);
	lws_service(fuzz_peer_cx, 0);
	lws_sul_cancel(&fuzz_peer_sul);
}
