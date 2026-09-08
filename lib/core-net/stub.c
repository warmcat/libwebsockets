/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * lws_stub - generalized API for spawning and communicating with root stubs
 * via UDS and JSON-RPC
 */

#include "private-lib-core.h"
#include <string.h>

#if defined(LWS_STUB_AUTONOMOUS_EXIT)
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#if defined(LWS_HAVE_GETPPID) && defined(LWS_HAVE_SIGACTION)
/*
 * The spawned stub process can detect by itself that the parent process
 * which spawned it has died, clean up its UDS socket and exit, rather than
 * lingering on uselessly.  It needs getppid() to notice it was re-parented
 * because the original parent died, and sigaction() to convert the linux
 * PR_SET_PDEATHSIG SIGTERM (armed by lws_spawn_piped()) into an orderly
 * exit instead of an abrupt default-disposition death.
 */
#define LWS_STUB_AUTONOMOUS_EXIT
#endif

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#if defined(LWS_WITH_CLIENT)
struct lws_stub_req {
	struct lws_dll2			list;
	char				*tx_buf;
	size_t				tx_len;
	size_t				tx_pos;
	struct lejp_ctx			jctx;
	signed char			(*rx_cb)(struct lejp_ctx *ctx, char reason);
	void				(*raw_cb)(const char *in, size_t len, void *user);
	void				*user;
	lws_stub_req_h			h;
	uint8_t				awaits_reply;	/* jctx is constructed */
};

struct lws_stub_manager {
	struct lws_context		*cx;
	struct lws_vhost		*vh;
	struct lws_vhost		*vh_client;
	char				uds_path[256];
	char				stub_name[128];
	char				secret[129];
	struct lws_spawn_piped		*lsp;
	struct lws_stub_config		config;

	struct lws_dll2			cx_list; /* cx->owner_stub_mgrs */

	const struct lws_protocols	*protocols;

	struct lws			*wsi_client;
	struct lws_dll2_owner		reqs;
	lws_stub_req_h			next_h;	/* last handle we issued */

	lws_sorted_usec_list_t		sul;
	uint16_t			ctry;
	char				stub_arg[128];
	const char			*exec_array[5];
	char				addr[256];
	char				exe_path[256];
};

static int
lws_stub_client_connect(struct lws_stub_manager *mgr);

/*
 * Parser for the reply to a request that has no rx_cb of its own.  It exists
 * only so that lejp tells us when the JSON reply completed: that is the only
 * framing a reply has, and without it a raw request would sit at the head of
 * the queue forever and block every request queued behind it.
 */
static signed char
lws_stub_reply_done_cb(struct lejp_ctx *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return 0;
}

/*
 * Tell the owner his request is over, exactly once however it ended, and stop
 * pointing at anything of his afterwards.
 *
 * The request itself may live on after this (a cancelled request that is
 * already on the wire has to stay at the head of the queue until its reply
 * has been consumed, since replies are matched to requests positionally).
 */
static void
lws_stub_req_detach(struct lws_stub_req *req)
{
	if (req->awaits_reply) {
		/*
		 * Swap his parser callback for our do-nothing one, keeping
		 * the parse position so a reply that is already half-consumed
		 * still ends where it really ends.  That issues his
		 * LEJPCB_DESTRUCTED, and neither his callback, his user
		 * pointer nor his paths are touched again after it.
		 */
		lejp_change_callback(&req->jctx, lws_stub_reply_done_cb);
		req->jctx.user = NULL;
		req->jctx.pst[0].paths = NULL;
		req->jctx.pst[0].count_paths = 0;
	}

	if (req->raw_cb)
		/* the raw request's equivalent of LEJPCB_DESTRUCTED */
		req->raw_cb(NULL, 0, req->user);

	req->rx_cb	= NULL;
	req->raw_cb	= NULL;
	req->user	= NULL;
	req->h		= 0;
}

/*
 * Retire a request: it is off the queue and gone after this, whether it was
 * answered, abandoned or cancelled.
 */
static void
lws_stub_req_retire(struct lws_stub_req *req)
{
	lws_dll2_remove(&req->list);
	lws_stub_req_detach(req);

	if (req->awaits_reply)
		lejp_destruct(&req->jctx);

	if (req->tx_buf) {
		/*
		 * Every request carries the stub secret, and some of them a
		 * private key: do not leave it lying in the heap
		 */
		lws_explicit_bzero(req->tx_buf, req->tx_len + LWS_PRE + 1);
		lws_free(req->tx_buf);
	}

	lws_free(req);
}

/*
 * The stub client connection is made on its own private, no-listen vhost,
 * with this as the vhost's protocols[0].  This has two effects:
 *
 *  - the client wsi protocol binding to "lws-stub-client" cannot fail
 *    because the caller's vhost lacks it, which would misroute all the
 *    client wsi callbacks elsewhere, and
 *
 *  - wsi destroy notifications are delivered to the vhost protocols[0],
 *    ie, to lws_callback_stub_client, even for wsi that never established
 *    and even when the context is being destroyed and other callbacks are
 *    suppressed.  That is how we reliably learn our wsi was freed, so we
 *    can stop holding a stale pointer to it.
 */
static const struct lws_protocols stub_client_protocols[] = {
	{
		.name			= "lws-stub-client",
		.callback		= lws_callback_stub_client,
		.per_session_data_size	= 0,
		.rx_buffer_size		= 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};

struct lws_stub_manager *
lws_stub_spawn(const struct lws_stub_config *config)
{
	struct lws_stub_manager *mgr;
	struct lws_spawn_piped_info spawn_info;
	int n = 0;
	uint8_t rand[64];

	if (!config->parent_protocol_name) {
		lwsl_err("%s: stub '%s': parent_protocol_name is required, "
			 "the stub stdio pipes need a protocol that "
			 "drains them\n", __func__,
			 config->stub_name ? config->stub_name : "?");

		return NULL;
	}

	mgr = lws_zalloc(sizeof(*mgr), "stub_mgr");
	if (!mgr)
		return NULL;

	mgr->cx = config->cx;
	mgr->vh = config->vh;
	memcpy(&mgr->config, config, sizeof(mgr->config));
	if (config->uds_path)
		lws_strncpy(mgr->uds_path, config->uds_path, sizeof(mgr->uds_path));
	mgr->config.uds_path = mgr->uds_path;
	if (config->stub_name)
		lws_strncpy(mgr->stub_name, config->stub_name, sizeof(mgr->stub_name));
	mgr->config.stub_name = mgr->stub_name;
	mgr->protocols = config->protocols;

	/*
	 * track the mgr on the context, so a stub can never outlive either
	 * the context or the vhost it was spawned on, even if the caller
	 * never gets a PROTOCOL_DESTROY to destroy it from (eg, in a
	 * plugins build, his vhost protocol was never instantiated)
	 */
	lws_dll2_add_tail(&mgr->cx_list, &config->cx->owner_stub_mgrs);

	/*
	 * Generate a secure 128-char secret.  It is the only thing that
	 * authenticates a request to the privileged stub, so a short or failed
	 * RNG read must fail the spawn rather than hex-encode whatever was on
	 * the stack.
	 */
	if (lws_get_random(mgr->cx, rand, sizeof(rand)) != sizeof(rand)) {
		lwsl_vhost_err(mgr->vh, "%s: stub '%s': unable to get %u "
			       "random bytes for the stub secret\n", __func__,
			       config->stub_name ? config->stub_name : "?",
			       (unsigned int)sizeof(rand));
		lws_stub_destroy(&mgr);

		return NULL;
	}
	lws_hex_from_byte_array(rand, sizeof(rand), mgr->secret, sizeof(mgr->secret));
	lws_explicit_bzero(rand, sizeof(rand));

	memset(&spawn_info, 0, sizeof(spawn_info));
	const char *exe_path = "/usr/local/bin/lwsws";

#if defined(__APPLE__)
	{
		uint32_t size = sizeof(mgr->exe_path);
		if (_NSGetExecutablePath(mgr->exe_path, &size) == 0)
			exe_path = mgr->exe_path;
	}
#elif defined(__linux__)
	{
		int m = (int)readlink("/proc/self/exe", mgr->exe_path, sizeof(mgr->exe_path) - 1);
		if (m > 0) {
			mgr->exe_path[m] = '\0';
			exe_path = mgr->exe_path;
		}
	}
#elif defined(__FreeBSD__)
	{
		int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
		size_t cb = sizeof(mgr->exe_path);
		if (sysctl(mib, 4, mgr->exe_path, &cb, NULL, 0) == 0) {
			mgr->exe_path[cb] = '\0';
			exe_path = mgr->exe_path;
		}
	}
#elif defined(WIN32)
	{
		/*
		 * Windows has a first-class way to find our own executable
		 * path, independent of how we were invoked or whether the
		 * caller passed argc / argv into the context
		 */
		DWORD m = GetModuleFileNameA(NULL, mgr->exe_path,
					     sizeof(mgr->exe_path));

		if (m > 0 && m < sizeof(mgr->exe_path)) {
			mgr->exe_path[m] = '\0';
			exe_path = mgr->exe_path;
		} else {
			const char *argv0 = lws_cmdline_option_cx_argv0(mgr->cx);

			if (argv0)
				exe_path = argv0;
		}
	}
#else
	{
		const char *argv0 = lws_cmdline_option_cx_argv0(mgr->cx);
		if (argv0) {
			if (argv0[0] == '/') {
				lws_strncpy(mgr->exe_path, argv0, sizeof(mgr->exe_path));
				exe_path = mgr->exe_path;
			} else if (realpath(argv0, mgr->exe_path))
				exe_path = mgr->exe_path;
			else
				exe_path = argv0;
		}
	}
#endif

	mgr->exec_array[n++] = exe_path;
	lwsl_vhost_notice(mgr->vh, "%s: Spawning stub '%s' with exe: %s\n", __func__, config->stub_name, exe_path);
	/* Construct the stub argument dynamically */
	lws_snprintf(mgr->stub_arg, sizeof(mgr->stub_arg), "--lws-stub=%s", config->stub_name);
	mgr->exec_array[n++] = mgr->stub_arg;
	mgr->exec_array[n++] = NULL;

	spawn_info.exec_array = mgr->exec_array;
	spawn_info.vh = mgr->vh;
	spawn_info.opaque = mgr;
	if (config->parent_protocol_name)
		spawn_info.protocol_name = config->parent_protocol_name;

	mgr->lsp = lws_spawn_piped(&spawn_info);
	if (mgr->lsp) {
		lws_filefd_type stdin_fd = lws_spawn_get_fd_stdxxx(mgr->lsp, 0);
#if defined(WIN32)
		if (stdin_fd) {
			DWORD bw;
			if (!WriteFile(stdin_fd, mgr->secret, 128, &bw, NULL)) {
				lwsl_vhost_err(mgr->vh, "%s: stub '%s' failed writing secret to pipe\n", __func__, config->stub_name);
				goto spawn_fail;
			}
			if (config->extra_payload && config->extra_payload_len) {
				if (!WriteFile(stdin_fd, config->extra_payload, (DWORD)config->extra_payload_len, &bw, NULL)) {
					lwsl_vhost_err(mgr->vh, "%s: stub '%s' failed writing extra payload to pipe\n", __func__, config->stub_name);
					goto spawn_fail;
				}
			}
		} else {
			lwsl_vhost_err(mgr->vh, "%s: stub '%s' no stdin pipe available\n", __func__, config->stub_name);
			goto spawn_fail;
		}
#else
		if (stdin_fd >= 0) {
			if (write(stdin_fd, mgr->secret, 128) < 0) {
				lwsl_vhost_err(mgr->vh, "%s: stub '%s' failed writing secret to pipe\n", __func__, config->stub_name);
				goto spawn_fail;
			}
			if (config->extra_payload && config->extra_payload_len) {
				if (write(stdin_fd, config->extra_payload, (unsigned int)config->extra_payload_len) < 0) {
					lwsl_vhost_err(mgr->vh, "%s: stub '%s' failed writing extra payload to pipe\n", __func__, config->stub_name);
					goto spawn_fail;
				}
			}
		} else {
			lwsl_vhost_err(mgr->vh, "%s: stub '%s' no stdin pipe available\n", __func__, config->stub_name);
			goto spawn_fail;
		}
#endif
	} else {
		lwsl_vhost_err(mgr->vh, "%s: Failed to spawn stub '%s'\n", __func__, config->stub_name);
		lws_stub_destroy(&mgr);
		return NULL;
	}

	lwsl_vhost_notice(mgr->vh, "%s: Spawned stub '%s'\n", __func__, config->stub_name);

	{
		struct lws_context_creation_info ci;
		char name[192];

		memset(&ci, 0, sizeof(ci));
		ci.port		= CONTEXT_PORT_NO_LISTEN;
		ci.protocols	= stub_client_protocols;
		lws_snprintf(name, sizeof(name), "%s-client", mgr->stub_name);
		ci.vhost_name	= name;

		mgr->vh_client = lws_create_vhost(mgr->cx, &ci);
	}

	if (!mgr->vh_client) {
		lwsl_vhost_err(mgr->vh, "%s: stub '%s': failed to create client vhost\n",
			       __func__, config->stub_name);
		goto spawn_fail;
	}

	if (!lws_dll2_owner(&mgr->sul.list) && !mgr->wsi_client)
		lws_stub_client_connect(mgr);

	return mgr;

spawn_fail:
	lwsl_vhost_err(mgr->vh, "%s: Failed to initialize spawned stub '%s'\n", __func__, config->stub_name);
	lws_stub_destroy(&mgr);
	return NULL;
}
#endif

#if defined(LWS_STUB_AUTONOMOUS_EXIT)

/* how often we check if the parent process is still alive */
#define LWS_STUB_WATCHDOG_US (250 * LWS_US_PER_MS)

/*
 * Child-side state for the stub server vhost we created, used to detect the
 * death of the spawning parent process and exit autonomously.  The design is
 * one stub server per process (the child is exec'd with a single
 * --lws-stub=<name>), so a single instance is enough.
 */
static struct {
	struct lws_context	*cx;
	lws_sorted_usec_list_t	sul;
	char			uds_path[256];
	char			stub_name[128];
	void			(*parent_gone_cb)(void *user);
	void			*user;
	pid_t			ppid0;
	/* identity of the socket file we created, so at exit we only remove
	 * the file if it is still ours */
	dev_t			uds_dev;
	ino_t			uds_ino;
	char			have_uds_ino;
	char			inited;
} stub_child;

static volatile sig_atomic_t stub_child_sigterm;

static void
lws_stub_child_sigterm_cb(int sig)
{
	(void)sig;

	stub_child_sigterm = 1;
}

/*
 * Remove our UDS socket file, but only if it is still ours: if the socket
 * file at the path has a different inode (eg, a newer stub instance that has
 * already re-used the path, or our parent already removed it and something
 * else appeared there), we must not touch it.
 *
 * We hold a fd on the socket file's parent directory, and issue both the
 * identity check and the unlink against it using only the basename: the
 * path is not re-resolved between the check and the use, and symlinks at
 * the socket path are not followed when deciding.  POSIX can only unlink
 * by name, so a race on the basename inside the one directory is inherent;
 * the dev+ino comparison limits the damage of that to removing a socket
 * file we created ourselves.
 */
static void
lws_stub_child_unlink_own_uds(void)
{
	char dir[sizeof(stub_child.uds_path)];
	struct stat st;
	const char *base;
	char *slash;
	int dirfd;

	if (!stub_child.have_uds_ino)
		return;

	slash = strrchr(stub_child.uds_path, '/');
	base = slash ? slash + 1 : stub_child.uds_path;

	if (!*base)
		/* path has no basename (eg, it ends in '/'), not our socket */
		return;

	if (!slash) {
		/* bare filename in the current working directory */
		dirfd = AT_FDCWD;
	} else {
		size_t dn = (size_t)(slash - stub_child.uds_path);

		if (dn) {
			memcpy(dir, stub_child.uds_path, dn);
			dir[dn] = '\0';
		} else
			/* the socket file sits directly under "/" */
			dir[0] = '/', dir[1] = '\0';

		dirfd = lws_open(dir, O_RDONLY | O_DIRECTORY);
		if (dirfd < 0)
			/* cannot get at the directory, so cannot check */
			return;
	}

	/*
	 * Only unlink it if what is at the basename now is still the socket
	 * file we created, rather than a symlink or a replacement file
	 */
	if (!fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW) &&
	    st.st_dev == stub_child.uds_dev &&
	    st.st_ino == stub_child.uds_ino)
		unlinkat(dirfd, base, 0);

	if (slash)
		close(dirfd);
}

/*
 * Called from the service loop: if the parent that spawned us is gone, or we
 * accepted a SIGTERM that would otherwise have killed us abruptly, perform
 * the stub's final cleanup and exit the process.  Without the parent, the
 * stub process has no further reason to exist.
 */
static void
lws_stub_child_watchdog(lws_sorted_usec_list_t *sul)
{
	if (!stub_child_sigterm) {
		if (getppid() == stub_child.ppid0) {
			/* parent still alive, keep watching */
			lws_sul_schedule(stub_child.cx, 0, &stub_child.sul,
					 lws_stub_child_watchdog,
					 LWS_STUB_WATCHDOG_US);
			return;
		}
		lwsl_notice("%s: stub '%s': parent PID %d died, cleaning up "
			    "and exiting\n", __func__, stub_child.stub_name,
			    (int)stub_child.ppid0);
	} else
		lwsl_notice("%s: stub '%s': SIGTERM, cleaning up and "
			    "exiting\n", __func__, stub_child.stub_name);

	if (stub_child.parent_gone_cb)
		stub_child.parent_gone_cb(stub_child.user);

	lws_stub_child_unlink_own_uds();

	exit(0);
}

static void
lws_stub_child_watchdog_init(const struct lws_stub_config *config)
{
	struct sigaction sa_now, sa;
	struct stat st;

	if (stub_child.inited)
		lwsl_warn("%s: stub '%s': autonomous exit is already "
			  "tracking stub '%s', replacing it\n", __func__,
			  config->stub_name ? config->stub_name : "?",
			  stub_child.stub_name);

	/*
	 * Remember the current parent pid, so re-parenting (the kernel
	 * reparents us to init / a subreaper when the real parent dies)
	 * reliably tells us the spawning process has gone
	 */
	stub_child.cx		= config->cx;
	stub_child.ppid0	= getppid();
	stub_child.parent_gone_cb = config->parent_gone_cb;
	stub_child.user		= config->user;
	lws_strncpy(stub_child.uds_path, config->uds_path,
		    sizeof(stub_child.uds_path));
	lws_strncpy(stub_child.stub_name,
		    config->stub_name ? config->stub_name : "?",
		    sizeof(stub_child.stub_name));

	/*
	 * Record the identity of the socket file we just created, so at exit
	 * we only unlink it if it is still ours.  Comparing the path stat
	 * against the listener fd does not work for UDS: on linux they live
	 * in different filesystems (eg, tmpfs dirent vs sockfs).
	 */
	stub_child.have_uds_ino = !stat(config->uds_path, &st);
	if (stub_child.have_uds_ino) {
		stub_child.uds_dev = st.st_dev;
		stub_child.uds_ino = st.st_ino;
	} else
		lwsl_warn("%s: stub '%s': cannot identify our own UDS "
			  "socket file\n", __func__,
			  config->stub_name ? config->stub_name : "?");

	stub_child.inited	= 1;

	/*
	 * lws_spawn_piped() arms PR_SET_PDEATHSIG on linux, so parent death
	 * arrives as a SIGTERM that, with default disposition, would kill us
	 * abruptly with no chance to clean up.  If the application has not
	 * given SIGTERM its own handler, take it over so we can convert it
	 * into an orderly stub exit.  Applications that handle SIGTERM
	 * themselves are left completely in control.
	 */
	if (!sigaction(SIGTERM, NULL, &sa_now) &&
	    sa_now.sa_handler == SIG_DFL) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = lws_stub_child_sigterm_cb;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		sigaction(SIGTERM, &sa, NULL);
	}

	lws_sul_cancel(&stub_child.sul);
	lws_sul_schedule(stub_child.cx, 0, &stub_child.sul,
			 lws_stub_child_watchdog, LWS_STUB_WATCHDOG_US);
}
#endif /* LWS_STUB_AUTONOMOUS_EXIT */

int
lws_stub_server_init(const struct lws_stub_config *config, char *secret_out, void *extra_out, size_t extra_len)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh_uds;
#if !defined(WIN32)
	mode_t om;
#endif

	size_t rx = 0;

#if defined(WIN32)
	_setmode(0, _O_BINARY);
#endif

	/*
	 * 1. Read the secret from stdin.  It is exactly 128 chars and it is
	 *    compared against by length, so anything shorter is useless: a
	 *    partial read would otherwise leave the tail of the buffer
	 *    uninitialised inside the secret we compare with.
	 */
	memset(secret_out, 0, 129);

	while (rx < 128) {
		ssize_t n = read(0, (void *)(secret_out + rx), 128 - (unsigned int)rx);
		if (n <= 0)
			break;
		rx += (size_t)n;
	}

	if (rx != 128) {
		lwsl_err("%s: stub '%s': Failed to read secret from stdin\n", __func__, config->stub_name ? config->stub_name : "unknown");
		lws_explicit_bzero(secret_out, 129);

		return -1;
	}

	/* 1.5. Read extra payload if provided */
	if (extra_out && extra_len > 0) {
		/* We only do a single read here because the payload size is variable
		 * and unknown to the child, and the pipe remains open for future IPC. */
		ssize_t n = read(0, (void *)extra_out, (unsigned int)extra_len);
		if (n < 0) {
			lwsl_err("%s: stub '%s': Failed to read extra payload\n", __func__, config->stub_name ? config->stub_name : "unknown");
			/* Non-fatal */
		}
	}

	/* 2. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = config->uds_path;
	info.protocols = config->protocols;
	info.vhost_name = config->stub_name;
	info.user = config->user;

	/*
	 * Secure permissions: only the uid we run as may connect.
	 *
	 * bind() inside lws_create_vhost() creates the socket file with its
	 * mode masked by the process umask, so that is the only place the mode
	 * can be decided without a window where it is wrong: lws_daemonize()
	 * sets umask(0), which would create it world-connectable, and a
	 * chmod() afterwards both leaves that window open and resolves the
	 * path again (following any symlink a local user managed to put there
	 * in the meantime, with our privilege).  So bind under our own umask
	 * and do not chmod the path at all.
	 */
#if !defined(WIN32)
	om = umask(0077);
#endif

	unlink(info.iface);
	vh_uds = lws_create_vhost(config->cx, &info);

#if !defined(WIN32)
	umask(om);
#endif

	if (!vh_uds) {
		lwsl_err("%s: stub '%s': Failed to create UDS vhost\n", __func__, config->stub_name ? config->stub_name : "unknown");
		return -1;
	}

#if defined(LWS_STUB_AUTONOMOUS_EXIT)
	/*
	 * 4. Arm detection of the parent dying, so we clean up our UDS
	 *    socket and exit autonomously instead of lingering with no
	 *    parent to serve
	 */
	lws_stub_child_watchdog_init(config);
#endif

	/* Signal ready */
	lwsl_notice("STUB-READY (%s)\n", config->stub_name);

	return 0;
}

#if defined(LWS_WITH_CLIENT)
static const uint32_t backoff_ms[] = { 100, 250, 500, 1000, 5000 };

static const lws_retry_bo_t stub_retry = {
	.retry_ms_table			= backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(backoff_ms),
	.conceal_count			= 1000,
	.secs_since_valid_ping		= 300,
	.secs_since_valid_hangup	= 310,
	.jitter_percent			= 0,
};

static void
stub_retry_cb(lws_sorted_usec_list_t *sul);

#if (_LWS_ENABLED_LOGS & (LLL_NOTICE | LLL_ERR))
static int
lws_stub_child_is_alive(struct lws_stub_manager *mgr)
{
	if (!mgr || !mgr->lsp)
		return 0;

#if !defined(WIN32)
	if (mgr->lsp->child_pid <= 0)
		return 0;
	if (kill(mgr->lsp->child_pid, 0) == 0 || errno == EPERM)
		return 1;
	return 0;
#else
	return 1;
#endif
}
#endif

static int
lws_stub_client_connect(struct lws_stub_manager *mgr)
{
	struct lws_client_connect_info i;

	if (mgr->cx->being_destroyed)
		/* nobody will service anything we start from now on */
		return -1;

	memset(&i, 0, sizeof(i));
	i.context		= mgr->cx;
	i.vhost			= mgr->vh_client;

	/* UNIX domain socket addresses need a '+' prefix */
	lws_snprintf(mgr->addr, sizeof(mgr->addr), "+%s", mgr->uds_path);
	i.address		= mgr->addr;

	i.port			= 0;
	i.protocol		= "lws-stub-client";
	i.local_protocol_name	= "lws-stub-client";
	i.host			= NULL;
	i.origin		= NULL;
	i.opaque_user_data	= mgr;
	i.retry_and_idle_policy = &stub_retry;
	i.method		= "RAW"; /* RAW connection */

	lwsl_vhost_notice(mgr->vh, "%s: stub '%s', protocol %s, addr %s\n", __func__, mgr->config.stub_name, i.protocol, i.address);
	mgr->wsi_client = lws_client_connect_via_info(&i);
	if (!mgr->wsi_client) {
		if (mgr->ctry < 10) {
			uint32_t ms = stub_retry.retry_ms_table[
				mgr->ctry < stub_retry.retry_ms_table_count ?
				mgr->ctry : stub_retry.retry_ms_table_count - 1];
			mgr->ctry++;
			if (mgr->ctry > 1) {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
				int alive = lws_stub_child_is_alive(mgr);
				lwsl_vhost_notice(mgr->vh, "%s: stub '%s': Synchronous connect failed (errno %d), stub process %s (PID %d), retrying in %u ms (attempt %d)\n",
						  __func__, mgr->config.stub_name, LWS_ERRNO,
						  alive ? "is alive" : "has DIED/DOES NOT EXIST",
						  mgr->lsp ? (int)(intptr_t)mgr->lsp->child_pid : -1,
						  (unsigned int)ms, mgr->ctry);
#endif
			}
			lws_sul_schedule(mgr->cx, 0, &mgr->sul, stub_retry_cb, ms * 1000);
		}

		return -1;
	}

	return 0;
}

static void
stub_retry_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_stub_manager *mgr = lws_container_of(sul, struct lws_stub_manager, sul);

	if (!mgr->wsi_client)
		lws_stub_client_connect(mgr);
}

/*
 * The UDS connection went away.
 *
 * A request that already went (even partly) on the wire cannot be retried: we
 * do not know if the stub acted on it, and resuming a partial write on a new
 * connection would send the tail of one request as the start of a new one.
 * So retire it, telling its owner it is over.
 *
 * Requests that never reached the wire (only the queue head is ever written)
 * are untouched and go out on the reconnect.
 */
static void
lws_stub_conn_lost(struct lws_stub_manager *mgr)
{
	struct lws_dll2 *d = lws_dll2_get_head(&mgr->reqs);

	if (d) {
		struct lws_stub_req *req = lws_container_of(d,
						struct lws_stub_req, list);

		if (req->tx_pos) {
			lwsl_vhost_warn(mgr->vh, "%s: stub '%s': connection "
					"lost with a request in flight\n",
					__func__, mgr->config.stub_name);

			lws_stub_req_retire(req);
		}
	}

	if (lws_dll2_is_empty(&mgr->reqs) || mgr->cx->being_destroyed)
		return;

	/* there is still work queued: get the connection back */

	lws_retry_sul_schedule(mgr->cx, 0, &mgr->sul, &stub_retry,
			       stub_retry_cb, &mgr->ctry);
}

LWS_VISIBLE int
lws_callback_stub_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct lws_stub_manager *mgr = (struct lws_stub_manager *)lws_get_opaque_user_data(wsi);
	if (!mgr)
		return 0;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
#if (_LWS_ENABLED_LOGS & LLL_ERR)
		int alive = lws_stub_child_is_alive(mgr);
		lwsl_vhost_err(mgr->vh, "%s: stub '%s': Client connection failed (stub process %s, PID %d)\n",
			       __func__, mgr->config.stub_name,
			       alive ? "is alive" : "has DIED/DOES NOT EXIST",
			       mgr->lsp ? (int)(intptr_t)mgr->lsp->child_pid : -1);
#endif
		mgr->wsi_client = NULL;
		lws_retry_sul_schedule(mgr->cx, 0, &mgr->sul, &stub_retry, stub_retry_cb, &mgr->ctry);
		break;
	}

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_vhost_notice(mgr->vh, "%s: stub '%s': UDS connected\n", __func__, mgr->config.stub_name);
		mgr->ctry = 0; /* Reset retry counter on success */
		if (mgr->config.connected_cb)
			mgr->config.connected_cb(mgr);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		struct lws_dll2 *d = lws_dll2_get_head(&mgr->reqs);
		struct lws_stub_req *req;

		if (!d)
			break;

		req = lws_container_of(d, struct lws_stub_req, list);
		if (req->tx_pos < req->tx_len) {
			int n = lws_write(wsi, (unsigned char *)req->tx_buf + LWS_PRE + req->tx_pos,
					  req->tx_len - req->tx_pos, LWS_WRITE_RAW);
			if (n < 0)
				return -1;
			req->tx_pos += (size_t)n;
		}

		if (req->tx_pos < req->tx_len) {
			lws_callback_on_writable(wsi);
		} else if (!req->awaits_reply) {
			/* No response expected, so we can complete and free the request immediately */
			lws_stub_req_retire(req);

			/* If there are more requests queued, ask for writable again */
			if (!lws_dll2_is_empty(&mgr->reqs))
				lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_RAW_RX: {
		struct lws_dll2 *d = lws_dll2_get_head(&mgr->reqs);
		struct lws_stub_req *req;
		int m;

		req = d ? lws_container_of(d, struct lws_stub_req, list) : NULL;

		if (!req || !req->awaits_reply || req->tx_pos != req->tx_len) {
			/*
			 * Replies are matched to requests positionally, so the
			 * only request this rx can belong to is the head, and
			 * only if the head is completely on the wire and does
			 * expect a reply.  Anything else means the stub
			 * answered something we are not tracking (eg, a
			 * fire-and-forget request, which by contract is not
			 * answered) and we no longer know what a subsequent
			 * reply would belong to... drop the connection to
			 * resync rather than hand it to the wrong requester.
			 */
			lwsl_vhost_err(mgr->vh, "%s: stub '%s': unattributable "
				       "rx, resyncing\n", __func__,
				       mgr->config.stub_name);

			return -1;
		}

		if (req->raw_cb)
			req->raw_cb((const char *)in, len, req->user);

		/*
		 * Every request that expects a reply has a parser, even one
		 * that only wanted the raw bytes: completion of the JSON
		 * reply is the only signal that the request is over and the
		 * next one may go.
		 */

		m = lejp_parse(&req->jctx, (uint8_t *)in, (int)len);
		if (m < 0 && m != LEJP_CONTINUE) {
			lwsl_vhost_err(mgr->vh, "%s: stub '%s' lejp parse failed: %d\n", __func__, mgr->config.stub_name, m);
			lws_stub_req_retire(req);

			/*
			 * We have no idea where in the reply stream we are any
			 * more, so we cannot attribute what follows either...
			 * drop the connection to resync, anything still queued
			 * goes out on the reconnect
			 */
			return -1;
		}

		if (!m) {
			/*
			 * The reply completed the request: retire it, or it
			 * stays at the head of the queue forever and blocks
			 * every later queued request
			 */
			lws_stub_req_retire(req);
			if (!lws_dll2_is_empty(&mgr->reqs))
				lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_CLIENT_CLOSED:
		mgr->wsi_client = NULL;
		lws_stub_conn_lost(mgr);
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		/*
		 * Unconditional last call before the wsi memory is freed.
		 * For wsi that never established, it's the only notification
		 * we get at all when the context is being destroyed, since
		 * the usual close callbacks are suppressed then.  Drop our
		 * pointer to the wsi before its memory goes away.
		 */
		if (mgr->wsi_client == wsi)
			mgr->wsi_client = NULL;
		break;

	default:
		break;
	}

	return 0;
}

lws_stub_req_h
lws_stub_request_h(struct lws_stub_manager *mgr,
		   const char *json,
		   const char * const *rx_paths,
		   size_t rx_paths_count,
		   signed char (*rx_cb)(struct lejp_ctx *ctx, char reason),
		   void (*raw_cb)(const char *in, size_t len, void *user),
		   void *user)
{
	struct lws_stub_req *req;
	size_t n;

	if (!mgr)
		return 0;

	req = lws_zalloc(sizeof(*req), "stub_req");
	if (!req)
		return 0;

	req->rx_cb	= rx_cb;
	req->raw_cb	= raw_cb;
	req->user	= user;
	/*
	 * Whether the stub will answer this one decides when the next request
	 * may go on the wire, and whether rx arriving while it is at the head
	 * may be attributed to it
	 */
	req->awaits_reply = !!(rx_cb || raw_cb);

	if (req->awaits_reply)
		/*
		 * A request that only wants the raw reply bytes has no way to
		 * tell us the reply ended, so it gets our do-nothing parser
		 * purely so we can see that and retire it
		 */
		lejp_construct(&req->jctx, rx_cb ? rx_cb : lws_stub_reply_done_cb,
			       user, rx_cb ? rx_paths : NULL,
			       rx_cb ? (uint8_t)rx_paths_count : 0);

	n = strlen(json);
	req->tx_buf = lws_malloc(n + LWS_PRE + 1, "stub_req_tx");
	if (!req->tx_buf) {
		if (req->awaits_reply)
			lejp_destruct(&req->jctx);
		lws_free(req);
		return 0;
	}
	memcpy((unsigned char *)req->tx_buf + LWS_PRE, json, n);
	req->tx_len = n;

	req->h = ++mgr->next_h;

	lws_dll2_add_tail(&req->list, &mgr->reqs);

	if (!mgr->wsi_client) {
		if (!lws_dll2_owner(&mgr->sul.list)) {
			if (mgr->ctry >= 10) {
				/* If we hit max retries, reset and try again if new requests come in */
				mgr->ctry = 0;
			}
			lws_stub_client_connect(mgr);
		}
	} else
		lws_callback_on_writable(mgr->wsi_client);

	return req->h;
}

int
lws_stub_request(struct lws_stub_manager *mgr,
		 const char *json,
		 const char * const *rx_paths,
		 size_t rx_paths_count,
		 signed char (*rx_cb)(struct lejp_ctx *ctx, char reason),
		 void (*raw_cb)(const char *in, size_t len, void *user),
		 void *user)
{
	return lws_stub_request_h(mgr, json, rx_paths, rx_paths_count, rx_cb,
				  raw_cb, user) ? 0 : -1;
}

void
lws_stub_request_cancel(struct lws_stub_manager *mgr, lws_stub_req_h h)
{
	if (!mgr || !h)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&mgr->reqs)) {
		struct lws_stub_req *req = lws_container_of(d,
						struct lws_stub_req, list);

		if (req->h != h)
			continue;

		if (!req->tx_pos) {
			/* it never went on the wire: it can just disappear */
			lws_stub_req_retire(req);

			return;
		}

		/*
		 * It is already on the wire and the stub may still answer it.
		 * Replies are matched to requests positionally, so it has to
		 * stay at the head and consume its reply... but nothing of
		 * the owner's is reachable through it any more, and it is
		 * retired when the reply completes or the connection goes.
		 */
		lws_stub_req_detach(req);

		return;

	} lws_end_foreach_dll(d);
}


void
lws_stub_destroy(struct lws_stub_manager **_mgr)
{
	struct lws_stub_manager *mgr = *_mgr;

	if (!mgr)
		return;

	/*
	 * Take the caller's pointer away before we start.  Destroying the
	 * lsp closes its stdwsi synchronously, and freeing the last stdwsi
	 * can complete a deferred vhost destruction re-entrantly, issuing
	 * PROTOCOL_DESTROY on our protocol; if the caller also destroys us
	 * from there (as lwsws plugins and the api test do), the nested call
	 * must see the pointer already cleared and do nothing, or we will
	 * destroy the same lsp and mgr twice.
	 */
	*_mgr = NULL;

	/* we are tracked on the context, stop that */
	lws_dll2_remove(&mgr->cx_list);

	/* the retry sul is embedded in us: stop it pointing at freed memory */
	lws_sul_cancel(&mgr->sul);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&mgr->reqs)) {
		struct lws_stub_req *req = lws_container_of(d, struct lws_stub_req, list);

		lws_stub_req_retire(req);
	} lws_end_foreach_dll_safe(d, d1);

	if (mgr->wsi_client)
		lws_set_opaque_user_data(mgr->wsi_client, NULL);

	/*
	 * The client vhost is private to us and nothing else is bound to it,
	 * so it goes when we go... its dieback closes wsi_client (which no
	 * longer points at us) and it is finalized when that has completed.
	 * During context destruction every vhost is destroyed anyway, and
	 * doing it from in here would recurse into the walk doing that.
	 */
	if (mgr->vh_client && !mgr->cx->being_destroyed)
		lws_vhost_destroy(mgr->vh_client);

	mgr->vh_client = NULL;
	mgr->wsi_client = NULL;

	if (mgr->lsp) {
		lws_spawn_piped_kill_child_process(mgr->lsp);
		/*
		 * Any still-open stdwsi are marked to close asynchronously
		 * here; stdwsi that already went through close processing
		 * have been removed from lsp->stdwsi[] by their protocol
		 * handler calling lws_spawn_stdwsi_closed().
		 */
		lws_spawn_piped_destroy(&mgr->lsp);
	}

	unlink(mgr->uds_path);

	lws_free(mgr);
}

const char *
lws_stub_get_secret(struct lws_stub_manager *mgr)
{
	if (!mgr)
		return NULL;
	return mgr->secret;
}

struct lws_spawn_piped *
lws_stub_get_lsp(struct lws_stub_manager *mgr)
{
	if (!mgr)
		return NULL;

	return mgr->lsp;
}

/*
 * This is called from __lws_vhost_destroy2() for every vhost, so stubs
 * spawned on the vhost are destroyed with it even if nobody else destroys
 * them.  It is legal (and expected) that PROTOCOL_DESTROY-based destroy
 * paths already removed the mgr from the tracking list.
 */
void
lws_stub_destroy_all_on_vhost(struct lws_vhost *vh)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vh->context->owner_stub_mgrs)) {
		struct lws_stub_manager *mgr =
			lws_container_of(d, struct lws_stub_manager, cx_list);

		if (mgr->vh == vh)
			lws_stub_destroy(&mgr);

	} lws_end_foreach_dll_safe(d, d1);
}
#endif
