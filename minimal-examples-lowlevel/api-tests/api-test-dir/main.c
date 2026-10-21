/*
 * lws-api-test-dir
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#if defined(WIN32)
#include <direct.h>
#define mkdir(x,y) _mkdir(x)
#define rmdir _rmdir
#else
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#endif

static int
create_file(const char *path, size_t size)
{
	int fd = lws_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	char buf[1024];
	size_t s = size;

	if (fd < 0)
		return 1;

	memset(buf, 'A', sizeof(buf));

	while (s) {
		size_t w = sizeof(buf);
		if (w > s)
			w = s;
		if (write(fd, buf, LWS_POSIX_LENGTH_CAST(w)) != (ssize_t)w) {
			close(fd);
			return 1;
		}
		s -= w;
	}

	close(fd);

	return 0;
}

#if !defined(WIN32)
static int
link_is(const char *link, const char *expect)
{
	char buf[128];
	ssize_t n = readlink(link, buf, sizeof(buf) - 1);

	if (n < 0)
		return !expect; /* no link at all */
	buf[n] = '\0';

	return expect && !strcmp(buf, expect);
}

/*
 * lws_dir_symlink_rotate() as a cert store uses it: each newly written
 * timestamped file becomes -latest, and what -latest pointed at before
 * becomes -previous
 */

static int
test_symlink_rotate(void)
{
	static const char *cur = "./test-rot/example.com-latest-fullchain.crt",
			  *prev = "./test-rot/example.com-previous-fullchain.crt";
	int r = 1;

	if (mkdir("./test-rot", 0700) < 0) {
		lwsl_err("%s: failed mkdir test-rot\n", __func__);
		return 1;
	}

	/* first cert: nothing is outgoing yet */
	if (lws_dir_symlink_rotate(cur, "example.com-1-fullchain.crt",
				   "-latest", "-previous") ||
	    !link_is(cur, "example.com-1-fullchain.crt") ||
	    !link_is(prev, NULL)) {
		lwsl_err("%s: first rotation wrong\n", __func__);
		goto bail;
	}

	/* renewal: the first cert becomes previous */
	if (lws_dir_symlink_rotate(cur, "example.com-2-fullchain.crt",
				   "-latest", "-previous") ||
	    !link_is(cur, "example.com-2-fullchain.crt") ||
	    !link_is(prev, "example.com-1-fullchain.crt")) {
		lwsl_err("%s: second rotation wrong\n", __func__);
		goto bail;
	}

	/* saving the same cert again must not lose the real previous one */
	if (lws_dir_symlink_rotate(cur, "example.com-2-fullchain.crt",
				   "-latest", "-previous") ||
	    !link_is(prev, "example.com-1-fullchain.crt")) {
		lwsl_err("%s: repeated rotation lost previous\n", __func__);
		goto bail;
	}

	/* the next renewal moves previous on */
	if (lws_dir_symlink_rotate(cur, "example.com-3-fullchain.crt",
				   "-latest", "-previous") ||
	    !link_is(cur, "example.com-3-fullchain.crt") ||
	    !link_is(prev, "example.com-2-fullchain.crt")) {
		lwsl_err("%s: third rotation wrong\n", __func__);
		goto bail;
	}

	/* a path without the tag is refused, and nothing is created */
	errno = 0;
	if (!lws_dir_symlink_rotate("./test-rot/untagged.crt", "x",
				    "-latest", "-previous") || errno != EINVAL ||
	    !link_is("./test-rot/untagged.crt", NULL)) {
		lwsl_err("%s: untagged path not refused with EINVAL\n",
			 __func__);
		goto bail;
	}

	/* a failed link reports the filesystem's reason */
	errno = 0;
	if (!lws_dir_symlink_rotate("./test-rot/missing/example.com-latest.crt",
				    "x", "-latest", "-previous") ||
	    errno != ENOENT) {
		lwsl_err("%s: link in a missing dir not refused with ENOENT\n",
			 __func__);
		goto bail;
	}

	lwsl_user("%s: ok\n", __func__);
	r = 0;

bail:
	lws_dir("./test-rot", NULL, lws_dir_rm_rf_cb);
	rmdir("./test-rot");

	return r;
}
#endif

#if !defined(WIN32)
/*
 * lws_dir_rm_rf_cb() must act on exactly the entries it walks, however long
 * their paths: never a truncated prefix of one, which names the directory
 * being walked, an ancestor (so it recursed forever) or a sibling outside
 * the tree (so it was deleted).  And it must stop at its depth bound.
 */

#define RMRF_BASE "./test-rmrf"

static int
exists(const char *path)
{
	struct stat st;

	return !lstat(path, &st);
}

/*
 * Extend path p with directories until it is exactly target chars long.
 *
 * Each one is made relative to an fd on its parent, never by the whole path,
 * so the tree can go deeper than a path the platform takes in one piece (OSX
 * PATH_MAX is 1024).  If pdfd is given, it is set to an fd on the deepest
 * dir, which the caller closes.
 */

static int
grow_to(char *p, size_t cap, size_t target, char c, int *pdfd)
{
	size_t l = strlen(p), n, rest;
	int dfd, fd;

	if (target + 1 > cap)
		return 1;

	dfd = open(p, O_RDONLY | O_DIRECTORY);
	if (dfd < 0)
		return 1;

	while (l < target) {
		/*
		 * Up to 200 chars a component after its '/', but never leaving
		 * just 1, since the next component can't be empty
		 */
		rest = target - l - 1;
		if (rest == 201)
			n = 199;
		else
			n = rest > 200 ? 200 : rest;
		p[l] = '/';
		memset(p + l + 1, c, n);
		p[l + 1 + n] = '\0';
		if (mkdirat(dfd, p + l + 1, 0700)) {
			close(dfd);
			return 1;
		}
		fd = openat(dfd, p + l + 1, O_RDONLY | O_DIRECTORY);
		close(dfd);
		if (fd < 0)
			return 1;
		dfd = fd;
		l += 1 + n;
	}

	if (pdfd)
		*pdfd = dfd;
	else
		close(dfd);

	return 0;
}

static int
cat_to(char *p, size_t cap, const char *s)
{
	size_t l = strlen(p);

	return lws_snprintf(p + l, cap - l, "%s", s) >= (int)(cap - l);
}

static int
mkdir_sub(char *p, size_t cap, const char *sub)
{
	if (cat_to(p, cap, "/") || cat_to(p, cap, sub))
		return 1;

	return mkdir(p, 0700);
}

static int
test_rm_rf_long(void)
{
	char p[2048], root[512], keep[512];
	int r = 1, n, dfd, fd;

	lwsl_user("%s\n", __func__);

	if (mkdir(RMRF_BASE, 0700)) {
		lwsl_err("%s: mkdir failed %d\n", __func__, errno);
		return 1;
	}

	/*
	 * A tree whose own path is 400 long.  Its entries' paths cut at 383
	 * name "keep", its sibling: that must survive the tree's removal.
	 */

	lws_strncpy(root, RMRF_BASE, sizeof(root));
	if (grow_to(root, sizeof(root), 299, 'p', NULL))
		goto setup;
	lws_strncpy(keep, root, sizeof(keep));
	if (grow_to(keep, sizeof(keep), 383, 'r', NULL))
		goto setup;
	lws_strncpy(p, keep, sizeof(p));
	if (mkdir_sub(p, sizeof(p), "x") || create_file(RMRF_BASE "/kf", 1))
		goto setup;
	cat_to(p, sizeof(p), "/f");
	if (create_file(p, 1))
		goto setup;

	root[299] = '\0';
	if (grow_to(root, sizeof(root), 400, 'r', NULL))
		goto setup;
	lws_strncpy(p, root, sizeof(p));
	if (mkdir_sub(p, sizeof(p), "a") || mkdir_sub(p, sizeof(p), "b"))
		goto setup;
	cat_to(p, sizeof(p), "/f");
	if (create_file(p, 1))
		goto setup;

	lws_dir(root, NULL, lws_dir_rm_rf_cb);
	if (rmdir(root)) {
		lwsl_err("%s: long tree not emptied\n", __func__);
		goto bail;
	}
	cat_to(keep, sizeof(keep), "/x/f");
	if (!exists(keep) || !exists(RMRF_BASE "/kf")) {
		lwsl_err("%s: rm -rf reached outside its tree\n", __func__);
		goto bail;
	}

	/*
	 * Directories whose paths are exactly 382 (cut, its child's path is
	 * the dir itself) and 383 (cut, its grandchildren's paths are it), and
	 * a branch on to past 1KB, each with more below.
	 */

	lws_strncpy(root, RMRF_BASE "/deep", sizeof(root));
	if (mkdir(root, 0700))
		goto setup;

	for (n = 382; n <= 383; n++) {
		lws_snprintf(p, sizeof(p), "%s/%c", root, 'a' + (n & 1));
		if (mkdir(p, 0700) ||
		    grow_to(p, sizeof(p), (size_t)n, 'd', NULL) ||
		    mkdir_sub(p, sizeof(p), "x") || mkdir_sub(p, sizeof(p), "y"))
			goto setup;
		cat_to(p, sizeof(p), "/f");
		if (create_file(p, 1))
			goto setup;
	}

	lws_snprintf(p, sizeof(p), "%s/c", root);
	if (mkdir(p, 0700) || grow_to(p, sizeof(p), 1100, 'e', &dfd))
		goto setup;
	/* its path is too long to name in one piece everywhere */
	fd = openat(dfd, "f", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	close(dfd);
	if (fd < 0)
		goto setup;
	close(fd);

	lws_dir(root, NULL, lws_dir_rm_rf_cb);
	if (rmdir(root)) {
		lwsl_err("%s: deep tree not emptied\n", __func__);
		goto bail;
	}

	/* a nesting past the depth bound is left alone, not recursed into */

	lws_strncpy(p, root, sizeof(p));
	if (mkdir(p, 0700))
		goto setup;
	for (n = 0; n < 70; n++)
		if (mkdir_sub(p, sizeof(p), "d"))
			goto setup;

	lws_dir(root, NULL, lws_dir_rm_rf_cb);
	if (!exists(root) || !rmdir(root)) {
		lwsl_err("%s: depth bound not applied\n", __func__);
		goto bail;
	}

	/* ... and removing it from halfway down gets it all */
	p[strlen(root) + 2 * 35] = '\0';
	lws_dir(p, NULL, lws_dir_rm_rf_cb);
	lws_dir(root, NULL, lws_dir_rm_rf_cb);
	if (rmdir(root)) {
		lwsl_err("%s: depth-bounded tree not removable\n", __func__);
		goto bail;
	}

	lwsl_user("%s: ok\n", __func__);
	r = 0;
	goto bail;

setup:
	lwsl_err("%s: making the test tree failed %d\n", __func__, errno);
bail:
	lws_dir(RMRF_BASE, NULL, lws_dir_rm_rf_cb);
	rmdir(RMRF_BASE);

	return r;
}
#endif

#if !defined(WIN32)
/*
 * lws_dir_rm_rf_cb() must never act outside the tree it was given, even
 * when a directory in the tree is swapped for a symlink to somewhere else
 * while it is being removed.  A child process keeps exchanging the
 * directory ./test-rmrf-race/root/d with a symlink to ../outside, which
 * holds sentinel files with the same names as the files in d, while the
 * parent rm -rf's root over and over.  Not one sentinel may go.
 */

#define RACE_BASE	"./test-rmrf-race"
#define RACE_ROOT	RACE_BASE "/root"
#define RACE_D		RACE_ROOT "/d"
#define RACE_LNK	RACE_BASE "/lnk"
#define RACE_TMP	RACE_BASE "/tmpd"
#define RACE_OUT	RACE_BASE "/outside"
#define RACE_FILES	64
#define RACE_PASSES	400

#if defined(__linux__) && defined(SYS_renameat2)
#if !defined(RENAME_EXCHANGE)
#define RENAME_EXCHANGE (1 << 1)
#endif
static int
race_swap(void)
{
	/* one atomic exchange of the two names */
	return (int)syscall(SYS_renameat2, AT_FDCWD, RACE_D, AT_FDCWD,
			    RACE_LNK, RENAME_EXCHANGE);
}
#else
static int
race_swap(void)
{
	/* without an atomic exchange, two renames each way */
	if (rename(RACE_D, RACE_TMP))
		return -1;
	if (rename(RACE_LNK, RACE_D)) {
		rename(RACE_TMP, RACE_D);
		return -1;
	}
	if (rename(RACE_D, RACE_LNK))
		return -1;

	return rename(RACE_TMP, RACE_D);
}
#endif

/*
 * The parent parks the swapper by writing a byte on ctl, and the swapper
 * answers on ack once it is between two swaps, then waits for another byte
 * on ctl before it goes on.  Stopping it with SIGSTOP instead doesn't tell
 * us where it stopped: on OSX, kill() and waitpid() can return while a
 * rename() it was in the middle of has still to finish, and that rename
 * then lands in the middle of race_reset().
 */

static void
race_swapper(int ctl, int ack)
{
	struct pollfd pfd;
	ssize_t r;
	char c;

	pfd.fd = ctl;
	pfd.events = POLLIN;

	/* ctl is nonblocking: swap until asked to park */
	while (1) {
		race_swap();

		r = read(ctl, &c, 1);
		switch (r) {
		case 1:
			break;
		case 0:
			_exit(0); /* the parent is gone */
		default:
			if (errno == EAGAIN || errno == EINTR)
				continue;
			_exit(1);
		}

		if (write(ack, &c, 1) != 1)
			_exit(1);

		/* parked, until the parent's next byte (or it is gone) */
		pfd.revents = 0;
		if (poll(&pfd, 1, -1) < 0 || read(ctl, &c, 1) != 1)
			_exit(0);
	}
}

/* whatever the swapper left at path, get rid of it (swapper is parked) */

static void
race_clear(const char *path)
{
	/*
	 * Whatever is at path goes, without asking first what it is: a file
	 * or a symlink unlinks, only a directory refuses and is emptied
	 */
	if (!unlink(path))
		return;

	lws_dir(path, NULL, lws_dir_rm_rf_cb);
	rmdir(path);
}

/*
 * Put the swapped names back to a directory full of files at RACE_D and a
 * symlink to the outside at RACE_LNK, and count (and replace) any sentinel
 * that went missing.  The swapper is parked while this runs.
 */

static int
race_reset(void)
{
	char p[64];
	int n, lost = 0;

	race_clear(RACE_D);
	race_clear(RACE_LNK);
	race_clear(RACE_TMP);

	if (mkdir(RACE_D, 0700) || symlink("../outside", RACE_LNK))
		goto fail;

	for (n = 0; n < RACE_FILES; n++) {
		lws_snprintf(p, sizeof(p), RACE_D "/s%02d", n);
		if (create_file(p, 1))
			goto fail;
		lws_snprintf(p, sizeof(p), RACE_OUT "/s%02d", n);
		if (!exists(p)) {
			lost++;
			if (create_file(p, 1))
				goto fail;
		}
	}

	return lost;

fail:
	lwsl_err("%s: failed %d\n", __func__, errno);

	return -1;
}

static int
test_rm_rf_swap_race(void)
{
	int r = 1, n, pass, lost = 0, ctl[2] = { -1, -1 }, ack[2] = { -1, -1 };
	pid_t child = -1;
	char p[64], c = 0;

	lwsl_user("%s\n", __func__);

	if (mkdir(RACE_BASE, 0700) || mkdir(RACE_ROOT, 0700) ||
	    mkdir(RACE_OUT, 0700))
		goto setup;
	for (n = 0; n < RACE_FILES; n++) {
		lws_snprintf(p, sizeof(p), RACE_OUT "/s%02d", n);
		if (create_file(p, 1))
			goto setup;
	}

	/* a symlink in the tree, to a dir and to a file, is removed itself */

	if (race_reset() || symlink("../outside", RACE_ROOT "/ldir") ||
	    symlink("../outside/s00", RACE_ROOT "/lfile"))
		goto setup;
	lws_dir(RACE_ROOT, NULL, lws_dir_rm_rf_cb);
	if (exists(RACE_ROOT "/ldir") || exists(RACE_ROOT "/lfile") ||
	    exists(RACE_D)) {
		lwsl_err("%s: tree not emptied\n", __func__);
		goto bail0;
	}
	race_clear(RACE_LNK);
	if (race_reset()) {
		lwsl_err("%s: static symlink followed\n", __func__);
		goto bail0;
	}

	/* a swapper that died is EPIPE for us below, not a SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
	if (pipe(ctl) || pipe(ack))
		goto setup;

	child = fork();
	if (child < 0)
		goto setup;
	if (!child) {
		close(ctl[1]);
		close(ack[0]);
		if (fcntl(ctl[0], F_SETFL, O_NONBLOCK))
			_exit(1);
		race_swapper(ctl[0], ack[1]);
	}

	close(ctl[0]);
	ctl[0] = -1;
	close(ack[1]);
	ack[1] = -1;

	/* the walk warns about every swap it meets, keep it quiet */
	lws_set_log_level(LLL_ERR | LLL_USER, NULL);

	for (pass = 0; pass < RACE_PASSES; pass++) {
		lws_dir(RACE_ROOT, NULL, lws_dir_rm_rf_cb);

		/* park the swapper while we set up the next pass */
		if (write(ctl[1], &c, 1) != 1 || read(ack[0], &c, 1) != 1) {
			lwsl_err("%s: parking the swapper failed %d\n",
				 __func__, errno);
			goto bail;
		}

		n = race_reset();
		if (n < 0) {
			lwsl_err("%s: pass %d: reset failed\n", __func__, pass);
			goto bail;
		}
		lost += n;

		if (write(ctl[1], &c, 1) != 1) {
			lwsl_err("%s: resuming the swapper failed %d\n",
				 __func__, errno);
			goto bail;
		}
	}

	if (lost) {
		lwsl_err("%s: %d files outside the tree deleted\n", __func__,
			 lost);
		goto bail;
	}

	lwsl_user("%s: ok\n", __func__);
	r = 0;

bail:
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);
	kill(child, SIGKILL);
	waitpid(child, &n, 0);
	goto bail0;

setup:
	lwsl_err("%s: making the test tree failed %d\n", __func__, errno);
bail0:
	for (n = 0; n < 2; n++) {
		if (ctl[n] >= 0)
			close(ctl[n]);
		if (ack[n] >= 0)
			close(ack[n]);
	}
	race_clear(RACE_D);
	race_clear(RACE_LNK);
	race_clear(RACE_TMP);
	lws_dir(RACE_BASE, NULL, lws_dir_rm_rf_cb);
	rmdir(RACE_BASE);

	return r;
}
#endif


int main(int argc, const char **argv)
{
	
	lws_dir_du_t du;
	int result = 0;

	lwsl_user("lws-api-test-dir\n");
	lwsl_user("LWS API selftest: lws_dir du\n");

	/* Create test directory structure */
	if (mkdir("./test-dir", 0700) < 0) {
		lwsl_err("%s: failed mkdir test-dir\n", __func__);
		result = 1;
		goto cleanup;
	}
	if (mkdir("./test-dir/subdir", 0700) < 0) {
		lwsl_err("%s: failed mkdir test-dir/subdir\n", __func__);
		result = 1;
		goto cleanup;
	}

	if (create_file("./test-dir/file1", 10)) {
		lwsl_err("Failed to create file1\n");
		result = 1;
		goto cleanup;
	}
	if (create_file("./test-dir/file2", 20)) {
		lwsl_err("Failed to create file2\n");
		result = 1;
		goto cleanup;
	}
	if (create_file("./test-dir/subdir/file3", 30)) {
		lwsl_err("Failed to create file3\n");
		result = 1;
		goto cleanup;
	}

	memset(&du, 0, sizeof(du));
	if (!lws_dir("./test-dir", &du, lws_dir_du_cb)) {
		lwsl_err("lws_dir failed\n");
		result = 1;
		goto cleanup;
	}

	lwsl_user("Total size: %llu, total files: %u\n",
		  (unsigned long long)du.size_in_bytes, du.count_files);

	if (du.size_in_bytes != 60) {
		lwsl_err("size_in_bytes is %llu, expected 60\n",
			 (unsigned long long)du.size_in_bytes);
		result = 1;
	}

	if (du.count_files != 3) {
		lwsl_err("count_files is %u, expected 3\n", du.count_files);
		result = 1;
	}

#if !defined(WIN32)
	if (test_symlink_rotate())
		result = 1;
	if (test_rm_rf_long())
		result = 1;
	if (test_rm_rf_swap_race())
		result = 1;
#endif

cleanup:
	/* Clean up test directory structure */
	lws_dir("./test-dir", NULL, lws_dir_rm_rf_cb);
	rmdir("./test-dir");

	if (!result)
		lwsl_user("Completed successfully\n");
	else
		lwsl_err("Failed\n");

	return result;
}
