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
