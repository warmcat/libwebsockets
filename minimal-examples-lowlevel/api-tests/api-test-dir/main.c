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

#if defined(WIN32)
#include <direct.h>
#define mkdir(x,y) _mkdir(x)
#define rmdir _rmdir
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

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	lws_dir_du_t du;
	int result = 0;

	lwsl_user("lws-api-test-dir\n");
	lws_set_log_level(logs, NULL);
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
