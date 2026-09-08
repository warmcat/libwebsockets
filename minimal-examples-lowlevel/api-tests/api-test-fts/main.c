/*
 * lws-api-test-fts - lws full-text search api test
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#if defined(LWS_HAS_GETOPT_LONG) || defined(WIN32)
#include <getopt.h>
#endif
#include <fcntl.h>
#include <ctype.h>

#if defined(LWS_HAS_GETOPT_LONG) || defined(WIN32)
static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "createindex", no_argument,		NULL, 'c' },
	{ "index",	required_argument,	NULL, 'i' },
	{ "file",	required_argument,	NULL, 'f' },
	{ "lines",	required_argument,	NULL, 'l' },
	{ "selftest",	no_argument,		NULL, 's' },
	{ NULL, 0, 0, 0 }
};
#endif

static const char *index_filepath = "/tmp/lws-fts-test-index"; // NOSONAR
static char filepath[256];

/* a token that appears as a whole word in both of the shipped corpus files */

static const char *selftest_needle = "the";

/*
 * Is needle in the line that starts at ofs, ignoring case?  The comparison is
 * byte-wise, which is all we need for an ASCII needle.
 */

static int
line_has_needle(const char *fb, size_t len, size_t ofs, const char *needle)
{
	size_t nl = strlen(needle), n;

	while (ofs < len && fb[ofs] != '\n') {
		if (ofs + nl > len)
			return 0;

		for (n = 0; n < nl; n++)
			if (tolower((unsigned char)fb[ofs + n]) !=
			    tolower((unsigned char)needle[n]))
				break;

		if (n == nl)
			return 1;

		ofs++;
	}

	return 0;
}

/*
 * Confirm one filepath result against the original input file: every match
 * record must be present (the stride is fixed, see lws-fts.h), name a line
 * that exists, give the byte offset that line actually starts at, and quote
 * a line that actually contains the needle.
 *
 * This is what catches a line table that was written for a different file,
 * an off-by-one line number, and any short or desynchronised match record.
 */

static int
selftest_filepath(struct lws_fts_result_filepath *fp, const char *needle,
		  int flags)
{
	const char *path = ((const char *)(fp + 1)) + fp->matches_length;
	const uint32_t *li = (const uint32_t *)(void *)(fp + 1);
	size_t *lofs = NULL, nlines = 0, len = 0, alloc, m;
	int fd, n, stride, ret = 1;
	char *fb = NULL;
	off_t size;

	stride = 2;
	if (flags & LWSFTS_F_QUERY_QUOTE_LINE)
		stride += (int)(sizeof(const char *) / sizeof(uint32_t));

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, path);

		return 1;
	}

	size = lseek(fd, 0, SEEK_END);
	if (size <= 0 || lseek(fd, 0, SEEK_SET) < 0)
		goto bail;

	alloc = (size_t)size;
	fb = malloc(alloc + 1);
	if (!fb)
		goto bail;

	while (len < alloc) {
		int r = (int)read(fd, fb + len, alloc - len);

		if (r <= 0)
			break;

		len += (size_t)r;
	}

	if (len != alloc)
		goto bail;

	fb[len] = '\0';

	/* line 1 starts at 0, and line n + 1 starts after the nth newline */

	for (m = 0; m < len; m++)
		if (fb[m] == '\n')
			nlines++;

	lofs = malloc((nlines + 1) * sizeof(*lofs));
	if (!lofs)
		goto bail;

	lofs[0] = 0;
	nlines = 0;
	for (m = 0; m < len; m++)
		if (fb[m] == '\n')
			lofs[++nlines] = m + 1;

	if (fp->lines_in_file != (int)nlines) {
		lwsl_err("%s: %s: reported %d lines, file has %d\n", __func__,
			 path, fp->lines_in_file, (int)nlines);

		goto bail;
	}

	for (n = 0; n < fp->matches; n++) {
		const uint32_t *r = li + ((size_t)n * (size_t)stride);
		uint32_t line = r[0], ofs = r[1];

		if (!line || line > nlines) {
			lwsl_err("%s: %s: match %d: line %u out of range\n",
				 __func__, path, n, (unsigned int)line);

			goto bail;
		}

		if (ofs != lofs[line - 1]) {
			lwsl_err("%s: %s: match %d: line %u at 0x%x, "
				 "index says 0x%x\n", __func__, path, n,
				 (unsigned int)line,
				 (unsigned int)lofs[line - 1],
				 (unsigned int)ofs);

			goto bail;
		}

		if (!line_has_needle(fb, len, ofs, needle)) {
			lwsl_err("%s: %s: match %d: line %u has no '%s'\n",
				 __func__, path, n, (unsigned int)line, needle);

			goto bail;
		}

		if (flags & LWSFTS_F_QUERY_QUOTE_LINE) {
			const char *q;

			memcpy(&q, &r[2], sizeof(q));

			if (!q || !line_has_needle(q, strlen(q), 0, needle)) {
				lwsl_err("%s: %s: match %d: bad quote\n",
					 __func__, path, n);

				goto bail;
			}
		}
	}

	ret = 0;

bail:
	free(lofs);
	free(fb);
	close(fd);

	return ret;
}

static int
index_one_file(struct lws_fts *t, const char *path, char *buf, size_t bufsize)
{
	int fd, fi;

	fi = lws_fts_file_index(t, path, (int)strlen(path), 1);
	if (fi < 0) {
		lwsl_err("%s: failed to get file idx for %s\n", __func__, path);

		return 1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open %s for read\n", __func__, path);

		return 1;
	}

	do {
		int n = (int)read(fd, buf, bufsize);

		if (n <= 0)
			break;

		if (lws_fts_fill(t, (uint32_t)fi, buf, (size_t)n)) {
			lwsl_err("%s: lws_fts_fill failed\n", __func__);
			close(fd);

			return 1;
		}

	} while (1);

	close(fd);

	return 0;
}

/*
 * The two corpus files that ship with this test are CRLF, which means their
 * tokens are always terminated by the CR rather than by the newline itself.
 * Generate a small LF-only file as well, whose tokens include ones that end a
 * line, and one that ends the last line of the file... those have to resolve
 * to the line they are actually on.
 */

static char genpath[320];

static int
selftest_make_lf_corpus(void)
{
	static const char *content =
		"the sun and the moon\n"
		"a line that ends with the\n"
		"the middle of the file\n"
		"the last line also ends with the\n";
	size_t len = strlen(content);
	int fd;

	lws_snprintf(genpath, sizeof(genpath), "%s-lf.txt", index_filepath);

	fd = open(genpath, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("%s: unable to create %s\n", __func__, genpath);

		return 1;
	}

	if ((size_t)write(fd, content, len) != len) {
		lwsl_err("%s: unable to write %s\n", __func__, genpath);
		close(fd);

		return 1;
	}

	close(fd);

	return 0;
}

int main(int argc, char * const * argv)
{
	int ft, createindex = 0, flags = LWSFTS_F_QUERY_AUTOCOMPLETE;
	struct lws_context_creation_info cx_info;
	struct lws_fts_search_params params;
	struct lws_fts_result *result;
	int selftest = 0, first_input;
	struct lws_fts_file *jtf;
	struct lws_fts *t;
	char buf[16384];
	int n;

	lws_context_info_defaults(&cx_info, NULL);
	lws_cmdline_option_handle_builtin(argc, (const char **)argv, &cx_info);

	do {
#if defined(LWS_HAS_GETOPT_LONG) || defined(WIN32)
		n = getopt_long(argc, argv, "hd:i:cfls", options, NULL);
#else
       n = getopt(argc, argv, "hd:i:cfls");
#endif
		if (n < 0)
			continue;
		switch (n) {
		case 'i':
			strncpy(filepath, optarg, sizeof(filepath) - 1);
			filepath[sizeof(filepath) - 1] = '\0';
			index_filepath = filepath;
			break;
		case 'c':
			createindex = 1;
			break;
		case 's':
			selftest = 1;
			createindex = 1;
			break;
		case 'f':
			flags &= ~LWSFTS_F_QUERY_AUTOCOMPLETE;
			flags |= LWSFTS_F_QUERY_FILES;
			break;
		case 'l':
			flags |= LWSFTS_F_QUERY_FILES |
				 LWSFTS_F_QUERY_FILE_LINES;
			break;
		case 'h':
			fprintf(stderr,
				"Usage: %s [--createindex] [--selftest] "
					"[--index=<index filepath>] "
					"[-d <log bitfield>] file1 file2 \n",
					argv[0]);
			exit(1);
		}
	} while (n >= 0);

	lwsl_user("LWS API selftest: full-text search\n");

	if (createindex) {

		lwsl_notice("Creating index\n");

		if (selftest && selftest_make_lf_corpus())
			goto bail;

		/*
		 * create an index by shifting through argv and indexing each
		 * file given there into a single combined index
		 */

		ft = open(index_filepath, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (ft < 0) {
			lwsl_err("%s: can't open index %s\n", __func__,
				 index_filepath);

			goto bail;
		}

		t = lws_fts_create(ft);
		if (!t) {
			lwsl_err("%s: Unable to allocate trie\n", __func__);

			goto bail1;
		}

		first_input = optind;

		while (optind < argc) {

			if (index_one_file(t, argv[optind], buf, sizeof(buf)))
				goto bail;

			optind++;
		}

		/* indexed last, so it is not file index 0 */

		if (selftest && index_one_file(t, genpath, buf, sizeof(buf)))
			goto bail;

		if (lws_fts_serialize(t)) {
			lwsl_err("%s: serialize failed\n", __func__);

			goto bail;
		}

		lws_fts_destroy(&t);
		close(ft);

		if (!selftest)
			return 0;

		/*
		 * Selftest: query the index we just made and confirm every
		 * match record it gives us against the original input files.
		 */

		jtf = lws_fts_open(index_filepath);
		if (!jtf)
			goto bail;

		memset(&params, 0, sizeof(params));

		params.needle = selftest_needle;
		params.flags = LWSFTS_F_QUERY_FILES |
			       LWSFTS_F_QUERY_FILE_LINES |
			       LWSFTS_F_QUERY_QUOTE_LINE;
		params.max_files = 20;

		result = lws_fts_search(jtf, &params);
		if (!result) {
			lwsl_err("%s: selftest search failed\n", __func__);
			lws_fts_close(jtf);

			goto bail;
		}

		n = 0;
		{
			struct lws_fts_result_filepath *fp =
						result->filepath_head;

			while (fp) {
				if (selftest_filepath(fp, selftest_needle,
						      params.flags)) {
					lwsac_free(&params.results_head);
					lws_fts_close(jtf);

					goto bail;
				}

				n++;
				fp = fp->next;
			}
		}

		lwsac_free(&params.results_head);
		lws_fts_close(jtf);

		/*
		 * every input file contains the needle, so all of them, plus
		 * the generated LF one, must appear
		 */

		if (n != (argc - first_input) + 1) {
			lwsl_err("%s: %d filepath results, expected %d\n",
				 __func__, n, (argc - first_input) + 1);

			goto bail;
		}

		lwsl_user("Completed: PASS\n");

		return 0;
	}

	/*
	 * shift through argv searching for each token
	 */

	jtf = lws_fts_open(index_filepath);
	if (!jtf)
		goto bail;

	while (optind < argc) {

		struct lws_fts_result_autocomplete *ac;
		struct lws_fts_result_filepath *fp;
		uint32_t *l, n;

		memset(&params, 0, sizeof(params));

		params.needle = argv[optind];
		params.flags = flags;
		params.max_autocomplete = 20;
		params.max_files = 20;

		result = lws_fts_search(jtf, &params);

		if (!result) {
			lwsl_err("%s: search failed\n", __func__);
			lws_fts_close(jtf);
			goto bail;
		}

		ac = result->autocomplete_head;
		fp = result->filepath_head;

		if (!ac)
			lwsl_notice("%s: no autocomplete results\n", __func__);

		while (ac) {
			lwsl_notice("%s: AC %s: %d agg hits\n", __func__,
				((char *)(ac + 1)), ac->instances);

			ac = ac->next;
		}

		if (!fp)
			lwsl_notice("%s: no filepath results\n", __func__);

		while (fp) {
			lwsl_notice("%s: %s: (%d lines) %d hits \n", __func__,
				(((char *)(fp + 1)) + fp->matches_length),
				fp->lines_in_file, fp->matches);

			if (fp->matches_length) {
				/*
				 * the match records have a fixed stride, of
				 * the line number, the file offset of the
				 * line, and if it was asked for, a pointer to
				 * the quoted line (see lws-fts.h)
				 */

				int stride = 2;

				if (flags & LWSFTS_F_QUERY_QUOTE_LINE)
					stride += (int)(sizeof(const char *) /
							sizeof(uint32_t));

				l = (uint32_t *)(void *)(fp + 1);
				for (n = 0; (int)n < fp->matches;
				     n++, l += stride)
					lwsl_notice(" line %d, offset %d\n",
						    l[0], l[1]);
			}
			fp = fp->next;
		}

		lwsac_free(&params.results_head);

		optind++;
	}

	lws_fts_close(jtf);

	return 0;

bail1:
	close(ft);
bail:
	lwsl_user("FAILED\n");

	return 1;
}
