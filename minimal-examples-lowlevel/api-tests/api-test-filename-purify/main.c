/*
 * lws-api-test-filename-purify
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences lws_filename_purify_inplace() (G-553): whatever name it is given,
 * the result is one path component, the same on every platform:
 *
 *  - no '/' or '\', so it is neither absolute nor has a directory part
 *  - no "..", no leading '.', so it is never ".", ".." or a hidden file
 *  - no control characters, no ':' (drive / NTFS stream) or the other
 *    characters Windows refuses
 *  - not a Windows device name, with or without an extension
 *  - the length is unchanged, ordinary names are left alone, and purifying
 *    the result again changes nothing
 */

#include <libwebsockets.h>

#include <string.h>

static int fails, oks;

#define CHECK(_c, ...) do { \
	if (_c) oks++; else { fails++; lwsl_err(__VA_ARGS__); } \
} while (0)

static const struct {
	const char	*in;
	const char	*out;
} cases[] = {
	/* ordinary names are untouched */
	{ "picture.png",		"picture.png" },
	{ "my file (1).tar.gz",		"my file (1).tar.gz" },
	{ "a.b.c",			"a.b.c" },
	{ "CONSOLE.txt",		"CONSOLE.txt" },
	{ "nullify",			"nullify" },
	{ "COM10",			"COM10" },
	{ "\xc3\xa9t\xc3\xa9.txt",	"\xc3\xa9t\xc3\xa9.txt" },
	{ "",				"" },

	/* absolute and multi-component paths */
	{ "/etc/passwd",		"_etc_passwd" },
	{ "/home/user/.ssh/authorized_keys",
					"_home_user_.ssh_authorized_keys" },
	{ "a/b",			"a_b" },
	{ "dir/",			"dir_" },
	{ "/",				"_" },
	{ "\\Windows\\system.ini",	"_Windows_system.ini" },
	{ "\\\\server\\share\\x",	"__server_share_x" },
	{ "C:\\boot.ini",		"C__boot.ini" },
	{ "C:x",			"C_x" },
	{ "file.txt:stream",		"file.txt_stream" },

	/* parent / current dir and dotfiles */
	{ "..",				"__" },
	{ ".",				"_" },
	{ "...",			"__." },
	{ "../../etc/passwd",		"______etc_passwd" },
	{ "..\\..\\x",			"______x" },
	{ "a/../b",			"a____b" },
	{ "x..y",			"x__y" },
	{ ".hidden",			"_hidden" },
	{ ".bashrc",			"_bashrc" },

	/* control characters */
	{ "a\nb",			"a_b" },
	{ "a\rb\tc",			"a_b_c" },
	{ "\x1b[31mred",		"_[31mred" },
	{ "del\x7f",			"del_" },

	/* characters Windows refuses, and the old set */
	{ "a*b?c\"d<e>f|g",		"a_b_c_d_e_f_g" },
	{ "$HOME%PATH%",		"_HOME_PATH_" },

	/* Windows device names, with or without extension */
	{ "CON",			"_ON" },
	{ "con.txt",			"_on.txt" },
	{ "nul",			"_ul" },
	{ "NUL.tar.gz",			"_UL.tar.gz" },
	{ "Aux",			"_ux" },
	{ "prn.",			"_rn." },
	{ "COM1",			"_OM1" },
	{ "lpt9.log",			"_pt9.log" },
	{ "CON .txt",			"_ON .txt" },

	/*
	 * Names a WebTransport peer sends minimal-webtransport-qir in a GET,
	 * PUSH or datagram header (G-609): it refuses any name this changes,
	 * so the interop runner's names must come through as they are
	 */
	{ "5kR2mX9qAb",			"5kR2mX9qAb" },
	{ "file_1.bin",			"file_1.bin" },
	{ "/../../tmp/x",		"_______tmp_x" },
	{ "..\\x",			"___x" },
	{ ".x.part",			"_x.part" },
	{ "x\r\nPUSH y",		"x__PUSH y" },
};

static int
is_one_component(const char *s)
{
	const char *p;

	if (*s == '.')
		return 0;

	for (p = s; *p; p++) {
		unsigned char c = (unsigned char)*p;

		if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' ||
		    c == ':' || (c == '.' && p[1] == '.'))
			return 0;
	}

	return 1;
}

int
main(int argc, const char **argv)
{
	char buf[128], again[128];
	size_t n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: lws_filename_purify_inplace\n");

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {
		lws_strncpy(buf, cases[n].in, sizeof(buf));
		lws_filename_purify_inplace(buf);

		CHECK(!strcmp(buf, cases[n].out),
		      "case %d: got '%s', expected '%s'\n", (int)n, buf,
		      cases[n].out);
		CHECK(strlen(buf) == strlen(cases[n].in),
		      "case %d: length changed\n", (int)n);
		CHECK(is_one_component(buf),
		      "case %d: '%s' is not one safe component\n", (int)n, buf);

		lws_strncpy(again, buf, sizeof(again));
		lws_filename_purify_inplace(again);
		CHECK(!strcmp(again, buf), "case %d: not idempotent\n", (int)n);
	}

	/* every single byte, alone and as a component of a path */

	for (n = 1; n < 256; n++) {
		buf[0] = (char)n;
		buf[1] = '\0';
		lws_filename_purify_inplace(buf);
		CHECK(is_one_component(buf) && strlen(buf) == 1,
		      "byte 0x%02x alone is unsafe\n", (unsigned int)n);

		buf[0] = '.';
		buf[1] = (char)n;
		buf[2] = '/';
		buf[3] = '\0';
		lws_filename_purify_inplace(buf);
		CHECK(is_one_component(buf) && strlen(buf) == 3,
		      "byte 0x%02x in a path is unsafe\n", (unsigned int)n);
	}

	lwsl_user("Completed: %s (%d ok, %d failed)\n",
		  fails ? "FAIL" : "PASS", oks, fails);

	(void)argc;
	(void)argv;

	return !!fails;
}
