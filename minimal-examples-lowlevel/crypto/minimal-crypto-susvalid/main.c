/*
 * lws-crypto-susvalid
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

static const char *
is_suspicious(uint32_t cp)
{
	/* Zero Width Spaces and direction marks (LRM, RLM) */
	if (cp >= 0x200B && cp <= 0x200F) return "Zero Width Space or Direction Mark";
	/* Bidi Override Controls (LRE, RLE, PDF, LRO, RLO) */
	if (cp >= 0x202A && cp <= 0x202E) return "Bidi Override Control";
	/* Word joiners and Bidi isolate controls (LRI, RLI, FSI, PDI) */
	if (cp >= 0x2060 && cp <= 0x2069) return "Word Joiner or Bidi Isolate";
	/* Variation Selectors */
	if (cp >= 0xFE00 && cp <= 0xFE0F) return "Variation Selector";
	/* Variation Selectors Supplement */
	if (cp >= 0xE0100 && cp <= 0xE01EF) return "Variation Selectors Supplement";
	/* Tags Block */
	if (cp >= 0xE0000 && cp <= 0xE007F) return "Tags Block";

	/* Hangul Fillers, BOM, Mongolian Vowel Separator */
	if (cp == 0x3164 || cp == 0xFEFF || cp == 0xFFA0 || cp == 0x180E) return "Filler, BOM, or Separator";

	return NULL;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	/* RFC 2045: hexadecimal letters A through F must be uppercase */
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

struct parse_state {
	int line, col;
	size_t raw_byte_pos;

	uint8_t ring[64];
	size_t ring_head;
	size_t ring_count;

	int fd;
	int issues;

	unsigned int codepoint;
	int utf8_expect;
	int utf8_invalid;

	int qp_state;
	char qp_hex1;
};

static void
dump_context(struct parse_state *s)
{
	uint8_t temp[80];
	size_t i, start;
	ssize_t ahead = 0;

	if (!s->ring_count)
		return;

	start = (s->ring_head + 64 - s->ring_count) % 64;
	for (i = 0; i < s->ring_count; i++)
		temp[i] = s->ring[(start + i) % 64];

	if (s->fd >= 0) {
		off_t cur = lseek(s->fd, 0, SEEK_CUR);
		if (cur >= (off_t)0) {
			lseek(s->fd, (off_t)s->raw_byte_pos, SEEK_SET);
			ahead = read(s->fd, temp + s->ring_count, 16);
			lseek(s->fd, cur, SEEK_SET);
		}
		if (ahead < 0)
			ahead = 0;
	}

	lwsl_hexdump_warn(temp, s->ring_count + (size_t)ahead);
}

static void
emit_byte(struct parse_state *s, uint8_t b)
{
	if (s->utf8_expect == 0) {
		if ((b & 0x80) == 0) {
			s->codepoint = b;
			s->utf8_expect = 0;
		} else if ((b & 0xE0) == 0xC0) {
			s->codepoint = b & 0x1F;
			s->utf8_expect = 1;
		} else if ((b & 0xF0) == 0xE0) {
			s->codepoint = b & 0x0F;
			s->utf8_expect = 2;
		} else if ((b & 0xF8) == 0xF0) {
			s->codepoint = b & 0x07;
			s->utf8_expect = 3;
		} else {
			/* Invalid UTF-8 start byte */
			lwsl_warn("Invalid UTF-8 start byte 0x%02X found at byte %zu (line %d, col %d)\n",
				  b, s->raw_byte_pos, s->line, s->col);
			dump_context(s);
			s->issues++;
			s->utf8_invalid = 1;
			s->utf8_expect = 0;
			return;
		}
	} else {
		if ((b & 0xC0) != 0x80) {
			/* Invalid continuation byte */
			lwsl_warn("Invalid UTF-8 continuation byte 0x%02X found at byte %zu (line %d, col %d)\n",
				  b, s->raw_byte_pos, s->line, s->col);
			dump_context(s);
			s->issues++;
			s->utf8_invalid = 1;
			s->utf8_expect = 0;
			return;
		}
		s->codepoint = (s->codepoint << 6) | (b & 0x3F);
		s->utf8_expect--;
	}

	if (s->utf8_expect == 0) {
		const char *reason = is_suspicious(s->codepoint);
		if (reason) {
			lwsl_notice("Suspicious Unicode U+%04X (%s) found at byte %zu (line %d, col %d)\n",
				    s->codepoint, reason, s->raw_byte_pos, s->line, s->col);
			s->issues++;
		}
	}
}

static void
process_byte(struct parse_state *s, uint8_t b)
{
	int v1, v2;

	s->raw_byte_pos++;

	s->ring[s->ring_head] = b;
	s->ring_head = (s->ring_head + 1) % sizeof(s->ring);
	if (s->ring_count < sizeof(s->ring))
		s->ring_count++;

	/* basic line/col accounting on the raw input stream */
	if (b == '\n') {
		s->line++;
		s->col = 1;
	} else {
		s->col++;
	}

	/* Quoted-Printable state machine */
	switch (s->qp_state) {
	case 0: /* Normal */
		if (b == '=') {
			s->qp_state = 1;
		} else {
			emit_byte(s, b);
		}
		break;
	case 1: /* Seen '=' */
		if (b == '\r') {
			s->qp_state = 2;
		} else if (b == '\n') {
			s->qp_state = 0; /* soft line break */
		} else {
			v1 = hex_val((char)b);
			if (v1 >= 0) {
				s->qp_hex1 = (char)b;
				s->qp_state = 3;
			} else {
				/* Not a valid hex char, treat '=' literally */
				emit_byte(s, '=');
				emit_byte(s, b);
				s->qp_state = 0;
			}
		}
		break;
	case 2: /* Seen '=\r' */
		if (b == '\n') {
			s->qp_state = 0; /* soft line break */
		} else {
			/* Invalid soft line break, treat literally */
			emit_byte(s, '=');
			emit_byte(s, '\r');
			if (b == '=') {
				s->qp_state = 1;
			} else {
				emit_byte(s, b);
				s->qp_state = 0;
			}
		}
		break;
	case 3: /* Seen '=X' */
		v1 = hex_val(s->qp_hex1);
		v2 = hex_val((char)b);
		if (v2 >= 0) {
			emit_byte(s, (uint8_t)((v1 << 4) | v2));
		} else {
			/* Invalid second hex, emit literal */
			emit_byte(s, '=');
			emit_byte(s, (uint8_t)s->qp_hex1);
			if (b == '=') {
				s->qp_state = 1;
			} else {
				emit_byte(s, b);
			}
		}
		s->qp_state = 0;
		break;
	}
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct parse_state s;
	const char *p;
	uint8_t buf[1024];
	ssize_t n;
	int fd;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS Suspicious Unicode Validator\n");

	if (argc < 2 || lws_cmdline_option(argc, argv, "-h")) {
		lwsl_user("Usage: %s <file>\n", argv[0]);
		return 1;
	}

	lwsl_user("Checking %s for suspicious bitwise Unicode and Quoted-Printable (email) encoding errors...\n", argv[argc - 1]);

	fd = open(argv[argc - 1], O_RDONLY);
	if (fd < 0) {
		lwsl_err("Failed to open %s\n", argv[argc - 1]);
		return 1;
	}

	memset(&s, 0, sizeof(s));
	s.line = 1;
	s.col = 1;
	s.fd = fd;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (ssize_t i = 0; i < n; i++)
			process_byte(&s, buf[i]);
	}

	close(fd);

	if (s.utf8_invalid)
		lwsl_warn("Warning: Invalid UTF-8 sequences were encountered.\n");

	if (s.issues)
		lwsl_user("Completed with %d issue(s) found.\n", s.issues);
	else
		lwsl_user("Completed cleanly. 0 issues found.\n");

	return 0;
}
