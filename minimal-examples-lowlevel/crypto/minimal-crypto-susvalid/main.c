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

static int
is_suspicious(uint32_t cp)
{
	/* Zero Width Spaces and direction marks (LRM, RLM) */
	if (cp >= 0x200B && cp <= 0x200F) return 1;
	/* Bidi Override Controls (LRE, RLE, PDF, LRO, RLO) */
	if (cp >= 0x202A && cp <= 0x202E) return 1;
	/* Word joiners and Bidi isolate controls (LRI, RLI, FSI, PDI) */
	if (cp >= 0x2060 && cp <= 0x2069) return 1;
	/* Variation Selectors */
	if (cp >= 0xFE00 && cp <= 0xFE0F) return 1;
	/* Variation Selectors Supplement */
	if (cp >= 0xE0100 && cp <= 0xE01EF) return 1;
	/* Tags Block */
	if (cp >= 0xE0000 && cp <= 0xE007F) return 1;

	/* Hangul Fillers, BOM, Mongolian Vowel Separator */
	if (cp == 0x3164 || cp == 0xFEFF || cp == 0xFFA0 || cp == 0x180E) return 1;

	return 0;
}

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

struct parse_state {
	int line, col;
	size_t raw_byte_pos;

	unsigned int codepoint;
	int utf8_expect;
	int utf8_invalid;

	int qp_state;
	char qp_hex1;
};

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
			s->utf8_invalid = 1;
			s->utf8_expect = 0;
			return;
		}
	} else {
		if ((b & 0xC0) != 0x80) {
			/* Invalid continuation byte */
			s->utf8_invalid = 1;
			s->utf8_expect = 0;
			return;
		}
		s->codepoint = (s->codepoint << 6) | (b & 0x3F);
		s->utf8_expect--;
	}

	if (s->utf8_expect == 0 && !s->utf8_invalid) {
		if (is_suspicious(s->codepoint)) {
			lwsl_notice("Suspicious Unicode U+%04X found at byte %zu (line %d, col %d)\n",
				    s->codepoint, s->raw_byte_pos, s->line, s->col);
		}
	}
}

static void
process_byte(struct parse_state *s, uint8_t b)
{
	int v1, v2;

	s->raw_byte_pos++;

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

	fd = open(argv[argc - 1], O_RDONLY);
	if (fd < 0) {
		lwsl_err("Failed to open %s\n", argv[argc - 1]);
		return 1;
	}

	memset(&s, 0, sizeof(s));
	s.line = 1;
	s.col = 1;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (ssize_t i = 0; i < n; i++)
			process_byte(&s, buf[i]);
	}

	close(fd);

	if (s.utf8_invalid)
		lwsl_warn("Warning: Invalid UTF-8 sequences were encountered.\n");

	return 0;
}
