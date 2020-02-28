/*
 * minilex.c
 *
 * High efficiency lexical state parser
 *
 * Copyright (C)2011-2020 Andy Green <andy@warmcat.com>
 *
 * Licensed under MIT
 *
 * Usage: gcc minilex.c -o minilex && ./minilex > lextable.h
 *
 * Run it twice to test parsing on the generated table on stderr
 *
 * Whoo this got a bit complicated by lws-buildtime deselection of some
 * headers optionally.  There are 3 x vars, UNCOMMON, WS, H2 so we make
 * eight copies of the lextable selected by the appropriate #if defined()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* get all the strings */

#define LWS_ROLE_WS 1
#define LWS_WITH_HTTP_UNCOMMON_HEADERS 1
#define LWS_ROLE_H2 1

#include "lextable-strings.h"

#undef LWS_ROLE_WS
#undef LWS_WITH_HTTP_UNCOMMON_HEADERS
#undef LWS_ROLE_H2

/* bitfield for the 8 versions as to which strings exist... index layout
 *
 *        b0      b1 b2
 *  0 =
 *  1 = uncommon
 *  2 =           ws
 *  3 = uncommon  ws
 *  4 =              h2
 *  5 = uncommon     h2
 *  6 =           ws h2
 *  7 = uncommon  ws h2
 */

unsigned char filter_array[] = {
	0xff, 0xff, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xff, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xff, 0xf0, 0xff, 0xaa,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xfa, 0xcc, 0xcc, 0xcc, 0xf0, 0xf0, 0xf0, 0xf0,
	0xf0, 0xfa, 0xff, 0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xfa, 0xfa, 0xfa, 0xff, 0xff, 0xff, 0xff, 0xfa, 0xff,
	0xfa, 0xfa, 0xfa, 0xfa, 0xaa, 0xaa, 0xaa, 0xff, 0xaa, 0xaa,
	0xff, 0xff, 0xff, 0xff, 0xfa, 0xfa, 0xf0, 0xff, 0xff
};

static unsigned char lws_header_implies_psuedoheader_map[] = {
	0x07, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00 /* <-64 */,
	0x0e /* <- 72 */, 0x04 /* <- 80 */, 0, 0, 0, 0
};

/*
 * b7 = 0 = 1-byte seq
 *	    0x08 = fail
 *	    2-byte seq
 *	    0x00 - 0x07, then terminal as given in 2nd byte
	    3-byte seq
 *	    no match: go fwd 3 byte, match: jump fwd by amt in +1/+2 bytes
 *    = 1 = 1-byte seq
 *	    no match: die, match go fwd 1 byte
 */

unsigned char lextable[][2000] = {
	{
			#include "lextable.h"
	},
#define LWS_WITH_HTTP_UNCOMMON_HEADERS
	{
			#include "lextable.h"
	},
#undef LWS_WITH_HTTP_UNCOMMON_HEADERS
#define LWS_ROLE_WS 1
	{
			#include "lextable.h"
	},
#define LWS_WITH_HTTP_UNCOMMON_HEADERS
	{
			#include "lextable.h"
	},
#undef LWS_ROLE_WS
#undef LWS_WITH_HTTP_UNCOMMON_HEADERS
#define LWS_ROLE_H2 1
	{
			#include "lextable.h"
	},
#define LWS_WITH_HTTP_UNCOMMON_HEADERS
	{
			#include "lextable.h"
	},
#undef LWS_WITH_HTTP_UNCOMMON_HEADERS
#define LWS_ROLE_WS 1
	{
			#include "lextable.h"
	},
#define LWS_WITH_HTTP_UNCOMMON_HEADERS 1
	{
			#include "lextable.h"
	},
};

#define PARALLEL 30

struct state {
	char c[PARALLEL];
	int state[PARALLEL];
	int count;
	int bytepos;

	int real_pos;
};

static unsigned char pseudomap[8][16];

struct state state[1000];
int next = 1;

#define FAIL_CHAR 0x08

int lextable_decode(int version, int pos, char c)
{
	while (1) {
		if (lextable[version][pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
			if ((lextable[version][pos] & 0x7f) != c)
				return -1;
			/* fall thru */
			pos++;
			if (lextable[version][pos] == FAIL_CHAR)
				return -1;
			return pos;
		} else { /* b7 = 0, end or 3-byte */
			if (lextable[version][pos] < FAIL_CHAR) /* terminal marker */
				return pos;

			if (lextable[version][pos] == c) /* goto */
				return pos + (lextable[version][pos + 1]) +
						(lextable[version][pos + 2] << 8);
			/* fall thru goto */
			pos += 3;
			/* continue */
		}
	}
}

int issue(int version)
{
	const char *rset[200];
	int n = 0;
	int m;
	int prev;
	int walk;
	int saw;
	int y;
	int j;
	int pos = 0;

	int setmembers = 0;

	memset(rset, 0, sizeof(rset));

	printf("#if %cdefined(LWS_WITH_HTTP_UNCOMMON_HEADERS) && "
		 "%cdefined(LWS_ROLE_WS) && "
		 "%cdefined(LWS_ROLE_H2)\n", version & 1 ? ' ' : '!',
		     version & 2 ? ' ' : '!', version & 4 ? ' ' : '!');

	/*
	 * let's create version's view of the set of strings
	 */

	for (n = 0; n < sizeof(set) / sizeof(set[0]); n++)
		if (filter_array[n] & (1 << version)) {
			printf("\t/* %d: %d: %s */\n", setmembers, n, set[n]);
			if (lws_header_implies_psuedoheader_map[n >> 3] & (1 << (n & 7)))
				pseudomap[version][(setmembers >> 3)] |= 1 << (setmembers & 7);
			rset[setmembers++] = set[n];
		}

	n = 0;
	while (n < setmembers) {

		m = 0;
		walk = 0;
		prev = 0;

		if (rset[n][0] == '\0') {
			n++;
			continue;
		}

		while (rset[n][m]) {

			saw = 0;
			for (y = 0; y < state[walk].count; y++)
				if (state[walk].c[y] == rset[n][m]) {
					/* exists -- go forward */
					walk = state[walk].state[y];
					saw = 1;
					break;
				}

			if (saw)
				goto again;

			/* something we didn't see before */

			state[walk].c[state[walk].count] = rset[n][m];

			state[walk].state[state[walk].count] = next;
			state[walk].count++;
			walk = next++;
again:
			m++;
		}

		state[walk].c[0] = n++;
		state[walk].state[0] = 0; /* terminal marker */
		state[walk].count = 1;
	}

	walk = 0;
	for (n = 0; n < next; n++) {
		state[n].bytepos = walk;
		walk += (2 * state[n].count);
	}

	/* compute everyone's position first */

	pos = 0;
	walk = 0;
	for (n = 0; n < next; n++) {

		state[n].real_pos = pos;

		for (m = 0; m < state[n].count; m++) {

			if (state[n].state[m] == 0)
				pos += 2; /* terminal marker */
			else { /* c is a character */
				if ((state[state[n].state[m]].bytepos -
								walk) == 2)
					pos++;
				else {
					pos += 3;
					if (m == state[n].count - 1)
						pos++; /* fail */
				}
			}
			walk += 2;
		}
	}

	walk = 0;
	pos = 0;
	for (n = 0; n < next; n++) {
		for (m = 0; m < state[n].count; m++) {

			if (!m)
				fprintf(stdout, "/* pos %04x: %3d */ ",
							  state[n].real_pos, n);
			else
				fprintf(stdout, "                    ");

			y = state[n].c[m];
			saw = state[n].state[m];

			if (saw == 0) { // c is a terminal then

				if (y > 0x7ff) {
					fprintf(stderr, "terminal too big\n");
					return 2;
				}

				fprintf(stdout, "   0x%02X, 0x%02X           "
					"       "
					"/* - terminal marker %2d - */,\n",
						    y >> 8, y & 0xff, y & 0x7f);
				pos += 2;
				walk += 2;
				continue;
			}

			/* c is a character */

			prev = y &0x7f;
			if (prev < 32 || prev > 126)
				prev = '.';


			if ((state[saw].bytepos - walk) == 2) {
				fprintf(stdout, "   0x%02X /* '%c' -> */,\n",
						y | 0x80, prev);
				pos++;
				walk += 2;
				continue;
			}

			j = state[saw].real_pos - pos;

			if (j > 0xffff) {
				fprintf(stderr,
				  "Jump > 64K bytes ahead (%d to %d)\n",
					state[n].real_pos, state[saw].real_pos);
				return 1;
			}
			fprintf(stdout, "   0x%02X /* '%c' */, 0x%02X, 0x%02X  "
				"/* (to 0x%04X state %3d) */,\n",
				y, prev,
				j & 0xff, j >> 8,
				state[saw].real_pos, saw);
			pos += 3;

			if (m == state[n].count - 1) {
				fprintf(stdout,
				  "                       0x%02X, /* fail */\n",
								FAIL_CHAR);
				pos++; /* fail */
			}

			walk += 2;
		}
	}

	fprintf(stdout, "/* total size %d bytes */\n", pos);

	printf("#endif\n\n");

	/*
	 * Try to parse every legal input string
	 */

	for (n = 0; n < setmembers; n++) {
		walk = 0;
		m = 0;
		y = -1;

		if (rset[n][0] == '\0')
			continue;

		fprintf(stderr, "  trying %d '%s'\n", n, rset[n]);

		while (rset[n][m]) {
			walk = lextable_decode(version, walk, rset[n][m]);
			if (walk < 0) {
				fprintf(stderr, "failed\n");
				return 3;
			}

			if (lextable[version][walk] < FAIL_CHAR) {
				y = (lextable[version][walk] << 8) +
				     lextable[version][walk + 1];
				break;
			}
			m++;
		}

		if (y != n) {
			fprintf(stderr, "decode failed %d\n", y);
			return 4;
		}
	}

	fprintf(stderr, "All decode OK\n");

	return 0;
}

int main(void)
{
	int m, n;

	for (n = 0; n < 8; n++) {
		issue(n);
	}

	printf("\n/*\n");

	for (n = 0; n < 8; n++) {

		printf("#if %cdefined(LWS_WITH_HTTP_UNCOMMON_HEADERS) && "
			 "%cdefined(LWS_ROLE_WS) && "
			 "%cdefined(LWS_ROLE_H2)\n", n & 1 ? ' ' : '!',
			     n & 2 ? ' ' : '!', n & 4 ? ' ' : '!');

		printf("static uint8_t lws_header_implies_psuedoheader_map[] = {\n\t");

		for (m = 0; m < sizeof(pseudomap[n]); m++)
			printf("0x%02x,", pseudomap[n][m]);

		printf("\n};\n");

		printf("#endif\n");
	}

	printf("*/\n");

	fprintf(stderr, "did all the variants\n");
}
