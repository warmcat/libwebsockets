/*
 * minilex.c
 *
 * High efficiency lexical state parser
 *
 * Copyright (C)2011-2013 Andy Green <andy@warmcat.com>
 *
 * Licensed under LGPL2
 *
 * Usage: gcc minilex.c -o minilex && ./minilex > lextable.h
 *
 * Run it twice to test parsing on the generated table on stderr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* set of parsable strings -- ALL LOWER CASE */

const char *set[] = {
	"get ",
	"post ",
	"host:",
	"connection:",
	"sec-websocket-key1:",
	"sec-websocket-key2:",
	"sec-websocket-protocol:",
	"upgrade:",
	"origin:",
	"sec-websocket-draft:",
	"\x0d\x0a",

	"sec-websocket-key:",
	"sec-websocket-version:",
	"sec-websocket-origin:",

	"sec-websocket-extensions:",

	"sec-websocket-accept:",
	"sec-websocket-nonce:",
	"http/1.1 ",

	"accept:",
	"if-modified-since:",
	"accept-encoding:",
	"accept-language:",
	"pragma:",
	"cache-control:",
	"authorization:",
	"cookie:",
	"content-length:",
	"content-type:",
	"date:",
	"range:",
	"referer:",
	"", /* not matchable */

};

unsigned char lextable[] = {
	#include "lextable.h"
};

#define PARALLEL 30

struct state {
	char c[PARALLEL];
	int state[PARALLEL];
	int count;
	int bytepos;
};

struct state state[1000];
int next = 1;


int lextable_decode(int pos, char c)
{
	while (1) {
		if (!lextable[pos + 1]) /* terminal marker */
			return pos;

		if ((lextable[pos] & 0x7f) == c) /* goto */
			return pos + (lextable[pos + 1] << 1);

		if (lextable[pos] & 0x80) /* fail */
			return -1;

		pos += 2;
	}
}


int main(void)
{
	int n = 0;
	int m = 0;
	int prev;
	char c;
	int walk;
	int saw;
	int y;

	while (n < sizeof(set) / sizeof(set[0])) {

		m = 0;
		walk = 0;
		prev = 0;

		if (set[n][0] == '\0') {
			n++;
			continue;
		}

		while (set[n][m]) {

			saw = 0;
			for (y = 0; y < state[walk].count; y++)
				if (state[walk].c[y] == set[n][m]) {
					/* exists -- go forward */
					walk = state[walk].state[y];
					saw = 1;
					break;
				}

			if (saw)
				goto again;

			/* something we didn't see before */

			state[walk].c[state[walk].count] = set[n][m];

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

	walk = 0;
	for (n = 0; n < next; n++) {
		for (m = 0; m < state[n].count; m++) {

			if (!m)
				fprintf(stdout, "/* pos %3d: state %3d */ ",
								      walk, n);
			else
				fprintf(stdout, "                         ");

			y = state[n].c[m];
			saw = state[n].state[m];

			if (m == state[n].count - 1)
				y |= 0x80; /* last option */

			if (saw == 0) // c is a terminal then
				fprintf(stdout, "   0x%02X, 0x00            "
					"/* - terminal marker %2d - */, \n",
								  y, y - 0x80);
			else { /* c is a character and we need a byte delta */
				if ((state[saw].bytepos - walk) / 2 > 0xff) {
					fprintf(stdout,
					  "Tried to jump > 510 bytes ahead\n");
					return 1;
				}
				prev = y &0x7f;
				if (prev < 32 || prev > 126)
					prev = '.';
				fprintf(stdout, "   0x%02X /* '%c' */, 0x%02X  "
					"/* (to pos %3d state %3d) */,\n",
					y, prev,
					(state[saw].bytepos - walk) / 2,
					state[saw].bytepos, saw);
			}
			walk += 2;
		}
	}

	fprintf(stdout, "/* total size %d bytes */\n", walk);

	/*
	 * Test parser... real parser code is the same
	 */

	for (n = 0; n < sizeof(set) / sizeof(set[0]); n++) {
		walk = 0;
		m = 0;

		if (set[n][0] == '\0')
			continue;

		fprintf(stderr, "Trying '%s'\n", set[n]);

		while (set[n][m]) {
			walk = lextable_decode(walk, set[n][m]);
			if (walk < 0) {
				fprintf(stderr, "failed\n");
				break;
			}
			if (lextable[walk + 1] == 0) {
				fprintf(stderr, "decode: %d\n",
						lextable[walk] & 0x7f);
				break;
			}
			m++;
		}
	}

	return 0;
}
