/*
 * minilex.c
 *
 * High efficiency lexical s parser
 *
 * Copyright (C)2011-2022 Andy Green <andy@warmcat.com>
 *
 * Licensed under MIT
 *
 * This is a version of the original lws http minilex that can handle ambiguous
 * terminals and accepts the terminal list from stdin, producing a parsing
 * table on stdout.
 *
 * Usage: gcc minilex.c -o minilex && \
 * 	cat css-lextable-strings.txt | ./minilex > css-lextable.h
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define PARALLEL 30

struct s {
	char c[PARALLEL];
	int s[PARALLEL];
	int count;
	int bytepos;

	int real_pos;
};

struct s s[1000];
int next = 1;

#define FAIL_CHAR 0x08

int
main(void)
{
	const char *rset[200];
	int n = 0;
	int m;
	int prev;
	int walk;
	int y;
	int j;
	int pos = 0;
	size_t sl = 0;
	char *line = NULL;
	ssize_t r;
	int setmembers = 0;

	memset(rset, 0, sizeof(rset));

	/* Step 1: collect the strings from stdin and list in a comment */

	do {
		r = getline(&line, &sl, stdin);
		if (r <= 0 || setmembers == sizeof(rset) / sizeof(rset[0]))
			break;
		if (line[r - 1] == '\n')
			line[r - 1] = '\0';
		printf("\t/* %d: %s */\n", setmembers, line);
		rset[setmembers++] = strdup(line);
	} while (1);

	free(line);

	/* Step 2: produce an enum template for the strings in a comment */

	printf("/* enum {\n");

	n = 0;
	while (n < setmembers) {
		char def[100];

		strncpy(def, rset[n], sizeof(def));
		j = 0;
		while (def[j]) {
			if (def[j] == '-')
				def[j] = '_';
			if (def[j] == ':' && !def[j + 1])
				def[j] = '\0';
			else
				if (def[j] >= 'a' && def[j] <= 'z')
					def[j] = def[j] - ('a' - 'A');

			j++;
		}
		printf("\tXXXX_%s,\n", def);
		n++;
	}

	printf("}; */\n\n");

	/*
	 * Step 3: issue each character of each string into the tree, reusing
	 *         any existing common substring subtrees
	 */

	n = 0;
	while (n < setmembers) {
		m = 0;
		walk = 0;
		prev = 0;

		while (rset[n][m]) {

			int saw = 0;
			for (y = 0; y < s[walk].count; y++)
				if (s[walk].c[y] == rset[n][m]) {
					/* exists -- go forward */
					walk = s[walk].s[y];
					saw = 1;
					break;
				}

			if (saw) {
				m++;
				continue;
			}

			/* If something we didn't see before, insert a
			 * conditional goto for it... however if there
			 * is already a terminal, we must insert the
			 * conditional before it.  This handles
			 * matches on "xx" and "xxy" where "xx" is
			 * listed first */

			s[walk].count++;

			if (s[walk].count > 1 &&
			    !s[walk].s[s[walk].count - 2]) {
				/*
				 * This s currently has a terminal
				 * at the end... insert a conditional
				 * behind it
				 */
				s[walk].c[s[walk].count - 1] =
					s[walk].c[s[walk].count - 2];
				s[walk].s[s[walk].count - 1] =
					s[walk].s[s[walk].count - 2];

				s[walk].c[s[walk].count - 2] = rset[n][m];
				s[walk].s[s[walk].count - 2] = next;
			} else {
				/* just append a conditional */
				s[walk].c[s[walk].count - 1] = rset[n][m];
				s[walk].s[s[walk].count - 1] = next;
			}

			walk = next++;

			m++;
		}

		/* reached the end of rset[n] */

		s[walk].c[s[walk].count] = n++;
		s[walk].s[s[walk].count++] = 0; /* terminal marker */
	}

	walk = 0;
	for (n = 0; n < next; n++) {
		s[n].bytepos = walk;
		walk += (2 * s[n].count);
	}

	/* compute everyone's position first */

	pos = 0;
	walk = 0;
	for (n = 0; n < next; n++) {

		s[n].real_pos = pos;

		for (m = 0; m < s[n].count; m++) {

			if (s[n].s[m] == 0)
				pos += 2; /* terminal marker */
			else { /* c is a character */
				if ((s[s[n].s[m]].bytepos -
								walk) == 2)
					pos++;
				else {
					pos += 3;
					if (m == s[n].count - 1)
						pos++; /* fail */
				}
			}
			walk += 2;
		}
	}

	walk = 0;
	pos = 0;
	for (n = 0; n < next; n++) {
		for (m = 0; m < s[n].count; m++) {

			int saw = s[n].s[m];

			if (!m)
				fprintf(stdout, "/* pos %04x: %3d */ ",
							  s[n].real_pos, n);
			else
				fprintf(stdout, "                    ");

			y = s[n].c[m];

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


			if ((s[saw].bytepos - walk) == 2) {
				fprintf(stdout, "   0x%02X /* '%c' -> */,\n",
						y | 0x80, prev);
				pos++;
				walk += 2;
				continue;
			}

			j = s[saw].real_pos - pos;

			if (j > 0xffff) {
				fprintf(stderr,
				  "Jump > 64K bytes ahead (%d to %d)\n",
					s[n].real_pos, s[saw].real_pos);
				return 1;
			}
			fprintf(stdout, "   0x%02X /* '%c' */, 0x%02X, 0x%02X  "
				"/* (to 0x%04X s %3d) */,\n",
				y, prev,
				j & 0xff, j >> 8,
				s[saw].real_pos, saw);
			pos += 3;

			if (m == s[n].count - 1) {
				fprintf(stdout,
				  "                       0x%02X, /* fail */\n",
								FAIL_CHAR);
				pos++; /* fail */
			}

			walk += 2;
		}
	}

	fprintf(stdout, "/* total size %d bytes */\n", pos);

	for (n = 0;n < setmembers; n++) {
		free((void *)rset[n]);
		rset[n] = NULL;
	}

	return 0;
}
