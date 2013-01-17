#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *set[] = {
	"GET ",
	"Host:",
	"Connection:",
	"Sec-WebSocket-Key1:",
	"Sec-WebSocket-Key2:",
	"Sec-WebSocket-Protocol:",
	"Upgrade:",
	"Origin:",
	"Sec-WebSocket-Draft:",
	"\x0d\x0a",

	"Sec-WebSocket-Key:",
	"Sec-WebSocket-Version:",
	"Sec-WebSocket-Origin:",

	"Sec-WebSocket-Extensions:",

	"Sec-WebSocket-Accept:",
	"Sec-WebSocket-Nonce:",
	"HTTP/1.1 ",
};

unsigned char lextable[] = {
/* pos 0: state 0 */
   0x47 /* 'G' */, 0x07 /* to pos 14 state 1 */,
   0x48 /* 'H' */, 0x0A /* to pos 22 state 5 */,
   0x43 /* 'C' */, 0x0F /* to pos 34 state 10 */,
   0x53 /* 'S' */, 0x19 /* to pos 56 state 21 */,
   0x55 /* 'U' */, 0x3F /* to pos 134 state 51 */,
   0x4F /* 'O' */, 0x46 /* to pos 150 state 59 */,
   0x8D /* '.' */, 0x52 /* to pos 176 state 72 */,
/* pos 14: state 1 */
   0xC5 /* 'E' */, 0x01 /* to pos 16 state 2 */,
/* pos 16: state 2 */
   0xD4 /* 'T' */, 0x01 /* to pos 18 state 3 */,
/* pos 18: state 3 */
   0xA0 /* ' ' */, 0x01 /* to pos 20 state 4 */,
/* pos 20: state 4 */
   0x80, 0x00 /* terminal marker */, 
/* pos 22: state 5 */
   0x6F /* 'o' */, 0x02 /* to pos 26 state 6 */,
   0xD4 /* 'T' */, 0x76 /* to pos 260 state 114 */,
/* pos 26: state 6 */
   0xF3 /* 's' */, 0x01 /* to pos 28 state 7 */,
/* pos 28: state 7 */
   0xF4 /* 't' */, 0x01 /* to pos 30 state 8 */,
/* pos 30: state 8 */
   0xBA /* ':' */, 0x01 /* to pos 32 state 9 */,
/* pos 32: state 9 */
   0x81, 0x00 /* terminal marker */, 
/* pos 34: state 10 */
   0xEF /* 'o' */, 0x01 /* to pos 36 state 11 */,
/* pos 36: state 11 */
   0xEE /* 'n' */, 0x01 /* to pos 38 state 12 */,
/* pos 38: state 12 */
   0xEE /* 'n' */, 0x01 /* to pos 40 state 13 */,
/* pos 40: state 13 */
   0xE5 /* 'e' */, 0x01 /* to pos 42 state 14 */,
/* pos 42: state 14 */
   0xE3 /* 'c' */, 0x01 /* to pos 44 state 15 */,
/* pos 44: state 15 */
   0xF4 /* 't' */, 0x01 /* to pos 46 state 16 */,
/* pos 46: state 16 */
   0xE9 /* 'i' */, 0x01 /* to pos 48 state 17 */,
/* pos 48: state 17 */
   0xEF /* 'o' */, 0x01 /* to pos 50 state 18 */,
/* pos 50: state 18 */
   0xEE /* 'n' */, 0x01 /* to pos 52 state 19 */,
/* pos 52: state 19 */
   0xBA /* ':' */, 0x01 /* to pos 54 state 20 */,
/* pos 54: state 20 */
   0x82, 0x00 /* terminal marker */, 
/* pos 56: state 21 */
   0xE5 /* 'e' */, 0x01 /* to pos 58 state 22 */,
/* pos 58: state 22 */
   0xE3 /* 'c' */, 0x01 /* to pos 60 state 23 */,
/* pos 60: state 23 */
   0xAD /* '-' */, 0x01 /* to pos 62 state 24 */,
/* pos 62: state 24 */
   0xD7 /* 'W' */, 0x01 /* to pos 64 state 25 */,
/* pos 64: state 25 */
   0xE5 /* 'e' */, 0x01 /* to pos 66 state 26 */,
/* pos 66: state 26 */
   0xE2 /* 'b' */, 0x01 /* to pos 68 state 27 */,
/* pos 68: state 27 */
   0xD3 /* 'S' */, 0x01 /* to pos 70 state 28 */,
/* pos 70: state 28 */
   0xEF /* 'o' */, 0x01 /* to pos 72 state 29 */,
/* pos 72: state 29 */
   0xE3 /* 'c' */, 0x01 /* to pos 74 state 30 */,
/* pos 74: state 30 */
   0xEB /* 'k' */, 0x01 /* to pos 76 state 31 */,
/* pos 76: state 31 */
   0xE5 /* 'e' */, 0x01 /* to pos 78 state 32 */,
/* pos 78: state 32 */
   0xF4 /* 't' */, 0x01 /* to pos 80 state 33 */,
/* pos 80: state 33 */
   0xAD /* '-' */, 0x01 /* to pos 82 state 34 */,
/* pos 82: state 34 */
   0x4B /* 'K' */, 0x08 /* to pos 98 state 35 */,
   0x50 /* 'P' */, 0x10 /* to pos 116 state 42 */,
   0x44 /* 'D' */, 0x27 /* to pos 164 state 66 */,
   0x56 /* 'V' */, 0x2F /* to pos 182 state 75 */,
   0x4F /* 'O' */, 0x36 /* to pos 198 state 83 */,
   0x45 /* 'E' */, 0x3C /* to pos 212 state 90 */,
   0x41 /* 'A' */, 0x46 /* to pos 234 state 101 */,
   0xCE /* 'N' */, 0x4C /* to pos 248 state 108 */,
/* pos 98: state 35 */
   0xE5 /* 'e' */, 0x01 /* to pos 100 state 36 */,
/* pos 100: state 36 */
   0xF9 /* 'y' */, 0x01 /* to pos 102 state 37 */,
/* pos 102: state 37 */
   0x31 /* '1' */, 0x03 /* to pos 108 state 38 */,
   0x32 /* '2' */, 0x04 /* to pos 112 state 40 */,
   0xBA /* ':' */, 0x25 /* to pos 180 state 74 */,
/* pos 108: state 38 */
   0xBA /* ':' */, 0x01 /* to pos 110 state 39 */,
/* pos 110: state 39 */
   0x83, 0x00 /* terminal marker */, 
/* pos 112: state 40 */
   0xBA /* ':' */, 0x01 /* to pos 114 state 41 */,
/* pos 114: state 41 */
   0x84, 0x00 /* terminal marker */, 
/* pos 116: state 42 */
   0xF2 /* 'r' */, 0x01 /* to pos 118 state 43 */,
/* pos 118: state 43 */
   0xEF /* 'o' */, 0x01 /* to pos 120 state 44 */,
/* pos 120: state 44 */
   0xF4 /* 't' */, 0x01 /* to pos 122 state 45 */,
/* pos 122: state 45 */
   0xEF /* 'o' */, 0x01 /* to pos 124 state 46 */,
/* pos 124: state 46 */
   0xE3 /* 'c' */, 0x01 /* to pos 126 state 47 */,
/* pos 126: state 47 */
   0xEF /* 'o' */, 0x01 /* to pos 128 state 48 */,
/* pos 128: state 48 */
   0xEC /* 'l' */, 0x01 /* to pos 130 state 49 */,
/* pos 130: state 49 */
   0xBA /* ':' */, 0x01 /* to pos 132 state 50 */,
/* pos 132: state 50 */
   0x85, 0x00 /* terminal marker */, 
/* pos 134: state 51 */
   0xF0 /* 'p' */, 0x01 /* to pos 136 state 52 */,
/* pos 136: state 52 */
   0xE7 /* 'g' */, 0x01 /* to pos 138 state 53 */,
/* pos 138: state 53 */
   0xF2 /* 'r' */, 0x01 /* to pos 140 state 54 */,
/* pos 140: state 54 */
   0xE1 /* 'a' */, 0x01 /* to pos 142 state 55 */,
/* pos 142: state 55 */
   0xE4 /* 'd' */, 0x01 /* to pos 144 state 56 */,
/* pos 144: state 56 */
   0xE5 /* 'e' */, 0x01 /* to pos 146 state 57 */,
/* pos 146: state 57 */
   0xBA /* ':' */, 0x01 /* to pos 148 state 58 */,
/* pos 148: state 58 */
   0x86, 0x00 /* terminal marker */, 
/* pos 150: state 59 */
   0xF2 /* 'r' */, 0x01 /* to pos 152 state 60 */,
/* pos 152: state 60 */
   0xE9 /* 'i' */, 0x01 /* to pos 154 state 61 */,
/* pos 154: state 61 */
   0xE7 /* 'g' */, 0x01 /* to pos 156 state 62 */,
/* pos 156: state 62 */
   0xE9 /* 'i' */, 0x01 /* to pos 158 state 63 */,
/* pos 158: state 63 */
   0xEE /* 'n' */, 0x01 /* to pos 160 state 64 */,
/* pos 160: state 64 */
   0xBA /* ':' */, 0x01 /* to pos 162 state 65 */,
/* pos 162: state 65 */
   0x87, 0x00 /* terminal marker */, 
/* pos 164: state 66 */
   0xF2 /* 'r' */, 0x01 /* to pos 166 state 67 */,
/* pos 166: state 67 */
   0xE1 /* 'a' */, 0x01 /* to pos 168 state 68 */,
/* pos 168: state 68 */
   0xE6 /* 'f' */, 0x01 /* to pos 170 state 69 */,
/* pos 170: state 69 */
   0xF4 /* 't' */, 0x01 /* to pos 172 state 70 */,
/* pos 172: state 70 */
   0xBA /* ':' */, 0x01 /* to pos 174 state 71 */,
/* pos 174: state 71 */
   0x88, 0x00 /* terminal marker */, 
/* pos 176: state 72 */
   0x8A /* '.' */, 0x01 /* to pos 178 state 73 */,
/* pos 178: state 73 */
   0x89, 0x00 /* terminal marker */, 
/* pos 180: state 74 */
   0x8A, 0x00 /* terminal marker */, 
/* pos 182: state 75 */
   0xE5 /* 'e' */, 0x01 /* to pos 184 state 76 */,
/* pos 184: state 76 */
   0xF2 /* 'r' */, 0x01 /* to pos 186 state 77 */,
/* pos 186: state 77 */
   0xF3 /* 's' */, 0x01 /* to pos 188 state 78 */,
/* pos 188: state 78 */
   0xE9 /* 'i' */, 0x01 /* to pos 190 state 79 */,
/* pos 190: state 79 */
   0xEF /* 'o' */, 0x01 /* to pos 192 state 80 */,
/* pos 192: state 80 */
   0xEE /* 'n' */, 0x01 /* to pos 194 state 81 */,
/* pos 194: state 81 */
   0xBA /* ':' */, 0x01 /* to pos 196 state 82 */,
/* pos 196: state 82 */
   0x8B, 0x00 /* terminal marker */, 
/* pos 198: state 83 */
   0xF2 /* 'r' */, 0x01 /* to pos 200 state 84 */,
/* pos 200: state 84 */
   0xE9 /* 'i' */, 0x01 /* to pos 202 state 85 */,
/* pos 202: state 85 */
   0xE7 /* 'g' */, 0x01 /* to pos 204 state 86 */,
/* pos 204: state 86 */
   0xE9 /* 'i' */, 0x01 /* to pos 206 state 87 */,
/* pos 206: state 87 */
   0xEE /* 'n' */, 0x01 /* to pos 208 state 88 */,
/* pos 208: state 88 */
   0xBA /* ':' */, 0x01 /* to pos 210 state 89 */,
/* pos 210: state 89 */
   0x8C, 0x00 /* terminal marker */, 
/* pos 212: state 90 */
   0xF8 /* 'x' */, 0x01 /* to pos 214 state 91 */,
/* pos 214: state 91 */
   0xF4 /* 't' */, 0x01 /* to pos 216 state 92 */,
/* pos 216: state 92 */
   0xE5 /* 'e' */, 0x01 /* to pos 218 state 93 */,
/* pos 218: state 93 */
   0xEE /* 'n' */, 0x01 /* to pos 220 state 94 */,
/* pos 220: state 94 */
   0xF3 /* 's' */, 0x01 /* to pos 222 state 95 */,
/* pos 222: state 95 */
   0xE9 /* 'i' */, 0x01 /* to pos 224 state 96 */,
/* pos 224: state 96 */
   0xEF /* 'o' */, 0x01 /* to pos 226 state 97 */,
/* pos 226: state 97 */
   0xEE /* 'n' */, 0x01 /* to pos 228 state 98 */,
/* pos 228: state 98 */
   0xF3 /* 's' */, 0x01 /* to pos 230 state 99 */,
/* pos 230: state 99 */
   0xBA /* ':' */, 0x01 /* to pos 232 state 100 */,
/* pos 232: state 100 */
   0x8D, 0x00 /* terminal marker */, 
/* pos 234: state 101 */
   0xE3 /* 'c' */, 0x01 /* to pos 236 state 102 */,
/* pos 236: state 102 */
   0xE3 /* 'c' */, 0x01 /* to pos 238 state 103 */,
/* pos 238: state 103 */
   0xE5 /* 'e' */, 0x01 /* to pos 240 state 104 */,
/* pos 240: state 104 */
   0xF0 /* 'p' */, 0x01 /* to pos 242 state 105 */,
/* pos 242: state 105 */
   0xF4 /* 't' */, 0x01 /* to pos 244 state 106 */,
/* pos 244: state 106 */
   0xBA /* ':' */, 0x01 /* to pos 246 state 107 */,
/* pos 246: state 107 */
   0x8E, 0x00 /* terminal marker */, 
/* pos 248: state 108 */
   0xEF /* 'o' */, 0x01 /* to pos 250 state 109 */,
/* pos 250: state 109 */
   0xEE /* 'n' */, 0x01 /* to pos 252 state 110 */,
/* pos 252: state 110 */
   0xE3 /* 'c' */, 0x01 /* to pos 254 state 111 */,
/* pos 254: state 111 */
   0xE5 /* 'e' */, 0x01 /* to pos 256 state 112 */,
/* pos 256: state 112 */
   0xBA /* ':' */, 0x01 /* to pos 258 state 113 */,
/* pos 258: state 113 */
   0x8F, 0x00 /* terminal marker */, 
/* pos 260: state 114 */
   0xD4 /* 'T' */, 0x01 /* to pos 262 state 115 */,
/* pos 262: state 115 */
   0xD0 /* 'P' */, 0x01 /* to pos 264 state 116 */,
/* pos 264: state 116 */
   0xAF /* '/' */, 0x01 /* to pos 266 state 117 */,
/* pos 266: state 117 */
   0xB1 /* '1' */, 0x01 /* to pos 268 state 118 */,
/* pos 268: state 118 */
   0xAE /* '.' */, 0x01 /* to pos 270 state 119 */,
/* pos 270: state 119 */
   0xB1 /* '1' */, 0x01 /* to pos 272 state 120 */,
/* pos 272: state 120 */
   0xA0 /* ' ' */, 0x01 /* to pos 274 state 121 */,
/* pos 274: state 121 */
   0x90, 0x00 /* terminal marker */, 
/* total size 276 bytes */


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
		if (lextable[pos + 1] == 0) // terminal marker
			return pos;

		if ((lextable[pos] & 0x7f) == c)
			return pos + (lextable[pos + 1] << 1);

		if (lextable[pos] & 0x80)
			return -1;

		pos += 2;
	}
	return pos;
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

		while (set[n][m]) {

			saw = 0;
			for (y = 0; y < state[walk].count; y++)
				if (state[walk].c[y] == set[n][m]) { /* exists */
					walk = state[walk].state[y]; /* go forward */
					saw = 1;
					break;
				}

			if (saw)
				goto again;

			/* something we didn't see before */

			state[walk].c[state[walk].count] = set[n][m];

			state[walk].state[state[walk].count] = next;
			state[walk].count++;

//			if (set[n][m + 1] == '\0') /* terminal */
				walk = next++;
again:
			m++;
		}

		state[walk].c[0] = n;
		state[walk].state[0] = 0; /* terminal marker */
		state[walk].count = 1;

		n++;

	}

	walk = 0;
	for (n = 0; n < next; n++) {
		state[n].bytepos = walk;
		walk += (2 * state[n].count);
	}
#if 0
	for (n = 0; n < next; n++) {
		fprintf(stderr, "State %d\n", n);
		for (m = 0; m < state[n].count; m++)
			fprintf(stderr, "'%c' -> %d\n", state[n].c[m], state[n].state[m]);
		fprintf(stderr, "(stop)\n");
	}
#endif

	walk = 0;
	for (n = 0; n < next; n++) {
		fprintf(stderr, "/* pos %d: state %d */\n", walk, n);
		for (m = 0; m < state[n].count; m++) {
			y = state[n].c[m];
			saw = state[n].state[m];

			if (m == state[n].count - 1)
				y |= 0x80; /* last option */

			if (saw == 0) // c is a terminal then
				fprintf(stderr, "   0x%02X, 0x00 /* terminal marker */, \n", y);
			else { // c is a character and we need a byte delta
				if ((state[saw].bytepos - walk) / 2 > 0xff) {
					fprintf(stderr, "Tried to jump > 510 bytes ahead\n");
					return 1;
				}
				prev = y &0x7f;
				if (prev < 32 || prev > 126)
					prev = '.';
				fprintf(stderr, "   0x%02X /* '%c' */, 0x%02X /* to pos %d state %d */,\n", y, prev, (state[saw].bytepos - walk) / 2, state[saw].bytepos, saw);
			}
			walk += 2;
		}
	}

	fprintf(stderr, "/* total size %d bytes */\n", walk);

	for (n = 0; n < sizeof(set) / sizeof(set[0]); n++) {
		walk = 0;
		m = 0;

		fprintf(stderr, "Trying %s\n", set[n]);

		while (set[n][m]) {
			walk = lextable_decode(walk, set[n][m]);
			if (walk < 0) {
				fprintf(stderr, "failed\n");
				break;
			}
			if (lextable[walk + 1] == 0) {
				fprintf(stderr, "decode: %d\n", lextable[walk] & 0x7f);
				break;
			}
			m++;
		}
	}

	return 0;
}



