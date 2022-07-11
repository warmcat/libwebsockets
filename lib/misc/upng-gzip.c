/*
 * LWS PNG -- derived from uPNG -- derived from LodePNG version 20100808
 * Stateful, linewise PNG decode requiring ~36KB fixed heap
 *
 * Copyright (c) 2005-2010 Lode Vandevenne (LodePNG)
 * Copyright (c) 2010 Sean Middleditch (uPNG)
 * Copyright (c) 2021 Andy Green <andy@warmcat.com> (Stateful, incremental)
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.

 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must not
 *      claim that you wrote the original software. If you use this software
 *      in a product, an acknowledgment in the product documentation would be
 *	appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must not be
 *	misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *	distribution.
 *
 *  AG: The above notice is the ZLIB license, libpng also uses it.
 *
 * This version was rewritten from the upng project's fork of lodepng and
 * adapted to be a stateful stream parser.  This rewrite retains the ZLIB
 * license of the source material for simplicity.
 *
 * That allows it to use a fixed 32KB ringbuffer to hold decodes, and
 * incrementally decode chunks into it as we want output lines that are not yet
 * present there.  The input png nor the output bitmap need to be all in one
 * place at one time.
 */

#include <private-lib-core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static const huff_t huff_length_base[] = {
	/* the base lengths represented by codes 257-285 */
	3, 4, 5, 6, 7, 8, 9, 10,
	11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115,
	131, 163, 195, 227, 258, 0
};

static const huff_t huff_length_extra[] = {
	/* the extra bits used by codes 257-285 (added to base length) */
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4,
	5, 5, 5, 5, 0, 127
};

static const huff_t huff_distance_base[] = {
	/*
	 * The base backwards distances (the bits of distance codes appear
	 * after length codes and use their own huffman tree)
	 */
	1, 2, 3, 4, 5, 7, 9, 13,
	17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073,
	4097, 6145, 8193, 12289, 16385, 24577, 0, 0
};

static const huff_t huff_distance_extra[] = {
	/* the extra bits of backwards distances (added to base) */
	0, 0, 0, 0, 1, 1, 2, 2,
	3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10,
	11, 11, 12, 12, 13, 13, 0, 0
};

static const huff_t huff_cl_cl[] = {
	/*
	 * The order in which "code length alphabet code lengths" are stored,
	 * out of this the huffman tree of the dynamic huffman tree lengths
	 * is generated
	 */
	16, 17, 18, 0,
	8, 7, 9, 6,
	10, 5, 11, 4,
	12, 3, 13, 2,
	14, 1, 15
};

static const huff_t FIXED_DEFLATE_CODE_TREE[NUM_DEFLATE_CODE_SYMBOLS * 2] = {
	289, 370,
	290, 307,
	546, 291,
	561, 292,
	293, 300,
	294, 297,
	295, 296,
	0, 1,
	2, 3,
	298, 299,
	4, 5, 6, 7, 301, 304, 302, 303, 8, 9, 10, 11, 305,
	306, 12, 13, 14, 15, 308, 339, 309, 324, 310, 317, 311, 314, 312, 313,
	16, 17, 18, 19, 315, 316, 20, 21, 22, 23, 318, 321, 319, 320, 24, 25,
	26, 27, 322, 323, 28, 29, 30, 31, 325, 332, 326, 329, 327, 328, 32, 33,
	34, 35, 330, 331, 36, 37, 38, 39, 333, 336, 334, 335, 40, 41, 42, 43,
	337, 338, 44, 45, 46, 47, 340, 355, 341, 348, 342, 345, 343, 344, 48,
	49, 50, 51, 346, 347, 52, 53, 54, 55, 349, 352, 350, 351, 56, 57, 58,
	59, 353, 354, 60, 61, 62, 63, 356, 363, 357, 360, 358, 359, 64, 65, 66,
	67, 361, 362, 68, 69, 70, 71, 364, 367, 365, 366, 72, 73, 74, 75, 368,
	369, 76, 77, 78, 79, 371, 434, 372, 403, 373, 388, 374, 381, 375, 378,
	376, 377, 80, 81, 82, 83, 379, 380, 84, 85, 86, 87, 382, 385, 383, 384,
	88, 89, 90, 91, 386, 387, 92, 93, 94, 95, 389, 396, 390, 393, 391, 392,
	96, 97, 98, 99, 394, 395, 100, 101, 102, 103, 397, 400, 398, 399, 104,
	105, 106, 107, 401, 402, 108, 109, 110, 111, 404, 419, 405, 412, 406,
	409, 407, 408, 112, 113, 114, 115, 410, 411, 116, 117, 118, 119, 413,
	416, 414, 415, 120, 121, 122, 123, 417, 418, 124, 125, 126, 127, 420,
	427, 421, 424, 422, 423, 128, 129, 130, 131, 425, 426, 132, 133, 134,
	135, 428, 431, 429, 430, 136, 137, 138, 139, 432, 433, 140, 141, 142,
	143, 435, 483, 436, 452, 568, 437, 438, 445, 439, 442, 440, 441, 144,
	145, 146, 147, 443, 444, 148, 149, 150, 151, 446, 449, 447, 448, 152,
	153, 154, 155, 450, 451, 156, 157, 158, 159, 453, 468, 454, 461, 455,
	458, 456, 457, 160, 161, 162, 163, 459, 460, 164, 165, 166, 167, 462,
	465, 463, 464, 168, 169, 170, 171, 466, 467, 172, 173, 174, 175, 469,
	476, 470, 473, 471, 472, 176, 177, 178, 179, 474, 475, 180, 181, 182,
	183, 477, 480, 478, 479, 184, 185, 186, 187, 481, 482, 188, 189, 190,
	191, 484, 515, 485, 500, 486, 493, 487, 490, 488, 489, 192, 193, 194,
	195, 491, 492, 196, 197, 198, 199, 494, 497, 495, 496, 200, 201, 202,
	203, 498, 499, 204, 205, 206, 207, 501, 508, 502, 505, 503, 504, 208,
	209, 210, 211, 506, 507, 212, 213, 214, 215, 509, 512, 510, 511, 216,
	217, 218, 219, 513, 514, 220, 221, 222, 223, 516, 531, 517, 524, 518,
	521, 519, 520, 224, 225, 226, 227, 522, 523, 228, 229, 230, 231, 525,
	528, 526, 527, 232, 233, 234, 235, 529, 530, 236, 237, 238, 239, 532,
	539, 533, 536, 534, 535, 240, 241, 242, 243, 537, 538, 244, 245, 246,
	247, 540, 543, 541, 542, 248, 249, 250, 251, 544, 545, 252, 253, 254,
	255, 547, 554, 548, 551, 549, 550, 256, 257, 258, 259, 552, 553, 260,
	261, 262, 263, 555, 558, 556, 557, 264, 265, 266, 267, 559, 560, 268,
	269, 270, 271, 562, 565, 563, 564, 272, 273, 274, 275, 566, 567, 276,
	277, 278, 279, 569, 572, 570, 571, 280, 281, 282, 283, 573, 574, 284,
	285, 286, 287, 0, 0
};

static const huff_t FIXED_DISTANCE_TREE[NUM_DISTANCE_SYMBOLS * 2] = {
	33, 48, 34, 41, 35, 38, 36, 37,
	0, 1, 2, 3, 39, 40, 4, 5,
	6, 7, 42, 45, 43, 44, 8, 9,
	10, 11, 46, 47, 12, 13, 14, 15,
	49, 56, 50, 53, 51, 52, 16, 17,
	18, 19, 54, 55, 20, 21, 22, 23,
	57, 60, 58, 59, 24, 25, 26, 27,
	61, 62, 28, 29, 30, 31, 0, 0
};

static lws_stateful_ret_t
read_bit(inflator_ctx_t *inf, uint8_t *bits)
{
	size_t bo = inf->bp >> 3;

	if (bo + inf->inpos >= inf->inlen)
		return LWS_SRET_WANT_INPUT;

	*bits = (uint8_t)((*(inf->in + inf->inpos + bo) >> (inf->bp & 7)) & 1);

	inf->bp++;

	return LWS_SRET_OK;
}

/* Stateful, so it can pick up after running out of input partway thru */

static lws_stateful_ret_t
read_bits(inflator_ctx_t *inf, unsigned int nbits, unsigned int *bits)
{
	lws_stateful_ret_t r;
	uint8_t b;

	if (!inf->read_bits_ongoing) {
		inf->read_bits_ongoing	= 1;
		inf->read_bits_shifter	= 0;
		inf->read_bits_limit	= nbits;
		inf->read_bits_i	= 0;
	}

	while (inf->read_bits_i < inf->read_bits_limit) {
		 r =read_bit(inf, &b);
		 if (r)
			 return r;

		 inf->read_bits_shifter = inf->read_bits_shifter | (unsigned int)(b << inf->read_bits_i);

		 inf->read_bits_i++;
	}

	inf->read_bits_ongoing = 0;
	*bits = inf->read_bits_shifter;

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
read_byte(inflator_ctx_t *inf, uint8_t *byte)
{
	size_t bo;

	while (inf->bp & 7)
		inf->bp++;

	bo = inf->bp >> 3;

	if (bo + inf->inpos >= inf->inlen)
		return LWS_SRET_WANT_INPUT;

	*byte = *(inf->in + inf->inpos + bo);

	inf->bp += 8;

	return LWS_SRET_OK;
}

/* buffer must be numcodes*2 in size! */
static void
huffman_tree_init(htree_t *tree, huff_t *buffer, uint16_t numcodes,
		  uint16_t maxbitlen)
{
	tree->tree2d = buffer;

	tree->numcodes = numcodes;
	tree->maxbitlen = maxbitlen;
}

#define EMPTY 32767

/*
 * Given the code lengths (as stored in the PNG file), generate the tree as
 * defined by Deflate. maxbitlen is the maximum bits that a code in the tree
 * can have.
 */
static lws_stateful_ret_t
huffman_tree_create_lengths(htree_t *tree, const unsigned *bitlen)
{
	unsigned int tree1d[NUM_DEFLATE_CODE_SYMBOLS], /* sized to worst */
		     blcount[NUM_DEFLATE_CODE_SYMBOLS], /* sized to worst */
		     nextcode[MAX_BIT_LENGTH + 1], bits, n, i,
		     nodefilled = 0, treepos = 0;

	memset(blcount, 0, sizeof(blcount));
	memset(nextcode, 0, sizeof(nextcode));

	assert(tree->numcodes <= LWS_ARRAY_SIZE(blcount));

	for (bits = 0; bits < tree->numcodes; bits++) {
		/* any counts exceeding our private buffer length are fatal */
		if (bitlen[bits] >= LWS_ARRAY_SIZE(blcount))
			return LWS_SRET_FATAL + 1;

		blcount[bitlen[bits]]++;
	}

	assert(tree->maxbitlen && tree->maxbitlen - 1u <= LWS_ARRAY_SIZE(blcount));
	assert(tree->maxbitlen - 1u <= LWS_ARRAY_SIZE(nextcode));

	for (bits = 1; bits <= (unsigned int)tree->maxbitlen; bits++)
		nextcode[bits] = (nextcode[bits - 1] + blcount[bits - 1]) << 1;

	assert(tree->numcodes <= LWS_ARRAY_SIZE(tree1d));

	for (n = 0; n < tree->numcodes; n++)
		if (bitlen[n])
			tree1d[n] = nextcode[bitlen[n]]++;

	for (n = 0; n < (unsigned int)tree->numcodes * 2u; n++)
		tree->tree2d[n] = EMPTY;

	for (n = 0; n < tree->numcodes; n++) {	/* the codes */
		for (i = 0; i < bitlen[n]; i++) { /* the bits for this code */
			uint8_t bit = (uint8_t)((tree1d[n] >>
						(bitlen[n] - i - 1)) & 1);

			/* check if oversubscribed */
			if (treepos > tree->numcodes - 2u)
				return LWS_SRET_FATAL + 1;

			if (tree->tree2d[2 * treepos + bit] == EMPTY) {
				if (i + 1 == bitlen[n]) { /* ... last bit */
					tree->tree2d[2 * treepos + bit] = (huff_t)n;
					treepos = 0;
				} else {
					nodefilled++;
					tree->tree2d[2 * treepos + bit] =
					  (huff_t)(nodefilled + tree->numcodes);
					treepos = nodefilled;
				}
			} else
				treepos = (unsigned int)(tree->tree2d[2 * treepos + bit] -
						tree->numcodes);
		}
	}

	for (n = 0; n < tree->numcodes * 2u; n++)
		if (tree->tree2d[n] == EMPTY)
			tree->tree2d[n] = 0;

	return LWS_SRET_OK;
}



static lws_stateful_ret_t
huffman_decode_symbol(inflator_ctx_t *inf, const htree_t *ct, unsigned int *uct)
{
	lws_stateful_ret_t r;
	uint8_t bit;

	do {
		r = read_bit(inf, &bit);
		if (r)
			return r;

		*uct = ct->tree2d[(inf->treepos << 1) | bit];
		if (*uct < ct->numcodes)
			return LWS_SRET_OK;

		inf->treepos = *uct - ct->numcodes;
		if (inf->treepos >= ct->numcodes)
			return LWS_SRET_FATAL + 2;
	} while (1);
}

lws_stateful_ret_t
_lws_upng_inflate_data(inflator_ctx_t *inf)
{
	unsigned int count, val, tu;
	uint8_t t, done = 0;
	lws_stateful_ret_t r;
	size_t virt;

	while (!done) {
		switch (inf->state) {
		case UPNS_ID_BL_GB_DONE:
			r = read_bit(inf, &inf->done);
			if (r)
				return r;
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPEb0:
			r = read_bit(inf, &inf->btype);
			if (r)
				return r;
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPEb1:
			r = read_bit(inf, &t);
			if (r)
				return r;

			inf->btype |= (uint8_t)(t << 1);

			if (inf->btype == 3)
				return LWS_SRET_FATAL + 3;

			inf->i = 0;

			inf->state = UPNS_ID_BL_GB_BTYPE_0 + inf->btype;

			lwsl_debug("%s: (%lu) block type %d\n", __func__,
				(unsigned long)inf->archive_pos + (inf->bp >> 3),
				inf->btype);

			/* uncompressed starts on a byte boundary */

			if (!inf->btype && (inf->bp & 7)) {
				lwsl_debug("%s: skipping %d alignment bits for type 0\n",
						__func__, (int)(8 - (inf->bp & 7)) & 7);
				inf->bp = ((inf->bp >> 3) + 1) << 3;
			}
			continue;

		case UPNS_ID_BL_GB_BTYPE_0: /* no compression */
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->len = t;
			inf->state = UPNS_ID_BL_GB_BTYPE_0a;

			// lwsl_notice("%s: no compression block\n", __func__);

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_0a:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->len = inf->len | (unsigned int)(t << 8);
			inf->state++;
			/* fallthru */

		case UPNS_ID_BL_GB_BTYPE_0b:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->nlen = t;
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_0c:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->nlen = inf->nlen | (unsigned int)(t << 8);

			if (inf->len + inf->nlen != 65535)
				return LWS_SRET_FATAL + 4;

			lwsl_debug("%s: type 0 expects len %d\n", __func__, inf->len);

			inf->state++;
			inf->n = 0;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_0d:

			if (inf->n < inf->len) {

				r = read_byte(inf, &t);
				if (r)
					return r;

				inf->out[inf->outpos++] = t;
				if (inf->outpos >= inf->outlen)
					inf->outpos = 0;
				inf->outpos_linear++;
				inf->n++;

				if (inf->outpos_linear - inf->consumed_linear >=
						inf->bypl + 1) {
					return LWS_SRET_WANT_OUTPUT;
				}

				continue;
			}

			inf->treepos = 0;
			inf->state = UPNS_ID_BL_GB_DONE;
			continue;

		case UPNS_ID_BL_GB_BTYPE_1: /* fixed trees */

			huffman_tree_init(&inf->ct,
					  (huff_t *)FIXED_DEFLATE_CODE_TREE,
					  NUM_DEFLATE_CODE_SYMBOLS,
					  DEFLATE_CODE_BITLEN);
			huffman_tree_init(&inf->ctD,
					  (huff_t *)FIXED_DISTANCE_TREE,
					  NUM_DISTANCE_SYMBOLS,
					  DISTANCE_BITLEN);

			lwsl_debug("%s: fixed tree init\n", __func__);
			inf->treepos = 0;
			inf->state = UPNS_ID_BL_GB_SPIN;
			continue;

		case UPNS_ID_BL_GB_BTYPE_2: /* dynamic trees */
			huffman_tree_init(&inf->ct, inf->ct_buffer,
					  NUM_DEFLATE_CODE_SYMBOLS,
					  DEFLATE_CODE_BITLEN);
			huffman_tree_init(&inf->ctD, inf->ctD_buffer,
					  NUM_DISTANCE_SYMBOLS,
					  DISTANCE_BITLEN);
			huffman_tree_init(&inf->clct, inf->clct_buffer,
					  NUM_CODE_LENGTH_CODES,
					  CODE_LENGTH_BITLEN);

			// lwsl_notice("%s: dyn tree init\n", __func__);
			inf->treepos = 0;

			/* clear bitlen arrays */
			memset(inf->bitlen, 0, sizeof(inf->bitlen));
			memset(inf->bitlenD, 0, sizeof(inf->bitlenD));

			inf->state = UPNS_ID_BL_GB_BTYPE_2a;

			inf->hlit = 0;
			inf->hdist = 0;
			inf->hclen = 0;

			/* fallthru */

		case UPNS_ID_BL_GB_BTYPE_2a:
			r = read_bits(inf, 5, &inf->hlit);
			if (r)
				return r;
			inf->hlit += 257;
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_2b:
			r = read_bits(inf, 5, &inf->hdist);
			if (r)
				return r;
			inf->hdist++;
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_2c:
			r = read_bits(inf, 4, &inf->hclen);
			if (r)
				return r;
			inf->hclen += 4;
			inf->state = UPNS_ID_BL_GB_BTYPE_2d;
			inf->i = 0;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_2d:
			if (inf->i < NUM_CODE_LENGTH_CODES) {
				if (inf->i < inf->hclen) {
					r = read_bits(inf, 3,
						&inf->clenc[huff_cl_cl[inf->i]]);
					if (r)
						return r;
				} else
					/*if not, it must stay 0 */
					inf->clenc[huff_cl_cl[inf->i]] = 0;

				inf->i++;
				continue;
			}

			r = huffman_tree_create_lengths(&inf->clct, inf->clenc);
			if (r)
				return r;

			inf->i = 0;
			inf->state = UPNS_ID_BL_GB_BTYPE_2e;
			inf->treepos = 0;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_2e:

			if (inf->i >= inf->hlit + inf->hdist) {
				if (inf->bitlen[256] == 0)
					return LWS_SRET_FATAL + 6;

				if (huffman_tree_create_lengths(&inf->ct,
								inf->bitlen))
					return LWS_SRET_FATAL + 7;

				if (huffman_tree_create_lengths(&inf->ctD,
								inf->bitlenD))
					return LWS_SRET_FATAL + 8;

				inf->treepos = 0;
				inf->state = UPNS_ID_BL_GB_SPIN;
				continue;
			}

			r = huffman_decode_symbol(inf, &inf->clct, &inf->code);
			if (r)
				return r;

			switch (inf->code) {
			case 16:
				inf->state = UPNS_ID_BL_GB_BTYPE_2_16;
				continue;
			case 17:
				inf->state = UPNS_ID_BL_GB_BTYPE_2_17;
				continue;
			case 18:
				inf->state = UPNS_ID_BL_GB_BTYPE_2_18;
				continue;
			default:
				if (inf->code > 15)
					return LWS_SRET_FATAL + 9;

				if (inf->i < inf->hlit)
					inf->bitlen[inf->i] = inf->code;
				else
					inf->bitlenD[inf->i - inf->hlit] =
								inf->code;

				inf->i++;
				inf->treepos = 0;

				/* stay in 2e */
				continue;
			}

		case UPNS_ID_BL_GB_BTYPE_2_16: /* repeat previous */
			r = read_bits(inf, 2, &tu);
			if (r)
				return r;
			count = tu + 3;

			if (!inf->i) /* from google fuzzer */
				return LWS_SRET_FATAL + 29;

			if (inf->i - 1 < inf->hlit)
				val = inf->bitlen[inf->i - 1];
			else
				val = inf->bitlenD[inf->i - inf->hlit - 1];

			goto fill;

		case UPNS_ID_BL_GB_BTYPE_2_17: /*repeat "0" 3-10 times */
			r = read_bits(inf, 3, &tu);
			if (r)
				return r;
			count = tu + 3;

			val = 0;
			goto fill;

		case UPNS_ID_BL_GB_BTYPE_2_18: /*repeat "0" 11-138 times */
			r = read_bits(inf, 7, &tu);
			if (r)
				return r;
			count = tu + 11;
			val = 0;
fill:

			if (inf->i + count > inf->hlit + inf->hdist) {
				lwsl_err("%s: inf->i (%d) > %d\n", __func__,
					inf->i + count, inf->hlit + inf->hdist);
				return LWS_SRET_FATAL + 10;
			}

			{
				unsigned int n;

				for (n = 0; n < count; n++) {

					if (inf->i < inf->hlit)
						inf->bitlen[inf->i] = val;
					else
						inf->bitlenD[inf->i - inf->hlit] = val;

					inf->i++;
				}
			}
			inf->state = UPNS_ID_BL_GB_BTYPE_2e;
			inf->treepos = 0;
			continue;


		case UPNS_ID_BL_GB_SPIN:

			r = huffman_decode_symbol(inf, &inf->ct, &inf->code);
			if (r)
				return r;

			if (inf->code >= FIRST_LENGTH_CODE_INDEX &&
			    inf->code - FIRST_LENGTH_CODE_INDEX <
					    LWS_ARRAY_SIZE(huff_length_base))
				inf->length = huff_length_base[inf->code -
			                               FIRST_LENGTH_CODE_INDEX];
			else
				inf->length = 0;

			if (inf->code == 256) {
				/*
				 * We're finished with this huffman block, we
				 * need to go back up a level
				 */
				done = inf->done;
				inf->state = UPNS_ID_BL_GB_DONE;
				continue;
			}

			if (inf->code <= 255) {
				inf->state = UPNS_ID_BL_GB_SPINa;
				continue;
			}

			if (inf->code < FIRST_LENGTH_CODE_INDEX ||
			    inf->code > LAST_LENGTH_CODE_INDEX) {
				inf->treepos = 0;
				continue;
			}

			inf->exbits = huff_length_extra[inf->code -
			                                FIRST_LENGTH_CODE_INDEX];
			inf->state = UPNS_ID_BL_GB_SPINb;

			/* fallthru */
		case UPNS_ID_BL_GB_SPINb:
			r = read_bits(inf, (unsigned int)inf->exbits, &tu);
			if (r)
				return r;

			inf->length += tu;
			inf->state++;
			inf->treepos = 0;

			/* fallthru */
		case UPNS_ID_BL_GB_SPINc:

			/* part 3: get distance code */

			r = huffman_decode_symbol(inf, &inf->ctD, &inf->codeD);
			if (r)
				return r;

			/* invalid distance code (30-31 are never used) */
			if (inf->codeD > 29) {
				lwsl_err("%s: invalid dist %d\n", __func__, inf->codeD);
				return LWS_SRET_FATAL + 11;
			}

			inf->distance = huff_distance_base[inf->codeD];

			/* part 4: get extra bits from distance */

			inf->exbitsD = huff_distance_extra[inf->codeD];
			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_SPINd:

			r = read_bits(inf, inf->exbitsD, &tu);
			if (r)
				return r;

			inf->distance += tu;

			if (inf->distance > inf->info_size) {
				lwsl_err("%s: distance %lu\n", __func__,
						(unsigned long)inf->distance);
				assert(0);
			}

			/*
			 * Part 5: fill in all the out[n] values based
			 * on the length and dist
			 */
			inf->start = inf->outpos;
			inf->forward = 0;
			inf->backward = inf->distance; /* from inf->start */

			inf->state++;

			/* fallthru */
		case UPNS_ID_BL_GB_SPINe:

			if (inf->forward >= inf->length) {
				inf->treepos = 0;
				inf->state = UPNS_ID_BL_GB_SPIN;
				continue;
			}

			if (inf->backward <= inf->start)
				virt = inf->start - inf->backward;
			else /* wrapped... backward >= start */
				virt = inf->info_size -
					(inf->backward - inf->start);

			if (virt >= inf->info_size)
				lwsl_err("virt %d\n", (int)virt);

			inf->out[inf->outpos++] = inf->out[virt];
			if (inf->outpos >= inf->outlen)
				inf->outpos = 0;

			inf->outpos_linear++;
			inf->backward--;

			if (!inf->backward)
				inf->backward = inf->distance;

			inf->forward++;

			if (inf->outpos_linear - inf->consumed_linear >=
								inf->bypl + 1)
				return LWS_SRET_WANT_OUTPUT;

			continue;

		case UPNS_ID_BL_GB_SPINa:

			inf->out[inf->outpos++] = (uint8_t)inf->code;
			if (inf->outpos >= inf->outlen)
				inf->outpos = 0;

			inf->outpos_linear++;
			inf->treepos = 0;
			inf->state = UPNS_ID_BL_GB_SPIN;

			if (inf->outpos_linear - inf->consumed_linear >=
								inf->bypl + 1)
				return LWS_SRET_WANT_OUTPUT;

			continue;


		case UPNS_ID_BL_GB_GZIP_ID1:
			r = read_byte(inf, &t);
			if (r)
				return r;
			if (t != 0x1f)
				return LWS_SRET_FATAL + 32;
			inf->state++;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_ID2:
			r = read_byte(inf, &t);
			if (r)
				return r;
			if (t != 0x8b)
				return LWS_SRET_FATAL + 33;
			inf->state++;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_METHOD:
			r = read_byte(inf, &t);
			if (r)
				return r;
			if (t != 8)
				return LWS_SRET_FATAL + 34;
			inf->state++;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_FLAGS:
			r = read_byte(inf, &t);
			if (r)
				return r;
			if (t & 0xe0)
				return LWS_SRET_FATAL + 35;
			inf->gz_flags = t;
			inf->state++;
			inf->ctr = 6;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_EOH:
			/* we want skip 6 bytes */
			if (inf->ctr--) {
				r = read_byte(inf, &t);
				if (r)
					return r;

				continue;
			}

			if (inf->gz_flags & 4)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_EXTRA_C1;
			else
			if (inf->gz_flags & 8)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_FILENAME;
			else
			if (inf->gz_flags & 16)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_COMMENT;
			else
			if (inf->gz_flags & 2) {
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_CRC;
				inf->ctr = 2;
			} else
				inf->state = UPNS_ID_BL_GB_DONE;

			continue;

		case UPNS_ID_BL_GB_GZIP_SKIP_EXTRA_C1:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->ctr = t;

			inf->state++;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_SKIP_EXTRA_C2:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->ctr = (uint16_t)(inf->ctr | (t << 8));

			inf->state++;

			/* fallthru */

		case UPNS_ID_BL_GB_GZIP_SKIP_EXTRA:
			if (inf->ctr--) {
				r = read_byte(inf, &t);
				if (r)
					return r;

				continue;
			}

			if (inf->gz_flags & 8)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_FILENAME;
			else
			if (inf->gz_flags & 16)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_COMMENT;
			else
			if (inf->gz_flags & 2) {
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_CRC;
				inf->ctr = 2;
			} else
				inf->state = UPNS_ID_BL_GB_DONE;

			continue;

		case UPNS_ID_BL_GB_GZIP_SKIP_FILENAME: /* zero-terminated */
			r = read_byte(inf, &t);
			if (r)
				return r;

			if (t)
				continue;

			if (inf->gz_flags & 16)
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_COMMENT;
			else
			if (inf->gz_flags & 2) {
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_CRC;
				inf->ctr = 2;
			} else
				inf->state = UPNS_ID_BL_GB_DONE;

			continue;

		case UPNS_ID_BL_GB_GZIP_SKIP_COMMENT: /* zero-terminated */
			r = read_byte(inf, &t);
			if (r)
				return r;

			if (t)
				continue;

			if (inf->gz_flags & 2) {
				inf->state = UPNS_ID_BL_GB_GZIP_SKIP_CRC;
				inf->ctr = 2;
			}
			else
				inf->state = UPNS_ID_BL_GB_DONE;

			continue;

		case UPNS_ID_BL_GB_GZIP_SKIP_CRC:
			if (inf->ctr--) {
				r = read_byte(inf, &t);
				if (r)
					return r;

				continue;
			}
			inf->state = UPNS_ID_BL_GB_DONE;
			continue;
		}
	}

	return LWS_SRET_OK;
}

struct inflator_ctx *
lws_upng_inflator_create(const uint8_t **outring, size_t *outringlen,
			 size_t **opl, size_t **cl)
{
	inflator_ctx_t *inf = lws_zalloc(sizeof(*inf), __func__);

	if (!inf) {
		lwsl_notice("%s: OOM\n", __func__);

		return NULL;
	}

	/* 32KB gz sliding window */
	inf->info_size	= 32768;
	inf->bypl	= 0;
	inf->outlen	= inf->info_size;
	inf->outpos	= 0;
	inf->state	= UPNS_ID_BL_GB_GZIP_ID1;

	inf->out = (uint8_t *)lws_malloc(inf->info_size, __func__);
	if (!inf->out) {
		lwsl_notice("%s: inf malloc %u OOM\n",
			__func__, (unsigned int)inf->info_size);

		lws_free(inf);

		return NULL;
	}

	*outring = inf->out;
	*outringlen = inf->info_size;
	*opl = &inf->outpos_linear;
	*cl = &inf->consumed_linear;

	return inf;
}

lws_stateful_ret_t
lws_upng_inflate_data(struct inflator_ctx *inf, const void *buf, size_t len)
{
	lws_stateful_ret_t r;

	if (buf) {
		inf->in		= buf;
		inf->inlen	= len;
		inf->inpos	= 0;
		inf->bp		= 0;
	}

	if (!inf->bypl)
		inf->bypl = 4095;

	r = _lws_upng_inflate_data(inf);

	if ((inf->bp >> 3) == inf->inlen) {
		inf->archive_pos += inf->inlen;
		inf->inlen = 0;
		inf->bp = 0;
	}

	return r;
}

void
lws_upng_inflator_destroy(struct inflator_ctx **inf)
{
	lws_free_set_NULL((*inf)->out);
	lws_free_set_NULL(*inf);
}


