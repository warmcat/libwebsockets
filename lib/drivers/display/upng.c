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

#define MAKE_BYTE(b) ((b) & 0xFF)
#define MAKE_DWORD(a,b,c,d) ((MAKE_BYTE(a) << 24) | (MAKE_BYTE(b) << 16) | \
			     (MAKE_BYTE(c) << 8) | MAKE_BYTE(d))
#define MAKE_DWORD_PTR(p) MAKE_DWORD((p)[0], (p)[1], (p)[2], (p)[3])

#define CHUNK_IHDR MAKE_DWORD('I','H','D','R')
#define CHUNK_IDAT MAKE_DWORD('I','D','A','T')
#define CHUNK_IEND MAKE_DWORD('I','E','N','D')

#define FIRST_LENGTH_CODE_INDEX		257
#define LAST_LENGTH_CODE_INDEX		285

/*256 literals, the end code, some length codes, and 2 unused codes */
#define NUM_DEFLATE_CODE_SYMBOLS	288
/*the distance codes have their own symbols, 30 used, 2 unused */
#define NUM_DISTANCE_SYMBOLS		32
/* The code length codes. 0-15: code lengths, 16: copy previous 3-6 times,
 * 17: 3-10 zeros, 18: 11-138 zeros */
#define NUM_CODE_LENGTH_CODES		19
/* largest number of symbols used by any tree type */
#define MAX_SYMBOLS			288

#define DEFLATE_CODE_BITLEN		15
#define DISTANCE_BITLEN			15
#define CODE_LENGTH_BITLEN		7
/* largest bitlen used by any tree type */
#define MAX_BIT_LENGTH			15

#define DEFLATE_CODE_BUFFER_SIZE	(NUM_DEFLATE_CODE_SYMBOLS * 2)
#define DISTANCE_BUFFER_SIZE		(NUM_DISTANCE_SYMBOLS * 2)
#define CODE_LENGTH_BUFFER_SIZE		(NUM_DISTANCE_SYMBOLS * 2)

#define upng_chunk_length(chunk)	MAKE_DWORD_PTR(chunk)
#define upng_chunk_type(chunk)		MAKE_DWORD_PTR((chunk) + 4)
#define upng_chunk_critical(chunk)	(((chunk)[4] & 32) == 0)

typedef uint16_t huff_t;

typedef enum upng_state {
	UPNG_ERROR		= -1,
	UPNG_DECODED		= 0,
	UPNG_HEADER		= 1,
	UPNG_NEW		= 2
} upng_state;

typedef enum upng_color {
	UPNG_LUM		= 0,
	UPNG_RGB		= 2,
	UPNG_LUMA		= 4,
	UPNG_RGBA		= 6
} upng_color;

typedef struct upng_source {
	const uint8_t		*buffer;
	size_t			size;
	char			owning;
} upng_source;

struct upng_unfline {
	uint8_t			*recon;
	const uint8_t		*scanline;
	const uint8_t		*precon;
	uint8_t			filterType;
	unsigned int		bypp;
	unsigned int		bypl;

	const uint8_t		*in;
	uint8_t			*lines;
	unsigned int		bpp;

	unsigned int		y;
	unsigned long		diff;
	unsigned long		ibp;
	unsigned long		sp;

	char			padded;
	char			alt;
};

typedef struct htree {
	huff_t			*tree2d;
	/*maximum number of bits a single code can get */
	uint16_t		maxbitlen;
	/*number of symbols in the alphabet = number of codes */
	uint16_t		numcodes;
} htree_t;

typedef enum {
	UPNS_ID_BL_GB_DONE,
	UPNS_ID_BL_GB_BTYPEb0,
	UPNS_ID_BL_GB_BTYPEb1,

	UPNS_ID_BL_GB_BTYPE_0,
	UPNS_ID_BL_GB_BTYPE_1,
	UPNS_ID_BL_GB_BTYPE_2,

	UPNS_ID_BL_GB_BTYPE_0a,
	UPNS_ID_BL_GB_BTYPE_0b,
	UPNS_ID_BL_GB_BTYPE_0c,
	UPNS_ID_BL_GB_BTYPE_0d,

	UPNS_ID_BL_GB_BTYPE_2a,
	UPNS_ID_BL_GB_BTYPE_2b,
	UPNS_ID_BL_GB_BTYPE_2c,
	UPNS_ID_BL_GB_BTYPE_2d,
	UPNS_ID_BL_GB_BTYPE_2e,

	UPNS_ID_BL_GB_BTYPE_2_16,
	UPNS_ID_BL_GB_BTYPE_2_17,
	UPNS_ID_BL_GB_BTYPE_2_18,

	UPNS_ID_BL_GB_SPIN,

	UPNS_ID_BL_GB_SPINa,
	UPNS_ID_BL_GB_SPINb,
	UPNS_ID_BL_GB_SPINc,
	UPNS_ID_BL_GB_SPINd,
	UPNS_ID_BL_GB_SPINe,

} upng_inflate_states_t;

typedef struct inflator_ctx {
	unsigned int		clenc[NUM_CODE_LENGTH_CODES];
	unsigned int		bitlen[NUM_DEFLATE_CODE_SYMBOLS];
	unsigned int		bitlenD[NUM_DISTANCE_SYMBOLS];
	huff_t			clct_buffer[CODE_LENGTH_BUFFER_SIZE];
	huff_t			ct_buffer[DEFLATE_CODE_BUFFER_SIZE];
	huff_t			ctD_buffer[DISTANCE_BUFFER_SIZE];

	upng_t			*upng;

	const uint8_t		*in;
	uint8_t			*out;

	htree_t			clct;
	htree_t			ct;
	htree_t			ctD;

	size_t			bp;
	size_t			inpos;
	size_t			inlen;
	size_t			outpos;
	size_t			outpos_linear;
	size_t			outlen;
	size_t			length;
	size_t			start;
	size_t			forward;
	size_t			backward;
	size_t			exbits;

	upng_inflate_states_t	state;

	unsigned int		len;
	unsigned int		nlen;
	unsigned int		n;
	unsigned int		hlit;
	unsigned int		hdist;
	unsigned int		hclen;
	unsigned int		i;
	unsigned int		t;
	unsigned int		codeD;
	unsigned int		distance;
	unsigned int		exbitsD;
	unsigned int		code;
	unsigned int		treepos;

	unsigned int		read_bits_shifter;
	unsigned int		read_bits_limit;
	unsigned int 		read_bits_i;

	/* these are offsets into upng->inflated, to use it as a ringbuffer */

	unsigned int		info_size;

	uint8_t			subsequent;
	uint8_t			btype;
	uint8_t			done;

	char			read_bits_ongoing;
} inflator_ctx_t;

struct upng_t {
	struct upng_unfline	u;
	inflator_ctx_t		inf;

	unsigned		width;
	unsigned		height;

	upng_color		color_type;
	unsigned		color_depth;
	upng_format		format;

	const uint8_t		*chunk;
	uint8_t			*inflated;
	size_t			size;

	upng_state		state;
	upng_source		source;
};

static const huff_t huff_length_base[] = {
	/*the base lengths represented by codes 257-285 */
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
	67, 83, 99, 115, 131, 163, 195, 227, 258
};

static const huff_t huff_length_extra[] = {
	/*the extra bits used by codes 257-285 (added to base length) */
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
	5, 5, 5, 5, 0
};

static const huff_t huff_distance_base[] = {
	/*
	 * The base backwards distances (the bits of distance codes appear
	 * after length codes and use their own huffman tree)
	 */
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
	513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

static const huff_t huff_distance_extra[] = {
	/* the extra bits of backwards distances (added to base) */
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
	10, 11, 11, 12, 12, 13, 13
};

static const huff_t huff_cl_cl[] = {
	/*
	 * The order in which "code length alphabet code lengths" are stored,
	 * out of this the huffman tree of the dynamic huffman tree lengths
	 * is generated
	 */
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

static const huff_t FIXED_DEFLATE_CODE_TREE[NUM_DEFLATE_CODE_SYMBOLS * 2] = {
	289, 370, 290, 307, 546, 291, 561, 292, 293, 300, 294, 297, 295, 296,
	0, 1, 2, 3, 298, 299, 4, 5, 6, 7, 301, 304, 302, 303, 8, 9, 10, 11, 305,
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

static const huff_t FIXED_DISTANCE_TREE[] = {
	33, 48, 34, 41, 35, 38, 36, 37,
	0, 1, 2, 3, 39, 40, 4, 5,
	6, 7, 42, 45, 43, 44, 8, 9,
	10, 11, 46, 47, 12, 13, 14, 15,
	49, 56, 50, 53, 51, 52, 16, 17,
	18, 19, 54, 55, 20, 21, 22, 23,
	57, 60, 58, 59, 24, 25, 26, 27,
	61, 62, 28, 29, 30, 31, 0, 0
};

static upng_ret_t
read_bit(inflator_ctx_t *inf, uint8_t *bits)
{
	size_t bo = inf->bp >> 3;

	if (bo + inf->inpos >= inf->inlen)
		return UPNG_WANT_INPUT;

	*bits = (uint8_t)((*(inf->in + inf->inpos + bo) >> (inf->bp & 7)) & 1);

	inf->bp++;

	return UPNG_OK;
}

/* Stateful, so it can pick up after running out of input partway thru */

static upng_ret_t
read_bits(inflator_ctx_t *inf, unsigned int nbits, unsigned int *bits)
{
	upng_ret_t r;
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

		 inf->read_bits_shifter |= b << inf->read_bits_i;

		 inf->read_bits_i++;
	}

	inf->read_bits_ongoing = 0;
	*bits = inf->read_bits_shifter;

	return UPNG_OK;
}

static upng_ret_t
read_byte(inflator_ctx_t *inf, uint8_t *byte)
{
	size_t bo;

	while (inf->bp & 7)
		inf->bp++;

	bo = inf->bp >> 3;

	if (bo + inf->inpos >= inf->inlen)
		return UPNG_WANT_INPUT;

	*byte = *(inf->in + inf->inpos + bo);

	inf->bp += 8;

	return UPNG_OK;
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
static upng_ret_t
huffman_tree_create_lengths(upng_t *upng, htree_t *tree, const unsigned *bitlen)
{
	unsigned int tree1d[MAX_SYMBOLS], blcount[MAX_BIT_LENGTH],
		     nextcode[MAX_BIT_LENGTH + 1];
	unsigned int bits, n, i, nodefilled = 0, treepos = 0;

	memset(blcount, 0, sizeof(blcount));
	memset(nextcode, 0, sizeof(nextcode));

	for (bits = 0; bits < tree->numcodes; bits++)
		blcount[bitlen[bits]]++;

	for (bits = 1; bits <= tree->maxbitlen; bits++)
		nextcode[bits] = (nextcode[bits - 1] + blcount[bits - 1]) << 1;

	for (n = 0; n < tree->numcodes; n++)
		if (bitlen[n])
			tree1d[n] = nextcode[bitlen[n]]++;

	for (n = 0; n < tree->numcodes * 2; n++)
		tree->tree2d[n] = EMPTY;

	for (n = 0; n < tree->numcodes; n++) {	/* the codes */
		for (i = 0; i < bitlen[n]; i++) { /* the bits for this code */
			uint8_t bit = (uint8_t)((tree1d[n] >>
						(bitlen[n] - i - 1)) & 1);

			/* check if oversubscribed */
			if (treepos > tree->numcodes - 2u)
				return UPNG_FATAL + 1;

			if (tree->tree2d[2 * treepos + bit] == EMPTY) {
				if (i + 1 == bitlen[n]) { /* ... last bit */
					tree->tree2d[2 * treepos + bit] = n;
					treepos = 0;
				} else {
					nodefilled++;
					tree->tree2d[2 * treepos + bit] =
						nodefilled + tree->numcodes;
					treepos = nodefilled;
				}
			} else
				treepos = tree->tree2d[2 * treepos + bit] -
						tree->numcodes;
		}
	}

	for (n = 0; n < tree->numcodes * 2; n++)
		if (tree->tree2d[n] == EMPTY)
			tree->tree2d[n] = 0;

	return UPNG_OK;
}

static upng_ret_t
huffman_decode_symbol(inflator_ctx_t *inf, const htree_t *ct, unsigned int *uct)
{
	upng_ret_t r;
	uint8_t bit;

	do {
		r = read_bit(inf, &bit);
		if (r)
			return r;

		*uct = ct->tree2d[(inf->treepos << 1) | bit];
		if (*uct < ct->numcodes)
			return UPNG_OK;

		inf->treepos = *uct - ct->numcodes;
		if (inf->treepos >= ct->numcodes)
			return UPNG_FATAL + 2;
	} while (1);
}

static upng_ret_t
uz_inflate_data(inflator_ctx_t *inf)
{
	unsigned int count, val, tu;
	uint8_t t, done = 0;
	upng_ret_t r;
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

			inf->btype |= t << 1;

			if (inf->btype == 3)
				return UPNG_FATAL + 3;

			inf->i = 0;

			inf->state = UPNS_ID_BL_GB_BTYPE_0 + inf->btype;
			continue;

		case UPNS_ID_BL_GB_BTYPE_0: /* no compression */
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->len = t;
			inf->state = UPNS_ID_BL_GB_BTYPE_0a;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_0a:
			r = read_byte(inf, &t);
			if (r)
				return r;

			inf->len |= t << 8;
			inf->state++;

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

			inf->nlen |= t << 8;

			if (inf->len + inf->nlen != 65535)
				return UPNG_FATAL + 4;

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
				continue;
			}

			inf->treepos = 0;
			inf->state = UPNS_ID_BL_GB_SPIN;
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

			lwsl_notice("%s: fixed tree init\n", __func__);
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

			/* clear bitlen arrays */
			memset(inf->bitlen, 0, sizeof(inf->bitlen));
			memset(inf->bitlenD, 0, sizeof(inf->bitlenD));

			inf->state = UPNS_ID_BL_GB_BTYPE_2a;

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

			r = huffman_tree_create_lengths(inf->upng, &inf->clct,
							inf->clenc);
			if (r)
				return r;

			inf->i = 0;
			inf->state = UPNS_ID_BL_GB_BTYPE_2e;
			inf->treepos = 0;

			/* fallthru */
		case UPNS_ID_BL_GB_BTYPE_2e:

			if (inf->i >= inf->hlit + inf->hdist) {
				if (inf->bitlen[256] == 0)
					return UPNG_FATAL + 6;

				if (huffman_tree_create_lengths(inf->upng,
								&inf->ct,
								inf->bitlen))
					return UPNG_FATAL + 7;

				if (huffman_tree_create_lengths(inf->upng,
								&inf->ctD,
								inf->bitlenD))
					return UPNG_FATAL + 8;

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
					return UPNG_FATAL + 9;

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

			if ((inf->i - 1) < inf->hlit)
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
			if (inf->i + count > inf->hlit + inf->hdist)
				return UPNG_FATAL + 10;

			for (unsigned int n = 0; n < count; n++) {

				if (inf->i < inf->hlit)
					inf->bitlen[inf->i] = val;
				else
					inf->bitlenD[inf->i - inf->hlit] = val;

				inf->i++;
			}
			inf->state = UPNS_ID_BL_GB_BTYPE_2e;
			inf->treepos = 0;
			continue;


		case UPNS_ID_BL_GB_SPIN:

			r = huffman_decode_symbol(inf, &inf->ct, &inf->code);
			if (r)
				return r;

			inf->length = huff_length_base[inf->code -
			                               FIRST_LENGTH_CODE_INDEX];

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
			r = read_bits(inf, inf->exbits, &tu);
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
			if (inf->codeD > 29)
				return UPNG_FATAL + 11;

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
			continue;

		case UPNS_ID_BL_GB_SPINa:

			inf->out[inf->outpos++] = (uint8_t)inf->code;
			if (inf->outpos >= inf->outlen)
				inf->outpos = 0;

			inf->outpos_linear++;
			inf->treepos = 0;
			inf->state = UPNS_ID_BL_GB_SPIN;
			continue;
		}
	}

	return UPNG_OK;
}

static int
paeth(int a, int b, int c)
{
	int p = a + b - c;
	int pa = p > a ? p - a : a - p;
	int pb = p > b ? p - b : b - p;
	int pc = p > c ? p - c : c - p;

	if (pa <= pb && pa <= pc)
		return a;

	if (pb <= pc)
		return b;

	return c;
}

static upng_ret_t
unfilter_scanline(upng_t *upng)
{
	struct upng_unfline *u = &upng->u;
	unsigned long i;

	switch (u->filterType) {
	case 0: /* None */
		for (i = 0; i < u->bypl; i++)
			u->recon[i] = upng->inf.out[(u->sp + i) %
			                            upng->inf.info_size];
		break;
	case 1: /* Sub */
		for (i = 0; i <  u->bypp; i++)
			u->recon[i] = upng->inf.out[(u->sp + i) %
			                            upng->inf.info_size];

		for (i = u->bypp; i < u->bypl; i++)
			u->recon[i] = upng->inf.out[(u->sp + i) %
			                            upng->inf.info_size] +
				u->recon[i - u->bypp];
		break;
	case 2: /* Up */
		if (u->y)
			for (i = 0; i < u->bypl; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				            upng->inf.info_size] + u->precon[i];
		else
			for (i = 0; i < u->bypl; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				                          upng->inf.info_size];
		break;
	case 3: /* Average */
		if (u->y) {
			for (i = 0; i < u->bypp; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				        upng->inf.info_size] + u->precon[i] / 2;
			for (i = u->bypp; i < u->bypl; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				        upng->inf.info_size] +
					((u->recon[i - u->bypp] +
							u->precon[i]) / 2);
		} else {
			for (i = 0; i < u->bypp; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				                         upng->inf.info_size];
			for (i = u->bypp; i < u->bypl; i++)
				u->recon[i] = upng->inf.out[(u->sp + i) %
				                         upng->inf.info_size] +
					u->recon[i - u->bypp] / 2;
		}
		break;
	case 4: /* Paeth */
		if (u->y) {
			for (i = 0; i < u->bypp; i++)
				u->recon[i] = (uint8_t)(upng->inf.out[(u->sp + i) %
				                          upng->inf.info_size] +
					paeth(0, u->precon[i], 0));
			for (i = u->bypp; i < u->bypl; i++)
				u->recon[i] = (uint8_t)(upng->inf.out[(u->sp + i) %
				                          upng->inf.info_size] +
					paeth(u->recon[i - u->bypp],
							u->precon[i],
							u->precon[i - u->bypp]));
			break;
		}

		for (i = 0; i < u->bypp; i++)
			u->recon[i] = upng->inf.out[(u->sp + i) %
			                            upng->inf.info_size];
		for (i = u->bypp; i < u->bypl; i++)
			u->recon[i] = (uint8_t)(upng->inf.out[(u->sp + i) %
			                                upng->inf.info_size] +
				paeth(u->recon[i - u->bypp], 0, 0));
		break;
	default:
		lwsl_err("%s: line start is broken %d\n", __func__,
				u->filterType);
		return UPNG_FATAL + 12;
	}

	return UPNG_OK;
}

static int
upng_chonk(upng_t *upng)
{
	const uint8_t *data;
	size_t length;
	upng_ret_t r;

	/*
	 * We only want to do one IDAT chunk, but we may have to wade through
	 * other kinds of chunk to get to that, so it's in a loop.
	 */

	while (upng->chunk < upng->source.buffer + upng->source.size) {

		length = upng_chunk_length(upng->chunk);
		data = upng->chunk + 8;

		if (upng_chunk_type(upng->chunk) == CHUNK_IDAT) {

			upng->inf.in	= data;
			upng->inf.inlen	= length;

			if (!upng->inf.subsequent) {

				if (upng->inf.inlen < 2)
					goto bail;

				if ((upng->inf.in[0] * 256 + upng->inf.in[1]) % 31)
					goto bail;

				if ((upng->inf.in[0] & 15) != 8 ||
				   ((upng->inf.in[0] >> 4) & 15) > 7)
					goto bail;

				if ((upng->inf.in[1] >> 5) & 1)
					goto bail;

				upng->inf.subsequent = 1;
			} else
				upng->inf.inpos = 0;

			upng->inf.bp		= 0;

			/* decompress chunk of image data */

			r = uz_inflate_data(&upng->inf);
			switch (r) {
			case UPNG_WANT_INPUT:
			case UPNG_OK:
				goto ok;
			default:
				lwsl_notice("%s: inflate %d: FATAL + %d\n",
						__func__, upng->inf.state,
						r - UPNG_FATAL);
				goto bail;
			}

		} /* idat */

		if (upng_chunk_type(upng->chunk) == CHUNK_IEND)
			return 1;

		upng->chunk += upng_chunk_length(upng->chunk) + 12;
	}

	return 1;

ok:
	if (upng_chunk_type(upng->chunk) == CHUNK_IEND)
		return 1;

	upng->chunk += upng_chunk_length(upng->chunk) + 12;

	return 0;

bail:
	return -1;
}

upng_ret_t
upng_emit_next_line(upng_t *upng, const uint8_t **ppix)
{
	struct upng_unfline	*u = &upng->u;
	unsigned long		inindex;
	unsigned long		obp = u->alt ? u->bypl : 0;
	unsigned long		over = upng->inf.outpos_linear % (1 + u->bypl);
	long			vect;
	unsigned int		lib, ltot;
	upng_ret_t		ret = UPNG_OK;

	assert(upng->inf.info_size);
	assert(upng->u.bypl + 1);

	lib = upng->inf.info_size / (upng->u.bypl + 1);
	ltot = upng->inf.outpos_linear / (upng->u.bypl + 1);

	vect		= ((long)upng->inf.outpos - over -
				(1l + (long)u->bypl) * (long)(ltot - u->y));
	if (vect >= 0)
		inindex	= vect % (unsigned long)upng->inf.info_size;
	else
		inindex	= vect + (((-vect / upng->inf.info_size) + 1) *
						upng->inf.info_size);

	*ppix = NULL;

	if (u->y >= upng->height)
		goto out;

	if (u->y >= ltot) {
		switch (upng_chonk(upng)) {
		case 0:
		case 1:
			break;
		default:
			goto out;
		}

		assert(upng->inf.info_size);
		assert(upng->u.bypl + 1);

		over = upng->inf.outpos_linear % (1 + u->bypl);
		ltot = upng->inf.outpos_linear / (upng->u.bypl + 1);
		vect = ((long)upng->inf.outpos - over - (1l + (long)u->bypl) *
					(long)(ltot - u->y));
		if (vect >= 0)
			inindex	= vect % (unsigned long)upng->inf.info_size;
		else
			inindex	= vect + (((-vect / upng->inf.info_size) + 1) *
						upng->inf.info_size);

		if (ltot > lib && u->y <= ltot - lib)
			goto out;
	}

	if (ltot > lib && u->y <= ltot - lib)
		goto out;

	u->precon	= u->alt ? u->lines : u->lines + u->bypl;
	u->recon	= &u->lines[obp];
	u->filterType	= u->in[inindex];
	u->sp		= inindex + 1;

	if (unfilter_scanline(upng)) {
		ret = UPNG_FATAL + 13;

		goto out;
	}

	*ppix = u->recon;

	if (u->padded) {
		unsigned long x;

		for (x = 0; x < upng->width * u->bpp; x++) {
			uint8_t bit = (uint8_t)((u->in[(u->ibp) >> 3] >>
						(7 - ((u->ibp) & 7))) & 1);
			u->ibp++;

			if (!bit)
				u->lines[obp >> 3] &=
					(uint8_t)(~(1 << (7 - (obp & 7))));
			else
				u->lines[obp >> 3] |= (1 << (7 - (obp & 7)));

			obp++;
		}

		u->ibp += u->diff;
	}

out:
	u->alt ^= 1;
	u->y++;

	return ret;
}

static upng_format
determine_format(upng_t* upng) {
	switch (upng->color_type) {
	case UPNG_LUM:
		switch (upng->color_depth) {
		case 1:
			return UPNG_LUMINANCE1;
		case 2:
			return UPNG_LUMINANCE2;
		case 4:
			return UPNG_LUMINANCE4;
		case 8:
			return UPNG_LUMINANCE8;
		default:
			return UPNG_BADFORMAT;
		}
	case UPNG_RGB:
		switch (upng->color_depth) {
		case 8:
			return UPNG_RGB8;
		case 16:
			return UPNG_RGB16;
		default:
			return UPNG_BADFORMAT;
		}
	case UPNG_LUMA:
		switch (upng->color_depth) {
		case 1:
			return UPNG_LUMINANCE_ALPHA1;
		case 2:
			return UPNG_LUMINANCE_ALPHA2;
		case 4:
			return UPNG_LUMINANCE_ALPHA4;
		case 8:
			return UPNG_LUMINANCE_ALPHA8;
		default:
			return UPNG_BADFORMAT;
		}
	case UPNG_RGBA:
		switch (upng->color_depth) {
		case 8:
			return UPNG_RGBA8;
		case 16:
			return UPNG_RGBA16;
		default:
			return UPNG_BADFORMAT;
		}
	default:
		return UPNG_BADFORMAT;
	}
}

static void
upng_free_source(upng_t* upng)
{
	if (upng->source.owning)
		free((void*)upng->source.buffer);

	upng->source.buffer = NULL;
	upng->source.size = 0;
	upng->source.owning = 0;
}

upng_ret_t
upng_header(upng_t *upng)
{
	if (upng->state != UPNG_NEW)
		return UPNG_OK;

	if (upng->source.size < 29)
		return UPNG_FATAL + 16;

	/* check that PNG header matches expected val */
	if (upng->source.buffer[0] != 137 ||
	    upng->source.buffer[1] != 80 ||
	    upng->source.buffer[2] != 78 ||
	    upng->source.buffer[3] != 71 ||
	    upng->source.buffer[4] != 13 ||
	    upng->source.buffer[5] != 10 ||
	    upng->source.buffer[6] != 26 ||
	    upng->source.buffer[7] != 10)
		return UPNG_FATAL + 17;

	/* check that the first chunk is the IHDR chunk */
	if (MAKE_DWORD_PTR(upng->source.buffer + 12) != CHUNK_IHDR)
		return UPNG_FATAL + 18;

	/* read the values given in the header */
	upng->width = MAKE_DWORD_PTR(upng->source.buffer + 16);
	upng->height = MAKE_DWORD_PTR(upng->source.buffer + 20);
	upng->color_depth = upng->source.buffer[24];
	upng->color_type = (upng_color)upng->source.buffer[25];

	/* determine our color format */
	upng->format = determine_format(upng);
	if (upng->format == UPNG_BADFORMAT)
		return UPNG_FATAL + 19;

	if (upng->source.buffer[26] ||
	    upng->source.buffer[27] ||
	    upng->source.buffer[28]) /* only support comp type 0 */
		return UPNG_FATAL + 20;

	upng->state = UPNG_HEADER;

	return UPNG_OK;
}

upng_ret_t
upng_decode(upng_t* upng)
{
	memset(&upng->inf, 0, sizeof(upng->inf));
	upng->inf.upng = upng;

	/* parse the main header, if necessary */
	if (upng_header(upng))
		return UPNG_FATAL + 23;

	upng->chunk = upng->source.buffer + 33;

	while (upng->chunk < upng->source.buffer + upng->source.size) {
		size_t co = lws_ptr_diff_size_t(upng->chunk,
						upng->source.buffer);
		size_t length;

		length = upng_chunk_length(upng->chunk);
		if (length > INT_MAX)
			return UPNG_FATAL + 24;

		if (co + 12u > upng->source.size)
			return UPNG_FATAL + 25;

		if (co + 12u + length > upng->source.size)
			return UPNG_FATAL + 26;

		if (upng_chunk_type(upng->chunk) == CHUNK_IEND)
			break;

		if (upng_chunk_type(upng->chunk) != CHUNK_IDAT &&
		    upng_chunk_critical(upng->chunk))
			return UPNG_FATAL + 27;

		upng->chunk += upng_chunk_length(upng->chunk) + 12u;
	}

	upng->chunk = upng->source.buffer + 33;

	/*
	 * Do the first chunk to get started, then continue to do it as we need
	 * more lines
	 */

	upng->inf.info_size = 32768 + 512; /* 32KB sliding windows gz */
	upng->inflated = (uint8_t*)lws_malloc(upng->inf.info_size, __func__);
	if (!upng->inflated) {
		lwsl_notice("%s: inf malloc OOM\n",
				__func__);
		return UPNG_FATAL + 28;
	}

	upng->inf.out	 = upng->inflated;
	upng->inf.outlen = upng->inf.info_size;
	upng->inf.inpos	 = 2;
	upng->inf.outpos = 0;
	upng->inf.state	 = UPNS_ID_BL_GB_DONE;

	upng->u.bpp	 = upng_get_bpp(upng);
	upng->size	 = (upng->height * upng->width * upng->u.bpp + 7) / 8;

	if (!upng->u.bpp)
		return UPNG_FATAL + 14;

	upng->u.y	 = 0;
	upng->u.ibp	 = 0;
	upng->u.bypp	 = (upng->u.bpp + 7) / 8;
	upng->u.bypl	 = upng->width * upng->u.bypp;
	upng->u.in	 = upng->inflated;
	upng->u.lines	 = malloc(upng->u.bypl* 2);
	upng->u.alt	 = 0; /* which of the two lines to write to */
	upng->u.padded	 = upng->u.bpp < 8 &&
			   upng->width * upng->u.bpp !=
				      ((upng->width * upng->u.bpp + 7) / 8) * 8;
	upng->u.diff	 = (((upng->width * upng->u.bpp + 7) / 8) * 8) -
					(upng->width * upng->u.bpp);

	switch (upng_chonk(upng)) {
	case 0:
		return UPNG_OK;
	case 1:
		lwsl_notice("%s: chonk said 1\n", __func__);
		upng_free_source(upng);
		upng->state = UPNG_DECODED;

		return 1;
	default:
		lwsl_notice("%s: chonk said -1\n", __func__);
		break;
	}

	if (upng->inflated)
		lws_free_set_NULL(upng->inflated);

	return UPNG_FATAL + 31;
}

static upng_t *
upng_new(void)
{
	upng_t* upng;

	upng = (upng_t*)lws_zalloc(sizeof(upng_t), __func__);
	if (upng == NULL)
		return NULL;

	upng->color_type = UPNG_RGBA;
	upng->color_depth = 8;
	upng->format = UPNG_RGBA8;

	upng->state = UPNG_NEW;

	return upng;
}

upng_t *
upng_new_from_bytes(const uint8_t* buffer, unsigned long size)
{
	upng_t* upng = upng_new();
	if (upng == NULL)
		return NULL;

	upng->source.buffer = buffer;
	upng->source.size = size;
	upng->source.owning = 0;

	return upng;
}

void
upng_free(upng_t* upng)
{
	if (upng->inflated)
		free(upng->inflated);

	upng_free_source(upng);
	lws_free(upng);
}


unsigned int
upng_get_width(const upng_t* upng)
{
	return upng->width;
}

unsigned int
upng_get_height(const upng_t* upng)
{
	return upng->height;
}

unsigned int
upng_get_bpp(const upng_t* upng)
{
	return upng_get_bitdepth(upng) * upng_get_components(upng);
}

unsigned int
upng_get_components(const upng_t* upng)
{
	switch (upng->color_type) {
	case UPNG_LUM:
		return 1;
	case UPNG_RGB:
		return 3;
	case UPNG_LUMA:
		return 2;
	case UPNG_RGBA:
		return 4;
	default:
		return 0;
	}
}

unsigned int
upng_get_bitdepth(const upng_t* upng)
{
	return upng->color_depth;
}

unsigned int
upng_get_pixelsize(const upng_t* upng)
{
	unsigned bits = upng_get_bitdepth(upng) * upng_get_components(upng);

	bits += bits % 8;

	return bits;
}

upng_format upng_get_format(const upng_t *upng)
{
	return upng->format;
}

unsigned int
upng_get_size(const upng_t *upng)
{
	return upng->size;
}
