/*
 * The 16-level waveform for the T5 4.7"'s E Ink ED047TC1 panel
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Made by ../epd-waveform.py, change that and make this again, rather than
 * changing this.  See "The 16-level waveform" in the README.
 *
 * Passes drive rows for 12us, then three times for 0.6us, in turn,
 * the same for every update in flight, so updates can overlap freely.
 * Greys reached by a little drive from rest are grainy, so whatever it moves
 * from, each level is:
 *
 *  - driven black for the first 24 passes, so every pixel starts from the
 *    same place
 *
 *  - lightened from there by white in the last of the long and the short
 *    passes, this many of each, so it's driven right up to the end
 *
 *	level	 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
 *	long	 0   0   0   0   0   0   0   0   0   0   0   0   0   1   1   6
 *	short	 0   1   2   3   3   5   6   8   9  12  14  16  18   1   2  18
 *
 * Level 3's short passes are 43, 46, 47, not the last 3:
 * one after a pass with no drive lightens less.
 *
 * Black stays driven black to the end, since black left undriven relaxes.
 */

#include <libwebsockets.h>
#include "epd-waveform.h"

#define N LWS_EPDD_NONE
#define B LWS_EPDD_BLACK
#define W LWS_EPDD_WHITE

/* moving to a level is driven the same, whatever level it's moving from */
#define F(_c)	LWS_EPDD_PACK4(_c, _c, _c, _c), LWS_EPDD_PACK4(_c, _c, _c, _c), \
		LWS_EPDD_PACK4(_c, _c, _c, _c), LWS_EPDD_PACK4(_c, _c, _c, _c)

static const uint8_t wf_update[] = {
	/*	moving to level
	 *	0     1     2     3     4     5     6     7
	 *	8     9     10    11    12    13    14    15 */

	/* pass 0, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 1, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 2, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 3, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 4, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 5, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 6, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 7, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 8, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 9, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 10, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 11, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 12, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 13, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 14, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 15, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 16, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 17, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 18, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 19, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 20, 12us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 21, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 22, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 23, 0.6us */
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),
	F(B), F(B), F(B), F(B), F(B), F(B), F(B), F(B),

	/* pass 24, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(N), F(N), F(W),

	/* pass 25, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(W), F(N), F(N), F(W),

	/* pass 26, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(W), F(N), F(N), F(W),

	/* pass 27, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(W), F(W), F(N), F(N), F(W),

	/* pass 28, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(N), F(N), F(W),

	/* pass 29, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(W), F(W), F(N), F(N), F(W),

	/* pass 30, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 31, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 32, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(N), F(N), F(W),

	/* pass 33, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 34, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 35, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 36, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(N), F(N), F(W),

	/* pass 37, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 38, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 39, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 40, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(N), F(N), F(W),

	/* pass 41, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 42, 0.6us */
	F(B), F(N), F(N), F(N), F(N), F(W), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 43, 0.6us */
	F(B), F(N), F(N), F(W), F(N), F(W), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 44, 12us */
	F(B), F(N), F(N), F(N), F(N), F(N), F(N), F(N),
	F(N), F(N), F(N), F(N), F(N), F(W), F(W), F(W),

	/* pass 45, 0.6us */
	F(B), F(N), F(N), F(N), F(W), F(W), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(N), F(W),

	/* pass 46, 0.6us */
	F(B), F(N), F(W), F(W), F(W), F(W), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(N), F(W), F(W),

	/* pass 47, 0.6us */
	F(B), F(W), F(W), F(W), F(W), F(W), F(W), F(W),
	F(W), F(W), F(W), F(W), F(W), F(W), F(W), F(W),
};

/* the clear is 4 times 4 passes black then 4 white, of 50us each */

static const uint8_t wf_clear[] = {
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
};

const lws_epd_direct_waveform_t t547_wf_16 = {
	.update			= wf_update,
	.update_passes		= 48,
	.levels			= 16,
	.clear			= wf_clear,
	.clear_len		= LWS_ARRAY_SIZE(wf_clear),
	.drive_ns		= 600,
	.drive_cycle_ns		= { 12000, 600, 600, 600 },
	.clear_drive_ns		= 50000,
};

/*
 * What each level looks like, in linear light, the way
 * lws_display_palettize_grey() compares them.  The levels are spaced evenly
 * in sRGB lightness, as measured, so in linear light they go with a 2.2 power.
 */

#define P(_y) PALETTE_RGBY(_y, _y, _y)

const lws_display_colour_t t547_palette_16[16] = {
	P(0), P(1), P(3), P(7), P(14), P(23), P(34), P(48),
	P(64), P(83), P(105), P(129), P(156), P(186), P(219), P(255),
};
