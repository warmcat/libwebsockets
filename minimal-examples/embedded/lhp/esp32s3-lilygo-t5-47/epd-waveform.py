#!/usr/bin/env python3
#
# Makes main/epd-waveform.c, the 16-level waveform for the T5 4.7"'s E Ink
# ED047TC1 panel
#
# Written in 2026 by Andy Green <andy@warmcat.com>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# usage: ./epd-waveform.py > main/epd-waveform.c
#
# The waveform was tuned on the panel, measuring photos of the "Grey levels"
# settings page with scripts/epd-grey-levels.py, see "The 16-level waveform"
# in the README for how it works and what was learned tuning it.  To tune it,
# change LIGHT below, make the .c again and measure the result.

import sys

N, B, W = 'N', 'B', 'W'

# the short drive, and the drive in each pass of a cycle of four: one long
# drive, then three short ones to lighten finely
DRIVE_NS = 600
CYCLE = [12000, DRIVE_NS, DRIVE_NS, DRIVE_NS]

# every level is first driven black for this many passes...
SAT = 24
# ... then lightened by white in some of this many passes after that
TAIL = 24

PASSES = SAT + TAIL
LONG = [p for p in range(SAT, PASSES) if not p % 4]
SHORT = [p for p in range(SAT, PASSES) if p % 4]

#
# For each level, how many of the long and short passes it's lightened in,
# always the last that many of them, so it's driven up to the end.  The
# shorts can instead be a tuple of the short passes to use.
#
LIGHT = [(0, 0), (0, 1), (0, 2), (0, (43, 46, 47)), (0, 3), (0, 5), (0, 6),
         (0, 8), (0, 9), (0, 12), (0, 14), (0, 16), (0, 18), (1, 1), (1, 2),
         (len(LONG), len(SHORT))]


def shorts(n):
    return set(n) if isinstance(n, tuple) else set(SHORT[len(SHORT) - n:])


def longs(n):
    return set(LONG[len(LONG) - n:])


assert len(LIGHT) == 16
assert PASSES % len(CYCLE) == 0 and PASSES <= 64
assert all(nl <= len(LONG) and shorts(ns) <= set(SHORT) for nl, ns in LIGHT)


def code(p, t):
    """the drive in pass p for moving to level t, from any level"""
    nl, ns = LIGHT[t]
    # black stays driven to the end, since black left undriven relaxes
    if t == 0 or p < SAT:
        return B
    if p in shorts(ns) or p in longs(nl):
        return W
    return N


# each level's linear light, if they're evenly spaced in sRGB lightness
PALETTE = [round(255 * (t / 15) ** 2.2) for t in range(16)]


def col(vals):
    return '  '.join(f'{v:2}' for v in vals)


o = [f'''/*
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
 * Passes drive rows for {CYCLE[0] / 1000:g}us, then three times for {DRIVE_NS / 1000:g}us, in turn,
 * the same for every update in flight, so updates can overlap freely.
 * Greys reached by a little drive from rest are grainy, so whatever it moves
 * from, each level is:
 *
 *  - driven black for the first {SAT} passes, so every pixel starts from the
 *    same place
 *
 *  - lightened from there by white in the last of the long and the short
 *    passes, this many of each, so it's driven right up to the end
 *
 *	level	{col(range(16))}
 *	long	{col(len(longs(c[0])) for c in LIGHT)}
 *	short	{col(len(shorts(c[1])) for c in LIGHT)}''']
for t, (nl, ns) in enumerate(LIGHT):
    if isinstance(ns, tuple):
        o.append(f' *\n * Level {t}\'s short passes are {", ".join(str(p) for p in sorted(shorts(ns)))}, not the '
                 f'last {len(shorts(ns))}:\n * one after a pass with no drive lightens less.')
o.append(''' *
 * Black stays driven black to the end, since black left undriven relaxes.
 */

#include <libwebsockets.h>
#include "epd-waveform.h"

#define N LWS_EPDD_NONE
#define B LWS_EPDD_BLACK
#define W LWS_EPDD_WHITE

/* moving to a level is driven the same, whatever level it's moving from */
#define F(_c)	LWS_EPDD_PACK4(_c, _c, _c, _c), LWS_EPDD_PACK4(_c, _c, _c, _c), \\
		LWS_EPDD_PACK4(_c, _c, _c, _c), LWS_EPDD_PACK4(_c, _c, _c, _c)

static const uint8_t wf_update[] = {
	/*	moving to level
	 *	0     1     2     3     4     5     6     7
	 *	8     9     10    11    12    13    14    15 */''')
for p in range(PASSES):
    cs = [f'F({code(p, t)})' for t in range(16)]
    o.append(f'\n\t/* pass {p}, {CYCLE[p % len(CYCLE)] / 1000:g}us */')
    o.append('\t' + ', '.join(cs[:8]) + ',')
    o.append('\t' + ', '.join(cs[8:]) + ',')
o.append(f'''}};

/* the clear is 4 times 4 passes black then 4 white, of 50us each */

static const uint8_t wf_clear[] = {{
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
}};

const lws_epd_direct_waveform_t t547_wf_16 = {{
	.update			= wf_update,
	.update_passes		= {PASSES},
	.levels			= 16,
	.clear			= wf_clear,
	.clear_len		= LWS_ARRAY_SIZE(wf_clear),
	.drive_ns		= {DRIVE_NS},
	.drive_cycle_ns		= {{ {", ".join(str(c) for c in CYCLE)} }},
	.clear_drive_ns		= 50000,
}};

/*
 * What each level looks like, in linear light, the way
 * lws_display_palettize_grey() compares them.  The levels are spaced evenly
 * in sRGB lightness, as measured, so in linear light they go with a 2.2 power.
 */

#define P(_y) PALETTE_RGBY(_y, _y, _y)

const lws_display_colour_t t547_palette_16[16] = {{
	{", ".join(f"P({y})" for y in PALETTE[:8])},
	{", ".join(f"P({y})" for y in PALETTE[8:])},
}};''')
sys.stdout.write('\n'.join(o) + '\n')
