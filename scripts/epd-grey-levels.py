#!/usr/bin/env python3
#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


"""
Measure the grey levels an EPD actually shows, from a photo of it showing a
grey ramp test pattern.

The pattern is two rows of N equal-width bars (default 16), one per level,
filling what can be seen of the display, eg, as shown by "Grey levels" in the
settings of the lhp embedded examples (minimal-examples/embedded/lhp).  The
top row goes from black to white, left to right, and the bottom row from
white to black.  So whatever levels the panel really shows, the bar in each
slot of one row shows the same level as the bar in the mirrored slot of the
other: that's what the pattern is recognised by, not the levels themselves,
which may be anything, even out of order.

The photo may be taken from any side, upside down, portrait or landscape,
off level and not square on.  The pattern filling what can be seen, all of
it is placed by the four corners of what can be seen, through the
perspective they were photographed with.  On a downscaled copy,

 - long straight edges are found, roughly along the photo and roughly up
   and down it, and every quadrilateral two of each make is a guess at what
   can be seen

 - each guess is scored by how strongly the photo steps across the lines
   the pattern has where it says they are: its outline, the "spine" between
   the rows, and the boundaries between bars, through both rows.  Bars next
   to each other may show the same level, and so not step, but most do.
   Each line is in pieces, each between the same two bars, so stepping the
   same way all along: the step is averaged along a piece before its size
   is taken, so the panel's mottle, stepping every which way, averages out.
   Outside the outline, there must be the bezel, or touch panel mask, all
   round what can be seen, at least as light as the bars just inside it:
   that rules out the outer edges of the bezel, and things around the
   panel in the photo, eg, a cable lined up with an edge of it

 - the best guesses' corners are moved to where the lines fit best, along
   with how far the pattern runs on under the bezel past the ends of the
   rows, in case the display's inset isn't right, and where the spine is.
   The best of them is checked: the bars' boundaries must stand out from
   lines halfway between them, and the bars of one row must match those
   mirrored in the other

Then on the full size photo, the middle of each bar, inset by --margin-x and
--margin-y, is averaged, dropping the darkest and lightest --trim of pixels
so dust and specks don't skew it.

Each row is normalised on its own, its black bar as 0% and its white bar as
100%, so light falling unevenly top to bottom doesn't count, and the two rows
are averaged: since each level is at mirrored places in the two rows, that
cancels light falling off evenly from one side to the other.  The difference
between the rows is shown, as a measure of how much to trust the result.

The percentages are of lightness from black.  By default they're of the luma
of the photo's sRGB-encoded pixels, which is how the levels are encoded in
the display's line buffer, so an evenly spaced ramp ideally shows as steps of
100 / (N - 1)%.  With --linear, the pixels are decoded to linear light first,
ie, how much light each bar reflects.  Either way the camera's own tone curve
is in the result, so it's best to shoot with fixed exposure, no HDR and no
"scene optimisation", under even, diffuse light without reflections.

ImageMagick (magick, or convert) is used to decode the photo.  --overlay
writes a copy of the photo showing what was found and where was sampled,
which should be checked before trusting the numbers.
"""

import argparse
import itertools
import math
import os
import shutil
import subprocess
import sys
import tempfile
from array import array

DET_SIZE = 1000			# longest side of the copy the pattern is found in
LINE_TILT = 30			# degrees an edge may be off the photo's axes
LINES_KEPT = 24			# edges kept each way, to make guesses from
GUESSES_SCORED = 300		# best guesses at a glance that are scored
GUESSES_REFINED = 6		# best guesses whose corners are refined
MIN_SIDE = 0.15			# least fraction of the photo a side spans
MASK_TOL = 12.0			# luma the bezel may be darker than a bar by
RIB_CONTRAST = 3.0		# boundaries' steps over those halfway between
MIRROR_MIN_CORR = 0.8		# of each row's bars with the other's mirrored
MIN_SPREAD = 4.0		# luma the bars' means must spread by, at least


def die(msg):
    sys.stderr.write("epd-grey-levels: %s\n" % msg)
    sys.exit(1)


class NotFound(Exception):
    """the pattern isn't where we're looking for it"""


def magick_cmd():
    for c in ("magick", "convert"):
        p = shutil.which(c)
        if p:
            return [p]
    die("needs ImageMagick (magick or convert)")
    return None


# ImageMagick takes a filename as more than a filename, eg, "|cmd" runs cmd,
# "coder:file" picks how it's read, "@file" reads a list of files, and a
# leading "-" is an option.  So the paths we're given never reach its
# command line: we read and write the files, and ImageMagick only sees
# stdin and stdout, with the format of what it writes chosen from this list
# by the overlay's extension.

OVERLAY_FORMATS = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".webp": "webp",
    ".tif": "tiff",
    ".tiff": "tiff",
    ".bmp": "bmp",
}


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        die("unable to read %s: %s" % (path, e.strerror))
    return None


def write_file(path, data):
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        die("unable to write %s: %s" % (path, e.strerror))


# ---------------------------------------------------------------------------
# Image loading
# ---------------------------------------------------------------------------

class Image:
    """8-bit RGB pixels, decoded and oriented by ImageMagick"""

    def __init__(self, path, size=None):
        cmd = magick_cmd() + ["-", "-auto-orient"]
        if size:
            cmd += ["-scale", "%dx%d" % (size, size)]
        cmd += ["-depth", "8", "ppm:-"]
        r = subprocess.run(cmd, input=read_file(path),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode:
            die("unable to decode %s: %s" %
                (path, r.stderr.decode(errors="replace").strip()))
        self.w, self.h, self.rgb = self._parse_ppm(r.stdout)

    @staticmethod
    def _ppm_field(d, pos):
        """the next field of a PPM header from pos, past any whitespace and
        comments, and where it ends"""
        while True:
            while pos < len(d) and d[pos:pos + 1].isspace():
                pos += 1
            if d[pos:pos + 1] != b"#":
                break
            while pos < len(d) and d[pos:pos + 1] not in (b"\n", b"\r"):
                pos += 1
        start = pos
        while pos < len(d) and not d[pos:pos + 1].isspace():
            pos += 1
        if start == pos:
            die("truncated PPM from ImageMagick")
        return d[start:pos], pos

    @staticmethod
    def _parse_ppm(d):
        fields = []
        pos = 0
        while len(fields) < 4:
            f, pos = Image._ppm_field(d, pos)
            fields.append(f)
        pos += 1		# the single whitespace before the pixels
        if fields[0] != b"P6" or fields[3] != b"255":
            die("unexpected PPM from ImageMagick")
        w, h = int(fields[1]), int(fields[2])
        if w < 64 or h < 64 or len(d) - pos < w * h * 3:
            die("image too small or truncated")
        return w, h, memoryview(d)[pos:pos + w * h * 3]


def luma_luts(linear):
    """per-channel tables whose sum is Rec.709 luma, 0 - 255"""

    def lin(v):
        c = v / 255.0
        c = c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        return c * 255.0

    f = lin if linear else float
    return tuple([k * f(v) for v in range(256)]
                 for k in (0.2126, 0.7152, 0.0722))


def luma_plane(img, luts):
    lr, lg, lb = luts
    rgb = img.rgb
    return array("f", (lr[rgb[i]] + lg[rgb[i + 1]] + lb[rgb[i + 2]]
                       for i in range(0, img.w * img.h * 3, 3)))


# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------

def bilinear(Y, w, h, x, y):
    if x < 0 or y < 0 or x > w - 1.001 or y > h - 1.001:
        return None
    ix, iy = int(x), int(y)
    fx, fy = x - ix, y - iy
    i = iy * w + ix
    top = Y[i] + (Y[i + 1] - Y[i]) * fx
    bot = Y[i + w] + (Y[i + w + 1] - Y[i + w]) * fx
    return top + (bot - top) * fy


def pearson(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    sxx = sum((a - mx) ** 2 for a in xs)
    syy = sum((b - my) ** 2 for b in ys)
    if sxx <= 0 or syy <= 0:
        return 0.0
    return sxy / math.sqrt(sxx * syy)


def intersect(l1, l2):
    """where lines n . p = rho meet, or None if they're near parallel"""
    (a1, b1, r1), (a2, b2, r2) = l1, l2
    d = a1 * b2 - a2 * b1
    if abs(d) < 1e-6:
        return None
    return ((r1 * b2 - r2 * b1) / d, (a1 * r2 - a2 * r1) / d)


class Homography:
    """
    Maps (u, v) on the pattern, 0 - 1 along the rows and 0 - 1 across them,
    to the photo, given where its corners (0, 0), (1, 0), (1, 1) and (0, 1)
    are
    """

    def __init__(self, c):
        (x0, y0), (x1, y1), (x2, y2), (x3, y3) = c
        dx1, dx2, dx3 = x1 - x2, x3 - x2, x0 - x1 + x2 - x3
        dy1, dy2, dy3 = y1 - y2, y3 - y2, y0 - y1 + y2 - y3
        den = dx1 * dy2 - dx2 * dy1
        if abs(den) < 1e-9:
            raise NotFound("degenerate corners")
        g = (dx3 * dy2 - dx2 * dy3) / den
        h = (dx1 * dy3 - dx3 * dy1) / den
        self.m = (x1 - x0 + g * x1, x3 - x0 + h * x3, x0,
                  y1 - y0 + g * y1, y3 - y0 + h * y3, y0, g, h)

    def xy(self, u, v):
        a, b, c, d, e, f, g, h = self.m
        w = g * u + h * v + 1.0
        return (a * u + b * v + c) / w, (d * u + e * v + f) / w


class Fit:
    """
    Where the pattern is: the corners of what can be seen of the display,
    in the pattern's order, how far the pattern runs past the ends of what
    can be seen along the rows, ea and eb, as fractions of it, in case the
    inset isn't right, and where across it the spine is, d
    """

    def __init__(self, c, ea=0.0, eb=0.0, d=0.5):
        self.c = [tuple(p) for p in c]
        self.ea, self.eb, self.d = ea, eb, d
        self._H = None

    def params(self):
        return [v for p in self.c for v in p] + [self.ea, self.eb, self.d]

    @classmethod
    def from_params(cls, p):
        return cls([(p[0], p[1]), (p[2], p[3]), (p[4], p[5]), (p[6], p[7])],
                   p[8], p[9], p[10])

    def homography(self):
        if not self._H:
            self._H = Homography(self.c)
        return self._H

    def lengths(self):
        c = self.c
        return (0.5 * (math.dist(c[0], c[1]) + math.dist(c[3], c[2])),
                0.5 * (math.dist(c[0], c[3]) + math.dist(c[1], c[2])))

    def plausible(self, nb):
        return (abs(self.ea) <= 1.5 / nb and abs(self.eb) <= 1.5 / nb and
                0.35 <= self.d <= 0.65)

    def rib(self, i, nb):
        """where boundary i of 0 - nb is along the rows of what's seen"""
        return -self.ea + (1.0 + self.ea + self.eb) * i / nb

    def bar(self, i, nb, margin):
        """the part of bar i that's seen, less a margin of its width"""
        u0 = max(0.0, self.rib(i, nb))
        u1 = min(1.0, self.rib(i + 1, nb))
        m = margin * (u1 - u0)
        return u0 + m, u1 - m

    def row(self, r, margin):
        """the part of row r, 0 or 1, that's seen, less a margin of it"""
        v0, v1 = (0.0, self.d) if r == 0 else (self.d, 1.0)
        m = margin * (v1 - v0)
        return v0 + m, v1 - m

    def __str__(self):
        return ("corners %s, past the ends %.3f %.3f, spine %.3f" %
                (" ".join("%.1f,%.1f" % p for p in self.c), self.ea,
                 self.eb, self.d))


def convex(c):
    """are the corners, in order, a convex quadrilateral"""
    s = 0
    for k in range(4):
        (x0, y0), (x1, y1), (x2, y2) = c[k], c[(k + 1) % 4], c[(k + 2) % 4]
        z = (x1 - x0) * (y2 - y1) - (y1 - y0) * (x2 - x1)
        if abs(z) < 1e-6:
            return False
        if s and (z > 0) != (s > 0):
            return False
        s = z
    return True


# ---------------------------------------------------------------------------
# Finding the pattern
# ---------------------------------------------------------------------------

class Finder:

    def __init__(self, img, luts, nbars, verbose):
        self.w, self.h = img.w, img.h
        self.Y = luma_plane(img, luts)
        self.nbars = nbars
        self.verbose = verbose
        self._gradients()

    def log(self, msg):
        if self.verbose:
            sys.stderr.write(msg + "\n")

    def _gradients(self):
        """Sobel, everywhere, and the strongest few percent of it"""
        w, h, Y = self.w, self.h, self.Y
        gx = array("f", bytes(4 * w * h))
        gy = array("f", bytes(4 * w * h))
        for y in range(1, h - 1):
            r0, r1, r2 = (y - 1) * w, y * w, (y + 1) * w
            for x in range(1, w - 1):
                gx[r1 + x] = (Y[r0 + x + 1] + 2 * Y[r1 + x + 1] +
                              Y[r2 + x + 1] - Y[r0 + x - 1] -
                              2 * Y[r1 + x - 1] - Y[r2 + x - 1]) * 0.125
                gy[r1 + x] = (Y[r2 + x - 1] + 2 * Y[r2 + x] +
                              Y[r2 + x + 1] - Y[r0 + x - 1] -
                              2 * Y[r0 + x] - Y[r0 + x + 1]) * 0.125
        self.gx, self.gy = gx, gy

        # what's strong is relative to the photo, which may be lit unevenly
        mags = sorted(abs(gx[i]) + abs(gy[i]) for i in range(0, w * h, 7))
        self.g_strong = max(2.0, mags[int(0.92 * len(mags))])

    def _hough(self):
        """votes for lines through the strong edges, by (angle, rho)"""
        w, h, gx, gy = self.w, self.h, self.gx, self.gy
        acc = {}
        for y in range(2, h - 2):
            r = y * w
            for x in range(2, w - 2):
                ex, ey = gx[r + x], gy[r + x]
                m = abs(ex) + abs(ey)
                if m < self.g_strong:
                    continue
                # the edge runs across its gradient
                phi = int(round(math.degrees(math.atan2(ey, ex)))) % 180
                for p in (phi - 1, phi, phi + 1):
                    p %= 180
                    t = math.radians(p)
                    rho = int(round(x * math.cos(t) + y * math.sin(t)))
                    k = (p, rho)
                    acc[k] = acc.get(k, 0.0) + m
        return acc

    @staticmethod
    def _family(p):
        """
        By the angle of its normal, p, 90 being an edge along the photo, 0
        for a line roughly along the photo, 1 for one roughly up and down
        it, or None
        """
        if abs(p - 90) <= LINE_TILT:
            return 0
        if p <= LINE_TILT or p >= 180 - LINE_TILT:
            return 1
        return None

    @staticmethod
    def _near(fam, p, rho):
        """is there a line in fam close to (p, rho)"""
        for (o, op) in fam:
            dp = min(abs(p - op), 180 - abs(p - op))
            # rho of the same line flips sign across p = 0 / 180
            if dp <= 3 and abs(abs(o[2]) - abs(rho)) <= 6:
                return True
        return False

    def lines(self):
        """
        Long straight edges, as (a, b, rho), a line being a x + b y = rho,
        the strongest LINES_KEPT of them roughly along the photo, and of
        them roughly up and down it
        """
        acc = self._hough()

        # an edge's votes spread over neighbouring rho
        cand = []
        for (p, rho), v in acc.items():
            s = v + acc.get((p, rho - 1), 0.0) + acc.get((p, rho + 1), 0.0)
            cand.append((s, p, rho))
        cand.sort(reverse=True)

        fam = {0: [], 1: []}
        for _, p, rho in cand:
            f = self._family(p)
            if f is None or len(fam[f]) >= LINES_KEPT:
                continue
            if not self._near(fam[f], p, rho):
                t = math.radians(p)
                fam[f].append(((math.cos(t), math.sin(t), float(rho)), p))
            if len(fam[0]) >= LINES_KEPT and len(fam[1]) >= LINES_KEPT:
                break
        self.log("edges: %d along the photo, %d up and down it" %
                 (len(fam[0]), len(fam[1])))
        return [ln for ln, _ in fam[0]], [ln for ln, _ in fam[1]]

    def _quad(self, a0, a1, u0, u1, minspan):
        """
        The quadrilateral lines a0 and a1 roughly along the photo make with
        u0 and u1 roughly up and down it, as its corners in the pattern's
        order, if it's plausible, else None
        """
        w, h = self.w, self.h
        c = [intersect(a0, u0), intersect(a0, u1),
             intersect(a1, u1), intersect(a1, u0)]
        if None in c or not all(1 <= x <= w - 2 and 1 <= y <= h - 2
                                for x, y in c):
            return None
        if not convex(c):
            return None
        la = 0.5 * (math.dist(c[0], c[1]) + math.dist(c[3], c[2]))
        lu = 0.5 * (math.dist(c[0], c[3]) + math.dist(c[1], c[2]))
        if min(la, lu) < minspan:
            return None
        # the rows run along the longer sides
        return c if la >= lu else [c[0], c[3], c[2], c[1]]

    def guesses(self):
        """every plausible quadrilateral two of each way of line make, as
        its corners in the pattern's order"""
        along, updown = self.lines()
        minspan = MIN_SIDE * max(self.w, self.h)
        out = []
        for (a0, a1), (u0, u1) in itertools.product(
                itertools.combinations(along, 2),
                itertools.combinations(updown, 2)):
            c = self._quad(a0, a1, u0, u1, minspan)
            if c:
                out.append(c)
        self.log("guesses: %d" % len(out))
        return out

    def _edge(self, x, y, nx, ny, fine):
        """the gradient across a line with normal (nx, ny) at x, y, signed"""
        w, h = self.w, self.h
        if fine:
            ex = bilinear(self.gx, w, h, x, y)
            if ex is None:
                return 0.0
            ey = bilinear(self.gy, w, h, x, y)
        else:
            xi, yi = int(x + 0.5), int(y + 0.5)
            if not (0 <= xi < w and 0 <= yi < h):
                return 0.0
            ex, ey = self.gx[yi * w + xi], self.gy[yi * w + xi]
        return ex * nx + ey * ny

    def _line_score(self, hom, ln, per, fine):
        """
        The mean step across a line of the pattern.  The line is in pieces,
        each between the same two bars, or a bar and the bezel, so stepping
        the same way all along it: the step is averaged along each piece
        before its size is taken, so the panel's mottle, stepping every
        which way, averages out, and only the pattern's own edges count
        """
        u0, v0, u1, v1, cuts = ln
        x0, y0 = hom.xy(u0, v0)
        x1, y1 = hom.xy(u1, v1)
        ll = math.hypot(x1 - x0, y1 - y0)
        if ll < 1:
            return 0.0
        nx, ny = -(y1 - y0) / ll, (x1 - x0) / ll
        ends = [0.0] + [c for c in cuts if 0.0 < c < 1.0] + [1.0]
        tot = 0.0
        for a, b in zip(ends, ends[1:]):
            s = 0.0
            for k in range(per):
                f = a + (b - a) * (k + 0.5) / per
                x, y = hom.xy(u0 + (u1 - u0) * f, v0 + (v1 - v0) * f)
                s += self._edge(x, y, nx, ny, fine)
            tot += abs(s / per) * (b - a)
        return tot

    def _mask(self, hom, ns):
        """
        The fraction of the outline with the bezel outside it at least as
        light as the bar inside it, as the bezel or a touch panel's mask is
        """
        w, h, Y = self.w, self.h, self.Y
        cx, cy = hom.xy(0.5, 0.5)
        sides = ((0, 0, 1, 0), (1, 0, 1, 1), (1, 1, 0, 1), (0, 1, 0, 0))
        ok = tot = 0
        for (u0, v0, u1, v1) in sides:
            x0, y0 = hom.xy(u0, v0)
            x1, y1 = hom.xy(u1, v1)
            ll = math.hypot(x1 - x0, y1 - y0)
            if ll < 1:
                return 0.0
            nx, ny = -(y1 - y0) / ll, (x1 - x0) / ll
            # outward
            mx, my = 0.5 * (x0 + x1), 0.5 * (y0 + y1)
            if nx * (mx - cx) + ny * (my - cy) < 0:
                nx, ny = -nx, -ny
            for k in range(ns):
                f = (k + 0.5) / ns
                x, y = hom.xy(u0 + (u1 - u0) * f, v0 + (v1 - v0) * f)
                lo = bilinear(Y, w, h, x + 4 * nx, y + 4 * ny)
                li = bilinear(Y, w, h, x - 4 * nx, y - 4 * ny)
                tot += 1
                if lo is not None and li is not None and \
                        lo >= li - MASK_TOL:
                    ok += 1
        return ok / tot

    def _lines(self, f, mid):
        """
        The pattern's lines placed by fit f, as (u0, v0, u1, v1) on what can
        be seen: the boundaries between bars and the ends of the pattern
        where they can be seen, or with mid, lines halfway between them
        instead, and with them, unless mid, the spine
        """
        nb = self.nbars
        out = []
        for i in range(nb + 1):
            u = f.rib(i + 0.5 if mid else i, nb)
            if (not mid or i < nb) and 0.01 < u < 0.99:
                # in a piece for each row
                out.append((u, 0.0, u, 1.0, [f.d]))
        if not mid:
            out.append((0.0, f.d, 1.0, f.d, self._bar_cuts(f)))
        return out

    def _bar_cuts(self, f):
        """where along the rows a line along them goes from bar to bar"""
        return [f.rib(i, self.nbars) for i in range(1, self.nbars)]

    def _outline(self, f):
        """the edges of what can be seen, in pieces as the other lines"""
        bc = self._bar_cuts(f)
        return [(0, 0, 1, 0, bc), (1, 0, 1, 1, [f.d]),
                (0, 1, 1, 1, bc), (0, 0, 0, 1, [f.d])]

    def score(self, f, fine):
        """
        How well the pattern placed by fit f fits the photo: the mean step
        across its lines and the outline of what can be seen, scaled by how
        much of the outline has the bezel outside it
        """
        try:
            hom = f.homography()
        except NotFound:
            return 0.0
        per = 4 if fine else 2
        lines = self._lines(f, False) + self._outline(f)
        tot = sum(self._line_score(hom, ln, per * (1 if ln[4] and
                                                 len(ln[4]) > 1 else 3),
                                   fine) for ln in lines)
        return tot / len(lines) * self._mask(hom, 6 * per)

    def glance(self, f):
        """
        A quick score, for choosing which guesses to score: the steps across
        just the outline and the spine, and a little of the bezel
        """
        try:
            hom = f.homography()
        except NotFound:
            return 0.0
        lines = [(0, 0, 1, 0, []), (1, 0, 1, 1, []), (0, 1, 1, 1, []),
                 (0, 0, 0, 1, []), (0, 0.5, 1, 0.5, [0.5])]
        tot = sum(self._line_score(hom, ln, 6, False) for ln in lines)
        return tot / len(lines) * self._mask(hom, 2)

    def ribs_contrast(self, f):
        """the boundaries' steps over those along lines halfway between"""
        hom = f.homography()
        on = [self._line_score(hom, ln, 12, True)
              for ln in self._lines(f, False)[:-1]]
        off = [self._line_score(hom, ln, 12, True)
               for ln in self._lines(f, True)]
        if not on or not off:
            return 0.0
        return (sum(on) / len(on)) / (sum(off) / len(off) + 0.5)

    def _ends(self, f):
        """the best fit of how far the pattern runs past the ends of what
        can be seen, from fit f, and its score"""
        nb = self.nbars
        best, bf = -1.0, f
        for a in range(-3, 4):
            for b in range(-3, 4):
                g = Fit(f.c, 0.25 * a / nb, 0.25 * b / nb, f.d)
                v = self.score(g, True)
                if v > best:
                    best, bf = v, g
        return bf, best

    def _try_move(self, p, k, d, best):
        """
        Move parameter k of fit parameters p by d, keeping the move and
        returning the new score if it fits better than best, otherwise
        putting it back and returning None
        """
        p[k] += d
        g = Fit.from_params(p)
        if g.plausible(self.nbars):
            v = self.score(g, True)
            if v > best:
                return v
        p[k] -= d
        return None

    def _sweep(self, p, unit, step, best):
        """move each parameter in turn by a step either way, where that
        fits better: the best score after, and if any moved"""
        moved = False
        for k in range(len(p)):
            for s in (step, -step):
                v = self._try_move(p, k, s * unit[k], best)
                if v is not None:
                    best, moved = v, True
                    break
        return best, moved

    def refine(self, f):
        """
        Find how far the pattern runs past the ends of what can be seen, in
        case the inset isn't right, then move everything while it fits
        better, in smaller and smaller steps
        """
        bf, best = self._ends(f)
        p = bf.params()
        # a px of the corners, and of the others, in their units
        lu, lv = bf.lengths()
        unit = [1.0] * 8 + [1.0 / lu, 1.0 / lu, 1.0 / lv]
        for step in (3.0, 1.5, 0.75, 0.35):
            moved = True
            while moved:
                best, moved = self._sweep(p, unit, step, best)
        return Fit.from_params(p), best

    def _cell_mean(self, f, r, i, mx, my):
        """the mean luma in the middle of bar i of row r, here"""
        (u0, u1), (v0, v1) = f.bar(i, self.nbars, mx), f.row(r, my)
        hom = f.homography()
        s, n = 0.0, 0
        for a in range(5):
            for b in range(5):
                x, y = hom.xy(u0 + (u1 - u0) * (a + 0.5) / 5,
                              v0 + (v1 - v0) * (b + 0.5) / 5)
                val = bilinear(self.Y, self.w, self.h, x, y)
                if val is not None:
                    s += val
                    n += 1
        if not n:
            raise NotFound("bars outside the photo")
        return s / n

    def cell_means(self, f, mx, my):
        """the mean luma in the middle of each bar, here, of each row"""
        return [[self._cell_mean(f, r, i, mx, my) for i in range(self.nbars)]
                for r in range(2)]

    def check(self, f):
        """is the pattern really where fit f puts it"""
        contrast = self.ribs_contrast(f)
        top, bot = self.cell_means(f, 0.25, 0.15)
        mirror = pearson(top, bot[::-1])
        spread = min(max(top) - min(top), max(bot) - min(bot))
        self.log("  boundaries %.1fx the steps between them, rows mirror "
                 "%.2f, spread %.0f" % (contrast, mirror, spread))
        if contrast < RIB_CONTRAST:
            raise NotFound("bar boundaries don't stand out")
        if spread < MIN_SPREAD:
            raise NotFound("bars all alike")
        if mirror < MIRROR_MIN_CORR:
            raise NotFound("rows don't mirror each other")

    def find(self):
        gs = self.guesses()
        if not gs:
            raise NotFound("no quadrilateral of edges")
        gs = sorted(gs, key=lambda c: -self.glance(Fit(c)))
        scored = sorted(((self.score(Fit(c), False), c)
                         for c in gs[:GUESSES_SCORED]), key=lambda t: -t[0])

        # refine the best few distinct guesses
        refined = []
        for s, c in scored:
            if len(refined) == GUESSES_REFINED:
                break
            if any(max(math.dist(p, q) for p, q in zip(c, o.c)) < 4
                   for o in (r[1] for r in refined)):
                continue
            rf, rs = self.refine(Fit(c))
            self.log("guess %.2f, refined %.2f: %s" % (s, rs, rf))
            refined.append((rs, rf))
        refined.sort(key=lambda t: -t[0])

        for rs, rf in refined:
            try:
                self.check(rf)
            except NotFound as e:
                self.log("  rejected: %s" % e)
                continue
            self.fit = rf
            return
        raise NotFound("no guess was the pattern")


# ---------------------------------------------------------------------------
# Measuring
# ---------------------------------------------------------------------------

def cell_corners(fd, row, i, mx, my):
    """
    The four corners, in detection image coordinates, of the part of bar i
    of a row (0 or 1) that's sampled, and a function mapping (u, v) in it to
    detection image coordinates
    """
    f = fd.fit
    hom = f.homography()
    (u0, u1), (v0, v1) = f.bar(i, fd.nbars, mx), f.row(row, my)

    def at(a, b):
        return hom.xy(u0 + (u1 - u0) * a, v0 + (v1 - v0) * b)

    return [at(0, 0), at(1, 0), at(1, 1), at(0, 1)], at


def measure_cell(img, luts, at, scale, trim):
    """trimmed mean, std and count of the luma of the full size pixels in
    the sampled part of a cell"""
    (x0, y0), (x1, y1), (x3, y3) = at(0, 0), at(1, 0), at(0, 1)
    nu = max(4, int(math.hypot(x1 - x0, y1 - y0) * scale))
    nv = max(4, int(math.hypot(x3 - x0, y3 - y0) * scale))
    lr, lg, lb = luts
    rgb, w, h = img.rgb, img.w, img.h
    vals = []
    for kv in range(nv):
        v = (kv + 0.5) / nv
        # the cell's sides are straight, so interpolate along each row
        xa, ya = at(0, v)
        xb, yb = at(1, v)
        for ku in range(nu):
            u = (ku + 0.5) / nu
            x = int((xa + (xb - xa) * u + 0.5) * scale)
            y = int((ya + (yb - ya) * u + 0.5) * scale)
            if 0 <= x < w and 0 <= y < h:
                o = (y * w + x) * 3
                vals.append(lr[rgb[o]] + lg[rgb[o + 1]] + lb[rgb[o + 2]])
    if len(vals) < 16:
        die("bar sample area too small")
    vals.sort()
    k = int(len(vals) * trim)
    kept = vals[k:len(vals) - k]
    mean = sum(kept) / len(kept)
    std = math.sqrt(sum((x - mean) ** 2 for x in kept) / len(kept))
    return mean, std, len(kept)


def overlay_format(path):
    fmt = OVERLAY_FORMATS.get(os.path.splitext(path)[1].lower())
    if not fmt:
        die("--overlay must end in one of %s" %
            " ".join(sorted(OVERLAY_FORMATS)))
    return fmt


def write_overlay(path, fmt, src, fd, cells, scale):
    def p(xy):
        return "%.1f,%.1f" % ((xy[0] + 0.5) * scale - 0.5,
                              (xy[1] + 0.5) * scale - 0.5)

    f, nb = fd.fit, fd.nbars
    hom = f.homography()
    sw = max(2, int(scale * 1.5))
    mvg = ["stroke-width %d" % sw, "fill none", "stroke cyan",
           "polygon " + " ".join(p(c) for c in f.c),
           "stroke red",
           "line %s %s" % (p(hom.xy(0, f.d)), p(hom.xy(1, f.d))),
           "stroke yellow"]
    for i in range(nb + 1):
        u = f.rib(i, nb)
        if 0.0 < u < 1.0:
            mvg.append("line %s %s" % (p(hom.xy(u, 0)), p(hom.xy(u, 1))))
    mvg.append("stroke lime")
    for (row, i, level, corners) in cells:
        mvg.append("polygon " + " ".join(p(c) for c in corners))
    mvg += ["stroke none", "fill magenta",
            "font-size %d" % int(scale * 10)]
    for (row, i, level, corners) in cells:
        cx = sum(c[0] for c in corners) / 4
        cy = sum(c[1] for c in corners) / 4
        mvg.append("text %s '%d'" % (p((cx - 4, cy)), level))

    with tempfile.TemporaryDirectory() as td:
        mf = os.path.join(td, "overlay.mvg")
        with open(mf, "w") as f:
            f.write("\n".join(mvg) + "\n")
        cmd = magick_cmd() + ["-", "-auto-orient", "-draw", "@" + mf,
                              fmt + ":-"]
        r = subprocess.run(cmd, input=read_file(src),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode:
            die("unable to draw overlay: %s" %
                r.stderr.decode(errors="replace").strip())
    write_file(path, r.stdout)


def parse_args():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0].strip(),
        epilog="See the top of this script for how it works.")
    ap.add_argument("photo", help="photo of the panel showing the ramp")
    ap.add_argument("--levels", type=int, default=16,
                    help="bars per row (default 16)")
    ap.add_argument("--linear", action="store_true",
                    help="measure in linear light, not sRGB-encoded luma")
    ap.add_argument("--margin-x", type=float, default=0.2,
                    help="fraction of a bar's width not sampled at each "
                         "side (default 0.2)")
    ap.add_argument("--margin-y", type=float, default=0.1,
                    help="fraction of a row's height not sampled at the "
                         "spine and the outer edge (default 0.1)")
    ap.add_argument("--trim", type=float, default=0.05,
                    help="fraction of darkest and of lightest pixels "
                         "dropped from each bar (default 0.05)")
    ap.add_argument("--overlay", metavar="OUT",
                    help="write a copy of the photo showing what was found "
                         "and sampled, as .png, .jpg, .webp, .tif or .bmp")
    ap.add_argument("--csv", action="store_true", help="output as CSV")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="say what was found, on stderr")
    args = ap.parse_args()

    if args.levels < 3 or args.levels > 64:
        die("--levels must be 3 - 64")
    if not (0 <= args.margin_x < 0.45 and 0 <= args.margin_y < 0.45):
        die("margins must be 0 - 0.45")
    if not 0 <= args.trim < 0.4:
        die("--trim must be 0 - 0.4")
    return args


def measure(fd, full, luts, scale, args):
    """
    The trimmed mean, std and count of each bar, by (row, i), and the
    sampled part of each, as [row, i, level, corners], its level to be
    filled in
    """
    raw = {}
    cells = []
    for row in (0, 1):
        for i in range(fd.nbars):
            corners, at = cell_corners(fd, row, i, args.margin_x,
                                       args.margin_y)
            raw[(row, i)] = measure_cell(full, luts, at, scale, args.trim)
            cells.append([row, i, 0, corners])
    return raw, cells


def ascending(raw, row, nb):
    """does the row go from black at the left"""
    return raw[(row, 0)][0] < raw[(row, nb - 1)][0]


def normalise(raw, nb):
    """
    Each row normalised by its own ends, darkest as black, by (row, level),
    as the percentage and the raw measurement
    """
    norm = {}
    for row in (0, 1):
        asc = ascending(raw, row, nb)
        ends = (raw[(row, 0)][0], raw[(row, nb - 1)][0])
        black, white = (ends if asc else ends[::-1])
        if white - black < 1.0:
            die("no contrast between the ends of a row")
        for i in range(nb):
            level = i if asc else nb - 1 - i
            norm[(row, level)] = (100.0 * (raw[(row, i)][0] - black) /
                                  (white - black), raw[(row, i)])
    return norm


def results(norm, nb, top_row):
    """a row of results for each level, as printed"""
    rows = []
    prev = None
    for lv in range(nb):
        ideal = 100.0 * lv / (nb - 1)
        top, (ty, tsd, _) = norm[(top_row, lv)]
        bot, (by, bsd, _) = norm[(1 - top_row, lv)]
        mean = 0.5 * (top + bot)
        rows.append((lv, ideal, mean, mean - ideal,
                     None if prev is None else mean - prev,
                     top, bot, top - bot, ty, tsd, by, bsd))
        prev = mean
    return rows


def print_csv(rows):
    print("level,ideal,measured,error,step,top,bottom,top_minus_bottom,"
          "top_luma,top_std,bottom_luma,bottom_std")
    for r in rows:
        print(",".join("" if v is None else
                       ("%d" % v if k == 0 else "%.2f" % v)
                       for k, v in enumerate(r)))


def print_table(photo, space, rows):
    nb = len(rows)
    print("%s: lightness from black, %%, of %s" % (photo, space))
    print("level  ideal  measured  error   step |   top  bottom  top-bot |"
          " top luma (sd)  bottom luma (sd)")
    for r in rows:
        print("%5d %6.1f %9.1f %6.1f %6s | %5.1f %7.1f %8.1f |"
              " %6.1f (%4.1f)  %7.1f (%4.1f)" %
              (r[0], r[1], r[2], r[3], "" if r[4] is None else "%.1f" % r[4],
               r[5], r[6], r[7], r[8], r[9], r[10], r[11]))
    errs = [r[3] for r in rows]
    diffs = [abs(r[7]) for r in rows]
    mono = all(r[4] > 0 for r in rows[1:])
    print("rms error %.1f, worst %.1f at level %d; rows differ by up to %.1f;"
          " %s" % (math.sqrt(sum(e * e for e in errs) / nb),
                   max(errs, key=abs),
                   max(range(nb), key=lambda k: abs(errs[k])),
                   max(diffs),
                   "monotonic" if mono else "NOT monotonic"))


def main():
    args = parse_args()
    # before the work of finding the pattern, not after it
    ofmt = overlay_format(args.overlay) if args.overlay else None

    luts = luma_luts(args.linear)
    det = Image(args.photo, DET_SIZE)
    fd = Finder(det, luts, args.levels, args.verbose)
    try:
        fd.find()
    except NotFound as e:
        fd.log(str(e))
        die("no %d bar grey ramp found; check the photo, or try -v" %
            args.levels)
    full = Image(args.photo)
    scale = full.w / det.w

    nb = args.levels
    raw, cells = measure(fd, full, luts, scale, args)
    norm = normalise(raw, nb)
    for c in cells:
        c[2] = c[1] if ascending(raw, c[0], nb) else nb - 1 - c[1]

    if args.overlay:
        write_overlay(args.overlay, ofmt, args.photo, fd, cells, scale)

    # "top" is the row that's top in the pattern: the one black at the left
    rows = results(norm, nb, 0 if ascending(raw, 0, nb) else 1)

    if args.csv:
        print_csv(rows)
    else:
        print_table(args.photo, "linear light" if args.linear else
                    "sRGB-encoded luma", rows)


if __name__ == "__main__":
    main()
