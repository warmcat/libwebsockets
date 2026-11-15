#!/usr/bin/env python3
#
# Time zone picker assets generator
#
# Written in 2010-2026 by Andy Green <andy@warmcat.com>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# Makes, from public domain sources,
#
#  - tz-map.svg: an equirectangular map of the world's land, from Natural
#    Earth's 1:110m land polygons, with a dot at the principal city of each
#    time zone in tzdata's zone1970.tab
#
#  - tz-zones.h: those zones as a C table, with where their city is and their
#    POSIX TZ string, the last line of each compiled tzdata zone file, for
#    lws_tz_at(), and the map's projection, so a press on the map can be
#    turned into somewhere on earth
#
# It isn't run by the build: run it again and check the results in if tzdata
# changes.  Run it with -I, and pass it the paths: it only reads them.
#
#  $ curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_land.geojson
#  $ python3 -I gen-tz.py ne_110m_land.geojson /usr/share/zoneinfo <outdir>

import json
import math
import os
import sys

# the map: 4 units a degree, from 180W, and from 84N down to 60S, leaving out
# Antarctica, whose zones are research stations

UPD = 4
LAT_TOP = 84
LAT_BOT = -60
W = 360 * UPD
H = (LAT_TOP - LAT_BOT) * UPD

# how far, in map units, simplified coastlines may stray, and the smallest
# island kept, in square map units
TOLERANCE = 1.5
MIN_AREA = 6

# the city dots, in map units: a white square inside a black one
DOT_OUTER = 7
DOT_INNER = 3


def proj(lon, lat):
    lat = max(min(lat, LAT_TOP), LAT_BOT)
    return (round((lon + 180) * UPD), round((LAT_TOP - lat) * UPD))


def dp(pts, tol):
    """Douglas-Peucker, iteratively"""
    keep = [False] * len(pts)
    keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        a, b = stack.pop()
        ax, ay = pts[a]
        bx, by = pts[b]
        dx, dy = bx - ax, by - ay
        ln = math.hypot(dx, dy)
        worst, wi = -1, -1
        for i in range(a + 1, b):
            px, py = pts[i]
            if ln:
                d = abs(dy * (px - ax) - dx * (py - ay)) / ln
            else:
                d = math.hypot(px - ax, py - ay)
            if d > worst:
                worst, wi = d, i
        if worst > tol:
            keep[wi] = True
            stack += [(a, wi), (wi, b)]
    return [p for p, k in zip(pts, keep) if k]


def area(pts):
    return abs(sum(pts[i][0] * pts[i - 1][1] - pts[i - 1][0] * pts[i][1]
                   for i in range(len(pts)))) / 2


def ring_path(ring):
    pts = [proj(lon, lat) for lon, lat in ring]
    if all(lat < LAT_BOT for lon, lat in ring):
        return ''
    # drop repeats, then simplify, keeping the ring closed
    q = [pts[0]]
    for p in pts[1:]:
        if p != q[-1]:
            q.append(p)
    if len(q) < 4:
        return ''
    q = dp(q, TOLERANCE)
    if len(q) < 4 or area(q) < MIN_AREA:
        return ''
    if q[0] == q[-1]:
        q = q[:-1]
    s = 'M%d %d' % q[0]
    for i in range(1, len(q)):
        s += 'l%d %d' % (q[i][0] - q[i - 1][0], q[i][1] - q[i - 1][1])
    return s + 'z'


def coord(s):
    """ISO 6709 +-DDMM[SS] or +-DDDMM[SS] as degrees"""
    sign = -1 if s[0] == '-' else 1
    s = s[1:]
    dl = 2 if len(s) in (4, 6) else 3
    d = int(s[:dl])
    m = int(s[dl:dl + 2])
    sec = int(s[dl + 2:dl + 4]) if len(s) > dl + 2 else 0
    return sign * (d + m / 60 + sec / 3600)


def main():
    land, zi, out = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(land, encoding='utf-8') as f:
        gj = json.load(f)

    d = ''
    for feat in gj['features']:
        g = feat['geometry']
        polys = g['coordinates'] if g['type'] == 'MultiPolygon' else \
            [g['coordinates']]
        for poly in polys:
            for ring in poly:
                d += ring_path(ring)

    zones = []
    with open(os.path.join(zi, 'zone1970.tab'), encoding='utf-8') as f:
        for line in f:
            if line.startswith('#'):
                continue
            cols = line.rstrip('\n').split('\t')
            name, c = cols[2], cols[1]
            i = 1
            while c[i] not in '+-':
                i += 1
            lat, lon = coord(c[:i]), coord(c[i:])
            with open(os.path.join(zi, name), 'rb') as z:
                tz = z.read().rstrip(b'\n').split(b'\n')[-1].decode('ascii')
            if not tz or lat < LAT_BOT:
                continue
            zones.append((name, lat, lon, tz))

    zones.sort()

    # each city is a white square in a black one, so it's seen on land and
    # sea alike: as two filled paths, not circles, which a renderer turns
    # into far more points, and strokes, which it turns into more shapes
    outer = ''
    inner = ''
    for name, lat, lon, tz in zones:
        x, y = proj(lon, lat)
        outer += 'M%d %dh%dv%dh-%dz' % (x - DOT_OUTER // 2, y - DOT_OUTER // 2,
                                       DOT_OUTER, DOT_OUTER, DOT_OUTER)
        inner += 'M%d %dh%dv%dh-%dz' % (x - DOT_INNER // 2, y - DOT_INNER // 2,
                                       DOT_INNER, DOT_INNER, DOT_INNER)

    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
           'width="%d" height="%d">'
           '<rect width="%d" height="%d" fill="#fff"/>'
           '<path fill="#000" fill-rule="evenodd" d="%s"/>'
           '<path fill="#000" d="%s"/><path fill="#fff" d="%s"/>'
           '</svg>\n' % (W, H, W, H, W, H, d, outer, inner))

    with open(os.path.join(out, 'tz-map.svg'), 'w', encoding='ascii') as f:
        f.write(svg)

    with open(os.path.join(out, 'tz-zones.h'), 'w', encoding='ascii') as f:
        f.write('/*\n * Made by contrib/assets/tz/gen-tz.py from tzdata '
                'zone1970.tab, which is\n * public domain.\n'
                ' * The map, tz-map.svg, is %d x %d units, %d a degree, '
                'from 180W\n * and from %dN down to %dS.\n */\n\n' %
                (W, H, UPD, LAT_TOP, -LAT_BOT))
        f.write('#define TZ_MAP_W\t\t%d\n#define TZ_MAP_H\t\t%d\n'
                '#define TZ_MAP_LAT_TOP\t\t%d\n#define TZ_MAP_LAT_BOT\t\t%d\n'
                '\n' % (W, H, LAT_TOP, LAT_BOT))
        f.write('/* name, latitude and longitude in hundredths of a degree, '
                'TZ string */\n\n')
        for name, lat, lon, tz in zones:
            f.write('\t{ "%s", %d, %d, "%s" },\n' %
                    (name, round(lat * 100), round(lon * 100), tz))


main()
