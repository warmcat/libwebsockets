#!/usr/bin/env python3
#
# lws-api-test-tz test vector generator
#
# Written in 2010-2026 by Andy Green <andy@warmcat.com>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# Makes tz-vectors.h from what the C library of the machine it runs on, eg,
# glibc, says about each distinct POSIX TZ string of the zones in tzdata's
# zone1970.tab, and some made up to cover rule forms tzdata doesn't use now:
# what applies in mid-month moments of 2026 and 2027, and either side of each
# 2026 transition.  It needs a Linux box with tzdata, and isn't run by the
# test: run it again and check the result in if tzdata changes.
#
#  $ python3 -I gen-vectors.py /usr/share/zoneinfo > tz-vectors.h

import calendar
import os
import re
import sys
import time

zi = sys.argv[1] if len(sys.argv) > 1 else '/usr/share/zoneinfo'

# a zone's name is a path under zi: nothing in it may lead outside
ZONE_NAME = re.compile(r'[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*')

footers = set()
with open(os.path.join(zi, 'zone1970.tab'), encoding='utf-8') as f:
    for line in f:
        if line.startswith('#'):
            continue
        name = line.split('\t')[2].strip()
        if not ZONE_NAME.fullmatch(name):
            sys.exit('gen-vectors: unexpected zone name %r' % name)
        with open(os.path.join(zi, name), 'rb') as z:
            last = z.read().rstrip(b'\n').split(b'\n')[-1].decode('ascii')
        if last:
            footers.add(last)

# rule forms tzdata doesn't use at the moment

footers |= {
    'EST5EDT',				# dst without rules: US rules
    'AAA3BBB,J60/2,J300/2',		# Jn, Mar 1 in leap and other years
    'AAA3BBB,59/2,299/2',		# n, counting Feb 29
    'AAA-10BBB-11:30,M10.1.0,M4.1.0/3',	# southern, half hour dst
    'EST5EDT,0/0,J365/25',		# dst all year
    'AAA-5:45',				# minutes
    'AAA4BBB,M1.5.6/-1,M12.5.6/26',	# week 5, negative and >24h times
}


# glibc gives an hour of standard time at each new year for this, where
# tzfile(5) says it is daylight saving time all year: take only mid-month
# moments for it
NO_EDGES = {'EST5EDT,0/0,J365/25'}


def info(tz, t):
    os.environ['TZ'] = tz
    time.tzset()
    lt = time.localtime(t)
    return lt.tm_gmtoff, lt.tm_zone, lt.tm_isdst


rows = []
for tz in sorted(footers):
    ts = []
    for y in (2026, 2027):
        for m in range(1, 13, 2):
            ts.append(calendar.timegm((y, m, 15, 12, 0, 0)))

    # either side of each 2026 transition, found hourly then by bisection
    t0 = calendar.timegm((2026, 1, 1, 0, 0, 0))
    t1 = calendar.timegm((2027, 1, 1, 0, 0, 0))
    prev = info(tz, t0)
    t = t0
    while t < t1 and tz not in NO_EDGES:
        n = info(tz, t + 3600)
        if n != prev:
            lo, hi = t, t + 3600
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if info(tz, mid) == prev:
                    lo = mid
                else:
                    hi = mid
            ts += [lo, hi]
            prev = n
        t += 3600

    for t in ts:
        off, abbr, dst = info(tz, t)
        rows.append('\t{ "%s", %d, %d, "%s", %d },' % (tz, t, off, abbr, dst))

print('/* made by gen-vectors.py, from %s */\n' % zi)
print('\n'.join(rows))
