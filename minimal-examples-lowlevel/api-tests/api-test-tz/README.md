# lws api test tz

Exercises the civil time conversions, `lws_civil_to_unix()` and
`lws_unix_to_civil()`, and the POSIX TZ string support, `lws_tz_at()` and
`lws_tz_local()`, from `lws-tz.h`.

 - the civil time conversions against known times, every day from 1970 to
   2200 there and back, and refusing times that don't exist

 - every distinct TZ string of the zones in tzdata's `zone1970.tab`, and some
   made up for the rule forms tzdata doesn't use at the moment, against what
   glibc says about them, in mid-month moments of 2026 and 2027 and either
   side of each 2026 transition: the offset from UTC, the zone's name then,
   and whether it's daylight saving time

 - refusing TZ strings that are malformed or out of range

The expected results are in `tz-vectors.h`, made by `gen-vectors.py` on a
Linux box with tzdata, so the test itself needs neither.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-tz
[2026/11/15 07:13:41:8638] U: LWS API selftest: tz
[2026/11/15 07:13:41:8854] U: Passed all 1280 tz tests
```
