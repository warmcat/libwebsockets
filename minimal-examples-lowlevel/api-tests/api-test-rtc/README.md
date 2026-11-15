# lws api test rtc

Exercises the rtc class, `lws-rtc.h`, and its PCF8563 driver,
`lws-pcf8563-i2c.h`, against a simulated PCF8563 behind a mock
`lws_i2c_ops_t`, so no hardware is needed.

 - the driver finding the chip, taking it out of test mode and stopping its
   CLKOUT, reading the time, not believing it when the chip says it lost
   power or isn't counting, refusing registers that aren't a time, and
   setting the time with the chip stopped while it's set

 - the class on a context: `lws_rtc_attach()`, the chip being set when the
   time comes from ntp (`lws_system_time_set()` with `LWS_SYSTIME_SRC_NTP`)
   and not from elsewhere, and `lws_rtc_set_from_system()`

The system clock of the machine running the test is already set, so the
chip's time isn't used for it here.

Requires `LWS_WITH_DRIVERS`.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-rtc
[2026/11/15 07:06:49:7641] U: LWS API selftest: rtc
...
[2026/11/15 07:06:49:7908] U: Passed all rtc tests
```
