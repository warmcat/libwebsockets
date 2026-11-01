# lws api test touch

Tests the touch controller class without hardware.

 - The classifier is fed sample sequences at chosen times, checking taps,
   long presses seen from a timeout, from held samples, or only when the
   finger lifts, scrolls streamed or only seen where the finger lifted, and
   a custom regime.

 - Two CST816S controllers, behind a simulated i2c bus and gpio, are taken
   from reset through to the lws_smd events they issue.  One maps its
   coordinates one to one, the other is turned on its side over a display
   of half the resolution.  The simulated chip goes to sleep and NAKs its
   address, which must be understood as the finger lifting, and reports
   coordinates off the panel, which must be clamped.

Requires `LWS_WITH_DRIVERS` and `LWS_WITH_SYS_SMD`.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-touch
[2026/11/01 12:00:00:0000] U: LWS API selftest: touch
[2026/11/01 12:00:00:8500] U: Passed all touch tests
```
