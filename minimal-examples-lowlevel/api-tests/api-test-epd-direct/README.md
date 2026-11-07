# lws api test epd direct

Tests the driver for EPD panels with no controller of their own
(`lws-epd-direct.h`) against a simulated panel, without hardware.

The simulated transport keeps where each pixel's ink is between black and
white, and moves it a step for each pass it's driven in, by the 2-bit codes
latched in its simulated source driver.  So what it ends up showing is what a
real panel would, if the waveforms suited it.  It checks

 - the clear after init leaves the panel white, whatever it showed before

 - an update leaves the panel showing what was blitted, and rows with
   nothing changing on them aren't driven

 - transitions of different lengths in one update end on the same pass

 - a row is only ever stepped over with "no drive" latched in the source
   driver, since stepping over drives what's latched onto the row

 - two updates started passes apart are in flight at once

 - a pixel wanted back while it's still moving finishes moving, then moves
   back

 - a line blitted without pixels is white

 - with `full_refresh_every`, the panel is cleared before every so many
   updates

 - the panel supplies are turned off once the passes are done

Requires `LWS_WITH_DRIVERS` and `LWS_WITH_SYS_SMD`.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-epd-direct
```
