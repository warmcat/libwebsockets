# lhp on the LilyGo T-Display S3 Long, ESP32-S3

The LilyGo T-Display S3 Long (ESP32-S3R8, 16MB flash, 8MB octal PSRAM) has
a 3.4" 180 x 640 LCD on an AXS15231B controller, spoken to over quad SPI, and
a Hynitron CST3530 touch controller over it on i2c.

## Display

The controller is on SPI2 in quad mode, using `lws-axs15231b-qspi.h` and the
quad support in the ESP32 SPI ops, `lws_bb_spi_t` `.quad`:

GPIO|Signal
---|---
12|nCS
17|SCK
13, 18, 21, 14|D0 - D3
16|nRESET, shared with the touch controller
1|backlight LED driver enable, PWM

The controller can't rotate what it's sent, so the display is used in its
own portrait orientation, 180px wide.  It's only updated whole, since how it
takes a window of rows on their own hasn't been checked on this panel.

## Touch

The CST3530 is on i2c, bitbanged, SDA on GPIO15 and SCL on GPIO10, at 0x58,
with its INT on GPIO11.  It uses `lws-cst3530-i2c.h`.  It has no reset line
of its own: it is reset with the display, so its driver doesn't reset it,
it waits for it to come up after the display reset and retries for it for a
while.  LilyGo's pin list gives GPIO2 as its reset, but on the schematic
GPIO2 is only the battery voltage divider, so it isn't touched.

Pressing a link follows it, and the page shown can be dragged, to see the
rest of one bigger than the display.

When it comes up, the driver logs what the chip says about itself, something
like

```
N: cst3530_describe: ts: chip 0xcaca220e fw 0x... project 0x... at 0x58: 180 x 640, ...
```

and warns if the resolution isn't the `.wh_native` in `main/devices.c`.  If
it says `no CST3530 answering at 0x58`, the board may be a variant with the
touch in the AXS15231B, at 0x3b, which isn't supported yet.

The same i2c bus has the board's SY6970 battery charger, at 0x6a, which
isn't used yet.  With no battery connected, its charge LED blinks.

## Buttons

BOOT, on GPIO0, is the `user` button.  The other button LilyGo's pin list
gives, GPIO21, is the display's D2 line, so it isn't used.

## Build

As for the other lhp examples, see `../README.md`; it uses h3, so it needs
the patched mbedtls component described there.

```
 $ idf.py build flash monitor
```

The console is on the USB Serial / JTAG port, the board's USB-C.
