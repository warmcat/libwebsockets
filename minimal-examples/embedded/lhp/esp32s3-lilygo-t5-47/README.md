# lhp on the LilyGo T5 4.7" e-paper, ESP32-S3

The LilyGo T5 4.7" (V2.3 / V2.4, ESP32-S3 N16R8) has a 960 x 540 E Ink
ED047TC1 panel with no controller of its own.  This example drives it with
the generic directly-driven EPD support, `lws-epd-direct.h`, and its ESP32
transport, `lws-esp32-epd-direct.h`: the panel's source driver data bus is
the S3's i80 LCD bus, the gate clock comes from an RMT channel, and the other
control lines and the panel supplies are on a 74HCT4094 shift register.

It's black and white only for now, and the touch panel isn't supported yet.

## Choosing the IO routing

`main/devices.c` describes three ways the panel signals can be routed,
selected by `T547_ROUTING` near the top of the file:

Routing|What it is
---|---
`T547_ROUTING_WATCH` (default)|No panel: a Waveshare ESP32-S3-Touch-LCD-1.28, with the signals put on gpios it doesn't use, to check the driver and its timing on a scope
`T547_ROUTING_V23`|The LilyGo V2.3 board.  XLE, SPV, XOE, MODE1, the supply enables and the board power hold are on the 4094
`T547_ROUTING_V24`|The LilyGo V2.4 board.  As V2.3, but XLE is on GPIO48 and SPV on GPIO45

The watch routing is the default until the LilyGo boards are to hand.

### Watch routing signals

These are on the watch's 12-pin GPIO_OUT header:

GPIO|Signal|Suggested scope channel
---|---|---
15|XCL / CKH, source data clock|1
16|XSTL / STH, source start pulse|2
17|CKV, gate clock|3
18|XLE, source latch|4
21|D0|
33|4094 STR, shows when the shift register is written|

D1 - D7 are on 36 - 42, the 4094 data and clock on 34 and 35, and SPV on 47.
The watch has no 4094, so what would be on its outputs (XOE, MODE1, the
supply enables) isn't seen.  Its button is BOOT, on GPIO0.

## sdkconfig for the LilyGo boards

`sdkconfig` is set up for the watch's 2MB quad PSRAM.  The LilyGo boards
have 8MB octal PSRAM, so before building for V2.3 or V2.4, set
`CONFIG_SPIRAM_MODE_OCT=y` (and unset `CONFIG_SPIRAM_MODE_QUAD`), eg, with
`idf.py menuconfig`, Component config -> ESP PSRAM.  Their user button is
GPIO21; GPIO0 is the 4094 strobe once we're running.

## Building

This builds http/3, so it needs IDF given an mbedtls component with the lws
QUIC patches, see "http/3 needs mbedtls with the lws QUIC patches" in
`../README.md`, eg

```
 $ idf.py -D EXTRA_COMPONENT_DIRS=$HOME/idf-comp/mbedtls build
```

## Not yet confirmed on the panel

These come from the panel datasheet, LilyGo's schematic and their vendor
code, and need checking on a real board:

 - the 2-bit drive codes for black, white and no drive (1, 2 and 0 in
   `lws_epd_direct_panel_ed047tc1`), and which pixel of a bus byte is first

 - the gate start sequence: SPV, then one CKV clock, then
   `.frame_lead_ckv` more before the first row, which is 0 here

 - which 4094 output is which, see the table in `main/devices.c`, and the
   V2.4 gpios for XLE and SPV

 - the power sequencing delays

 - the waveforms in `main/devices.c`, 20 passes for each transition and
   a black / white / black / white clear, which are only a starting point
