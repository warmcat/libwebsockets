# lhp on the LilyGo T5 4.7" e-paper, ESP32-S3

The LilyGo T5 4.7" (V2.3 / V2.4, ESP32-S3 N16R8) has a 960 x 540 E Ink
ED047TC1 panel with no controller of its own.  This example drives it with
the generic directly-driven EPD support, `lws-epd-direct.h`, and its ESP32
transport, `lws-esp32-epd-direct.h`: the panel's source driver data bus is
the S3's i80 LCD bus, the gate clock comes from an RMT channel, and the other
control lines and the panel supplies are on a 74HCT4094 shift register.

It's black and white only for now.

## Choosing the IO routing

`main/devices.c` describes three ways the panel signals can be routed,
selected by `T547_ROUTING` near the top of the file:

Routing|What it is
---|---
`T547_ROUTING_WATCH`|No panel: a Waveshare ESP32-S3-Touch-LCD-1.28, with the signals put on gpios it doesn't use, to check the driver and its timing on a scope
`T547_ROUTING_V23`|The LilyGo V2.3 board.  XLE, SPV, XOE, MODE1, the supply enables and the board power hold are on the 4094
`T547_ROUTING_V24` (default)|The LilyGo V2.4 board.  As V2.3, but XLE is on GPIO48 and SPV on GPIO45

V2.4 is the default.  If your board is V2.3, as printed on its silkscreen,
set `T547_ROUTING` to `T547_ROUTING_V23` in `main/devices.c`.

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

## Touch

The LilyGo boards' touch panel is a Goodix GT911, on its own i2c bus, SDA on
GPIO18 and SCL on GPIO17, with its INT on GPIO47 and its reset not
connected.  It uses `lws-gt911-i2c.h`.  The watch routing has no touch,
since it uses those gpios for the panel signals.

Pressing a link follows it, and the page shown can be dragged, to see the
rest of one bigger than the display.  Each drag redraws the panel, as an
update of only the pixels that change.

When it comes up, the driver logs what the chip says about itself, its
address, the resolution and orientation it reports in, and how its INT is
configured, something like

```
N: gt911_describe: ts: GT911 fw 0x1060 at 0x5d: config v65, 540 x 960, 5 contacts, INT falling
```

and warns if the resolution isn't the `.wh_native` in `main/devices.c`.

## How the passes are run

Panel passes run on a FreeRTOS task of their own pinned to core 1, using the
ESP32 runner in `lws-esp32-epd-direct.h`, so rendering and networking on the
lws event loop don't stall them.  That's why `sdkconfig` is dual-core.
Every 100ms of continuous passes, the runner sleeps for one FreeRTOS tick
so core 1's idle task can run for the task watchdog; `sdkconfig` sets a
1kHz tick so that gap is only 1ms.

The transport drives the LCD_CAM i80 bus, its GDMA channel, the RMT channel
for CKV and the control gpios at register level, with no IDF driver calls
per row and no interrupts.  It uses IDF hal and private headers to do that,
so it is written against esp-idf v6.1 and may need adapting for other IDF
versions.

XCL runs at 20MHz, the panel's typical rate.  A row then takes about 12us to
send, but the next row can't be latched until the previous row's 20us CKV
drive has ended, so rows come every 21.5 - 22us, about 12ms per pass.  On
V2.3, XLE is on the 4094, so each row also costs two shift register writes.

The panel allows at most 85 passes a second, so a pass takes at least 11.8ms
however few rows change.  The waveforms in `main/devices.c` give pixels
about the drive LilyGo's own code does: an update is 5 passes of 20us drive,
about 60ms, and the clear is 32 passes of 50us drive, about 0.9s.

Since an update only drives the pixels that change, and is that quick, the
display says it can show animation, `.anim_hz`, so the update page shows its
spinner, moved on twice a second.  The panel can't be sent a band of its
lines, so each time, the page is drawn whole again as it was laid out, and
the update drives only the pixels of the spinner and the progress bar that
changed.

On the watch routing, what to look at on the scope is:

 - the row period (rising XSTL to rising XSTL) should be about 22us, with
   XLE straight after the data and CKV rising as XLE falls

 - during an update, passes should follow each other without gaps, apart
   from the 1ms one every 100ms

 - at the start of each pass, SPV should fall while the first CKV pulse is
   still high

## Scope test pattern

Setting `T547_SCOPE_PATTERN` to 1 near the top of `main/devices.c` replaces
whatever lhp draws with a fixed pattern of black marks on white, so you know
exactly what bytes should go out on the bus.  A mark is four pixels, one bus
byte of black drive codes, 0x55, so D0 is high and D1 low for that byte, and
the other bytes are 0x00.

Row|Marks at bus bytes (of 0 - 239)
---|---
100 - 107|0, 16 x (row - 99), ie, 16, 32 ... 128, and 239
108 - 111|0, 200 and 239, all four rows the same

After the boot clear, the first update draws it in 5 passes.  Each pass has
row 100 - 111 data bursts, one all-zero burst on row 112 to stop driving,
and gate steps with no data for the other rows.  The first pass also has an
all-zero burst on row 0.

The clear's bursts are all 0x55 or 0xAA, so D0 doesn't change during them.
Triggering on a positive D0 pulse shorter than 100ns catches the pattern's
first row instead.

## sdkconfig for the watch routing

`sdkconfig` is set up for the LilyGo boards' 8MB octal PSRAM.  The watch has
2MB quad PSRAM, so before building for the watch routing, set
`CONFIG_SPIRAM_MODE_QUAD=y` (and unset `CONFIG_SPIRAM_MODE_OCT`), with
`CONFIG_SPIRAM_SPEED_40M`, eg, with `idf.py menuconfig`, Component config ->
ESP PSRAM.

The LilyGo boards' user button is GPIO21; GPIO0 is the 4094 strobe once
we're running.

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

 - the waveforms in `main/devices.c`, which give pixels about the drive
   LilyGo's own code does, but in fewer, longer passes

 - the touch panel's resolution and orientation, `.wh_native` and `.flags`
   in `main/devices.c`, and that its INT, configured in the chip, works
   with a falling edge.  These follow LilyGo's example code, which is for
   the S3 boards generally; it's not checked yet against the V2.3 or V2.4
   schematic
