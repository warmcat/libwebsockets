# lhp (HTML renderer) embedded demos

These are demos for various ESP32 + display combinations.  A lot of
the code is common between the demos and is in the toplevel dir
(where this README lives).

Notice that although the demos are for ESP32 currently, there is no
ESP32-specific code in the common part.  Only `main/devices.c` in the
combination-specific directories has the platform-specific init.

Everything on the display is html, laid out and rendered by lhp.

## Boot overlay

From boot, a strip ui (`lws-dlo-ui.h`, see READMEs/README.display-list.md)
titled "Boot" shows how far booting has got, as a list of icons for the
stages

|Stage|Reached when|
|---|---|
|setup|wifi credentials are stored|
|wlan|associated to the AP|
|ipv4|an IPv4 address was acquired|
|ipv6|an IPv6 address was acquired (optional, never waited for)|
|internet|captive portal detection says we have internet|
|date|the time is known, from an rtc chip or ntp|
|ota|the first update check says we are on the latest firmware|
|auth|the system passed its AUTH states|

Each stage is a row of the list, its icon and next to it what is known
about it: the AP stored in the settings, or "Not configured" if there is
none, the AP being looked for, or joined, the IPv4 and IPv6 addresses,
whether there is internet, the time, the OTA variant and what the update
check said.  Stages reached are shown as they are, the others dimmed.  The
row of the stage being worked on, the first not reached, is highlighted, and
kept in the middle of the list: when the display is too short for the whole
list, eg, the 64px high heltec OLED, it scrolls as the boot moves on.

If no wifi credentials are stored, once a scan has found some APs, the
settings are shown instead, once, to set the passphrase of one, see
"Settings" below.  If there are none we can use, the device is also an AP to be set
up from a browser meanwhile, see "Setting up wifi" below, and the setup row
says which AP to join and what to browse.  When its credentials are stored, the wifi netdev, which
keeps scanning while it isn't joined, joins the AP when it next sees it, and
the boot list is shown again; pressing the "Settings" title goes back too.  While the boot list is up, pressing its "Boot" title shows the
settings.

The ui's title strip is given the example's own colours, by the css it
passes the ui (`lws_dlo_ui_info_t .css`) to follow its default theme.

On the round LCD of `esp32s3-waveshare-240-240-touch`, whose display says
it's `.round`, everything is kept inside the circle that can be seen; it
also says it's `.band`, so only the strips that changed are sent to it.

On a landscape display with room for it, eg, the T5's 960 x 540 EPD, the
boot list doesn't need all of the display: its title and list strips are a
column at the left, about 200px wide there, and the product's own html is
shown right of it, as the strip ui's aside (`lws_dlo_ui_set_aside()`).  It's
made from `boot.html`, `boot.css` and any `boot-*` files it shows, eg,
`boot-picture.jpg`, in `product/`, see "Product header" below.  The common
one shows the maker's logo and name and the model's name; the T5 has its own,
a JPEG picture.  It goes with the boot list when booting is over: on an EPD,
the white page that cleans the boot list off is all of the display, the
aside's part too.  Here, the 400 x 300 and 600 x 448 EPDs have it too.
Displays that aren't landscape, eg, the 122 x 250 EPD, or are round, or are
too small for both, eg, the 320 x 240 LCDs and the 128 x 64 OLED, show only
the boot list as before.

Until the network is up, the overlay only uses what is built in: a font,
and the stage icons, which `boot-icons.cmake` makes into C arrays at build
time from the svg in `contrib/assets/boot-status`, served from the dlo
filesystem.  What the rows say is worked out by `boot-ui.c`, which has
nothing platform-specific in it.

On a slow display, eg, an EPD taking 20s to update, the overlay is only
redrawn once the previous update has finished, showing the state as it is
then.

Once the system is OPERATIONAL and the first update check ended, saying
we're up to date, or failing, the boot list is replaced by the frame, and the
application html is shown in it, see "Frame and status" below.  If the update
check doesn't end in 90s, we carry on anyway.  If an update is found, a modal update display with its progress
takes over the display instead, whatever is on it.

The update display, made by `update-ui.c`, which also has nothing
platform-specific in it, follows the overlay's look: the same title strip
saying "Updating", in the same colours, then what is being updated and a
bar filling up as it arrives, with the percentage in the middle of it.  The
bar is a capsule with `overflow: hidden`, which clips what is in it to its
rounded ends, so the start of the fill is the capsule's own rounded end,
filled in.  The percentage is in it twice, dark on the bar and light inside
the fill, so where the fill ends inside the text, its colour changes there.
On a display too small for the text to fit in the bar, it goes below it.

Everything on it is placed for the display: on a round one, the bar is
across the middle where the circle is widest and all of it is inside the
circle; on a rectangular one, it goes in the middle of the space below the
strip, with the update spinner as big as there is room for.  Drawing it
takes time from fetching and flashing the update, so after the first, it is
redrawn every 0.5s, moving the spinner on and showing the progress by then.
A display that can't show animation (`lws_display_anim_interval()` is 0),
eg, an EPD taking seconds for each update, has no spinner, and is only
redrawn every 3s, and only if the progress changed.

The spinner is an svg animated with SMIL,
`contrib/assets/update/update-1-spinner.svg`, built in by `boot-icons.cmake`
like the stage icons.  `lhp-ss.c` sets the render state's `.anim_t` to the
time each page is drawn, so each time the update display is redrawn, the
spinner has moved on.

The page is only laid out once.  Its display list is kept, and after that
the progress is changed in place, by `lhp_update_progress()`: the fill's
width with `lws_display_render_set_width()` and the percentage with
`lws_display_render_set_text()`, found by their ids.  Then
`lws_display_render_damage()` says what of the display changed, the lines of
the bar and of the spinner, which is animated, and `redraw_damage()` in
`lhp-ss.c` draws only those again, if the display can be sent a band of its
lines (`.band`, eg, the round LCD).  They're all drawn first, then sent to the
display together, so they appear at once.  A display that can only be
updated whole has all of the page drawn again, as it was laid out.

### The time

The date row shows the time in the home time zone, and in the away one if
there is one, see "Time zones" below, eg, "Sun 15 Nov 15:56 JST, away 06:56
GMT", followed by where the time came from, "rtc" or "ntp".

A board with a battery-backed rtc chip attaches it with `lws_rtc_attach()`
(see `lib/drivers/rtc/README.md`), eg, `esp32s3-lilygo-t5-47`'s PCF8563.  If
the chip has a time it believes, the system clock is set from it at once, so
the date stage is reached at boot, without waiting for the network, and ntp
is asked in the background.  When ntp answers, the system clock and the
chip are set from it, and the row says "ntp".  Without an rtc, or one whose
time can't be believed, eg, its battery ran out, the date stage waits for
ntp, as before.  The example's `lws_system_ops_t .set_clock()` redraws the
boot list each time the time is set.

## Frame and status

After boot, the same title strip stays at the top of the display, saying
which page of the carousel is shown, eg, "Page 1", over the application's
page: the strip ui's frame page (`lws_dlo_ui_frame()`).  The page is laid out
on the body below the strip (`lws_dlo_ui_frame_body()`), and `render()` in
`lhp-ss.c` takes the strip's lines from the ui
(`lws_dlo_ui_frame_line()`) before the page's, so the whole display is drawn
in one update.

On displays that aren't bistable, the frame is drawn by itself as the boot
list goes, with a white body, and the first page is browsed once it's on the
display, so it's clear booting is over.  An EPD, eg, the 7-colour one taking
20s for an update, only shows the frame with the first page.  One with a
`.clear` op, eg, the directly-driven T5's, is quick enough that the boot list
is cleaned off it first, leaving it white while the first page is fetched and
laid out.

At the right of the title strip, inside the circle on a round display, a
status capsule shows the wlan's signal as up to four bars, and on boards
with a battery, how charged it is.  It's brought up to date every 5s, and as
the link goes up or down: the ui only draws it again when what it shows
changed.  On a `.band` display, only the title strip is sent again.  On a
display that isn't, but isn't bistable either, eg, the wrover-kit LCD, the
page is drawn again under it if it was kept (`rs.retained`, on touch boards),
otherwise the change is shown with the next page.  On an EPD it's shown with
the next page.

No board here has a battery wired up yet.  A board with one sets
`plat_battery` (see `main.h`) in its `init_plat_devices()`, to a function
saying how charged it is and whether it's charging.

## Settings

Pressing the status capsule on a touch display, or clicking a button named
`settings`, shows the settings, made by `settings-ui.c`, which has nothing
platform-specific in it.  It's a dialog of the strip ui
(`lws_dlo_ui_dialog()`), titled "Settings": html it writes, and what to do
when a link in it is pressed, so it's also an example of how an application
can make a dialog of its own settings.  It has

 - the product's own header: the maker's logo and name, the model's name
   and a picture of it, see "Product header" below

 - "WLAN": a table of the APs, with a line around and between its rows, kept
   up to date while it's shown: those scanned, strongest first, one row per
   network, then those we have credentials for that aren't in range, dimmed.
   Each row starts with the AP's signal, as the same four bars the status
   capsule shows for the AP we are on (`lhp_rssi_bars()`), none lit if it
   isn't in range.  Then the SSID, over a smaller line of what we know about
   it, then the icons to press:
    - a key, if we have its passphrase
    - how it authenticates, eg, "WPA2", if it's in range
    - how the last try to join it went: a check if it was joined, a cross if
      its passphrase was refused, or a warning sign if it failed some other
      way, eg, it didn't answer
    - a globe, if the internet was ever reached through it
    - a cog, to set its passphrase, or for an open AP, to add it
    - a bin, to forget it with `lws_netdev_credentials_remove()`, if we have
      credentials for it

   For an AP we have no credentials for, there's nothing to lose by
   pressing its SSID: all of that cell does what its cog does.

 - "Hostname": the hostname, shaded like an editbox, which pressing edits

 - "Display": on a touch display, "Edges and touch", which shows the edges
   and touch page, and on a display that can show greys, "Grey levels", which
   shows the grey levels page, see below

 - "Time", on a touch display: the time zones, which shows the time zone
   page, see below

How joining went, and the internet being reached, are noted by the netdev in
the stored credentials, so they're known after a reboot.  Changing the
passphrase forgets how joining went, but not that the internet was reached.
The icons are from `contrib/assets/settings`, and the key and globe from
`contrib/assets/boot-status`.

Pressing the cog shows the edit page, titled "Passphrase", with its
keyboard, to type it in.  It's shown as it is typed, so typos can be seen;
dragging the keyboard moves it around to reach the keys.  It starts empty,
even if a passphrase is stored for the AP: what is stored is never shown,
not even its length.  Only when Done is pressed with at least the 8
characters WPA needs, the credentials are stored with
`lws_netdev_credentials_add()`; pressing the title abandons it.  Credentials
can be stored for any number of APs: the wifi netdev joins the strongest one
it sees that it has credentials for.

Pressing the hostname shows it on the edit page, to change it.  However the
edit is left, by Done, the title, or the settings being closed, it's stored
with `lws_netdev_hostname_set()` if it's valid, and given in DHCP from the
next time an address is acquired: a single DNS label of up to 32 of a-z, 0-9
and '-', not starting or ending with '-'.  Done with something invalid
keeps it being edited; nothing typed goes back to the default, `lws-` and
the last three bytes of the MAC in hex.

Pressing the title, or the status capsule again, closes the settings, back
to what was shown before.  While the settings are shown, the carousel waits;
after them, the page that was shown is drawn again, and it goes on.

The settings need a way to move around them and the keyboard: a touch
display, or buttons named `up`, `down`, `left`, `right` and `enter`, and
optionally `esc` to go back.  Their clicks go to `lws_dlo_ui_interaction()`,
which moves a cursor over the dialog's links and the keyboard.  The boards here only
have a single `user` button, so for now only the ones with a touch panel can
show the settings; a board given those
buttons, and a `settings` one, in its `lws_button_map_t` needs no other
changes.

### Edges and touch

The edges of a display may not all be seen, eg, under a bezel or the mask of
a touch panel over it.  The display's inset (`lws_display_t .inset`, see
`lib/drivers/display/README.md`) says how many px are hidden at each edge, and
pages are laid out on what's inside it.  "Edges and touch" in the settings
shows a page, made by `edges-ui.c`, for finding out what the inset should be
on the device in hand, and for seeing if touches land where they are on the
display.

It's a 1px black line around the edges of what can be seen with the inset in
use, and a row of controls for each edge: `-` and `+` make the inset there a
px smaller or bigger, moving the line out or in, with how many px it is
between them.  The inset is right when the line is just seen all the way
round.  The page is laid out again with each change, on what can be seen then,
and rows that went into the inset are made white.  Below the controls is the
size of what can be seen.  Reset goes back to the board's inset.

For the touch panel, there's a target to touch, a cross in a square.  A touch
that isn't on a control is marked with a dot where the panel says it landed,
it's shown where that is on what can be seen and on the display's surface,
and how far it was from the middle of the target, then the next target is
shown.  There are six, near the corners and halfway down the sides, or on the
diagonals of a round display.  Once all six are touched, the mean of how far
off they were, in x and y, and the worst, are shown, and the next touch starts
another round.  Touches all off in the same direction mean the touch panel
isn't where the display is; each is also logged.  Changing the inset starts
the targets again, since they move with it.

Done stores the inset in the settings, as `lhp.inset`, and it's used instead
of the board's from then on, including after a reboot.  Then what was shown
before, the boot list or the page, is laid out again on what can be seen now,
and the carousel goes on.

It's only offered on a touch display, since it's used by pressing on it.

### Grey levels

"Grey levels" in the settings shows a page, made by `greys-ui.c`, with every
grey level the display can show, for seeing how evenly spaced they really
are, eg, while tuning an EPD's waveform.  It's two rows of equal-width bars,
one bar per level, filling what can be seen: the top row goes from black to
white, left to right, and the bottom row from white to black.

On a greyscale display with a palette, eg, an EPD, there's a bar for each of
its palette's levels.  The grey written in the page's css for each is the one
`lws_display_palettize_grey()` turns into exactly that level after its gamma
correction, so each bar is all one level, not dithered from its neighbours;
a palette level no grey gives exactly is warned about in the log.  On other
displays it's 16 evenly spaced greys.  It's not offered on a display with a
palette of colours.

There's nothing else on the page, so it can be photographed and measured with
`scripts/epd-grey-levels.py`, from any angle, eg:

```
$ scripts/epd-grey-levels.py --levels 16 --overlay check.jpg photo.jpg
```

Pressing anywhere on it, or the `settings` button, goes back to what was shown
before.

### Time zones

The device knows two time zones: "home", where it usually is, and
optionally "away", where it is now, eg, while travelling.  Until home is
picked, it's UTC.  Pressing the time zones in the settings shows a page, made
by `tz-ui.c`, for picking them.

It's a map of the world, with a dot at the principal city of each tzdata
zone.  Pressing on the map picks the zone whose city is nearest where it was
pressed.  Below the map are a row for home and one for away, each with the
zone picked and the time there.  Pressing "Home" or "Away" says which one the
map picks, shown black; "Off" turns away off, and "On" turns it back on, the
next press on the map picking it.  The zones picked are marked on the map,
"H" and "A".  Done stores them in the settings, as `lhp.tz.home` and
`lhp.tz.away`, by their tzdata names, and goes back to what was shown before.

The zones are compiled in: `contrib/assets/tz/gen-tz.py` makes the map,
`tz-map.svg`, from Natural Earth's land polygons, and the table of zones,
`tz-zones.h`, from tzdata, with where each zone's city is and its POSIX TZ
string; `boot-icons.cmake` makes the map a C array and copies the table
beside it.  The local time is found with `lws_tz_local()` (`lws-tz.h`), not
the platform's own time zone support, so it's the same everywhere, and home
and away can be used at once, where TZ is one zone for the whole process.

Like the edges page, it's only offered on a touch display.

## Product header

The settings, on the display and served to a browser, start with the
product's own header: the maker's logo and name, then the model's name, and
a picture of the device.  It's made of files in `product/`, embedded in the
firmware by `product.cmake`, so a product only has to change those:

|File|What it is|
|---|---|
|`header.html`|the header's html: `@LHP_MODEL@` in it is the board's model name|
|`header.css`|its css, after the settings' own (it can't contain `<`)|
|`logo.svg`|the maker's logo, served as `product-logo.svg`|
|`device.svg`|a picture of the device, served as `product-device.svg`|
|`boot.html`|the html beside the boot list on a landscape display, `@LHP_MODEL@` as for the header|
|`boot.css`|its css (it can't contain `<`)|
|`boot-*`|anything `boot.html` shows, eg, `boot-picture.jpg`, in the dlo filesystem by its own name|

The ones here are placeholders.  A board can have its own of any of them in
`product/` in its own dir, eg, a picture of that board, which is used
instead of the common one; a board's `boot-*` files are as well as the
common ones, or instead of one with the same name.  Adding or removing a
`boot-*` file is noticed the next time the build runs, without reconfiguring
by hand.  The model name is given by the board's `main/CMakeLists.txt`, to
`lhp_product()`; it's used as html.  `product.cmake` makes the boot ones into
`product-boot.h`, beside `product.h`, for `boot-ui.c`.

The images are registered in the dlo filesystem for the display, and given
to `lws_wifi_provision_create()` in `.files` to be served beside the settings,
with the html and css as its `.header_html` and `.css`.  Everything is
the firmware's own, so it can be trusted as markup; the settings' html,
which has the SSIDs anyone nearby can choose in it, is escaped.

## Application

The application is a placeholder for now: it visits each of a short list
of pages using h2 and renders them on the device + display combination,
showing each for 10s once it is on the display, the last one too, then it
ends.

The page's images are given back once the render has drawn past them, and
on a touch display, each pan draws the page again.  So they would be fetched
again for every pan: instead, a 128KB in-memory asset cache keeps the ones
that are small enough, so a pan redraws them from there.  It's kept small to
leave the heap for whatever else the device is for.

An EPD keeps showing its image with no power, so whatever is left on it is
what it shows in storage: it should be left white.  On boards whose display
says it's `bistable` in its `lws_display_t`, as the EPD drivers do, a white
page is shown after the last page, and it ends once that is on the display.
On other displays, the display is turned off as it ends.

A display that only changes the pixels that differ, eg, a directly-driven
EPD, can leave a trace of what it showed before.  If its `lws_display_t` has
a `.clear` op, it's called as each carousel page starts, unless the display
was left white, and before the white pages after the boot list and at the
end, so that update starts with the display cleared, eg, an EPD's flashing
refresh.

Ending tears everything down, the devices in `deinit_plat_devices()`, then
the lws context, and logs the free heap from before the context was created
and after it was destroyed, and the low water mark of the free heap.  If the
heap came back, to within `HEAP_RETURN_MARGIN` for what the platform keeps
once it has used it, it logs `Completed: PASS`, which is what Sai's
`sai-expect` looks for when the demo runs as a CI test; otherwise
`Completed: FAIL` with how much is missing, which means something leaked.

ESP32 WROVER KIT, and ESP32S2 Kaluga boards and displays are
supported, along with Waveshare ESP32 dev board and a variety of
E-ink displays, the Waveshare ESP32-S3-Touch-LCD-1.28 round LCD with
a touch panel, and the LilyGo T-Display S3 Long, a 180 x 640 LCD on quad SPI
with a touch panel.

## Touch

On boards with a touch panel (`esp32s3-waveshare-240-240-touch`,
`esp32s3-lilygo-t5-47` and `esp32s3-lilygo-t-display-s3-long`), touches on the strip ui, the boot list, the settings, or the frame's title strip, are
for it, see above.  Pressing a link on the page in the frame's body follows
it, and stops the carousel: the user is
driving then, so it no longer ends by itself.  Dragging the page moves it
around on the display, and gives it another 10s on the display before the
carousel moves on.

The whole page is laid out, as far down as 16384px (`rs.layout_h`), if there
is the memory for it, so all of a page longer or wider than the display can be
dragged into view, as far as its end, including anything positioned or
overflowing outside the box it is in.  Beyond the page is white.  On a
round display, the frame's body is the part of the circle below the title
strip, so the page can also be dragged beyond its sides and bottom, far
enough to bring what is in the corners the circle doesn't show into view.
Its top corners are in the circle already, below the strip.

Dragging the page doesn't lay it out again: it is drawn again from the display
list it was laid out in, from where it was dragged to, with
`lws_display_render_pan()`.  If the finger moves faster than the display can
be drawn, it is drawn where the finger got to once the display is free again.
Images on the page have to be fetched again each time it's drawn, unless the
context has a document asset cache (`dlo_asset_cache_dir`), which these boards
don't, so moving a page with images on it is slower.

The touch controller issues `{"type":"touch",...}` `LWSSMDCL_INTERACTION`
events, see `lib/drivers/touch/README.md`.  A `press` is resolved to the
link displayed under it with `lws_display_dl_hit_test()`, at where it is on
the page, below the title strip, wherever it was dragged to.  A `scroll` that began on the page
(after its `down`) moves the page.  Scrolls and long presses do not follow
links.

To make that possible, on these boards the display list is kept after the
page has been rendered (`rs.retained`), for as long as the page is on the
display: the render state owns it until the next browse begins, in
`init_browse()`.  Boards without touch free the display list as it is
rendered, as before.

## Fonts

Most of the demos build in each face they use, which costs a lot of flash.
`esp32-waveshare-600-448-7col` builds in only one small face, Fira Sans
Condensed Regular 12, and gets the rest from the `lws-mcufonts` plugin on
libwebsockets.org with `lws_fonts_register_manifest()`, at whatever size the
css asks for, a page of 256 codepoints of a face at a time as the text needs
them.  Text whose pages can't be had yet, for example while the server is
making a size nobody asked for before, is shown in the built-in face
meanwhile.  The manifest is only registered once the system is
OPERATIONAL, since layout waits for it the first time: so the boot
overlay, shown before there is any network, uses the built-in face.  Its
first redraw after that waits for the manifest to arrive.  See
`plugins/protocol_lws_mcufonts/README.md` to serve fonts like that yourself,
and change `FONTS_MANIFEST_URL` in its `main/devices.c` to point to your
server.

The pages a layout used may have been evicted for the memory by the time
the render gets to them.  They are fetched again then, but if the render
still can't have them after a few seconds, eg, the heap is full or the
server went away, drawing that text in the built-in face where the other
one was laid out can't look right.  So the render gives up, and the page is
laid out again, this time keeping the faces from the server its text uses
resident until its display list is destroyed, and rendered from the top: see
`.relayout` and `.fonts_hold` in `lws_display_render_state_t`.  The heap the
first layout held is free by then, so the faces can usually be had again.  A
face that can't is replaced while laying out by the closest one that can,
another size of it that is resident, or a built-in face, as if that had been
chosen from the start.

## Setting up wifi

On boards that can show the settings, press the cog of the AP and type its
passphrase on the device, see "Settings" above.

Every board, with a display or not, can also be set up from a browser: when
it has no wifi credentials it can use, it becomes an open AP of its own,
named for its hostname, eg, `lws-a1b2c3`, and serves the same settings, made
by the same `lws_wifi_settings_html()`, at `http://192.168.4.1/`.  The boot
list's setup row says which AP to join and where to browse, as do the
settings on the display.  This is `lws_wifi_provision_create()` in the
library, see `include/libwebsockets/lws-netdev.h`; `main.c` creates it for
any board with wifi.  The page has the same product header as the display,
see "Product header" above.

While the browser shows the settings, its `wifi.js` keeps a websocket open
to the device, and the device sends it the list of APs again whenever it's
different, eg, a scan found another AP, or how joining one went changed:
the list stays live without reloading the page.  `wifi.js` is served by the
library, since the strict CSP the pages have allows no inline script.

|Credentials stored|Becomes an AP|
|---|---|
|none|at once|
|only ones the AP refused|at once|
|one that joined, or reached the internet, before|never, it keeps trying them|
|only ones not tried yet, or that failed to join|if it hasn't joined in 60s|

It keeps scanning and trying to join as a station meanwhile, so if an AP it
has credentials for comes back, it joins it and stops being an AP.  When
credentials are stored, from the browser or on the display, the device
restarts to join that AP.

A board can name a led in `init_plat_devices()`, `plat_status_led`, which
double-blinks while it is an AP waiting to be set up.  Boards with a "red"
led use it, the wrover kit its blue one; it also shows the demo's fetching
and rendering, which `lhp_demo_phase()` in `main.c` leaves alone meanwhile.  The
240x240 round board has no led but its backlight, so it has none.

It can also name a button, `plat_reset_button`, every board here uses its
"user" one, to forget the stored credentials, a "factory reset".  On most
of these boards, eg, the 240x240 round watch, that's the BOOT button, on
GPIO0: press RESET (or power it up), then straight after, press BOOT and
hold it for 5s.  The status led, if any, blinks fast and the device
restarts with no credentials, so it becomes an AP to be set up again.

BOOT can't be held *through* RESET: GPIO0 is a strapping pin, and low as the
chip comes out of reset it starts the ROM's download mode instead of the
firmware.  But it can be pressed as soon as RESET is let go, and kept held
while the firmware starts: `main.c` gives the provisioning the button
controller (`.buttons`), so it sees, by `lws_button_is_down()`, a button
already held when it starts, which sends no event.  It can also be pressed
any time in the first 10s after that.

The device's AP has no passphrase and the page is plain http/1.1 (browsers
only use h2 over tls), so the passphrase given is in the clear on that AP,
to anyone in range at that time.  The page is served with the strict CSP
headers lws applies for `LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE`.

While it's an AP, it is also a captive portal: the boards build with
`LWS_WITH_SYS_CAPTIVE_DNS`, so to whoever joins, every name is the device
(`lws_captive_dns_start()`), and a request for any other host is redirected to
the settings.  A phone or laptop that joins checks for internet, eg,
Android fetches `http://connectivitycheck.gstatic.com/generate_204`, gets the
redirect, and offers to "sign in to the network", which shows the settings.

Browsing to `http://192.168.4.1/` yourself works too, in most browsers: in
testing, Firefox on Android never connected to it, where Chrome did.  Use the
sign-in notification, or another browser.

## Building

Set up for esp-idf, enter the platform-specific subdir and edit
`build.sh` to point to the correct USB device path.

OTA update support needs the public key the firmware manifests are signed
with, `~/.lws_ota/libwebsockets.org-ota-v1.public.jwk`.  Without it the
`esp32-waveshare-104-212` example builds with OTA off, which is how CI
builds it.

### http/3 needs mbedtls with the lws QUIC patches

lws builds http/3 by default, and on mbedtls that needs the lws QUIC
transport ops patches, the four `quic: Epoch 2` commits on the
`development` branch of https://libwebsockets.org/repo/mbedtls .  Without them, configure stops
saying so: either build with `-DLWS_WITH_HTTP3=0 -DLWS_ROLE_QUIC=0`, as CI
does, or give IDF a patched mbedtls component.

`esp32-waveshare-600-448-7col` uses http/3 for its content, and
`esp32s3-waveshare-240-240-touch`, `esp32s3-lilygo-t5-47` and
`esp32s3-lilygo-t-display-s3-long` build it beside h2, so they need the
patched component.  For esp-idf v6.1 (mbedtls 4.1), you can make one
without touching the IDF install: copy IDF's component, apply the patches
to the mbedtls inside it, and enable them in IDF's mbedtls config

```
 $ cp -a $IDF_PATH/components/mbedtls ~/idf-comp/mbedtls
 $ cd ~/idf-comp/mbedtls/mbedtls
 $ rm -f .git && git init -q && git add -A && git commit -qm idf
 $ git clone -b development https://libwebsockets.org/repo/mbedtls /tmp/lm
 $ git -C /tmp/lm log --oneline -6     # find the four quic: Epoch 2 commits
 $ git -C /tmp/lm format-patch -o /tmp/lm-quic <commit before 1/4>..<4/4>
 $ git am /tmp/lm-quic/*.patch
```

and add to `~/idf-comp/mbedtls/port/include/mbedtls/esp_config.h`, after
`MBEDTLS_SSL_PROTO_TLS1_3` is decided

```
#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_LWS_QUIC_SUPPORT
#endif
```

Then build with it in place of IDF's

```
 $ idf.py -D EXTRA_COMPONENT_DIRS=$HOME/idf-comp/mbedtls build
```

### Seeing what holds the heap

Build with `-D LWS_WITH_FOOTPRINT=1` added to the `idf.py` command line and
the example logs a `fp:` line per heap-holding participant, with the total
and how much of the heap used since the context was created no participant
accounts for: as each carousel page starts, when its layout is complete, and
if a layout fails.  See `READMEs/README.lws_footprint.md`.

```
 $ idf.py -D LWS_WITH_FOOTPRINT=1 build
```

Add `-D LWS_WITH_ALLOC_SITES=1` too and each dump also lists what lws's own
allocations hold, by who asked for them, which is how to find what the
heap "not accounted for" is.  Each allocation then carries a 40-byte header,
so the heap is tighter than in a normal build.

### Flashing

The first time we need to erase the whole flash and blow the whole
image and partition table

```
 $ ./build.sh erase-flash
 $ ./build.sh
```

Afterwards you can force-build like this which flashes both OTA
partitions with the new imahe

```
 $ ./build.sh f
```

After you have changed `./build.sh` to your own OTA keys and upload path, and adapted the
policy to look at your firmware server, you will typically build via uploading to that,
which resets the board so it can find and install the update and reboot

```
 $ ./build.sh u
```

