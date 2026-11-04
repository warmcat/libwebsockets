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
|date|the time is known|
|ota|the first update check says we are on the latest firmware|
|auth|the system passed its AUTH states|

Each stage is a row of the list, its icon and next to it what is known
about it: the AP stored in the settings, or "Not configured" if there is
none, the AP being looked for, or joined, the IPv4 and IPv6 addresses,
whether there is internet, the date, the OTA variant and what the update
check said.  Stages reached are shown as they are, the others dimmed.  The
row of the stage being worked on, the first not reached, is highlighted, and
kept in the middle of the list: when the display is too short for the whole
list, eg, the 64px high heltec OLED, it scrolls as the boot moves on.

If no wifi credentials are stored, once a scan has found some APs, the ui
is titled "AP" instead and lists them, strongest first, one row per network.
On a touch display, the list can be dragged to scroll it, and an AP picked by
pressing it.  If the AP needs one, the ui then shows its edit page, titled
"Passphrase", with its keyboard, to type it in, shown as it is typed:
dragging the keyboard moves it around to reach the keys, and pressing the
title goes back to the APs.  It starts empty, even if a passphrase is stored
for the AP already.  When Done is pressed with at least the 8 characters WPA
needs, the credentials are stored with `lws_netdev_credentials_add()`, the
wifi netdev, which keeps scanning while it isn't joined, joins the AP when it
next sees it, and the ui is titled "Boot" again.

Credentials can be stored for any number of APs: the wifi netdev joins the
strongest one it sees that it has credentials for.  While the overlay is up,
pressing the "Boot" title shows the APs, the ones with credentials stored
highlighted, to pick one to add, or to change its passphrase; pressing the
"AP" title goes back.  This is only a stopgap until there is a settings ui.

The ui's title strip is given the example's own colours, by the css it
passes the ui (`lws_dlo_ui_info_t .css`) to follow its default theme.

On the round LCD of `esp32s3-waveshare-240-240-touch`, whose display says
it's `.round`, everything is kept inside the circle that can be seen; it
also says it's `.band`, so only the strips that changed are sent to it.

Until the network is up, the overlay only uses what is built in: a font,
and the stage icons, which `boot-icons.cmake` makes into C arrays at build
time from the svg in `contrib/assets/boot-status`, served from the dlo
filesystem.  What the rows say is worked out by `boot-ui.c`, which has
nothing platform-specific in it.

On a slow display, eg, an EPD taking 20s to update, the overlay is only
redrawn once the previous update has finished, showing the state as it is
then.

Once the system is OPERATIONAL and the first update check ended, saying
we're up to date, or failing, the overlay comes down and the application
html is shown.  If the update check doesn't end in 90s, we carry on
anyway.  If an update is found, a modal update display with its progress
takes over the display instead, whatever is on it.

## Application

The application is a placeholder for now: it visits each of a short list
of pages using h2 and renders them on the device + display combination,
showing each for 10s once it is on the display, the last one too, then it
ends.

An EPD keeps showing its image with no power, so whatever is left on it is
what it shows in storage: it should be left white.  On boards whose display
says it's `bistable` in its `lws_display_t`, as the EPD drivers do, a white
page is shown after the last page, and it ends once that is on the display.
On other displays, the display is turned off as it ends.

Ending tears everything down, the devices in `deinit_plat_devices()`, then
the lws context, and logs the free heap from before the context was created
and after it was destroyed, and the low water mark of the free heap.  If the
heap came back, to within `HEAP_RETURN_MARGIN` for what the platform keeps
once it has used it, it logs `Completed: PASS`, which is what Sai's
`sai-expect` looks for when the demo runs as a CI test; otherwise
`Completed: FAIL` with how much is missing, which means something leaked.

ESP32 WROVER KIT, and ESP32S2 Kaluga boards and displays are
supported, along with Waveshare ESP32 dev board and a variety of
E-ink displays, and the Waveshare ESP32-S3-Touch-LCD-1.28 round LCD with
a touch panel.

## Touch

On boards with a touch panel (`esp32s3-waveshare-240-240-touch`), while the
boot overlay is up, touches are for it, see above.  After that, pressing
a link on the displayed page follows it, and stops the carousel: the user is
driving then, so it no longer ends by itself.

The touch controller issues `{"type":"touch",...}` `LWSSMDCL_INTERACTION`
events, see `lib/drivers/touch/README.md`.  A `press` is resolved to the
link displayed under it with `lws_display_dl_hit_test()`.  Scrolls and long
presses do not follow links.

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

On boards with a touch panel, pick the AP and type its passphrase on the
device, see "Boot overlay" above.

Other boards can't do that yet.  Edit ./main/devices.c in your
platform-specific subdir, enable this section and set your wifi SSID and
passphrase in the `xxx` strings.  This will store the information on flash
on the device.

Boot once with that and then remove your information and disable the code
section again and rebuild.

```
#if 0
	/*
	 * This is a temp hack to bootstrap the settings to contain the test
	 * AP ssid and passphrase for one time, so the settings can be stored
	 * while there's no UI atm
	 */
	{
		lws_wifi_creds_t creds;

		memset(&creds, 0, sizeof(creds));

		lws_strncpy(creds.ssid, "xxx", sizeof(creds.ssid));
		lws_strncpy(creds.passphrase, "xxx", sizeof(creds.passphrase));
		lws_dll2_add_tail(&creds.list, &netdevs->owner_creds);

		if (lws_netdev_credentials_settings_set(netdevs)) {
			lwsl_err("%s: failed to write bootstrap creds\n",
					__func__);
			return 1;
		}
	}
#endif
```


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

`esp32-waveshare-600-448-7col` uses http/3 for its content, so it needs
the patched component.  For esp-idf v6.1 (mbedtls 4.1), you can make one
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

