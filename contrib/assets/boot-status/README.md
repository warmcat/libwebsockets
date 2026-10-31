# Boot status icons

Generic 24px square SVG icons for the stages of a device's boot, from having
connectivity credentials through to being recognized by the server.

|Order|File|Stage|Meaning|Icon|
|---|---|---|---|---|
|1|`boot-1-setup.svg`|SETUP|the BSS / WPA2 passphrase for connectivity is stored|key|
|2|`boot-2-wlan.svg`|WLAN|associated to the AP|radio waves|
|3|`boot-3-ipv4.svg`|IPV4|received an IPv4 address|address badge with a 4|
|4|`boot-4-ipv6.svg`|IPV6|received an IPv6 address|address badge with a 6|
|5|`boot-5-internet.svg`|INTERNET|confirmed we are not in a captive portal|globe|
|6|`boot-6-date.svg`|DATE|received ntp time / date|calendar|
|7|`boot-7-ota.svg`|OTA|confirmed we are on the latest firmware|download to device|
|8|`boot-8-auth.svg`|AUTH|the server recognizes us as a valid user|shield with check|

The icons carry no state: the intention is they are shown at reduced opacity
until their stage is reached.

## Layout for lhp / dlo

Show them as a vertical list, top to bottom in the order above.  The dlo
display list is rasterized a single row at a time, so stacking the icons
vertically means each icon's rows are finished before the next icon's begin,
rather than every icon being live across the same rows as in a horizontal
strip.

## Design

 - `width="24" height="24" viewBox="0 0 24 24"`, so they scale cleanly.
 - Meaning is carried by the line work, with round caps and joins; the
   heavier strokes (2.5) mark the key element (the digit, the arrow, the
   check), the lighter ones (1.5) the frames and detail.  The colour and the
   0.15 opacity tints are secondary, so the icons work in monochrome too.
 - They use only the subset the lws SVG renderer supports (see
   `READMEs/README.svg-renderer.md`): stroked and filled `path`, `rect`,
   `circle` and `ellipse`, with no text, gradients or `<use>`.  The 4 and 6
   are drawn as paths for that reason.

To check how they render with lws:

```
$ lws-api-test-svg --svg boot-5-internet.svg --out internet.bmp --scale 4 --bg ffffff
```
