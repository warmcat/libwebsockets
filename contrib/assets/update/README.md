# Update icons

SVG for showing a firmware update is in progress, eg, on the lhp embedded
examples' update display.

|Order|File|Meaning|Icon|
|---|---|---|---|
|1|`update-1-spinner.svg`|an update is being fetched and flashed|animated spinner|

## Design

The spinner is 96px square, `viewBox="0 0 96 96"`, in the lhp examples'
green and the boot status icons' orange, and is animated with the SMIL
subset the lws SVG renderer supports (see the "Animation" section of
`READMEs/README.svg-renderer.md`).  Every part repeats on a period of its
own, so however often it is drawn, it looks alive, eg, on an EPD redrawn
every few seconds:

 - an outer ring of dots, fading in turn as a chase, the ring turning slowly
 - a comet going around between the dots and the arcs, turned to point the
   way it goes (`animateMotion rotate="auto"`)
 - two arcs turning opposite ways, the inner one eased with `keySplines`
 - a pulsing core
 - two moons on a tilted elliptical orbit around the core

The animations come before what is drawn in the element they animate, as the
lws renderer needs.  Browsers show it the same.

To check how it renders with lws at a time, eg, 750ms:

```
$ lws-api-test-svg --svg update-1-spinner.svg --out spinner.bmp --scale 3 --t 750
```
