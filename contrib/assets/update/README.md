# Update icons

SVG for showing a firmware update is in progress, eg, on the lhp embedded
examples' update display.

|Order|File|Meaning|Icon|
|---|---|---|---|
|1|`update-1-spinner.svg`|an update is being fetched and flashed|animated spinner|

## Design

The spinner is 48px square, `viewBox="0 0 48 48"`, in the lhp examples'
green and the boot status icons' orange, and is animated with the SMIL
subset the lws SVG renderer supports (see the "Animation" section of
`READMEs/README.svg-renderer.md`).

It's kept calm on purpose.  An embedded display may only be redrawn a couple
of times a second, and slowly enough that the redraw can be seen, so many
parts changing, or parts changing a lot between redraws, look like flashing
rather than movement.  It has only two moving parts, each moving on only a
little in 0.5s:

 - an arc of a little over a quarter turn, going round a faint track once in
   6s, 30 degrees each 0.5s
 - a dot going round inside it the other way once in 12s, 15 degrees each 0.5s

The animations come before what is drawn in the element they animate, as the
lws renderer needs.  Browsers show it the same.

To check how it renders with lws at a time, eg, 750ms:

```
$ lws-api-test-svg --svg update-1-spinner.svg --out spinner.bmp --scale 3 --t 750
```
