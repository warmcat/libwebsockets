# Settings icons

Generic 24px square SVG icons for a settings dialog, eg, the list of APs in
the lhp embedded examples' Settings.  They go with the boot status icons in
`../boot-status`, whose key (credentials are stored) and globe (the internet
was reached) mean the same things in settings.

|Order|File|Meaning|Icon|
|---|---|---|---|
|1|`settings-1-cog.svg`|set or change it, eg, an AP's passphrase|cog|
|2|`settings-2-forget.svg`|throw away what is stored, eg, an AP's credentials|bin|
|3|`settings-3-ok.svg`|the last try worked, eg, the AP was joined|circle with check|
|4|`settings-4-refused.svg`|the last try was refused, eg, the passphrase|circle with cross|
|5|`settings-5-failed.svg`|the last try failed some other way, eg, no answer|triangle with !|
|6|`settings-6-sig0.svg`|no signal, eg, an AP that wasn't seen|four bars, none lit|
|7|`settings-7-sig1.svg`|a weak signal|four bars, one lit|
|8|`settings-8-sig2.svg`|a usable signal|four bars, two lit|
|9|`settings-9-sig3.svg`|a good signal|four bars, three lit|
|10|`settings-10-sig4.svg`|a strong signal|four bars, all lit|

## Design

As the boot status icons: `width="24" height="24" viewBox="0 0 24 24"`, line
work with round caps and joins carrying the meaning, the heavier strokes (2.5)
for the key element, the signal bars filled, those not lit faintly, and only the subset the lws SVG renderer supports (see
`READMEs/README.svg-renderer.md`).  Give the `<img>`s their size in the css,
so they needn't be fetched during the layout to find it.

To check how they render with lws:

```
$ lws-api-test-svg --svg settings-1-cog.svg --out cog.bmp --scale 4 --bg ffffff
```
