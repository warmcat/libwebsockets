# lws_display

lws provides a generic "display" object that is independent of the connection
to the display, i2c and spi implementations are provided.

Its purpose is to provide basic blit, backlight binding to lws_pwm, backlight /
power management and display info like pixels wide and high in a generic way.

The generic display object `lws_display_t` can be included at the top of a
specific display implementation object, eg, binding it to additional members
to define the actual IO operations to be used, eg, i2c or spi.

When the display is instantiated, it allocates an additional structure on heap
that contains dynamic information about display state, `lws_display_state_t`.

## Power state machine

lws_display objects have convenient power state management using a single lws
sul event loop timer that is managed automatically.

State|Meaning
---|---
OFF|The display is in sleep and not showing anything
BECOMING_ACTIVE|The display was asked to come out of sleep and is waiting for .latency_wake_ms befor proceeding to ACTIVE.  The backlight if any is off.  After the delay, the backlight is sequenced up to `.bl_active` using `.bl_transition` sequencer
ACTIVE|The backlight is ON and the dim timer is running
AUTODIMMED|The dim timer was not told the display was active for `.autodim_ms`, we are at `.bl_dim` brightness.  After `.off_ms` we will transition to OFF 

The lws_pwm sequencers are used to provide customizable, smooth transitions for
the backlight, which may be nonlinear.

## Active notification

Calling `lws_display_state_active(&lds)` on eg, user interaction causes the
display state to transition to ACTIVE smoothly, taking care of waking the display
and waiting out a display-specific wake period, and sequencing the backlight
transition to active level as specified in the display structure.

## Inset

The edges of a display's surface may not all be seen, eg, under a bezel or
the mask of a touch panel over it.  `.inset` in `lws_display_t` says how many
px are hidden at the left, top, right and bottom.  The display state's `.ic`
is the part inside that, what to lay things out and draw them on, and
`lws_display_blit()` blits what was drawn on it where it belongs on the
surface, so the display's own blit is still given lines of its whole surface.
`lws_display_visible_xy()` gives where a point on the surface, eg, a touch,
is on `.ic`.  The inset can be changed at runtime with
`lws_display_set_inset()`, eg, while finding out what it should be.

Rows in the inset are white, but they're only blitted when they may show
something else: by the first update, since what the display showed before is
unknown, and after the inset changed, eg, it was made bigger over rows that
were drawn on.  Then the first update starting at the top of `.ic`, and the
first ending at its bottom, are widened to include the inset rows above or
below them, so a display taking bands is still given each band's lines all
together.

## Animation

Something animated on a display, eg, a spinner, is moved on by updating the
display again.  `.anim_hz` says how often at most that's useful, and
`lws_display_anim_interval()` gives how often to do it, or 0 if the display
can't usefully show animation at all, eg, an EPD taking seconds for each
update, when nothing animated should be put on it.  A bistable display is
taken to be like that unless it gives `.anim_hz`, eg, a directly-driven EPD
that can show differential updates a few times a second.

With a retained display list, an update for that only needs to draw again
what `lws_display_render_damage()` says changed, the lines of what is
animated: a display with `.ic.band` can be sent only those lines.

## Directly-driven EPD panels

Some EPD panels, eg, the ED047TC1 on the LilyGo T5 4.7", have no controller:
`lws-epd-direct.h` makes lws the controller.  It's in three parts, the
generic driver `epd-direct.c`, panel descriptions from their datasheets in
`epd-direct-panels.c`, and a transport the platform provides,
`lws_epd_direct_bus_ops_t`, eg, the ESP32 one in
`lib/plat/freertos/esp32/drivers/epd-direct-esp32.c`.

Updates are differential: only pixels that change are driven, wherever they
are on the panel, and several updates can be in flight at once, so a later
one doesn't wait for an earlier one to finish.

Pixels may have 2, 4 or 16 grey levels, from the display's palette.  The
waveform, `lws_epd_direct_waveform_t`, has a transition table saying, for
each pass, what a pixel moving from one level to another is driven with, so
each pixel moving runs the transition for where it's coming from and going
to.  Transitions start every 4th pass, and pixels in the same span of
`.start_span_px` along a row (default 8) share when theirs started: a pixel
whose span has a transition in flight waits for it to finish.  That keeps
what the passes have to read for each pixel small, about 12 bits for 16
levels, which matters when it's in PSRAM.  A transport can give
`.alloc_fast` for what the passes read most, eg, internal RAM on an ESP32.

The panel is cleared at start, optionally every `.full_refresh_every`
updates, and before the next update after the display's `.clear` op is
called, eg, when what's shown is replaced by a different page.

By default the passes are run from the lws event loop.  Panels need passes
to follow each other without gaps, so a platform can instead give
`.runner`, a `lws_epd_direct_runner_t` that runs the passes on a thread of
its own by calling `lws_display_epd_direct_service()` until it returns
`LWS_EPDD_SVC_STOP`, eg, the FreeRTOS one in
`lib/plat/freertos/esp32/drivers/epd-direct-runner-esp32.c`.  The runner
side never calls other lws apis.

`minimal-examples-lowlevel/api-tests/api-test-epd-direct` checks the driver
against a simulated panel, and
`minimal-examples/embedded/lhp/esp32s3-lilygo-t5-47` uses it on hardware.
