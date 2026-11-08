# LWS touch controller class drivers

Lws provides a touch controller class for touch panels over a display.  It
maps what the controller reports into the display's pixel coordinates and
classifies it into the interactions user code cares about, issuing them as
`lws_smd` events like the button class does.

Specific controllers are small "subclasses" that only know how to read their
chip.  Currently there is

|Controller|Bus|Header|
|---|---|---|
|Hynitron CST816S|i2c|`lws-cst816s-i2c.h`|
|Goodix GT911|i2c|`lws-gt911-i2c.h`|

## Classification

An interaction starts when a finger comes down, and it becomes exactly one
of

 - a **scroll**, if the finger moves further than `px_slop` from where it came
   down.  It is only ever a scroll from then on, it is never a press.
 - a **long press**, if it is held near where it came down for
   `ms_longpress`.  This is issued while the finger is still down.
 - a **press**, if it lifts near where it came down before that.

The defaults are 10px and 500ms, they can be changed by pointing the
controller definition's `.regime` at a `lws_touch_regime_t`.

Controllers differ in how much they report.  The classifier is correct for
one that reports movement continuously, and for one that only reports the
finger coming down and lifting: for that, a long press is issued from an OS
timer, and a scroll is issued as one movement when the finger lifts, if the
controller says where that was.

The classifier is usable on its own via `lws_touch_classify_sample()`,
`lws_touch_classify_timeout()` and `lws_touch_classify_deadline()`, eg, to
treat a mouse the same way.

## Coordinates

The controller definition gives the extent of the coordinates the controller
reports in `.wh_native`, and the extent of the display pixels they cover in
`.wh_px`.  Reported coordinates are untrusted: they are clamped into the
native extent first, then the `.flags` are applied, `LWSTOUCH_FL_SWAP_XY`
then `LWSTOUCH_FL_INVERT_X` / `LWSTOUCH_FL_INVERT_Y`, and finally they are
scaled into `.wh_px`.  So the panel may be mounted in any orientation over
the display, and may report at a different resolution to it.

## lws_smd events

Events are of class `LWSSMDCL_INTERACTION`, with JSON payloads like

```
{"type":"touch","src":"ts","event":"press","x":120,"y":64}
```

`src` is the controller definition's `.name`.

|event|Meaning|
|---|---|
|down|a finger came down at x, y|
|longpress|it has been held at x, y, where it came down|
|scroll|it moved, it is now at x, y, and moved by dx, dy since the last scroll event|
|up|it lifted, at x, y, where it was last seen.  Always the last event of an interaction|
|press|it was a press at x, y, where it came down.  Issued after the up|

Because they are interaction events, any existing handling that, eg, wakes a
dimmed display on any interaction, works for touches too.

A press or long press can be resolved to what is displayed under it, for
example with `lws_display_dl_hit_test()` on the display list that was
rendered, see `minimal-examples/embedded/lhp`.

## Threading

On platforms with OS timers, like FreeRTOS, the controller's interrupt
schedules a bottom half on an OS timer, which reads the controller,
classifies and issues the smd events, in the same way as the button class.
That is the OS timer task, not the lws thread, so nothing there touches lws
state other than `lws_smd`, which is threadsafe.  Resolving a press into
something on the display happens in the smd handler, on the lws thread.

Elsewhere, `lws_touch_service()` reads and processes what the controller
has to say, for integrations that poll or have their own interrupt
handling.

## Hynitron CST816S

The CST816S is asleep unless a finger is on it, or was very recently, and
while asleep it does not answer on i2c.  So it is never probed or configured:
after an optional reset it is only read when its IRQ says it has something to
report, as the Linux `hynitron-cst816x` driver does.  For the same reason, if
it cannot be read, it is taken to mean the finger has gone.

```
static const lws_touch_cst816s_t touch = {
	.touch = {
		lws_touch_cst816s_ops,
		.gpio		= &lws_gpio_plat,
		.name		= "ts",
		.wh_native	= { 240, 240 },
		.wh_px		= { 240, 240 },
		.irq_gpio	= GPIO_NUM_5,
		.irq_edge	= LWSGGPIO_IRQ_FALLING,
	},
	.i2c			= &li2c.bb_ops,
	.reset_gpio		= GPIO_NUM_13,
	.has_reset_gpio		= 1,
};

	struct lws_touch_state *ts = lws_touch_create(cx, &touch.touch);
```

The i2c ops must have been initialized already.
