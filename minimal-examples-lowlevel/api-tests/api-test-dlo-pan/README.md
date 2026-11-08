# lws api test dlo pan

Pans around a page laid out taller and wider than the display it is shown on,
with `lws_display_render_pan()`, without laying it out again.

The page, in the dlo filesystem, is bands of colour 100px tall, the first one
400px wide, with a png 160px tall, red over blue, between them.  It's laid out
to `.layout_h`, taller than the display, and rendered on a pretend 240 x 240
display that keeps what it is sent in a framebuffer: first a round one, like
the Waveshare ESP32-S3-Touch-LCD-1.28's, then a rectangular one.  It checks

 - the page wasn't cut short by the layout, though it's longer than the
   display

 - panning down shows what is further down the page

 - panning back up a little shows the top of the png again, though the
   previous render stopped partway down it and its decoder only goes forwards

 - the view can't go further than the end of the page; on the round display,
   only as much further as it takes to bring each corner of the page to the
   first pixel of the circle that can be seen there, 36px in from each side on
   a 240px circle

 - what the view shows beyond the page is white

 - the view can go across to the right edge of the wider band, but not
   further

 - a page shorter than the display stays where it was laid out, unless it's
   moved.  It is as wide as the display: on the round display it can be
   moved right to bring its right corners into the circle, and up and left
   for its top left corner, but not down, since the bottom of what is in it
   is in the circle already

 - in a page whose body has a fixed height, what overflows a box, here a box
   500px tall in one 20px tall, can be panned down to and is drawn

 - on a surface that's only the part of the round display below a title
   strip (`.round_top`), the circle is still the display's: what can be seen
   of its lines is what can be seen of the display's lines there, and the
   view can go beyond the sides and bottom of the page as on the whole round
   display, but not above it

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-dlo-pan
[2026/11/04 18:19:01:7471] U: LWS API Test - dlo pan
...
[2026/11/04 18:19:02:0067] U: Completed: PASS
```
