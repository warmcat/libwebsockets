# lws api test dlo ui

Shows the strip ui (`lws-dlo-ui.h`) on a pretend 240 x 240 round display,
like the Waveshare ESP32-S3-Touch-LCD-1.28's, which keeps what it is sent in
a framebuffer and notes the window of each update.  It checks

 - the first update is of the whole display, and only white is drawn
   outside the circle that can be seen

 - the title and the list's rows were drawn

 - pressing a row picks it, and pressing the title, or below the last row,
   doesn't

 - dragging the list scrolls it, and only the list's band of lines is sent
   to the display again; setting the title only sends the title's band

 - destroying the ui gives back all the heap it took

Everything is local: the ui's html and the icon are in the dlo filesystem.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-dlo-ui
[2026/11/04 15:23:48:5471] U: LWS API Test - dlo strip ui
...
[2026/11/04 15:23:48:5471] U: Completed: PASS
```
