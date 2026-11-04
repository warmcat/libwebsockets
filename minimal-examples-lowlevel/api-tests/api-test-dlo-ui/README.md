# lws api test dlo ui

Shows the strip ui (`lws-dlo-ui.h`) on a pretend 240 x 240 round display,
like the Waveshare ESP32-S3-Touch-LCD-1.28's, which keeps what it is sent in
a framebuffer and notes the window of each update.  It checks

 - the first update is of the whole display, and on the list page, only
   white is drawn outside the circle that can be seen, except for the title
   strip's colour in the default theme

 - the title and the list's rows were drawn

 - pressing a row picks it, and pressing the title, or below the last row,
   doesn't

 - dragging the list scrolls it, and only the list's band of lines is sent
   to the display again; setting the title only sends the title's band

 - the edit page: typing on its keyboard, with shift and the symbols layer,
   only sends the edit strip's band, or the keyboard's when that changes;
   dragging the keyboard moves it without typing anything; Done gives what
   was typed, or keeps it being edited if the caller refuses it, then the
   list page is shown again; pressing the title abandons an edit

 - the theme: the first time, the default theme's title strip colour is
   drawn; the second time, the ui is given css making the title strip white
   with red text, which is drawn instead, and nothing at all is drawn outside
   the circle on the list page

 - destroying the ui gives back all the heap it took, checked the second
   time, once the context has made what it makes on first use

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
