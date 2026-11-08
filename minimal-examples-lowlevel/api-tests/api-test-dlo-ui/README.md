# lws api test dlo ui

Shows the strip ui (`lws-dlo-ui.h`) on a pretend 240 x 240 round display,
like the Waveshare ESP32-S3-Touch-LCD-1.28's, which keeps what it is sent in
a framebuffer and notes the window of each update.  It checks

 - the first update is of the whole display, and on the list page, only
   white is drawn outside the circle that can be seen, except for the title
   strip's colour in the default theme

 - the title and the list's rows were drawn

 - pressing a row picks it, and pressing below the last row doesn't;
   pressing the title calls the title callback instead

 - dragging the list scrolls it, and only the list's band of lines is sent
   to the display again; setting the title only sends the title's band

 - the edit page: typing on its keyboard, with shift and the symbols layer,
   only sends the edit strip's band, or the keyboard's when that changes;
   dragging the keyboard moves it without typing anything; Done gives what
   was typed, or keeps it being edited if the caller refuses it, then the
   list page is shown again; pressing the title abandons an edit

 - the status capsule: drawn at the right end of the title strip, inside the
   circle, sending only the title strip's band when it changes, and nothing
   when what it shows doesn't; pressing it issues its button's interaction
   event, `"src":"ui/settings"`, as a physical button called "settings" would

 - buttons: `lws_dlo_ui_nav()`, or button events given to
   `lws_dlo_ui_interaction()`, move a cursor down the list, pick its row, and
   go back like the title; on the edit page, which can start with something
   already typed, they move the cursor over the keys, type with them and
   press Done

 - the frame page: drawn all at once with its body white, then drawn by the
   caller around a body of its own, taking the title strip's lines from the
   ui, which match what the ui drew itself.  Touches on the body and nav are
   left to the caller.  Changing the title or status then sends only the
   title strip's band, leaving the body alone, or on a display that can't
   take a band, asks the caller to draw it all again.  Laying the title strip
   out again while a page browsed into the body is still fetching its image,
   from a server of the test's own that never answers, doesn't stop the
   image: cancelling that page's browse does

 - the theme: the first time, the default theme's title strip colour is
   drawn; the second time, the ui is given css making the title strip white
   with red text, which is drawn instead, and nothing at all is drawn outside
   the circle on the list page

 - the dialog page: a table of links taller than the panel, drawn only
   inside the circle and above the bottom of the panel.  The title, or esc,
   is the title callback; pressing the title strip a little before the
   status capsule is the capsule.  The first nav shows a cursor ring on the
   first link, pressing inside it presses that link, and the caller's action
   is given its href; left and right go to the link before or after, up and
   down to the one above or below, scrolling to the last.  Only the panel's
   band is sent for those.  An edit from it, with `LWS_DLO_UI_EDIT_KEEP`,
   gives what was typed when the title, or `lws_dlo_ui_edit_abandon()`,
   abandons it, and comes back to the dialog, still scrolled;
   `lws_dlo_ui_dialog_changed()` draws it again where it was; dragging it
   scrolls it without pressing anything, and showing the list ends it

 - destroying the ui gives back all the heap it took, checked the second
   time, once the context has made what it makes on first use

Everything is local: the ui's html, the icon and the body's page are in the
dlo filesystem, and the body's image is on a raw server on a free port of the
test's own.

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
