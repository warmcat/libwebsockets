/*
 * lhp-browser unix plat backend
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * Made available under the Creative Commons CC0 1.0 Universal Public Domain
 * Dedication.
 *
 * Presents the app core's document framebuffer in an X11 window and turns
 * X events into core calls.  Works headless under Xvfb.  X protocol errors
 * are made synchronous (and so attributable to the exact call) by setting
 * the environment variable LHP_XSYNC.
 *
 * Touchpads scroll with XInput2 smooth-scroll valuator events rather than
 * legacy button 4/5 clicks, so where the Xi extension is available we
 * select those and translate the valuator deltas.
 */

#include "../private-lhp-browser.h"

#include <poll.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/cursorfont.h>
#include <X11/extensions/XInput2.h>

static struct {
	Display		*dpy;
	Window		xw;
	GC		gc;
	XImage		*ximg;
	uint32_t	*xdata;
	Atom		wm_delete;
	Cursor		cursor;    /* the font cursor shown, 0 = default */
	int		img_w, img_h;
} x11;

/*
 * XInput2 smooth scrolling state.  Fixed point: the XI2 doubles are
 * converted to lws fixed point where they are read, and all of the
 * arithmetic on them is lws_fx_t.
 *
 * We receive events through the master devices, and their valuators are
 * numbered in the master's axis space: the scroll axes are learned from
 * the masters themselves, per device.
 */

#define XI2_MAX_AXES 8
#define XI2_MAX_DEVS 8

static struct {
	int		opcode;    /* 0 if no XI2 available */
	struct {
		int	deviceid;                  /* 0 = slot unused */
		lws_fx_t incr[XI2_MAX_AXES];    /* zero = not scroll */
	} dev[XI2_MAX_DEVS];
	lws_fx_t	last[XI2_MAX_DEVS][XI2_MAX_AXES];
	char		have[XI2_MAX_DEVS][XI2_MAX_AXES];
	lws_fx_t	acc;       /* accumulated vertical scroll, px */
} xi;

/*
 * The only place floating point is touched: XI2 reports valuator state
 * as doubles, converted here at the api boundary
 */

static lws_fx_t
xi_d2fx(double d)
{
	lws_fx_t f;

	f.whole = (int32_t)d;
	f.frac  = (int32_t)((d - (double)f.whole) * 100000000.0);

	return f;
}

/* truncate an lws_fx_t toward zero (whole alone is not it: the ops can
 * leave a positive frac on a negative whole and vice versa) */

static int
xi_fx_trunc(const lws_fx_t *a)
{
	if (a->whole > 0 || (a->whole == 0 && a->frac >= 0))
		return a->whole - (a->frac < 0 ? 1 : 0);

	return a->whole + (a->frac > 0 ? 1 : 0);
}

/*
 * Presentation is staged: rendered lines are copied into a window-sized
 * staging image one at a time (as an EPD line renderer would produce
 * them), and lhp_browser_plat_present() puts the whole viewport to the
 * window in a single step.  Without this, the compositor can sample the
 * window between per-line protocol updates and show a tearing band of
 * the previous frame.
 */

static void
win_x11_stage_size(void)
{
	if (x11.ximg && x11.img_w == win.vw && x11.img_h == win.vh)
		return;

	if (x11.cursor)
		XFreeCursor(x11.dpy, x11.cursor);

	if (x11.ximg) {
		x11.ximg->data = NULL;
		XDestroyImage(x11.ximg);
		free(x11.xdata);
	}
	x11.xdata = malloc((size_t)win.vw * (size_t)win.vh * 4);
	if (!x11.xdata)
		return;
	x11.img_w = win.vw;
	x11.img_h = win.vh;
	x11.ximg = XCreateImage(x11.dpy, CopyFromParent, 24, ZPixmap, 0,
				(char *)x11.xdata, (unsigned)win.vw,
				(unsigned)win.vh, 32, 0);
	if (!x11.ximg) {
		free(x11.xdata);
		x11.xdata = NULL;
	}
}

/* stage one rendered document line at window row wy */

void
lhp_browser_plat_line(int wy, const uint8_t *rgb, int w)
{
	uint32_t *dst;
	int x;

	if (wy < 0 || wy >= win.vh || w <= 0)
		return;
	if (w > win.vw)
		w = win.vw;

	win_x11_stage_size();
	if (!x11.xdata)
		return;

	dst = x11.xdata + (size_t)wy * (size_t)win.vw;
	for (x = 0; x < w; x++) {
		uint32_t r = *rgb++, g = *rgb++, b = *rgb++;

		*dst++ = 0xff000000u | (r << 16) | (g << 8) | b;
	}
}

/* stage window rows wy..wy+wh-1 as blank paper */

/*
 * The core's platform-neutral cursor shapes map on to the X11 cursor font
 */

void
lhp_browser_plat_cursor(lws_dlo_cursor_t cursor)
{
	unsigned int shape;

	if (!x11.dpy)
		return;

	switch (cursor) {
	case LWS_DLO_CURSOR_POINTER:	shape = XC_hand2;		break;
	case LWS_DLO_CURSOR_TEXT:	shape = XC_xterm;		break;
	case LWS_DLO_CURSOR_CROSSHAIR:	shape = XC_crosshair;		break;
	case LWS_DLO_CURSOR_MOVE:	shape = XC_fleur;		break;
	case LWS_DLO_CURSOR_WAIT:	shape = XC_watch;		break;
	case LWS_DLO_CURSOR_HELP:	shape = XC_question_arrow;	break;
	case LWS_DLO_CURSOR_NOT_ALLOWED: shape = XC_X_cursor;		break;
	default:			shape = 0;			break;
	}

	if (x11.cursor) {
		XFreeCursor(x11.dpy, x11.cursor);
		x11.cursor = 0;
	}

	if (!shape) {
		/* back to the parent's (the default arrow) */
		XUndefineCursor(x11.dpy, x11.xw);
		XFlush(x11.dpy);
		return;
	}

	x11.cursor = XCreateFontCursor(x11.dpy, shape);
	XDefineCursor(x11.dpy, x11.xw, x11.cursor);
	XFlush(x11.dpy);
}

void
lhp_browser_plat_clear(int wy, int wh)
{
	if (wy < 0) {
		wh += wy;
		wy = 0;
	}
	if (wy + wh > win.vh)
		wh = win.vh - wy;
	if (wh <= 0)
		return;

	win_x11_stage_size();
	if (!x11.xdata)
		return;

	for (; wh; wh--, wy++)
		memset(x11.xdata + (size_t)wy * (size_t)win.vw, 0xff,
		       sizeof(*x11.xdata) * (size_t)win.vw);
}

/* put the staged viewport to the window in one step */

void
lhp_browser_plat_present(void)
{
	if (!x11.ximg)
		return;

	XPutImage(x11.dpy, x11.xw, x11.gc, x11.ximg, 0, 0, 0, 0,
		  (unsigned)win.vw, (unsigned)win.vh);
	XFlush(x11.dpy);
}

static void
win_x11_key(KeySym ks)
{
	switch (ks) {
	case XK_Up:		lhp_browser_key(LHPBK_UP);		break;
	case XK_Down:		lhp_browser_key(LHPBK_DOWN);		break;
	case XK_Page_Up:	lhp_browser_key(LHPBK_PAGE_UP);	break;
	case XK_Page_Down:	lhp_browser_key(LHPBK_PAGE_DOWN);	break;
	case XK_Home:		lhp_browser_key(LHPBK_HOME);		break;
	case XK_End:		lhp_browser_key(LHPBK_END);		break;
	case XK_q:
	case XK_Q:
	case XK_Escape:
		lhp_browser_key(LHPBK_QUIT);
		break;
	default:
		break;
	}
}

/*
 * XI2 setup: learn which valuator axes are smooth scroll axes, and select
 * XI motion / button events through the master devices.  When it worked,
 * core motion / button events for those devices are no longer delivered
 * and we handle them here instead.
 */

/* learn the scroll axes of the master devices */

static void
win_xi2_learn(void)
{
	XIDeviceInfo *dev;
	int ndev = 0, i, j, k;

	memset(xi.dev, 0, sizeof(xi.dev));
	memset(xi.have, 0, sizeof(xi.have));

	dev = XIQueryDevice(x11.dpy, XIAllMasterDevices, &ndev);
	if (!dev)
		return;

	for (i = 0, k = 0; i < ndev && k < XI2_MAX_DEVS; i++) {
		if (dev[i].use != XIMasterPointer &&
		    dev[i].use != XIMasterKeyboard)
			continue;

		xi.dev[k].deviceid = dev[i].deviceid;

		for (j = 0; j < dev[i].num_classes; j++) {
			XIAnyClassInfo *any = dev[i].classes[j];

			if (any->type == XIScrollClass) {
				XIScrollClassInfo *sc = (XIScrollClassInfo *)any;
				lws_fx_t z;
				char buf[3 * 32];

				if (sc->scroll_type != XIScrollTypeVertical ||
				    sc->number >= XI2_MAX_AXES)
					continue;

				xi.dev[k].incr[sc->number] =
							xi_d2fx(sc->increment);

				lws_fx_set(z, 0, 0);
				if (!lws_fx_comp(&xi.dev[k].incr[sc->number], &z))
					/* a zero increment is unusable */
					lws_fx_set(xi.dev[k].incr[sc->number], 1, 0);

				lws_fx_string(&xi.dev[k].incr[sc->number],
						buf, sizeof(buf));
				lwsl_user("xi2: master %d: vertical scroll "
					    "axis %d, increment %s\n",
					    dev[i].deviceid, sc->number, buf);
			}
		}
		k++;
	}

	XIFreeDeviceInfo(dev);
}

static void
win_xi2_setup(void)
{
	unsigned char mask[XIMaskLen(XI_LASTEVENT)];
	XIEventMask em;
	int ev, err;
	int major = 2, minor = 2;

	if (!XQueryExtension(x11.dpy, "XInputExtension", &xi.opcode,
			     &ev, &err))
		goto no_xi2;

	if (XIQueryVersion(x11.dpy, &major, &minor) != Success)
		goto no_xi2;

	win_xi2_learn();

	memset(mask, 0, sizeof(mask));
	XISetMask(mask, XI_Motion);
	XISetMask(mask, XI_ButtonPress);
	XISetMask(mask, XI_DeviceChanged);

	em.deviceid	= XIAllMasterDevices;
	em.mask_len	= sizeof(mask);
	em.mask		= mask;

	if (XISelectEvents(x11.dpy, x11.xw, &em, 1) != Success)
		goto no_xi2;

	lwsl_info("%s: XI2 smooth scrolling enabled\n", __func__);

	return;

no_xi2:
	xi.opcode = 0;
	lwsl_info("%s: no usable XI2, legacy wheel buttons only\n", __func__);
}

/* complain once per device that motion is arriving with no scroll axes
 * matched, to make touchpad trouble diagnosable */

static void
win_xi2_no_scroll(XIDeviceEvent *xde)
{
	int a;

	for (a = 0; a < XI2_MAX_DEVS; a++)
		if (xi.dev[a].deviceid == xde->deviceid) {
			static char warned[XI2_MAX_DEVS];

			if (!warned[a]) {
				warned[a] = 1;
				lwsl_user("xi2: motion from master %d with no "
					    "vertical scroll axis matched (axes "
					    "set: %d bytes)\n", xde->deviceid,
					    xde->valuators.mask_len);
			}

			return;
		}
}

/* a valuator axis moved on a master device: turn the delta into
 * scrolling if it is a scroll axis on that device; returns 1 if the
 * axis was a scroll axis on that device (whether it moved enough to
 * scroll or not)
 */

static int
win_xi2_valuator(XIDeviceEvent *xde, int axis, double v)
{
	lws_fx_t fv, d, t, lim, z;
	int dv = -1, a;

	for (a = 0; a < XI2_MAX_DEVS; a++)
		if (xi.dev[a].deviceid == xde->deviceid) {
			dv = a;
			break;
		}

	if (dv < 0 || axis < 0 || axis >= XI2_MAX_AXES)
		return 0;

	lws_fx_set(z, 0, 0);
	if (!lws_fx_comp(&xi.dev[dv].incr[axis], &z))
		return 0; /* not a scroll axis on this device */

	fv = xi_d2fx(v);

	if (!xi.have[dv][axis]) {
		xi.have[dv][axis] = 1;
		xi.last[dv][axis] = fv;

		return 1;
	}

	lws_fx_sub(&d, &fv, &xi.last[dv][axis]);
	xi.last[dv][axis] = fv;

	lws_fx_set(lim, 100, 0);
	if (lws_fx_comp(&d, &lim) > 0)
		/* the axis jumped, eg a device change reset it */
		return 1;
	lws_fx_set(lim, -100, 0);
	if (lws_fx_comp(&d, &lim) < 0)
		return 1;

	/* accumulate in px, scrolling whole pixels as they accrue */

	lws_fx_div(&t, &d, &xi.dev[dv].incr[axis]);
	lws_fx_set(lim, 40, 0);
	lws_fx_mul(&t, &t, &lim);
	lws_fx_add(&xi.acc, &xi.acc, &t);

	lws_fx_set(lim, 1, 0);
	lws_fx_set(t, -1, 0);
	if (lws_fx_comp(&xi.acc, &lim) >= 0 || lws_fx_comp(&xi.acc, &t) <= 0) {
		int px = xi_fx_trunc(&xi.acc);

		lws_fx_set(t, px, 0);
		lws_fx_sub(&xi.acc, &xi.acc, &t);

		lwsl_user("touchpad scroll: %+d px (viewport y -> %d)\n",
			   px, win.scroll_y + px);

		lhp_browser_scroll(px);
	}

	return 1;
}

static void
win_xi2_event(XGenericEventCookie *cookie)
{
	if (cookie->evtype == XI_Motion) {
		XIDeviceEvent *xde = (XIDeviceEvent *)cookie->data;
		int a, k = 0, matched = 0;

		/* pointer position for the cursor shape, whatever the
		 * valuators say (scroll events carry it too) */
		lhp_browser_motion((int)xde->event_x, (int)xde->event_y);

		for (a = 0; a < xde->valuators.mask_len * 8; a++)
			if (XIMaskIsSet(xde->valuators.mask, a))
				matched += win_xi2_valuator(xde, a,
						xde->valuators.values[k++]);

		if (!matched)
			win_xi2_no_scroll(xde);

		return;
	}

	if (cookie->evtype == XI_ButtonPress) {
		XIDeviceEvent *xde = (XIDeviceEvent *)cookie->data;

		switch (xde->detail) {
		case 1:
			lhp_browser_click((int)xde->event_x,
					  (int)xde->event_y);
			break;
		case 4: /* wheel up */
			lhp_browser_scroll(-60);
			break;
		case 5: /* wheel down */
			lhp_browser_scroll(60);
			break;
		}

		return;
	}

	if (cookie->evtype == XI_DeviceChanged)
		/* the slaves attached to the master changed, or their
		 * classes did: relearn the master scroll axes */

		win_xi2_learn();
}

/* returns nonzero when the app should exit */

int
lhp_browser_plat_pump(void)
{
	while (XPending(x11.dpy)) {
		XEvent e;

		XNextEvent(x11.dpy, &e);

		switch (e.type) {
		case Expose:
			lhp_browser_repaint();
			break;

		case ConfigureNotify:
			lhp_browser_resize(e.xconfigure.width,
					   e.xconfigure.height);
			break;

		case MotionNotify:
			/* core X motion, when XI2 isn't delivering it */
			if (!xi.opcode)
				lhp_browser_motion(e.xmotion.x, e.xmotion.y);
			break;

		case ButtonPress:
			switch (e.xbutton.button) {
			case 1:
				lhp_browser_click(e.xbutton.x, e.xbutton.y);
				break;
			case 4: /* wheel up */
				lhp_browser_scroll(-60);
				break;
			case 5: /* wheel down */
				lhp_browser_scroll(60);
				break;
			}
			break;

		case KeyPress: {
			char buf[32];
			KeySym ks;

			XLookupString(&e.xkey, buf, sizeof(buf), &ks, NULL);
			win_x11_key(ks);
			break;
		}

		case GenericEvent:
			if (e.xcookie.extension == xi.opcode &&
			    XGetEventData(x11.dpy, &e.xcookie)) {
				win_xi2_event(&e.xcookie);
				XFreeEventData(x11.dpy, &e.xcookie);
			}
			break;

		case ClientMessage:
			if ((Atom)e.xclient.data.l[0] == x11.wm_delete)
				return 1;
			break;

		default:
			break;
		}
	}

	return win.quitting;
}

/* sleep until X events can arrive, or timeout_ms: lws parks in a
 * days-long poll when idle and the X fd is not in its wait set, so the
 * bounded wait on window input belongs here */

void
lhp_browser_plat_wait(int timeout_ms)
{
	struct pollfd pfd;

	pfd.fd		= ConnectionNumber(x11.dpy);
	pfd.events	= POLLIN;

	(void)poll(&pfd, 1, timeout_ms);
}

int
lhp_browser_plat_init(int w, int h)
{
	Window root;
	int screen;

	x11.dpy = XOpenDisplay(NULL);
	if (!x11.dpy) {
		lwsl_err("%s: unable to open display\n", __func__);

		return 1;
	}

	if (getenv("LHP_XSYNC"))
		XSynchronize(x11.dpy, True);

	screen = DefaultScreen(x11.dpy);
	root = RootWindow(x11.dpy, screen);

	x11.xw = XCreateSimpleWindow(x11.dpy, root, 0, 0,
				     (unsigned)w, (unsigned)h, 0,
				     BlackPixel(x11.dpy, screen),
				     WhitePixel(x11.dpy, screen));
	if (!x11.xw) {
		lwsl_err("%s: unable to create window\n", __func__);

		return 1;
	}

	x11.gc = XCreateGC(x11.dpy, x11.xw, 0, NULL);

	XSelectInput(x11.dpy, x11.xw, StructureNotifyMask | ExposureMask |
				    ButtonPressMask | KeyPressMask |
				    PointerMotionMask);

	x11.wm_delete = XInternAtom(x11.dpy, "WM_DELETE_WINDOW", False);
	XSetWMProtocols(x11.dpy, x11.xw, &x11.wm_delete, 1);

	XStoreName(x11.dpy, x11.xw, "lhp-browser");

	XMapWindow(x11.dpy, x11.xw);

	win_xi2_setup();

	return 0;
}

void
lhp_browser_plat_destroy(void)
{
	if (!x11.dpy)
		return;

	if (x11.ximg) {
		x11.ximg->data = NULL;
		XDestroyImage(x11.ximg);
		free(x11.xdata);
		x11.ximg = NULL;
		x11.xdata = NULL;
	}
	if (x11.gc) {
		XFreeGC(x11.dpy, x11.gc);
		x11.gc = NULL;
	}
	if (x11.xw) {
		XDestroyWindow(x11.dpy, x11.xw);
		x11.xw = 0;
	}

	XCloseDisplay(x11.dpy);
	x11.dpy = NULL;
}
