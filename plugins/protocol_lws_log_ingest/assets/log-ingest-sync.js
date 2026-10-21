/*
 * lws-log-ingest synchronised logs
 *
 * Panes side by side, one for each source host with lines in a session's
 * window, see READMEs/README.log-ship.md.
 *
 * Every pane shows its lines either side of one instant, the line across the
 * middle of each.  The instant goes:
 *
 *  - line by line in a pane, with the wheel, the arrow keys or a finger
 *    dragged there, and the other panes follow it in time
 *  - anywhere in the session, with the time bar on the right, which is the
 *    session's window, padded
 *
 * What's in a pane comes from the ingestor a piece at a time, around the
 * instant, as it's needed: GET api/pane.  Panes are filled from the left, only
 * while they can be seen, and a fetch that's overtaken by a jump elsewhere is
 * cancelled.  While the session is still running, its window grows, and we
 * ask again what it is every few seconds.
 *
 * Panes can be reordered by dragging their header, sized by the splitter
 * after them, and folded to a narrow strip out of the way by double-clicking
 * the header.  The order and sizes are kept in localStorage by kind/host, so
 * a host's pane goes where it went last time, whichever session it is.
 *
 * Everything shown from the api is untrusted, so it only ever goes into the
 * page as text.  log-ingest.js creates it and says when it can be seen.
 */

"use strict";

class LwsLogSync {
	constructor(el, opts) {
		this.el = el;
		this.api = opts.api;		/* path, signal -> promise of JSON */
		this.on_instant = opts.on_instant;	/* the instant moved */

		this.ctx = null;		/* the answer to api/sync */
		this.session = null;		/* its session id */
		this.panes = [];
		this.T = 0;			/* the instant, UTC us */
		this.fetching = null;		/* the pane being filled */
		this.kick_timer = null;
		this.refresh_timer = null;
		this.gen = 0;			/* which open() we're on */
		this.active = false;		/* it can be seen */

		this.layout = this.layout_load();

		this.build();
	}

	/* ---- helpers the page shares ---- */

	/* an element, with a class and text, never markup */
	static mk(tag, cls, text) {
		var e = document.createElement(tag);

		if (cls)
			e.className = cls;
		if (text !== undefined && text !== null)
			e.textContent = String(text);

		return e;
	}

	/* UTC us -> "2026-10-14T11:58:02.123456Z" */
	static utc(t) {
		var s = new Date(Math.floor(t / 1000)).toISOString();

		return s.substring(0, 23) +
			String(Math.floor(t) % 1000).padStart(3, "0") + "Z";
	}

	/* ...the same, from the api's ISO form, back to us, or NaN */
	static utc_us(s) {
		var ms, us;

		if (typeof s !== "string" ||
		    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(s))
			return NaN;
		ms = Date.parse(s.substring(0, 23) + "Z");
		us = parseInt(s.substring(23, 26), 10);

		return ms * 1000 + us;
	}

	/*
	 * A line's level, the LLL_ bit, as a letter and a class.  It should
	 * be just one bit, but if not, the most important says it.
	 */
	static lvl(l) {
		var names = [ "err", "warn", "notice", "info", "debug", "parser",
			      "header", "ext", "client", "latency", "user",
			      "thread" ],
		    letters = "EWNIDPHXCLUT", n;

		for (n = 0; n < names.length; n++)
			if (l & (1 << n))
				return { c: letters[n], name: names[n] };

		return { c: "?", name: "unknown" };
	}

	static lvl_el(l) {
		var v = LwsLogSync.lvl(l), e = LwsLogSync.mk("span",
					"li-lvl li-lvl-" + v.name, v.c);

		e.title = v.name;

		return e;
	}

	/* ---- what we keep in localStorage ---- */

	static get LS_LAYOUT() { return "lws-log-ingest-sync-layout"; }

	layout_load() {
		var l = null;

		try {
			l = JSON.parse(localStorage.getItem(LwsLogSync.LS_LAYOUT));
		} catch (e) {}
		if (!l || !Array.isArray(l.order) || typeof l.widths !== "object" ||
		    !l.widths)
			l = { order: [], widths: {} };
		/* the width a folded pane unfolds to */
		if (typeof l.unfold !== "object" || !l.unfold)
			l.unfold = {};

		return l;
	}

	layout_save() {
		try {
			localStorage.setItem(LwsLogSync.LS_LAYOUT,
					     JSON.stringify(this.layout));
		} catch (e) {}
	}

	/* ---- the furniture ---- */

	build() {
		var mk = LwsLogSync.mk, bar = mk("div", "sync-bar"),
		    body = mk("div", "sync-body");

		this.start_btn = mk("button", "sync-jump", "\u21e4");
		this.start_btn.type = "button";
		this.start_btn.title = "Go to the start of the session";
		this.end_btn = mk("button", "sync-jump", "\u21e5");
		this.end_btn.type = "button";
		this.end_btn.title = "Go to the end of the session, or now " +
				     "while it's running";
		this.instant_el = mk("span", "sync-instant");
		this.instant_el.title = "The instant across the middle of " +
					"every pane, in UTC, and how far into " +
					"the session it is";
		this.hint_el = mk("span", "sync-hint");

		bar.append(this.start_btn, this.instant_el, this.end_btn,
			   this.hint_el);

		this.panes_el = mk("div", "sync-panes");
		this.time_el = mk("div", "sync-time");
		this.time_el.title = "The session's window: click or drag to " +
				     "go anywhere in it";
		this.time_run_el = mk("div", "sync-time-run hidden");
		this.thumb_el = mk("div", "sync-time-thumb hidden");
		this.time_el.append(this.time_run_el, this.thumb_el);
		body.append(this.panes_el, this.time_el);

		this.el.append(bar, body);

		this.start_btn.addEventListener("click", () => {
			if (this.ctx)
				this.set_instant(this.ctx.start_us, null, true);
		});
		this.end_btn.addEventListener("click", () => {
			if (this.ctx)
				this.set_instant(this.ctx.end_us, null, true);
		});

		this.time_bar_events();

		this.panes_el.addEventListener("scroll", () => this.kick());

		if (window.ResizeObserver)
			new ResizeObserver(() => this.relayout()).observe(body);
	}

	hint(s) {
		this.hint_el.textContent = s || "";
	}

	/* log-ingest.js says when we can be seen, and are worth filling */
	set_active(a) {
		this.active = !!a;
		if (!this.active)
			return;
		this.relayout();
		if (this.ctx && this.ctx.running)
			this.refresh();
		this.kick();
	}

	/* ---- a session to look at ---- */

	/* forget the session we were showing */
	close() {
		this.gen++;
		this.panes.forEach((p) => this.pane_drop(p));
		this.panes = [];
		this.panes_el.replaceChildren();
		this.fetching = null;
		if (this.refresh_timer)
			clearInterval(this.refresh_timer);
		this.refresh_timer = null;
		if (this.kick_timer)
			clearTimeout(this.kick_timer);
		this.kick_timer = null;
		this.ctx = null;
		this.session = null;
		this.instant_el.textContent = "";
		this.time_run_el.classList.add("hidden");
		this.thumb_el.classList.add("hidden");
		this.hint("");
	}

	/* show session id, at UTC us at, or its start without one */
	open(id, at) {
		var gen, q = "api/sync?session=" + encodeURIComponent(id);

		this.close();
		gen = this.gen;
		this.session = id;

		if (typeof at === "number" && isFinite(at))
			q += "&at=" + Math.max(0, Math.round(at));

		this.hint("Finding out about the session...");

		return this.api(q)
			.then((j) => {
				if (gen !== this.gen)
					return;
				this.set_ctx(j);
				this.set_instant(j.at_us, null, true);
			})
			.catch((e) => {
				if (gen === this.gen)
					this.hint(e.message);
			});
	}

	panes_hint() {
		var c = this.ctx;

		this.hint(c && !c.panes.length ? (c.running ?
			"No source has sent lines in the window yet" :
			"No source sent lines in the window") : "");
	}

	set_ctx(j) {
		this.ctx = j;
		this.time_run_el.classList.remove("hidden");
		this.thumb_el.classList.remove("hidden");

		this.order(j.panes).forEach((d) => this.pane_add(d));
		this.panes_hint();

		this.refresh_timer = j.running ?
			setInterval(() => this.refresh(), 5000) : null;

		this.time_bar_render();
	}

	/*
	 * While the session is going, its window grows, and the panes at its
	 * end have more to show
	 */
	refresh() {
		var c = this.ctx, gen = this.gen;

		if (!c || !this.active)
			return;

		this.api("api/sync?session=" + encodeURIComponent(this.session) +
			 "&at=" + Math.round(this.T))
			.catch(() => null)
			.then((j) => {
				if (!j || gen !== this.gen)
					return;

				c.end_us = j.end_us;
				c.to_us = j.to_us;
				c.running = j.running;
				if (!j.running && this.refresh_timer) {
					clearInterval(this.refresh_timer);
					this.refresh_timer = null;
				}

				/* hosts that have spoken up since */
				this.order(j.panes).forEach((d) => {
					if (!this.panes.find((p) => p.id === d.pane)) {
						c.panes.push(d);
						this.pane_add(d);
					}
				});
				this.panes_hint();

				this.panes.forEach((p) => {
					if (!p.more_after)
						p.stale = true;
				});

				this.instant_render();
				this.time_bar_render();
				this.kick();
			});
	}

	/* what a pane is, for remembering where it goes and how wide it is */
	static pane_key(d) {
		return d.kind + "/" + d.host;
	}

	/* the remembered order first, then the rest as the ingestor had them */
	order(ds) {
		var o = this.layout.order;

		return ds.map((d, i) => ({ d: d, i: i,
					   at: o.indexOf(LwsLogSync.pane_key(d)) }))
			.sort((a, b) => {
				if (a.at >= 0 && b.at >= 0)
					return a.at - b.at;
				if (a.at >= 0 || b.at >= 0)
					return a.at >= 0 ? -1 : 1;
				return a.i - b.i;
			})
			.map((x) => x.d);
	}

	pane_add(d) {
		var mk = LwsLogSync.mk, p = {
			id: d.pane, d: d, key: LwsLogSync.pane_key(d),
			rows: [], els: null, more_before: false,
			more_after: false, loaded: false, stale: false,
			ctl: null, k: -1, wheel: 0, line_h: 14
		}, w = this.layout.widths[p.key], s, name;

		p.el = mk("div", "sync-pane");
		p.head = mk("div", "sync-pane-head");
		p.head.draggable = true;
		name = mk("span", "sync-pane-name");
		name.append(mk("span", "sync-pane-kind", d.kind),
			    document.createTextNode(" " + d.host));
		p.delta_el = mk("span", "sync-pane-delta");
		p.head.append(name, p.delta_el);

		p.view = mk("div", "sync-pane-view");
		p.view.tabIndex = 0;
		p.scroll = mk("div", "sync-pane-scroll");
		p.text = mk("div", "sync-pane-text");
		p.state_el = mk("div", "sync-pane-state");
		p.scroll.append(p.text);
		p.view.append(p.scroll, mk("div", "sync-pane-cursor"),
			      p.state_el);
		p.el.append(p.head, p.view);

		s = d.kind + " " + d.host + "\nits clock was " + d.lag_ms +
		    "ms behind the ingestor's, or its lines waited that long";
		if (d.insts > 1)
			s += "\n" + d.insts + " instances of it in the window, " +
			     "eg, it restarted";
		p.head.title = s + "\ndrag to move it, double-click to fold or " +
			       "unfold it";

		p.split = mk("div", "sync-split");
		p.split.title = "Drag to size the pane before it";

		this.panes_el.append(p.el, p.split);
		this.panes.push(p);

		this.pane_width(p, typeof w === "number" ? w : 420);
		this.pane_events(p);
		this.split_events(p);
		this.pane_text_pad(p);
	}

	pane_drop(p) {
		if (p.ctl)
			p.ctl.abort();
		p.ctl = null;
	}

	/* narrow enough and it's folded out of the way */
	pane_width(p, w) {
		p.width = Math.max(14, w);
		p.el.style.flex = "0 0 " + p.width + "px";
		p.el.classList.toggle("folded", p.width < 48);
	}

	pane_events(p) {
		p.view.addEventListener("wheel", (e) => {
			var n;

			e.preventDefault();
			/*
			 * A step a line: a wheel's notch is usually 3 lines,
			 * or about 100px, and a touchpad's is a little at a
			 * time
			 */
			p.wheel += e.deltaMode === 1 ? e.deltaY * 33 :
				   (e.deltaMode === 2 ? e.deltaY * 660 :
				    e.deltaY);
			n = Math.trunc(p.wheel / 33);
			if (!n)
				return;
			p.wheel -= n * 33;
			this.step(p, n);
		}, { passive: false });

		p.view.addEventListener("keydown", (e) => {
			var n = { ArrowDown: 1, ArrowUp: -1, PageDown: 20,
				  PageUp: -20 }[e.key];

			if (n) {
				e.preventDefault();
				this.step(p, n);
			}
		});

		/* a finger drags the instant along the pane */
		p.view.addEventListener("touchstart", (e) => {
			if (e.touches.length === 1)
				p.touch_y = e.touches[0].clientY;
		}, { passive: true });
		p.view.addEventListener("touchmove", (e) => {
			var y, n;

			if (e.touches.length !== 1 || p.touch_y === undefined)
				return;
			e.preventDefault();
			y = e.touches[0].clientY;
			n = Math.trunc((p.touch_y - y) / 16);
			if (n) {
				p.touch_y -= n * 16;
				this.step(p, n);
			}
		}, { passive: false });

		p.head.addEventListener("dblclick", () => {
			var w = p.width < 48 ? (this.layout.unfold[p.key] ||
					      420) : 14;

			if (p.width >= 48)
				this.layout.unfold[p.key] = p.width;
			this.pane_width(p, w);
			this.layout.widths[p.key] = p.width;
			this.layout_save();
			this.relayout();
			this.kick();
		});

		/* reordering, by dragging the header onto another */
		p.head.addEventListener("dragstart", (e) => {
			e.dataTransfer.setData("text/plain", p.id);
			e.dataTransfer.effectAllowed = "move";
			this.dragging = p;
		});
		p.head.addEventListener("dragend", () => {
			this.dragging = null;
			this.panes.forEach((x) =>
				x.el.classList.remove("drop-before",
						      "drop-after"));
		});
		p.el.addEventListener("dragover", (e) => {
			var r, after;

			if (!this.dragging || this.dragging === p)
				return;
			e.preventDefault();
			r = p.el.getBoundingClientRect();
			after = e.clientX > r.left + r.width / 2;
			p.el.classList.toggle("drop-after", after);
			p.el.classList.toggle("drop-before", !after);
		});
		p.el.addEventListener("dragleave", () => {
			p.el.classList.remove("drop-before", "drop-after");
		});
		p.el.addEventListener("drop", (e) => {
			var from = this.dragging, after;

			e.preventDefault();
			after = p.el.classList.contains("drop-after");
			p.el.classList.remove("drop-before", "drop-after");
			if (from && from !== p)
				this.pane_move(from, p, after);
		});
	}

	/*
	 * The splitter after a pane sizes it.  Pointer capture keeps the drag
	 * ours wherever the pointer goes, and touch-action: none on it in the
	 * css stops a finger on it being taken for a scroll.
	 */
	split_events(p) {
		var x0 = 0, w0 = 0, end = (e) => {
			if (!p.split.hasPointerCapture(e.pointerId))
				return;
			p.split.releasePointerCapture(e.pointerId);
			p.split.classList.remove("dragging");
			this.layout.widths[p.key] = p.width;
			this.layout_save();
			this.relayout();
			this.kick();
		};

		p.split.addEventListener("pointerdown", (e) => {
			if (e.button !== 0)
				return;
			e.preventDefault();
			p.split.setPointerCapture(e.pointerId);
			p.split.classList.add("dragging");
			x0 = e.clientX;
			w0 = p.el.getBoundingClientRect().width;
		});
		p.split.addEventListener("pointermove", (e) => {
			if (!p.split.hasPointerCapture(e.pointerId))
				return;
			this.pane_width(p, Math.round(w0 + e.clientX - x0));
			this.pane_position(p);
		});
		p.split.addEventListener("pointerup", end);
		p.split.addEventListener("pointercancel", end);
	}

	pane_move(p, to, after) {
		var ref = after ? to.split.nextSibling : to.el;

		this.panes_el.insertBefore(p.el, ref);
		this.panes_el.insertBefore(p.split, ref);

		this.panes.splice(this.panes.indexOf(p), 1);
		this.panes.splice(this.panes.indexOf(to) + (after ? 1 : 0), 0, p);

		/* the panes we have now, in front of any we don't */
		this.layout.order = this.panes.map((x) => x.key).concat(
			this.layout.order.filter((k) =>
				!this.panes.find((x) => x.key === k)));
		this.layout_save();
		this.kick();
	}

	/*
	 * Room above the first line and below the last, so either can sit on
	 * the instant line in the middle
	 */
	pane_text_pad(p) {
		var h = Math.round(p.view.clientHeight / 2) + "px";

		p.text.style.paddingTop = h;
		p.text.style.paddingBottom = h;
	}

	relayout() {
		this.panes.forEach((p) => {
			this.pane_text_pad(p);
			this.pane_position(p);
		});
		this.time_bar_render();
	}

	/* ---- the instant ---- */

	/*
	 * origin is the pane it was stepped in, if any.  A jump is a move
	 * that leaves what the panes have behind, so what they're fetching
	 * is no use.
	 */
	set_instant(T, origin, jump) {
		var c = this.ctx;

		if (!c)
			return;
		this.T = Math.min(Math.max(T, c.from_us), c.to_us);

		if (jump)
			this.panes.forEach((p) => {
				if (p.ctl && p !== origin) {
					p.ctl.abort();
					p.ctl = null;
				}
			});

		this.instant_render();
		this.panes.forEach((p) => this.pane_position(p));
		this.time_bar_render();
		this.kick(jump);

		if (this.on_instant)
			this.on_instant(this.T);
	}

	instant_render() {
		var c = this.ctx, rel;

		if (!c)
			return;

		rel = (this.T - c.start_us) / 1000000;
		this.instant_el.textContent = LwsLogSync.utc(this.T) + " " +
			(rel < 0 ? "-" : "+") + Math.abs(rel).toFixed(6) + "s";
	}

	/* the pane's last row at or before the instant, or -1 */
	pane_k(p) {
		var lo = 0, hi = p.rows.length - 1, k = -1, m;

		while (lo <= hi) {
			m = (lo + hi) >> 1;
			if (p.rows[m].t <= this.T) {
				k = m;
				lo = m + 1;
			} else
				hi = m - 1;
		}

		return k;
	}

	/*
	 * n lines on in pane p, or back, by the times of its rows: rows logged
	 * in the same us are one step.  At the end of what the pane has, it
	 * fetches more and the step waits for it.
	 */
	step(p, n) {
		var r = p.rows, k = this.pane_k(p), t;

		if (!r.length)
			return;

		if (n > 0) {
			if (k < 0) {
				k = 0;
				n--;
			}
			while (n-- > 0) {
				t = r[k].t;
				while (k < r.length - 1 && r[k].t === t)
					k++;
				if (r[k].t === t)
					break;	/* that's all it has */
			}
		} else {
			if (k < 0)
				return;
			/* to the first row of the instant's time */
			while (k > 0 && r[k - 1].t === r[k].t)
				k--;
			while (n++ < 0 && k > 0) {
				k--;
				while (k > 0 && r[k - 1].t === r[k].t)
					k--;
			}
		}

		this.set_instant(r[k].t, p, false);
	}

	/* the instant on the line in the middle, and its rows marked */
	pane_position(p) {
		var k, k0, i, els = p.els, top, d;

		if (!els)
			return;

		els.forEach((e) => e.classList.remove("sync-now"));
		p.delta_el.textContent = "";

		k = this.pane_k(p);
		p.k = k;
		if (k < 0) {
			/* before its first row: that's just after the line */
			top = els.length ? els[0].offsetTop - p.line_h : 0;
		} else {
			for (k0 = k; k0 > 0 && p.rows[k0 - 1].t === p.rows[k].t;
			     k0--)
				;
			for (i = k0; i <= k; i++)
				els[i].classList.add("sync-now");
			top = els[k].offsetTop;
			d = (p.rows[k].t - this.T) / 1000000;
			if (d)
				p.delta_el.textContent = d.toFixed(3) + "s";
		}

		/* the middle of its line on the line */
		p.scroll.scrollTop = Math.max(0, top + Math.round(p.line_h / 2) -
				Math.round(p.view.clientHeight / 2));
	}

	/* ---- filling the panes ---- */

	/*
	 * Whether a pane needs more around the instant: it has nothing yet,
	 * the instant is past what it has, or near the end of it with more
	 * there
	 */
	pane_needs(p) {
		var k, margin = 40;

		/* it failed here, until the instant moves */
		if (p.failed_at === this.T)
			return false;
		if (!p.loaded || p.stale)
			return true;

		k = this.pane_k(p);
		if (p.more_before && k < margin)
			return true;
		if (p.more_after && k > p.rows.length - 1 - margin)
			return true;

		return false;
	}

	/* folded, or scrolled out of sight, it can wait */
	pane_visible(p) {
		var r = p.el.getBoundingClientRect(),
		    v = this.panes_el.getBoundingClientRect();

		return p.width >= 48 && r.right > v.left && r.left < v.right;
	}

	/*
	 * Fill the panes soon.  After a jump, wait until it's stopped moving,
	 * eg, the time bar being dragged, so we only fetch where it ends up.
	 */
	kick(jump) {
		if (this.kick_timer) {
			if (!jump)
				return;
			clearTimeout(this.kick_timer);
		}
		this.kick_timer = setTimeout(() => {
			this.kick_timer = null;
			this.fill();
		}, jump ? 150 : 60);
	}

	/* one at a time, from the left */
	fill() {
		var p, gen = this.gen;

		if (this.fetching || !this.active || !this.ctx)
			return;

		p = this.panes.find((x) => this.pane_visible(x) &&
					   this.pane_needs(x));
		if (!p)
			return;

		this.fetching = p;
		this.pane_fetch(p).finally(() => {
			/* a close() in the meanwhile has started afresh */
			if (gen !== this.gen)
				return;
			this.fetching = null;
			this.fill();
		});
	}

	pane_fetch(p) {
		var at = Math.round(this.T), gen = this.gen,
		    q = "api/pane?pane=" + encodeURIComponent(p.id) + "&at=" + at +
			"&before=150&after=150";

		p.ctl = new AbortController();
		if (!p.loaded)
			p.state_el.textContent = "...";

		return this.api(q, p.ctl.signal)
			.then((j) => {
				if (gen !== this.gen)
					return;
				p.rows = j.before.concat(j.after);
				p.more_before = !!j.more_before;
				p.more_after = !!j.more_after;
				p.loaded = true;
				p.stale = false;
				p.failed_at = undefined;
				p.state_el.textContent = p.rows.length ? "" :
						"nothing around then";
				this.pane_render(p);
				this.pane_position(p);
			})
			.catch((e) => {
				if (e.name === "AbortError" || gen !== this.gen)
					return;
				p.failed_at = at;
				p.state_el.textContent = e.message;
			})
			.finally(() => {
				p.ctl = null;
			});
	}

	/* ---- drawing a pane ---- */

	pane_render(p) {
		var mk = LwsLogSync.mk, frag = document.createDocumentFragment(),
		    src = null;

		p.els = [];
		p.rows.forEach((r) => {
			var row = mk("div", "sync-row"), v = LwsLogSync.lvl(r.l);

			row.classList.add("li-l-" + v.name);
			if (src !== null && r.s !== src)
				frag.append(mk("div", "sync-inst",
					       "another instance of " +
					       p.d.host));
			src = r.s;

			/* the time of day to the us; the date's in the bar */
			row.append(mk("span", "sync-t",
				      LwsLogSync.utc(r.t).substring(11, 26)),
				   LwsLogSync.lvl_el(r.l),
				   document.createTextNode(" " + (r.x || "")));
			frag.append(row);
			p.els.push(row);
		});

		p.text.replaceChildren(frag);
		p.line_h = parseFloat(getComputedStyle(p.text).lineHeight) || 14;
	}

	/* ---- the time bar: the session's window, top to bottom ---- */

	time_y(t) {
		var c = this.ctx, h = this.time_el.clientHeight;

		return Math.round((t - c.from_us) /
				  Math.max(1, c.to_us - c.from_us) * h);
	}

	time_bar_render() {
		var c = this.ctx, y0, y1;

		if (!c || !this.time_el.clientHeight)
			return;

		y0 = this.time_y(c.start_us);
		y1 = this.time_y(c.end_us);
		this.time_run_el.style.top = y0 + "px";
		this.time_run_el.style.height = Math.max(2, y1 - y0) + "px";
		this.time_run_el.classList.toggle("running", !!c.running);
		this.thumb_el.style.top = (this.time_y(this.T) - 1) + "px";
	}

	time_bar_events() {
		var to_t = (e) => {
			var c = this.ctx, r = this.time_el.getBoundingClientRect();

			return c.from_us + Math.round(Math.min(1, Math.max(0,
				(e.clientY - r.top) / r.height)) *
				(c.to_us - c.from_us));
		}, end = (e) => {
			if (this.time_el.hasPointerCapture(e.pointerId))
				this.time_el.releasePointerCapture(e.pointerId);
			this.time_el.classList.remove("dragging");
		};

		this.time_el.addEventListener("pointerdown", (e) => {
			if (!this.ctx || e.button !== 0)
				return;
			e.preventDefault();
			this.time_el.setPointerCapture(e.pointerId);
			this.time_el.classList.add("dragging");
			this.set_instant(to_t(e), null, true);
		});
		this.time_el.addEventListener("pointermove", (e) => {
			if (this.ctx && this.time_el.hasPointerCapture(e.pointerId))
				this.set_instant(to_t(e), null, true);
		});
		this.time_el.addEventListener("pointerup", end);
		this.time_el.addEventListener("pointercancel", end);
	}
}
