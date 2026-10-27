/*
 * lws-log-ingest web page
 *
 * The sessions the ingestor knows, a form to start another, and the log
 * shippers connected to it now, see
 * READMEs/README.log-ship.md for the api.
 *
 * Choosing a session shows its logs, either synchronised, a pane for each
 * source host side by side at one instant (log-ingest-sync.js), or merged, all
 * its lines in UTC order a page at a time.
 *
 * The page's fragment says what it's showing, eg
 *
 *   #session=0123456789abcdef[&view=merged][&at=<UTC us>]
 *
 * so other tools can link straight to a session, or a moment in one.  Choosing
 * a session goes in the history; moving the instant or changing the view just
 * updates the fragment in place.
 *
 * Everything from the api is untrusted, it only goes into the page as text.
 */

"use strict";

(function() {

	var mk, sync, cur = { session: null, view: "sync", obj: null },
	    sessions_json = null, polling = false, hash_timer = null,
	    merged = { loaded: false, next: null, srcs: new Map(), n: 0,
		       ctl: null };

	/* the LLL_ levels a session or query may name, most important first */
	var lvl_names = [ "err", "warn", "notice", "info", "debug" ];

	function $(id)
	{
		return document.getElementById(id);
	}

	/*
	 * The api, relative to us.  It answers JSON, or for a refusal it can
	 * explain, {"error":"why"}.  Anything else, eg, a login page from the
	 * front end, is an error.
	 */
	function api(path, signal, body)
	{
		var o = { credentials: "same-origin", cache: "no-store" };

		if (signal)
			o.signal = signal;
		if (body !== undefined) {
			o.method = "POST";
			o.headers = { "Content-Type": "application/json" };
			o.body = JSON.stringify(body);
		}

		return fetch(path, o).then((r) => r.text().then((t) => {
			var j = null;

			try {
				j = JSON.parse(t);
			} catch (e) {}

			if (!r.ok) {
				if (j && typeof j.error === "string")
					throw new Error(j.error);
				throw new Error(r.status === 403 ?
					"Not allowed: log in with the grant" :
					"The ingestor said " + r.status);
			}
			if (!j || typeof j !== "object")
				throw new Error("The ingestor's answer wasn't " +
						"JSON, are you logged in?");

			return j;
		}));
	}

	function status(s)
	{
		$("li_status").textContent = s || "";
	}

	function valid_id(s)
	{
		return typeof s === "string" && /^[0-9a-f]{16}$/.test(s);
	}

	/* a session's lvl mask, as the name it was started with */
	function lvl_mask_name(m)
	{
		var n, name = "as configured";

		for (n = 0; n < lvl_names.length; n++)
			if (m & (1 << n))
				name = lvl_names[n];

		return name;
	}

	function secs(s)
	{
		s = Math.round(s);
		if (s < 120)
			return s + "s";
		if (s < 7200)
			return Math.round(s / 60) + "m";

		return Math.round(s / 3600) + "h";
	}

	function button(text, cls, title)
	{
		var b = mk("button", cls, text);

		b.type = "button";
		if (title)
			b.title = title;

		return b;
	}

	/* ---- the fragment ---- */

	function hash_parse()
	{
		var h = new URLSearchParams(location.hash.substring(1)),
		    at = h.get("at"), r = {
			session: h.get("session"),
			view: h.get("view") === "merged" ? "merged" : "sync",
			at: null
		    };

		if (!valid_id(r.session))
			r.session = null;
		if (at && /^\d{1,17}$/.test(at))
			r.at = Number.parseInt(at, 10);

		return r;
	}

	function hash_make(at)
	{
		var s = "session=" + cur.session;

		if (cur.view === "merged")
			s += "&view=merged";
		if (typeof at === "number")
			s += "&at=" + Math.round(at);

		return "#" + s;
	}

	/* the same session, with the view or instant changed: no history */
	function hash_update()
	{
		if (hash_timer)
			clearTimeout(hash_timer);
		hash_timer = setTimeout(() => {
			hash_timer = null;
			if (cur.session)
				history.replaceState(null, "", hash_make(
					sync.ctx ? sync.T : undefined));
		}, 400);
	}

	/* what the fragment says, unless it's what we're showing already */
	function route()
	{
		var h = hash_parse();

		if (!h.session) {
			view_close();
			return;
		}

		if (h.session !== cur.session) {
			view_open(h.session, h.view, h.at);
			return;
		}

		if (h.view !== cur.view)
			view_set(h.view);
		if (h.at !== null && sync.ctx && h.at !== sync.T)
			sync.set_instant(h.at, null, true);
	}

	/* ---- the sessions ---- */

	function session_row(s)
	{
		var tr = mk("tr", "li-srow"), td, b, id;

		tr.classList.toggle("li-open", !!s.open);
		tr.classList.toggle("li-selected", s.session === cur.session);
		tr.title = "Show its logs";

		td = mk("td", "li-mono");
		id = mk("a", null, s.session);
		id.href = "#session=" + s.session;
		td.append(id);
		if (s.open)
			td.append(mk("span", "li-badge", "open"));
		tr.append(td);

		tr.append(mk("td", "li-mono li-opt", s.created),
			  mk("td", "li-mono", s.from),
			  mk("td", null, secs((s.until_us - s.from_us) / 1000000)),
			  mk("td", "li-opt", lvl_mask_name(s.lvl)),
			  mk("td", "li-mono", s.src || "all"),
			  mk("td", "li-opt", s.who || ""),
			  mk("td", "li-note", s.note || ""));

		td = mk("td");
		if (s.open) {
			b = button("Stop", "li-stop", "End the session now");
			b.addEventListener("click", (e) => {
				e.stopPropagation();
				session_stop(s.session);
			});
			td.append(b);
		}
		tr.append(td);

		tr.addEventListener("click", (e) => {
			/* the one we show already: just make room for it */
			if (s.session === cur.session) {
				e.preventDefault();
				$("li_top").open = false;
				return;
			}
			/* the link does it by itself */
			if (e.target.closest("a"))
				return;
			location.hash = "session=" + s.session;
		});

		return tr;
	}

	function sessions_render(list)
	{
		var tb = $("li_sessions_body"), tr, td;

		tb.replaceChildren();
		if (!list.length) {
			tr = mk("tr");
			td = mk("td", "li-none", "No sessions yet");
			td.colSpan = 9;
			tr.append(td);
			tb.append(tr);
			return;
		}
		list.forEach((s) => tb.append(session_row(s)));
	}

	function sessions_refresh()
	{
		return api("api/sessions")
			.then((j) => {
				var js = JSON.stringify(j.sessions), s;

				$("li_sessions_err").textContent = "";
				/* only redraw what changed, it's polled */
				if (js !== sessions_json) {
					sessions_json = js;
					sessions_render(j.sessions);
				}

				/* the one we show may have ended meanwhile */
				s = j.sessions.find((x) =>
						x.session === cur.session);
				if (s)
					view_session(s);
			})
			.catch((e) => {
				$("li_sessions_err").textContent = e.message;
			});
	}

	function session_stop(id)
	{
		return api("api/sessions/" + encodeURIComponent(id) + "/stop",
			   null, {})
			.then((s) => {
				status("Stopped session " + s.session);
				if (s.session === cur.session) {
					view_session(s);
					sync.refresh();
				}
				return sessions_refresh();
			})
			.catch((e) => status(e.message));
	}

	function session_start(e)
	{
		var b = {}, from = $("li_start_from").value.trim(),
		    dur = $("li_start_duration").value.trim(),
		    err = $("li_start_err");

		e.preventDefault();
		err.textContent = "";

		if (!/^\d+$/.test(from) || !/^\d+$/.test(dur)) {
			err.textContent = "From and For are whole seconds";
			return;
		}
		b.from = "-" + from;
		b.duration = Number.parseInt(dur, 10);
		if ($("li_start_lvl").value)
			b.lvl = $("li_start_lvl").value;
		if ($("li_start_src").value.trim())
			b.src = $("li_start_src").value.trim();
		if ($("li_start_note").value.trim())
			b.note = $("li_start_note").value.trim();

		$("li_start_go").disabled = true;
		api("api/sessions", null, b)
			.then((s) => {
				status("Started session " + s.session);
				$("li_start_note").value = "";
				sessions_refresh();
				location.hash = "session=" + s.session;
			})
			.catch((e) => {
				err.textContent = e.message;
			})
			.finally(() => {
				$("li_start_go").disabled = false;
			});
	}

	/* ---- the shippers ---- */

	function sources_render(j)
	{
		var ul = $("li_connected"), tb = $("li_recent_body"), now = Date.now();

		ul.replaceChildren();
		if (!j.connected.length)
			ul.append(mk("li", "li-none", "None connected"));
		j.connected.forEach((c) => {
			var li = mk("li", "li-shipper"), w = null;

			if (c.window_until)
				w = LwsLogSync.utc_us(c.window_until);
			li.classList.toggle("li-sending", w !== null);
			li.append(mk("span", "li-dot"),
				  mk("span", "li-kind", c.kind),
				  mk("span", "li-host", c.host));
			if (c.local)
				li.append(mk("span", "li-local", "local"));
			li.append(mk("span", "li-inst", c.inst),
				  mk("span", "li-window", w === null ? "idle" :
				     (c.local ? "keeping for " : "sending for ") +
				     secs(Math.max(0,
					w / 1000 - now) / 1000)));
			li.title = (c.local ? "The ingestor's own process, " +
				    "kept here without a connection\n" : "") +
				   (w === null ? "Not in a window" :
				    "In a window until " + c.window_until) +
				   "\nclick to add its host to the sources " +
				   "of a session to start";
			li.addEventListener("click", () => src_add(c.host));
			ul.append(li);
		});

		tb.replaceChildren();
		j.sources.forEach((s) => {
			var tr = mk("tr"), td = mk("td", "li-mono",
						    s.kind + "/" + s.host);

			td.title = "instance " + s.inst + "\nfirst " + s.first;
			tr.append(td, mk("td", "li-mono", s.last),
				  mk("td", null, s.lag_ms + "ms"));
			tb.append(tr);
		});
		$("li_recent_sum").textContent = "Sources seen in the last day (" +
						 j.sources.length + ")";
	}

	/* a host to the sources of the session being started, if not there */
	function src_add(host)
	{
		var el = $("li_start_src"), v = el.value.trim(),
		    a = v ? v.split(",") : [];

		if (a.indexOf(host) < 0)
			a.push(host);
		el.value = a.join(",");
	}

	function sources_refresh()
	{
		return api("api/sources")
			.then((j) => {
				status("");
				sources_render(j);
			})
			.catch((e) => status(e.message));
	}

	/* every few seconds, while anyone's looking */
	function poll()
	{
		if (polling || document.hidden)
			return;
		polling = true;
		Promise.all([ sources_refresh(), sessions_refresh() ])
			.finally(() => {
				polling = false;
			});
	}

	/* ---- the session's logs ---- */

	/* what the bar says about the session we show */
	function view_session(s)
	{
		var t = s.session + "  " + s.from + " for " +
			secs((s.until_us - s.from_us) / 1000000) +
			(s.open ? ", open" : "");

		cur.obj = s;
		if (s.note)
			t += "  — " + s.note;
		$("li_view_session").textContent = t;
		$("li_view_session").title = "src " + (s.src || "all") +
			", level " + lvl_mask_name(s.lvl) + ", by " +
			(s.who || "?");
		$("li_view_stop").classList.toggle("hidden", !s.open);
	}

	function view_open(id, view, at)
	{
		cur.session = id;
		cur.obj = null;
		$("li_view_session").textContent = id;
		$("li_view_stop").classList.add("hidden");

		/* the table marks the one we show */
		document.querySelectorAll("#li_sessions_body tr.li-srow")
			.forEach((tr) => {
				var a = tr.querySelector("a");

				tr.classList.toggle("li-selected",
					!!a && a.textContent === id);
			});

		/* it may not be among the latest in the table */
		api("api/sessions/" + id)
			.then((s) => {
				if (cur.session === id)
					view_session(s);
			})
			.catch((e) => {
				if (cur.session === id)
					status(e.message);
			});

		merged_reset();
		$("li_view").classList.remove("hidden");
		$("li_empty").classList.add("hidden");
		/* the logs want the room */
		$("li_top").open = false;

		cur.view = view;
		sync.open(id, at);
		view_set(view);
	}

	function view_close()
	{
		cur.session = null;
		cur.obj = null;
		sync.close();
		sync.set_active(false);
		merged_reset();
		$("li_view").classList.add("hidden");
		$("li_empty").classList.remove("hidden");
		document.querySelectorAll("#li_sessions_body tr.li-selected")
			.forEach((tr) => tr.classList.remove("li-selected"));
	}

	function view_set(v)
	{
		cur.view = v;
		$("li_tab_sync").classList.toggle("active", v === "sync");
		$("li_tab_sync").setAttribute("aria-selected", v === "sync");
		$("li_tab_merged").classList.toggle("active", v === "merged");
		$("li_tab_merged").setAttribute("aria-selected", v === "merged");
		$("li_sync").classList.toggle("hidden", v !== "sync");
		$("li_merged").classList.toggle("hidden", v !== "merged");

		sync.set_active(v === "sync");
		if (v === "merged" && !merged.loaded)
			merged_load(false);

		hash_update();
	}

	/* a line of the merged view in the synchronised one */
	function sync_at(t)
	{
		view_set("sync");
		if (sync.ctx && sync.session === cur.session)
			sync.set_instant(t, null, true);
		else
			sync.open(cur.session, t);
	}

	/* ---- the merged view ---- */

	function merged_reset()
	{
		if (merged.ctl)
			merged.ctl.abort();
		merged.ctl = null;
		merged.loaded = false;
		merged.next = null;
		merged.srcs.clear();
		merged.n = 0;
		$("li_merged_lines").replaceChildren();
		$("li_merged_count").textContent = "";
		$("li_merged_state").textContent = "";
		$("li_merged_more").classList.add("hidden");
	}

	function merged_row(l)
	{
		var row = mk("div", "li-mrow"), s = merged.srcs.get(l.src),
		    v = LwsLogSync.lvl(l.l), src;

		row.classList.add("li-l-" + v.name);
		src = mk("span", "li-msrc", s ? s.kind + "/" + s.host :
			 "#" + l.src);
		if (s)
			src.title = "instance " + s.inst + ", lag " +
				    s.lag_ms + "ms";
		row.append(mk("span", "li-mt", l.t), LwsLogSync.lvl_el(l.l), src,
			   mk("span", "li-mx", l.x || ""));
		row.title = "Click to see it synchronised";
		row.addEventListener("click", () => {
			var t = typeof l.t_us === "number" ? l.t_us :
					LwsLogSync.utc_us(l.t);

			/* don't take a text selection for a click */
			if (!Number.isNaN(t) && !String(window.getSelection()))
				sync_at(t);
		});

		return row;
	}

	/* the first page, or with more, the next one after what we have */
	function merged_load(more)
	{
		var id = cur.session, q = "api/logs?session=" +
			encodeURIComponent(id) + "&limit=500",
		    lvl = $("li_merged_lvl").value,
		    src = $("li_merged_src").value.trim(),
		    grep = $("li_merged_grep").value;

		if (!id)
			return;
		if (!more)
			merged_reset();
		else if (!merged.next)
			return;

		if (lvl)
			q += "&lvl=" + encodeURIComponent(lvl);
		if (src)
			q += "&src=" + encodeURIComponent(src);
		if (grep)
			q += "&grep=" + encodeURIComponent(grep);
		if (more)
			q += "&after=" + encodeURIComponent(merged.next);

		if (merged.ctl)
			merged.ctl.abort();
		merged.ctl = new AbortController();
		merged.loaded = true;
		$("li_merged_more").classList.add("hidden");
		$("li_merged_state").textContent = "...";

		api(q, merged.ctl.signal)
			.then((j) => {
				var frag = document.createDocumentFragment();

				if (id !== cur.session)
					return;
				j.sources.forEach((s) => merged.srcs.set(s.id, s));
				j.lines.forEach((l) => frag.append(merged_row(l)));
				$("li_merged_lines").append(frag);
				merged.n += j.lines.length;
				merged.next = j.truncated && j.next ? j.next : null;

				$("li_merged_count").textContent = merged.n +
					(merged.next ? "+" : "") + " lines, " +
					j.from + " to " + j.to;
				$("li_merged_more").classList.toggle("hidden",
							!merged.next);
				$("li_merged_state").textContent = merged.n ? "" :
					"No lines match";
			})
			.catch((e) => {
				if (e.name === "AbortError" || id !== cur.session)
					return;
				$("li_merged_state").textContent = e.message;
				/* so More can try it again */
				$("li_merged_more").classList.toggle("hidden",
							!merged.next);
			})
			.finally(() => {
				if (id === cur.session)
					merged.ctl = null;
			});
	}

	/* ---- starting up ---- */

	document.addEventListener("DOMContentLoaded", () => {
		mk = LwsLogSync.mk;

		sync = new LwsLogSync($("li_sync"), {
			api: api,
			on_instant: () => hash_update()
		});

		$("li_start").addEventListener("submit", session_start);
		$("li_tab_sync").addEventListener("click", () => view_set("sync"));
		$("li_tab_merged").addEventListener("click",
						    () => view_set("merged"));
		$("li_view_close").addEventListener("click", () => {
			history.pushState(null, "", location.pathname +
					  location.search);
			view_close();
		});
		$("li_view_stop").addEventListener("click", () => {
			if (cur.session)
				session_stop(cur.session);
		});
		$("li_merged_form").addEventListener("submit", (e) => {
			e.preventDefault();
			merged_load(false);
		});
		$("li_merged_more").addEventListener("click",
						     () => merged_load(true));

		/* when it's opened, it may want the sync view's room back */
		$("li_top").addEventListener("toggle", () => sync.relayout());

		window.addEventListener("hashchange", route);
		window.addEventListener("popstate", route);
		document.addEventListener("visibilitychange", poll);

		poll();
		setInterval(poll, 5000);
		route();
	});

}());
