(function() {

	var server_max_size = 0, username = "", ws;

	/* most text we will pull into the textarea from a shared file */
	var max_text_view = 1024 * 1024;

	function san(s)
	{
		if (!s)
			return "";
               return s.replace(/&/g, "&amp;").
               replace(/\</g, "&lt;").
               replace(/\>/g, "&gt;").
               replace(/\"/g, "&quot;").
               replace(/%/g, "&#37;");
	}

	function pad(n) {
		return n < 10 ? '0' + n : n;
	}

	/*
	 * Everything we build a URL from here is a single path segment (a
	 * filename), so it must be escaped with encodeURIComponent(), not
	 * encodeURI(): encodeURI() deliberately passes the reserved set
	 * through, so a name containing '#', '?', '/' or '&' would change
	 * which resource the URL names.
	 */
	function lws_urlencode(s)
	{
		return encodeURIComponent(s);
	}

	function trim(num)
	{
		var s = num.toString();

		if (!s.indexOf("."))
			return s;

		while (s.length && s[s.length - 1] === "0")
			s = s.substring(0, s.length - 1);

		if (s[s.length - 1] === ".")
			s = s.substring(0, s.length - 1);

		return s;
	}

	function humanize(n)
	{
		if (typeof n !== 'number')
			return "NaN";

		if (n < 1024)
			return san(n + "B");

		if (n < 1024 * 1024)
			return san(trim((n / 1024).toFixed(2)) + "KiB");

		if (n < 1024 * 1024 * 1024)
			return san(trim((n / (1024 * 1024)).toFixed(2)) + "MiB");

		return san(trim((n / (1024 * 1024 * 1024)).toFixed(2)) + "GiB");
	}

	function da_enter(e)
	{
		var da = document.getElementById("da");

		e.preventDefault();
		da.classList.add("trot");
	}

	function da_leave(e)
	{
		var da = document.getElementById("da");

		e.preventDefault();
		da.classList.remove("trot");
	}

	function da_over(e)
	{
		var da = document.getElementById("da");

		e.preventDefault();
		da.classList.add("trot");
	}

	function clear_errors() {
		var n, t = document.getElementById("ongoing-tbody");

		for (n = 0; n < t.rows.length; n++)
			if (t.rows[n].cells[0].classList.contains("err"))
				t.deleteRow(n);
	}

	/*
	 * Generic uploader: takes FormData, a display name and a display size
	 */
	function _do_upload(formData, displayName, displaySize) {
		var t = document.getElementById("ongoing-tbody");
		var row = t.insertRow(0), c1 = row.insertCell(0),
		    c2 = row.insertCell(1), c3 = row.insertCell(2);

		c1.classList.add("ogn");
		c1.classList.add("r");

		if (displaySize > server_max_size) {
			c1.innerHTML = "Too Large";
			c1.classList.add("err");
		} else
			c1.innerHTML = "<img class=\"working\">";

		c2.classList.add("ogn");
		c2.classList.add("r");
		c2.innerHTML = humanize(displaySize);

		c3.classList.add("ogn");
		c3.innerHTML = san(displayName);

		if (displaySize > server_max_size)
			return;

		fetch("upload/" + lws_urlencode(displayName), {
			method: "POST",
			body: formData,
			credentials: "same-origin" /* Tells browser to send auth header */
		})
		.then((e) => { /* this just means we got a response code */
			if (e.ok === true) {
				if (row && row.parentNode)
					row.parentNode.removeChild(row);
			} else {
				c1.textContent = "Failed " + san(e.status.toString());
				c1.classList.remove("working");
				c1.classList.add("err");
			}
		})
		.catch((e) => {
			c1.textContent = "FAIL";
			c1.classList.remove("working");
			c1.classList.add("err");
		});
	}

	function do_upload(file) {
		var formData = new FormData(),
		    displayName = file.name;

		if (!username) { // Do not allow unauthenticated file uploads
			alert("You must be logged in to upload files.");
			return;
		}

		// The server is authoritative for the filename, we send the original.
		formData.append("file", file, displayName);
		_do_upload(formData, file.name, file.size);
	}

	function da_drop(e) {
		var da = document.getElementById("da");

		e.preventDefault();
		da.classList.remove("trot");

		clear_errors();

		([...e.dataTransfer.files]).forEach(do_upload);
	}

	function upl_button(e) {
		var fi = document.getElementById("file");

		clear_errors();
		e.preventDefault();

		([...fi.files]).forEach(do_upload);
	}

	function upl_text_button(e) {
		var content = document.getElementById("text_content"),
		    d = new Date(),
		    ts = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' +
		         pad(d.getDate()) + '_' + pad(d.getHours()) + '-' +
			 pad(d.getMinutes()) + '-' + pad(d.getSeconds()),
		    generated_filename,
		    formData = new FormData(), blob;

		e.preventDefault();

		if (!username) { // Do not allow unauthenticated text uploads
			alert("You must be logged in to upload text.");
			return;
		}
		clear_errors();

		// Server is authoritative for prefixing, just generate a unique name
		generated_filename = ts + '.txt';

		blob = new File([content.value], generated_filename, { type: "text/plain" });
		formData.append("file", blob, generated_filename);

		_do_upload(formData, generated_filename, blob.size);
		content.value = "";
		text_inp(); // Manually update button state after clearing
	}

	/*
	 * `filename` is the original, unescaped name as it arrived in the
	 * listing JSON, held in the click closure.  Do not recover it from the
	 * markup: the HTML parser decodes the escaping san() applied, so what
	 * comes back out of the attribute is the raw name again.  And compose
	 * the request with JSON.stringify() rather than by concatenation, so a
	 * name containing a quote or a backslash cannot forge the message.
	 */
	function delfile(e, filename)
	{
		e.stopPropagation();
		e.preventDefault();

		if (ws && ws.readyState === WebSocket.OPEN)
			ws.send(JSON.stringify({ del: filename }));
	}

	/*
	 * The drop is shared, so this loads content another user uploaded.  It
	 * goes into the textarea only: the clipboard is the user's, and is not
	 * ours to overwrite as a side effect of viewing a file.  "Copy" does
	 * that, when the user asks for it.
	 */
	function load_text(e, filename)
	{
		var content = document.getElementById("text_content");

		e.stopPropagation();
		e.preventDefault();

		fetch("get/" + lws_urlencode(filename), {
			credentials: "same-origin"
		})
		.then(response => response.text())
		.then(text => {
			if (text.length > max_text_view)
				text = text.substring(0, max_text_view);
			content.value = text;
			content.select();
			text_inp();
		})
		.catch((ex) => { console.error("load_text failed", ex); });
	}

	function copy_text_button(e)
	{
		var content = document.getElementById("text_content");

		e.preventDefault();

		content.select();
		if (navigator.clipboard)
			navigator.clipboard.writeText(content.value).
				catch((ex) => { console.error("clipboard", ex); });
	}

	function body_drop(e) {
		e.preventDefault();
	}

	function file_inp() {
		var fi = document.getElementById("file"),
		upl = document.getElementById("upl");
		upl.disabled = !fi.files.length;
	}

	function text_inp() {
		var content = document.getElementById("text_content"),
		    upl_text = document.getElementById("upl_text"),
		    copy_text = document.getElementById("copy_text");
		upl_text.disabled = !content.value.length;
		if (copy_text)
			copy_text.disabled = !content.value.length;
	}

	function get_appropriate_ws_url(extra_url) {
		var pcol,
		    url = new URL(document.URL);

		if (url.protocol === "https:") {
			pcol = "wss://";
		} else {
			pcol = "ws://";
		}

		var path = url.pathname;
		/*
		 * If the path looks like it has a filename (eg, contains a '.'),
		 * then get its parent directory. Otherwise, use the path as-is.
		 * This makes it robust for vhost paths like /.../docrepo/ vs
		 * /.../docrepo/index.html
		 */
		if (path.split('/').pop().indexOf('.') !== -1)
			path = path.substring(0, path.lastIndexOf('/') + 1);

		return pcol + url.host + path + extra_url;
	}

	function new_ws(urlpath, protocol)
	{
		return new WebSocket(urlpath, protocol);
	}

	/* Reconnection logic */
	const initial_reconnect_delay = 1000;
	const max_reconnect_delay = 30000;
	let current_reconnect_delay = initial_reconnect_delay;

	let tabId = sessionStorage.getItem('ddTabId');
	if (!tabId) {
		tabId = Math.random().toString(36).substring(2, 10);
		sessionStorage.setItem('ddTabId', tabId);
	}

	function updateTable(tbodyId, rowDataArray, rowIdFn, createRowHtmlFn, postUpdateFn) {
		var tbody = document.getElementById(tbodyId);
		if (!tbody) return;

		var existingRows = {};
		for (var i = 0; i < tbody.children.length; i++) {
			var tr = tbody.children[i];
			if (tr.id) existingRows[tr.id] = tr;
		}

		var newRows = {};
		rowDataArray.forEach(function(item, index) {
			var id = rowIdFn(item, index);
			newRows[id] = item;
			var tr = existingRows[id];
			var newHtml = createRowHtmlFn(item, index);
			
			if (!tr) {
				tr = document.createElement("tr");
				tr.id = id;
				tr.innerHTML = newHtml;
				tr.classList.add("fade-in");
				tr.setAttribute("data-content", newHtml);
			} else {
				if (tr.getAttribute("data-content") !== newHtml) {
					tr.innerHTML = newHtml;
					tr.setAttribute("data-content", newHtml);
					tr.classList.remove("fade-in");
					void tr.offsetWidth; // trigger reflow
					tr.classList.add("fade-in");
				}
			}

			/* Place it in the correct order in the DOM, ignoring fade-out rows */
			var targetNode = tbody.children[index];
			/* If the row is already in the right place, do nothing. 
			 * Otherwise, insert it before the current node at this index.
			 * (If targetNode is null, it appends to the end) */
			if (targetNode !== tr) {
				tbody.insertBefore(tr, targetNode);
			}

			if (postUpdateFn) postUpdateFn(tr, item, index);
		});

		for (var id in existingRows) {
			if (!newRows[id]) {
				var tr = existingRows[id];
				if (!tr.classList.contains("fade-out")) {
					tr.classList.add("fade-out");
					setTimeout((function(el) { 
						return function() { 
							if (el.parentNode) el.parentNode.removeChild(el); 
						}; 
					})(tr), 500);
				}
			}
		}
	}

	document.addEventListener("DOMContentLoaded", function() {
		console.log("deaddrop DOMContentLoaded fired. lws-login status: ", typeof renderLwsLoginStatus);
		if (typeof renderLwsLoginStatus === 'function')
			renderLwsLoginStatus("user-info");
		else
			console.log("renderLwsLoginStatus is NOT A FUNCTION!");

		var da = document.getElementById("da"),
		    fi = document.getElementById("file"),
		    upl = document.getElementById("upl"),
		    text_content = document.getElementById("text_content"),
		    upl_text = document.getElementById("upl_text"),
		    copy_text = document.getElementById("copy_text");

		da.addEventListener("dragenter", da_enter, false);
		da.addEventListener("dragleave", da_leave, false);
		da.addEventListener("dragover", da_over, false);
		da.addEventListener("drop", da_drop, false);

		upl.addEventListener("click", upl_button, false);
		fi.addEventListener("change", file_inp, false);

		upl_text.addEventListener("click", upl_text_button, false);
		if (copy_text)
			copy_text.addEventListener("click", copy_text_button, false);
		text_content.addEventListener("input", text_inp, false);

		window.addEventListener("dragover", body_drop, false);
		window.addEventListener("drop", body_drop, false);

		function connect_ws() {
			ws = new_ws(get_appropriate_ws_url("?tabId=" + tabId), "lws-deaddrop");
			try {
				ws.onopen = function() {
					console.log("WebSocket connection established.");
					var dd = document.getElementById("ddrop"),
					da = document.getElementById("da");

					/* We are connected, so reset the backoff delay */
					current_reconnect_delay = initial_reconnect_delay;

					dd.classList.remove("noconn");
					da.classList.remove("disa");
				};

				ws.onerror = function(ev) {
					console.error("WebSocket error observed:", ev);
				};

				ws.onmessage = function got_packet(msg) {
					var j = JSON.parse(msg.data);

					username = j.user || "";
					if (j.max_size) {
						server_max_size = j.max_size;
						document.getElementById("size").innerHTML =
							"Server maximum file size " + humanize(j.max_size);
					}

					if (j.files) {
						updateTable("files-tbody", j.files, 
							function(f) { return "file-" + btoa(unescape(encodeURIComponent(f.name))).replace(/=/g, ""); },
							function(f) {
								var fullName = f.name;
								var displayName = fullName;
								var isOwner = f.yours;

								if (f.uploader && f.uploader.length > 0)
									displayName = fullName.substring(f.uploader.length + 1);

								var date = new Date(f.mtime * 1000);
								var html = "<td class=\"dow r\">" + humanize(f.size) + "</td>" +
										   "<td class=\"dow\">" + date.toDateString() + " " + date.toLocaleTimeString() + "</td>" +
										   "<td class=\"btn-cell\">";

								/*
								 * No filename is carried in the markup: the
								 * click handlers close over the original name
								 * from the listing instead.
								 */
								if (f.is_text)
									html += "<button class=\"textbtn\" title=\"" + san(displayName) + "\">T</button>";
								else
									html += "<span class=\"textbtn_spacer\"></span>";

								if (isOwner)
									html += "<img class=\"delbtn\" title=\"Delete " + san(displayName) + "\">";
								else
									html += " ";

								/*
								 * encodeURIComponent() escapes '&', '"', '<'
								 * and '>', so its result is already safe in
								 * this double-quoted attribute; san()ing it
								 * first would only get undone by the HTML
								 * parser and corrupt the path.
								 */
								html += "</td><td class=\"ogn\"><a href=\"get/" +
										lws_urlencode(fullName) + "\" download=\"" + san(displayName) + "\">" +
										san(displayName) + "</a></td>";
								return html;
							},
							function(tr, f) {
								/*
								 * onclick, not addEventListener: this runs on
								 * every listing update, including ones that
								 * leave the row's markup (and so its button
								 * elements) alone.
								 */
								var d = tr.querySelector(".delbtn");
								if (d) d.onclick = function(e) { delfile(e, f.name); };
								var t = tr.querySelector(".textbtn");
								if (t) t.onclick = function(e) { load_text(e, f.name); };
							}
						);
					}

					if (j.connected_users) {
						updateTable("users-tbody", j.connected_users,
							function(u) { return "user-" + btoa(unescape(encodeURIComponent(u.user + u.ip + u.platform))).replace(/=/g, ""); },
							function(u) {
								var display_user = san(u.user);
								if (u.is_self) display_user = "<b>" + display_user + "</b>";
								if (u.is_admin) display_user += " (Admin)";
								return "<td>" + display_user + "</td>" +
									   "<td>" + san(u.ip) + "</td>" +
									   "<td>" + san(u.platform) + "</td>" +
									   "<td>" + san(u.browser) + "</td>";
							}
						);
					}
				};

			ws.onclose = function() {
				var dd = document.getElementById("ddrop"),
				da = document.getElementById("da");
				console.log("WebSocket closed. Reconnecting in " + (current_reconnect_delay / 1000) + " seconds...");

				dd.classList.add("noconn");
				da.classList.add("disa");

				/* Schedule the next reconnection attempt */
				setTimeout(connect_ws, current_reconnect_delay);

				/* Apply exponential backoff */
				current_reconnect_delay = Math.min(max_reconnect_delay, current_reconnect_delay * 2);
			};
			} catch(exception) {
				alert("<p>Error " + exception);
			}
		}

		/* Initial connection attempt */
		connect_ws();
	});
}());
