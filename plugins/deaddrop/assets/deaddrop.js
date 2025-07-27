(function() {

	var server_max_size = 0, username = "", ws;

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

	function lws_urlencode(s)
	{
		return encodeURI(s).replace(/@/g, "%40");
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
		var n, t = document.getElementById("ongoing");

		for (n = 0; n < t.rows.length; n++)
			if (t.rows[n].cells[0].classList.contains("err"))
				t.deleteRow(n);
	}

	/*
	 * Generic uploader: takes FormData, a display name and a display size
	 */
	function _do_upload(formData, displayName, displaySize) {
		var t = document.getElementById("ongoing");
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
			body: formData
		})
		.then((e) => { /* this just means we got a response code */
			var us = e.url.split("/"), ul = us[us.length - 1], n;

			for (n = 0; n < t.rows.length; n++)
				if (ul === lws_urlencode(
					      t.rows[n].cells[2].textContent)) {
					if (e.ok === true) {
						t.deleteRow(n);
					} else {
						t.rows[n].cells[0].textContent =
					"Failed " + san(e.status.toString());
						t.rows[n].cells[0].
							classList.add("err");
					}
					break;
				}
		})
		.catch((e) => {
			var us = e.url.split("/"), ul = us[us.length - 1], n;

			for (n = 0; n < t.rows.length; n++)
				if (ul === lws_urlencode(
					  t.rows[n].cells[2].textContent)) {
					t.rows[n].cells[0] = "FAIL";
					break;
				}
		});
	}

	function do_upload(file) {
		var formData = new FormData();
		formData.append("file", file);
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
		    generated_filename = ts + (username ? '_' + username : '') + '.txt',
		    formData = new FormData(), blob;

		e.preventDefault();
		clear_errors();

		blob = new Blob([content.value], { type: "text/plain" });
		formData.append("file", blob, generated_filename);

		_do_upload(formData, generated_filename, blob.size);
		content.value = "";
		text_inp(); // Manually update button state after clearing
	}

	function delfile(e)
	{
		e.stopPropagation();
		e.preventDefault();

		ws.send("{\"del\":\"" + e.target.getAttribute("file") + "\"}");
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
		    upl_text = document.getElementById("upl_text");
		upl_text.disabled = !content.value.length;
	}

	function get_appropriate_ws_url(extra_url)
	{
		var pcol;
		var u = document.URL;

		/*
		 * We open the websocket encrypted if this page came on an
		 * https:// url itself, otherwise unencrypted
		 */

		if (u.substring(0, 5) === "https") {
			pcol = "wss://";
			u = u.substr(8);
		} else {
			pcol = "ws://";
			if (u.substring(0, 4) === "http")
				u = u.substr(7);
		}

		u = u.split("/");

		/* + "/xxx" bit is for IE10 workaround */

		return pcol + u[0] + "/" + extra_url;
	}

	function new_ws(urlpath, protocol)
	{
		return new WebSocket(urlpath, protocol);
	}

	document.addEventListener("DOMContentLoaded", function() {
		var da = document.getElementById("da"),
		    fi = document.getElementById("file"),
		    upl = document.getElementById("upl"),
		    text_content = document.getElementById("text_content"),
		    upl_text = document.getElementById("upl_text");

		da.addEventListener("dragenter", da_enter, false);
		da.addEventListener("dragleave", da_leave, false);
		da.addEventListener("dragover", da_over, false);
		da.addEventListener("drop", da_drop, false);

		upl.addEventListener("click", upl_button, false);
		fi.addEventListener("change", file_inp, false);

		upl_text.addEventListener("click", upl_text_button, false);
		text_content.addEventListener("input", text_inp, false);

		window.addEventListener("dragover", body_drop, false);
		window.addEventListener("drop", body_drop, false);

		ws = new_ws(get_appropriate_ws_url(""), "lws-deaddrop");
		try {
			ws.onopen = function() {
				var dd = document.getElementById("ddrop"),
				da = document.getElementById("da");

				dd.classList.remove("noconn");
				da.classList.remove("disa");
			};

			ws.onmessage = function got_packet(msg) {
				var j = JSON.parse(msg.data), s = "", n,
				t = document.getElementById("dd-list");

				username = j.user || "";
				server_max_size = j.max_size;
				document.getElementById("size").innerHTML =
					"Server maximum file size " +
					humanize(j.max_size);

				s += "<table class=\"nb\">";
				for (n = 0; n < j.files.length; n++) {
					var date = new Date(j.files[n].mtime * 1000);
					s += "<tr><td class=\"dow r\">" +
					humanize(j.files[n].size) +
					"</td><td class=\"dow\">" +
					date.toDateString() + " " +
					date.toLocaleTimeString() + "</td><td>";

					if (username) /* any authenticated user can delete */
						s += "<img id=\"d" + n +
					  "\" class=\"delbtn\" file=\"" +
						san(j.files[n].name) + "\">";
					else
						s += " ";

					s += "</td><td class=\"ogn\"><a href=\"get/" +
					lws_urlencode(san(j.files[n].name)) +
					  "\" download>" +
					san(j.files[n].name) + "</a></td></tr>";
				}
				s += "</table>";

				t.innerHTML = s;

				for (n = 0; n < j.files.length; n++) {
					var d = document.getElementById("d" + n);
					if (d)
						d.addEventListener("click", delfile, false);
				}
			};

			ws.onclose = function() {
				var dd = document.getElementById("ddrop"),
				da = document.getElementById("da");

				dd.classList.add("noconn");
				da.classList.add("disa");
			};
		} catch(exception) {
			alert("<p>Error " + exception);
		}

	});
}());

