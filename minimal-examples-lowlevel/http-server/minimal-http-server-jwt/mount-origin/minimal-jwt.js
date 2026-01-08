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

	var ws = new_ws(get_appropriate_ws_url(""), "minimal-jwt");

	ws.onopen = function() {
		console.log("WebSocket connected");
	};

	ws.onmessage = function(msg) {
		var j = JSON.parse(msg.data);
		console.log("Received:", j);

		var auth_container = document.getElementById("auth-container");
		var public_content = document.getElementById("public-content");
		var private_content = document.getElementById("private-content");

		if (j.authorized) {
			/* Authenticated state */
			auth_container.innerHTML =
				'<div style="display: flex; align-items: center; gap: 10px;">' +
				'<span>Welcome <b>' + j.user + '</b></span>' +
				'<form action="/logout" method="post" style="margin: 0;">' +
				'<input type="hidden" name="success_redir" value="/">' +
				'<button type="submit" style="padding: 2px 8px;">Log Out</button>' +
				'</form>' +
				'</div>';

			private_content.style.display = "block";
		} else {
			/* Unauthenticated state - Show Login Form */
			auth_container.innerHTML =
				'<form action="/login" method="post" style="display: flex; gap: 5px; margin: 0;">' +
				'<input type="text" name="username" placeholder="Username" value="admin" style="width: 100px;">' +
				'<input type="password" name="password" placeholder="Password" value="password" style="width: 100px;">' +
				'<input type="hidden" name="success_redir" value="/">' +
				'<button type="submit">Log In</button>' +
				'</form>';

			private_content.style.display = "none";
		}
	};

	ws.onclose = function() {
		console.log("WebSocket closed");
	};

}, false);
