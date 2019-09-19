(function() {

/*
 * We display untrusted stuff in html context... reject anything
 * that has HTML stuff in it
 */

function san(s)
{
	if (s.search("<") !== -1)
		return "invalid string";
	
	return s;
}

function humanize(s)
{
	var i = parseInt(s, 10);
	
	if (i >= (1024 * 1024 * 1024))
		return (i / (1024 * 1024 * 1024)).toFixed(3) + "Gi";
	
	if (i >= (1024 * 1024))
		return (i / (1024 * 1024)).toFixed(3) + "Mi";
	
	if (i > 1024)
		return (i / 1024).toFixed(3) + "Ki";
	
	return s;
}

function get_appropriate_ws_url()
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

	return pcol + u[0] + "/xxx";
}


	var socket_status, jso, s;

function ws_open_server_status()
{	
	socket_status = new WebSocket(get_appropriate_ws_url(),
				   "lws-server-status");

	try {
		socket_status.onopen = function() {
			document.getElementById("title").innerHTML = "Server Status (Active)";
			lws_gray_out(false);
		};

		socket_status.onmessage =function got_packet(msg) {
			var u, ci, n;
			//document.getElementById("json").innerHTML = "<pre>"+msg.data+"</pre>";
			if (msg.data.length < 100)
				return;
			jso = JSON.parse(msg.data);
			u = parseInt(san(jso.i.uptime), 10);

			if (parseInt(jso.i.contexts[0].deprecated, 10) === 0)
				s = "<table><tr><td></td><td class=\"c0\">";
			else
				s = "<table><tr><td></td><td class=\"dc0\">";
			s +=
			  "Server</td><td>" +
			  "<span class=\"sn\">Server Version:</span> <span class=\"v\">" +
			   san(jso.i.version) + "</span><br>" +
			  "<span class=\"sn\">Host Uptime:</span> <span class=\"v\">" +
			  ((u / (24 * 3600)) | 0) + "d " +
			  (((u % (24 * 3600)) / 3600) | 0) + "h " +
			  (((u % 3600) / 60) | 0) + "m</span>";
			if (jso.i.l1)
				s = s + ", <span class=\"sn\">Host Load:</span> <span class=\"v\">" + san(jso.i.l1) + " ";
			if (jso.i.l2)
				s = s + san(jso.i.l2) + " ";
			if (jso.i.l3)
				s = s + san(jso.i.l3);
			if (jso.i.l1)
				s =s + "</span>";
				
			if (jso.i.statm) {
				var sm = jso.i.statm.split(" ");
				s += ", <span class=\"sn\">Virt stack + heap Usage:</span> <span class=\"v\">" +
					humanize(parseInt(sm[5], 10) * 4096) + "B</span>";
			}
			s += ", <span class=\"sn\">lws heap usage:</span> <span class=\"v\">" +
			humanize(jso.i.heap) + "B</span>";

				
			for (n = 0; n < jso.files.length; n++) {
				s += "<br><span class=n>" + san(jso.files[n].path) + ":</span><br>    " + san(jso.files[n].val);
			}
			s += "</td></tr>";

			for (ci = 0; ci < jso.i.contexts.length; ci++) {

				if (parseInt(jso.i.contexts[ci].deprecated, 10) === 0)
					s += "<tr><td></td><td class=\"c\">" +
					  "Active Context</td><td>";
				else
					s += "<tr><td></td><td class=\"c1\">" +
					  "Deprecated Context " + ci + "</td><td>";

				  u = parseInt(san(jso.i.contexts[ci].context_uptime), 10);
	  			  s += "<span class=n>Server Uptime:</span> <span class=v>" +
				  ((u / (24 * 3600)) | 0) + "d " +
				  (((u % (24 * 3600)) / 3600) | 0) + "h " +
				  (((u % 3600) / 60) | 0) + "m</span>";

				s = s +
				  "<br>" +
				  "<span class=n>Listening wsi:</span> <span class=v>" + san(jso.i.contexts[ci].listen_wsi) + "</span>, " +
				  "<span class=n>Current wsi alive:</span> <span class=v>" + (parseInt(san(jso.i.contexts[ci].wsi_alive), 10) -
						  parseInt(san(jso.i.contexts[ci].listen_wsi), 10)) + "</span><br>" +
			  	  "<span class=n>Total Rx:</span> <span class=v>" + humanize(san(jso.i.contexts[ci].rx)) +"B</span>, " +
			  	  "<span class=n>Total Tx:</span> <span class=v>" + humanize(san(jso.i.contexts[ci].tx)) +"B</span><br>" +
			  	  
			  	  "<span class=n>CONNECTIONS: HTTP/1.x:</span> <span class=v>" + san(jso.i.contexts[ci].h1_conn) +"</span>, " +
			  	  "<span class=n>Websocket:</span> <span class=v>" + san(jso.i.contexts[ci].ws_upg) +"</span>, " +
			  	  "<span class=n>H2 upgrade:</span> <span class=v>" + san(jso.i.contexts[ci].h2_upg) +"</span>, " +
			  	  "<span class=n>H2 ALPN:</span> <span class=v>" + san(jso.i.contexts[ci].h2_alpn) +"</span>, " +
			  	  "<span class=n>Rejected:</span> <span class=v>" + san(jso.i.contexts[ci].rejected) +"</span><br>" +

			  	  "<span class=n>TRANSACTIONS: HTTP/1.x:</span> <span class=v>" + san(jso.i.contexts[ci].h1_trans) + "</span>, " +
			  	  "<span class=n>H2:</span> <span class=v>" + san(jso.i.contexts[ci].h2_trans) +"</span>, " +
			  	   "<span class=n>Total H2 substreams:</span> <span class=v>" + san(jso.i.contexts[ci].h2_subs) +"</span><br>" +

				  "<span class=n>CGI: alive:</span> <span class=v>" + san(jso.i.contexts[ci].cgi_alive) + "</span>, " +
				  "<span class=n>spawned:</span> <span class=v>" + san(jso.i.contexts[ci].cgi_spawned) +
				  "</span><table>";
				
				for (n = 0; n < jso.i.contexts[ci].pt.length; n++) {

					if (parseInt(jso.i.contexts[ci].deprecated, 10) === 0)
						s += "<tr><td>&nbsp;&nbsp;</td><td class=\"l\">service thread " + (n + 1);
					else
						s += "<tr><td>&nbsp;&nbsp;</td><td class=\"dl\">service thread " + (n + 1);
					s += "</td><td>" +
					"<span class=n>fds:</span> <span class=v>" + san(jso.i.contexts[ci].pt[n].fds_count) + " / " +
						  san(jso.i.contexts[ci].pt_fd_max) + "</span>, ";
					s = s + "<span class=n>ah pool:</span> <span class=v>" + san(jso.i.contexts[ci].pt[n].ah_pool_inuse) + " / " +
						      san(jso.i.contexts[ci].ah_pool_max) + "</span>, " +
					"<span class=n>ah waiting list:</span> <span class=v>" + san(jso.i.contexts[ci].pt[n].ah_wait_list);
	
					s = s + "</span></td></tr>";
	
				}
				for (n = 0; n < jso.i.contexts[ci].vhosts.length; n++) {
					if (parseInt(jso.i.contexts[ci].deprecated, 10) === 0)
						s += "<tr><td>&nbsp;&nbsp;</td><td class=\"l\">vhost " + (n + 1);
					else
						s += "<tr><td>&nbsp;&nbsp;</td><td class=\"dl\">vhost " + (n + 1);
					s += "</td><td><span class=\"mountname\">";
					if (jso.i.contexts[ci].vhosts[n].use_ssl === "1")
						s = s + "https://";
					else
						s = s + "http://";
					s = s + san(jso.i.contexts[ci].vhosts[n].name) + ":" +
						san(jso.i.contexts[ci].vhosts[n].port) + "</span>";
					if (jso.i.contexts[ci].vhosts[n].sts === "1")
						s = s + " (STS)";
					s = s +"<br>" +
					
					  "<span class=n>Total Rx:</span> <span class=v>" + humanize(san(jso.i.contexts[ci].vhosts[n].rx)) +"B</span>, " +
					  "<span class=n>Total Tx:</span> <span class=v>" + humanize(san(jso.i.contexts[ci].vhosts[n].tx)) +"B</span><br>" +
					  
					  "<span class=n>CONNECTIONS: HTTP/1.x:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h1_conn) +"</span>, " +
					  "<span class=n>Websocket:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].ws_upg) +"</span>, " +
					  "<span class=n>H2 upgrade:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h2_upg) +"</span>, " +
					  "<span class=n>H2 ALPN:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h2_alpn) +"</span>, " +
					  "<span class=n>Rejected:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].rejected) +"</span><br>" +
					
					  "<span class=n>TRANSACTIONS: HTTP/1.x:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h1_trans) + "</span>, " +
					  "<span class=n>H2:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h2_trans) +"</span>, " +
					  "<span class=n>Total H2 substreams:</span> <span class=v>" + san(jso.i.contexts[ci].vhosts[n].h2_subs) +"</span><br>";
					
					if (jso.i.contexts[ci].vhosts[n].mounts) {
						s = s + "<table><tr><td class=t>Mountpoint</td><td class=t>Origin</td><td class=t>Cache Policy</td></tr>";
	
						var m;
						for (m = 0; m < jso.i.contexts[ci].vhosts[n].mounts.length; m++) {
							s = s + "<tr><td>";
							s = s + "<span class=\"m1\">" + san(jso.i.contexts[ci].vhosts[n].mounts[m].mountpoint) +
								"</span></td><td><span class=\"m2\">" +
								san(jso.i.contexts[ci].vhosts[n].mounts[m].origin) +
								"</span></td><td>";
							if (parseInt(san(jso.i.contexts[ci].vhosts[n].mounts[m].cache_max_age), 10))
								s = s + "<span class=n>max-age:</span> <span class=v>" +
								san(jso.i.contexts[ci].vhosts[n].mounts[m].cache_max_age) +
								"</span>, <span class=n>reuse:</span> <span class=v>" +
								san(jso.i.contexts[ci].vhosts[n].mounts[m].cache_reuse) +
								"</span>, <span class=n>reval:</span> <span class=v>" +
								san(jso.i.contexts[ci].vhosts[n].mounts[m].cache_revalidate) +
								"</span>, <span class=n>inter:</span> <span class=v>" +
								san(jso.i.contexts[ci].vhosts[n].mounts[m].cache_intermediaries);
							s = s + "</span></td></tr>";
						}
						s = s + "</table>";
					}
					s = s + "</td></tr>";
				}

				s += "</table></td></tr>";
				
			} // context
			s = s + "</table>";
			
			document.getElementById("conninfo").innerHTML = s;
		};

		socket_status.onclose = function(){
			document.getElementById("title").innerHTML = "Server Status (Disconnected)";
			lws_gray_out(true,{"zindex":"499"});
		};
	} catch(exception) {
		alert("<p>Error" + exception);  
	}
}

/* stuff that has to be delayed until all the page assets are loaded */

window.addEventListener("load", function() {

	lws_gray_out(true,{"zindex":"499"});
	
	ws_open_server_status();
	
}, false);

}());

