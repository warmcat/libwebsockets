/* gitws.js: javascript functions for gitws
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * Licensed under GNU General Public License v2
 *   (see COPYING for full license text)
 */

(function () {
function san(s)
{
	if (!s)
		return "";
	if (s.search("<") != -1)
		return "invalid string";
	
	return s;
}

function get_appropriate_ws_url(extra_url)
{
	var pcol;
	var u = document.URL;

	/*
	 * We open the websocket encrypted if this page came on an
	 * https:// url itself, otherwise unencrypted
	 */

	if (u.substring(0, 5) == "https") {
		pcol = "wss://";
		u = u.substr(8);
	} else {
		pcol = "ws://";
		if (u.substring(0, 4) == "http")
			u = u.substr(7);
	}

	u = u.split('/');

	/* + "/xxx" bit is for IE10 workaround */

	return pcol + u[0] + "/" + extra_url;
}

var age_names = [  "s",  "m",    "h", " days", " weeks", " months", " years" ];
var age_div =   [   1,   60,   3600,   86400,   604800,   2419200, 31536000  ];
var age_limit = [ 120, 7200, 172800, 1209600,  4838400,  63072000,        0  ];

function agify(now, secs)
{
	var d = now - secs, n;
	
	if (!secs)
		return "";
	
	for (n = 0; n < age_names.length; n++)
		if (d < age_limit[n] || age_limit[n] == 0)
			return "<span class='age-" + n + "' ut='" + secs +
				"'>" + Math.ceil(d / age_div[n]) +
				age_names[n] + "</span>";
}

function comp_reftime(a, b)
{
	return b.summary.time - a.summary.time;
}

function comp_reftime_tag(a, b)
{
	return b.summary.time - a.summary.time;
}

function identity(i)
{
	if (!i)
		return "";
	return "<span class=gravatar alt='" + san(i.email) + "'>" +
		   "<img class='inline' src='//www.gravatar.com/avatar/" + i.md5 +
		   "?s=13&amp;d=retro' width='13' height='13' alt='Gravatar' />" +
		   "<img class='onhover' src='//www.gravatar.com/avatar/" + i.md5 +
		   "?s=128&amp;d=retro'/>" + san(i.name) + "</span>";
}

function new_ws(urlpath, protocol)
{
	if (typeof MozWebSocket != "undefined")
		return new MozWebSocket(urlpath, protocol);

	return new WebSocket(urlpath, protocol);
}

var branches = new(Array), tags = new(Array);

function display_summary(j)
{
	var n, s = "<table>", now = new Date().getTime() / 1000;

	s += "<tr><td class='heading' style='width:128px'>Branch" +
    	     "</td><td class='heading'>Commit message" +
    	     "</td><td class='heading'>Author" +
    	     "</td><td class='heading'>Age" +
    	     "</td><td>" +
    	     "</td></tr>";

	for (n = 0; n < branches.length && n < 10; n++)
		s += "<tr><td>" + branches[n].name.substr(11) +
		     "</td><td>" + san(branches[n].summary.msg) +
		     "</td><td>" + identity(branches[n].summary.sig_author) +
		     "</td><td>" + agify(now, branches[n].summary.time) +
		     "</td></tr>";
	     
	s += "<tr><td colspan=5>&nbsp;</td></tr>";

	s += "<tr><td class='heading'>Tag" +
	     "</td><td class='heading'>Message" +
	     "</td><td class='heading'>Author" +
	     "</td><td class='heading'>Age" +
	     "</td><td>" +
	     "</td></tr>";
	
	for (n = 0; n < tags.length && n < 10; n++)
		s += "<tr><td>" + tags[n].name.substr(10) +
		"</td><td>" + san(tags[n].summary.msg_tag) +
		"</td><td>" + identity(tags[n].summary.sig_tagger) +
	     "</td><td>" + agify(now, tags[n].summary.time) +
	     "</td></tr>";
	
	s += "<tr><td colspan=5>&nbsp;</td></tr>";
	
	s += "<tr><td class='heading'>" +
    "</td><td class='heading'>Message" +
    "</td><td class='heading'>Author" +
    "</td><td class='heading'>Age" +
    "</td><td class='heading'>" +
    "</td></tr>";

	for (n = 0; n < j.items[1].log.length && n < 10; n++) {
		var irefs = "", m, r, c;
		
		for (m = 0; m < j.items[1].log[n].name.alias.length; m++) {
			r = j.items[1].log[n].name.alias[m];

			if (r.substr(0, 11) == "refs/heads/")
				irefs += " <span class='inline_head'>" + r.substr(11) + "</span>";
			else
				if (r.substr(0, 10) == "refs/tags/")
					irefs += " <span class='inline_tag'>" + r.substr(10) + "</span>";
		}
		
		s += "<tr><td>" + 
		"</td><td>" + san(j.items[1].log[n].summary.msg) + irefs +
		"</td><td>" + identity(j.items[1].log[n].summary.sig_author) +
	     "</td><td>" + agify(now, j.items[1].log[n].summary.time) +
	     "</td><td>" + //j.items[1].log[n].name.substr(10) +
	     "</td></tr>";
	}
	
	s += "</table>";

	document.getElementById("result").innerHTML = s;
}

function parse_json_reflist(j)
{
	var n;
	
	branches.length = 0;
	tags.length = 0;
	
	for (n = 0; n < j.items[0].reflist.length; n++) {
		var l = j.items[0].reflist[n];
		if (l.name.substr(0, 11) == "refs/heads/")
			branches.push(l);
		else
			if (l.name.substr(0, 10) == "refs/tags/") {
				if (l.summary.sig_tagger &&
				    l.summary.sig_tagger.git_time)
					l.summary.time = l.summary.sig_tagger.git_time.time;
				if (!l.summary.sig_tagger && l.summary.sig_author)
					l.summary.sig_tagger = l.summary.sig_author;
				if (!l.summary.msg_tag && l.summary.msg)
					l.summary.msg_tag = l.summary.msg;
				tags.push(l);
			}
	}
	
	branches.sort(comp_reftime);
	tags.sort(comp_reftime_tag);
}

function parse_json(j)
{
	var n;

	if (j.items[0].reflist)
		parse_json_reflist(j);
}

var ws, j;

window.addEventListener("load", function() {
	console.log("load");
}, false);

document.addEventListener("DOMContentLoaded", function() {
	
	console.log("DOM content");
	var init = document.getElementById("initial-json");	
	 ws = new_ws(get_appropriate_ws_url(""), "lws-gitws");
	 
		if (init) {
			j = JSON.parse(init.textContent);
			console.log("parsed initial json");
			parse_json(j);
			display_summary(j);
			init.textContent = "";
		}
	 
	 try {
			ws.onopen = function() {
				console.log("ot_open.onopen");
			}
			ws.onmessage =function got_packet(msg) {
				// document.getElementById("result").textContent = msg.data;
				j = JSON.parse(msg.data);
				parse_json(j);
				
				display_summary(j);
			}
			ws.onclose = function(e){
				console.log(" websocket connection CLOSED, code: " + e.code +
					    ", reason: " + e.reason);
			}
		} catch(exception) {
			alert('<p>Error' + exception);  
		}
}, false);

window.addEventListener("hashchange", function() {
	console.log("hashchange");
}, false);

})();
