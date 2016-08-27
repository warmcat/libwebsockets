function lwsgt_get_appropriate_ws_url()
{
	var pcol;
	var u = document.URL;

	if (u.substring(0, 5) == "https") {
		pcol = "wss://";
		u = u.substr(8);
	} else {
		pcol = "ws://";
		if (u.substring(0, 4) == "http")
			u = u.substr(7);
	}

	return pcol + u;
}

function lwsgt_app_hdr(j, bc, ws)
{
	var s = "", n, m = 0;

	ws.bcq = 0;
					
	for (n = 0; n < j.cols.length; n++)
		if (!j.cols[n].hide)
			m++;

	s = "<tr><td colspan=\"" + m + "\" class=\"lwsgt_title\">" + ws.lwsgt_title + "</td></tr>"

	if (!!bc) {
		s += "<tr><td colspan=\"" + m + "\" class=\"lwsgt_breadcrumbs\">";
		for (n = 0; n < bc.length; n++) {
			s += " / ";
			if (!bc[n].url && bc[n].url !== "")
				s += " " + lws_san(bc[n].name) + " ";
			else {
				s = s + "<a href=# id=\"bc_"+ ws.divname + ws.bcq + "\" h=\"" + ws.lwsgt_cb + "\" p=\""+ws.lwsgt_parent+"\" aa=\"="+
					lws_san(encodeURI(bc[n].url))+"\" m=\"-1\" n=\"-1\">" +
					lws_san(bc[n].name) + "</a> ";
				ws.bcq++;
			}
		}
		s += "</td></tr>";
	}
	s += "<tr>";
	for (n = 0; n < j.cols.length; n++)
		if (!j.cols[n].hide)
			s = s + "<td class=\"lwsgt_hdr\">" + lws_san(j.cols[n].name) + "</td>";
	
	s += "</tr>";
	
	return s;
} 

function lwsgt_initial(title, pcol, divname, cb, gname)
{
	this.divname = divname;
	
	lws_gray_out(true,{'zindex':'499'});

	if (typeof MozWebSocket != "undefined")
		this.lwsgt_ws = new MozWebSocket(lwsgt_get_appropriate_ws_url(), pcol);
	else
		this.lwsgt_ws = new WebSocket(lwsgt_get_appropriate_ws_url(), pcol);
	this.lwsgt_ws.divname = divname;
	this.lwsgt_ws.lwsgt_cb = cb;
	this.lwsgt_ws.lwsgt_parent = gname;
	this.lwsgt_ws.lwsgt_title = title;
	try {
		this.lwsgt_ws.onopen = function() {
			lws_gray_out(false);
		//	document.getElementById("debug").textContent =
		//		"ws opened " + lwsgt_get_appropriate_ws_url();
		}
		this.lwsgt_ws.onmessage = function got_packet(msg) {
			var s, m, n, j = JSON.parse(msg.data);
			document.getElementById("debug").textContent = msg.data;
			if (j.cols) {
				this.hdr = j;
			}
			if (j.breadcrumbs) 
				this.breadcrumbs = j.breadcrumbs;

			if (j.data) {
				var q = 0;
				s = "<table class=\"lwsgt_table\">" +
					lwsgt_app_hdr(this.hdr, this.breadcrumbs, this);
				for (m = 0; m < j.data.length; m++) {
					s = s + "<tr class=\"lwsgt_tr\">";
					for (n = 0; n < this.hdr.cols.length; n++) {
						if (!this.hdr.cols[n].hide) {
							if (!this.hdr.cols[n].align)
								s = s + "<td class=\"lwsgt_td\">";
							else
								s = s + "<td class=\"lwsgt_td\" style=\"text-align: right\">";

							if (this.hdr.cols[n].href &&
							    !!j.data[m][this.hdr.cols[n].href]) {
								s = s + "<a href=# id=\""+ this.divname + q + "\" h=\"" + this.lwsgt_cb + "\" p=\""+this.lwsgt_parent+"\" aa=\""+
									lws_san(encodeURI(j.data[m][this.hdr.cols[n].href]))+"\" m=\""+m+"\" n=\""+n+"\">" +
									lws_san(j.data[m][this.hdr.cols[n].name]) +
									"</a>";
								q++;
							}
							else
								s = s + lws_san(j.data[m][this.hdr.cols[n].name]);
			
							s = s + "</td>";
						}
					}
	
					s = s + "</tr>";
				}
				s = s + "</table>";
				document.getElementById(this.divname).innerHTML = s;
				for (n = 0; n < q; n++)
					document.getElementById(this.divname + n).onclick = lwsgt_click_callthru;

				for (n = 0; n < this.bcq; n++)
					document.getElementById("bc_" + this.divname + n).onclick = lwsgt_click_callthru;

			}		
		}
		this.lwsgt_ws.onclose = function(){
			lws_gray_out(true,{'zindex':'499'});
		}
	} catch(exception) {
		alert('<p>Error' + exception);  
	}
}

function lwsgt_click_callthru()
{
	window[this.getAttribute("h")](this.getAttribute("p"), this.getAttribute("aa"), this.getAttribute("m"), this.getAttribute("n"));
	event.preventDefault();
}

