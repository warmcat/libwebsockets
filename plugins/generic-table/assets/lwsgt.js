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

function lwsgt_san(s)
{
	if (!s)
		return "";
	if (s.search("<") != -1)
		return "invalid string";
	
	return s;
}


function lwsgt_app_hdr(j, bc, ws)
{
	var s = "", n, m = 0;
					
	for (n = 0; n < j.cols.length; n++)
		if (!j.cols[n].hide)
			m++;

	s = "<tr><td colspan=\"" + m + "\" class=\"lwsgt_title\">" + ws.lwsgt_title + "</td></tr>"

	if (!!bc) {
		s += "<tr><td colspan=\"" + m + "\" class=\"lwsgt_breadcrumbs\">";
		for (n = 0; n < bc.length; n++) {
			s += " / ";
			if (!bc[n].url && bc[n].url !== "")
				s += " " + lwsgt_san(bc[n].name) + " ";
			else
				s += " <a href=\"#\"onclick=\"window[\'"+ ws.lwsgt_cb +"\']('" +
					ws.lwsgt_parent + "', '=" + 
					lwsgt_san(encodeURI(bc[n].url)) +
					"', -1, -1); event.preventDefault();\">" +
					lwsgt_san(bc[n].name) + "</a> ";
		}
		s += "</td></tr>";
	}
	s += "<tr>";
	for (n = 0; n < j.cols.length; n++)
		if (!j.cols[n].hide)
			s = s + "<td class=\"lwsgt_hdr\">" + lwsgt_san(j.cols[n].name) + "</td>";
	
	s += "</tr>";
	
	return s;
} 

function lwsgt_initial(title, pcol, divname, cb, gname)
{
	this.divname = divname;

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
		//	document.getElementById("debug").textContent =
		//		"ws opened " + lwsgt_get_appropriate_ws_url();
		}
		this.lwsgt_ws.onmessage = function got_packet(msg) {
			var s, m, n, j = JSON.parse(msg.data);
			// document.getElementById("debug").textContent = msg.data;
			if (j.cols) {
				this.hdr = j;
			}
			if (j.breadcrumbs) 
				this.breadcrumbs = j.breadcrumbs;

			if (j.data) {
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
							    !!j.data[m][this.hdr.cols[n].href])
								s = s + "<a href=\"#\" onclick=\"window[\'"+this.lwsgt_cb +"\']('" +
									this.lwsgt_parent + "', '" + 
									lwsgt_san(encodeURI(j.data[m][this.hdr.cols[n].href])) +
									"', " + m + ", " + n + "); event.preventDefault();\">" + 
									lwsgt_san(j.data[m][this.hdr.cols[n].name]) +
									"</a>";
							else
								s = s + lwsgt_san(j.data[m][this.hdr.cols[n].name]);
			
							s = s + "</td>";
						}
					}
	
					s = s + "</tr>";
				}
				s = s + "</table>";
				document.getElementById(this.divname).innerHTML = s;
			}		
		}
		this.lwsgt_ws.onclose = function(){
		}
	} catch(exception) {
		alert('<p>Error' + exception);  
	}
}