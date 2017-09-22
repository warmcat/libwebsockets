/*
 * This section around grayOut came from here:
 * http://www.codingforums.com/archive/index.php/t-151720.html
 * Assumed public domain
 *
 * Init like this in your main html script, this also reapplies the gray
 *
 *    lws_gray_out(true,{'zindex':'499'});
 *
 * To remove the gray
 *
 *    lws_gray_out(false);
 *
 */

function lws_gray_out(vis, options) {
	var options = options || {};
	var zindex = options.zindex || 50;
	var opacity = options.opacity || 70;
	var opaque = (opacity / 100);
	var bgcolor = options.bgcolor || '#000000';
	var dark = document.getElementById('darkenScreenObject');

	if (!dark) {
		var tbody = document.getElementsByTagName("body")[0];
		var tnode = document.createElement('div');
		tnode.style.position = 'absolute';
		tnode.style.top = '0px';
		tnode.style.left = '0px';
		tnode.style.overflow = 'hidden';
		tnode.style.display ='none';
		tnode.id = 'darkenScreenObject';
		tbody.appendChild(tnode);
		dark = document.getElementById('darkenScreenObject');
	}
	if (vis) {
		dark.style.opacity = opaque;
		dark.style.MozOpacity = opaque;
		dark.style.filter ='alpha(opacity='+opacity+')';
		dark.style.zIndex = zindex;
		dark.style.backgroundColor = bgcolor;
		dark.style.width = gsize(1);
		dark.style.height = gsize(0);
		dark.style.display ='block';
		addEvent(window, "resize",
			function() {
				dark.style.height = gsize(0);
				dark.style.width = gsize(1);
			}
		);
	} else {
		dark.style.display = 'none';
		removeEvent(window, "resize",
			function() {
				dark.style.height = gsize(0);
				dark.style.width = gsize(1);
			}
		);
	}
}

function gsize(ptype)
{
	var h = document.compatMode == 'CSS1Compat' &&
		!window.opera ?
			document.documentElement.clientHeight :
						document.body.clientHeight;
	var w = document.compatMode == 'CSS1Compat' &&
		!window.opera ? 
			document.documentElement.clientWidth :
						document.body.clientWidth;
	if (document.body && 
		    (document.body.scrollWidth || document.body.scrollHeight)) {
		var pageWidth = (w > (t = document.body.scrollWidth)) ?
					("" + w + "px") : ("" + (t) + "px");
		var pageHeight = (h > (t = document.body.scrollHeight)) ?
					("" + h + "px") : ("" + (t) + "px");
	} else if (document.body.offsetWidth) {
		var pageWidth = (w > (t = document.body.offsetWidth)) ?
					("" + w + "px") : ("" + (t) + "px");
		var pageHeight =(h > (t = document.body.offsetHeight)) ?
					("" + h + "px") : ("" + (t) + "px");
	} else {
		var pageWidth = '100%';
		var pageHeight = '100%';
	}
	return (ptype == 1) ? pageWidth : pageHeight;
}

function addEvent( obj, type, fn ) {
	if ( obj.attachEvent ) {
		obj['e' + type + fn] = fn;
		obj[type+fn] = function() { obj['e' + type+fn]( window.event );}
		obj.attachEvent('on' + type, obj[type + fn]);
	} else
		obj.addEventListener(type, fn, false);
}

function removeEvent( obj, type, fn ) {
	if ( obj.detachEvent ) {
		obj.detachEvent('on' + type, obj[type + fn]);
		obj[type + fn] = null;
	} else
		obj.removeEventListener(type, fn, false);
}

/*
 * end of grayOut related stuff
 */
 
/*
 * lws-meta helpers
 */

var lws_meta_cmd = {
	OPEN_SUBCHANNEL: 0x41,
	/**< Client requests to open new subchannel
	 */
	OPEN_RESULT: 0x42,
	/**< Result of client request to open new subchannel */
	CLOSE_NOT: 0x43,
	CLOSE_RQ: 0x44,
	/**< client requests to close a subchannel */
	WRITE: 0x45,
	/**< connection writes something to specific channel index */
	RX: 0x46,
};

function new_ws(urlpath, protocol)
{
	if (typeof MozWebSocket != "undefined")
		return new MozWebSocket(urlpath, protocol);

	return new WebSocket(urlpath, protocol);
}

function lws_meta_ws() {
	var real;
	
	var channel_id_to_child;
	var pending_children;
	var active_children;
}

function lws_meta_ws_child() {
	var onopen;
	var onmessage;
	var onclose;
	
	var channel_id;
	
	var subprotocol;
	var suburl;
	var cookie;
	
	var extensions;
	
	var parent;
}

lws_meta_ws_child.prototype.send = function(data)
{

	if (typeof data == "string") {
		data = String.fromCharCode(lws_meta_cmd.WRITE) +
			String.fromCharCode(this.channel_id) +
			data;
		
		return this.parent.real.send(data);
	}
	
	{

		var ab = new Uint8Array(data.length + 2);

		ab[0] = lws_meta_cmd.WRITE;
		ab[1] = this.channel_id;
		ab.set(data, 2);
	
		return this.parent.real.send(ab);
	}
}

lws_meta_ws_child.prototype.close = function(close_code, close_string)
{
	var pkt = new Uint8Array(129), m = 0, pkt1;
	
	pkt[m++] = lws_meta_cmd.CLOSE_RQ;
	pkt[m++] = this.channel_id;
	
	pkt[m++] = close_string.length + 0x20;
	
	pkt[m++] = close_code / 256;
	pkt[m++] = close_code % 256;
	
	for (i = 0; i < close_string.length; i++)
		pkt[m++] = close_string.charCodeAt(i);
	
	pkt1 = new Uint8Array(m);
	for (n = 0; n < m; n++)
		pkt1[n] = pkt[n];
		
	this.parent.real.send(pkt1.buffer);
}

/* make a real ws connection using lws_meta*/
lws_meta_ws.prototype.new_parent = function(urlpath)
{
	var n, i, m = 0, pkt1;
	
	this.ordinal = 1;
	this.pending_children = [];
	this.active_children = [];
	this.real = new_ws(urlpath, "lws-meta");
	
	this.real.binaryType = 'arraybuffer';
	this.real.myparent = this;

	this.real.onopen = function() {
		pkt = new Uint8Array(1024);
			var n, i, m = 0, pkt1;
		console.log("real open - pending children " + this.myparent.pending_children.length);
		for (n = 0; n < this.myparent.pending_children.length; n++) {
		
			var p = this.myparent.pending_children[n];
		
			pkt[m++] = lws_meta_cmd.OPEN_SUBCHANNEL;
			for (i = 0; i < p.subprotocol.length; i++)
				pkt[m++] = p.subprotocol.charCodeAt(i);
			pkt[m++] = 0;
			for (i = 0; i < p.suburl.length; i++)
				pkt[m++] = p.suburl.charCodeAt(i);
			pkt[m++] = 0;
			for (i = 0; i < p.cookie.length; i++)
				pkt[m++] = p.cookie.charCodeAt(i);
			pkt[m++] = 0;
		}
		
		pkt1 = new Uint8Array(m);
		for (n = 0; n < m; n++)
			pkt1[n] = pkt[n];
		
		console.log(this.myparent.pending_children[0].subprotocol);
		console.log(pkt1);
		
		this.send(pkt1.buffer);
	}


	this.real.onmessage = function(msg) {
	
		if (typeof msg.data != "string") {
			var ba = new Uint8Array(msg.data), n = 0;
			
			while (n < ba.length) {

				switch (ba[n++]) {
				case lws_meta_cmd.OPEN_RESULT:
				{
					var m = 0, cookie = "", protocol = "", ch = 0;
					var ws = this.myparent;
					/* cookie NUL
					 * channel index + 0x20
					 * protocol NUL
					 */
					 while (ba[n])
					 	cookie = cookie + String.fromCharCode(ba[n++]);
					 n++;
					 ch = ba[n++];
					 
					 while (ba[n])
					 	protocol = protocol + String.fromCharCode(ba[n++]);
					 	
					console.log("open result " + cookie + " " + protocol + " " + ch + " pending len " + ws.pending_children.length);
					
					for (m = 0; m < ws.pending_children.length; m++) {
						if (ws.pending_children[m].cookie == cookie) {
							var newchild = ws.pending_children[m];
			
							/* found it */
							ws.pending_children[m].channel_id = ch;
							/* add to active children array */
							ws.active_children.push(ws.pending_children[m]);
							/* remove from pending children array */
							ws.pending_children.splice(m, 1);
							
							newchild.parent = ws;
							newchild.extensions = this.extensions;
							
							newchild.onopen();
							
							console.log("made active " + cookie);
							break;
						}
					}
					break;
				}
	
				case lws_meta_cmd.CLOSE_NOT:
				{
					var code = 0, str = "", ch = 0, m, le;
					var ba = new Uint8Array(msg.data);
					/*
					 * BYTE: channel
					 * BYTE: MSB status code
					 * BYTE: LSB status code
					 * BYTES: rest of message is close status string
					 */
					 
					 ch = ba[n++];
					 le = ba[n++] - 0x20;
					 code = ba[n++] * 256;
					 code += ba[n++];
					 
					 while (le--)
					 	str += String.fromCharCode(ba[n++]);
					 	
					console.log("channel id " + ch + " code " + code + " str " + str + " len " + str.length);
					 	
					for (m = 0; m < this.myparent.active_children.length; m++)
						if (this.myparent.active_children[m].channel_id == ch) {
							var child = this.myparent.active_children[m];
							var ms = new CloseEvent("close", { code:code, reason:str } );
							
							/* reply with close ack */
							this.send(msg.data);
							
							if (child.onclose)
								child.onclose(ms);
							
							this.myparent.active_children.splice(m, 1);
							break;
						}

				}
				} // switch
			}
		} else {
			if (msg.data.charCodeAt(0) == lws_meta_cmd.WRITE ) {
				var ch = msg.data.charCodeAt(1), m, ms;
				var ws = this.myparent, ms;
								
				for (m = 0; m < ws.active_children.length; m++) {
					if (ws.active_children[m].channel_id == ch) {
						ms = new MessageEvent("WebSocket", { data: msg.data.substr(2, msg.data.length - 2) } );
						if (ws.active_children[m].onmessage)
							ws.active_children[m].onmessage(ms);
						break;
					}
				}
			}
		}
	}
	this.real.onclose = function() {
		var ws = this.myparent, m;
		for (m = 0; m < ws.active_children.length; m++) {
			var child = ws.active_children[m];
			var ms = new CloseEvent("close", { code:1000, reason:"parent closed" } );
			
			if (child.onclose)
				child.onclose(ms);
		}
	}

}



/* make a child connection using existing lws_meta real ws connection */
lws_meta_ws.prototype.new_ws = function(suburl, protocol)
{
	var ch = new lws_meta_ws_child();
	
	ch.suburl = suburl;
	ch.subprotocol = protocol;
	ch.cookie = "C" + this.ordinal++;
	
	this.pending_children.push(ch);
	
	if (this.real.readyState == 1)
		this.real.onopen();
	
	return ch;
}


/*
 * end of lws-meta helpers
 */
 
function lws_san(s)
{
	if (s.search("<") != -1)
		return "invalid string";
	
	return s;
}
