Notes about generic-table
=========================

@section gtint What is generic-table?

Generic-table is a JSON schema and client-side JS file that makes it easy to
display live, table structured HTML over a ws link.

An example plugin and index.html using it are provided, but lwsgt itself doesn't
have its own plugin, it's just a JSON schema and client-side JS that other
plugins can use to simplify displaying live, table-based data without having
to reinvent the wheel each time.

The ws protocol sends JSON describing the table, and then JSON updating the table
contents when it chooses, the brower table is updated automatically, live.

\image html lwsgt-overview.png

 - Example protocol plugin (displays directory contents): https://github.com/warmcat/libwebsockets/tree/master/plugins/generic-table/protocol_table_dirlisting.c

 - Example HTML: https://github.com/warmcat/libwebsockets/tree/master/plugins/generic-table/assets/index.html
 
 - lwsgt.js (client-side table rendering / ws link management): https://github.com/warmcat/libwebsockets/tree/master/plugins/generic-table/assets/lwsgt.js


@section gteb Enabling for build

Enable the demo plugin at CMake with -DLWS_WITH_PLUGINS=1


@section gtinth Integrating with your html

 - In your HEAD section, include lwsgt.js

```
	<script src="lwsgt.js"></script>
```

 - Also in your HEAD section, style the lwsgt CSS, eg

```
	<style>
	.lwsgt_title { font-size: 24; text-align:center }
	.lwsgt_breadcrumbs { font-size: 18; text-align:left }
	.lwsgt_table { font-size: 14; padding:12px; margin: 12px; align:center }
	.lwsgt_hdr { font-size: 18; text-align:center;
		     background-color: rgba(40, 40, 40, 0.8); color: white }
	.lwsgt_tr { padding: 10px  }
	.lwsgt_td { padding: 3px  }
	</style>
```

You can skip this but the result will be less beautiful until some CSS is
provided.

 - In your body section, declare a div with an id (can be whatever you want)

```
	<tr><td><div id="lwsgt1" class="group1"></div></td></tr>
```

lwsgt JS will put its content there.

 - Finally in a <script> at the end of your page, instantiate lwsgt and
provide a custom callback for clickable links

```
	<script>
	var v1 = new lwsgt_initial("Dir listing demo",
				   "protocol-lws-table-dirlisting",
				   "lwsgt1", "lwsgt_dir_click", "v1");
	
	function lwsgt_dir_click(gt, u, col, row)
	{
		if (u[0] == '=') { /* change directory */
			window[gt].lwsgt_ws.send(u.substring(1, u.length));
			return;
		}
		var win = window.open(u, '_blank');
	  	win.focus();
	}

  	</script>
```

In the callback, you can recover the ws object by `window[gt].lwsgt_ws`.


@section gtc Lwsgt constructor

To instantiate the ws link and lwsgt instance, your HTML must call a lwsgt
constructor for each region on the page managed by lwsgt.

`var myvar = new lwsgt_initial(title, ws_protocol, div_id, click_cb, myvar);`

All of the arguments are strings.

| Parameter       | Description                                             |
|-----------------|---------------------------------------------------------|
| title           | Title string to go above the table                      |
| ws_protocol     | Protocol name string to use when making ws connection   |
| div_id          | HTML id of div to fill with content                     |
| click_cb        | Callback function name string to handle clickable links |
| myvar           | Name of var used to hold this instantiation globally    |

Note "myvar" is needed so it can be passed to the click handling callback.


@section gtclick Lwsgt click handling function

When a clickable link produced by lwsgt is clicked, the function named in the
click_cb parameter to lwsgt_initial is called.

That function is expected to take four parameters, eg

`function lwsgt_dir_click(gt, u, col, row)`

| Parameter | Description                                               |
|------- ---|-----------------------------------------------------------|
| gt        | Name of global var holding this lwsgt context (ie, myvar) |
| u         | Link "url" string                                         |
| col       | Table column number link is from                          |
| row       | Table row number link is from                             |



@section gtgj Generic-table JSON

### Column layout

When the ws connection is established, the protocol should send a JSON message
describing the table columns.  For example

```
	  "cols": [
		{ "name": "Date" },
		{ "name": "Size", "align": "right" },
		{ "name": "Icon" },
		{ "name": "Name", "href": "uri"},
		{ "name": "uri", "hide": "1" }
	    ]
	  }
```

 - This describes 5 columns

 - Only four columns (not "uri") should be visible

 - "Name" should be presented as a clickable link using "uri" as the
   destination, when a "uri" field is presented.
   
 - "Size" field should be presented aligned to the right
 
 ### Breadcrumbs
 
 When a view is hierarchical, it's useful to provide a "path" with links back
 in the "path", known as "breadcrumbs".
 
 Elements before the last one should provide a "url" member as well as the
 displayable name, which is used to create the link destination.
 
 The last element, being the current displayed page should not have a url
 member and be displayed without link style.
 
 
 ```
 	"breadcrumbs":[{"name":"top", "url": "/" }, {"name":"mydir"}]
 ```
 
 ### Table data
 
 The actual file data consists of an array of rows, containing the columns
 mentioned in the original "cols" section.
 
 ```
 	"data":[
 		{
 		 "Icon":" ",
 		 "Date":"2015-Feb-06 03:08:35 +0000",
 		 "Size":"1406",
 		 "uri":"./serve//favicon.ico",
 		 "Name":"favicon.ico"
 		}
 	]

 ```
 
 @section gtdirl Setting up protocol-lws-table-dirlisting
 
 The example protocol needs two mounts, one to provide the index.html, js and
 the protocol itself
 
 ```
 	{
	 "mountpoint": "/dirtest",
         "origin": "file:///usr/share/libwebsockets-test-server/generic-table",
	 "origin": "callback://protocol-lws-table-dirlisting",
	 "default": "index.html",
	 "pmo": [{
		"dir": "/usr/share/libwebsockets-test-server"
	 }]
	},
```

The protocol wants a per-mount option (PMO) to tell it the base directory it
is serving from, named "dir".

The other mount is there to simply serve items that get clicked on from the
table in a secure way

```
	{
	 "mountpoint": "/dirtest/serve",
         "origin": "file:///usr/share/libwebsockets-test-server",
	 "default": "index.html"
	},
```

This last bit is not related to using lwsgt itself.
