var NAVTREE =
[
  [ "libwebsockets", "index.html", [
    [ "Libwebsockets API introduction", "index.html", null ],
    [ "Notes about building lws", "md_README.build.html", [
      [ "Introduction to CMake", "md_README.build.html#cm", null ],
      [ "Building the library and test apps", "md_README.build.html#build1", null ],
      [ "Building on Unix:", "md_README.build.html#bu", null ],
      [ "Quirk of cmake", "md_README.build.html#cmq", null ],
      [ "Building on Windows (Visual Studio)", "md_README.build.html#cmw", null ],
      [ "Building on Windows (MinGW)", "md_README.build.html#cmwmgw", null ],
      [ "Building on mbed3", "md_README.build.html#mbed3", null ],
      [ "Setting compile options", "md_README.build.html#cmco", [
        [ "Command line", "md_README.build.html#cmcocl", null ],
        [ "Unix GUI", "md_README.build.html#cmcoug", null ],
        [ "Windows GUI", "md_README.build.html#cmcowg", null ]
      ] ],
      [ "wolfSSL/CyaSSL replacement for OpenSSL", "md_README.build.html#wolf", null ],
      [ "Compiling libwebsockets with wolfSSL", "md_README.build.html#wolf1", null ],
      [ "Compiling libwebsockets with CyaSSL", "md_README.build.html#cya", null ],
      [ "Building plugins outside of lws itself", "md_README.build.html#extplugins", null ],
      [ "Reproducing HTTP2.0 tests", "md_README.build.html#http2rp", null ],
      [ "Cross compiling", "md_README.build.html#cross", null ],
      [ "Memory efficiency", "md_README.build.html#mem", null ]
    ] ],
    [ "Debugging problems", "md_README.problems.html", null ],
    [ "Notes about lwsws", "md_README.lwsws.html", [
      [ "Libwebsockets Web Server", "md_README.lwsws.html#lwsws", null ],
      [ "Build", "md_README.lwsws.html#lwswsb", null ],
      [ "Lwsws Configuration", "md_README.lwsws.html#lwswsc", null ],
      [ "Lwsws Vhosts", "md_README.lwsws.html#lwswsv", null ],
      [ "Lwsws Vhost name and port sharing", "md_README.lwsws.html#lwswsvn", null ],
      [ "Lwsws Protocols", "md_README.lwsws.html#lwswspr", null ],
      [ "Lwsws Other vhost options", "md_README.lwsws.html#lwswsovo", null ],
      [ "Lwsws Mounts", "md_README.lwsws.html#lwswsm", null ],
      [ "Lwsws Other mount options", "md_README.lwsws.html#lwswsomo", null ],
      [ "Lwsws Plugins", "md_README.lwsws.html#lwswspl", null ],
      [ "Additional plugin search paths", "md_README.lwsws.html#lwswsplaplp", null ],
      [ "lws-server-status plugin", "md_README.lwsws.html#lwswsssp", null ],
      [ "Lwsws Integration with Systemd", "md_README.lwsws.html#lwswssysd", null ],
      [ "Lwsws Integration with logrotate", "md_README.lwsws.html#lwswslr", null ]
    ] ],
    [ "Notes about coding with lws", "md_README.coding.html", [
      [ "Daemonization", "md_README.coding.html#dae", null ],
      [ "Maximum number of connections", "md_README.coding.html#conns", null ],
      [ "Libwebsockets is singlethreaded", "md_README.coding.html#evtloop", null ],
      [ "Only send data when socket writeable", "md_README.coding.html#writeable", null ],
      [ "Do not rely on only your own WRITEABLE requests appearing", "md_README.coding.html#otherwr", null ],
      [ "Closing connections from the user side", "md_README.coding.html#closing", null ],
      [ "Fragmented messages", "md_README.coding.html#frags", null ],
      [ "Debug Logging", "md_README.coding.html#debuglog", null ],
      [ "External Polling Loop support", "md_README.coding.html#extpoll", null ],
      [ "Using with in c++ apps", "md_README.coding.html#cpp", null ],
      [ "Availability of header information", "md_README.coding.html#headerinfo", null ],
      [ "TCP Keepalive", "md_README.coding.html#ka", null ],
      [ "Optimizing SSL connections", "md_README.coding.html#sslopt", null ],
      [ "Async nature of client connections", "md_README.coding.html#clientasync", null ],
      [ "Lws platform-independent file access apis", "md_README.coding.html#fileapi", null ],
      [ "ECDH Support", "md_README.coding.html#ecdh", null ],
      [ "SMP / Multithreaded service", "md_README.coding.html#smp", null ],
      [ "Libev / Libuv support", "md_README.coding.html#libevuv", null ],
      [ "Extension option control from user code", "md_README.coding.html#extopts", null ],
      [ "Client connections as HTTP[S] rather than WS[S]", "md_README.coding.html#httpsclient", null ],
      [ "Using lws vhosts", "md_README.coding.html#vhosts", null ],
      [ "How lws matches hostname or SNI to a vhost", "md_README.coding.html#sni", null ],
      [ "Using lws mounts on a vhost", "md_README.coding.html#mounts", null ],
      [ "Operation of LWSMPRO_CALLBACK mounts", "md_README.coding.html#mountcallback", null ],
      [ "Dimming webpage when connection lost", "md_README.coding.html#dim", null ]
    ] ],
    [ "Notes about generic-sessions Plugin", "md_README.generic-sessions.html", [
      [ "Enabling lwsgs for build", "md_README.generic-sessions.html#gseb", null ],
      [ "lwsgs Introduction", "md_README.generic-sessions.html#gsi", null ],
      [ "Lwsgs Integration to HTML", "md_README.generic-sessions.html#gsin", null ],
      [ "Lwsgs Overall Flow@", "md_README.generic-sessions.html#gsof", null ],
      [ "Lwsgs Configuration", "md_README.generic-sessions.html#gsconf", null ],
      [ "Lwsgs Password Confounder", "md_README.generic-sessions.html#gspwc", null ],
      [ "Lwsgs Preparing the db directory", "md_README.generic-sessions.html#gsprep", null ],
      [ "Lwsgs Email configuration", "md_README.generic-sessions.html#gsrmail", null ],
      [ "Lwsgs Integration with another protocol", "md_README.generic-sessions.html#gsap", null ]
    ] ],
    [ "Notes about generic-table", "md_README.generic-table.html", [
      [ "What is generic-table?", "md_README.generic-table.html#gtint", null ],
      [ "Enabling for build", "md_README.generic-table.html#gteb", null ],
      [ "Integrating with your html", "md_README.generic-table.html#gtinth", null ],
      [ "Lwsgt constructor", "md_README.generic-table.html#gtc", null ],
      [ "Lwsgt click handling function", "md_README.generic-table.html#gtclick", null ],
      [ "Generic-table JSON", "md_README.generic-table.html#gtgj", null ],
      [ "Setting up protocol-lws-table-dirlisting", "md_README.generic-table.html#gtdirl", null ]
    ] ],
    [ "Overview of lws test apps", "md_README.test-apps.html", [
      [ "Testing server with a browser", "md_README.test-apps.html#tsb", null ],
      [ "Running test server as a Daemon", "md_README.test-apps.html#tsd", null ],
      [ "Using SSL on the server side", "md_README.test-apps.html#sssl", null ],
      [ "Testing websocket client support", "md_README.test-apps.html#wscl", null ],
      [ "Choosing between test server variations", "md_README.test-apps.html#choosingts", null ],
      [ "Testing simple echo", "md_README.test-apps.html#echo", null ],
      [ "Testing SSL on the client side", "md_README.test-apps.html#tassl", null ],
      [ "Using the websocket ping utility", "md_README.test-apps.html#taping", null ],
      [ "fraggle Fraggle test app", "md_README.test-apps.html#ta", null ],
      [ "proxy support", "md_README.test-apps.html#taproxy", null ],
      [ "debug logging", "md_README.test-apps.html#talog", null ],
      [ "Websocket version supported", "md_README.test-apps.html#ws13", null ],
      [ "Latency Tracking", "md_README.test-apps.html#latency", null ],
      [ "Autobahn Test Suite", "md_README.test-apps.html#autobahn", null ],
      [ "Autobahn Test Notes", "md_README.test-apps.html#autobahnnotes", null ]
    ] ],
    [ "Deprecated List", "deprecated.html", null ],
    [ "Modules", "modules.html", "modules" ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Class Hierarchy", "hierarchy.html", "hierarchy" ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", null ],
        [ "Functions", "functions_func.html", null ],
        [ "Variables", "functions_vars.html", null ]
      ] ]
    ] ],
    [ "Files", null, [
      [ "File List", "files.html", "files" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", null ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"annotated.html",
"group__context-and-vhost.html#gga41c2d763f78cc248df3b9f8645dbd2a5aa0158b4e85420811e6b0f1378c6ded0f",
"group__service.html#gad82efa5466d14a9f05aa06416375b28d",
"group__wsstatus.html#gaeca4afc94b1f026034f99cbba37e2f85",
"structlws__http__mount.html#aabec1a326780aafe11b977000983be0c"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';