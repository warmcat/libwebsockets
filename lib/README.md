## Library sources layout

Code that goes in the libwebsockets library itself lives down ./lib

Path|Sources
---|---
lib/core|Core lws code related to generic fd and wsi servicing and management
lib/event-libs|Code containing optional event-lib specific adaptations
lib/misc|Code for various mostly optional miscellaneous features
lib/plat|Platform-specific adaptation code
lib/roles|Code for specific optional wsi roles, eg, http/1, h2, ws, raw, etc
lib/tls|Code supporting the various TLS libraries
libwebsockets.h|Public API header for the whole of lws

