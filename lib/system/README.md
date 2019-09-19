# LWS System Helpers

Lws now has a little collection of helper utilities for common network-based
functions necessary for normal device operation, eg, async DNS, ntpclient
(necessary for tls validation), and DHCP client.

## Conventions

If any system helper is enabled for build, lws creates an additional vhost
"system" at Context Creation time.  Wsi that are created for the system
features are bound to this.  In the context object, this is available as
`.vhost_system`.

