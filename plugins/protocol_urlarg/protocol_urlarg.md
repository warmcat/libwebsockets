# lws-urlarg-protocol

## Introduction

The `lws-urlarg-protocol` plugin is a simple testing resource. It examines incoming HTTP requests and queries the URL arguments for a specific argument named `x` using `lws_get_urlarg_by_name_safe`. If found, it responds to the client by sending back an HTTP 200 OK along with an HTML snippet showing the isolated value of `x`.

The value of `x` is attacker-controlled and is echoed into a `text/html` body, so it is HTML-escaped (`&`, `<`, `>`, `"` and `'`) before being sent.  Values longer than 2048 bytes are not accepted.

If there is no usable `x` argument, the plugin answers HTTP 400 with a short static page explaining the usage, rather than announcing a `content-length` for a body it will never send.

## Per-Vhost Options (PVOs)

This plugin does not utilize any Per-Vhost Options (PVOs) for its instantiation configuration.
