# lws-auth-device-client plugin

## Overview

This plugin provides an abstract, reusable client implementation of the RFC 8628 OAuth 2.0 Device Authorization Grant. It's designed to securely provision headless and IoT devices by exchanging an interactive pairing code for a long-lived access token. The plugin automatically handles token persistence locally on the filesystem, enabling $n$ concurrent logical devices.

By decoupling the Device Flow state machine into this plugin, any LWS application can seamlessly pair with an authorization server and obtain access tokens simply by implementing the callback ops and invoking the API.

## PVOs

The plugin is configured via Protocol Vhost Options (PVOs) to exchange ABI structures between the application and the plugin.

| PVO name | Type | Description |
|---|---|---|
| `app-auth-ops` | `struct lws_auth_device_client_ops *` | (Required) Pointer to the application's callback structure for device auth events (e.g. `auth_success`, `pairing_indication`). |
| `lws-auth-client-api` | `struct lws_auth_device_client_api **` | (Required) Pointer to where the plugin should write its API struct. The application uses this API to trigger `start_auth_flow()`. |

## lejp-conf Example

If configuring via `lejp-conf` JSON (though the ABI struct pointers are typically passed natively in C), the layout is as follows:

```json
{
	"vhosts": [{
		"name": "my-vhost",
		"ws-protocols": [{
			"lws-auth-device-client": {
				"status": "ok",
				"app-auth-ops": "my_auth_ops_ptr",
				"lws-auth-client-api": "my_auth_api_ptr"
			}
		}]
	}]
}
```

*Note: Since the PVO values must resolve to memory pointers for the ABI exchange, dynamic resolution or native C instantiation is typically required.*
