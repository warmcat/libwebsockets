# lws-rtc-camera plugin

## Overview

This plugin implements a WebRTC camera integration within libwebsockets. It manages V4L2 device capture, multimedia encoding, and secure routing to an `lws-webrtc-mixer` endpoint. The plugin encapsulates complex multimedia pipelines behind a simple operational API that the application can trigger dynamically.

**Important:** This plugin requires `protocol_lws_auth_device_client` to be enabled to operate securely. The authentication plugin handles the RFC 8628 Device Authorization Flow to securely pair headless cameras with the mixer and acquire the necessary access tokens required by `protocol_lws_rtc_camera` during the attachment phase.

## PVOs

The plugin is configured via Protocol Vhost Options (PVOs) to exchange ABI structures between the application and the plugin.

| PVO name | Type | Description |
|---|---|---|
| `lws-webrtc-ops` | `struct lws_webrtc_ops **` | Pointer to receive the underlying `protocol_lws_webrtc` ops, allowing this plugin to bind to the WebRTC subsystem. |
| `lws-rtc-camera-ops` | `struct lws_rtc_camera_ops **` | Pointer to where the plugin should write its operational API struct (`cam_ops`). The application invokes this to trigger camera attachment/detachment. |
| `app-ops` | `struct lws_rtc_camera_ops *` | (Optional) Pointer to the application's callback structure to receive notifications on camera state changes (e.g. `state_cb`). |

## lejp-conf Example

Below is an example of configuring the camera plugin through JSON:

```json
{
	"vhosts": [{
		"name": "my-camera-vhost",
		"ws-protocols": [{
			"lws-rtc-camera": {
				"status": "ok",
				"lws-webrtc-ops": "my_webrtc_ops_ptr",
				"lws-rtc-camera-ops": "my_cam_ops_ptr",
				"app-ops": "my_app_ops_ptr"
			}
		}]
	}]
}
```

*Note: Since the PVO values must resolve to memory pointers for the ABI exchange, dynamic resolution or native C instantiation is typically required in practice.*
