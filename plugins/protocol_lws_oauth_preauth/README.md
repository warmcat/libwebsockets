# lws-oauth-preauth

This plugin provides a WebSocket-based waiting room for devices that have not yet been paired/authorized via RFC 8628 (OAuth 2.0 Device Authorization Grant). It acts as an intermediary signaling channel where pre-authenticated admin clients can securely identify and interact with unauthenticated devices before full pairing.

## Features

- Maintains a list of connected unauthenticated "devices" and authorized "listeners" (admins).
- Validates authorized admin listeners via JWT (JSON Web Tokens) provided via an HTTP cookie.
- Allows admins to discover unauthenticated devices currently waiting for pairing.
- Facilitates sending "identify" commands to specific devices, often used to trigger a physical indication (like a blinking LED) so the admin can verify physical possession of the device before authorizing it.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `cookie-name` | The name of the HTTP cookie that carries the JWT for admin validation. | `auth_session` |
| `jwt-jwk` | The JSON Web Key (JWK) string used to verify the JWT signature. Can be the literal JSON or a path to a file depending on LWS configuration. | N/A |
| `max-devices` | Maximum number of unauthenticated devices pending simultaneously, bounding what they can hold open. When the room is full, a new device displaces the oldest device that has never announced a `serial`; if every device has, the newcomer is refused. `0` disables the cap. | `32` |
| `max-devices-per-peer` | Maximum pending devices from one peer address. A peer at its cap displaces its own oldest device (a silent one first), so one address can only ever evict itself, never another peer's devices. `0` disables the cap. Raise it where many devices pair at once from behind one NAT. | `8` |

## Operation

- **Devices**: Devices connect to this protocol over WebSocket and send JSON payloads containing their identifying information (`name`, `serial`, `user_code`).
- **Listeners (Admins)**: Admins connect to the same protocol, providing their JWT cookie. If validation succeeds, they are registered as a listener.
- **Broadcast**: When a device connects or disconnects, the plugin broadcasts its state to all connected listeners.
- **Identification**: A listener can send `{"cmd": "identify", "serial": "<device-serial>"}`. The plugin will route this `identify` command down to the target device, allowing it to perform a physical identification action (e.g., blink an LED).
