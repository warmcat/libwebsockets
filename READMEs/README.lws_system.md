# `lws_system`

See `include/libwebsockets/lws-system.h` for function and object prototypes.

## System integration api

`lws_system` allows you to set a `system_ops` struct at context creation time,
which can write up some function callbacks for system integration.  The goal
is the user code calls these by getting the ops struct pointer from the
context using `lws_system_get_ops(context)` or `lws_system_get_info()` and
so does not spread system dependencies around the user code.

```
typedef struct lws_system_ops {
	int (*get_info)(lws_system_item_t i, lws_system_arg_t *arg);
	int (*reboot)(void);
	int (*set_clock)(lws_usec_t us);
} lws_system_ops_t;
```

### `get_info`

This allows the user code to query some common system values without introducing
any system dependencies in the code itself.  The defined item numbers are

|Item|Meaning|
|---|---|
|`LWS_SYSI_HRS_DEVICE_MODEL`|String describing device model|
|`LWS_SYSI_HRS_DEVICE_SERIAL`|String for the device serial number|
|`LWS_SYSI_HRS_FIRMWARE_VERSION`|String describing the current firmware version|
|`LWS_SYSI_HRS_NTP_SERVER`|String with the ntp server address (defaults to pool.ntp.org)|

### `reboot`

Reboots the device

### `set_clock`

Set the system clock to us-resolution Unix time in secods

## System state and notifiers

Lws implements a state in the context that reflects the readiness of the system for various
steps leading up to normal operation.  By default it acts in a backwards-compatible way and
directly reaches the OPERATIONAL state just after the context is created.

However other pieces of lws and user code may define notification handlers that get called
back with desired state changes and may veto or delay them until work necessary for the new
state has completed asynchronously.  The states defined are

|State|Meaning|
|---|---|
|`LWS_SYSTATE_CONTEXT_CREATED`|The context was just created.|
|`LWS_SYSTATE_INITIALIZED`|The vhost protocols have been initialized|
|`LWS_SYSTATE_TIME_VALID`|The system knows the time|
|`LWS_SYSTATE_POLICY_VALID`|If the system needs information about how to act from the net, it has it|
|`LWS_SYSTATE_OPERATIONAL`|The system is ready for user code to work normally|
|`LWS_SYSTATE_POLICY_INVALID`|All connections are being dropped because policy information is changing.  It will transition back to `LWS_SYSTATE_INITIALIZED` afterwards with the new policy|

### Inserting a notifier

You should create an object `lws_system_notify_link_t` in non-const memory and zero it down.
Set the `notify_cb` member and the `name` member and then register it using either
`lws_system_reg_notifier()` or the `.register_notifier` member of the context creation info
struct to make sure it will exist early enough to see all events.

