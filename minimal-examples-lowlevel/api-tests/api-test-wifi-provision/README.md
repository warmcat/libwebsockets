# lws api test wifi provision

Checks the wifi settings html, and giving a device wifi credentials from a
browser while it is an AP of its own, `lws_wifi_provision_create()`.

There's no real wifi: a fake wifi netdev, "wl0", has two APs in its scan
results, a WPA2 one and an open one whose SSID has characters html has to
escape, and when it is asked to be an AP, its AP's address is this host,
127.0.0.1.  The settings are kept in memory, and the system's reboot op only
counts the reboots asked for.  The test is a client of the server it creates,
on `--port`.

It checks

 - `lws_html_w_t` escapes text and url arguments, and refuses what doesn't
   fit rather than give something truncated

 - `lws_wifi_settings_href()` understands the settings' links, and refuses
   SSIDs that are empty or too long

 - with no credentials, it becomes an AP at once, named for the hostname,
   eg, "lws-a1b2c3", and serves the settings: the APs scanned, escaped, with
   their links, the settings' css, the icons given to it, and 404 for
   anything else

 - the page for an AP's link has a form for its passphrase, or a Join button
   for an open AP, and a passphrase that is too short is refused

 - an unknown action is a 400

 - the hostname can be set, redirecting back to the settings, which show it,
   and one that isn't valid is refused

 - storing a passphrase stores the credentials, says it's restarting, and the
   system's reboot op is called a few seconds later, the AP stopped

 - with credentials that never worked, it waits for them to join, then
   becomes an AP when they don't, and stops being one when they join after all

 - a reset button already held when it starts, on a fake gpio so it sends
   no events, is seen by `lws_button_is_down()`: let go before it's held
   long enough it isn't taken as still held, and held long enough it forgets
   the credentials and restarts

 - with credentials that worked before, it doesn't become an AP

## Options

|Option|Meaning|
|---|---|
|--port <port>|Port to serve the settings on, default 7681|
|--help|Show this help information|

## build

```
 $ cmake .. -DLWS_WITH_DRIVERS=1 -DLWS_WITH_SYS_SMD=1 -DLWS_WITH_MINIMAL_EXAMPLES=1 && make
```

## usage

```
 $ ./bin/lws-api-test-wifi-provision
[2026/11/13 10:00:00:0000] U: LWS API Test - wifi provision
...
[2026/11/13 10:00:12:0000] U: Completed: PASS
```
