# lhp (HTML renderer) embedded demos

These are demos for various ESP32 + display combinations.  A lot of
the code is common between the demos and is in the toplevel dir
(where this README lives).

Notice that although the demos are for ESP32 currently, there is no
ESP32-specific code in the common part.  Only `main/devices.c` in the
combination-specific directories has the platform-specific init.

The demo visits each of a short list of pages using h2 and renders them
on the device + display combination, 10s apart.  When the last one is on
the display it logs `Completed: PASS`, which is what Sai's `sai-expect`
looks for when the demo runs as a CI test, and leaves it there.

ESP32 WROVER KIT, and ESP32S2 Kaluga boards and displays are
supported, along with Waveshare ESP32 dev board and a variety of
E-ink displays.

## Setting up wifi

Edit ./main/devices.c in your platform-specific subdir, enable this section
 and set your wifi SSID and passphrase in the `xxx` strings.  This will store
the information on flash on the device.

Boot once with that and then remove your information and disable the code
section again and rebuild.

```
#if 0
	/*
	 * This is a temp hack to bootstrap the settings to contain the test
	 * AP ssid and passphrase for one time, so the settings can be stored
	 * while there's no UI atm
	 */
	{
		lws_wifi_creds_t creds;

		memset(&creds, 0, sizeof(creds));

		lws_strncpy(creds.ssid, "xxx", sizeof(creds.ssid));
		lws_strncpy(creds.passphrase, "xxx", sizeof(creds.passphrase));
		lws_dll2_add_tail(&creds.list, &netdevs->owner_creds);

		if (lws_netdev_credentials_settings_set(netdevs)) {
			lwsl_err("%s: failed to write bootstrap creds\n",
					__func__);
			return 1;
		}
	}
#endif
```

Eventually there will be a better way to set this up.

## Building

Set up for esp-idf, enter the platform-specific subdir and edit
`build.sh` to point to the correct USB device path.

OTA update support needs the public key the firmware manifests are signed
with, `~/.lws_ota/libwebsockets.org-ota-v1.public.jwk`.  Without it the
`esp32-waveshare-104-212` example builds with OTA off, which is how CI
builds it.

The first time we need to erase the whole flash and blow the whole
image and partition table

```
 $ ./build.sh erase-flash
 $ ./build.sh
```

Afterwards you can force-build like this which flashes both OTA
partitions with the new imahe

```
 $ ./build.sh f
```

After you have changed `./build.sh` to your own OTA keys and upload path, and adapted the
policy to look at your firmware server, you will typically build via uploading to that,
which resets the board so it can find and install the update and reboot

```
 $ ./build.sh u
```

