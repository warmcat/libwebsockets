# lws api test netdev creds

Stores wifi credentials for several APs with `lws_netdev_credentials_add()`,
in a settings store kept in memory, and checks

 - with none stored, there are none, and that isn't an error

 - credentials for several APs can be added, and come back from the
   settings as they went in, including passphrases and SSIDs with characters
   JSON has to escape, and an open AP's empty passphrase

 - adding them for an AP again replaces its passphrase

 - they are stored for any BSS of the AP

 - `lws_netdev_credentials_has()` and `lws_netdev_credentials_remove()`

 - too long SSIDs or passphrases are refused

 - many APs, with the longest passphrases, all of whose characters have to
   be escaped, can be stored

 - once nothing holds them, they are freed and the heap all comes back

It needs `LWS_WITH_DRIVERS`.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-netdev-creds
[2026/11/04 17:20:00:0000] U: LWS API Test - netdev credentials
[2026/11/04 17:20:00:0000] U: Completed: PASS
```
