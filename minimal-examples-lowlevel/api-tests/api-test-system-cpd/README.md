# api test system CPD gating

Confirms that once the platform stack has done the DHCP and reported an IP on
an interface via an SMD "ipacq" message, system state progression continues to
OPERATIONAL without waiting on the outcome of lws' own captive portal
detection, which is advisory.  It also confirms that before any interface has
an IP, system progress is still held at the DHCP gate.

No network connectivity is needed, the CPD streamtype is deliberately not in
any policy so the CPD attempt cannot complete.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
 $ ./lws-api-test-system-cpd
[2026/08/31 10:13:41:7683] U: LWS API selftest: system CPD gating
[2026/08/31 10:13:42:5246] U: Phase 1: held before OPERATIONAL with no IP: PASS
[2026/08/31 10:13:42:6011] U: smd_cb: reached OPERATIONAL after ipacq
[2026/08/31 10:13:42:6012] U: Completed: ALL PASS
```
