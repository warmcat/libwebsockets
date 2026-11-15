# LWS rtc class drivers

Lws provides a class for battery-backed real time clock chips, which keep the
time while the rest of the device is off.  With one, a device knows the time
as soon as it boots, without waiting for the network and ntp.

Specific chips are small "subclasses" that only know how to read and write
their registers, as a UTC `lws_civil_t`.  Currently there is

|Chip|Bus|Header|
|---|---|---|
|NXP PCF8563|i2c|`lws-pcf8563-i2c.h`|

## Using it

Define the chip statically, like other lws drivers, and attach it to the
context once its bus is initialized, eg

```
static const lws_rtc_pcf8563_t rtc = {
	.rtc = {
		lws_rtc_pcf8563_ops,
		.name		= "rtc",
	},
	.i2c			= &li2c.bb_ops,
};

	...
	lws_rtc_attach(cx, &rtc.rtc);
```

## What the class does with it

 - **At attach**, the chip is read.  If the system clock isn't set yet, and
   the chip has a time it believes, the system clock is set from it, with
   `lws_system_time_set()`, and the system state is moved on, so it can pass
   `LWS_SYSTATE_TIME_VALID` at once.  `lws_system_time_source()` says
   `LWS_SYSTIME_SRC_RTC`.

 - **ntp in the background**: with `LWS_WITH_SYS_NTPCLIENT`, when the system
   state passes `LWS_SYSTATE_TIME_VALID` on time from the rtc, ntp is asked
   anyway.  It doesn't hold anything up, since we already have a time.

 - **Keeping the chip right**: whenever ntp sets the time, the chip is set
   from it too, so it's right next boot.  `lws_rtc_set_from_system()` does the
   same at any other time, eg, the time came from somewhere else.

lws only sets the system clock itself on FreeRTOS, where it also moves timers
pending against the system clock by the step.  Elsewhere, the OS usually
looks after the system clock and any rtc itself; the time is given to
`lws_system_ops_t .set_clock()`, as ntp's is, for user code to decide.

## Believing the chip

What the chip says is untrusted: the registers must be a real time after
2020, or it isn't used.  Chips also say when their time can't be believed,
eg, the PCF8563's VL bit, set when its supply fell too low to keep counting,
or its STOP bit; then it isn't used either, until it has been set again.

The chip is only touched from the lws event loop thread.  If its bus is shared
with devices used from other threads, eg, a touch controller read from an OS
timer, give the bus `lws_i2c_ops_t .lock` and `.unlock`, eg, with
`lws_bb_i2c_ops_locked()`, so their transactions don't interleave.
