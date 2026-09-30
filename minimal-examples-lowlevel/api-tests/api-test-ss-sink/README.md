# lws-api-test-ss-sink

Confirms how creating a Secure Stream of a `"local_sink"` streamtype fails
when there is no sink for it, or the sink does not want it.

A stream of a streamtype the policy marks `"local_sink": true` does not
connect anywhere: it is bound to a stream the registered sink accepts for it.
The sink can refuse the new stream at `LWSSSCS_SINK_JOIN`, or by returning
`LWSSSSRET_DESTROY_ME` from the accepted sink stream's own `LWSSSCS_CREATING`,
`LWSSSCS_CONNECTING` or `LWSSSCS_CONNECTED`.  In every case `lws_ss_create()`
must fail cleanly for the source, leaving no handle, and any accepted sink
stream made for it must be destroyed exactly once.

The user code counts `LWSSSCS_CREATING` and `LWSSSCS_DESTROYING` for the
sources and the accepted sinks, which must balance after each case.

|case|what happens|
|---|---|
|no-sink|the streamtype `nosink` has no sink registered|
|join-refused|the sink refuses at `LWSSSCS_SINK_JOIN`|
|creating-refused|the accepted sink refuses in `LWSSSCS_CREATING`|
|connected-refused|the accepted sink refuses in `LWSSSCS_CONNECTED`|
|accepted|the sink takes the stream; destroying the source destroys the accepted sink with it|

## Switches

|Option|Meaning|
|---|---|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-sink
```
