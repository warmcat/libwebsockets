# lws-api-test-ss-policy

Confirms that a JSON Secure Streams policy the parser rejects is thrown away
cleanly, and leaves the policy that was in force before it alone.

The context starts with the policy given by `-c`, which has a client
streamtype `polt_cli` and a tls server streamtype `polt_srv` whose cert and
key come from the policy.

|step|what is fed|must happen|
|---|---|---|
|fetched|documents the parser must reject, each defining a cert before the part that is rejected (unknown trust store cert, trust store stack before its name, unknown server cert, a kept server cert followed by an unknown trust store cert), fed the way the fetch_policy system stream feeds a policy from the network|each is rejected, `polt_cli` still exists and no streamtype from the rejected document does|
|truncated|a document that stops partway through a cert, then abandoned twice, as a fetch that disconnects and is then destroyed does|the original policy is still in force|
|overlay|the same rejected documents as `lws_ss_policy_overlay()` on the live policy|each is rejected and the live policy is still usable|
|server|creating `polt_srv`, after all the rejected documents above, some of which kept server certs of their own before failing|it comes up with the original policy's cert and key|
|metadata|a streamtype with 256 metadata, and a metadata value of 256 bytes|both are rejected (a policy streamtype counts its metadata in a `uint8_t`, and the value length is a `uint8_t`), and one with 255 metadata is accepted with all 255|
|valid|a valid document whose one metadata value is 255 bytes, longer than one lejp string chunk, then abandoned|it parses to one metadata item holding the whole value, and abandoning it puts the original policy back|

Build lws with `-DLWS_WITH_ASAN=1` to see the teardown of the rejected
documents is clean.

## Switches

|Option|Meaning|
|---|---|
|-c <path>|The JSON policy to start with|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-policy
```
