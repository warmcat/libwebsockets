# lws-api-test-transport-sequencer-restart

Two transport sequencers, A sending to B, over a network simulated in this
process that can drop chosen chunks.

 - **B restarts in the middle of A's stream.**  The new B receives from 0,
   while A's stream carries on past the new B's window.  Told B lost its
   session, A renumbers what B hadn't acked from 0 with
   `lws_transport_sequencer_tx_rebase()` and sends it again: the new B gets
   it, in order, and A's session completes.

 - **B never takes one chunk**, but takes and acks the ones written after it.
   A's session fails on time, instead of resending that chunk forever.

```
$ ./lws-api-test-transport-sequencer-restart
[2026/10/22 09:40:00:0000] U: LWS API selftest: transport sequencer, peer restart and stuck chunk
[2026/10/22 09:40:00:0000] U: B acked up to 3072, restarting it
[2026/10/22 09:40:00:0000] U: the restarted B got the rest of A's stream
[2026/10/22 09:40:01:0000] U: A gave up on the chunk B refuses, after 15 more chunks were acked
[2026/10/22 09:40:01:0000] U: Completed: PASS
```
