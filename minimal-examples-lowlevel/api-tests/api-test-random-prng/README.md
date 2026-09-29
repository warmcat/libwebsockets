# lws api test random-prng

Fault injection's seeded PRNG in place of the platform random source
(`READMEs/README.fault-injection.md`, "Replacing the random source with a
seeded PRNG"), needing `-DLWS_WITH_SYS_FAULT_INJECTION=1`.

It checks that:

 - with the fault `random_prng` in the creation info's fic, the context's
   `lws_get_random()` is a stream seeded from the fic's seed: two contexts
   with the same seed draw the same bytes
 - another seed draws other bytes
 - faults consuming the fault context's own PRNG between draws do not move
   the random stream
 - `lws_fi_random_seed()` seeds a context created without the fault, and
   seed 1234 gives a known vector (xoshiro256** seeded by splitmix64,
   results little-endian), which a port replaying lws' transcripts must
   produce too; seeding again restarts the stream
 - a context without either still gets the platform's random

## build

```
 $ cmake .. -DLWS_WITH_SYS_FAULT_INJECTION=1 && make
```

## usage

```
 $ ./bin/lws-api-test-random-prng
[2026/09/29 10:00:00:0000] U: LWS API selftest: seeded random source
...
[2026/09/29 10:00:00:0000] U: Completed: PASS
```
