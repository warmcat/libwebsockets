# lws api test i2c

Exercises the generic i2c helpers `lws_i2c_read_regs()` and
`lws_i2c_write_regs()`, `lws_i2c_read_regs16()` and
`lws_i2c_write_regs16()` for devices with 16-bit register addresses, and
`lws_i2c_read_regs32()` and `lws_i2c_write_regs32()` for 32-bit ones, against
a simulated peripheral behind a mock `lws_i2c_ops_t`.  The mock enforces the
bus protocol at the level of the ops (START / repeated START, address and
data ACK / NAK, the master NAKing the last byte it reads), holds a 256-byte
register file, and takes 8-bit, 16-bit or 32-bit register addresses, checking
the longer ones arrive most significant byte first, so no hardware is
needed.  With `.lock` and `.unlock`, as for a bus shared between threads, it
checks each transaction holds the bus throughout and gives it back, even when
it fails, and that nothing is done on a bus that can't be taken.

Requires `LWS_WITH_DRIVERS`.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-i2c
[2026/11/01 12:00:00:0000] U: LWS API selftest: i2c
[2026/11/01 12:00:00:0000] U: Passed all i2c tests
```
