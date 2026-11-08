# lws api test i2c

Exercises the generic i2c helpers `lws_i2c_read_regs()` and
`lws_i2c_write_regs()`, and `lws_i2c_read_regs16()` and
`lws_i2c_write_regs16()` for devices with 16-bit register addresses, against
a simulated peripheral behind a mock `lws_i2c_ops_t`.  The mock enforces the
bus protocol at the level of the ops (START / repeated START, address and
data ACK / NAK, the master NAKing the last byte it reads), holds a 256-byte
register file, and takes either 8-bit or 16-bit register addresses, checking
the 16-bit ones arrive most significant byte first, so no hardware is
needed.

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
