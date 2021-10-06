# SS example for RT595S Eval Board

## Overview

This example uses serialized Secure Streams to run the binance example and a
simple get example stream on the RT595S eval board, via an SS proxy over the
UART / CDC ACM link, with no networking available at the RT595S.

It operates over a composite CDC ACM (ie, serial port) USB device link to a
host PC, one CDC channel is used to show logs from the RT595S and the second is
used to pass serialized SS to the SS proxy to make it work.

It shows live information from binance, and every 5s does a get from
libwebsockets.org and dumps the start and end of each chunk, demonstrating
multiple streams working simultaneously over a single ACM link.

## Setting up

1) Set SW7 boot mode `1: OFF, 2: OFF, 3: ON`

2) Hook J40 Micro USB B to Host PC -- this is the flashing tool connection
   and appears as `/dev/ttyACM0`

3) Hook J38 Micro USB B to Host PC -- this is the user USB connection we will
   be controlling with this example, after it is flashed and running, it will
   appear as `/dev/ttyACM1` and `2`

4) Build lws on the host PC with `-DLWS_WITH_MINIMAL_EXAMPLES=1` and
   `-DLWS_WITH_SECURE_STREAMS_PROXY_API=1`, it should produce an example in
   the build dir `./bin/lws-minimal-ssproxy-custom-transport-uart`

## Building

First edit the `TOOLCHAIN_PATH` at the top of CMakeLists.txt in this dir to
point to the NXP toolchain

A typical path is like

```
set(TOOLCHAIN_PATH "/usr/local/mcuxpressoide-11.4.1_6260/ide/plugins/com.nxp.mcuxpresso.tools.linux_11.4.0.202103011116/tools/bin/arm-none-eabi")
```

Then build this example in a build dir

```
$ mkdir build     <<<=== the subdir build is mandatory
$ cd build
$ cmake .. && make
```

...that builds a tiny libwebsockets.a and produces the `rt500-hello.axf`
selfcontained elf already linked to the library.

## Flashing the RT595S eval board

To flash the board, run the commandline flasher that is part of mcuxpresso IDE,
its path is like this

```
$ /usr/local/mcuxpressoide-11.4.1_6260/ide/plugins/com.nxp.mcuxpresso.tools.bin.linux_11.4.0.202109131312/binaries/crt_emu_cm_redlink
  -flash-load-exec rt500-hello.axf \
  -vendor=NXP \
  -flash-driver=MIMXRT500_SFDP_MXIC_OSPI.cfx \
  -p MIMXRT595S \
  -x ../project/Debug
```

This will look like

```
Ns: MCUXpresso IDE RedlinkMulti Driver v11.4 (Sep 13 2021 15:09:55 - crt_emu_cm_redlink build 16)
Wc(03). No cache support.
Nc: Found chip XML file in ../project/Debug/MIMXRT595S.xml
Nc: Reconnected to existing LinkServer process.
Nc: Probe Firmware: LPC-LINK2 CMSIS-DAP V5.361 (NXP Semiconductors)
Nc: Serial Number:  FRAQBQAR
Nc: VID:PID:  1FC9:0090
Nc: USB Path: /dev/hidraw7
Nc: Using memory from core 0 after searching for a good core
Pc: ( 30) Emulator Connected
Nc: processor is in secure mode
Pc: ( 40) Debug Halt
Pc: ( 50) CPU ID
Nc: debug interface type      = CoreSight DP (DAP DP ID 6BA02477) over SWD TAP 0
Nc: processor type            = Cortex-M33 (CPU ID 00000D21) on DAP AP 0
Nc: number of h/w breakpoints = 8
Nc: number of flash patches   = 0
Nc: number of h/w watchpoints = 4
Nc: Probe(0): Connected&Reset. DpID: 6BA02477. CpuID: 00000D21. Info: <None>
Nc: Debug protocol: SWD. RTCK: Disabled. Vector catch: Disabled.
Ns: Content of CoreSight Debug ROM(s):
Nc: RBASE E00FE000: CID B105100D PID 0000095000 ROM (type 0x1)
Nc: ROM 1 E00FF000: CID B105100D PID 04000BB4C9 ROM (type 0x1)
Nc: ROM 2 E000E000: CID B105900D PID 04000BBD21 CSt ARM ARMv8-M type 0x0 Misc - Undefined
Nc: ROM 2 E0001000: CID B105900D PID 04000BBD21 CSt ARM DWTv2 type 0x0 Misc - Undefined
Nc: ROM 2 E0002000: CID B105900D PID 04000BBD21 CSt ARM FPBv2 type 0x0 Misc - Undefined
Nc: ROM 2 E0000000: CID B105900D PID 04000BBD21 CSt ARM ITMv2 type 0x43 Trace Source - Bus
Nc: ROM 2 E0041000: CID B105900D PID 04002BBD21 CSt ARM ETMv4.0 type 0x13 Trace Source - Core
Nc: ROM 2 E0042000: CID B105900D PID 04000BBD21 CSt ARM CTIv2 type 0x14 Debug Control - Trigger, e.g. ECT
Nc: ROM 1 E0040000: CID B105900D PID 04000BBD21 CSt type 0x11 Trace Sink - TPIU
Nc: NXP: MIMXRT595S
Nc: DAP stride is 1024 bytes (256 words)
Nc: Inspected v.2 External Flash Device on SPI using SFDP JEDEC ID MIMXRT500_SFDP_MXIC_OSPI.cfx
Nc: Image 'iMXRT500_SFDP_MXIC_OSPI Sep 14 2021 15:07:17'
Nc: Opening flash driver MIMXRT500_SFDP_MXIC_OSPI.cfx
Nc: Sending VECTRESET to run flash driver
Nc: Flash variant 'JEDEC_FlexSPI_Device' detected (64MB = 1024*64K at 0x8000000)
Nc: Closing flash driver MIMXRT500_SFDP_MXIC_OSPI.cfx
Nt: Loading 'rt500-hello.axf' ELF 0x08000000 len 0x17F90
Nc: Opening flash driver MIMXRT500_SFDP_MXIC_OSPI.cfx (already resident)
Nc: Sending VECTRESET to run flash driver
Nc: Flash variant 'JEDEC_FlexSPI_Device' detected (64MB = 1024*64K at 0x8000000)
Nc: Sectors written: 2, unchanged: 0, total: 2
Nc: Closing flash driver MIMXRT500_SFDP_MXIC_OSPI.cfx
Nt: Loaded 0x17F90 bytes in 1094ms (about 89kB/s)
Nt: Reset target (system)
Nc: Starting execution using system reset
Nc: processor is in non-secure mode
Nc: state - running or following reset request - re-read of state failed - rc Nn(05). Wire ACK Fault in DAP access
Xw:
```

... the last bit is normal, the cpu is reset and running the flashed code.

## Connecting a logging console

You should be able to open a terminal emulator on the host PC to `/dev/ttyACM1`,
the baud rate and other serial details are ignored, so 115200/8/N/1 is fine.
The log shows the logging of the firmware running on the RT595S, initially
something like

```
17227078: (null): sul_ping_cb: no PONG came
19227106: (null): sul_ping_cb: issuing ping
21227133: (null): sul_ping_cb: no PONG came
23227160: (null): sul_ping_cb: issuing ping
25227186: (null): sul_ping_cb: no PONG came
27227214: (null): sul_ping_cb: issuing ping
29227240: (null): sul_ping_cb: no PONG came
```

since there is no SS proxy for it to link up to yet.

If you run on the host PC from the lws build dir

```
$ ./bin/lws-minimal-ssproxy-custom-transport-uart -i /dev/ttyACM2
```

then after a second or two the RT595 firmware and the SS proxy should link up
over ttyACM2, and start updating the bitcoin information and dumping the GET
every 5s.  That looks like this kind of thing

```
155228906: (null): sul_ping_cb: issuing ping
157228932: (null): sul_ping_cb: no PONG came
157633108: lws_sspc_create: txp path txp_inside_sspc -> txpmuxc
157633235: (null): lws_transport_mux_retry_connect
157633286: (null): lws_transport_path_client_dump: lws_transport_mux_retry_connect: MUX: 0x852ec, IN: ops=txp_inside_sspc, priv=0x853f8, ONW: ops=txpmuxc, priv=0x0
157633333: (null): lws_transport_mux_retry_connect: transport not operational
157633375: binance_state: LWSSSCS_UPSTREAM_LINK_RETRY (18), ord 0x0
157633444: lws_sspc_create: txp path txp_inside_sspc -> txpmuxc
157633481: (null): lws_transport_mux_retry_connect
157633530: (null): lws_transport_path_client_dump: lws_transport_mux_retry_connect: MUX: 0x852ec, IN: ops=txp_inside_sspc, priv=0x876d4, ONW: ops=txpmuxc, priv=0x0
157633579: (null): lws_transport_mux_retry_connect: transport not operational
157633616: get_state: LWSSSCS_UPSTREAM_LINK_RETRY (18), ord 0x0
157633685: (null): lws_transport_mux_rx_parse: got PING
157633779: (null): lws_transport_mux_pending: send RESET_TRANSPORT
157633824: (null): lws_transport_mux_pending: issuing PING
157633864: (null): lws_transport_mux_pending: issuing PONG
157633924: (null): lws_transport_path_client_dump: cpath: MUX: 0x0, IN: ops=txpmuxc, priv=0x852ec (IsTM), ONW: ops=txpserial, priv=0x0
157633966: (null): txp_serial_write: writing 27
157634016: (null): lws_transport_mux_rx_parse: PONG payload mismatch 0xab4fba 0x9654d3d
157634180: (null): lws_transport_mux_rx_parse: got PONG
157634213: (null): lws_transport_mux_rx_parse: got PONGACK: ustime 1635076485985673
157634252: (null): lws_transport_set_link: ******* transport mux link is UP
157634305: (null): lws_transport_mux_pending: issuing PONGACK
157634370: (null): lws_transport_path_client_dump: cpath: MUX: 0x0, IN: ops=txpmuxc, priv=0x852ec (IsTM), ONW: ops=txpserial, priv=0x0
157634414: (null): txp_serial_write: writing 9
158633431: (null): lws_transport_mux_retry_connect
158633480: (null): lws_transport_path_client_dump: lws_transport_mux_retry_connect: MUX: 0x852ec, IN: ops=txp_inside_sspc, priv=0x853f8, ONW: ops=txpmuxc, priv=0x0
158633537: (null): lws_transport_mux_retry_connect: added channel
158633618: (null): lws_transport_path_client_dump: cpath: MUX: 0x0, IN: ops=txpmuxc, priv=0x852ec (IsTM), ONW: ops=txpserial, priv=0x0
158633659: (null): txp_serial_write: writing 2
158633689: (null): lws_transport_mux_retry_connect
158633737: (null): lws_transport_path_client_dump: lws_transport_mux_retry_connect: MUX: 0x852ec, IN: ops=txp_inside_sspc, priv=0x876d4, ONW: ops=txpmuxc, priv=0x0
158633788: (null): lws_transport_mux_retry_connect: added channel
158633890: (null): lws_transport_path_client_dump: cpath: MUX: 0x0, IN: ops=txpmuxc, priv=0x852ec (IsTM), ONW: ops=txpserial, priv=0x0
158633931: (null): txp_serial_write: writing 2
158634079: (null): lws_transport_mux_rx_parse: ch 255 fully open
158634112: ltm_ch_opens: 0
158634143: lws_sspc_txp_connect_disposition: CONNECTED (binance), txpmuxc
158634213: (null): lws_transport_mux_write: 19
158634249: (null): txp_serial_write: writing 23
158634292: (null): lws_transport_mux_rx_parse: ch 254 fully open
158634330: ltm_ch_opens: 0
158634358: lws_sspc_txp_connect_disposition: CONNECTED (mintest-lws), txpmuxc
158634456: (null): lws_transport_mux_write: 23
158634484: (null): txp_serial_write: writing 27
158634845: lws_ss_serialize_state_transition: LPCSCLI_WAITING_CREATE_RESULT -> LPCSCLI_LOCAL_CONNECTED
158634896: lws_ss_check_next_state_sspc: (unset) -> LWSSSCS_CREATING
158634933: binance_state: LWSSSCS_CREATING (1), ord 0x0
158635016: lws_sspc_txp_tx: (local_conn) onward connect
158635062: (null): lws_transport_mux_write: 3
158635089: (null): txp_serial_write: writing 7
158635144: lws_ss_check_next_state_sspc: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
158635191: binance_state: LWSSSCS_CONNECTING (6), ord 0x0
158635303: lws_ss_serialize_state_transition: LPCSCLI_WAITING_CREATE_RESULT -> LPCSCLI_LOCAL_CONNECTED
158635345: lws_ss_check_next_state_sspc: (unset) -> LWSSSCS_CREATING
158635381: get_state: LWSSSCS_CREATING (1), ord 0x0
158635467: lws_sspc_txp_tx: (local_conn) onward connect
158635503: (null): lws_transport_mux_write: 3
158635530: (null): txp_serial_write: writing 7
158635816: lws_ss_check_next_state_sspc: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
158635853: get_state: LWSSSCS_CONNECTING (6), ord 0x0
159693591: lws_sspc_deserialize_parse: CONNECTED binance
159693623: lws_ss_serialize_state_transition: LPCSCLI_LOCAL_CONNECTED -> LPCSCLI_OPERATIONAL
159693665: lws_ss_check_next_state_sspc: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
159693701: binance_state: LWSSSCS_CONNECTED (5), ord 0x0
160693746: (null): sul_hz_cb: price: min: 6031470¢, max: 6032348¢, avg: 6031713¢, (31 prices/s)
160693801: (null): sul_hz_cb: elatency: min: 136ms, max: 361ms, avg: 206ms, (31 msg/s, 72 KiBytes/s SS RX)
161693748: (null): sul_hz_cb: price: min: 6028681¢, max: 6032500¢, avg: 6030043¢, (30 prices/s)
161693801: (null): sul_hz_cb: elatency: min: 136ms, max: 175ms, avg: 144ms, (30 msg/s, 126 KiBytes/s SS RX)
162693751: (null): sul_hz_cb: price: min: 5968822¢, max: 6029283¢, avg: 6026034¢, (30 prices/s)
162693812: (null): sul_hz_cb: elatency: min: 135ms, max: 173ms, avg: 142ms, (30 msg/s, 123 KiBytes/s SS RX)
162800988: get_rx: RX 5, flags 0x43
162801104: (null): 0000: 7B 22 70 65 65 00 00 00 00 00 00 F4 3C A8 9B AA    {"pee.......<...
162801135: (null): 
162801221: lws_sspc_deserialize_parse: CONNECTED mintest-lws
162801254: lws_ss_serialize_state_transition: LPCSCLI_LOCAL_CONNECTED -> LPCSCLI_OPERATIONAL
162801297: lws_ss_check_next_state_sspc: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
162801335: get_state: LWSSSCS_CONNECTED (5), ord 0x0
162802084: get_rx: RX 1520, flags 0x1
162802194: (null): 0000: 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 0A    <!DOCTYPE html>.
162802226: (null): 
162802318: (null): 0000: 3C 6C 69 3E 38 30 20 6D 69 6E 69 6D 61 6C 20 65    <li>80 minimal e
162802352: (null): 
162802731: get_rx: RX 1520, flags 0x0
162802840: (null): 0000: 78 61 6D 70 6C 65 73 3A 20 3C 61 20 68 72 65 66    xamples: <a href
162802872: (null): 
162802964: (null): 0000: AD 98 3C 2F 74 64 3E 3C 74 64 20 63 6C 61 73 73    ..</td><td class
162802998: (null): 
162803403: get_rx: RX 1520, flags 0x0
162803512: (null): 0000: 3D 22 67 22 3E E2 AD 98 3C 2F 74 64 3E 3C 2F 74    ="g">...</td></t
162803544: (null): 
162803636: (null): 0000: 77 65 62 73 6F 63 6B 65 74 73 2F 74 72 65 65 2F    websockets/tree/
162803670: (null): 
162804105: get_rx: RX 1520, flags 0x0
162804215: (null): 0000: 6C 69 62 2F 65 76 65 6E 74 2D 6C 69 62 73 22 20    lib/event-libs" 
162804247: (null): 
162804339: (null): 0000: 31 36 20 69 62 22 3E 0A 20 20 20 20 20 3C 68 31    16 ib">.     <h1
162804373: (null): 
162804708: get_rx: RX 1277, flags 0x0
162804818: (null): 0000: 3E 51 41 3C 2F 68 31 3E 0A 20 20 20 20 20 20 4C    >QA</h1>.      L
162804849: (null): 
162804941: (null): 0000: 3C 2F 62 6F 64 79 3E 0A 3C 2F 68 74 6D 6C 3E 0A    </body>.</html>.
162804975: (null): 
162805084: get_rx: RX 0, flags 0x2
162805120: lws_ss_check_next_state_sspc: LWSSSCS_CONNECTED -> LWSSSCS_QOS_ACK_REMOTE
162805160: get_state: LWSSSCS_QOS_ACK_REMOTE (10), ord 0x0
162805198: lws_ss_serialize_state_transition: LPCSCLI_OPERATIONAL -> LPCSCLI_LOCAL_CONNECTED
162805239: lws_ss_check_next_state_sspc: LWSSSCS_QOS_ACK_REMOTE -> LWSSSCS_DISCONNECTED
162805276: get_state: LWSSSCS_DISCONNECTED (2), ord 0x0
163635428: (null): lws_sspc_request_tx: state 8, conn_req_state 0
163635484: lws_sspc_txp_tx: (local_conn) onward connect
163635527: (null): lws_transport_mux_write: 3
163635555: (null): txp_serial_write: writing 7
163636075: lws_ss_check_next_state_sspc: LWSSSCS_DISCONNECTED -> LWSSSCS_CONNECTING
163636114: get_state: LWSSSCS_CONNECTING (6), ord 0x0
163693754: (null): sul_hz_cb: price: min: 6025722¢, max: 6026388¢, avg: 6026199¢, (31 prices/s)
163693805: (null): sul_hz_cb: elatency: min: 134ms, max: 170ms, avg: 139ms, (31 msg/s, 72 KiBytes/s SS RX)
164693759: (null): sul_hz_cb: price: min: 6025359¢, max: 6026340¢, avg: 6025954¢, (30 prices/s)
164693810: (null): sul_hz_cb: elatency: min: 135ms, max: 143ms, avg: 137ms, (30 msg/s, 93 KiBytes/s SS RX)
...
```
