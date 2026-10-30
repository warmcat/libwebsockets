#!/usr/bin/env python3
#
# Makes the seeds of fuzz-quic, programs in its op language (see main.c)
#
# Written in 2010 - 2026 Andy Green <andy@warmcat.com>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# The seeds the fuzzer can go furthest from carry a real TLS 1.3 ClientHello
# with QUIC's transport parameters, which isn't something to write by hand:
#
#   python3 fuzz/fuzz-quic/gen-seeds.py
#

import os, struct

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seeds')

OP_DGRAM, OP_PACKET, OP_TIME, OP_TX, OP_PEER, OP_SHORT, OP_CRYPTO, OP_STREAM = \
    range(8)

INITIAL, HANDSHAKE, APP, APP_NEXT_PHASE = range(4)

def op(o, a=0):
    return bytes([(a << 3) | o])

def u16(n): return struct.pack('>H', n)
def u24(n): return struct.pack('>I', n)[1:]

def varint(n):
    if n < 0x40: return bytes([n])
    if n < 0x4000: return struct.pack('>H', 0x4000 | n)
    return struct.pack('>I', 0x80000000 | n)

def scid(c): return b'fzqscid' + bytes([0x30 + c])

def tp(c):
    """QUIC transport parameters (RFC 9000 18.2) of client c"""
    def p(i, v): return varint(i) + varint(len(v)) + v
    return (p(0x0f, scid(c)) +		# initial_source_connection_id
            p(0x01, varint(30000)) +	# max_idle_timeout
            p(0x03, varint(1452)) +	# max_udp_payload_size
            p(0x04, varint(1048576)) +	# initial_max_data
            p(0x05, varint(262144)) +
            p(0x06, varint(262144)) +
            p(0x07, varint(262144)) +
            p(0x08, varint(100)) +	# initial_max_streams_bidi
            p(0x09, varint(100)) +
            p(0x0e, varint(4)) +		# active_connection_id_limit
            p(0x20, varint(65535)))	# max_datagram_frame_size

def ext(t, v): return u16(t) + u16(len(v)) + v

def client_hello(c, alpn=b'h3'):
    exts = (ext(0x0000, u16(7) + b'\x00' + u16(4) + b'fuzz') +
            ext(0x000a, u16(4) + u16(0x001d) + u16(0x0017)) +
            ext(0x000d, u16(6) + u16(0x0403) + u16(0x0804) + u16(0x0401)) +
            ext(0x0010, u16(len(alpn) + 1) + bytes([len(alpn)]) + alpn) +
            ext(0x002b, b'\x02' + u16(0x0304)) +
            ext(0x002d, b'\x01\x01') +
            # any 32 bytes are an x25519 public key
            ext(0x0033, u16(36) + u16(0x001d) + u16(32) +
                bytes(range(0x40 + c, 0x60 + c))) +
            ext(0x0039, tp(c)))
    body = (u16(0x0303) + bytes(range(32)) + b'\x00' +
            u16(6) + u16(0x1301) + u16(0x1302) + u16(0x1303) + b'\x01\x00' +
            u16(len(exts)) + exts)
    return b'\x01' + u24(len(body)) + body

def crypto(c, data, piece=256):
    """client c's crypto stream, as CRYPTO ops of at most piece bytes"""
    out = b''
    for i in range(0, len(data), piece):
        k = data[i:i + piece]
        out += op(OP_CRYPTO, c) + bytes([len(k) - 1]) + k
    return out

def packet(c, level, payload, repeat=False):
    return op(OP_PACKET, c | (level << 2) | (0x10 if repeat else 0)) + \
           bytes([len(payload) - 1]) + payload

def initial(c, payload, repeat=False):
    return packet(c, INITIAL, payload, repeat)

def hs_crypto(c, data):
    return op(OP_CRYPTO, c | 4) + bytes([len(data) - 1]) + data

def finished(c):
    """the client's Finished, which the harness makes"""
    return op(OP_CRYPTO, c | 8)

SID_0, SID_4, SID_CONTROL, SID_QPACK_ENC = range(4)

def stream(c, s, data, fin=False):
    out = b''
    for i in range(0, len(data), 256):
        k = data[i:i + 256]
        last = fin and i + 256 >= len(data)
        out += op(OP_STREAM, c | (s << 2) | (0x10 if last else 0)) + \
               bytes([len(k) - 1]) + k
    return out

def handshake(c, hello=None):
    """ClientHello, the server's flight, our Finished"""
    return crypto(c, hello or client_hello(c)) + time(10) + finished(c)

def h3_frame(t, payload): return varint(t) + varint(len(payload)) + payload

# h3 SETTINGS on the control stream: qpack table capacity 4096, blocked 16,
# extended CONNECT, h3 datagrams and WebTransport, as a WebTransport client
# sends
h3_control = varint(0) + h3_frame(4, varint(1) + varint(4096) +
                                     varint(7) + varint(16) +
                                     varint(8) + varint(1) +
                                     varint(0x33) + varint(1) +
                                     varint(0x2b603742) + varint(1))

def wt_connect(path=b'/wt'):
    """HEADERS of a WebTransport extended CONNECT"""
    fl = (b'\x00\x00' +
          b'\xcf' +				# :method CONNECT
          b'\x27\x02:protocol\x0cwebtransport' +	# literal name and value
          b'\xd7' +				# :scheme https
          b'\x51' + bytes([len(path)]) + path +
          b'\x50\x04fuzz' +
          # the protocol it asks for, a literal name and value
          b'\x27\x0fwt-available-protocols\x0e"webtransport"')
    return h3_frame(1, fl)

def h3_get(path=b'/'):
    """HEADERS of a GET, every field from qpack's static table but the path
    and authority, whose names are"""
    fl = (b'\x00\x00' +			# required insert count 0, base 0
          b'\xd1' +			# :method GET
          b'\xd7' +			# :scheme https
          b'\x51' + bytes([len(path)]) + path +	# :path, literal
          b'\x50\x04fuzz')			# :authority, literal
    return h3_frame(1, fl)

def dgram(data):
    if len(data) <= 31:
        return op(OP_DGRAM, len(data) - 1) + data
    return op(OP_DGRAM, 31) + u16(len(data) - 32) + data

def time(a): return op(OP_TIME, a)

ack0 = b'\x02\x00\x00\x00\x00'		# ACK of the server's pn 0
ping = b'\x01'

seeds = {
    # the whole ClientHello, the server's first flight, then its PTOs
    'hello': crypto(0, client_hello(0)) + time(10) + time(14) + time(16),
    # in small pieces, and acking the server's first Initial
    'hello-split': crypto(1, client_hello(1), 40) + initial(1, ack0 + ping) +
                   time(12),
    # the network takes nothing: the server holds what it has, then sends
    'hello-tx-held': op(OP_TX, 1) + crypto(0, client_hello(0)) + time(12) +
                     op(OP_TX, 0) + time(12),
    # the same Initial twice, and a packet number gone back
    'hello-dup': crypto(2, client_hello(2)) + initial(2, ping, True) +
                 initial(2, ping) + time(14),
    # the client moves after its first flight
    'hello-migrate': crypto(0, client_hello(0)) + op(OP_PEER, 5) +
                     initial(0, ack0 + ping) + op(OP_PEER, 0x12) +
                     op(OP_SHORT, 0 | (7 << 2)) + bytes(8) + time(14),
    # two clients at once, from two addresses
    'two-clients': crypto(0, client_hello(0)) + op(OP_PEER, 1) +
                   crypto(3, client_hello(3)) + time(12) + time(18),
    # the client gives up in its Initial: CONNECTION_CLOSE
    'hello-close': crypto(1, client_hello(1)) +
                   initial(1, b'\x1c\x0a\x06\x00'),
    # an alpn the server doesn't have
    'hello-bad-alpn': crypto(0, client_hello(0, b'h2')),
    # a ClientHello arriving out of order
    'hello-reorder': initial(2, b'\x06' + varint(100) +
                             varint(len(client_hello(2)) - 100) +
                             client_hello(2)[100:]) +
                     initial(2, b'\x06\x00' + varint(100) +
                             client_hello(2)[:100]) + time(12),
    # a version we don't speak, in a datagram big enough to be answered
    'version-negotiation': dgram(b'\xc0\x1a\x2a\x3a\x4a\x08fzqodcid' +
                                 b'\x08fzqscid0' + bytes(1200 - 23)),
    # a short header packet for no connection: a stateless reset
    'stateless-reset': dgram(b'\x40' + b'nobodys!' + bytes(40)),
    # Initials that never finish a handshake, from many places, then time
    'unproven-flood': b''.join(op(OP_PEER, p) + initial(p & 3, ping)
                               for p in range(16)) + time(16),
}

seeds.update({
    # past the handshake: the server's HANDSHAKE_DONE, then its idle timeout
    'handshake': handshake(0) + time(14),
    # an h3 GET, with the control stream before it
    'h3-get': handshake(1) + stream(1, SID_CONTROL, h3_control) +
              stream(1, SID_0, h3_get(), True) + time(12) +
              stream(1, SID_CONTROL, h3_frame(7, varint(0))) + time(12),
    # a request body, in pieces, on another stream
    'h3-post': handshake(2) + stream(2, SID_CONTROL, h3_control) +
               stream(2, SID_4, h3_frame(1, b'\x00\x00\xd1\xd7\x51\x01/' +
                                         b'\x50\x04fuzz')[:-1] +
                      b'z') +
               stream(2, SID_4, h3_frame(0, bytes(300))) +
               stream(2, SID_4, h3_frame(0, b'end'), True) + time(12),
    # a key update, then more on the new keys
    'key-update': handshake(0) + packet(0, APP_NEXT_PHASE, ping) +
                  packet(0, APP, ping) + time(12),
    # a short header before the server has 1-RTT keys, which it holds
    # until it has them, and then can't authenticate
    'short-before-finished': crypto(3, client_hello(3)) + time(10) +
                             op(OP_SHORT, 3 | (7 << 2)) + bytes(8) +
                             finished(3) + time(12),
    # the client's own CONNECTION_CLOSE once established
    'app-close': handshake(1) + packet(1, APP, b'\x1d\x00\x00'),
    # a WebTransport session on stream 0, a bidi stream of it on 4, a uni
    # stream of it on 6, and a datagram of it
    'wt-session': handshake(3) + stream(3, SID_CONTROL, h3_control) +
                  stream(3, SID_0, wt_connect()) + time(12) +
                  stream(3, SID_4, varint(0x41) + varint(0) + b'hello') +
                  stream(3, SID_QPACK_ENC, varint(0x54) + varint(0) +
                         b'uni hello', True) +
                  packet(3, APP, b'\x31\x05\x00dgrm') + time(12) +
                  stream(3, SID_4, b'more', True) + time(14),
    # an empty DATA, and more after it, while the request waits for the
    # server to be able to send: an empty segment for the deferred body
    'regress-empty-data-deferred': crypto(2, client_hello(2)) +
                                   op(OP_TX, 1) + time(10) + finished(2) +
                                   stream(2, SID_4, h3_get()) +
                                   stream(2, SID_4, b'\x00\x00\x00'),
    # a FIN alone for a request blocked on a qpack insert that never comes:
    # an empty segment for what it holds
    'regress-fin-qpack-blocked': handshake(0) +
                                 stream(0, SID_CONTROL, h3_control) +
                                 stream(0, SID_0, h3_frame(1, b'\x02\x00\x80')) +
                                 packet(0, APP, b'\x0d\x00' + varint(5)) +
                                 time(12),
    # it moves once established: path validation
    'migrate-1rtt': handshake(0) + op(OP_PEER, 6) + packet(0, APP, ping) +
                    time(12),
})

os.makedirs(D, exist_ok=True)
for name, prog in seeds.items():
    with open(os.path.join(D, name), 'wb') as f:
        f.write(prog)
