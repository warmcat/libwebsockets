# lws-mirror-protocol

## Introduction

The `lws-mirror-protocol` plugin is a WebSocket protocol handler that demonstrates pub/sub or broadcast-like behavior. Devices or clients connecting to the same mirror instance will see all messages sent by any participants mirrored across all connected clients on that instance. Different mirror instances can be joined by adding a URL argument `?mirror=xxx`.

The instance name is the only thing separating one mirror instance from another, so it must be storable whole: names longer than 29 characters are refused with the connection closed, rather than stored truncated and matched against in full (which would let a prefix of somebody else's long name join his instance).

Up to 8 named instances can exist at once; a connection asking for a new name past that is refused.  The default instance (no `?mirror=` argument) doesn't count against the limit, so idle connections holding every named instance can't keep anyone out of it.

## Messages

The mirror relays whole ws messages, as the type (TEXT or BINARY) they were sent as, and everyone on the instance receives each one as a single message.  A message sent in several fragments, or arriving in several pieces because it is bigger than one read, is reassembled first, so other members never receive part of a message, or a TEXT message ending partway through a UTF-8 character.

The sender is disconnected, and nothing of the message relayed, if it sends

 - a message bigger than 4096 bytes (close 1009), or
 - a TEXT message that is not valid UTF-8 (close 1007): lws checks this itself unless the vhost disabled it, but the mirror checks again before relaying, since every browser on the instance must fail its connection on such a message.

## Per-Vhost Options (PVOs)

This plugin currently does not accept any Per-Vhost Options (PVOs) for configuration. All mirror logic operates based on runtime connections and internal instance states.
