# LEJP JSON Stream Parser

|||
|---|---|---|
|cmake| `LWS_WITH_LEJP`|
|Header| ./include/libwebsockets/lws-lejp.h|
|api-test| ./minimal-examples/api-tests/api-test-lejp/|
|test app| ./test-apps/test-lejp.c -> libwebsockets-test-lejp|

LEJP is a lightweight JSON stream parser.

The features are:

 - completely immune to input fragmentation, give it any size blocks of JSON as
   they become available, 1 byte, or 100K at a time give identical parsing
   results
 - input chunks discarded as they are parsed, whole JSON never needed in memory
 - nonrecursive, fixed stack usage of a few dozen bytes
 - no heap allocations at all, just requires ~500 byte context usually on
   caller stack
 - creates callbacks to a user-provided handler as members are parsed out
 - no payload size limit, supports huge / endless strings bigger than
   system memory
 - collates utf-8 text payloads into a 250-byte chunk buffer in the json parser
   context object for ease of access

## LEJP Context initialization

lejp doesn't allocate at all, you define a `struct lejp_ctx` usually on the
stack somewhere, and call `lejp_construct()` to initialize it.

To minimize surprises as lejp evolves, there is now a `flags` member of the
ctx, which defaults to zero for compatibility with older versions.  After
the `lejp_construct()` call, you can set `ctx.flags` to indicate you want
newer options

|lejp flags|Meaning|
|---|---|
|LEJP_FLAG_FEAT_OBJECT_INDEXES|Provide indexes for { x, y, x } lists same as for arrays|
|LEJP_FLAG_FEAT_LEADING_WC|Allow path matches involving leading wildcards, like `*[]`|
|LEJP_FLAG_LATEST|Alias indicating you want the "best" current options, even if incompatible with old behaviours|

## Type handling

LEJP leaves all numbers in text form, they are signalled in different callbacks
according to int or float, but delivered as text strings in the first
`ctx->npos` chars of `ctx->buf`.

For numeric types, you would typically use `atoi()` or similar to recover the
number as a host type.

## Callback reasons

The user callback does not have to handle any callbacks, it only needs to
process the data for the ones it is interested in.

|Callback reason|JSON structure|Associated data|
|---|---|---|
|`LEJPCB_CONSTRUCTED`|Created the parse context||
|`LEJPCB_DESTRUCTED`|Destroyed the parse context||
|`LEJPCB_COMPLETE`|The parsing completed OK||
|`LEJPCB_FAILED`|The parsing failed||
|`LEJPCB_VAL_TRUE`|boolean true||
|`LEJPCB_VAL_FALSE`|boolean false||
|`LEJPCB_VAL_NULL`|explicit NULL||
|`LEJPCB_PAIR_NAME`|The name part of a JSON `key: value` map pair|`ctx->buf`|
|`LEJPCB_VAL_STR_START`|A UTF-8 string is starting||
|`LEJPCB_VAL_STR_CHUNK`|The next string chunk|`ctx->npos` bytes in `ctx->buf`|
|`LEJPCB_VAL_STR_END`|The last string chunk|`ctx->npos` bytes in `ctx->buf`|
|`LEJPCB_ARRAY_START`|An array is starting||
|`LEJPCB_ARRAY_END`|An array has ended||
|`LEJPCB_OBJECT_START`|A JSON object is starting||
|`LEJPCB_OBJECT_END`|A JSON object has ended||

## Handling JSON UTF-8 strings

When a string is parsed, an advisory callback of `LECPCB_VAL_STR_START` occurs
first.  No payload is delivered with the START callback.

Payload is collated into `ctx->buf[]`, the valid length is in `ctx->npos`.

For short strings or blobs where the length is known, the whole payload is
delivered in a single `LECPCB_VAL_STR_END` callback.

For payloads larger than the size of `ctx->buf[]`, `LECPCB_VAL_STR_CHUNK`
callbacks occur delivering each sequential bufferload.

The last chunk (which may be zero length) is delievered by `LECPCB_VAL_STR_END`.

## Parsing paths

LEJP maintains a "parsing path" in `ctx->path` that represents the context of
the callback events.  As a convenience, at LEJP context creation time, you can
pass in an array of path strings you want to match on, and have any match
checkable in the callback using `ctx->path_match`, it's 0 if no active match,
or the match index from your path array starting from 1 for the first entry.

|CBOR element|Representation in path|
|---|---|
|JSON Array|`[]`|
|JSON Map|`.`|
|JSON Map entry key string|`keystring`|
|Wildcard|`*[]`, or `abc.*[]` etc (depends on `ctx.flags` with `LEJP_FLAG_FEAT_LEADING_WC`)|

## Details of object and array indexes

LEJP maintains a "stack" of index counters, each element represents one level
in the current hierarchy that may have a list or array of objects in it.
The amount of levels currently is held in `ctx->ipos`, and `ctx->i[]` holds
`uint16_t` index counts for each level.

By querying these, you can understand at which element index in a hierarchy of
arrays in the JSON you are at, unambiguously.

By default that is done for each `[]` array level, if you set `ctx.flags` with
`LEJP_FLAG_FEAT_OBJECT_INDEXES` option, it is also done for each `{}` object
level, which can also take comma-separated lists that need index tracking.

## Comparison with LECP (CBOR parser)

LECP is based on the same principles as LEJP and shares most of the callbacks.
The major differences:

 - LEJP value callbacks all appear in `ctx->buf[]`, ie, floating-point is
   provided to the callback in ascii form like `"1.0"`.  CBOR provides a more
   strict typing system, and the different type values are provided either in
   `ctx->buf[]` for blobs or utf-8 text strtings, or the `item.u` union for
   converted types, with additional callback reasons specific to each type.

 - CBOR "maps" use `_OBJECT_START` and `_END` parsing callbacks around the
   key / value pairs.  LEJP has a special callback type `PAIR_NAME` for the
   key string / integer, but in LECP these are provided as generic callbacks
   dependent on type, ie, generic string callbacks or integer ones, and the
   value part is represented according to whatever comes.


