# lws-api-test-dht-create

This API test covers cleanup when DHT context creation cannot allocate its
random node ID.

It installs a custom lws allocator, injects a failure for the
`lws_dht_hash_create` allocation, and checks that every allocation made while
`lws_dht_create()` was active has been released before the function returns.

The test does not open a listening socket and does not require network access.

Build as part of the main tree with DHT enabled, for example:

```
cmake -DLWS_WITH_DHT=ON -DLWS_WITH_MINIMAL_EXAMPLES=ON ..
ctest -R api-test-dht-create --output-on-failure
```
