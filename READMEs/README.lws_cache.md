# `lws_cache` Flexible single and multilevel caching

lws provides apis that encapsulate single and multilevel caches of blobs keyed
by a unique string.  The first, L1 level is always in local heap, but the max
heap footprint of its items and max number of items can be capped.

Subsequent, parent cache levels are optional, if present they will typically be
in a slower medium like disk or flash filesystem.

LRU tracking is optional at each level, but typically desired at least at L1 to
make the best use of a limited amount of heap that is fast to access for items
that were recently relevant.

Wildcard querying is supported, 