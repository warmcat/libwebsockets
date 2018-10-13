## LWS Allocated Chunks

These apis provide a way to allocate a linked-list of allocated regions,
and to manage use of subregions inside.

[ HEAD alloc ] -> [ next alloc ] -> [ next alloc ] -> [ curr alloc ]

When you make an allocation using `lwsac_use()`, you can either
set the `chunk_size` arg to zero or a specific chunk size.

If zero, then the allocations are made in chunks of 4000 bytes if that
is larger than the requested size, or the requested size plus the
necessary overhead if it's larger.  If non-zero, the chunk is sized
exactly to `chunk_size` plus the overhead.

Subsequent `lwsac_use()` calls will use the remaining space inside
the current chunk if possible; if not enough remaining space it is
skipped and a new allocation chained on.

Combined with linked-list pointers being stored in the objects inside
the lwsac, it means all the linked-list pointers, and all the things
pointed-to are stored in a small number of allocations and can be completely
rolled up by freeing a single allocation list.  There may be thousands of
objects in the lwsac each indexed on multiple sorted lists, but it can only
take a dozen allocations or frees to allocate and destroy the whole thing
including all the internal lists.

