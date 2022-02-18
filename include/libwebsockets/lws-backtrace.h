/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/** \defgroup lws_backtrace generic and compressed backtrace acquisition
 * ##Backtrace apis
 * \ingroup lwsbacktrace
 *
 * lws_backtrace
 *
 * These apis abstract acquisition and optionally compressed on binary back-
 * traces, effectively build-specific signatures for where in the code you are
 * and how you got there.
 */
//@{

typedef struct {
	uintptr_t	st[32];
	uintptr_t	asize;

	uint8_t		sp;
	uint8_t		pre;
	uint8_t		post;
} lws_backtrace_info_t;

typedef struct {
	uint8_t		*comp;
	size_t		pos;
	size_t		len;
} lws_backtrace_comp_t;

/*
 * lws_backtrace() - init and fiull a backtrace struct
 *
 * \param si: the backtrace struct to populate
 * \param pre: the number of call levels to snip from the top
 * \param post: the number of call levels to snip from the bottom
 *
 * This describes the call stack into \p si.  \p si doesn't need preparing
 * before the call.  \p pre levels of the call stack at the top will be snipped,
 * this will usually want to be 1 or 2 to conceal the helpers that are making
 * the call stack, such as lws_backtrace itself.
 *
 * \p post levels of the call stack at the bottom will be snipped, this is to
 * conceal loaders or other machinery that was used to start your application,
 * otherwise those entries will bloat all call stacks results on that platform.
 *
 * Returns 0 for success.
 */
LWS_VISIBLE LWS_EXTERN int
lws_backtrace(lws_backtrace_info_t *si, uint8_t pre, uint8_t post);

/*
 * lws_backtrace_compression_stream_init() - init and fiull a backtrace struct
 *
 * \param c: the backtrace compression struct
 * \param comp: the buffer to take the compressed bytes
 * \param comp_len: the number of bytes available at \p comp
 *
 * This initializes the caller's lws_backtrace_comp_t.  Because it's expected
 * the caller will want to put his own compressed data after the compressed
 * backtrace, he is responsible for the compression context.
 */
LWS_VISIBLE LWS_EXTERN void
lws_backtrace_compression_stream_init(lws_backtrace_comp_t *c,
				      uint8_t *comp, size_t comp_len);

/*
 * lws_backtrace_compression_stream() - add bitfields to compression stream
 *
 * \param c: the backtrace compression context struct
 * \param v: the bitfield to add to the stream
 * \param bits: the number of bits of v to add
 *
 * This inserts bits from the LSB end of v to the compression stream.
 *
 * This is used by the backtrace compression, user code can use this to add
 * its own bitfields into the compression stream after the compressed backtrace.
 *
 * User data should be added after, so that the backtrace can be processed even
 * if the additional data is not understood by the processing script.
 *
 * Returns 0 for success or nonzero if ran out of compression output buffer.
 */
LWS_VISIBLE LWS_EXTERN int
lws_backtrace_compression_stream(lws_backtrace_comp_t *c, uintptr_t v,
				 unsigned int bits);

/*
 * lws_backtrace_compression_destream() - add bitfields to compression stream
 *
 * \param c: the backtrace compression context struct
 * \param _v: pointer to take the bitfield result
 * \param bits: the number of bits to bring out into _v
 *
 * This reads the compression stream and creates a bitfield from it in \p _v.
 *
 * Returns 0 for success (with \p _v set to the value), or nonzero if ran out
 * of compression output buffer.
 */
LWS_VISIBLE LWS_EXTERN int
lws_backtrace_compression_destream(lws_backtrace_comp_t *c, uintptr_t *_v,
				   unsigned int bits);

/*
 * lws_backtrace_compress_backtrace() - compress backtrace si into c
 *
 * \param si: the backtrace struct to compress
 * \param c: the backtrace compression context struct
 *
 * This compresses backtrace information acquired in \p si into the compression
 * context \p c.  It compresses first the call stack length and then each IP
 * address in turn.
 *
 * Returns 0 for success.
 */
LWS_VISIBLE LWS_EXTERN int
lws_backtrace_compress_backtrace(lws_backtrace_info_t *si,
				 lws_backtrace_comp_t *c);

//@}

/** \defgroup lws_alloc_metadata helpers for allocator instrumentation
 * ##Alloc Metadata APIs
 * \ingroup lwsallocmetadata
 *
 * lws_alloc_metadata
 *
 * These helpers let you rapidly instrument your libc or platform memory
 * allocator so that you can later dump details, including a backtrace of where
 * the allocation was made, for every live heap allocation.
 *
 * You would use it at peak memory usage, to audit who is using what at that
 * time.
 *
 * Effective compression is used to keep the metadata overhead to ~48 bytes
 * per active allocation on 32-bit systems.
 */
//@{

/**
 * lws_alloc_metadata_gen() - generate metadata blob (with compressed backtrace)
 *
 * \param size: the allocation size
 * \param comp: buffer for compressed backtrace
 * \param comp_len: number of bytes available in the compressed backtrace
 * \param adj: takes the count of additional bytes needed for metadata behind
 *             the allocation we tell the user about
 * \param cl: takes the count of bytes used in comp
 *
 * This helper creates the compressed part of the alloc metadata blob and
 * calculates the total overallocation that is needed in \p adj.
 *
 * This doesn't need any locking.
 *
 * If \p comp_len is too small for the whole result, or it was not possible to
 * get the backtrace information, the compressed part is set to empty (total
 * length 2 to carry the 00 00 length).
 *
 * 6 or 10 (64-bit) bytes per backtrace IP allowed (currently 16) should always
 * be enough, typically the compression reduces this very significantly.
 */
LWS_VISIBLE LWS_EXTERN void
lws_alloc_metadata_gen(size_t size, uint8_t *comp, size_t comp_len, size_t *adj,
								size_t *cl);

/**
 * _lws_alloc_metadata_adjust() - helper to inject metadata and list as active
 *
 * \param active: the allocation owner
 * \param v: Original, true allocation pointer, adjusted on exit
 * \param adj: Total size of metadata overallocation
 * \param comp: The compressed metadata
 * \param cl: takes the count of bytes used in comp
 *
 * THIS MUST BE LOCKED BY THE CALLER IF YOUR ALLOCATOR MAY BE CALLED BY OTHER
 * THREADS.  You can call it from an existing mutex or similar -protected
 * critical section in your allocator if there is one already, or you will have
 * to protect the caller of it with your own mutex so it cannot reenter.
 *
 * This is a helper that adjusts the allocation past the metadata part so the
 * caller of the allocator using this sees what he asked for.  The deallocator
 * must call _lws_alloc_metadata_trim() to balance this before actual
 * deallocation.
 */
LWS_VISIBLE LWS_EXTERN void
_lws_alloc_metadata_adjust(lws_dll2_owner_t *active, void **v, size_t adj, uint8_t *comp, unsigned int cl);

/**
 * _lws_alloc_metadata_trim() - helper to trim metadata and remove from active
 *
 * \param ptr: Adjusted allocation pointer on entry, true allocation ptr on exit
 * \param comp: NULL, or set on exit to point to start of compressed area
 * \param complen: NULL, or set on exit to length of compressed area in bytes
 *
 * THIS MUST BE LOCKED BY THE CALLER IF YOUR DEALLOCATOR MAY BE CALLED BY OTHER
 * THREADS.  You can call it from an existing mutex or similar -protected
 * critical section in your deallocator if there is one already, or you will
 * have to protect that caller of it with your own mutex so it cannot reenter.
 */
LWS_VISIBLE LWS_EXTERN void
_lws_alloc_metadata_trim(void **ptr, uint8_t **comp, uint16_t *complen);

/**
 * lws_alloc_metadata_parse() - parse compressed metadata into struct
 *
 * \param si: Struct to take the backtrace results from decompression
 * \param adjusted_alloc: pointer to adjusted, user allocation start
 *
 * This api parses and decompresses the blob behind the \p adjusted_alloc
 * address into \p si.
 *
 * Returns 0 for success.
 */
LWS_VISIBLE LWS_EXTERN int
lws_alloc_metadata_parse(lws_backtrace_info_t *si, const uint8_t *adjusted_alloc);

/**
 * lws_alloc_metadata_dump_stdout() - helper to print base64 blob on stdout
 *
 * \param d: the current list item
 * \param user: the optional arg given to the dump api (ignored)
 *
 * Generic helper that can be given to _lws_alloc_metadata_dump() as the
 * callback that will emit a standardized base64 blob for the alloc metadata
 */
LWS_VISIBLE LWS_EXTERN int
lws_alloc_metadata_dump_stdout(struct lws_dll2 *d, void *user);

/**
 * lws_alloc_metadata_dump_stdout() - dump all live allocs in instrumented heap
 *
 * \param active: the owner of the active allocation list for this heap
 * \param cb: the callback to receive information
 * \param arg: optional arg devivered to the callback
 *
 * THIS MUST BE LOCKED BY THE CALLER IF YOUR ALLOCATOR MAY BE CALLED BY OTHER
 * THREADS.  You can call it from an existing mutex or similar -protected
 * critical section in your allocator if there is one already, or you will have
 * to protect the caller of it with your own mutex so it cannot reenter.
 *
 * Iterates through the list of instrumented allocations calling the given
 * callback for each one.
 */
LWS_VISIBLE LWS_EXTERN void
_lws_alloc_metadata_dump(lws_dll2_owner_t *active, lws_dll2_foreach_cb_t cb,
			 void *arg);

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
/*
 * Wrapper for _lws_alloc_metadata_dump() that uses the list owner that tracks
 *
 */
LWS_VISIBLE LWS_EXTERN void
_lws_alloc_metadata_dump_lws(lws_dll2_foreach_cb_t cb, void *arg);
#else
#define _lws_alloc_metadata_dump_lws(_a, _b)
#endif

//@}
