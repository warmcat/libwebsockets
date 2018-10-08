/*
 * libwebsockets - lws-ring multi-tail abstract ringbuffer api
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"

LWS_VISIBLE LWS_EXTERN struct lws_ring *
lws_ring_create(size_t element_len, size_t count,
		void (*destroy_element)(void *))
{
	struct lws_ring *ring = lws_malloc(sizeof(*ring), "ring create");

	if (!ring)
		return NULL;

	ring->buflen = (uint32_t)(count * element_len);
	ring->element_len = (uint32_t)element_len;
	ring->head = 0;
	ring->oldest_tail = 0;
	ring->destroy_element = destroy_element;

	ring->buf = lws_malloc(ring->buflen, "ring buf");
	if (!ring->buf) {
		lws_free(ring);

		return NULL;
	}

	return ring;
}

LWS_VISIBLE LWS_EXTERN void
lws_ring_destroy(struct lws_ring *ring)
{
	if (ring->destroy_element)
		while (ring->oldest_tail != ring->head) {
			ring->destroy_element((uint8_t *)ring->buf +
					      ring->oldest_tail);
			ring->oldest_tail =
				(ring->oldest_tail + ring->element_len) %
				ring->buflen;
		}
	if (ring->buf)
		lws_free_set_NULL(ring->buf);

	lws_free(ring);
}

LWS_VISIBLE LWS_EXTERN size_t
lws_ring_get_count_free_elements(struct lws_ring *ring)
{
	int f;

	/*
	 * possible ringbuf patterns
	 *
	 * h == t
	 * |--------t***h---|
	 * |**h-----------t*|
	 * |t**************h|
	 * |*****ht*********|
	 */
	if (ring->head == ring->oldest_tail)
		f = ring->buflen - ring->element_len;
	else
		if (ring->head < ring->oldest_tail)
			f = (ring->oldest_tail - ring->head) -
			    ring->element_len;
		else
			f = (ring->buflen - ring->head) + ring->oldest_tail -
			    ring->element_len;

	if (f < 2)
		return 0;

	return f / ring->element_len;
}

LWS_VISIBLE LWS_EXTERN size_t
lws_ring_get_count_waiting_elements(struct lws_ring *ring, uint32_t *tail)
{	int f;

	if (!tail)
		tail = &ring->oldest_tail;
	/*
	 * possible ringbuf patterns
	 *
	 * h == t
	 * |--------t***h---|
	 * |**h-----------t*|
	 * |t**************h|
	 * |*****ht*********|
	 */
	if (ring->head == *tail)
		f = 0;
	else
		if (ring->head > *tail)
			f = (ring->head - *tail);
		else
			f = (ring->buflen - *tail) + ring->head;

	return f / ring->element_len;
}

LWS_VISIBLE LWS_EXTERN int
lws_ring_next_linear_insert_range(struct lws_ring *ring, void **start,
				  size_t *bytes)
{
	int n;

	/* n is how many bytes the whole fifo can take */
	n = (int)(lws_ring_get_count_free_elements(ring) * ring->element_len);

	if (!n)
		return 1;

	if (ring->head + n > ring->buflen) {
		*start = (void *)(((uint8_t *)ring->buf) + ring->head);
		*bytes = ring->buflen - ring->head;

		return 0;
	}

	*start = (void *)(((uint8_t *)ring->buf) + ring->head);
	*bytes = n;

	return 0;
}

LWS_VISIBLE LWS_EXTERN void
lws_ring_bump_head(struct lws_ring *ring, size_t bytes)
{
	ring->head = (ring->head + (uint32_t)bytes) % ring->buflen;
}

LWS_VISIBLE LWS_EXTERN size_t
lws_ring_insert(struct lws_ring *ring, const void *src, size_t max_count)
{
	const uint8_t *osrc = src;
	int m, n;

	/* n is how many bytes the whole fifo can take */
	n = (int)(lws_ring_get_count_free_elements(ring) * ring->element_len);

	/* restrict n to how much we want to insert */
	if ((uint32_t)n > max_count * ring->element_len)
		n = (int)(max_count * ring->element_len);

	/*
	 * n is legal to insert, but as an optimization we can cut the
	 * insert into one or two memcpys, depending on if it wraps
	 */
	if (ring->head + n > ring->buflen) {

		/*
		 * He does wrap.  The first memcpy should take us up to
		 * the end of the buffer
		 */

		m = ring->buflen - ring->head;
		memcpy(((uint8_t *)ring->buf) + ring->head, src, m);
		/* we know it will wrap exactly back to zero */
		ring->head = 0;

		/* adapt the second memcpy for what we already did */

		src = ((uint8_t *)src) + m;
		n -= m;
	}

	memcpy(((uint8_t *)ring->buf) + ring->head, src, n);
	ring->head = (ring->head + n) % ring->buflen;

	return (((uint8_t *)src + n) - osrc) / ring->element_len;
}

LWS_VISIBLE LWS_EXTERN size_t
lws_ring_consume(struct lws_ring *ring, uint32_t *tail, void *dest,
		 size_t max_count)
{
	uint8_t *odest = dest;
	void *orig_tail = tail;
	uint32_t fake_tail;
	int m, n;

	if (!tail) {
		fake_tail = ring->oldest_tail;
		tail = &fake_tail;
	}

	/* n is how many bytes the whole fifo has for us */
	n = (int)(lws_ring_get_count_waiting_elements(ring, tail) *
							ring->element_len);

	/* restrict n to how much we want to insert */
	if ((size_t)n > max_count * ring->element_len)
		n = (int)(max_count * ring->element_len);

	if (!dest) {
		*tail = ((*tail) + n) % ring->buflen;
		if (!orig_tail) /* single tail */
			lws_ring_update_oldest_tail(ring, *tail);

		return n / ring->element_len;
	}
	if (*tail + n > ring->buflen) {

		/*
		 * He does wrap.  The first memcpy should take us up to
		 * the end of the buffer
		 */

		m = ring->buflen - *tail;
		memcpy(dest, ((uint8_t *)ring->buf) + *tail, m);
		/* we know it will wrap exactly back to zero */
		*tail = 0;

		/* adapt the second memcpy for what we already did */

		dest = ((uint8_t *)dest) + m;
		n -= m;
	}

	memcpy(dest, ((uint8_t *)ring->buf) + *tail, n);

	*tail = ((*tail) + n) % ring->buflen;
	if (!orig_tail) /* single tail */
		lws_ring_update_oldest_tail(ring, *tail);

	return (((uint8_t *)dest + n) - odest) / ring->element_len;
}

LWS_VISIBLE LWS_EXTERN const void *
lws_ring_get_element(struct lws_ring *ring, uint32_t *tail)
{
	if (!tail)
		tail = &ring->oldest_tail;

	if (*tail == ring->head)
		return NULL;

	return ((uint8_t *)ring->buf) + *tail;
}

LWS_VISIBLE LWS_EXTERN void
lws_ring_update_oldest_tail(struct lws_ring *ring, uint32_t tail)
{
	if (!ring->destroy_element) {
		ring->oldest_tail = tail;
		return;
	}

	while (ring->oldest_tail != tail) {
		ring->destroy_element((uint8_t *)ring->buf + ring->oldest_tail);
		ring->oldest_tail = (ring->oldest_tail + ring->element_len) %
				    ring->buflen;
	}
}

LWS_VISIBLE LWS_EXTERN uint32_t
lws_ring_get_oldest_tail(struct lws_ring *ring)
{
	return ring->oldest_tail;
}

LWS_VISIBLE LWS_EXTERN void
lws_ring_dump(struct lws_ring *ring, uint32_t *tail)
{
	if (tail == NULL)
		tail = &ring->oldest_tail;
	lwsl_notice("ring %p: buflen %u, elem_len %u, head %u, oldest_tail %u\n"
		    "     free_elems: %u; for tail %u, waiting elements: %u\n",
		    ring, ring->buflen, ring->element_len, ring->head,
		    ring->oldest_tail,
		    (int)lws_ring_get_count_free_elements(ring), *tail,
		    (int)lws_ring_get_count_waiting_elements(ring, tail));
}
