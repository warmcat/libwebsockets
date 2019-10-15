/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"
#include "private-lib-misc-lwsac.h"

void
lws_list_ptr_insert(lws_list_ptr *head, lws_list_ptr *add,
		    lws_list_ptr_sort_func_t sort_func)
{
	while (sort_func && *head) {
		if (sort_func(add, *head) <= 0)
			break;

		head = *head;
	}

	*add = *head;
	*head = add;
}

size_t
lwsac_align(size_t length)
{
	size_t align = sizeof(int *);

	if (length & (align - 1))
		length += align - (length & (align - 1));

	return length;
}

size_t
lwsac_sizeof(void)
{
	return sizeof(struct lwsac);
}

size_t
lwsac_get_tail_pos(struct lwsac *lac)
{
	return lac->ofs;
}

struct lwsac *
lwsac_get_next(struct lwsac *lac)
{
	return lac->next;
}

void *
lwsac_use(struct lwsac **head, size_t ensure, size_t chunk_size)
{
	size_t ofs, alloc, al;
	struct lwsac *chunk;

	/* ensure there's a chunk and enough space in it for this name */

	if (!*head || (*head)->curr->alloc_size - (*head)->curr->ofs < ensure) {

		if (!chunk_size)
			alloc = LWSAC_CHUNK_SIZE + sizeof(*chunk);
		else
			alloc = chunk_size + sizeof(*chunk);

		/*
		 * If we get asked for something outside our expectation,
		 * allocate to meet it
		 */

		if (ensure >= alloc - sizeof(*chunk))
			alloc = ensure + sizeof(*chunk);

		chunk = malloc(alloc);
		if (!chunk) {
			lwsl_err("%s: OOM trying to alloc %llud\n", __func__,
					(unsigned long long)alloc);
			return NULL;
		}

		if (!*head) {
			*head = chunk;
			chunk->total_alloc_size = 0;
			chunk->total_blocks = 0;
		}
		else
			(*head)->curr->next = chunk;

		(*head)->curr = chunk;
		(*head)->curr->head = *head;

		chunk->next = NULL;
		chunk->alloc_size = alloc;
		chunk->detached = 0;
		chunk->refcount = 0;

		(*head)->total_alloc_size += alloc;
		(*head)->total_blocks++;

		/*
		 * belabouring the point... ofs is aligned to the platform's
		 * generic struct alignment at the start then
		 */
		(*head)->curr->ofs = sizeof(*chunk);
	}

	ofs = (*head)->curr->ofs;

	al = lwsac_align(ensure);
	if (al > ensure) {
		/* zero down the alignment padding part */

		memset((char *)(*head)->curr + ofs + ensure, 0, al - ensure);
	}
	(*head)->curr->ofs += al;
	if ((*head)->curr->ofs >= (*head)->curr->alloc_size)
		(*head)->curr->ofs = (*head)->curr->alloc_size;

	return (char *)(*head)->curr + ofs;
}

uint8_t *
lwsac_scan_extant(struct lwsac *head, uint8_t *find, size_t len, int nul)
{
	while (head) {
		uint8_t *pos = (uint8_t *)&head[1],
			*end = ((uint8_t *)head) + head->ofs - len;

		if (head->ofs - sizeof(*head) >= len)
			while (pos < end) {
				if (*pos == *find && (!nul || !pos[len]) &&
				    pos[len - 1] == find[len - 1] &&
				    !memcmp(pos, find, len))
					/* found the blob */
					return pos;
				pos++;
			}

		head = head->next;
	}

	return NULL;
}

void *
lwsac_use_zero(struct lwsac **head, size_t ensure, size_t chunk_size)
{
	void *p = lwsac_use(head, ensure, chunk_size);

	if (p)
		memset(p, 0, ensure);

	return p;
}

void
lwsac_free(struct lwsac **head)
{
	struct lwsac *it = *head;

	*head = NULL;
	lwsl_debug("%s: head %p\n", __func__, *head);

	while (it) {
		struct lwsac *tmp = it->next;

		free(it);
		it = tmp;
	}
}

void
lwsac_info(struct lwsac *head)
{
	if (!head)
		lwsl_debug("%s: empty\n", __func__);
	else
		lwsl_debug("%s: lac %p: %dKiB in %d blocks\n", __func__, head,
		   (int)(head->total_alloc_size >> 10), head->total_blocks);
}

uint64_t
lwsac_total_alloc(struct lwsac *head)
{
	return head->total_alloc_size;
}

void
lwsac_reference(struct lwsac *head)
{
	head->refcount++;
	lwsl_debug("%s: head %p: (det %d) refcount -> %d\n",
		    __func__, head, head->detached, head->refcount);
}

void
lwsac_unreference(struct lwsac **head)
{
	if (!(*head))
		return;

	if (!(*head)->refcount)
		lwsl_warn("%s: refcount going below zero\n", __func__);

	(*head)->refcount--;

	lwsl_debug("%s: head %p: (det %d) refcount -> %d\n",
		    __func__, *head, (*head)->detached, (*head)->refcount);

	if ((*head)->detached && !(*head)->refcount) {
		lwsl_debug("%s: head %p: FREED\n", __func__, *head);
		lwsac_free(head);
	}
}

void
lwsac_detach(struct lwsac **head)
{
	(*head)->detached = 1;
	if (!(*head)->refcount) {
		lwsl_debug("%s: head %p: FREED\n", __func__, *head);
		lwsac_free(head);
	} else
		lwsl_debug("%s: head %p: refcount %d: Marked as detached\n",
			    __func__, *head, (*head)->refcount);
}
