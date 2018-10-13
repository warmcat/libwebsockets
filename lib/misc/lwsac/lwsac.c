/*
 * libwebsockets - lws alloc chunk
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
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
#include "misc/lwsac/private.h"

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
	struct lwsac *chunk;
	size_t ofs, alloc;

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

	(*head)->curr->ofs += lwsac_align(ensure);
	if ((*head)->curr->ofs >= (*head)->curr->alloc_size)
		(*head)->curr->ofs = (*head)->curr->alloc_size;

	return (char *)(*head)->curr + ofs;
}

void
lwsac_free(struct lwsac **head)
{
	struct lwsac *it = *head;

	while (it) {
		struct lwsac *tmp = it->next;

		free(it);
		it = tmp;
	}

	*head = NULL;
}

void
lwsac_info(struct lwsac *head)
{
	lwsl_notice("%s: lac %p: %dKiB in %d blocks\n", __func__, head,
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
}

void
lwsac_unreference(struct lwsac **head)
{
	(*head)->refcount--;
	if ((*head)->detached && !(*head)->refcount)
		lwsac_free(head);
}

void
lwsac_detach(struct lwsac **head)
{
	(*head)->detached = 1;
	if (!(*head)->refcount)
		lwsac_free(head);
}
