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

#if !defined(LWS_PLAT_OPTEE)
#include <sys/stat.h>
#endif

/* under page size of 4096 to allow overhead */
#define LWSAC_CHUNK_SIZE 4000

/*
 * the chunk list members all point back to the head themselves so the list
 * can be detached from the formal head and free itself when its reference
 * count reaches zero.
 */

struct lwsac {
	struct lwsac *next;
	struct lwsac *head; /* pointer back to the first chunk */
	struct lwsac *curr; /* applies to head chunk only */
	size_t total_alloc_size; /* applies to head chunk only */
	size_t alloc_size;
	size_t ofs; /* next writeable position inside chunk */
	int refcount; /* applies to head chunk only */
	int total_blocks; /* applies to head chunk only */
	char detached; /* if our refcount gets to zero, free the chunk list */
};

#if !defined(LWS_PLAT_OPTEE)
struct cached_file_info {
	struct stat s;
	time_t last_confirm;
};
#endif
