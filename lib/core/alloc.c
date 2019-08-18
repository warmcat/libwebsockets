#include "private-lib-core.h"

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)

#include <malloc.h>

/* the heap is processwide */
static size_t allocated;
#endif

#if defined(LWS_PLAT_OPTEE)

#define TEE_USER_MEM_HINT_NO_FILL_ZERO       0x80000000
#if defined (LWS_WITH_NETWORK)

/* normal TA apis */

void *__attribute__((weak))
	TEE_Malloc(uint32_t size, uint32_t hint)
{
	return NULL;
}
void *__attribute__((weak))
	TEE_Realloc(void *buffer, uint32_t newSize)
{
	return NULL;
}
void __attribute__((weak))
	TEE_Free(void *buffer)
{
}
#else

/* in-OP-TEE core apis */

void *
	TEE_Malloc(uint32_t size, uint32_t hint)
{
	return malloc(size);
}
void *
	TEE_Realloc(void *buffer, uint32_t newSize)
{
	return realloc(buffer, newSize);
}
void
	TEE_Free(void *buffer)
{
	free(buffer);
}

#endif

void *lws_realloc(void *ptr, size_t size, const char *reason)
{
	return TEE_Realloc(ptr, size);
}

void *lws_malloc(size_t size, const char *reason)
{
	return TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
}

void lws_free(void *p)
{
	TEE_Free(p);
}

void *lws_zalloc(size_t size, const char *reason)
{
	void *ptr = TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

void lws_set_allocator(void *(*cb)(void *ptr, size_t size, const char *reason))
{
	(void)cb;
}
#else

static void *
_realloc(void *ptr, size_t size, const char *reason)
{
	void *v;

	if (size) {
#if defined(LWS_PLAT_FREERTOS)
		lwsl_notice("%s: size %lu: %s (free heap %d)\n", __func__,
#if defined(LWS_AMAZON_RTOS)
			    (unsigned long)size, reason, (unsigned int)xPortGetFreeHeapSize() - (int)size);
#else
			    (unsigned long)size, reason, (unsigned int)esp_get_free_heap_size() - (int)size);
#endif
#else
		lwsl_debug("%s: size %lu: %s\n", __func__,
			   (unsigned long)size, reason);
#endif

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		if (ptr)
			allocated -= malloc_usable_size(ptr);
#endif

#if defined(LWS_PLAT_OPTEE)
		v = (void *)TEE_Realloc(ptr, size);
#else
		v = (void *)realloc(ptr, size);
#endif
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		allocated += malloc_usable_size(v);
#endif
		return v;
	}
	if (ptr) {
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		allocated -= malloc_usable_size(ptr);
#endif
		free(ptr);
	}

	return NULL;
}

void *(*_lws_realloc)(void *ptr, size_t size, const char *reason) = _realloc;

void *lws_realloc(void *ptr, size_t size, const char *reason)
{
	return _lws_realloc(ptr, size, reason);
}

void *lws_zalloc(size_t size, const char *reason)
{
	void *ptr = _lws_realloc(NULL, size, reason);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

void lws_set_allocator(void *(*cb)(void *ptr, size_t size, const char *reason))
{
	_lws_realloc = cb;
}

size_t lws_get_allocated_heap(void)
{
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
	return allocated;
#else
	return 0;
#endif
}
#endif
