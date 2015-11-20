/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2015 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"
#include "libwebsockets.h"

#if defined(WIN32) || defined(_WIN32)

HANDLE compatible_file_open(const char* filename, unsigned long* filelen){
	HANDLE ret;
	WCHAR buffer[MAX_PATH];

	MultiByteToWideChar(CP_UTF8, 0, filename, -1, buffer,
				sizeof(buffer) / sizeof(buffer[0]));
	ret = CreateFileW(buffer, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ret != LWS_INVALID_FILE)
		*filelen = GetFileSize(ret, NULL);

	return ret;
}

void compatible_file_close(void*fd){
	CloseHandle((HANDLE)fd);
}

unsigned long compatible_file_seek_cur(void* fd, long offset){
	return SetFilePointer((HANDLE)fd, offset, NULL, FILE_CURRENT);
}

void compatible_file_read(unsigned long* amount, void* fd, unsigned char* buf, unsigned long len){
	DWORD _amount;
	if (!ReadFile((HANDLE)fd, buf, (DWORD)len, &_amount, NULL))
		*amount = -1;
	else
		*amount = (unsigned long)_amount;
}

#else /* not windows --> */

int compatible_file_open(const char* filename, unsigned long* filelen){
	struct stat stat_buf;
	int ret = open(filename, O_RDONLY);

	if (ret < 0)
		return LWS_INVALID_FILE;

	if (fstat(ret, &stat_buf) < 0) {
		close(ret);
		return LWS_INVALID_FILE;
	}
	*filelen = stat_buf.st_size;
	return ret;
}

void compatible_file_close(void*fd){
	close((int)fd)
}

unsigned long compatible_file_seek_cur(void* fd, long offset){
	return lseek((int)fd, offset, SEEK_CUR);
}

void compatible_file_read(unsigned long amount, void* fd, unsigned char* buf, unsigned long* len){
	*amount = read((int)fd, buf, len);
}

#endif // WIN32 || _WIN32


LWS_VISIBLE void
lws_context_init_file_callbacks(struct lws_context_creation_info *info, 
	struct libwebsocket_context *context)
{
	struct libwebsocket_file_callbacks* cb;

	cb = info->file_callbacks;

	if(cb && cb->pfn_open)
		context->file_callbacks.pfn_open = cb->pfn_open;
	else
		context->file_callbacks.pfn_open = compatible_file_open;

	if(cb && cb->pfn_close)
		context->file_callbacks.pfn_close = cb->pfn_close;
	else
		context->file_callbacks.pfn_close = compatible_file_close;

	if(cb && cb->pfn_seek_cur)
		context->file_callbacks.pfn_seek_cur = cb->pfn_seek_cur;
	else
		context->file_callbacks.pfn_seek_cur = compatible_file_seek_cur;

	if(cb && cb->pfn_read)
		context->file_callbacks.pfn_read = cb->pfn_read;
	else
		context->file_callbacks.pfn_read = compatible_file_read;

}