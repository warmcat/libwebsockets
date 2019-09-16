/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
#include "tls/private.h"

#if !defined(LWS_PLAT_OPTEE) && !defined(OPTEE_DEV_KIT)
#if defined(LWS_WITH_ESP32) && !defined(LWS_AMAZON_RTOS)
int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
	       lws_filepos_t *amount)
{
	nvs_handle nvh;
	size_t s;
	int n = 0;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, filename, NULL, &s) != ESP_OK) {
		n = 1;
		goto bail;
	}
	*buf = lws_malloc(s + 1, "alloc_file");
	if (!*buf) {
		n = 2;
		goto bail;
	}
	if (nvs_get_blob(nvh, filename, (char *)*buf, &s) != ESP_OK) {
		lws_free(*buf);
		n = 1;
		goto bail;
	}

	*amount = s;
	(*buf)[s] = '\0';

	lwsl_notice("%s: nvs: read %s, %d bytes\n", __func__, filename, (int)s);

bail:
	nvs_close(nvh);

	return n;
}
#else
int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
		lws_filepos_t *amount)
{
	FILE *f;
	size_t s;
	int n = 0;

	f = fopen(filename, "rb");
	if (f == NULL) {
		n = 1;
		goto bail;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		n = 1;
		goto bail;
	}

	s = ftell(f);
	if (s == (size_t)-1) {
		n = 1;
		goto bail;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		n = 1;
		goto bail;
	}

	*buf = lws_malloc(s, "alloc_file");
	if (!*buf) {
		n = 2;
		goto bail;
	}

	if (fread(*buf, s, 1, f) != 1) {
		lws_free(*buf);
		n = 1;
		goto bail;
	}

	*amount = s;

bail:
	if (f)
		fclose(f);

	return n;

}
#endif

/*
 * filename: NULL means use buffer inbuf length inlen directly, otherwise
 *           load the file "filename" into an allocated buffer.
 *
 * Allocates a separate DER output buffer if inbuf / inlen are the input,
 * since the
 *
 * Contents may be PEM or DER: returns with buf pointing to DER and amount
 * set to the DER length.
 */

int
lws_tls_alloc_pem_to_der_file(struct lws_context *context, const char *filename,
			      const char *inbuf, lws_filepos_t inlen,
			      uint8_t **buf, lws_filepos_t *amount)
{
	uint8_t *pem = NULL, *p, *end, *opem;
	lws_filepos_t len;
	uint8_t *q;
	int n;

	if (filename) {
		n = alloc_file(context, filename, (uint8_t **)&pem, &len);
		if (n)
			return n;
	} else {
		pem = (uint8_t *)inbuf;
		len = inlen;
	}

	opem = p = pem;
	end = p + len;

	if (strncmp((char *)p, "-----", 5)) {

		/* take it as being already DER */

		pem = lws_malloc(inlen, "alloc_der");
		if (!pem)
			return 1;

		memcpy(pem, inbuf, inlen);

		*buf = pem;
		*amount = inlen;

		return 0;
	}

	/* PEM -> DER */

	if (!filename) {
		/* we don't know if it's in const memory... alloc the output */
		pem = lws_malloc((inlen * 3) / 4, "alloc_der");
		if (!pem) {
			lwsl_err("a\n");
			return 1;
		}


	} /* else overwrite the allocated, b64 input with decoded DER */

	/* trim the first line */

	p += 5;
	while (p < end && *p != '\n' && *p != '-')
		p++;

	if (*p != '-') {
		lwsl_err("b\n");
		goto bail;
	}

	while (p < end && *p != '\n')
		p++;

	if (p >= end) {
		lwsl_err("c\n");
		goto bail;
	}

	p++;

	/* trim the last line */

	q = (uint8_t *)end - 2;

	while (q > opem && *q != '\n')
		q--;

	if (*q != '\n') {
		lwsl_err("d\n");
		goto bail;
	}

	/* we can't write into the input buffer for mem, since it may be in RO
	 * const segment
	 */
	if (filename)
		*q = '\0';

	*amount = lws_b64_decode_string_len((char *)p, lws_ptr_diff(q, p),
					    (char *)pem, (int)(long long)len);
	*buf = (uint8_t *)pem;

	return 0;

bail:
	lws_free((uint8_t *)pem);

	return 4;
}


#endif

#if !defined(LWS_WITH_ESP32) && !defined(LWS_PLAT_OPTEE) && !defined(OPTEE_DEV_KIT)


static int
lws_tls_extant(const char *name)
{
	/* it exists if we can open it... */
	int fd = open(name, O_RDONLY), n;
	char buf[1];

	if (fd < 0)
		return 1;

	/* and we can read at least one byte out of it */
	n = read(fd, buf, 1);
	close(fd);

	return n != 1;
}
#endif
/*
 * Returns 0 if the filepath "name" exists and can be read from.
 *
 * In addition, if "name".upd exists, backup "name" to "name.old.1"
 * and rename "name".upd to "name" before reporting its existence.
 *
 * There are four situations and three results possible:
 *
 * 1) LWS_TLS_EXTANT_NO: There are no certs at all (we are waiting for them to
 *    be provisioned).  We also feel like this if we need privs we don't have
 *    any more to look in the directory.
 *
 * 2) There are provisioned certs written (xxx.upd) and we still have root
 *    privs... in this case we rename any existing cert to have a backup name
 *    and move the upd cert into place with the correct name.  This then becomes
 *    situation 4 for the caller.
 *
 * 3) LWS_TLS_EXTANT_ALTERNATIVE: There are provisioned certs written (xxx.upd)
 *    but we no longer have the privs needed to read or rename them.  In this
 *    case, indicate that the caller should use temp copies if any we do have
 *    rights to access.  This is normal after we have updated the cert.
 *
 *    But if we dropped privs, we can't detect the provisioned xxx.upd cert +
 *    key, because we can't see in the dir.  So we have to upgrade NO to
 *    ALTERNATIVE when we actually have the in-memory alternative.
 *
 * 4) LWS_TLS_EXTANT_YES: The certs are present with the correct name and we
 *    have the rights to read them.
 */
#if !defined(LWS_AMAZON_RTOS)
enum lws_tls_extant
lws_tls_use_any_upgrade_check_extant(const char *name)
{
#if !defined(LWS_PLAT_OPTEE)

	int n;

#if !defined(LWS_WITH_ESP32)
	char buf[256];

	lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
	if (!lws_tls_extant(buf)) {
		/* ah there is an updated file... how about the desired file? */
		if (!lws_tls_extant(name)) {
			/* rename the desired file */
			for (n = 0; n < 50; n++) {
				lws_snprintf(buf, sizeof(buf) - 1,
					     "%s.old.%d", name, n);
				if (!rename(name, buf))
					break;
			}
			if (n == 50) {
				lwsl_notice("unable to rename %s\n", name);

				return LWS_TLS_EXTANT_ALTERNATIVE;
			}
			lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
		}
		/* desired file is out of the way, rename the updated file */
		if (rename(buf, name)) {
			lwsl_notice("unable to rename %s to %s\n", buf, name);

			return LWS_TLS_EXTANT_ALTERNATIVE;
		}
	}

	if (lws_tls_extant(name))
		return LWS_TLS_EXTANT_NO;
#else
	nvs_handle nvh;
	size_t s = 8192;

	if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
		lwsl_notice("%s: can't open nvs\n", __func__);
		return LWS_TLS_EXTANT_NO;
	}

	n = nvs_get_blob(nvh, name, NULL, &s);
	nvs_close(nvh);

	if (n)
		return LWS_TLS_EXTANT_NO;
#endif
#endif
	return LWS_TLS_EXTANT_YES;
}
#endif

