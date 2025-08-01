// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "private-lib-core.h"

#include "ssl_lib.h"
#include "ssl_pkey.h"
#include "ssl_x509.h"
#include "ssl_cert.h"
#include "ssl_dbg.h"
#include "ssl_port.h"

char *
lws_strncpy(char *dest, const char *src, size_t size);

#define SSL_SEND_DATA_MAX_LENGTH 1460

/**
 * @brief create a new SSL session object
 */
static SSL_SESSION* SSL_SESSION_new(void)
{
    SSL_SESSION *session;

    session = ssl_mem_zalloc(sizeof(SSL_SESSION));
    if (!session) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "no enough memory > (session)");
        goto failed1;
    }

    session->peer = X509_new();
    if (!session->peer) {
       SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "X509_new() return NULL");
       goto failed2;
    }

    return session;

failed2:
    ssl_mem_free(session);
failed1:
    return NULL;
}

/**
 * @brief free a new SSL session object
 */
static void SSL_SESSION_free(SSL_SESSION *session)
{
    X509_free(session->peer);
    ssl_mem_free(session);
}

/**
 * @brief Discover whether the current connection is in the error state
 */
int ossl_statem_in_error(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    if (ssl->statem.state == MSG_FLOW_ERROR)
        return 1;

    return 0;
}

/**
 * @brief get the SSL specifical statement
 */
int SSL_want(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->rwstate;
}

/**
 * @brief check if SSL want nothing
 */
int SSL_want_nothing(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    if (ssl->err)
	    return 1;

    return (SSL_want(ssl) == SSL_NOTHING);
}

/**
 * @brief check if SSL want to read
 */
int SSL_want_read(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    if (ssl->err)
	    return 0;

    return (SSL_want(ssl) == SSL_READING);
}

/**
 * @brief check if SSL want to write
 */
int SSL_want_write(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    if (ssl->err)
	    return 0;

    return (SSL_want(ssl) == SSL_WRITING);
}

/**
 * @brief check if SSL want to lookup X509 certification
 */
int SSL_want_x509_lookup(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return (SSL_want(ssl) == SSL_WRITING);
}

/**
 * @brief get SSL error code
 */
int SSL_get_error(const SSL *ssl, int ret_code)
{
    int ret = SSL_ERROR_SYSCALL;

    SSL_ASSERT1(ssl);

    if (ret_code > 0)
        ret = SSL_ERROR_NONE;
    else if (ret_code < 0)
    {
        if (ssl->err == SSL_ERROR_WANT_READ || SSL_want_read(ssl))
            ret = SSL_ERROR_WANT_READ;
        else if (ssl->err == SSL_ERROR_WANT_WRITE || SSL_want_write(ssl))
            ret = SSL_ERROR_WANT_WRITE;
        else
            ret = SSL_ERROR_SYSCALL; //unknown
    }
    else // ret_code == 0
    {
        if (ssl->shutdown & SSL_RECEIVED_SHUTDOWN)
            ret = SSL_ERROR_ZERO_RETURN;
        else
            ret = SSL_ERROR_SYSCALL;
    }

    return ret;
}

/**
 * @brief get the SSL state
 */
OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl)
{
    OSSL_HANDSHAKE_STATE state;

    SSL_ASSERT1(ssl);

    state = SSL_METHOD_CALL(get_state, ssl);

    return state;
}

const char *mbedtls_client_preload_filepath;

/**
 * @brief create a SSL context
 */
SSL_CTX* SSL_CTX_new(const SSL_METHOD *method, void *rngctx)
{
    SSL_CTX *ctx;
    CERT *cert;
    X509 *client_ca;
#if defined(LWS_HAVE_mbedtls_x509_crt_parse_file)
    int n;
#endif

    if (!method) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "no no_method");
        return NULL;
    }

    client_ca = X509_new();
    if (!client_ca) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "X509_new() return NULL");
        goto failed1;
    }

    cert = ssl_cert_new(rngctx);
    if (!cert) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "ssl_cert_new() return NULL");
        goto failed2;
    }

    ctx = (SSL_CTX *)ssl_mem_zalloc(sizeof(SSL_CTX));
    if (!ctx) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "no enough memory > (ctx)");
        goto failed3;
    }

    ctx->method = method;
    ctx->client_CA = client_ca;
    ctx->cert = cert;
    ctx->rngctx = rngctx;

    ctx->version = method->version;

#if defined(LWS_HAVE_mbedtls_x509_crt_parse_file)
    if (mbedtls_client_preload_filepath) {
	mbedtls_x509_crt **px = (mbedtls_x509_crt **)ctx->client_CA->x509_pm;

	*px = malloc(sizeof(**px));
	mbedtls_x509_crt_init(*px);
	n = mbedtls_x509_crt_parse_file(*px, mbedtls_client_preload_filepath);
	if (n < 0) {
		lwsl_err("%s: unable to load cert bundle 0x%x\n", __func__, -n);
		mbedtls_x509_crt_free(*px);
		free(*px);
	} else
		lwsl_info("%s: loaded cert bundle %d\n", __func__, n);
    }
#endif

    return ctx;

failed3:
    ssl_cert_free(cert);
failed2:
    X509_free(client_ca);
failed1:
    return NULL;
}

/**
 * @brief free a SSL context
 */
void SSL_CTX_free(SSL_CTX* ctx)
{
    SSL_ASSERT3(ctx);

    ssl_cert_free(ctx->cert);

#if defined(LWS_HAVE_mbedtls_x509_crt_parse_file)
    if (mbedtls_client_preload_filepath) {
        mbedtls_x509_crt **px = (mbedtls_x509_crt **)ctx->client_CA->x509_pm;

        if (*px) {
            mbedtls_x509_crt_free(*px);
            free(*px);
        }
    }
#endif

    X509_free(ctx->client_CA);

    if (ctx->alpn_protos) {
	    ssl_mem_free((void *)ctx->alpn_protos);
	    ctx->alpn_protos = NULL;
    }

    ssl_mem_free(ctx);
}

/**
 * @brief set  the SSL context version
 */
int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)
{
    SSL_ASSERT1(ctx);
    SSL_ASSERT1(meth);

    ctx->method = meth;

    ctx->version = meth->version;

    return 1;
}

/**
 * @brief get the SSL context current method
 */
const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx)
{
    SSL_ASSERT2(ctx);

    return ctx->method;
}

/**
 * @brief create a SSL
 */
SSL *SSL_new(SSL_CTX *ctx)
{
    int ret = 0;
    SSL *ssl;

    if (!ctx) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "no ctx");
        return NULL;
    }

    ssl = (SSL *)ssl_mem_zalloc(sizeof(SSL));
    if (!ssl) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "no enough memory > (ssl)");
        goto failed1;
    }

    ssl->session = SSL_SESSION_new();
    if (!ssl->session) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_SESSION_new() return NULL");
        goto failed2;
    }

    ssl->cert = __ssl_cert_new(ctx->cert, ctx->rngctx);
    if (!ssl->cert) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "__ssl_cert_new() return NULL");
        goto failed3;
    }

    ssl->client_CA = __X509_new(ctx->client_CA);
    if (!ssl->client_CA) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "__X509_new() return NULL");
        goto failed4;
    }

    ssl->ctx = ctx;
    ssl->method = ctx->method;

    ssl->version = ctx->version;
    ssl->options = ctx->options;

    ssl->verify_mode = ctx->verify_mode;

    ret = SSL_METHOD_CALL(new, ssl);
    if (ret) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_METHOD_CALL(new) return %d", ret);
        goto failed5;
    }

   _ssl_set_alpn_list(ssl);

    ssl->rwstate = SSL_NOTHING;

    return ssl;

failed5:
    X509_free(ssl->client_CA);
failed4:
    ssl_cert_free(ssl->cert);
failed3:
    SSL_SESSION_free(ssl->session);
failed2:
    ssl_mem_free(ssl);
failed1:
    return NULL;
}

/**
 * @brief free the SSL
 */
void SSL_free(SSL *ssl)
{
    SSL_ASSERT3(ssl);

    SSL_METHOD_CALL(free, ssl);

    X509_free(ssl->client_CA);

    ssl_cert_free(ssl->cert);

    SSL_SESSION_free(ssl->session);

    if (ssl->alpn_protos) {
	    ssl_mem_free((void *)ssl->alpn_protos);
	    ssl->alpn_protos = NULL;
    }

    ssl_mem_free(ssl);
}

/**
 * @brief perform the SSL handshake
 */
int SSL_do_handshake(SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_METHOD_CALL(handshake, ssl);

    return ret;
}

/**
 * @brief connect to the remote SSL server
 */
int SSL_connect(SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return SSL_do_handshake(ssl);
}

/**
 * @brief accept the remote connection
 */
int SSL_accept(SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return SSL_do_handshake(ssl);
}

/**
 * @brief shutdown the connection
 */
int SSL_shutdown(SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    if (SSL_get_state(ssl) != TLS_ST_OK) return 1;

    ret = SSL_METHOD_CALL(shutdown, ssl);

    return ret;
}

/**
 * @brief reset the SSL
 */
int SSL_clear(SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_shutdown(ssl);
    if (1 != ret) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_shutdown return %d", ret);
        goto failed1;
    }

    SSL_METHOD_CALL(free, ssl);

    ret = SSL_METHOD_CALL(new, ssl);
    if (!ret) {
        SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_METHOD_CALL(new) return %d", ret);
        goto failed1;
    }

    return 1;

failed1:
    return ret;
}

/**
 * @brief read data from to remote
 */
int SSL_read(SSL *ssl, void *buffer, int len)
{
    int ret;

    SSL_ASSERT1(ssl);
    SSL_ASSERT1(buffer);
    SSL_ASSERT1(len);

    ssl->rwstate = SSL_READING;

    ret = SSL_METHOD_CALL(read, ssl, buffer, len);

    if (ret == len)
        ssl->rwstate = SSL_NOTHING;

    return ret;
}

/**
 * @brief send the data to remote
 */
int SSL_write(SSL *ssl, const void *buffer, int len)
{
    int ret;
    int send_bytes, bytes;
    const unsigned char *pbuf;

    SSL_ASSERT1(ssl);
    SSL_ASSERT1(buffer);
    SSL_ASSERT1(len);

    ssl->rwstate = SSL_WRITING;

    send_bytes = len;
    pbuf = (const unsigned char *)buffer;

    do {
        if (send_bytes > SSL_SEND_DATA_MAX_LENGTH)
            bytes = SSL_SEND_DATA_MAX_LENGTH;
        else
            bytes = send_bytes;

	if (ssl->interrupted_remaining_write) {
		bytes = ssl->interrupted_remaining_write;
		ssl->interrupted_remaining_write = 0;
	}

        ret = SSL_METHOD_CALL(send, ssl, pbuf, bytes);
	//printf("%s: ssl_pm said %d for %d requested (cum %d)\n", __func__, ret, bytes, len -send_bytes);
        /* the return is a NEGATIVE OpenSSL error code, or the length sent */
        if (ret > 0) {
            pbuf += ret;
            send_bytes -= ret;
        } else
		ssl->interrupted_remaining_write = bytes;
    } while (ret > 0 && send_bytes && ret == bytes);

    if (ret >= 0) {
        ret = len - send_bytes;
	if (!ret)
	        ssl->rwstate = SSL_NOTHING;
    } else {
	    if (send_bytes == len)
		ret = -1;
	    else
		    ret = len - send_bytes;
    }

    return ret;
}

/**
 * @brief get SSL context of the SSL
 */
SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)
{
    SSL_ASSERT2(ssl);

    return ssl->ctx;
}

/**
 * @brief get the SSL current method
 */
const SSL_METHOD *SSL_get_ssl_method(SSL *ssl)
{
    SSL_ASSERT2(ssl);

    return ssl->method;
}

/**
 * @brief set the SSL method
 */
int SSL_set_ssl_method(SSL *ssl, const SSL_METHOD *method)
{
    int ret;

    SSL_ASSERT1(ssl);
    SSL_ASSERT1(method);

    if (ssl->version != method->version) {

        ret = SSL_shutdown(ssl);
        if (1 != ret) {
            SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_shutdown return %d", ret);
            goto failed1;
        }

        SSL_METHOD_CALL(free, ssl);

        ssl->method = method;

        ret = SSL_METHOD_CALL(new, ssl);
        if (!ret) {
            SSL_DEBUG(SSL_LIB_ERROR_LEVEL, "SSL_METHOD_CALL(new) return %d", ret);
            goto failed1;
        }
    } else {
        ssl->method = method;
    }


    return 1;

failed1:
    return ret;
}

/**
 * @brief get SSL shutdown mode
 */
int SSL_get_shutdown(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->shutdown;
}

/**
 * @brief set SSL shutdown mode
 */
void SSL_set_shutdown(SSL *ssl, int mode)
{
    SSL_ASSERT3(ssl);

    ssl->shutdown = mode;
}


/**
 * @brief get the number of the bytes to be read
 */
int SSL_pending(const SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_METHOD_CALL(pending, ssl);

    return ret;
}

/**
 * @brief check if some data can be read
 */
int SSL_has_pending(const SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    if (SSL_pending(ssl))
        ret = 1;
    else
        ret = 0;

    return ret;
}

/**
 * @brief clear the SSL context option bit of "op"
 */
unsigned long SSL_CTX_clear_options(SSL_CTX *ctx, unsigned long op)
{
    SSL_ASSERT1(ctx);

    return ctx->options &= ~op;
}

/**
 * @brief get the SSL context option
 */
unsigned long SSL_CTX_get_options(SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->options;
}

/**
 * @brief set the option of the SSL context
 */
unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long opt)
{
    SSL_ASSERT1(ctx);

    return ctx->options |= opt;
}

/**
 * @brief clear SSL option
 */
unsigned long SSL_clear_options(SSL *ssl, unsigned long op)
{
    SSL_ASSERT1(ssl);

    return ssl->options & ~op;
}

/**
 * @brief get SSL option
 */
unsigned long SSL_get_options(SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->options;
}

/**
 * @brief clear SSL option
 */
unsigned long SSL_set_options(SSL *ssl, unsigned long op)
{
    SSL_ASSERT1(ssl);

    return ssl->options |= op;
}

/**
 * @brief get the socket handle of the SSL
 */
int SSL_get_fd(const SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_METHOD_CALL(get_fd, ssl, 0);

    return ret;
}

/**
 * @brief get the read only socket handle of the SSL
 */
int SSL_get_rfd(const SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_METHOD_CALL(get_fd, ssl, 0);

    return ret;
}

/**
 * @brief get the write only socket handle of the SSL
 */
int SSL_get_wfd(const SSL *ssl)
{
    int ret;

    SSL_ASSERT1(ssl);

    ret = SSL_METHOD_CALL(get_fd, ssl, 0);

    return ret;
}

/**
 * @brief bind the socket file description into the SSL
 */
int SSL_set_fd(SSL *ssl, int fd)
{
    SSL_ASSERT1(ssl);
    SSL_ASSERT1(fd >= 0);

    SSL_METHOD_CALL(set_fd, ssl, fd, 0);

    return 1;
}

/**
 * @brief bind the read only socket file description into the SSL
 */
int SSL_set_rfd(SSL *ssl, int fd)
{
    SSL_ASSERT1(ssl);
    SSL_ASSERT1(fd >= 0);

    SSL_METHOD_CALL(set_fd, ssl, fd, 0);

    return 1;
}

/**
 * @brief bind the write only socket file description into the SSL
 */
int SSL_set_wfd(SSL *ssl, int fd)
{
    SSL_ASSERT1(ssl);
    SSL_ASSERT1(fd >= 0);

    SSL_METHOD_CALL(set_fd, ssl, fd, 0);

    return 1;
}

/**
 * @brief get SSL version
 */
int SSL_version(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->version;
}

/**
 * @brief get the SSL version string
 */
static const char* ssl_protocol_to_string(int version)
{
    const char *str;

    if (version == TLS1_2_VERSION)
        str = "TLSv1.2";
    else if (version == TLS1_1_VERSION)
        str = "TLSv1.1";
    else if (version == TLS1_VERSION)
        str = "TLSv1";
    else if (version == SSL3_VERSION)
        str = "SSLv3";
    else
        str = "unknown";

    return str;
}

/**
 * @brief get the SSL current version
 */
const char *SSL_get_version(const SSL *ssl)
{
    SSL_ASSERT2(ssl);

    return ssl_protocol_to_string(SSL_version(ssl));
}

/**
 * @brief get alert type string
 */
const char *SSL_alert_type_string(int value)
{
    const char *str;

    switch (value >> 8)
    {
    case SSL3_AL_WARNING:
        str = "W";
        break;
    case SSL3_AL_FATAL:
        str = "F";
        break;
    default:
        str = "U";
        break;
    }

    return str;
}

/**
 * @brief set the SSL context read buffer length
 */
void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len)
{
    SSL_ASSERT3(ctx);

    ctx->read_buffer_len = (int)len;
}

/**
 * @brief set the SSL read buffer length
 */
void SSL_set_default_read_buffer_len(SSL *ssl, size_t len)
{
    SSL_ASSERT3(ssl);
    SSL_ASSERT3(len);

    SSL_METHOD_CALL(set_bufflen, ssl, (int)len);
}

/**
 * @brief set the SSL information callback function
 */
void SSL_set_info_callback(SSL *ssl, void (*cb) (const SSL *ssl, int type, int val))
{
    SSL_ASSERT3(ssl);

    ssl->info_callback = cb;
}

/**
 * @brief add SSL context reference count by '1'
 */
int SSL_CTX_up_ref(SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    /**
     * no support multi-thread SSL here
     */
    ctx->references++;

    return 1;
}

/**
 * @brief set the SSL security level
 */
void SSL_set_security_level(SSL *ssl, int level)
{
    SSL_ASSERT3(ssl);

    ssl->cert->sec_level = level;
}

/**
 * @brief get the SSL security level
 */
int SSL_get_security_level(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->cert->sec_level;
}

/**
 * @brief get the SSL verifying mode of the SSL context
 */
int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->verify_mode;
}

/**
 * @brief set the session timeout time
 */
long SSL_CTX_set_timeout(SSL_CTX *ctx, long t)
{
    long l;

    SSL_ASSERT1(ctx);

    l = ctx->session_timeout;
    ctx->session_timeout = t;

    return l;
}

/**
 * @brief get the session timeout time
 */
long SSL_CTX_get_timeout(const SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->session_timeout;
}

/**
 * @brief set the SSL if we can read as many as data
 */
void SSL_set_read_ahead(SSL *ssl, int yes)
{
    SSL_ASSERT3(ssl);

    ssl->rlayer.read_ahead = yes;
}

/**
 * @brief set the SSL context if we can read as many as data
 */
void SSL_CTX_set_read_ahead(SSL_CTX *ctx, int yes)
{
    SSL_ASSERT3(ctx);

    ctx->read_ahead = yes;
}

/**
 * @brief get the SSL ahead signal if we can read as many as data
 */
int SSL_get_read_ahead(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->rlayer.read_ahead;
}

/**
 * @brief get the SSL context ahead signal if we can read as many as data
 */
long SSL_CTX_get_read_ahead(SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->read_ahead;
}

/**
 * @brief check if the SSL context can read as many as data
 */
long SSL_CTX_get_default_read_ahead(SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->read_ahead;
}

/**
 * @brief set SSL session time
 */
long SSL_set_time(SSL *ssl, long t)
{
    SSL_ASSERT1(ssl);

    ssl->session->time = t;

    return t;
}

/**
 * @brief set SSL session timeout time
 */
long SSL_set_timeout(SSL *ssl, long t)
{
    SSL_ASSERT1(ssl);

    ssl->session->timeout = t;

    return t;
}

/**
 * @brief get the verifying result of the SSL certification
 */
long SSL_get_verify_result(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return SSL_METHOD_CALL(get_verify_result, ssl);
}

/**
 * @brief get the SSL verifying depth of the SSL context
 */
int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)
{
    SSL_ASSERT1(ctx);

    return ctx->param.depth;
}

/**
 * @brief set the SSL verify depth of the SSL context
 */
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
    SSL_ASSERT3(ctx);

    ctx->param.depth = depth;
}

/**
 * @brief get the SSL verifying depth of the SSL
 */
int SSL_get_verify_depth(const SSL *ssl)
{
    SSL_ASSERT1(ssl);

    return ssl->param.depth;
}

/**
 * @brief set the SSL verify depth of the SSL
 */
void SSL_set_verify_depth(SSL *ssl, int depth)
{
    SSL_ASSERT3(ssl);

    ssl->param.depth = depth;
}

/**
 * @brief set the SSL context verifying of the SSL context
 */
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*verify_callback)(SSL *, mbedtls_x509_crt *))
{
    SSL_ASSERT3(ctx);

    ctx->verify_mode = mode;
    ctx->default_verify_callback = verify_callback;
}

/**
 * @brief set the SSL verifying of the SSL context
 */
void SSL_set_verify(SSL *ssl, int mode, int (*verify_callback)(SSL *, mbedtls_x509_crt *))
{
    SSL_ASSERT3(ssl);

    ssl->verify_mode = mode;
    ssl->verify_callback = verify_callback;
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
	lws_strncpy(buf, "unknown", len);
}

void ERR_free_strings(void)
{
}

char *ERR_error_string(unsigned long e, char *buf)
{
	if (!buf)
		return "unknown";

	switch(e) {
		case X509_V_ERR_INVALID_CA:
			strcpy(buf, "CA is not trusted");
			break;
		case X509_V_ERR_HOSTNAME_MISMATCH:
			strcpy(buf, "Hostname mismatch");
			break;
		case X509_V_ERR_CA_KEY_TOO_SMALL:
			strcpy(buf, "CA key too small");
			break;
		case X509_V_ERR_CA_MD_TOO_WEAK:
			strcpy(buf, "MD key too weak");
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
			strcpy(buf, "Cert from the future");
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			strcpy(buf, "Cert expired");
			break;
		default:
			strcpy(buf, "unknown");
			break;
	}

	return buf;
}

void *SSL_CTX_get_ex_data(const SSL_CTX *ctx, int idx)
{
	return NULL;
}

/*
 * Openssl wants the valid protocol names supplied like this:
 *
 * (unsigned char *)"\x02h2\x08http/1.1", 6 + 9
 *
 * Mbedtls wants this:
 *
 * Pointer to a NULL-terminated list of supported protocols, in decreasing
 * preference order. The pointer to the list is recorded by the library for
 * later reference as required, so the lifetime of the table must be at least
 * as long as the lifetime of the SSL configuration structure.
 *
 * So accept the OpenSSL style and convert to mbedtls style
 */


static void
_openssl_alpn_to_mbedtls(struct alpn_ctx *ac, char ***palpn_protos)
{
	unsigned char *p = ac->data, *q;
	unsigned char len;
	char **alpn_protos;
	int count = 0;

	/* find out how many entries he gave us */

	if (ac->len) {
		len = *p++;
		if (len)
			count++;
		while (p - ac->data < ac->len) {
			if (len--) {
				p++;
				continue;
			}
			len = *p++;
			if (!len)
				break;
			count++;
		}
	}

	if (!count)
		return;

	/* allocate space for count + 1 pointers and the data afterwards */

	alpn_protos = ssl_mem_zalloc((unsigned int)(count + 1) * sizeof(char *) + ac->len + 1);
	if (!alpn_protos)
		return;

	*palpn_protos = alpn_protos;

	/* convert to mbedtls format */

	q = (unsigned char *)alpn_protos + (unsigned int)(count + 1) * sizeof(char *);
	p = ac->data;
	count = 0;

	len = *p++;
	alpn_protos[count] = (char *)q;
	while (p - ac->data < ac->len) {
		if (len--) {
			*q++ = *p++;
			continue;
		}
		*q++ = '\0';
		count++;
		len = *p++;
		alpn_protos[count] = (char *)q;
		if (!len)
			break;
	}
	if (!len) {
		*q++ = '\0';
		count++;
		/* len = *p++; */
		alpn_protos[count] = (char *)q;
	}
	alpn_protos[count] = NULL; /* last pointer ends list with NULL */
}

void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, next_proto_cb cb, void *arg)
{
	struct alpn_ctx *ac = arg;

	ctx->alpn_cb = cb;

	_openssl_alpn_to_mbedtls(ac, (char ***)&ctx->alpn_protos);
}

void SSL_set_alpn_select_cb(SSL *ssl, void *arg)
{
	struct alpn_ctx *ac = arg;

	_openssl_alpn_to_mbedtls(ac, (char ***)&ssl->alpn_protos);

	_ssl_set_alpn_list(ssl);
}

int SSL_CTX_load_verify_file(SSL_CTX *ctx, const char *CAfile)
{
	X509 *x;
	int ret;

	SSL_ASSERT1(ctx);
	SSL_ASSERT1(CAfile);

	x = X509_new();
	ret = X509_METHOD_CALL(load_file, x, CAfile);
	if (ret) {
		X509_free(x);
		return 0;
	}

	SSL_CTX_add_client_CA(ctx, x);
	return 1;
}

int SSL_CTX_load_verify_dir(SSL_CTX *ctx, const char *CApath)
{
	X509 *x;
	int ret;

	SSL_ASSERT1(ctx);
	SSL_ASSERT1(CApath);

	x = X509_new();
	ret = X509_METHOD_CALL(load_path, x, CApath);
	if (ret) {
		X509_free(x);
		return 0;
	}

	SSL_CTX_add_client_CA(ctx, x);
	return 1;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
	if (CAfile == NULL && CApath == NULL) {
		return 0;
	}

	if (CAfile != NULL && !SSL_CTX_load_verify_file(ctx, CAfile)) {
		return 0;
	}

	if (CApath != NULL && !SSL_CTX_load_verify_dir(ctx, CApath)) {
		return 0;
	}

	return 1;
}
