/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
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
 *
 *
 * These headers are related to providing user Secure Streams Serialization
 * transport implementations in user code.
 *
 * The default implementation uses wsi for proxy serving and connecting clients,
 * but it's also possible to provide user implementations of the operations
 * needed to serve on a different transport for proxy, and to connect out on
 * the different transport for client.
 *
 * You can provide your own lws_sss_ops_client_t and lws_sss_ops_proxy_t to
 * control how serialized data is transmitted and received, to use SS
 * serialization over, eg, UART instead.
 *
 * This allows situations where full SS proxy services can be offered to much
 * weker devices, without any networking stack or tls library being needed.
 */

/*
 * SSS Proxy Transport-related implementation apis
 */

struct lws_sss_proxy_conn;


