/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * lws-io.h: the transport half of lws.  Creating a context and vhosts,
 * adopting and connecting sockets, service, the tls library, dns, event
 * loops, and the platform's devices.  Everything in here names something
 * outside the process's own memory.  See READMEs/README.sans-io-split.md.
 *
 * Needs lws-core.h and lws-sansio.h first.
 */

#if defined(LWS_WITH_TRANSPORT_SEQUENCER)
#include <libwebsockets/lws-transport-sequencer.h>
#endif
#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-adopt.h>
/*
 * addresses are data and belong with core, but lws_sockaddr46 is defined in
 * lws-adopt.h today; it moves when the type does
 */
#include <libwebsockets/lws-network-helper.h>
#endif

#include <libwebsockets/lws-ota.h>
#include <libwebsockets/lws-system.h>
#include <libwebsockets/lws-whois.h>

#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-latency.h>
#endif

#if defined(LWS_WITH_JOSE)
#include <libwebsockets/lws-interceptor.h>
#endif

#include <libwebsockets/lws-context-vhost.h>

#if defined(LWS_WITH_NETWORK)
#if defined(LWS_WITH_CONMON)
#include <libwebsockets/lws-conmon.h>
#endif
#include <libwebsockets/lws-client.h>
#include <libwebsockets/lws-async-ipc.h>
#include <libwebsockets/lws-service.h>
#endif
#include <libwebsockets/lws-gendtls.h>
#include <libwebsockets/lws-stun.h>
#include <libwebsockets/lws-x509.h>
#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-cgi.h>
#endif
#include <libwebsockets/lws-gencrypto.h>
#include <libwebsockets/lws-cose.h>

#include <libwebsockets/lws-secure-streams.h>
#include <libwebsockets/lws-secure-streams-serialization.h>
#include <libwebsockets/lws-secure-streams-policy.h>
#include <libwebsockets/lws-secure-streams-client.h>
#include <libwebsockets/lws-secure-streams-transport-proxy.h>
#include <libwebsockets/lws-jrpc.h>
#include <libwebsockets/lws-stub.h>

#include <libwebsockets/lws-async-dns.h>
#if defined(LWS_WITH_AUTHORITATIVE_DNS)
#include <libwebsockets/lws-auth-dns.h>
#endif

#if defined(LWS_WITH_TLS)

#include <libwebsockets/lws-tls-sessions.h>

#if defined(LWS_WITH_MBEDTLS)
#if !defined(LWS_HAVE_MBEDTLS_V4)
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#else
#include <psa/crypto.h>
#endif
#endif
#if defined(LWS_WITH_BEARSSL)
#include <bearssl.h>
#endif

#include <libwebsockets/lws-genhash.h>
#include <libwebsockets/lws-genrsa.h>
#include <libwebsockets/lws-genaes.h>
#include <libwebsockets/lws-genchacha.h>
#include <libwebsockets/lws-genec.h>

#include <libwebsockets/lws-jwk.h>
#include <libwebsockets/lws-jose.h>
#include <libwebsockets/lws-jws.h>
#include <libwebsockets/lws-jwe.h>
#include <libwebsockets/lws-jwt-auth.h>

#endif

#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-eventlib-exports.h>
#endif
#include <libwebsockets/lws-i2c.h>
#include <libwebsockets/lws-spi.h>
#if defined(LWS_ESP_PLATFORM)
#include <libwebsockets/lws-esp32-spi.h>
#endif
#include <libwebsockets/lws-gpio.h>
#include <libwebsockets/lws-bb-i2c.h>
#include <libwebsockets/lws-bb-spi.h>
#include <libwebsockets/lws-button.h>
#include <libwebsockets/lws-led.h>
#include <libwebsockets/lws-pwm.h>
#include <libwebsockets/lws-display.h>
#include <libwebsockets/lws-dlo.h>
#include <libwebsockets/lws-ssd1306-i2c.h>
#include <libwebsockets/lws-ili9341-spi.h>
#include <libwebsockets/lws-gc9a01a-spi.h>
#include <libwebsockets/lws-spd1656-spi.h>
#include <libwebsockets/lws-ssd1675b-spi.h>
#include <libwebsockets/lws-uc8176-spi.h>
#if defined(LWS_WITH_DLTS)
#include <libwebsockets/lws-gendtls.h>
#endif
#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-netdev.h>
#include <libwebsockets/lws-txpacer.h>
#include "libwebsockets/lws-dht.h"
#include "libwebsockets/lws-dht-dnssec.h"
#if defined(LWS_WITH_TRANSCODE)
#include <libwebsockets/lws-transcode.h>
#endif
#if defined(LWS_WITH_V4L2)
#include <libwebsockets/lws-v4l2.h>
#endif
#if defined(LWS_WITH_ALSA)
#include <libwebsockets/lws-alsa.h>
#include <libwebsockets/lws-audio-features.h>
#endif
#endif

/* the html layout engine renders into the display list: it lives with it */
#include <libwebsockets/lws-html.h>

#include <libwebsockets/lws-smtp-client.h>

#if defined(LWS_WITH_DIR)
#include <libwebsockets/lws-dir-notify.h>
#endif
