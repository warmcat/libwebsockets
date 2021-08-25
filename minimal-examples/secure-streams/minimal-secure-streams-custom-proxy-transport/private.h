/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is a version of minimal-secure-streams-proxy that uses a custom
 * transport.
 */

extern const lws_transport_proxy_ops_t lws_transport_ops_serial;
extern struct lws_protocols protocol_sspc_serial_transport;
extern const lws_transport_proxy_ops_t lws_transport_mux_transport_ops;
