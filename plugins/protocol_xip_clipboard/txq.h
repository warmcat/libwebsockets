/*
 * Simple outbound frame queue shared by relay plugin and client.
 * Each node owns its buffer with LWS_PRE headroom so queued frames can be
 * handed to lws_write() without copying.
 */
#ifndef XIP_TXQ_H
#define XIP_TXQ_H

#include <stddef.h>

#include <libwebsockets.h>

#ifdef __cplusplus
extern "C" {
#endif

struct xip_txq_node {
	struct xip_txq_node *next;
	uint8_t	       *buf;		/* LWS_PRE + payload */
	size_t		len;		/* payload length */
	size_t		off;		/* payload offset (partial writes) */
};

/* 0 = ok, -1 = OOM */
int xip_txq_append(struct xip_txq_node **head, const void *payload,
		   size_t len);

struct xip_txq_node *xip_txq_pop(struct xip_txq_node **head);
void xip_txq_free_node(struct xip_txq_node *n);
void xip_txq_destroy(struct xip_txq_node **head);

#ifdef __cplusplus
}
#endif

#endif
