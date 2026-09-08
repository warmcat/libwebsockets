#include <stdlib.h>
#include <string.h>

#include "txq.h"

int
xip_txq_append(struct xip_txq_node **head, const void *payload, size_t len,
	       size_t max_bytes)
{
	struct xip_txq_node *n, **tail;
	size_t queued = 0;

	/*
	 * We are walking to the tail anyway, so total up what is already
	 * waiting: a peer that never reads (or that spams cheap "fetch"
	 * requests, each of which queues the whole cached clip) otherwise
	 * grows this list without any bound at all.
	 */
	for (tail = head; *tail; tail = &(*tail)->next)
		queued += (*tail)->len - (*tail)->off;

	if (max_bytes && queued + len > max_bytes)
		return -1;

	n = (struct xip_txq_node *)malloc(sizeof(*n));
	if (!n)
		return -1;
	n->next = NULL;
	n->buf = (uint8_t *)malloc(LWS_PRE + len);
	if (!n->buf) {
		free(n);
		return -1;
	}
	memcpy(n->buf + LWS_PRE, payload, len);
	n->len = len;
	n->off = 0;

	*tail = n;

	return 0;
}

struct xip_txq_node *
xip_txq_pop(struct xip_txq_node **head)
{
	struct xip_txq_node *n = *head;

	if (n)
		*head = n->next;

	return n;
}

void
xip_txq_free_node(struct xip_txq_node *n)
{
	if (n) {
		free(n->buf);
		free(n);
	}
}

void
xip_txq_destroy(struct xip_txq_node **head)
{
	struct xip_txq_node *n;

	while ((n = xip_txq_pop(head)))
		xip_txq_free_node(n);
}
