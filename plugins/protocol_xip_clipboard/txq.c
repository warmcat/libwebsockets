#include <stdlib.h>
#include <string.h>

#include "txq.h"

int
xip_txq_append(struct xip_txq_node **head, const void *payload, size_t len)
{
	struct xip_txq_node *n = (struct xip_txq_node *)
			malloc(sizeof(*n));
	struct xip_txq_node **tail;

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

	for (tail = head; *tail; tail = &(*tail)->next)
		;
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
