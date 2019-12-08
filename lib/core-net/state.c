/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

void
lws_state_reg_notifier(lws_state_manager_t *mgr,
		       lws_state_notify_link_t *notify_link)
{
	lws_dll2_add_head(&notify_link->list, &mgr->notify_list);
}

void
lws_state_reg_deregister(lws_state_notify_link_t *nl)
{
	lws_dll2_remove(&nl->list);
}

void
lws_state_reg_notifier_list(lws_state_manager_t *mgr,
			    lws_state_notify_link_t * const *notify_link_array)
{
	if (notify_link_array)
		while (*notify_link_array)
			lws_state_reg_notifier(mgr, *notify_link_array++);
}

#if defined(_DEBUG)
static const char *
_systnm(lws_state_manager_t *mgr, int state, char *temp8)
{
	if (!mgr->state_names) {
		lws_snprintf(temp8, 8, "%d", state);
		return temp8;
	}

	return mgr->state_names[state];
}
#endif

static int
_report(lws_state_manager_t *mgr, int a, int b)
{
#if defined(_DEBUG)
	char temp8[8];
#endif

	lws_start_foreach_dll(struct lws_dll2 *, d, mgr->notify_list.head) {
		lws_state_notify_link_t *l =
			lws_container_of(d, lws_state_notify_link_t, list);

		if (l->notify_cb(mgr, l, a, b)) {
			/* a dependency took responsibility for retry */
#if defined(_DEBUG)
			lwsl_info("%s: %s: %s: rejected '%s' -> '%s'\n",
				   __func__, mgr->name, l->name,
				   _systnm(mgr, a, temp8),
				   _systnm(mgr, b, temp8));
#endif
			return 1;
		}

	} lws_end_foreach_dll(d);

	return 0;
}

static int
_lws_state_transition(lws_state_manager_t *mgr, int target)
{
#if defined(_DEBUG)
	char temp8[8];
#endif

	if (_report(mgr, mgr->state, target))
		return 1;

#if defined(_DEBUG)
	lwsl_debug("%s: %s: changed %d '%s' -> %d '%s'\n", __func__, mgr->name,
		   mgr->state, _systnm(mgr, mgr->state, temp8), target,
		   _systnm(mgr, target, temp8));
#endif

	mgr->state = target;

	/* Indicate success by calling the notifers again with both args same */
	_report(mgr, target, target);

	return 0;
}

int
lws_state_transition_steps(lws_state_manager_t *mgr, int target)
{
	int n = 0;
#if defined(_DEBUG)
	int i = mgr->state;
	char temp8[8];
#endif

	while (!n && mgr->state != target)
		n = _lws_state_transition(mgr, mgr->state + 1);

#if defined(_DEBUG)
	lwsl_info("%s: %s -> %s\n", __func__, _systnm(mgr, i, temp8),
			_systnm(mgr, mgr->state, temp8));
#endif

	return 0;
}

int
lws_state_transition(lws_state_manager_t *mgr, int target)
{
	if (mgr->state != target)
		_lws_state_transition(mgr, target);

	return 0;
}
