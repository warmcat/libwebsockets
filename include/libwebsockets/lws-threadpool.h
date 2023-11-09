/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

/** \defgroup threadpool Threadpool related functions
 * ##Threadpool
 * \ingroup lwsapi
 *
 * This allows you to create one or more pool of threads which can run tasks
 * associated with a wsi.  If the pool is busy, tasks wait on a queue.
 *
 * Tasks don't have to be atomic, if they will take more than a few tens of ms
 * they should return back to the threadpool worker with a return of 0.  This
 * will allow them to abort cleanly.
 */
//@{

struct lws_threadpool;
struct lws_threadpool_task;

enum lws_threadpool_task_status {
	LWS_TP_STATUS_QUEUED,
	LWS_TP_STATUS_RUNNING,
	LWS_TP_STATUS_SYNCING,
	LWS_TP_STATUS_STOPPING,
	LWS_TP_STATUS_FINISHED, /* lws_threadpool_task_status() frees task */
	LWS_TP_STATUS_STOPPED   /* lws_threadpool_task_status() frees task */
};

enum lws_threadpool_task_return {
	/** Still work to do, just confirming not being stopped */
	LWS_TP_RETURN_CHECKING_IN,
	/** Still work to do, enter cond_wait until service thread syncs.  This
	 * is used if you have filled your buffer(s) of data to the service
	 * thread and are blocked until the service thread completes sending at
	 * least one.
	 */
	LWS_TP_RETURN_SYNC,
	/** No more work to do... */
	LWS_TP_RETURN_FINISHED,
	/** Responding to request to stop */
	LWS_TP_RETURN_STOPPED,

	/* OR on to indicate this task wishes to outlive its wsi */
	LWS_TP_RETURN_FLAG_OUTLIVE = 64
};

struct lws_threadpool_create_args {
	int threads;
	int max_queue_depth;
};

struct lws_threadpool_task_args {
#if defined(LWS_WITH_SECURE_STREAMS)
	struct lws_ss_handle *ss; /**< either wsi or ss must be set */
#endif
	struct lws *wsi;	/**< either wsi or ss must be set */

	void *user;		/**< user may set (user-private pointer) */
	const char *name;	/**< user may set to describe task */
	char async_task;	/**< set to allow the task to shrug off the loss
				     of the associated wsi and continue to
				     completion */
	enum lws_threadpool_task_return (*task)(void *user,
					enum lws_threadpool_task_status s);
	/**< user must set to actual task function */
	void (*cleanup)(struct lws *wsi, void *user);
	/**< socket lifecycle may end while task is not stoppable, so the task
	 * must be able to detach from any wsi and clean itself up when it does
	 * stop.  If NULL, no cleanup necessary, otherwise point to a user-
	 * supplied function that destroys the stuff in \p user.
	 *
	 * wsi may be NULL on entry, indicating the task got detached due to the
	 * wsi closing before.
	 */
};

/**
 * lws_threadpool_create() - create a pool of worker threads
 *
 * \param context: the lws_context the threadpool will exist inside
 * \param args: argument struct prepared by caller
 * \param format: printf-type format for the task name
 * \param ...: printf type args for the task name format
 *
 * Creates a pool of worker threads with \p threads and a queue of up to
 * \p max_queue_depth waiting tasks if all the threads are busy.
 *
 * Returns NULL if OOM, or a struct lws_threadpool pointer that must be
 * destroyed by lws_threadpool_destroy().
 */
LWS_VISIBLE LWS_EXTERN struct lws_threadpool *
lws_threadpool_create(struct lws_context *context,
		      const struct lws_threadpool_create_args *args,
		      const char *format, ...) LWS_FORMAT(3);

/**
 * lws_threadpool_finish() - Stop all pending and running tasks
 *
 * \param tp: the threadpool object
 *
 * Marks the threadpool as under destruction.  Removes everything from the
 * pending queue and completes those tasks as LWS_TP_STATUS_STOPPED.
 *
 * Running tasks will also get LWS_TP_STATUS_STOPPED as soon as they
 * "resurface".
 *
 * This doesn't reap tasks or free the threadpool, the reaping is done by the
 * lws_threadpool_task_status() on the done task.
 */
LWS_VISIBLE LWS_EXTERN void
lws_threadpool_finish(struct lws_threadpool *tp);

/**
 * lws_threadpool_destroy() - Destroy a threadpool
 *
 * \param tp: the threadpool object
 *
 * Waits for all worker threads to stop, ends the threads and frees the tp.
 */
LWS_VISIBLE LWS_EXTERN void
lws_threadpool_destroy(struct lws_threadpool *tp);

/**
 * lws_threadpool_enqueue() - Queue the task and run it on a worker thread when possible
 *
 * \param tp: the threadpool to queue / run on
 * \param args: information about what to run
 * \param format: printf-type format for the task name
 * \param ...: printf type args for the task name format
 *
 * This asks for a task to run ASAP on a worker thread in threadpool \p tp.
 *
 * The args defines the wsi, a user-private pointer, a timeout in secs and
 * a pointer to the task function.
 *
 * Returns NULL or an opaque pointer to the queued (or running, or completed)
 * task.
 *
 * Once a task is created and enqueued, it can only be destroyed by calling
 * lws_threadpool_task_status() on it after it has reached the state
 * LWS_TP_STATUS_FINISHED or LWS_TP_STATUS_STOPPED.
 */
LWS_VISIBLE LWS_EXTERN struct lws_threadpool_task *
lws_threadpool_enqueue(struct lws_threadpool *tp,
		       const struct lws_threadpool_task_args *args,
		       const char *format, ...) LWS_FORMAT(3);

/**
 * lws_threadpool_dequeue() - Dequeue or try to stop a running task
 *
 * \param wsi: the wsi whose current task we want to eliminate
 *
 * Returns 0 is the task was dequeued or already compeleted, or 1 if the task
 * has been asked to stop asynchronously.
 *
 * This doesn't free the task.  It only shortcuts it to state
 * LWS_TP_STATUS_STOPPED.  lws_threadpool_task_status() must be performed on
 * the task separately once it is in LWS_TP_STATUS_STOPPED to free the task.
 *
 * DEPRECATED: You should use lws_threadpool_dequeue_task() with
 * lws_threadpool_get_task_wsi() / _ss() if you know there can only be one task
 * per connection, or call it via lws_threadpool_foreach_task_wsi() / _ss() to
 * get the tasks bound to the connection.
 */
LWS_VISIBLE LWS_EXTERN int
lws_threadpool_dequeue(struct lws *wsi) LWS_WARN_DEPRECATED;

LWS_VISIBLE LWS_EXTERN int
lws_threadpool_dequeue_task(struct lws_threadpool_task *task);


/**
 * lws_threadpool_task_status() - reap completed tasks
 *
 * \param wsi: the wsi to query the current task of
 * \param task: receives a pointer to the opaque task
 * \param user: receives a void * pointer to the task user data
 *
 * This is the equivalent of posix waitpid()... it returns the status of the
 * task, and if the task is in state LWS_TP_STATUS_FINISHED or
 * LWS_TP_STATUS_STOPPED, frees \p task.  If in another state, the task
 * continues to exist.
 *
 * This is designed to be called from the service thread.
 *
 * Its use is to make sure the service thread has seen the state of the task
 * before deleting it.
 *
 * DEPRECATED... use lws_threadpool_task_status() instead and get the task
 * pointer from lws_threadpool_get_task_wsi() / _ss() if you know there can only
 * be one, else call it via lws_threadpool_foreach_task_wsi() / _ss()
 */
LWS_VISIBLE LWS_EXTERN enum lws_threadpool_task_status
lws_threadpool_task_status_wsi(struct lws *wsi,
			       struct lws_threadpool_task **task, void **user)
				LWS_WARN_DEPRECATED;

LWS_VISIBLE LWS_EXTERN enum lws_threadpool_task_status
lws_threadpool_task_status(struct lws_threadpool_task *task, void **user);

LWS_VISIBLE LWS_EXTERN enum lws_threadpool_task_status
lws_threadpool_task_status_noreap(struct lws_threadpool_task *task);

/**
 * lws_threadpool_task_sync() - Indicate to a stalled task it may continue
 *
 * \param task: the task to unblock
 * \param stop: 0 = run after unblock, 1 = when he unblocks, stop him
 *
 * Inform the task that the service thread has finished with the shared data
 * and that the task, if blocked in LWS_TP_RETURN_SYNC, may continue.
 *
 * If the lws service context determined that the task must be aborted, it
 * should still call this but with stop = 1, causing the task to finish.
 */
LWS_VISIBLE LWS_EXTERN void
lws_threadpool_task_sync(struct lws_threadpool_task *task, int stop);

/**
 * lws_threadpool_dump() - dump the state of a threadpool to the log
 *
 * \param tp: The threadpool to dump
 *
 * This locks the threadpool and then dumps the pending queue, the worker
 * threads and the done queue, together with time information for how long
 * the tasks have been in their current state, how long they have occupied a
 * thread, etc.
 *
 * This only does anything on lws builds with CMAKE_BUILD_TYPE=DEBUG, otherwise
 * while it still exists, it's a NOP.
 */

LWS_VISIBLE LWS_EXTERN void
lws_threadpool_dump(struct lws_threadpool *tp);



LWS_VISIBLE LWS_EXTERN struct lws_threadpool_task *
lws_threadpool_get_task_wsi(struct lws *wsi);

#if defined(LWS_WITH_SECURE_STREAMS)
LWS_VISIBLE LWS_EXTERN struct lws_threadpool_task *
lws_threadpool_get_task_ss(struct lws_ss_handle *ss);
#endif


LWS_VISIBLE LWS_EXTERN int
lws_threadpool_foreach_task_wsi(struct lws *wsi, void *user,
				int (*cb)(struct lws_threadpool_task *task,
					  void *user));

#if defined(LWS_WITH_SECURE_STREAMS)
LWS_VISIBLE LWS_EXTERN int
lws_threadpool_foreach_task_ss(struct lws_ss_handle *ss, void *user,
		int (*cb)(struct lws_threadpool_task *task, void *user));
#endif


//@}
