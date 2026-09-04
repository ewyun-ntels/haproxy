/* Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_CLIENT_H
#define _HAPROXY_GLOBAL_LB_CLIENT_H
#include <haproxy/global_lb_client-t.h>
#include <haproxy/global_lb_store-t.h>
#ifdef USE_GLOBAL_LB
#include <sys/socket.h>

/* ALL APIs are restricted to worker thread 0. No hot-path calls, global lock,
 * background thread, DNS or blocking I/O. A post-fork init hook creates the
 * writer identity only when global-lb is configured; the step-5 publisher
 * calls start automatically for opted-in Backends.
 * Start once per worker, with an already resolved IPv4/IPv6 TCP address.
 * Timers come from global_lb_cfg; limits are copied. Callback may submit or
 * stop, but must not block. Return 1 on success, 0 without starting on error.
 */
int global_lb_client_start(const struct sockaddr_storage *address,
		const struct global_lb_client_limits *limits,
		global_lb_client_cb callback, void *context);

/* Only READY accepts a command. On success the client owns malloc-ed *wire
 * and sets it NULL; on refusal caller retains ownership. The buffer must
 * contain exactly one encoded RESP2 command. No queue or automatic replay.
 * Timeout includes sending and receiving, and is not renewed by fragments.
 */
int global_lb_client_submit(unsigned char **wire, size_t len);

/* Terminal stop: cancel timers, close fd, discard command, destroy task.
 * Does not delete a store snapshot or close any traffic connections.
 */
void global_lb_client_stop(void);

/* One caller timer on the SAME driver task. Nonzero delay, thread 0 only.
 * TIMER is delivered only in READY. No catch-up queue after failures.
 */
void global_lb_client_schedule(unsigned int delay);
/* Nonblocking address provider, called before each connect attempt. Zero
 * means DNS is not ready and uses normal reconnect backoff. */
void global_lb_client_resolver(int (*resolve)(struct sockaddr_storage *));

enum global_lb_client_state global_lb_client_state(void);
/* Mutable only on thread 0; use store_writer_next for fresh store operations.
 * Reconnect/transport failure never generates UUIDs or resets the sequence.
 */
struct global_lb_store_writer *global_lb_client_writer(void);

/* Pure helpers exported for deterministic backoff/tick-boundary unit tests. */
unsigned int global_lb_client_retry_delay(unsigned int base, unsigned int cap,
					 unsigned int jitter, unsigned int random);
unsigned int global_lb_client_retry_next(unsigned int base, unsigned int cap);
#endif
#endif
