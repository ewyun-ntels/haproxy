/* Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_CLIENT_H
#define _HAPROXY_GLOBAL_LB_CLIENT_H
#include <haproxy/global_lb_client-t.h>
#include <haproxy/global_lb_store-t.h>
#ifdef USE_GLOBAL_LB
#include <sys/socket.h>

/* Transport/writer APIs are restricted to worker thread 0 (shutdown request
 * and copied/scalar diagnostic reads are the explicitly documented exceptions).
 * No hot-path calls, global lock,
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
/* UD-007/010 v2-r2: cap the transport deadline by the admission's original
 * queue+send+reply deadline. Thread 0. Legacy submit retains its semantics. */
int global_lb_client_submit_deadline(unsigned char **wire, size_t len,
		unsigned int absolute_deadline);
/* Any traffic thread may kick the existing task; coalesced, no second task.
 * Caller must have detached dying stream ownership before its task is freed. */
void global_lb_client_kick(void);

/* Terminal stop: cancel timers, close fd, discard command, destroy task.
 * Does not delete a store snapshot or close any traffic connections.
 */
void global_lb_client_stop(void);

/* UD-012 r1-shutdown-20261002. Wake the existing thread-0 task for a terminal
 * shutdown. Drain one in-flight command, then allow one DELETE on the same
 * connection. No reconnect or replay; the entire operation is capped at 100ms.
 */
void global_lb_client_shutdown(void);
enum global_lb_client_state global_lb_client_observed_state(void);
const char *global_lb_client_state_name(enum global_lb_client_state state);
const char *global_lb_client_error_name(enum global_lb_client_error error);

/* One caller timer on the SAME driver task. Nonzero delay, thread 0 only.
 * TIMER is delivered only in READY. No catch-up queue after failures.
 */
void global_lb_client_schedule(unsigned int delay);
/* Nonblocking address provider, called before each connect attempt. Zero
 * means DNS is not ready and uses normal reconnect backoff. */
void global_lb_client_resolver(int (*resolve)(struct sockaddr_storage *));

/* UD-008 r2-global-cache-20260908. Request a clean reconnect after the
 * current callback returns. Intended for application-level hard limits after
 * a complete RESP reply was consumed.
 * The unconfirmed command is never replayed. Returns 1 when accepted.
 */
int global_lb_client_request_reconnect(enum global_lb_client_error error);

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
