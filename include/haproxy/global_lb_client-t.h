/* Optional Global LB async transport. Copyright 2026 nTels.
 * LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_CLIENT_T_H
#define _HAPROXY_GLOBAL_LB_CLIENT_T_H
#ifdef USE_GLOBAL_LB
#include <stddef.h>
#include <haproxy/global_lb_resp-t.h>

/* UD-007 r6-async-client-20260904 / UD-011 r4-worker-identity-20260904. */
enum global_lb_client_state {
	GLB_CLIENT_DISABLED, GLB_CLIENT_IDLE, GLB_CLIENT_BACKOFF,
	GLB_CLIENT_CONNECTING, GLB_CLIENT_READY, GLB_CLIENT_COMMAND,
	GLB_CLIENT_STOPPED,
};

enum global_lb_client_event {
	GLB_CLIENT_CONNECTED, GLB_CLIENT_REPLY, GLB_CLIENT_FAILED,
};

enum global_lb_client_error {
	GLB_CLIENT_OK, GLB_CLIENT_SOCKET_ERROR, GLB_CLIENT_CONNECT_TIMEOUT,
	GLB_CLIENT_COMMAND_TIMEOUT, GLB_CLIENT_IO_ERROR, GLB_CLIENT_EOF,
	GLB_CLIENT_PROTOCOL_ERROR,
};

/* Caller-supplied resource budgets, not new production scale defaults. */
struct global_lb_client_limits {
	size_t tx_bytes;
	struct global_lb_resp_limits reply;
	size_t io_bytes;              /* maximum bytes per task invocation */
	unsigned int io_calls;        /* maximum send/recv calls per invocation */
};

/* Callback runs on worker thread 0, never in the fd callback. Reply/parser
 * views are borrowed until it returns. An error RESP reply is still REPLY,
 * not application success. Failure discards the unconfirmed command.
 */
typedef void (*global_lb_client_cb)(enum global_lb_client_event event,
		enum global_lb_client_error error,
		const struct global_lb_resp_parser *reply, void *context);
#endif
#endif
