/* UD-006/007/008/010/011 v2-r3-20261003. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_LIFECYCLE_H
#define _HAPROXY_GLOBAL_LB_LIFECYCLE_H
#ifdef USE_GLOBAL_LB
#include <haproxy/global_lb_client-t.h>
#include <haproxy/global_lb_reserve-t.h>
/* UD-012 v2-r4-20261004. Published by thread 0, copied on any CLI thread.
 * Ages describe confirmed local replies, not an independent store query. */
struct global_lb_lifecycle_status {
	unsigned int initialized, phase, control, started, blocked, active;
	unsigned int last_hb, have_hb, last_restore, have_restore;
	uint64_t revision, starts, restores, heartbeats, activations, barriers;
	uint64_t failures, command_timeouts;
	enum global_lb_client_error last_error;
	int last_result, have_result;
	char reason[96];
};
void global_lb_lifecycle_get_status(struct global_lb_lifecycle_status *);
int global_lb_lifecycle_init(void);
void global_lb_lifecycle_shutdown(void);
/* Thread 0: admission gate serializes submit vs any-thread terminal request.
 * Encoding/I/O and native LB locks must never be held beneath this gate. */
int global_lb_lifecycle_submit(unsigned char **, size_t, unsigned int deadline,
		int terminal_command);
void global_lb_lifecycle_event(enum global_lb_client_event,
		enum global_lb_client_error, const struct global_lb_resp_parser *, void *);
#endif
#endif
