/* UD-006/007/008/010/011 v2-r3-20261003. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_LIFECYCLE_H
#define _HAPROXY_GLOBAL_LB_LIFECYCLE_H
#ifdef USE_GLOBAL_LB
#include <haproxy/global_lb_client-t.h>
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
