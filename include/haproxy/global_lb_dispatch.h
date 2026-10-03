/* UD-005/007/009/010/011 v2-r2-20261003. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_DISPATCH_H
#define _HAPROXY_GLOBAL_LB_DISPATCH_H
#ifdef USE_GLOBAL_LB
#include <haproxy/global_lb_client-t.h>
#include <haproxy/global_lb_ledger.h>
/* Internal adapter access, NEVER a CLI borrowed view. Hold this short lock
 * only for registry metadata mutations; no I/O/encoding/LB locks beneath it. */
struct glb_ledger *global_lb_dispatch_lock(void);
void global_lb_dispatch_unlock(void);
/* Step 3 calls configure and owns the client callback. Numeric budgets must
 * come from lifecycle policy, not an arbitrary connection limit in step 2. */
int global_lb_dispatch_configure(const struct global_lb_reserve_limits *,
		size_t wire_limit, size_t ledger_limit);
/* Thread 0 only. Route REPLY/FAILED here before handling control commands.
 * Returns 1 iff a dispatcher command owned that transport completion. */
int global_lb_dispatch_event(enum global_lb_client_event,
		const struct global_lb_resp_parser *);
/* At most one command, only READY. Returns 1 iff a command was submitted.
 * Lifecycle services due HB/restore/control before calling pump. */
int global_lb_dispatch_pump(void);
#endif
#endif
