/* UD-005/007/010/011 v2-r2-20261003. Copyright 2026 nTels.
 * LGPL-2.1 exclusively. Adapter to the existing thread-0 client task.
 * No new task, OS thread, socket, startup/HB/restore or shutdown policy. */
#ifdef USE_GLOBAL_LB
#include <stdlib.h>
#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_dispatch.h>
#include <haproxy/global_lb_reserve.h>
#include <haproxy/init.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>

static void wake_owner(void *owner)
{
	/* Owner is a task, cleared under the same lock before stream destruction. */
	task_wakeup(owner, TASK_WOKEN_MSG);
}
static struct glb_ledger ledger = { .max_entries = SIZE_MAX, .wake = wake_owner };
static HA_SPINLOCK_T ledger_lock;
static struct global_lb_reserve_limits limits;
static size_t wire_limit;

struct glb_ledger *global_lb_dispatch_lock(void)
{
	HA_SPIN_LOCK(OTHER_LOCK, &ledger_lock);
	return &ledger;
}
void global_lb_dispatch_unlock(void)
{
	HA_SPIN_UNLOCK(OTHER_LOCK, &ledger_lock);
}
int global_lb_dispatch_configure(const struct global_lb_reserve_limits *budget,
		size_t wire, size_t max)
{
	int ok;
	if (tid || master || !budget || !budget->instances || !budget->count_fields ||
	    !budget->requests || !wire || !max) return 0;
	global_lb_dispatch_lock();
	ok = !ledger.active && !ledger.inflight && max >= ledger.count;
	if (ok) { limits = *budget; wire_limit = wire; ledger.max_entries = max; }
	global_lb_dispatch_unlock();
	return ok;
}
int global_lb_dispatch_event(enum global_lb_client_event event,
		const struct global_lb_resp_parser *parser)
{
	struct global_lb_reserve_reply result;
	int owned;
	if (tid || master) return 0;
	global_lb_dispatch_lock();
	owned = !!ledger.inflight;
	if (event == GLB_CLIENT_FAILED) {
		if (owned) glb_ledger_complete(&ledger, NULL);
		else glb_ledger_invalidate(&ledger);
	}
	else if (event == GLB_CLIENT_REPLY && owned)
		glb_ledger_complete(&ledger, global_lb_reserve_result(parser, &result) ? &result : NULL);
	global_lb_dispatch_unlock();
	if (owned) global_lb_client_kick();
	return owned;
}
int global_lb_dispatch_pump(void)
{
	struct global_lb_reserve_command command = { 0 };
	struct glb_entry *entry;
	unsigned char *wire = NULL;
	size_t len = 0;
	unsigned int deadline;
	if (tid || master || !wire_limit || global_lb_client_state() != GLB_CLIENT_READY) return 0;
	global_lb_dispatch_lock();
	entry = ledger.head;
	/* One expired admission per invocation: yield instead of draining a storm. */
	if (entry && entry->state == GLB_WAIT && tick_is_expired(entry->deadline, now_ms)) {
		glb_ledger_expire(&ledger, entry);
		global_lb_dispatch_unlock(); global_lb_client_kick(); return 0;
	}
	entry = glb_ledger_next(&ledger, &command.op);
	if (!entry) { global_lb_dispatch_unlock(); return 0; }
	command.prefix = global_lb_cfg.key_prefix;
	command.instance_id = global_lb_cfg.instance_id;
	command.writer_generation = ledger.writer;
	command.revision = entry->revision; command.request_id = entry->id;
	command.instance_timeout = global_lb_cfg.instance_timeout;
	command.tie_seed = entry->seed ? entry->seed : 1; command.limits = limits;
	if (command.op == GLB_RESERVE_TAKE) {
		command.service_id = entry->service;
		command.candidates = (const char * const *)entry->candidates;
		command.candidate_count = entry->candidate_count;
	}
	deadline = command.op == GLB_RESERVE_TAKE ? entry->deadline :
	           tick_add(now_ms, global_lb_cfg.command_timeout);
	/* In-flight entry/keys/UUID cannot be reclaimed or replaced until completion. */
	global_lb_dispatch_unlock();
	if (global_lb_reserve_encode(&command, wire_limit, &wire, &len) != GLB_RESP_OK ||
	    !global_lb_client_submit_deadline(&wire, len, deadline)) {
		free(wire);
		global_lb_dispatch_lock(); glb_ledger_complete(&ledger, NULL); global_lb_dispatch_unlock();
		return 0;
	}
	return 1;
}
static void dispatch_deinit(void)
{
	/* After all traffic threads stop; client stop discards its borrowed command. */
	glb_ledger_destroy(&ledger);
}
REGISTER_POST_DEINIT(dispatch_deinit);
#endif
