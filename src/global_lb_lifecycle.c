/* UD-006/007/008/010/011 v2-r3-20261003. Copyright 2026 nTels.
 * LGPL-2.1 exclusively. Production lifecycle on the existing worker thread-0
 * RESP2 task/connection. No periodic count sync, OS thread or traffic lock
 * around allocation, string copying, encoding, network I/O or Lua execution.
 */
#ifdef USE_GLOBAL_LB
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_dispatch.h>
#include <haproxy/global_lb_lifecycle.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/global_lb_reserve.h>
#include <haproxy/init.h>
#include <haproxy/log.h>
#include <haproxy/ticks.h>

#define GLB_CAPTURE_BATCH 32
static struct {
	struct global_lb_reserve_limits limits;
	struct global_lb_reserve_entry *rows;
	size_t count, capacity, key_bytes;
	uint64_t revision, changes, water;
	unsigned int phase, control, started, terminal, blocked;
	unsigned int next_hb, retry;
	const char *reason;
} runtime;
static HA_SPINLOCK_T control_lock;
/* UD-012 v2-r4-20261004: never expose runtime.rows or client/ledger views.
 * Only thread 0 writes observed; CLI takes a fixed-size copy under this lock.
 * No diagnostic lock is nested beneath traffic metadata/control locks. */
static HA_SPINLOCK_T status_lock;
static struct global_lb_lifecycle_status observed, published;
static void publish_status(void)
{
	struct glb_ledger *l = global_lb_dispatch_lock();
	observed.active = l->active;
	global_lb_dispatch_unlock();
	observed.phase = runtime.phase; observed.control = runtime.control;
	observed.started = runtime.started; observed.blocked = runtime.blocked;
	observed.revision = runtime.revision;
	snprintf(observed.reason, sizeof(observed.reason), "%s", runtime.reason ? runtime.reason : "startup");
	HA_SPIN_LOCK(OTHER_LOCK, &status_lock); published = observed; HA_SPIN_UNLOCK(OTHER_LOCK, &status_lock);
}
void global_lb_lifecycle_get_status(struct global_lb_lifecycle_status *s)
{
	HA_SPIN_LOCK(OTHER_LOCK, &status_lock); *s = published; HA_SPIN_UNLOCK(OTHER_LOCK, &status_lock);
}

static void note(const char *reason)
{
	/* Transition-only: repeated transport/limit failures do not flood logs. */
	if (!runtime.reason || strcmp(runtime.reason, reason)) {
		if (strstr(reason, "limit")) ha_warning("global-lb v2: %s.\n", reason);
		else ha_notice("global-lb v2: %s.\n", reason);
		send_log(NULL, strstr(reason, "limit") ? LOG_ERR : LOG_NOTICE, "global-lb v2: %s.\n", reason);
	}
	runtime.reason = reason;
}
static void discard(void)
{
	while (runtime.count) free((void *)runtime.rows[--runtime.count].endpoint_key);
	runtime.phase = 0; runtime.key_bytes = 0;
}
static void fallback(const char *reason)
{
	struct glb_ledger *l = global_lb_dispatch_lock();
	glb_ledger_invalidate(l);
	l->cursor = NULL;
	global_lb_dispatch_unlock();
	discard(); note(reason);
	runtime.retry = tick_add(now_ms, global_lb_cfg.reconnect_initial);
	global_lb_client_schedule(global_lb_cfg.reconnect_initial);
}
int global_lb_lifecycle_init(void)
{
	HA_SPIN_INIT(&control_lock);
	HA_SPIN_INIT(&status_lock);
	observed.initialized = 1;
	publish_status();
	runtime.limits = (struct global_lb_reserve_limits){global_lb_cfg.max_instances,
		global_lb_cfg.max_instances * GLB_PUBLISH_MAX_ENDPOINTS, global_lb_cfg.max_requests};
	/* Local metadata also retains uncertain/detached cleanup records. This is
	 * NOT the group active request limit or the unique endpoint limit. */
	return global_lb_dispatch_configure(&runtime.limits, GLB_PUBLISH_WIRE_SIZE,
		(size_t)global_lb_cfg.max_requests * 2);
}
int global_lb_lifecycle_submit(unsigned char **wire, size_t len,
		unsigned int deadline, int terminal_command)
{
	int ok;
	HA_SPIN_LOCK(OTHER_LOCK, &control_lock);
	ok = (!_HA_ATOMIC_LOAD(&runtime.terminal) || terminal_command) &&
		global_lb_client_submit_deadline(wire, len, deadline);
	HA_SPIN_UNLOCK(OTHER_LOCK, &control_lock);
	return ok;
}
void global_lb_lifecycle_shutdown(void)
{
	struct glb_ledger *l;
	/* May run on a CLI/traffic thread. Only this scalar and serial ledger are
	 * touched here; the thread-0 client consumes/frees its own control state. */
	HA_SPIN_LOCK(OTHER_LOCK, &control_lock);
	_HA_ATOMIC_STORE(&runtime.terminal, 1);
	l = global_lb_dispatch_lock(); l->terminal = 1; glb_ledger_invalidate(l); global_lb_dispatch_unlock();
	/* Anchor 100ms before frontend suspension, not after it. */
	global_lb_client_shutdown();
	HA_SPIN_UNLOCK(OTHER_LOCK, &control_lock);
}

static int send_control(enum global_lb_reserve_op op)
{
	struct global_lb_reserve_command c = { 0 };
	unsigned char *wire = NULL;
	size_t len;
	c.op = op; c.prefix = global_lb_cfg.key_prefix; c.instance_id = global_lb_cfg.instance_id;
	c.writer_generation = global_lb_client_writer()->writer_generation;
	c.revision = runtime.revision ? runtime.revision : 1;
	c.instance_timeout = global_lb_cfg.instance_timeout;
	c.tie_seed = 1; c.limits = runtime.limits;
	if (op == GLB_RESERVE_START || op == GLB_RESERVE_RESTORE) {
		c.high_water = runtime.water;
		c.entries = runtime.rows; c.entry_count = runtime.count;
	}
	if (global_lb_reserve_encode(&c, GLB_PUBLISH_WIRE_SIZE, &wire, &len) != GLB_RESP_OK ||
	    !global_lb_lifecycle_submit(&wire, len, tick_add(now_ms, global_lb_cfg.command_timeout),
				       op == GLB_RESERVE_STOP)) { free(wire); return 0; }
	runtime.control = op + 1;
	if (op == GLB_RESERVE_START) observed.starts++;
	else if (op == GLB_RESERVE_RESTORE) observed.restores++;
	else if (op == GLB_RESERVE_HEARTBEAT) observed.heartbeats++;
	/* Ambiguous START is never retried and reconnect never generates a UUID. */
	if (op == GLB_RESERVE_START) runtime.started = 1;
	return 1;
}
static int copy_row(uint64_t id, const char *key)
{
	struct global_lb_reserve_entry *rows;
	size_t capacity;
	char *copy;
	/* Reserve room for script/envelope; encoding performs the exact check. */
	if (runtime.count >= global_lb_cfg.max_requests || strlen(key) + 64 >
	    GLB_PUBLISH_WIRE_SIZE - 65536 - runtime.key_bytes) return 0;
	if (runtime.count == runtime.capacity) {
		capacity = runtime.capacity ? runtime.capacity * 2 : 128;
		if (capacity > global_lb_cfg.max_requests) capacity = global_lb_cfg.max_requests;
		/* Even configured large connection counts cannot grow beyond wire cap. */
		if (capacity > GLB_PUBLISH_WIRE_SIZE / sizeof(*rows)) return 0;
		rows = realloc(runtime.rows, capacity * sizeof(*rows));
		if (!rows) return 0;
		runtime.rows = rows; runtime.capacity = capacity;
	}
	copy = strdup(key);
	if (!copy) return 0;
	runtime.key_bytes += strlen(key) + 64;
	runtime.rows[runtime.count++] = (struct global_lb_reserve_entry){id, copy};
	return 1;
}
static void advance(void)
{
	struct glb_ledger *l;
	struct glb_entry *e;
	unsigned int i;
	int active, native, ok, done;
	uint64_t id;
	if (global_lb_client_state() != GLB_CLIENT_READY || runtime.control || runtime.blocked) return;
	if (_HA_ATOMIC_LOAD(&runtime.terminal)) {
		discard();
		if (!runtime.started || !send_control(GLB_RESERVE_STOP))
			global_lb_publish_shutdown_finish("not-submitted");
		return;
	}
	l = global_lb_dispatch_lock(); active = l->active; global_lb_dispatch_unlock();
	if (active) {
		if (tick_is_expired(runtime.next_hb, now_ms)) {
			if (!send_control(GLB_RESERVE_HEARTBEAT)) fallback("heartbeat-not-submitted; local leastconn");
		}
		else {
			global_lb_client_schedule(tick_remain(now_ms, runtime.next_hb));
			global_lb_dispatch_pump();
		}
		return;
	}
	if (!runtime.phase) {
		if (tick_isset(runtime.retry) && !tick_is_expired(runtime.retry, now_ms)) {
			global_lb_client_schedule(tick_remain(now_ms, runtime.retry)); return;
		}
		l = global_lb_dispatch_lock();
		ok = glb_ledger_walk_begin(l, &runtime.changes, &runtime.water);
		global_lb_dispatch_unlock();
		if (!ok || runtime.revision == UINT64_MAX) { fallback("incomplete local ledger; local leastconn"); return; }
		runtime.revision++; runtime.phase = 1;
	}
	if (runtime.phase == 1) {
		for (i = 0; i < GLB_CAPTURE_BATCH; i++) {
			l = global_lb_dispatch_lock();
			e = glb_ledger_walk_pin(l);
			native = e && e->native; id = e ? e->id : 0;
			global_lb_dispatch_unlock();
			if (!e) break;
			ok = !native || copy_row(id, e->endpoint);
			global_lb_dispatch_lock(); glb_ledger_unpin(e); global_lb_dispatch_unlock();
			if (!ok) { fallback("restore local request/wire/allocation limit; local leastconn"); return; }
		}
		l = global_lb_dispatch_lock();
		ok = !l->untracked && l->changes == runtime.changes;
		done = !l->cursor;
		global_lb_dispatch_unlock();
		if (!ok) { observed.barriers++; discard(); runtime.retry = now_ms; global_lb_client_kick(); return; }
		if (!done) { global_lb_client_kick(); return; }
		if (!send_control(runtime.started ? GLB_RESERVE_RESTORE : GLB_RESERVE_START))
			fallback("restore wire/allocation/submit limit; local leastconn");
		return;
	}
	/* Confirmed snapshot, but traffic stays local until every entry's new
	 * revision is installed and the final short-lock mutation barrier agrees. */
	l = global_lb_dispatch_lock();
	ok = !l->untracked && l->changes == runtime.changes;
	done = ok && glb_ledger_settle(l, runtime.revision, GLB_CAPTURE_BATCH);
	if (done) ok = glb_ledger_commit(l, global_lb_client_writer()->writer_generation,
		runtime.revision, runtime.changes);
	global_lb_dispatch_unlock();
	if (!ok) { observed.barriers++; discard(); runtime.retry = now_ms; global_lb_client_kick(); return; }
	if (!done) { global_lb_client_kick(); return; }
	discard(); runtime.next_hb = tick_add(now_ms, global_lb_cfg.heartbeat_interval);
	observed.activations++; observed.have_restore = 1; observed.last_restore = now_ms;
	note("ACTIVE after confirmed atomic restore");
	global_lb_client_schedule(global_lb_cfg.heartbeat_interval);
	global_lb_client_kick();
}
static void lifecycle_event(enum global_lb_client_event event,
		enum global_lb_client_error error, const struct global_lb_resp_parser *parser, void *context)
{
	struct global_lb_reserve_reply r;
	struct glb_ledger *l;
	uint64_t changes, water;
	unsigned int control = runtime.control;
	int result = event == GLB_CLIENT_REPLY && global_lb_reserve_result(parser, &r);
	int owned = global_lb_dispatch_event(event, parser);
	(void)context;
	if (event == GLB_CLIENT_FAILED) {
		observed.failures++; observed.last_error = error;
		if (error == GLB_CLIENT_COMMAND_TIMEOUT) observed.command_timeouts++;
	}
	if (event == GLB_CLIENT_REPLY && !owned && control) {
		observed.have_result = result;
		if (result) observed.last_result = r.status;
	}
	if (_HA_ATOMIC_LOAD(&runtime.terminal)) {
		if (event == GLB_CLIENT_FAILED) {
			global_lb_publish_shutdown_finish(error == GLB_CLIENT_COMMAND_TIMEOUT ? "timeout" : "transport-error"); return;
		}
		if (event == GLB_CLIENT_REPLY && !owned) {
			runtime.control = 0;
			if (control == GLB_RESERVE_STOP + 1) {
				global_lb_publish_shutdown_finish(result &&
					(r.status == GLB_RESERVE_OK || r.status == GLB_RESERVE_ABSENT) ? "excluded" : "rejected"); return;
			}
		}
		if (global_lb_client_state() != GLB_CLIENT_READY && global_lb_client_state() != GLB_CLIENT_COMMAND) {
			global_lb_publish_shutdown_finish("unavailable"); return;
		}
		/* STOP checks UUID, not revision; other owners are never deleted. */
		runtime.blocked = 0; advance(); return;
	}
	if (event == GLB_CLIENT_FAILED) {
		runtime.control = 0; fallback("transport failure; local leastconn"); return;
	}
	if (event == GLB_CLIENT_CONNECTED) {
		runtime.control = 0; discard(); runtime.retry = now_ms;
	}
	if (event == GLB_CLIENT_REPLY) {
		if (owned && (!result || r.status < 0)) {
			fallback(result && r.status == GLB_RESERVE_LIMIT ? "store resource limit; local leastconn" : "reservation rejected; local leastconn");
			global_lb_client_request_reconnect(GLB_CLIENT_RESOURCE_LIMIT);
		}
		if (!owned && control) {
			runtime.control = 0;
			if (!result || r.endpoint_len || r.count ||
			    (r.status != GLB_RESERVE_OK && r.status != GLB_RESERVE_DUPLICATE)) {
				fallback(result && r.status == GLB_RESERVE_LIMIT ? "store resource limit; local leastconn" : "control rejected; local leastconn");
				if (result && (r.status == GLB_RESERVE_OTHER_WRITER || r.status == GLB_RESERVE_TERMINAL)) {
					runtime.blocked = 1; note("owner/terminal fenced; restart or operator recovery required");
				}
				global_lb_client_request_reconnect(GLB_CLIENT_RESOURCE_LIMIT); return;
			}
			if (control == GLB_RESERVE_START + 1 || control == GLB_RESERVE_RESTORE + 1) {
				l = global_lb_dispatch_lock();
				result = glb_ledger_walk_begin(l, &changes, &water) && changes == runtime.changes;
				global_lb_dispatch_unlock();
				if (result) runtime.phase = 2;
				else { observed.barriers++; discard(); runtime.retry = now_ms; }
			}
			else {
				observed.have_hb = 1; observed.last_hb = now_ms;
				runtime.next_hb = tick_add(now_ms, global_lb_cfg.heartbeat_interval);
			}
		}
	}
	advance();
}
void global_lb_lifecycle_event(enum global_lb_client_event event,
		enum global_lb_client_error error, const struct global_lb_resp_parser *parser, void *context)
{
	lifecycle_event(event, error, parser, context);
	publish_status();
}
static void lifecycle_free(void) { discard(); free(runtime.rows); }
REGISTER_POST_DEINIT(lifecycle_free);
#endif
