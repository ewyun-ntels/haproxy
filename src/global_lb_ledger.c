/* UD-005/006/007/010/011 v2-r2-20261003. Copyright 2026 nTels.
 * LGPL-2.1 exclusively. Serial reservation metadata, not a served counter. */
#ifdef USE_GLOBAL_LB
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_ledger.h>
#include <haproxy/global_lb_store.h>

static char *copy_string(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);
	if (p) memcpy(p, s, n);
	return p;
}
static void enqueue(struct glb_ledger *l, struct glb_entry *e)
{
	if (e->queued || l->inflight == e) return;
	e->queued_op = e->state == GLB_WAIT ? GLB_RESERVE_TAKE :
	               e->remote ? GLB_RESERVE_RELEASE : GLB_RESERVE_CANCEL;
	l->stats.queued[e->queued_op - GLB_RESERVE_TAKE]++;
	e->queued = 1; e->qnext = NULL; e->qprev = l->tail;
	if (l->tail) l->tail->qnext = e;
	else l->head = e;
	l->tail = e;
}
static void unqueue(struct glb_ledger *l, struct glb_entry *e)
{
	if (!e->queued) return;
	l->stats.queued[e->queued_op - GLB_RESERVE_TAKE]--;
	if (e->qprev) e->qprev->qnext = e->qnext;
	else l->head = e->qnext;
	if (e->qnext) e->qnext->qprev = e->qprev;
	else l->tail = e->qprev;
	e->queued = 0; e->qnext = e->qprev = NULL;
}
static void dispose(struct glb_ledger *l, struct glb_entry *e)
{
	unqueue(l, e);
	if (l->cursor == e) l->cursor = e->next;
	if (e->prev) e->prev->next = e->next;
	else l->entries = e->next;
	if (e->next) e->next->prev = e->prev;
	l->count--; e->removed = 1;
	l->stats.states[e->state]--;
	if (!e->pins) glb_ledger_free_prepared(e);
}
void glb_ledger_free_prepared(struct glb_entry *e)
{
	size_t i;
	if (!e) return;
	for (i = 0; i < e->candidate_count; i++) free(e->candidates[i]);
	free(e->candidates); free(e->endpoint); free(e->service); free(e);
}
static void notify(struct glb_ledger *l, struct glb_entry *e)
{
	if (e->owner && l->wake) l->wake(e->owner);
}
/* UD-012 v2-r4-20261004: maintain metadata tallies at existing transitions
 * so CLI reads do not scan/pin the ledger or interfere with restore cursors. */
static void set_state(struct glb_ledger *l, struct glb_entry *e, enum glb_entry_state state)
{
	l->stats.states[e->state]--;
	e->state = state;
	l->stats.states[state]++;
}
void glb_ledger_get_status(const struct glb_ledger *l, struct glb_ledger_status *s)
{
	*s = (struct glb_ledger_status){ .stats = l->stats, .count = l->count,
		.max_entries = l->max_entries, .revision = l->revision, .changes = l->changes,
		.next_id = l->next_id, .active = l->active, .dirty = l->dirty,
		.untracked = l->untracked, .terminal = l->terminal,
		.inflight = !!l->inflight, .inflight_op = l->inflight_op };
}
static struct glb_entry *allocate(struct glb_ledger *l, void *owner)
{
	struct glb_entry *e;
	if (l->count >= l->max_entries || l->next_id == UINT64_MAX) return NULL;
	e = calloc(1, sizeof(*e));
	if (!e) return NULL;
	e->id = ++l->next_id; e->owner = owner; e->revision = l->revision;
	e->next = l->entries;
	if (l->entries) l->entries->prev = e;
	l->entries = e; l->count++;
	l->stats.states[e->state]++;
	return e;
}
void glb_ledger_init(struct glb_ledger *l, size_t max, void (*wake)(void *))
{
	memset(l, 0, sizeof(*l)); l->max_entries = max; l->wake = wake;
}
void glb_ledger_destroy(struct glb_ledger *l)
{
	l->inflight = NULL;
	while (l->entries) dispose(l, l->entries);
	memset(l, 0, sizeof(*l));
}
struct glb_entry *glb_ledger_request(struct glb_ledger *l, void *owner,
		const char *service, const char * const *keys, size_t n,
		unsigned int deadline, unsigned int seed)
{
	struct glb_entry *e = glb_ledger_prepare(owner, service, keys, n, deadline, seed);
	if (e && !glb_ledger_admit(l, e)) { glb_ledger_free_prepared(e); e = NULL; }
	return e;
}
int glb_ledger_admit(struct glb_ledger *l, struct glb_entry *e)
{
	if (l->terminal || !l->active || !e || l->count >= l->max_entries || l->next_id == UINT64_MAX) return 0;
	e->id = ++l->next_id; e->revision = l->revision;
	e->next = l->entries;
	if (l->entries) l->entries->prev = e;
	l->entries = e; l->count++;
	l->stats.states[e->state]++; l->stats.admitted++;
	enqueue(l, e);
	return 1;
}
struct glb_entry *glb_ledger_prepare(void *owner, const char *service,
		const char * const *keys, size_t n, unsigned int deadline, unsigned int seed)
{
	struct glb_entry *e;
	size_t i;
	if (!owner || !service || !*service || !n || !keys ||
	    n > SIZE_MAX / sizeof(*keys)) return NULL;
	e = calloc(1, sizeof(*e));
	if (!e) return NULL;
	e->owner = owner;
	e->service = copy_string(service);
	e->candidates = calloc(n, sizeof(*keys));
	if (!e->service || !e->candidates) goto fail;
	for (i = 0; i < n; i++) {
		if (!keys[i] || !*keys[i]) goto fail;
		e->candidates[i] = copy_string(keys[i]);
		if (!e->candidates[i]) goto fail;
		e->candidate_count++;
	}
	e->deadline = deadline; e->seed = seed; e->state = GLB_WAIT;
	return e;
fail:
	glb_ledger_free_prepared(e);
	return NULL;
}
void glb_ledger_expire(struct glb_ledger *l, struct glb_entry *e)
{
	if (e->state != GLB_WAIT && e->state != GLB_READY) return;
	if (e->sent) l->stats.abandoned_sent++;
	else l->stats.abandoned_unsent++;
	set_state(l, e, GLB_FAILED);
	unqueue(l, e);
	/* A sent reservation is uncertain even before any response arrives. */
	if (e->sent && l->inflight != e) enqueue(l, e);
	notify(l, e);
}
void glb_ledger_drop(struct glb_ledger *l, struct glb_entry *e)
{
	if (!e) return;
	/* Clear callback ownership before stream/task destruction. */
	e->owner = NULL;
	if (e->native) { e->native = 0; l->changes++; }
	set_state(l, e, GLB_CLEANUP);
	if (l->inflight == e) return;
	if (e->sent || e->remote) enqueue(l, e);
	else dispose(l, e);
}
struct glb_entry *glb_ledger_native(struct glb_ledger *l, struct glb_entry *e,
		void *owner, const char *key)
{
	if (!owner || !key || !*key) {
		glb_ledger_drop(l, e); l->untracked++; glb_ledger_invalidate(l); return NULL;
	}
	if (e && e->state == GLB_READY && e->endpoint && !strcmp(e->endpoint, key)) {
		e->native = 1; set_state(l, e, GLB_NATIVE); l->changes++;
		return e;
	}
	glb_ledger_drop(l, e);
	e = allocate(l, owner);
	if (!e) { l->untracked++; glb_ledger_invalidate(l); return NULL; }
	e->endpoint = copy_string(key);
	if (!e->endpoint) {
		dispose(l, e); l->untracked++; glb_ledger_invalidate(l); return NULL;
	}
	set_state(l, e, GLB_NATIVE); e->native = 1; l->changes++;
	/* Local fallback is not in the store: no HB/Global admission until restore. */
	glb_ledger_invalidate(l);
	return e;
}
void glb_ledger_invalidate(struct glb_ledger *l)
{
	struct glb_entry *e;
	if (!l->active && l->dirty) return;
	l->active = 0; l->dirty = 1;
	for (e = l->entries; e; e = e->next) {
		if (e->state == GLB_WAIT || e->state == GLB_READY) {
			glb_ledger_expire(l, e);
		}
	}
}
struct glb_entry *glb_ledger_next(struct glb_ledger *l, enum global_lb_reserve_op *op)
{
	struct glb_entry *e;
	if (l->inflight || !l->head) return NULL;
	/* Dirty state forbids admissions/HB, but known idempotent cleanup may
	 * still run on the current healthy connection before a restore barrier. */
	if (!l->active && l->head->state == GLB_WAIT) return NULL;
	e = l->head;
	unqueue(l, e);
	*op = e->state == GLB_WAIT ? GLB_RESERVE_TAKE :
	      e->remote ? GLB_RESERVE_RELEASE : GLB_RESERVE_CANCEL;
	l->inflight_op = *op;
	l->inflight = e; e->sent = 1;
	return e;
}
void glb_ledger_complete(struct glb_ledger *l, const struct global_lb_reserve_reply *r)
{
	struct glb_entry *e = l->inflight;
	size_t i;
	int valid = 0;
	if (!e) return;
	l->inflight = NULL;
	if (!r || r->status < 0) {
		l->stats.failures++;
		glb_ledger_invalidate(l);
		return;
	}
	if (e->state == GLB_WAIT) {
		if ((r->status == GLB_RESERVE_OK || r->status == GLB_RESERVE_DUPLICATE) && r->count) {
			for (i = 0; i < e->candidate_count; i++) {
				if (strlen(e->candidates[i]) == r->endpoint_len &&
				    !memcmp(e->candidates[i], r->endpoint, r->endpoint_len)) {
					e->endpoint = copy_string(e->candidates[i]); valid = !!e->endpoint; break;
				}
			}
		}
		if (valid) { e->remote = 1; set_state(l, e, GLB_READY); l->stats.confirmed++; notify(l, e); }
		else {
			/* Impossible shape/unknown endpoint is ambiguous, not a clean reject. */
			if (r->status != GLB_RESERVE_STALE) glb_ledger_invalidate(l);
			glb_ledger_expire(l, e);
		}
	}
	else if (l->inflight_op != GLB_RESERVE_TAKE && !r->count &&
	         (!r->endpoint_len || !e->endpoint ||
	          (r->endpoint_len == strlen(e->endpoint) && !memcmp(r->endpoint, e->endpoint, r->endpoint_len))) &&
	         (r->status == GLB_RESERVE_RELEASED || r->status == GLB_RESERVE_CANCELLED ||
	          r->status == GLB_RESERVE_ABSENT || r->status == GLB_RESERVE_STALE)) {
		if (l->inflight_op == GLB_RESERVE_RELEASE) l->stats.released++;
		else l->stats.cancelled++;
		e->sent = e->remote = 0;
		if (!e->owner) dispose(l, e);
	}
	else {
		/* Late TAKE reply for an expired/detached owner: cancel by request ID. */
		if (l->inflight_op == GLB_RESERVE_TAKE) enqueue(l, e);
		else glb_ledger_invalidate(l);
	}
}
int glb_ledger_capture(struct glb_ledger *l, struct global_lb_reserve_entry **out,
		size_t *n, uint64_t *changes, uint64_t *high_water)
{
	struct glb_entry *e;
	size_t count = 0, i = 0;
	struct global_lb_reserve_entry *rows;
	*out = NULL; *n = 0;
	if (l->untracked || l->inflight) return 0;
	for (e = l->entries; e; e = e->next) if (e->native) count++;
	rows = calloc(count ? count : 1, sizeof(*rows));
	if (!rows) return 0;
	for (e = l->entries; e; e = e->next) if (e->native) {
		rows[i].request_id = e->id; rows[i].endpoint_key = copy_string(e->endpoint);
		if (!rows[i].endpoint_key) {
			while (i) free((void *)rows[--i].endpoint_key);
			free(rows); return 0;
		}
		i++;
	}
	*out = rows; *n = count; *changes = l->changes; *high_water = l->next_id;
	return 1;
}
int glb_ledger_activate(struct glb_ledger *l, const char *uuid, uint64_t revision,
		uint64_t changes)
{
	struct glb_entry *e, *next;
	if (l->terminal || !global_lb_store_valid_uuid(uuid) || !revision || revision <= l->revision ||
	    (l->writer[0] && strcmp(l->writer, uuid)) ||
	    l->inflight || l->untracked || changes != l->changes) return 0;
	/* The lifecycle must confirm START/RESTORE on the new revision first. */
	for (e = l->entries; e; e = next) {
		next = e->next;
		if (!e->native) {
			if (!e->owner) dispose(l, e);
			else { e->sent = e->remote = 0; unqueue(l, e); set_state(l, e, GLB_FAILED); notify(l, e); }
		}
		else { e->revision = revision; e->remote = 1; e->sent = 1; }
	}
	memcpy(l->writer, uuid, 37); l->revision = revision;
	l->active = 1; l->dirty = 0;
	return 1;
}

/* UD-006/011 v2-r3-20261003. No whole-ledger allocation/copy under the
 * traffic lock. Native endpoint strings never change during entry lifetime. */
int glb_ledger_walk_begin(struct glb_ledger *l, uint64_t *changes, uint64_t *water)
{
	if (l->terminal || l->active || l->untracked || l->inflight) return 0;
	l->cursor = l->entries; *changes = l->changes; *water = l->next_id;
	return 1;
}
struct glb_entry *glb_ledger_walk_pin(struct glb_ledger *l)
{
	struct glb_entry *e = l->cursor;
	if (e) { l->cursor = e->next; e->pins++; }
	return e;
}
void glb_ledger_unpin(struct glb_entry *e)
{
	if (!e || !e->pins) return;
	if (!--e->pins && e->removed) glb_ledger_free_prepared(e);
}
int glb_ledger_settle(struct glb_ledger *l, uint64_t revision, size_t budget)
{
	struct glb_entry *e;
	while (budget-- && (e = l->cursor)) {
		l->cursor = e->next;
		if (e->native) { e->revision = revision; e->remote = e->sent = 1; }
		else if (!e->owner) dispose(l, e);
		else { e->sent = e->remote = 0; unqueue(l, e); set_state(l, e, GLB_FAILED); notify(l, e); }
	}
	return !l->cursor;
}
int glb_ledger_commit(struct glb_ledger *l, const char *uuid, uint64_t revision,
		uint64_t changes)
{
	if (l->terminal || l->active || l->cursor || l->inflight || l->untracked || changes != l->changes ||
	    !global_lb_store_valid_uuid(uuid) || !revision || revision <= l->revision ||
	    (l->writer[0] && strcmp(l->writer, uuid))) return 0;
	memcpy(l->writer, uuid, 37); l->revision = revision; l->active = 1; l->dirty = 0;
	return 1;
}
#endif
