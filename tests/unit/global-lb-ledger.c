/* UD-005/006/007/010/011/016 v2-r2-20261003. Serial core regression. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_ledger.h>
static unsigned int wakes;
static long fail_after = -1;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t n)
{
	if (fail_after == 0) return NULL;
	if (fail_after > 0) fail_after--;
	return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t size)
{
	if (fail_after == 0) return NULL;
	if (fail_after > 0) fail_after--;
	return __real_calloc(n, size);
}
static void wake(void *p) { assert(p); wakes++; }
static const char *uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
static const char *keys[] = { "be|127.0.0.1:5000", "be|127.0.0.2:5000" };
/* UD-012/016 v2-r4-20261004. Scan in tests ONLY; getters are byte-read-only. */
static void check_status(const struct glb_ledger *l)
{
	struct glb_ledger before = *l;
	struct glb_ledger_status s;
	const struct glb_entry *e;
	size_t states[5] = {0}, queued[3] = {0}, n = 0;
	for (e = l->entries; e; e = e->next) { n++; states[e->state]++; }
	for (e = l->head; e; e = e->qnext) {
		enum global_lb_reserve_op op = e->state == GLB_WAIT ? GLB_RESERVE_TAKE :
		                              e->remote ? GLB_RESERVE_RELEASE : GLB_RESERVE_CANCEL;
		queued[op - GLB_RESERVE_TAKE]++;
	}
	glb_ledger_get_status(l, &s);
	assert(!memcmp(&before, l, sizeof(before)));
	assert(s.count == n && s.revision == l->revision && s.next_id == l->next_id);
	assert(s.active == l->active && s.dirty == l->dirty && s.terminal == l->terminal);
	assert(!memcmp(states, s.stats.states, sizeof(states)));
	assert(!memcmp(queued, s.stats.queued, sizeof(queued)));
	assert(s.inflight == !!l->inflight);
}
static void reply(struct glb_ledger *l, int status, const char *key, uint64_t count)
{
	struct global_lb_reserve_reply r = { status, (const unsigned char *)key, strlen(key), count };
	glb_ledger_complete(l, &r);
	check_status(l);
}
static void release(struct glb_ledger *l, struct glb_entry *e)
{
	enum global_lb_reserve_op op;
	glb_ledger_drop(l, e);
	check_status(l);
	assert(glb_ledger_next(l, &op) == e && op == GLB_RESERVE_RELEASE);
	reply(l, GLB_RESERVE_RELEASED, "", 0);
}
static struct glb_entry *request(struct glb_ledger *l, void *owner,
		const char *service, const char * const *candidates, size_t n,
		unsigned int deadline, unsigned int seed)
{
	struct glb_entry *e = glb_ledger_prepare(owner, service, candidates, n, deadline, seed);
	if (e && !glb_ledger_admit(l, e)) { glb_ledger_free_prepared(e); return NULL; }
	return e;
}
static size_t capture(struct glb_ledger *l, uint64_t *changes, uint64_t *high)
{
	struct glb_entry *e;
	size_t n = 0;
	assert(glb_ledger_walk_begin(l, changes, high));
	while ((e = glb_ledger_walk_pin(l))) {
		if (e->native) { assert(e->id && e->endpoint); n++; }
		glb_ledger_unpin(e);
	}
	return n;
}
static void capture_activate(struct glb_ledger *l, uint64_t revision, size_t expected)
{
	uint64_t changes, high;
	check_status(l);
	assert(capture(l, &changes, &high) == expected && high == l->next_id);
	assert(glb_ledger_walk_begin(l, &changes, &high));
	while (!glb_ledger_settle(l, revision, 32)) {}
	assert(glb_ledger_commit(l, uuid, revision, changes));
	check_status(l);
}
int main(void)
{
	struct glb_ledger l;
	struct glb_entry *a, *b, *c;
	enum global_lb_reserve_op op;
	unsigned int before;
	size_t n;
	uint64_t changes, high;
	long fail;
	glb_ledger_init(&l, 1000, wake);
	assert(!request(&l, &l, "be", keys, 2, 100, 1));
	capture_activate(&l, 1, 0);
	for (fail = 0; fail < 5; fail++) {
		fail_after = fail;
		assert(!request(&l, &l, "be", keys, 2, 100, 1));
		fail_after = -1;
		assert(!l.count && !l.next_id);
	}
	a = request(&l, &l, "be", keys, 2, 100, 1); assert(a);
	b = request(&l, &l, "be", keys, 2, 100, 2); assert(b && b->id > a->id);
	assert(glb_ledger_next(&l, &op) == a && op == GLB_RESERVE_TAKE);
	assert(!glb_ledger_next(&l, &op));
	assert(!glb_ledger_walk_begin(&l, &changes, &high));
	reply(&l, 1, keys[0], 1); assert(a->state == GLB_READY && a->remote && wakes == 1);
	assert(!a->candidates && !a->candidate_count && !a->service); /* no long-lived candidate retention */
	assert(glb_ledger_native(&l, a, &l, keys[0]) == a && a->native);
	assert(glb_ledger_next(&l, &op) == b);
	reply(&l, 1, keys[1], 1); assert(b->state == GLB_READY);
	assert(glb_ledger_native(&l, b, &l, keys[1]) == b);
	assert(l.count == 2);
	release(&l, a); assert(l.count == 1);
	release(&l, b); assert(l.count == 0);
	/* Expiration BEFORE dispatch performs no unnecessary store decrement. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	glb_ledger_expire(&l, a); glb_ledger_drop(&l, a);
	assert(!glb_ledger_next(&l, &op) && !l.count);
	/* Timeout/stream death DURING TAKE: no wake of a dead owner, late result
 * is cancelled by request ID, with no saved server pointer. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a);
	glb_ledger_expire(&l, a); glb_ledger_drop(&l, a); before = wakes;
	reply(&l, 1, keys[1], 1); assert(wakes == before);
	assert(glb_ledger_next(&l, &op) == a && op == GLB_RESERVE_CANCEL);
	reply(&l, 4, "", 0); assert(!l.count);
	/* Successful reply then health/identity rejection: release exactly once. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); reply(&l, 1, keys[0], 1);
	release(&l, a); assert(!l.count);
	/* Lost RELEASE invalidates Global/HB; fallback native assignments survive
 * in capture. Restoration, not expiry alone, removes the lost store delta. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); reply(&l, 1, keys[0], 1);
	glb_ledger_native(&l, a, &l, keys[0]); glb_ledger_drop(&l, a);
	assert(glb_ledger_next(&l, &op) == a); glb_ledger_complete(&l, NULL);
	assert(!l.active && l.dirty && l.count == 1);
	b = glb_ledger_native(&l, NULL, &l, keys[1]); assert(b && b->native && !b->remote);
	assert(capture(&l, &changes, &high) == 1);
	assert(!strcmp(b->endpoint, keys[1]));
	c = glb_ledger_native(&l, NULL, &l, keys[0]); assert(c);
	assert(!glb_ledger_commit(&l, uuid, 2, changes)); /* changed capture */
	capture_activate(&l, 2, 2); assert(l.count == 2 && b->remote && c->remote);
	release(&l, b); release(&l, c);
	/* Unknown response endpoint / wrong control reply / UUID rejection never
 * becomes an admission and requires fresh reconciliation. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); reply(&l, 1, "wrong|127.0.0.1:9", 1);
	assert(!l.active && a->state == GLB_FAILED); glb_ledger_drop(&l, a);
	capture_activate(&l, 3, 0); assert(!l.count);
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); reply(&l, -1, "", 0);
	assert(!l.active); glb_ledger_drop(&l, a); capture_activate(&l, 4, 0);
	/* No response/error on reserve plus detached owner. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); glb_ledger_drop(&l, a);
	glb_ledger_complete(&l, NULL); capture_activate(&l, 5, 0);
	/* Native identity immutability on a remapped slot. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a); reply(&l, 1, keys[0], 1);
	b = glb_ledger_native(&l, a, &l, keys[1]); assert(b != a && !l.active);
	capture_activate(&l, 6, 1); assert(!strcmp(b->endpoint, keys[1])); release(&l, b);
	/* Allocation failure while decoding a successful reserve cannot silently
 * lose its uncertain remote reservation or activate incomplete local state. */
	a = request(&l, &l, "be", keys, 2, 100, 1);
	assert(glb_ledger_next(&l, &op) == a);
	fail_after = 0; reply(&l, 1, keys[0], 1); fail_after = -1;
	assert(!l.active && a->state == GLB_FAILED);
	glb_ledger_drop(&l, a); capture_activate(&l, 7, 0);
	for (fail = 0; fail < 2; fail++) {
		fail_after = fail;
		assert(!glb_ledger_native(&l, NULL, &l, keys[0])); fail_after = -1;
		assert(l.untracked == 1 && !l.active); l.untracked--;
		capture_activate(&l, 8+fail, 0);
	}
	/* uint64 monotonic IDs do not reset on restore, refuse overflow. */
	l.next_id = UINT64_MAX - 1;
	a = request(&l, &l, "be", keys, 2, 100, 1); assert(a && a->id == UINT64_MAX);
	assert(!request(&l, &l, "be", keys, 2, 100, 1)); glb_ledger_drop(&l, a);
	glb_ledger_destroy(&l);
	/* Caller budget refusal does not overrun native counters; untracked local
 * slots prohibit an incomplete restore/Global activation. */
	glb_ledger_init(&l, 1, wake); capture_activate(&l, 1, 0);
	a = glb_ledger_native(&l, NULL, &l, keys[0]); assert(a);
	assert(!glb_ledger_native(&l, NULL, &l, keys[1]) && l.untracked == 1);
	assert(!glb_ledger_walk_begin(&l, &changes, &high));
	l.untracked--; glb_ledger_drop(&l, a); capture_activate(&l, 2, 0);
	glb_ledger_destroy(&l);
	/* Incremental production capture pins immutable keys outside lock. A
 * removed cursor advances safely, a pinned detached entry remains readable. */
	glb_ledger_init(&l, 1000, wake);
	a = glb_ledger_native(&l, NULL, &l, keys[0]);
	b = glb_ledger_native(&l, NULL, &l, keys[1]);
	c = glb_ledger_native(&l, NULL, &l, keys[0]);
	assert(glb_ledger_walk_begin(&l, &changes, &high));
	assert(glb_ledger_walk_pin(&l) == c);
	glb_ledger_drop(&l, c); assert(c->removed && !strcmp(c->endpoint, keys[0]));
	glb_ledger_drop(&l, b); /* pending cursor removed */
	assert(glb_ledger_walk_pin(&l) == a);
	glb_ledger_unpin(c); glb_ledger_unpin(a);
	assert(!glb_ledger_walk_pin(&l));
	assert(!glb_ledger_commit(&l, uuid, 1, changes));
	assert(glb_ledger_walk_begin(&l, &changes, &high));
	assert(glb_ledger_settle(&l, 1, 1));
	assert(glb_ledger_commit(&l, uuid, 1, changes));
	assert(a->remote && a->revision == 1 && l.active);
	release(&l, a);
	glb_ledger_invalidate(&l);
	for (n = 0; n < 100; n++) assert(glb_ledger_native(&l, NULL, &l, keys[n%2]));
	assert(glb_ledger_walk_begin(&l, &changes, &high));
	assert(!glb_ledger_settle(&l, 2, 32));
	assert(!glb_ledger_settle(&l, 2, 32));
	assert(!glb_ledger_settle(&l, 2, 32));
	assert(glb_ledger_settle(&l, 2, 32));
	assert(glb_ledger_commit(&l, uuid, 2, changes));
	l.terminal = 1; glb_ledger_invalidate(&l);
	assert(!glb_ledger_walk_begin(&l, &changes, &high));
	assert(!glb_ledger_commit(&l, uuid, 3, l.changes));
	assert(!glb_ledger_commit(&l, uuid, 3, l.changes));
	assert(!request(&l, &l, "be", keys, 2, 100, 1));
	glb_ledger_destroy(&l);
	check_status(&l);
	puts("PASS: v2 ledger admission, cancel, release, incremental capture/commit, identity, limits and read-only tallies");
	return 0;
}
