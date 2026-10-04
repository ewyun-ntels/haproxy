/* UD-005/006/007/010/011 v2-r2-20261003. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_LEDGER_H
#define _HAPROXY_GLOBAL_LB_LEDGER_H
#ifdef USE_GLOBAL_LB
#include <haproxy/global_lb_reserve-t.h>

/* Serial core. The HAProxy adapter holds its short registry lock for mutations.
 * No stream/server pointers, I/O, native counter changes or internal locks.
 * A detached owner is never called again; transport retains the entry until
 * completion/cleanup, so late replies cannot reference a freed stream.
 */
enum glb_entry_state { GLB_WAIT, GLB_READY, GLB_NATIVE, GLB_FAILED, GLB_CLEANUP };
/* UD-012 v2-r4-20261004. O(1) copied diagnostics, not native counters.
 * queued[] indexes TAKE/RELEASE/CANCEL minus GLB_RESERVE_TAKE. */
struct glb_ledger_stats {
	size_t states[5], queued[3];
	uint64_t admitted, confirmed, released, cancelled;
	uint64_t abandoned_unsent, abandoned_sent, failures;
};
struct glb_ledger_status {
	struct glb_ledger_stats stats;
	size_t count, max_entries;
	uint64_t revision, changes, next_id;
	unsigned int active, dirty, untracked, terminal, inflight;
	enum global_lb_reserve_op inflight_op;
};
struct glb_entry {
	struct glb_entry *next, *prev, *qnext, *qprev;
	void *owner;
	uint64_t id, revision;
	unsigned int deadline, seed;
	enum glb_entry_state state;
	enum global_lb_reserve_op queued_op;
	unsigned int queued, sent, remote, native;
	unsigned int pins, removed;
	char *service, *endpoint;
	char **candidates;
	size_t candidate_count;
};
struct glb_ledger {
	struct glb_entry *entries, *head, *tail, *inflight;
	/* One lifecycle cursor, repaired on removal under the registry lock. */
	struct glb_entry *cursor;
	enum global_lb_reserve_op inflight_op;
	uint64_t next_id, revision, changes;
	size_t count, max_entries;
	unsigned int active, dirty, untracked, terminal;
	char writer[37];
	void (*wake)(void *);
	struct glb_ledger_stats stats;
};
/* Serial core: caller must hold the adapter's metadata lock. No allocation,
 * cursor mutation, request expiry, wakeup or borrowed entry/owner pointer. */
void glb_ledger_get_status(const struct glb_ledger *, struct glb_ledger_status *);
void glb_ledger_init(struct glb_ledger *, size_t, void (*wake)(void *));
void glb_ledger_destroy(struct glb_ledger *);
/* Allocate/copy candidates BEFORE acquiring the traffic registry lock. */
struct glb_entry *glb_ledger_prepare(void *, const char *, const char * const *,
		size_t, unsigned int, unsigned int);
void glb_ledger_free_prepared(struct glb_entry *);
int glb_ledger_admit(struct glb_ledger *, struct glb_entry *);
/* Caller expires with HAProxy tick functions (including wrap boundaries). */
void glb_ledger_expire(struct glb_ledger *, struct glb_entry *);
/* Adopt the native slot. A READY entry must match the resolved key exactly.
 * Otherwise detach/cancel it and create a fallback ledger entry. */
struct glb_entry *glb_ledger_native(struct glb_ledger *, struct glb_entry *,
		void *, const char *endpoint);
void glb_ledger_drop(struct glb_ledger *, struct glb_entry *);
void glb_ledger_invalidate(struct glb_ledger *);
/* One command in flight. Borrowed candidates stay alive until completion.
 * Cleanup is FIFO with admissions (bounded fairness, no replay of TAKE). */
struct glb_entry *glb_ledger_next(struct glb_ledger *, enum global_lb_reserve_op *);
void glb_ledger_complete(struct glb_ledger *, const struct global_lb_reserve_reply *);
/* UD-006/011 v2-r3: incremental production capture/commit. Pin one entry
 * under lock, copy its immutable key outside lock, then unpin under lock.
 * begin/commit require inactive state; concurrent native mutations invalidate
 * the changes barrier. At most budget entries are settled per lock hold. */
int glb_ledger_walk_begin(struct glb_ledger *, uint64_t *, uint64_t *);
struct glb_entry *glb_ledger_walk_pin(struct glb_ledger *);
void glb_ledger_unpin(struct glb_entry *);
int glb_ledger_settle(struct glb_ledger *, uint64_t revision, size_t budget);
int glb_ledger_commit(struct glb_ledger *, const char *, uint64_t, uint64_t);
#endif
#endif
