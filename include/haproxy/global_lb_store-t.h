/* Optional Global LB storage protocol types.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_STORE_T_H
#define _HAPROXY_GLOBAL_LB_STORE_T_H

#ifdef USE_GLOBAL_LB
#include <stddef.h>
#include <stdint.h>

/* UD-007 r5-store-protocol-20260904 / UD-011 r3-sequenced-store-20260904. */
enum global_lb_store_op {
	GLB_STORE_START, GLB_STORE_UPDATE, GLB_STORE_DELETE,
};

/* Integer replies from the embedded script, not transport/parser status. */
enum global_lb_store_result {
	GLB_STORE_CORRUPT = -3,
	GLB_STORE_INVALID = -2,
	GLB_STORE_OTHER_WRITER = -1,
	GLB_STORE_STALE = 0,
	GLB_STORE_STORED = 1,
	GLB_STORE_DELETED = 2,
	GLB_STORE_ABSENT = 3,
};

/* Owned by one future worker task. No concurrent access or reconnect reset. */
struct global_lb_store_writer {
	char writer_generation[37];
	uint64_t snapshot_sequence;
};

/* An already resolved, unique canonical endpoint and its absolute cur_sess.
 * The publisher must filter opt-in backends and handle unresolved rows before
 * calling the builder. This protocol never reads counters or sums duplicates.
 */
struct global_lb_store_entry {
	const char *endpoint_key;
	uint64_t active_count;
};
#endif
#endif
