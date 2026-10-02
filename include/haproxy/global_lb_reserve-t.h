/* UD-007/009/011 v2-r1-20261003. Global reservation protocol only.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_RESERVE_T_H
#define _HAPROXY_GLOBAL_LB_RESERVE_T_H
#ifdef USE_GLOBAL_LB
#include <stddef.h>
#include <stdint.h>

enum global_lb_reserve_op {
	GLB_RESERVE_START, GLB_RESERVE_RESTORE, GLB_RESERVE_TAKE,
	GLB_RESERVE_RELEASE, GLB_RESERVE_CANCEL, GLB_RESERVE_HEARTBEAT,
	GLB_RESERVE_STOP,
};

enum global_lb_reserve_status {
	GLB_RESERVE_TERMINAL = -7, GLB_RESERVE_EXPIRED = -6,
	GLB_RESERVE_LIMIT = -5, GLB_RESERVE_REVISION = -4,
	GLB_RESERVE_CORRUPT = -3, GLB_RESERVE_INVALID = -2,
	GLB_RESERVE_OTHER_WRITER = -1, GLB_RESERVE_STALE = 0,
	GLB_RESERVE_OK = 1, GLB_RESERVE_DUPLICATE = 2,
	GLB_RESERVE_RELEASED = 3, GLB_RESERVE_CANCELLED = 4,
	GLB_RESERVE_ABSENT = 5,
};

/* Metadata for a native HAProxy reservation, NOT a replacement served counter.
 * START/RESTORE derive counts from these active endpoint assignments.
 * The stream ledger/capture and target/srv_conn hooks belong to v2 step 2/3.
 */
struct global_lb_reserve_entry {
	uint64_t request_id;
	const char *endpoint_key;
};

/* Explicit caller budgets; not new deployment-size defaults. */
struct global_lb_reserve_limits {
	unsigned int instances;
	unsigned int count_fields;
	unsigned int requests;
};

struct global_lb_reserve_command {
	enum global_lb_reserve_op op;
	const char *prefix;
	const char *instance_id;
	const char *writer_generation;
	/* Revision advances on START/RESTORE, not per reconnect or per request.
	 * Every delta echoes its revision: pre-restore operations cannot modify
	 * the restored state. request_id is monotonic per writer, never reset.
	 */
	uint64_t revision;
	uint64_t request_id;
	uint64_t high_water;
	unsigned int instance_timeout;
	unsigned int tie_seed;
	struct global_lb_reserve_limits limits;
	const char *service_id;
	const char * const *candidates;
	size_t candidate_count;
	const struct global_lb_reserve_entry *entries;
	size_t entry_count;
};

/* endpoint view is borrowed from the completed RESP parser. */
struct global_lb_reserve_reply {
	enum global_lb_reserve_status status;
	const unsigned char *endpoint;
	size_t endpoint_len;
	uint64_t count;
};
#endif
#endif
