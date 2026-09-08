/* Optional Global LeastConn snapshot collector types.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_COLLECT_T_H
#define _HAPROXY_GLOBAL_LB_COLLECT_T_H

#ifdef USE_GLOBAL_LEASTCONN
#include <stddef.h>
#include <stdint.h>

/* UD-008 r2-global-cache-20260908.
 * This is the supported unique endpoint ceiling for one complete cache, not
 * a connection or HAProxy-instance limit. The 4097th endpoint invalidates the
 * cache and forces native local leastconn fallback.
 */
#define GLB_COLLECT_MAX_ENDPOINTS 4096
#define GLB_COLLECT_SCAN_COUNT 32
#define GLB_COLLECT_REPLY_BYTES (8U * 1024U * 1024U)
#define GLB_COLLECT_REPLY_NODES (2U * (GLB_COLLECT_MAX_ENDPOINTS + 3U) + 1U)
#define GLB_COLLECT_REPLY_DEPTH 2

enum global_lb_collect_result {
	GLB_COLLECT_ERROR = -1,
	GLB_COLLECT_LIMIT = -2,
	GLB_COLLECT_NEXT = 1,
	GLB_COLLECT_COMPLETE = 2,
};

/* A copied lookup result. No cache-owned pointer escapes the read lock. */
struct global_lb_cache_value {
	uint64_t global_count;
	uint64_t own_count;
	uint64_t version;
	unsigned int completed_at;
	size_t endpoint_count;
	unsigned int found;
};

struct global_lb_cache_status {
	uint64_t version;
	unsigned int completed_at;
	size_t endpoint_count;
	unsigned int valid;
};
#endif /* USE_GLOBAL_LEASTCONN */
#endif /* _HAPROXY_GLOBAL_LB_COLLECT_T_H */
