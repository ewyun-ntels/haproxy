/* Optional Global LB RESP2 types. Copyright 2026 nTels.
 * Licensed under GNU LGPL version 2.1 exclusively.
 * UD-007 r4-resp2-codec-20260904, USE_GLOBAL_LB.
 */
#ifndef _HAPROXY_GLOBAL_LB_RESP_T_H
#define _HAPROXY_GLOBAL_LB_RESP_T_H
#ifdef USE_GLOBAL_LB

#include <stddef.h>
#include <stdint.h>

enum global_lb_resp_status {
	GLB_RESP_ERROR = -1,
	GLB_RESP_MORE = 0,
	GLB_RESP_DONE = 1,
};

enum global_lb_resp_error {
	GLB_RESP_OK = 0,
	GLB_RESP_INVALID,
	GLB_RESP_LIMIT,
	GLB_RESP_NOMEM,
	GLB_RESP_BADARG,
};

/* Explicit caller limits, not new deployment defaults. Depth counts arrays. */
struct global_lb_resp_limits {
	size_t bytes;
	size_t nodes;
	size_t depth;
};

/* Flat preorder tree. next skips the entire subtree; children is the immediate
 * array length. For +, -, $ strings use wire + offset and len (not NUL-terminated).
 * Null bulk/array is distinct from empty. A '-' reply is data, not a parse error.
 */
struct global_lb_resp_node {
	char type;
	int is_null;
	int64_t integer;
	size_t offset, len, children, next;
};

struct global_lb_resp_level {
	size_t node, remaining;
};

/* One owner/thread per parser. Internal state must not be modified by callers.
 * Only consume wire/nodes after DONE; their storage is owned by this parser.
 */
struct global_lb_resp_parser {
	struct global_lb_resp_limits limits;
	enum global_lb_resp_status status;
	enum global_lb_resp_error error;
	unsigned char *wire;
	struct global_lb_resp_node *nodes;
	struct global_lb_resp_level *stack;
	size_t used, count, depth;
	size_t wire_cap, node_cap, stack_cap;
	size_t bulk_left;
	unsigned int state;
};

struct global_lb_resp_arg {
	const void *data;
	size_t len;
};

#endif /* USE_GLOBAL_LB */
#endif /* _HAPROXY_GLOBAL_LB_RESP_T_H */
