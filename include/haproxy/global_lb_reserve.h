/* UD-007/009/011 v2-r1-20261003. Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_RESERVE_H
#define _HAPROXY_GLOBAL_LB_RESERVE_H
#include <haproxy/global_lb_reserve-t.h>
#include <haproxy/global_lb_resp-t.h>
#ifdef USE_GLOBAL_LB
/* Four fixed Hash keys in a v2 namespace, disjoint from v1 snapshots.
 * Hex escaping prevents prefix collisions. Caller frees the returned key.
 * index: 0 owners, 1 liveness, 2 counts, 3 active requests.
 */
enum global_lb_resp_error global_lb_reserve_key(const char *prefix,
		unsigned int index, size_t max_bytes, char **key);
const char *global_lb_reserve_script(size_t *len);
/* Pure bounded encoder: no I/O, no counter/UUID/sequence mutation.
 * Success transfers a malloc buffer to caller. Failure sets NULL/0.
 */
enum global_lb_resp_error global_lb_reserve_encode(
		const struct global_lb_reserve_command *command, size_t max_bytes,
		unsigned char **wire, size_t *wire_len);
int global_lb_reserve_result(const struct global_lb_resp_parser *parser,
		struct global_lb_reserve_reply *reply);
#endif
#endif
