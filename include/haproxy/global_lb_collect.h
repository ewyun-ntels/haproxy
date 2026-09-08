/* Optional Global LeastConn snapshot collector.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_COLLECT_H
#define _HAPROXY_GLOBAL_LB_COLLECT_H

#include <haproxy/global_lb_collect-t.h>

#ifdef USE_GLOBAL_LEASTCONN
#include <haproxy/global_lb_resp-t.h>
#include <haproxy/global_lb_store-t.h>

/* One collector exists beside the existing publisher on worker thread 0.
 * SCAN/HGETALL commands are returned as malloc-owned RESP2 buffers. The caller
 * submits exactly one through the shared single-flight client and frees a
 * refused buffer. No state-store I/O occurs in this module.
 */
int global_lb_collect_init(const char *prefix, const char *instance_id,
			   size_t command_limit);
void global_lb_collect_deinit(void);
enum global_lb_collect_result global_lb_collect_start(
		const struct global_lb_store_writer *writer,
		unsigned char **wire, size_t *wire_len);
enum global_lb_collect_result global_lb_collect_reply(
		const struct global_lb_resp_parser *reply, unsigned int completed_at,
		unsigned char **wire, size_t *wire_len);
/* Discard only the incomplete staging cycle. The last complete cache remains. */
void global_lb_collect_abort(void);
/* Explicit unsupported-scale path: incomplete and published caches are invalid. */
void global_lb_collect_invalidate(void);

/* Thread-safe, allocation-free read APIs for the future selector/observability. */
int global_lb_cache_lookup(const char *endpoint_key,
			   struct global_lb_cache_value *value);
void global_lb_cache_get_status(struct global_lb_cache_status *status);
#endif /* USE_GLOBAL_LEASTCONN */
#endif /* _HAPROXY_GLOBAL_LB_COLLECT_H */
