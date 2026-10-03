/* Optional Global LeastConn traffic-path selector.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_SELECT_H
#define _HAPROXY_GLOBAL_LB_SELECT_H

#ifdef USE_GLOBAL_LEASTCONN
#include <stddef.h>
struct server;
struct stream;
struct proxy;

/* UD-009 v2-r2-20261003: shared v1/v2 canonical identity and native
 * active/backup eligibility, borrowed only during this stream invocation. */
int global_lb_server_key(const struct stream *, struct server *, char *, size_t);
int global_lb_candidate(const struct proxy *, const struct server *);

/* Return non-zero when the Global Cache was usable and a global selection was
 * attempted. <selected> may still be NULL when every eligible server is full.
 * Return zero to request the caller's native local leastconn fallback.
 */
int global_lb_select_server(struct stream *stream, struct server *avoid,
			    struct server **selected);
#endif
#endif
