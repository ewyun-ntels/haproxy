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

/* UD-009 v2-r2-20261003: canonical endpoint identity and native
 * active/backup eligibility, borrowed only during this stream invocation. */
int global_lb_server_key(const struct stream *, struct server *, char *, size_t);
int global_lb_candidate(const struct proxy *, const struct server *);

#endif
#endif
