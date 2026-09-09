/* Optional Global LeastConn traffic-path selector.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_SELECT_H
#define _HAPROXY_GLOBAL_LB_SELECT_H

#ifdef USE_GLOBAL_LEASTCONN
struct server;
struct stream;

/* Return non-zero when the Global Cache was usable and a global selection was
 * attempted. <selected> may still be NULL when every eligible server is full.
 * Return zero to request the caller's native local leastconn fallback.
 */
int global_lb_select_server(struct stream *stream, struct server *avoid,
			    struct server **selected);
#endif
#endif
