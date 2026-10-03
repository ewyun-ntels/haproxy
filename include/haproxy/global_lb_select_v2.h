/* UD-005/009/010/011 v2-r2-20261003. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_SELECT_V2_H
#define _HAPROXY_GLOBAL_LB_SELECT_V2_H
#ifdef USE_GLOBAL_LEASTCONN
struct stream;
struct server;
struct sockaddr_storage;
/* Returns 1 to suspend only this stream in SC_ST_REQ; 0 for native processing.
 * Sets SF_ASSIGNED for a revalidated Global result, else native LC fallback. */
int global_lb_v2_select(struct stream *);
void global_lb_v2_slot(struct stream *, struct server *);
void global_lb_v2_drop(struct stream *);
/* Cancel a selected remote reserve if native slot acquisition queued/failed. */
void global_lb_v2_no_slot(struct stream *);
/* Identity may change between selection/slot acquisition and TCP connect. */
int global_lb_v2_validate(struct stream *);
int global_lb_v2_destination(struct stream *, const struct sockaddr_storage *);
void global_lb_v2_account(struct stream *);
#endif
#endif
