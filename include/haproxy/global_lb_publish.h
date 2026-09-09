/* UD-007 r7 / UD-005 r6 endpoint lifecycle, 2026-09-04.
 * Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_PUBLISH_H
#define _HAPROXY_GLOBAL_LB_PUBLISH_H
#ifdef USE_GLOBAL_LB
#include <stdint.h>
#include <sys/socket.h>
#include <haproxy/obj_type-t.h>
struct stream;
struct resolvers;
struct resolv_requester;
struct dns_counters;

/* Internal safety ceilings, not certified deployment scale. Failure suppresses
 * the WHOLE publication, never substitutes partial/zero counts. */
#define GLB_PUBLISH_MAX_ENDPOINTS 4096
#define GLB_PUBLISH_KEY_SIZE 1024
#define GLB_PUBLISH_WIRE_SIZE (8U * 1024U * 1024U)

struct global_lb_dns {
	enum obj_type obj_type;
	char *hostname_dn;
	int hostname_dn_len;
	struct resolvers *resolvers;
	struct resolv_requester *requester;
};
int global_lb_dns_success(struct resolv_requester *, struct dns_counters *);
int global_lb_dns_error(struct resolv_requester *, int);
int global_lb_publish_init(void);
void global_lb_publish_deinit(void);
/* Called only alongside SF_CURR_SESS transitions on the owning stream thread.
 * Destination is the connection's actual address, not the current server slot.
 * No I/O, traffic shutdown, mutation of cur_sess, or allocation in these hooks.
 */
void global_lb_endpoint_take(struct stream *, const struct sockaddr_storage *);
void global_lb_endpoint_drop(struct stream *);
#ifdef USE_GLOBAL_LEASTCONN
/* Copy the current local absolute count for one canonical endpoint. Returns
 * zero when the registry cannot provide a complete local view.
 */
int global_lb_endpoint_local_count(const char *, uint64_t *);
#endif
#endif
#endif
