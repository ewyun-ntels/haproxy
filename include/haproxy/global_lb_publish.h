/* UD-007 r7 / UD-005 r6 endpoint lifecycle, 2026-09-04.
 * Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_PUBLISH_H
#define _HAPROXY_GLOBAL_LB_PUBLISH_H
#ifdef USE_GLOBAL_LB
#include <stdint.h>
#include <sys/socket.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/global_lb_client-t.h>
struct resolvers;
struct resolv_requester;
struct dns_counters;

/* UD-007 v2-only-20261004: bounded reservation protocol resources. */
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

/* UD-012 r1-shutdown-20261002 / UD-013 r1-observability-20261002.
 * Read-only, lock-protected copied diagnostics; no task/client-owned pointer.
 */
struct global_lb_publish_status {
	unsigned int enabled, shutdown;
	char writer_generation[37];
	char cleanup[32];
};
int global_lb_publish_shutdown(void);
int global_lb_publish_stop_ready(void);
void global_lb_publish_get_status(struct global_lb_publish_status *status);
/* Thread-0 lifecycle completion re-enters the existing terminal signal queue. */
void global_lb_publish_shutdown_finish(const char *result);
#endif
#endif
