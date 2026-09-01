/*
 * Read-only local snapshot API for optional Global LB support.
 *
 * Copyright 2026 nTels
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>

#include <haproxy/atomic.h>
#include <haproxy/global_lb.h>
#include <haproxy/list.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/tools.h>

static enum global_lb_oper_state global_lb_map_server_state(enum srv_state state)
{
	switch (state) {
	case SRV_ST_STOPPED:
		return GLOBAL_LB_OPER_STOPPED;
	case SRV_ST_STARTING:
		return GLOBAL_LB_OPER_STARTING;
	case SRV_ST_RUNNING:
		return GLOBAL_LB_OPER_RUNNING;
	case SRV_ST_STOPPING:
		return GLOBAL_LB_OPER_STOPPING;
	}

	return GLOBAL_LB_OPER_UNKNOWN;
}

const char *global_lb_oper_state_name(enum global_lb_oper_state state)
{
	switch (state) {
	case GLOBAL_LB_OPER_STOPPED:
		return "STOPPED";
	case GLOBAL_LB_OPER_STARTING:
		return "STARTING";
	case GLOBAL_LB_OPER_RUNNING:
		return "RUNNING";
	case GLOBAL_LB_OPER_STOPPING:
		return "STOPPING";
	case GLOBAL_LB_OPER_UNKNOWN:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

int global_lb_format_endpoint(const struct global_lb_local_entry *entry,
			      char *endpoint, size_t endpoint_size)
{
	char addr[INET6_ADDRSTRLEN + 1];
	int family;

	family = addr_to_str(&entry->endpoint_addr, addr, sizeof(addr));
	switch (family) {
	case AF_INET:
		snprintf(endpoint, endpoint_size, "%s:%u", addr, entry->endpoint_port);
		break;
	case AF_INET6:
		snprintf(endpoint, endpoint_size, "[%s]:%u", addr, entry->endpoint_port);
		break;
	default:
		snprintf(endpoint, endpoint_size, "-");
		break;
	}

	return family == AF_INET || family == AF_INET6;
}

void global_lb_local_snapshot_init(struct global_lb_local_snapshot_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	watcher_init(&ctx->px_watch, &ctx->px,
		     offsetof(struct proxy, watcher_list));
	watcher_init(&ctx->srv_watch, &ctx->srv,
		     offsetof(struct server, watcher_list));
	watcher_attach(&ctx->px_watch, proxies_list);
}

int global_lb_local_snapshot_current(struct global_lb_local_snapshot_ctx *ctx,
				     struct global_lb_local_entry *entry)
{
	struct server *srv;

	while (ctx->px) {
		if ((ctx->px->cap & (PR_CAP_BE | PR_CAP_INT)) != PR_CAP_BE)
			goto next_proxy;

		if (!ctx->servers_attached) {
			watcher_attach(&ctx->srv_watch, ctx->px->srv);
			ctx->servers_attached = 1;
		}

		if (ctx->srv) {
			srv = ctx->srv;
			entry->backend_name = ctx->px->id;
			entry->server_name = srv->id;
			entry->endpoint_addr = srv->addr;
			entry->endpoint_port = srv->svc_port;
			entry->oper_state = global_lb_map_server_state(srv->cur_state);
			entry->cur_sess = _HA_ATOMIC_LOAD(&srv->cur_sess);
			entry->served = _HA_ATOMIC_LOAD(&srv->served);
			return 1;
		}

	 next_proxy:
		ctx->servers_attached = 0;
		watcher_next(&ctx->px_watch, ctx->px->next);
	}

	return 0;
}

void global_lb_local_snapshot_advance(struct global_lb_local_snapshot_ctx *ctx)
{
	if (!ctx->srv)
		return;

	watcher_next(&ctx->srv_watch, ctx->srv->next);
}

void global_lb_local_snapshot_release(struct global_lb_local_snapshot_ctx *ctx)
{
	watcher_detach(&ctx->px_watch);
	watcher_detach(&ctx->srv_watch);
}
