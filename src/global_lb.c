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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/atomic.h>
#include <haproxy/global_lb.h>
#include <haproxy/list.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/thread.h>
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

static int global_lb_format_endpoint_value(const struct sockaddr_storage *addr,
					   unsigned int port,
					   char *endpoint, size_t endpoint_size)
{
	char text[INET6_ADDRSTRLEN + 1];
	int family;

	family = addr_to_str(addr, text, sizeof(text));
	switch (family) {
	case AF_INET:
		snprintf(endpoint, endpoint_size, "%s:%u", text, port);
		break;
	case AF_INET6:
		snprintf(endpoint, endpoint_size, "[%s]:%u", text, port);
		break;
	default:
		snprintf(endpoint, endpoint_size, "-");
		break;
	}

	return family == AF_INET || family == AF_INET6;
}

int global_lb_format_endpoint(const struct global_lb_local_entry *entry,
			      char *endpoint, size_t endpoint_size)
{
	return global_lb_format_endpoint_value(&entry->endpoint_addr,
					       entry->endpoint_port,
					       endpoint, endpoint_size);
}

int global_lb_format_absolute_endpoint(const struct global_lb_absolute_entry *entry,
				       char *endpoint, size_t endpoint_size)
{
	return global_lb_format_endpoint_value(&entry->endpoint_addr,
					       entry->endpoint_port,
					       endpoint, endpoint_size);
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

			/*
			 * Runtime address/state changes use the server lock. Keep it
			 * only for the per-row copy; allocation and consumers run after
			 * it is released. Counters remain atomic HAProxy values.
			 */
			HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
			entry->endpoint_addr = srv->addr;
			entry->endpoint_port = srv->svc_port;
			entry->oper_state = global_lb_map_server_state(srv->cur_state);
			entry->cur_sess = _HA_ATOMIC_LOAD(&srv->cur_sess);
			entry->served = _HA_ATOMIC_LOAD(&srv->served);
			HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
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

void global_lb_absolute_snapshot_init(struct global_lb_absolute_snapshot *snapshot)
{
	memset(snapshot, 0, sizeof(*snapshot));
}

void global_lb_absolute_snapshot_release(struct global_lb_absolute_snapshot *snapshot)
{
	size_t index;

	for (index = 0; index < snapshot->count; ++index) {
		free(snapshot->entries[index].backend_name);
		free(snapshot->entries[index].server_name);
	}
	free(snapshot->entries);
	global_lb_absolute_snapshot_init(snapshot);
}

static int global_lb_absolute_snapshot_reserve(struct global_lb_absolute_snapshot *snapshot,
					       size_t needed)
{
	struct global_lb_absolute_entry *entries;
	size_t capacity;

	if (needed <= snapshot->capacity)
		return 1;
	if (needed > SIZE_MAX / sizeof(*entries))
		return 0;

	capacity = snapshot->capacity ? snapshot->capacity : 8;
	while (capacity < needed) {
		if (capacity > SIZE_MAX / 2) {
			capacity = needed;
			break;
		}
		capacity *= 2;
	}
	if (capacity > SIZE_MAX / sizeof(*entries))
		capacity = needed;

	entries = realloc(snapshot->entries, capacity * sizeof(*entries));
	if (!entries)
		return 0;

	snapshot->entries = entries;
	snapshot->capacity = capacity;
	return 1;
}

static int global_lb_absolute_snapshot_append(struct global_lb_absolute_snapshot *snapshot,
					      const struct global_lb_local_entry *local)
{
	struct global_lb_absolute_entry *entry;
	char *backend_name;
	char *server_name;

	if (snapshot->count == SIZE_MAX)
		return 0;
	if (!global_lb_absolute_snapshot_reserve(snapshot, snapshot->count + 1))
		return 0;

	backend_name = strdup(local->backend_name ? local->backend_name : "");
	server_name = strdup(local->server_name ? local->server_name : "");
	if (!backend_name || !server_name) {
		free(backend_name);
		free(server_name);
		return 0;
	}

	entry = &snapshot->entries[snapshot->count++];
	entry->backend_name = backend_name;
	entry->server_name = server_name;
	entry->endpoint_addr = local->endpoint_addr;
	entry->endpoint_port = local->endpoint_port;
	entry->oper_state = local->oper_state;
	entry->active_count = local->cur_sess;
	entry->served = local->served;
	return 1;
}

/*
 * Materialize all current local rows before replacing <snapshot>. "Absolute"
 * means that each active_count is a complete cur_sess value, not a delta. The
 * rows are sampled independently; this function does not freeze all servers at
 * one global instant. On allocation failure, the previous snapshot is kept.
 */
int global_lb_absolute_snapshot_capture(struct global_lb_absolute_snapshot *snapshot)
{
	struct global_lb_absolute_snapshot next;
	struct global_lb_local_snapshot_ctx iterator;
	struct global_lb_local_entry local;

	global_lb_absolute_snapshot_init(&next);
	global_lb_local_snapshot_init(&iterator);

	while (global_lb_local_snapshot_current(&iterator, &local)) {
		if (!global_lb_absolute_snapshot_append(&next, &local))
			goto fail;
		global_lb_local_snapshot_advance(&iterator);
	}

	global_lb_local_snapshot_release(&iterator);
	global_lb_absolute_snapshot_release(snapshot);
	*snapshot = next;
	return 1;

 fail:
	global_lb_local_snapshot_release(&iterator);
	global_lb_absolute_snapshot_release(&next);
	return 0;
}
