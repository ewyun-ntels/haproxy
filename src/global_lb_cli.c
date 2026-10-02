/*
 * Runtime CLI for optional Global LB support.
 *
 * Copyright 2026 nTels
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include <sys/socket.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/chunk.h>
#include <haproxy/cli.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_collect.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/time.h>

/* UD-013 r1-observability-20261002. Read-only copied status, safe on any
 * traffic thread. The cache command owns its copied rows while output yields.
 */
struct global_lb_status_cli_ctx {
	char *text;
};

static int cli_parse_show_global_lb_status(char **args, char *payload,
		struct appctx *appctx, void *private)
{
	struct global_lb_status_cli_ctx *ctx;
	struct global_lb_publish_status status;
	const char *state = "DISABLED", *reason;
	uint64_t version = 0;
	size_t endpoints = 0;
	unsigned int usable = 0, successes = 0;
	long long age = -1;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;
	if (*args[3])
		return cli_err(appctx, "show global-lb status expects no arguments.\n");
	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	ctx->text = calloc(1, 2048);
	if (!ctx->text)
		return cli_err(appctx, "Failed to allocate Global LB status.\n");
	global_lb_publish_get_status(&status);
	reason = status.reason[0] ? status.reason : "not-enabled";
#ifdef USE_GLOBAL_LEASTCONN
	{
		struct global_lb_cache_status cached;
		global_lb_cache_get_status(now_ms, &cached);
		if (status.enabled)
			state = global_lb_cache_state_name(cached.state);
		usable = cached.usable;
		version = cached.version;
		endpoints = cached.endpoint_count;
		successes = cached.recovery_successes;
		if (cached.version)
			age = (unsigned int)(now_ms - cached.completed_at);
		if (cached.valid && !cached.usable && cached.state == GLB_CACHE_FALLBACK &&
		    age >= global_lb_cfg.stale_after)
			reason = "stale-cache";
	}
#endif
	snprintf(ctx->text, 2048,
		"enabled: %u\nstate: %s\nusable: %u\nreason: %s\n"
		"transport: %s\ninstance-id: %s\nwriter_generation: %s\n"
		"snapshot_sequence: %" PRIu64 "\npublications: %" PRIu64 "\n"
		"failures: %" PRIu64 "\nuntracked: %" PRIu64 "\n"
		"cache_version: %" PRIu64 "\ncache_endpoints: %zu\n"
		"cache_age_ms: %lld\nlast_publish_age_ms: %lld\n"
		"recovery: %u/%u\nsync_interval_ms: %u\nstale_after_ms: %u\n"
		"shutdown: %s\ncleanup: %s\n",
		status.enabled, state, usable, reason,
		global_lb_client_state_name(global_lb_client_observed_state()),
		global_lb_cfg.instance_id ? global_lb_cfg.instance_id : "-",
		status.writer_generation[0] ? status.writer_generation : "-",
		status.sequence, status.publications, status.failures, status.untracked,
		version, endpoints, age,
		status.publications ? (long long)(unsigned int)(now_ms - status.last_publish) : -1LL,
		successes, global_lb_cfg.recovery_successes, global_lb_cfg.sync_interval,
		global_lb_cfg.stale_after,
		status.shutdown >= 2 ? "complete" : status.shutdown ? "pending" : "running",
		status.cleanup[0] ? status.cleanup : "not-requested");
	return 0;
}

static int cli_io_handler_show_global_lb_status(struct appctx *appctx)
{
	struct global_lb_status_cli_ctx *ctx = appctx->svcctx;
	chunk_printf(&trash, "%s", ctx->text);
	return applet_putchk(appctx, &trash) == -1 ? 0 : 1;
}

static void cli_io_release_show_global_lb_status(struct appctx *appctx)
{
	struct global_lb_status_cli_ctx *ctx = appctx->svcctx;
	free(ctx->text);
}

#ifdef USE_GLOBAL_LEASTCONN
struct global_lb_cache_cli_ctx {
	struct global_lb_cache_snapshot snapshot;
	size_t next;
	unsigned int header;
};

static int cli_parse_show_global_lb_cache(char **args, char *payload,
		struct appctx *appctx, void *private)
{
	struct global_lb_cache_cli_ctx *ctx;
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;
	if (*args[3])
		return cli_err(appctx, "show global-lb cache expects no arguments.\n");
	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	ctx->next = ctx->header = 0;
	if (!global_lb_cache_snapshot_capture(now_ms, &ctx->snapshot))
		return cli_err(appctx, "Failed to allocate Global LB cache snapshot.\n");
	return 0;
}

static int cli_io_handler_show_global_lb_cache(struct appctx *appctx)
{
	struct global_lb_cache_cli_ctx *ctx = appctx->svcctx;
	if (!ctx->header) {
		chunk_printf(&trash, "# state=%s usable=%u version=%" PRIu64 "\n"
			"# endpoint\tglobal\tcache_own\tlocal_current\tadjusted\n",
			global_lb_cache_state_name(ctx->snapshot.status.state),
			ctx->snapshot.status.usable, ctx->snapshot.status.version);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
		ctx->header = 1;
	}
	while (ctx->next < ctx->snapshot.count) {
		const struct global_lb_cache_row *row = &ctx->snapshot.rows[ctx->next];
		uint64_t local, remote;
		char local_text[32] = "unknown", adjusted[32] = "unknown";
		if (global_lb_endpoint_local_count(row->key, &local)) {
			snprintf(local_text, sizeof(local_text), "%" PRIu64, local);
			if (row->global_count >= row->own_count) {
				remote = row->global_count - row->own_count;
				if (UINT64_MAX - remote >= local)
					snprintf(adjusted, sizeof(adjusted), "%" PRIu64, remote + local);
			}
		}
		chunk_printf(&trash, "%s\t%" PRIu64 "\t%" PRIu64 "\t%s\t%s\n",
			row->key, row->global_count, row->own_count, local_text, adjusted);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
		ctx->next++;
	}
	return 1;
}

static void cli_io_release_show_global_lb_cache(struct appctx *appctx)
{
	struct global_lb_cache_cli_ctx *ctx = appctx->svcctx;
	global_lb_cache_snapshot_release(&ctx->snapshot);
}
#endif

struct global_lb_local_cli_ctx {
	struct global_lb_absolute_snapshot snapshot;
	size_t next_entry;
	unsigned int header_done;
};

static int cli_parse_show_global_lb_local(char **args, char *payload,
					  struct appctx *appctx, void *private)
{
	struct global_lb_local_cli_ctx *ctx;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	global_lb_absolute_snapshot_init(&ctx->snapshot);
	if (!global_lb_absolute_snapshot_capture(&ctx->snapshot)) {
		global_lb_absolute_snapshot_release(&ctx->snapshot);
		return cli_err(appctx, "Failed to allocate the Global LB local snapshot.\n");
	}
	return 0;
}

static int cli_io_handler_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_cli_ctx *ctx = appctx->svcctx;
	const struct global_lb_absolute_entry *entry;
	char endpoint[INET6_ADDRSTRLEN + 16];

	if (!ctx->header_done) {
		chunk_printf(&trash,
		             "# backend\tserver\tendpoint\toper_state\tcur_sess\tserved\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
		ctx->header_done = 1;
	}

	while (ctx->next_entry < ctx->snapshot.count) {
		entry = &ctx->snapshot.entries[ctx->next_entry];
		global_lb_format_absolute_endpoint(entry, endpoint, sizeof(endpoint));
		chunk_printf(&trash, "%s\t%s\t%s\t%s\t%d\t%d\n",
		             entry->backend_name, entry->server_name, endpoint,
		             global_lb_oper_state_name(entry->oper_state),
		             entry->active_count, entry->served);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		ctx->next_entry++;
	}

	return 1;
}

static void cli_io_release_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_cli_ctx *ctx = appctx->svcctx;

	global_lb_absolute_snapshot_release(&ctx->snapshot);
}

static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "global-lb", "status", NULL },
	  "show global-lb status                   : dump read-only Global LB runtime status",
	  cli_parse_show_global_lb_status, cli_io_handler_show_global_lb_status,
	  cli_io_release_show_global_lb_status, NULL, ACCESS_LVL_ADMIN },
#ifdef USE_GLOBAL_LEASTCONN
	{ { "show", "global-lb", "cache", NULL },
	  "show global-lb cache                    : dump read-only Global LB cache and adjusted counts",
	  cli_parse_show_global_lb_cache, cli_io_handler_show_global_lb_cache,
	  cli_io_release_show_global_lb_cache, NULL, ACCESS_LVL_ADMIN },
#endif
	{ { "show", "global-lb", "local", NULL },
	  "show global-lb local                    : dump the read-only local backend connection snapshot",
	  cli_parse_show_global_lb_local,
	  cli_io_handler_show_global_lb_local,
	  cli_io_release_show_global_lb_local,
	  NULL, ACCESS_LVL_ADMIN },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
