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
#include <haproxy/global_lb_dispatch.h>
#include <haproxy/global_lb_lifecycle.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/time.h>

/* UD-013 r1-observability-20261002. Read-only copied status, safe on any
 * traffic thread. The cache command owns its copied rows while output yields.
 */
struct global_lb_status_cli_ctx {
	char *text;
	size_t next;
};

/* UD-012/016 v2-r4-20261004, USE_GLOBAL_LB. Scalar snapshots only; no
 * store I/O, state transitions, ledger walk/restore cursor or borrowed rows.
 * Lifecycle and ledger are sampled separately, not a distributed snapshot. */
static const char *v2_control_name(unsigned int control)
{
	static const char *names[] = { "none", "START", "RESTORE", "TAKE", "RELEASE", "CANCEL", "HEARTBEAT", "STOP" };
	return control < sizeof(names) / sizeof(*names) ? names[control] : "unknown";
}
static void v2_ledger_status(struct glb_ledger_status *s)
{
	struct glb_ledger *l = global_lb_dispatch_lock();
	glb_ledger_get_status(l, s);
	global_lb_dispatch_unlock();
}
static void format_v2_status(char *text, size_t size, const struct global_lb_publish_status *publisher)
{
	struct global_lb_lifecycle_status s;
	struct glb_ledger_status l;
	const char *state, *reason, *phase;
	char result[32];
	global_lb_lifecycle_get_status(&s);
	v2_ledger_status(&l);
	state = !publisher->enabled ? "DISABLED" : l.terminal ? "STOPPING" :
	        s.blocked ? "FENCED" : l.active ? "ACTIVE" : "FALLBACK";
	reason = !publisher->enabled ? "not-enabled" : l.terminal ? "stopping" :
	         !l.active && s.active ? "local-ledger-dirty; fresh restore required" : s.reason;
	phase = s.phase == 1 ? "CAPTURING" : s.phase == 2 ? "COMMITTING" : "IDLE";
	if (s.have_result) snprintf(result, sizeof(result), "%d", s.last_result);
	else strcpy(result, "unknown");
	snprintf(text, size,
		"mode: v2-reservation\nenabled: %u\nstate: %s\nusable: %u\nreason: %s\n"
		"transport: %s\nlast_transport_error: %s\ninstance-id: %.1024s\ninstance-id-truncated: %s\nwriter_generation: %s\n"
		"owner: %s\ncontrol: %s\nrestore_phase: %s\nrestore_revision: %" PRIu64 "\n"
		"committed_revision: %" PRIu64 "\nlast_control_result: %s\n"
		"heartbeat_reply_age_ms: %lld\nrestore_confirmed_age_ms: %lld\n"
		"starts: %" PRIu64 "\nrestores: %" PRIu64 "\nheartbeats: %" PRIu64 "\n"
		"activations: %" PRIu64 "\nrestore_barrier_retries: %" PRIu64 "\n"
		"transport_failures: %" PRIu64 "\ncommand_timeouts: %" PRIu64 "\n"
		"ledger_entries: %zu\nledger_limit: %zu\nnative_slots: %zu\nuntracked: %u\n"
		"dirty: %u\nrequest_high_water: %" PRIu64 "\n"
		"queued_reserve: %zu\nqueued_release: %zu\nqueued_cancel: %zu\ninflight: %s\n"
		"reserve_timeout_ms: %u\nheartbeat_interval_ms: %u\ninstance_timeout_ms: %u\n"
		"max_instances: %u\nmax_requests: %u\nshutdown: %s\ncleanup: %s\n",
		publisher->enabled, state, publisher->enabled && l.active && !l.terminal, reason,
		global_lb_client_state_name(global_lb_client_observed_state()), global_lb_client_error_name(s.last_error),
		global_lb_cfg.instance_id ? global_lb_cfg.instance_id : "-",
		global_lb_cfg.instance_id && strlen(global_lb_cfg.instance_id) > 1024 ? "yes" : "no",
		publisher->writer_generation[0] ? publisher->writer_generation : "-",
		!publisher->enabled ? "not-registered" : s.blocked ? "fenced" : l.active ? "confirmed" : "unconfirmed",
		v2_control_name(s.control), phase, s.revision, l.revision, result,
		s.have_hb ? (long long)(unsigned int)(now_ms - s.last_hb) : -1LL,
		s.have_restore ? (long long)(unsigned int)(now_ms - s.last_restore) : -1LL,
		s.starts, s.restores, s.heartbeats, s.activations, s.barriers, s.failures, s.command_timeouts,
		l.count, s.initialized ? l.max_entries : 0, l.stats.states[GLB_NATIVE], l.untracked,
		l.dirty, l.next_id, l.stats.queued[0], l.stats.queued[1], l.stats.queued[2],
		v2_control_name(l.inflight ? l.inflight_op + 1 : 0), global_lb_cfg.reserve_timeout,
		global_lb_cfg.heartbeat_interval, global_lb_cfg.instance_timeout,
		global_lb_cfg.max_instances, global_lb_cfg.max_requests,
		publisher->shutdown >= 2 ? "complete" : publisher->shutdown ? "pending" : "running",
		publisher->cleanup[0] ? publisher->cleanup : "not-requested");
}

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
	ctx->next = 0;
	ctx->text = calloc(1, 4096);
	if (!ctx->text)
		return cli_err(appctx, "Failed to allocate Global LB status.\n");
	global_lb_publish_get_status(&status);
	if (global_lb_cfg.reservation_mode) {
		format_v2_status(ctx->text, 4096, &status);
		return 0;
	}
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
	/* UD-012 v2-r4: resumable output, also with tune.bufsize 1024. */
	while (ctx->text[ctx->next]) {
		size_t count = MIN(strlen(ctx->text + ctx->next), 256);
		chunk_printf(&trash, "%.*s", (int)count, ctx->text + ctx->next);
		if (applet_putchk(appctx, &trash) == -1) return 0;
		ctx->next += count;
	}
	return 1;
}

static void cli_io_release_show_global_lb_status(struct appctx *appctx)
{
	struct global_lb_status_cli_ctx *ctx = appctx->svcctx;
	free(ctx->text);
}

static int cli_parse_show_global_lb_reservations(char **args, char *payload,
		struct appctx *appctx, void *private)
{
	struct global_lb_status_cli_ctx *ctx;
	struct glb_ledger_status l;
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN)) return 1;
	if (*args[3]) return cli_err(appctx, "show global-lb reservations expects no arguments.\n");
	if (!global_lb_cfg.reservation_mode)
		return cli_err(appctx, "show global-lb reservations requires v2 reservation mode.\n");
	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	ctx->next = 0;
	ctx->text = calloc(1, 2048);
	if (!ctx->text) return cli_err(appctx, "Failed to allocate Global LB reservation status.\n");
	v2_ledger_status(&l);
	snprintf(ctx->text, 2048,
		"# v2 local metadata only; no live global count or store query\n"
		"entries: %zu\nwaiting: %zu\nready: %zu\nnative_slots: %zu\nfailed: %zu\ncleanup: %zu\n"
		"queued_reserve: %zu\nqueued_release: %zu\nqueued_cancel: %zu\ninflight: %s\n"
		"admitted: %" PRIu64 "\nreserve_confirmed: %" PRIu64 "\n"
		"release_confirmed: %" PRIu64 "\ncancel_confirmed: %" PRIu64 "\n"
		"abandoned_unsent: %" PRIu64 "\nabandoned_sent: %" PRIu64 "\n"
		"command_failures: %" PRIu64 "\nuntracked: %u\ndirty: %u\nterminal: %u\n",
		l.count, l.stats.states[GLB_WAIT], l.stats.states[GLB_READY], l.stats.states[GLB_NATIVE],
		l.stats.states[GLB_FAILED], l.stats.states[GLB_CLEANUP],
		l.stats.queued[0], l.stats.queued[1], l.stats.queued[2], v2_control_name(l.inflight ? l.inflight_op + 1 : 0),
		l.stats.admitted, l.stats.confirmed, l.stats.released, l.stats.cancelled,
		l.stats.abandoned_unsent, l.stats.abandoned_sent, l.stats.failures, l.untracked, l.dirty, l.terminal);
	return 0;
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
	if (global_lb_cfg.reservation_mode)
		return cli_err(appctx, "v2 uses atomic reservations, not a periodic Global Cache. Use show global-lb status or show global-lb reservations.\n");
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
	{ { "show", "global-lb", "reservations", NULL },
	  "show global-lb reservations             : dump read-only v2 local reservation metadata",
	  cli_parse_show_global_lb_reservations, cli_io_handler_show_global_lb_status,
	  cli_io_release_show_global_lb_status, NULL, ACCESS_LVL_ADMIN },
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
