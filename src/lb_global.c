/*
 * Read-only local connection snapshot for optional Global LB support.
 *
 * Copyright 2026 nTels
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include <sys/socket.h>

#include <stdio.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/atomic.h>
#include <haproxy/chunk.h>
#include <haproxy/cli.h>
#include <haproxy/list.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/tools.h>

struct global_lb_local_ctx {
	struct proxy *px;
	struct server *srv;
	struct watcher px_watch;
	struct watcher srv_watch;
	unsigned int header_done;
};

static const char *global_lb_server_state(enum srv_state state)
{
	switch (state) {
	case SRV_ST_STOPPED:
		return "STOPPED";
	case SRV_ST_STARTING:
		return "STARTING";
	case SRV_ST_RUNNING:
		return "RUNNING";
	case SRV_ST_STOPPING:
		return "STOPPING";
	}

	return "UNKNOWN";
}

static void global_lb_format_endpoint(const struct server *srv, char *endpoint,
				      size_t endpoint_size)
{
	char addr[INET6_ADDRSTRLEN + 1];

	switch (addr_to_str(&srv->addr, addr, sizeof(addr))) {
	case AF_INET:
		snprintf(endpoint, endpoint_size, "%s:%u", addr, srv->svc_port);
		break;
	case AF_INET6:
		snprintf(endpoint, endpoint_size, "[%s]:%u", addr, srv->svc_port);
		break;
	default:
		snprintf(endpoint, endpoint_size, "-");
		break;
	}
}

static int cli_parse_show_global_lb_local(char **args, char *payload,
					  struct appctx *appctx, void *private)
{
	struct global_lb_local_ctx *ctx;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	watcher_init(&ctx->px_watch, &ctx->px,
		     offsetof(struct proxy, watcher_list));
	watcher_init(&ctx->srv_watch, &ctx->srv,
		     offsetof(struct server, watcher_list));
	return 0;
}

static int cli_io_handler_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_ctx *ctx = appctx->svcctx;
	struct proxy *px;
	struct server *srv;
	char endpoint[INET6_ADDRSTRLEN + 16];

	if (!ctx->header_done) {
		chunk_printf(&trash,
		             "# backend\tserver\tendpoint\toper_state\tcur_sess\tserved\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		ctx->header_done = 1;
		watcher_attach(&ctx->px_watch, proxies_list);
	}

	for (; ctx->px; watcher_next(&ctx->px_watch, ctx->px->next)) {
		px = ctx->px;

		if ((px->cap & (PR_CAP_BE | PR_CAP_INT)) != PR_CAP_BE)
			continue;

		if (!ctx->srv)
			watcher_attach(&ctx->srv_watch, px->srv);

		for (; ctx->srv; watcher_next(&ctx->srv_watch, ctx->srv->next)) {
			srv = ctx->srv;
			global_lb_format_endpoint(srv, endpoint, sizeof(endpoint));

			chunk_printf(&trash, "%s\t%s\t%s\t%s\t%d\t%d\n",
			             px->id, srv->id, endpoint,
			             global_lb_server_state(srv->cur_state),
			             _HA_ATOMIC_LOAD(&srv->cur_sess),
			             _HA_ATOMIC_LOAD(&srv->served));
			if (applet_putchk(appctx, &trash) == -1)
				return 0;
		}
	}

	return 1;
}

static void cli_io_release_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_ctx *ctx = appctx->svcctx;

	watcher_detach(&ctx->px_watch);
	watcher_detach(&ctx->srv_watch);
}

static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "global-lb", "local", NULL },
	  "show global-lb local                    : dump the read-only local backend connection snapshot",
	  cli_parse_show_global_lb_local,
	  cli_io_handler_show_global_lb_local,
	  cli_io_release_show_global_lb_local,
	  NULL, ACCESS_LVL_ADMIN },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
