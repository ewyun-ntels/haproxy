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

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/chunk.h>
#include <haproxy/cli.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>

struct global_lb_local_cli_ctx {
	struct global_lb_local_snapshot_ctx snapshot;
	unsigned int header_done;
};

static int cli_parse_show_global_lb_local(char **args, char *payload,
					  struct appctx *appctx, void *private)
{
	struct global_lb_local_cli_ctx *ctx;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	global_lb_local_snapshot_init(&ctx->snapshot);
	return 0;
}

static int cli_io_handler_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_cli_ctx *ctx = appctx->svcctx;
	struct global_lb_local_entry entry;
	char endpoint[INET6_ADDRSTRLEN + 16];

	if (!ctx->header_done) {
		chunk_printf(&trash,
		             "# backend\tserver\tendpoint\toper_state\tcur_sess\tserved\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;
		ctx->header_done = 1;
	}

	while (global_lb_local_snapshot_current(&ctx->snapshot, &entry)) {
		global_lb_format_endpoint(&entry, endpoint, sizeof(endpoint));
		chunk_printf(&trash, "%s\t%s\t%s\t%s\t%d\t%d\n",
		             entry.backend_name, entry.server_name, endpoint,
		             global_lb_oper_state_name(entry.oper_state),
		             entry.cur_sess, entry.served);
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		global_lb_local_snapshot_advance(&ctx->snapshot);
	}

	return 1;
}

static void cli_io_release_show_global_lb_local(struct appctx *appctx)
{
	struct global_lb_local_cli_ctx *ctx = appctx->svcctx;

	global_lb_local_snapshot_release(&ctx->snapshot);
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
