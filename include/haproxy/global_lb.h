/*
 * include/haproxy/global_lb.h
 * Functions for optional Global LB support.
 *
 * Copyright 2026 nTels
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 */

#ifndef _HAPROXY_GLOBAL_LB_H
#define _HAPROXY_GLOBAL_LB_H

#include <stddef.h>

#include <haproxy/global_lb-t.h>

void global_lb_local_snapshot_init(struct global_lb_local_snapshot_ctx *ctx);
int global_lb_local_snapshot_current(struct global_lb_local_snapshot_ctx *ctx,
				     struct global_lb_local_entry *entry);
void global_lb_local_snapshot_advance(struct global_lb_local_snapshot_ctx *ctx);
void global_lb_local_snapshot_release(struct global_lb_local_snapshot_ctx *ctx);

void global_lb_absolute_snapshot_init(struct global_lb_absolute_snapshot *snapshot);
int global_lb_absolute_snapshot_capture(struct global_lb_absolute_snapshot *snapshot);
void global_lb_absolute_snapshot_release(struct global_lb_absolute_snapshot *snapshot);

int global_lb_format_endpoint(const struct global_lb_local_entry *entry,
			      char *endpoint, size_t endpoint_size);
int global_lb_format_absolute_endpoint(const struct global_lb_absolute_entry *entry,
				       char *endpoint, size_t endpoint_size);
const char *global_lb_oper_state_name(enum global_lb_oper_state state);

#endif /* _HAPROXY_GLOBAL_LB_H */
