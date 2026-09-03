/*
 * include/haproxy/global_lb-t.h
 * Types for optional Global LB support.
 *
 * Copyright 2026 nTels
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 */

#ifndef _HAPROXY_GLOBAL_LB_T_H
#define _HAPROXY_GLOBAL_LB_T_H

#include <stddef.h>
#include <sys/socket.h>

#include <haproxy/list-t.h>

struct proxy;
struct server;

enum global_lb_oper_state {
	GLOBAL_LB_OPER_STOPPED = 0,
	GLOBAL_LB_OPER_STARTING,
	GLOBAL_LB_OPER_RUNNING,
	GLOBAL_LB_OPER_STOPPING,
	GLOBAL_LB_OPER_UNKNOWN,
};

/* One read-only local sample. Names remain valid until the iterator advances. */
struct global_lb_local_entry {
	const char *backend_name;
	const char *server_name;
	struct sockaddr_storage endpoint_addr;
	unsigned int endpoint_port;
	enum global_lb_oper_state oper_state;
	int cur_sess;
	int served;
};

/* Iterator state protected against runtime proxy/server deletion by watchers. */
struct global_lb_local_snapshot_ctx {
	struct proxy *px;
	struct server *srv;
	struct watcher px_watch;
	struct watcher srv_watch;
	unsigned int servers_attached;
};

/*
 * One entry owned by an absolute snapshot. endpoint_key is built only for a
 * resolved IP address and never contains the server-template slot name.
 * active_count is the authoritative local count copied from server.cur_sess.
 * served is diagnostic only.
 */
struct global_lb_absolute_entry {
	char *backend_name;
	char *server_name;
	char *endpoint_key;
	struct sockaddr_storage endpoint_addr;
	unsigned int endpoint_port;
	enum global_lb_oper_state oper_state;
	int active_count;
	int served;
};

/*
 * A materialized local snapshot. Entries and their strings remain valid until
 * the snapshot is replaced or released.
 */
struct global_lb_absolute_snapshot {
	struct global_lb_absolute_entry *entries;
	size_t count;
	size_t capacity;
};

#endif /* _HAPROXY_GLOBAL_LB_T_H */
