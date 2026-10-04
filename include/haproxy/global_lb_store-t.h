/* UD-011 v2-only-20261004. Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_STORE_T_H
#define _HAPROXY_GLOBAL_LB_STORE_T_H
#ifdef USE_GLOBAL_LB
/* One worker UUID, generated after fork and retained across reconnects. */
struct global_lb_store_writer {
	char writer_generation[37];
};
#endif
#endif
