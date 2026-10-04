/* UD-011 v2-only-20261004. Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifndef _HAPROXY_GLOBAL_LB_STORE_H
#define _HAPROXY_GLOBAL_LB_STORE_H
#include <haproxy/global_lb_store-t.h>
#ifdef USE_GLOBAL_LB
/* Format UUID v4 from entropy supplied once at worker creation. */
int global_lb_store_writer_init(struct global_lb_store_writer *,
                               const unsigned char entropy[16]);
int global_lb_store_valid_uuid(const char *);
#endif
#endif
