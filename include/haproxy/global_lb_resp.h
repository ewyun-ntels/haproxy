/* Optional Global LB RESP2 API. Copyright 2026 nTels.
 * Licensed under GNU LGPL version 2.1 exclusively.
 * UD-007 r4-resp2-codec-20260904, USE_GLOBAL_LB.
 */
#ifndef _HAPROXY_GLOBAL_LB_RESP_H
#define _HAPROXY_GLOBAL_LB_RESP_H
#ifdef USE_GLOBAL_LB

#include <haproxy/global_lb_resp-t.h>

/* Initialize fresh/unallocated storage. Returns 1 or 0 (invalid limits).
 * No allocations occur until feed. Release before reinitializing a live parser.
 */
int global_lb_resp_init(struct global_lb_resp_parser *p,
			const struct global_lb_resp_limits *limits);
/* Reset retains bounded allocations; release frees them and invalidates p. */
void global_lb_resp_reset(struct global_lb_resp_parser *p);
void global_lb_resp_release(struct global_lb_resp_parser *p);
/* Consume at most one reply. *consumed is exact, leaving trailing replies to
 * the caller. MORE means an incomplete frame, not an error or a zero count.
 * DONE/ERROR are sticky until reset. On EOF, MORE must be handled by the caller
 * as a truncated response. input may be NULL only if len==0. Input must not
 * alias parser-owned memory. Supply a valid consumed pointer.
 */
enum global_lb_resp_status global_lb_resp_feed(struct global_lb_resp_parser *p,
			const void *input, size_t len, size_t *consumed);
/* Binary-safe array-of-bulk-strings command encoder. On success caller owns
 * *output (free it) and *len. On failure output=NULL, len=0; no partial command.
 * Nonzero argc; NULL argument data only for an empty bulk string. max_bytes
 * caps encoded wire size. No implicit strlen or terminating NUL is added.
 */
enum global_lb_resp_error global_lb_resp_encode(const struct global_lb_resp_arg *args,
			size_t argc, size_t max_bytes, unsigned char **output, size_t *len);

#endif /* USE_GLOBAL_LB */
#endif /* _HAPROXY_GLOBAL_LB_RESP_H */
