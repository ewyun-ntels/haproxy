/* Optional Global LB storage protocol. Copyright 2026 nTels.
 * LGPL-2.1 exclusively.
 */
#ifndef _HAPROXY_GLOBAL_LB_STORE_H
#define _HAPROXY_GLOBAL_LB_STORE_H

#include <haproxy/global_lb_store-t.h>
#include <haproxy/global_lb_resp-t.h>

#ifdef USE_GLOBAL_LB
/* Format UUID v4 from 16 independently random bytes supplied by the caller.
 * Call once after worker creation, never on reconnect. This function does NOT
 * obtain entropy or install a worker startup hook. Sequence starts at zero.
 */
int global_lb_store_writer_init(struct global_lb_store_writer *writer,
				const unsigned char entropy[16]);
/* Reserve a new sequence for a fresh operation (including cleanup). Gaps are
 * allowed on capture/encode/send failure. Zero/overflow are never published.
 */
int global_lb_store_writer_next(struct global_lb_store_writer *writer);

/* malloc-owned key; free it. Hex encoding keeps pool/instance boundaries
 * unambiguous and makes a future prefix SCAN independent of glob characters.
 * owner=1 selects persistent metadata; owner=0 selects the expiring snapshot.
 */
enum global_lb_resp_error global_lb_store_key(const char *prefix,
		const char *instance_id, int owner, size_t max_bytes, char **key);

/* A fixed parameterized script, embedded in EVAL. No USE_LUA or installation. */
const char *global_lb_store_script(size_t *len);

/* Encode a complete RESP2 EVAL request. No I/O, no sequence mutation. Caller
 * frees *wire. Explicit max_bytes bounds encoded wire and temporary storage.
 * ttl_ms is 1..INT_MAX; DELETE requires no entries (TTL is validated but unused).
 * All keys/entries are borrowed only during this call. Failure sets NULL/0.
 */
enum global_lb_resp_error global_lb_store_encode(enum global_lb_store_op op,
		const char *prefix, const char *instance_id,
		const struct global_lb_store_writer *writer, unsigned int ttl_ms,
		const struct global_lb_store_entry *entries, size_t count,
		size_t max_bytes, unsigned char **wire, size_t *wire_len);

/* Accept only one completed integer reply in the defined application range.
 * RESP error replies and unexpected shapes are not successful commands.
 */
int global_lb_store_result(const struct global_lb_resp_parser *parser,
			   enum global_lb_store_result *result);
#endif
#endif
