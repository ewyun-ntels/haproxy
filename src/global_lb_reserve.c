/* UD-007/009/011 v2-r1-20261003. Pure Global reservation protocol helpers.
 * Copyright 2026 nTels. LGPL-2.1 exclusively. No runtime or stream hooks.
 */
#ifdef USE_GLOBAL_LB
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_reserve.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>
#include <haproxy/global_lb_reserve_script.h>

static const char hex[] = "0123456789abcdef";

static char *hex_token(const char *text, size_t max_bytes)
{
	size_t i, len;
	char *out;
	if (!text || !*text)
		return NULL;
	len = strlen(text);
	if (len > (SIZE_MAX - 1) / 2 || 2 * len >= max_bytes)
		return NULL;
	out = malloc(2 * len + 1);
	if (!out)
		return NULL;
	for (i = 0; i < len; i++) {
		out[2*i] = hex[(unsigned char)text[i] >> 4];
		out[2*i+1] = hex[(unsigned char)text[i] & 15];
	}
	out[2*len] = 0;
	return out;
}

enum global_lb_resp_error global_lb_reserve_key(const char *prefix,
		unsigned int index, size_t max_bytes, char **key)
{
	static const char *suffixes[] = { "owners", "liveness", "counts", "requests" };
	char *encoded;
	size_t len;
	if (!key)
		return GLB_RESP_BADARG;
	*key = NULL;
	if (!prefix || !*prefix || index >= 4)
		return GLB_RESP_BADARG;
	if (max_bytes < 20 || strlen(prefix) > (max_bytes - 20) / 2)
		return GLB_RESP_LIMIT;
	encoded = hex_token(prefix, max_bytes);
	if (!encoded)
		return GLB_RESP_NOMEM;
	len = 8 + strlen(encoded) + strlen(suffixes[index]);
	if (len >= max_bytes) {
		free(encoded);
		return GLB_RESP_LIMIT;
	}
	*key = malloc(len + 1);
	if (*key)
		snprintf(*key, len + 1, "glb:v2:%s:%s", encoded, suffixes[index]);
	free(encoded);
	return *key ? GLB_RESP_OK : GLB_RESP_NOMEM;
}

const char *global_lb_reserve_script(size_t *len)
{
	if (len) *len = sizeof(global_lb_reserve_lua) - 1;
	return global_lb_reserve_lua;
}

enum global_lb_resp_error global_lb_reserve_encode(
		const struct global_lb_reserve_command *c, size_t max_bytes,
		unsigned char **wire, size_t *wire_len)
{
	static const char *ops[] = { "start", "restore", "reserve", "release", "cancel", "heartbeat", "stop" };
	struct global_lb_resp_arg *args = NULL;
	char *keys[4] = { NULL }, *instance = NULL, *ids = NULL;
	char numbers[10][21];
	uint64_t values[10];
	size_t i, n, pos, service_len;
	int control, request;
	enum global_lb_resp_error err = GLB_RESP_BADARG;
	if (wire) *wire = NULL;
	if (wire_len) *wire_len = 0;
	if (!wire || !wire_len || !c || (unsigned int)c->op > GLB_RESERVE_STOP ||
	    !c->prefix || !*c->prefix || !c->instance_id || !*c->instance_id ||
	    !global_lb_store_valid_uuid(c->writer_generation) || !c->revision ||
	    !c->instance_timeout || c->instance_timeout > INT_MAX ||
	    !c->tie_seed || c->tie_seed > INT_MAX || !c->limits.instances ||
	    c->limits.instances > INT_MAX || !c->limits.count_fields || c->limits.count_fields > INT_MAX ||
	    !c->limits.requests || c->limits.requests > INT_MAX ||
	    (c->candidate_count && !c->candidates) || (c->entry_count && !c->entries))
		return err;
	control = c->op == GLB_RESERVE_START || c->op == GLB_RESERVE_RESTORE;
	request = c->op >= GLB_RESERVE_TAKE && c->op <= GLB_RESERVE_CANCEL;
	if ((request && !c->request_id) || (!request && c->request_id) ||
	    (!control && (c->entry_count || c->high_water)) ||
	    (c->op != GLB_RESERVE_TAKE && c->candidate_count) ||
	    (c->op == GLB_RESERVE_TAKE && (!c->candidate_count || !c->service_id || !*c->service_id)))
		return err;
	if (max_bytes <= sizeof(global_lb_reserve_lua) || c->candidate_count > max_bytes / 8 ||
	    c->entry_count > max_bytes / 24 || c->candidate_count > c->limits.count_fields ||
	    c->entry_count > c->limits.requests || c->candidate_count > INT_MAX || c->entry_count > INT_MAX)
		return GLB_RESP_LIMIT;
	if (strlen(c->instance_id) > (max_bytes - 1) / 2)
		return GLB_RESP_LIMIT;
	service_len = c->service_id ? strlen(c->service_id) : 0;
	for (i = 0; i < c->candidate_count; i++) {
		if (!c->candidates[i] || strncmp(c->candidates[i], c->service_id, service_len) ||
		    c->candidates[i][service_len] != '|' || !c->candidates[i][service_len+1])
			return GLB_RESP_BADARG;
	}
	for (i = 0; i < c->entry_count; i++) {
		const char *separator = c->entries[i].endpoint_key ? strchr(c->entries[i].endpoint_key, '|') : NULL;
		if (!c->entries[i].request_id || c->entries[i].request_id > c->high_water ||
		    !separator || separator == c->entries[i].endpoint_key || !separator[1])
			return GLB_RESP_BADARG;
	}
	n = 21 + c->candidate_count + 2 * c->entry_count;
	/* Earlier max_bytes division checks bound all descriptor arithmetic. */
	if (n > SIZE_MAX / sizeof(*args) || c->entry_count > SIZE_MAX / 21)
		return GLB_RESP_LIMIT;
	args = calloc(n, sizeof(*args));
	ids = malloc(c->entry_count ? c->entry_count * 21 : 1);
	instance = hex_token(c->instance_id, max_bytes);
	err = GLB_RESP_NOMEM;
	if (!args || !ids || !instance)
		goto out;
	for (i = 0; i < 4; i++) {
		err = global_lb_reserve_key(c->prefix, i, max_bytes, &keys[i]);
		if (err != GLB_RESP_OK) goto out;
	}
	args[0].data = "EVAL";
	args[1].data = global_lb_reserve_lua;
	args[2].data = "4";
	for (i = 0; i < 4; i++) args[3+i].data = keys[i];
	args[7].data = ops[c->op];
	args[8].data = instance;
	args[9].data = c->writer_generation;
	values[0] = c->revision; values[1] = c->request_id; values[2] = c->high_water;
	values[3] = c->instance_timeout; values[4] = c->tie_seed;
	values[5] = c->limits.instances; values[6] = c->limits.count_fields;
	values[7] = c->limits.requests; values[8] = c->candidate_count; values[9] = c->entry_count;
	for (i = 0; i < 10; i++) snprintf(numbers[i], sizeof(numbers[i]), "%" PRIu64, values[i]);
	for (i = 0; i < 8; i++) args[10+i].data = numbers[i];
	args[18].data = c->service_id ? c->service_id : "";
	args[19].data = numbers[8];
	pos = 20;
	for (i = 0; i < c->candidate_count; i++) args[pos++].data = c->candidates[i];
	args[pos++].data = numbers[9];
	for (i = 0; i < c->entry_count; i++) {
		snprintf(ids + 21*i, 21, "%" PRIu64, c->entries[i].request_id);
		args[pos++].data = ids + 21*i;
		args[pos++].data = c->entries[i].endpoint_key;
	}
	for (i = 0; i < n; i++) args[i].len = strlen(args[i].data);
	err = global_lb_resp_encode(args, n, max_bytes, wire, wire_len);
out:
	for (i = 0; i < 4; i++) free(keys[i]);
	free(instance); free(ids); free(args);
	return err;
}

int global_lb_reserve_result(const struct global_lb_resp_parser *p,
		struct global_lb_reserve_reply *r)
{
	const struct global_lb_resp_node *n;
	int64_t status;
	if (!p || !r || p->status != GLB_RESP_DONE || !p->nodes || !p->wire || p->count != 4)
		return 0;
	n = p->nodes;
	if (n[0].type != '*' || n[0].is_null || n[0].children != 3 || n[0].next != 4 ||
	    n[1].type != ':' || n[2].type != '$' || n[2].is_null || n[3].type != ':' ||
	    n[3].integer < 0 || n[2].offset > p->used || n[2].len > p->used - n[2].offset)
		return 0;
	status = n[1].integer;
	if (status < GLB_RESERVE_TERMINAL || status > GLB_RESERVE_ABSENT)
		return 0;
	r->status = (enum global_lb_reserve_status)status;
	r->endpoint = p->wire + n[2].offset;
	r->endpoint_len = n[2].len;
	r->count = n[3].integer;
	return 1;
}
#endif
