/* Global LB: parameterized Redis/Valkey storage protocol, no runtime hooks.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 * UD-007 r5-store-protocol-20260904 / UD-011 r3-sequenced-store-20260904.
 */
#ifdef USE_GLOBAL_LB
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>

/* KEYS: owner, snapshot. ARGV: operation, UUID, sequence, TTL, field/count...
 * Validate before writes; compare uint64 decimal strings without Lua doubles.
 * START intentionally replaces a different UUID: late initial registration is
 * an accepted v1 limitation (R2), NOT solved by the per-UUID sequence fence.
 */
static const char store_script[] =
"local function uint(s, zero, limit)\n"
"  if not s or not string.match(s, '^%d+$') then return false end\n"
"  if #s > 1 and string.sub(s, 1, 1) == '0' then return false end\n"
"  if not zero and s == '0' then return false end\n"
"  return #s < #limit or (#s == #limit and s <= limit)\n"
"end\n"
"local function uuid(s)\n"
"  if not s or #s ~= 36 then return false end\n"
"  for i = 1, 36 do\n"
"    local c = string.sub(s, i, i)\n"
"    if i == 9 or i == 14 or i == 19 or i == 24 then\n"
"      if c ~= '-' then return false end\n"
"    elseif not string.match(c, '^[0-9a-f]$') then return false end\n"
"  end\n"
"  return string.sub(s, 15, 15) == '4' and\n"
"    string.match(string.sub(s, 20, 20), '^[89ab]$') ~= nil\n"
"end\n"
"local max = '18446744073709551615'\n"
"if #KEYS ~= 2 or KEYS[1] == KEYS[2] or #KEYS[1] == 0 or #KEYS[2] == 0 then return -2 end\n"
"if #ARGV < 4 or (#ARGV - 4) % 2 ~= 0 then return -2 end\n"
"local op, gen, seq, ttl = ARGV[1], ARGV[2], ARGV[3], ARGV[4]\n"
"if op ~= 'start' and op ~= 'update' and op ~= 'delete' then return -2 end\n"
"if not uuid(gen) or not uint(seq, false, max) or not uint(ttl, false, '2147483647') then return -2 end\n"
"if op == 'delete' and #ARGV ~= 4 then return -2 end\n"
"local seen = {}\n"
"for i = 5, #ARGV, 2 do\n"
"  local field = ARGV[i]\n"
"  if #field <= 2 or string.sub(field, 1, 2) ~= 'c:' or seen[field] or\n"
"    not uint(ARGV[i+1], true, max) then return -2 end\n"
"  seen[field] = true\n"
"end\n"
"for i = 1, 2 do\n"
"  local t = redis.call('TYPE', KEYS[i]).ok\n"
"  if t ~= 'none' and t ~= 'hash' then return -3 end\n"
"end\n"
"local old = redis.call('HGET', KEYS[1], 'writer_generation')\n"
"local last = redis.call('HGET', KEYS[1], 'snapshot_sequence')\n"
"if redis.call('EXISTS', KEYS[1]) == 1 then\n"
"  if not uuid(old) or not uint(last, false, max) or\n"
"    redis.call('HLEN', KEYS[1]) ~= 2 or redis.call('PTTL', KEYS[1]) ~= -1 then return -3 end\n"
"end\n"
"if old and old ~= gen and op ~= 'start' then return -1 end\n"
"if old == gen and (#seq < #last or (#seq == #last and seq <= last)) then return 0 end\n"
"if not old and op == 'delete' then return 3 end\n"
"-- Sequence is kept even after cleanup or a failed snapshot write.\n"
"-- This is atomic execution, not rollback. Invalidate a failed replacement.\n"
"local ok, result = pcall(function()\n"
"  redis.call('HSET', KEYS[1], 'writer_generation', gen, 'snapshot_sequence', seq)\n"
"  redis.call('DEL', KEYS[2])\n"
"  if op == 'delete' then return 2 end\n"
"  redis.call('HSET', KEYS[2], 'writer_generation', gen, 'snapshot_sequence', seq)\n"
"  redis.call('PEXPIRE', KEYS[2], ttl)\n"
"  for i = 5, #ARGV, 2 do redis.call('HSET', KEYS[2], ARGV[i], ARGV[i+1]) end\n"
"  return 1\n"
"end)\n"
"if not ok then\n"
"  redis.pcall('DEL', KEYS[2])\n"
"  return redis.error_reply('ERR global-lb snapshot write failed')\n"
"end\n"
"return result\n";

static const char hex[] = "0123456789abcdef";

static int valid_uuid(const char *s)
{
	size_t i;

	if (!s || strlen(s) != 36)
		return 0;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (s[i] != '-')
				return 0;
		}
		else if (!strchr(hex, s[i]))
			return 0;
	}
	return s[14] == '4' && strchr("89ab", s[19]) != NULL;
}

int global_lb_store_writer_init(struct global_lb_store_writer *writer,
				const unsigned char entropy[16])
{
	unsigned char bytes[16];
	size_t i, pos = 0;

	if (!writer || !entropy)
		return 0;
	memcpy(bytes, entropy, sizeof(bytes));
	bytes[6] = (bytes[6] & 15) | 64;
	bytes[8] = (bytes[8] & 63) | 128;
	for (i = 0; i < sizeof(bytes); i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			writer->writer_generation[pos++] = '-';
		writer->writer_generation[pos++] = hex[bytes[i] >> 4];
		writer->writer_generation[pos++] = hex[bytes[i] & 15];
	}
	writer->writer_generation[pos] = 0;
	writer->snapshot_sequence = 0;
	return 1;
}

int global_lb_store_writer_next(struct global_lb_store_writer *writer)
{
	if (!writer || !memchr(writer->writer_generation, 0, 37) ||
	    !valid_uuid(writer->writer_generation) || writer->snapshot_sequence == UINT64_MAX)
		return 0;
	writer->snapshot_sequence++;
	return 1;
}

enum global_lb_resp_error global_lb_store_key(const char *prefix,
		const char *instance_id, int owner, size_t max_bytes, char **key)
{
	size_t a, b, len, i, pos;
	char *out;
	const char *suffix = owner ? ":owner" : ":snapshot";

	if (!key)
		return GLB_RESP_BADARG;
	*key = NULL;
	if (!prefix || !*prefix || !instance_id || !*instance_id || (owner != 0 && owner != 1))
		return GLB_RESP_BADARG;
	a = strlen(prefix);
	b = strlen(instance_id);
	if (a > (SIZE_MAX - 18) / 2 || b > (SIZE_MAX - 18) / 2 - a)
		return GLB_RESP_LIMIT;
	len = 7 + 2 * a + 1 + 2 * b + strlen(suffix);
	if (len >= max_bytes)
		return GLB_RESP_LIMIT;
	out = malloc(len + 1);
	if (!out)
		return GLB_RESP_NOMEM;
	memcpy(out, "glb:v1:", 7);
	pos = 7;
	for (i = 0; i < a; i++) {
		out[pos++] = hex[(unsigned char)prefix[i] >> 4];
		out[pos++] = hex[(unsigned char)prefix[i] & 15];
	}
	out[pos++] = ':';
	for (i = 0; i < b; i++) {
		out[pos++] = hex[(unsigned char)instance_id[i] >> 4];
		out[pos++] = hex[(unsigned char)instance_id[i] & 15];
	}
	memcpy(out + pos, suffix, strlen(suffix) + 1);
	*key = out;
	return GLB_RESP_OK;
}

const char *global_lb_store_script(size_t *len)
{
	if (len)
		*len = sizeof(store_script) - 1;
	return store_script;
}

static int compare_fields(const void *a, const void *b)
{
	const struct global_lb_resp_arg *x = a, *y = b;
	return strcmp(x->data, y->data);
}

enum global_lb_resp_error global_lb_store_encode(enum global_lb_store_op op,
		const char *prefix, const char *instance_id,
		const struct global_lb_store_writer *writer, unsigned int ttl_ms,
		const struct global_lb_store_entry *entries, size_t count,
		size_t max_bytes, unsigned char **wire, size_t *wire_len)
{
	static const char *ops[] = { "start", "update", "delete" };
	struct global_lb_resp_arg *args = NULL;
	char *owner = NULL, *snapshot = NULL, *data = NULL, *p;
	char seq[21], ttl[11];
	size_t i, n, total = 0, len;
	enum global_lb_resp_error err = GLB_RESP_BADARG;

	if (wire) *wire = NULL;
	if (wire_len) *wire_len = 0;
	if (!wire || !wire_len || !writer || !memchr(writer->writer_generation, 0, 37) ||
	    !valid_uuid(writer->writer_generation) || !writer->snapshot_sequence ||
	    (unsigned int)op > GLB_STORE_DELETE || !ttl_ms || ttl_ms > INT_MAX ||
	    (count && !entries) || (op == GLB_STORE_DELETE && count))
		return err;
	/* A wire cannot fit even the script, or the minimum field/value payload.
	 * Check before allocating per-row descriptors or dereferencing entries.
	 */
	if (max_bytes <= sizeof(store_script) || count > max_bytes / 24 ||
	    count > (SIZE_MAX / sizeof(*args) - 9) / 2)
		return GLB_RESP_LIMIT;
	n = 9 + 2 * count;
	for (i = 0; i < count; i++) {
		if (!entries[i].endpoint_key || !*entries[i].endpoint_key)
			return GLB_RESP_BADARG;
		len = strlen(entries[i].endpoint_key);
		if (len > max_bytes - 24 || total > max_bytes - 24 - len)
			return GLB_RESP_LIMIT;
		total += len + 24; /* c:field NUL + uint64 decimal NUL */
	}
	err = global_lb_store_key(prefix, instance_id, 1, max_bytes, &owner);
	if (err != GLB_RESP_OK)
		goto out;
	err = global_lb_store_key(prefix, instance_id, 0, max_bytes, &snapshot);
	if (err != GLB_RESP_OK)
		goto out;
	err = GLB_RESP_NOMEM;
	args = calloc(n, sizeof(*args));
	data = malloc(total ? total : 1);
	if (!args || !data)
		goto out;
	snprintf(seq, sizeof(seq), "%" PRIu64, writer->snapshot_sequence);
	snprintf(ttl, sizeof(ttl), "%u", ttl_ms);
	args[0].data = "EVAL";
	args[1].data = store_script;
	args[2].data = "2";
	args[3].data = owner;
	args[4].data = snapshot;
	args[5].data = ops[op];
	args[6].data = writer->writer_generation;
	args[7].data = seq;
	args[8].data = ttl;
	p = data;
	for (i = 0; i < count; i++) {
		len = strlen(entries[i].endpoint_key);
		args[9 + 2*i].data = p;
		memcpy(p, "c:", 2);
		memcpy(p + 2, entries[i].endpoint_key, len + 1);
		p += len + 3;
		args[10 + 2*i].data = p;
		p += snprintf(p, 21, "%" PRIu64, entries[i].active_count) + 1;
	}
	/* Sort whole field/value pairs, not just field descriptors. */
	if (count > 1)
		qsort(args + 9, count, 2 * sizeof(*args), compare_fields);
	for (i = 1; i < count; i++) {
		if (!strcmp(args[9 + 2*(i-1)].data, args[9 + 2*i].data)) {
			err = GLB_RESP_BADARG;
			goto out;
		}
	}
	for (i = 0; i < n; i++)
		args[i].len = strlen(args[i].data);
	err = global_lb_resp_encode(args, n, max_bytes, wire, wire_len);
out:
	free(data);
	free(args);
	free(snapshot);
	free(owner);
	return err;
}

int global_lb_store_result(const struct global_lb_resp_parser *parser,
			   enum global_lb_store_result *result)
{
	int64_t value;

	if (!parser || !result || parser->status != GLB_RESP_DONE ||
	    parser->count != 1 || !parser->nodes || parser->nodes[0].type != ':')
		return 0;
	value = parser->nodes[0].integer;
	if (value < GLB_STORE_CORRUPT || value > GLB_STORE_ABSENT)
		return 0;
	*result = (enum global_lb_store_result)value;
	return 1;
}
#endif /* USE_GLOBAL_LB */
