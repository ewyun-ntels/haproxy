/* Complete Redis/Valkey snapshot collection and immutable cache publication.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 * UD-008 r2-global-cache-20260908, USE_GLOBAL_LEASTCONN.
 * This module does not select servers or implement stale/recovery policy.
 */
#ifdef USE_GLOBAL_LEASTCONN
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/global_lb_collect.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>
#include <haproxy/thread.h>

#define GLB_CACHE_BUCKETS 8192

struct glb_cache_entry {
	char *key;
	uint64_t global_count;
	uint64_t own_count;
	int next;
};

struct glb_cache_buffer {
	struct glb_cache_entry *entries;
	int *buckets;
	size_t count;
};

struct glb_seen_key {
	char *key;
	size_t len;
	uint64_t hash;
};

enum glb_collect_state {
	GLB_COLLECT_IDLE,
	GLB_COLLECT_SCAN,
	GLB_COLLECT_HGETALL,
};

static struct {
	struct glb_cache_buffer buffers[2];
	struct glb_cache_buffer *active;
	unsigned int valid;
	unsigned int completed_at;
	uint64_t version;
	HA_RWLOCK_T lock;
} cache;

static struct {
	enum glb_collect_state state;
	struct glb_cache_buffer *staging;
	struct glb_seen_key *keys;
	size_t key_count, key_capacity, key_index;
	size_t *seen_slots;
	size_t seen_capacity;
	char *pattern;
	char *self_key;
	char expected_generation[37];
	uint64_t expected_sequence;
	char cursor[21];
	size_t command_limit;
	unsigned int self_seen;
} collector;

static uint64_t glb_hash(const void *data, size_t len)
{
	const unsigned char *p = data;
	uint64_t hash = UINT64_C(1469598103934665603);

	while (len--)
		hash = (hash ^ *p++) * UINT64_C(1099511628211);
	return hash;
}

static int node_is(const struct global_lb_resp_parser *reply, size_t index,
		   char type, const char *text)
{
	const struct global_lb_resp_node *node;
	size_t len = strlen(text);

	if (!reply || index >= reply->count)
		return 0;
	node = &reply->nodes[index];
	return node->type == type && !node->is_null && node->len == len &&
	       !memcmp(reply->wire + node->offset, text, len);
}

static int parse_uint64_node(const struct global_lb_resp_parser *reply,
			     size_t index, int allow_zero, uint64_t *value)
{
	const struct global_lb_resp_node *node;
	uint64_t n = 0;
	size_t i;

	if (!reply || !value || index >= reply->count)
		return 0;
	node = &reply->nodes[index];
	if (node->type != '$' || node->is_null || !node->len || node->len > 20)
		return 0;
	if (node->len > 1 && reply->wire[node->offset] == '0')
		return 0;
	for (i = 0; i < node->len; i++) {
		unsigned int digit = reply->wire[node->offset + i] - '0';
		if (digit > 9 || n > (UINT64_MAX - digit) / 10)
			return 0;
		n = n * 10 + digit;
	}
	if (!allow_zero && !n)
		return 0;
	*value = n;
	return 1;
}

static void cache_buffer_reset(struct glb_cache_buffer *buffer)
{
	size_t i;

	if (!buffer)
		return;
	for (i = 0; i < buffer->count; i++) {
		free(buffer->entries[i].key);
		buffer->entries[i].key = NULL;
		buffer->entries[i].global_count = 0;
		buffer->entries[i].own_count = 0;
		buffer->entries[i].next = -1;
	}
	buffer->count = 0;
	if (buffer->buckets)
		memset(buffer->buckets, 0xff, GLB_CACHE_BUCKETS * sizeof(*buffer->buckets));
}

static int cache_buffer_add(struct glb_cache_buffer *buffer, const char *key,
			    size_t len, uint64_t count, int own)
{
	uint64_t hash = glb_hash(key, len);
	unsigned int bucket = hash % GLB_CACHE_BUCKETS;
	struct glb_cache_entry *entry;
	int index;

	for (index = buffer->buckets[bucket]; index >= 0; index = entry->next) {
		entry = &buffer->entries[index];
		if (strlen(entry->key) == len && !memcmp(entry->key, key, len))
			goto found;
	}
	if (buffer->count == GLB_COLLECT_MAX_ENDPOINTS)
		return -1;
	entry = &buffer->entries[buffer->count];
	entry->key = malloc(len + 1);
	if (!entry->key)
		return 0;
	memcpy(entry->key, key, len);
	entry->key[len] = 0;
	entry->global_count = 0;
	entry->own_count = 0;
	entry->next = buffer->buckets[bucket];
	buffer->buckets[bucket] = buffer->count++;

 found:
	if (UINT64_MAX - entry->global_count < count ||
	    (own && UINT64_MAX - entry->own_count < count))
		return -1;
	entry->global_count += count;
	if (own)
		entry->own_count += count;
	return 1;
}

static struct glb_cache_entry *cache_buffer_find(struct glb_cache_buffer *buffer,
						 const char *key)
{
	uint64_t hash;
	int index;

	if (!buffer || !key)
		return NULL;
	hash = glb_hash(key, strlen(key));
	for (index = buffer->buckets[hash % GLB_CACHE_BUCKETS]; index >= 0;
	     index = buffer->entries[index].next) {
		if (!strcmp(buffer->entries[index].key, key))
			return &buffer->entries[index];
	}
	return NULL;
}

static void seen_reset(void)
{
	size_t i;

	for (i = 0; i < collector.key_count; i++)
		free(collector.keys[i].key);
	free(collector.keys);
	free(collector.seen_slots);
	collector.keys = NULL;
	collector.seen_slots = NULL;
	collector.key_count = collector.key_capacity = collector.key_index = 0;
	collector.seen_capacity = 0;
}

static int seen_rehash(size_t capacity)
{
	size_t *slots;
	size_t i, pos;

	slots = calloc(capacity, sizeof(*slots));
	if (!slots)
		return 0;
	for (i = 0; i < collector.key_count; i++) {
		pos = collector.keys[i].hash & (capacity - 1);
		while (slots[pos])
			pos = (pos + 1) & (capacity - 1);
		slots[pos] = i + 1;
	}
	free(collector.seen_slots);
	collector.seen_slots = slots;
	collector.seen_capacity = capacity;
	return 1;
}

static int seen_append(const char *key, size_t len)
{
	struct glb_seen_key *keys;
	uint64_t hash = glb_hash(key, len);
	size_t pos, index, capacity;
	char *copy;

	if (!collector.seen_capacity && !seen_rehash(64))
		return 0;
	if ((collector.key_count + 1) * 2 >= collector.seen_capacity &&
	    !seen_rehash(collector.seen_capacity * 2))
		return 0;
	pos = hash & (collector.seen_capacity - 1);
	while ((index = collector.seen_slots[pos]) != 0) {
		if (collector.keys[index - 1].hash == hash &&
		    collector.keys[index - 1].len == len &&
		    !memcmp(collector.keys[index - 1].key, key, len))
			return 1; /* SCAN may legally return duplicates. */
		pos = (pos + 1) & (collector.seen_capacity - 1);
	}
	if (collector.key_count == collector.key_capacity) {
		capacity = collector.key_capacity ? collector.key_capacity * 2 : 32;
		if (capacity < collector.key_capacity ||
		    capacity > SIZE_MAX / sizeof(*collector.keys))
			return 0;
		keys = realloc(collector.keys, capacity * sizeof(*keys));
		if (!keys)
			return 0;
		collector.keys = keys;
		collector.key_capacity = capacity;
	}
	copy = malloc(len + 1);
	if (!copy)
		return 0;
	memcpy(copy, key, len);
	copy[len] = 0;
	collector.keys[collector.key_count] = (struct glb_seen_key){ copy, len, hash };
	collector.seen_slots[pos] = ++collector.key_count;
	return 1;
}

static enum global_lb_resp_error encode_command(const char **values, size_t count,
						 unsigned char **wire, size_t *wire_len)
{
	struct global_lb_resp_arg args[6];
	size_t i;

	if (count > sizeof(args) / sizeof(args[0]))
		return GLB_RESP_BADARG;
	for (i = 0; i < count; i++) {
		args[i].data = values[i];
		args[i].len = strlen(values[i]);
	}
	return global_lb_resp_encode(args, count, collector.command_limit, wire, wire_len);
}

static enum global_lb_collect_result encode_scan(unsigned char **wire, size_t *wire_len)
{
	const char *args[] = { "SCAN", collector.cursor, "MATCH", collector.pattern,
			       "COUNT", "32" };

	collector.state = GLB_COLLECT_SCAN;
	return encode_command(args, 6, wire, wire_len) == GLB_RESP_OK ?
	       GLB_COLLECT_NEXT : GLB_COLLECT_ERROR;
}

static enum global_lb_collect_result encode_hgetall(unsigned char **wire, size_t *wire_len)
{
	const char *args[] = { "HGETALL", collector.keys[collector.key_index].key };

	collector.state = GLB_COLLECT_HGETALL;
	return encode_command(args, 2, wire, wire_len) == GLB_RESP_OK ?
	       GLB_COLLECT_NEXT : GLB_COLLECT_ERROR;
}

static int valid_snapshot_key(const unsigned char *key, size_t len)
{
	const char *star = strchr(collector.pattern, '*');
	size_t head = star - collector.pattern;
	const char *suffix = ":snapshot";
	size_t tail = strlen(suffix), i;

	if (len <= head + tail || memcmp(key, collector.pattern, head) ||
	    memcmp(key + len - tail, suffix, tail) || (len - head - tail) % 2)
		return 0;
	for (i = head; i < len - tail; i++)
		if (!((key[i] >= '0' && key[i] <= '9') ||
		      (key[i] >= 'a' && key[i] <= 'f')))
			return 0;
	return 1;
}

static int parse_scan(const struct global_lb_resp_parser *reply)
{
	const struct global_lb_resp_node *root, *cursor, *keys, *key;
	uint64_t cursor_value;
	size_t i;

	if (!reply || reply->status != GLB_RESP_DONE || reply->count < 3)
		return 0;
	root = &reply->nodes[0];
	cursor = &reply->nodes[1];
	keys = &reply->nodes[2];
	if (root->type != '*' || root->is_null || root->children != 2 ||
	    root->next != reply->count || cursor->type != '$' || cursor->is_null ||
	    keys->type != '*' || keys->is_null || keys->next != reply->count ||
	    !parse_uint64_node(reply, 1, 1, &cursor_value))
		return 0;
	if (cursor->len >= sizeof(collector.cursor))
		return 0;
	(void)cursor_value;
	memcpy(collector.cursor, reply->wire + cursor->offset, cursor->len);
	collector.cursor[cursor->len] = 0;
	for (i = 0; i < keys->children; i++) {
		key = &reply->nodes[3 + i];
		if (key->type != '$' || key->is_null || key->next != 4 + i ||
		    !valid_snapshot_key(reply->wire + key->offset, key->len) ||
		    !seen_append((const char *)reply->wire + key->offset, key->len))
			return 0;
	}
	return 3 + keys->children == reply->count;
}

static int parse_snapshot(const struct global_lb_resp_parser *reply,
			  const struct glb_seen_key *snapshot, int *limit)
{
	const struct global_lb_resp_node *root, *field, *value;
	char generation[37] = { 0 };
	uint64_t sequence = 0, count;
	size_t i;
	int have_generation = 0, have_sequence = 0, own;

	*limit = 0;
	if (!reply || reply->status != GLB_RESP_DONE || !reply->count)
		return 0;
	root = &reply->nodes[0];
	if (root->type != '*' || root->is_null || root->next != reply->count ||
	    root->children % 2 || root->children + 1 != reply->count)
		return 0;
	/* A key may expire after SCAN. It contributes nothing, except our just
	 * published snapshot which is required to prove this cycle complete.
	 */
	own = snapshot->len == strlen(collector.self_key) &&
	      !memcmp(snapshot->key, collector.self_key, snapshot->len);
	if (!root->children)
		return own ? 0 : 1;
	for (i = 1; i < reply->count; i += 2) {
		field = &reply->nodes[i];
		value = &reply->nodes[i + 1];
		if (field->type != '$' || field->is_null || value->type != '$' || value->is_null)
			return 0;
		if (node_is(reply, i, '$', "writer_generation")) {
			if (have_generation || value->len != 36)
				return 0;
			memcpy(generation, reply->wire + value->offset, 36);
			if (!global_lb_store_valid_uuid(generation))
				return 0;
			have_generation = 1;
		}
		else if (node_is(reply, i, '$', "snapshot_sequence")) {
			if (have_sequence || !parse_uint64_node(reply, i + 1, 0, &sequence))
				return 0;
			have_sequence = 1;
		}
		else if (field->len > 2 &&
			 reply->wire[field->offset] == 'c' &&
			 reply->wire[field->offset + 1] == ':') {
			int added;
			if (field->len - 2 >= 1024 ||
			    !parse_uint64_node(reply, i + 1, 1, &count))
				return 0;
			added = cache_buffer_add(collector.staging,
				(const char *)reply->wire + field->offset + 2,
				field->len - 2, count, own);
			if (added <= 0) {
				*limit = added < 0;
				return 0;
			}
		}
		else
			return 0;
	}
	if (!have_generation || !have_sequence)
		return 0;
	if (own) {
		if (strcmp(generation, collector.expected_generation) ||
		    sequence != collector.expected_sequence)
			return 0;
		collector.self_seen = 1;
	}
	return 1;
}

static void publish_cache(unsigned int completed_at)
{
	struct glb_cache_buffer *old;

	HA_RWLOCK_WRLOCK(OTHER_LOCK, &cache.lock);
	old = cache.active;
	cache.active = collector.staging;
	cache.valid = 1;
	cache.completed_at = completed_at;
	cache.version++;
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &cache.lock);
	collector.staging = old;
	cache_buffer_reset(collector.staging);
}

static void collector_reset(void)
{
	collector.state = GLB_COLLECT_IDLE;
	collector.expected_generation[0] = 0;
	collector.expected_sequence = 0;
	collector.cursor[0] = '0';
	collector.cursor[1] = 0;
	collector.self_seen = 0;
	cache_buffer_reset(collector.staging);
	seen_reset();
}

int global_lb_collect_init(const char *prefix, const char *instance_id,
			   size_t command_limit)
{
	static const char hex[] = "0123456789abcdef";
	size_t prefix_len, pattern_len, i, pos;

	if (!prefix || !*prefix || !instance_id || !*instance_id || !command_limit ||
	    collector.pattern || cache.buffers[0].entries)
		return 0;
	prefix_len = strlen(prefix);
	if (prefix_len > (SIZE_MAX - 19) / 2)
		return 0;
	pattern_len = 7 + 2 * prefix_len + 1 + 1 + strlen(":snapshot");
	collector.pattern = malloc(pattern_len + 1);
	if (!collector.pattern)
		return 0;
	memcpy(collector.pattern, "glb:v1:", 7);
	pos = 7;
	for (i = 0; i < prefix_len; i++) {
		collector.pattern[pos++] = hex[(unsigned char)prefix[i] >> 4];
		collector.pattern[pos++] = hex[(unsigned char)prefix[i] & 15];
	}
	memcpy(collector.pattern + pos, ":*:snapshot", 12);
	if (global_lb_store_key(prefix, instance_id, 0, command_limit,
				&collector.self_key) != GLB_RESP_OK)
		goto fail;
	for (i = 0; i < 2; i++) {
		cache.buffers[i].entries = calloc(GLB_COLLECT_MAX_ENDPOINTS,
						  sizeof(*cache.buffers[i].entries));
		cache.buffers[i].buckets = malloc(GLB_CACHE_BUCKETS *
						 sizeof(*cache.buffers[i].buckets));
		if (!cache.buffers[i].entries || !cache.buffers[i].buckets)
			goto fail;
		cache_buffer_reset(&cache.buffers[i]);
	}
	HA_RWLOCK_INIT(&cache.lock);
	cache.active = &cache.buffers[0];
	collector.staging = &cache.buffers[1];
	collector.command_limit = command_limit;
	collector_reset();
	return 1;

 fail:
	global_lb_collect_deinit();
	return 0;
}

void global_lb_collect_deinit(void)
{
	size_t i;

	seen_reset();
	for (i = 0; i < 2; i++) {
		cache_buffer_reset(&cache.buffers[i]);
		free(cache.buffers[i].entries);
		free(cache.buffers[i].buckets);
		memset(&cache.buffers[i], 0, sizeof(cache.buffers[i]));
	}
	if (cache.active)
		HA_RWLOCK_DESTROY(&cache.lock);
	free(collector.pattern);
	free(collector.self_key);
	memset(&cache, 0, sizeof(cache));
	memset(&collector, 0, sizeof(collector));
}

enum global_lb_collect_result global_lb_collect_start(
		const struct global_lb_store_writer *writer,
		unsigned char **wire, size_t *wire_len)
{
	if (wire) *wire = NULL;
	if (wire_len) *wire_len = 0;
	if (!wire || !wire_len || !collector.pattern || !writer ||
	    !global_lb_store_valid_uuid(writer->writer_generation) ||
	    !writer->snapshot_sequence)
		return GLB_COLLECT_ERROR;
	collector_reset();
	memcpy(collector.expected_generation, writer->writer_generation, 37);
	collector.expected_sequence = writer->snapshot_sequence;
	return encode_scan(wire, wire_len);
}

enum global_lb_collect_result global_lb_collect_reply(
		const struct global_lb_resp_parser *reply, unsigned int completed_at,
		unsigned char **wire, size_t *wire_len)
{
	enum global_lb_collect_result result;
	int limit = 0;

	if (wire) *wire = NULL;
	if (wire_len) *wire_len = 0;
	if (!wire || !wire_len || collector.state == GLB_COLLECT_IDLE)
		return GLB_COLLECT_ERROR;
	if (collector.state == GLB_COLLECT_SCAN) {
		if (!parse_scan(reply))
			goto error;
	}
	else {
		if (collector.key_index >= collector.key_count ||
		    !parse_snapshot(reply, &collector.keys[collector.key_index], &limit)) {
			if (limit)
				goto limit;
			goto error;
		}
		collector.key_index++;
	}
	if (collector.key_index < collector.key_count) {
		result = encode_hgetall(wire, wire_len);
		if (result != GLB_COLLECT_NEXT)
			goto error;
		return result;
	}
	if (strcmp(collector.cursor, "0")) {
		result = encode_scan(wire, wire_len);
		if (result != GLB_COLLECT_NEXT)
			goto error;
		return result;
	}
	if (!collector.self_seen)
		goto error;
	publish_cache(completed_at);
	seen_reset();
	collector.state = GLB_COLLECT_IDLE;
	return GLB_COLLECT_COMPLETE;

 limit:
	global_lb_collect_invalidate();
	return GLB_COLLECT_LIMIT;
 error:
	global_lb_collect_abort();
	return GLB_COLLECT_ERROR;
}

void global_lb_collect_abort(void)
{
	if (collector.staging)
		collector_reset();
}

void global_lb_collect_invalidate(void)
{
	global_lb_collect_abort();
	HA_RWLOCK_WRLOCK(OTHER_LOCK, &cache.lock);
	cache.valid = 0;
	HA_RWLOCK_WRUNLOCK(OTHER_LOCK, &cache.lock);
}

int global_lb_cache_lookup(const char *endpoint_key,
			   struct global_lb_cache_value *value)
{
	struct glb_cache_entry *entry;

	if (!value)
		return 0;
	memset(value, 0, sizeof(*value));
	if (!endpoint_key || !cache.active)
		return 0;
	HA_RWLOCK_RDLOCK(OTHER_LOCK, &cache.lock);
	if (!cache.valid) {
		HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &cache.lock);
		return 0;
	}
	value->version = cache.version;
	value->completed_at = cache.completed_at;
	value->endpoint_count = cache.active->count;
	entry = cache_buffer_find(cache.active, endpoint_key);
	if (entry) {
		value->global_count = entry->global_count;
		value->own_count = entry->own_count;
		value->found = 1;
	}
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &cache.lock);
	return 1;
}

void global_lb_cache_get_status(struct global_lb_cache_status *status)
{
	if (!status)
		return;
	memset(status, 0, sizeof(*status));
	if (!cache.active)
		return;
	HA_RWLOCK_RDLOCK(OTHER_LOCK, &cache.lock);
	status->valid = cache.valid;
	status->version = cache.version;
	status->completed_at = cache.completed_at;
	status->endpoint_count = cache.active->count;
	HA_RWLOCK_RDUNLOCK(OTHER_LOCK, &cache.lock);
}
#endif /* USE_GLOBAL_LEASTCONN */
