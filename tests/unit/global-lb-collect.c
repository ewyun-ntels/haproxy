/* UD-008 r2-global-cache-20260908. Pure collector/cache unit test. */
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/global_lb_collect.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>

struct text {
	char *area;
	size_t len, size;
};

static void add(struct text *text, const char *format, ...)
{
	va_list args;
	int needed;

	for (;;) {
		va_start(args, format);
		needed = vsnprintf(text->area ? text->area + text->len : NULL,
				   text->size - text->len, format, args);
		va_end(args);
		assert(needed >= 0);
		if ((size_t)needed < text->size - text->len) {
			text->len += needed;
			return;
		}
		text->size = text->size ? text->size * 2 : 1024;
		while (text->size <= text->len + (size_t)needed)
			text->size *= 2;
		text->area = realloc(text->area, text->size);
		assert(text->area);
	}
}

static void bulk(struct text *text, const char *value)
{
	add(text, "$%zu\r\n%s\r\n", strlen(value), value);
}

static struct global_lb_resp_parser parse(const void *wire, size_t len)
{
	struct global_lb_resp_parser parser;
	struct global_lb_resp_limits limits = {
		GLB_COLLECT_REPLY_BYTES, GLB_COLLECT_REPLY_NODES,
		GLB_COLLECT_REPLY_DEPTH,
	};
	size_t used;

	assert(global_lb_resp_init(&parser, &limits));
	assert(global_lb_resp_feed(&parser, wire, len, &used) == GLB_RESP_DONE);
	assert(used == len);
	return parser;
}

static void node_text(const struct global_lb_resp_parser *parser,
		      size_t index, const char *expected)
{
	const struct global_lb_resp_node *node = &parser->nodes[index];
	assert(node->type == '$' && !node->is_null);
	assert(node->len == strlen(expected));
	assert(!memcmp(parser->wire + node->offset, expected, node->len));
}

static void command(unsigned char *wire, size_t len, const char **args, size_t count)
{
	struct global_lb_resp_parser parser = parse(wire, len);
	size_t i;

	assert(parser.nodes[0].type == '*' && parser.nodes[0].children == count);
	assert(parser.count == count + 1);
	for (i = 0; i < count; i++)
		node_text(&parser, i + 1, args[i]);
	global_lb_resp_release(&parser);
	free(wire);
}

static struct global_lb_resp_parser scan_reply(const char *cursor,
						 const char **keys, size_t count)
{
	struct text text = { 0 };
	size_t i;

	add(&text, "*2\r\n");
	bulk(&text, cursor);
	add(&text, "*%zu\r\n", count);
	for (i = 0; i < count; i++)
		bulk(&text, keys[i]);
	{
		struct global_lb_resp_parser parser = parse(text.area, text.len);
		free(text.area);
		return parser;
	}
}

static struct global_lb_resp_parser snapshot_reply(const char *generation,
						     uint64_t sequence,
						     const char **keys,
						     const uint64_t *counts,
						     size_t count)
{
	struct text text = { 0 };
	size_t i;

	add(&text, "*%zu\r\n", 4 + 2 * count);
	bulk(&text, "writer_generation");
	bulk(&text, generation);
	bulk(&text, "snapshot_sequence");
	{
		char value[21];
		snprintf(value, sizeof(value), "%" PRIu64, sequence);
		bulk(&text, value);
	}
	for (i = 0; i < count; i++) {
		char field[1100], value[21];
		snprintf(field, sizeof(field), "c:%s", keys[i]);
		snprintf(value, sizeof(value), "%" PRIu64, counts[i]);
		bulk(&text, field);
		bulk(&text, value);
	}
	{
		struct global_lb_resp_parser parser = parse(text.area, text.len);
		free(text.area);
		return parser;
	}
}

static struct global_lb_resp_parser empty_snapshot(void)
{
	return parse("*0\r\n", 4);
}

static enum global_lb_collect_result reply(struct global_lb_resp_parser *parser,
						    unsigned int now,
						    unsigned char **wire,
						    size_t *wire_len)
{
	enum global_lb_collect_result result =
		global_lb_collect_reply(parser, now, wire, wire_len);
	global_lb_resp_release(parser);
	return result;
}

static void complete_empty(struct global_lb_store_writer *writer,
			   const char *self, unsigned int now)
{
	struct global_lb_resp_parser parser;
	unsigned char *wire;
	size_t wire_len;
	const char *keys[] = { self };

	assert(global_lb_collect_start(writer, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	parser = scan_reply("0", keys, 1);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	parser = snapshot_reply(writer->writer_generation, writer->snapshot_sequence,
				NULL, NULL, 0);
	assert(reply(&parser, now, &wire, &wire_len) == GLB_COLLECT_COMPLETE);
	assert(!wire && !wire_len);
}

int main(void)
{
	const char generation[] = "00000000-0000-4000-8000-000000000000";
	const char peer_generation[] = "11111111-1111-4111-8111-111111111111";
	struct global_lb_store_writer writer;
	struct global_lb_resp_parser parser;
	struct global_lb_cache_value value;
	struct global_lb_cache_status status;
	unsigned char *wire;
	size_t wire_len, i;
	char *self, *peer, *expired;
	const char *scan_args[6], *hgetall_args[2];
	const char *keys[3];
	const char *self_endpoints[] = { "be|10.0.0.1:5000", "be|10.0.0.2:5000" };
	const uint64_t self_counts[] = { 2, 1 };
	const char *peer_endpoints[] = { "be|10.0.0.1:5000", "be|10.0.0.3:5000" };
	const uint64_t peer_counts[] = { 3, 4 };

	memcpy(writer.writer_generation, generation, sizeof(generation));
	writer.snapshot_sequence = 10;
	assert(global_lb_collect_init("pool", "ha-0", 8U * 1024U * 1024U,
				      3000, 1));
	assert(global_lb_store_key("pool", "ha-0", 0, 1024, &self) == GLB_RESP_OK);
	assert(global_lb_store_key("pool", "ha-1", 0, 1024, &peer) == GLB_RESP_OK);
	assert(global_lb_store_key("pool", "ha-2", 0, 1024, &expired) == GLB_RESP_OK);

	assert(global_lb_collect_start(&writer, &wire, &wire_len) == GLB_COLLECT_NEXT);
	scan_args[0] = "SCAN"; scan_args[1] = "0"; scan_args[2] = "MATCH";
	scan_args[3] = "glb:v1:706f6f6c:*:snapshot";
	scan_args[4] = "COUNT"; scan_args[5] = "32";
	command(wire, wire_len, scan_args, 6);

	keys[0] = self; keys[1] = peer;
	parser = scan_reply("7", keys, 2);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	hgetall_args[0] = "HGETALL"; hgetall_args[1] = self;
	command(wire, wire_len, hgetall_args, 2);
	parser = snapshot_reply(generation, 10, self_endpoints, self_counts, 2);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	hgetall_args[1] = peer;
	command(wire, wire_len, hgetall_args, 2);
	parser = snapshot_reply(peer_generation, 99, peer_endpoints, peer_counts, 2);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	scan_args[1] = "7";
	command(wire, wire_len, scan_args, 6);

	/* Duplicate peer is skipped; an expired non-self key contributes zero. */
	keys[0] = peer; keys[1] = expired;
	parser = scan_reply("0", keys, 2);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	hgetall_args[1] = expired;
	command(wire, wire_len, hgetall_args, 2);
	parser = empty_snapshot();
	assert(reply(&parser, 1234, &wire, &wire_len) == GLB_COLLECT_COMPLETE);
	assert(!wire && !wire_len);
	assert(global_lb_cache_lookup("be|10.0.0.1:5000", 1234, &value));
	assert(value.found && value.global_count == 5 && value.own_count == 2);
	assert(value.endpoint_count == 3 && value.completed_at == 1234 && value.version == 1);
	assert(global_lb_cache_lookup("be|10.0.0.3:5000", 1234, &value));
	assert(value.found && value.global_count == 4 && value.own_count == 0);
	assert(global_lb_cache_lookup("missing", 1234, &value) && !value.found);

	/* A malformed later cycle never replaces the last complete cache. */
	writer.snapshot_sequence++;
	assert(global_lb_collect_start(&writer, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	keys[0] = self;
	parser = scan_reply("0", keys, 1);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	parser = snapshot_reply(generation, 999, self_endpoints, self_counts, 2);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_ERROR);
	global_lb_cache_get_status(1234, &status);
	assert(status.valid && status.version == 1 && status.endpoint_count == 3);

	/* The 4097th unique endpoint is the explicit unsupported-scale path. */
	writer.snapshot_sequence++;
	assert(global_lb_collect_start(&writer, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	parser = scan_reply("0", keys, 1);
	assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_NEXT);
	free(wire);
	{
		char **many = calloc(GLB_COLLECT_MAX_ENDPOINTS + 1, sizeof(*many));
		uint64_t *counts = calloc(GLB_COLLECT_MAX_ENDPOINTS + 1, sizeof(*counts));
		assert(many && counts);
		for (i = 0; i <= GLB_COLLECT_MAX_ENDPOINTS; i++) {
			many[i] = malloc(64);
			assert(many[i]);
			snprintf(many[i], 64, "be|10.1.%zu.%zu:5000", i / 250, i % 250);
			counts[i] = 1;
		}
		parser = snapshot_reply(generation, writer.snapshot_sequence,
					(const char **)many, counts, GLB_COLLECT_MAX_ENDPOINTS + 1);
		assert(reply(&parser, 0, &wire, &wire_len) == GLB_COLLECT_LIMIT);
		for (i = 0; i <= GLB_COLLECT_MAX_ENDPOINTS; i++)
			free(many[i]);
		free(many);
		free(counts);
	}
	global_lb_cache_get_status(1234, &status);
	assert(!status.valid && !global_lb_cache_lookup("be|10.0.0.1:5000", 1234, &value));

	/* UD-010: empty complete cycles count; three are required at startup. */
	global_lb_collect_deinit();
	assert(global_lb_collect_init("pool", "ha-0", 8U * 1024U * 1024U,
				      3000, 3));
	for (i = 0; i < 3; i++) {
		writer.snapshot_sequence++;
		complete_empty(&writer, self, 2000 + i * 300);
		global_lb_cache_get_status(2000 + i * 300, &status);
		assert(status.valid && status.endpoint_count == 0);
		assert(status.recovery_successes == i + 1);
		assert(status.state == (i == 2 ? GLB_CACHE_ACTIVE : GLB_CACHE_RECOVERING));
		assert(status.usable == (i == 2));
	}
	assert(global_lb_cache_lookup("missing", 2600, &value) &&
	       value.usable && !value.found && value.state == GLB_CACHE_ACTIVE);
	global_lb_cache_note_failure(2800);
	global_lb_cache_get_status(2800, &status);
	assert(status.state == GLB_CACHE_GRACE && status.usable &&
	       status.recovery_successes == 0);
	global_lb_cache_get_status(5600, &status);
	assert(status.state == GLB_CACHE_FALLBACK && !status.usable);

	/* A success after stale fallback starts at 1/3; a failure resets it. */
	writer.snapshot_sequence++;
	complete_empty(&writer, self, 5900);
	global_lb_cache_get_status(5900, &status);
	assert(status.state == GLB_CACHE_RECOVERING && status.recovery_successes == 1);
	global_lb_cache_note_failure(6000);
	global_lb_cache_get_status(6000, &status);
	assert(status.state == GLB_CACHE_FALLBACK && status.recovery_successes == 0);
	for (i = 0; i < 3; i++) {
		writer.snapshot_sequence++;
		complete_empty(&writer, self, 6200 + i * 300);
	}
	global_lb_cache_get_status(6800, &status);
	assert(status.state == GLB_CACHE_ACTIVE && status.usable &&
	       status.recovery_successes == 3);

	/* Recovery successes separated by a stale window are not consecutive. */
	global_lb_collect_deinit();
	assert(global_lb_collect_init("pool", "ha-0", 8U * 1024U * 1024U,
				      3000, 3));
	writer.snapshot_sequence++;
	complete_empty(&writer, self, 1000);
	writer.snapshot_sequence++;
	complete_empty(&writer, self, 4000);
	global_lb_cache_get_status(4000, &status);
	assert(status.state == GLB_CACHE_RECOVERING &&
	       status.recovery_successes == 1 && !status.usable);

	free(expired);
	free(peer);
	free(self);
	global_lb_collect_deinit();
	puts("PASS: collector/cache plus startup/empty recovery, grace, stale fallback, reset and 3-cycle reactivation");
	return 0;
}
