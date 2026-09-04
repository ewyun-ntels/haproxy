/* UD-007 r4-resp2-codec-20260904: standalone codec regression, no store I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_resp.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static size_t checks;
static long fail_after = -1;
void *__real_malloc(size_t n);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n)
{
	if (fail_after == 0) return NULL;
	if (fail_after > 0) fail_after--;
	return __real_malloc(n);
}
void *__wrap_realloc(void *p, size_t n)
{
	if (fail_after == 0) return NULL;
	if (fail_after > 0) fail_after--;
	return __real_realloc(p, n);
}

static const struct global_lb_resp_limits limits = { 8192, 512, 32 };

static void invariant(const struct global_lb_resp_parser *p)
{
	size_t i;

	CHECK(p->used <= p->limits.bytes && p->count <= p->limits.nodes);
	CHECK(p->wire_cap <= p->limits.bytes && p->node_cap <= p->limits.nodes);
	CHECK(p->depth <= p->limits.depth && p->stack_cap <= p->limits.depth);
	if (p->status != GLB_RESP_DONE)
		return;
	CHECK(p->count && p->nodes[0].next == p->count && !p->depth);
	for (i = 0; i < p->count; i++) {
		const struct global_lb_resp_node *n = &p->nodes[i];
		size_t j = i + 1, children = 0;

		CHECK(n->next > i && n->next <= p->count);
		CHECK(n->offset <= p->used && n->len <= p->used - n->offset);
		if (n->type == '*') {
			while (j < n->next) {
				j = p->nodes[j].next;
				children++;
			}
			CHECK(j == n->next && children == n->children);
		}
		else CHECK(n->next == i + 1);
	}
}

/* Every possible two-chunk boundary, followed by one-byte fragmentation. */
static void valid(const void *wire, size_t len)
{
	const unsigned char *s = wire;
	struct global_lb_resp_parser p;
	size_t split, used, i;

	for (split = 0; split <= len; split++) {
		CHECK(global_lb_resp_init(&p, &limits));
		CHECK(global_lb_resp_feed(&p, s, split, &used) == (split == len ? GLB_RESP_DONE : GLB_RESP_MORE));
		CHECK(used == split);
		CHECK(global_lb_resp_feed(&p, s + split, len - split, &used) == GLB_RESP_DONE);
		CHECK(used == len - split && p.used == len);
		CHECK(!memcmp(p.wire, s, len));
		invariant(&p);
		CHECK(global_lb_resp_feed(&p, "garbage", 7, &used) == GLB_RESP_DONE && !used);
		global_lb_resp_release(&p);
		checks++;
	}
	CHECK(global_lb_resp_init(&p, &limits));
	for (i = 0; i < len; i++) {
		CHECK(global_lb_resp_feed(&p, s + i, 1, &used) == (i + 1 == len ? GLB_RESP_DONE : GLB_RESP_MORE));
		CHECK(used == 1);
	}
	invariant(&p);
	global_lb_resp_release(&p);
	checks++;
}

static void rejected(const char *wire, struct global_lb_resp_limits lim, enum global_lb_resp_error error)
{
	struct global_lb_resp_parser p;
	size_t used, i, len = strlen(wire);

	CHECK(global_lb_resp_init(&p, &lim));
	CHECK(global_lb_resp_feed(&p, wire, len, &used) == GLB_RESP_ERROR);
	CHECK(p.error == error && used <= len);
	invariant(&p);
	CHECK(global_lb_resp_feed(&p, "+OK\r\n", 5, &used) == GLB_RESP_ERROR && !used);
	global_lb_resp_reset(&p);
	for (i = 0; i < len; i++) {
		if (global_lb_resp_feed(&p, wire + i, 1, &used) == GLB_RESP_ERROR)
			break;
	}
	CHECK(p.status == GLB_RESP_ERROR && p.error == error);
	global_lb_resp_release(&p);
	checks++;
}

static void semantics(void)
{
	const char wire[] = "*5\r\n$-1\r\n$0\r\n\r\n*2\r\n:-9223372036854775808\r\n:+9223372036854775807\r\n*-1\r\n-ERR test\r\n";
	struct global_lb_resp_parser p;
	size_t used;

	valid(wire, sizeof(wire) - 1);
	CHECK(global_lb_resp_init(&p, &limits));
	CHECK(global_lb_resp_feed(&p, wire, sizeof(wire) - 1, &used) == GLB_RESP_DONE);
	CHECK(p.count == 8 && p.nodes[0].children == 5);
	CHECK(p.nodes[1].is_null && p.nodes[1].type == '$');
	CHECK(!p.nodes[2].is_null && p.nodes[2].len == 0);
	CHECK(p.nodes[3].children == 2 && p.nodes[3].next == 6);
	CHECK(p.nodes[4].integer == INT64_MIN && p.nodes[5].integer == INT64_MAX);
	CHECK(p.nodes[6].type == '*' && p.nodes[6].is_null);
	CHECK(p.nodes[7].type == '-' && p.error == GLB_RESP_OK);
	CHECK(p.nodes[7].len == 8 && !memcmp(p.wire + p.nodes[7].offset, "ERR test", 8));
	global_lb_resp_reset(&p);
	CHECK(global_lb_resp_feed(&p, "+OK\r\n:1\r\n", 9, &used) == GLB_RESP_DONE && used == 5);
	global_lb_resp_reset(&p);
	CHECK(global_lb_resp_feed(&p, ":1\r\n", 4, &used) == GLB_RESP_DONE && used == 4);
	CHECK(p.nodes[0].integer == 1);
	global_lb_resp_reset(&p);
	CHECK(global_lb_resp_feed(&p, "$3\r\nxy", 6, &used) == GLB_RESP_MORE);
	CHECK(global_lb_resp_feed(&p, NULL, 0, &used) == GLB_RESP_MORE && !used);
	global_lb_resp_release(&p);
	global_lb_resp_release(&p);
	CHECK(!p.wire && !p.nodes && !p.stack);
}

static void encoder(void)
{
	const unsigned char binary[] = { 'a', 0, '\r', '\n', 255 };
	const unsigned char expected[] = "*3\r\n$4\r\nECHO\r\n$5\r\na\0\r\n\xff\r\n$0\r\n\r\n";
	struct global_lb_resp_arg args[] = {{"ECHO", 4}, {binary, sizeof(binary)}, {NULL, 0}};
	struct global_lb_resp_parser p;
	unsigned char *out;
	size_t len, used;

	CHECK(global_lb_resp_encode(args, 3, sizeof(expected) - 1, &out, &len) == GLB_RESP_OK);
	CHECK(len == sizeof(expected) - 1 && !memcmp(out, expected, len));
	valid(out, len);
	CHECK(global_lb_resp_init(&p, &limits));
	CHECK(global_lb_resp_feed(&p, out, len, &used) == GLB_RESP_DONE);
	CHECK(p.nodes[2].len == sizeof(binary));
	CHECK(!memcmp(p.wire + p.nodes[2].offset, binary, sizeof(binary)));
	global_lb_resp_release(&p);
	free(out);
	CHECK(global_lb_resp_encode(args, 3, sizeof(expected) - 2, &out, &len) == GLB_RESP_LIMIT);
	CHECK(!out && !len);
	CHECK(global_lb_resp_encode(args, 0, 100, &out, &len) == GLB_RESP_BADARG);
	CHECK(global_lb_resp_encode(NULL, 1, 100, &out, &len) == GLB_RESP_BADARG);
	CHECK(global_lb_resp_encode(args, SIZE_MAX, 100, &out, &len) == GLB_RESP_LIMIT);
	args[0].len = SIZE_MAX;
	CHECK(global_lb_resp_encode(args, 3, SIZE_MAX, &out, &len) == GLB_RESP_LIMIT);
	args[0].len = 1;
	args[0].data = NULL;
	CHECK(global_lb_resp_encode(args, 3, 100, &out, &len) == GLB_RESP_BADARG);
}

static void allocation_failures(void)
{
	const char *wire = "*2\r\n$20\r\n01234567890123456789\r\n*1\r\n+OK\r\n";
	struct global_lb_resp_parser p;
	struct global_lb_resp_arg arg = {"PING", 4};
	unsigned char *out;
	size_t used, len;
	int n, completed = 0;

	for (n = 0; n < 20; n++) {
		CHECK(global_lb_resp_init(&p, &limits));
		fail_after = n;
		global_lb_resp_feed(&p, wire, strlen(wire), &used);
		fail_after = -1;
		if (p.status == GLB_RESP_DONE) completed = 1;
		else CHECK(p.status == GLB_RESP_ERROR && p.error == GLB_RESP_NOMEM);
		invariant(&p);
		global_lb_resp_reset(&p);
		CHECK(global_lb_resp_feed(&p, "+OK\r\n", 5, &used) == GLB_RESP_DONE);
		global_lb_resp_release(&p);
		if (completed) break;
	}
	CHECK(completed);
	fail_after = 0;
	CHECK(global_lb_resp_encode(&arg, 1, 100, &out, &len) == GLB_RESP_NOMEM);
	fail_after = -1;
	CHECK(!out && !len);
}

static void growth_and_roundtrips(void)
{
	struct global_lb_resp_arg args[64];
	unsigned char payload[64][40], *out;
	char nested[128];
	struct global_lb_resp_parser p;
	struct global_lb_resp_limits lim = limits;
	size_t i, j, len, used;
	int failure, completed = 0;

	for (i = 0; i < 30; i++) memcpy(nested + i * 4, "*1\r\n", 4);
	memcpy(nested + 120, ":1\r\n", 4);
	valid(nested, 124); /* includes stack growth beyond its initial capacity */
	for (i = 0; i < 64; i++) {
		for (j = 0; j < 40; j++) payload[i][j] = (unsigned char)(i * 41 + j);
		args[i].data = payload[i];
		args[i].len = i % 41;
	}
	CHECK(global_lb_resp_encode(args, 64, 8192, &out, &len) == GLB_RESP_OK);
	CHECK(global_lb_resp_init(&p, &limits));
	for (i = 0; i < len; i++) {
		global_lb_resp_feed(&p, out + i, 1, &used);
		CHECK(used == 1);
	}
	CHECK(p.status == GLB_RESP_DONE && p.count == 65);
	invariant(&p);
	for (i = 0; i < 64; i++) {
		CHECK(p.nodes[i + 1].len == args[i].len);
		CHECK(!memcmp(p.wire + p.nodes[i + 1].offset, args[i].data, args[i].len));
	}
	global_lb_resp_release(&p);
	/* Exact node/depth limits accept this command. */
	lim.nodes = 65; lim.depth = 1; lim.bytes = len;
	CHECK(global_lb_resp_init(&p, &lim));
	CHECK(global_lb_resp_feed(&p, out, len, &used) == GLB_RESP_DONE);
	global_lb_resp_release(&p);
	/* Exercise every allocation failure, including node/wire realloc growth. */
	for (failure = 0; failure < 40; failure++) {
		CHECK(global_lb_resp_init(&p, &limits));
		fail_after = failure;
		global_lb_resp_feed(&p, out, len, &used);
		fail_after = -1;
		if (p.status == GLB_RESP_DONE) completed = 1;
		else CHECK(p.status == GLB_RESP_ERROR && p.error == GLB_RESP_NOMEM);
		invariant(&p);
		global_lb_resp_release(&p);
		if (completed) break;
	}
	CHECK(completed);
	free(out);
}

static void fuzz_smoke(void)
{
	struct global_lb_resp_parser p;
	struct global_lb_resp_limits lim = {256, 32, 8};
	unsigned char data[128];
	uint32_t rng = 0x7124a53U;
	size_t i, j, used;

	CHECK(global_lb_resp_init(&p, &lim));
	for (i = 0; i < 20000; i++) {
		global_lb_resp_reset(&p);
		for (j = 0; j < sizeof(data); j++) {
			rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
			data[j] = (unsigned char)rng;
		}
		if (i % 2) data[0] = "+-:$*"[i % 5];
		global_lb_resp_feed(&p, data, sizeof(data), &used);
		CHECK(used <= sizeof(data));
		invariant(&p);
	}
	global_lb_resp_release(&p);
}

int main(void)
{
	const char *good[] = {"+OK\r\n", "-ERR failure\r\n", ":0\r\n", ":-0\r\n", ":+1\r\n",
		"$-1\r\n", "$0\r\n\r\n", "*0\r\n", "*-1\r\n", "*2\r\n*0\r\n*1\r\n:5\r\n"};
	const char *bad[] = {"_\r\n", "%0\r\n", "?x\r\n", "+x\ny", "+x\rx", ":\r\n", ":+\r\n",
		":1x\r\n", ":9223372036854775808\r\n", ":-9223372036854775809\r\n",
		":18446744073709551617\r\n", "$-2\r\n", "$+1\r\n", "$1x\r\n", "$1\r\nXxx",
		"$1\r\nX\rx", "*-2\r\n", "*+1\r\n", "*x\r\n", "*999999999999999999999\r\n"};
	struct global_lb_resp_parser p;
	struct global_lb_resp_limits lim;
	size_t i, used;

	for (i = 0; i < sizeof(good) / sizeof(*good); i++) valid(good[i], strlen(good[i]));
	valid("$5\r\na\0\r\nz\r\n", 11);
	for (i = 0; i < sizeof(bad) / sizeof(*bad); i++) rejected(bad[i], limits, GLB_RESP_INVALID);
	lim = limits; lim.bytes = 5;
	rejected("+long\r\n", lim, GLB_RESP_LIMIT);
	rejected("$1\r\nx\r\n", lim, GLB_RESP_LIMIT);
	CHECK(global_lb_resp_init(&p, &lim));
	CHECK(global_lb_resp_feed(&p, "+OK\r\n", 5, &used) == GLB_RESP_DONE);
	global_lb_resp_release(&p);
	lim = limits; lim.nodes = 2;
	rejected("*2\r\n:1\r\n:2\r\n", lim, GLB_RESP_LIMIT);
	lim = limits; lim.depth = 1;
	rejected("*1\r\n*0\r\n", lim, GLB_RESP_LIMIT);
	rejected("*1\r\n*-1\r\n", lim, GLB_RESP_LIMIT);
	lim = limits; lim.bytes = 2;
	CHECK(!global_lb_resp_init(&p, &lim));
	CHECK(p.error == GLB_RESP_BADARG);
	global_lb_resp_release(&p);
	CHECK(global_lb_resp_init(&p, &limits));
	CHECK(global_lb_resp_feed(&p, NULL, 1, &used) == GLB_RESP_ERROR && !used);
	global_lb_resp_release(&p);
	semantics(); encoder(); allocation_failures(); growth_and_roundtrips(); fuzz_smoke();
	printf("PASS: RESP2 %zu fragmentation/malformed/limit cases, semantics, encoder, OOM and 20000 fuzz inputs\n", checks);
	return 0;
}
