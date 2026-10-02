/* UD-007/009/011 v2-r1-20261003: pure encoder/reply tests and wire driver. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_reserve.h>
#include <haproxy/global_lb_resp.h>

static int allocations = -1;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t n)
{
	if (allocations == 0) return NULL;
	if (allocations > 0) allocations--;
	return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t m)
{
	if (allocations == 0) return NULL;
	if (allocations > 0) allocations--;
	return __real_calloc(n, m);
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static const char gen[] = "00000000-0000-4000-8000-000000000001";

static struct global_lb_reserve_command defaults(void)
{
	struct global_lb_reserve_command c = {
		.op = GLB_RESERVE_START, .prefix = "test[*]:pool", .instance_id = "ha-0",
		.writer_generation = gen, .revision = 1, .instance_timeout = 3000,
		.tie_seed = 1, .limits = { 64, 4096, 100000 },
	};
	return c;
}

static void decode(const char *wire, int valid, int status)
{
	struct global_lb_resp_parser p = {0};
	struct global_lb_resp_limits limits = {256, 16, 3};
	struct global_lb_reserve_reply r;
	size_t consumed;
	CHECK(global_lb_resp_init(&p, &limits));
	CHECK(global_lb_resp_feed(&p, wire, strlen(wire), &consumed) == GLB_RESP_DONE);
	CHECK(global_lb_reserve_result(&p, &r) == valid);
	if (valid) CHECK((int)r.status == status);
	global_lb_resp_release(&p);
}

static int driver(int argc, char **argv)
{
	struct global_lb_reserve_command c = defaults();
	struct global_lb_reserve_entry *entries;
	unsigned char *wire;
	size_t len, i, pos;
	if (argc < 17) return 2;
	c.op = atoi(argv[2]); c.prefix = argv[3]; c.instance_id = argv[4];
	c.writer_generation = argv[5]; c.revision = strtoull(argv[6], NULL, 10);
	c.request_id = strtoull(argv[7], NULL, 10); c.high_water = strtoull(argv[8], NULL, 10);
	c.instance_timeout = strtoul(argv[9], NULL, 10); c.tie_seed = strtoul(argv[10], NULL, 10);
	c.limits.instances = strtoul(argv[11], NULL, 10);
	c.limits.count_fields = strtoul(argv[12], NULL, 10);
	c.limits.requests = strtoul(argv[13], NULL, 10); c.service_id = argv[14];
	c.candidate_count = strtoul(argv[15], NULL, 10);
	if (c.candidate_count > (size_t)argc - 17) return 2;
	c.candidates = (const char * const *)(argv + 16);
	pos = 16 + c.candidate_count;
	c.entry_count = strtoul(argv[pos++], NULL, 10);
	if (c.entry_count > ((size_t)argc - pos) / 2 || pos + 2*c.entry_count != (size_t)argc) return 2;
	entries = calloc(c.entry_count ? c.entry_count : 1, sizeof(*entries));
	if (!entries) return 2;
	for (i = 0; i < c.entry_count; i++) {
		entries[i].request_id = strtoull(argv[pos++], NULL, 10);
		entries[i].endpoint_key = argv[pos++];
	}
	c.entries = entries;
	if (global_lb_reserve_encode(&c, 8*1024*1024, &wire, &len) != GLB_RESP_OK) {
		free(entries); return 2;
	}
	CHECK(fwrite(wire, 1, len, stdout) == len);
	free(entries); free(wire);
	return 0;
}

int main(int argc, char **argv)
{
	struct global_lb_reserve_command c = defaults();
	struct global_lb_reserve_entry entry = { UINT64_MAX, "be|[::1]:5000" };
	const char *candidates[] = { "be|10.0.0.1:5000", "be|[::1]:5000" };
	unsigned char *wire;
	size_t len, exact, i;
	char *key;
	if (argc > 1) return driver(argc, argv);
	CHECK(global_lb_reserve_key("a:b", 0, 256, &key) == GLB_RESP_OK);
	CHECK(!strcmp(key, "glb:v2:613a62:owners")); free(key);
	CHECK(global_lb_reserve_key("a:b", 4, 256, &key) == GLB_RESP_BADARG && !key);
	CHECK(global_lb_reserve_key("a:b", 0, 3, &key) == GLB_RESP_LIMIT && !key);
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_OK);
	exact = len; free(wire);
	CHECK(global_lb_reserve_encode(&c, exact, &wire, &len) == GLB_RESP_OK && len == exact); free(wire);
	CHECK(global_lb_reserve_encode(&c, exact-1, &wire, &len) == GLB_RESP_LIMIT && !wire && !len);
	c.op = GLB_RESERVE_TAKE; c.request_id = UINT64_MAX;
	c.service_id = "be"; c.candidates = candidates; c.candidate_count = 2;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_OK); free(wire);
	c.service_id = "other";
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults(); c.entry_count = 1; c.entries = &entry; c.high_water = UINT64_MAX;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_OK); free(wire);
	c.high_water = UINT64_MAX-1;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults(); c.writer_generation = "invalid";
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults(); c.revision = 0;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults(); c.op = GLB_RESERVE_CANCEL;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults(); c.limits.requests = 0;
	CHECK(global_lb_reserve_encode(&c, 1024*1024, &wire, &len) == GLB_RESP_BADARG);
	c = defaults();
	for (i = 0; i < 16; i++) {
		enum global_lb_resp_error result;
		allocations = i;
		result = global_lb_reserve_encode(&c, 1024*1024, &wire, &len);
		allocations = -1;
		CHECK(result == GLB_RESP_NOMEM || result == GLB_RESP_OK);
		if (result == GLB_RESP_OK) free(wire);
		else CHECK(!wire && !len);
	}
	decode("*3\r\n:1\r\n$2\r\nbe\r\n:3\r\n", 1, 1);
	decode("*3\r\n:-7\r\n$0\r\n\r\n:0\r\n", 1, -7);
	decode("*3\r\n:99\r\n$0\r\n\r\n:0\r\n", 0, 0);
	decode("*3\r\n:1\r\n$-1\r\n:0\r\n", 0, 0);
	decode("*3\r\n:1\r\n$0\r\n\r\n:-1\r\n", 0, 0);
	decode("-ERR test\r\n", 0, 0);
	decode(":1\r\n", 0, 0);
	puts("PASS: v2 reservation encoding, limits, allocation failures and replies");
	return 0;
}
