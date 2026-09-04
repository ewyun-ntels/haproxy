/* UD-007 r5-store-protocol-20260904 / UD-011 r3-sequenced-store-20260904. */
#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
static int fail_at = -1, allocations;
void *__wrap_malloc(size_t n)
{
	return allocations++ == fail_at ? NULL : __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t s)
{
	return allocations++ == fail_at ? NULL : __real_calloc(n, s);
}

static struct global_lb_resp_parser parse(const void *wire, size_t len)
{
	struct global_lb_resp_parser p;
	struct global_lb_resp_limits limits = { 1048576, 32768, 4 };
	size_t used;
	assert(global_lb_resp_init(&p, &limits));
	assert(global_lb_resp_feed(&p, wire, len, &used) == GLB_RESP_DONE);
	assert(used == len);
	return p;
}

static void strnode(struct global_lb_resp_parser *p, size_t n, const char *s)
{
	assert(p->nodes[n].type == '$');
	assert(p->nodes[n].len == strlen(s));
	assert(!memcmp(p->wire + p->nodes[n].offset, s, strlen(s)));
}

/* Utility mode used by integration tests: build the ACTUAL C EVAL request. */
static int request(int argc, char **argv)
{
	struct global_lb_store_writer w;
	struct global_lb_store_entry *entries;
	unsigned char *wire = NULL;
	size_t len = 0, n, i;
	enum global_lb_resp_error err;
	if (argc < 9 || (argc - 9) % 2 || strlen(argv[5]) != 36)
		return 2;
	n = (argc - 9) / 2;
	entries = calloc(n ? n : 1, sizeof(*entries));
	assert(entries);
	memcpy(w.writer_generation, argv[5], 37);
	w.snapshot_sequence = strtoull(argv[6], NULL, 10);
	for (i = 0; i < n; i++) {
		entries[i].endpoint_key = argv[9 + 2*i];
		entries[i].active_count = strtoull(argv[10 + 2*i], NULL, 10);
	}
	err = global_lb_store_encode(atoi(argv[2]), argv[3], argv[4], &w,
			strtoul(argv[7], NULL, 10), entries, n,
			strtoull(argv[8], NULL, 10), &wire, &len);
	free(entries);
	if (err != GLB_RESP_OK)
		return 3;
	assert(fwrite(wire, 1, len, stdout) == len);
	free(wire);
	return 0;
}

int main(int argc, char **argv)
{
	struct global_lb_store_writer w, copy;
	struct global_lb_store_entry entries[] = {
		{ "be_b|[::1]:5000", UINT64_MAX }, { "be_a|127.0.0.1:5000", 10 }
	};
	struct global_lb_resp_parser p;
	enum global_lb_store_result result;
	enum global_lb_resp_error err;
	unsigned char entropy[16] = { 0 }, *wire;
	char *key, *other;
	size_t len, exact;
	int i, nalloc;
	if (argc == 2 && !strcmp(argv[1], "--script")) {
		fputs(global_lb_store_script(NULL), stdout);
		return 0;
	}
	if (argc > 1 && !strcmp(argv[1], "--request"))
		return request(argc, argv);
	assert(global_lb_store_writer_init(&w, entropy));
	assert(!strcmp(w.writer_generation, "00000000-0000-4000-8000-000000000000"));
	assert(w.snapshot_sequence == 0);
	assert(!global_lb_store_writer_init(NULL, entropy));
	assert(!global_lb_store_writer_init(&w, NULL));
	assert(!global_lb_store_writer_next(NULL));
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, 3000,
		NULL, 0, 65536, &wire, &len) == GLB_RESP_BADARG);
	assert(wire == NULL && len == 0);
	assert(global_lb_store_writer_next(&w));
	copy = w;
	assert(global_lb_store_key("a:b", "c", 1, 1024, &key) == GLB_RESP_OK);
	assert(!strcmp(key, "glb:v1:613a62:63:owner"));
	assert(global_lb_store_key("a", "b:c", 1, 1024, &other) == GLB_RESP_OK);
	assert(strcmp(key, other));
	free(other);
	assert(global_lb_store_key("a:b", "c", 0, 1024, &other) == GLB_RESP_OK);
	assert(strcmp(key, other));
	free(other);
	exact = strlen(key) + 1;
	free(key);
	assert(global_lb_store_key("a:b", "c", 1, exact, &key) == GLB_RESP_OK);
	free(key);
	assert(global_lb_store_key("a:b", "c", 1, exact-1, &key) == GLB_RESP_LIMIT && !key);
	assert(global_lb_store_key("", "c", 1, 1024, &key) == GLB_RESP_BADARG);
	assert(global_lb_store_key("a", NULL, 1, 1024, &key) == GLB_RESP_BADARG);
	assert(global_lb_store_key("a", "c", 2, 1024, &key) == GLB_RESP_BADARG);
	assert(global_lb_store_encode(GLB_STORE_START, "pool[*]", "ha-0", &w, 3000,
		entries, 2, 65536, &wire, &len) == GLB_RESP_OK);
	assert(!memcmp(&copy, &w, sizeof(w)));
	exact = len;
	p = parse(wire, len);
	assert(p.nodes[0].children == 13);
	strnode(&p, 1, "EVAL");
	strnode(&p, 3, "2");
	strnode(&p, 4, "glb:v1:706f6f6c5b2a5d:68612d30:owner");
	strnode(&p, 6, "start");
	strnode(&p, 7, w.writer_generation);
	strnode(&p, 8, "1");
	strnode(&p, 9, "3000");
	strnode(&p, 10, "c:be_a|127.0.0.1:5000");
	strnode(&p, 11, "10");
	strnode(&p, 12, "c:be_b|[::1]:5000");
	strnode(&p, 13, "18446744073709551615");
	global_lb_resp_release(&p);
	free(wire);
	assert(global_lb_store_encode(GLB_STORE_START, "pool[*]", "ha-0", &w, 3000,
		entries, 2, exact, &wire, &len) == GLB_RESP_OK);
	free(wire);
	assert(global_lb_store_encode(GLB_STORE_START, "pool[*]", "ha-0", &w, 3000,
		entries, 2, exact-1, &wire, &len) == GLB_RESP_LIMIT && !wire && !len);
	for (i = 0; i < 3; i++) {
		assert(global_lb_store_encode(i, "pool", "ha-0", &w, 3000,
			NULL, 0, 65536, &wire, &len) == GLB_RESP_OK);
		free(wire);
	}
	assert(global_lb_store_encode(GLB_STORE_DELETE, "pool", "ha-0", &w, 3000,
		entries, 2, 65536, &wire, &len) == GLB_RESP_BADARG);
	assert(global_lb_store_encode(-1, "pool", "ha-0", &w, 3000,
		NULL, 0, 65536, &wire, &len) == GLB_RESP_BADARG);
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, 0,
		NULL, 0, 65536, &wire, &len) == GLB_RESP_BADARG);
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, UINT_MAX,
		NULL, 0, 65536, &wire, &len) == GLB_RESP_BADARG);
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, 3000,
		entries, SIZE_MAX, 65536, &wire, &len) == GLB_RESP_LIMIT);
	entries[1].endpoint_key = entries[0].endpoint_key;
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, 3000,
		entries, 2, 65536, &wire, &len) == GLB_RESP_BADARG);
	entries[1].endpoint_key = NULL;
	assert(global_lb_store_encode(GLB_STORE_START, "pool", "ha-0", &w, 3000,
		entries, 2, 65536, &wire, &len) == GLB_RESP_BADARG);
	entries[1].endpoint_key = "writer_generation"; /* protected by c: namespace */
	allocations = 0;
	assert(global_lb_store_encode(GLB_STORE_UPDATE, "p", "i", &w, 3000,
		entries, 2, 65536, &wire, &len) == GLB_RESP_OK);
	nalloc = allocations;
	free(wire);
	for (i = 0; i < nalloc; i++) {
		fail_at = i;
		allocations = 0;
		err = global_lb_store_encode(GLB_STORE_UPDATE, "p", "i", &w, 3000,
			entries, 2, 65536, &wire, &len);
		assert(err == GLB_RESP_NOMEM && !wire && !len);
	}
	fail_at = -1;
	w.snapshot_sequence = UINT64_MAX - 1;
	assert(global_lb_store_writer_next(&w));
	assert(w.snapshot_sequence == UINT64_MAX);
	assert(!global_lb_store_writer_next(&w));
	assert(w.snapshot_sequence == UINT64_MAX);
	for (i = -3; i <= 4; i++) {
		char reply[32];
		len = snprintf(reply, sizeof(reply), ":%d\r\n", i);
		p = parse(reply, len);
		assert(global_lb_store_result(&p, &result) == (i <= 3));
		if (i <= 3) assert((int)result == i);
		global_lb_resp_release(&p);
	}
	p = parse("-ERR failure\r\n", 14);
	assert(!global_lb_store_result(&p, &result));
	global_lb_resp_release(&p);
	p = parse("*1\r\n:1\r\n", 8);
	assert(!global_lb_store_result(&p, &result));
	global_lb_resp_release(&p);
	memset(w.writer_generation, 'a', sizeof(w.writer_generation));
	assert(!global_lb_store_writer_next(&w));
	assert(global_lb_store_encode(GLB_STORE_START, "p", "i", &w, 3000,
		NULL, 0, 65536, &wire, &len) == GLB_RESP_BADARG);
	puts("PASS: store UUID/sequence, key encoding, EVAL builder, limits, allocation failures, replies");
	return 0;
}
