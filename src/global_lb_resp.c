/* Global LB bounded incremental RESP2 codec. Copyright 2026 nTels.
 * Licensed under GNU GPL version 2 or later.
 * UD-007 r4-resp2-codec-20260904, USE_GLOBAL_LB.
 * No socket, task, shared state, hiredis, Lua or selector dependencies.
 */
#ifdef USE_GLOBAL_LB

#include <stdlib.h>
#include <string.h>
#include <haproxy/global_lb_resp.h>

enum { RESP_PREFIX, RESP_LINE, RESP_LINE_LF, RESP_BULK, RESP_BULK_CR, RESP_BULK_LF };

static enum global_lb_resp_status resp_fail(struct global_lb_resp_parser *p,
					   enum global_lb_resp_error error)
{
	p->error = error;
	p->status = GLB_RESP_ERROR;
	return p->status;
}

static enum global_lb_resp_error resp_reserve(void **ptr, size_t *cap,
					     size_t need, size_t max, size_t size)
{
	size_t n;
	void *next;

	if (need > max || max > SIZE_MAX / size)
		return GLB_RESP_LIMIT;
	if (need <= *cap)
		return GLB_RESP_OK;
	n = *cap ? *cap : (max < 16 ? max : 16);
	while (n < need)
		n = n > max / 2 ? max : n * 2;
	next = realloc(*ptr, n * size);
	if (!next)
		return GLB_RESP_NOMEM;
	*ptr = next;
	*cap = n;
	return GLB_RESP_OK;
}

int global_lb_resp_init(struct global_lb_resp_parser *p,
			const struct global_lb_resp_limits *limits)
{
	if (!p)
		return 0;
	memset(p, 0, sizeof(*p));
	if (!limits || limits->bytes < 3 || !limits->nodes || !limits->depth ||
	    limits->nodes > SIZE_MAX / sizeof(*p->nodes) ||
	    limits->depth > SIZE_MAX / sizeof(*p->stack)) {
		resp_fail(p, GLB_RESP_BADARG);
		return 0;
	}
	p->limits = *limits;
	return 1;
}

void global_lb_resp_reset(struct global_lb_resp_parser *p)
{
	p->used = p->count = p->depth = p->bulk_left = 0;
	p->state = RESP_PREFIX;
	p->status = GLB_RESP_MORE;
	p->error = GLB_RESP_OK;
	if (p->limits.bytes < 3 || !p->limits.nodes || !p->limits.depth)
		resp_fail(p, GLB_RESP_BADARG);
}

void global_lb_resp_release(struct global_lb_resp_parser *p)
{
	if (!p)
		return;
	free(p->wire);
	free(p->nodes);
	free(p->stack);
	memset(p, 0, sizeof(*p));
	resp_fail(p, GLB_RESP_BADARG);
}

/* Parse bounded decimal digits without C-string access or integer wrapping. */
static int resp_unsigned(const unsigned char *s, size_t len, uint64_t max, uint64_t *out)
{
	uint64_t n = 0;
	size_t i;

	if (!len)
		return 0;
	for (i = 0; i < len; i++) {
		unsigned int d = (unsigned int)s[i] - '0';

		if (d > 9 || n > max / 10 || (n == max / 10 && d > max % 10))
			return 0;
		n = n * 10 + d;
	}
	*out = n;
	return 1;
}

static void resp_finish(struct global_lb_resp_parser *p)
{
	p->nodes[p->count - 1].next = p->count;
	p->state = RESP_PREFIX;
	while (p->depth) {
		struct global_lb_resp_level *level = &p->stack[p->depth - 1];

		if (--level->remaining)
			return;
		p->nodes[level->node].next = p->count;
		p->depth--;
	}
	p->status = GLB_RESP_DONE;
}

static void resp_header(struct global_lb_resp_parser *p)
{
	struct global_lb_resp_node *node = &p->nodes[p->count - 1];
	const unsigned char *text = p->wire + node->offset;
	size_t len = p->used - node->offset - 2;
	uint64_t n;
	enum global_lb_resp_error err;
	void *storage;

	if (node->type == '+' || node->type == '-') {
		node->len = len;
		resp_finish(p);
		return;
	}
	if (node->type == ':') {
		int negative = len && text[0] == '-';
		int sign = len && (text[0] == '+' || text[0] == '-');

		if (!resp_unsigned(text + sign, len - sign, (uint64_t)INT64_MAX + negative, &n))
			goto invalid;
		node->integer = negative ? -(int64_t)(n >> 1) * 2 - (int64_t)(n & 1) : (int64_t)n;
		resp_finish(p);
		return;
	}
	if (len == 2 && text[0] == '-' && text[1] == '1') {
		node->is_null = 1;
		if (node->type == '*' && p->depth == p->limits.depth)
			goto limit;
		resp_finish(p);
		return;
	}
	if (!resp_unsigned(text, len, INT64_MAX, &n))
		goto invalid;
	if (node->type == '$') {
		/* Include the mandatory trailing CRLF in the wire limit. */
		if (p->limits.bytes - p->used < 2 || n > p->limits.bytes - p->used - 2)
			goto limit;
		node->offset = p->used;
		node->len = p->bulk_left = (size_t)n;
		p->state = n ? RESP_BULK : RESP_BULK_CR;
		return;
	}
	if (p->depth == p->limits.depth || n > p->limits.nodes - p->count)
		goto limit;
	node->children = (size_t)n;
	if (!n) {
		resp_finish(p);
		return;
	}
	storage = p->stack;
	err = resp_reserve(&storage, &p->stack_cap, p->depth + 1,
			   p->limits.depth, sizeof(*p->stack));
	if (err) {
		resp_fail(p, err);
		return;
	}
	p->stack = storage;
	p->stack[p->depth].node = p->count - 1;
	p->stack[p->depth++].remaining = (size_t)n;
	p->state = RESP_PREFIX;
	return;

 invalid:
	resp_fail(p, GLB_RESP_INVALID);
	return;
 limit:
	resp_fail(p, GLB_RESP_LIMIT);
}

enum global_lb_resp_status global_lb_resp_feed(struct global_lb_resp_parser *p,
			const void *input, size_t len, size_t *consumed)
{
	const unsigned char *s = input;
	enum global_lb_resp_error err;
	size_t i;
	void *storage;

	if (consumed)
		*consumed = 0;
	if (!p)
		return GLB_RESP_ERROR;
	if (!consumed || (!input && len))
		return resp_fail(p, GLB_RESP_BADARG);
	if (p->status != GLB_RESP_MORE)
		return p->status;
	for (i = 0; i < len && p->status == GLB_RESP_MORE; i++) {
		unsigned char c = s[i];

		if (p->used == p->limits.bytes)
			return resp_fail(p, GLB_RESP_LIMIT);
		storage = p->wire;
		err = resp_reserve(&storage, &p->wire_cap, p->used + 1,
				   p->limits.bytes, 1);
		if (err)
			return resp_fail(p, err);
		p->wire = storage;
		p->wire[p->used++] = c;
		*consumed = i + 1;
		switch (p->state) {
		case RESP_PREFIX:
			if (c != '+' && c != '-' && c != ':' && c != '$' && c != '*')
				return resp_fail(p, GLB_RESP_INVALID);
			if (p->count == p->limits.nodes)
				return resp_fail(p, GLB_RESP_LIMIT);
			storage = p->nodes;
			err = resp_reserve(&storage, &p->node_cap, p->count + 1,
					   p->limits.nodes, sizeof(*p->nodes));
			if (err)
				return resp_fail(p, err);
			p->nodes = storage;
			memset(&p->nodes[p->count], 0, sizeof(*p->nodes));
			p->nodes[p->count].type = c;
			p->nodes[p->count++].offset = p->used;
			p->state = RESP_LINE;
			break;
		case RESP_LINE:
			if (c == '\r')
				p->state = RESP_LINE_LF;
			else if (c == '\n')
				return resp_fail(p, GLB_RESP_INVALID);
			break;
		case RESP_LINE_LF:
			if (c != '\n')
				return resp_fail(p, GLB_RESP_INVALID);
			resp_header(p);
			break;
		case RESP_BULK:
			if (!--p->bulk_left)
				p->state = RESP_BULK_CR;
			break;
		case RESP_BULK_CR:
			if (c != '\r')
				return resp_fail(p, GLB_RESP_INVALID);
			p->state = RESP_BULK_LF;
			break;
		case RESP_BULK_LF:
			if (c != '\n')
				return resp_fail(p, GLB_RESP_INVALID);
			resp_finish(p);
			break;
		}
	}
	/* No continuation can complete a frame once the entire byte budget is used. */
	if (p->status == GLB_RESP_MORE && p->used == p->limits.bytes)
		return resp_fail(p, GLB_RESP_LIMIT);
	return p->status;
}

static size_t resp_digits(size_t n)
{
	size_t digits = 1;

	while (n >= 10) {
		digits++;
		n /= 10;
	}
	return digits;
}

static unsigned char *resp_write_length(unsigned char *out, char type, size_t n)
{
	size_t digits = resp_digits(n), i = digits;

	*out++ = type;
	do {
		out[--i] = '0' + n % 10;
		n /= 10;
	} while (i);
	out += digits;
	*out++ = '\r';
	*out++ = '\n';
	return out;
}

enum global_lb_resp_error global_lb_resp_encode(const struct global_lb_resp_arg *args,
			size_t argc, size_t max_bytes, unsigned char **output, size_t *len)
{
	size_t total, overhead, i;
	unsigned char *wire, *pos;

	if (output)
		*output = NULL;
	if (len)
		*len = 0;
	if (!output || !len || !args || !argc)
		return GLB_RESP_BADARG;
	if (argc > INT64_MAX || argc > max_bytes / 6)
		return GLB_RESP_LIMIT;
	total = resp_digits(argc) + 3;
	if (total > max_bytes)
		return GLB_RESP_LIMIT;
	for (i = 0; i < argc; i++) {
		if (!args[i].data && args[i].len)
			return GLB_RESP_BADARG;
		overhead = resp_digits(args[i].len) + 5;
		if (args[i].len > INT64_MAX || overhead > max_bytes - total)
			return GLB_RESP_LIMIT;
		total += overhead;
		if (args[i].len > max_bytes - total)
			return GLB_RESP_LIMIT;
		total += args[i].len;
	}
	wire = malloc(total);
	if (!wire)
		return GLB_RESP_NOMEM;
	pos = resp_write_length(wire, '*', argc);
	for (i = 0; i < argc; i++) {
		pos = resp_write_length(pos, '$', args[i].len);
		if (args[i].len) {
			memcpy(pos, args[i].data, args[i].len);
			pos += args[i].len;
		}
		*pos++ = '\r';
		*pos++ = '\n';
	}
	*output = wire;
	*len = total;
	return GLB_RESP_OK;
}

#endif /* USE_GLOBAL_LB */
