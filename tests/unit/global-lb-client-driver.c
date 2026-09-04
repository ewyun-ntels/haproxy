/* Test-only HAProxy event-loop driver. NOT linked by the production Makefile.
 * Build with EXTRA_OBJS=tests/unit/global-lb-client-driver.o.
 * UD-007 r6-async-client-20260904 / UD-011 r4-worker-identity-20260904.
 */
#ifdef USE_GLOBAL_LB
#include <assert.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>
#include <haproxy/init.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>

static const char *plan;
static char generation[37];
static unsigned int ready_count, reply_count, failures;
static size_t byte_limit = 1048576;

static void done(void)
{
	struct global_lb_store_writer *writer = global_lb_client_writer();
	global_lb_client_stop();
	assert(global_lb_client_state() == GLB_CLIENT_STOPPED);
	assert(!strcmp(writer->writer_generation, generation));
	printf("GLB_TEST DONE ready=%u reply=%u failed=%u uuid=%s seq=%" PRIu64 "\n",
	       ready_count, reply_count, failures, generation, writer->snapshot_sequence);
	fflush(stdout);
}

static struct task *stop_later(struct task *task, void *context, unsigned int state)
{
	task_destroy(task);
	done();
	return NULL;
}

static void schedule_stop(void)
{
	struct task *task = task_new_here();
	assert(task);
	task->process = stop_later;
	task->expire = tick_add(now_ms, 20);
	task_queue(task);
}

static void submit(void)
{
	struct global_lb_store_writer *writer = global_lb_client_writer();
	struct global_lb_resp_arg args[2];
	struct global_lb_store_entry entry = { "be_test|127.0.0.1:5000", 100 };
	unsigned char *wire, *second, *saved;
	size_t len, second_len;
	char *payload = NULL;
	assert(global_lb_store_writer_next(writer));
	if (!strcmp(plan, "store")) {
		enum global_lb_store_op op = reply_count == 0 ? GLB_STORE_START :
		                            reply_count == 1 ? GLB_STORE_UPDATE : GLB_STORE_DELETE;
		if (reply_count) entry.active_count = 7;
		assert(global_lb_store_encode(op, global_lb_cfg.key_prefix, global_lb_cfg.instance_id,
			writer, global_lb_cfg.snapshot_ttl, &entry, op == GLB_STORE_DELETE ? 0 : 1,
			byte_limit, &wire, &len) == GLB_RESP_OK);
	}
	else {
		args[0] = (struct global_lb_resp_arg){ "ECHO", 4 };
		if (!strcmp(plan, "large")) {
			int fd;
			/* Force actual short writes/EAGAIN on just the test store fd. */
			for (fd = 3; fd < 1024; fd++) {
				struct sockaddr_in address;
				socklen_t alen = sizeof(address);
				int size = 4096;
				if (getpeername(fd, (struct sockaddr *)&address, &alen) == 0 &&
				    address.sin_family == AF_INET &&
				    ntohs(address.sin_port) == global_lb_cfg.state_store_port)
					assert(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
			}
			payload = malloc(262144);
			assert(payload);
			memset(payload, 'x', 262144);
			payload[10] = 0;
			payload[11] = '\r';
			payload[12] = '\n';
			args[1] = (struct global_lb_resp_arg){ payload, 262144 };
		}
		else {
			const char *value = ready_count == 1 ? "first" : "fresh";
			args[1] = (struct global_lb_resp_arg){ value, 5 };
		}
		assert(global_lb_resp_encode(args, 2, byte_limit, &wire, &len) == GLB_RESP_OK);
		free(payload);
	}
	/* Refusal must retain ownership. Then accept one command, refuse a second. */
	saved = wire;
	assert(!global_lb_client_submit(&wire, byte_limit + 1) && wire == saved);
	assert(global_lb_client_submit(&wire, len) && wire == NULL);
	args[0] = (struct global_lb_resp_arg){ "PING", 4 };
	assert(global_lb_resp_encode(args, 1, byte_limit, &second, &second_len) == GLB_RESP_OK);
	saved = second;
	assert(!global_lb_client_submit(&second, second_len) && second == saved);
	free(second);
	printf("GLB_TEST SEND seq=%" PRIu64 "\n", writer->snapshot_sequence);
	fflush(stdout);
}

static void event(enum global_lb_client_event event, enum global_lb_client_error error,
		  const struct global_lb_resp_parser *reply, void *context)
{
	struct global_lb_store_writer *writer = global_lb_client_writer();
	assert(tid == 0 && !master && !strcmp(writer->writer_generation, generation));
	assert(context == &ready_count);
	if (event == GLB_CLIENT_CONNECTED) {
		ready_count++;
		printf("GLB_TEST READY count=%u uuid=%s seq=%" PRIu64 "\n",
		       ready_count, generation, writer->snapshot_sequence);
		fflush(stdout);
		if (!strcmp(plan, "stop-ready"))
			done();
		else if (strcmp(plan, "idle")) {
			submit();
			if (!strcmp(plan, "stop-pending"))
				schedule_stop();
		}
	}
	else if (event == GLB_CLIENT_REPLY) {
		reply_count++;
		assert(reply && reply->status == GLB_RESP_DONE);
		printf("GLB_TEST REPLY type=%c nodes=%zu\n", reply->nodes[0].type, reply->count);
		fflush(stdout);
		if (!strcmp(plan, "store")) {
			enum global_lb_store_result result;
			assert(global_lb_store_result(reply, &result));
			assert(result == (reply_count == 3 ? GLB_STORE_DELETED : GLB_STORE_STORED));
			if (reply_count < 3) {
				submit(); /* reentrant submit must not invalidate borrowed reply */
				assert(global_lb_store_result(reply, &result));
				return;
			}
		}
		else if (!strcmp(plan, "error"))
			assert(reply->nodes[0].type == '-');
		else if (!strcmp(plan, "large")) {
			assert(reply->nodes[0].type == '$' && reply->nodes[0].len == 262144);
			assert(reply->wire[reply->nodes[0].offset + 10] == 0);
		}
		else {
			assert(reply->nodes[0].type == '$' && reply->nodes[0].len == 5);
			assert(!memcmp(reply->wire + reply->nodes[0].offset,
			               ready_count == 1 ? "first" : "fresh", 5));
		}
		done();
		assert(reply->status == GLB_RESP_DONE); /* stop defers borrowed parser release */
	}
	else {
		const char *expected = getenv("GLB_CLIENT_TEST_ERROR");
		failures++;
		printf("GLB_TEST FAIL error=%d time=%u\n", error, now_ms);
		fflush(stdout);
		assert(!reply && error != GLB_CLIENT_OK);
		if (expected) assert(error == atoi(expected));
		if (!strcmp(plan, "reconnect")) {
			assert(failures == 1);
			return;
		}
		if (!strcmp(plan, "backoff") && failures < 4)
			return;
		done();
	}
}

static struct task *boot(struct task *task, void *ctx, unsigned int state)
{
	struct global_lb_client_limits limits = { 1048576, { 1048576, 128, 8 }, 4096, 2 };
	struct sockaddr_storage address = { 0 };
	struct global_lb_store_writer *writer = global_lb_client_writer();
	unsigned int i, x;
	assert(writer && global_lb_client_state() == GLB_CLIENT_IDLE);
	assert(writer->snapshot_sequence == 0);
	memcpy(generation, writer->writer_generation, 37);
	assert(generation[14] == '4' && strchr("89ab", generation[19]));
	for (i = 0; i < 10000; i++) {
		x = global_lb_client_retry_delay(100, 5000, 20, i);
		assert(x >= 80 && x <= 120);
		x = global_lb_client_retry_delay(5000, 5000, 20, i);
		assert(x >= 4000 && x <= 5000);
		x = global_lb_client_retry_delay(INT_MAX, INT_MAX, 100, i);
		assert(x >= 1 && x <= INT_MAX);
	}
	assert(global_lb_client_retry_delay(100, 5000, 0, 0) == 100);
	assert(!global_lb_client_retry_delay(0, 5000, 20, 0));
	assert(global_lb_client_retry_next(100, 5000) == 200);
	assert(global_lb_client_retry_next(4000, 5000) == 5000);
	assert(global_lb_client_retry_next(INT_MAX-1, INT_MAX) == INT_MAX);
	assert(tick_is_expired(tick_add(UINT_MAX - 50, 100), 60));
	assert(!tick_is_expired(tick_add(UINT_MAX - 50, 100), UINT_MAX - 20));
	if (strchr(global_lb_cfg.state_store_host, ':')) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(global_lb_cfg.state_store_port);
		assert(inet_pton(AF_INET6, global_lb_cfg.state_store_host, &a->sin6_addr) == 1);
	}
	else {
		struct sockaddr_in *a = (struct sockaddr_in *)&address;
		a->sin_family = AF_INET;
		a->sin_port = htons(global_lb_cfg.state_store_port);
		assert(inet_pton(AF_INET, global_lb_cfg.state_store_host, &a->sin_addr) == 1);
	}
	assert(!global_lb_client_start(NULL, &limits, event, &ready_count));
	assert(!global_lb_client_start(&address, NULL, event, &ready_count));
	if (!strcmp(plan, "rxlimit")) limits.reply.bytes = 64;
	assert(global_lb_client_start(&address, &limits, event, &ready_count));
	assert(!global_lb_client_start(&address, &limits, event, &ready_count));
	if (!strcmp(plan, "stop-connecting"))
		schedule_stop();
	task_destroy(task);
	return NULL;
}

static int driver_init(void)
{
	struct task *task;
	if (master || !getenv("GLB_CLIENT_TEST_PLAN"))
		return 1;
	if (tid) {
		assert(!global_lb_client_writer());
		assert(global_lb_client_state() == GLB_CLIENT_DISABLED);
		assert(!global_lb_client_start(NULL, NULL, NULL, NULL));
		global_lb_client_stop(); /* wrong thread must not stop the singleton */
		return 1;
	}
	plan = getenv("GLB_CLIENT_TEST_PLAN");
	task = task_new_here();
	assert(task);
	task->process = boot;
	task_wakeup(task, TASK_WOKEN_INIT);
	return 1;
}
REGISTER_PER_THREAD_INIT(driver_init);
#endif
