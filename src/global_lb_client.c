/* One event-loop-owned nonblocking RESP2 transport per HAProxy worker.
 * Copyright 2026 nTels. LGPL-2.1 exclusively.
 * UD-007 r6-async-client-20260904 / UD-011 r4-worker-identity-20260904.
 */
#ifdef USE_GLOBAL_LB
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_resp.h>
#include <haproxy/global_lb_store.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/init.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>

static struct {
	enum global_lb_client_state state;
	struct global_lb_store_writer writer;
	struct sockaddr_storage address;
	struct global_lb_client_limits limits;
	struct global_lb_resp_parser parser;
	struct task *task;
	global_lb_client_cb callback;
	void *context;
	unsigned char *tx;
	size_t tx_len, tx_sent;
	unsigned int deadline, backoff;
	unsigned int caller_deadline;
	int (*resolve)(struct sockaddr_storage *);
	int fd, delivering;
} client = { .fd = -1 };

unsigned int global_lb_client_retry_next(unsigned int base, unsigned int cap)
{
	return base >= cap || base > cap / 2 ? cap : base * 2;
}

unsigned int global_lb_client_retry_delay(unsigned int base, unsigned int cap,
					 unsigned int jitter, unsigned int random)
{
	uint64_t spread, low, high;

	if (!base || !cap || jitter > 100)
		return 0;
	base = MIN(base, cap);
	spread = (uint64_t)base * jitter / 100;
	low = MAX(1, base - spread);
	high = MIN((uint64_t)cap, base + spread);
	return low + random % (high - low + 1);
}

enum global_lb_client_state global_lb_client_state(void)
{
	return tid || master ? GLB_CLIENT_DISABLED : client.state;
}

struct global_lb_store_writer *global_lb_client_writer(void)
{
	return tid || master || client.state == GLB_CLIENT_DISABLED ? NULL : &client.writer;
}

static void client_close(void)
{
	if (client.fd >= 0) {
		fd_delete(client.fd); /* fd_delete owns close(), do not close twice. */
		client.fd = -1;
	}
	free(client.tx);
	client.tx = NULL;
	client.tx_len = client.tx_sent = 0;
}

void global_lb_client_stop(void)
{
	if (tid || master || client.state == GLB_CLIENT_DISABLED)
		return;
	client.state = GLB_CLIENT_STOPPED;
	client.deadline = TICK_ETERNITY;
	client_close();
	/* Preserve a borrowed reply while inside the caller's callback. */
	if (!client.delivering)
		global_lb_resp_release(&client.parser);
	task_destroy(client.task);
	client.task = NULL;
	client.callback = NULL;
}

static void client_fail(enum global_lb_client_error error)
{
	unsigned int delay;

	client_close();
	global_lb_resp_reset(&client.parser);
	delay = global_lb_client_retry_delay(client.backoff, global_lb_cfg.reconnect_max,
			global_lb_cfg.reconnect_jitter, (unsigned int)ha_random64());
	client.backoff = global_lb_client_retry_next(client.backoff, global_lb_cfg.reconnect_max);
	client.state = GLB_CLIENT_BACKOFF;
	client.deadline = tick_add(now_ms, delay);
	client.callback(GLB_CLIENT_FAILED, error, NULL, client.context);
}

/* Disable activity until the pinned task consumes readiness. It will rearm
 * directions with fd_want_* and acknowledge EAGAIN with fd_cant_*.
 */
static void client_fd_handler(int fd)
{
	fd_stop_both(fd);
	task_wakeup(client.task, TASK_WOKEN_IO);
}

static void client_connected(void)
{
	client.state = GLB_CLIENT_READY;
	client.deadline = TICK_ETERNITY;
	fd_stop_send(client.fd);
	client.callback(GLB_CLIENT_CONNECTED, GLB_CLIENT_OK, NULL, client.context);
}

static void client_connect(void)
{
	int fd, ret;

	if (client.resolve && !client.resolve(&client.address)) {
		client_fail(GLB_CLIENT_SOCKET_ERROR);
		return;
	}

	fd = socket(client.address.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		client_fail(GLB_CLIENT_SOCKET_ERROR);
		return;
	}
	if (fd >= global.maxsock || fd_set_nonblock(fd) == -1 || fd_set_cloexec(fd) == -1) {
		close(fd); /* not yet inserted in fdtab */
		client_fail(GLB_CLIENT_SOCKET_ERROR);
		return;
	}
	client.fd = fd;
	fd_insert(fd, &client, client_fd_handler, ti->tgid, ti->ltid_bit);
	client.state = GLB_CLIENT_CONNECTING;
	client.deadline = tick_add(now_ms, global_lb_cfg.connect_timeout);
	ret = connect(fd, (struct sockaddr *)&client.address, get_addr_len(&client.address));
	if (ret == 0) {
		client_connected();
		return;
	}
	if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR) {
		client_fail(GLB_CLIENT_IO_ERROR);
		return;
	}
	fd_cant_send(fd);
	fd_cant_recv(fd);
}

int global_lb_client_submit(unsigned char **wire, size_t len)
{
	if (tid || master || stopping || client.state != GLB_CLIENT_READY ||
	    !wire || !*wire || !len || len > client.limits.tx_bytes)
		return 0;
	if (!client.delivering)
		global_lb_resp_reset(&client.parser);
	client.tx = *wire;
	*wire = NULL;
	client.tx_len = len;
	client.tx_sent = 0;
	client.state = GLB_CLIENT_COMMAND;
	client.deadline = tick_add(now_ms, global_lb_cfg.command_timeout);
	fd_may_send(client.fd);
	task_wakeup(client.task, TASK_WOKEN_MSG);
	return 1;
}

void global_lb_client_schedule(unsigned int delay)
{
	if (tid || master || !client.task || !delay)
		return;
	client.caller_deadline = tick_add(now_ms, delay);
	task_wakeup(client.task, TASK_WOKEN_MSG);
}

void global_lb_client_resolver(int (*resolve)(struct sockaddr_storage *))
{
	if (!tid && !master)
		client.resolve = resolve;
}

static struct task *client_process(struct task *t, void *context, unsigned int state)
{
	unsigned char buffer[4096];
	size_t budget = client.limits.io_bytes;
	unsigned int calls = client.limits.io_calls;

	if (stopping) {
		global_lb_client_stop();
		return NULL;
	}
	if (client.state == GLB_CLIENT_BACKOFF && tick_is_expired(client.deadline, now_ms))
		client_connect();
	if (!client.task)
		return NULL;
	if (client.state == GLB_CLIENT_CONNECTING) {
		int error = 0;
		socklen_t len = sizeof(error);
		if (tick_is_expired(client.deadline, now_ms))
			client_fail(GLB_CLIENT_CONNECT_TIMEOUT);
		else if (fd_send_ready(client.fd)) {
			if (getsockopt(client.fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error)
				client_fail(GLB_CLIENT_IO_ERROR);
			else
				client_connected();
		}
	}
	if (client.state == GLB_CLIENT_COMMAND && tick_is_expired(client.deadline, now_ms))
		client_fail(GLB_CLIENT_COMMAND_TIMEOUT);
	/* Calls and bytes are both bounded, including EINTR and writable sockets. */
	while (client.state == GLB_CLIENT_COMMAND && client.tx_sent < client.tx_len &&
	       fd_send_ready(client.fd) && calls && budget) {
		ssize_t n;
		calls--;
		n = send(client.fd, client.tx + client.tx_sent,
			 MIN(client.tx_len - client.tx_sent, budget), MSG_NOSIGNAL);
		if (n > 0) {
			client.tx_sent += n;
			budget -= n;
		}
		else if (n < 0 && errno == EINTR)
			continue;
		else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			fd_cant_send(client.fd);
			break;
		}
		else {
			client_fail(GLB_CLIENT_IO_ERROR);
			break;
		}
	}
	while ((client.state == GLB_CLIENT_READY || client.state == GLB_CLIENT_COMMAND) &&
	       fd_recv_ready(client.fd) && calls && budget) {
		ssize_t n;
		size_t used;
		enum global_lb_resp_status status;
		calls--;
		n = recv(client.fd, buffer, MIN(sizeof(buffer), budget), 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			fd_cant_recv(client.fd);
			break;
		}
		if (n <= 0) {
			client_fail(n == 0 ? GLB_CLIENT_EOF : GLB_CLIENT_IO_ERROR);
			break;
		}
		budget -= n;
		/* No unsolicited replies or replies before the command was sent. */
		if (client.state != GLB_CLIENT_COMMAND || client.tx_sent != client.tx_len) {
			client_fail(GLB_CLIENT_PROTOCOL_ERROR);
			break;
		}
		status = global_lb_resp_feed(&client.parser, buffer, n, &used);
		if (status == GLB_RESP_ERROR || used != (size_t)n) {
			client_fail(GLB_CLIENT_PROTOCOL_ERROR);
			break;
		}
		if (status == GLB_RESP_DONE) {
			free(client.tx);
			client.tx = NULL;
			client.tx_len = client.tx_sent = 0;
			client.state = GLB_CLIENT_READY;
			client.deadline = TICK_ETERNITY;
			client.backoff = global_lb_cfg.reconnect_initial;
			client.delivering = 1;
			client.callback(GLB_CLIENT_REPLY, GLB_CLIENT_OK, &client.parser, client.context);
			client.delivering = 0;
			if (client.state == GLB_CLIENT_STOPPED)
				global_lb_resp_release(&client.parser);
			else
				global_lb_resp_reset(&client.parser);
			/* A callback may have submitted the next command. Yield first. */
			break;
		}
	}
	if (!client.task)
		return NULL;
	if (client.state == GLB_CLIENT_READY && tick_is_expired(client.caller_deadline, now_ms)) {
		client.caller_deadline = TICK_ETERNITY;
		client.callback(GLB_CLIENT_TIMER, GLB_CLIENT_OK, NULL, client.context);
	}
	if (!client.task)
		return NULL;
	if (client.fd >= 0) {
		if (client.state == GLB_CLIENT_CONNECTING)
			fd_want_send(client.fd);
		else {
			fd_want_recv(client.fd); /* also detect idle EOF/unsolicited data */
			if (client.tx_sent < client.tx_len)
				fd_want_send(client.fd);
			else
				fd_stop_send(client.fd);
		}
	}
	client.task->expire = client.deadline;
	if (client.state == GLB_CLIENT_READY)
		client.task->expire = tick_first(client.deadline, client.caller_deadline);
	task_queue(client.task);
	return client.task;
}

int global_lb_client_start(const struct sockaddr_storage *address,
		const struct global_lb_client_limits *limits,
		global_lb_client_cb callback, void *context)
{
	if (tid || master || stopping || client.state != GLB_CLIENT_IDLE ||
	    !address || !limits || !callback || !limits->tx_bytes ||
	    !limits->io_bytes || !limits->io_calls ||
	    !global_lb_cfg.connect_timeout || !global_lb_cfg.command_timeout ||
	    !global_lb_cfg.reconnect_initial || global_lb_cfg.reconnect_jitter > 100 ||
	    global_lb_cfg.reconnect_initial > global_lb_cfg.reconnect_max)
		return 0;
	if ((address->ss_family != AF_INET && address->ss_family != AF_INET6) ||
	    !get_host_port(address))
		return 0;
	if (!global_lb_resp_init(&client.parser, &limits->reply))
		return 0;
	client.task = task_new_here();
	if (!client.task) {
		global_lb_resp_release(&client.parser);
		return 0;
	}
	client.address = *address;
	client.limits = *limits;
	client.callback = callback;
	client.context = context;
	client.backoff = global_lb_cfg.reconnect_initial;
	client.state = GLB_CLIENT_BACKOFF;
	client.deadline = tick_add(now_ms, 1);
	client.caller_deadline = TICK_ETERNITY;
	client.task->process = client_process;
	client.task->context = &client;
	client.task->expire = client.deadline;
	task_queue(client.task);
	return 1;
}

/* Reserve only one control-plane socket, independently of thread count. */
static int client_check(void)
{
	if (!master && global_lb_cfg.configured && global.maxsock < INT_MAX)
		global.maxsock++;
	return 0;
}

static int client_worker_init(void)
{
	uint64_t entropy[2];

	if (master || tid || !global_lb_cfg.configured)
		return 1;
	/* Called after fork, clock_init_thread_date and ha_random_seed_thread.
	 * Reuse HAProxy's hashed UUID entropy source; no blocking /dev/urandom
	 * open under chroot, no master-owned identity inherited by workers.
	 */
	ha_random64_pair_hashed(&entropy[0], &entropy[1]);
	global_lb_store_writer_init(&client.writer, (unsigned char *)entropy);
	client.state = GLB_CLIENT_IDLE;
	return global_lb_publish_init();
}

static void client_worker_deinit(void)
{
	global_lb_client_stop();
	if (!tid && !master)
		global_lb_publish_deinit();
}

REGISTER_POST_CHECK(client_check);
REGISTER_PER_THREAD_INIT(client_worker_init);
REGISTER_PER_THREAD_DEINIT(client_worker_deinit);
#endif /* USE_GLOBAL_LB */
