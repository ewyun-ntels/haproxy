/* UD-007/009/016 v2-r2-20261003. TEST-ONLY lifecycle driver.
 * Linked ONLY via EXTRA_OBJS in a separate test binary. Never in Makefile's
 * production object list. Supplies empty START/HB for actual native-hook I/O
 * tests; does NOT implement/certify step-3 recovery/shutdown/runtime policy. */
#if defined(USE_GLOBAL_LB) && defined(USE_GLOBAL_LEASTCONN)
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <haproxy/api.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_dispatch.h>
#include <haproxy/global_lb_reserve.h>
#include <haproxy/init.h>
#include <haproxy/ticks.h>

static int control, active;
static uint64_t captured;
static unsigned int next_hb;
static void send_control(enum global_lb_reserve_op op)
{
	struct global_lb_reserve_command c = { 0 };
	struct glb_ledger *l;
	unsigned char *wire = NULL;
	size_t len;
	c.op = op; c.prefix = global_lb_cfg.key_prefix; c.instance_id = global_lb_cfg.instance_id;
	c.writer_generation = global_lb_client_writer()->writer_generation;
	c.revision = 1; c.instance_timeout = global_lb_cfg.instance_timeout;
	c.tie_seed = 1;
	c.limits = (struct global_lb_reserve_limits){64, 4096, 100000};
	l = global_lb_dispatch_lock(); captured = l->changes; global_lb_dispatch_unlock();
	if (global_lb_reserve_encode(&c, 8U*1024*1024, &wire, &len) != GLB_RESP_OK ||
	    !global_lb_client_submit(&wire, len)) abort();
	control = op + 1; free(wire);
}
static void callback(enum global_lb_client_event event, enum global_lb_client_error error,
		const struct global_lb_resp_parser *parser, void *context)
{
	struct global_lb_reserve_reply r;
	struct glb_ledger *l;
	int owned = global_lb_dispatch_event(event, parser);
	if (getenv("GLB_TEST_DEBUG")) fprintf(stderr, "TEST event=%d error=%d owned=%d control=%d\n", event, error, owned, control);
	(void)error; (void)context;
	if (event == GLB_CLIENT_FAILED || event == GLB_CLIENT_SHUTDOWN) { active = 0; return; }
	if (event == GLB_CLIENT_CONNECTED) {
		/* Test deliberately does not claim reconnection/restore support. */
		if (!next_hb) send_control(GLB_RESERVE_START);
		return;
	}
	if (event == GLB_CLIENT_REPLY && !owned && control) {
		if (!global_lb_reserve_result(parser, &r) || r.status != GLB_RESERVE_OK) abort();
		if (control == GLB_RESERVE_START + 1) {
			l = global_lb_dispatch_lock();
			active = glb_ledger_activate(l, global_lb_client_writer()->writer_generation, 1, captured);
			global_lb_dispatch_unlock();
			if (!active) abort();
		}
		control = 0; next_hb = tick_add(now_ms, global_lb_cfg.heartbeat_interval);
		global_lb_client_schedule(global_lb_cfg.heartbeat_interval);
	}
	l = global_lb_dispatch_lock(); active = l->active; global_lb_dispatch_unlock();
	if (control) return;
	if (active && tick_is_expired(next_hb, now_ms)) send_control(GLB_RESERVE_HEARTBEAT);
	else global_lb_dispatch_pump();
}
static int test_init(void)
{
	struct sockaddr_storage address = { 0 };
	struct sockaddr_in *v4 = (void *)&address;
	struct global_lb_reserve_limits budget = {64, 4096, 100000};
	struct global_lb_client_limits transport = {
		.tx_bytes = 8U*1024*1024, .reply = { .bytes = 65536,
		.nodes = 16, .depth = 4 },
		.io_bytes = 65536, .io_calls = 16,
	};
	if (tid || master || !global_lb_cfg.reservation_mode) return 1;
	if (getenv("GLB_TEST_DEBUG")) fprintf(stderr, "TEST init state=%d\n", global_lb_client_state());
	v4->sin_family = AF_INET; v4->sin_port = htons(global_lb_cfg.state_store_port);
	if (inet_pton(AF_INET, global_lb_cfg.state_store_host, &v4->sin_addr) != 1) return 0;
	if (!global_lb_dispatch_configure(&budget, transport.tx_bytes, 200000)) return 0;
	return global_lb_client_start(&address, &transport, callback, NULL);
}
REGISTER_PER_THREAD_INIT(test_init);
#endif
