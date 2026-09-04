/* UD-005 r6: registry identity/lifetime/limit tests. Not linked into HAProxy. */
#include <assert.h>
#include <haproxy/cfgparse.h>
#include <haproxy/init.h>
#undef REGISTER_CONFIG_POSTPARSER
#undef REGISTER_POST_DEINIT
#define REGISTER_CONFIG_POSTPARSER(...)
#define REGISTER_POST_DEINIT(...)
#include "../../src/global_lb_publish.c"

void complain(int *counter, const char *message, int taint) { fputs(message, stderr); abort(); }
void ha_backtrace_to_stderr(void) { abort(); }

int main(int argc, char **argv)
{
	struct proxy be = { .id = "be", .global_lb_enabled = 1 };
	struct sockaddr_storage addr = { .ss_family = AF_INET };
	struct stream *streams = calloc(GLB_PUBLISH_MAX_ENDPOINTS + 2, sizeof(*streams));
	size_t count;
	unsigned int i;
	assert(streams);
	publisher.records = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.records));
	publisher.entries = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.entries));
	publisher.keys = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.keys));
	assert(publisher.records && publisher.entries && publisher.keys);
	for (i = 0; i < GLB_PUBLISH_MAX_ENDPOINTS; i++) {
		publisher.records[i].next = publisher.free;
		publisher.free = &publisher.records[i];
	}
	for (i = 0; i < GLB_PUBLISH_MAX_ENDPOINTS + 2; i++)
		streams[i].be = &be;
	inet_pton(AF_INET, "127.0.0.1", &((struct sockaddr_in *)&addr)->sin_addr);
	for (i = 0; i < GLB_PUBLISH_MAX_ENDPOINTS; i++) {
		set_host_port(&addr, i + 1);
		global_lb_endpoint_take(&streams[i], &addr);
		assert(streams[i].global_lb_endpoint);
	}
	assert(publisher_capture(&count) && count == GLB_PUBLISH_MAX_ENDPOINTS);
	/* Duplicate actual endpoints share counts even at the record ceiling. */
	global_lb_endpoint_take(&streams[i], &addr);
	assert(streams[i].global_lb_endpoint == streams[i - 1].global_lb_endpoint);
	assert(((struct endpoint_count *)streams[i].global_lb_endpoint)->count == 2);
	global_lb_endpoint_drop(&streams[i]);
	set_host_port(&addr, i + 1);
	global_lb_endpoint_take(&streams[i], &addr);
	assert(streams[i].global_lb_untracked && !publisher_capture(&count));
	global_lb_endpoint_drop(&streams[0]);
	assert(!publisher_capture(&count)); /* don't disguise existing untracked connection */
	global_lb_endpoint_drop(&streams[i]);
	assert(publisher_capture(&count) && count == GLB_PUBLISH_MAX_ENDPOINTS - 1);
	global_lb_endpoint_take(&streams[i], &addr);
	assert(streams[i].global_lb_endpoint && !streams[i].global_lb_untracked);
	for (i = 0; i <= GLB_PUBLISH_MAX_ENDPOINTS; i++) {
		global_lb_endpoint_drop(&streams[i]);
		global_lb_endpoint_drop(&streams[i]); /* idempotent after lifecycle release */
	}
	assert(publisher_capture(&count) && !count && !publisher.untracked);
	global_lb_endpoint_take(&streams[0], NULL);
	assert(!publisher_capture(&count));
	global_lb_endpoint_drop(&streams[0]);
	assert(publisher_capture(&count) && !count);
	/* Feature runtime opt-out has no counter side effects. */
	be.global_lb_enabled = 0;
	global_lb_endpoint_take(&streams[0], &addr);
	assert(!streams[0].global_lb_endpoint && !streams[0].global_lb_untracked);
	be.global_lb_enabled = 1;
	addr.ss_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &((struct sockaddr_in6 *)&addr)->sin6_addr);
	set_host_port(&addr, 9000);
	global_lb_endpoint_take(&streams[0], &addr);
	assert(publisher_capture(&count) && count == 1);
	assert(!strcmp(publisher.entries[0].endpoint_key, "be|[2001:db8::1]:9000"));
	global_lb_endpoint_drop(&streams[0]);
	publisher_free();
	free(streams);
	puts("PASS: endpoint capacity, duplicate aggregation, missing-count fail-closed, reuse, release, opt-out, IPv6");
	return 0;
}
