/* Worker automatic absolute publisher. Copyright 2026 nTels.
 * LGPL-2.1 exclusively.
 * UD-007 r7-publisher-20260904 / UD-005 r6-endpoint-lifecycle-20260904.
 * UD-008 r2-global-cache-20260908 coordinates the fenced collector only.
 * This is NOT a global selector. Native LC stays active.
 */
#ifdef USE_GLOBAL_LB
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_collect.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/global_lb_store.h>
#include <haproxy/init.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/server.h>
#include <haproxy/stream-t.h>
#include <haproxy/tools.h>

#define GLB_BUCKETS 256
struct endpoint_count {
	struct endpoint_count *next;
	uint64_t count;
	unsigned int bucket;
	char key[GLB_PUBLISH_KEY_SIZE];
};

static struct {
	struct endpoint_count *records, *free, *bucket[GLB_BUCKETS];
	struct global_lb_store_entry *entries;
	char (*keys)[GLB_PUBLISH_KEY_SIZE];
	uint64_t untracked;
	unsigned int enabled, started, reported;
#ifdef USE_GLOBAL_LEASTCONN
	unsigned int collecting, collect_reported;
#endif
	struct global_lb_dns dns;
	struct sockaddr_storage numeric;
	HA_SPINLOCK_T lock;
} publisher;

/* cur_sess semantics, including connecting attempts, not served/queue counts.
 * Counters exist only while referenced by streams; freed slots are reusable.
 * A shared short lock serializes registry access and absolute capture. All
 * storage is bounded and preallocated before traffic, never malloc under lock.
 */
void global_lb_endpoint_take(struct stream *s, const struct sockaddr_storage *dst)
{
	struct endpoint_count *entry;
	char key[GLB_PUBLISH_KEY_SIZE];
	const unsigned char *p;
	unsigned int hash = 2166136261U;
	int valid;

	if (!s->be->global_lb_enabled || !publisher.records)
		return;
	BUG_ON(s->global_lb_endpoint || s->global_lb_untracked);
	valid = dst && get_host_port(dst) &&
	        global_lb_format_endpoint_key(s->be->id, dst, get_host_port(dst), key, sizeof(key));
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	if (!valid)
		goto missing;
	for (p = (unsigned char *)key; *p; p++)
		hash = (hash ^ *p) * 16777619U;
	hash %= GLB_BUCKETS;
	for (entry = publisher.bucket[hash]; entry; entry = entry->next)
		if (!strcmp(entry->key, key))
			break;
	if (!entry) {
		entry = publisher.free;
		if (!entry)
			goto missing;
		publisher.free = entry->next;
		entry->next = publisher.bucket[hash];
		publisher.bucket[hash] = entry;
		entry->bucket = hash;
		entry->count = 0;
		strcpy(entry->key, key);
	}
	entry->count++;
	s->global_lb_endpoint = entry;
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
	return;
 missing:
	publisher.untracked++;
	s->global_lb_untracked = 1;
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
}

void global_lb_endpoint_drop(struct stream *s)
{
	struct endpoint_count *entry = s->global_lb_endpoint, **link;
	if (!entry && !s->global_lb_untracked)
		return;
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	if (entry) {
		BUG_ON(!entry->count);
		if (!--entry->count) {
			for (link = &publisher.bucket[entry->bucket]; *link != entry; link = &(*link)->next)
				;
			*link = entry->next;
			entry->next = publisher.free;
			publisher.free = entry;
		}
		s->global_lb_endpoint = NULL;
	}
	if (s->global_lb_untracked) {
		BUG_ON(!publisher.untracked);
		publisher.untracked--;
		s->global_lb_untracked = 0;
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
}

/* Only the optional registry is locked; traffic hooks contend on this lock.
 * There is no server lock or whole-process thread isolation here.
 * Zero endpoints are omitted: a complete Hash replacement removes old fields.
 * Duplicate slots to the same actual endpoint share a counter automatically.
 * Old endpoints remain until their last connection releases its reference.
 */
static int publisher_capture(size_t *count)
{
	struct endpoint_count *entry;
	size_t n = 0;
	unsigned int i;
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	if (publisher.untracked) {
		HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
		return 0;
	}
	for (i = 0; i < GLB_BUCKETS; i++) {
		for (entry = publisher.bucket[i]; entry; entry = entry->next) {
			BUG_ON(n >= GLB_PUBLISH_MAX_ENDPOINTS);
			strcpy(publisher.keys[n], entry->key);
			publisher.entries[n].endpoint_key = publisher.keys[n];
			publisher.entries[n].active_count = entry->count;
			n++;
		}
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
	*count = n;
	return 1;
}

/* DNS callbacks deliberately do not touch the client/task (another thread may
 * execute them). The client reads a copied address under the resolver lock.
 */
int global_lb_dns_success(struct resolv_requester *req, struct dns_counters *counters) { return 1; }
int global_lb_dns_error(struct resolv_requester *req, int error) { return 0; }

static int publisher_resolve(struct sockaddr_storage *address)
{
	struct global_lb_dns *dns = &publisher.dns;
	struct resolv_options opts = { .family_prio = AF_INET, .accept_duplicate_ip = 1 };
	struct resolv_resolution *res;
	short family = AF_UNSPEC;
	void *ip = NULL;
	int ok = 0;

	if (publisher.numeric.ss_family) {
		*address = publisher.numeric;
		return 1;
	}
	if (!dns->resolvers || !dns->requester)
		return 0;
	HA_SPIN_LOCK(DNS_LOCK, &dns->resolvers->lock);
	res = dns->requester->resolution;
	if (res && res->status == RSLV_STATUS_VALID) {
		resolv_get_ip_from_response(&res->response, &opts, NULL, 0, &ip, &family, NULL);
		if (ip && (family == AF_INET || family == AF_INET6)) {
			memset(address, 0, sizeof(*address));
			address->ss_family = family;
			if (family == AF_INET)
				memcpy(&((struct sockaddr_in *)address)->sin_addr, ip, 4);
			else
				memcpy(&((struct sockaddr_in6 *)address)->sin6_addr, ip, 16);
			set_host_port(address, global_lb_cfg.state_store_port);
			ok = 1;
		}
	}
	resolv_trigger_resolution(dns->requester);
	HA_SPIN_UNLOCK(DNS_LOCK, &dns->resolvers->lock);
	return ok;
}

static void publisher_event(enum global_lb_client_event event, enum global_lb_client_error error,
		const struct global_lb_resp_parser *reply, void *context)
{
	struct global_lb_store_writer *writer = global_lb_client_writer();
	enum global_lb_store_result result;
	unsigned char *wire = NULL;
	size_t count, len;
	int failed = 0;

	if (event == GLB_CLIENT_FAILED) {
#ifdef USE_GLOBAL_LEASTCONN
		publisher.collecting = 0;
		global_lb_collect_abort();
#endif
		return; /* transport discards; CONNECTED will capture fresh data */
	}
	if (event == GLB_CLIENT_REPLY) {
#ifdef USE_GLOBAL_LEASTCONN
		if (publisher.collecting) {
			enum global_lb_collect_result collected;

			collected = global_lb_collect_reply(reply, now_ms, &wire, &len);
			if (collected == GLB_COLLECT_NEXT &&
			    global_lb_client_submit(&wire, len))
				return;
			free(wire);
			publisher.collecting = 0;
			if (collected == GLB_COLLECT_COMPLETE) {
				publisher.collect_reported = 0;
				global_lb_client_schedule(global_lb_cfg.sync_interval);
				return;
			}
			global_lb_collect_abort();
			if (!publisher.collect_reported)
				ha_warning(collected == GLB_COLLECT_LIMIT ?
					"global-lb: Global Cache exceeds 4096 unique endpoints; cache invalidated and native local leastconn remains active.\n" :
					"global-lb: incomplete or invalid snapshot collection; previous complete cache is unchanged.\n");
			publisher.collect_reported = 1;
			if (collected == GLB_COLLECT_LIMIT &&
			    global_lb_client_request_reconnect(GLB_CLIENT_RESOURCE_LIMIT))
				return;
			global_lb_client_schedule(global_lb_cfg.sync_interval);
			return;
		}
#endif
		if (!global_lb_store_result(reply, &result) || result != GLB_STORE_STORED) {
			if (!publisher.reported)
				ha_warning("global-lb: snapshot rejected or invalid store reply; keeping native local leastconn.\n");
			publisher.reported = 1;
		}
		else {
			publisher.reported = 0;
		#ifdef USE_GLOBAL_LEASTCONN
			if (global_lb_collect_start(writer, &wire, &len) == GLB_COLLECT_NEXT &&
			    global_lb_client_submit(&wire, len)) {
				publisher.collecting = 1;
				return;
			}
			free(wire);
			global_lb_collect_abort();
			if (!publisher.collect_reported)
				ha_warning("global-lb: cannot start complete snapshot collection; native local leastconn remains active.\n");
			publisher.collect_reported = 1;
		#endif
		}
		global_lb_client_schedule(global_lb_cfg.sync_interval);
		return;
	}
	if (event != GLB_CLIENT_CONNECTED && event != GLB_CLIENT_TIMER)
		return;
	if (!publisher_capture(&count) || !global_lb_store_writer_next(writer))
		failed = 1;
	else if (global_lb_store_encode(publisher.started ? GLB_STORE_UPDATE : GLB_STORE_START,
		global_lb_cfg.key_prefix, global_lb_cfg.instance_id, writer,
		global_lb_cfg.snapshot_ttl, publisher.entries, count,
		GLB_PUBLISH_WIRE_SIZE, &wire, &len) != GLB_RESP_OK)
		failed = 1;
	else if (!global_lb_client_submit(&wire, len))
		failed = 1;
	else {
		/* Once START is submitted, NEVER retry it after an ambiguous outcome.
		 * UPDATE with same UUID registers only if absent; cannot seize owner.
		 */
		publisher.started = 1;
	#ifdef USE_GLOBAL_LEASTCONN
		publisher.collecting = 0;
	#endif
	}
	free(wire);
	if (failed) {
		if (!publisher.reported)
			ha_warning("global-lb: incomplete/oversized local snapshot; publication suppressed, existing snapshot expires by TTL.\n");
		publisher.reported = 1;
		global_lb_client_schedule(global_lb_cfg.sync_interval);
	}
}

static int publisher_check(void)
{
	struct proxy *px;
	struct server *srv;
	int errors = 0;
	for (px = proxies_list; px; px = px->next) {
		if (!px->global_lb_enabled || !(px->cap & PR_CAP_BE) || (px->cap & PR_CAP_INT))
			continue;
		publisher.enabled = 1;
		if (!global_lb_cfg.configured || !global_lb_cfg.state_store_host || !global_lb_cfg.instance_id) {
			ha_alert("global-lb: backend '%s' requires global state-store and instance-id.\n", px->id);
			errors++;
		}
		if (px->mode != PR_MODE_TCP || strlen(px->id) + INET6_ADDRSTRLEN + 10 > GLB_PUBLISH_KEY_SIZE) {
			ha_alert("global-lb: backend '%s' requires mode tcp and an endpoint key shorter than %u bytes.\n", px->id, GLB_PUBLISH_KEY_SIZE);
			errors++;
		}
		for (srv = px->srv; srv; srv = srv->next) {
			if (px->srv && srv->uweight != px->srv->uweight) {
				ha_alert("global-lb: backend '%s' requires equal server weights.\n", px->id);
				errors++;
				break;
			}
		}
	}
	return errors;
}

int global_lb_publish_init(void)
{
	struct sockaddr_storage placeholder = { .ss_family = AF_INET };
	struct global_lb_client_limits limits = {
		.tx_bytes = GLB_PUBLISH_WIRE_SIZE,
#ifdef USE_GLOBAL_LEASTCONN
		.reply = { .bytes = GLB_COLLECT_REPLY_BYTES,
			   .nodes = GLB_COLLECT_REPLY_NODES,
			   .depth = GLB_COLLECT_REPLY_DEPTH },
#else
		.reply = { .bytes = 4096, .nodes = 8, .depth = 2 },
#endif
		.io_bytes = 65536, .io_calls = 16,
	};
	struct global_lb_dns *dns = &publisher.dns;
	char label[256];
	unsigned int i;

	if (!publisher.enabled)
		return 1;
	HA_SPIN_INIT(&publisher.lock);
	publisher.records = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.records));
	publisher.entries = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.entries));
	publisher.keys = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*publisher.keys));
	if (!publisher.records || !publisher.entries || !publisher.keys)
		goto fail;
	for (i = 0; i < GLB_PUBLISH_MAX_ENDPOINTS; i++) {
		publisher.records[i].next = publisher.free;
		publisher.free = &publisher.records[i];
	}
#ifdef USE_GLOBAL_LEASTCONN
	if (!global_lb_collect_init(global_lb_cfg.key_prefix,
				    global_lb_cfg.instance_id, GLB_PUBLISH_WIRE_SIZE))
		goto fail;
#endif
	if (inet_pton(AF_INET, global_lb_cfg.state_store_host, &((struct sockaddr_in *)&publisher.numeric)->sin_addr) == 1)
		publisher.numeric.ss_family = AF_INET;
	else if (inet_pton(AF_INET6, global_lb_cfg.state_store_host, &((struct sockaddr_in6 *)&publisher.numeric)->sin6_addr) == 1)
		publisher.numeric.ss_family = AF_INET6;
	if (publisher.numeric.ss_family)
		set_host_port(&publisher.numeric, global_lb_cfg.state_store_port);
	else {
		dns->obj_type = OBJ_TYPE_GLOBAL_LB_DNS;
		dns->resolvers = find_resolvers_by_id("default");
		dns->hostname_dn_len = resolv_str_to_dn_label(global_lb_cfg.state_store_host,
			strlen(global_lb_cfg.state_store_host), label, sizeof(label));
		if (dns->resolvers && dns->hostname_dn_len > 0) {
			dns->hostname_dn = strdup(label);
			if (!dns->hostname_dn)
				goto fail;
			HA_SPIN_LOCK(DNS_LOCK, &dns->resolvers->lock);
			if (resolv_link_resolution(dns, OBJ_TYPE_GLOBAL_LB_DNS, 0) != 0) {
				HA_SPIN_UNLOCK(DNS_LOCK, &dns->resolvers->lock);
				goto fail;
			}
			resolv_trigger_resolution(dns->requester);
			HA_SPIN_UNLOCK(DNS_LOCK, &dns->resolvers->lock);
		}
		else
			ha_warning("global-lb: hostname requires a valid hostname and resolvers 'default'; publication unavailable, native local leastconn remains active.\n");
	}
	set_host_port(&placeholder, global_lb_cfg.state_store_port);
	if (!global_lb_client_start(&placeholder, &limits, publisher_event, NULL))
		goto fail;
	global_lb_client_resolver(publisher_resolve);
	return 1;
 fail:
	ha_alert("global-lb: cannot allocate publisher resources.\n");
	return 0;
}

void global_lb_publish_deinit(void)
{
	/* Other traffic threads may still be draining their streams. Registry
	 * storage is released only by the process-wide post-deinit hook. */
	struct global_lb_dns *dns = &publisher.dns;
	if (dns->requester) {
		HA_SPIN_LOCK(DNS_LOCK, &dns->resolvers->lock);
		resolv_unlink_resolution(dns->requester);
		pool_free(resolv_requester_pool, dns->requester);
		dns->requester = NULL;
		HA_SPIN_UNLOCK(DNS_LOCK, &dns->resolvers->lock);
	}
}

static void publisher_free(void)
{
#ifdef USE_GLOBAL_LEASTCONN
	global_lb_collect_deinit();
#endif
	free(publisher.records);
	free(publisher.entries);
	free(publisher.keys);
	free(publisher.dns.hostname_dn);
}

REGISTER_CONFIG_POSTPARSER("global-lb publisher", publisher_check);
REGISTER_POST_DEINIT(publisher_free);
#endif
