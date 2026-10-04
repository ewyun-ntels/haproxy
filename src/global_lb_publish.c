/* UD-007/011/012/013 v2-only-20261004, USE_GLOBAL_LB.
 * Worker transport setup, DNS and bounded terminal cleanup for v2.
 * Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifdef USE_GLOBAL_LB
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_lifecycle.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/init.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/server.h>
#include <haproxy/signal.h>
#include <haproxy/stream.h>
#include <haproxy/stream-t.h>
#include <haproxy/tools.h>

static struct {
	unsigned int enabled, runtime_ready, shutdown;
	struct global_lb_publish_status status;
	struct sig_handler *term_handler, *int_handler, *usr1_handler;
	struct global_lb_dns dns;
	struct sockaddr_storage numeric;
	HA_SPINLOCK_T lock;
} publisher;

void global_lb_publish_get_status(struct global_lb_publish_status *status)
{
	memset(status, 0, sizeof(*status));
	if (!publisher.runtime_ready)
		return;
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	*status = publisher.status;
	status->enabled = publisher.enabled;
	status->shutdown = publisher.shutdown;
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
}

/* UD-012 r1-shutdown-20261002. soft_stop() enters here before setting stopping.
 * Signal callbacks/CLI may request stop; only the existing thread-0 client
 * runs cleanup and resumes native shutdown. Repeated signals do not reset it.
 */
int global_lb_publish_shutdown(void)
{
	unsigned int begin = 0;
	struct proxy *px;
	if (master || !publisher.runtime_ready)
		return 0;
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	if (!publisher.shutdown) {
		_HA_ATOMIC_INC(&jobs); /* acquire before exposing the stop request */
		_HA_ATOMIC_STORE(&publisher.shutdown, 1);
		strcpy(publisher.status.cleanup, "pending");
		begin = 1;
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
	if (begin) {
		global_lb_lifecycle_shutdown();
		/* Stop admissions before excluding counts, then close native streams. */
		for (px = proxies_list; px; px = px->next)
			if (px->cap & PR_CAP_FE) pause_proxy(px);
	}
	return _HA_ATOMIC_LOAD(&publisher.shutdown) != 0;
}

/* Complete terminal stop once, in the normal thread-0 signal queue. Starting
 * native stop from a task can leave another idle thread asleep while signal
 * zero is pending, before that thread acknowledges the stopping state.
 */
int global_lb_publish_stop_ready(void)
{
	unsigned int ready = 0;
	if (master || !publisher.runtime_ready)
		return 0;
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	if (publisher.shutdown == 2) {
		_HA_ATOMIC_STORE(&publisher.shutdown, 3);
		ready = 1;
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
	return ready;
}

static void publisher_signal_stop(struct sig_handler *handler)
{
	soft_stop();
}

void global_lb_publish_shutdown_finish(const char *result)
{
	HA_SPIN_LOCK(OTHER_LOCK, &publisher.lock);
	_HA_ATOMIC_STORE(&publisher.shutdown, 2);
	strlcpy2(publisher.status.cleanup, result, sizeof(publisher.status.cleanup));
	HA_SPIN_UNLOCK(OTHER_LOCK, &publisher.lock);
	ha_notice("global-lb: shutdown reservation cleanup=%s; closing traffic.\n", result);
	send_log(NULL, LOG_NOTICE, "global-lb: shutdown reservation cleanup=%s; closing traffic.\n", result);
	global_lb_client_stop();
	/* Re-enter native soft_stop through its existing signal queue. It drains
	 * the stopping broadcast in the same pass, avoiding a lost stop wakeup.
	 */
	signal_handler(SIGUSR1);
	_HA_ATOMIC_DEC(&jobs);
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
		.reply = { .bytes = 65536, .nodes = 16, .depth = 4 },
		.io_bytes = 65536, .io_calls = 16,
	};
	struct global_lb_dns *dns = &publisher.dns;
	char label[256];

	if (!publisher.enabled)
		return 1;
	HA_SPIN_INIT(&publisher.lock);
	if (!global_lb_lifecycle_init()) goto fail;
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
			ha_warning("global-lb: hostname requires a valid hostname and resolvers 'default'; state-store unavailable, native local leastconn remains active.\n");
	}
	set_host_port(&placeholder, global_lb_cfg.state_store_port);
	if (!global_lb_client_start(&placeholder, &limits,
		global_lb_lifecycle_event, NULL))
		goto fail;
	global_lb_client_resolver(publisher_resolve);
	/* Only opted-in workers intercept terminal signals. Native configs keep
	 * the original HAProxy signal behavior; SIGUSR1 is routed by soft_stop().
	 */
	publisher.term_handler = signal_register_fct(SIGTERM, publisher_signal_stop, SIGTERM);
	publisher.int_handler = signal_register_fct(SIGINT, publisher_signal_stop, SIGINT);
	/* Native SIGUSR1 soft-stop unregisters its one-shot handler after the
	 * deferred first call. Keep an opted-in handler for the completion pass.
	 */
	publisher.usr1_handler = signal_register_fct(SIGUSR1, publisher_signal_stop, SIGUSR1);
	if (!publisher.term_handler || !publisher.int_handler || !publisher.usr1_handler)
		goto fail;
	strcpy(publisher.status.writer_generation, global_lb_client_writer()->writer_generation);
	strcpy(publisher.status.cleanup, "not-requested");
	publisher.runtime_ready = 1;
	return 1;
 fail:
	ha_alert("global-lb: cannot allocate worker resources.\n");
	return 0;
}

void global_lb_publish_deinit(void)
{
	/* Thread-0 transport has stopped before unlinking DNS callbacks. */
	struct global_lb_dns *dns = &publisher.dns;
	if (publisher.term_handler) {
		signal_unregister_handler(publisher.term_handler);
		publisher.term_handler = NULL;
	}
	if (publisher.int_handler) {
		signal_unregister_handler(publisher.int_handler);
		publisher.int_handler = NULL;
	}
	if (publisher.usr1_handler) {
		signal_unregister_handler(publisher.usr1_handler);
		publisher.usr1_handler = NULL;
	}
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
	free(publisher.dns.hostname_dn);
}

REGISTER_CONFIG_POSTPARSER("global-lb publisher", publisher_check);
REGISTER_POST_DEINIT(publisher_free);
#endif
