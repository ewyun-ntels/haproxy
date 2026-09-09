/* Global LeastConn traffic-path selector. Copyright 2026 nTels.
 * LGPL-2.1 exclusively.
 * UD-011 r1-global-selector-20260909.
 */
#ifdef USE_GLOBAL_LEASTCONN
#include <stdint.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_collect.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/global_lb_select.h>
#include <haproxy/proxy-t.h>
#include <haproxy/queue.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

/* Build the same actual backend|IP:port identity later observed by
 * global_lb_endpoint_take(). This mirrors alloc_dst_address() without
 * allocating or modifying the stream.
 */
static int global_lb_server_key(const struct stream *stream,
				struct server *srv, char *key, size_t size)
{
	struct sockaddr_storage address = srv->addr;
	const struct sockaddr_storage *incoming;
	int port;

	if (srv->flags & SRV_F_RHTTP)
		return 0;
	set_host_port(&address, srv->svc_port);
	incoming = sc_dst(stream->scf);
	if (!is_addr(&address)) {
		if (!incoming || (incoming->ss_family != AF_INET &&
		                  incoming->ss_family != AF_INET6))
			return 0;
		if (incoming->ss_family == AF_INET) {
			address.ss_family = AF_INET;
			((struct sockaddr_in *)&address)->sin_addr =
				((const struct sockaddr_in *)incoming)->sin_addr;
		}
		else {
			address.ss_family = AF_INET6;
			((struct sockaddr_in6 *)&address)->sin6_addr =
				((const struct sockaddr_in6 *)incoming)->sin6_addr;
		}
	}
	if (srv->flags & SRV_F_MAPPORTS) {
		if (!incoming)
			return 0;
		port = get_host_port(incoming) + get_host_port(&address);
		if (port <= 0 || port > 65535)
			return 0;
		set_host_port(&address, port);
	}
	port = get_host_port(&address);
	return port > 0 && global_lb_format_endpoint_key(stream->be->id,
							  &address, port, key, size);
}

static int global_lb_candidate(const struct proxy *proxy,
			       const struct server *srv)
{
	if (!srv_currently_usable(srv))
		return 0;
	if (proxy->srv_act)
		return !(srv->flags & SRV_F_BACKUP);
	if (proxy->lbprm.fbck)
		return srv == proxy->lbprm.fbck;
	return !!(srv->flags & SRV_F_BACKUP);
}

static int global_lb_has_capacity(const struct server *srv)
{
	unsigned int served, queued;

	if (!srv->maxconn)
		return 1;
	served = _HA_ATOMIC_LOAD(&srv->served);
	queued = _HA_ATOMIC_LOAD(&srv->queueslength);
	return (uint64_t)served + queued <
	       (uint64_t)srv_dynamic_maxconn(srv) + srv->maxqueue;
}

/* cached global - the same cache's own contribution + the current local
 * absolute count. Missing endpoints have zero remote contribution. Arithmetic
 * inconsistency is fail-closed to native local leastconn.
 */
static int global_lb_score(const struct global_lb_cache_value *cached,
			   uint64_t local_count, uint64_t *score)
{
	uint64_t remote = 0;

	if (cached->found) {
		if (cached->global_count < cached->own_count)
			return 0;
		remote = cached->global_count - cached->own_count;
	}
	if (UINT64_MAX - remote < local_count)
		return 0;
	*score = remote + local_count;
	return 1;
}

int global_lb_select_server(struct stream *stream, struct server *avoid,
			    struct server **selected)
{
	struct global_lb_cache_status status;
	struct server *srv, *best = NULL, *avoided = NULL;
	uint64_t best_score = UINT64_MAX;
	unsigned int ties = 0;
	int fallback = 0;

	*selected = NULL;
	global_lb_cache_get_status(now_ms, &status);
	if (!status.usable)
		return 0;

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &stream->be->lbprm.lock);
	for (srv = stream->be->srv; srv; srv = srv->next) {
		struct global_lb_cache_value cached;
		uint64_t local_count, score;
		char key[GLB_PUBLISH_KEY_SIZE];

		if (!global_lb_candidate(stream->be, srv) ||
		    !global_lb_has_capacity(srv))
			continue;
		if (!global_lb_server_key(stream, srv, key, sizeof(key))) {
			fallback = 1;
			break;
		}
		global_lb_cache_lookup(key, now_ms, &cached);
		if (!cached.usable || cached.version != status.version ||
		    !global_lb_endpoint_local_count(key, &local_count) ||
		    !global_lb_score(&cached, local_count, &score)) {
			fallback = 1;
			break;
		}

		if (srv == avoid) {
			avoided = srv;
			continue;
		}
		if (!best || score < best_score) {
			best = srv;
			best_score = score;
			ties = 1;
		}
		else if (score == best_score &&
		         statistical_prng_range(++ties) == 0)
			best = srv;
	}
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &stream->be->lbprm.lock);

	if (fallback)
		return 0;
	*selected = best ? best : avoided;
	return 1;
}
#endif /* USE_GLOBAL_LEASTCONN */
