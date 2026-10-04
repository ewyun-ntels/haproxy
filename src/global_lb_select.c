/* UD-009 v2-only-20261004: shared endpoint identity and eligibility. Copyright 2026 nTels.
 * LGPL-2.1 exclusively.
 * UD-011 r1-global-selector-20260909.
 */
#ifdef USE_GLOBAL_LEASTCONN
#include <stdint.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/global_lb_select.h>
#include <haproxy/proxy-t.h>
#include <haproxy/queue.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

/* Build the actual backend|IP:port identity used by v2 reservations.
 * This mirrors alloc_dst_address() without
 * allocating or modifying the stream.
 */
int global_lb_server_key(const struct stream *stream,
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

int global_lb_candidate(const struct proxy *proxy,
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

#endif /* USE_GLOBAL_LEASTCONN */
