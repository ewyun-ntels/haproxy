/* UD-005/007/009/010/011 v2-r2-20261003. Copyright 2026 nTels.
 * LGPL-2.1 exclusively. Native slot lifecycle, no served reimplementation. */
#ifdef USE_GLOBAL_LEASTCONN
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/api.h>
#include <haproxy/global_lb.h>
#include <haproxy/global_lb_client.h>
#include <haproxy/global_lb_dispatch.h>
#include <haproxy/global_lb_publish.h>
#include <haproxy/global_lb_select_v2.h>
#include <haproxy/global_lb_select.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/queue.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/stream.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>

static int enabled(const struct stream *s)
{
	return global_lb_cfg.reservation_mode && s->be->global_lb_enabled;
}
static int capacity(const struct server *srv)
{
	/* Do not reserve an endpoint-specific queue entry. If native CAS loses,
 * no_slot cancels and native queues remain unchanged. */
	return !srv->maxconn || (!_HA_ATOMIC_LOAD(&srv->queueslength) &&
	       _HA_ATOMIC_LOAD(&srv->served) < srv_dynamic_maxconn(srv));
}
static int collect(struct stream *s, char ***out, size_t *count)
{
	struct server *srv, *avoid = objt_server(s->target);
	char **keys;
	size_t n = 0, i;
	char key[GLB_PUBLISH_KEY_SIZE], avoided[GLB_PUBLISH_KEY_SIZE] = "";
	int valid = 1;
	keys = calloc(GLB_PUBLISH_MAX_ENDPOINTS, sizeof(*keys));
	if (!keys) return 0;
	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
	for (srv = s->be->srv; srv; srv = srv->next) {
		if (!global_lb_candidate(s->be, srv) || !capacity(srv)) continue;
		if (!global_lb_server_key(s, srv, key, sizeof(key))) { valid = 0; break; }
		if (srv == avoid) { memcpy(avoided, key, sizeof(avoided)); continue; }
		for (i = 0; i < n; i++) if (!strcmp(keys[i], key)) break;
		if (i != n) continue;
		if (n == GLB_PUBLISH_MAX_ENDPOINTS || !(keys[n] = strdup(key))) { valid = 0; break; }
		n++;
	}
	if (valid && !n && *avoided) {
		keys[0] = strdup(avoided); n = !!keys[0]; valid = !!n;
	}
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
	if (!valid || !n) {
		while (n) free(keys[--n]);
		free(keys); return 0;
	}
	*out = keys; *count = n; return 1;
}
void global_lb_v2_drop(struct stream *s)
{
	struct glb_ledger *l;
	if (!s->global_lb_reservation && !s->global_lb_v2_untracked) return;
	l = global_lb_dispatch_lock();
	glb_ledger_drop(l, s->global_lb_reservation); s->global_lb_reservation = NULL;
	if (s->global_lb_v2_untracked) { l->untracked--; s->global_lb_v2_untracked = 0; }
	global_lb_dispatch_unlock();
	s->global_lb_reserve_deadline = TICK_ETERNITY;
	global_lb_client_kick();
}
int global_lb_v2_select(struct stream *s)
{
	struct glb_ledger *l;
	struct glb_entry *e = s->global_lb_reservation;
	char endpoint[GLB_PUBLISH_KEY_SIZE] = "";
	char **keys = NULL;
	size_t n = 0, i;
	struct server *srv, *best = NULL;
	int active;
	if (!enabled(s) || (s->flags & (SF_ASSIGNED | SF_DIRECT | SF_FORCE_PRST)) ||
	    s->srv_conn || s->pend_pos) return 0;
	if (!e) {
		l = global_lb_dispatch_lock(); active = l->active; global_lb_dispatch_unlock();
		if (!active || !collect(s, &keys, &n)) return 0;
		e = glb_ledger_prepare(s->task, s->be->id, (const char * const *)keys, n,
		                      tick_add(now_ms, global_lb_cfg.reserve_timeout),
		                      statistical_prng_range(INT_MAX) + 1);
		for (i = 0; i < n; i++) free(keys[i]);
		free(keys);
		if (!e) return 0;
		l = global_lb_dispatch_lock(); active = glb_ledger_admit(l, e); global_lb_dispatch_unlock();
		if (!active) { glb_ledger_free_prepared(e); return 0; }
		s->global_lb_reservation = e; s->global_lb_reserve_deadline = e->deadline;
		if (objt_server(s->target))
			s->global_lb_v2_prev_id = __objt_server(s->target)->puid;
		/* No unregistered dynamic server pointer survives asynchronous wait. */
		stream_set_target(s, NULL);
		global_lb_client_kick(); return 1;
	}
	l = global_lb_dispatch_lock();
	if ((e->state == GLB_WAIT || e->state == GLB_READY) &&
	    tick_is_expired(e->deadline, now_ms)) glb_ledger_expire(l, e);
	if (e->state == GLB_WAIT) { global_lb_dispatch_unlock(); return 1; }
	if (e->state == GLB_READY && e->endpoint)
		strlcpy2(endpoint, e->endpoint, sizeof(endpoint));
	global_lb_dispatch_unlock();
	s->global_lb_reserve_deadline = TICK_ETERNITY;
	if (!*endpoint) { global_lb_v2_drop(s); return 0; }
	/* DNS remap, runtime delete, health/backup/maintenance/drain/capacity may
 * have changed while waiting. Resolve a CURRENT eligible slot, never a
 * borrowed server pointer saved at submission time. */
	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
	for (srv = s->be->srv; srv; srv = srv->next) {
		char key[GLB_PUBLISH_KEY_SIZE];
		if (global_lb_candidate(s->be, srv) && capacity(srv) &&
		    global_lb_server_key(s, srv, key, sizeof(key)) && !strcmp(key, endpoint)) {
			best = srv; break;
		}
	}
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
	if (!best) { global_lb_v2_drop(s); return 0; }
	stream_set_srv_target(s, best); s->flags |= SF_ASSIGNED;
	if (s->be_tgcounters) _HA_ATOMIC_INC(&s->be_tgcounters->cum_lbconn);
	if (best->counters.shared.tg)
		_HA_ATOMIC_INC(&best->counters.shared.tg[tgid - 1]->cum_lbconn);
	return 0;
}
void global_lb_v2_slot(struct stream *s, struct server *srv)
{
	struct glb_ledger *l;
	char key[GLB_PUBLISH_KEY_SIZE];
	if (!enabled(s)) return;
	if (!global_lb_server_key(s, srv, key, sizeof(key))) {
		global_lb_v2_drop(s);
		l = global_lb_dispatch_lock(); l->untracked++; glb_ledger_invalidate(l);
		s->global_lb_v2_untracked = 1; global_lb_dispatch_unlock(); return;
	}
	l = global_lb_dispatch_lock();
	s->global_lb_reservation = glb_ledger_native(l, s->global_lb_reservation, s->task, key);
	s->global_lb_v2_untracked = !s->global_lb_reservation;
	global_lb_dispatch_unlock(); global_lb_client_kick();
}
void global_lb_v2_no_slot(struct stream *s)
{
	if (s->global_lb_reservation && !s->srv_conn) global_lb_v2_drop(s);
}
int global_lb_v2_validate(struct stream *s)
{
	char key[GLB_PUBLISH_KEY_SIZE];
	struct server *srv = objt_server(s->target);
	int valid = 1;
	if (!enabled(s) || !s->global_lb_reservation || !srv) return 1;
	if (!global_lb_server_key(s, srv, key, sizeof(key))) return 0;
	global_lb_dispatch_lock();
	valid = s->global_lb_reservation->endpoint &&
	        !strcmp(s->global_lb_reservation->endpoint, key);
	global_lb_dispatch_unlock();
	return valid;
}
void global_lb_v2_account(struct stream *s)
{
	struct server *old, *srv = objt_server(s->target);
	unsigned int id = s->global_lb_v2_prev_id;
	if (!id) return;
	s->global_lb_v2_prev_id = 0;
	if (srv && srv->puid == id) {
		if (s->be_tgcounters) _HA_ATOMIC_INC(&s->be_tgcounters->retries);
		if (s->sv_tgcounters) _HA_ATOMIC_INC(&s->sv_tgcounters->retries);
		return;
	}
	if (s->txn.http && (s->txn.http->flags & TX_CK_MASK) == TX_CK_VALID) {
		s->txn.http->flags &= ~TX_CK_MASK; s->txn.http->flags |= TX_CK_DOWN;
	}
	s->flags |= SF_REDISP;
	if (s->be_tgcounters) _HA_ATOMIC_INC(&s->be_tgcounters->redispatches);
	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
	for (old = s->be->srv; old; old = old->next) if (old->puid == id) {
		if (old->counters.shared.tg)
			_HA_ATOMIC_INC(&old->counters.shared.tg[tgid - 1]->redispatches);
		break;
	}
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &s->be->lbprm.lock);
}
int global_lb_v2_destination(struct stream *s, const struct sockaddr_storage *dst)
{
	char key[GLB_PUBLISH_KEY_SIZE];
	int valid;
	if (!enabled(s) || !s->global_lb_reservation) return 1;
	if (!global_lb_format_endpoint_key(s->be->id, dst, get_host_port(dst), key, sizeof(key))) return 0;
	global_lb_dispatch_lock();
	valid = s->global_lb_reservation->endpoint &&
	        !strcmp(s->global_lb_reservation->endpoint, key);
	global_lb_dispatch_unlock();
	return valid;
}
#endif
