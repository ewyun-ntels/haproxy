/*
 * Optional Global LB configuration parser.
 *
 * Copyright 2026 nTels
 * Licensed under the GNU General Public License, version 2 or later.
 *
 * User Define: UD-007 r3-config-parser-20260904 (USE_GLOBAL_LB).
 * UD-008 r2-global-cache-20260908, UD-010 r2-state-machine-20260909 and
 * UD-011 r1-writer-uuid-lifecycle-20260904 provide the runtime consumers.
 * The parser itself installs no I/O, task, cache or selector.
 */

#ifdef USE_GLOBAL_LB

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <haproxy/cfgparse.h>
#include <haproxy/global_lb.h>
#include <haproxy/log.h>
#include <haproxy/tools.h>

struct global_lb_config global_lb_cfg = {
	.key_prefix = "global-lb",
	.sync_interval = 300,
	.connect_timeout = 200,
	.command_timeout = 100,
	.reconnect_initial = 100,
	.reconnect_max = 5000,
	.reconnect_jitter = 20,
	.snapshot_ttl = 3000,
	.stale_after = 3000,
	.recovery_successes = 3,
};

enum global_lb_cfg_option {
	GLB_STORE, GLB_INSTANCE, GLB_PREFIX, GLB_SYNC, GLB_CONNECT, GLB_COMMAND,
	GLB_RECONNECT, GLB_JITTER, GLB_TTL, GLB_STALE, GLB_RECOVERY,
};

/* Set only after successful parsing; reject duplicates across global sections. */
static unsigned int global_lb_cfg_seen;

static int global_lb_parse_uint(const char *text, unsigned int min,
				unsigned int max, unsigned int *value)
{
	unsigned int n = 0;
	const unsigned char *p = (const unsigned char *)text;

	if (!*p)
		return 0;
	for (; *p; p++) {
		if (*p < '0' || *p > '9' || n > max / 10 ||
		    (n == max / 10 && (unsigned int)(*p - '0') > max % 10))
			return 0;
		n = n * 10 + (*p - '0');
	}
	if (n < min)
		return 0;
	*value = n;
	return 1;
}

static int global_lb_parse_time(const char *text, unsigned int *value, char **err)
{
	unsigned int ms;
	unsigned long long n = 0, limit = INT_MAX;
	const char *p = text;

	/* The native parser rounds up, but currently tolerates trailing text and
	 * can wrap extremely long numeric inputs. Validate before conversion.
	 */
	for (; *p >= '0' && *p <= '9'; p++) {
		if (n > ((unsigned long long)INT_MAX * 1000 - (*p - '0')) / 10)
			goto invalid;
		n = n * 10 + (*p - '0');
	}
	if (!strcmp(p, "us"))
		limit *= 1000;
	else if (!strcmp(p, "s"))
		limit /= 1000;
	else if (!strcmp(p, "m"))
		limit /= 60000;
	else if (!strcmp(p, "h"))
		limit /= 3600000;
	else if (!strcmp(p, "d"))
		limit /= 86400000;
	else if (*p && strcmp(p, "ms"))
		goto invalid;
	if (p == text || !n || n > limit || parse_time_err(text, &ms, TIME_UNIT_MS))
		goto invalid;
	*value = ms;
	return 0;

 invalid:
	memprintf(err, "'global-lb' expects a duration from 1 to %d ms, got '%s'", INT_MAX, text);
	return -1;
}

/* Identifiers remain opaque here. Key construction/escaping belongs to the
 * future storage protocol, not this configuration-only stage.
 */
static int global_lb_valid_identifier(const char *text)
{
	const unsigned char *p = (const unsigned char *)text;

	if (!*p)
		return 0;
	for (; *p; p++) {
		if (*p < 33 || *p > 126)
			return 0;
	}
	return 1;
}

/* Only plain TCP endpoints: no URI, credentials, socket FD or port range.
 * Parse a numeric address or retain a hostname without a DNS lookup. The
 * connector's resolution lifecycle is deliberately not implemented here.
 */
static int global_lb_parse_store(const char *text, char **err)
{
	const char *host = text, *end, *port;
	struct in6_addr addr6;
	struct in_addr addr4;
	char *copy;
	unsigned int number;
	int bracketed = (*text == '[');

	if (bracketed) {
		host++;
		end = strchr(host, ']');
		if (!end || end[1] != ':')
			goto invalid;
		port = end + 2;
	}
	else {
		end = strchr(host, ':');
		if (!end)
			goto invalid;
		port = end + 1;
	}
	if (end == host || !global_lb_parse_uint(port, 1, 65535, &number))
		goto invalid;
	copy = my_strndup(host, end - host);
	if (!copy) {
		memprintf(err, "out of memory parsing 'global-lb state-store'");
		return -1;
	}
	if (bracketed) {
		if (inet_pton(AF_INET6, copy, &addr6) != 1)
			goto invalid_copy;
	}
	else if (inet_pton(AF_INET, copy, &addr4) != 1) {
		const char *label = copy, *p;

		if (strlen(copy) > 253 || invalid_domainchar(copy) ||
		    strspn(copy, "0123456789.") == strlen(copy))
			goto invalid_copy;
		for (p = copy; ; p++) {
			if (*p && *p != '.')
				continue;
			if (p == label || p - label > 63 || *label == '-' || p[-1] == '-')
				goto invalid_copy;
			if (!*p || !p[1]) /* allow a final DNS root dot */
				break;
			label = p + 1;
		}
	}
	global_lb_cfg.state_store_host = copy;
	global_lb_cfg.state_store_port = number;
	return 0;

 invalid_copy:
	free(copy);
 invalid:
	memprintf(err, "'global-lb state-store' expects host:port or [IPv6]:port with port 1..65535 (plain TCP only)");
	return -1;
}

static int cfg_parse_global_lb(char **args, int section_type, struct proxy *curpx,
			       const struct proxy *defpx, const char *file, int line,
			       char **err)
{
	enum global_lb_cfg_option option;
	unsigned int *timer = NULL, first, second;
	int argc = 2;
	char *copy;

	if (!strcmp(args[1], "state-store"))
		option = GLB_STORE;
	else if (!strcmp(args[1], "instance-id"))
		option = GLB_INSTANCE;
	else if (!strcmp(args[1], "key-prefix"))
		option = GLB_PREFIX;
	else if (!strcmp(args[1], "sync-interval")) {
		option = GLB_SYNC;
		timer = &global_lb_cfg.sync_interval;
	}
	else if (!strcmp(args[1], "timeout")) {
		argc = 3;
		if (!strcmp(args[2], "connect")) {
			option = GLB_CONNECT;
			timer = &global_lb_cfg.connect_timeout;
		}
		else if (!strcmp(args[2], "command")) {
			option = GLB_COMMAND;
			timer = &global_lb_cfg.command_timeout;
		}
		else {
			memprintf(err, "'global-lb timeout' expects 'connect' or 'command'");
			return -1;
		}
	}
	else if (!strcmp(args[1], "reconnect")) {
		option = GLB_RECONNECT;
		argc = 3;
	}
	else if (!strcmp(args[1], "reconnect-jitter"))
		option = GLB_JITTER;
	else if (!strcmp(args[1], "snapshot-ttl")) {
		option = GLB_TTL;
		timer = &global_lb_cfg.snapshot_ttl;
	}
	else if (!strcmp(args[1], "stale-after")) {
		option = GLB_STALE;
		timer = &global_lb_cfg.stale_after;
	}
	else if (!strcmp(args[1], "recovery-successes"))
		option = GLB_RECOVERY;
	else {
		memprintf(err, "'global-lb' expects state-store, instance-id, key-prefix, sync-interval, timeout, reconnect, reconnect-jitter, snapshot-ttl, stale-after or recovery-successes");
		return -1;
	}

	if (!*args[2] || (argc == 3 && !*args[3]) || too_many_args(argc, args, err, NULL)) {
		if (!*err)
			memprintf(err, "'global-lb %s' expects %d argument(s)", args[1], argc - 1);
		return -1;
	}
	if (global_lb_cfg_seen & (1U << option)) {
		memprintf(err, "'global-lb %s%s%s' already specified", args[1],
		          option == GLB_CONNECT || option == GLB_COMMAND ? " " : "",
		          option == GLB_CONNECT || option == GLB_COMMAND ? args[2] : "");
		return -1;
	}

	if (timer) {
		if (global_lb_parse_time(args[argc], timer, err) < 0)
			return -1;
	}
	else if (option == GLB_STORE) {
		if (global_lb_parse_store(args[2], err) < 0)
			return -1;
	}
	else if (option == GLB_INSTANCE || option == GLB_PREFIX) {
		if (!global_lb_valid_identifier(args[2])) {
			memprintf(err, "'global-lb %s' expects a non-empty printable ASCII token without whitespace", args[1]);
			return -1;
		}
		copy = strdup(args[2]);
		if (!copy) {
			memprintf(err, "out of memory parsing 'global-lb %s'", args[1]);
			return -1;
		}
		if (option == GLB_INSTANCE)
			global_lb_cfg.instance_id = copy;
		else
			global_lb_cfg.key_prefix = copy;
	}
	else if (option == GLB_RECONNECT) {
		if (global_lb_parse_time(args[2], &first, err) < 0 ||
		    global_lb_parse_time(args[3], &second, err) < 0)
			return -1;
		if (first > second) {
			memprintf(err, "'global-lb reconnect' initial delay must not exceed maximum delay");
			return -1;
		}
		global_lb_cfg.reconnect_initial = first;
		global_lb_cfg.reconnect_max = second;
	}
	else {
		unsigned int min = option == GLB_JITTER ? 0 : 1;
		unsigned int max = option == GLB_JITTER ? 100 : INT_MAX;

		if (!global_lb_parse_uint(args[2], min, max, &first)) {
			memprintf(err, "'global-lb %s' expects an integer from %u to %u", args[1], min, max);
			return -1;
		}
		if (option == GLB_JITTER)
			global_lb_cfg.reconnect_jitter = first;
		else
			global_lb_cfg.recovery_successes = first;
	}
	global_lb_cfg_seen |= 1U << option;
	global_lb_cfg.configured = 1;
	return 0;
}

static int global_lb_check_config(void)
{
	int errors = 0;

	/* Feature-enabled builds still accept all legacy configurations. */
	if (!global_lb_cfg.configured)
		return 0;
	if (!global_lb_cfg.state_store_host || !global_lb_cfg.instance_id) {
		ha_alert("global-lb: both 'state-store' and 'instance-id' are required when any global-lb setting is used.\n");
		errors++;
	}
	if (global_lb_cfg.snapshot_ttl <= global_lb_cfg.sync_interval ||
	    global_lb_cfg.stale_after <= global_lb_cfg.sync_interval) {
		ha_alert("global-lb: 'snapshot-ttl' and 'stale-after' must exceed 'sync-interval'.\n");
		errors++;
	}
	return errors;
}

static void global_lb_deinit_config(void)
{
	ha_free(&global_lb_cfg.state_store_host);
	ha_free(&global_lb_cfg.instance_id);
	if (global_lb_cfg_seen & (1U << GLB_PREFIX))
		free((char *)global_lb_cfg.key_prefix);
	global_lb_cfg.key_prefix = "global-lb";
	global_lb_cfg_seen = 0;
	global_lb_cfg.configured = 0;
}

static int cfg_parse_global_lb_backend(char **args, int section_type, struct proxy *curpx,
		const struct proxy *defpx, const char *file, int line, char **err)
{
#ifdef USE_GLOBAL_LEASTCONN
	if ((curpx->cap & PR_CAP_BE) && !strcmp(args[1], "fallback") &&
	    !strcmp(args[2], "leastconn") && !*args[3])
		return 0; /* Native LC is the only v1 fallback. */
#endif
	memprintf(err, "backend global-lb requires USE_GLOBAL_LEASTCONN and 'fallback leastconn'");
	return -1;
}

static struct cfg_kw_list global_lb_cfg_kws = { ILH, {
	{ CFG_GLOBAL, "global-lb", cfg_parse_global_lb },
	{ CFG_LISTEN, "global-lb", cfg_parse_global_lb_backend },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &global_lb_cfg_kws);
REGISTER_CONFIG_POSTPARSER("global-lb", global_lb_check_config);
REGISTER_POST_DEINIT(global_lb_deinit_config);

#endif /* USE_GLOBAL_LB */
