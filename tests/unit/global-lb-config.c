/* UD-007 r3-config-parser-20260904: stored defaults/ownership regression.
 * Run with tests/unit/global-lb-config-unit.sh from the source root.
 * Include the parser to test private functions without adding production APIs.
 */
#include <stdio.h>
#include <haproxy/cfgparse.h>
#include <haproxy/log.h>

#undef INITCALL1
#undef REGISTER_CONFIG_POSTPARSER
#undef REGISTER_POST_DEINIT
#define INITCALL1(...)
#define REGISTER_CONFIG_POSTPARSER(...)
#define REGISTER_POST_DEINIT(...)
#include "../../src/global_lb_cfg.c"

static int alerts, warnings;
void ha_alert(const char *fmt, ...) { alerts++; }
void ha_warning(const char *fmt, ...) { warnings++; }

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #test); exit(1); } } while (0)

static int parse(const char *name, const char *first, const char *second)
{
	char *args[] = { "global-lb", (char *)name, (char *)first, (char *)second, "" };
	char *err = NULL;
	int ret;

	ret = cfg_parse_global_lb(args, CFG_GLOBAL, NULL, NULL, "unit", 1, &err);
	CHECK((ret < 0) == (err != NULL));
	free(err);
	return ret;
}

int main(int argc, char **argv)
{
	unsigned int value;
	struct global_lb_config defaults = global_lb_cfg;

	CHECK(!global_lb_cfg.configured);
	CHECK(!global_lb_cfg.state_store_host && !global_lb_cfg.instance_id);
	CHECK(!global_lb_cfg.state_store_port);
	CHECK(!strcmp(global_lb_cfg.key_prefix, "global-lb"));
	CHECK(global_lb_cfg.sync_interval == 300);
	CHECK(global_lb_cfg.connect_timeout == 200);
	CHECK(global_lb_cfg.command_timeout == 100);
	CHECK(global_lb_cfg.reconnect_initial == 100);
	CHECK(global_lb_cfg.reconnect_max == 5000);
	CHECK(global_lb_cfg.reconnect_jitter == 20);
	CHECK(global_lb_cfg.snapshot_ttl == 3000);
	CHECK(global_lb_cfg.stale_after == 3000);
	CHECK(global_lb_cfg.recovery_successes == 3);
	CHECK(global_lb_check_config() == 0 && !alerts && !warnings);
	CHECK(global_lb_cfg_kws.kw[0].section == CFG_GLOBAL);

	CHECK(parse("state-store", "[::1]:6379", "") == 0);
	CHECK(!strcmp(global_lb_cfg.state_store_host, "::1"));
	CHECK(global_lb_cfg.state_store_port == 6379);
	CHECK(parse("instance-id", "cluster-a/haproxy-0", "") == 0);
	CHECK(!strcmp(global_lb_cfg.instance_id, "cluster-a/haproxy-0"));
	CHECK(global_lb_check_config() == 0 && !alerts && warnings == 1);
	CHECK(parse("key-prefix", "test:pool", "") == 0);
	CHECK(!strcmp(global_lb_cfg.key_prefix, "test:pool"));
	CHECK(parse("sync-interval", "500ms", "") == 0);
	CHECK(parse("timeout", "connect", "400ms") == 0);
	CHECK(parse("timeout", "command", "250ms") == 0);
	CHECK(parse("reconnect", "200ms", "10s") == 0);
	CHECK(parse("reconnect-jitter", "0", "") == 0);
	CHECK(parse("snapshot-ttl", "4s", "") == 0);
	CHECK(parse("stale-after", "5s", "") == 0);
	CHECK(parse("recovery-successes", "5", "") == 0);
	CHECK(global_lb_cfg.sync_interval == 500);
	CHECK(global_lb_cfg.connect_timeout == 400);
	CHECK(global_lb_cfg.command_timeout == 250);
	CHECK(global_lb_cfg.reconnect_initial == 200);
	CHECK(global_lb_cfg.reconnect_max == 10000);
	CHECK(global_lb_cfg.reconnect_jitter == 0);
	CHECK(global_lb_cfg.snapshot_ttl == 4000);
	CHECK(global_lb_cfg.stale_after == 5000);
	CHECK(global_lb_cfg.recovery_successes == 5);
	CHECK(parse("sync-interval", "600ms", "") < 0);
	CHECK(global_lb_cfg.sync_interval == 500);
	CHECK(parse("state-store", "other:6380", "") < 0);
	CHECK(!strcmp(global_lb_cfg.state_store_host, "::1"));
	global_lb_deinit_config();
	global_lb_deinit_config(); /* release is safe even after partial config */
	CHECK(!global_lb_cfg.state_store_host && !global_lb_cfg.instance_id);
	CHECK(!global_lb_cfg_seen && !global_lb_cfg.configured);
	CHECK(!strcmp(global_lb_cfg.key_prefix, "global-lb"));

	global_lb_cfg = defaults;
	CHECK(parse("state-store", "store.example.invalid:1234", "") == 0);
	CHECK(!strcmp(global_lb_cfg.state_store_host, "store.example.invalid"));
	CHECK(global_lb_check_config() != 0); /* missing required instance */
	CHECK(parse("instance-id", "test", "") == 0);
	CHECK(parse("reconnect", "5s", "100ms") < 0);
	CHECK(global_lb_cfg.reconnect_initial == 100 && global_lb_cfg.reconnect_max == 5000);
	CHECK(parse("sync-interval", "18446744073709551617ms", "") < 0);
	CHECK(global_lb_cfg.sync_interval == 300);
	CHECK(!(global_lb_cfg_seen & (1U << GLB_SYNC)));
	CHECK(parse("sync-interval", "1us", "") == 0);
	CHECK(global_lb_cfg.sync_interval == 1);
	global_lb_deinit_config();
	value = 123;
	CHECK(!global_lb_parse_uint("4294973675", 1, 65535, &value) && value == 123);
	puts("PASS: Global LB stored defaults, overrides and parser ownership");
	return 0;
}
