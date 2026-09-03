/*
 * Canonical Global LB endpoint key tests.
 *
 * Build example:
 *   cc -Iinclude -ffunction-sections -fdata-sections -c src/global_lb.c \
 *      -o /tmp/global_lb.o
 *   cc -Iinclude -ffunction-sections -fdata-sections \
 *      tests/unit/global-lb-key.c /tmp/global_lb.o -Wl,--gc-sections \
 *      -o /tmp/global-lb-key
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include <haproxy/global_lb.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

static void set_ipv4(struct sockaddr_storage *addr, const char *text)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	memset(addr, 0, sizeof(*addr));
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, text, &sin->sin_addr);
}

static void set_ipv6(struct sockaddr_storage *addr, const char *text)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

	memset(addr, 0, sizeof(*addr));
	sin6->sin6_family = AF_INET6;
	inet_pton(AF_INET6, text, &sin6->sin6_addr);
}

static int run_tests(void)
{
	struct sockaddr_storage addr;
	char key[256];
	char exact_key[sizeof("be_ipmdn|192.0.2.10:5000")];
	char one_short[sizeof("be_ipmdn|192.0.2.10:5000") - 1];

	set_ipv4(&addr, "192.0.2.10");
	CHECK(global_lb_format_endpoint_key("be_ipmdn", &addr, 5000,
					    key, sizeof(key)) == 1);
	CHECK(strcmp(key, "be_ipmdn|192.0.2.10:5000") == 0);
	CHECK(global_lb_format_endpoint_key("be_ipmdn", &addr, 5000,
					    exact_key, sizeof(exact_key)) == 1);
	CHECK(strcmp(exact_key, "be_ipmdn|192.0.2.10:5000") == 0);
	strcpy(one_short, "dirty");
	CHECK(global_lb_format_endpoint_key("be_ipmdn", &addr, 5000,
					    one_short, sizeof(one_short)) == 0);
	CHECK(one_short[0] == '\0');

	set_ipv6(&addr, "2001:db8::20");
	CHECK(global_lb_format_endpoint_key("be_ipmdn", &addr, 5000,
					    key, sizeof(key)) == 1);
	CHECK(strcmp(key, "be_ipmdn|[2001:db8::20]:5000") == 0);

	memset(&addr, 0, sizeof(addr));
	strcpy(key, "dirty");
	CHECK(global_lb_format_endpoint_key("be_ipmdn", &addr, 5000,
					    key, sizeof(key)) == 0);
	CHECK(key[0] == '\0');

	set_ipv4(&addr, "192.0.2.10");
	strcpy(key, "dirty");
	CHECK(global_lb_format_endpoint_key("", &addr, 5000,
					    key, sizeof(key)) == 0);
	CHECK(key[0] == '\0');

	CHECK(global_lb_format_endpoint_key("be_other", &addr, 5000,
					    key, sizeof(key)) == 1);
	CHECK(strcmp(key, "be_other|192.0.2.10:5000") == 0);
	return 0;
}

int main(void)
{
	int line = run_tests();

	if (line) {
		fprintf(stderr, "global-lb key test failed at line %d\n", line);
		return 1;
	}
	return 0;
}
