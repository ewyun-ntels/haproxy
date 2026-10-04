/* UD-011 v2-only-20261004: worker UUID helpers shared by v2 transport/protocol.
 * Copyright 2026 nTels. LGPL-2.1 exclusively. */
#ifdef USE_GLOBAL_LB
#include <string.h>
#include <haproxy/global_lb_store.h>

static const char hex[] = "0123456789abcdef";

int global_lb_store_valid_uuid(const char *s)
{
	size_t i;

	if (!s || strlen(s) != 36)
		return 0;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (s[i] != '-')
				return 0;
		}
		else if (!strchr(hex, s[i]))
			return 0;
	}
	return s[14] == '4' && strchr("89ab", s[19]) != NULL;
}

int global_lb_store_writer_init(struct global_lb_store_writer *writer,
				const unsigned char entropy[16])
{
	unsigned char bytes[16];
	size_t i, pos = 0;

	if (!writer || !entropy)
		return 0;
	memcpy(bytes, entropy, sizeof(bytes));
	bytes[6] = (bytes[6] & 15) | 64;
	bytes[8] = (bytes[8] & 63) | 128;
	for (i = 0; i < sizeof(bytes); i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			writer->writer_generation[pos++] = '-';
		writer->writer_generation[pos++] = hex[bytes[i] >> 4];
		writer->writer_generation[pos++] = hex[bytes[i] & 15];
	}
	writer->writer_generation[pos] = 0;
	return 1;
}

#endif
