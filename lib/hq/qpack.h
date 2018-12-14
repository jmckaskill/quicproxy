#pragma once
#include "header.h"

typedef struct hq_dict_entry hq_dict_entry_t;
struct hq_dict_entry {
	uint16_t name_off;
	uint16_t name_len;
	uint16_t value_off;
	uint16_t value_len;
};

typedef struct hq_dictionary hq_dictionary_t;
struct hq_dictionary {
	const uint8_t *data;
	const hq_dict_entry_t *entries;
	size_t num_entries;
	int64_t discarded;
	int64_t base;
	int64_t max;
};

int hq_decode_header(qslice_t *s, qslice_t *buf, const hq_dictionary_t *dict, hq_header *hdr);

#define HQ_SECURE 1
#define HQ_PLAINTEXT 2
int hq_encode_header(qslice_t *s, const hq_header *hdr, const void *value, size_t len, int flags);

extern const hq_dictionary_t HQ_STATIC_DICT;
