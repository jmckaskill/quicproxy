#pragma once
#include "http.h"
#include <stdio.h>

extern struct hq_stream_class hq_file_source_vtable;

typedef struct hq_file_source hq_file_source;
struct hq_file_source {
	const hq_stream_class *vtable;
	FILE *file;
	char *buf;
	size_t bufsz;
	uint64_t start;
	uint64_t end;
	size_t hdr_num;
	hq_header headers[3];
	struct {
		size_t len;
		char c_str[32];
	} content_length;
};

int hq_open_file_source(const char *path);

