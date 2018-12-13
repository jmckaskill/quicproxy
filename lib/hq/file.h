#pragma once
#include "http.h"
#include <stdio.h>

extern const hq_stream_class hq_file_source_vtable;

typedef struct hq_file_source hq_file_source;
struct hq_file_source {
	const hq_stream_class *vtable;
	FILE *file;
	char *buf;
	size_t bufsz, have;
};

int hq_open_file_source(hq_file_source *s, const char *path, char *buf, size_t bufsz);

