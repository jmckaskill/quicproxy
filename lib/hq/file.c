#include "file.h"
#include <cutils/file.h>
#include <cutils/path.h>
#include <cutils/char-array.h>

static ssize_t read_file(const hq_source_class **vt, const hq_source_class **notify, const void **pdata) {
	hq_file_source *s = container_of(vt, hq_file_source, vtable);
	assert(s->file);
	if (s->have) {
		*pdata = s->buf;
		return s->have;
	} else {
		return feof(s->file) ? 0 : HQ_PENDING;
	}
}

static void populate_buffer(hq_file_source *s) {
	s->have = fread(s->buf, 1, s->bufsz, s->file);
	fseek(s->file, -(long)s->have, SEEK_CUR);
}

static void finish_read(const hq_source_class **vt, ssize_t sz) {
	hq_file_source *s = container_of(vt, hq_file_source, vtable);
	assert(s->file);
	if (sz < 0) {
		fclose(s->file);
		s->file = NULL;
	} else {
		fseek(s->file, (long)sz, SEEK_CUR);
		populate_buffer(s);
	}
}

const hq_source_class hq_file_source_vtable = {
	&read_file,
	&finish_read,
	NULL,
};

int hq_open_file_source(hq_file_source *s, const char *path, char *buf, size_t bufsz) {
	memset(s, 0, sizeof(*s));
	s->file = fopen_utf8(path, "rb");
	if (!s->file) {
		return -1;
	}
	s->vtable = &hq_file_source_vtable;
	s->buf = buf;
	s->bufsz = bufsz;

	setvbuf(s->file, NULL, _IONBF, 0);
	populate_buffer(s);
	return 0;
}


