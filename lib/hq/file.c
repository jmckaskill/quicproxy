#include "file.h"
#include <cutils/file.h>
#include <cutils/path.h>
#include <cutils/char-array.h>

static void set_sink(const hq_stream_class **vt, const hq_stream_class **sink) {
	(void)vt;
	(void)sink;
}

static ssize_t peek_file(const hq_stream_class **vt, size_t off, const void **pdata) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	assert(off <= s->have);
	if (off >= s->have) {
		return (s->bufsz == s->have) ? HQ_PENDING : 0;
	}
	*pdata = s->buf + off;
	return s->have - off;
}

static void seek_file(const hq_stream_class **vt, size_t sz) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	fseek(s->file, (long)sz, SEEK_CUR);
	s->have = fread(s->buf, 1, s->bufsz, s->file);
	fseek(s->file, -(long)s->have, SEEK_CUR);
}

static void close_file(const hq_stream_class **vt, int errnum) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	fclose(s->file);
	s->file = NULL;
}

const hq_stream_class hq_file_source_vtable = {
	&set_sink,
	&peek_file,
	&seek_file,
	&close_file,
	NULL,
	NULL,
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
	seek_file(&s->vtable, 0);
	return 0;
}


