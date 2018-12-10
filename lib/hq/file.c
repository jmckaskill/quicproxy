#include "file.h"
#include <cutils/file.h>
#include <cutils/path.h>
#include <cutils/char-array.h>

static const hq_header *fs_peek_header(const hq_stream_class **vt, size_t idx) {
	hq_file_source *s = (hq_file_source*)vt;
	return idx < s->hdr_num ? &s->headers[idx] : NULL;
}

ssize_t fs_peek_data(const hq_stream_class **vt, uint64_t off, const void **pdata) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	assert(off >= s->start);
	if (off >= s->end) {
		return 0;
	} else if (off >= s->start + s->bufsz) {
		return HQ_TRY_AGAIN;
	}
	*pdata = s->buf + (size_t)(off - s->start);
	return (size_t)(MIN(s->start + s->bufsz, s->end) - off);
}

static void fs_read(const hq_stream_class **vt, size_t hdr_off, uint64_t data_off) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	if (data_off != s->start) {
		fread(s->buf, 1, s->bufsz, s->file);
	}
}

static void fs_finished(const hq_stream_class **vt, int errnum) {
	hq_file_source *s = (hq_file_source*)vt;
	assert(s->file);
	fclose(s->file);
	s->file = NULL;
}

const hq_stream_class hq_file_source_vtable = {
	sizeof(hq_file_source),
	NULL,
	NULL,
	&fs_peek_header,
	&fs_peek_data,
	&fs_read,
	NULL,
	NULL,
};

int hq_open_file_source(hq_file_source *s, const char *path, char *buf, size_t bufsz) {
	FILE *f = fopen_utf8(path, "rb");
	if (!f) {
		return -1;
	}
	s->vtable = &hq_file_source_vtable;
	s->buf = buf;
	s->bufsz = bufsz;
	s->start = 0;

	setvbuf(f, NULL, _IONBF, 0);
	fseek(f, 0, SEEK_END);
#ifdef _MSC_VER
	s->end = _ftelli64(f);
#else
	s->end = ftello(f);
#endif
	ca_setf(&s->content_length, "%"PRIu64, s->end);
	hq_header *h = &s->headers[0];

	*(h++) = HQ_STATUS_200;

	*h = HQ_CONTENT_LENGTH_0;
	h->value = s->content_length.c_str;
	h->value_len = s->content_length.len;
	h->flags = 0;
	h++;

	fread(buf, 1, bufsz, f);
	const char *ext = path_file_extension(path);
	if (!strcasecmp(ext, ".html")) {
		*(h++) = &HQ_CONTENT_TYPE_TEXT_HTML_CHARSET_UTF_8;
	} else if (!strcasecmp(ext, ".js")) {
		*(h++) = &HQ_CONTENT_TYPE_APPLICATION_JAVASCRIPT;
	}

	s->hdr_num = (size_t)(h - s->headers);
	return 0;
}