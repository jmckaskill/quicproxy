#pragma once
#include "common.h"

typedef struct qsource_class qsource_class;
typedef struct qcontinuation qcontinuation;
typedef void(*q_continue_fn)(void* user, int error);

struct qcontinuation {
	q_continue_fn fn;
	void *user;
};

static inline void q_cancel_continuation(qcontinuation *c) {
	c->fn = NULL;
}
static inline void q_call_contiuation(qcontinuation *c, int error) {
	q_continue_fn fn = c->fn;
	if (fn) {
		c->fn = NULL;
		fn(c->user, error);
	}
}

struct qsource_class {
	ssize_t(*read)(const qsource_class **vt, size_t off, size_t minsz, const void **pdata, q_continue_fn cb, void *user);
	void(*stop)(const qsource_class **vt, int error);
	void(*seek)(const qsource_class **vt, size_t seek);
};

