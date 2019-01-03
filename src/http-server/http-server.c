#include "lib/hq/http1.h"

int main() {
	hq_poll p;
	hq_init_poll(&p);

	while (!p.vtable->poll(&p.vtable)) {
	}

	return 0;
}