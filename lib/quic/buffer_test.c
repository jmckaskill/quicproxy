#include "buffer.h"
#include <cutils/test.h>


int main(int argc, const char *argv[]) {
	start_test(argc, argv);


	char buf[108];
	qbuffer_t b = { 0 };
	qbuf_init(&b, buf, sizeof(buf));
	EXPECT_EQ(96, qbuf_max(&b));

	uint64_t off;
	const void *p;
	size_t sz;

	// receive a chunk in order
	static char abcde[] = "abcde";
	EXPECT_EQ(5, qbuf_insert(&b, 0, abcde, 5));
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(0, off);
	EXPECT_BYTES_EQ("abcde", 5, p, sz);

	// consume a bit
	qbuf_consume(&b, 3);
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(3, off);
	EXPECT_BYTES_EQ("de", 2, p, sz);
	qbuf_fold(&b);

	// now receive a chunk out of order
	static char fghij[] = "fghij";
	static char klmno[] = "klmno";
	EXPECT_EQ(0, qbuf_insert(&b, 10, klmno, 5));
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(3, off);
	EXPECT_BYTES_EQ("de", 2, p, sz);

	// even if we consume what's in the buffer, we shouldn't see the out of order stuff yet
	qbuf_consume(&b, 2);
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(5, off);
	EXPECT_BYTES_EQ("", 0, p, sz);
	qbuf_fold(&b);

	// now send the hole
	EXPECT_EQ(10, qbuf_insert(&b, 5, fghij, 5));
	qbuf_fold(&b);
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(5, off);
	EXPECT_BYTES_EQ("fghijklmno", 10, p, sz);
	qbuf_consume(&b, 10);

	// receive enough to force us out of the first chunk
	EXPECT_EQ(32, qbuf_insert(&b, 15, "12345678901234567890123456789012", 32));
	qbuf_fold(&b);
	qbuf_consume(&b, 32);

	// now receive a large chunk out of order
	static char qrst[] = "qrst";
	static char uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz[] = "uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
	EXPECT_EQ(0, qbuf_insert(&b, 48, qrst, 4));
	EXPECT_EQ(0, qbuf_insert(&b, 52, uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz, 58));
	qbuf_fold(&b);
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(47, off);
	EXPECT_BYTES_EQ("", 0, p, sz);
	EXPECT_EQ(63, qbuf_insert(&b, 47, "p", 1));
	qbuf_fold(&b);
	sz = qbuf_data(&b, &off, &p);
	EXPECT_EQ(47, off);
	EXPECT_BYTES_EQ("pqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 63, p, sz);
	qbuf_consume(&b, 63);
	static char zeros[8] = { 0 };
	EXPECT_BYTES_EQ(zeros, 8, b.valid, 8);

	return finish_test();
}
