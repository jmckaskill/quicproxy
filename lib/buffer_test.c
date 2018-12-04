#include "buffer.h"
#include <cutils/test.h>


int main(int argc, const char *argv[]) {
	start_test(argc, argv);


	char buf[72];
	qbuffer_t b = { 0 };
	qbuf_init(&b, buf, sizeof(buf));
	EXPECT_EQ(64, b.size);

	const void *p;
	size_t sz;

	// receive a chunk in order
	static char abcde[] = "abcde";
	EXPECT_EQ(5, qbuf_insert(&b, 0, abcde, 5));
	EXPECT_EQ(0, b.head);
	EXPECT_EQ(5, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("abcde", 5, p, sz);

	// consume a bit
	qbuf_consume(&b, 3);
	EXPECT_EQ(3, b.head);
	EXPECT_EQ(5, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("de", 2, p, sz);
	qbuf_fold(&b);

	// now receive a chunk out of order
	static char fghij[] = "fghij";
	static char klmno[] = "klmno";
	EXPECT_EQ(0, qbuf_insert(&b, 10, klmno, 5));
	EXPECT_EQ(3, b.head);
	EXPECT_EQ(5, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("de", 2, p, sz);

	// even if we consume what's in the buffer, we shouldn't see the out of order stuff yet
	qbuf_consume(&b, 2);
	EXPECT_EQ(5, b.head);
	EXPECT_EQ(5, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("", 0, p, sz);
	qbuf_fold(&b);

	// now send the hole
	EXPECT_EQ(10, qbuf_insert(&b, 5, fghij, 5));
	qbuf_fold(&b);
	EXPECT_EQ(5, b.head);
	EXPECT_EQ(15, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("fghijklmno", 10, p, sz);
	qbuf_consume(&b, 10);

	// now receive a large chunk out of order
	static char pqrst[] = "pqrst";
	static char uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz[] = "uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
	EXPECT_EQ(0, qbuf_insert(&b, 20, uvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz, 58));
	qbuf_fold(&b);
	EXPECT_EQ(15, b.head);
	EXPECT_EQ(15, b.tail);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("", 0, p, sz);
	EXPECT_EQ(63, qbuf_insert(&b, 15, pqrst, 5));
	qbuf_fold(&b);
	EXPECT_EQ(15, b.head);
	EXPECT_EQ(78, b.tail);
	// we should only see the right side of the buffer
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("pqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 49, p, sz);
	// consume one less than the right side of the buffer
	EXPECT_EQ(15, b.head);
	qbuf_consume(&b, 48);
	EXPECT_EQ(63, b.head);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("l", 1, p, sz);
	// consume the right side of the buffer
	EXPECT_EQ(63, b.head);
	qbuf_consume(&b, 1);
	EXPECT_EQ(64, b.head);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("mnopqrstuvwxyz", 14, p, sz);
	// consume the left side of the buffer
	EXPECT_EQ(64, b.head);
	qbuf_consume(&b, 14);
	EXPECT_EQ(78, b.head);
	sz = qbuf_data(&b, b.head, b.tail, &p);
	EXPECT_BYTES_EQ("", 0, p, sz);
	EXPECT_EQ(78, b.head);
	static char zeros[8] = { 0 };
	EXPECT_BYTES_EQ(zeros, 8, b.valid, 8);

	return finish_test();
}
