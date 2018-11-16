#include "rx-stream.h"
#include <cutils/test.h>


int main(int argc, const char *argv[]) {
	start_test(argc, argv);


	char buf[36];
	qrx_stream_t r;
	EXPECT_EQ(-1, qrx_init(&r, buf, sizeof(buf) - 1));
	EXPECT_EQ(0, qrx_init(&r, buf, sizeof(buf)));

	// receive a chunk in order
	static char abcde[] = "abcde";
	EXPECT_EQ(0, qrx_append(&r, false, 0, abcde, 5));
	char *p;
	ssize_t sz = qrx_recv(&r, 1, &p);
	EXPECT_PTREQ(abcde, p);
	EXPECT_BYTES_EQ("abcde", 5, p, sz);

	// consume a bit, we should still be using the provided buffer
	qrx_consume(&r, 3);
	sz = qrx_recv(&r, 1, &p);
	EXPECT_PTREQ(abcde + 3, p);
	EXPECT_BYTES_EQ("de", 2, p, sz);

	// request too much and we should get a wait error
	EXPECT_EQ(QRX_WAIT, qrx_recv(&r, 3, &p));

	// fold the remainder in and we should see it in the stream buffer
	qrx_fold(&r);
	sz = qrx_recv(&r, 1, &p);
	EXPECT_BYTES_EQ("de", 2, p, sz);
	EXPECT_TRUE(buf <= p && p < buf + sizeof(buf));

	// now receive a chunk out of order
	static char fghij[] = "fghij";
	static char klmno[] = "klmno";
	EXPECT_EQ(0, qrx_append(&r, false, 10, klmno, 5));
	sz = qrx_recv(&r, 1, &p);
	EXPECT_BYTES_EQ("de", 2, p, sz);

	// even if we consume what's in the buffer, we shouldn't see the out of order stuff yet
	qrx_consume(&r, 2);
	EXPECT_EQ(QRX_WAIT, qrx_recv(&r, 1, &p));

	// now send the hole
	qrx_fold(&r);
	EXPECT_EQ(0, qrx_append(&r, false, 5, fghij, 5));
	sz = qrx_recv(&r, 1, &p);
	// if we only request 1 byte, then we should only see the provided buffer
	EXPECT_BYTES_EQ("fghij", 5, p, sz);
	EXPECT_PTREQ(fghij, p);
	// if we request more than that, we should see the full lot of the stream buffer
	EXPECT_EQ(QRX_WAIT, qrx_recv(&r, 11, &p));
	sz = qrx_recv(&r, 6, &p);
	EXPECT_BYTES_EQ("fghijklmno", 10, p, sz);


	return finish_test();
}