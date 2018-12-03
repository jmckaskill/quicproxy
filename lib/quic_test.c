#include "connection.h"
#include <cutils/test.h>
#include <cutils/timer.h>
#include "internal.h"

static const unsigned char EC_Q[] = {
		0x04, 0x5F, 0x38, 0x9D, 0xA7, 0xFF, 0x4D, 0x8A, 0xAF, 0xF6, 0x34, 0x39,
		0x46, 0x1A, 0xFC, 0x3A, 0xDF, 0xF4, 0x23, 0xAA, 0xA9, 0xEA, 0xFB, 0xC5,
		0x08, 0xDE, 0x00, 0x8E, 0xBE, 0x79, 0xA5, 0x37, 0x58, 0x4C, 0x6D, 0xDD,
		0x01, 0xCA, 0xAB, 0x47, 0xDF, 0x89, 0xB6, 0xC7, 0x17, 0x1F, 0x38, 0xFC,
		0x1D, 0x20, 0x14, 0xDD, 0x45, 0xC0, 0xE0, 0x8F, 0x93, 0x4E, 0x38, 0x0B,
		0xFC, 0xE9, 0x99, 0xA1, 0x49
};

static const br_ec_public_key test_pkey = {
		23,
		(unsigned char *)EC_Q, sizeof EC_Q
};

static const unsigned char EC_X[] = {
		0x03, 0x91, 0x5B, 0x42, 0x06, 0x90, 0x73, 0x91, 0x1B, 0x48, 0xEF, 0x08,
		0xFB, 0xB5, 0xAD, 0x75, 0x65, 0xF9, 0xE6, 0xF7, 0x21, 0x47, 0x62, 0x48,
		0xFA, 0x3F, 0x97, 0x7B, 0x70, 0x9D, 0x86, 0xA5
};

static const br_ec_private_key test_skey = {
		23,
		(unsigned char *)EC_X, sizeof EC_X
};

static const unsigned char CERT0[] = {
		0x30, 0x82, 0x01, 0xB0, 0x30, 0x82, 0x01, 0x56, 0xA0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x14, 0x1C, 0x4D, 0x00, 0x91, 0x69, 0xE2, 0x46, 0xAC, 0x90,
		0x7C, 0x64, 0x5C, 0x53, 0xF1, 0xFF, 0xB7, 0xC1, 0xCB, 0x6E, 0x7A, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
		0x27, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x43, 0x41, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
		0x0F, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74,
		0x65, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x30, 0x30, 0x31,
		0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33,
		0x37, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A,
		0x30, 0x21, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
		0x02, 0x43, 0x41, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x13, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x30,
		0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
		0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42,
		0x00, 0x04, 0x5F, 0x38, 0x9D, 0xA7, 0xFF, 0x4D, 0x8A, 0xAF, 0xF6, 0x34,
		0x39, 0x46, 0x1A, 0xFC, 0x3A, 0xDF, 0xF4, 0x23, 0xAA, 0xA9, 0xEA, 0xFB,
		0xC5, 0x08, 0xDE, 0x00, 0x8E, 0xBE, 0x79, 0xA5, 0x37, 0x58, 0x4C, 0x6D,
		0xDD, 0x01, 0xCA, 0xAB, 0x47, 0xDF, 0x89, 0xB6, 0xC7, 0x17, 0x1F, 0x38,
		0xFC, 0x1D, 0x20, 0x14, 0xDD, 0x45, 0xC0, 0xE0, 0x8F, 0x93, 0x4E, 0x38,
		0x0B, 0xFC, 0xE9, 0x99, 0xA1, 0x49, 0xA3, 0x66, 0x30, 0x64, 0x30, 0x1F,
		0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xF0,
		0xD0, 0xF1, 0x22, 0xF9, 0x7A, 0x48, 0x17, 0x06, 0x7B, 0x3D, 0xBD, 0xB8,
		0xF5, 0xCD, 0x55, 0x9C, 0x5C, 0x3E, 0x70, 0x30, 0x1D, 0x06, 0x03, 0x55,
		0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xC3, 0x0E, 0x86, 0xAA, 0x75, 0xB4,
		0x15, 0xC0, 0xE5, 0x95, 0x09, 0x32, 0xBE, 0x5E, 0x92, 0x75, 0xA9, 0xE4,
		0x44, 0x9B, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
		0x04, 0x02, 0x30, 0x00, 0x30, 0x14, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04,
		0x0D, 0x30, 0x0B, 0x82, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
		0x73, 0x74, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
		0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x91, 0xFB,
		0xF4, 0x04, 0xD0, 0xE5, 0x2E, 0x01, 0xD4, 0x8C, 0xF0, 0x17, 0x62, 0x0F,
		0xDC, 0xCC, 0x80, 0xCA, 0x18, 0xC4, 0x40, 0x7C, 0x27, 0x03, 0xCB, 0x34,
		0x03, 0x0D, 0x9B, 0xC8, 0x59, 0x4D, 0x02, 0x20, 0x05, 0x55, 0x69, 0xE2,
		0xD8, 0xA1, 0x40, 0x33, 0x34, 0x0E, 0x7E, 0x49, 0x32, 0x64, 0x1D, 0x3F,
		0x6B, 0x1F, 0xD0, 0x2D, 0xB7, 0x2F, 0x52, 0x04, 0x56, 0xAF, 0xD3, 0x37,
		0x8F, 0x87, 0x99, 0xA2
};

static const unsigned char CERT1[] = {
		0x30, 0x82, 0x01, 0xA9, 0x30, 0x82, 0x01, 0x4E, 0xA0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x14, 0x20, 0xD3, 0xEB, 0xE2, 0x8C, 0xFE, 0xDA, 0xE6, 0xA3,
		0x2C, 0x5E, 0x3B, 0xF2, 0x66, 0x3A, 0x2B, 0x36, 0x7B, 0xB0, 0xCA, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
		0x1C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x43, 0x41, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
		0x04, 0x52, 0x6F, 0x6F, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x30, 0x30,
		0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D,
		0x33, 0x37, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
		0x5A, 0x30, 0x27, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
		0x13, 0x02, 0x43, 0x41, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x0F, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69,
		0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
		0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x70, 0x2E, 0x92,
		0x82, 0x01, 0x17, 0x6C, 0x6D, 0xAB, 0xE1, 0xD1, 0x63, 0x09, 0x48, 0x49,
		0xD2, 0xA6, 0x35, 0x52, 0xD3, 0x3C, 0x73, 0xBB, 0xB2, 0x88, 0x37, 0x98,
		0x87, 0xF1, 0x8D, 0xE0, 0xEC, 0x65, 0x9A, 0x0E, 0x13, 0xF5, 0xED, 0x91,
		0x61, 0xC8, 0xB6, 0x6D, 0x33, 0x84, 0x6E, 0xAE, 0x8E, 0x55, 0x80, 0xCD,
		0x49, 0x9E, 0x07, 0xBF, 0xD0, 0xAE, 0x9D, 0xE6, 0xD0, 0xB3, 0x27, 0x16,
		0xA1, 0xA3, 0x63, 0x30, 0x61, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23,
		0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x95, 0x41, 0xB4, 0xE2, 0x67, 0xAA,
		0xF1, 0x7F, 0xBC, 0x8F, 0x79, 0xF3, 0x68, 0x14, 0x5A, 0x6B, 0x92, 0x16,
		0xA2, 0x40, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04,
		0x14, 0xF0, 0xD0, 0xF1, 0x22, 0xF9, 0x7A, 0x48, 0x17, 0x06, 0x7B, 0x3D,
		0xBD, 0xB8, 0xF5, 0xCD, 0x55, 0x9C, 0x5C, 0x3E, 0x70, 0x30, 0x0E, 0x06,
		0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x00,
		0x86, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04,
		0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
		0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02,
		0x21, 0x00, 0x85, 0xE3, 0x46, 0x68, 0x99, 0xD6, 0x02, 0x7A, 0x59, 0x66,
		0x1C, 0xB7, 0x4F, 0x35, 0x2D, 0x08, 0x36, 0x38, 0x61, 0x7E, 0x05, 0x48,
		0xD8, 0x69, 0x43, 0x1F, 0xEB, 0x56, 0xE9, 0xAD, 0x06, 0x0E, 0x02, 0x21,
		0x00, 0x82, 0x70, 0xB4, 0x62, 0x03, 0x49, 0x46, 0xC8, 0x54, 0x59, 0x05,
		0xD9, 0x78, 0xDB, 0x53, 0x1C, 0xE0, 0x6E, 0x66, 0xF5, 0x0F, 0x14, 0x3B,
		0xC9, 0x2D, 0x38, 0x12, 0x70, 0x91, 0x56, 0xF9, 0xA9
};

static const br_x509_certificate CHAIN[] = {
		{ (unsigned char *)CERT0, sizeof CERT0 },
		{ (unsigned char *)CERT1, sizeof CERT1 }
};

#define CHAIN_LEN   2

struct msg {
	char buf[1500];
	size_t sz;
};

static tick_t NOW;

struct tester {
	const qinterface_t *vtable;
	struct msg msgv[10];
	size_t msgn;
	bool stream_open;
	bool conn_closed;
	int shutdown_reason;
	qstream_t s;
	char txbuf[32 * 1024];
	char rxbuf[32 * 1024];
	qconnection_t c[1024];
	br_x509_knownkey_context x509;
};

static void close_test(const qinterface_t **vt) {
	struct tester *t = (struct tester*)vt;
	assert(!t->conn_closed);
	t->conn_closed = true;
}

static void shutdown_test(const qinterface_t **vt, int errnum) {
	struct tester *t = (struct tester*)vt;
	t->shutdown_reason = errnum;
}

static int send_test(const qinterface_t **vt, const void *buf, size_t sz, const struct sockaddr *sa, socklen_t salen, tick_t *sent) {
	struct tester *t = (struct tester*)vt;
	*sent = NOW;
	if (t->msgn == 10) {
		return -1;
	}
	struct msg *m = &t->msgv[t->msgn++];
	assert(sz < sizeof(m->buf));
	memcpy(m->buf, buf, sz);
	m->sz = sz;
	return 0;
}

static qstream_t *new_test_stream(const qinterface_t **vt, bool unidirectional) {
	struct tester *t = (struct tester*)vt;
	if (t->stream_open) {
		return NULL;
	}
	t->stream_open = true;
	qinit_stream(&t->s, t->txbuf, sizeof(t->txbuf), t->rxbuf, sizeof(t->rxbuf));
	return &t->s;
}

static void free_test_stream(const qinterface_t **vt, qstream_t *s) {
	struct tester *t = (struct tester*)vt;
	assert(t->stream_open);
	t->stream_open = false;
}

static const br_x509_class **start_test_chain(const qinterface_t **vt, const char *server_name) {
	struct tester *t = (struct tester*)vt;
	br_x509_knownkey_init_ec(&t->x509, &test_pkey, BR_KEYTYPE_KEYX);
	t->x509.vtable->start_chain(&t->x509.vtable, server_name);
	return &t->x509.vtable;
}

static const qinterface_t test_interface = {
	&close_test,
	&shutdown_test,
	&send_test,
	&new_test_stream,
	&free_test_stream,
	NULL,
	NULL,
	&start_test_chain,
};

static const uint32_t client_versions[] = { 0x1A2A3A4A, QUIC_VERSION, 0 };

static qconnection_cfg_t client_cfg = {
	.max_data = 4096,
	.stream_data_bidi_local = 1024,
	.groups = TLS_DEFAULT_GROUPS,
	.ciphers = TLS_DEFAULT_CIPHERS,
	.signatures = TLS_DEFAULT_SIGNATURES,
	.versions = client_versions,
};

static qconnection_cfg_t server_cfg = {
	.bidi_streams = 1,
	.uni_streams = 1,
	.max_data = 4096,
	.stream_data_bidi_remote = 1024,
	.groups = TLS_DEFAULT_GROUPS,
	.ciphers = TLS_DEFAULT_CIPHERS,
	.signatures = TLS_DEFAULT_SIGNATURES,
	.validate_path = true,
};

int main(int argc, const char *argv[]) {
	client_cfg.debug = server_cfg.debug = start_test(argc, argv);

	static const uint8_t token_key[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	qcipher_aes_gcm token_cipher;
	init_aes_128_gcm(&token_cipher, token_key);
	server_cfg.server_key = &token_cipher.vtable;

	struct tester c = { &test_interface };
	struct tester s = { &test_interface };
	dispatcher_t d;
	qsigner_ecdsa signer;

	tick_t MS = 1000;
	NOW = 1000 * MS;
	init_dispatcher(&d, NOW);

	struct client_handshake *ch = (struct client_handshake*)c.c;
	struct server_handshake *sh = (struct server_handshake*)s.c;
	uint8_t addr[QUIC_ADDRESS_SIZE];
	qconnect_request_t req;

	struct sockaddr_in c4 = { 0 }, s4 = { 0 };
	struct sockaddr *ca = (struct sockaddr*) &c4;
	struct sockaddr *sa = (struct sockaddr*) &s4;
	c4.sin_family = AF_INET;
	c4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	c4.sin_port = htons(12345);
	s4.sin_family = AF_INET;
	s4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	s4.sin_port = htons(443);

	// Send the client hello
	EXPECT_EQ(0, qc_connect(c.c, sizeof(c.c), &d, &c.vtable, "localhost", &client_cfg));
	EXPECT_EQ(1, c.msgn); // Client Hello
	EXPECT_EQ(1, ch->h.pkts[0].tx_next);
	EXPECT_EQ(0, ch->h.pkts[0].tx_oldest);
	EXPECT_EQ(NOW, ch->h.pkts[0].sent[0].sent);
	EXPECT_EQ(0x1A2A3A4A, ch->h.c.version);

	// Verify that get destination works with a dummy version
	NOW += 10 * MS;
	EXPECT_EQ(0, qc_get_destination(c.msgv[0].buf, c.msgv[0].sz, addr));
	EXPECT_BYTES_EQ(ch->h.c.peer_id, QUIC_ADDRESS_SIZE, addr, QUIC_ADDRESS_SIZE);
	// Receive the client hello & return a version negotiation
	EXPECT_EQ(QC_WRONG_VERSION, qc_decode_request(&req, &server_cfg, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW));
	c.msgn = 0;
	s.msgv[0].sz = qc_reject(&req, QC_WRONG_VERSION, s.msgv[0].buf, sizeof(s.msgv[0].buf));
	EXPECT_EQ(1 + 4 + 1 + 8 + 8 + 4 + 4, s.msgv[0].sz);

	// Receive the version negotiation & send another client hello
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	EXPECT_EQ(1, c.msgn);
	EXPECT_EQ(2, ch->h.pkts[0].tx_next);
	EXPECT_EQ(QUIC_VERSION, ch->h.c.version);
	EXPECT_EQ(0x1A2A3A4A, ch->initial_version);

	// Receive the client hello & return a retry request
	NOW += 10 * MS;
	EXPECT_EQ(QC_STATELESS_RETRY, qc_decode_request(&req, &server_cfg, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW));
	c.msgn = 0;
	s.msgv[0].sz = qc_reject(&req, QC_STATELESS_RETRY, s.msgv[0].buf, sizeof(s.msgv[0].buf));
	EXPECT_GT(s.msgv[0].sz, 0);

	// Receive the retry & send another client hello
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, c.msgn);
	EXPECT_EQ(3, ch->h.pkts[0].tx_next);
	EXPECT_EQ(8, ch->h.original_destination[0]);
	EXPECT_TRUE(memcmp(ch->h.original_destination, ch->h.c.peer_id, QUIC_ADDRESS_SIZE) != 0);

	// Receive the client hello & send the server hello
	NOW += 10 * MS;
	EXPECT_EQ(0, qc_decode_request(&req, &server_cfg, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW));
	c.msgn = 0;
	EXPECT_EQ(0, qsigner_ecdsa_init(&signer, TLS_ECDSA_SIGNATURES, &test_skey, CHAIN, CHAIN_LEN));
	EXPECT_EQ(0, qc_accept(s.c, sizeof(s.c), &d, &s.vtable, &req, &signer.vtable));
	EXPECT_EQ(1, s.msgn); // Server Hello

	// Receive the server hello & send the client finished
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_TRUE(ch->h.c.peer_verified);
	EXPECT_TRUE(!ch->h.c.handshake_complete);
	EXPECT_TRUE(!sh->h.c.peer_verified);
	EXPECT_EQ(client_cfg.max_data, sh->h.c.peer_cfg.max_data);
	EXPECT_EQ(client_cfg.bidi_streams, sh->h.c.peer_cfg.bidi_streams);
	EXPECT_EQ(1, c.msgn); // Client Finished
	EXPECT_EQ(20 * MS, ch->h.c.srtt);

	// Receive the client finished & send an ACK
	NOW += 10 * MS;
	qc_recv(s.c, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	c.msgn = 0;
	EXPECT_TRUE(sh->h.c.peer_verified);
	EXPECT_TRUE(sh->h.c.handshake_complete);
	EXPECT_EQ(20 * MS, sh->h.c.srtt);
	EXPECT_EQ(1, s.msgn); // ACK

	// Receive the ACK
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_TRUE(ch->h.c.handshake_complete);
	EXPECT_EQ(0, c.msgn);

	// Send a bidi stream
	NOW += 10 * MS;
	EXPECT_TRUE(!c.stream_open);
	c.stream_open = true;
	qinit_stream(&c.s, c.txbuf, sizeof(c.txbuf), c.rxbuf, sizeof(c.rxbuf));
	qtx_write(&c.s, "hello", 5);
	qtx_finish(&c.s);
	qc_flush(c.c, &c.s);
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(0, c.s.id);
	EXPECT_EQ(1, c.msgn);

	// Receive the bidi stream
	NOW += 10 * MS;
	qc_recv(s.c, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	c.msgn = 0;
	EXPECT_TRUE(s.stream_open);
	char buf[64];
	size_t sz = qrx_read(&s.s, buf, sizeof(buf));
	EXPECT_BYTES_EQ("hello", 5, buf, sz);
	EXPECT_EQ(0, qrx_read(&s.s, buf, sizeof(buf)));
	EXPECT_TRUE(qrx_eof(&s.s));

	// the ack may be coalesced
	if (!s.msgn) {
		NOW += 25 * MS;
		dispatch_apcs(&d, NOW, 1000);
	}
	EXPECT_EQ(1, s.msgn);

	// receive the ack
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_TRUE((c.s.flags & QS_TX_COMPLETE) && !(c.s.flags & QS_RX_COMPLETE));
	EXPECT_EQ(20 * MS, ch->h.c.srtt); // ack delay should be accommodated for

	// send something back
	qtx_write(&s.s, "world", 5);
	qtx_finish(&s.s);
	qc_flush(s.c, &s.s);
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, s.msgn);

	// receive the response
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_TRUE((c.s.flags & QS_TX_COMPLETE) && (c.s.flags & QS_RX_COMPLETE));
	EXPECT_TRUE(!c.stream_open); // since we have both the receive and transmit, the library should release the stream
	EXPECT_TRUE(s.stream_open); // the fin hasn't been acknowledged yet
	sz = qrx_read(&c.s, buf, sizeof(buf));
	EXPECT_BYTES_EQ("world", 5, buf, sz);
	EXPECT_EQ(0, qrx_read(&c.s, buf, sizeof(buf)));
	EXPECT_TRUE(qrx_eof(&c.s));

	// the ack may be coalesced
	if (!c.msgn) {
		NOW += 25 * MS;
		dispatch_apcs(&d, NOW, 1000);
	}
	EXPECT_EQ(1, c.msgn);

	// and receive the ack back at the server
	// and send back an updated max id
	NOW += 10 * MS;
	qc_recv(s.c, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	c.msgn = 0;
	EXPECT_TRUE(!s.stream_open);
	EXPECT_EQ(1, s.msgn);

	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_EQ(0, c.msgn);

	// send a big chunk
	c.stream_open = true;
	qinit_stream(&c.s, c.txbuf, sizeof(c.txbuf), NULL, 0);
	for (int i = 0; i < 17400 / 4; i++) {
		uint8_t le[4];
		write_little_32(le, i);
		qtx_write(&c.s, le, 4);
	}
	qc_flush(c.c, &c.s);
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, c.msgn); // the new stream is at min flow

	for (;;) {
		// receive a chunk
		NOW += 10 * MS;
		for (size_t i = 0; i < c.msgn; i++) {
			qc_recv(s.c, c.msgv[i].buf, c.msgv[i].sz, ca, sizeof(c4), NOW);
		}
		dispatch_apcs(&d, NOW, 1000);
		c.msgn = 0;

		if (qrx_size(&s.s) == c.s.tx.tail) {
			break;
		}
		EXPECT_TRUE(s.stream_open);

		// generate the ack - this may have already been created
		dispatch_apcs(&d, NOW, 1000);
		if (!s.msgn) {
			NOW += 25 * MS;
			dispatch_apcs(&d, NOW, 1000);
		}
		EXPECT_EQ(1, s.msgn);

		// about half way through indicate that we've got all the data
		if (qrx_size(&s.s) > c.s.tx.tail / 2) {
			qtx_finish(&c.s);
			qc_flush(c.c, &c.s);
		}

		// receive the ack & generate the next window full
		NOW += 10 * MS;
		qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
		dispatch_apcs(&d, NOW, 1000);
		s.msgn = 0;
		if (c.s.tx_max_sent < c.s.tx.tail) {
			EXPECT_EQ(4, c.msgn);
		}
		EXPECT_GT(c.msgn, 0);
	}

	EXPECT_TRUE(!s.stream_open);
	EXPECT_EQ(1, s.msgn); // ack and max id for uni streams

	// Finish the stream on the client side
	NOW += 10 * MS;
	EXPECT_TRUE(!is_apc_active(&ch->h.c.tx_timer));
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_EQ(0, c.msgn);
	EXPECT_TRUE(!c.stream_open);
	NOW += 25 * MS;
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, c.msgn); // ack for the max id

	// have the client migrate address on the ack
	c4.sin_port++;
	NOW += 10 * MS;
	qc_recv(s.c, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	c.msgn = 0;
	EXPECT_BYTES_EQ(ca, sizeof(c4), &sh->h.c.addr, sh->h.c.addr_len);
	EXPECT_TRUE(!sh->h.c.path_validated && sh->h.c.challenge_sent);
	EXPECT_EQ(1, s.msgn);
	EXPECT_EQ(100 * 1000, sh->h.c.srtt);
	EXPECT_EQ(0, sh->h.c.rttvar);
	EXPECT_TRUE(!sh->h.c.have_srtt);
	EXPECT_EQ(INITIAL_WINDOW, sh->h.c.congestion_window);

	// receive the challenge on the client side
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_EQ(1, c.msgn);
	EXPECT_TRUE(ch->h.c.have_path_response && ch->h.c.path_response_sent);

	// receive the response on the server side
	NOW += 10 * MS;
	qc_recv(s.c, c.msgv[0].buf, c.msgv[0].sz, ca, sizeof(c4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	c.msgn = 0;
	EXPECT_EQ(20 * 1000, sh->h.c.srtt);
	EXPECT_TRUE(sh->h.c.have_srtt);
	EXPECT_TRUE(sh->h.c.path_validated);
	NOW += 25 * MS;
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, s.msgn); // send back an ack

	// receive the ack on the client side
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_TRUE(!ch->h.c.have_path_response);

	// now have the server shut down the connection
	NOW += 10 * MS;
	qc_shutdown(s.c, QC_ERR_SERVER_BUSY);
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_EQ(1, s.msgn);
	EXPECT_EQ(0, s.shutdown_reason); // as we called qc_shutdown, the callback shouldn't be called
	EXPECT_TRUE(!s.conn_closed); // we shouldn't shutdown just yet
	EXPECT_TRUE(sh->h.c.closing);
	EXPECT_TRUE(!sh->h.c.draining);

	// receive the shutdown on the client
	NOW += 10 * MS;
	qc_recv(c.c, s.msgv[0].buf, s.msgv[0].sz, sa, sizeof(s4), NOW);
	dispatch_apcs(&d, NOW, 1000);
	s.msgn = 0;
	EXPECT_EQ(QC_ERR_SERVER_BUSY, c.shutdown_reason);
	EXPECT_TRUE(ch->h.c.closing);
	EXPECT_TRUE(ch->h.c.draining);
	EXPECT_TRUE(!c.conn_closed);

	// and sometime later both sides should shut down
	NOW += 600 * MS;
	dispatch_apcs(&d, NOW, 1000);
	EXPECT_TRUE(c.conn_closed);
	EXPECT_TRUE(s.conn_closed);

	return finish_test();
}