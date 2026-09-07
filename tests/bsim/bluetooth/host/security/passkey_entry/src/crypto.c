/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/printk.h>
#include "babblekit/testcase.h"
#include "crypto/bt_spake.h"
#include "vectors.h"

void test_spake_crypto(void)
{
	struct bt_spake_direct a = {.central = true, .password = 123456};
	struct bt_spake_direct b = {.central = false, .password = 123456};
	struct bt_spake_transcript t;
	uint8_t scalar[32] = {0}, point[64], ka[32], kb[32];

	for (int i = 0; i < 7; i++) {
		t.a[i] = i;
		t.b[i] = i + 7;
		t.preq[i] = i + 14;
		t.prsp[i] = i + 21;
	}
	for (int i = 0; i < 16; i++) {
		t.na[i] = i;
		t.nb[i] = i + 16;
	}
	memcpy(t.pka, vector_pka, 64);
	memcpy(t.pkb, vector_pkb, 64);
	scalar[31] = 5;
	TEST_ASSERT(bt_spake_point_mul(scalar, vector_pkb, point) == 0, "Full DH failed");
	TEST_ASSERT(memcmp(point, vector_m, 64) == 0, "Full DH differs from oracle");
	memcpy(a.m, point, 64);
	memcpy(b.m, point, 64);
	a.secret[31] = 2;
	b.secret[31] = 3;
	TEST_ASSERT(bt_spake_mask(&a) == 0 && bt_spake_mask(&b) == 0, "Mask failed");
	TEST_ASSERT(memcmp(a.local, vector_xstar, 64) == 0, "X* differs from oracle");
	TEST_ASSERT(memcmp(b.local, vector_ystar, 64) == 0, "Y* differs from oracle");
	memcpy(a.peer, b.local, 64);
	memcpy(b.peer, a.local, 64);
	TEST_ASSERT(bt_spake_shared(&a) == 0 && bt_spake_shared(&b) == 0, "Unmask failed");
	TEST_ASSERT(memcmp(a.shared, vector_shared, 64) == 0, "ZA differs from oracle");
	TEST_ASSERT(memcmp(b.shared, vector_shared, 64) == 0, "ZB differs from oracle");
	TEST_ASSERT(bt_spake_derive(&a, &t, ka) == 0 && bt_spake_derive(&b, &t, kb) == 0,
		    "KDF failed");
	TEST_ASSERT(memcmp(ka, vector_key, 32) == 0 && memcmp(kb, vector_key, 32) == 0,
		    "KDF differs from independent SHA256 oracle");
	t.preq[0] ^= 1;
	TEST_ASSERT(bt_spake_derive(&a, &t, kb) == 0 && memcmp(ka, kb, 32) != 0,
		    "Transcript not bound");

	/* Zero password must work; it is not a valid scalar for ecp_mul itself. */
	a.password = b.password = 0;
	TEST_ASSERT(bt_spake_mask(&a) == 0 && bt_spake_mask(&b) == 0, "Zero mask failed");
	memcpy(a.peer, b.local, 64);
	memcpy(b.peer, a.local, 64);
	TEST_ASSERT(bt_spake_shared(&a) == 0 && bt_spake_shared(&b) == 0, "Zero unmask");
	TEST_ASSERT(memcmp(a.shared, vector_shared, 64) == 0 &&
		    memcmp(b.shared, vector_shared, 64) == 0, "Zero shared differs");

	a.password = 123456;
	b.password = 123457;
	TEST_ASSERT(bt_spake_mask(&a) == 0 && bt_spake_mask(&b) == 0, "Mismatch mask");
	memcpy(a.peer, b.local, 64);
	memcpy(b.peer, a.local, 64);
	TEST_ASSERT(bt_spake_shared(&a) == 0 && bt_spake_shared(&b) == 0, "Mismatch shared");
	TEST_ASSERT(bt_spake_derive(&a, &t, ka) == 0 && bt_spake_derive(&b, &t, kb) == 0,
		    "Mismatch KDF");
	TEST_ASSERT(memcmp(ka, kb, 32) != 0, "Different passwords produced same key");
	memset(a.peer, 0, 64);
	TEST_ASSERT(bt_spake_shared(&a) != 0, "Invalid point accepted");
	bt_spake_clear(&a);
	bt_spake_clear(&b);
	TEST_ASSERT(memcmp(&a, &b, sizeof(a)) == 0, "Context cleanup failed");
	printk("SPAKE crypto: independent vectors, zero, mismatch and invalid point passed\n");
}
