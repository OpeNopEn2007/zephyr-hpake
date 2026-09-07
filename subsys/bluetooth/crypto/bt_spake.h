/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ZEPHYR_SUBSYS_BLUETOOTH_CRYPTO_BT_SPAKE_H_
#define ZEPHYR_SUBSYS_BLUETOOTH_CRYPTO_BT_SPAKE_H_

#include <stdbool.h>
#include <stdint.h>

/* Internal experiment API. All coordinates/scalars here are big endian;
 * points are X || Y, without the SEC1 0x04 prefix. No SMP state lives here.
 */
struct bt_spake_direct {
	uint8_t m[64];
	uint8_t secret[32];
	uint8_t local[64];
	uint8_t peer[64];
	uint8_t shared[64];
	uint32_t password;
	bool central;
};

struct bt_spake_transcript {
	uint8_t a[7];
	uint8_t b[7];
	uint8_t preq[7];
	uint8_t prsp[7];
	uint8_t pka[64];
	uint8_t pkb[64];
	uint8_t na[16];
	uint8_t nb[16];
};

int bt_spake_point_mul(const uint8_t scalar[32], const uint8_t point[64], uint8_t out[64]);
int bt_spake_generate(struct bt_spake_direct *ctx);
/* Deterministic primitive for independent known-answer tests. */
int bt_spake_mask(struct bt_spake_direct *ctx);
int bt_spake_shared(struct bt_spake_direct *ctx);
int bt_spake_derive(const struct bt_spake_direct *ctx,
		    const struct bt_spake_transcript *transcript, uint8_t key[32]);
void bt_spake_clear(struct bt_spake_direct *ctx);
void bt_spake_point_swap(uint8_t out[64], const uint8_t in[64]);

#endif
