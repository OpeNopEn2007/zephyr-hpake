/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/platform_util.h>
#include <zephyr/sys/byteorder.h>

#include "bt_spake.h"

/* SPAKE experiment: M = abG from the initial ECDH; N is the published
 * P-256 auxiliary point from RFC 9382 section 6, decoded to X || Y, BE.
 * Check with passkey_entry/tools/rfc9382_basis.py. No runtime decompression.
 * This custom dynamic-M composition is not a complete RFC 9382 implementation;
 * resistance to offline guessing still requires analysis of the full protocol.
 * This adapter deliberately targets the pinned TF-PSA-Crypto builtin backend.
 */
static const uint8_t spake_n[64] = {
	0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37,
	0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
	0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2,
	0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
	0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50,
	0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6,
	0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5,
	0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
};

static int random_bytes(void *unused, unsigned char *out, size_t len)
{
	(void)unused;
	return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -EIO;
}

static int read_point(mbedtls_ecp_group *grp, mbedtls_ecp_point *p, const uint8_t in[64])
{
	uint8_t sec1[65] = {0x04};
	int ret;

	memcpy(sec1 + 1, in, 64);
	ret = mbedtls_ecp_point_read_binary(grp, p, sec1, sizeof(sec1));
	if (ret == 0) {
		ret = mbedtls_ecp_check_pubkey(grp, p);
	}
	return ret;
}

static int write_point(mbedtls_ecp_group *grp, const mbedtls_ecp_point *p, uint8_t out[64])
{
	uint8_t sec1[65];
	size_t len;
	int ret;

	ret = mbedtls_ecp_check_pubkey(grp, p);
	if (ret == 0) {
		ret = mbedtls_ecp_point_write_binary(grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED,
						   &len, sec1, sizeof(sec1));
	}
	if (ret == 0) {
		memcpy(out, sec1 + 1, 64);
	}
	mbedtls_platform_zeroize(sec1, sizeof(sec1));
	return ret;
}

void bt_spake_point_swap(uint8_t out[64], const uint8_t in[64])
{
	sys_memcpy_swap(out, in, 32);
	sys_memcpy_swap(out + 32, in + 32, 32);
}

int bt_spake_point_mul(const uint8_t scalar[32], const uint8_t point[64], uint8_t out[64])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point p, result;
	mbedtls_mpi k;
	int ret = 0;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&p);
	mbedtls_ecp_point_init(&result);
	mbedtls_mpi_init(&k);
	MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
	MBEDTLS_MPI_CHK(read_point(&grp, &p, point));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&k, scalar, 32));
	MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &result, &k, &p, random_bytes, NULL));
	MBEDTLS_MPI_CHK(write_point(&grp, &result, out));
cleanup:
	mbedtls_mpi_free(&k);
	mbedtls_ecp_point_free(&result);
	mbedtls_ecp_point_free(&p);
	mbedtls_ecp_group_free(&grp);
	return ret;
}

int bt_spake_generate(struct bt_spake_context *ctx)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi k;
	int ret = 0;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&k);
	MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
	MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&grp, &k, random_bytes, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&k, ctx->secret, sizeof(ctx->secret)));
cleanup:
	mbedtls_mpi_free(&k);
	mbedtls_ecp_group_free(&grp);
	return ret ? ret : bt_spake_mask(ctx);
}

/* Multiply secrets separately using ecp_mul, then use muladd only with
 * public coefficients +1/-1. This is not a side-channel audit of the prototype.
 */
static int masked_operation(struct bt_spake_context *ctx, bool receive)
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point base, mask, point, result;
	mbedtls_mpi w, secret, one, sign;
	int ret = 0;

	if (ctx->password > 999999) {
		return -EINVAL;
	}
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&base);
	mbedtls_ecp_point_init(&mask);
	mbedtls_ecp_point_init(&point);
	mbedtls_ecp_point_init(&result);
	mbedtls_mpi_init(&w);
	mbedtls_mpi_init(&secret);
	mbedtls_mpi_init(&one);
	mbedtls_mpi_init(&sign);
	MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&w, ctx->password));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&secret, ctx->secret, sizeof(ctx->secret)));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&sign, receive ? -1 : 1));
	if (ctx->central != receive) {
		MBEDTLS_MPI_CHK(read_point(&grp, &base, ctx->m));
	} else {
		MBEDTLS_MPI_CHK(read_point(&grp, &base, spake_n));
	}
	if (receive) {
		MBEDTLS_MPI_CHK(read_point(&grp, &point, ctx->peer));
	} else {
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &point, &secret, &grp.G, random_bytes, NULL));
	}
	if (ctx->password != 0) {
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &mask, &w, &base, random_bytes, NULL));
		MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, &result, &one, &point, &sign, &mask));
	} else {
		MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&result, &point));
	}
	MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(&grp, &result));
	if (receive) {
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &point, &secret, &result,
					    random_bytes, NULL));
		MBEDTLS_MPI_CHK(write_point(&grp, &point, ctx->shared));
	} else {
		MBEDTLS_MPI_CHK(write_point(&grp, &result, ctx->local));
	}
cleanup:
	mbedtls_mpi_free(&sign);
	mbedtls_mpi_free(&one);
	mbedtls_mpi_free(&secret);
	mbedtls_mpi_free(&w);
	mbedtls_ecp_point_free(&result);
	mbedtls_ecp_point_free(&point);
	mbedtls_ecp_point_free(&mask);
	mbedtls_ecp_point_free(&base);
	mbedtls_ecp_group_free(&grp);
	return ret;
}

int bt_spake_mask(struct bt_spake_context *ctx)
{
	return masked_operation(ctx, false);
}

int bt_spake_shared(struct bt_spake_context *ctx)
{
	return masked_operation(ctx, true);
}

int bt_spake_derive(const struct bt_spake_context *ctx,
		    const struct bt_spake_transcript *t, uint8_t key[32])
{
	static const uint8_t domain[] = "BLE-SPAKE-RFC9382-N-v3";
	uint8_t w[32] = {0};
	psa_hash_operation_t hash = PSA_HASH_OPERATION_INIT;
	size_t len;
	int ret = 0;

	sys_put_be32(ctx->password, w + 28);
	MBEDTLS_MPI_CHK(psa_hash_setup(&hash, PSA_ALG_SHA_256));
#define HASH(data, size) MBEDTLS_MPI_CHK(psa_hash_update(&hash, data, size))
	HASH(domain, sizeof(domain) - 1);
	HASH(t->a, sizeof(t->a));
	HASH(t->b, sizeof(t->b));
	HASH(t->preq, sizeof(t->preq));
	HASH(t->prsp, sizeof(t->prsp));
	HASH(t->pka, sizeof(t->pka));
	HASH(t->pkb, sizeof(t->pkb));
	HASH(ctx->m, sizeof(ctx->m));
	HASH(spake_n, sizeof(spake_n));
	HASH(ctx->central ? ctx->local : ctx->peer, 64);
	HASH(ctx->central ? ctx->peer : ctx->local, 64);
	HASH(w, sizeof(w));
	HASH(ctx->shared, sizeof(ctx->shared));
	HASH(t->na, sizeof(t->na));
	HASH(t->nb, sizeof(t->nb));
	MBEDTLS_MPI_CHK(psa_hash_finish(&hash, key, 32, &len));
#undef HASH
cleanup:
	psa_hash_abort(&hash);
	mbedtls_platform_zeroize(w, sizeof(w));
	return ret;
}

void bt_spake_clear(struct bt_spake_context *ctx)
{
	mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}
