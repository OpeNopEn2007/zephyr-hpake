#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decode and check the published RFC 9382 section 6 P-256 N.

Offline public-parameter tool only; no HashToCurve or random point generation.
The firmware consumes the resulting 64-byte big-endian X || Y constant.
"""
import argparse
import json
from pathlib import Path
import re

from reference_vectors import G, P, enc, mul

SOURCE = 'https://www.rfc-editor.org/rfc/rfc9382.html#section-6'
N_COMPRESSED = bytes.fromhex(
    '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49')
CURVE_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def decode_point(compressed):
    if len(compressed) != 33 or compressed[0] not in (2, 3):
        raise ValueError('Expected a compressed SEC1 P-256 point')
    x = int.from_bytes(compressed[1:], 'big')
    if x >= P:
        raise ValueError('Non-canonical X coordinate')
    rhs = (x*x*x - 3*x + CURVE_B) % P
    y = pow(rhs, (P+1)//4, P)
    if y*y % P != rhs:
        raise ValueError('Point is not on P-256')
    if y % 2 != compressed[0] % 2:
        y = -y % P
    if bytes([2 | (y & 1)]) + x.to_bytes(32, 'big') != compressed:
        raise ValueError('SEC1 round trip failed')
    return x, y


def load_basis():
    point = decode_point(N_COMPRESSED)
    if point in (G, (G[0], -G[1] % P)) or mul(ORDER, point) is not None:
        raise ValueError('Invalid auxiliary point or order')
    return point


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', type=Path, metavar='BT_SPAKE_C',
                        help='Check firmware spake_n against the published point')
    args = parser.parse_args()
    point = load_basis()
    if args.check:
        match = re.search(r'static const uint8_t spake_n\[64\] = \{([^}]+)\};',
                          args.check.read_text())
        if not match:
            raise ValueError('Missing spake_n[64] constant')
        actual = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})\b', match[1]))
        if actual != enc(point):
            raise ValueError('Firmware N differs from RFC 9382')
    print(json.dumps({'source': SOURCE, 'n_compressed_hex': N_COMPRESSED.hex(),
                      'n_xy_be_hex': enc(point).hex(),
                      'source_constant_checked': args.check is not None}, indent=2))


if __name__ == '__main__':
    main()
