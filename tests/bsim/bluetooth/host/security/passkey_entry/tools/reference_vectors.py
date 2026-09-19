#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline test oracle only; never linked into firmware. Print the C fixtures.

Independent affine P-256 arithmetic and hashlib, with fixed tiny scalars for
known-answer tests. Not constant-time and not suitable for protocol execution.
"""
import hashlib

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x - 3) * pow(2*y, -1, P) if a == b
             else (v-y) * pow(u-x, -1, P)) % P
    r = (slope*slope - x - u) % P
    return r, (slope*(x-r)-y) % P


def mul(k, a):
    r = None
    while k:
        if k & 1:
            r = add(r, a)
        a = add(a, a)
        k >>= 1
    return r


def enc(a):
    return a[0].to_bytes(32, 'big') + a[1].to_bytes(32, 'big')


def emit(name, data):
    print(f'static const uint8_t {name}[{len(data)}] = {{')
    for i in range(0, len(data), 8):
        print('\t' + ', '.join(f'0x{x:02x}' for x in data[i:i+8]) + ',')
    print('};')


if __name__ == '__main__':
    from rfc9382_basis import load_basis

    n = load_basis()
    print('/* SPDX-License-Identifier: Apache-2.0 */')
    print('/* Reproduce with: python3 tools/reference_vectors.py */\n')
    m = mul(35, G)
    w = 123456
    xstar = add(mul(2, G), mul(w, m))
    ystar = add(mul(3, G), mul(w, n))
    shared = mul(6, G)
    points = [('pka', mul(5, G)), ('pkb', mul(7, G)), ('m', m), ('n', n),
              ('xstar', xstar), ('ystar', ystar), ('shared', shared)]
    for name, point in points:
        emit('vector_' + name, enc(point))
        print()
    transcript = (b'BLE-SPAKE-RFC9382-N-v3' + bytes(range(28)) + enc(mul(5, G))
                  + enc(mul(7, G)) + enc(m) + enc(n) + enc(xstar) + enc(ystar)
                  + w.to_bytes(32, 'big') + enc(shared) + bytes(range(32)))
    emit('vector_key', hashlib.sha256(transcript).digest())
