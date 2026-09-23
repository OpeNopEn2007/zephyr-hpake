#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the old N=G chosen-point equation against the RFC-N construction.

This is an algebraic regression for one fixed transcript, not a proof that no
offline verifier exists. The tiny private scalars are test fixtures only.
"""

from reference_vectors import G, P, add, mul
from rfc9382_basis import load_basis


def neg(point):
    return point[0], (-point[1]) % P


def sub(left, right):
    return add(left, neg(right))


def signed_mul(scalar, point):
    result = mul(abs(scalar), point)
    return neg(result) if scalar < 0 else result


def main():
    a, b, x, t, password = 5, 7, 11, 13, 123456
    m = mul(a * b, G)
    xstar = add(mul(x, G), mul(password, m))
    ystar = mul(t, G)  # A malicious B omits its password mask.
    candidates = (password - 1, password, password + 1)

    def old_equation(candidate):
        # B knows b and can reconstruct M from A's public key.
        return signed_mul(t - candidate, sub(xstar, mul(candidate, m)))

    direct_shared = mul(x, sub(ystar, mul(password, G)))
    fixed_shared = mul(x, sub(ystar, mul(password, load_basis())))
    direct_matches = [candidate for candidate in candidates
                      if old_equation(candidate) == direct_shared]
    fixed_matches = [candidate for candidate in candidates
                     if old_equation(candidate) == fixed_shared]
    assert direct_matches == [password], direct_matches
    assert fixed_matches == [], fixed_matches
    print("old N=G equation: direct version identifies the password")
    print("old N=G equation: RFC-N version yields no matching candidate")


if __name__ == "__main__":
    main()
