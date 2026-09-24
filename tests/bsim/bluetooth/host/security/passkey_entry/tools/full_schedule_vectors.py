#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent test-only SHA-256 -> Bluetooth f5/f6 vectors for this fixture.

Requires Python cryptography. This script is never linked into firmware and
does not claim that the custom protocol has an RFC 9382 security proof.
"""

import hashlib

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

from reference_vectors import G, add, enc, mul
from rfc9382_basis import load_basis


SALT = bytes.fromhex("6c888391aaf5a53860370bdb5a6083be")


def cmac(key, data):
    mac = CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()


def address(addr):
    """Convert type || on-wire six octets to f5/f6's CMAC order."""
    assert len(addr) == 7
    return addr[:1] + addr[1:][::-1]


def f5(key_be, na_wire, nb_wire, a_wire, b_wire):
    t = cmac(SALT, key_be)
    suffix = (b"btle" + na_wire[::-1] + nb_wire[::-1]
              + address(a_wire) + address(b_wire) + b"\x01\x00")
    return (cmac(t, b"\x00" + suffix)[::-1],
            cmac(t, b"\x01" + suffix)[::-1])


def f6(mackey_wire, n1_wire, n2_wire, r_wire, io_cap, a_wire, b_wire):
    message = (n1_wire[::-1] + n2_wire[::-1] + r_wire[::-1] + io_cap[::-1]
               + address(a_wire) + address(b_wire))
    return cmac(mackey_wire[::-1], message)[::-1]


def emit(name, data):
    print(f"static const uint8_t {name}[{len(data)}] = {{")
    for offset in range(0, len(data), 8):
        print("\t" + ", ".join(f"0x{value:02x}" for value in data[offset:offset + 8]) + ",")
    print("};")


def check_bluetooth_f5_example():
    # Existing Zephyr SMP self-test fixture from the Bluetooth specification.
    w = bytes.fromhex("98a6bf73f3348d86f166f8b4136b7999"
                      "9b7d390aa610103405adc857a33402ec")
    n1 = bytes.fromhex("abae2b71ecb2ffff3e7377d15484cbd5")
    n2 = bytes.fromhex("cfc43dfff78365216e5fa725cce7e8a6")
    a1 = bytes.fromhex("00cebf37371256")
    a2 = bytes.fromhex("00c1cf2d7013a7")
    mackey, ltk = f5(w[::-1], n1, n2, a1, a2)
    assert mackey == bytes.fromhex("206e63ce206a3ffd024a08a176f16529")
    assert ltk == bytes.fromhex("380a7594b522059823cdd76911798669")
    r = bytes.fromhex("c80f2d0cd242da0854bb53b43b34a312")
    assert f6(mackey, n1, n2, r, bytes.fromhex("020101"), a1, a2) == bytes.fromhex(
        "618f95da090b6cd2c5e8d09c9873c4e3")


def main():
    check_bluetooth_f5_example()
    w = 123456
    a, b = bytes(range(7)), bytes(range(7, 14))
    preq, prsp = bytes(range(14, 21)), bytes(range(21, 28))
    na, nb = bytes(range(16)), bytes(range(16, 32))
    m = mul(35, G)
    n = load_basis()
    xstar = add(mul(2, G), mul(w, m))
    ystar = add(mul(3, G), mul(w, n))
    transcript = (b"BLE-SPAKE-RFC9382-N-v3" + a + b + preq + prsp
                  + enc(mul(5, G)) + enc(mul(7, G)) + enc(m) + enc(n)
                  + enc(xstar) + enc(ystar) + w.to_bytes(32, "big")
                  + enc(mul(6, G)) + na + nb)
    key = hashlib.sha256(transcript).digest()
    mackey, ltk = f5(key, na, nb, a, b)
    r = w.to_bytes(4, "little") + bytes(12)
    ea = f6(mackey, na, nb, r, preq[1:4], a, b)
    eb = f6(mackey, nb, na, r, prsp[1:4], b, a)
    emit("vector_mackey", mackey)
    print()
    emit("vector_ltk", ltk)
    print()
    emit("vector_ea", ea)
    print()
    emit("vector_eb", eb)


if __name__ == "__main__":
    main()
