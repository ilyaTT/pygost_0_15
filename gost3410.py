# coding: utf-8
# pygost -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2016 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
""" GOST R 34.10 public-key signature function.

This is implementation of GOST R 34.10-2001 (:rfc:`5832`), GOST R
34.10-2012 (:rfc:`7091`). The difference between 2001 and 2012 is the
hash function and corresponding digest and signature lengths.
"""

from os import urandom

from pygost.gost3411_94 import GOST341194
from pygost.utils import bytes2long
from pygost.utils import hexdec
from pygost.utils import long2bytes
from pygost.utils import modinvert


SIZE_341001 = 32
SIZE_341012 = 64


DEFAULT_CURVE = "GostR3410_2001_CryptoPro_A_ParamSet"
# Curve parameters are the following: p, q, a, b, x, y
CURVE_PARAMS = {
    "GostR3410_2001_ParamSet_cc": (
        "C0000000000000000000000000000000000000000000000000000000000003C7",
        "5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
        "C0000000000000000000000000000000000000000000000000000000000003c4",
        "2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c",
    ),
    "GostR3410_2001_TestParamSet": (
        "8000000000000000000000000000000000000000000000000000000000000431",
        "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
    ),
    "GostR3410_2001_CryptoPro_A_ParamSet": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "00000000000000000000000000000000000000000000000000000000000000a6",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
    ),
    "GostR3410_2001_CryptoPro_B_ParamSet": (
        "8000000000000000000000000000000000000000000000000000000000000C99",
        "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
        "8000000000000000000000000000000000000000000000000000000000000C96",
        "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
    ),
    "GostR3410_2001_CryptoPro_C_ParamSet": (
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
        "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
        "000000000000000000000000000000000000000000000000000000000000805a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
    ),
    "GostR3410_2001_CryptoPro_XchA_ParamSet": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "00000000000000000000000000000000000000000000000000000000000000a6",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
    ),
    "GostR3410_2001_CryptoPro_XchB_ParamSet": (
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
        "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
        "000000000000000000000000000000000000000000000000000000000000805a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
    ),
}
for c, params in CURVE_PARAMS.items():
    CURVE_PARAMS[c] = [hexdec(s) for s in params]


class GOST3410Curve(object):
    """ GOST 34.10 validated curve

    >>> p, q, a, b, x, y = CURVE_PARAMS["GostR3410_2001_TestParamSet"]
    >>> curve = GOST3410Curve(p, q, a, b, x, y)
    >>> priv = bytes2long(urandom(32))
    >>> signature = sign(curve, priv, GOST341194(data).digest())
    >>> pubX, pubY = public_key(curve, priv)
    >>> verify(curve, pubX, pubY, GOST341194(data).digest(), signature)
    True
    """
    def __init__(self, p, q, a, b, x, y):
        self.p = bytes2long(p)
        self.q = bytes2long(q)
        self.a = bytes2long(a)
        self.b = bytes2long(b)
        self.x = bytes2long(x)
        self.y = bytes2long(y)
        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if r2 < 0:
            r2 += self.p
        if r1 != r2:
            raise ValueError("Invalid parameters")

    def exp(self, degree, x=None, y=None):
        p = self.p
        a = self.a
        x = x or self.x
        y = y or self.y
        X, Y, Z = 1, 1, 0
        degree_bin = bin(degree)[2:]
        i = len(degree_bin) - 1
        if i == 0:
            raise ValueError("Bad degree value")
        while i >= 0:
            # Doubling
            if Z != 0:
                lm2 = X * X % p * 3
                lm1 = Z * Z * a % p
                lm1 += lm2
                lm2 = Y * Z % p
                lm3 = lm2 * X * Y % p
                lm5 = lm3 * 8
                lm4 = lm1 * lm1 % p - lm5
                lm5 = lm2 * 2 % p
                lm6 = lm5 * 2 * lm5 % p
                X = lm4 * lm5 % p
                lm7 = Y * Y % p * lm6
                Y = ((lm3 * 4 - lm4) * lm1 - lm7) % p
                Z = lm2 * lm6 % p
                if X < 0:
                    X += p
                if Y < 0:
                    Y += p
                if Z < 0:
                    Z += p
            # Adding
            if degree_bin[-i - 1] == "1":
                if Z == 0:
                    X, Y, Z = x, y, 1
                else:
                    lm1 = y * Z % p - Y
                    lm3 = x * Z % p - X
                    lm2 = lm3 * lm3 % p
                    lm4 = lm2 * lm3 % p
                    lm5 = 2 * X * lm2 % p
                    lm6 = lm1 * lm1 * Z % p - lm4 - lm5
                    lm5 = Y * lm4 % p
                    Y = ((lm2 * X - lm6) * lm1 - lm5) % p
                    X = lm3 * lm6 % p
                    Z = Z * lm4 % p
                    if X < 0:
                        X += p
                    if Y < 0:
                        Y += p
                    if Z < 0:
                        Z += p
            i -= 1
        if Z == 0:
            return -1, -1
        lm1 = modinvert(Z, p)
        r1, r2 = X * lm1 % p, Y * lm1 % p
        return r1, r2


def public_key(curve, private_key):
    """ Generate public key from the private one

    :param GOST3410Curve curve: curve to use
    :param long private_key: private key
    :return: public key's parts, X and Y
    :rtype: (long, long)
    """
    return curve.exp(private_key)


def kek(curve, private_key, ukm, pubkey):
    """ Make Diffie-Hellman computation

    :param GOST3410Curve curve: curve to use
    :param long private_key: private key
    :param ukm: UKM value (VKO-factor)
    :type ukm: bytes, 8 bytes
    :param pubkey: public key's part
    :type pubkey: (long, long)
    :return: Key Encryption Key (shared key)
    :rtype: bytes, 32 bytes

    Shared Key Encryption Key computation is based on
    :rfc:`4357` VKO GOST 34.10-2001 with little-endian
    hash output.
    """
    key = curve.exp(private_key, pubkey[0], pubkey[1])
    key = curve.exp(bytes2long(24 * b'\x00' + ukm), key[0], key[1])
    return GOST341194(
        (long2bytes(key[1]) + long2bytes(key[0]))[::-1],
        "GostR3411_94_CryptoProParamSet"
    ).digest()[::-1]


def sign(curve, private_key, digest, size=SIZE_341001):
    """ Calculate signature for provided digest

    :param GOST3410Curve curve: curve to use
    :param long private_key: private key
    :param digest: digest for signing
    :type digest: bytes, 32 bytes
    :param size: signature size
    :type size: 32 (for 34.10-2001) or 64 (for 34.10-2012)
    :return: signature
    :rtype: bytes, 64 bytes
    """
    if len(digest) != size:
        raise ValueError("Invalid digest length")
    q = curve.q
    e = bytes2long(digest) % q
    if e == 0:
        e = 1
    while True:
        k = bytes2long(urandom(size)) % q
        if k == 0:
            continue
        r, _ = curve.exp(k)
        r %= q
        if r == 0:
            continue
        d = private_key * r
        k *= e
        s = (d + k) % q
        if s == 0:
            continue
        break
    return long2bytes(s, size) + long2bytes(r, size)


def verify(curve, pubkeyX, pubkeyY, digest, signature, size=SIZE_341001):
    """ Verify provided digest with the signature

    :param GOST3410Curve curve: curve to use
    :param long pubkeyX: public key's X
    :param long pubkeyY: public key's Y
    :param digest: digest needed to check
    :type digest: bytes, 32 bytes
    :param signature: signature to verify with
    :type signature: bytes, 64 bytes
    :param size: signature size
    :type size: 32 (for 34.10-2001) or 64 (for 34.10-2012)
    :rtype: bool
    """
    if len(digest) != size:
        raise ValueError("Invalid digest length")
    if len(signature) != size * 2:
        raise ValueError("Invalid signature length")
    q = curve.q
    p = curve.p
    s = bytes2long(signature[:size])
    r = bytes2long(signature[size:])
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    e = bytes2long(digest) % curve.q
    if e == 0:
        e = 1
    v = modinvert(e, q)
    z1 = s * v % q
    z2 = q - r * v % q
    p1x, p1y = curve.exp(z1)
    q1x, q1y = curve.exp(degree=z2, x=pubkeyX, y=pubkeyY)
    lm = q1x - p1x
    if lm < 0:
        lm += p
    lm = modinvert(lm, p)
    z1 = q1y - p1y
    lm = lm * z1 % p
    lm = lm * lm % p
    lm = lm - p1x - q1x
    lm = lm % p
    if lm < 0:
        lm += p
    lm %= q
    # This is not constant time comparison!
    return lm == r
