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
""" :rfc:`4491` (using GOST algorithms with X.509) compatibility helpers

Signature, public and private keys formats are defined in the RFC above.
"""

from pygost.gost3410 import CURVE_PARAMS
from pygost.gost3410 import DEFAULT_CURVE
from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import public_key as _public_key
from pygost.gost3410 import sign as _sign
from pygost.gost3410 import verify as _verify
from pygost.gost3411_94 import GOST341194
from pygost.utils import bytes2long
from pygost.utils import long2bytes


GOST341194_SBOX = "GostR3411_94_CryptoProParamSet"


def keypair_gen(seed):
    """ Generate keypair

    :param seed: random data used as an entropy source
    :type seed: bytes, 32 bytes
    :return: private and public keys
    :rtype: (bytes, bytes), 32 and 64 bytes
    """
    if len(seed) != 32:
        raise ValueError("Invalid seed size")
    curve = GOST3410Curve(*CURVE_PARAMS[DEFAULT_CURVE])
    private_key = seed
    public_key_x, public_key_y = _public_key(curve, bytes2long(private_key))
    public_key = (long2bytes(public_key_y) + long2bytes(public_key_x))[::-1]
    return private_key[::-1], public_key


def sign(private_key, data):
    """ Sign data

    :param private_key: private key to sign with
    :type private_key: bytes, 32 bytes
    :param bytes data: arbitrary data
    :return: signature
    :rtype: bytes, 64 bytes
    """
    curve = GOST3410Curve(*CURVE_PARAMS[DEFAULT_CURVE])
    return _sign(
        curve,
        bytes2long(private_key[::-1]),
        GOST341194(data, GOST341194_SBOX).digest(),
    )


def verify(public_key, data, signature):
    """ Verify signature

    :param public_key: public key to verify with
    :type public_key: bytes, 64 bytes
    :param bytes data: arbitrary data
    :type signature: bytes, 64 bytes
    :rtype: bool
    """
    curve = GOST3410Curve(*CURVE_PARAMS[DEFAULT_CURVE])
    public_key = public_key[::-1]
    return _verify(
        curve,
        bytes2long(public_key[32:]),
        bytes2long(public_key[:32]),
        GOST341194(data, GOST341194_SBOX).digest(),
        signature,
    )
