# Copyright (c) 2026 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# flake8: noqa ignore lines too long


import pytest

from fido2.bls12_381 import BBS_SCHNORR, BBS_SCHNORR_SUITE, Schnorr


def test_schnorr_signature():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    sk, pk = schnorr.kgen()
    msg = b"Hello, World!"
    sig = schnorr.sign_encode(sk, msg)
    assert schnorr.verify_encoded(pk, sig, msg)


def test_schnorr_signature_deterministic():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    sk, pk = schnorr.kgen(ikm=b"test_schnorr_signature_deterministic|kgen")
    msg = b"Hello, World!"
    sig = schnorr.sign_encode(
        sk, msg, ikm=b"test_schnorr_signature_deterministic|sign_encode"
    )
    sig2 = schnorr.sign_encode(
        sk, msg, ikm=b"test_schnorr_signature_deterministic|sign_encode|2"
    )
    assert schnorr.verify_encoded(pk, sig, msg)
    assert schnorr.verify_encoded(pk, sig2, msg)
    assert sig == bytes.fromhex(
        "6f1dfc8ec105e7540b70f48ecb7fb6f2c0ec6d98efb6c56d6b092f1f1084ee366af6e9503bc1e6a40706e44012e7b49f0afa13e9f4e559c6226d5e513d24a465"
    )
    assert sig != sig2
