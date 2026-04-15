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

from fido2.bls12_381 import BBS_SCHNORR_SUITE, BbsSchnorr, Schnorr, matrix_mul


def test_schnorr_signature_htf():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    sk, pk = schnorr.kgen()
    msg = b"Hello, World!"
    sig = schnorr.sign_htf_encode(sk, msg)
    assert schnorr.verify_htf_encoded(pk, sig, msg)


def test_schnorr_signature_sha256():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    sk, pk = schnorr.kgen()
    msg = b"Hello, World!"
    sig = schnorr.sign_sha256_encode(sk, msg)
    assert schnorr.verify_sha256_encoded(pk, sig, msg)


def test_schnorr_signature_deterministic():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    sk, pk = schnorr.kgen(ikm=b"test_schnorr_signature_deterministic|kgen")
    msg = b"Hello, World!"
    sig = schnorr.sign_htf_encode(
        sk, msg, ikm=b"test_schnorr_signature_deterministic|sign_encode"
    )
    sig2 = schnorr.sign_htf_encode(
        sk, msg, ikm=b"test_schnorr_signature_deterministic|sign_encode|2"
    )
    assert schnorr.verify_htf_encoded(pk, sig, msg)
    assert schnorr.verify_htf_encoded(pk, sig2, msg)
    assert sig == bytes.fromhex(
        "6af6e9503bc1e6a40706e44012e7b49f0afa13e9f4e559c6226d5e513d24a4656f1dfc8ec105e7540b70f48ecb7fb6f2c0ec6d98efb6c56d6b092f1f1084ee36"
    )
    assert sig != sig2


def test_schnorr_nizk():
    schnorr = Schnorr(BBS_SCHNORR_SUITE)
    m = 2
    n = 3
    M = [[schnorr.kgen()[1] for i in range(n)] for j in range(m)]
    x = [schnorr.kgen()[0] for i in range(n)]
    Y = matrix_mul(M, x)
    proof = schnorr.nizk_prove(M, Y, x, b"test_schnorr_nizk")
    assert schnorr.nizk_verify(M, Y, proof, b"test_schnorr_nizk")
    assert not schnorr.nizk_verify(M, Y, proof, b"test_schnorr_nizk0")
    assert not schnorr.nizk_verify(
        M, matrix_mul(M, [x + 1 for x in x]), proof, b"test_schnorr_nizk"
    )


def test_bbs_schnorr():
    bbs = BbsSchnorr(BBS_SCHNORR_SUITE)

    isk, ipk = bbs.iss_kgen()
    dsk, dpk = bbs.dev_kgen()
    attrs = [1, 2, 3]
    sigma = bbs.issue(isk, dpk, attrs)

    assert bbs.vf_cred(ipk, sigma, dpk, attrs)

    ust, umsg = bbs.show_user_1(ipk, dpk, sigma, attrs, b"Hello, World!", [1])
    smsg = bbs.show_se_1(ipk, dsk, umsg, b"Hello, World!")
    tau = bbs.show_user_2(ust, smsg)

    smsg2 = bbs.show_se_1(ipk, dsk, umsg, b"Hello, Worldz!")
    tau2 = bbs.show_user_2(ust, smsg2)

    assert bbs.verify(ipk, b"Hello, World!", [1], [2], tau)
    assert not bbs.verify(ipk, b"Hello, World!", [1], [2], tau2)
    assert not bbs.verify(ipk, b"Hello, World!", [], [], tau)
    assert not bbs.verify(ipk, b"Hello, World!", [], [2], tau)
    assert not bbs.verify(ipk, b"Hello, World!", [1], [1], tau)
    assert not bbs.verify(ipk, b"Hello, World!", [1], [3], tau)
    assert not bbs.verify(ipk, b"Hello, Worldz!", [1], [2], tau)
    assert not bbs.verify(ipk, b"Hello, World!", [0, 1], [1, 2], tau)
    # assert not bbs.verify(ipk * 2, b"Hello, World!", [1], [2], tau)  TODO: implement pairing check
