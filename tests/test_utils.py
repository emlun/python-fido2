# coding=utf-8

# Copyright (c) 2013 Yubico AB
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


import datetime
import os
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)

from fido2.utils import hmac_sha256, sha256, websafe_decode, websafe_encode
from fido2.cose import CoseKey
from fido2.webauthn import AttestationObject, AuthenticatorData, AttestedCredentialData


class TestSha256(unittest.TestCase):
    def test_sha256_vectors(self):
        self.assertEqual(
            sha256(b"abc"),
            bytes.fromhex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
        )
        self.assertEqual(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            bytes.fromhex(
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            ),
        )


class TestHmacSha256(unittest.TestCase):
    def test_hmac_sha256_vectors(self):
        self.assertEqual(
            hmac_sha256(b"\x0b" * 20, b"Hi There"),
            bytes.fromhex(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            ),
        )

        self.assertEqual(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            bytes.fromhex(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            ),
        )


class TestWebSafe(unittest.TestCase):
    # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10

    def test_websafe_decode(self):
        self.assertEqual(websafe_decode(b""), b"")
        self.assertEqual(websafe_decode(b"Zg"), b"f")
        self.assertEqual(websafe_decode(b"Zm8"), b"fo")
        self.assertEqual(websafe_decode(b"Zm9v"), b"foo")
        self.assertEqual(websafe_decode(b"Zm9vYg"), b"foob")
        self.assertEqual(websafe_decode(b"Zm9vYmE"), b"fooba")
        self.assertEqual(websafe_decode(b"Zm9vYmFy"), b"foobar")

    def test_websafe_decode_unicode(self):
        self.assertEqual(websafe_decode(""), b"")
        self.assertEqual(websafe_decode("Zm9vYmFy"), b"foobar")

    def test_websafe_encode(self):
        self.assertEqual(websafe_encode(b""), "")
        self.assertEqual(websafe_encode(b"f"), "Zg")
        self.assertEqual(websafe_encode(b"fo"), "Zm8")
        self.assertEqual(websafe_encode(b"foo"), "Zm9v")
        self.assertEqual(websafe_encode(b"foob"), "Zm9vYg")
        self.assertEqual(websafe_encode(b"fooba"), "Zm9vYmE")
        self.assertEqual(websafe_encode(b"foobar"), "Zm9vYmFy")


def generate_attestation_ca_cert(
    ca_key: CertificateIssuerPrivateKeyTypes,
    hash_alg: hashes.HashAlgorithm | None,
) -> x509.Certificate:
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "TEST attestation CA"),
        ]
    )
    subject = issuer

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=10)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hash_alg)
    )

    return ca_cert


def generate_attestation_cert(
    public_key: CertificatePublicKeyTypes,
    ca_cert: x509.Certificate,
    ca_key: CertificateIssuerPrivateKeyTypes,
    ca_hash_alg: hashes.HashAlgorithm | None,
) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "TEST attestation"),
            x509.NameAttribute(
                x509.NameOID.COUNTRY_NAME, "AA"
            ),  # AA: User-assigned ISO 3166 country code
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Yubico"),
            x509.NameAttribute(
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
        ]
    )

    att_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=10)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, ca_hash_alg)
    )

    return att_cert


def generate_packed_attestation_object(
    credential_public_key: CoseKey,
    attestation_cert: x509.Certificate,
    attestation_key: PrivateKeyTypes,
    attestation_sign_args: list,
    rp_id_hash: bytes,
    credential_id: bytes,
    client_data_hash: bytes,
) -> AttestationObject:

    auth_data = AuthenticatorData.create(
        rp_id_hash,
        AuthenticatorData.FLAG.AT,
        0,
        AttestedCredentialData.create(
            bytes([0] * 16), credential_id, credential_public_key
        ),
    )
    return AttestationObject.create(
        "packed",
        auth_data,
        {
            "alg": credential_public_key.ALGORITHM,
            "sig": attestation_key.sign(
                auth_data + client_data_hash, *attestation_sign_args
            ),
            "x5c": [attestation_cert.public_bytes(Encoding.DER)],
        },
    )
