# ruff: noqa: S101

import math
import os
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm

from .arkg import _HTF
from .utils import sha256


def modpow(base, exp, modulus):
    result = 1
    base %= modulus

    while exp > 0:
        if (exp & 1) == 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus

    return result


def modinv(n, primeModulus):
    return modpow(n, primeModulus - 2, primeModulus)


def modsqrt(n, primeModulus):
    assert (primeModulus % 4) == 3
    if n in [0, 1]:
        return n
    else:
        s = modpow(n, (primeModulus + 1) // 4, primeModulus)
        if modpow(s, 2, primeModulus) == n:
            return s
        else:
            return None


def matrix_mul[T](mat: list[list[T]], vec: list[T]) -> list[T]:
    assert len(mat[0]) == len(vec)
    assert all(len(mrow) == len(mat[0]) for mrow in mat)
    return [sum((m * v) for m, v in zip(mrow, vec)) for mrow in mat]


type PointAffine = "PointAffine"
type PointProjective = "PoinProjective"


class Curve:
    def __init__(self, p, a, b, n, h, coord_len, scalar_len, generator):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.h = h
        self.coord_len = coord_len
        self.scalar_len = scalar_len
        (gx, gy) = generator
        self.generator = PointAffine(gx, gy, self).to_projective()

    def zero(self):
        return PointAffine(0, 0, self).zero().to_projective()

    def pow(self, b, e):
        return modpow(b, e, self.p)

    def sqrt(self, a):
        return modsqrt(a, self.p)

    def sign_gf_p(self, y: int) -> bool:
        return y > (self.p - 1) // 2

    def find_y(self, x):
        y = self.sqrt(self.pow(x, 3) + self.a * x + self.b)
        if y is not None:
            if self.p - y < y:
                return self.p - y
            else:
                return y

    def insecure_random_scalar(self):
        return int.from_bytes(os.urandom(self.scalar_len * 2), "big") % self.n

    def insecure_random_point(self):
        return self.generator * self.insecure_random_scalar()

    def find_bls_generator(self):
        for x in range(0, 100):
            y = self.find_y(x)
            if y is not None:
                g = PointAffine(x, y, self) * self.h
                if g.is_valid_nonzero():
                    return g.to_projective()

    def scalar_to_big_endian(self, x):
        return int.to_bytes(x, self.scalar_len, "big")

    def point_from_cose(self, cose):
        assert cose[1] == 1  # kty: OKP
        assert cose[-1] in [13, -65601]  # crv: BLS12-381 (requested value, placeholder value)
        return self.point_from_bytes_compact(cose[-2])

    def point_from_sec1_uncompressed(self, sec1: bytes):
        assert sec1[0] == 0x04
        x = int.from_bytes(sec1[1 : (1 + self.coord_len)], "big")
        y = int.from_bytes(sec1[(1 + self.coord_len) : (1 + self.coord_len * 2)], "big")
        return PointAffine(x, y, self).to_projective()

    def point_from_bytes_compact(self, s_string: bytes):
        """https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html#name-point-de-serialization"""
        m_byte = s_string[0]
        assert m_byte not in [0x20, 0x60, 0xE0], "Invalid m_byte"
        c_bit = m_byte & 0x80
        assert c_bit != 0, "Uncompressed encoding not allowed"
        assert len(s_string) == 48
        i_bit = m_byte & 0x40
        s_bit = m_byte & 0x20
        s_string = bytes([s_string[0] & 0x1F]) + s_string[1:]
        if i_bit != 0:
            assert all(b == 0 for b in s_string), "Infinity point must have zero coordinate"
            return self.zero()
        else:
            x = int.from_bytes(s_string, 'big')
            y2 = (self.pow(x, 3) + 4) % self.p
            y = self.sqrt(y2)
            y_bit = self.sign_gf_p(y)
            return PointAffine(x, y if y_bit == (s_bit != 0) else self.p - y, self).to_projective()

    def parse_scalar_from(self, b: bytes) -> (int, bytes):
        return int.from_bytes(b[: self.scalar_len], "big"), b[self.scalar_len :]

    def parse_point_affine_from(self, b: bytes) -> (PointAffine, bytes):
        L = 1 + 2 * self.coord_len
        return self.point_from_sec1_uncompressed(b[:L]), b[L:]

    def parse_point_projective_from(self, b: bytes) -> (PointProjective, bytes):
        p, rest = self.parse_point_affine_from(b)
        return p.to_projective(), rest


class PointAffine:
    def __init__(self, x, y, crv, is_zero=False):
        self.is_zero = is_zero
        self.x = x
        self.y = y
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointAffine) or isinstance(o, PointProjective), (
            f"self: {self}, o: {o}"
        )
        assert self.crv is o.crv
        if isinstance(o, PointProjective):
            return self.to_projective() == o
        if self.is_zero and o.is_zero:
            return True
        elif self.is_zero != o.is_zero:
            return False
        else:
            return self.x == o.x and self.y == o.y

    def __repr__(self):
        if self.is_zero:
            return "(ZERO)"
        else:
            L = math.ceil(math.log2(self.crv.p) / 8)
            x = int.to_bytes(self.x, L, "big").hex()
            y = int.to_bytes(self.y, L, "big").hex()
            return f"(0x{x}, 0x{y})"

    def zero(self):
        return PointAffine(0, 0, self.crv, is_zero=True)

    def to_projective(self):
        q = PointProjective(self.x, self.y, 1, self.crv)
        if self.is_zero:
            return q.zero()
        else:
            return q

    def coordinate_to_big_endian(self, x):
        return int.to_bytes(x, self.crv.coord_len, "big")

    def to_big_endian_coordinates(self):
        assert not self.is_zero
        return (
            self.coordinate_to_big_endian(self.x),
            self.coordinate_to_big_endian(self.y),
        )

    def to_sec1_uncompressed(self):
        x, y = self.to_big_endian_coordinates()
        return bytes([0x04]) + x + y

    def to_bytes_compact(self):
        """https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html#name-point-serialization"""
        c_bit = 0x80
        i_bit = 0x40 if self.is_zero else 0x00
        s_bit = 0x00 if i_bit != 0x00 else 0x20 if self.crv.sign_gf_p(self.y) else 0x00
        m_byte = c_bit | i_bit | s_bit
        s_string = bytes([0x00]) * self.crv.coord_len if self.is_zero else self.coordinate_to_big_endian(self.x)
        s_string = bytes([s_string[0] | m_byte]) + s_string[1:]
        return s_string

    def is_valid_nonzero(self):
        return (
            not self.is_zero
            and self.crv.pow(self.y, 2)
            == (self.crv.pow(self.x, 3) + self.crv.a * self.x + self.crv.b) % self.crv.p
        )

    def __neg__(self):
        return PointAffine(
            self.x, (-self.y) % self.crv.p, self.crv, is_zero=self.is_zero
        )

    def __add__(self, q):
        if isinstance(q, int) and q == 0:
            # Special case for self + sum(...) with empty sum
            return self

        assert isinstance(q, PointAffine), f"p: {self}, q: {q}"
        assert self.crv is q.crv
        p = self

        if self.is_zero:
            return q

        elif q.is_zero:
            return p

        else:
            if p.x == q.x:
                if p.y == (-q.y % self.crv.p):
                    return self.zero()
                else:
                    kn = 3 * p.x**2 + self.crv.a
                    kd = 2 * p.y
                    k = kn * modinv(kd, self.crv.p)
            else:
                kn = q.y - p.y
                kd = q.x - p.x
                k = kn * modinv(kd, self.crv.p)

            xr = (k**2 - p.x - q.x) % self.crv.p
            yr = (k * (p.x - xr) - p.y) % self.crv.p
            return PointAffine(xr, yr, self.crv)

    def __radd__(self, other):
        # Required in order for built-in sum() to work with PointAffine
        if other == 0:
            return self
        else:
            raise NotImplementedError()

    def __mul__(self, k):
        k = k % self.crv.n
        pPow2 = self
        result = self.zero()

        while k > 0:
            if k % 2 != 0:
                result += pPow2
            pPow2 += pPow2
            k >>= 1

        return result


class PointProjective:
    def __init__(self, x, y, z, crv):
        self.x = x
        self.y = y
        self.z = z
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointProjective) or isinstance(o, PointAffine)
        assert self.crv is o.crv
        if isinstance(o, PointAffine):
            return self == o.to_projective()
        if self.is_zero() and o.is_zero():
            return True
        elif (self.is_zero()) != (o.is_zero()):
            return False
        else:
            return ((self.x * o.z) % self.crv.p == (o.x * self.z) % self.crv.p) and (
                (self.y * o.z) % self.crv.p == (o.y * self.z) % self.crv.p
            )

    def __repr__(self):
        if self.is_zero():
            return "(ZERO)"
        else:
            L = math.ceil(math.log2(self.crv.p) / 8)
            x = int.to_bytes(self.x, L, "big").hex()
            y = int.to_bytes(self.y, L, "big").hex()
            z = int.to_bytes(self.z, L, "big").hex()
            return f"P(0x{x}, 0x{y}, 0x{z})"

    def zero(self):
        return PointProjective(0, 1, 0, self.crv)

    def to_affine(self):
        zinv = modinv(self.z, self.crv.p)
        return PointAffine(
            (self.x * zinv) % self.crv.p, (self.y * zinv) % self.crv.p, self.crv
        )

    def is_zero(self):
        return self.z == 0

    def is_valid_nonzero(self):
        if self.is_zero():
            return False
        else:
            z2 = self.crv.pow(self.z, 2)
            z3 = self.crv.pow(self.z, 3)
            lhs = self.crv.pow(self.y, 2) * self.z
            rhs = self.crv.pow(self.x, 3) + self.crv.a * self.x * z2 + self.crv.b * z3
            return (lhs % self.crv.p) == (rhs % self.crv.p)

    def __neg__(self):
        return PointProjective(self.x, (-self.y) % self.crv.p, self.z, self.crv)

    def __add__(self, q):
        if isinstance(q, int) and q == 0:
            # Special case for self + sum(...) with empty sum
            return self

        assert isinstance(q, PointProjective)
        assert self.crv is q.crv
        p = self

        if self.is_zero():
            return q

        elif q.is_zero():
            return p

        else:
            if p.x * q.z == q.x * p.z:
                if p.y * q.z == ((-q.y * p.z) % self.crv.p):
                    return self.zero()
                else:
                    yp2 = self.crv.pow(p.y, 2)
                    zp2 = self.crv.pow(p.z, 2)
                    k = (3 * self.crv.pow(p.x, 2) + self.crv.a * zp2) % self.crv.p
                    zr1 = (4 * zp2 * yp2) % self.crv.p
                    xr1 = (self.crv.pow(k, 2) - 8 * p.x * yp2 * p.z) % self.crv.p
                    yr = (2 * p.y) * k * (
                        p.x * zr1 - xr1 * p.z
                    ) - 4 * p.z * zr1 * self.crv.pow(p.y, 3)
                    yr = yr % self.crv.p

                    zr2 = 4 * zp2 * yp2
                    zr = (zr1 * zr2) % self.crv.p
                    xr = (xr1 * zr2) % self.crv.p
                    return PointProjective(xr, yr, zr, self.crv)
            else:
                pxqz = p.x * q.z
                pyqz = p.y * q.z
                qypz = q.y * p.z
                qxpz = q.x * p.z
                pzqz = p.z * q.z
                xpzqmxqzp = pxqz - qxpz
                xpzqmxqzp2 = self.crv.pow(xpzqmxqzp, 2)
                ypzqmyqzp = (pyqz - qypz) % self.crv.p
                ypzqmyqzp2 = self.crv.pow(ypzqmyqzp, 2)
                pzqz_xpzqmxqzp2 = pzqz * xpzqmxqzp2
                k = (pzqz * ypzqmyqzp2 - xpzqmxqzp2 * (pxqz + qxpz)) % self.crv.p
                xr = (xpzqmxqzp * k) % self.crv.p
                yr = (
                    pzqz_xpzqmxqzp2 * (q.x * p.y - p.x * q.y) - ypzqmyqzp * k
                ) % self.crv.p
                zr = (pzqz_xpzqmxqzp2 * xpzqmxqzp) % self.crv.p
                return PointProjective(xr, yr, zr, self.crv)

    def __radd__(self, other):
        # Required in order for built-in sum() to work with PointAffine
        if other == 0:
            return self
        else:
            raise NotImplementedError()

    def __sub__(self, q):
        return self + (-q)

    def __mul__(self, k):
        k = k % self.crv.n
        pPow2 = self
        result = self.zero()

        while k > 0:
            if k % 2 != 0:
                result += pPow2
            pPow2 += pPow2
            k >>= 1

        return result

    def to_sec1_uncompressed(self):
        return self.to_affine().to_sec1_uncompressed()

    def to_bytes_compact(self):
        return self.to_affine().to_bytes_compact()

    def verify_ecsdsa_sha256(self, signature: bytes, message: bytes):
        assert len(signature) == self.crv.scalar_len * 2
        s = int.from_bytes(signature[: self.crv.scalar_len], "big")
        e = int.from_bytes(signature[self.crv.scalar_len :], "big")
        rv = self.crv.generator * s + self * e
        rv_bin = rv.to_bytes_compact()
        ev_bin = sha256(rv_bin + message)
        ev = int.from_bytes(ev_bin, "big") % self.crv.n
        if ev == e:
            return
        raise InvalidSignature()


class Suite:
    def __init__(
        self,
        crv_g1: Curve,
        crv_g2: Curve,
        H0: PointProjective,
        Hi: list[PointProjective],
        security_level: int,
        hash_to_field_hash: HashAlgorithm,
    ):
        assert crv_g1.n == crv_g2.n
        self.n = crv_g1.n
        self.crv_g1 = crv_g1
        self.crv_g2 = crv_g2
        self.g1 = crv_g1.generator
        self.g2 = crv_g2.generator
        self.H0 = H0
        self.Hi = Hi
        self.security_level = security_level
        self.hash_to_field_hash = hash_to_field_hash

    def _htf_scalar(self, dst: bytes) -> _HTF:
        L = math.ceil((math.ceil(math.log2(self.n)) + self.security_level) / 8)
        return _HTF(dst, self.n, L, self.hash_to_field_hash)

    def or_rand(self, ikm: Optional[bytes], L: Optional[int]) -> bytes:
        L = L if L is not None else self.security_level * 2 // 8
        return ikm if ikm is not None else os.urandom(L)

    def sample_scalar(self, dst: bytes, ikm: Optional[bytes]) -> int:
        return self._htf_scalar(dst).hash_to_field(self.or_rand(ikm, None), 1)[0]

    def hash_to_scalar(self, dst: bytes, msg: bytes) -> int:
        return self._htf_scalar(dst).hash_to_field(msg, 1)[0]


class Schnorr:
    """Schnorr signature scheme as defined in https://eprint.iacr.org/2025/1995 ,
    using:

    - SEC 1 uncompressed encoding of curve points, and
    - binary concatenation for combining hash function inputs.
    """

    def __init__(self, suite: Suite):
        self.suite = suite

    def kgen(self, ikm: Optional[bytes] = None) -> (int, PointProjective):
        sk = self.suite.sample_scalar(b"Schnorr.KGen", ikm)
        pk = self.suite.H0 * sk
        return sk, pk

    def encode_point(self, p: PointProjective) -> bytes:
        return p.to_bytes_compact()

    def encode_signature(self, sig: (int, int)) -> bytes:
        c, s = sig
        return b"".join(self.suite.crv_g1.scalar_to_big_endian(x) for x in (s, c))

    def parse_signature(self, sig: bytes) -> (int, int):
        s, sig = self.suite.crv_g1.parse_scalar_from(sig)
        c, sig = self.suite.crv_g1.parse_scalar_from(sig)
        assert sig == b""
        return c, s

    def sign_htf(self, sk: int, m: bytes, ikm: Optional[bytes] = None) -> (int, int):
        """
        Sign using hash_to_field as the hash function H.
        """
        omega = self.suite.sample_scalar(b"Schnorr.Sign", ikm)
        r = self.suite.H0 * omega
        c = self.suite.hash_to_scalar(b"Schnorr.Sign", self.encode_point(r) + m)
        s = (omega + c * sk) % self.suite.n
        return c, s

    def sign_sha256(self, sk: int, m: bytes) -> (int, int):
        """
        Sign using SHA-256 as the hash function H, with rejection sampling to fall under the group order.
        """
        while True:
            omega = self.suite.sample_scalar(b"Schnorr.Sign", None)
            r = self.suite.H0 * omega
            h = Hash(SHA256())
            h.update(self.encode_point(r) + m)
            c = int.from_bytes(h.finalize(), "big")
            if c < self.suite.n:
                s = (omega + c * sk) % self.suite.n
                return c, s

    def sign_htf_encode(self, sk: int, m: bytes, ikm: Optional[bytes] = None) -> bytes:
        return self.encode_signature(self.sign_htf(sk, m, ikm))

    def sign_sha256_encode(self, sk: int, m: bytes) -> bytes:
        return self.encode_signature(self.sign_sha256(sk, m))

    def verify_htf(self, pk: PointProjective, sig: (int, int), m: bytes) -> bool:
        """
        Verify using hash_to_field as the hash function H.
        """
        c, s = sig
        return c == self.suite.hash_to_scalar(
            b"Schnorr.Sign",
            self.encode_point(self.suite.H0 * s - pk * c) + m,
        )

    def verify_htf_encoded(self, pk: PointProjective, sig: bytes, m: bytes) -> bool:
        return self.verify_htf(pk, self.parse_signature(sig), m)

    def verify_sha256(self, pk: PointProjective, sig: (int, int), m: bytes) -> bool:
        """
        Verify using SHA-256 as the hash function H, rejecting is the hash is greater than the group order.
        """
        c, s = sig
        h = Hash(SHA256())
        h.update(self.encode_point(self.suite.H0 * s - pk * c) + m)
        c2 = int.from_bytes(h.finalize(), "big")
        return c2 < self.suite.n and c == c2

    def verify_sha256_encoded(self, pk: PointProjective, sig: bytes, m: bytes) -> bool:
        return self.verify_sha256(pk, self.parse_signature(sig), m)

    def re_rand_pk(self, pk: PointProjective, r_key: int) -> PointProjective:
        return pk + self.suite.H0 * r_key

    def adapt_sig(self, sig: (int, int), r_key: int, m: bytes) -> (int, int):
        c, s = sig
        return (c, (s + c * r_key) % self.suite.n)

    def nizk_prove(
        self,
        M: list[list[PointProjective]],
        Y: list[PointProjective],
        x: list[int],
        ctx: bytes,
        ikm: Optional[bytes] = None,
    ) -> (int, list[int]):
        """Schnorr NIZK as defined in appendix F.1 of https://eprint.iacr.org/2025/1995 ,
        using:

        - hash_to_field as the hash function H,
        - SEC 1 uncompressed encoding of curve points, and
        - binary concatenation for combining hash function inputs.
        """
        m = len(M)
        n = len(M[0])
        assert len(Y) == m
        assert len(x) == n
        assert matrix_mul(M, x) == Y
        omega = [
            self.suite.sample_scalar(b"Schnorr.NIZK.Prove.omega." + bytes([i]), ikm)
            for i in range(n)
        ]
        R = matrix_mul(M, omega)
        c = self.suite.hash_to_scalar(
            b"Schnorr.NIZK.Proof",
            b"".join(
                self.encode_point(p)
                for p in [
                    *[m for mrow in M for m in mrow],
                    *Y,
                    *R,
                ]
            )
            + ctx,
        )
        s = [o + (c * x) % self.suite.n for o, x in zip(omega, x)]
        return c, s

    def nizk_verify(
        self,
        M: list[list[PointProjective]],
        Y: list[PointProjective],
        sig: (int, list[int]),
        ctx: bytes,
    ) -> bool:
        c, s = sig
        Ms = matrix_mul(M, s)
        Yc = [y * c for y in Y]
        return c == self.suite.hash_to_scalar(
            b"Schnorr.NIZK.Proof",
            b"".join(
                self.encode_point(p)
                for p in [
                    *[m for mrow in M for m in mrow],
                    *Y,
                    *(Msi - Yci for Msi, Yci in zip(Ms, Yc)),
                ]
            )
            + ctx,
        )


class BbsSchnorr:
    """BBS-Schnorr scheme proposed in https://eprint.iacr.org/2025/1995"""

    def __init__(self, suite: Suite):
        """Setup procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        assert suite.n == suite.crv_g2.n

        self.suite = suite
        self.l = len(self.suite.Hi)
        self.p = suite.n
        self.zero_g1 = suite.crv_g1.zero()
        self.Sig = Schnorr(suite)

    def iss_kgen(self, ikm: Optional[bytes] = None) -> (int, PointProjective):
        """IssKGen procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        isk = self.suite.sample_scalar(b"IssKGen", ikm)
        ipk = self.suite.g2 * isk
        print("isk: " + str(isk))
        return isk, ipk

    def dev_kgen(self, ikm: Optional[bytes] = None) -> (int, PointProjective):
        """DevKGen procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        dsk = self.suite.sample_scalar(b"DevKGen", ikm)
        dpk = self.suite.H0 * dsk
        return dsk, dpk

    def issue(
        self,
        isk: int,
        dpk: PointProjective,
        attrs: list[int],
        ikm: Optional[bytes] = None,
    ) -> (PointProjective, int):
        """Issue procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        e = self.suite.sample_scalar(b"Issue", ikm)
        C = self.suite.g1 + dpk + sum(H * a for a, H in zip(attrs, self.suite.Hi))
        A = C * modinv((isk + e) % self.p, self.p)
        return A, e

    def verify(
        self,
        ipk: PointProjective,
        ctx: bytes,
        disclosed_idx: list[int],
        disclosed_attrs: list[int],
        tau: (
            PointProjective,
            any,
            PointProjective,
            PointProjective,
            PointProjective,
            any,
        ),
    ) -> bool:
        """Verify procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        dpkbar, pi_se, Abar, Bbar, Cbar, pi_bbs = tau
        non_disclosed_idx = [i for i in range(self.l) if i not in disclosed_idx]
        if not self.Sig.verify_sha256(
            dpkbar, pi_se, self.Sig.encode_point(dpkbar) + ctx
        ):
            return False
        if len(disclosed_idx) != len(disclosed_attrs):
            return False
        if len(pi_bbs[1]) != 4 + len(non_disclosed_idx):
            return False

        Y = (
            self.suite.g1
            + dpkbar
            + sum(
                self.suite.Hi[j] * disclosed_attrs[j]
                for j, i in enumerate(disclosed_idx)
            )
        )

        print("Abar: " + Abar.to_sec1_uncompressed().hex())
        print("ipk: " + ipk.to_sec1_uncompressed().hex())
        print("Bbar: " + Bbar.to_sec1_uncompressed().hex())
        print("G2: " + self.suite.g2.to_sec1_uncompressed().hex())

        return (
            (not Abar.is_zero())
            and (True)  # TODO: Check pairing equality
            and self.Sig.nizk_verify(
                [
                    [
                        Cbar,
                        self.suite.H0,
                        *(-self.suite.Hi[j] for j in non_disclosed_idx),
                        *(2 * [self.zero_g1]),
                    ],
                    [*((2 + len(non_disclosed_idx)) * [self.zero_g1]), Cbar, -Abar],
                ],
                [Y, Bbar],
                pi_bbs,
                ctx,
            )
        )

    def vf_cred(
        self,
        ipk: PointProjective,
        sigma: (PointProjective, int),
        dpk: PointProjective,
        attrs: list[int],
    ) -> bool:
        """VfCred procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        A, e = sigma
        C = self.suite.g1 + dpk + sum(H * a for a, H in zip(attrs, self.suite.Hi))
        print("A: " + A.to_sec1_uncompressed().hex())
        print("ipk: " + ipk.to_sec1_uncompressed().hex())
        print("e: " + str(e))
        print("G2: " + self.suite.g2.to_sec1_uncompressed().hex())
        print("C: " + C.to_sec1_uncompressed().hex())
        return (
            (not A.is_zero()) and (True)  # TODO: Check pairing equality
        )

    def show_user_1(
        self,
        ipk: PointProjective,
        dpk: PointProjective,
        sigma: (PointProjective, int),
        attrs: list[int],
        ctx: bytes,
        disclose_idx: list[int],
        ikm: Optional[bytes] = None,
    ) -> (
        (
            PointProjective,
            PointProjective,
            PointProjective,
            int,
            (PointProjective, int),
            list[int],
            bytes,
            list[int],
            bytes,
        ),
        PointProjective,
    ):
        """ShowUser1 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        assert len(attrs) == len(self.suite.Hi)
        assert all(d >= 0 and d < len(attrs) for d in disclose_idx)
        assert 0 not in disclose_idx

        r_key = self.suite.sample_scalar(b"ShowUser1.r_key", ikm)
        dpkbar = self.Sig.re_rand_pk(dpk, r_key)
        umsg = dpkbar
        ust = (ipk, dpk, dpkbar, r_key, sigma, attrs, ctx, disclose_idx, ikm)
        return ust, umsg

    def show_se_1(
        self,
        ipk: PointProjective,
        dsk: int,
        umsg: PointProjective,
        ctx: bytes,
    ) -> bytes:
        """ShowSE1 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        smsg = self.Sig.sign_sha256_encode(dsk, self.Sig.encode_point(umsg) + ctx)
        return smsg

    def show_user_2(
        self,
        ust: (
            PointProjective,
            PointProjective,
            PointProjective,
            int,
            (PointProjective, int),
            list[int],
            bytes,
            list[int],
            bytes,
        ),
        smsg: bytes,
    ) -> bytes:
        """ShowUser2 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995"""
        ipk, dpk, dpkbar, r_key, sigma, attrs, ctx, disclose_idx, ikm = ust
        non_disclose_idx = [i for i in range(self.l) if i not in disclose_idx]
        pi_se = self.Sig.adapt_sig(
            self.Sig.parse_signature(smsg), r_key, self.Sig.encode_point(dpkbar) + ctx
        )
        A, e = sigma
        r1 = self.suite.sample_scalar(b"ShowUser2.r1", ikm)
        r2 = self.suite.sample_scalar(b"ShowUser2.r2", ikm)
        C = self.suite.g1 + dpk + sum(H * a for a, H in zip(attrs, self.suite.Hi))
        Cbar = C * r1
        Abar = A * r2 * r1
        Bbar = Cbar * r2 - Abar * e
        Y = (
            self.suite.g1
            + dpkbar
            + sum(self.suite.Hi[i] * attrs[i] for i in disclose_idx)
        )

        pi_bbs = self.Sig.nizk_prove(
            [
                [
                    Cbar,
                    self.suite.H0,
                    *(-self.suite.Hi[j] for j in non_disclose_idx),
                    *(2 * [self.zero_g1]),
                ],
                [*((2 + len(non_disclose_idx)) * [self.zero_g1]), Cbar, -Abar],
            ],
            [Y, Bbar],
            [modinv(r1, self.p), r_key, *(attrs[j] for j in non_disclose_idx), r2, e],
            ctx,
        )
        return dpkbar, pi_se, Abar, Bbar, Cbar, pi_bbs


CRV_BLS = Curve(
    0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB,
    0,
    4,
    0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    0x396C8C005555E1568C00AAAB0000AAAB,
    48,
    32,
    (
        0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
        0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1,
    ),
)

BBS_SCHNORR_SUITE = Suite(
    CRV_BLS,
    # TODO: Actually use G2
    CRV_BLS,
    # TODO: Use distinct generators
    CRV_BLS.generator,
    3 * [CRV_BLS.generator],
    128,
    SHA256(),
)
