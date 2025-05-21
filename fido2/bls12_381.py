from __future__ import annotations

import math
import os

from cryptography.exceptions import InvalidSignature
from functools import reduce
from itertools import zip_longest
from typing import Callable, Optional

from . import cbor
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
    s = modpow(n, (primeModulus + 1)//4, primeModulus)
    if s != 0 and s != 1 and modpow(s, 2, primeModulus) == n:
        return s
    else:
        return None


def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif b == 0:
        return a
    else:
        return gcd(b, a % b)


primes = [2, 3]
def factorize(a):
    factors = []

    for p in primes:
        quot, rem = divmod(a, p)
        if rem == 0:
            return factors + [p] + factorize(quot)

    i = primes[-1]
    while a > 1:
        i += 2
        if all(i % p != 0 for p in primes):
            primes.append(i)

            quot, rem = divmod(a, i)
            while rem == 0:
                factors.append(i)
                a = quot
                quot, rem = divmod(a, i)

    return factors


def product(it, start=1):
    return reduce(lambda a, b: a*b, it, start)


def find_element_order(element, group_order: int | list[int]):
    factors = factorize(group_order) if isinstance(group_order, int) else group_order
    o = product(factors)
    for f in factors:
        oo = o // f
        if element**(oo + 1) == element:
            o = oo
    return o


class PrimeField:
    def __init__(self, q: int):
        self.q = q  # Field characteristic (modulus)
        self.coord_len = math.ceil(math.log2(q) / 8)

    def characteristic(self):
        return self.q

    def ext_degree(self):
        return 1

    def size(self):
        return self.q

    def to_bytes(self, c: int) -> bytes:
        assert isinstance(c, int), c
        return int.to_bytes(c, self.coord_len, 'big')

    def el(self, el: int) -> int:
        assert isinstance(el, int), (el, self)
        return el % self.q

    def promote(self, el: int | Polynomial) -> int | Polynomial:
        assert isinstance(el, (int, Polynomial)), (el, self)
        return el

    def pol(self, coeffs: list[int]) -> Polynomial:
        return Polynomial([self.el(c) for c in coeffs], self, None)

    def zero(self) -> int:
        return 0

    def one(self) -> int:
        return 1

    def monoup(self, degree: int) -> int:
        return self.pol([0] * degree + [1])

    def invert(self, a):
        # if isinstance(a, Polynomial):
            # return a.inv()
        # else:
        assert isinstance(a, int), a
        return modinv(a, self.q)

    def __repr__(self):
        return f"Field(q={self.q})"


class ExtensionField:
    def __init__(self, base: PrimeField | ExtensionField, modulus: None | Polynomial | list[int] | list[Polynomial]):
        assert modulus is None or isinstance(modulus, (list, Polynomial)), (modulus, self)
        if isinstance(modulus, Polynomial):
            assert modulus.cfield is base, (modulus, modulus.cfield, base)
            assert modulus.pfield is None or modulus.pfield is self, (modulus, modulus.pfield, self)
        self.base = base
        self.modulus = ((modulus if isinstance(modulus, Polynomial) else base.pol(modulus)).with_pfield(self)
                        if modulus is not None else None)

    def without_modulus(self) -> ExtensionField:
        base = self.base.without_modulus() if isinstance(self.base, ExtensionField) else self.base
        return self if base is self.base and self.modulus is None else ExtensionField(base, None)

    def promote(self, c: int | Polynomial) -> Polynomial:
        if isinstance(c, int) or c.pfield is self.base:
            return self.mono(0) * c
        elif c.cfield is self.base:
            return c if c.pfield is self else c.with_pfield(self)
        elif isinstance(self.base, ExtensionField):
            return self.mono(0) * self.base.promote(c)
        else:
            return c

    def size(self):
        return self.base.size()**self.modulus.degree()

    def characteristic(self):
        return self.base.characteristic()

    def to_bytes(self, p: Polynomial) -> bytes:
        assert isinstance(p, Polynomial), (p, self)
        pad_len = self.modulus.degree() - len(p.coeffs)
        padded = [*p.coeffs, *([self.base.zero()] * pad_len)]
        return b''.join(self.base.to_bytes(c) for c in padded)

    def ext_degree(self):
        return self.modulus.degree() * self.base.ext_degree()

    def el(self, coeffs: Polynomial | list[int] | list[Polynomial]) -> Polynomial:
        """Wrap `coeffs` as a little-endian polynomial over the field."""
        if isinstance(coeffs, Polynomial):
            assert coeffs.cfield is self.base, (coeffs, coeffs.cfield, self)
            return coeffs if coeffs.pfield is self else Polynomial(coeffs.coeffs, coeffs.cfield, self)
        else:
            assert isinstance(coeffs, list), (coeffs, self)
            assert isinstance(coeffs[0], (int, Polynomial)), (coeffs, self)
            if isinstance(coeffs[0], Polynomial):
                assert coeffs[0].pfield is self.base, f"{coeffs[0].pfield} != {self.base}"
            return Polynomial([self.base.el(a) for a in coeffs], self.base, self).reduce()

    def pol(self, coeffs: list[Polynomial]) -> Polynomial:
        return Polynomial(coeffs, self, None)

    def zero(self) -> int:
        return self.el([self.base.zero()])

    def one(self) -> int:
        return self.el([self.base.one()])

    def mono(self, degree: int) -> int:
        return self.el([self.base.zero()] * degree + [self.base.one()])

    def monoup(self, degree: int) -> int:
        return self.pol([self.zero()] * degree + [self.one()])

    def invert(self, a):
        if isinstance(a, int):
            return modinv(a, self.characteristic())
        elif a.pfield is not self:
            return self.invert(self.promote(a))
        assert isinstance(a, Polynomial), (a, self)
        assert a.pfield is self, (a, self)
        return a.inv()

    def __repr__(self):
        return f"ExtField(mod={self.modulus}, base={self.base})"


class Polynomial:
    def __init__(self, coeffs: list[int] | list[Polynomial], cfield: PrimeField | ExtensionField, pfield: None | ExtensionField):
        assert isinstance(coeffs, list)
        assert isinstance(cfield, (PrimeField, ExtensionField))
        assert pfield is None or isinstance(pfield, ExtensionField)
        self.coeffs = coeffs  # Little-endian order
        self.cfield = cfield  # Field of coefficients
        self.pfield = pfield  # Field containing this polynomial

    def with_pfield(self, pfield: ExtensionField) -> Polynomial:
        return Polynomial(
            [c.with_pfield(pfield.base) if isinstance(c, Polynomial) else c for c in self.coeffs],
            pfield.base,
            pfield
        )

    def without_modulus(self) -> Polynomial:
        return self.with_pfield(self.pfield.without_modulus())

    def untower(self) -> Polynomial:
        if isinstance(self.cfield, PrimeField):
            return self.with_pfield(ExtensionField(self.cfield, None))
        else:
            x = self.without_modulus()
            return x.eval(self.cfield.modulus.with_pfield(x.cfield)).with_pfield(self.cfield).untower()

    def sibl(self, coeffs: list[int] | list[Polynomial]) -> Polynomial:
        return Polynomial(coeffs, self.cfield, self.pfield)

    def to_bytes(self) -> bytes:
        return self.pfield.to_bytes(self)

    def degree(self) -> int:
        return max((i for i, cb in enumerate(self.coeffs) if cb != 0), default=0)

    def invertible(self) -> bool:
        return self.pfield is not None and self.pfield.modulus is not None and all(isinstance(c, int) or c.invertible() for c in self.coeffs)

    def reduce(self) -> Polynomial:
        if self.pfield is None or self.pfield.modulus is None:
            return self.trunc()
        else:
            deg = self.degree()
            degm = self.pfield.modulus.degree()
            if deg >= degm:
                return (self % self.pfield.modulus).trunc()
            else:
                return self.trunc()

    def trunc(self) -> int:
        return self.sibl(self.coeffs[:(self.degree()+1)])

    def eval(self, x: int | Polynomial | PointAffine) -> int | Polynomial:
        if isinstance(x, (int, Polynomial)):
            return sum(c * x**i for i, c in enumerate(self.coeffs))
        assert isinstance(x, PointAffine)
        return self.eval(x.y).eval(x.x)

    def gcd(self, b: Polynomial) -> Polynomial:
        if b == 0:
            return self
        else:
            q, r = divmod(self, b)
            if q == 0:
                return self.pfield.one()
            return b.gcd(r)

    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
    def div_euclid(self, b: Polynomial) -> (Polynomial, Polynomial, Polynomial):
        """Compute `(s, t, gcd)` such that `self*s + b*t = gcd`."""
        assert self.pfield is not None, self

        (old_r, r) = (self, b)
        (old_s, s) = (self.pfield.one(), self.pfield.zero())
        (old_t, t) = (self.pfield.zero(), self.pfield.one())

        while r != 0:
            quotient, rem = divmod(old_r, r)
            (old_r, r) = (r, rem)
            (old_s, s) = (s, old_s - quotient * s)
            (old_t, t) = (t, old_t - quotient * t)

        return old_s, old_t, old_r

    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Simple_algebraic_field_extensions
    def inv(self) -> Polynomial:
        """Compute the multiplicative inverse of `a` in the enclosing polynomial field."""
        assert self.pfield is not None, (self, self.cfield)
        assert self.invertible(), (self, self.pfield)
        s, _, gcd = self.div_euclid(self.pfield.modulus)

        if gcd.degree() > 0:
            raise ValueError("Either p is not irreducible or a is a multiple of p")

        return s * self.cfield.invert(gcd.coeffs[0])

    def __eq__(self, o):
        if isinstance(o, int):
            return self.coeffs[0] == o and all (c == 0 for c in self.coeffs[1:])

        assert isinstance(o, Polynomial), f'self: {self}, o: {o}'
        assert self.cfield is o.cfield
        return self.coeffs == o.coeffs

    def __hash__(self):
        return hash((tuple(self.coeffs), self.cfield, self.pfield))

    def __repr__(self):
        # comps_hex = ", ".join([f"0x{int.to_bytes(c, self.cfield.coord_len, 'big').hex()}" for c in self.coeffs])
        comps_dec = ", ".join(str(c) for c in self.coeffs)
        comps = comps_dec
        return f"F[{comps}]"

    def __neg__(self):
        return self.sibl([self.cfield.el(-a) for a in self.coeffs]).reduce()

    def __add__(self, o):
        if isinstance(o, int) or o.pfield is self.cfield:
            return self + self.sibl([o])
        elif o.cfield is not self.cfield:
            return o.pfield.promote(self) + self.pfield.promote(o)

        assert isinstance(o, Polynomial), f'self: {self}, o: {o}'
        assert self.cfield is o.cfield
        return self.sibl([self.cfield.el(a+b) for a, b in zip_longest(self.coeffs, o.coeffs, fillvalue=self.cfield.zero())]).reduce()

    def __sub__(self, o):
        return self + (-o)

    def __mul__(self, o):
        if isinstance(o, Rational):
            return o * self
        elif isinstance(o, int) or o.pfield is self.cfield:
            return self.sibl([self.cfield.el(a * o) for a in self.coeffs]).reduce()
        elif o.cfield is self.pfield:
            return o * self
        elif o.cfield is not self.cfield:
            return o.pfield.promote(self) * self.pfield.promote(o)

        assert o.cfield is self.cfield, (self, self.cfield, o, o.cfield)

        prod = self.sibl([0] * (len(self.coeffs) + len(o.coeffs) + 1))
        for i, c in enumerate(o.coeffs):
            p = self.sibl([0]*i + self.coeffs) * c
            prod += p
            # print()
            # print("i\t", i)
            # print("c\t", c)
            # print("p\t", p)
            # print("prod\t", prod)

        return prod

    def __truediv__(self, o):
        if isinstance(o, int):
            return self.pfield.promote(o) / self
        elif o.invertible():
            return self * o.inv()
        else:
            return Rational(self, o)

    def __mod__(self, o):
        _, r = divmod(self, o)
        return r

    def __divmod__(self, b: int | Polynomial) -> (Polynomial, Polynomial):
        """Compute `(quotient, remainder)` of `self` divided by `b`."""
        assert isinstance(b, (int, Polynomial)), (self, b)
        if isinstance(b, int):
            return divmod(self, self.pfield.mono(0) * b)
        elif self.cfield is not b.cfield:
            return divmod(b.pfield.promote(self), self.pfield.promote(b))

        if b.degree() > self.degree():
            return self.sibl([self.cfield.zero()]), self

        a = self

        quot = Polynomial([self.cfield.zero()] * len(a.coeffs), self.cfield, self.pfield)
        deg_b = b.degree()

        while a.degree() >= deg_b and a != 0:
            deg_a = a.degree()

            # print()
            # print("a\t", a)
            # print("b\t", b)
            # print("deg_a\t", deg_a)
            # print("deg_b\t", deg_b)

            deg_quot = deg_a - deg_b
            d = Polynomial([0] * deg_quot + b.coeffs, self.cfield, None)
            if isinstance(b.cfield, ExtensionField) and b.cfield.modulus is None:
                q, r = divmod(a.coeffs[deg_a], b.coeffs[deg_b])
            else:
                q = a.coeffs[deg_a] * b.cfield.invert(b.coeffs[deg_b])
                r = 0
            quot.coeffs[deg_quot] += q
            if isinstance(self.cfield, PrimeField):
                quot.coeffs[deg_quot] %= self.cfield.q
            a -= d * q

            if r != 0:
                break

            # print("deg_quot\t", deg_quot)
            # print("d\t", d)
            # print("q\t", q)
            # print("quot\t", quot)

        return quot.reduce(), a

    def __lshift__(self, i):
        return self.sibl([self.cfield.zero()]*i + self.coeffs)

    def __rshift__(self, i):
        return self.sibl(self.coeffs[i:] or [self.cfield.zero()])

    def __radd__(self, o):
        return self + o

    def __rsub__(self, o):
        return (-self) + o

    def __rmul__(self, o):
        return self * o

    def __rtruediv__(self, o):
        return o * self.inv()

    def __pow__(self, e):
        if e < 0:
            return self.inv()**(-e)

        squared = self
        result = self.pfield.one()

        while e > 0:
            if e % 2 != 0:
                result *= squared
            squared = squared * squared
            e >>= 1

        return result


class Rational:
    def __init__(self, n: Polynomial, d: Polynomial):
        assert isinstance(n, Polynomial)
        assert isinstance(d, Polynomial)
        n, d = (d.pfield.promote(n), n.pfield.promote(d))
        self.n = n  # Nominator
        self.d = d  # Denominator

    def inv(self) -> Rational:
        assert self.d != 0
        return Rational(self.d, self.n)

    def invertible(self) -> bool:
        return True

    def eval(self, P: PointAffine) -> int | Polynomial:
        assert isinstance(P, PointAffine)
        return self.n.eval(P) / self.d.eval(P)

    def __eq__(self, o):
        if isinstance(o, Rational):
            return self.n * o.d == o.n * self.d
        else:
            return self.d == 1 and self.n == o

    def __hash__(self):
        return hash((self.n, self.d))

    def __repr__(self):
        return f"R[{self.n} / {self.d}]"

    def __neg__(self):
        return Rational(-self.n, self.d)

    def __add__(self, o):
        if isinstance(o, Rational):
            return Rational(self.n * o.d + o.n * self.d, self.d * o.d)
        else:
            return Rational(self.n + self.d * o, self.d)

    def __sub__(self, o):
        return self + (-o)

    def __mul__(self, o) -> Rational | Polynomial:
        if isinstance(o, Rational):
            n = self.n * o.n
            d = self.d * o.d

            q, r = divmod(n, o.d)
            if r == 0:
                n, d = (q, self.d)

            q, r = divmod(n, self.d)
            if r == 0:
                n, d = (q, o.d)

            return Rational(n, d)

        else:
            n = self.n * o
            q, r = divmod(n, self.d)
            if r == 0:
                return q
            else:
                return Rational(n, self.d)

    def __truediv__(self, o):
        if isinstance(o, Rational):
            return self * o.inv()
        else:
            q, r = divmod(self.n, o)
            if r == 0:
                return Rational(q, self.d)
            elif o.invertible():
                return self * self.pfield.invert(o)
            else:
                return Rational(self.n, self.d * o)

    def __mod__(self, o):
        _, r = divmod(self, o)
        return r

    def __divmod__(self, o: int | Polynomial | Rational) -> (Rational, Rational):
        if isinstance(o, Rational):
            q, r = divmod(self.n * o.d, o.n * self.d)
            d = self.d * o.d
            return Rational(q, d), Rational(r, d)
        else:
            return divmod(self, Rational(o, o.pfield.one()))

    def __pow__(self, e):
        return Rational(self.n**e, self.d**e)


class Curve:
    def __init__(self, field, a, b, n, h, generator):
        self.field = field
        self.a = a
        self.b = b
        self.n = n
        self.h = h
        self.scalar_len = math.ceil(math.log2(n) / 8)
        (gx, gy) = generator
        # print(generator)
        self.generator = PointAffine(field.el(gx), field.el(gy), self).to_projective()

    def twist(self, generator=None) -> (Curve, Callable[[PointAffine], PointAffine]):
        crv = self
        def twist_xy(x: Polynomial, y: Polynomial) -> (int | Polynomial, int | Polynomial):
            return (crv.field.mono(2) * x, crv.field.mono(3) * y)

        def untwist_xy(xp: int | Polynomial, yp: int | Polynomial) -> (Polynomial, Polynomial):
            return (xp / crv.field.mono(2), yp / crv.field.mono(3))

        g = crv.generator.to_affine()
        tcrv = Curve(
            field=crv.field,
            a=crv.a * crv.field.mono(4),
            b=crv.b * crv.field.mono(6),
            n=crv.n,
            h=crv.h,
            generator=generator or twist_xy(g.x, g.y),
        )

        def twist_point(p: PointAffine) -> PointAffine:
            assert isinstance(p, PointAffine)
            if p.is_zero():
                return tcrv.zero()
            return PointAffine(*twist_xy(p.x, p.y), tcrv)

        def untwist_point(pp: PointAffine) -> PointAffine:
            assert isinstance(pp, PointAffine)
            if pp.is_zero():
                return crv.zero()
            return PointAffine(*untwist_xy(pp.x, pp.y), crv)

        return (tcrv, twist_point, untwist_point)

    def zero(self):
        return PointAffine(0, 0, self).zero().to_projective()

    # def pow(self, b, e):
    #     return modpow(b, e, self.p)

    # def sqrt(self, a):
    #     return modsqrt(a, self.p)

    # def find_y(self, x):
    #     y = self.sqrt(self.pow(x, 3) + self.a * x + self.b)
    #     if y is not None:
    #         if self.p - y < y:
    #             return self.p - y
    #         else:
    #             return y

    def insecure_random_scalar(self):
        return int.from_bytes(os.urandom(self.scalar_len * 2), 'big') % self.n

    def insecure_random_point(self):
        return self.generator * self.insecure_random_scalar()

    # def find_bls_generator(self):
    #     for x in range(0, 100):
    #         y = self.find_y(x)
    #         if y is not None:
    #             g = PointAffine(x, y, self) * self.h
    #             if g.is_valid_nonzero():
    #                 return g.to_projective()

    def scalar_to_big_endian(self, x):
        return int.to_bytes(x, self.scalar_len, 'big')

    def point_from_cose(self, cose):
        assert cose[1] == 2  # kty: EC2
        assert cose[-1] == -65601  # crv: BLS12-381 (placeholder value)
        assert len(cose[-2]) == self.coord_len
        assert len(cose[-3]) == self.coord_len
        x = int.from_bytes(cose[-2], 'big')
        y = int.from_bytes(cose[-3], 'big')
        return PointAffine(x, y, self).to_projective()

    def point_from_sec1_uncompressed(self, sec1: bytes):
        assert sec1[0] == 0x04
        x = int.from_bytes(sec1[1:(1+self.coord_len)], 'big')
        y = int.from_bytes(sec1[(1+self.coord_len):(1+self.coord_len*2)], 'big')
        return PointAffine(x, y, self).to_projective()


class PointAffine:
    def __init__(self, x, y, crv, is_zero=False):
        self._is_zero = is_zero
        self.x = x
        self.y = y
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointAffine) or isinstance(o, PointProjective), f'self: {self}, o: {o}'
        assert self.crv is o.crv
        if isinstance(o, PointProjective):
            return self.to_projective() == o
        if self.is_zero() and o.is_zero():
            return True
        elif self.is_zero() != o.is_zero():
            return False
        else:
            return self.x == o.x and self.y == o.y

    def __hash__(self):
        return hash((self._is_zero, self.x, self.y, self.crv))

    def __repr__(self):
        if self.is_zero():
            return "(ZERO)"
        else:
            # l = math.ceil(math.log2(self.crv.field.q)/8)
            # return f"(0x{int.to_bytes(self.x, l, 'big').hex()}, 0x{int.to_bytes(self.y, l, 'big').hex()})"
            return f"({self.x}, {self.y})"

    def zero(self):
        return PointAffine(0, 0, self.crv, is_zero=True)

    def is_zero(self):
        return self._is_zero

    def to_projective(self):
        q = PointProjective(self.x, self.y, 1, self.crv)
        if self.is_zero():
            return q.zero()
        else:
            return q

    def trace_map(self):
        q = self.crv.field.characteristic()
        k = self.crv.field.ext_degree()
        return sum(
            (PointAffine(self.x**(q**i), self.y**(q**i), self.crv) for i in range(k)),
            start=self.crv.zero().to_affine()
        )

    def anti_trace_map(self):
        k = self.crv.field.ext_degree()
        return self * k - self.trace_map()

    def coordinate_to_big_endian(self, x):
        return int.to_bytes(x, self.crv.field.coord_len, 'big')

    def to_big_endian_coordinates(self):
        return (self.coordinate_to_big_endian(self.x), self.coordinate_to_big_endian(self.y))

    def to_sec1_uncompressed(self):
        x, y = self.to_big_endian_coordinates()
        return bytes([0x04]) + x + y

    def is_valid_nonzero(self):
        return not self.is_zero() and self.y**2 == self.x**3 + self.crv.a * self.x + self.crv.b

    def __neg__(self):
        return PointAffine(self.x, -self.y, self.crv, is_zero=self.is_zero())

    def __add__(self, q):
        assert isinstance(q, PointAffine), f'p: {self}, q: {q}'
        assert self.crv is q.crv
        p = self

        if self.is_zero():
            return q

        elif q.is_zero():
            return p

        else:
            if p.x == q.x:
                if p.y == -q.y:
                    return self.zero()
                else:
                    kn = 3 * p.x**2 + self.crv.a
                    kd = 2 * p.y
                    k = kn * self.crv.field.invert(kd)
            else:
                kn = q.y - p.y
                kd = q.x - p.x
                k = kn * self.crv.field.invert(kd)

            xr = k**2 - p.x - q.x
            yr = k * (p.x - xr) - p.y
            return PointAffine(self.crv.field.el(xr), self.crv.field.el(yr), self.crv)

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
            return ((self.x * o.z == o.x * self.z)
                    and (self.y * o.z == o.y * self.z))

    def __hash__(self):
        return hash(self.to_affine())

    def __repr__(self):
        if self.is_zero():
            return "(ZERO)"
        else:
            # l = math.ceil(math.log2(self.crv.field.q)/8)
            # return f"P(0x{int.to_bytes(self.x, l, 'big').hex()}, 0x{int.to_bytes(self.y, l, 'big').hex()}, 0x{int.to_bytes(self.z, l, 'big').hex()})"
            return f"P({self.x}, {self.y}, {self.z})"

    def zero(self):
        return PointProjective(0, 1, 0, self.crv)

    def to_affine(self):
        zinv = self.crv.field.invert(self.z)
        p = PointAffine(self.x * zinv, self.y * zinv, self.crv)
        return p.zero() if self.is_zero() else p

    def is_zero(self):
        return self.z == 0

    def is_valid_nonzero(self):
        if self.is_zero():
            return False
        else:
            z2 = self.z**2
            z3 = self.z**3
            lhs = self.y**2 * self.z
            rhs = self.x**3 + self.crv.a * self.x * z2 + self.crv.b * z3
            return lhs == rhs

    def __neg__(self):
        return PointProjective(self.x, -self.y, self.z, self.crv)

    def __add__(self, q):
        assert isinstance(q, PointProjective)
        assert self.crv is q.crv
        p = self

        if self.is_zero():
            return q

        elif q.is_zero():
            return p

        else:
            if p.x * q.z == q.x * p.z:
                if p.y * q.z == -q.y * p.z:
                    return self.zero()
                else:
                    yp2 = p.y**2
                    zp2 = p.z**2
                    k = 3 * p.x**2 + self.crv.a * zp2
                    zr1 = 4 * zp2 * yp2
                    xr1 = k**2 - 8 * p.x * yp2 * p.z
                    yr = (2 * p.y) * k * (p.x * zr1 - xr1 * p.z) - 4 * p.z * zr1 * p.y**3

                    zr2 = 4 * zp2 * yp2
                    zr = zr1 * zr2
                    xr = xr1 * zr2
                    return PointProjective(xr, yr, zr, self.crv)
            else:
                pxqz = p.x * q.z
                pyqz = p.y * q.z
                qypz = q.y * p.z
                qxpz = q.x * p.z
                pzqz = p.z * q.z
                xpzqmxqzp = pxqz - qxpz
                xpzqmxqzp2 = xpzqmxqzp**2
                ypzqmyqzp = pyqz - qypz
                ypzqmyqzp2 = ypzqmyqzp**2
                pzqz_xpzqmxqzp2 = pzqz * xpzqmxqzp2
                k = pzqz * ypzqmyqzp2 - xpzqmxqzp2 * (pxqz + qxpz)
                xr = xpzqmxqzp * k
                yr = pzqz_xpzqmxqzp2 * (q.x*p.y - p.x*q.y) - ypzqmyqzp * k
                zr = pzqz_xpzqmxqzp2 * xpzqmxqzp
                return PointProjective(xr, yr, zr, self.crv)

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

    def verify_ecsdsa_sha256(self, signature: bytes, message: bytes):
        assert len(signature) == self.crv.scalar_len * 2
        s = int.from_bytes(signature[:self.crv.scalar_len], 'big')
        e = int.from_bytes(signature[self.crv.scalar_len:], 'big')
        rv = self.crv.generator * s + self * e
        rv_bin = rv.to_affine().to_sec1_uncompressed()
        ev_bin = sha256(rv_bin + message)
        ev = int.from_bytes(ev_bin, 'big') % self.crv.n
        if ev == e:
            return
        raise InvalidSignature()

    def verify_ecsdsa_sha256_split_bbs(self, signature: bytes, message: bytes, t2prime: Optional[any]):
        '''Verification of device binding signature based on "Split BBS" proposal by Cordian Daniluk and Anja Lehmann'''
        assert len(signature) == self.crv.scalar_len * 3
        if t2prime is None:
            t2prime = self.crv.generator * 0
        s = int.from_bytes(signature[:self.crv.scalar_len], 'big')
        c = signature[self.crv.scalar_len:self.crv.scalar_len*2]
        c_int = int.from_bytes(c, 'big') % self.crv.n
        n = signature[self.crv.scalar_len*2:]
        t_dsk = self.crv.generator * s + self * c_int
        t2 = t_dsk + t2prime
        t2_bin = t2.to_sec1_uncompressed()
        cv = sha256(n + t2_bin + message)
        cv_int = int.from_bytes(cv, 'big') % self.crv.n
        if cv_int == c_int:
            return
        raise InvalidSignature()


def split_bbs_sign(
        crv: Curve,
        sk: int,
        dpk: PointProjective,
        attrs: list[int],
        attr_generators: list[PointProjective],
) -> tuple[PointProjective, int]:
    g1 = crv.generator
    e = crv.insecure_random_scalar()
    A = (g1 + dpk + sum((hi * ai for hi, ai in zip(attr_generators, attrs)), crv.zero())) * modinv((e + sk) % crv.n, crv.n)
    if A.is_zero():
        raise ValueError("A was zero")
    return A, e


def begin_split_bbs_proof(
        A: PointProjective,
        e: int,
        dpk: PointProjective,
        attrs: list[int],
        attr_generators: list[PointProjective],
        pk: PointProjective,
        disclose_idx: set[int],
        ctx: bytes,
):
    '''First part of "Split BBS.ZKProve" based on proposal by Cordian Daniluk and Anja Lehmann'''
    assert len(attrs) == len(attr_generators)
    assert all(d >= 0 and d < len(attrs) for d in disclose_idx)
    assert 0 not in disclose_idx

    crv = CRV_BLS
    g1 = crv.generator
    idx = list(range(len(attrs)))
    undisclosed_idx = set(idx) - disclose_idx
    undisclosed_idx_nonzero = undisclosed_idx - set([0])

    r1 = crv.insecure_random_scalar()
    r2 = crv.insecure_random_scalar()
    r2inv = modinv(r2, crv.n)
    Abar = A * (r1 * r2inv)
    D = (g1 + dpk + sum((hi * ai for hi, ai in zip(attr_generators[1:], attrs[1:])), crv.zero())) * r2inv
    Bbar = (D * r1) + (Abar * (-e))
    rr1 = crv.insecure_random_scalar()
    rr2 = crv.insecure_random_scalar()
    re = crv.insecure_random_scalar()
    rai = [crv.insecure_random_scalar() if i in undisclosed_idx_nonzero else None for i in idx]
    t1 = (D * rr1) + (Abar * re)
    t2prime = D * rr2 + sum((attr_generators[i] * rai[i] for i in undisclosed_idx_nonzero), crv.zero())
    c_host = sha256(cbor.encode([
        Abar.to_sec1_uncompressed(),
        Bbar.to_sec1_uncompressed(),
        D.to_sec1_uncompressed(),
        g1.to_sec1_uncompressed(),
        g1.to_sec1_uncompressed(),
        [gen.to_sec1_uncompressed() for gen in attr_generators],
        len(attr_generators) + 1,
        t1.to_sec1_uncompressed(),
        [crv.scalar_to_big_endian(attrs[i]) for i in sorted(disclose_idx)],
        sorted(disclose_idx),
        pk.to_sec1_uncompressed(),
    ]))

    return c_host, rr1, r1, rr2, r2, re, e, rai, attrs, disclose_idx, Abar, Bbar, D, t2prime, dpk


def finish_split_bbs_proof(
        c_host: bytes,
        rr1: int, r1: int, rr2: int, r2: int, re: int, e: int, rai: list[int],
        attrs: list[int],
        disclose_idx: set[int],
        Abar: PointProjective,
        Bbar: PointProjective,
        D: PointProjective,
        sa0: int,
        c: bytes,
        n: bytes,
        t2prime: PointProjective,
        dpk: PointProjective,
):
    '''Second part of "Split BBS.ZKProve" based on proposal by Cordian Daniluk and Anja Lehmann'''
    assert len(attrs) == len(rai)
    assert 0 not in disclose_idx

    crv = CRV_BLS
    g1 = crv.generator
    idx = list(range(len(attrs)))
    undisclosed_idx = set(range(len(attrs))) - disclose_idx
    undisclosed_idx_nonzero = undisclosed_idx - set([0])

    c = int.from_bytes(c, 'big') % crv.n
    t_dsk = g1 * sa0 + dpk * c
    t2 = t_dsk + t2prime
    t2_bin = t2.to_sec1_uncompressed()
    c2 = sha256(n + t2_bin + c_host)
    c2_int = int.from_bytes(c2, 'big') % crv.n
    assert c2_int == c

    sr1 = (rr1 + c * r1) % crv.n
    sr2 = (rr2 + c * r2) % crv.n
    se = (re - c * e) % crv.n
    sai = [
        sa0,
        *[rai[i] - c * attrs[i] if i in undisclosed_idx_nonzero else None for i in idx[1:]]
    ]

    return Abar, Bbar, D, c, sr1, sr2, se, sai, n

def verify_split_bbs_proof(
        Abar: PointProjective,
        Bbar: PointProjective,
        D: PointProjective,
        c: int,
        sr1: int,
        sr2: int,
        se: int,
        sai: list[int],
        pk: PointProjective,
        disclosed_idx: set[int],
        attrs: list[int | None],
        attr_generators: list[PointProjective],
        ctx: bytes,
        n: bytes,
):
    assert len(attrs) == len(attr_generators)
    assert len(sai) == len(attr_generators)
    assert all(d >= 0 and d < len(attr_generators) for d in disclosed_idx)

    crv = CRV_BLS
    g1 = crv.generator
    undisclosed_idx = set(range(len(attr_generators))) - disclosed_idx

    t1 = D * sr1 + Abar * se + Bbar * (-c)
    t2 = (
        D * sr2 + sum((attr_generators[i] * sai[i] for i in undisclosed_idx), crv.zero())
        + (g1 + sum((attr_generators[i] * attrs[i] for i in disclosed_idx), crv.zero())) * (-c))

    c_host = sha256(cbor.encode([
        Abar.to_sec1_uncompressed(),
        Bbar.to_sec1_uncompressed(),
        D.to_sec1_uncompressed(),
        g1.to_sec1_uncompressed(),
        g1.to_sec1_uncompressed(),
        [gen.to_sec1_uncompressed() for gen in attr_generators],
        len(attr_generators) + 1,
        t1.to_sec1_uncompressed(),
        [crv.scalar_to_big_endian(attrs[i]) for i in sorted(disclosed_idx)],
        sorted(disclosed_idx),
        pk.to_sec1_uncompressed(),
    ]))
    cv = sha256(n + t2.to_sec1_uncompressed() + c_host)
    cv_int = int.from_bytes(cv, 'big') % crv.n
    return cv_int == c


def line_function(Q1: PointAffine, Q2: PointAffine, P: PointAffine):
    assert isinstance(Q1, PointAffine)
    assert isinstance(Q2, PointAffine)
    assert isinstance(P, PointAffine)
    assert Q1.crv is Q2.crv
    # assert Q1.crv.field.q == P.crv.field.q

    (x1, y1) = (Q1.x, Q1.y)
    (x2, y2) = (Q2.x, Q2.y)
    (x, y) = (P.x, P.y)
    if Q1 == Q2:
        lf = (3 * x1**2) / (2 * y1)
    elif Q1 == -Q2:
        return x - x1
    else:
        lf = (y2 - y1) / (x2 - x1)
    return lf * (x - x1) + y1 - y


def lambda_nu(P: PointAffine, Q: PointAffine) -> (int | Polynomial, int | Polynomial):
    assert isinstance(P, PointAffine)
    assert isinstance(Q, PointAffine)
    assert (not P.is_zero()) and (not Q.is_zero())
    if P == Q:
        lmbd = (3*(P.x**2) + P.crv.a) * P.crv.field.invert((2*P.y))
        nu = P.y - lmbd * P.x
    else:
        lmbd = (Q.y - P.y) * P.crv.field.invert(Q.x - P.x)
        nu = P.y - lmbd * P.x
    return P.crv.field.el(lmbd), P.crv.field.el(nu)


def intersect_fn(P: PointAffine, Q: PointAffine, yfield: ExtensionField) -> Polynomial:
    lmbd, nu = lambda_nu(P, Q)
    xfield = yfield.base
    return yfield.mono(1) - (lmbd * xfield.mono(1) + nu * xfield.mono(0)) * yfield.mono(0)


def vertical_fn(P: PointAffine, yfield: ExtensionField) -> Polynomial:
    xfield = yfield.base
    return xfield.mono(1) - P.x


def slow_frp(P: PointAffine) -> Polynomial:
    assert isinstance(P, PointAffine)

    r = P.crv.n
    fx = ExtensionField(P.crv.field, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + P.crv.a * fx.mono(1) + P.crv.b), 0, 1])

    f = fx.mono(0)
    for i in range(1, r-1):
        lf = intersect_fn(P, P*i, fy)
        vf = fy.promote(vertical_fn(P*(i+1), fy))
        f = f * lf / vf
    vf = fy.promote(vertical_fn(P, fy))
    f *= vf
    return f


def weil_pairing(P: PointAffine, Q: PointAffine) -> Polynomial:
    assert isinstance(P, PointAffine)
    assert isinstance(Q, PointAffine)
    assert P.crv is Q.crv

    r = P.crv.n
    frp = slow_frp(P)
    frq = slow_frp(Q)
    R = Q*2
    # S = P*2
    f = frp / ((intersect_fn(P, R, frp.pfield) / vertical_fn(P+R, frp.pfield))**r)
    # g = frq / ((intersect_fn(Q, S, frq.pfield) / vertical_fn(Q+S, frq.pfield))**r)
    # return f.eval(Q+S) * g.eval(R) / (f.eval(S) * g.eval(P + R))
    return f.eval(Q) * frq.eval(R) / (frq.eval(P + R))


def rtate_pairing(P: PointAffine, Q: PointAffine) -> Polynomial:
    assert isinstance(P, PointAffine)
    assert isinstance(Q, PointAffine)
    assert P.crv is Q.crv

    q = P.crv.field.characteristic()
    k = P.crv.field.ext_degree()
    r = P.crv.n
    f = slow_frp(P)
    R = P*2
    return (f.eval(Q+R)/f.eval(R))**((q**k - 1)//r)


def miller_eval(P: PointAffine, DQ: (list[PointAffine], list[PointAffine])) -> Polynomial:
    DQn, DQd = DQ
    assert isinstance(P, PointAffine)
    assert isinstance(DQn, list)
    assert all(isinstance(n, PointAffine) for n in DQn)
    assert isinstance(DQd, list)
    assert all(isinstance(d, PointAffine) for d in DQd)
    assert all(P.crv is n.crv for n in DQn)
    assert all(P.crv is d.crv for d in DQd)

    r = P.crv.n
    fx = ExtensionField(P.crv.field, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + P.crv.a * fx.mono(1) + P.crv.b), 0, 1])
    n = math.ceil(math.log2(r))

    R = P
    f = 1
    for i in reversed(range(n - 2 + 1)):
        assert not R.is_zero(), (i, r, P, DQ)
        # print(i, R)

        R2 = R * 2
        lrr = intersect_fn(R, R, fy)
        v2r = fy.promote(vertical_fn(R2, fy))
        lv = lrr / v2r
        R = R2
        updn = product(lv.eval(n) for n in DQn)
        updd = product(lv.eval(d) for d in DQd)
        upd = updn / updd
        f = f**2 * upd
        # print(f"{i}\tlv: {lv}  \tupdn: {updn}  \tupdd: {updd}  \tupd: {upd}  \tf:{f}")

        if (r >> i) % 2 == 1:
            # print(i, R)
            RP = R + P
            if R == -P:
                lv = fy.promote(vertical_fn(P, fy))
            else:
                lrp = intersect_fn(R, P, fy)
                vrp = fy.promote(vertical_fn(RP, fy))
                lv = lrp / vrp
            R = RP
            updn = product(lv.eval(n) for n in DQn)
            updd = product(lv.eval(d) for d in DQd)
            upd = updn / updd
            f = f * upd
            # print(f"{i}\tlv: {lv}  \tupdn: {updn}  \tupdd: {updd}  \tupd: {upd}  \tf:{f}")

    return f


def miller_rtate_pairing(P: PointAffine, Q: PointAffine) -> Polynomial:
    q = P.crv.field.characteristic()
    k = P.crv.field.ext_degree()
    r = P.crv.n
    return miller_eval(P, ([Q*2], [Q]))**((q**k)//r)


def miller_weil_pairing(P: PointAffine, Q: PointAffine) -> Polynomial:
    r = P.crv.n
    fx = ExtensionField(P.crv.field, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + P.crv.a * fx.mono(1) + P.crv.b), 0, 1])

    frp_dq = miller_eval(P, ([Q*2], [Q]))
    frq_dp = miller_eval(Q, ([P*2], [P]))
    R = P
    S = Q
    lpr = intersect_fn(P, R, fy)
    vpr = vertical_fn(P + R, fy)
    lqs = intersect_fn(Q, S, fy)
    vqs = vertical_fn(Q + S, fy)
    f_div = lpr / vpr
    g_div = lqs / vqs
    wr_denominator = (f_div.eval(Q + S) / f_div.eval(S))**r * frq_dp / (g_div.eval(P + R) / g_div.eval(R))**r
    return frp_dq / wr_denominator


def opt_ate_pairing(P: PointProjective, Q: PointProjective, c: list[-1 | 0 | 1], t: int, k: int, untwist) -> Polynomial:
    assert isinstance(P, PointProjective)
    assert isinstance(Q, PointProjective)
    assert all(ci in [-1, 0, 1] for ci in c), c
    assert sum(ci * 2**i for i, ci in enumerate(c)) == t
    assert P.crv.n == Q.crv.n
    p = P.crv.field.characteristic()
    r = P.crv.n

    Paff = P.to_affine()
    Qaff = Q.to_affine()

    f = 1
    T = Q
    if c[-1] == -1:
        T = -T
    for i in reversed(range(len(c))):
        print(i)
        f = f**2 * line_function(T.to_affine(), T.to_affine(), Paff)
        T = T + T
        if c[i] == 1:
            f = f * line_function(T.to_affine(), Qaff, Paff)
            T = T + Q
        elif c[i] == -1:
            f = f * line_function(T.to_affine(), -Qaff, Paff)
            T = T - Q
    quot, rem = divmod(p**k - 1, r)
    print(p, r, p**k - 1, quot, rem)
    assert rem == 0
    f = f**quot
    return f


t = -2**63 - 2**62 - 2**60 - 2**57 - 2**48 - 2**16
p = (t - 1)**2 * (t**4 - t**2 + 1) // 3 + t
r = t**4 - t**2 + 1
assert p == 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
assert r == 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
gfp = PrimeField(p)
gfp2 = ExtensionField(gfp, [1, 0, 1])
gfp6 = ExtensionField(gfp2, [-gfp2.mono(1) - gfp2.mono(0), gfp2.zero(), gfp2.zero(), gfp2.one()])
gfp12 = ExtensionField(gfp6, [-gfp6.mono(1), gfp6.zero(), gfp6.one()])
CRV_BLS = Curve(
    field=gfp12,
    a=gfp12.zero(),
    b=4 * gfp12.one(),
    n=r,
    h=0x396c8c005555e1568c00aaab0000aaab,
    generator=(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb * gfp12.one(),
               0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1 * gfp12.one())
)
# gfp2 = ExtensionField(gfp, [1, 0, 1])
# CRV_BLS_G2 = Curve(
#     gfp2,
#     0,
#     gfp2.el([4, 4]),
#     r,
#     0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5,
#     (
#         [
#             0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
#             0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
#         ],
#         [
#             0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801,
#             0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be,
#         ],
#     ),
# )
