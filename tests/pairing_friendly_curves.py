"""
Coding along to formulas and examples from "Pairings for beginners" by Craig Costello
https://static1.squarespace.com/static/5fdbb09f31d71c1227082339/t/5ff394720493bd28278889c6/1609798774687/PairingsForBeginners.pdf
"""

import pytest

from fido2.bls12_381 import *


def test_wikipedia_extended_eucliedean_algorithm():
    """
    Wikipedia polynomial example of Extended Euclidean algorithm
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Example_2
    """
    f = ExtensionField(PrimeField(2), [1, 1, 0, 1, 1, 0, 0, 0, 1])
    x = f.el([1, 1, 0, 0, 1, 0, 1])
    xx = f.one()
    for e in range(f.size() + 1):
        xe = x**e
        assert xe == xx, f"e: {e}, x^e: {xe}, x*...*x: {xx}"
        assert ((xe) * (x ** (-e))) == 1, (
            f"e: {e}, x^e: {xe}, x^(-e): {x ** (-e)}, x^e * x^(-e): {xe * (x ** (-e))}"
        )
        assert (xe * xe.inv()) == 1, (
            f"e: {e}, x^e: {xe}, (x^e)^(-1): {xe.inv()}, x^e * (x^e)^(-1): {xe * xe.inv()}"
        )
        xx *= x
    assert x.inv() == f.el([0, 1, 0, 1, 0, 0, 1, 1]), (
        f"{x} != {f.el([0, 1, 0, 1, 0, 0, 1, 1])}"
    )


def test_pfb_ex_4_1_1():
    """
    "Pairings for beginners" example 4.1.1
    """
    q = 11
    r = 3
    h = 4
    k = 2
    f = PrimeField(q)
    fq2 = ExtensionField(f, [1, 0, 1])
    crv = Curve(field=f, a=0, b=4, n=r, h=h, generator=None)
    crv2 = Curve(field=fq2, a=0, b=4, n=r**2, h=h, generator=None)

    points = [
        crv2.zero().to_affine(),
        *[
            p
            for p in [
                PointAffine(fq2.el([x0, x1]), fq2.el([y0, y1]), crv2)
                for x0 in range(q)
                for x1 in range(q)
                for y0 in range(q)
                for y1 in range(q)
            ]
            if p.is_zero() or p.is_valid_nonzero()
        ],
    ]

    r_torsion = [p for p in points if (p * r).is_zero()]
    assert len(r_torsion) == 9
    assert set(
        [
            p
            for p in r_torsion
            if p.is_zero() or (p.x.degree() == 0 and p.y.degree() == 0)
        ]
    ) == set([crv2.zero()] + crv2.points([([0], [2]), ([0], [9])]))

    assert set(r_torsion) == set(
        [crv2.zero()]
        + crv2.points(
            [
                ([0], [2]),
                ([0], [9]),
                ([8], [0, 1]),
                ([8], [0, 10]),
                ([7, 2], [0, 10]),
                ([7, 2], [0, 1]),
                ([7, 9], [0, 10]),
                ([7, 9], [0, 1]),
            ]
        )
    )


def test_pfb_ex_4_1_5():
    """
    "Pairings for beginners" example 4.1.5
    """
    f = ExtensionField(PrimeField(59), [1, 0, 1])

    def phi(p):
        x, y = p
        return (-x, f.el([0, 1]) * y)

    p = (f.el([51, 28]), f.el([49, 25]))
    assert phi(p) == (f.el([8, 31]), f.el([34, 49]))
    assert phi(phi(p)) == (f.el([51, 28]), f.el([10, 34]))
    assert phi(phi(phi(p))) == (f.el([8, 31]), f.el([25, 10]))
    assert p == phi(phi(phi(phi(p))))

    x, y = p

    g = f.el([3, 1])  # Generator of GF(59^2)
    xx = f.one()
    for e in range(f.size() + 1):
        xe = x**e
        assert xe == xx, f"e: {e}, x^e: {xe}, x*...*x: {xx}"
        assert ((xe) * (x ** (-e))) == 1, (
            f"e: {e}, x^e: {xe}, x^(-e): {x ** (-e)}, x^e * x^(-e): {xe * (x ** (-e))}"
        )
        assert (xe * xe.inv()) == 1, (
            f"e: {e}, x^e: {xe}, (x^e)^(-1): {xe.inv()}, x^e * (x^e)^(-1): {xe * xe.inv()}"
        )
        xx *= x
    assert x ** (59**2) == x


def test_pfb_ex_4_3_1():
    """
    "Pairings for beginners" example 4.3.1
    """
    q = 11
    r = 3
    h = 4
    k = 2
    fq = PrimeField(q)
    fq2 = ExtensionField(fq, [1, 0, 1])
    crv = Curve(field=fq, a=0, b=4, n=r, h=h, generator=None)
    crv2 = Curve(field=fq2, a=0, b=4, n=r**2, h=h, generator=None)
    tcrv = Curve(field=fq, a=0, b=-4, n=r, h=h, generator=None)

    def psi_inv(p):
        if p.is_zero():
            return p.crv.zero()
        return PointAffine(-p.x, fq2.mono(1) * p.y, p.crv)

    def psi(p):
        if p.is_zero():
            return p.crv.zero()
        return PointAffine(-p.x, -fq2.mono(1) * p.y, p.crv)

    tcrv2, twistp, untwistp = crv2.twist()

    print(crv2.point([8], [0, 1]))
    print(psi_inv(crv2.point([8], [0, 1])))
    print(crv.point(3, 10))
    assert psi_inv(crv2.point([8], [0, 1])) == crv2.point([3], [10])
    assert psi_inv(crv2.point([8], [0, 10])) == crv2.point([3], [1])


def test_pfb_ex_4_3_2():
    """
    "Pairings for beginners" example 4.3.2
    """
    q = 103
    r = 7
    f = PrimeField(q)
    ef = ExtensionField(f, 2 * f.monoup(0) + f.monoup(6))
    crv = Curve(
        field=ef,
        a=0,
        b=72,
        n=r,
        h=84 // r,
        generator=(35 * ef.mono(4), 42 * ef.mono(3)),
    )
    tcrv, twistp, untwistp = crv.twist(generator=(ef.el([33]), ef.el([19])))

    subgroup = [twistp(crv.generator.to_affine()) * i for i in range(r)]
    assert subgroup == [tcrv.generator * i for i in range(r)]
    assert subgroup == [
        tcrv.zero(),
        tcrv.point([33], [19]),
        tcrv.point([97], [19]),
        tcrv.point([76], [84]),
        tcrv.point([76], [19]),
        tcrv.point([97], [84]),
        tcrv.point([33], [84]),
    ]

    for i in range(crv.n + 1):
        gi = crv.generator * i
        tgi = untwistp(twistp(crv.generator.to_affine()) * i)
        assert gi == tgi, (gi, tgi)


def test_pfb_ex_5_0_1():
    """
    "Pairings for beginners" example 5.0.1
    """
    q = 23
    k = 1
    fq = PrimeField(q)
    crv = Curve(field=fq, a=17, b=6, n=5, h=30 // 5, generator=(0, 0))
    P = PointAffine(fq.el(10), fq.el(7), crv)

    fx = ExtensionField(fq, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + 17 * fx.mono(1) + 6), 0, 1])
    f2p = (fy.mono(1) + (2 * fx.mono(1) + 19)) / (fx.mono(1) + 16)
    f3p = f2p * (fy.mono(1) + (fx.mono(1) + 6)) / (fx.mono(1) + 16)
    f4p = f3p * (fy.mono(1) + (2 * fx.mono(1) + 19)) / (fx.mono(1) + 13)
    f5p = f4p * (fx.mono(1) - 10)
    assert f5p == (fx.mono(1) + 22) * fy.mono(1) + (
        5 * fx.mono(2) + 3 * fx.mono(1) + 5
    ), f5p

    f2p2 = intersect_fn(P, P, fy) / vertical_fn(P * 2, fy)
    f3p2 = f2p2 * intersect_fn(P, P * 2, fy) / vertical_fn(P * 3, fy)
    f4p2 = f3p2 * intersect_fn(P, P * 3, fy) / vertical_fn(P * 4, fy)
    f5p2 = f4p2 * vertical_fn(P, fy)
    assert f5p2 == f5p, f5p2
    f = slow_frp(P)
    f.cfield = f5p.cfield
    assert f == f5p, f


def test_pfb_ex_5_1_1():
    """
    "Pairings for beginners" example 5.1.1
    """
    q = 23
    k = 2
    r = 3
    fq = PrimeField(q)
    fq2 = ExtensionField(fq, fq.monoup(2) + 1)
    crv = Curve(
        fq2,
        a=fq2.el([-1]),
        b=fq2.zero(),
        n=r,
        h=24 // r,
        generator=(fq2.zero(), fq2.zero()),
    )
    P = PointAffine(fq2.el([2]), fq2.el([11]), crv)
    Q = PointAffine(fq2.el([21]), fq2.el([0, 12]), crv)
    assert (P + P + P).is_zero()
    assert (P * 3).is_zero()
    assert (Q + Q + Q).is_zero()
    assert (Q * 3).is_zero()
    assert Q.trace_map().is_zero()
    frp = slow_frp(P)
    frq = slow_frp(Q)
    assert frp == frp.pfield.mono(1) + 11 * frp.cfield.mono(1) + 13
    assert frq == frq.pfield.mono(1) + (11 * fq2.mono(1)) * frq.cfield.mono(
        1
    ) + 10 * fq2.mono(1)
    # R = PointAffine(fq2.el([0, 17]), fq2.el([21, 2]), crv)
    # S = PointAffine(fq2.el([18, 10]), fq2.el([13, 13]), crv)
    R = P
    S = Q
    f = frp / ((intersect_fn(P, R, frp.pfield) / vertical_fn(P + R, frp.pfield)) ** 3)
    wr = f.eval(Q) / (frq.eval(P + R) / frq.eval(R))
    assert wr == fq2.el([11, 15])
    g = frq / ((intersect_fn(Q, S, frq.pfield) / vertical_fn(Q + S, frq.pfield)) ** 3)
    wr = f.eval(Q + S) * g.eval(R) / (f.eval(S) * g.eval(P + R))
    assert wr == fq2.el([11, 15])
    wr = (f.eval(Q + S) / f.eval(S)) / (g.eval(P + R) / g.eval(R))
    assert wr == fq2.el([11, 15])
    assert weil_pairing(P, Q) == fq2.el([11, 15])


def test_pfb_ex_5_2_1():
    """
    "Pairings for beginners" example 5.2.1
    """
    q = 5
    k = 2
    r = 3
    h = 4
    fq = PrimeField(q)
    fq2 = ExtensionField(fq, fq.monoup(2) + 2)
    crv2 = Curve(fq2, a=0, b=-3, n=r**2, h=h, generator=(fq2.zero(), fq2.zero()))
    points = [
        crv2.zero().to_affine(),
        *[
            p
            for p in [
                PointAffine(fq2.el([x0, x1]), fq2.el([y0, y1]), crv2)
                for x0 in range(q)
                for x1 in range(q)
                for y0 in range(q)
                for y1 in range(q)
            ]
            if p.is_zero() or p.is_valid_nonzero()
        ],
    ]
    assert len(points) == 36
    assert set(points) == set(
        [crv2.zero().to_affine()]
        + crv2.points(
            [
                ([4, 3], [0]),
                ([4, 2], [0]),
                ([2], [0]),
                ([3], [2]),
                ([4], [1]),
                ([0, 2], [3, 4]),
                ([0, 3], [3, 1]),
                ([2, 1], [0, 1]),
                ([1], [0, 1]),
                ([0], [0, 3]),
                ([2, 4], [0, 1]),
                ([1, 2], [2]),
                ([1, 1], [3, 1]),
                ([4, 4], [3, 4]),
                ([3, 1], [1]),
                ([3, 1], [4]),
                ([1, 1], [2, 4]),
                ([4, 4], [2, 1]),
                ([1, 2], [3]),
                ([1], [0, 4]),
                ([2, 4], [0, 4]),
                ([0], [0, 2]),
                ([2, 1], [0, 4]),
                ([0, 3], [2, 4]),
                ([0, 2], [2, 1]),
                ([3], [3]),
                ([4], [4]),
                ([3, 4], [4]),
                ([1, 3], [3]),
                ([1, 4], [2, 1]),
                ([4, 1], [2, 4]),
                ([3, 4], [1]),
                ([1, 4], [3, 4]),
                ([1, 3], [2]),
                ([4, 1], [3, 1]),
            ]
        )
    )

    r_torsion = [p for p in points if (p * r).is_zero()]
    assert set(r_torsion) == set(
        [crv2.zero().to_affine()]
        + crv2.points(
            [
                ([3], [3]),
                ([3], [2]),
                ([0], [0, 3]),
                ([0], [0, 2]),
                ([1, 3], [3]),
                ([1, 3], [2]),
                ([1, 2], [3]),
                ([1, 2], [2]),
            ]
        )
    )

    rE = [p * r for p in points]
    assert set(rE) == set(
        [
            crv2.zero().to_affine(),
            PointAffine(fq2.el([4, 3]), fq2.zero(), crv2),
            PointAffine(fq2.el([4, 2]), fq2.zero(), crv2),
            PointAffine(fq2.el([2]), fq2.zero(), crv2),
        ]
    )


def test_pfb_ex_5_2_2():
    """
    "Pairings for beginners" example 5.2.2
    """
    q = 5
    k = 2
    r = 3
    h = 4
    fq = PrimeField(q)
    fq2 = ExtensionField(fq, fq.monoup(2) + 2)
    crv2 = Curve(fq2, a=0, b=-3, n=r**2, h=h, generator=(fq2.zero(), fq2.zero()))
    P = PointAffine(fq2.el([3]), fq2.el([2]), crv2)
    Q = PointAffine(fq2.el([1, 1]), fq2.el([2, 4]), crv2)
    R = PointAffine(fq2.el([0, 2]), fq2.el([2, 1]), crv2)
    fx = ExtensionField(fq2, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + crv2.a * fx.mono(1) + crv2.b), 0, 1])
    f = fy.mono(1) + 2 * fx.mono(1) + 2
    ft = fy.mono(1) + 3 * fx.mono(1) + 3
    assert f.eval(Q + R) / f.eval(R) == 4 * fq2.mono(1) + 4
    assert f.eval(Q * 2 + R) / f.eval(R) == 2 * fq2.mono(1) + 4
    assert ft.eval(Q + R) / ft.eval(R) == 3 * fq2.mono(1) + 2

    assert (f.eval(Q * 2 + R) / f.eval(R)) ** ((q**k - 1) // r) == 4 * fq2.mono(1) + 2
    assert (ft.eval(Q + R) / ft.eval(R)) ** ((q**k - 1) // r) == 4 * fq2.mono(1) + 2


def test_pfb_ex_5_2_3():
    """
    "Pairings for beginners" example 5.2.3
    """
    q = 19
    k = 2
    r = 5
    fq = PrimeField(q)
    fq2 = ExtensionField(fq, fq.pol([1, 0, 1]))
    crv = Curve(
        field=fq2,
        a=fq2.el([14]),
        b=fq2.el([3]),
        n=r,
        h=20 // r,
        generator=(fq2.zero(), fq2.zero()),
    )
    P = PointAffine(fq2.el([17]), fq2.el([9]), crv)
    Q = PointAffine(fq2.el([16]), fq2.el([0, 16]), crv)
    assert rtate_pairing(P, Q) == 15 * fq2.mono(1) + 2
    assert rtate_pairing(P, Q) ** 4 == 4 * fq2.mono(1) + 2
    assert rtate_pairing(P * 4, Q) == 4 * fq2.mono(1) + 2
    assert rtate_pairing(P, Q * 4) == 4 * fq2.mono(1) + 2
    assert rtate_pairing(P * 2, Q * 2) == 4 * fq2.mono(1) + 2


def test_pfb_ex_5_3_1():
    """
    "Pairings for beginners" example 5.3.1
    """
    q = 47
    k = 4
    r = 17
    fq = PrimeField(q)
    fq4 = ExtensionField(fq, fq.pol([5, 0, -4, 0, 1]))
    crv = Curve(
        field=fq4,
        a=fq4.el([21]),
        b=fq4.el([15]),
        n=r,
        h=(3**3 * 5**4 * 17**2) // r,
        generator=(fq4.zero(), fq4.zero()),
    )
    P = PointAffine(fq4.el([45]), fq4.el([23]), crv)
    Q = PointAffine(fq4.el([29, 0, 31]), fq4.el([0, 11, 0, 35]), crv)
    assert rtate_pairing(P, Q) == fq4.el([39, 45, 43, 33])
    assert weil_pairing(P, Q) == fq4.el([13, 32, 12, 22])
    me, log = miller_eval(P, ([Q * 2], [Q]))
    assert me == fq4.el([22, 10, 6, 17])
    assert log == [
        (crv.point([45], [23]), None, None, None, 1),
        (
            crv.point([12], [16]),
            fq4.el([4, 9, 21, 20]),
            fq4.el([33, 36, 19, 6]),
            fq4.el([21, 2, 32, 41]),
            fq4.el([21, 2, 32, 41]),
        ),
        (
            crv.point([27], [14]),
            fq4.el([9, 38, 18, 40]),
            fq4.el([18, 20, 8, 39]),
            fq4.el([17, 28, 5, 4]),
            fq4.el([33, 30, 27, 22]),
        ),
        (
            crv.point([18], [31]),
            fq4.el([14, 8, 15, 29]),
            fq4.el([30, 41, 32, 18]),
            fq4.el([28, 33, 13, 6]),
            fq4.el([37, 21, 2, 36]),
        ),
        (
            crv.point([45], [24]),
            fq4.el([19, 14, 3, 10]),
            fq4.el([20, 25, 26, 21]),
            fq4.el([20, 1, 45, 46]),
            fq4.el([25, 40, 21, 10]),
        ),
        (
            crv.zero(),
            fq4.el([27, 0, 7]),
            fq4.el([31, 0, 31]),
            fq4.el([43, 0, 6]),
            fq4.el([22, 10, 6, 17]),
        ),
    ]
    mert, log2 = miller_rtate_pairing(P, Q)
    assert log2 == log
    assert mert == fq4.el([39, 45, 43, 33])
    frp_dq, _ = miller_eval(P, ([Q * 2], [Q]))
    frq_dp, _ = miller_eval(Q, ([P * 2], [P]))
    assert frp_dq == fq4.el([22, 10, 6, 17])
    fx = ExtensionField(P.crv.field, None)
    fy = ExtensionField(fx, [-(fx.mono(3) + P.crv.a * fx.mono(1) + P.crv.b), 0, 1])
    R = P
    S = Q
    lpr = intersect_fn(P, R, fy)
    vpr = vertical_fn(P + R, fy)
    lqs = intersect_fn(Q, S, fy)
    vqs = vertical_fn(Q + S, fy)
    f_div = lpr / vpr
    g_div = lqs / vqs
    wr_denominator = (
        (f_div.eval(Q + S) / f_div.eval(S)) ** r
        * frq_dp
        / (g_div.eval(P + R) / g_div.eval(R)) ** r
    )
    assert wr_denominator == fq4.el([40, 6, 2])
    wr = frp_dq / wr_denominator
    assert wr == fq4.el([13, 32, 12, 22])
    assert miller_weil_pairing(P, Q) == fq4.el([13, 32, 12, 22])


def test_pfb_ex_7_1_1():
    """
    "Pairings for beginners" example 7.1.1
    """
    q = 47
    k = 4
    r = 17
    h = 3
    fq = PrimeField(q)
    fq4 = ExtensionField(fq, fq.pol([5, 0, -4, 0, 1]))
    crv = Curve(
        field=fq4,
        a=fq4.el([21]),
        b=fq4.el([15]),
        n=r,
        h=(3**3 * 5**4 * 17**2) // r,
        generator=(fq4.zero(), fq4.zero()),
    )
    P = PointAffine(fq4.el([45]), fq4.el([23]), crv)
    Q = PointAffine(fq4.el([29, 0, 31]), fq4.el([0, 11, 0, 35]), crv)
    me, log = miller_eval_point(P, Q)
    assert me == fq4.el([12, 43, 17, 32])
    assert log == [
        (crv.point([45], [23]), None, None, None, 1),
        (
            crv.point([12], [16]),
            fq4.el([13, 11, 36, 35]),
            fq4.el([17, 0, 31]),
            fq4.el([33, 36, 19, 6]),
            fq4.el([33, 36, 19, 6]),
        ),
        (
            crv.point([27], [14]),
            fq4.el([18, 11, 15, 35]),
            fq4.el([2, 0, 31]),
            fq4.el([18, 20, 8, 39]),
            fq4.el([4, 24, 17, 11]),
        ),
        (
            crv.point([18], [31]),
            fq4.el([23, 11, 33, 35]),
            fq4.el([11, 0, 31]),
            fq4.el([30, 41, 32, 18]),
            fq4.el([10, 5, 34, 22]),
        ),
        (
            crv.point([45], [24]),
            fq4.el([21, 11, 44, 35]),
            fq4.el([31, 0, 31]),
            fq4.el([20, 25, 26, 21]),
            fq4.el([27, 5, 22, 8]),
        ),
        (
            crv.zero(),
            fq4.el([29, 0, 31]) + fq4.el([2]),
            fq4.el([1]),
            fq4.el([31, 0, 31]),
            fq4.el([12, 43, 17, 32]),
        ),
    ]
    mert, log2 = miller_rtate_pairing_point(P, Q)
    assert log2 == log
    assert mert == fq4.el([39, 45, 43, 33])
