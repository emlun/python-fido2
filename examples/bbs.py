from fido2.bls12_381 import *


# Wikipedia polynomial example of Extended Euclidean algorithm
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Example_2
f = ExtensionField(PrimeField(2), [1, 1, 0, 1, 1, 0, 0, 0, 1])
x = f.el([1, 1, 0, 0, 1, 0, 1])
xx = f.one()
for e in range(f.size() + 1):
    xe = x**e
    assert xe == xx, f"e: {e}, x^e: {xe}, x*...*x: {xx}"
    assert ((xe) * (x**(-e))) == 1, f"e: {e}, x^e: {xe}, x^(-e): {x**(-e)}, x^e * x^(-e): {xe * (x**(-e))}"
    assert (xe * xe.inv()) == 1, f"e: {e}, x^e: {xe}, (x^e)^(-1): {xe.inv()}, x^e * (x^e)^(-1): {xe * xe.inv()}"
    xx *= x
assert x.inv() == f.el([0, 1, 0, 1, 0, 0, 1, 1]), f"{x} != {f.el([0, 1, 0, 1, 0, 0, 1, 1])}"


# "Pairings for beginners" example 4.1.5
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
    assert ((xe) * (x**(-e))) == 1, f"e: {e}, x^e: {xe}, x^(-e): {x**(-e)}, x^e * x^(-e): {xe * (x**(-e))}"
    assert (xe * xe.inv()) == 1, f"e: {e}, x^e: {xe}, (x^e)^(-1): {xe.inv()}, x^e * (x^e)^(-1): {xe * xe.inv()}"
    xx *= x
assert x**(59**2) == x


# def pfb_example_4_3_2():
'''Example 4.3.2 in "Pairings for beginners"'''
q = 103
f = PrimeField(q)
ef = ExtensionField(f, 2 * f.monoup(0) + f.monoup(6))
crv = Curve(field=ef, a=0, b=72, n=7, h=84//7, generator=(35 * ef.mono(4), 42 * ef.mono(3)))

# def twist(x: Polynomial, y: Polynomial) -> (int, int):
#     return (ef.mono(2) * x, ef.mono(3) * y)

# def untwist(xp: int, yp: int) -> (Polynomial, Polynomial):
#     return (xp / ef.mono(2), yp / ef.mono(3))

# tcrv = Curve(field=ef, a=0, b=72*ef.mono(6), n=7, h=84//7, generator=twist(crv.generator.x, crv.generator.y))

# def twistp(p: PointAffine) -> PointAffine:
#     if p.is_zero():
#         return tcrv.zero()
#     return PointAffine(*twist(p.x, p.y), tcrv)

# def untwistp(pp: PointAffine) -> PointAffine:
#     if pp.is_zero():
#         return crv.zero()
#     return PointAffine(*untwist(pp.x, pp.y), crv)

tcrv, twistp, untwistp = crv.twist()

for i in range(crv.n+1):
    gi = crv.generator * i
    tgi = untwistp(twistp(crv.generator.to_affine()) * i)
    assert gi == tgi, (gi, tgi)



    # return crv


# g1 = CRV_BLS.generator
# # g2 = CRV_BLS_G2.generator

# # gfp2 = ExtensionField(CRV_BLS.field, [1, 0, 1])
# # gfp6 = ExtensionField(gfp2, [-gfp2.monoup(1) - gfp2.monoup(0), gfp2.zero(), gfp2.zero(), gfp2.one()])
# # gfp12 = ExtensionField(gfp6, [-gfp6.monoup(1), gfp6.zero(), gfp6.one()])

# for f in [gfp2, gfp6, gfp12]:
#     for d in range(f.modulus.degree() + 1):
#         x = ef.mono(d)
#         xe = x**(f.size()-2)
#         assert d == 0 or xe != f.one(), (d, x, xe, f)
#         xe *= x
#         assert xe == f.one()
#         assert xe * x == x


# CRV_BLS_G2, twist, untwist = CRV_BLS.twist(generator=(
#     gfp12.mono(0)*0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
#     + gfp12.mono(1)*0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
#     gfp12.mono(0)*0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
#     + gfp12.mono(1)*0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
# ))

# P = CRV_BLS.generator
# # Q = untwist(CRV_BLS_G2.generator.to_affine()).to_projective()
# Q = CRV_BLS_G2.generator

# # c = t = -2^63 - 2^62 - 2^60 - 2^57 - 2^48 - 2^16
# c = [0] * 64
# c[63] = -1
# c[62] = -1
# c[60] = -1
# c[57] = -1
# c[48] = -1
# c[16] = -1
# k = 12
# e = opt_ate_pairing(P, Q, c, k, untwist)
# print(e)
# print(e.to_bytes().hex())

fq = PrimeField(97)
alpha = 5
fq2 = ExtensionField(fq, fq.monoup(2) - alpha * fq.monoup(0))
# fq2 = ExtensionField(fq, [-alpha, 0, 1])
fq6 = ExtensionField(fq2, fq2.monoup(3) - fq2.mono(1) * fq2.monoup(0))
# fq6 = ExtensionField(fq2, [-fq2.mono(1), fq2.zero(), fq2.zero(), fq2.one()])
fq12 = ExtensionField(fq6, fq6.monoup(2) - fq6.mono(1) * fq6.monoup(0))
                      # [-fq6.mono(1), fq6.zero(), fq6.one()])
fq12d = ExtensionField(fq, fq.monoup(12) - alpha * fq.monoup(0))




# Example 5.0.1
q = 23
k = 1
fq = PrimeField(q)
crv = Curve(field=fq, a=17, b=6, n=5, h=30//5, generator=(0, 0))
P = PointAffine(fq.el(10), fq.el(7), crv)

fx = ExtensionField(fq, None)
fy = ExtensionField(fx, [-(fx.mono(3) + 17 * fx.mono(1) + 6), 0, 1])
f2p = (fy.mono(1) + (2*fx.mono(1) + 19)) / (fx.mono(1) + 16)
f3p = f2p * (fy.mono(1) + (fx.mono(1) + 6)) / (fx.mono(1) + 16)
f4p = f3p * (fy.mono(1) + (2*fx.mono(1) + 19)) / (fx.mono(1) + 13)
f5p = f4p * (fx.mono(1) - 10)
assert f5p == (fx.mono(1) + 22)*fy.mono(1) + (5*fx.mono(2) + 3*fx.mono(1) + 5), f5p

f2p2 = intersect_fn(P, P, fy) / vertical_fn(P*2, fy)
f3p2 = f2p2 * intersect_fn(P, P*2, fy) / vertical_fn(P*3, fy)
f4p2 = f3p2 * intersect_fn(P, P*3, fy) / vertical_fn(P*4, fy)
f5p2 = f4p2 * vertical_fn(P, fy)
assert f5p2 == f5p, f5p2
f = slow_frp(P)
f.cfield = f5p.cfield
assert f == f5p, f



# Example 5.1.1
q = 23
k = 2
r = 3
fq = PrimeField(q)
fq2 = ExtensionField(fq, fq.monoup(2) + 1)
crv = Curve(fq2, a=fq2.el([-1]), b=fq2.zero(), n=r, h=24//r, generator=(fq2.zero(), fq2.zero()))
P = PointAffine(fq2.el([2]), fq2.el([11]), crv)
Q = PointAffine(fq2.el([21]), fq2.el([0, 12]), crv)
assert (P+P+P).is_zero()
assert (P*3).is_zero()
assert (Q+Q+Q).is_zero()
assert (Q*3).is_zero()
assert Q.trace_map().is_zero()
frp = slow_frp(P)
frq = slow_frp(Q)
assert frp == frp.pfield.mono(1) + 11*frp.cfield.mono(1) + 13
assert frq == frq.pfield.mono(1) + (11*fq2.mono(1))*frq.cfield.mono(1) + 10*fq2.mono(1)
# R = PointAffine(fq2.el([0, 17]), fq2.el([21, 2]), crv)
# S = PointAffine(fq2.el([18, 10]), fq2.el([13, 13]), crv)
R = P
S = Q
f = frp / ((intersect_fn(P, R, frp.pfield) / vertical_fn(P+R, frp.pfield))**3)
wr = f.eval(Q) / (frq.eval(P + R) / frq.eval(R))
assert wr == fq2.el([11, 15])
g = frq / ((intersect_fn(Q, S, frq.pfield) / vertical_fn(Q+S, frq.pfield))**3)
wr = f.eval(Q+S) * g.eval(R) / (f.eval(S) * g.eval(P + R))
assert wr == fq2.el([11, 15])
wr = (f.eval(Q+S) / f.eval(S)) / (g.eval(P + R) / g.eval(R))
assert wr == fq2.el([11, 15])
assert weil_pairing(P, Q) == fq2.el([11, 15])


# Example 5.2.1
q = 5
k = 2
r = 3
fq = PrimeField(q)
fq2 = ExtensionField(fq, fq.monoup(2) + 2)
crv = Curve(fq, a=0, b=-3, n=r, h=6//r, generator=(1, 1))
crv2 = Curve(fq2, a=0, b=-3, n=r, h=4, generator=(fq2.zero(), fq2.zero()))
points = [crv2.zero().to_affine(),
          *[p for p in [PointAffine(fq2.el([x0, x1]), fq2.el([y0, y1]), crv2)
                        for x0 in range(q) for x1 in range(q) for y0 in range(q) for y1 in range(q)]
            if p.is_zero() or p.is_valid_nonzero()
            ]
          ]



# Example 5.2.2
P = PointAffine(fq2.el([3]), fq2.el([2]), crv2)
Q = PointAffine(fq2.el([1, 1]), fq2.el([2, 4]), crv2)
R = PointAffine(fq2.el([0, 2]), fq2.el([2, 1]), crv2)
fx = ExtensionField(fq2, None)
fy = ExtensionField(fx, [-(fx.mono(3) + crv.a * fx.mono(1) + crv.b), 0, 1])
f = fy.mono(1) + 2*fx.mono(1) + 2
ft = fy.mono(1) + 3*fx.mono(1) + 3
assert f.eval(Q+R)/f.eval(R) == 4*fq2.mono(1) + 4
assert f.eval(Q*2+R)/f.eval(R) == 2*fq2.mono(1) + 4
assert ft.eval(Q+R)/ft.eval(R) == 3*fq2.mono(1) + 2

assert (f.eval(Q*2+R)/f.eval(R))**((q**k - 1) // r) == 4*fq2.mono(1) + 2
assert (ft.eval(Q+R)/ft.eval(R))**((q**k - 1) // r) == 4*fq2.mono(1) + 2



# Example 5.2.3
q = 19
k = 2
r = 5
fq = PrimeField(q)
fq2 = ExtensionField(fq, fq.pol([1, 0, 1]))
crv = Curve(field=fq2, a=fq2.el([14]), b=fq2.el([3]), n=r, h=20//r, generator=(fq2.zero(), fq2.zero()))
P = PointAffine(fq2.el([17]), fq2.el([9]), crv)
Q = PointAffine(fq2.el([16]), fq2.el([0, 16]), crv)
assert rtate_pairing(P, Q) == 15*fq2.mono(1) + 2
assert rtate_pairing(P, Q)**4 == 4*fq2.mono(1) + 2
assert rtate_pairing(P*4, Q) == 4*fq2.mono(1) + 2
assert rtate_pairing(P, Q*4) == 4*fq2.mono(1) + 2
assert rtate_pairing(P*2, Q*2) == 4*fq2.mono(1) + 2



# Example 5.3.1
q = 47
k = 4
r = 17
fq = PrimeField(q)
fq4 = ExtensionField(fq, fq.pol([5, 0, -4, 0, 1]))
crv = Curve(field=fq4, a=fq4.el([21]), b=fq4.el([15]), n=r, h=(3**3 * 5**4 * 17**2)//r, generator=(fq4.zero(), fq4.zero()))
P = PointAffine(fq4.el([45]), fq4.el([23]), crv)
Q = PointAffine(fq4.el([29, 0, 31]), fq4.el([0, 11, 0, 35]), crv)
assert rtate_pairing(P, Q) == fq4.el([39, 45, 43, 33])
assert weil_pairing(P, Q) == fq4.el([13, 32, 12, 22])
assert miller_eval(P, ([Q*2], [Q])) == fq4.el([22, 10, 6, 17])
assert miller_rtate_pairing(P, Q) == fq4.el([39, 45, 43, 33])
frp_dq = miller_eval(P, ([Q*2], [Q]))
frq_dp = miller_eval(Q, ([P*2], [P]))
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
wr_denominator = (f_div.eval(Q + S) / f_div.eval(S))**r * frq_dp / (g_div.eval(P + R) / g_div.eval(R))**r
assert wr_denominator == fq4.el([40, 6, 2])
wr = frp_dq / wr_denominator
assert wr == fq4.el([13, 32, 12, 22])
assert miller_weil_pairing(P, Q) == fq4.el([13, 32, 12, 22])
