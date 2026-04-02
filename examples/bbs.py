from fido2.bls12_381 import *

# g1 = CRV_BLS.generator
# g2 = CRV_BLS_G2.generator

# gfp2 = ExtensionField(CRV_BLS.field, [1, 0, 1])
# gfp6 = ExtensionField(gfp2, [-gfp2.monoup(1) - gfp2.monoup(0), gfp2.zero(), gfp2.zero(), gfp2.one()])
# gfp12 = ExtensionField(gfp6, [-gfp6.monoup(1), gfp6.zero(), gfp6.one()])

# for f in [gfp2, gfp6, gfp12]:
#     for d in range(f.modulus.degree() + 1):
#         x = ef.mono(d)
#         xe = x**(f.size()-2)
#         assert d == 0 or xe != f.one(), (d, x, xe, f)
#         xe *= x
#         assert xe == f.one()
#         assert xe * x == x


CRV_BLS_G2_TW, twist, untwist = CRV_BLS.twist(
    generator=(
        gfp12.mono(0)
        * 0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
        + gfp12.mono(1)
        * 0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
        gfp12.mono(0)
        * 0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801
        + gfp12.mono(1)
        * 0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
    )
)

P = PointAffine(
    gfp12.promote(CRV_BLS_G1.generator.x),
    gfp12.promote(CRV_BLS_G1.generator.y),
    CRV_BLS,
)
# Q = untwist(CRV_BLS_G2.generator.to_affine()).to_projective()
Q = CRV_BLS_G2_TW.generator

# c = t = -2^63 - 2^62 - 2^60 - 2^57 - 2^48 - 2^16
t = -(2**63) - 2**62 - 2**60 - 2**57 - 2**48 - 2**16
c = [0] * 64
c[63] = -1
c[62] = -1
c[60] = -1
c[57] = -1
c[48] = -1
c[16] = -1
k = 12
# e = opt_ate_pairing(P, Q, c, t, k, untwist)
# print(e)
# print(e.to_bytes().hex())

Qu = untwist(Q.to_affine())
