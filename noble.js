const { bls12_381 } = await import("@noble/curves/bls12-381.js");
const { bytesToHex, hexToBytes, concatBytes } = await import('@noble/curves/utils.js');


// const isk = 45669532586867178027808139201198804664733679037608175063888412923087225960903n;
// const Abin = hexToBytes("0408c2f49b3cc2f99f8d3bd9b497ced53ee2aed62716fe6b613d9602ef1013dee407825fba40290024428258b416a033910a6c62f2c3f85a879164a308b3466cff1eb1bd4cc983af0ea63bcd62aae7631804159361f37ef3474d08f6ea234541a2");
// const e = 45036059035782713676400381143045022070647401752626540982321741738800636561616n;
// const Cbin = hexToBytes("0411a33c872e5de3aeea7759a42c142495478907b732947336060a6e40309eff08375560ba863ecd4926c21a5651fe438f00599ac9c44952c063937949e8de5337711abdefa73171973cc9fa33fb20aa7e56a74390e1c3094a210ff77f7deb8a88");


// const ipk = bls12_381.G2.Point.BASE.multiply(isk);
// const A = bls12_381.G1.Point.fromBytes(Abin.slice(1));
// const C = bls12_381.G1.Point.fromBytes(Cbin.slice(1));

// if (bls12_381.fields.Fp12.eql(
//   bls12_381.pairing(A, ipk.add(bls12_381.G2.Point.BASE.multiply(e))),
//   bls12_381.pairing(C, bls12_381.G2.Point.BASE),
// )) {
//   console.log("Success!");
// } else {
//   console.log("FAIL!");
// }



const isk = 27006176974354612095876140861930126267430506226913580886574343873345624117297n;
const Abarbin = hexToBytes("04073647c02a6ccbb4b9c54e99dc740ce58599a222a7a6cd49f2b832df945e685f22327f6fcc58c8ca437cf448ff812e8703e37b815302047b488ee3bc9ba653562029a6ac0ee62f56e8dfdfd3f174c80ef65187927279a152a6c4e261a1d80ece");
const Bbarbin = hexToBytes("0408855cb2a4392445ad1733eb57001a7025ea7814d5d71efe5e67bad90ca35376391487c9ee6d57900db82533d39cc85e0cf8b311fe9c800fe3494cae4a12dca694d50a7435ad2c8980406cf71623d5a3700268288c96114cff0c7d2070f3ae8c");


const ipk = bls12_381.G2.Point.BASE.multiply(isk);
const Abar = bls12_381.G1.Point.fromBytes(Abarbin.slice(1));
const Bbar = bls12_381.G1.Point.fromBytes(Bbarbin.slice(1));

if (bls12_381.fields.Fp12.eql(
  bls12_381.pairing(Abar, ipk),
  bls12_381.pairing(Bbar, bls12_381.G2.Point.BASE),
)) {
  console.log("Success!");
} else {
  console.log("FAIL!");
}
