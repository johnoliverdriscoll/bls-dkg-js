// Implementation of BLS + DKG.
'use strict'
const bls = require('noble-bls12-381')
const math = require('noble-bls12-381/math')

/** Convert a Buffer to a native BigInt. */
function bufferToBigInt(buf) {
  return BigInt('0x' + buf.toString('hex'))
}

/** Convert a native BigInt to a Buffer. */
function bigIntToBuffer(bigint) {
  const hex = bigint.toString(16)
  return Buffer.from('0'.slice(0, hex.length % 2) + hex, 'hex')
}

/** Return a random field element as a native BigInt. */
function randomFieldElement() {
  const buf = Buffer.alloc(32)
  for (let i = 0; i < buf.length; i++) {
    buf[i] = Math.floor(Math.random() * 256)
  }
  // Can replace above with crypto.randomBytes or similar.
  return new math.Fr(bufferToBigInt(buf)).value
}

/** Genereta a polynomial of order m. */
function generatePolynomial(m) {
  const poly = Array(m)
  for (let i = 0; i < m; i++) {
    poly[i] = randomFieldElement()
    while (i == m - 1 && poly[i].value === 0n) {
      poly[i] = randomFieldElement()
    }
  }
  return poly
}

/** Get the value of a point in the polynomial. */
function polynomialValue(poly, point) {
  let value = new math.Fr(0n)
  let pow = 1n
  for (let i = 0; i < poly.length; i++) {
    value = value.add(new math.Fr(poly[i]).multiply(pow))
    pow *= point
  }
  return value.value
}

/** Generate secret shares for n participants. */
function secretShares(poly, n) {
  const shares = Array(n)
  for (let i = 0n; i < n; i++) {
    shares[i] = polynomialValue(poly, i + 1n)
  }
  return shares
}

/** Generate a participant's public share. */
function publicShare(poly) {
  return bufferToBigInt(Buffer.from(bls.PointG1.BASE.multiply(poly[0]).toCompressedHex()))
}

/** Merge secret shares to produce a signing key. */
function mergeSecretShares(shares) {
  return shares.reduce((sum, share) => new math.Fr(sum + share).value, 0n)
}

/** Merge public shares to produce a common public key. */
function mergePublicShares(shares) {
  const sum = shares.slice(1).reduce((sum, share) => {
    return sum.add(bls.PointG1.fromCompressedHex(bigIntToBuffer(share)))
  }, bls.PointG1.fromCompressedHex(bigIntToBuffer(shares[0])))
  return bufferToBigInt(Buffer.from(sum.toCompressedHex()))
}

/** Compute Lagrange coefficients for a point in a polynomial. */
function lagrangeCoefficients(idx) {
  const res = Array(idx.length)
  const w = idx.reduce((w, id) => w * id, 1n)
  for (let i = 0; i < idx.length; i++) {
    let v = idx[i]
    for (let j = 0; j < idx.length; j++) {
      if (j != i) {
        v *= idx[j] - idx[i]
      }
    }
    res[i] = new math.Fr(v).invert().multiply(w).value
  }
  return res
}

/** Compute a shared signature from shares. */
function mergeSignatures(shares) {
  const ids = Object.keys(shares)
  const coeffs = lagrangeCoefficients(ids.map(id => BigInt(id)))
  let sign = bls.PointG2.ZERO
  for (let i = 0; i < ids.length; i++) {
    sign = sign.add(bls.PointG2.fromSignature(bigIntToBuffer(shares[ids[i]])).multiply(coeffs[i]))
  }
  return bufferToBigInt(Buffer.from(sign.toSignature()))
}

/** Generic BLS sign function. Can be used with a secret key or a secret share. */
async function sign(message, key) {
  if (typeof message === 'string') {
    message = new Uint8Array(Buffer.from(message))
  }
  const hashPoint = await bls.PointG2.hashToCurve(message)
  return bufferToBigInt(Buffer.from(hashPoint.multiply(new math.Fq(key)).toSignature()))
}

/** Generic BLS verify function. Can be used with a pubilc key or a public share. */
async function verify(sig, message, key) {
  if (typeof message === 'string') {
    message = new Uint8Array(Buffer.from(message))
  }
  return await bls.verify(bls.PointG2.fromSignature(bigIntToBuffer(sig)), message, bls.PointG1.fromCompressedHex(bigIntToBuffer(key)))
}

module.exports = {
  generatePolynomial,
  secretShares,
  publicShare,
  mergeSecretShares,
  mergePublicShares,
  mergeSignatures,
  sign,
  verify,
}
