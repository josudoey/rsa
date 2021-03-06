const crypto = require('crypto')
const BN = require('bn.js')
const Ber = require('asn1').Ber
const PublicKey = require('./public-key')
const DigestInfo = require('./digest-info')
const mgf1 = require('./mgf1')

// ref https://tools.ietf.org/html/rfc3447#section-3.2
class PrivateKey {
  static fromPEM (pem) {
    // ref https://tools.ietf.org/html/rfc2313#section-7.2
    // ref https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    const buffer = Buffer.from(pem.split('\n').slice(1, -1).join(''), 'base64')
    const reader = new Ber.Reader(buffer)
    reader.readSequence()
    reader.readString(Ber.Integer, true) // version
    const modulus = reader.readString(Ber.Integer, true)
    const publicExponent = reader.readString(Ber.Integer, true)
    const privateExponent = reader.readString(Ber.Integer, true)
    const prime1 = reader.readString(Ber.Integer, true)
    const prime2 = reader.readString(Ber.Integer, true)
    const exponent1 = reader.readString(Ber.Integer, true) // exponent1 -- d mod (p-1)
    const exponent2 = reader.readString(Ber.Integer, true) // exponent2 -- d mod (q-1)
    const coefficient = reader.readString(Ber.Integer, true) // coefficient -- q-1 mod p
    return new PrivateKey(
      modulus,
      publicExponent,
      privateExponent,
      prime1,
      prime2,
      exponent1,
      exponent2,
      coefficient
    )
  }

  constructor (
    modulus,
    publicExponent,
    privateExponent,
    prime1,
    prime2,
    exponent1,
    exponent2,
    coefficient
  ) {
    // Notation
    // ref https://tools.ietf.org/html/rfc8017#section-1.1
    const n = new BN(modulus)
    const length = n.toBuffer().length
    this.k = length
    this.n = BN.red(n)
    this.e = new BN(publicExponent)
    this.d = new BN(privateExponent)
    this.p = new BN(prime1)
    this.q = new BN(prime2)
    this.dP = new BN(exponent1)
    this.dQ = new BN(exponent2)
    this.qInv = new BN(coefficient)
  }

  toPEM () {
    const unsigned = (bn) => {
      const signBitIndex = bn.byteLength() * 8 - 1
      if (bn.testn(signBitIndex)) {
        return Buffer.concat([Buffer.from([0x00]), bn.toBuffer()])
      }
      return bn.toBuffer()
    }
    const n = unsigned(this.n.m)
    const e = unsigned(this.e)
    const d = unsigned(this.d)
    const p = unsigned(this.p)
    const q = unsigned(this.q)
    const dP = unsigned(this.dP)
    const dQ = unsigned(this.dQ)
    const qInv = unsigned(this.qInv)

    const writer = new Ber.Writer()
    writer.startSequence()
    writer.writeInt(0)
    writer.writeBuffer(n, Ber.Integer)
    writer.writeBuffer(e, Ber.Integer)
    writer.writeBuffer(d, Ber.Integer)
    writer.writeBuffer(p, Ber.Integer)
    writer.writeBuffer(q, Ber.Integer)
    writer.writeBuffer(dP, Ber.Integer)
    writer.writeBuffer(dQ, Ber.Integer)
    writer.writeBuffer(qInv, Ber.Integer)
    writer.endSequence()
    const base64text = writer.buffer.toString('base64').split(/(.{64})/g).filter(v => v).join('\n')
    return `-----BEGIN RSA PRIVATE KEY-----\n${base64text}\n-----END RSA PRIVATE KEY-----\n`
  }

  getPublicKey () {
    return new PublicKey(this.n.m.toBuffer(), this.e.toBuffer())
  }

  decrypt (cipher) {
    return this.oaepDecrypt(cipher)
  }

  v15Decrypt (cipher) {
    // RSAES-PKCS1-V1_5-DECRYPT
    // ref https://tools.ietf.org/html/rfc8017#section-7.2.2

    const { n, d } = this

    const C = Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher)
    if (C.length !== this.k || this.k < 11) {
      throw new Error('decryption error')
    }

    // RSADP
    // https://tools.ietf.org/html/rfc8017#section-5.1.2
    // m = c^d mod n
    const m = new BN(C).toRed(n).redPow(d)
    const EM = m.toBuffer('be', this.k)
    if (EM[0] !== 0x00 || EM[1] !== 0x02) {
      throw new Error('decryption error')
    }
    const zeroIndex = EM.indexOf(0x00, 2)
    if (zeroIndex < 0) {
      throw new Error('decryption error')
    }
    const PSLength = zeroIndex - 2
    if (PSLength < 8) {
      throw new Error('decryption error')
    }
    const M = EM.slice(zeroIndex + 1)
    return M
  }

  oaepDecrypt (cipher) {
    // RSAES-OAEP-DECRYPT
    // ref https://tools.ietf.org/html/rfc3447#section-7.1.2

    const { n, d } = this
    const L = Buffer.alloc(0)

    const hLen = 20
    const C = Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher)
    if (C.length !== this.k || this.k < 2 * hLen + 2) {
      throw new Error('decryption error')
    }

    // RSADP
    // https://tools.ietf.org/html/rfc8017#section-5.1.2
    // m = c^d mod n
    const m = new BN(C).toRed(n).redPow(d)
    const EM = m.toBuffer('be', this.k)

    // EME-OAEP
    const seed = EM.slice(1, hLen + 1)
    const DB = EM.slice(1 + hLen)

    const seedMask = mgf1.sha1(DB, hLen)
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i]
    }

    const dbMask = mgf1.sha1(seed, this.k - hLen - 1)
    for (let i = 0; i < DB.length; i++) {
      DB[i] ^= dbMask[i]
    }

    const lHash = crypto.createHash('sha1').update(L).digest()

    if (DB.slice(0, hLen).compare(lHash) !== 0) {
      throw new Error('decryption error')
    }

    const oneIndex = DB.indexOf(0x01, hLen)
    if (oneIndex < 0) {
      throw new Error('decryption error')
    }
    const M = DB.slice(oneIndex + 1)
    return M
  }

  sign (message) {
    // RSASSA-PKCS1-V1_5-SIGN
    // ref https://tools.ietf.org/html/rfc8017#section-8.2.1
    const { n, d } = this

    // EMSA-PKCS1-v1_5-ENCODE
    // ref https://tools.ietf.org/html/rfc8017#section-9.2
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    const H = crypto.createHash('sha256').update(M).digest()
    const T = Buffer.concat([DigestInfo.sha256, H])
    if (this.k < T.length + 11) {
      throw new Error('intended encoded message length too short')
    }
    const PS = Buffer.alloc(this.k - T.length - 3, 0xff)
    const EM = Buffer.concat([Buffer.from([0x00, 0x01]), PS, Buffer.from([0x00]), T])

    // RSASP1
    // https://tools.ietf.org/html/rfc8017#section-5.2.1
    // s = m^d mod n
    const s = new BN(EM).toRed(n).redPow(d)
    const S = s.toBuffer('be', this.k)
    return S
  }

  encrypt (message) {
    // Encryption process
    // ref https://tools.ietf.org/html/rfc2313#section-8
    const { n, d } = this

    // Encryption-block formatting
    // ref https://tools.ietf.org/html/rfc2313#section-8.1
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    if (M.length > this.k - 11) {
      throw new Error('message too long')
    }

    const PS = Buffer.alloc(this.k - 3 - M.length, 0xff)
    const BT = Buffer.from([0x01])
    const EM = Buffer.concat([Buffer.from([0x00]), BT, PS, Buffer.from([0x00]), M])

    // RSA computation
    // https://tools.ietf.org/html/rfc2313#section-8.3
    // y = x^c mod n
    const c = new BN(EM).toRed(n).redPow(d)
    const C = c.toBuffer('be', this.k)
    return C
  }
}

module.exports = PrivateKey
