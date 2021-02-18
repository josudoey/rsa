const crypto = require('crypto')
const BN = require('bn.js')
const Ber = require('asn1').Ber
const DigestInfo = require('./digest-info')
const mgf1 = require('./mgf1')

// ref https://tools.ietf.org/html/rfc3447#section-3.1
class PublicKey {
  static fromPEM (pem) {
    // ref https://tools.ietf.org/html/rfc2313#section-7.1
    // ref https://tools.ietf.org/html/rfc3447#appendix-A.1.1
    const buffer = Buffer.from(pem.split('\n').slice(1, -1).join(''), 'base64')
    const reader = new Ber.Reader(buffer)
    reader.readSequence()
    const modulus = reader.readString(Ber.Integer, true) // modulus
    const publicExponent = reader.readString(Ber.Integer, true) // publicExponent
    return new PublicKey(
      modulus,
      publicExponent
    )
  }

  constructor (
    modulus,
    publicExponent
  ) {
    // Notation
    // ref https://tools.ietf.org/html/rfc8017#section-1.1
    const n = new BN(modulus)
    const length = n.toBuffer().length
    this.k = length
    this.n = BN.red(n)
    this.e = new BN(publicExponent)
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

    const writer = new Ber.Writer()
    writer.startSequence()
    writer.writeBuffer(n, Ber.Integer)
    writer.writeBuffer(e, Ber.Integer)
    writer.endSequence()
    const base64text = writer.buffer.toString('base64').split(/(.{64})/g).filter(v => v).join('\n')
    return `-----BEGIN RSA PUBLIC KEY-----\n${base64text}\n-----END RSA PUBLIC KEY-----\n`
  }

  encrypt (message) {
    return this.oaepEncrypt(message)
  }

  oaepEncrypt (message) {
    // RSAES-OAEP-ENCRYPT
    // ref https://tools.ietf.org/html/rfc3447#section-7.1.1
    const { n, e } = this
    const L = Buffer.alloc(0)

    const hLen = 20
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    if (M.length > this.k - 2 * hLen - 2) {
      throw new Error('message too long')
    }

    // EME-OAEP
    const lHash = crypto.createHash('sha1').update(L).digest()
    const PS = Buffer.alloc(this.k - M.length - 2 * hLen - 2, 0x00)

    // DB = lHash || PS || 0x01 || M
    const DB = Buffer.concat([lHash, PS, Buffer.from([0x01]), M])

    // d. Generate a random octet string seed of length hLen.
    const seed = crypto.randomBytes(hLen)

    // e. Let dbMask = MGF(seed, k - hLen - 1).
    // MGF1
    // ref https://tools.ietf.org/html/rfc3447#appendix-B.2.1
    const dbMask = mgf1.sha1(seed, this.k - hLen - 1)

    // f. Let maskedDB = DB \xor dbMask
    for (let i = 0; i < DB.length; i++) {
      DB[i] ^= dbMask[i]
    }

    // g. Let seedMask = MGF(maskedDB, hLen).
    const seedMask = mgf1.sha1(DB, hLen)

    // h. Let maskedSeed = seed \xor seedMask.
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i]
    }

    const EM = Buffer.concat([Buffer.from([0x00]), seed, DB])
    const m = new BN(EM)

    // RSAEP
    // ref https://tools.ietf.org/html/rfc8017#section-5.1.1
    // c = m^e mod n
    const c = m.toRed(n).redPow(e)
    const C = c.toBuffer('be', this.k)
    return C
  }

  v15Encrypt (message) {
    // RSAES-PKCS1-V1_5-ENCRYPT
    // ref https://tools.ietf.org/html/rfc8017#section-7.2.1

    const { n, e } = this
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    if (M.length > this.k - 11) {
      throw new Error('message too long')
    }

    const PS = crypto.randomBytes(this.k - M.length - 3)
    for (let i = 0; i < PS.length; i++) {
      while (PS[i] === 0) { // non-zero only
        PS[i] = crypto.randomBytes(1)[0]
      }
    }
    const EM = Buffer.concat([Buffer.from([0x00, 0x02]), PS, Buffer.from([0x00]), M])
    const m = new BN(EM)

    // RSAEP
    // ref https://tools.ietf.org/html/rfc8017#section-5.1.1
    // c = m^e mod n
    const c = m.toRed(n).redPow(e)
    const C = c.toBuffer('be', this.k)
    return C
  }

  verify (message, signature) {
    // RSASSA-PKCS1-V1_5-VERIFY
    // ref https://tools.ietf.org/html/rfc8017#section-8.2.2
    const { n, e } = this

    // RSAVP1
    // ref https://tools.ietf.org/html/rfc8017#section-5.2.2
    const S = Buffer.isBuffer(signature) ? signature : Buffer.from(signature)
    const s = new BN(S)
    // m = s^e mod n
    const m = s.toRed(n).redPow(e)
    const EM = m.toBuffer('be', this.k)

    // EMSA-PKCS1-v1_5-ENCODE
    // ref https://tools.ietf.org/html/rfc8017#section-9.2
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    const H = crypto.createHash('sha256').update(M).digest()
    const T = Buffer.concat([DigestInfo.sha256, H])
    if (this.k < T.length + 11) {
      throw new Error('intended encoded message length too short')
    }
    const PS = Buffer.alloc(this.k - T.length - 3, 0xff)
    const EM$ = Buffer.concat([Buffer.from([0x00, 0x01]), PS, Buffer.from([0x00]), T])

    return EM.compare(EM$) === 0
  }

  decrypt (cipher) {
    // Decryption process
    // ref https://tools.ietf.org/html/rfc2313#section-9
    const { n, e } = this

    const C = Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher)
    if (C.length !== this.k || this.k < 11) {
      throw new Error('decryption error')
    }

    // RSA computation
    // https://tools.ietf.org/html/rfc2313#section-9.4
    // y = x^c mod n
    const m = new BN(C).toRed(n).redPow(e)
    const EM = m.toBuffer('be', this.k)
    if (EM[0] !== 0x00 || EM[1] !== 0x01) {
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
}

module.exports = PublicKey
