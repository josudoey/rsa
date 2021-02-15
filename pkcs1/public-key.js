const crypto = require('crypto')
const BN = require('bn.js')
const Ber = require('asn1').Ber
const DigestInfo = require('./digest-info')

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

  encrypt (message) {
    // RSAES-PKCS1-V1_5-ENCRYPT
    // ref https://tools.ietf.org/html/rfc8017#section-7.2.1

    const { n, e } = this
    const M = Buffer.isBuffer(message) ? message : Buffer.from(message)
    if (M.length > this.k - 11) {
      throw new Error('message too long')
    }

    const PS = crypto.randomBytes(this.k - M.length - 3)
    for (let i = 0; i < PS.length; i++) {
      if (PS[i] !== 0) {
        continue
      }
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
    const PSEndIndex = EM.indexOf(0x00, 2)
    if (PSEndIndex < 0) {
      throw new Error('decryption error')
    }
    const PSLength = PSEndIndex - 2
    if (PSLength < 8) {
      throw new Error('decryption error')
    }
    const M = EM.slice(PSEndIndex + 1)
    return M
  }
}

module.exports = PublicKey
