/* eslint-env jest */
const assert = require('assert')
const crypto = require('crypto')
const PrivateKey = require('../pkcs1/private-key')
const PublicKey = require('../pkcs1/public-key')

describe('rsa', () => {
  let pem
  beforeAll(async () => {
    pem = await new Promise((resolve, reject) => {
      crypto.generateKeyPair('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        }
      }, (err, publicKey, privateKey) => {
        if (err) {
          return reject(err)
        }
        return resolve({
          publicKey,
          privateKey
        })
      })
    })
  })

  describe('PrivateKey', () => {
    it('decrypt', () => {
      const message = Buffer.from('hello world')
      const cipher = crypto.publicEncrypt({
        key: pem.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, message)
      const privateKey = PrivateKey.fromPEM(pem.privateKey)
      const decrypted = privateKey.decrypt(cipher)
      assert.strictEqual(decrypted.toString(), 'hello world')
    })

    it('sign', () => {
      const message = Buffer.from('hello world')
      const privateKey = PrivateKey.fromPEM(pem.privateKey)
      const signature = privateKey.sign(message)
      assert.strictEqual(signature.length, 256)
      assert.strictEqual(crypto.verify(null, message, pem.publicKey, signature), true)

      const verifier = crypto.createVerify('RSA-SHA256').update(message)
      assert.strictEqual(verifier.verify(pem.publicKey, signature), true)
    })

    it('encrypt', () => {
      const message = crypto.randomBytes(256 - 11)
      const privateKey = PrivateKey.fromPEM(pem.privateKey)
      const cipher = privateKey.encrypt(message)
      const decrypted = crypto.publicDecrypt({
        key: pem.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, cipher)
      assert.strictEqual(cipher.length, 256)
      assert.strictEqual(decrypted.compare(message), 0)
    })
  })

  describe('PublicKey', () => {
    it('encrypt', () => {
      const message = Buffer.from('hello world')
      const publicKey = PublicKey.fromPEM(pem.publicKey)
      const cipher = publicKey.encrypt(message)
      assert.strictEqual(cipher.length, 256)

      const decrypted = crypto.privateDecrypt({
        key: pem.privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, cipher)
      assert.strictEqual(decrypted.toString(), 'hello world')
    })

    it('verify', () => {
      const message = Buffer.from('hello world')
      const signature = crypto.sign(null, message, pem.privateKey)
      const publicKey = PublicKey.fromPEM(pem.publicKey)
      assert.strictEqual(publicKey.verify(message, signature), true)

      const signature2 = crypto.createSign('RSA-SHA256').update(message).sign(pem.privateKey)
      assert.strictEqual(publicKey.verify(message, signature2), true)
    })

    it('decrypt', () => {
      const message = crypto.randomBytes(256 - 11)
      const cipher = crypto.privateEncrypt({
        key: pem.privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, message)
      const publicKey = PublicKey.fromPEM(pem.publicKey)
      const decrypted = publicKey.decrypt(cipher)
      assert.strictEqual(decrypted.compare(message), 0)
    })
  })
})
