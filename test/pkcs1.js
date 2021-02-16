/* eslint-env jest */
const assert = require('assert')
const crypto = require('crypto')
const PrivateKey = require('../pkcs1/private-key')
const PublicKey = require('../pkcs1/public-key')

describe('pkcs1', () => {
  let pem, privateKey, publicKey
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

    privateKey = PrivateKey.fromPEM(pem.privateKey)
    publicKey = PublicKey.fromPEM(pem.publicKey)
  })

  describe('PublicKey', () => {
    it('toPEM', () => {
      assert.strictEqual(publicKey.toPEM(), pem.publicKey)
    })

    it('encrypt', () => {
      const message = Buffer.from('hello world')
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
      const decrypted = publicKey.decrypt(cipher)
      assert.strictEqual(decrypted.compare(message), 0)
    })
  })

  describe('PrivateKey', () => {
    it('toPEM', () => {
      assert.strictEqual(privateKey.toPEM(), pem.privateKey)
    })

    it('getPublicKey', () => {
      assert.strictEqual(privateKey.getPublicKey().toPEM(), pem.publicKey)
    })

    it('decrypt', () => {
      const message = Buffer.from('hello world')
      const cipher = crypto.publicEncrypt({
        key: pem.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, message)
      const decrypted = privateKey.decrypt(cipher)
      assert.strictEqual(decrypted.toString(), 'hello world')
    })

    it('sign', () => {
      const message = Buffer.from('hello world')
      const signature = privateKey.sign(message)
      assert.strictEqual(signature.length, 256)
      assert.strictEqual(crypto.verify(null, message, pem.publicKey, signature), true)

      const verifier = crypto.createVerify('RSA-SHA256').update(message)
      assert.strictEqual(verifier.verify(pem.publicKey, signature), true)
    })

    it('encrypt', () => {
      const message = crypto.randomBytes(256 - 11)
      const cipher = privateKey.encrypt(message)
      const decrypted = crypto.publicDecrypt({
        key: pem.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, cipher)
      assert.strictEqual(cipher.length, 256)
      assert.strictEqual(decrypted.compare(message), 0)
    })
  })

  describe('Message Size Limit', () => {
    test.each([1, 10, 50, 100, 1024])('sign&verify message size: %i byte', (size) => {
      const message = crypto.randomBytes(size)
      const signature = privateKey.sign(message)
      assert.strictEqual(signature.length, 256)
      assert.strictEqual(publicKey.verify(message, signature), true)
    })

    test.each([1, 10, 50, 100, 245])('publicEncrypt&privateDecrypt message size: %i byte', (size) => {
      const message = crypto.randomBytes(size)
      const cipher = publicKey.encrypt(message)
      assert.strictEqual(cipher.length, 256)
      const decrypted = privateKey.decrypt(cipher)
      assert.strictEqual(decrypted.compare(message), 0)
    })
  })
})
