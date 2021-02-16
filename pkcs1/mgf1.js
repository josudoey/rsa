const crypto = require('crypto')
// MGF1
// ref https://tools.ietf.org/html/rfc3447#appendix-B.2.1
module.exports = {
  sha1: (seed, maskLen) => {
    const hLen = 20
    const counter = Math.ceil(maskLen / hLen)
    const T = Buffer.alloc(hLen * counter)
    const C = Buffer.alloc(4)
    for (let i = 0; i < counter; ++i) {
      C.writeUInt32BE(i, 0)
      crypto
        .createHash('sha1')
        .update(seed)
        .update(C)
        .digest().copy(T, i * hLen)
    }
    return T.slice(0, maskLen)
  }
}
