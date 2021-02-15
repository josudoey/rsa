// ref https://tools.ietf.org/html/rfc8017#section-9.2
module.exports = {
  md2: Buffer.from('3020300c06082a864886f70d020205000410', 'hex'),
  md5: Buffer.from('3020300c06082a864886f70d020505000410', 'hex'),
  sha1: Buffer.from('3021300906052b0e03021a05000414', 'hex'),
  sha224: Buffer.from('302d300d06096086480165030402040500041c', 'hex'),
  sha256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  sha384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  sha512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
  ripemd160: Buffer.from('3021300906052b2403020105000414', 'hex'),
  rmd160: Buffer.from('3021300906052b2403020105000414', 'hex')
}