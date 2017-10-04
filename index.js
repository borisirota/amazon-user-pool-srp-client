var sjcl = require('sjcl-aws')
var BigInteger = require('./BigInteger')

var WEEK_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
var MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
var padTime = function (time) {
  return time < 10 ? ('0' + time) : time
}

var initN = '' +
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
  'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
  'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
  'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
  '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'

var SRPClient = function (poolName) {
  this.poolName = poolName

  this.N = new BigInteger(initN, 16)
  this.g = new BigInteger('2', 16)
  this.k = new BigInteger(this.hexHash('00' + this.N.toString(16) + '0' + this.g.toString(16)), 16)

  this.infoBits = 'Caldera Derived Key'
}

SRPClient.prototype = {
  generateRandomSmallA: function () {
    this.smallAValue = new BigInteger(sjcl.codec.hex.fromBits(sjcl.random.randomWords(8, 0)), 16).mod(this.N)
    return this.smallAValue.toString(16)
  },
  calculateA: function (a) {
    a = new BigInteger(a || this.generateRandomSmallA(), 16)
    this.largeAValue = this.g.modPow(a, this.N)
    if (this.largeAValue.mod(this.N).equals(BigInteger.ZERO)) throw new Error('Illegal paramater. A mod N cannot be 0.')
    return this.largeAValue.toString(16)
  },
  calculateU: function (A, B) {
    return new BigInteger(this.hexHash(this.padHex(A) + this.padHex(B)), 16)
  },
  getPasswordAuthenticationKey: function (username, password, serverBValue, salt) {
    serverBValue = new BigInteger(serverBValue, '16')
    salt = new BigInteger(salt, '16')

    if (serverBValue.mod(this.N).equals(BigInteger.ZERO)) throw new Error('B cannot be zero.')

    this.UValue = this.calculateU(this.largeAValue, serverBValue)
    if (this.UValue.equals(BigInteger.ZERO)) throw new Error('U cannot be zero.')

    var usernamePassword = this.poolName + username + ':' + password
    var usernamePasswordHash = this.hash(usernamePassword)

    var xValue = new BigInteger(this.hexHash(this.padHex(salt) + usernamePasswordHash), 16)

    var gModPowXN = this.g.modPow(xValue, this.N)

    var intValue2 = serverBValue.subtract(this.k.multiply(gModPowXN))

    var sValue = intValue2.modPow(
      this.smallAValue.add(this.UValue.multiply(xValue)),
      this.N
    ).mod(this.N)

    var hkdf = this.computehkdf(this.padHex(sValue), this.padHex(this.UValue.toString(16)))

    return hkdf
  },
  padHex: function (bigInt) {
    let hashStr = bigInt.toString(16)
    if (hashStr.length % 2 === 1) hashStr = `0${hashStr}`
    else if ('89ABCDEFabcdef'.indexOf(hashStr[0]) !== -1) hashStr = '00' + hashStr
    return hashStr
  },
  hash: function (str) {
    var hashHex = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str))
    return (new Array(64 - hashHex.length).join('0')) + hashHex
  },
  hexHash: function (str) {
    return this.hash(sjcl.codec.hex.toBits(str))
  },
  computehkdf: function (ikm, salt) {
    return sjcl.misc.hkdf(sjcl.codec.hex.toBits(ikm), 128, sjcl.codec.hex.toBits(salt), this.infoBits)
  }
}

function calculateSignature (hkdf, userPoolId, username, secretBlock, dateNow) {
  var mac = new sjcl.misc.hmac(hkdf)
  mac.update(sjcl.codec.utf8String.toBits(userPoolId))
  mac.update(sjcl.codec.utf8String.toBits(username))
  mac.update(sjcl.codec.base64.toBits(secretBlock))
  mac.update(sjcl.codec.utf8String.toBits(dateNow))
  return sjcl.codec.base64.fromBits(mac.digest())
}

function getNowString () {
  var now = new Date()
  var weekDay = WEEK_NAMES[now.getUTCDay()]
  var month = MONTH_NAMES[now.getUTCMonth()]
  var day = now.getUTCDate()
  var hours = padTime(now.getUTCHours())
  var minutes = padTime(now.getUTCMinutes())
  var seconds = padTime(now.getUTCSeconds())
  var year = now.getUTCFullYear()
  var dateNow = weekDay + ' ' + month + ' ' + day + ' ' + hours + ':' + minutes + ':' + seconds + ' UTC ' + year // ddd MMM D HH:mm:ss UTC YYYY
  return dateNow
}

module.exports.SRPClient = SRPClient
module.exports.calculateSignature = calculateSignature
module.exports.getNowString = getNowString
