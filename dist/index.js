
'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./ecdsa-secp256k1-verification-key-2019.cjs.production.min.js')
} else {
  module.exports = require('./ecdsa-secp256k1-verification-key-2019.cjs.development.js')
}
