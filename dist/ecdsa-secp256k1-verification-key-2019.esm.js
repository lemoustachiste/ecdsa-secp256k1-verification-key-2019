import base64url from 'base64url';
import createHash from 'create-hash';
import secp256k1__default, { publicKeyCreate, privateKeyVerify, ecdsaSign, ecdsaVerify } from 'secp256k1';
import randomBytes from 'randombytes';
import cryptoLd from 'crypto-ld';
import { decode, encode } from 'base58-universal';
import keyto from '@trust/keyto';

// @ts-nocheck
const SUITE_ID = 'EcdsaSecp256k1VerificationKey2019';

const sha256 = data => createHash('sha256').update(data).digest();

class EcdsaSecp256k1VerificationKey2019 extends cryptoLd.LDKeyPair {
  constructor({
    publicKeyBase58,
    privateKeyBase58,
    ...options
  }) {
    super(options);
    this.type = void 0;
    this.publicKeyBase58 = void 0;
    this.privateKeyBase58 = void 0;

    if (privateKeyBase58 && !publicKeyBase58) {
      const publicKey = publicKeyCreate(decode(privateKeyBase58));
      this.publicKeyBase58 = encode(publicKey);
    } else {
      this.publicKeyBase58 = publicKeyBase58;
    }

    this.type = SUITE_ID;
    this.privateKeyBase58 = privateKeyBase58;

    if (!this.publicKeyBase58) {
      throw new TypeError('The "publicKeyBase58" property is required.');
    }
  }

  static from(options) {
    if (options.publicKeyHex || options.privateKeyHex) {
      const {
        publicKeyHex,
        privateKeyHex,
        ...rest
      } = options;
      return new EcdsaSecp256k1VerificationKey2019({ ...rest,
        publicKeyBase58: publicKeyHex ? encode(Buffer.from(publicKeyHex, 'hex')) : undefined,
        privateKeyBase58: privateKeyHex ? encode(Buffer.from(privateKeyHex, 'hex')) : undefined
      });
    }

    return new EcdsaSecp256k1VerificationKey2019(options);
  }

  static async generate({
    seed,
    compressed,
    ...keyPairOptions
  }) {
    if (seed && !privateKeyVerify(seed)) {
      throw new Error('Provided seed is not a valid private key');
    }

    let privateKey = seed;

    while (typeof privateKey === 'undefined' || !privateKeyVerify(privateKey)) {
      privateKey = new Uint8Array(randomBytes(32));
    }

    const publicKey = publicKeyCreate(privateKey, compressed);
    return new EcdsaSecp256k1VerificationKey2019({
      publicKeyBase58: encode(publicKey),
      privateKeyBase58: encode(privateKey),
      ...keyPairOptions
    });
  }

  export({
    publicKey = false,
    privateKey = false,
    includeContext = false
  } = {}) {
    if (!(publicKey || privateKey)) {
      throw new TypeError('export requires specifying either "publicKey" or "privateKey".');
    }

    if (privateKey && !this.privateKeyBase58) {
      throw new TypeError('No privateKey to export.');
    }

    if (publicKey && !this.publicKeyBase58) {
      throw new TypeError('No publicKey to export.');
    }

    const exported = {
      type: this.type,
      id: this.id,
      controller: this.controller,
      revoked: this.revoked
    };

    if (includeContext) {
      exported['@context'] = EcdsaSecp256k1VerificationKey2019.SUITE_CONTEXT;
    }

    if (privateKey) exported.privateKeyBase58 = this.privateKeyBase58;
    if (publicKey) exported.publicKeyBase58 = this.publicKeyBase58;
    return exported;
  }

  signer() {
    const {
      privateKeyBase58
    } = this;

    if (!privateKeyBase58) {
      return {
        async sign() {
          throw new Error('No private key to sign with.');
        },

        id: this.id
      };
    }

    return {
      async sign({
        data
      }) {
        const encodedHeader = base64url.encode(JSON.stringify({
          alg: 'ES256K',
          b64: false,
          crit: ['b64']
        }));
        const payload = Buffer.from(data.buffer, data.byteOffset, data.length);
        const digest = sha256(Buffer.from(Buffer.concat([Buffer.from(`${encodedHeader}.`, 'utf8'), Buffer.from(payload.buffer, payload.byteOffset, payload.length)])));
        const {
          signature
        } = ecdsaSign(digest, decode(privateKeyBase58));
        const encodedSignature = base64url.encode(Buffer.from(signature));
        return `${encodedHeader}..${encodedSignature}`;
      },

      id: this.id
    };
  }

  verifier() {
    const {
      publicKeyBase58
    } = this;

    if (!publicKeyBase58) {
      return {
        async verify() {
          throw new Error('No public key to verify against');
        },

        id: this.id
      };
    }

    return {
      async verify({
        data,
        signature
      }) {
        if (signature.indexOf('..') < 0) return false;
        const [encodedHeader, encodedSignature] = signature.split('..');
        const header = JSON.parse(base64url.decode(encodedHeader));
        const isHeaderInvalid = header.alg !== 'ES256K' || header.b64 !== false || !header.crit || !header.crit.length || header.crit[0] !== 'b64';
        if (isHeaderInvalid) return false;
        const payload = Buffer.from(data.buffer, data.byteOffset, data.length);
        const digest = sha256(Buffer.from(Buffer.concat([Buffer.from(`${encodedHeader}.`, 'utf8'), Buffer.from(payload.buffer, payload.byteOffset, payload.length)])));
        let verified;

        try {
          verified = ecdsaVerify(Buffer.from(base64url.decode(encodedSignature, 'hex'), 'hex'), digest, decode(publicKeyBase58));
        } catch (e) {
          console.log(e);
          verified = false;
        }

        return verified;
      },

      id: this.id
    };
  }

}
EcdsaSecp256k1VerificationKey2019.suite = SUITE_ID;
EcdsaSecp256k1VerificationKey2019.SUITE_CONTEXT = 'https://ns.did.ai/suites/secp256k1-2019/v1';

const compressedHexEncodedPublicKeyLength = 66;
const publicKeyHexFrom = {
  publicKeyBase58: publicKeyBase58 => Buffer.from(decode(publicKeyBase58)).toString('hex'),
  publicKeyJWK: jwk => Buffer.from(secp256k1__default.publicKeyConvert(Buffer.from(keyto.from({ ...jwk,
    crv: 'K-256'
  }, 'jwk').toString('blk', 'public'), 'hex'), true)).toString('hex'),
  publicKeyUint8Array: publicKeyUint8Array => Buffer.from(publicKeyUint8Array).toString('hex'),
  privateKeyHex: privateKeyHex => Buffer.from(secp256k1__default.publicKeyCreate(new Uint8Array(Buffer.from(privateKeyHex, 'hex')))).toString('hex')
};
const privateKeyHexFrom = {
  privateKeyBase58: privateKeyBase58 => Buffer.from(decode(privateKeyBase58)).toString('hex'),
  privateKeyJWK: jwk => keyto.from({ ...jwk,
    crv: 'K-256'
  }, 'jwk').toString('blk', 'private'),
  privateKeyUint8Array: privateKeyUint8Array => Buffer.from(privateKeyUint8Array).toString('hex')
};
const publicKeyUint8ArrayFrom = {
  publicKeyBase58: publicKeyBase58 => decode(publicKeyBase58),
  publicKeyHex: publicKeyHex => Uint8Array.from(Buffer.from(publicKeyHex, 'hex')),
  publicKeyJWK: jwk => {
    let asBuffer = Buffer.from(publicKeyHexFrom.publicKeyJWK(jwk), 'hex');
    let padding = 32 - asBuffer.length;

    while (padding > 0) {
      asBuffer = Buffer.concat([Buffer.from('00', 'hex'), asBuffer]);
      padding -= 1;
    }

    return Uint8Array.from(asBuffer);
  },
  privateKeyUint8Array: privateKeyUint8Array => secp256k1__default.publicKeyCreate(privateKeyUint8Array)
};
const privateKeyUint8ArrayFrom = {
  privateKeyBase58: privateKeyBase58 => decode(privateKeyBase58),
  privateKeyHex: privateKeyHex => Uint8Array.from(Buffer.from(privateKeyHex, 'hex')),
  privateKeyJWK: jwk => {
    let asBuffer = Buffer.from(privateKeyHexFrom.privateKeyJWK(jwk), 'hex');
    let padding = 32 - asBuffer.length;

    while (padding > 0) {
      asBuffer = Buffer.concat([Buffer.from('00', 'hex'), asBuffer]);
      padding -= 1;
    }

    return Uint8Array.from(asBuffer);
  }
};
const publicKeyJWKFrom = {
  publicKeyBase58: (publicKeybase58, kid) => publicKeyJWKFrom.publicKeyHex(Buffer.from(decode(publicKeybase58)).toString('hex'), kid),
  publicKeyHex: (publicKeyHex, kid) => {
    const key = publicKeyHex.length === compressedHexEncodedPublicKeyLength ? Buffer.from(secp256k1__default.publicKeyConvert(Buffer.from(publicKeyHex, 'hex'), false)).toString('hex') : publicKeyHex;
    return { ...keyto.from(key, 'blk').toJwk('public'),
      crv: 'secp256k1',
      kid
    };
  },
  publicKeyUint8Array: (publicKeyUint8Array, kid) => publicKeyJWKFrom.publicKeyHex(Buffer.from(publicKeyUint8Array).toString('hex'), kid),
  privateKeyJWK: privateKeyJWK => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {
      d,
      ...publicKeyJWK
    } = privateKeyJWK;
    return publicKeyJWK;
  }
};
const privateKeyJWKFrom = {
  privateKeyBase58: (privateKeybase58, kid) => privateKeyJWKFrom.privateKeyHex(Buffer.from(decode(privateKeybase58)).toString('hex'), kid),
  privateKeyHex: (privateKeyHex, kid) => ({ ...keyto.from(privateKeyHex, 'blk').toJwk('private'),
    crv: 'secp256k1',
    kid
  }),
  privateKeyUint8Array: (privateKeyUint8Array, kid) => privateKeyJWKFrom.privateKeyHex(privateKeyHexFrom.privateKeyUint8Array(privateKeyUint8Array), kid)
};

var keyUtils = {
  __proto__: null,
  publicKeyHexFrom: publicKeyHexFrom,
  privateKeyHexFrom: privateKeyHexFrom,
  publicKeyUint8ArrayFrom: publicKeyUint8ArrayFrom,
  privateKeyUint8ArrayFrom: privateKeyUint8ArrayFrom,
  publicKeyJWKFrom: publicKeyJWKFrom,
  privateKeyJWKFrom: privateKeyJWKFrom
};

export { EcdsaSecp256k1VerificationKey2019, keyUtils };
//# sourceMappingURL=ecdsa-secp256k1-verification-key-2019.esm.js.map
