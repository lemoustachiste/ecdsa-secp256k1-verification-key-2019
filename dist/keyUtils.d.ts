export declare type PrivateKeyJWK = {
    kty: string;
    crv: string;
    d: string;
    x: string;
    y: string;
    kid: string;
};
export declare type PublicKeyJWK = {
    kty: string;
    crv: string;
    x: string;
    y: string;
    kid: string;
};
export declare const publicKeyHexFrom: {
    publicKeyBase58: (publicKeyBase58: string) => string;
    publicKeyJWK: (jwk: PublicKeyJWK) => string;
    publicKeyUint8Array: (publicKeyUint8Array: Uint8Array) => string;
    privateKeyHex: (privateKeyHex: string) => string;
};
export declare const privateKeyHexFrom: {
    privateKeyBase58: (privateKeyBase58: string) => string;
    privateKeyJWK: (jwk: PrivateKeyJWK) => string;
    privateKeyUint8Array: (privateKeyUint8Array: Uint8Array) => string;
};
export declare const publicKeyUint8ArrayFrom: {
    publicKeyBase58: (publicKeyBase58: string) => Uint8Array;
    publicKeyHex: (publicKeyHex: string) => Uint8Array;
    publicKeyJWK: (jwk: PublicKeyJWK) => Uint8Array;
    privateKeyUint8Array: (privateKeyUint8Array: Uint8Array) => Uint8Array;
};
export declare const privateKeyUint8ArrayFrom: {
    privateKeyBase58: (privateKeyBase58: string) => Uint8Array;
    privateKeyHex: (privateKeyHex: string) => Uint8Array;
    privateKeyJWK: (jwk: PrivateKeyJWK) => Uint8Array;
};
export declare const publicKeyJWKFrom: {
    publicKeyBase58: (publicKeybase58: string, kid: string) => PublicKeyJWK;
    publicKeyHex: (publicKeyHex: string, kid: string) => PublicKeyJWK;
    publicKeyUint8Array: (publicKeyUint8Array: Uint8Array, kid: string) => PublicKeyJWK;
    privateKeyJWK: (privateKeyJWK: PrivateKeyJWK) => PublicKeyJWK;
};
export declare const privateKeyJWKFrom: {
    privateKeyBase58: (privateKeybase58: string, kid: string) => PrivateKeyJWK;
    privateKeyHex: (privateKeyHex: string, kid: string) => PrivateKeyJWK;
    privateKeyUint8Array: (privateKeyUint8Array: Uint8Array, kid: string) => PrivateKeyJWK;
};
