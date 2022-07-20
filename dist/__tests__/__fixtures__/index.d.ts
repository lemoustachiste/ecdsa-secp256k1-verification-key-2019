export declare const keyConfig: {
    privateKeyHex: string;
    publicKeyHex: string;
    privateKeyBase58: string;
    publicKeyBase58: string;
    privateKeyJWK: {
        kty: string;
        crv: string;
        d: string;
        x: string;
        y: string;
        kid: string;
    };
    publicKeyJWK: {
        kty: string;
        crv: string;
        x: string;
        y: string;
        kid: string;
    };
    privateKeyUint8Array: Uint8Array;
    publicKeyUint8Array: Uint8Array;
};
export declare const document: {
    '@context': string[];
    '@type': string;
    name: string;
};
export declare const publicKeyPair: {
    '@context': string;
    id: string;
    type: string;
    controller: string;
    publicKeyBase58: string;
};
export declare const privateKeyPair: {
    '@context': string;
    id: string;
    type: string;
    controller: string;
    publicKeyBase58: string;
    privateKeyBase58: string;
};
