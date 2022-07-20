import cryptoLd from 'crypto-ld';
declare type ExportedKey = {
    '@context'?: string;
    type: string;
    id: string;
    controller: string;
    publicKeyBase58?: string;
    privateKeyBase58?: string;
    revoked?: boolean;
};
declare type EcdsaSecp256k1VerificationKey2019Options = {
    controller: string;
    id: string;
    revoked?: boolean;
    publicKeyBase58?: string;
    privateKeyBase58?: string;
};
declare type EcdsaSecp256k1VerificationKey2019HexKeyOptions = {
    controller: string;
    id: string;
    revoked?: boolean;
    publicKeyHex?: string;
    privateKeyHex?: string;
};
export declare class EcdsaSecp256k1VerificationKey2019 extends cryptoLd.LDKeyPair {
    type: string;
    publicKeyBase58?: string;
    privateKeyBase58?: string;
    constructor({ publicKeyBase58, privateKeyBase58, ...options }: EcdsaSecp256k1VerificationKey2019Options);
    static from(options: EcdsaSecp256k1VerificationKey2019Options | EcdsaSecp256k1VerificationKey2019HexKeyOptions): EcdsaSecp256k1VerificationKey2019;
    static generate({ seed, compressed, ...keyPairOptions }: Omit<EcdsaSecp256k1VerificationKey2019Options, 'publicKeyBase58' | 'privateKeyBase58'> & {
        seed?: Uint8Array;
        compressed?: boolean;
    }): Promise<EcdsaSecp256k1VerificationKey2019>;
    export({ publicKey, privateKey, includeContext, }?: {
        publicKey?: boolean;
        privateKey?: boolean;
        includeContext?: boolean;
    }): ExportedKey;
    signer(): {
        sign({ data }: {
            data: Uint8Array;
        }): Promise<string>;
        id: any;
    };
    verifier(): {
        verify({ data, signature }: {
            data: Uint8Array;
            signature: string;
        }): Promise<boolean>;
        id: any;
    };
}
export {};
