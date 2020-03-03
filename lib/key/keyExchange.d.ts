export declare type X25519Public = string;
export declare type X25519Private = string;
/**
 * Gets an ECDH session key for encryption and decryption between two parties
 * @param otherPublicStr 32 byte hexadecimal string of the other side public key
 * @param myPrivateStr 32 byte hexadecimal string of my side private key
 * @returns 32 byte hexadecimal string of the shared secret
 */
export declare const exchange: (otherPublicStr: string, myPrivateStr: string) => string;
/**
 * Gets the ed25519 public key for a private key
 * @param x25519PrivateStr 32 byte hexadecimal string of a secret key
 * @returns 32 byte hexadecimal string of the public key
 */
export declare const x25519GetPublicFromPrivate: (x25519PrivateStr: string) => string;
