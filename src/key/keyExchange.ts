import { toArray, toHex } from "../utility";

/**
 * @hidden
 */
const nacl = require("tweetnacl");

export type X25519Public = string;
export type X25519Private = string;

/**
 * Gets an ECDH session key for encryption and decryption between two parties
 * @param otherPublicStr 32 byte hexadecimal string of the other side public key
 * @param myPrivateStr 32 byte hexadecimal string of my side private key
 * @returns 32 byte hexadecimal string of the shared secret
 */
export const exchange = (
    otherPublicStr: X25519Public,
    myPrivateStr: X25519Private
): string => {
    const otherPublic = toArray(otherPublicStr);
    const myPrivate = toArray(myPrivateStr);
    const q = nacl.scalarMult(myPrivate, otherPublic);
    return toHex(q);
};

/**
 * Gets the ed25519 public key for a private key
 * @param x25519PrivateStr 32 byte hexadecimal string of a secret key
 * @returns 32 byte hexadecimal string of the public key
 */
export const x25519GetPublicFromPrivate = (
    x25519PrivateStr: string
): string => {
    const x25519Private = toArray(x25519PrivateStr);
    const x25519Public = nacl.scalarMult.base(x25519Private);
    return toHex(x25519Public);
};
