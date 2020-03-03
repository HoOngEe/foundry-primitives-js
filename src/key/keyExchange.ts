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
