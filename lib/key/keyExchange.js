"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const utility_1 = require("../utility");
/**
 * @hidden
 */
const nacl = require("tweetnacl");
/**
 * Gets an ECDH session key for encryption and decryption between two parties
 * @param otherPublicStr 32 byte hexadecimal string of the other side public key
 * @param myPrivateStr 32 byte hexadecimal string of my side private key
 * @returns 32 byte hexadecimal string of the shared secret
 */
exports.exchange = (otherPublicStr, myPrivateStr) => {
    const otherPublic = utility_1.toArray(otherPublicStr);
    const myPrivate = utility_1.toArray(myPrivateStr);
    const q = nacl.scalarMult(myPrivate, otherPublic);
    return utility_1.toHex(q);
};
/**
 * Gets the ed25519 public key for a private key
 * @param x25519PrivateStr 32 byte hexadecimal string of a secret key
 * @returns 32 byte hexadecimal string of the public key
 */
exports.x25519GetPublicFromPrivate = (x25519PrivateStr) => {
    const x25519Private = utility_1.toArray(x25519PrivateStr);
    const x25519Public = nacl.scalarMult.base(x25519Private);
    return utility_1.toHex(x25519Public);
};
//# sourceMappingURL=keyExchange.js.map