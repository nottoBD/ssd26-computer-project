/**
 * FILE: CryptoUtils.ts
 *
 * PURPOSE:
 *      Centralizes all client-side cryptographic primitives used by the
 *      frontend. The module implements key derivation,
 *      asymmetric key generation, symmetric encryption, and digital
 *      signatures required for end-to-end encrypted medical data and
 *      authenticated actions.
 *
 * UTILITIES:
 *  - Derive symmetric Key Encryption Keys (KEKs) from WebAuthn PRF output.
 *  - Generate X25519 key pairs for end-to-end encryption (E2EE).
 *  - Derive Ed25519 signing keys from X25519 private keys.
 *  - Encrypt and decrypt sensitive material using AES-GCM.
 *  - Perform ECDH shared secret derivation.
 *  - Sign and verify data using Ed25519.
 *  - Provide encoding helpers for hex and base64 conversions.
 *
 * SECURITY NOTES:
 *  - All cryptographic operations are performed client-side.
 *  - The server never receives plaintext private keys or derived secrets.
 *  - AES-GCM is used with random IVs to ensure confidentiality and integrity.
 *  - Key derivation uses HKDF-SHA256 with explicit context separation.
 *
 * LIMITATIONS:
 *  - Keys are handled as raw Uint8Array values in memory; memory zeroization
 *    is the responsibility of the calling code.
 *  - This module assumes correct randomness from the underlying platform.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { GCM } from "@stablelib/gcm";
import { randomBytes } from "@stablelib/random";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { AES } from "@stablelib/aes";

/**
 * FUNCTION: clampEd25519PrivateKey
 *
 * PURPOSE:
 *      Applies Ed25519 private key clamping as defined in RFC 8032.
 *  Manual clamping for Ed25519 private key (per spec: clear low 3 bits, clear bit 255, set bit 254)
 *
 * DETAILS:
 *  - Clears the lowest 3 bits.
 *  - Clears the highest bit.
 *  - Sets the second highest bit.
 *
 * WHY:
 *      Clamping ensures the private scalar lies in the correct subgroup
 *      and prevents small-subgroup and related-key attacks.
 */

function clampEd25519PrivateKey(bytes: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(bytes);
  clamped[0] &= 248; // Clear lowest 3 bits
  clamped[31] &= 63; // Clear highest bit (bit 255)
  clamped[31] |= 64; // Set bit 254
  return clamped;
}

/**
 * FUNCTION: deriveKEK
 *
 * PURPOSE:
 *      Derives a symmetric Key Encryption Key (KEK) from WebAuthn PRF output.
 *
 * CRYPTO:
 *  - HKDF with SHA-256
 *  - Output length: 32 bytes (AES-256 compatible)
 *
 * CONTEXT:
 *      Used to encrypt private keys before storage or transmission.
 */

export async function deriveKEK(prfBytes: Uint8Array): Promise<Uint8Array> {
  return hkdf(
    sha256,
    prfBytes,
    undefined,
    new TextEncoder().encode("HealthSecure KEK v1"),
    32,
  );
}

/**
 * FUNCTION: generateX25519Keypair
 *
 * PURPOSE:
 *      Generates an X25519 key pair for end-to-end encryption.
 *
 * USAGE:
 *  - Public key is stored on the server.
 *  - Private key remains client-side and is encrypted using a KEK.
 */

export function generateX25519Keypair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const priv = randomBytes(32);
  const pub = x25519.getPublicKey(priv);
  return { publicKey: pub, privateKey: priv };
}

/**
 * FUNCTION: deriveEd25519FromX25519
 *
 * PURPOSE:
 *      Deterministically derives an Ed25519 signing key pair from an
 *      X25519 private key.
 *
 * METHOD:
 *  - Hash X25519 private key using SHA-512.
 *  - Clamp derived scalar per Ed25519 specification.
 *
 * BENEFIT:
 *      Avoids managing multiple unrelated private keys while maintaining
 *      cryptographic separation between encryption and signing.
 */

export function deriveEd25519FromX25519(priv: Uint8Array): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  // Standard Ed25519: Hash seed with SHA-512, take lower 32 bytes, clamp
  const hash = sha512(priv);
  const scalar = clampEd25519PrivateKey(hash.slice(0, 32));
  const publicKey = ed25519.getPublicKey(scalar);
  return { privateKey: scalar, publicKey };
}

/**
 * FUNCTION: encryptAES
 *
 * PURPOSE:
 *      Encrypts sensitive data using AES-GCM.
 *
 * SECURITY:
 *  - Random 96-bit IV generated per encryption.
 *  - Authentication tag ensures integrity and authenticity.
 *
 * RETURNS:
 *  - Ciphertext
 *  - IV
 *  - Authentication tag
 */

export function encryptAES(
  data: Uint8Array,
  key: Uint8Array,
): { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array } {
  const iv = randomBytes(12);
  const aes = new AES(key);
  const cipher = new GCM(aes);
  const sealed = cipher.seal(iv, data);
  const ciphertext = sealed.slice(0, -16);
  const tag = sealed.slice(-16);
  return { ciphertext, iv, tag };
}

/**
 * FUNCTION: decryptAES
 *
 * PURPOSE:
 *      Decrypts AES-GCM encrypted data and verifies integrity.
 *
 * FAILURE MODE:
 *  - Throws an error if authentication tag verification fails.
 */

export function decryptAES(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
): Uint8Array {
  const sealed = new Uint8Array([...ciphertext, ...tag]);
  const aes = new AES(key);
  const cipher = new GCM(aes);
  const decrypted = cipher.open(iv, sealed);
  if (decrypted === null) {
    throw new Error("Decryption failed: invalid tag or ciphertext");
  }
  return decrypted;
}

/**
 * FUNCTION: ecdhSharedSecret
 *
 * PURPOSE:
 *      Computes a shared secret using X25519 Diffie–Hellman.
 *
 * USAGE:
 *      Used to derive symmetric keys for secure communication between users.
 */

export function ecdhSharedSecret(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
): Uint8Array {
  return x25519.getSharedSecret(myPriv, theirPub);
}

/**
 * FUNCTION: signEd25519
 *
 * PURPOSE:
 *      Signs data using Ed25519.
 *
 * CONTEXT:
 *      Used for authenticating requests and verifying data integrity
 *      in end-to-end encrypted workflows.
 */

export function signEd25519(data: Uint8Array, priv: Uint8Array): Uint8Array {
  return ed25519.sign(data, priv);
}

/**
 * FUNCTION: verifyEd25519
 *
 * PURPOSE:
 *      Verifies an Ed25519 signature against the given data and public key.
 */

export function verifyEd25519(
  sig: Uint8Array,
  data: Uint8Array,
  pub: Uint8Array,
): boolean {
  return ed25519.verify(sig, data, pub);
}

/**
 * FUNCTION GROUP: Encoding Helpers
 *
 * PURPOSE:
 *      Convert between binary formats and textual representations
 *      (hex and base64) for safe transport and storage.
 *
 * NOTE:
 *      These helpers do not perform validation beyond basic parsing.
 */

export { randomBytes } from "@stablelib/random";

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(hex: string): Uint8Array {
  if (!hex) {
    return new Uint8Array();
  }
  const bytes = hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? [];
  return new Uint8Array(bytes);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join(
    "",
  );
  return btoa(binString);
}

/**
 * FUNCTION: getX25519PublicFromPrivate
 *
 * PURPOSE:
 *      Computes the X25519 public key corresponding to a given private key.
 *
 * USAGE:
 *      Used to verify that decrypted or imported private keys match
 *      the public key stored on the server.
 */

export function getX25519PublicFromPrivate(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
export async function deriveMasterKEK(priv: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", priv);
  return new Uint8Array(digest);
}
