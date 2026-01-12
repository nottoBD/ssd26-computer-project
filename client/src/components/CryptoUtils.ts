import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { GCM } from "@stablelib/gcm";
import { randomBytes } from "@stablelib/random";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { AES } from "@stablelib/aes";

// Manual clamping for Ed25519 private key (per spec: clear low 3 bits, clear bit 255, set bit 254)
function clampEd25519PrivateKey(bytes: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(bytes);
  clamped[0] &= 248; // Clear lowest 3 bits
  clamped[31] &= 63; // Clear highest bit (bit 255)
  clamped[31] |= 64; // Set bit 254
  return clamped;
}

export async function deriveKEK(prfBytes: Uint8Array): Promise<Uint8Array> {
  return hkdf(
    sha256,
    prfBytes,
    undefined,
    new TextEncoder().encode("HealthSecure KEK v1"),
    32,
  );
}

export function generateX25519Keypair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const priv = randomBytes(32);
  const pub = x25519.getPublicKey(priv);
  return { publicKey: pub, privateKey: priv };
}

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

export function ecdhSharedSecret(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
): Uint8Array {
  return x25519.getSharedSecret(myPriv, theirPub);
}

export function signEd25519(data: Uint8Array, priv: Uint8Array): Uint8Array {
  return ed25519.sign(data, priv);
}

export function verifyEd25519(
  sig: Uint8Array,
  data: Uint8Array,
  pub: Uint8Array,
): boolean {
  return ed25519.verify(sig, data, pub);
}

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
