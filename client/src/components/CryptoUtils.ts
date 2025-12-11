import { ed25519 } from "@noble/curves";
import { x25519 } from "@noble/curves";
import { GCM } from "@stablelib/gcm";
import { randomBytes } from "@stablelib/random";
import { hkdf } from "@stablelib/hkdf";
import * as hashes from "@noble/hashes";

export async function deriveKEK(prfBytes: Uint8Array): Promise<Uint8Array> {
  // return type raw for GCM
  return hkdf(hashes.sha256, prfBytes, undefined, "HealthSecure KEK v1", 32);
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
  const hash = hashes.sha256(priv);
  const privKey = ed25519.utils.clamp(hash); // Proper clamping
  return { privateKey: privKey, publicKey: ed25519.getPublicKey(privKey) };
}

export function encryptAES(
  data: Uint8Array,
  key: Uint8Array,
): { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array } {
  const iv = randomBytes(12);
  const cipher = new GCM(key); //GCM takes key directly (AES-256 if 32 bytes)
  const sealed = cipher.encrypt(data, iv);
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
  const cipher = new GCM(key);
  return cipher.decrypt(sealed, iv);
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
