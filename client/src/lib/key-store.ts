// Client-side IndexedDB keystore for HealthSecure
// Used to persist cryptographic material bound to the browser profile
// Stores opaque CryptoKey objects or raw Uint8Array blobs
// This storage is scoped to the origin and never shared with the server
import { openDB, IDBPDatabase } from "idb";


// IndexedDB layout
// Separate object stores allow isolating private material from public data if needed
const DB_NAME = "healthsecure-keystore";
const STORE = "keys";
const STORE_PUB = "pub";

let dbPromise: Promise<IDBPDatabase> | null = null;


/**
 * FUNCTION: getDB
 *
 * PURPOSE:
 *  initializes and returns the IndexedDB connection used as a keystore
 *
 * SECURITY NOTES:
 * - IndexedDB is only available in a browser context
 * - Access is scoped to the current origin
 * - Database schema is minimal to reduce attack surface
 */
function getDB() {
  if (typeof window === "undefined")
    throw new Error("IndexedDB is not available in a Node/SSR context");

  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
        }
        if (!db.objectStoreNames.contains(STORE_PUB)) {
          db.createObjectStore(STORE_PUB);
        }
      },
    });
  }
  return dbPromise;
}


/**
 * FUNCTION: saveKey
 *
 * PURPOSE:
 * Persist a cryptographic key or key material in IndexedDB
 *
 * NOTES:
 * - Accepts either WebCrypto CryptoKey objects or raw byte material
 * - Caller is responsible for ensuring the key is safe to persist
 */
export async function saveKey(keyId: string, key: CryptoKey | Uint8Array) {
  const db = await getDB();
  await db.put(STORE, key, keyId);
}


/**
 * FUNCTION: getKey
 *
 * PURPOSE:
 * Retrieve previously stored key material from the client keystore
 *
 * RETURNS:
 * - CryptoKey or Uint8Array if present
 * - undefined if no entry exists for the given identifier
 */
export async function getKey(
  keyId: string,
): Promise<CryptoKey | Uint8Array | undefined> {
  const db = await getDB();
  return db.get(STORE, keyId);
}


/**
 * FUNCTION: deleteKey
 *
 * PURPOSE:
 * Remove key material from persistent client-side storage
 *
 * SECURITY USE CASE:
 * Used during logout, device revocation, or key rotation
 */
export async function deleteKey(keyId: string) {
  const db = await getDB();
  await db.delete(STORE, keyId);
}
