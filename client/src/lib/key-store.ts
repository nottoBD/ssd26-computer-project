// src/lib/key-store.ts
import { openDB, IDBPDatabase } from 'idb';

const DB_NAME = 'healthsecure-keystore';
const STORE = 'keys';
const STORE_PUB = 'pub';

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDB() {
    if (typeof window === 'undefined')
        throw new Error('IndexedDB is not available in a Node/SSR context');

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


export async function saveKey(keyId: string, key: CryptoKey | Uint8Array) {
    const db = await getDB();
    await db.put(STORE, key, keyId);
}

export async function getKey(keyId: string): Promise<CryptoKey | Uint8Array | undefined> {
    const db = await getDB();
    return db.get(STORE, keyId);
}

export async function deleteKey(keyId: string) {
    const db = await getDB();
    await db.delete(STORE, keyId);
}