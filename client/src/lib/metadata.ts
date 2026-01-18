import { signEd25519, bytesToHex } from "../components/CryptoUtils";
/**
 * Metadata interface for anomaly detection
 * Accompanies requests but does not depend on sensitive content
 */
export interface Metadata {
  timestamp: string;
  size: number;
  privileges: string[]; // Privileges/roles
  treeDepth: number; // 0 for root, 1+ for files
  requestType: "GET" | "POST" | "PUT" | "DELETE";
}

/**
 * Generate metadata for a request.
 * @param payload The request payload (object or string) to compute size.
 * @param privileges Array of required privileges.
 * @param method HTTP method for requestType.
 * @param treeDepth Optional tree depth.
 * @returns Metadata object.
 */
export function generateMetadata(
  payload: any,
  privileges: string[],
  method: "GET" | "POST" | "PUT" | "DELETE",
  treeDepth: number = 0,
): Metadata {
  const timestamp = new Date().toISOString();
  let size = 0;
  if (payload !== null) {
    size =
      typeof payload === "string"
        ? new TextEncoder().encode(payload).length
        : new TextEncoder().encode(JSON.stringify(payload)).length;
  }

  return {
    timestamp,
    size,
    privileges,
    treeDepth,
    requestType: method,
  };
}

export async function prepareMetadata(
  metadata: Metadata,
  signKey?: Uint8Array,
): Promise<string> {
  const metadataJson = JSON.stringify(metadata);
  const metadataB64 = btoa(metadataJson);

  if (!signKey) {
    return metadataB64;
  }

  // Sign the full JSON string
  const signature = signEd25519(
    new TextEncoder().encode(metadataJson),
    signKey,
  );
  const sigHex = bytesToHex(signature);

  return `${metadataB64}|${sigHex}`;
}
