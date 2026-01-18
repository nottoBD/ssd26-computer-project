import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { generateMetadata, prepareMetadata } from "./metadata";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export async function apiFetch(
  url: string,
  options: RequestInit = {},
  privileges: string[],
  treeDepth?: number,
) {
  const method = (options.method || "GET") as "GET" | "POST" | "PUT" | "DELETE";
  const body = options.body as string | null;
  const payload = body ? JSON.parse(body) : null;
  const metadataObj = generateMetadata(
    payload,
    privileges,
    method,
    treeDepth ?? 0,
  );
  const signKey = (window as any).__SIGN_PRIV__ || undefined;
  const metadataHeader = await prepareMetadata(metadataObj, signKey);

  const headers = {
    ...options.headers,
    "X-Metadata": metadataHeader,
    "Content-Type": "application/json",
  };

  return fetch(url, { ...options, headers });
}
