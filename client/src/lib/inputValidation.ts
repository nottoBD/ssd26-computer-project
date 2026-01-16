// client/src/lib/inputValidation.ts
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function cleanStr(v: unknown, maxLen: number, field: string, opts?: { lower?: boolean }) {
  if (typeof v !== "string") throw new Error(`${field}: must be a string`);
  let s = v.trim();
  if (opts?.lower) s = s.toLowerCase();
  if (s.length === 0) throw new Error(`${field}: required`);
  if (s.length > maxLen) throw new Error(`${field}: too long`);
  for (const ch of s) {
    if (ch.charCodeAt(0) < 32) throw new Error(`${field}: invalid characters`);
  }
  return s;
}

export function validateEmail(email: unknown) {
  const e = cleanStr(email, 254, "Email", { lower: true });
  if (!EMAIL_RE.test(e)) throw new Error("Email: invalid format");
  return e;
}

export function validateName(name: unknown, field: string) {
  const s = cleanStr(name, 50, field);
  return s;
}

export function validateDeviceName(v: unknown) {
  if (v == null || v === "") return "";
  const s = cleanStr(v, 40, "Device name");
  return s;
}

export function validateOrg(v: unknown) {
  if (v == null || v === "") return "";
  return cleanStr(v, 80, "Medical organization");
}

export function validateUUID(v: unknown, field: string) {
  const s = cleanStr(v, 64, field);
  if (!UUID_RE.test(s)) throw new Error(`${field}: invalid UUID`);
  return s;
}

export function validateAddCode(v: unknown) {
  const s = cleanStr(v, 128, "Add code");
  // ton code serveur = token_hex(16) => 32 chars
  if (s.length < 16) throw new Error("Add code: too short");
  return s;
}

