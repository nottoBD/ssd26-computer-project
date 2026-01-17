// client/src/lib/inputValidation.ts
// Client-side input validation helpers
// Used to sanitize and normalize user-provided strings before calling backend APIs
// This is not a security boundary, server must still validate


// Basic email shape check to catch obvious mistakes
// Not a full RFC validator by design
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/i;

// UUID v1–v5 format check
// Used for route params and API identifiers
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;


// Normalizes a string input and enforces basic safety constraints
// Trims whitespace, optional lowercasing, length bounds, and rejects control characters
// Throws with a field-specific message for UI feedback
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


// Normalizes and validates an email value from an untyped source
// Lowercases for consistent identity handling
export function validateEmail(email: unknown) {
  const e = cleanStr(email, 254, "Email", { lower: true });
  if (!EMAIL_RE.test(e)) throw new Error("Email: invalid format");
  return e;
}


// Generic human-readable name validation
// Keeps rules intentionally permissive while enforcing length and basic safety
export function validateName(name: unknown, field: string) {
  const s = cleanStr(name, 50, field);
  return s;
}



// Optional device label shown in UI and activity logs
// Empty is allowed so callers can omit it without failing validation
export function validateDeviceName(v: unknown) {
  if (v == null || v === "") return "";
  const s = cleanStr(v, 40, "Device name");
  return s;
}


// Optional medical organization field
// Normalizes input and enforces a reasonable maximum length
export function validateOrg(v: unknown) {
  if (v == null || v === "") return "";
  return cleanStr(v, 80, "Medical organization");
}


// Validates UUID values coming from route params or API payloads
// Uses a strict UUID format check to avoid accidental malformed identifiers
export function validateUUID(v: unknown, field: string) {
  const s = cleanStr(v, 64, field);
  if (!UUID_RE.test(s)) throw new Error(`${field}: invalid UUID`);
  return s;
}


// Validates the short-lived add-code used for pairing secondary devices
// Minimum length check matches the server token policy
export function validateAddCode(v: unknown) {
  const s = cleanStr(v, 128, "Add code");
  // ton code serveur = token_hex(16) => 32 chars
  // Server generates this as a hex token, so typical length is fixed and predictable
  if (s.length < 16) throw new Error("Add code: too short");
  return s;
}

