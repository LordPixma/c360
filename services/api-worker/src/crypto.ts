import { scrypt as scryptJs } from 'scrypt-js';

// Workers-safe base64 helpers (no Node Buffer)
export function toB64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function hashPasswordScrypt(password: string, salt: Uint8Array, N = 16384, r = 8, p = 1, dkLen = 32): Promise<string> {
  const pw = new TextEncoder().encode(password);
  const out = await scryptJs(pw, salt, N, r, p, dkLen);
  const bytes = out instanceof Uint8Array ? out : new Uint8Array(out);
  return toB64(bytes);
}

export async function verifyPasswordScrypt(password: string, saltB64: string, hashB64: string, N = 16384, r = 8, p = 1, dkLen = 32): Promise<boolean> {
  const salt = fromB64(saltB64);
  const derived = await hashPasswordScrypt(password, salt, N, r, p, dkLen);
  return timingSafeEqualB64(derived, hashB64);
}

export function randomSalt(length = 16): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}

export function timingSafeEqualB64(aB64: string, bB64: string): boolean {
  const a = fromB64(aB64);
  const b = fromB64(bB64);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
