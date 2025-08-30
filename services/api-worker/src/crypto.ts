import { scrypt as scryptJs } from 'scrypt-js';

export async function hashPasswordScrypt(password: string, salt: Uint8Array, N = 16384, r = 8, p = 1, dkLen = 32): Promise<string> {
  const pw = new TextEncoder().encode(password);
  const out = await scryptJs(pw, salt, N, r, p, dkLen);
  return Buffer.from(out).toString('base64');
}

export async function verifyPasswordScrypt(password: string, saltB64: string, hashB64: string, N = 16384, r = 8, p = 1, dkLen = 32): Promise<boolean> {
  const salt = Uint8Array.from(Buffer.from(saltB64, 'base64'));
  const derived = await hashPasswordScrypt(password, salt, N, r, p, dkLen);
  return timingSafeEqualB64(derived, hashB64);
}

export function randomSalt(length = 16): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}

export function timingSafeEqualB64(aB64: string, bB64: string): boolean {
  const a = Buffer.from(aB64, 'base64');
  const b = Buffer.from(bB64, 'base64');
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
