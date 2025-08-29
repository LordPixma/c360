// Minimal fallback aliases to avoid requiring @cloudflare/workers-types at scaffold time.
// Replace with actual types once dependencies are installed.
type D1Database = unknown;
type KVNamespace = unknown;
type R2Bucket = unknown;
type Queue = unknown;

export interface Env {
  DB: D1Database;
  CATALOG_KV: KVNamespace;
  EVIDENCE_BUCKET: R2Bucket;
  NOTIFICATIONS_QUEUE: Queue;
}
