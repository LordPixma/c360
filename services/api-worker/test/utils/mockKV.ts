// Mock KV class that implements the KV Namespace interface methods used by the worker
export class MockKV {
  private data = new Map<string, string>();

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.data.set(key, value);
    // In a real implementation, we'd handle expiration, but for testing this is sufficient
  }

  async get(key: string): Promise<string | null> {
    return this.data.get(key) || null;
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  async list(): Promise<{ keys: Array<{ name: string }> }> {
    return {
      keys: Array.from(this.data.keys()).map(name => ({ name }))
    };
  }
}