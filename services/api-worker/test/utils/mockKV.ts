export class MockKV {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
    if (options?.expirationTtl) {
      // In a real implementation, we'd set up expiration, but for tests this is enough
      setTimeout(() => this.store.delete(key), options.expirationTtl * 1000);
    }
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}