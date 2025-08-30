export class MockKV {
  private data = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.data.get(key) || null;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.data.set(key, value);
    // In a real implementation, we might handle expiration, but for testing this is sufficient
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  async list(): Promise<{ keys: { name: string }[] }> {
    return {
      keys: Array.from(this.data.keys()).map(name => ({ name }))
    };
  }
}