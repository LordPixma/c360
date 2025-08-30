export class MockKV {
  private store = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string, _options?: any): Promise<void> {
    this.store.set(key, value);
  }
}
