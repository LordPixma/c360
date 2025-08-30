export type Row = Record<string, any>;

// Mock D1 interfaces that match Cloudflare Workers D1 API
interface MockD1Meta {
  duration: number;
  size_after: number;
  rows_read: number;
  rows_written: number;
  last_row_id: number;
  changed_db: boolean;
  changes: number;
}

interface MockD1Result<T = Row> {
  success: true;
  meta: MockD1Meta;
  results: T[];
}

interface MockD1RunResult {
  success: true;
  meta: MockD1Meta;
}

export class MockD1 {
  private tenants: Row[] = [];
  private users: Row[] = [];

  private createMockMeta(changes = 0): MockD1Meta {
    return {
      duration: 0.1,
      size_after: 1024,
      rows_read: 0,
      rows_written: changes,
      last_row_id: 0,
      changed_db: changes > 0,
      changes,
    };
  }

  private createResult<T = Row>(results: T[], changes = 0): MockD1Result<T> {
    return {
      success: true,
      meta: this.createMockMeta(changes),
      results,
    };
  }

  private createRunResult(changes = 0): MockD1RunResult {
    return {
      success: true,
      meta: this.createMockMeta(changes),
    };
  }

  prepare(sql: string) {
    const lower = sql.trim().toLowerCase();
    const self = this;
    return {
      bind(...args: any[]) {
        return {
          async all() {
            // SELECTS
            if (lower.startsWith('select') && lower.includes('from tenants')) {
              if (lower.includes('where tenant_id = ?1')) {
                const id = args[0];
                return self.createResult(self.tenants.filter(t => t.tenant_id === id));
              }
              // list tenants
              return self.createResult([...self.tenants]);
            }
            if (lower.startsWith('select') && lower.includes('from users')) {
              if (lower.includes('where tenant_id = ?1 and user_id = ?2')) {
                const [tenantId, userId] = args;
                return self.createResult(self.users.filter(u => u.tenant_id === tenantId && u.user_id === userId));
              }
              if (lower.includes('where tenant_id = ?1')) {
                const [tenantId] = args;
                return self.createResult(self.users.filter(u => u.tenant_id === tenantId));
              }
              if (lower.includes('where user_id = ?1')) {
                const [userId] = args;
                return self.createResult(self.users.filter(u => u.user_id === userId));
              }
              return self.createResult([...self.users]);
            }
            return self.createResult([]);
          },
          async run() {
            // INSERTS
            if (lower.startsWith('insert into tenants')) {
              const [tenant_id, name] = args;
              self.tenants.push({ tenant_id, name, created_at: new Date().toISOString() });
              return self.createRunResult(1);
            }
            if (lower.startsWith('insert into users')) {
              const [user_id, tenant_id, email, role] = args;
              self.users.push({ user_id, tenant_id, email, role, created_at: new Date().toISOString() });
              return self.createRunResult(1);
            }
            // UPDATES
            if (lower.startsWith('update tenants set')) {
              const [id, name] = args;
              const t = self.tenants.find(t => t.tenant_id === id);
              if (!t) return self.createRunResult(0);
              if (name != null) t.name = name;
              return self.createRunResult(1);
            }
            if (lower.startsWith('update users set')) {
              const [tenantId, userId, email, role] = args;
              const u = self.users.find(u => u.tenant_id === tenantId && u.user_id === userId);
              if (!u) return self.createRunResult(0);
              if (email != null) u.email = email;
              if (role != null) u.role = role;
              return self.createRunResult(1);
            }
            // DELETES
            if (lower.startsWith('delete from tenants')) {
              const [id] = args;
              const before = self.tenants.length;
              self.tenants = self.tenants.filter(t => t.tenant_id !== id);
              return self.createRunResult(before - self.tenants.length);
            }
            if (lower.startsWith('delete from users')) {
              const [tenantId, userId] = args;
              const before = self.users.length;
              self.users = self.users.filter(u => !(u.tenant_id === tenantId && u.user_id === userId));
              return self.createRunResult(before - self.users.length);
            }
            return self.createRunResult(0);
          }
        };
      }
    };
  }
}
