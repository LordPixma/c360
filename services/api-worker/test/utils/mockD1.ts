export type Row = Record<string, any>;

export class MockD1 {
  private tenants: Row[] = [];
  private users: Row[] = [];

  // Allow tests to add data directly
  addUser(user: Row) {
    this.users.push(user);
  }

  addTenant(tenant: Row) {
    this.tenants.push(tenant);
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
                return { results: self.tenants.filter(t => t.tenant_id === id) };
              }
              // list tenants
              return { results: [...self.tenants] };
            }
            if (lower.startsWith('select') && lower.includes('from users')) {
              if (lower.includes('where tenant_id = ?1 and user_id = ?2')) {
                const [tenantId, userId] = args;
                return { results: self.users.filter(u => u.tenant_id === tenantId && u.user_id === userId) };
              }
              if (lower.includes('where tenant_id = ?1')) {
                const [tenantId] = args;
                return { results: self.users.filter(u => u.tenant_id === tenantId) };
              }
              if (lower.includes('where user_id = ?1')) {
                const [userId] = args;
                return { results: self.users.filter(u => u.user_id === userId) };
              }
              if (lower.includes('where email = ?1')) {
                const [email] = args;
                return { results: self.users.filter(u => u.email === email) };
              }
              return { results: [...self.users] };
            }
            return { results: [] };
          },
          async first() {
            const allResult = await this.all();
            return allResult.results?.[0] || null;
          },
          async run() {
            // INSERTS
            if (lower.startsWith('insert into tenants')) {
              const [tenant_id, name] = args;
              self.tenants.push({ tenant_id, name, created_at: new Date().toISOString() });
              return { meta: { changes: 1 } } as any;
            }
            if (lower.startsWith('insert into users')) {
              const [user_id, tenant_id, email, role] = args;
              self.users.push({ user_id, tenant_id, email, role, created_at: new Date().toISOString() });
              return { meta: { changes: 1 } } as any;
            }
            // UPDATES
            if (lower.startsWith('update tenants set')) {
              const [id, name] = args;
              const t = self.tenants.find(t => t.tenant_id === id);
              if (!t) return { meta: { changes: 0 } } as any;
              if (name != null) t.name = name;
              return { meta: { changes: 1 } } as any;
            }
            if (lower.startsWith('update users set')) {
              const [tenantId, userId, email, role] = args;
              const u = self.users.find(u => u.tenant_id === tenantId && u.user_id === userId);
              if (!u) return { meta: { changes: 0 } } as any;
              if (email != null) u.email = email;
              if (role != null) u.role = role;
              return { meta: { changes: 1 } } as any;
            }
            // DELETES
            if (lower.startsWith('delete from tenants')) {
              const [id] = args;
              const before = self.tenants.length;
              self.tenants = self.tenants.filter(t => t.tenant_id !== id);
              return { meta: { changes: before - self.tenants.length } } as any;
            }
            if (lower.startsWith('delete from users')) {
              const [tenantId, userId] = args;
              const before = self.users.length;
              self.users = self.users.filter(u => !(u.tenant_id === tenantId && u.user_id === userId));
              return { meta: { changes: before - self.users.length } } as any;
            }
            return { meta: { changes: 0 } } as any;
          }
        };
      }
    };
  }
}
