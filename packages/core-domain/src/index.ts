export type TenantId = string;
export type UserId = string;

export type Role = "company_admin" | "compliance_manager" | "team_member" | "viewer";

export interface Tenant {
  id: TenantId;
  slug: string;
  name: string;
  plan: "starter" | "professional" | "enterprise";
  createdAt: string;
}

export interface User {
  id: UserId;
  tenantId: TenantId;
  email: string;
  name: string;
  role: Role;
  status: "active" | "invited" | "disabled";
  createdAt: string;
}

export const RBAC = {
  company_admin: ["*"],
  compliance_manager: ["tasks:*", "assessments:*", "reports:*"],
  team_member: ["tasks:read", "tasks:update", "evidence:create"],
  viewer: ["dashboards:read", "reports:read"]
} as const satisfies Record<Role, readonly string[]>;

export function can(role: Role, permission: string): boolean {
  const allowed: readonly string[] = RBAC[role];
  return allowed.includes("*") || allowed.includes(permission);
}
