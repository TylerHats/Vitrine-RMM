import { AuthUser } from '../types/index.js';

export const ALL_GRANULAR_PERMISSIONS = [
  'devices:read',
  'devices:manage',
  'remote:connect',
  'scripts:run',
  'scripts:write',
  'automations:manage',
  'patches:approve',
  'software:deploy',
  'policies:write',
  'alerts:triage',
  'docs:write',
  'laps:reveal',
  'laps:rotate',
  'psa:manage',
  'audit:export'
] as const;

const MUTATION_PERMISSIONS = new Set<string>([
  'devices:manage',
  'remote:connect',
  'scripts:run',
  'scripts:write',
  'automations:manage',
  'patches:approve',
  'software:deploy',
  'policies:write',
  'alerts:triage',
  'docs:write',
  'laps:reveal',
  'laps:rotate',
  'psa:manage'
]);

export function isSuperAdmin(user?: AuthUser | { role?: string | null } | null): boolean {
  if (!user) return false;
  const role = String(user.role || '').toLowerCase();
  return role === 'msp_super_admin' || role === 'super_admin' || role === 'admin';
}

export function isTechnicianOrAbove(user?: AuthUser | { role?: string | null } | null): boolean {
  if (!user) return false;
  if (isSuperAdmin(user)) return true;
  const role = String(user.role || '').toLowerCase();
  return role === 'technician' || role === 'msp_tech' || role === 'senior_tech' || role === 'support_tech';
}

export function isReadOnlyUser(user?: AuthUser | { role?: string | null } | null): boolean {
  if (!user) return true;
  const role = String(user.role || '').toLowerCase();
  return role === 'client_admin' || role === 'auditor' || role === 'readonly';
}

export function hasPermission(user: AuthUser | null | undefined, permission: string): boolean {
  if (!user) return false;
  if (isSuperAdmin(user)) return true;
  if (isReadOnlyUser(user)) {
    const role = String(user.role || '').toLowerCase();
    return permission === 'devices:read' || (role === 'auditor' && permission === 'audit:export');
  }
  const perms = user.permissions;
  if (Array.isArray(perms)) {
    return perms.includes('*') || perms.includes(permission);
  }
  return isTechnicianOrAbove(user);
}

export function canMutateFleet(user?: AuthUser | null): boolean {
  if (!user) return false;
  if (isReadOnlyUser(user)) return false;
  if (isSuperAdmin(user)) return true;
  if (Array.isArray(user.permissions)) {
    return user.permissions.includes('*') || user.permissions.some((perm) => MUTATION_PERMISSIONS.has(perm));
  }
  return isTechnicianOrAbove(user);
}
