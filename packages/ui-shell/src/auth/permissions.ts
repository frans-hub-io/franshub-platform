import type { Me } from './types';

/**
 * True when `me` holds `perm`. Without `scope` only global permissions count (a global-only check); in a scope the
 * effective set is `global ∪ allScopes ∪ scopes[scope]`. Names match exactly; no wildcards are expanded.
 */
export function can(me: Me | null | undefined, perm: string, scope?: string): boolean {
  if (!me) return false;
  const p = me.permissions;
  if (p.global.includes(perm)) return true;
  if (scope === undefined) return false;
  if (p.allScopes.includes(perm)) return true;
  return Object.hasOwn(p.scopes, scope) && (p.scopes[scope]?.includes(perm) ?? false);
}
