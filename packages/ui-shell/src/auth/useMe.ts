import { useContext } from 'react';
import { can } from './permissions';
import { AuthContext, type AuthState } from './context';

/** The signed-in principal and its loading state; must be used inside `AuthProvider`. */
export function useMe(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useMe must be used inside AuthProvider');
  return ctx;
}

/** True when the signed-in principal holds `perm` (globally, or in `scope` when given); false while loading. */
export function useCan(perm: string, scope?: string): boolean {
  return can(useMe().me, perm, scope);
}
