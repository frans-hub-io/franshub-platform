import type { ReactNode } from 'react';
import { useCan } from './useMe';

export interface CanProps {
  perm: string;
  scope?: string;
  /** Rendered instead of `children` when the permission is missing; nothing by default. */
  fallback?: ReactNode;
  children: ReactNode;
}

/** Renders `children` only when the signed-in principal holds `perm` (in `scope`, see `can`). */
export function Can({ perm, scope, fallback = null, children }: CanProps) {
  return <>{useCan(perm, scope) ? children : fallback}</>;
}
