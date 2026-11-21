import type { ReactNode } from 'react';
import { can } from '../auth/permissions';
import type { Me } from '../auth/types';

export interface NavItem {
  label: string;
  href: string;
  icon?: ReactNode;
  /** Marks the current page. */
  active?: boolean;
  /** Hides the item unless the principal holds this permission. */
  permission?: string;
  /** The scope `permission` is checked in; global-only when unset. */
  scope?: string;
}

/** The items the principal may see: those without a permission, and those whose permission it holds. */
export function visibleNavItems(items: readonly NavItem[], me: Me | null | undefined): NavItem[] {
  return items.filter((i) => !i.permission || can(me, i.permission, i.scope));
}
