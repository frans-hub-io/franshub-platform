import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { apiErrorFrom, apiFetch, loginUrl, LOGOUT_PATH, ME_PATH, parseMe, safeRedirectTarget } from './api';
import { AuthContext, type AuthState } from './context';
import type { Me } from './types';

function browserRedirect(url: string): void {
  window.location.assign(url);
}

function currentPath(): string {
  const { pathname, search, hash } = window.location;
  return `${pathname}${search}${hash}`;
}

export interface AuthProviderProps {
  children: ReactNode;
  /** Leaves the page for `url`; `window.location.assign` by default (inject a fake in tests). */
  redirect?: (url: string) => void;
}

/**
 * Loads the signed-in principal from `GET /api/v1/me` once and shares it through `useMe()`. A 401 answer sends
 * the browser to `/auth/login?return=<current path>`.
 */
export function AuthProvider({ children, redirect = browserRedirect }: AuthProviderProps) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const started = useRef(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch(ME_PATH, { headers: { Accept: 'application/json' } });
      if (res.status === 401) {
        redirect(loginUrl(currentPath()));
        return;
      }
      if (!res.ok) throw await apiErrorFrom(res);
      setMe(parseMe(await res.json()));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    }
    setLoading(false);
  }, [redirect]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void load();
  }, [load]);

  const logout = useCallback(async () => {
    let target = '/';
    try {
      const res = await apiFetch(LOGOUT_PATH, { method: 'POST', headers: { Accept: 'application/json' } });
      if (res.ok) {
        const body = (await res.json()) as unknown;
        const url = body && typeof body === 'object' ? safeRedirectTarget((body as { logoutUrl?: unknown }).logoutUrl) : null;
        if (url) target = url;
      }
    } catch {
      /* the server could not be reached: leave for the start page anyway */
    }
    redirect(target);
  }, [redirect]);

  const value = useMemo<AuthState>(() => ({ me, loading, error, refresh: load, logout }), [me, loading, error, load, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
