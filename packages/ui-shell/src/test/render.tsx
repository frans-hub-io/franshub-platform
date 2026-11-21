import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { vi } from 'vitest';
import { AuthProvider } from '../auth/AuthProvider';
import { FransHubProvider } from '../theme/FransHubProvider';

export interface Call {
  method: string;
  url: string;
  headers: Headers;
  credentials: RequestCredentials;
}

export type Handler = (url: URL, method: string) => { status?: number; body?: unknown } | undefined;

/** Replaces `fetch` with `handler` and records every call. */
export function mockFetch(handler: Handler): Call[] {
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(new URL(String(input), 'http://localhost'), init);
    const url = new URL(req.url, 'http://localhost');
    calls.push({ method: req.method, url: url.pathname + url.search, headers: req.headers, credentials: init?.credentials ?? req.credentials });
    const r = handler(url, req.method) ?? { status: 404, body: { code: 'not_found', message: 'not found' } };
    const status = r.status ?? 200;
    return Promise.resolve(new Response(JSON.stringify(r.body ?? {}), { status, headers: { 'content-type': 'application/json' } }));
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

export const ALICE = {
  name: 'alice',
  kind: 'user',
  authMethod: 'session',
  groups: ['qa'],
  roles: ['viewer'],
  permissions: { global: ['launches:read'], scopes: { 'team-a': ['launches:write'] }, allScopes: ['dashboards:read'] },
};

export function renderThemed(ui: ReactElement) {
  return render(<FransHubProvider env="test">{ui}</FransHubProvider>);
}

export function renderWithAuth(ui: ReactElement, redirect: (url: string) => void = vi.fn()) {
  return render(
    <FransHubProvider env="test">
      <AuthProvider redirect={redirect}>{ui}</AuthProvider>
    </FransHubProvider>,
  );
}
