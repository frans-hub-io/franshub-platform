import { act, screen, waitFor } from '@testing-library/react';
import { useEffect } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ALICE, mockFetch, renderWithAuth } from '../test/render';
import { apiFetch, CSRF_HEADER } from './api';
import type { AuthState } from './context';
import { useMe } from './useMe';

let state: AuthState | null = null;

function Probe() {
  const current = useMe();
  useEffect(() => {
    state = current;
  });
  return <span data-testid="who">{current.loading ? 'loading' : (current.me?.name ?? current.error?.message ?? 'none')}</span>;
}

afterEach(() => {
  state = null;
  window.history.replaceState(null, '', '/');
});

describe('AuthProvider', () => {
  it('loads /api/v1/me once with same-origin credentials', async () => {
    const calls = mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    renderWithAuth(<Probe />);
    expect(screen.getByTestId('who')).toHaveTextContent('loading');
    await waitFor(() => expect(screen.getByTestId('who')).toHaveTextContent('alice'));
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toBe('/api/v1/me');
    expect(calls[0]?.credentials).toBe('same-origin');
    expect(calls[0]?.headers.has(CSRF_HEADER)).toBe(false);
    expect(state?.me).toMatchObject({ name: 'alice', kind: 'user', authMethod: 'session', groups: ['qa'], roles: ['viewer'] });
    expect(state?.error).toBeNull();
  });

  it('redirects to the login page on 401, returning to the current path', async () => {
    window.history.replaceState(null, '', '/launches/42?tab=logs#top');
    mockFetch(() => ({ status: 401, body: { code: 'unauthenticated', message: 'sign in' } }));
    const redirect = vi.fn();
    renderWithAuth(<Probe />, redirect);
    await waitFor(() => expect(redirect).toHaveBeenCalledTimes(1));
    expect(redirect).toHaveBeenCalledWith(`/auth/login?return=${encodeURIComponent('/launches/42?tab=logs#top')}`);
    expect(state?.me).toBeNull();
    expect(state?.loading).toBe(true);
  });

  it('exposes other failures as an error and refreshes on demand', async () => {
    let fail = true;
    const calls = mockFetch(() => (fail ? { status: 500, body: { code: 'internal', message: 'database unavailable' } } : { body: ALICE }));
    const redirect = vi.fn();
    renderWithAuth(<Probe />, redirect);
    await waitFor(() => expect(screen.getByTestId('who')).toHaveTextContent('database unavailable'));
    expect(state?.error).toMatchObject({ name: 'ApiError', status: 500, code: 'internal' });
    fail = false;
    await act(async () => {
      await state?.refresh();
    });
    expect(screen.getByTestId('who')).toHaveTextContent('alice');
    expect(state?.error).toBeNull();
    expect(calls).toHaveLength(2);
    expect(redirect).not.toHaveBeenCalled();
  });

  it('logs out with the CSRF header and follows the logout URL', async () => {
    const calls = mockFetch((url, method) => {
      if (url.pathname === '/api/v1/me') return { body: ALICE };
      if (url.pathname === '/auth/logout' && method === 'POST') return { body: { loggedOut: true, logoutUrl: 'https://id.example.com/logout?x=1' } };
      return undefined;
    });
    const redirect = vi.fn();
    renderWithAuth(<Probe />, redirect);
    await waitFor(() => expect(screen.getByTestId('who')).toHaveTextContent('alice'));
    await act(async () => {
      await state?.logout();
    });
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.url).toBe('/auth/logout');
    expect(post?.headers.get(CSRF_HEADER)).toBe('1');
    expect(post?.credentials).toBe('same-origin');
    expect(redirect).toHaveBeenCalledWith('https://id.example.com/logout?x=1');
  });

  it('goes to / after logout without a usable logout URL', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : { body: { loggedOut: true, logoutUrl: 'javascript:alert(1)' } }));
    const redirect = vi.fn();
    renderWithAuth(<Probe />, redirect);
    await waitFor(() => expect(screen.getByTestId('who')).toHaveTextContent('alice'));
    await act(async () => {
      await state?.logout();
    });
    expect(redirect).toHaveBeenCalledWith('/');
  });
});

describe('apiFetch', () => {
  it('adds the CSRF header only to unsafe methods', async () => {
    const calls = mockFetch(() => ({ body: {} }));
    await apiFetch('/api/v1/launches');
    await apiFetch('/api/v1/launches', { method: 'delete', headers: { 'Content-Type': 'application/json' } });
    expect(calls[0]?.headers.has(CSRF_HEADER)).toBe(false);
    expect(calls[0]?.credentials).toBe('same-origin');
    expect(calls[1]?.headers.get(CSRF_HEADER)).toBe('1');
    expect(calls[1]?.headers.get('content-type')).toBe('application/json');
  });
});
