import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ALICE, mockFetch, renderWithAuth } from '../test/render';
import { parseMe } from './api';
import { Can } from './PermissionGate';
import { can } from './permissions';
import { useCan } from './useMe';

const me = parseMe({
  name: 'alice',
  kind: 'user',
  authMethod: 'session',
  roles: [],
  permissions: {
    global: ['launches:read'],
    scopes: { 'team-a': ['launches:write'], 'team-b': ['reports:delete'] },
    allScopes: ['dashboards:read'],
  },
});

describe('can', () => {
  it('denies everything without a principal', () => {
    expect(can(null, 'launches:read')).toBe(false);
    expect(can(undefined, 'launches:read', 'team-a')).toBe(false);
  });

  it('checks only global permissions without a scope', () => {
    expect(can(me, 'launches:read')).toBe(true);
    expect(can(me, 'launches:write')).toBe(false);
    expect(can(me, 'dashboards:read')).toBe(false);
  });

  it('combines global, allScopes and the scope in a scope', () => {
    expect(can(me, 'launches:read', 'team-a')).toBe(true);
    expect(can(me, 'dashboards:read', 'team-a')).toBe(true);
    expect(can(me, 'dashboards:read', 'unknown')).toBe(true);
    expect(can(me, 'launches:write', 'team-a')).toBe(true);
    expect(can(me, 'launches:write', 'team-b')).toBe(false);
    expect(can(me, 'reports:delete', 'team-a')).toBe(false);
    expect(can(me, 'reports:delete', 'team-b')).toBe(true);
  });

  it('matches names exactly and ignores inherited object keys', () => {
    expect(can(me, 'launches')).toBe(false);
    expect(can(me, 'launches:*')).toBe(false);
    expect(can(me, 'toString', 'constructor')).toBe(false);
    expect(can(me, 'launches:write', '__proto__')).toBe(false);
  });

  it('tolerates missing permission lists', () => {
    const bare = parseMe({ name: 'bob', kind: 'token', authMethod: 'bearer' });
    expect(bare.permissions).toEqual({ global: [], scopes: {}, allScopes: [] });
    expect(bare.roles).toEqual([]);
    expect(can(bare, 'launches:read', 'team-a')).toBe(false);
  });
});

function Probe({ perm, scope }: { perm: string; scope?: string }) {
  return <span data-testid={`${perm}@${scope ?? 'global'}`}>{String(useCan(perm, scope))}</span>;
}

describe('useCan and Can', () => {
  it('follow the loaded principal', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    renderWithAuth(
      <>
        <Probe perm="launches:write" />
        <Probe perm="launches:write" scope="team-a" />
        <Probe perm="dashboards:read" scope="team-z" />
        <Can perm="launches:read">
          <span>can read</span>
        </Can>
        <Can perm="launches:write" fallback={<span>read only</span>}>
          <span>can write</span>
        </Can>
        <Can perm="launches:write" scope="team-a">
          <span>can write in team-a</span>
        </Can>
      </>,
    );
    expect(screen.getByTestId('launches:write@team-a')).toHaveTextContent('false');
    await waitFor(() => expect(screen.getByTestId('launches:write@team-a')).toHaveTextContent('true'));
    expect(screen.getByTestId('launches:write@global')).toHaveTextContent('false');
    expect(screen.getByTestId('dashboards:read@team-z')).toHaveTextContent('true');
    expect(screen.getByText('can read')).toBeInTheDocument();
    expect(screen.getByText('read only')).toBeInTheDocument();
    expect(screen.queryByText('can write')).not.toBeInTheDocument();
    expect(screen.getByText('can write in team-a')).toBeInTheDocument();
  });
});
