import { fireEvent, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ALICE, mockFetch, renderWithAuth } from '../test/render';
import { AppShellLayout } from './AppShellLayout';
import type { NavItem } from './nav';

const NAV: NavItem[] = [
  { label: 'Overview', href: '/', active: true },
  { label: 'Launches', href: '/launches', permission: 'launches:read' },
  { label: 'Team A launches', href: '/teams/team-a', permission: 'launches:write', scope: 'team-a' },
  { label: 'Team B launches', href: '/teams/team-b', permission: 'launches:write', scope: 'team-b' },
  { label: 'Settings', href: '/settings', permission: 'settings:write' },
];

function navLabels(): string[] {
  const nav = screen.getByRole('navigation', { name: 'Main' });
  return [...nav.querySelectorAll('a')].map((a) => a.textContent);
}

describe('AppShellLayout', () => {
  it('renders the product name and hides nav items without permission', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV}>
        <p>page content</p>
      </AppShellLayout>,
    );
    expect(screen.getByTestId('product-name')).toHaveTextContent('Example Reports');
    expect(screen.getByText('page content')).toBeInTheDocument();
    expect(navLabels()).toEqual(['Overview']);
    await waitFor(() => expect(screen.getByTestId('user-name')).toHaveTextContent('alice'));
    expect(navLabels()).toEqual(['Overview', 'Launches', 'Team A launches']);
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
  });

  it('navigates through onNavigate on plain clicks', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    const onNavigate = vi.fn();
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV} onNavigate={onNavigate} headerExtra={<span>extra</span>}>
        <p>page</p>
      </AppShellLayout>,
    );
    expect(screen.getByText('extra')).toBeInTheDocument();
    const link = await screen.findByRole('link', { name: 'Launches' });
    fireEvent.click(link);
    expect(onNavigate).toHaveBeenCalledWith('/launches');
  });

  it('names the search button by its visible text and announces the shortcut separately', () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV}>
        <p>page content</p>
      </AppShellLayout>,
    );
    const button = screen.getByTestId('open-palette');
    expect(button).not.toHaveAttribute('aria-label');
    expect(button).toHaveAccessibleName('Search or jump to…');
    expect(button).toHaveAttribute('aria-keyshortcuts', expect.stringMatching(/^(Control|Meta)\+K$/));
  });

  it('keeps the avatar initial out of the text of the account button so its label contains its visible text', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV}>
        <p>page content</p>
      </AppShellLayout>,
    );
    const button = await screen.findByTestId('user-menu');
    expect(button.querySelector('[data-initial]')).toHaveTextContent('');
    expect(button.querySelector('[data-initial]')?.getAttribute('data-initial')).toMatch(/^\S$/);
    expect(button.getAttribute('aria-label')).toContain(screen.getByTestId('user-name').textContent);
  });

  it('offers visible pages in the command palette', async () => {
    mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : undefined));
    const onNavigate = vi.fn();
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV} onNavigate={onNavigate}>
        <p>page</p>
      </AppShellLayout>,
    );
    await waitFor(() => expect(screen.getByTestId('user-name')).toHaveTextContent('alice'));
    fireEvent.click(screen.getByTestId('open-palette'));
    const input = await screen.findByTestId('palette-input');
    const items = screen.getAllByTestId('palette-item').map((el) => el.textContent);
    expect(items).toContain('Launches');
    expect(items).not.toContain('Settings');
    expect(items).toContain('Switch to light theme');
    fireEvent.change(input, { target: { value: 'team a' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onNavigate).toHaveBeenCalledWith('/teams/team-a');
  });

  it('signs out from the user menu', async () => {
    const calls = mockFetch((url) => (url.pathname === '/api/v1/me' ? { body: ALICE } : { body: { loggedOut: true } }));
    const redirect = vi.fn();
    renderWithAuth(
      <AppShellLayout productName="Example Reports" navItems={NAV}>
        <p>page</p>
      </AppShellLayout>,
      redirect,
    );
    fireEvent.click(await screen.findByTestId('user-menu'));
    fireEvent.click(await screen.findByTestId('logout'));
    await waitFor(() => expect(redirect).toHaveBeenCalledWith('/'));
    expect(calls.some((c) => c.method === 'POST' && c.url === '/auth/logout')).toBe(true);
  });
});
