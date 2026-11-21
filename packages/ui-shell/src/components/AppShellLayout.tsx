import { ActionIcon, Burger, Drawer, Group, Loader, Menu, NavLink, ScrollArea, Text, UnstyledButton } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useMemo, type MouseEvent, type ReactNode } from 'react';
import { useMe } from '../auth/useMe';
import type { PrincipalKind } from '../auth/types';
import { ThemeToggle } from '../theme/ThemeToggle';
import { useColorSchemeToggle } from '../theme/useColorSchemeToggle';
import classes from './AppShellLayout.module.css';
import { CommandPalette } from './CommandPalette';
import type { CommandItem } from './commands';
import { IconLogout, IconSearch } from './icons';
import { visibleNavItems, type NavItem } from './nav';

export interface AppShellLayoutProps {
  productName: string;
  /** Shown before the product name; a slanted monogram of its first letter by default. */
  logo?: ReactNode;
  navItems: NavItem[];
  /**
   * Client-side navigation (for example a router's `navigate`). Plain clicks on nav links and palette selections
   * call it instead of loading the page; without it they are ordinary links.
   */
  onNavigate?: (href: string) => void;
  children: ReactNode;
  /** Extra controls in the header, before the theme toggle. */
  headerExtra?: ReactNode;
  /** More command palette entries, after the pages and the theme switch. */
  commands?: CommandItem[];
  /** Where the logo links to; `/` by default. */
  homeHref?: string;
}

const KIND_LABEL: Record<PrincipalKind, string> = { user: 'User', token: 'Token', apiToken: 'API token' };

function isPlainClick(e: MouseEvent): boolean {
  return e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey;
}

function isMac(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad/i.test(navigator.userAgent);
}

function SearchButton({ onOpen }: { onOpen: () => void }) {
  const mod = isMac() ? '⌘' : 'Ctrl';
  return (
    <>
      <UnstyledButton className={classes.search} onClick={onOpen} aria-label={`Search (${mod}+K)`} data-testid="open-palette" visibleFrom="sm">
        <IconSearch size={16} />
        <span className={classes.searchText}>Search or jump to…</span>
        <span className="fh-kbd" aria-hidden>
          {mod} K
        </span>
      </UnstyledButton>
      <ActionIcon variant="default" size="lg" onClick={onOpen} aria-label="Search" hiddenFrom="sm">
        <IconSearch size={18} />
      </ActionIcon>
    </>
  );
}

function UserMenu() {
  const { me, loading, logout } = useMe();
  if (!me) return loading ? <Loader size="sm" aria-label="Loading account" /> : null;
  const who = me.name || 'anonymous';
  return (
    <Menu position="bottom-end" withArrow width={260}>
      <Menu.Target>
        <UnstyledButton aria-label={`Account: ${who}`} data-testid="user-menu" className={classes.principal}>
          <Group gap={8} wrap="nowrap">
            <span className={classes.avatar} aria-hidden>
              {(who.trim()[0] ?? '?').toUpperCase()}
            </span>
            <Text size="sm" fw={500} visibleFrom="sm" className="fh-truncate" maw={160} data-testid="user-name">
              {who}
            </Text>
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Signed in as</Menu.Label>
        <div className={classes.who}>
          <Text size="sm" fw={600} className="fh-truncate" title={who}>
            {who}
          </Text>
          <Text size="xs" c="dimmed">
            {KIND_LABEL[me.kind]}
          </Text>
          {me.groups && me.groups.length > 0 && (
            <Text size="xs" c="dimmed" lineClamp={3}>
              Groups: {me.groups.join(', ')}
            </Text>
          )}
        </div>
        <Menu.Divider />
        <Menu.Item leftSection={<IconLogout size={16} />} color="red" onClick={() => void logout()} data-testid="logout">
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

function Nav({ items, onFollow }: { items: NavItem[]; onFollow: (e: MouseEvent, href: string) => void }) {
  return (
    <nav aria-label="Main" className={classes.nav}>
      {items.map((i) => (
        <NavLink
          key={i.href}
          component="a"
          href={i.href}
          label={i.label}
          leftSection={i.icon}
          active={i.active}
          aria-current={i.active ? 'page' : undefined}
          onClick={(e) => onFollow(e, i.href)}
          variant="light"
          className={classes.navLink}
        />
      ))}
    </nav>
  );
}

/**
 * The FransHub application frame: a header (logo, product name, command palette trigger, extra controls, theme
 * toggle, user menu), a sidebar with the navigation (a drawer on small screens) and the page content.
 * Nav items with a permission the signed-in principal lacks are hidden. Must be used inside `AuthProvider`.
 */
export function AppShellLayout({ productName, logo, navItems, onNavigate, children, headerExtra, commands, homeHref = '/' }: AppShellLayoutProps) {
  const [drawer, drawerCtl] = useDisclosure(false);
  const [palette, setPalette] = useDisclosure(false);
  const { me } = useMe();
  const { colorScheme, toggle } = useColorSchemeToggle();
  const items = useMemo(() => visibleNavItems(navItems, me), [navItems, me]);

  const go = (href: string) => {
    if (onNavigate) onNavigate(href);
    else window.location.assign(href);
  };

  const follow = (e: MouseEvent, href: string) => {
    drawerCtl.close();
    if (!onNavigate || !isPlainClick(e)) return;
    e.preventDefault();
    onNavigate(href);
  };

  const next = colorScheme === 'dark' ? 'light' : 'dark';
  const paletteItems: CommandItem[] = [
    ...items.map((i) => ({ id: `page:${i.href}`, label: i.label, group: 'Pages', keywords: [i.href], onSelect: () => go(i.href) })),
    { id: 'action:theme', label: `Switch to ${next} theme`, group: 'Actions', keywords: ['theme', 'dark', 'light', 'mode'], onSelect: toggle },
    ...(commands ?? []),
  ];

  return (
    <div className={classes.root}>
      <a href="#main" className={classes.skip}>
        Skip to content
      </a>
      <header className={classes.header}>
        <Group gap="sm" wrap="nowrap" className={classes.headerLeft}>
          <Burger opened={drawer} onClick={drawerCtl.toggle} hiddenFrom="md" size="sm" aria-label="Toggle navigation" />
          <a href={homeHref} className={classes.brand} aria-label={productName} onClick={(e) => follow(e, homeHref)}>
            <span className={classes.logo}>
              {logo ?? (
                <span className={classes.mark} aria-hidden>
                  {(productName.trim()[0] ?? 'F').toUpperCase()}
                </span>
              )}
            </span>
            <span className={classes.productName} data-testid="product-name">
              {productName}
            </span>
          </a>
          <div className={classes.searchSlot}>
            <SearchButton onOpen={setPalette.open} />
          </div>
        </Group>
        <Group gap="xs" wrap="nowrap" className={classes.headerRight}>
          {headerExtra}
          <ThemeToggle />
          <UserMenu />
        </Group>
      </header>
      <div className={classes.body}>
        <div className={classes.sideCol}>
          <aside className={classes.sidebar}>
            <ScrollArea className={classes.sideScroll} scrollbarSize={6} type="hover">
              <Nav items={items} onFollow={follow} />
            </ScrollArea>
          </aside>
        </div>
        <Drawer opened={drawer} onClose={drawerCtl.close} size={288} title={productName} hiddenFrom="md" classNames={{ body: classes.drawerBody }}>
          <Nav items={items} onFollow={follow} />
        </Drawer>
        <main id="main" className={classes.main} tabIndex={-1}>
          <div className={classes.mainInner}>{children}</div>
        </main>
      </div>
      <CommandPalette items={paletteItems} opened={palette} onOpenChange={(o) => (o ? setPalette.open() : setPalette.close())} />
    </div>
  );
}
