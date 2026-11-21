# @franshub/ui-shell

The shared application frame of FransHub web UIs, for React 19 and Mantine 9:

- **Theme**: `franshubTheme` (brand palettes, Noto Sans and JetBrains Mono, radius and spacing scales, gold primary
  buttons), `FransHubProvider` (dark by default; the user's choice is remembered in `localStorage` under
  `franshub-color-scheme`), `useColorSchemeToggle()` and `ThemeToggle`.
- **Layout**: `AppShellLayout` with a header (logo, product name, command palette trigger, theme toggle, user menu with
  sign-out), a sidebar navigation that hides items the user may not use, and the page content.
- **Command palette**: `CommandPalette`, opened with Ctrl+K (Cmd+K on macOS).
- **Authentication**: `AuthProvider` and `useMe()` load `GET /api/v1/me` once and send the browser to `/auth/login`
  on 401. `useCan()`, `<Can>` and the pure `can()` check permissions. `apiFetch()` adds the CSRF header
  (`CSRF_HEADER`) to unsafe requests.
- **States**: `ErrorState` and `EmptyState`.

## Install

```sh
npm install @franshub/ui-shell @mantine/core @mantine/hooks react react-dom
```

`react`, `react-dom`, `@mantine/core` and `@mantine/hooks` are peer dependencies.

## Usage

```tsx
import '@mantine/core/styles.css';
import '@franshub/ui-shell/styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AppShellLayout,
  applyInitialColorScheme,
  AuthProvider,
  Can,
  EmptyState,
  FransHubProvider,
  type CommandItem,
  type NavItem,
} from '@franshub/ui-shell';

const nav: NavItem[] = [
  { label: 'Overview', href: '/', active: true },
  { label: 'Launches', href: '/launches', permission: 'launches:read' },
  { label: 'Team A', href: '/teams/team-a', permission: 'launches:write', scope: 'team-a' },
];

const commands: CommandItem[] = [
  { id: 'docs', label: 'Open the documentation', group: 'Help', keywords: ['help'], onSelect: () => window.open('https://docs.example.com') },
];

function App() {
  return (
    <AppShellLayout productName="Example Reports" navItems={nav} commands={commands}>
      <EmptyState
        title="No launches yet"
        description="Run your tests to see them here."
        action={
          <Can perm="launches:write" scope="team-a">
            <button type="button">Create a launch</button>
          </Can>
        }
      />
    </AppShellLayout>
  );
}

applyInitialColorScheme();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <FransHubProvider>
      <AuthProvider>
        <App />
      </AuthProvider>
    </FransHubProvider>
  </StrictMode>,
);
```

Import `@mantine/core/styles.css` before `@franshub/ui-shell/styles.css`. The package stylesheet carries the brand
tokens, the theme's CSS variables and the fonts (served from `fonts/` next to it, with their OFL licence texts), so
`FransHubProvider` injects no style tag by default, which suits a strict Content Security Policy. If you override
theme values that produce CSS variables, pass `withCssVariables` to `FransHubProvider`.

With a client-side router, pass its navigate function as `onNavigate`; plain clicks on nav links and palette
selections then call it instead of loading the page.

## Permissions

`/api/v1/me` returns `permissions: { global, scopes, allScopes }`. A check without a scope uses only `global`; a check
in scope `S` uses `global ∪ allScopes ∪ scopes[S]`. Permission names match exactly.

```ts
can(me, 'launches:read');            // global only
can(me, 'launches:write', 'team-a'); // global, all scopes, or team-a
```

## Development

```sh
npm install
npm run lint
npm run typecheck
npm test
npm run build
```

`src/styles/mantine-theme.css` is generated from `src/theme/theme.ts` by `src/theme/theme.test.tsx`; after changing the
theme run `npx vitest run src/theme/theme.test.tsx -u`.

## License

Apache-2.0. The bundled Noto Sans and JetBrains Mono fonts are under the SIL Open Font License 1.1.
