export { franshubTheme, franshubCssVariablesResolver } from './theme/theme';
export { FransHubProvider, type FransHubProviderProps } from './theme/FransHubProvider';
export { useColorSchemeToggle, type ColorSchemeToggle } from './theme/useColorSchemeToggle';
export { ThemeToggle } from './theme/ThemeToggle';
export {
  COLOR_SCHEME_STORAGE_KEY,
  DEFAULT_COLOR_SCHEME,
  applyInitialColorScheme,
  franshubColorSchemeManager,
  readStoredColorScheme,
} from './theme/colorScheme';

export { AppShellLayout, type AppShellLayoutProps } from './components/AppShellLayout';
export { visibleNavItems, type NavItem } from './components/nav';
export { CommandPalette, type CommandPaletteProps } from './components/CommandPalette';
export { filterCommands, matchesQuery, type CommandItem } from './components/commands';
export { ErrorState, EmptyState, type ErrorStateProps, type EmptyStateProps } from './components/States';

export { AuthProvider, type AuthProviderProps } from './auth/AuthProvider';
export type { AuthState } from './auth/context';
export { useMe, useCan } from './auth/useMe';
export { Can, type CanProps } from './auth/PermissionGate';
export { can } from './auth/permissions';
export {
  ApiError,
  CSRF_HEADER,
  LOGIN_PATH,
  LOGOUT_PATH,
  ME_PATH,
  apiErrorFrom,
  apiFetch,
  loginUrl,
  parseMe,
  safeRedirectTarget,
} from './auth/api';
export type { ApiErrorBody, AuthMethod, LogoutResponse, Me, MePermissions, PrincipalKind } from './auth/types';
