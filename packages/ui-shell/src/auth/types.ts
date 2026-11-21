/** Who the caller is: a signed-in user, a static token or a managed API token. */
export type PrincipalKind = 'user' | 'token' | 'apiToken';

/** How the caller authenticated. */
export type AuthMethod = 'session' | 'bearer' | 'staticToken' | 'managedToken';

/** `resource:action` permission names, by where they apply. */
export interface MePermissions {
  /** Held everywhere, including global-only operations. */
  global: string[];
  /** Held in one scope, keyed by scope name. */
  scopes: Record<string, string[]>;
  /** Held in every scope (but not for global-only operations). */
  allScopes: string[];
}

/** The `GET /api/v1/me` answer. */
export interface Me {
  name: string;
  kind: PrincipalKind;
  authMethod: AuthMethod;
  groups?: string[];
  roles: string[];
  tokenId?: string;
  permissions: MePermissions;
}

/** The JSON body of every error answer of the API. */
export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

/** The `POST /auth/logout` answer. */
export interface LogoutResponse {
  loggedOut: boolean;
  logoutUrl?: string;
}
