import type { ApiErrorBody, Me, MePermissions } from './types';

/** The header that cookie-authenticated requests other than GET and HEAD must carry (CSRF protection). */
export const CSRF_HEADER = 'X-FransHub-Request';

export const ME_PATH = '/api/v1/me';
export const LOGIN_PATH = '/auth/login';
export const LOGOUT_PATH = '/auth/logout';

function methodOf(input: RequestInfo | URL, init: RequestInit | undefined): string {
  return (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
}

/**
 * `fetch` for same-origin API calls: sends cookies (`credentials: 'same-origin'` unless given) and adds the
 * `X-FransHub-Request: 1` header to every method other than GET and HEAD.
 */
export function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
  const method = methodOf(input, init);
  if (method !== 'GET' && method !== 'HEAD') headers.set(CSRF_HEADER, '1');
  return fetch(input, { ...init, credentials: init?.credentials ?? 'same-origin', headers });
}

/** An API error answer: the HTTP status plus the `{ code, message, details }` body when the server sent one. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(status: number, body: Partial<ApiErrorBody> = {}) {
    super(body.message || `Request failed with status ${String(status)}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = body.code ?? 'http_error';
    this.details = body.details;
  }
}

/** Builds an `ApiError` from a failed response, reading the error body when it is JSON. */
export async function apiErrorFrom(res: Response): Promise<ApiError> {
  try {
    const body = (await res.json()) as unknown;
    if (body && typeof body === 'object') {
      const b = body as Record<string, unknown>;
      return new ApiError(res.status, {
        code: typeof b.code === 'string' ? b.code : undefined,
        message: typeof b.message === 'string' ? b.message : undefined,
        details: b.details,
      });
    }
  } catch {
    /* not JSON */
  }
  return new ApiError(res.status);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : [];
}

function scopeLists(value: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  if (!value || typeof value !== 'object') return out;
  for (const [k, v] of Object.entries(value)) out[k] = strings(v);
  return out;
}

/** Normalises a `/api/v1/me` body: missing lists become empty, values of the wrong type are dropped. */
export function parseMe(body: unknown): Me {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const p = (b.permissions && typeof b.permissions === 'object' ? b.permissions : {}) as Record<string, unknown>;
  const permissions: MePermissions = { global: strings(p.global), scopes: scopeLists(p.scopes), allScopes: strings(p.allScopes) };
  const me: Me = {
    name: typeof b.name === 'string' ? b.name : '',
    kind: b.kind === 'user' || b.kind === 'apiToken' ? b.kind : 'token',
    authMethod: b.authMethod === 'session' || b.authMethod === 'staticToken' || b.authMethod === 'managedToken' ? b.authMethod : 'bearer',
    roles: strings(b.roles),
    permissions,
  };
  if (Array.isArray(b.groups)) me.groups = strings(b.groups);
  if (typeof b.tokenId === 'string') me.tokenId = b.tokenId;
  return me;
}

/**
 * A redirect target that is safe to follow: a same-origin path (`/x`, not `//host`) or an absolute http(s) URL,
 * such as an identity provider's end-session URL. Anything else yields `null`.
 */
export function safeRedirectTarget(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null;
  if (value.startsWith('/')) return value.startsWith('//') || value.startsWith('/\\') ? null : value;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null;
  } catch {
    return null;
  }
}

/** The login URL that brings the user back to `returnTo` afterwards. */
export function loginUrl(returnTo: string): string {
  return `${LOGIN_PATH}?return=${encodeURIComponent(returnTo)}`;
}
