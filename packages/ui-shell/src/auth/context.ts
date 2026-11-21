import { createContext } from 'react';
import type { Me } from './types';

export interface AuthState {
  /** The signed-in principal, `null` until loaded or when loading failed. */
  me: Me | null;
  /** True while `/api/v1/me` is being fetched (and while redirecting to the login page). */
  loading: boolean;
  /** Why the last fetch failed, other than a 401 (which redirects to the login page). */
  error: Error | null;
  /** Fetches `/api/v1/me` again. */
  refresh: () => Promise<void>;
  /** Ends the session on the server, then leaves for the identity provider's logout page or `/`. */
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);
