import type { MantineColorScheme, MantineColorSchemeManager } from '@mantine/core';

/** The localStorage key that remembers the user's theme choice. */
export const COLOR_SCHEME_STORAGE_KEY = 'franshub-color-scheme';

/** The scheme used when the user has not chosen one. */
export const DEFAULT_COLOR_SCHEME = 'dark';

function isScheme(value: unknown): value is MantineColorScheme {
  return value === 'light' || value === 'dark' || value === 'auto';
}

/** The stored choice, or `null` when nothing (valid) is stored or storage cannot be read. */
export function readStoredColorScheme(key: string = COLOR_SCHEME_STORAGE_KEY): MantineColorScheme | null {
  try {
    const value = window.localStorage.getItem(key);
    return isScheme(value) ? value : null;
  } catch {
    return null;
  }
}

function writeStoredColorScheme(key: string, value: MantineColorScheme | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: the choice lasts for this page only */
  }
}

/**
 * A Mantine color scheme manager that keeps the choice in localStorage under `key` and follows changes made in
 * other tabs. Every storage access is guarded, so a browser that blocks storage still renders (in the default).
 */
export function franshubColorSchemeManager(key: string = COLOR_SCHEME_STORAGE_KEY): MantineColorSchemeManager {
  let listener: ((event: StorageEvent) => void) | null = null;
  return {
    get: (defaultValue) => readStoredColorScheme(key) ?? defaultValue,
    set: (value) => writeStoredColorScheme(key, value),
    subscribe: (onUpdate) => {
      listener = (event) => {
        if (event.key === key && isScheme(event.newValue)) onUpdate(event.newValue);
      };
      window.addEventListener('storage', listener);
    },
    unsubscribe: () => {
      if (listener) window.removeEventListener('storage', listener);
      listener = null;
    },
    clear: () => writeStoredColorScheme(key, null),
  };
}

/**
 * Sets the scheme attribute on `<html>` before React renders, so the first paint already has the right colors.
 * Call it once at startup, before `createRoot(...).render(...)`.
 */
export function applyInitialColorScheme(key: string = COLOR_SCHEME_STORAGE_KEY): void {
  const stored = readStoredColorScheme(key);
  const scheme = stored === 'light' || stored === 'dark' ? stored : DEFAULT_COLOR_SCHEME;
  document.documentElement.setAttribute('data-mantine-color-scheme', scheme);
}
