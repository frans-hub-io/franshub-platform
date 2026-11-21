import { useComputedColorScheme, useMantineColorScheme } from '@mantine/core';
import { useCallback } from 'react';

export interface ColorSchemeToggle {
  /** The scheme in effect now. */
  colorScheme: 'light' | 'dark';
  /** Switches to the other scheme and remembers the choice. */
  toggle: () => void;
  /** Selects a scheme and remembers the choice. */
  setColorScheme: (scheme: 'light' | 'dark') => void;
}

/** The current color scheme and a toggle that persists the user's choice. */
export function useColorSchemeToggle(): ColorSchemeToggle {
  const { setColorScheme } = useMantineColorScheme({ keepTransitions: true });
  const colorScheme = useComputedColorScheme('dark', { getInitialValueInEffect: false });
  const toggle = useCallback(() => setColorScheme(colorScheme === 'dark' ? 'light' : 'dark'), [colorScheme, setColorScheme]);
  return { colorScheme, toggle, setColorScheme };
}
