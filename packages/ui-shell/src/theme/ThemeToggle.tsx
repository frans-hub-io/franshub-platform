import { ActionIcon, Tooltip } from '@mantine/core';
import { IconMoon, IconSun } from '../components/icons';
import { useColorSchemeToggle } from './useColorSchemeToggle';

/** A header button that switches between the dark and light themes. */
export function ThemeToggle() {
  const { colorScheme, toggle } = useColorSchemeToggle();
  const next = colorScheme === 'dark' ? 'light' : 'dark';
  const label = `Switch to ${next} theme`;
  return (
    <Tooltip label={label} withArrow>
      <ActionIcon variant="default" size="lg" onClick={toggle} aria-label={label} data-testid="theme-toggle">
        {colorScheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
      </ActionIcon>
    </Tooltip>
  );
}
