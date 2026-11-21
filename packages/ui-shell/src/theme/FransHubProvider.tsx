import { MantineProvider, mergeThemeOverrides, type MantineProviderProps, type MantineThemeOverride } from '@mantine/core';
import { useMemo } from 'react';
import { COLOR_SCHEME_STORAGE_KEY, DEFAULT_COLOR_SCHEME, franshubColorSchemeManager } from './colorScheme';
import { franshubCssVariablesResolver, franshubTheme } from './theme';

export interface FransHubProviderProps extends Omit<MantineProviderProps, 'theme' | 'colorSchemeManager'> {
  /** Overrides merged on top of `franshubTheme`. */
  theme?: MantineThemeOverride;
  /** The localStorage key for the theme choice; `franshub-color-scheme` by default. */
  colorSchemeKey?: string;
}

/**
 * MantineProvider with the FransHub theme. Dark is the default when the user has not chosen; the theme toggle's
 * choice is remembered in localStorage. The theme's CSS variables come from `@franshub/ui-shell/styles.css`, so no
 * style tag is injected (pass `withCssVariables` to change that).
 */
export function FransHubProvider({
  theme,
  colorSchemeKey = COLOR_SCHEME_STORAGE_KEY,
  defaultColorScheme = DEFAULT_COLOR_SCHEME,
  withCssVariables = false,
  withGlobalClasses = false,
  cssVariablesResolver = franshubCssVariablesResolver,
  children,
  ...rest
}: FransHubProviderProps) {
  const manager = useMemo(() => franshubColorSchemeManager(colorSchemeKey), [colorSchemeKey]);
  const merged = useMemo(() => (theme ? mergeThemeOverrides(franshubTheme, theme) : franshubTheme), [theme]);
  return (
    <MantineProvider
      {...rest}
      theme={merged}
      colorSchemeManager={manager}
      defaultColorScheme={defaultColorScheme}
      withCssVariables={withCssVariables}
      withGlobalClasses={withGlobalClasses}
      cssVariablesResolver={cssVariablesResolver}
    >
      {children}
    </MantineProvider>
  );
}
