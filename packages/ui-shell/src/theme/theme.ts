import { Button, createTheme, Drawer, Modal, rem, SegmentedControl, Tooltip, type CSSVariablesResolver, type MantineColorsTuple } from '@mantine/core';

// FransHub brand kit v5.0 palettes (purple, yellow, graphite).
const fhPurple: MantineColorsTuple = ['#F6EDFF', '#EAD5FF', '#DBB6FF', '#C78BFF', '#B36CF9', '#9948EA', '#7C2ACB', '#6920AC', '#57158E', '#3F0B69'];
const fhYellow: MantineColorsTuple = ['#FFFDF0', '#FFF7C4', '#FFEE91', '#FFE45A', '#FFDC31', '#FFD028', '#F5BD00', '#D59E00', '#A87800', '#765100'];
const gray: MantineColorsTuple = ['#F8F6FC', '#EDE8F4', '#D5CEE1', '#B6ADC3', '#8D829A', '#686075', '#50485C', '#393344', '#282230', '#1A1522'];
// Mantine's dark scale runs from text (0) to the darkest surface (9); steps 4 and 6-9 are the kit's dark border,
// raised surface, surface, canvas and code background.
const dark: MantineColorsTuple = ['#EDE8F4', '#D5CEE1', '#B6ADC3', '#8D829A', '#655673', '#4A4157', '#393144', '#282230', '#1A1522', '#15101D'];
// Mantine red with the kit's danger colours as the filled shades, so danger buttons keep white text.
const red: MantineColorsTuple = ['#FFF5F5', '#FFE3E3', '#FFC9C9', '#FFA8A8', '#FF8787', '#FF6B6B', '#FA5252', '#B04135', '#962D24', '#7A231C'];

const SANS = "'Noto Sans', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";
const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

/**
 * The FransHub Mantine theme: brand palettes, Noto Sans and JetBrains Mono, the brand radius and spacing scales and
 * gold primary buttons. Its CSS variables ship in `styles.css`, so `FransHubProvider` does not inject a style tag.
 */
export const franshubTheme = createTheme({
  primaryColor: 'fhPurple',
  primaryShade: { light: 7, dark: 7 },
  colors: { fhPurple, fhYellow, gray, dark, red },
  autoContrast: true,
  // Black or white text, whichever contrasts more with a filled color: both stay at 4.5:1 or above.
  luminanceThreshold: 0.179,
  defaultRadius: 'md',
  radius: { xs: rem(4), sm: rem(6), md: rem(10), lg: rem(16), xl: rem(16) },
  spacing: { xs: rem(8), sm: rem(12), md: rem(16), lg: rem(24), xl: rem(32) },
  // Shadows follow the scheme: global.css defines --fh-ui-shadow-* for light and dark.
  shadows: { xs: 'var(--fh-ui-shadow-xs)', sm: 'var(--fh-ui-shadow-sm)', md: 'var(--fh-ui-shadow-md)', lg: 'var(--fh-ui-shadow-lg)', xl: 'var(--fh-ui-shadow-xl)' },
  cursorType: 'pointer',
  fontFamily: SANS,
  fontFamilyMonospace: MONO,
  headings: { fontFamily: SANS, fontWeight: '800' },
  components: {
    Tooltip: Tooltip.extend({ defaultProps: { withArrow: true } }),
    Modal: Modal.extend({ defaultProps: { radius: 'lg', overlayProps: { backgroundOpacity: 0.45, blur: 2 }, closeButtonProps: { 'aria-label': 'Close' } } }),
    Drawer: Drawer.extend({ defaultProps: { overlayProps: { backgroundOpacity: 0.45, blur: 2 }, closeButtonProps: { 'aria-label': 'Close' } } }),
    SegmentedControl: SegmentedControl.extend({ defaultProps: { radius: 'md' } }),
    // Primary actions are gold with dark on-accent text; other variants and explicit colors keep Mantine's rules.
    Button: Button.extend({
      vars: (t, props) => {
        const filled = (props.variant ?? 'filled') === 'filled';
        if (!filled || (props.color && props.color !== t.primaryColor)) return { root: {} };
        return {
          root: {
            '--button-bg': 'var(--fh-color-accent)',
            '--button-hover': 'var(--fh-color-button-hover)',
            '--button-color': 'var(--fh-color-on-accent)',
            '--button-hover-color': 'var(--fh-color-on-accent)',
            '--button-bd': `${rem(1)} solid transparent`,
          },
        };
      },
    }),
  },
});

const SEMANTIC: Record<string, string> = { red: 'danger', orange: 'warning', yellow: 'warning', green: 'success', blue: 'info', cyan: 'info' };

/**
 * Scheme variables on top of Mantine's defaults. The values point at the brand tokens (`--fh-*`), which follow
 * the color scheme, so the same values serve both schemes.
 */
export const franshubCssVariablesResolver: CSSVariablesResolver = () => {
  const shared: Record<string, string> = {
    '--mantine-color-body': 'var(--fh-color-surface)',
    '--mantine-color-text': 'var(--fh-color-text)',
    '--mantine-color-bright': 'var(--fh-color-text)',
    '--mantine-color-anchor': 'var(--fh-color-link)',
    '--mantine-color-dimmed': 'var(--fh-color-text-muted)',
    '--mantine-color-default': 'var(--fh-color-surface-raised)',
    '--mantine-color-default-color': 'var(--fh-color-text)',
    '--mantine-color-default-border': 'var(--fh-color-border)',
    '--mantine-color-error': 'var(--fh-semantic-danger-fg)',
    '--mantine-color-success': 'var(--fh-semantic-success-fg)',
    '--mantine-color-disabled': 'var(--fh-color-button-disabled)',
    '--mantine-color-disabled-color': 'var(--fh-color-button-disabled-fg)',
    '--mantine-color-disabled-border': 'var(--fh-color-border)',
  };
  for (const [color, tone] of Object.entries(SEMANTIC)) {
    shared[`--mantine-color-${color}-light`] = `var(--fh-semantic-${tone}-bg)`;
    shared[`--mantine-color-${color}-light-color`] = `var(--fh-semantic-${tone}-fg)`;
  }
  return {
    variables: {},
    light: {
      ...shared,
      '--mantine-color-default-hover': 'var(--mantine-color-gray-1)',
      '--mantine-color-placeholder': 'var(--mantine-color-gray-5)',
    },
    dark: {
      ...shared,
      '--mantine-color-default-hover': 'var(--mantine-color-dark-5)',
      '--mantine-color-placeholder': 'var(--mantine-color-dark-2)',
      // Purple 5 keeps white text above 4.5:1 and the fill above 3:1 against the dark surfaces.
      '--mantine-color-fhPurple-filled': 'var(--mantine-color-fhPurple-5)',
      '--mantine-color-fhPurple-filled-hover': 'var(--mantine-color-fhPurple-6)',
      '--mantine-color-fhPurple-light': 'var(--fh-color-selection)',
      '--mantine-color-fhPurple-light-hover': 'var(--mantine-color-fhPurple-8)',
    },
  };
};
