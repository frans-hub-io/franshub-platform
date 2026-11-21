import { Alert, Button, Center, Group, Stack, Text } from '@mantine/core';
import { useId, type ReactNode } from 'react';
import { IconAlertTriangle, IconInbox } from './icons';
import classes from './States.module.css';

export interface ErrorStateProps {
  /** Headline; `Something went wrong` by default. */
  title?: string;
  /** What failed, in words the user understands. */
  message: ReactNode;
  /** Shows a retry button that calls this. */
  onRetry?: () => void;
  retryLabel?: string;
}

/** A failed load or action, with an optional retry. */
export function ErrorState({ title = 'Something went wrong', message, onRetry, retryLabel = 'Retry' }: ErrorStateProps) {
  return (
    <Alert color="red" icon={<IconAlertTriangle size={18} />} title={title} role="alert" data-testid="error-state">
      <Stack gap="xs">
        <Text size="sm" component="div">
          {message}
        </Text>
        {onRetry && (
          <Group>
            <Button size="xs" variant="light" onClick={onRetry}>
              {retryLabel}
            </Button>
          </Group>
        )}
      </Stack>
    </Alert>
  );
}

/** A self-made illustration from the brand's shapes: two slanted cards (the monogram's italic), a gold dot. */
function Illustration({ icon }: { icon: ReactNode }) {
  const id = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  return (
    <div className={classes.art} aria-hidden>
      <svg viewBox="0 0 160 120" width="160" height="120" focusable="false">
        <defs>
          <linearGradient id={`${id}f`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" className={classes.fransA} />
            <stop offset="1" className={classes.fransB} />
          </linearGradient>
          <linearGradient id={`${id}h`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" className={classes.hubA} />
            <stop offset="1" className={classes.hubB} />
          </linearGradient>
        </defs>
        <ellipse cx="80" cy="66" rx="72" ry="46" className={classes.blob} />
        <g transform="skewX(-10) translate(14 0)">
          <rect x="36" y="22" width="70" height="56" rx="10" className={classes.back} />
          <rect x="50" y="36" width="74" height="58" rx="11" fill={`url(#${id}f)`} />
          <rect x="60" y="76" width="30" height="5" rx="2.5" className={classes.line} />
          <rect x="94" y="76" width="16" height="5" rx="2.5" className={classes.lineSoft} />
        </g>
        <circle cx="134" cy="28" r="9" fill={`url(#${id}h)`} />
        <circle cx="26" cy="92" r="5" className={classes.dot} />
        <circle cx="146" cy="88" r="3" className={classes.dot} />
      </svg>
      <span className={classes.artIcon}>{icon}</span>
    </div>
  );
}

export interface EmptyStateProps {
  title: string;
  /** One line on why it is empty or what to do. */
  description?: ReactNode;
  /** The primary action, for example a button. */
  action?: ReactNode;
  /** Replaces the default inbox glyph inside the illustration. */
  icon?: ReactNode;
}

/** What a screen shows when it has nothing to list: an illustration, the title, one line and the primary action. */
export function EmptyState({ title, description, action, icon }: EmptyStateProps) {
  return (
    <Center py={40} data-testid="empty-state">
      <Stack align="center" gap="xs" maw={480}>
        <Illustration icon={icon ?? <IconInbox size={26} />} />
        <Text fw={700} size="lg" ta="center">
          {title}
        </Text>
        {description && (
          <Text c="dimmed" size="sm" ta="center" component="div">
            {description}
          </Text>
        )}
        {action && (
          <Group gap="xs" justify="center" mt="xs">
            {action}
          </Group>
        )}
      </Stack>
    </Center>
  );
}
