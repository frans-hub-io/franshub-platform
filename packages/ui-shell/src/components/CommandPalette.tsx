import { Modal, Text, TextInput, UnstyledButton } from '@mantine/core';
import { useHotkeys } from '@mantine/hooks';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { filterCommands, type CommandItem } from './commands';
import { IconArrowRight, IconCornerDownLeft, IconSearch } from './icons';
import classes from './CommandPalette.module.css';

export interface CommandPaletteProps {
  items: CommandItem[];
  /** Controls the palette; leave unset to let it manage its own state. */
  opened?: boolean;
  /** Called when the palette asks to open or close (hotkey, Escape, selection, outside click). */
  onOpenChange?: (opened: boolean) => void;
  placeholder?: string;
}

/**
 * The command palette: Ctrl+K (Cmd+K on macOS) opens and closes it, typing filters the items, arrow keys move,
 * Enter runs the highlighted item and Escape closes it.
 */
export function CommandPalette({ items, opened, onOpenChange, placeholder = 'Search or jump to…' }: CommandPaletteProps) {
  const [ownOpen, setOwnOpen] = useState(false);
  const isOpen = opened ?? ownOpen;
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const listId = useId();
  const listRef = useRef<HTMLDivElement>(null);

  const setOpen = (next: boolean) => {
    if (opened === undefined) setOwnOpen(next);
    onOpenChange?.(next);
  };

  useHotkeys([['mod+K', () => setOpen(!isOpen)]], []);

  useEffect(() => {
    if (!isOpen) {
      setQuery('');
      setActive(0);
    }
  }, [isOpen]);

  const entries = useMemo(() => filterCommands(items, query), [items, query]);

  useEffect(() => {
    setActive((a) => (a >= entries.length ? 0 : a));
  }, [entries.length]);

  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const run = (item: CommandItem | undefined) => {
    if (!item) return;
    setOpen(false);
    item.onSelect();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => (entries.length ? (a + 1) % entries.length : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => (entries.length ? (a - 1 + entries.length) % entries.length : 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      run(entries[active]);
    }
  };

  return (
    <Modal
      opened={isOpen}
      onClose={() => setOpen(false)}
      withCloseButton={false}
      padding={0}
      size={640}
      yOffset="12vh"
      title={<span className="fh-sr-only">Command palette</span>}
      classNames={{ header: 'fh-sr-only', content: classes.content }}
      data-testid="command-palette"
    >
      <div className={classes.inputRow}>
        <TextInput
          data-autofocus
          variant="unstyled"
          size="md"
          value={query}
          onChange={(e) => {
            setQuery(e.currentTarget.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          leftSection={<IconSearch size={18} />}
          classNames={{ input: classes.input }}
          role="combobox"
          aria-label="Search commands"
          aria-expanded
          aria-controls={listId}
          aria-activedescendant={entries[active] ? `${listId}-${String(active)}` : undefined}
          aria-autocomplete="list"
          data-testid="palette-input"
        />
        <span className="fh-kbd">Esc</span>
      </div>
      <div className={classes.list} id={listId} role="listbox" aria-label="Results" ref={listRef}>
        {entries.length === 0 && (
          <Text size="sm" c="dimmed" ta="center" py="xl">
            Nothing matches “{query}”.
          </Text>
        )}
        {entries.map((item, i) => {
          const heading = item.group && item.group !== entries[i - 1]?.group ? item.group : null;
          return (
            <div key={item.id}>
              {heading && (
                <div className={classes.group} role="presentation">
                  {heading}
                </div>
              )}
              <UnstyledButton
                id={`${listId}-${String(i)}`}
                role="option"
                aria-selected={i === active}
                data-active={i === active}
                className={classes.item}
                onMouseMove={() => i !== active && setActive(i)}
                onClick={() => run(item)}
                tabIndex={-1}
                data-testid="palette-item"
              >
                <span className={classes.itemText}>
                  <span className={classes.itemLabel}>{item.label}</span>
                </span>
                <span className={classes.itemGo} aria-hidden>
                  {i === active ? <IconCornerDownLeft size={16} /> : <IconArrowRight size={14} />}
                </span>
              </UnstyledButton>
            </div>
          );
        })}
      </div>
      <div className={classes.footer}>
        <span>
          <span className="fh-kbd">↑</span> <span className="fh-kbd">↓</span> to move
        </span>
        <span>
          <span className="fh-kbd">Enter</span> to select
        </span>
      </div>
    </Modal>
  );
}
