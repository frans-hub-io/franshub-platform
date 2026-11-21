import { fireEvent, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderThemed } from '../test/render';
import { CommandPalette } from './CommandPalette';
import { filterCommands, type CommandItem } from './commands';

function items(onSelect: (id: string) => void): CommandItem[] {
  return [
    { id: 'launches', label: 'Launches', group: 'Pages', onSelect: () => onSelect('launches') },
    { id: 'reports', label: 'Reports', group: 'Pages', keywords: ['allure', 'results'], onSelect: () => onSelect('reports') },
    { id: 'new', label: 'Create a launch', group: 'Actions', onSelect: () => onSelect('new') },
  ];
}

const ctrlK = () => fireEvent.keyDown(document.body, { key: 'k', code: 'KeyK', ctrlKey: true });
const labels = () => screen.queryAllByTestId('palette-item').map((el) => el.textContent);

describe('filterCommands', () => {
  it('matches every word against label, group and keywords, grouped in first-seen order', () => {
    const list = [
      { id: 'a', label: 'Alpha', group: 'One', onSelect: vi.fn() },
      { id: 'b', label: 'Beta', group: 'Two', onSelect: vi.fn() },
      { id: 'c', label: 'Gamma', group: 'One', keywords: ['third'], onSelect: vi.fn() },
    ];
    expect(filterCommands(list, '').map((i) => i.id)).toEqual(['a', 'c', 'b']);
    expect(filterCommands(list, 'one THIRD').map((i) => i.id)).toEqual(['c']);
    expect(filterCommands(list, 'zzz')).toEqual([]);
  });
});

describe('CommandPalette', () => {
  it('opens on Ctrl+K, filters as you type and runs the item on Enter', async () => {
    const onSelect = vi.fn();
    renderThemed(<CommandPalette items={items(onSelect)} />);
    expect(screen.queryByTestId('palette-input')).not.toBeInTheDocument();

    ctrlK();
    const input = await screen.findByTestId('palette-input');
    expect(labels()).toEqual(['Launches', 'Reports', 'Create a launch']);

    fireEvent.change(input, { target: { value: 'allure' } });
    expect(labels()).toEqual(['Reports']);

    fireEvent.change(input, { target: { value: 'launch' } });
    expect(labels()).toEqual(['Launches', 'Create a launch']);
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(screen.getAllByTestId('palette-item')[1]).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(onSelect).toHaveBeenCalledWith('new');
    await waitFor(() => expect(screen.queryByTestId('palette-input')).not.toBeInTheDocument());
  });

  it('opens on Cmd+K and closes on Escape', async () => {
    const onSelect = vi.fn();
    renderThemed(<CommandPalette items={items(onSelect)} />);
    fireEvent.keyDown(document.body, { key: 'k', code: 'KeyK', metaKey: true });
    const input = await screen.findByTestId('palette-input');
    fireEvent.keyDown(input, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByTestId('palette-input')).not.toBeInTheDocument());
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('reports open changes when controlled', async () => {
    const onOpenChange = vi.fn();
    renderThemed(<CommandPalette items={items(vi.fn())} opened={false} onOpenChange={onOpenChange} />);
    ctrlK();
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(true));
    expect(screen.queryByTestId('palette-input')).not.toBeInTheDocument();
  });
});
