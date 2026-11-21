export interface CommandItem {
  id: string;
  label: string;
  /** Heading the item is listed under. */
  group?: string;
  /** Extra words the search matches besides the label and group. */
  keywords?: string[];
  onSelect: () => void;
}

/** True when every word of `query` occurs in `text` (case-insensitive). */
export function matchesQuery(text: string, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const t = text.toLowerCase();
  return words.every((w) => t.includes(w));
}

/** Filters `items` by `query` and orders them by group, keeping the given order inside each group. */
export function filterCommands(items: readonly CommandItem[], query: string): CommandItem[] {
  const groups = new Map<string, CommandItem[]>();
  for (const item of items) {
    const text = [item.label, item.group ?? '', ...(item.keywords ?? [])].join(' ');
    if (!matchesQuery(text, query)) continue;
    const key = item.group ?? '';
    const list = groups.get(key);
    if (list) list.push(item);
    else groups.set(key, [item]);
  }
  return [...groups.values()].flat();
}
