// Which sends the node has said it holds: it took the broadcast, or listed the
// transaction. Until then a send is queued, not sent, even when its record is
// saved as sent (the record is saved before the broadcast, which may not get
// through). Kept in a small file so a send that went out still reads as sent
// after the app is closed and opened with the node out of reach. Payment ids
// only, nothing secret.
import { jsonFile, type JsonFile } from '../storage';

let file: JsonFile = jsonFile('sends-reached.json');
let reached: Set<string> | null = null;

function loaded(): Set<string> {
  if (!reached) {
    const raw = file.read();
    reached = new Set(Array.isArray(raw) ? raw.filter((id): id is string => typeof id === 'string') : []);
  }
  return reached;
}

/** Whether the node has said it holds send `id`. */
export function hasReached(id: string): boolean {
  return loaded().has(id);
}

/** Remembers that the node holds send `id`. */
export function markReached(id: string) {
  const ids = loaded();
  if (ids.has(id)) {
    return;
  }
  ids.add(id);
  void file.write([...ids]).catch(() => {
    // Kept in memory; the next send that reaches the node writes the file again.
  });
}

/** Starts again from `next` (or the real file); for tests. */
export function resetReached(next?: JsonFile) {
  file = next ?? jsonFile('sends-reached.json');
  reached = null;
}
