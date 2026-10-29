// Whether the saved account's recovery words were checked. Skipping the word
// check at onboarding (the person's own choice) marks the backup not checked,
// and Settings shows it with a way to check the words now. Only that one
// fact is kept here, never a word. The choice to skip is never remembered:
// every check starts with the box unticked.
import { useSyncExternalStore } from 'react';

import { jsonFile, type JsonFile } from '../storage';

export type BackupStatusStore = {
  /** Whether the saved account's words were saved without a check. */
  unchecked(): boolean;
  /** Marks the backup checked (true) or not checked (false). */
  setChecked(checked: boolean): Promise<void>;
  subscribe(listener: () => void): () => void;
};

export function parseBackupStatus(raw: unknown): boolean {
  const value = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  return value.unchecked === true;
}

export function createBackupStatusStore(file: JsonFile): BackupStatusStore {
  let current: boolean | null = null;
  const listeners = new Set<() => void>();
  const unchecked = () => (current ??= parseBackupStatus(file.read()));
  return {
    unchecked,
    async setChecked(checked) {
      current = !checked;
      for (const listener of listeners) {
        listener();
      }
      await file.write({ unchecked: current });
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

export const backupStatusStore = createBackupStatusStore(jsonFile('backup-status.json'));

/** Whether Settings should say "Backup not checked". */
export function useBackupUnchecked(store: BackupStatusStore = backupStatusStore): boolean {
  return useSyncExternalStore(store.subscribe, store.unchecked);
}
