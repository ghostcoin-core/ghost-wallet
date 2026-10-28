// Small JSON files in the app's Documents folder. Only public data goes here:
// balances, activity and settings, never words or keys.

export type JsonFile = {
  /** The file's value, read at once; null when it is missing or unreadable. */
  read(): unknown;
  write(value: unknown): Promise<void>;
};

type FileSystem = typeof import('expo-file-system');

function fileSystem(): FileSystem | null {
  try {
    // Loaded lazily so that a build or test without the native module still starts.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('expo-file-system') as FileSystem;
  } catch {
    return null;
  }
}

export function jsonFile(name: string): JsonFile {
  return {
    read() {
      try {
        const fs = fileSystem();
        if (!fs) {
          return null;
        }
        const file = new fs.File(fs.Paths.document, name);
        return file.exists ? JSON.parse(file.textSync()) : null;
      } catch {
        return null;
      }
    },
    async write(value) {
      const fs = fileSystem();
      if (!fs) {
        return;
      }
      const file = new fs.File(fs.Paths.document, name);
      if (!file.exists) {
        file.create();
      }
      await file.write(JSON.stringify(value));
    },
  };
}
