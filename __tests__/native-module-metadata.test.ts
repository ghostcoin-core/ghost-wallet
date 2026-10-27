import fs from 'fs';
import path from 'path';

// The iOS binding generator and the generated pod read these fields from each
// native module's package.json; the Mac install fails without them.
const MODULES_DIR = path.join(__dirname, '..', 'modules');

const packageFiles = fs
  .readdirSync(MODULES_DIR)
  .map((name) => path.join(MODULES_DIR, name, 'package.json'))
  .filter((file) => fs.existsSync(file));

function readPackage(file: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function nonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

describe('native module metadata', () => {
  it('finds the native core module', () => {
    expect(packageFiles).toContain(path.join(MODULES_DIR, 'ghost-core', 'package.json'));
  });

  describe.each(packageFiles.map((file) => [path.relative(MODULES_DIR, file), file]))(
    '%s',
    (_name, file) => {
      const pkg = readPackage(file);

      it('has a repository', () => {
        const repository = pkg.repository;
        if (typeof repository === 'string') {
          expect(nonEmptyString(repository)).toBe(true);
        } else {
          expect(repository).toEqual(
            expect.objectContaining({ type: 'git', url: expect.stringMatching(/^https:\/\/\S+$/) }),
          );
        }
      });

      it('has an author', () => {
        const author = pkg.author;
        const name =
          author && typeof author === 'object' ? (author as { name?: unknown }).name : author;
        expect(nonEmptyString(name)).toBe(true);
      });

      it('has a homepage', () => {
        expect(pkg.homepage).toEqual(expect.stringMatching(/^https:\/\/\S+$/));
      });
    },
  );
});
