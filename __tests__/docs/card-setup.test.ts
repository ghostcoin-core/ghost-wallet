import fs from 'fs';
import path from 'path';

const DOC = path.join(__dirname, '..', '..', 'docs', 'card-setup.md');
const text = fs.readFileSync(DOC, 'utf8');

const SECTIONS = [
  'Why a card is set up once',
  'Test cards on the Mac Studio',
  "Production: the card maker's key-loading service",
  'What is checked after setup',
  'What is never done',
];

/** The body under `## title`, up to the next heading of level 2 or higher. */
function section(title: string): string {
  const lines = text.split('\n');
  const start = lines.findIndex((line) => line.trim() === `## ${title}`);
  if (start < 0) {
    throw new Error(`no section "## ${title}"`);
  }
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => /^#{1,2}\s/.test(line));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n').trim();
}

/** `body` on one line, so a phrase matches however the paragraph wraps. */
function flat(body: string): string {
  return body.replace(/\s+/g, ' ');
}

describe('docs/card-setup.md', () => {
  it('has every section, in order, none empty', () => {
    const headings = text
      .split('\n')
      .filter((line) => line.startsWith('## '))
      .map((line) => line.slice(3).trim());
    expect(headings).toEqual(SECTIONS);
    for (const title of SECTIONS) {
      expect(section(title).length).toBeGreaterThan(200);
    }
  });

  it('explains why a card is set up once, never in the field or from factory keys in the open', () => {
    const why = flat(section('Why a card is set up once'));
    expect(why).toMatch(/set up from factory keys in the open can be recorded/);
    expect(why).toMatch(/a card is never set up in the field/);
    expect(why).toMatch(/never from factory keys in an open room/);
  });

  it('sets test cards up on the Mac Studio in a room with no other readers, with the dev test Seal only', () => {
    const test = flat(section('Test cards on the Mac Studio'));
    expect(test).toMatch(/in a room with no other readers/);
    expect(test).toMatch(/refuses to run without `--dev-test-seal`/);
    expect(test).toMatch(/`ghost-seal\/dev-test-master\/v1`/);
  });

  it('sends production keys to the maker wrapped for its HSM, never in the clear', () => {
    const production = flat(section("Production: the card maker's key-loading service"));
    expect(production).toMatch(/wrapped for the maker's HSM, never in the clear/);
    expect(production).toMatch(/master key never leaves the enclave/);
  });

  it('verifies every key, the file mode, the permissions and SDM-off by fresh authentication, then registers', () => {
    const checked = flat(section('What is checked after setup'));
    expect(checked).toMatch(/fresh authentication/);
    expect(checked).toMatch(/Full mode, read and write key 2, read key 1, change key 0/);
    expect(checked).toMatch(/SDM off/);
    expect(checked).toMatch(/The UID is recorded in the registry/);
    expect(checked).toMatch(/A half-set-up card is finished or refused/);
  });

  it('lists what is never done', () => {
    const never = flat(section('What is never done'));
    expect(never).toMatch(/never set up in the field/);
    expect(never).toMatch(/never sent to a card maker in the clear/);
    expect(never).toMatch(/never registered before every key/);
  });

  it('names no ticket or tracker link', () => {
    expect(text).not.toMatch(/\b(?!(?:SHA|AES)-)[A-Z]{2,}-\d+\b/);
    expect(text).not.toMatch(/linear\.app/i);
  });
});
