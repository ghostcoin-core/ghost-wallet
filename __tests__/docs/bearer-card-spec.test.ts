import fs from 'fs';
import path from 'path';

const DOC = path.join(__dirname, '..', '..', 'docs', 'bearer-card-spec.md');
const text = fs.readFileSync(DOC, 'utf8');

/** The body under heading `#…# title` (level hashes), up to the next heading of that level or higher. */
function section(markdown: string, level: number, title: string): string {
  const lines = markdown.split('\n');
  const heading = `${'#'.repeat(level)} ${title}`;
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start < 0) {
    throw new Error(`no section "${heading}"`);
  }
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => {
    const match = /^(#+)\s/.exec(line);
    return match !== null && match[1].length <= level;
  });
  return (end < 0 ? rest : rest.slice(0, end)).join('\n').trim();
}

/** `body` on one line, so a phrase matches however the paragraph wraps. */
function flat(body: string): string {
  return body.replace(/\s+/g, ' ');
}

/** The titles of the headings of `level` directly inside `body`. */
function headings(body: string, level: number): string[] {
  const prefix = `${'#'.repeat(level)} `;
  return body
    .split('\n')
    .filter((line) => line.startsWith(prefix))
    .map((line) => line.slice(prefix.length).trim());
}

/** The words of `body` after `label`, up to the next bold label or the end. */
function after(body: string, label: string): string {
  const at = body.indexOf(label);
  if (at < 0) {
    return '';
  }
  const rest = body.slice(at + label.length);
  const next = rest.search(/\*\*[A-Z][^*]*:\*\*/);
  return (next < 0 ? rest : rest.slice(0, next)).trim();
}

/** The red-team items of `body`: each list item that starts with "**Attack:**". */
function attacks(body: string): string[] {
  return body
    .split(/\n(?=- \*\*Attack:\*\*)/)
    .map((item) => item.trim())
    .filter((item) => item.startsWith('- **Attack:**'));
}

describe('docs/bearer-card-spec.md', () => {
  it('has every top-level section the spec needs, none empty', () => {
    for (const title of ['Goal', 'Why NTAG 424 DNA cannot be a bearer object', 'Card type', 'Design', 'Open questions', 'Threat model', 'Red-team']) {
      expect(section(text, 2, title).length).toBeGreaterThan(200);
    }
  });

  it('chooses the card type: a programmable secure-element Java Card', () => {
    const body = flat(section(text, 2, 'Card type'));
    const chosen = after(body, '**Chosen:**');
    expect(chosen).toMatch(/secure-element card/);
    expect(chosen).toMatch(/Java Card/);
    expect(body).toMatch(/SHA3-256/);
    expect(body).toMatch(/random number generator/);
    expect(body).toMatch(/SATSCARD/);
  });

  it('covers the four parts of the design', () => {
    const design = section(text, 2, 'Design');
    for (const part of ['Made on the card', 'Seal check on every tap', 'Opening is one-way', 'Locked applet']) {
      expect(section(design, 3, part).length).toBeGreaterThan(200);
    }

    const made = flat(section(design, 3, 'Made on the card'));
    expect(made).toMatch(/draws 32 bytes from its own random source/);
    expect(made).toMatch(/It never answers with the key/);
    expect(made).toMatch(/\*\*Words are never shown\*\*, because the phone never has them/);

    const check = flat(section(design, 3, 'Seal check on every tap'));
    expect(check).toMatch(/fresh 32-byte random challenge/);
    expect(check).toMatch(/signed by its attestation key/);
    expect(check).toMatch(/the marker is not among the spent markers/);
    expect(check).toMatch(/\*\*Sealed: holds X GHOST\*\*/);
    expect(check).toMatch(/\*\*Opened: not safe to accept\*\*/);

    const open = flat(section(design, 3, 'Opening is one-way'));
    expect(open).toMatch(/first writes "opened"/);
    expect(open).toMatch(/Every later \*\*Check\*\* says opened/);

    const locked = flat(section(design, 3, 'Locked applet'));
    expect(locked).toMatch(/nobody can load, delete or personalise any applet/);
    expect(locked).toMatch(/no command that reads out its key/);
  });

  it('answers or rules out each of the three open questions, with reasons', () => {
    const body = section(text, 2, 'Open questions');
    expect(headings(body, 3)).toEqual([
      "The in-proof hash for F and the note's sealing",
      'A quantum-safe attestation signature',
      'Card supply and loading',
    ]);
    for (const question of headings(body, 3)) {
      const answer = section(body, 3, question);
      const verdict = after(answer, '**Answer:**') || after(answer, '**Ruled out:**');
      expect(verdict.length).toBeGreaterThan(40);
      expect(answer).toMatch(/\*\*Why[^*]*:\*\*/);
      expect(answer.length).toBeGreaterThan(600);
    }
  });

  it('states the threat model: assets, attackers, what remains to trust', () => {
    const body = section(text, 2, 'Threat model');
    expect(headings(body, 3)).toEqual(expect.arrayContaining(['Assets', 'Attackers', 'What remains to trust', 'Not protected']));

    const attackers = flat(section(body, 3, 'Attackers'));
    expect(attackers).toMatch(/\*\*modified app\*\*/);
    expect(attackers).toMatch(/\*\*Middleware\*\*/);
    expect(attackers).toMatch(/\*\*card maker and the issuer\*\*/);

    const trust = flat(section(body, 3, 'What remains to trust'));
    expect(trust).toMatch(/The card's hardware/);
    expect(trust).toMatch(/Whoever makes and loads the cards/);
  });

  it('red-teams a modified app, middleware and the card maker, answering every attack', () => {
    const body = section(text, 2, 'Red-team');
    for (const attacker of ['A modified app', 'Middleware', 'The card maker and loader']) {
      const items = attacks(section(body, 3, attacker));
      expect(items.length).toBeGreaterThanOrEqual(4);
      for (const item of items) {
        expect(after(item, '**Attack:**').length).toBeGreaterThan(20);
        expect(after(item, '**Answer:**').length).toBeGreaterThan(20);
      }
    }
    // No attack anywhere in the red-team goes unanswered.
    const all = attacks(body);
    expect(all.length).toBe((body.match(/\*\*Attack:\*\*/g) ?? []).length);
    expect(all.filter((item) => !item.includes('**Answer:**'))).toEqual([]);
  });

  it('states that NTAG 424 DNA is carry-to-Claim only and never safe to accept', () => {
    const body = flat(section(text, 3, 'NTAG 424 DNA is carry-to-Claim only'));
    expect(body).toMatch(/\*\*NTAG 424 DNA is carry-to-Claim only\.\*\*/);
    expect(body).toMatch(/never call such a card "sealed" or "safe to accept"/);
    expect(body).toMatch(/not shipped as a bearer feature/);
    // Card Vanish ships with no words shown; trust for a receiver still waits for the secure element.
    expect(body).toMatch(/Card Vanish now ships with no words shown/);
    expect(body).toMatch(/a seal check a receiver can trust still needs the secure-element card type/);
    const today = flat(section(text, 2, 'Why NTAG 424 DNA cannot be a bearer object'));
    expect(today).toMatch(/A Vanish to a card shows no words/);
    expect(today).toMatch(/The card is the only copy\./);
    expect(today).not.toMatch(/and shows the 24 words to be written down/);
    expect(flat(section(text, 2, 'Design'))).toMatch(/\*\*Carry to Claim: not safe to accept\*\* \(an NTAG 424 DNA card\)/);
  });

  it('names no ticket, link or build tool', () => {
    // A tracker id (two or more capitals, a dash, digits); SHA-256 and AES-256 are algorithms.
    expect(text).not.toMatch(/\b(?!(?:SHA|AES)-)[A-Z]{2,}-\d+\b/);
    expect(text).not.toMatch(/linear\.app/i);
    expect(text).not.toMatch(/https?:\/\//);
    expect(text).not.toMatch(/\]\(/);
    expect(text).not.toMatch(/\b(cargo|pnpm|npm|npx|yarn|xcode|xcodebuild|gradle|maven|jcardsim|gppro|globalplatformpro|ubrn|cocoapods|expo|ant-javacard)\b/i);
  });
});
