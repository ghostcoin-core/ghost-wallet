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

  it('names a Ghost Sealed card as the one exception to carry-to-Claim, pointing to its design', () => {
    const rule = section(text, 3, 'NTAG 424 DNA is carry-to-Claim only');
    const exception = flat(section(rule, 4, 'The one exception: a Ghost Sealed card'));
    expect(exception).toMatch(/A Ghost Sealed card is the one exception to this rule/);
    expect(exception).toMatch(/its keys and its Phantom Key live only in the Seal, an attested enclave/);
    expect(exception).toMatch(/can be accepted after a fresh Check/);
    expect(exception).toMatch(/Offline or trust-free certainty still needs the Java Card/);
    expect(exception).toMatch(/Its design is in `docs\/sealed-card\.md`/);
    expect(fs.existsSync(path.join(__dirname, '..', '..', 'docs', 'sealed-card.md'))).toBe(true);
    // The rule itself and the Java Card plan stay as they were.
    expect(flat(rule)).toMatch(/\*\*NTAG 424 DNA is carry-to-Claim only\.\*\*/);
    expect(section(text, 2, 'Card type')).toMatch(/Java Card/);
  });

  it('settles the J3R180: bytecode Keccak, SHA-256 digest, unsigned Make, Open in the clear, H10', () => {
    const card = flat(section(text, 2, 'Card type'));
    expect(card).toMatch(/\*\*The J3R180 qualifies\.\*\*/);
    expect(card).toMatch(/146 ms per permutation over iPhone NFC/);

    const design = section(text, 2, 'Design');
    const made = flat(section(design, 3, 'Made on the card'));
    expect(made).toMatch(/native SHA-256 into the commit-data digest/);
    expect(made).toMatch(/\*\*unsigned\*\*/);
    expect(made).toMatch(/with a \*\*Check\*\* in the same tap/);
    expect(made).toMatch(/SHA3-256\("ghost-card-key" \|\| card random \|\| writer nonce\)/);

    const open = flat(section(design, 3, 'Opening is one-way'));
    expect(open).toMatch(/\*\*in the clear\*\*/);
    expect(open).toMatch(/No AES is needed and none is used/);
    expect(open).toMatch(/trusts nothing in the release until it recomputes/);
    expect(open).toMatch(/LMS-signed statement/);
    expect(open).not.toMatch(/AES-256-CTR|AES-CMAC|open code/);

    const lms = flat(section(text, 3, 'A quantum-safe attestation signature'));
    expect(lms).toMatch(/\*\*height 10\*\*/);
    expect(lms).toMatch(/\*\*Why height 10, and not 9 or 8:\*\*/);
    expect(lms).toMatch(/\*\*How the checks count down:\*\*/);
  });

  it('makes cards reusable by fill and needs no Seal for Java Cards', () => {
    const design = section(text, 2, 'Design');
    const states = flat(section(design, 3, 'Card states'));
    expect(states).toMatch(/\*\*Sealed \(fill N\)\*\*/);
    expect(states).toMatch(/What carries over between fills/);
    expect(section(design, 3, 'Refill: filling the card again').length).toBeGreaterThan(200);
    expect(section(design, 3, 'Bearer: the card is all it takes').length).toBeGreaterThan(200);
    const noSeal = flat(section(design, 3, 'Java Cards need no Seal'));
    expect(noSeal).toMatch(/No Ghost server takes part/);
    expect(noSeal).toMatch(/What the receiver still checks/);
    expect(flat(section(text, 4, 'The one exception: a Ghost Sealed card'))).toMatch(/closed to new fills/);
    expect(flat(section(text, 2, 'Red-team'))).toMatch(/refill a card whose fill was just opened/);
  });

  it('makes the card a pure bearer object: no open code, and states the trade-off', () => {
    const design = section(text, 2, 'Design');
    expect(headings(design, 3)).not.toContain('The open code');
    const bearer = flat(section(design, 3, 'Bearer: the card is all it takes'));
    expect(bearer).toMatch(/whoever holds the card can open it/);
    expect(bearer).toMatch(/There is no open code, PIN or other secret/);
    expect(bearer).toMatch(/Anyone who gets a tap on the card can empty it/);
    expect(bearer).toMatch(/seed material crosses the radio in the clear/);
    expect(bearer).toMatch(/writer knows only the nonce/);
    expect(bearer).toMatch(/Receivers still \*\*Check\*\* before accepting/);

    const check = flat(section(design, 3, 'Seal check on every tap'));
    expect(check).toMatch(/"ghost-card-seal-v2"/);
    expect(check).toMatch(/Whoever holds this card can open it, like cash\./);
    expect(check).not.toMatch(/Open code wrong/);

    // Nothing anywhere still asks for or describes an open code.
    expect(text).not.toMatch(/AES-256-CTR|AES-CMAC|ghost-card-seal-v1|ghost-card-code|6982/);
    expect(text.replace(/There is no open code/g, '')).not.toMatch(/open code/i);
    const skim = attacks(section(text, 2, 'Red-team')).find((item) => /skim a card in a pocket/.test(item));
    expect(skim).toBeDefined();
    expect(flat(after(skim ?? '', '**Answer:**'))).toMatch(/a skimmer within a few centimetres can/);
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
