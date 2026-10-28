import fs from 'fs';
import path from 'path';

// The phase 1 screen mockups in docs/mockups must follow Ghost brand kit v1.0
// (brand/README.txt): kit colors only, light pages, the kit's own fonts and
// logo files linked by relative path, plain words, nothing from another host.
const ROOT = path.join(__dirname, '..');
const MOCKUPS = path.join(ROOT, 'docs', 'mockups');

const SCREENS = [
  'welcome.html',
  'backup.html',
  'backup-check.html',
  'import.html',
  'home.html',
  'send.html',
  'payment.html',
  'receive.html',
  'lock.html',
  'settings.html',
];

const KIT_COLORS = new Set(
  [
    '#FFFFFF', // Paper
    '#F5F5F8', // Mist
    '#E4E3EC', // Line
    '#0E0D1A', // Ink
    '#4A4860', // Body text
    '#6E6C82', // Quiet text
    '#ECEBF2', // the surface the darker quiet text sits on
    '#5F5D73', // Quiet text on #ECEBF2
    '#6B4CFF', // Ghost violet
    '#EEEAFF', // Violet tint
    '#4FF0C8', // Summon mint
  ].map((c) => c.toLowerCase()),
);

const LIGHT_BACKGROUNDS = new Set(['#ffffff', '#f5f5f8']);

// Kit files the mockups may link. They come from brand/ on main; this list
// keeps a typo or a made-up file name from passing.
const KIT_FILES = new Set([
  'brand/svg/ghost-logo-primary.svg',
  'brand/svg/ghost-logo-one-color-ink.svg',
  'brand/svg/ghost-lockup-primary.svg',
  'brand/svg/ghost-lockup-one-color-ink.svg',
  'brand/app-icon/ghost-app-icon-violet.svg',
  'brand/favicon/favicon.svg',
  'brand/fonts/InstrumentSans.ttf',
  'brand/fonts/IBMPlexMono-Regular.ttf',
  'brand/fonts/IBMPlexMono-Medium.ttf',
]);

// Logo versions for light backgrounds: the primary logo, the one-color ink
// logo, their lockups and the violet app icon.
const LIGHT_LOGOS = new Set([
  'brand/svg/ghost-logo-primary.svg',
  'brand/svg/ghost-logo-one-color-ink.svg',
  'brand/svg/ghost-lockup-primary.svg',
  'brand/svg/ghost-lockup-one-color-ink.svg',
  'brand/app-icon/ghost-app-icon-violet.svg',
]);

const KIT_ON_DISK = fs.existsSync(path.join(ROOT, 'brand', 'README.txt'));

const FORBIDDEN_JARGON = ['nonce', 'rpc', 'pow', 'mempool'];
// The balance shows at once and actions finish in about two seconds, so no
// screen may show a syncing or verifying wait.
const FORBIDDEN_WAITS = ['sync', 'syncing', 'synchronizing', 'verifying', 'spinner'];

const ALLOWED_FONT_FAMILIES = new Set([
  'instrument sans',
  'ibm plex mono',
  'sans-serif',
  'monospace',
  'inherit',
]);

function listFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full) : [full];
  });
}

function read(file: string): string {
  return fs.readFileSync(file, 'utf8');
}

function repoPath(file: string): string {
  return path.relative(ROOT, file).split(path.sep).join('/');
}

function stripComments(text: string): string {
  return text.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

// Every hex color in the text, as lowercase six-digit (or eight-digit) form.
// `&#123;` character references are not colors.
export function hexColors(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(/(?<![&\w])#([0-9a-f]{3,8})(?![0-9a-z_-])/gi)) {
    let hex = match[1].toLowerCase();
    if (hex.length === 3 || hex.length === 4) {
      hex = hex
        .split('')
        .map((d) => d + d)
        .join('');
    }
    found.push('#' + hex);
  }
  return found;
}

export function offKitColors(text: string): string[] {
  const bad = hexColors(text).filter((c) => !KIT_COLORS.has(c));
  // Colors written another way would get around the kit list.
  for (const match of text.matchAll(/\b(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/gi)) {
    bad.push(match[0]);
  }
  for (const value of declarationValues(text)) {
    const named = value.match(
      /\b(black|white|gray|grey|silver|red|green|blue|navy|purple|violet|indigo|teal|aqua|cyan|lime|yellow|orange|pink|magenta|fuchsia|maroon|olive|brown|gold|darkslategray|midnightblue)\b/i,
    );
    if (named) bad.push(named[0]);
  }
  return bad;
}

type Rule = { selectors: string[]; body: string };

export function cssRules(css: string): Rule[] {
  const rules: Rule[] = [];
  for (const match of stripComments(css).matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    rules.push({
      selectors: match[1]
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      body: match[2],
    });
  }
  return rules;
}

function declarations(body: string): { prop: string; value: string }[] {
  return body
    .split(';')
    .map((d) => d.trim())
    .filter((d) => d.includes(':'))
    .map((d) => {
      const at = d.indexOf(':');
      return { prop: d.slice(0, at).trim().toLowerCase(), value: d.slice(at + 1).trim() };
    });
}

// Values of CSS declarations in style sheets, <style> blocks and style="" attributes,
// plus SVG presentation attributes that take colors.
function declarationValues(text: string): string[] {
  const values: string[] = [];
  for (const rule of cssRules(styleText(text))) {
    values.push(...declarations(rule.body).map((d) => d.value));
  }
  for (const match of text.matchAll(/\bstyle\s*=\s*"([^"]*)"/gi)) {
    values.push(...declarations(match[1]).map((d) => d.value));
  }
  for (const match of text.matchAll(/\b(?:fill|stroke|color|stop-color|bgcolor)\s*=\s*"([^"]*)"/gi)) {
    values.push(match[1]);
  }
  return values;
}

// The CSS in a file: the whole file for .css, the <style> blocks for HTML.
function styleText(text: string): string {
  if (!/<\w/.test(text)) return text;
  return [...text.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]).join('\n');
}

function backgroundValue(body: string): string[] {
  return declarations(body)
    .filter((d) => d.prop === 'background' || d.prop === 'background-color')
    .map((d) => d.value.toLowerCase());
}

// True when the last compound of a selector is body, html or the .screen root.
export function targetsScreenRoot(selector: string): boolean {
  const compounds = selector.split(/\s*[\s>+~]\s*/).filter(Boolean);
  const subject = compounds[compounds.length - 1] ?? '';
  return /^(html|body)\b/.test(subject) || /\.screen(?![\w-])/.test(subject);
}

function isLightBackground(value: string): boolean {
  const colors = hexColors(value);
  const rest = value.replace(/#[0-9a-f]{3,8}/gi, '').trim();
  return colors.length === 1 && LIGHT_BACKGROUNDS.has(colors[0]) && rest === '';
}

// Backgrounds set on body, html or the .screen root that are not Paper or Mist.
export function darkRootBackgrounds(css: string, html: string): string[] {
  const bad: string[] = [];
  for (const rule of cssRules(css)) {
    if (!rule.selectors.some(targetsScreenRoot)) continue;
    for (const value of backgroundValue(rule.body)) {
      if (!isLightBackground(value)) bad.push(`${rule.selectors.join(', ')} { background: ${value} }`);
    }
  }
  for (const match of html.matchAll(/<(html|body|[a-z][\w-]*)\b([^>]*)>/gi)) {
    const [, tag, attrs] = match;
    const classes = (attrs.match(/\bclass\s*=\s*"([^"]*)"/i)?.[1] ?? '').split(/\s+/);
    const isRoot = /^(html|body)$/i.test(tag) || classes.includes('screen');
    if (!isRoot) continue;
    const style = attrs.match(/\bstyle\s*=\s*"([^"]*)"/i)?.[1];
    if (style) {
      for (const value of backgroundValue(style)) {
        if (!isLightBackground(value)) bad.push(`<${tag} style="background: ${value}">`);
      }
    }
    const bgcolor = attrs.match(/\bbgcolor\s*=\s*"([^"]*)"/i)?.[1];
    if (bgcolor) bad.push(`<${tag} bgcolor="${bgcolor}">`);
  }
  return bad;
}

// The logo's own geometry: its 26 x 26 squares and the ghost's round top.
export function redrawsLogo(text: string): boolean {
  const squares = [...text.matchAll(/<rect\b[^>]*>/gi)].filter(
    (m) => /\bwidth\s*=\s*"26"/.test(m[0]) && /\bheight\s*=\s*"26"/.test(m[0]),
  );
  return squares.length > 0 || /a\s*13[\s,]+13[\s,]+0[\s,]+0[\s,]*1[\s,]+26[\s,]+0/i.test(text);
}

export function forbiddenWords(text: string, words: string[]): string[] {
  const lower = text.toLowerCase();
  return words.filter((w) => new RegExp(`\\b${w}\\b`).test(lower));
}

// Every URL a file loads or links: src, href, url(), @import and srcset.
function references(text: string): string[] {
  const refs: string[] = [];
  for (const m of text.matchAll(/\b(?:src|href|action|poster|data)\s*=\s*"([^"]*)"/gi)) refs.push(m[1]);
  for (const m of text.matchAll(/\bsrcset\s*=\s*"([^"]*)"/gi)) {
    refs.push(...m[1].split(',').map((part) => part.trim().split(/\s+/)[0]));
  }
  for (const m of text.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi)) refs.push(m[1]);
  for (const m of text.matchAll(/@import\s+['"]([^'"]+)['"]/gi)) refs.push(m[1]);
  return refs;
}

function isExternal(ref: string): boolean {
  return /^([a-z][\w+.-]*:|\/\/)/i.test(ref.trim());
}

// A reference as a repository path, resolved from the file that makes it.
function resolveRef(fromFile: string, ref: string): string {
  const clean = ref.split('#')[0].split('?')[0];
  return repoPath(path.resolve(path.dirname(fromFile), clean));
}

function linkedStyleSheets(file: string, html: string): string[] {
  return [...html.matchAll(/<link\b[^>]*>/gi)]
    .map((m) => m[0])
    .filter((tag) => /\brel\s*=\s*"stylesheet"/i.test(tag))
    .map((tag) => tag.match(/\bhref\s*=\s*"([^"]*)"/i)?.[1] ?? '')
    .filter((href) => href && !isExternal(href))
    .map((href) => path.resolve(path.dirname(file), href));
}

// A screen's HTML and every local style sheet it links, each with its path.
function screenSources(file: string): { file: string; text: string }[] {
  const html = read(file);
  return [
    { file, text: html },
    ...linkedStyleSheets(file, html).map((css) => ({ file: css, text: read(css) })),
  ];
}

function fontFaces(source: { file: string; text: string }): { family: string; srcs: string[] }[] {
  return cssRules(styleText(source.text))
    .filter((rule) => rule.selectors.some((s) => s.toLowerCase() === '@font-face'))
    .map((rule) => {
      const decls = declarations(rule.body);
      const family = (decls.find((d) => d.prop === 'font-family')?.value ?? '')
        .replace(/['"]/g, '')
        .trim()
        .toLowerCase();
      const srcs = decls
        .filter((d) => d.prop === 'src')
        .flatMap((d) => references(d.value))
        .map((ref) => (isExternal(ref) ? ref : resolveRef(source.file, ref)));
      return { family, srcs };
    });
}

function fontFamilies(text: string): string[] {
  const families: string[] = [];
  const add = (prop: string, value: string) => {
    if (prop === 'font-family') families.push(...value.split(','));
    if (prop === 'font') {
      // The family list follows the size in the font shorthand.
      const list = value.match(/\d[\w.%]*(?:\s*\/\s*[\w.%]+)?\s+(.+)$/)?.[1];
      if (list) families.push(...list.split(','));
    }
  };
  for (const rule of cssRules(styleText(text))) {
    if (rule.selectors.some((s) => s.toLowerCase() === '@font-face')) continue;
    for (const d of declarations(rule.body)) add(d.prop, d.value);
  }
  for (const m of text.matchAll(/\bstyle\s*=\s*"([^"]*)"/gi)) {
    for (const d of declarations(m[1])) add(d.prop, d.value);
  }
  for (const m of text.matchAll(/\bfont-family\s*=\s*"([^"]*)"/gi)) families.push(...m[1].split(','));
  return families.map((f) => f.replace(/['"]/g, '').trim().toLowerCase()).filter(Boolean);
}

function imageSources(file: string, html: string): string[] {
  return [...html.matchAll(/<img\b[^>]*>/gi)]
    .map((m) => m[0].match(/\bsrc\s*=\s*"([^"]*)"/i)?.[1] ?? '')
    .filter(Boolean)
    .map((src) => (isExternal(src) ? src : resolveRef(file, src)));
}

function hrefs(html: string): string[] {
  return [...html.matchAll(/<a\b[^>]*\bhref\s*=\s*"([^"]*)"/gi)].map((m) => m[1].split('#')[0]);
}

const mockupFiles = listFiles(MOCKUPS);
const textFiles = mockupFiles.filter((f) => /\.(html|svg|css)$/i.test(f));
const pages = [...SCREENS, 'index.html'];

describe('mockup files', () => {
  it.each(pages)('%s exists', (name) => {
    expect(fs.existsSync(path.join(MOCKUPS, name))).toBe(true);
  });

  it('keeps no copies of kit files: fonts, logos and icons are linked from brand/', () => {
    const copies = mockupFiles
      .map(repoPath)
      .filter((f) => /\.(ttf|otf|woff2?|png|ico|svg)$/i.test(f) || /\/ghost-/.test(f));
    expect(copies).toEqual([]);
  });

  it('every screen is 390 x 844', () => {
    const css = read(path.join(MOCKUPS, 'mockups.css'));
    const screenRule = cssRules(css).find((r) => r.selectors.includes('.screen'));
    expect(screenRule).toBeDefined();
    const decls = declarations(screenRule!.body);
    expect(decls).toContainEqual({ prop: 'width', value: '390px' });
    expect(decls).toContainEqual({ prop: 'height', value: '844px' });
    for (const name of SCREENS) {
      expect(read(path.join(MOCKUPS, name))).toMatch(/<main\b[^>]*\bclass\s*=\s*"screen\b/);
    }
  });
});

describe('brand colors', () => {
  it('finds mockup files to check', () => {
    expect(textFiles.length).toBeGreaterThan(SCREENS.length);
  });

  it.each(textFiles.map(repoPath))('%s uses only kit colors', (file) => {
    expect(offKitColors(read(path.join(ROOT, file)))).toEqual([]);
  });

  it.each(pages)('%s keeps body and the screen root on Paper or Mist', (name) => {
    const sources = screenSources(path.join(MOCKUPS, name));
    const html = sources[0].text;
    const css = sources.map((s) => styleText(s.text)).join('\n');
    expect(darkRootBackgrounds(css, html)).toEqual([]);
    // The page itself sets a light background rather than leaving it to the browser.
    const bodyBackgrounds = cssRules(css)
      .filter((r) => r.selectors.includes('body'))
      .flatMap((r) => backgroundValue(r.body));
    expect(bodyBackgrounds.length).toBeGreaterThan(0);
  });
});

describe('brand fonts', () => {
  it.each(pages)('%s loads Instrument Sans from brand/fonts/', (name) => {
    const faces = screenSources(path.join(MOCKUPS, name)).flatMap(fontFaces);
    const instrument = faces.filter((f) => f.family === 'instrument sans');
    expect(instrument.length).toBeGreaterThan(0);
    for (const face of faces) {
      for (const src of face.srcs) expect(src).toMatch(/^brand\/fonts\/[^/]+\.ttf$/);
    }
    expect(instrument.flatMap((f) => f.srcs)).toContain('brand/fonts/InstrumentSans.ttf');
  });

  it.each(textFiles.map(repoPath))('%s names no font but Instrument Sans and IBM Plex Mono', (file) => {
    const families = fontFamilies(read(path.join(ROOT, file)));
    expect(families.filter((f) => !ALLOWED_FONT_FAMILIES.has(f))).toEqual([]);
  });
});

describe('logo and icons', () => {
  it.each(SCREENS)('%s shows a logo or app icon from brand/svg/ or brand/app-icon/', (name) => {
    const file = path.join(MOCKUPS, name);
    const html = read(file);
    expect(html).toMatch(/<img\b[^>]*\bsrc\s*=\s*"\.\.\/\.\.\/brand\/(svg|app-icon)\//);
    const logos = imageSources(file, html).filter((src) => /^brand\/(svg|app-icon)\//.test(src));
    expect(logos.length).toBeGreaterThan(0);
  });

  it.each(pages)('%s uses only the light-background logo versions', (name) => {
    const file = path.join(MOCKUPS, name);
    for (const src of imageSources(file, read(file))) {
      expect(LIGHT_LOGOS).toContain(src);
    }
  });

  it.each(textFiles.map(repoPath))('%s does not redraw the logo', (file) => {
    expect(redrawsLogo(read(path.join(ROOT, file)))).toBe(false);
  });

  it.each(pages)('%s draws icons as inline stroke SVG with no fill', (name) => {
    const html = read(path.join(MOCKUPS, name));
    for (const m of html.matchAll(/<svg\b[^>]*>/gi)) {
      expect(m[0]).toMatch(/\bclass\s*=\s*"icon\b/);
    }
    const iconRule = cssRules(read(path.join(MOCKUPS, 'mockups.css'))).find((r) =>
      r.selectors.includes('.icon'),
    );
    expect(declarations(iconRule!.body)).toEqual(
      expect.arrayContaining([
        { prop: 'fill', value: 'none' },
        { prop: 'stroke', value: 'currentColor' },
      ]),
    );
  });
});

describe('nothing from another host', () => {
  it.each(textFiles.map(repoPath))('%s loads and links only local files', (file) => {
    const full = path.join(ROOT, file);
    const text = read(full);
    const refs = references(text);
    expect(refs.filter(isExternal)).toEqual([]);
    expect(text).not.toMatch(/<script\b/i);
    for (const ref of refs) {
      if (ref.startsWith('#')) continue;
      const target = resolveRef(full, ref);
      if (target.startsWith('brand/')) {
        expect(KIT_FILES).toContain(target);
        if (KIT_ON_DISK) expect(fs.existsSync(path.join(ROOT, target))).toBe(true);
      } else {
        expect(target).toMatch(/^docs\/mockups\//);
        expect(fs.existsSync(path.join(ROOT, target))).toBe(true);
      }
    }
  });
});

describe('plain words', () => {
  it.each(textFiles.map(repoPath))('%s uses none of the forbidden jargon', (file) => {
    expect(forbiddenWords(read(path.join(ROOT, file)), FORBIDDEN_JARGON)).toEqual([]);
  });

  it.each(pages)('%s shows no syncing or verifying wait', (name) => {
    const text = read(path.join(MOCKUPS, name)).replace(/<[^>]*>/g, ' ');
    expect(forbiddenWords(text, FORBIDDEN_WAITS)).toEqual([]);
  });

  it.each(textFiles.map(repoPath))('%s has no emoji', (file) => {
    expect(read(path.join(ROOT, file))).not.toMatch(/\p{Extended_Pictographic}/u);
  });

  it.each(pages)('%s writes addresses as 0x and 40 hex characters', (name) => {
    const text = read(path.join(MOCKUPS, name));
    for (const m of text.matchAll(/0x[0-9a-z]*(…[0-9a-z]*)?/gi)) {
      if (m[1]) expect(m[0]).toMatch(/^0x[0-9a-f]{4}…[0-9a-f]{4}$/);
      else expect(m[0]).toMatch(/^0x[0-9a-f]{40}$/);
    }
  });

  it('shows the Test network badge on every screen', () => {
    for (const name of SCREENS) {
      expect(read(path.join(MOCKUPS, name))).toMatch(/class="badge"[^>]*>[\s\S]*?Test network/);
    }
  });

  it('never shows a real backup word', () => {
    const html = read(path.join(MOCKUPS, 'backup.html'));
    const slots = [...html.matchAll(/<span class="placeholder">([^<]*)<\/span>/g)].map((m) => m[1]);
    expect(slots).toHaveLength(24);
    for (const slot of slots) expect(slot).not.toMatch(/[a-z]/i);
    expect(html).toContain('Anyone with these words can spend your GHOST');
  });
});

describe('screen content', () => {
  const has = (name: string, ...needles: string[]) => {
    const html = read(path.join(MOCKUPS, name));
    for (const needle of needles) expect(html).toContain(needle);
  };

  it('welcome offers both ways in', () => {
    has('welcome.html', 'Create a new account', 'I already have 24 words');
  });

  it('import asks for 24 words', () => {
    const html = read(path.join(MOCKUPS, 'import.html'));
    expect(html.match(/<input\b/g)).toHaveLength(24);
  });

  it('backup check asks for three words', () => {
    const html = read(path.join(MOCKUPS, 'backup-check.html'));
    expect(html.match(/<input\b/g)).toHaveLength(3);
  });

  it('home shows the balance, Send, Receive and every activity state', () => {
    has('home.html', 'Balance', 'Send', 'Receive', 'Pending', 'Received', 'Failed, nothing spent', 'Conflicted');
  });

  it('send shows recipient, amount, fee, arrival and Face ID', () => {
    has('send.html', 'To', 'Amount', 'Fee', 'Arrives', 'Send with Face ID');
  });

  it('payment shows its progress, the safety line and both actions', () => {
    has('payment.html', 'Sent', 'In a block', 'Settled', 'Safe to close the app. It never pays twice.', 'Speed up', 'Cancel');
  });

  it('receive shows the address in Plex Mono, a QR placeholder, copy and share', () => {
    has('receive.html', 'class="address"', 'QR code', 'Copy', 'Share');
  });

  it('lock offers Face ID and passcode', () => {
    has('lock.html', 'Face ID', 'passcode');
  });

  it('settings lists account, backup words, app lock, network and about', () => {
    has('settings.html', 'Account', 'Backup words', 'App lock', 'Test network', 'About');
  });
});

describe('click-through', () => {
  it.each(SCREENS.map((name, i) => [name, SCREENS[i + 1] ?? 'index.html']))(
    '%s links to %s',
    (name, next) => {
      expect(hrefs(read(path.join(MOCKUPS, name)))).toContain(next);
    },
  );

  it('index shows and links every screen', () => {
    const html = read(path.join(MOCKUPS, 'index.html'));
    for (const name of SCREENS) {
      expect(html).toContain(`<iframe src="${name}"`);
      expect(hrefs(html)).toContain(name);
    }
  });

  it.each(pages)('%s uses real buttons and links, not clickable boxes', (name) => {
    const html = read(path.join(MOCKUPS, name));
    expect(html).not.toMatch(/\bonclick\s*=/i);
    expect(html).not.toMatch(/\brole\s*=\s*"(button|link)"/i);
    expect(html).not.toMatch(/<a\b(?![^>]*\bhref=)[^>]*>/i);
  });
});

describe('the checks catch off-brand mockups', () => {
  it('flags colors outside the kit, in any case or short form', () => {
    expect(offKitColors('a { color: #fff; background: #F5f5F8 }')).toEqual([]);
    expect(offKitColors('a { color: #123456 }')).toEqual(['#123456']);
    expect(offKitColors('a { color: #000 }')).toEqual(['#000000']);
    expect(offKitColors('<rect fill="#6B4CFF80"/>')).toEqual(['#6b4cff80']);
    expect(offKitColors('a { color: rgb(0, 0, 0) }')).toEqual(['rgb(']);
    expect(offKitColors('a { color: black }')).toEqual(['black']);
    expect(offKitColors('<p>&#8212;</p>')).toEqual([]);
  });

  it('flags a dark body or screen root', () => {
    expect(darkRootBackgrounds('body { background: #0E0D1A }', '')).not.toEqual([]);
    expect(darkRootBackgrounds('.screen.dark { background-color: #6B4CFF }', '')).not.toEqual([]);
    expect(darkRootBackgrounds('', '<main class="screen" style="background: #0e0d1a">')).not.toEqual([]);
    expect(darkRootBackgrounds('body { background: #fff } .screen .x { background: #0E0D1A }', '')).toEqual([]);
  });

  it('flags a redrawn logo', () => {
    expect(redrawsLogo('<rect x="0" y="0" width="26" height="26"/>')).toBe(true);
    expect(redrawsLogo('<path d="M37 50a13 13 0 0 1 26 0v13z"/>')).toBe(true);
    expect(redrawsLogo('<rect x="2" y="7" width="18" height="10" rx="2"/>')).toBe(false);
  });

  it('flags jargon words but not longer words that contain them', () => {
    expect(forbiddenWords('Waiting in the Mempool', FORBIDDEN_JARGON)).toEqual(['mempool']);
    expect(forbiddenWords('PoW and RPC', FORBIDDEN_JARGON)).toEqual(['rpc', 'pow']);
    expect(forbiddenWords('powerful', FORBIDDEN_JARGON)).toEqual([]);
  });
});
