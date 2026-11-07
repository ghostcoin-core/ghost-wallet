import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

const dockerfile = read('enclave', 'Dockerfile');
const buildEnv = read('enclave', 'build.env');
const lines = dockerfile.split('\n');

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

function buildSetting(name: string): string {
  const match = new RegExp(`^${name}=(.*)$`, 'm').exec(buildEnv);
  if (!match) {
    throw new Error(`enclave/build.env has no ${name}`);
  }
  return match[1].trim();
}

function lineOf(text: string): number {
  const index = lines.indexOf(text);
  if (index < 0) {
    throw new Error(`enclave/Dockerfile has no line ${JSON.stringify(text)}`);
  }
  return index;
}

/** One stage: its `FROM` line through the line before the next `FROM`. */
function stage(name: string): string {
  const start = lines.findIndex((line) => /^FROM\s/.test(line) && line.endsWith(` AS ${name}`));
  if (start < 0) {
    throw new Error(`enclave/Dockerfile has no stage ${name}`);
  }
  const next = lines.findIndex((line, i) => i > start && /^FROM\s/.test(line));
  return lines.slice(start, next < 0 ? lines.length : next).join('\n');
}

/**
 * The text the measured enclave images are built from. Part one runs from the
 * start of the file through the end of the enclave program's stage
 * (`enclave-build`, up to its first blank line): the header, the pinned
 * `build` stage and the region's build. Part two is the enclave image stage
 * (`enclave`) with the comment above it, through the end of the file, so the
 * image stays the last, default stage. The host proxy's stages sit between the
 * two and are not measured.
 */
function measuredText(): { program: string; image: string } {
  const programFrom = lineOf('FROM build AS enclave-build');
  const programEnd = lines.findIndex((line, i) => i > programFrom && line.trim() === '');
  if (programEnd < 0) {
    throw new Error('the enclave-build stage has no end');
  }
  let imageStart = lineOf('FROM scratch AS enclave');
  while (imageStart > 0 && lines[imageStart - 1].startsWith('#')) {
    imageStart -= 1;
  }
  return {
    program: lines.slice(0, programEnd).join('\n'),
    image: lines.slice(imageStart).join('\n'),
  };
}

// SHA-256 of the measured text as the three regions' PCRs were computed from
// it (commit b56ac6a). Changing any of it changes the enclave images.
const PROGRAM_TEXT_SHA256 = '85a3364f8a225ab05477cb33a4e27b9c711aa5e27f4ea0e0c05592a8e4d53431';
const IMAGE_TEXT_SHA256 = '0c9fd778261426691fc6baf1914136b74514859e1ff53090ca59b0df72d3a82d';

describe('enclave/Dockerfile: the measured stages', () => {
  it('leaves every line through the enclave program stage unchanged', () => {
    const { program } = measuredText();
    expect(program.startsWith('# The Seal\'s enclave image, one per region.')).toBe(true);
    expect(program).toContain('FROM docker.io/library/rust:');
    expect(program).toContain('--bin seal_enclave');
    expect(program).not.toContain('seal_proxy');
    expect(sha256(program)).toBe(PROGRAM_TEXT_SHA256);
  });

  it('leaves the enclave image stage unchanged, as the last stage of the file', () => {
    const { image } = measuredText();
    expect(image).toContain('FROM scratch AS enclave\nCOPY --from=enclave-build /seal_enclave /seal_enclave');
    expect(image.split('\n').filter((line) => /^FROM\s/.test(line))).toEqual(['FROM scratch AS enclave']);
    expect(sha256(image)).toBe(IMAGE_TEXT_SHA256);
  });

  it('installs no C toolchain outside the proxy stage', () => {
    const { program, image } = measuredText();
    for (const text of [program, image, stage('build'), stage('enclave-build'), stage('enclave')]) {
      expect(text).not.toMatch(/musl-gcc|musl-tools|dpkg|\bCC_|\bAR_/);
    }
  });
});

describe('enclave/Dockerfile: the host proxy stage', () => {
  const target = buildSetting('SEAL_PROXY_TARGET');
  const proxyBuild = stage('proxy-build');
  const ccVariable = `CC_${target.replace(/-/g, '_')}`;
  const arVariable = `AR_${target.replace(/-/g, '_')}`;

  it('builds the proxy for aarch64 musl from the pinned build stage', () => {
    expect(target).toBe('aarch64-unknown-linux-musl');
    expect(proxyBuild.split('\n')[0]).toBe('FROM build AS proxy-build');
    expect(proxyBuild).toContain('--bin seal_proxy --target "$SEAL_PROXY_TARGET"');
    expect(stage('proxy')).toContain('COPY --from=proxy-build /seal_proxy /seal_proxy');
  });

  it('installs a musl C compiler, each package checked against a fixed SHA-256', () => {
    const debs = [...proxyBuild.matchAll(/^ADD (https:\/\/\S+\.deb) (\/\S+\.deb)$/gm)];
    const names = debs.map(([, url]) => /\/([a-z-]+)_[^/]+_arm64\.deb$/.exec(url)?.[1]);
    expect(names.sort()).toEqual(['musl', 'musl-dev', 'musl-tools']);
    for (const [, url, file] of debs) {
      // A fixed archive snapshot, so the package never changes under the build.
      expect(url).toMatch(/^https:\/\/snapshot\.debian\.org\/archive\/debian\/\d{8}T\d{6}Z\/pool\//);
      expect(proxyBuild).toMatch(new RegExp(`echo "[0-9a-f]{64}  ${file}" \\| sha256sum -c -;`));
      expect(proxyBuild).toContain(file);
    }
    // Every package is checked before any is installed, and all are installed.
    const install = proxyBuild.indexOf('dpkg -i');
    expect(install).toBeGreaterThan(-1);
    expect(proxyBuild.lastIndexOf('sha256sum -c')).toBeLessThan(install);
    const installLine = proxyBuild.slice(install).split(';')[0];
    for (const [, , file] of debs) {
      expect(installLine).toContain(file);
    }
    expect(proxyBuild).toContain('command -v musl-gcc');
    expect(install).toBeLessThan(proxyBuild.indexOf('cargo build'));
  });

  it('points cc-rs at musl-gcc for the musl target before cargo builds', () => {
    expect(ccVariable).toBe('CC_aarch64_unknown_linux_musl');
    const cargo = proxyBuild.indexOf('cargo build');
    const cc = proxyBuild.indexOf(`export ${ccVariable}=musl-gcc;`);
    const ar = proxyBuild.indexOf(`export ${arVariable}=ar;`);
    expect(cc).toBeGreaterThan(-1);
    expect(ar).toBeGreaterThan(-1);
    expect(cc).toBeLessThan(cargo);
    expect(ar).toBeLessThan(cargo);
  });
});
