import fs from 'fs';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

const template = JSON.parse(read('enclave', 'deploy', 'seal-stack.template.json'));
const runbook = read('enclave', 'RUNBOOK.md');
const enclaveDoc = read('docs', 'seal-enclave.md');

const instanceType = template.Parameters.InstanceType;
const cpu = template.Parameters.EnclaveCpuCount;
const memory = template.Parameters.EnclaveMemoryMiB;

// A large Graviton host: 2 vCPU (one core each, no hyperthreads) and 4 GiB.
const LARGE_VCPUS = 2;
const LARGE_MEMORY_MIB = 4096;

/** The runbook's "Needs" section, up to the next heading. */
function needs(): string {
  const match = /^## Needs\n([\s\S]*?)(?=^## )/m.exec(runbook);
  if (!match) {
    throw new Error('the runbook has no "Needs" section');
  }
  return match[1].replace(/\s+/g, ' ');
}

describe('the Seal host size', () => {
  it('defaults to a c7g.large and allows it', () => {
    expect(instanceType.Default).toBe('c7g.large');
    expect(instanceType.AllowedValues).toContain('c7g.large');
  });

  it('allows the other large enclave-capable sizes, and still the xlarge ones', () => {
    for (const value of ['c6g.large', 'm7g.large', 'c7g.xlarge', 'c7g.2xlarge', 'm7g.xlarge', 'c6g.xlarge']) {
      expect([value, (instanceType.AllowedValues as string[]).includes(value)]).toEqual([value, true]);
    }
    expect(new Set(instanceType.AllowedValues).size).toBe(instanceType.AllowedValues.length);
  });

  it('gives the enclave 1 vCPU and 2048 MiB by default, within the parameters\' bounds', () => {
    expect(cpu.Default).toBe(1);
    expect(cpu.MinValue).toBeLessThanOrEqual(1);
    expect(cpu.MaxValue).toBeGreaterThanOrEqual(1);
    expect(memory.Default).toBe(2048);
    expect(memory.MinValue).toBeLessThanOrEqual(2048);
    expect(memory.MaxValue).toBeGreaterThanOrEqual(2048);
  });

  it('leaves the host of a large instance a vCPU and about 2 GiB of its own', () => {
    expect(LARGE_VCPUS - cpu.Default).toBeGreaterThanOrEqual(1);
    expect(LARGE_MEMORY_MIB - memory.Default).toBeGreaterThanOrEqual(2048);
  });

  it('still lets an xlarge host give the enclave more than one vCPU', () => {
    expect(cpu.MaxValue).toBeGreaterThanOrEqual(2);
  });
});

describe('the runbook and the design on the host size', () => {
  it('says three c7g.large hosts cost about $160 a month', () => {
    const text = needs();
    expect(text).toContain('about $160 a month for three c7g.large hosts');
    expect(text).not.toMatch(/\$200 to \$400/);
    expect(text).toContain('The enclave takes 1 vCPU and 2048 MiB');
  });

  it('says a larger size is a redeploy that replaces one region at a time', () => {
    const text = needs();
    expect(text).toContain('A larger size is a redeploy that replaces the host');
    expect(text).toContain('Replace one region at a time');
    expect(text).toContain('`InstanceType=c7g.xlarge`');
  });

  it('names the default size in the design', () => {
    const text = enclaveDoc.replace(/\s+/g, ' ');
    expect(text).toContain('By default it is a c7g.large (2 vCPU, 4 GiB): the enclave gets 1 vCPU and 2048 MiB');
  });
});
