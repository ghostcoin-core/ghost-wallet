import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

// deploy.sh --apply against a stub `aws` on the PATH: no AWS account, no
// network. The stub keeps each region's stack, its current host and the
// lines that host logs in /ghost-seal/<stack>, as a scenario scripts them.

const ROOT = path.join(__dirname, '..', '..');
const DEPLOY = path.join(ROOT, 'enclave', 'scripts', 'deploy.sh');
const regions = JSON.parse(fs.readFileSync(path.join(ROOT, 'enclave', 'deploy', 'regions.json'), 'utf8'));
const NAMES = (regions.regions as { region: string }[]).map((r) => r.region);
const PREFIX = regions.stackPrefix as string;
const [US, EU, AP] = NAMES;

const MADE = 'seal_proxy: the enclave answered: ok: made M (genesis)';
const RECEIVED = 'seal_proxy: the enclave answered: ok: received M from a running enclave';
const LIST = 'seal_proxy: the enclave answered: ok: took a signed list before the start';
const PARSE_REFUSED =
  'seal_proxy: the enclave answered: refused: join failed: the key share attestation could not be parsed';
const NO_M_REFUSED =
  'seal_proxy: the enclave answered: refused: join failed: the giver refused: this enclave holds no M yet';

/** What the host of one deploy logs: its lines, seen only after `afterPolls` looks at its stream. */
type Outcome = { lines: string[]; afterPolls?: number };

type Scenario = {
  /** Stacks that exist before the run: each region's current host and its log lines. */
  existing?: Record<string, { lines: string[] }>;
  /** Per region, what the host of its first, second, ... deploy in this run logs. */
  deploys: Record<string, Outcome[]>;
  /** Changes made once the run's `deploys`-th deploy returned. */
  after?: { deploys: number; region: string; instanceState: string }[];
};

/** One aws call the stub answered, and what it saw at that moment. */
type Call =
  | {
      kind: 'deploy';
      region: string;
      params: Record<string, string>;
      /** The host this deploy replaced, if the stack had one. */
      replaced: string | null;
      /** The regions holding M (running host that logged it) just before. */
      holdersBefore: string[];
    }
  | { kind: 'logs'; region: string; instance: string; current: boolean; lines: string[] }
  | { kind: 'other'; argv: string[] };

const STUB = String.raw`
const fs = require('fs');
const statePath = process.env.SEAL_STUB_STATE;
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
const argv = process.argv.slice(2);
const opt = (name) => {
  const at = argv.indexOf(name);
  return at < 0 ? undefined : argv[at + 1];
};
const save = () => fs.writeFileSync(statePath, JSON.stringify(state));
const done = (out, code = 0) => {
  save();
  if (out !== undefined) process.stdout.write(out + '\n');
  process.exit(code);
};
const fail = (message) => {
  state.calls.push({ kind: 'other', argv });
  save();
  process.stderr.write(message + '\n');
  process.exit(254);
};
const region = opt('--region');
const visible = (id) => {
  const host = state.instances[id];
  return host && host.polls > (host.afterPolls || 0) ? host.lines : [];
};
const holdsM = (name) => {
  const stack = state.stacks[name];
  if (!stack) return false;
  const host = state.instances[stack.instance];
  const lines = visible(stack.instance);
  return (
    host.state === 'running' &&
    !lines.some((l) => l.includes('refused:')) &&
    lines.some((l) => l.includes('ok: made M (genesis)') || l.includes('ok: received M from a running enclave'))
  );
};
const [service, command] = argv;
const stackOf = (name) => {
  const expected = state.prefix + '-' + region;
  if (name !== expected) fail('stub: stack ' + name + ' asked for in ' + region);
  return state.stacks[region];
};

if (service === 'cloudformation' && command === 'describe-stacks') {
  const stack = stackOf(opt('--stack-name'));
  if (!stack) fail('An error occurred (ValidationError): Stack with id ' + opt('--stack-name') + ' does not exist');
  state.calls.push({ kind: 'other', argv });
  const query = opt('--query') || '';
  if (query.includes("'ProxyAddress'")) done(region + '.proxy.example.test:443');
  if (query.includes("'InstanceId'")) done(stack.instance);
  if (query === 'Stacks[0].StackStatus') done(stack.status);
  done(JSON.stringify({ Stacks: [{ StackStatus: stack.status }] }));
}
if (service === 'cloudformation' && command === 'deploy') {
  if (opt('--stack-name') !== state.prefix + '-' + region) fail('stub: deploy of ' + opt('--stack-name') + ' in ' + region);
  const at = argv.indexOf('--parameter-overrides');
  const params = {};
  for (const pair of argv.slice(at + 1)) {
    const eq = pair.indexOf('=');
    params[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  const holdersBefore = Object.keys(state.stacks).filter(holdsM);
  state.deployCount += 1;
  const old = state.stacks[region];
  const number = (state.regionDeploys[region] || 0) + 1;
  state.regionDeploys[region] = number;
  // Every deploy replaces the host: the old one is gone, its stream stays.
  if (old) state.instances[old.instance].state = 'terminated';
  const instance = 'i-' + region + '-' + number;
  const outcome = (state.scenario.deploys[region] || [])[number - 1] || { lines: [] };
  state.instances[instance] = { region, state: 'running', lines: outcome.lines, afterPolls: outcome.afterPolls || 0, polls: 0 };
  state.stacks[region] = { instance, status: old ? 'UPDATE_COMPLETE' : 'CREATE_COMPLETE' };
  state.calls.push({ kind: 'deploy', region, params, replaced: old ? old.instance : null, holdersBefore });
  for (const change of state.scenario.after || []) {
    if (change.deploys === state.deployCount) {
      state.instances[state.stacks[change.region].instance].state = change.instanceState;
    }
  }
  done('Successfully created/updated stack - ' + opt('--stack-name'));
}
if (service === 'ec2' && command === 'describe-instances') {
  const host = state.instances[opt('--instance-ids')];
  if (!host || host.region !== region) fail('An error occurred (InvalidInstanceID.NotFound)');
  state.calls.push({ kind: 'other', argv });
  done(host.state);
}
if (service === 'ec2' && command === 'describe-vpcs') {
  state.calls.push({ kind: 'other', argv });
  done('vpc-test');
}
if (service === 'ec2' && command === 'describe-subnets') {
  state.calls.push({ kind: 'other', argv });
  done('subnet-test');
}
if (service === 'logs' && command === 'filter-log-events') {
  const id = opt('--log-stream-names');
  const host = state.instances[id];
  if (opt('--log-group-name') !== '/ghost-seal/' + state.prefix + '-' + region || !host || host.region !== region) {
    fail('An error occurred (ResourceNotFoundException): The specified log stream does not exist.');
  }
  host.polls += 1;
  const lines = visible(id);
  const current = state.stacks[region] !== undefined && state.stacks[region].instance === id;
  state.calls.push({ kind: 'logs', region, instance: id, current, lines });
  if (opt('--query') !== 'events[].message' || opt('--output') !== 'json') fail('stub: unexpected logs query');
  done(JSON.stringify(lines));
}
fail('stub: no answer for aws ' + argv.join(' '));
`;

const APPLY = [
  '--apply',
  '--proxy-url',
  'https://example.test/seal_proxy',
  '--proxy-sha256',
  '1'.repeat(64),
  '--measurements-url',
  'https://example.test/measurements.json',
  '--measurements-sha256',
  '2'.repeat(64),
  '--ghost-node',
  'node-one.example.test:443',
  '--ghost-node-2',
  'node-two.example.test:443',
  ...NAMES.flatMap((region, index) => [
    '--eif-url',
    `${region}=https://example.test/seal-${region}.eif`,
    '--eif-sha256',
    `${region}=${'abc'[index].repeat(64)}`,
  ]),
];

type Run = { status: number | null; stdout: string; stderr: string; calls: Call[] };

/** Runs deploy.sh --apply against the stub, the scenario scripting every region. */
function deployRun(scenario: Scenario, wait = 3): Run {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-deploy-safety-'));
  try {
    const stub = path.join(dir, 'aws');
    fs.writeFileSync(stub, `#!${process.execPath}\n${STUB}`);
    fs.chmodSync(stub, 0o755);
    const stacks: Record<string, { instance: string; status: string }> = {};
    const instances: Record<string, object> = {};
    for (const [region, host] of Object.entries(scenario.existing ?? {})) {
      const instance = `i-${region}-before`;
      stacks[region] = { instance, status: 'CREATE_COMPLETE' };
      instances[instance] = { region, state: 'running', lines: host.lines, afterPolls: 0, polls: 0 };
    }
    const statePath = path.join(dir, 'state.json');
    fs.writeFileSync(
      statePath,
      JSON.stringify({ prefix: PREFIX, scenario, stacks, instances, deployCount: 0, regionDeploys: {}, calls: [] }),
    );
    const result = spawnSync('bash', [DEPLOY, ...APPLY], {
      encoding: 'utf8',
      timeout: 60_000,
      env: {
        ...process.env,
        PATH: `${dir}${path.delimiter}${process.env.PATH ?? ''}`,
        SEAL_STUB_STATE: statePath,
        DEPLOY_START_WAIT: String(wait),
        DEPLOY_START_POLL: '0.1',
      },
    });
    const calls = JSON.parse(fs.readFileSync(statePath, 'utf8')).calls as Call[];
    return { status: result.status, stdout: result.stdout, stderr: result.stderr, calls };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const deploysOf = (run: Run) => run.calls.filter((c): c is Extract<Call, { kind: 'deploy' }> => c.kind === 'deploy');
const deployedRegions = (run: Run) => deploysOf(run).map((d) => d.region);
const ok = (line: string): Outcome => ({ lines: [LIST, line] });

/** Every region's first deploy logs that it holds M; `more` adds later deploys. */
function allHoldM(more: Record<string, Outcome[]> = {}): Record<string, Outcome[]> {
  const deploys: Record<string, Outcome[]> = {};
  NAMES.forEach((region, index) => {
    deploys[region] = [ok(index === 0 ? MADE : RECEIVED), ...(more[region] ?? [])];
  });
  return deploys;
}

/**
 * For each deploy that replaces an existing host: the regions the script
 * saw (in a logs call since the deploy before it) logging that they hold M
 * on their current host, besides the one replaced.
 */
function confirmedBefore(run: Run): { region: string; confirmed: string[] }[] {
  const out: { region: string; confirmed: string[] }[] = [];
  let seen = new Set<string>();
  for (const call of run.calls) {
    if (call.kind === 'logs' && call.current) {
      const holds = call.lines.some((l) => l.includes('ok: made M') || l.includes('ok: received M'));
      const refused = call.lines.some((l) => l.includes('refused:'));
      if (holds && !refused) {
        seen.add(call.region);
      }
    }
    if (call.kind === 'deploy') {
      if (call.replaced !== null) {
        out.push({ region: call.region, confirmed: [...seen].filter((r) => r !== call.region).sort() });
      }
      seen = new Set();
    }
  }
  return out;
}

/** For each deploy that replaced a host: how many other regions held M at that moment. */
const othersHoldingAtReplace = (run: Run) =>
  deploysOf(run)
    .filter((d) => d.replaced !== null)
    .map((d) => [d.region, d.holdersBefore.filter((r) => r !== d.region).length]);

describe('the deploy safety in enclave/RUNBOOK.md and in the printed plan', () => {
  const runbook = fs.readFileSync(path.join(ROOT, 'enclave', 'RUNBOOK.md'), 'utf8');
  const firstDeploy = /## First deploy\n([\s\S]*?)\n## /.exec(runbook)?.[1] ?? '';

  it('says deploy.sh waits for each start outcome, bounded, and stops on a refusal or at the end of the wait', () => {
    expect(firstDeploy).toContain('`/ghost-seal/<stack>`');
    expect(firstDeploy).toContain('`ok: made M (genesis)`');
    expect(firstDeploy).toContain('`ok: received M from a running enclave`');
    expect(firstDeploy).toMatch(/waits at most 15 minutes/);
    expect(firstDeploy).toContain('DEPLOY_START_WAIT=<seconds>');
    expect(firstDeploy).toMatch(/On any `refused:` line, or when\s+the wait runs out, it stops at once/);
    expect(firstDeploy).toMatch(/deploys nothing more: no later region and no second pass/);
  });

  it('says the second pass needs every region holding M and replaces one region at a time, after two others', () => {
    expect(firstDeploy).toMatch(/second pass runs only\s+once every region logged that it holds M/);
    expect(firstDeploy).toMatch(/replaces one region at a time, each\s+only after it checked just then that two other regions hold M and serve/);
    expect(firstDeploy).toMatch(/never replaces a region while it is the\s+only M holder/);
    expect(runbook).toMatch(/## Never[\s\S]*Never replace the host of a region that may be the only one holding M[\s\S]*## Needs/);
  });

  it('prints the wait and the second pass rule in the plan, without calling aws', () => {
    const result = spawnSync('bash', [DEPLOY], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `/nonexistent-aws-dir${path.delimiter}${process.env.PATH ?? ''}` },
    });
    expect(result.status).toBe(0);
    for (const region of NAMES) {
      expect(result.stdout).toContain(`# then wait up to 900s for ${PREFIX}-${region}'s host to log`);
    }
    expect(result.stdout).toContain('each only once two other regions hold M and serve');
  });
});

describe('deploy.sh --apply stops on a refusal', () => {
  it('stops at the refused join with that line, and deploys no later stack and no second pass', () => {
    // The first live deploy: genesis made M, eu-central-1's join was refused.
    const run = deployRun({ deploys: { [US]: [ok(MADE)], [EU]: [{ lines: [LIST, PARSE_REFUSED] }], [AP]: [ok(RECEIVED)] } });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(PARSE_REFUSED);
    expect(run.stderr).toContain('nothing more is deployed');
    expect(deployedRegions(run)).toEqual([US, EU]);
  });

  it('never redeploys the genesis region when the last region was refused M', () => {
    const run = deployRun({
      deploys: { [US]: [ok(MADE)], [EU]: [ok(RECEIVED)], [AP]: [{ lines: [LIST, NO_M_REFUSED] }] },
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(NO_M_REFUSED);
    expect(deployedRegions(run)).toEqual([US, EU, AP]);
  });

  it('stops on a refused: line even when the host also logged an ok', () => {
    const run = deployRun({
      deploys: { [US]: [{ lines: ['seal_proxy: the enclave answered: refused: the list is not signed', MADE] }] },
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('refused: the list is not signed');
    expect(deployedRegions(run)).toEqual([US]);
  });
});

describe('deploy.sh --apply waits for each start, bounded', () => {
  it('stops when a host logs no start outcome within the wait, and deploys nothing more', () => {
    const run = deployRun({ deploys: { [US]: [ok(MADE)], [EU]: [{ lines: [LIST] }], [AP]: [ok(RECEIVED)] } }, 1);
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(new RegExp(`${PREFIX}-${EU}: host i-${EU}-1 logged no start outcome .* within 1s`));
    expect(deployedRegions(run)).toEqual([US, EU]);
    // It looked more than once before it gave up.
    expect(run.calls.filter((c) => c.kind === 'logs' && c.instance === `i-${EU}-1`).length).toBeGreaterThan(2);
  });

  it('waits for an outcome that is logged late, and goes on only after it', () => {
    const deploys = allHoldM({ [US]: [ok(RECEIVED)], [EU]: [ok(RECEIVED)] });
    deploys[EU][0] = { lines: [LIST, RECEIVED], afterPolls: 4 };
    const run = deployRun({ deploys }, 20);
    expect(run.stderr).not.toMatch(/^deploy: /m);
    expect(run.status).toBe(0);
    const calls = run.calls;
    const euOk = calls.findIndex((c) => c.kind === 'logs' && c.instance === `i-${EU}-1` && c.lines.includes(RECEIVED));
    const apDeploy = calls.findIndex((c) => c.kind === 'deploy' && c.region === AP);
    expect(euOk).toBeGreaterThan(0);
    expect(apDeploy).toBeGreaterThan(euOk);
    expect(calls.filter((c) => c.kind === 'logs' && c.instance === `i-${EU}-1`).length).toBeGreaterThanOrEqual(5);
  });

  it('reads only the new host\'s stream: an old host\'s ok is no outcome for its replacement', () => {
    // The second pass replaces us-east-1; its new host never logs.
    const run = deployRun({ deploys: allHoldM({ [US]: [{ lines: [LIST] }] }) }, 1);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`host i-${US}-2 logged no start outcome`);
    expect(deployedRegions(run)).toEqual([US, EU, AP, US]);
  });
});

describe('deploy.sh --apply second pass', () => {
  it('redeploys the earlier regions one at a time, each only once the two others were seen holding M', () => {
    const run = deployRun({ deploys: allHoldM({ [US]: [ok(RECEIVED)], [EU]: [ok(RECEIVED)] }) });
    expect(run.stderr).not.toMatch(/^deploy: /m);
    expect(run.status).toBe(0);
    expect(deployedRegions(run)).toEqual([US, EU, AP, US, EU]);
    const replaced = confirmedBefore(run);
    expect(replaced.map((r) => r.region)).toEqual([US, EU]);
    for (const { region, confirmed } of replaced) {
      expect([region, confirmed]).toEqual([region, NAMES.filter((r) => r !== region).sort()]);
    }
    // Every replaced host had two other holders at that moment.
    expect(othersHoldingAtReplace(run)).toEqual([
      [US, 2],
      [EU, 2],
    ]);
    // The genesis region comes back in join mode, from a running region, with every anchor.
    const again = deploysOf(run)[3].params;
    expect(again.StartMode).toBe('join');
    expect(again.PeerAddress).toBe(`${EU}.proxy.example.test:443`);
    expect(again.AnchorPeerAddress).not.toBe('');
    expect(again.AnchorPeerAddress2).not.toBe('');
    // One at a time: eu-central-1 is replaced only after the new us-east-1 host logged M.
    const usNewOk = run.calls.findIndex((c) => c.kind === 'logs' && c.instance === `i-${US}-2` && c.lines.includes(RECEIVED));
    const euAgain = run.calls.findIndex((c) => c.kind === 'deploy' && c.region === EU && c.params.AnchorPeerAddress2 !== '');
    expect(usNewOk).toBeGreaterThan(0);
    expect(euAgain).toBeGreaterThan(usNewOk);
  });

  it('never replaces a region while it is the only one holding M', () => {
    // Every region logged M, then the hosts of both others stopped.
    const run = deployRun({
      deploys: allHoldM(),
      after: [
        { deploys: 3, region: EU, instanceState: 'stopped' },
        { deploys: 3, region: AP, instanceState: 'stopped' },
      ],
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(
      new RegExp(`^deploy: .*(needs every region to hold M|not replacing the host of ${PREFIX}-${US})`, 'm'),
    );
    expect(run.stderr).toContain(`${EU}'s host i-${EU}-1 is stopped`);
    expect(deployedRegions(run)).toEqual([US, EU, AP]);
  });

  it('does not replace a region when only one other region holds M and serves', () => {
    // The second pass's first replacement went well; then ap-southeast-1's host stopped.
    const run = deployRun({
      deploys: allHoldM({ [US]: [ok(RECEIVED)], [EU]: [ok(RECEIVED)] }),
      after: [{ deploys: 4, region: AP, instanceState: 'stopped' }],
    });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`not replacing the host of ${PREFIX}-${EU}: only 1 other region(s) hold M and serve`);
    expect(run.stderr).toContain(`${AP}'s host i-${AP}-1 is stopped`);
    expect(deployedRegions(run)).toEqual([US, EU, AP, US]);
  });

  it('stops the second pass when a replaced host is refused M, before the next region', () => {
    const run = deployRun({ deploys: allHoldM({ [US]: [{ lines: [LIST, NO_M_REFUSED] }] }) });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(NO_M_REFUSED);
    expect(deployedRegions(run)).toEqual([US, EU, AP, US]);
  });
});

describe('deploy.sh --apply with stacks that already exist', () => {
  it('leaves the only M holder as it is until two other regions hold M, then replaces it', () => {
    // The genesis stack exists and holds M; the others do not exist yet.
    const run = deployRun({
      existing: { [US]: { lines: [LIST, MADE] } },
      deploys: { [US]: [ok(RECEIVED)], [EU]: [ok(RECEIVED), ok(RECEIVED)], [AP]: [ok(RECEIVED)] },
    });
    expect(run.stderr).not.toMatch(/^deploy: /m);
    expect(run.status).toBe(0);
    expect(deployedRegions(run)).toEqual([EU, AP, US, EU]);
    expect(othersHoldingAtReplace(run)).toEqual([
      [US, 2],
      [EU, 2],
    ]);
    expect(confirmedBefore(run).map((r) => r.region)).toEqual([US, EU]);
    for (const { region, confirmed } of confirmedBefore(run)) {
      expect([region, confirmed]).toEqual([region, NAMES.filter((r) => r !== region).sort()]);
    }
    expect(run.stdout).toContain(`${PREFIX}-${US} is left as it is until the second pass`);
  });

  it('refuses to replace an existing host that may hold the only M', () => {
    // The genesis stack exists, its host logged nothing, and no other region holds M.
    const run = deployRun({ existing: { [US]: { lines: [LIST] } }, deploys: allHoldM() });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`not replacing the host of ${PREFIX}-${US}: no other region holds M and serves`);
    expect(deployedRegions(run)).toEqual([]);
  });

  it('replaces an existing host that holds M at once when two other regions hold M too', () => {
    const run = deployRun({
      existing: { [US]: { lines: [MADE] }, [EU]: { lines: [RECEIVED] }, [AP]: { lines: [RECEIVED] } },
      deploys: { [US]: [ok(RECEIVED)], [EU]: [ok(RECEIVED)], [AP]: [ok(RECEIVED)] },
    });
    expect(run.stderr).not.toMatch(/^deploy: /m);
    expect(run.status).toBe(0);
    expect(deployedRegions(run)).toEqual([US, EU, AP]);
    expect(othersHoldingAtReplace(run)).toEqual(NAMES.map((r) => [r, 2]));
    for (const { region, confirmed } of confirmedBefore(run)) {
      expect([region, confirmed]).toEqual([region, NAMES.filter((r) => r !== region).sort()]);
    }
  });
});
