import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

const TEMPLATE_TEXT = read('enclave', 'deploy', 'seal-stack.template.json');
const template = JSON.parse(TEMPLATE_TEXT);
const regions = JSON.parse(read('enclave', 'deploy', 'regions.json'));
const dockerfile = read('enclave', 'Dockerfile');
const buildEnv = read('enclave', 'build.env');
const reproducible = read('enclave', 'scripts', 'check-reproducible.sh');
const deploy = read('enclave', 'scripts', 'deploy.sh');
const cargoToml = read('seal', 'Cargo.toml');

type Resource = { Type: string; Properties: Record<string, any> };
const resources: [string, Resource][] = Object.entries(template.Resources);
const ofType = (type: string) => resources.filter(([, r]) => r.Type === type).map(([, r]) => r);

/** Every value of `key` anywhere under `node`. */
function everyValue(node: unknown, key: string): unknown[] {
  if (Array.isArray(node)) {
    return node.flatMap((item) => everyValue(item, key));
  }
  if (node && typeof node === 'object') {
    return Object.entries(node).flatMap(([k, v]) => (k === key ? [v, ...everyValue(v, key)] : everyValue(v, key)));
  }
  return [];
}

function userData(): string {
  const [launch] = ofType('AWS::EC2::LaunchTemplate');
  const sub = launch.Properties.LaunchTemplateData.UserData['Fn::Base64']['Fn::Sub'];
  return Array.isArray(sub) ? sub[0] : sub;
}

const buildSetting = (key: string) => {
  const match = new RegExp(`^${key}=(\\S+)$`, 'm').exec(buildEnv);
  if (!match) {
    throw new Error(`build.env has no ${key}`);
  }
  return match[1];
};

// Graviton families that support Nitro Enclaves, none burstable.
const ENCLAVE_FAMILIES = ['c6g', 'c7g', 'm6g', 'm7g', 'r6g', 'r7g', 'c8g', 'm8g', 'r8g'];

describe('enclave/deploy/seal-stack.template.json', () => {
  it('is a CloudFormation template with one enclave host, its address and its outputs', () => {
    expect(template.AWSTemplateFormatVersion).toBe('2010-09-09');
    expect(ofType('AWS::EC2::Instance')).toHaveLength(1);
    expect(ofType('AWS::EC2::LaunchTemplate')).toHaveLength(1);
    expect(ofType('AWS::EC2::EIP')).toHaveLength(1);
    expect(template.Outputs.ProxyAddress.Value['Fn::Sub']).toContain('${ProxyPort}');
    // No other kind of compute, storage or secret store.
    const allowed = [
      'AWS::EC2::Instance',
      'AWS::EC2::LaunchTemplate',
      'AWS::EC2::EIP',
      'AWS::EC2::SecurityGroup',
      'AWS::IAM::Role',
      'AWS::IAM::InstanceProfile',
      'AWS::Logs::LogGroup',
    ];
    for (const [name, resource] of resources) {
      expect([name, allowed.includes(resource.Type)]).toEqual([name, true]);
    }
  });

  it('turns enclave support on and allows only enclave-capable, non-burstable instance types', () => {
    const [launch] = ofType('AWS::EC2::LaunchTemplate');
    expect(launch.Properties.LaunchTemplateData.EnclaveOptions).toEqual({ Enabled: true });
    expect(launch.Properties.LaunchTemplateData.InstanceType).toEqual({ Ref: 'InstanceType' });
    const type = template.Parameters.InstanceType;
    expect(type.AllowedValues.length).toBeGreaterThan(0);
    expect(type.AllowedValues).toContain(type.Default);
    for (const value of type.AllowedValues as string[]) {
      const [family, size] = value.split('.');
      expect([value, ENCLAVE_FAMILIES.includes(family)]).toEqual([value, true]);
      expect(value).not.toMatch(/^t\d/);
      // Room for at least the enclave's one vCPU and the host's own.
      expect(size).toMatch(/^(large|\d*xlarge)$/);
    }
    // arm64 hosts for the arm64 enclave program.
    expect(buildSetting('SEAL_TARGET')).toBe('aarch64-unknown-linux-gnu');
    expect(template.Parameters.ImageId.Default).toMatch(/arm64$/);
    expect(TEMPLATE_TEXT).not.toMatch(/CreditSpecification|unlimited/);
  });

  it('allows instance metadata v2 only', () => {
    const [launch] = ofType('AWS::EC2::LaunchTemplate');
    const metadata = launch.Properties.LaunchTemplateData.MetadataOptions;
    expect(metadata.HttpTokens).toBe('required');
    expect(metadata.HttpPutResponseHopLimit).toBe(1);
    expect(everyValue(template, 'HttpTokens')).toEqual(['required']);
  });

  it('has no SSH key and no inbound port but the proxy port', () => {
    expect(TEMPLATE_TEXT).not.toMatch(/KeyName|KeyPair/);
    expect(ofType('AWS::EC2::SecurityGroupIngress')).toHaveLength(0);
    const groups = ofType('AWS::EC2::SecurityGroup');
    expect(groups).toHaveLength(1);
    const ingress = groups[0].Properties.SecurityGroupIngress;
    expect(ingress).toHaveLength(1);
    expect(ingress[0].IpProtocol).toBe('tcp');
    expect(ingress[0].FromPort).toEqual({ Ref: 'ProxyPort' });
    expect(ingress[0].ToPort).toEqual({ Ref: 'ProxyPort' });
    expect(template.Parameters.ProxyPort.Default).toBe(443);
    expect(TEMPLATE_TEXT).not.toMatch(/"FromPort":\s*22\b|"ToPort":\s*22\b/);
    expect(userData()).not.toMatch(/sshd|authorized_keys/);
  });

  it('gives the host a role with no KMS permission at all and no S3, secret or parameter read', () => {
    const roles = ofType('AWS::IAM::Role');
    expect(roles).toHaveLength(1);
    expect(roles[0].Properties.ManagedPolicyArns).toBeUndefined();
    expect(ofType('AWS::IAM::Policy')).toHaveLength(0);
    expect(ofType('AWS::IAM::ManagedPolicy')).toHaveLength(0);
    const actions = everyValue(roles[0].Properties.Policies, 'Action').flat() as string[];
    expect(actions.length).toBeGreaterThan(0);
    for (const action of actions) {
      expect(action).toMatch(/^logs:[A-Za-z]+$/);
    }
    expect(everyValue(roles[0].Properties.Policies, 'NotAction')).toEqual([]);
    expect(everyValue(roles[0].Properties.Policies, 'Effect')).toEqual(['Allow']);
    expect(TEMPLATE_TEXT).not.toMatch(/kms:|"kms|KmsKeyId/i);
    expect(TEMPLATE_TEXT).not.toMatch(/s3:|secretsmanager:|ssm:Get|ssm:\*/i);
    expect(TEMPLATE_TEXT).not.toMatch(/AmazonSSMManagedInstanceCore|AdministratorAccess/);
  });

  it('sets the enclave memory and CPUs aside and never starts it in debug mode', () => {
    const script = userData();
    expect(script).toContain('/etc/nitro_enclaves/allocator.yaml');
    expect(script).toContain('memory_mib: ${EnclaveMemoryMiB}');
    expect(script).toContain('cpu_count: ${EnclaveCpuCount}');
    expect(script).toContain('nitro-enclaves-allocator.service');
    expect(script).toMatch(/nitro-cli run-enclave .*--cpu-count \$\{EnclaveCpuCount\} --memory \$\{EnclaveMemoryMiB\}/);
    expect(script).not.toContain('--debug-mode');
    expect(template.Parameters.EnclaveCpuCount.MinValue).toBeGreaterThanOrEqual(1);
    expect(template.Parameters.EnclaveMemoryMiB.MinValue).toBeGreaterThanOrEqual(1024);
  });

  it('carries the enclave to the two nodes of its release node list, each on its own vsock port', () => {
    const script = userData();
    for (const name of ['GhostNodeAddress', 'GhostNodeAddress2']) {
      expect(template.Parameters[name].Type).toBe('String');
      expect(template.Parameters[name].AllowedPattern).toBe('^[A-Za-z0-9.-]+:[0-9]+$');
      expect(template.Parameters[name].Default).toBeUndefined();
    }
    expect(script).toContain("unit seal-node 'outbound 5003 ${GhostNodeAddress}'");
    expect(script).toContain("unit seal-node-2 'outbound 5004 ${GhostNodeAddress2}'");
    expect(script).toMatch(/systemctl enable --now seal-inbound seal-node seal-node-2\n/);
    // The journal store is the host's one other unit: on the enclave's
    // vsock port 5005, never on the network.
    expect(script).toContain('ExecStart=/opt/seal/seal_proxy journal 5005 /var/lib/seal/journal.log');
    expect(script).toMatch(/systemctl enable --now seal-journal\n/);
    expect(script).not.toMatch(/(inbound|outbound) [^']*5005/);
    // The vsock ports are the node list's.
    const nodeList = read('seal', 'src', 'node_list.rs');
    const ports = [...nodeList.matchAll(/^node \S+ \S+ 443 \/ghost-rpc (\d+)$/gm)].map((m) => Number(m[1]));
    expect(ports).toEqual([5003, 5004]);
    // Outbound only: neither node port is ever inbound.
    expect(script).not.toMatch(/inbound [^']*500[34]/);
  });

  it('runs only the published build, its proxy and its list, each checked against a pinned hash', () => {
    const script = userData();
    for (const [url, hash] of [
      ['EifUrl', 'EifSha256'],
      ['ProxyUrl', 'ProxySha256'],
      ['MeasurementsUrl', 'MeasurementsSha256'],
    ]) {
      expect(script).toMatch(new RegExp(`fetch '\\$\\{${url}\\}' \\S+ '\\$\\{${hash}\\}'`));
      expect(template.Parameters[hash].AllowedPattern).toBe('^[0-9a-f]{64}$');
      expect(template.Parameters[url].AllowedPattern).toBe('^https://.+');
    }
    expect(script).toContain('sha256sum -c -');
    // The journal store runs the same checked proxy binary: no new artifact.
    expect(script).not.toMatch(/fetch '\$\{[A-Za-z]*Journal[A-Za-z]*\}'/);
    expect(Object.keys(template.Parameters).filter((name) => /journal/i.test(name))).toEqual([]);
    expect(script).toContain("--proto '=https'");
    expect(script).toMatch(/seal_proxy start \$\{EnclaveCid\} \$\{StartMode\} \/opt\/seal\/measurements\.json/);
    expect(template.Parameters.StartMode.AllowedValues).toEqual(['genesis', 'join']);
    expect(template.Parameters.StartMode.Default).toBe('join');
    expect(template.Rules.JoinNeedsAPeer.RuleCondition).toEqual({ 'Fn::Equals': [{ Ref: 'StartMode' }, 'join'] });
  });
});

describe('enclave/deploy/regions.json', () => {
  it('lists 2 to 3 distinct regions, the genesis one first and once', () => {
    expect(regions.version).toBe(1);
    expect(regions.stackPrefix).toMatch(/^[a-z][a-z0-9-]+$/);
    const list = regions.regions as { region: string; start: string; peer?: string }[];
    expect(list.length).toBeGreaterThanOrEqual(2);
    expect(list.length).toBeLessThanOrEqual(3);
    const names = list.map((r) => r.region);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) {
      expect(name).toMatch(/^[a-z]{2}-[a-z]+-\d$/);
    }
    expect(list.filter((r) => r.start === 'genesis')).toHaveLength(1);
    expect(list[0].start).toBe('genesis');
    expect(list[0].peer).toBeUndefined();
  });

  it('has every other region join from one listed before it', () => {
    const list = regions.regions as { region: string; start: string; peer?: string }[];
    list.slice(1).forEach((r, i) => {
      expect(r.start).toBe('join');
      expect(list.slice(0, i + 1).map((e) => e.region)).toContain(r.peer);
    });
    for (const r of list) {
      expect(Object.keys(r).every((k) => ['region', 'start', 'peer'].includes(k))).toBe(true);
    }
  });
});

describe('enclave/Dockerfile and the build settings', () => {
  it('pins the toolchain image by digest and builds from scratch otherwise', () => {
    const froms = dockerfile.split('\n').filter((line) => /^FROM\s/.test(line));
    expect(froms.length).toBeGreaterThanOrEqual(2);
    const [builder, ...rest] = froms;
    expect(builder).toMatch(/^FROM docker\.io\/library\/rust:(\d+\.\d+\.\d+)-slim-[a-z]+@sha256:[0-9a-f]{64} AS build$/);
    expect(/rust:(\d+\.\d+\.\d+)/.exec(builder)?.[1]).toBe(buildSetting('SEAL_TOOLCHAIN'));
    // Every later stage starts from the pinned builder stage or from scratch.
    for (const line of rest) {
      expect(line).toMatch(/^FROM (scratch|build) AS [a-z-]+$/);
    }
    // The enclave image is the last, default stage.
    expect(froms[froms.length - 1]).toBe('FROM scratch AS enclave');
    expect(dockerfile).toContain('ENTRYPOINT ["/seal_enclave"]');
    expect(dockerfile).not.toMatch(/:latest|apt-get|apk add|curl |wget /);
  });

  it('builds locked, for the fixed target, with SOURCE_DATE_EPOCH and remapped paths', () => {
    expect(dockerfile).toContain('. /seal-build/enclave/build.env');
    expect(dockerfile).toMatch(/cargo build --release --locked --features nitro --bin seal_enclave/);
    expect(dockerfile).toContain('--target "$SEAL_TARGET"');
    expect(dockerfile).toContain('export SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"');
    expect(dockerfile).toContain('--remap-path-prefix=/seal-build=$SEAL_BUILD_ROOT');
    expect(dockerfile).toContain('--remap-path-prefix=$CARGO_HOME=$SEAL_CARGO_ROOT');
    expect(buildSetting('SEAL_SOURCE_DATE_EPOCH')).toMatch(/^\d{10}$/);
    expect(buildSetting('SEAL_TOOLCHAIN')).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('builds the same way in the reproducibility check', () => {
    const flags = '-C target-feature=$SEAL_TARGET_FEATURES -C link-arg=-Wl,--build-id=none';
    expect(dockerfile).toContain(flags);
    expect(reproducible).toContain(flags);
    expect(reproducible).toContain('enclave/build.env');
    expect(reproducible).toContain('RUSTUP_TOOLCHAIN="$SEAL_TOOLCHAIN"');
    expect(reproducible).toContain('SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"');
    expect(reproducible).toContain('--remap-path-prefix=$root=$SEAL_BUILD_ROOT');
    expect(reproducible).toMatch(/cargo build .*--release --locked --features nitro --bin seal_enclave/);
    // Each region twice, from two directories, with its region compiled in.
    expect(reproducible).toMatch(/first="\$\(build "\$work\/\$region\/first" "\$region"\)"/);
    expect(reproducible).toMatch(/second="\$\(build "\$work\/\$region\/second-build" "\$region"\)"/);
    expect(reproducible).toContain('if [ "$first" != "$second" ]');
    expect(reproducible).toContain('SEAL_REGION="$region"');
  });

  it('keeps the release profile deterministic', () => {
    const profile = /\[profile\.release\]([\s\S]*?)(\n\[|$)/.exec(cargoToml)?.[1] ?? '';
    expect(profile).toMatch(/codegen-units = 1/);
    expect(profile).toMatch(/incremental = false/);
    expect(profile).toMatch(/debug = false/);
    expect(profile).toMatch(/strip = "symbols"/);
  });
});

const REGION_NAMES = (regions.regions as { region: string }[]).map((r) => r.region);
const computePcrs = read('enclave', 'scripts', 'compute-pcrs.sh');
const measurements = JSON.parse(read('enclave', 'measurements.json'));
const runbook = read('enclave', 'RUNBOOK.md');
const enclaveDoc = read('docs', 'seal-enclave.md');

/** The Dockerfile's stages: each `FROM` line and the lines up to the next. */
function stages(): { from: string; body: string }[] {
  return dockerfile
    .split(/^(?=FROM\s)/m)
    .filter((part) => part.startsWith('FROM'))
    .map((part) => ({ from: part.split('\n')[0], body: part }));
}

const stage = (name: string) => {
  const found = stages().find((s) => s.from.endsWith(` AS ${name}`));
  if (!found) {
    throw new Error(`the Dockerfile has no stage ${name}`);
  }
  return found.body;
};

describe('one enclave image per region', () => {
  it('builds the enclave program with the SEAL_REGION build argument, and refuses one not on the compiled list', () => {
    const enclaveBuild = stage('enclave-build');
    expect(stages().find((s) => s.from.endsWith(' AS enclave-build'))?.from).toBe('FROM build AS enclave-build');
    expect(enclaveBuild).toMatch(/^ARG SEAL_REGION$/m);
    // The argument comes before the build, is required and checked against
    // the compiled region list, and reaches cargo (option_env! in seal_enclave).
    expect(enclaveBuild.indexOf('ARG SEAL_REGION')).toBeLessThan(enclaveBuild.indexOf('cargo build'));
    expect(enclaveBuild).toContain('--build-arg SEAL_REGION=<region> is required');
    expect(enclaveBuild).toContain('grep -q "^pub const RELEASE_REGIONS: .*\\"$SEAL_REGION\\"" /seal-build/seal/src/journal_anchor.rs');
    expect(enclaveBuild).toContain('export SEAL_REGION;');
    expect(enclaveBuild).toMatch(/cargo build --release --locked --features nitro --bin seal_enclave/);
    expect(read('seal', 'src', 'bin', 'seal_enclave.rs')).toContain('const OWN_REGION: Option<&str> = option_env!("SEAL_REGION");');
    // The enclave image takes the program built with the region.
    expect(stage('enclave')).toContain('COPY --from=enclave-build /seal_enclave /seal_enclave');
    // The pattern the Dockerfile greps for matches the compiled list's line.
    const anchorSource = read('seal', 'src', 'journal_anchor.rs');
    for (const region of REGION_NAMES) {
      expect(anchorSource).toMatch(new RegExp(`^pub const RELEASE_REGIONS: .*"${region}"`, 'm'));
    }
  });

  it('builds the host proxy without a region, and never sets SEAL_REGION in build.env', () => {
    const proxyBuild = stage('proxy-build');
    expect(proxyBuild).toMatch(/cargo build --release --locked --features nitro --bin seal_proxy/);
    expect(proxyBuild).not.toContain('SEAL_REGION');
    expect(stage('proxy')).toContain('COPY --from=proxy-build /seal_proxy /seal_proxy');
    // The enclave program is built only in its region's stage.
    expect(stage('build')).not.toContain('cargo build');
    expect(buildEnv).not.toMatch(/^SEAL_REGION=/m);
  });

  it('measures every region of regions.json, one EIF and one listed build each', () => {
    expect(computePcrs).toContain('regions_file="$repo/enclave/deploy/regions.json"');
    expect(computePcrs).toContain('if [ -z "$listed" ] || [ "$compiled" != "$listed" ]; then');
    expect(computePcrs).toMatch(/for region in "\$\{regions\[@\]\}"; do\n {2}image="ghost-seal-enclave:\$name-\$region"/);
    expect(computePcrs).toContain('--build-arg "SEAL_REGION=$region"');
    expect(computePcrs).toContain('eif="$out/seal-$region.eif"');
    expect(computePcrs).toContain('--arg name "$name-$region"');
    // No two regions may share a PCR0: each image has its own region.
    expect(computePcrs).toContain("each region's image must be its own");
    // The list changes once, after every region was measured.
    expect(computePcrs).toContain(`jq --argjson entries "$entries" '.builds += $entries' "$list"`);
    expect(computePcrs.indexOf('.builds += $entries')).toBeGreaterThan(computePcrs.lastIndexOf('docker build'));
  });

  it('checks every region builds reproducibly, and differently from the others', () => {
    expect(reproducible).toContain('regions_file="$repo/enclave/deploy/regions.json"');
    expect(reproducible).toMatch(/for region in "\$\{regions\[@\]\}"; do/);
    expect(reproducible).toContain('SEAL_REGION was not compiled in');
  });

  it('lists the published builds one per region of each release in measurements.json', () => {
    expect(measurements.version).toBe(1);
    const builds = measurements.builds as { name: string }[];
    const releases = new Map<string, string[]>();
    for (const build of builds) {
      const region = REGION_NAMES.find((r) => build.name.endsWith(`-${r}`));
      expect([build.name, region !== undefined]).toEqual([build.name, true]);
      const release = build.name.slice(0, build.name.length - (region as string).length - 1);
      releases.set(release, [...(releases.get(release) ?? []), region as string]);
    }
    for (const [release, listed] of releases) {
      expect([release, [...listed].sort()]).toEqual([release, [...REGION_NAMES].sort()]);
    }
  });

  it('documents the per-region images in the runbook and the design', () => {
    expect(runbook).toContain('--build-arg SEAL_REGION=<region>');
    expect(runbook).toContain('enclave/out/seal-<region>.eif');
    expect(runbook).toContain('seal-YYYY-MM-DD-<region>');
    expect(runbook).toContain('`--eif-url <region>=URL --eif-sha256 <region>=HEX`');
    expect(runbook).toContain('ok: took a signed list before the start');
    expect(runbook).toMatch(/Never run one region's EIF in another region's stack/);
    expect(runbook).not.toMatch(/do not pass `SEAL_REGION` yet/);
    expect(enclaveDoc).not.toMatch(/do not set it yet/);
    expect(enclaveDoc).toContain('--build-arg SEAL_REGION=<region>');
  });

  it('has the joining enclave take the signed list before its start, since its giver is another image', () => {
    const proxyMain = read('seal', 'src', 'bin', 'seal_proxy.rs');
    const start = /fn start\(cid: u32, mode: &str, list_file: &str\) -> ! \{([\s\S]*?)\n\}/.exec(proxyMain)?.[1] ?? '';
    const offered = start.indexOf('control(cid, &[&[CONTROL_SIGNED_LIST][..], &list].concat());');
    expect(offered).toBeGreaterThan(0);
    expect(offered).toBeLessThan(start.indexOf('control(cid, &[mode])'));
    const enclaveMain = read('seal', 'src', 'bin', 'seal_enclave.rs');
    expect(enclaveMain).not.toContain('refused: a list comes after the start');
    expect(enclaveMain).toContain('ok: took a signed list{when}');
  });
});

const DEPLOY = path.join(ROOT, 'enclave', 'scripts', 'deploy.sh');
const eifUrl = (region: string) => `https://example.test/seal-${region}.eif`;
const eifHash = (index: number) => 'abcdef'[index].repeat(64);

/** --eif-url and --eif-sha256 for each of `names`, each region its own. */
function eifArgs(names: string[] = REGION_NAMES): string[] {
  return names.flatMap((region) => [
    '--eif-url',
    `${region}=${eifUrl(region)}`,
    '--eif-sha256',
    `${region}=${eifHash(REGION_NAMES.indexOf(region))}`,
  ]);
}

/** The values --apply needs besides the EIFs. */
const APPLY_VALUES = [
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
];

/** Runs deploy.sh with `args`, an `aws` that only records it was called first on the PATH. */
function deployRun(args: string[]) {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-deploy-'));
  const called = path.join(bin, 'aws-called');
  fs.writeFileSync(path.join(bin, 'aws'), `#!/bin/sh\necho "$@" >> '${called}'\nexit 1\n`);
  fs.chmodSync(path.join(bin, 'aws'), 0o755);
  const result = spawnSync('bash', [DEPLOY, ...args], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` },
  });
  const awsCalled = fs.existsSync(called);
  fs.rmSync(bin, { recursive: true, force: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, awsCalled };
}

/** Each printed `aws cloudformation deploy`: its region and EIF parameters. */
function deploys(stdout: string): { region: string; url: string; hash: string }[] {
  return stdout
    .split('\n')
    .filter((line) => line.startsWith('aws cloudformation deploy '))
    .map((line) => ({
      region: /--region (\S+)/.exec(line)?.[1] ?? '',
      url: /EifUrl=(\S+)/.exec(line)?.[1] ?? '',
      hash: /EifSha256=(\S+)/.exec(line)?.[1] ?? '',
    }));
}

describe('enclave/scripts/deploy.sh, one EIF per region', () => {
  it('deploys each region with its own EIF URL and hash', () => {
    const run = deployRun(eifArgs());
    expect(run.stderr).not.toMatch(/^deploy: /m);
    expect(run.status).toBe(0);
    const planned = deploys(run.stdout);
    expect(planned.map((d) => d.region)).toEqual(REGION_NAMES);
    planned.forEach((d, index) => {
      expect(d).toEqual({ region: REGION_NAMES[index], url: eifUrl(REGION_NAMES[index]), hash: eifHash(index) });
    });
    expect(run.awsCalled).toBe(false);
  });

  it('prints a placeholder per region when no EIF is given and nothing is applied', () => {
    const run = deployRun([]);
    expect(run.status).toBe(0);
    const planned = deploys(run.stdout);
    expect(planned).toHaveLength(REGION_NAMES.length);
    planned.forEach((d, index) => {
      expect(d.url).toContain(`eif-url`);
      expect(d.url).toContain(REGION_NAMES[index]);
      expect(d.hash).toContain(REGION_NAMES[index]);
    });
  });

  it('refuses when any region has no EIF, printing or applying, before any aws command', () => {
    const last = REGION_NAMES[REGION_NAMES.length - 1];
    for (const args of [eifArgs(REGION_NAMES.slice(0, -1)), ['--apply', ...APPLY_VALUES, ...eifArgs(REGION_NAMES.slice(0, -1))]]) {
      const run = deployRun(args);
      expect(run.status).toBe(2);
      expect(run.stderr).toContain(`deploy: no EIF for ${last}`);
      expect(run.stdout).not.toContain('aws cloudformation deploy');
      expect(run.awsCalled).toBe(false);
    }
    // --apply with no EIF at all.
    const none = deployRun(['--apply', ...APPLY_VALUES]);
    expect(none.status).toBe(2);
    expect(none.stderr).toContain(`deploy: no EIF for ${REGION_NAMES[0]}`);
    expect(none.awsCalled).toBe(false);
    // A URL without its hash.
    const urlOnly = deployRun([...eifArgs().slice(0, -2)]);
    expect(urlOnly.status).toBe(2);
    expect(urlOnly.stderr).toContain(`deploy: no EIF for ${last}`);
  });

  it('refuses one EIF for two regions, a region not in regions.json, a region twice and the old one-EIF form', () => {
    const same = eifArgs().map((arg) => arg.replace(eifHash(1), eifHash(0)));
    const sameRun = deployRun(['--apply', ...APPLY_VALUES, ...same]);
    expect(sameRun.status).toBe(2);
    expect(sameRun.stderr).toContain(`deploy: ${REGION_NAMES[0]} and ${REGION_NAMES[1]} are given the same EIF`);
    expect(sameRun.awsCalled).toBe(false);

    const sameUrl = eifArgs().map((arg) => arg.replace(eifUrl(REGION_NAMES[2]), eifUrl(REGION_NAMES[0])));
    expect(deployRun(sameUrl).stderr).toContain('are given the same EIF');

    const unknown = deployRun([...eifArgs(), '--eif-url', `sa-east-1=${eifUrl('sa-east-1')}`]);
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain('deploy: --eif-url names sa-east-1, which is not in regions.json');

    const twice = deployRun([...eifArgs(), '--eif-sha256', `${REGION_NAMES[0]}=${eifHash(5)}`]);
    expect(twice.status).toBe(2);
    expect(twice.stderr).toContain(`deploy: --eif-sha256 gives ${REGION_NAMES[0]} twice`);

    const old = deployRun(['--eif-url', eifUrl('any'), '--eif-sha256', eifHash(0)]);
    expect(old.status).toBe(2);
    expect(old.stderr).toContain('deploy: --eif-url takes REGION=VALUE, one per region of regions.json');

    const badHash = deployRun(eifArgs().map((arg) => arg.replace(eifHash(0), 'not-hex')));
    expect(badHash.status).toBe(2);
    expect(badHash.stderr).toContain('the SHA-256 must be 64 lowercase hex digits');
  });

  it('passes each region its own EIF from the per-region arrays, never one EIF for all', () => {
    expect(deploy).toContain('"EifUrl=${eif_urls[index]}"');
    expect(deploy).toContain('"EifSha256=${eif_hashes[index]}"');
    expect(deploy).not.toMatch(/"EifUrl=\$eif_url"|"EifSha256=\$eif_sha256"/);
  });
});

describe('enclave/scripts/deploy.sh', () => {
  it('only prints what it would run unless given --apply', () => {
    expect(deploy).toMatch(/^apply=0$/m);
    expect(deploy).toContain('--apply) apply=1');
    expect(deploy).toMatch(/^run\(\) \{\n {2}if \[ "\$apply" = 1 \]; then\n {4}"\$@"\n {2}else\n {4}printf/m);
    // Every aws command goes through run, lookup or the --apply guard.
    for (const line of deploy.split('\n')) {
      if (/\baws (cloudformation|ec2)\b/.test(line) && !line.trim().startsWith('#')) {
        expect([line, /run aws|lookup "|\[ "\$apply" = 1 \] && aws/.test(line)]).toEqual([line, true]);
      }
    }
    expect(deploy).toContain('regions.json');
    expect(deploy).toContain('seal-stack.template.json');
  });

  it('passes both node addresses to every stack', () => {
    expect(deploy).toContain('--ghost-node) ghost_node=');
    expect(deploy).toContain('--ghost-node-2) ghost_node_2=');
    expect(deploy).toContain('"GhostNodeAddress=$ghost_node"');
    expect(deploy).toContain('"GhostNodeAddress2=$ghost_node_2"');
    // Both are required before anything is applied, and they must differ.
    expect(deploy).toMatch(/for value in [^\n]*"\$ghost_node" "\$ghost_node_2"; do/);
    expect(deploy).toContain('[ "$ghost_node" != "$ghost_node_2" ]');
  });

  it('gives every stack the two other regions as journal anchor peers, for ports 5006 and 5007', () => {
    for (const parameter of [
      '"AnchorPeerRegion=${others[0]}"',
      '"AnchorPeerRegion2=${others[1]}"',
      '"AnchorPeerAddress=$anchor"',
      '"AnchorPeerAddress2=$anchor_2"',
    ]) {
      expect(deploy).toContain(parameter);
    }
    // The other regions, in the list's order, this region left out.
    expect(deploy).toContain(`for other in $(jq -r '.regions[].region' "$regions"); do`);
    expect(deploy).toContain('[ "$other" = "$region" ] || others+=("$other")');
    expect(deploy).toMatch(/journal anchored in \$\{others\[0\]\} \(5006\) and \$\{others\[1\]\} \(5007\)/);
    // Each template parameter deploy.sh sets is one the template takes.
    const set = [...deploy.matchAll(/^ {4}"([A-Za-z0-9]+)=/gm)].map((m) => m[1]);
    expect(set).toEqual(expect.arrayContaining(['AnchorPeerRegion', 'AnchorPeerRegion2', 'AnchorPeerAddress', 'AnchorPeerAddress2']));
    for (const name of set) {
      expect([name, name in template.Parameters]).toEqual([name, true]);
    }
  });

  it('deploys a region again once every peer exists, and refuses a region list the image does not have', () => {
    expect(deploy).toContain('missing+=("$index")');
    expect(deploy).toMatch(/for index in "\$\{again\[@\]\}"; do\n[^\n]*\n {4}if ! two_others_hold_m "\$region"; then\n[\s\S]*?\n {4}deploy_region "\$index"\n {2}done/);
    expect(deploy).toContain('seal/src/journal_anchor.rs');
    expect(deploy).toContain('if [ "$compiled" != "$listed" ]; then');
    const anchor = read('seal', 'src', 'journal_anchor.rs');
    const compiled = /pub const RELEASE_REGIONS: \[&str; \d+\] = \[([^\]]*)\];/.exec(anchor)?.[1] ?? '';
    expect([...compiled.matchAll(/"([a-z0-9-]+)"/g)].map((m) => m[1])).toEqual(
      (regions.regions as { region: string }[]).map((r) => r.region),
    );
  });
});
