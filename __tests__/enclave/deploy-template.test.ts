import fs from 'fs';
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
      // Room for the enclave's two vCPUs and the host's own.
      expect(size).toMatch(/^\d*xlarge$/);
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
    expect(template.Parameters.EnclaveCpuCount.MinValue).toBeGreaterThanOrEqual(2);
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
    for (const line of rest) {
      expect(line).toMatch(/^FROM scratch AS [a-z]+$/);
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
    expect(reproducible).toMatch(/first="\$\(build "\$work\/first"\)"/);
    expect(reproducible).toMatch(/second="\$\(build "\$work\/second-build"\)"/);
    expect(reproducible).toContain('if [ "$first" != "$second" ]');
  });

  it('keeps the release profile deterministic', () => {
    const profile = /\[profile\.release\]([\s\S]*?)(\n\[|$)/.exec(cargoToml)?.[1] ?? '';
    expect(profile).toMatch(/codegen-units = 1/);
    expect(profile).toMatch(/incremental = false/);
    expect(profile).toMatch(/debug = false/);
    expect(profile).toMatch(/strip = "symbols"/);
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
});
