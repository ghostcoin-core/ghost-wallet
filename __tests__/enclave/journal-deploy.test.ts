import fs from 'fs';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

const template = JSON.parse(read('enclave', 'deploy', 'seal-stack.template.json'));
const runbook = read('enclave', 'RUNBOOK.md');
const hostJournal = read('seal', 'src', 'host_journal.rs');
const proxyMain = read('seal', 'src', 'bin', 'seal_proxy.rs');

type Resource = { Type: string; Properties: Record<string, any> };

function userData(): string {
  const resources = Object.values(template.Resources) as Resource[];
  const [launch] = resources.filter((r) => r.Type === 'AWS::EC2::LaunchTemplate');
  const sub = launch.Properties.LaunchTemplateData.UserData['Fn::Base64']['Fn::Sub'];
  return Array.isArray(sub) ? sub[0] : sub;
}

/** The text of the systemd unit file `name` the host script writes. */
function unitFile(script: string, name: string): string {
  const start = script.indexOf(`cat > /etc/systemd/system/${name}.service <<'UNIT'\n`);
  expect(start).toBeGreaterThanOrEqual(0);
  const body = script.slice(start).split('\n');
  const end = body.indexOf('UNIT', 1);
  expect(end).toBeGreaterThan(0);
  return body.slice(1, end).join('\n');
}

describe('the seal-journal unit in enclave/deploy/seal-stack.template.json', () => {
  const script = userData();
  const unit = unitFile(script, 'seal-journal');

  it('runs seal_proxy journal on vsock port 5005 with the journal file', () => {
    expect(unit).toMatch(/^ExecStart=\/opt\/seal\/seal_proxy journal 5005 \/var\/lib\/seal\/journal\.log$/m);
    expect(unit).toMatch(/^Restart=always$/m);
    expect(unit).toMatch(/^WantedBy=multi-user\.target$/m);
  });

  it('keeps the file in a systemd state directory that only the unit can read', () => {
    expect(unit).toMatch(/^StateDirectory=seal$/m);
    expect(unit).toMatch(/^StateDirectoryMode=0700$/m);
    expect(unit).toMatch(/^UMask=0077$/m);
    expect(unit).toMatch(/^DynamicUser=yes$/m);
    // The state directory is where the file is.
    expect(unit).toContain('/var/lib/seal/');
    // No capability: it binds no privileged port.
    expect(unit).not.toMatch(/AmbientCapabilities|CAP_/);
  });

  it('is enabled before the enclave runs and before its start frame', () => {
    const enabled = script.indexOf('systemctl enable --now seal-journal\n');
    expect(enabled).toBeGreaterThan(0);
    expect(enabled).toBeLessThan(script.indexOf('nitro-cli run-enclave'));
    expect(enabled).toBeLessThan(script.indexOf('/opt/seal/seal_proxy start'));
    // After the proxy binary is fetched and checked.
    expect(enabled).toBeGreaterThan(script.indexOf("fetch '${ProxyUrl}'"));
  });

  it('is a vsock service only: no inbound or outbound proxy on 5005', () => {
    expect(script).not.toMatch(/(inbound|outbound) [^']*5005/);
    const ports = template.Resources.SealSecurityGroup.Properties.SecurityGroupIngress;
    expect(ports).toHaveLength(1);
  });

  it('matches the port and file the code uses', () => {
    expect(hostJournal).toMatch(/pub const JOURNAL_PORT: u32 = 5005;/);
    expect(hostJournal).toMatch(/pub const JOURNAL_FILE: &str = "\/var\/lib\/seal\/journal\.log";/);
    expect(hostJournal).toMatch(/pub const PARENT_CID: u32 = 3;/);
    expect(proxyMain).toContain('["journal", port, file]');
    expect(proxyMain).toContain('seal_proxy journal <vsock port> <journal file>');
  });
});

describe('the journal store in enclave/RUNBOOK.md', () => {
  const section = /## The journal store\n([\s\S]*?)\n## /.exec(runbook)?.[1] ?? '';

  it('has a section for the journal store', () => {
    expect(section.length).toBeGreaterThan(0);
  });

  it('names seal_proxy journal, the file and port 5005', () => {
    expect(section).toContain('/opt/seal/seal_proxy journal 5005 /var/lib/seal/journal.log');
    expect(section).toContain('`seal-journal`');
    expect(section).toContain('vsock port 5005');
    expect(section).toContain('StateDirectory=seal');
    expect(section).toContain('0600');
  });

  it('says the journal does not survive the host instance being replaced', () => {
    expect(section).toMatch(/survives the enclave restarting and the host restarting/);
    expect(section).toMatch(/does \*\*not\*\* survive the host instance being replaced/);
    expect(runbook).toMatch(/## Replace a lost region[\s\S]*journal starts empty/);
  });

  it('says what the journal cannot catch: a tail cut while the enclave is stopped', () => {
    expect(section).toMatch(/cuts the end off the log while the enclave is stopped is not\s+caught/);
    expect(section).toMatch(/cut made while the enclave runs is caught/);
  });
});
