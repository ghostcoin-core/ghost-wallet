import fs from 'fs';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

const template = JSON.parse(read('enclave', 'deploy', 'seal-stack.template.json'));
const runbook = read('enclave', 'RUNBOOK.md');
const hostJournal = read('seal', 'src', 'host_journal.rs');
const proxyMain = read('seal', 'src', 'bin', 'seal_proxy.rs');
const anchor = read('seal', 'src', 'journal_anchor.rs');
const enclaveMain = read('seal', 'src', 'bin', 'seal_enclave.rs');

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

  it('runs seal_proxy journal on vsock port 5005 with the journal file and a peer log per other region', () => {
    expect(unit).toMatch(
      /^ExecStart=\/opt\/seal\/seal_proxy journal 5005 \/var\/lib\/seal\/journal\.log \$\{AnchorPeerRegion\}=\/var\/lib\/seal\/peer-\$\{AnchorPeerRegion\}\.log \$\{AnchorPeerRegion2\}=\/var\/lib\/seal\/peer-\$\{AnchorPeerRegion2\}\.log$/m,
    );
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
    expect(proxyMain).toContain('["journal", port, file, peers @ ..]');
    expect(proxyMain).toContain('seal_proxy journal <vsock port> <journal file> [<region>=<peer log file> ...]');
  });

  it('keeps the peer logs where the code says, in the same state directory', () => {
    expect(hostJournal).toMatch(/pub const PEER_LOG_DIR: &str = "\/var\/lib\/seal";/);
    expect(hostJournal).toContain('format!("{PEER_LOG_DIR}/peer-{origin}.log")');
    expect(hostJournal).toMatch(/pub const REQUEST_PEER: u8 = 3;/);
    const peerLogs = [...unit.matchAll(/(\$\{AnchorPeerRegion2?\})=(\S+)/g)].map((m) => [m[1], m[2]]);
    expect(peerLogs).toEqual([
      ['${AnchorPeerRegion}', '/var/lib/seal/peer-${AnchorPeerRegion}.log'],
      ['${AnchorPeerRegion2}', '/var/lib/seal/peer-${AnchorPeerRegion2}.log'],
    ]);
  });
});

describe('the journal anchor ports in enclave/deploy/seal-stack.template.json', () => {
  const script = userData();

  it('carries the enclave vsock ports 5006 and 5007 to the two other regions, outbound only', () => {
    expect(script).toContain("unit seal-anchor 'outbound 5006 ${AnchorPeerAddress}'");
    expect(script).toContain("unit seal-anchor-2 'outbound 5007 ${AnchorPeerAddress2}'");
    expect(script).toMatch(/if \[ -n '\$\{AnchorPeerAddress\}' \]; then\n[^\n]*seal-anchor [^\n]*\n[^\n]*\n {2}systemctl enable --now seal-anchor\n/);
    expect(script).toMatch(/if \[ -n '\$\{AnchorPeerAddress2\}' \]; then\n[^\n]*seal-anchor-2 [^\n]*\n[^\n]*\n {2}systemctl enable --now seal-anchor-2\n/);
    expect(script).not.toMatch(/inbound [^']*500[67]/);
    // Both start before the enclave's start frame.
    expect(script.indexOf('enable --now seal-anchor-2')).toBeLessThan(script.indexOf('/opt/seal/seal_proxy start'));
    // The peers are reached through their proxies' one inbound port: no new ingress.
    expect(template.Resources.SealSecurityGroup.Properties.SecurityGroupIngress).toHaveLength(1);
  });

  it('names the peer regions and their addresses as parameters', () => {
    for (const name of ['AnchorPeerRegion', 'AnchorPeerRegion2']) {
      expect(template.Parameters[name].AllowedPattern).toBe('^[a-z]{2}-[a-z]+-[0-9]$');
      expect(template.Parameters[name].Default).toBeUndefined();
    }
    for (const name of ['AnchorPeerAddress', 'AnchorPeerAddress2']) {
      expect(template.Parameters[name].Default).toBe('');
      expect(template.Parameters[name].AllowedPattern).toBe('^$|^[A-Za-z0-9.-]+:[0-9]+$');
    }
  });

  it('matches the ports, the deadline and the region list the code uses', () => {
    expect(anchor).toMatch(/pub const PEER_PORTS: \[u32; 2\] = \[5006, 5007\];/);
    expect(anchor).toMatch(/pub const PEER_DEADLINE: std::time::Duration = std::time::Duration::from_secs\(10\);/);
    expect(anchor).toMatch(/pub const SERVICE_KIND: u8 = 3;/);
    const compiled = /pub const RELEASE_REGIONS: \[&str; \d+\] = \[([^\]]*)\];/.exec(anchor)?.[1] ?? '';
    const list = [...compiled.matchAll(/"([a-z0-9-]+)"/g)].map((m) => m[1]);
    const regions = JSON.parse(read('enclave', 'deploy', 'regions.json')).regions.map((r: { region: string }) => r.region);
    expect(list).toEqual(regions);
    // The enclave's own region is compiled in, never read from the host.
    expect(enclaveMain).toContain('option_env!("SEAL_REGION")');
    expect(enclaveMain).toContain('.zip(PEER_PORTS)');
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

  it('names the peer log files, the anchor units and ports 5006 and 5007', () => {
    expect(section).toContain('/var/lib/seal/peer-<region>.log');
    expect(section).toContain('peer log files, one per other region');
    expect(section).toContain('vsock ports 5006 and 5007');
    expect(section).toContain('units `seal-anchor` and `seal-anchor-2`');
    expect(section).toContain('ciphertext only');
    expect(section).toMatch(/the durable journal could not be anchored in a peer\s+region/);
  });

  it('says the journal now survives a replaced host and catches a tail cut while the enclave is stopped', () => {
    expect(section).toMatch(/survives the enclave restarting and the host restarting/);
    expect(section).toMatch(/It survives the host instance being replaced/);
    expect(section).toMatch(/restores the whole log from a peer region\s+before it serves/);
    expect(section).toMatch(/cuts the end off the log while the enclave is stopped is\s+caught/);
    expect(section).not.toMatch(/does \*\*not\*\* survive the host instance being replaced/);
    expect(runbook).toMatch(/## Replace a lost region[\s\S]*restores it from a peer region before it serves/);
  });

  it('states the availability cost and what is still not covered', () => {
    expect(section).toMatch(/The cost is availability/);
    expect(section).toMatch(/every Fill and Open in the regions that need it waits/);
    expect(section).toContain('Keep every region running.');
    expect(section).toMatch(/A lost region is replaced by a\s+redeploy, which restores from a peer/);
    expect(section).toMatch(/every region lost at once, nor the hosts of every\s+region cutting the log at once/);
    expect(runbook).toMatch(/## Change the region list[\s\S]*finish every Fill and Open/);
  });
});
