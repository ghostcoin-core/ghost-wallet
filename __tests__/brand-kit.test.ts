import { createHash } from 'crypto';
import { readFileSync, readdirSync } from 'fs';
import { join, relative } from 'path';

const root = join(__dirname, '..');

// SHA-256 and path of every file in brand kit v1.0.
const expected = `
c5d213b3c17685402301a28ee1b15738ad3480076e50778ffccaa41bbfb01a64  brand/README.txt
1c21c67bc404426f27975503b2da7367e4d9c388dd7387592a32c91726cef973  brand/app-icon/ghost-app-icon-violet-1024.png
24b27804942b15b5578230f71ea4a9273c272fcbfb8c8cd26eea1d8b887ee6ac  brand/app-icon/ghost-app-icon-violet-192.png
ed4b40a53b7d4000cee1628eb255b39e96a33afc4b073d70885994236b7248b3  brand/app-icon/ghost-app-icon-violet-512.png
524fd2d6bd55dde328ce6ef5af6a61df8773b94aa51e885e1ddccff1ce15f621  brand/app-icon/ghost-app-icon-violet.svg
f0e666cd6792428c68f6a067a4553126e23b07a180737ad7d9e2ef50b0140ef0  brand/app-icon/ghost-app-icon-white-1024.png
c6908b1c122333852d6753db061d29f56ef1a18c8de6842db3d55cc5a1321eb0  brand/app-icon/ghost-app-icon-white.svg
0d301a746b107391c46120e772cefa521219733b7a39b56c7850e9f3255253a5  brand/favicon/apple-touch-icon.png
39d9cbddc2a8df9668f7b5433fb65854a6abbfb28abb80ad0618ebc2bb344bac  brand/favicon/favicon-16.png
1572e01b7654c00c3e2778942a8e3d03e73d4611e562035756ab24e3f79bed7e  brand/favicon/favicon-32.png
7e873b5dbe2c2ea10f543636b502cb07296b1b4d5d5e2d0b33b84c0bb71cfa26  brand/favicon/favicon-48.png
6fd49195acbbabb45c637d6bca77559bb107c24a8d642dee79234f18a1c05911  brand/favicon/favicon.ico
dc50af79adcb56031e7b1163787ecf182ea5f3928e91d3a44094cc87a51cbf80  brand/favicon/favicon.svg
a9b4c49bb299e05b5f6c481e7fb5e78943d2793249a0c8874ab574a2d1ea6755  brand/fonts/IBMPlexMono-Medium.ttf
7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da  brand/fonts/IBMPlexMono-OFL.txt
6a3412f058c7d8dfd9170c41e85ade48e5156ecb89356110ca57a0a27734af46  brand/fonts/IBMPlexMono-Regular.ttf
9e27a72ed30eb49a08678f6a5d6ed98ec7ba5368f541637ee0683ec9134ef966  brand/fonts/InstrumentSans-OFL.txt
b24f1812584816958afcf22e22d08e44318c5e51651e25d2438efdde389b33b1  brand/fonts/InstrumentSans.ttf
3320abb79ac6f37e858c4b43fce1af2cf7f0819c700fb2c4004ee3192a9f8787  brand/png/ghost-lockup-on-ink-2400.png
133ecc8fd2c815e45c932f0feaa9ae83390fdf711a50ad83ef4c87e6f5798246  brand/png/ghost-lockup-on-violet-2400.png
31b47e66ebefa87894de931519026319dea689a02b1ceca15232686e53d936d0  brand/png/ghost-lockup-one-color-ink-2400.png
f9275c0658d3c233e3afd103e6b74af4a0fd3d5882abc2f1db35f5bdce83bec7  brand/png/ghost-lockup-primary-2400.png
66f40d86b547e4db51dd349133bd1673836acfd82da7a8b85484b7496a79e281  brand/png/ghost-logo-on-ink-1024.png
719dbabd207af623010f112583e7b036a5fd9ca7f51ed1b33fe47af2d3fa72d2  brand/png/ghost-logo-on-ink-256.png
13bdb74516a4f3226c63e317a4adc78ed88ea71bdb0871257461958630996d94  brand/png/ghost-logo-on-violet-1024.png
dbe7d28c4d0772896127d8da57a67a27d21ba07d670bde7d1c9d48b5ce430f30  brand/png/ghost-logo-on-violet-256.png
2400952b0b9f890b176a874694594e289c04d4c4b9d54e7b28610d957e41b2fe  brand/png/ghost-logo-one-color-ink-1024.png
651f5375fc1efa107be82b62691ec4acda29449a817885f8ddb60a005d9836f2  brand/png/ghost-logo-one-color-ink-256.png
ed588e81dbc6828a8dafad5571c927e74885af60870efb49a7fa406278f2cdbe  brand/png/ghost-logo-one-color-white-1024.png
60703291b495fb5c76614363a8fa102deae6d0b805d2c2496c815f64786ff04a  brand/png/ghost-logo-one-color-white-256.png
a58ed9aa657262b4f55fdbc2c0c4161bcc0d7ae7b779866910a644c3e3e9c5bc  brand/png/ghost-logo-primary-1024.png
f672d92f51367d85d5753ae7922d8ef609b2dbb4e53619a43fded18e61447512  brand/png/ghost-logo-primary-256.png
fd9ee4e14e3d11e28d77015e4b96b089e3bace2d5171c1591bbfe1e4e74a4e3f  brand/social/ghost-avatar-800.png
b95bf9581118cd2f727a3815c538a329062a0e2f505b23fcb545408ceb9d20f0  brand/social/ghost-og-image-1200x630.png
f8a80d05e505c38f116fc6eb9e34ae81967c6d802c48b70166a23bd836b4b378  brand/svg/ghost-lockup-on-ink.svg
5d0cd09d4ace41a0e5df8a2d84a4becf9e28e1f1ec16f530643765f6b87dd5d1  brand/svg/ghost-lockup-on-violet.svg
2d9c793315c29eda65e022fcaffdb39c3d7537cc77594e48035dda0897e54880  brand/svg/ghost-lockup-one-color-ink.svg
8d2722f5f063d44f3ffdf8756cbc2694a21596fe69ebed7d5c26aa189669ae1f  brand/svg/ghost-lockup-primary.svg
68a2c92fba54c7a67158fe28fd619e8b30e6307310dcfdbef16119a3eba966b9  brand/svg/ghost-logo-on-ink.svg
f517e0866b02527cd293ed403a316c2fcb348645664e55d61a29556329bdc3b0  brand/svg/ghost-logo-on-violet.svg
13c6eade40bde3161f95ebaf6426932b1c4dfa0e65e2bb6495e85d10a7341e87  brand/svg/ghost-logo-one-color-ink.svg
7fa768269a55891d550728f52880d582ffc5e2d686b389b9efd8d9c7ca5500b4  brand/svg/ghost-logo-one-color-white.svg
17e3ff55b4b1d4668b65583e147d02ed4e662fb1ecad07021d46888354672b85  brand/svg/ghost-logo-primary.svg
`
  .trim()
  .split('\n')
  .map((line) => {
    const [hash, path] = line.split(/\s+/);
    return { hash, path };
  });

function listFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full) : [relative(root, full)];
  });
}

describe('brand kit v1.0', () => {
  it('lists 43 files', () => {
    expect(expected).toHaveLength(43);
  });

  it.each(expected)('$path has the pinned SHA-256', ({ hash, path }) => {
    const bytes = readFileSync(join(root, path));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(hash);
  });

  it('holds no other files except SOURCE.md', () => {
    const allowed = new Set([...expected.map((f) => f.path), 'brand/SOURCE.md']);
    const extra = listFiles(join(root, 'brand')).filter((f) => !allowed.has(f));
    expect(extra).toEqual([]);
  });
});
