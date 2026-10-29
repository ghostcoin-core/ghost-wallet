import fs from 'fs';
import path from 'path';

// app.config.js wraps app.json: unchanged for dev/test builds, store-ready
// when EXPO_PUBLIC_GHOST_BUILD=release.
const ROOT = path.join(__dirname, '..');

type Config = Record<string, any>;

// eslint-disable-next-line @typescript-eslint/no-require-imports
const appConfig = require('../app.config.js') as ((ctx: { config: Config }) => Config) & {
  buildConfig: (config: Config, env: Record<string, string | undefined>) => Config;
};

function appJson(): Config {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'app.json'), 'utf8')).expo;
}

function release(env: Record<string, string | undefined> = {}): Config {
  return appConfig.buildConfig(appJson(), { EXPO_PUBLIC_GHOST_BUILD: 'release', ...env });
}

describe('dev/test configuration', () => {
  it('equals app.json without EXPO_PUBLIC_GHOST_BUILD', () => {
    expect(appConfig.buildConfig(appJson(), {})).toEqual(appJson());
  });

  it('equals app.json for any build other than release', () => {
    expect(appConfig.buildConfig(appJson(), { EXPO_PUBLIC_GHOST_BUILD: 'test' })).toEqual(appJson());
  });

  it('keeps the local network access to the test node', () => {
    const plist = appConfig.buildConfig(appJson(), {}).ios.infoPlist;
    expect(plist.NSAppTransportSecurity.NSAllowsLocalNetworking).toBe(true);
    expect(plist.NSLocalNetworkUsageDescription).toEqual(expect.any(String));
  });

  it('reads process.env when Expo calls the default export', () => {
    const saved = process.env.EXPO_PUBLIC_GHOST_BUILD;
    try {
      delete process.env.EXPO_PUBLIC_GHOST_BUILD;
      expect(appConfig({ config: appJson() })).toEqual(appJson());
      process.env.EXPO_PUBLIC_GHOST_BUILD = 'release';
      expect(appConfig({ config: appJson() }).ios.infoPlist.ITSAppUsesNonExemptEncryption).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.EXPO_PUBLIC_GHOST_BUILD;
      else process.env.EXPO_PUBLIC_GHOST_BUILD = saved;
    }
  });
});

describe('release configuration', () => {
  it('drops the local-networking exception and its usage text', () => {
    const plist = release().ios.infoPlist;
    expect(plist).not.toHaveProperty('NSLocalNetworkUsageDescription');
    expect(plist.NSAppTransportSecurity?.NSAllowsLocalNetworking).toBeUndefined();
    expect(JSON.stringify(release())).not.toContain('NSAllowsLocalNetworking');
  });

  it('strips the local-networking keys that prebuild and plugins add to the generated Info.plist', async () => {
    const mod = release().mods?.ios?.infoPlist;
    expect(typeof mod).toBe('function');
    // What prebuild's template and the dev client write before the mod runs.
    const generated = {
      NSAppTransportSecurity: { NSAllowsArbitraryLoads: false, NSAllowsLocalNetworking: true },
      NSLocalNetworkUsageDescription: 'Expo Dev Launcher uses the local network.',
      NFCReaderUsageDescription: 'nfc',
    };
    const result = await mod({
      modResults: generated,
      modRequest: { nextMod: async (config: Config) => config, platform: 'ios', modName: 'infoPlist' },
    });
    expect(result.modResults).toEqual({
      NSAppTransportSecurity: { NSAllowsArbitraryLoads: false },
      NFCReaderUsageDescription: 'nfc',
      ITSAppUsesNonExemptEncryption: false,
    });
  });

  it('marks the app as exempt from export encryption rules', () => {
    const config = release();
    expect(config.ios.infoPlist.ITSAppUsesNonExemptEncryption).toBe(false);
    expect(config.ios.config.usesNonExemptEncryption).toBe(false);
  });

  it('keeps the NFC, Face ID and other dev/test values', () => {
    const dev = appJson();
    const config = release();
    expect(config.ios.infoPlist.NFCReaderUsageDescription).toBe(dev.ios.infoPlist.NFCReaderUsageDescription);
    expect(config.ios.infoPlist['com.apple.developer.nfc.readersession.iso7816.select-identifiers']).toEqual(
      dev.ios.infoPlist['com.apple.developer.nfc.readersession.iso7816.select-identifiers'],
    );
    expect(config.ios.entitlements).toEqual(dev.ios.entitlements);
    expect(config.ios.bundleIdentifier).toBe(dev.ios.bundleIdentifier);
    expect(config.plugins).toEqual(dev.plugins);
  });

  it('does not change the app.json object it was given', () => {
    const dev = appJson();
    appConfig.buildConfig(dev, { EXPO_PUBLIC_GHOST_BUILD: 'release' });
    expect(dev).toEqual(appJson());
  });

  it('declares no tracking in the privacy manifest', () => {
    const manifest = release().ios.privacyManifests;
    expect(manifest.NSPrivacyTracking).toBe(false);
    expect(manifest.NSPrivacyTrackingDomains).toEqual([]);
  });

  it('declares the required-reason APIs the app and its pods use', () => {
    const types = release().ios.privacyManifests.NSPrivacyAccessedAPITypes as {
      NSPrivacyAccessedAPIType: string;
      NSPrivacyAccessedAPITypeReasons: string[];
    }[];
    const reasons = Object.fromEntries(types.map((t) => [t.NSPrivacyAccessedAPIType, t.NSPrivacyAccessedAPITypeReasons]));
    expect(reasons.NSPrivacyAccessedAPICategoryFileTimestamp).toContain('C617.1');
    expect(reasons.NSPrivacyAccessedAPICategorySystemBootTime).toContain('35F9.1');
    expect(reasons.NSPrivacyAccessedAPICategoryDiskSpace).toContain('E174.1');
    expect(reasons.NSPrivacyAccessedAPICategoryUserDefaults).toContain('CA92.1');
  });

  it('has no privacy manifest in the dev/test configuration', () => {
    expect(appConfig.buildConfig(appJson(), {}).ios.privacyManifests).toBeUndefined();
  });

  it('takes the version from package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    expect(release().version).toBe(pkg.version);
  });

  it('takes the build number from GHOST_BUILD_NUMBER, default 1', () => {
    expect(release().ios.buildNumber).toBe('1');
    expect(release({ GHOST_BUILD_NUMBER: '' }).ios.buildNumber).toBe('1');
    expect(release({ GHOST_BUILD_NUMBER: '42' }).ios.buildNumber).toBe('42');
  });

  it('refuses a build number that is not a positive whole number', () => {
    for (const bad of ['0', '-3', '1.2', 'abc', '07']) {
      expect(() => release({ GHOST_BUILD_NUMBER: bad })).toThrow(/GHOST_BUILD_NUMBER/);
    }
  });
});

describe('icon and splash', () => {
  it('uses the violet app icon from the brand kit', () => {
    const icon = release().icon;
    expect(icon).toBe('./brand/app-icon/ghost-app-icon-violet-1024.png');
    expect(fs.existsSync(path.join(ROOT, icon))).toBe(true);
  });

  it('uses the logo on violet with the brand violet background', () => {
    const splash = release().splash;
    expect(splash.image).toBe('./brand/png/ghost-logo-on-violet-1024.png');
    expect(fs.existsSync(path.join(ROOT, splash.image))).toBe(true);
    expect(splash.backgroundColor).toBe('#6B4CFF');
  });
});

describe('docs/release.md', () => {
  it('records the export compliance decision', () => {
    const doc = fs.readFileSync(path.join(ROOT, 'docs/release.md'), 'utf8');
    expect(doc).toContain('ITSAppUsesNonExemptEncryption');
    expect(doc).toContain('EXPO_PUBLIC_GHOST_BUILD=release');
  });
});
