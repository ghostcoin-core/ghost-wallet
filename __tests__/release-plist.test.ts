import fs from 'fs';
import path from 'path';

// Rebuilds the Info.plist a release prebuild ships, from the same pieces
// prebuild uses: the React Native template's Info.plist, the config's
// ios.infoPlist merged over it, then the infoPlist mods. Prebuild itself needs
// the template from npm, macOS and Xcode, so it does not run here.
const ROOT = path.join(__dirname, '..');

type Config = Record<string, any>;

// eslint-disable-next-line @typescript-eslint/no-require-imports
const appConfig = require('../app.config.js') as {
  buildConfig: (config: Config, env: Record<string, string | undefined>) => Config;
};
// eslint-disable-next-line @typescript-eslint/no-require-imports
const plist = require('plist') as { build: (value: unknown) => string };

function appJson(): Config {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'app.json'), 'utf8')).expo;
}

/** Shaped like the React Native template's ios/<App>/Info.plist. */
function templateInfoPlist(): Config {
  return {
    CFBundleDisplayName: 'GhostWallet',
    CFBundleIdentifier: '$(PRODUCT_BUNDLE_IDENTIFIER)',
    LSRequiresIPhoneOS: true,
    NSAppTransportSecurity: { NSAllowsArbitraryLoads: false, NSAllowsLocalNetworking: true },
    UILaunchStoryboardName: 'SplashScreen',
  };
}

/** Prebuild copies each ios.infoPlist key over the template's, replacing whole values. */
function mergeOverTemplate(config: Config): Config {
  return { ...templateInfoPlist(), ...config.ios.infoPlist };
}

async function runInfoPlistMod(config: Config, infoPlist: Config): Promise<Config> {
  const mod = config.mods?.ios?.infoPlist;
  expect(typeof mod).toBe('function');
  const result = await mod({
    ...config,
    modResults: infoPlist,
    modRequest: { nextMod: async (c: Config) => c, platform: 'ios', modName: 'infoPlist' },
  });
  return result.modResults;
}

describe('release Info.plist', () => {
  const release = () => appConfig.buildConfig(appJson(), { EXPO_PUBLIC_GHOST_BUILD: 'release' });

  it('replaces the template ATS dict before any mod runs', () => {
    const merged = mergeOverTemplate(release());
    expect(merged.NSAppTransportSecurity).toEqual({ NSAllowsArbitraryLoads: false });
    expect(JSON.stringify(merged)).not.toContain('NSAllowsLocalNetworking');
    expect(merged).not.toHaveProperty('NSLocalNetworkUsageDescription');
  });

  it('ships no local-networking exception or usage text', async () => {
    const config = release();
    const shipped = await runInfoPlistMod(config, mergeOverTemplate(config));
    const xml = plist.build(shipped);
    expect(xml).toContain('<key>NSAppTransportSecurity</key>');
    expect(xml).not.toContain('NSAllowsLocalNetworking');
    expect(xml).not.toContain('NSLocalNetworkUsageDescription');
    expect(shipped.NSAppTransportSecurity).toEqual({ NSAllowsArbitraryLoads: false });
    expect(shipped.ITSAppUsesNonExemptEncryption).toBe(false);
    expect(shipped.UILaunchStoryboardName).toBe('SplashScreen');
  });

  it('keeps local networking in the dev/test build', () => {
    const merged = mergeOverTemplate(appConfig.buildConfig(appJson(), {}));
    expect(merged.NSAppTransportSecurity).toEqual({ NSAllowsLocalNetworking: true });
    expect(merged.NSLocalNetworkUsageDescription).toEqual(expect.any(String));
  });
});
