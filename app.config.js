// Wraps app.json. app.json is the dev/test configuration (dev client, local
// network access to the test node). With EXPO_PUBLIC_GHOST_BUILD=release the
// same project is configured for a store build. See docs/release.md.
const { withInfoPlist } = require('expo/config-plugins');
const pkg = require('./package.json');

// Required-reason APIs used by React Native, Expo modules and their pods.
// https://developer.apple.com/documentation/bundleresources/privacy_manifest_files/describing_use_of_required_reason_api
const PRIVACY_MANIFEST = {
  NSPrivacyTracking: false,
  NSPrivacyTrackingDomains: [],
  NSPrivacyCollectedDataTypes: [],
  NSPrivacyAccessedAPITypes: [
    {
      NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryFileTimestamp',
      NSPrivacyAccessedAPITypeReasons: ['C617.1', '0A2A.1', '3B52.1'],
    },
    {
      NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategorySystemBootTime',
      NSPrivacyAccessedAPITypeReasons: ['35F9.1'],
    },
    {
      NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryDiskSpace',
      NSPrivacyAccessedAPITypeReasons: ['E174.1', '85F4.1'],
    },
    {
      NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryUserDefaults',
      NSPrivacyAccessedAPITypeReasons: ['CA92.1'],
    },
  ],
};

function isRelease(env) {
  return env.EXPO_PUBLIC_GHOST_BUILD === 'release';
}

function buildNumber(env) {
  const value = (env.GHOST_BUILD_NUMBER ?? '').trim();
  if (value === '') return '1';
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`GHOST_BUILD_NUMBER must be a positive whole number, got "${value}"`);
  }
  return value;
}

/** Removes the local-network keys from an Info.plist object, in place. */
function stripLocalNetworking(infoPlist) {
  delete infoPlist.NSLocalNetworkUsageDescription;
  const ats = { ...infoPlist.NSAppTransportSecurity };
  delete ats.NSAllowsLocalNetworking;
  if (Object.keys(ats).length === 0) delete infoPlist.NSAppTransportSecurity;
  else infoPlist.NSAppTransportSecurity = ats;
  return infoPlist;
}

function releaseConfig(config, env) {
  const ios = config.ios ?? {};
  const infoPlist = stripLocalNetworking({ ...ios.infoPlist });

  infoPlist.ITSAppUsesNonExemptEncryption = false;

  // Prebuild's template and the dev client put NSAllowsLocalNetworking back
  // into the generated Info.plist. A mod added here runs after every plugin's
  // mod, so it has the last word.
  // withInfoPlist writes into config.mods, so give it copies.
  const mods = { ...config.mods, ios: { ...config.mods?.ios } };
  const withMods = withInfoPlist({ ...config, mods }, (modConfig) => {
    stripLocalNetworking(modConfig.modResults);
    modConfig.modResults.ITSAppUsesNonExemptEncryption = false;
    return modConfig;
  });

  return {
    ...withMods,
    version: pkg.version,
    ios: {
      ...ios,
      buildNumber: buildNumber(env),
      config: { ...ios.config, usesNonExemptEncryption: false },
      infoPlist,
      privacyManifests: PRIVACY_MANIFEST,
    },
  };
}

function buildConfig(config, env = process.env) {
  return isRelease(env) ? releaseConfig(config, env) : config;
}

module.exports = ({ config }) => buildConfig(config);
module.exports.buildConfig = buildConfig;
module.exports.PRIVACY_MANIFEST = PRIVACY_MANIFEST;
