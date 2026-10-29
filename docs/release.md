# Release build

`app.json` is the dev/test configuration: the Expo dev client, the local
network access the app needs to reach the Ghost test node on the Mac Studio,
and the test-node defaults. `app.config.js` wraps it. Without
`EXPO_PUBLIC_GHOST_BUILD` (or with any value other than `release`) the config is
exactly `app.json`.

With `EXPO_PUBLIC_GHOST_BUILD=release` the config:

- removes `NSLocalNetworkUsageDescription` from the Info.plist and sets
  `NSAppTransportSecurity` to `NSAllowsArbitraryLoads = false`, so the React
  Native template's `NSAllowsLocalNetworking` exception is replaced;
- sets `ITSAppUsesNonExemptEncryption` to `false` (see below);
- sets `ios.privacyManifests`, which prebuild writes to `PrivacyInfo.xcprivacy`
  in the app bundle;
- takes the version from `package.json` and the build number from
  `GHOST_BUILD_NUMBER`.

The same variable is read at runtime by the app to pick its node list; that
lives under `lib/` and is not part of this configuration.

## Building

On the Mac Studio:

```sh
EXPO_PUBLIC_GHOST_BUILD=release GHOST_BUILD_NUMBER=<n> pnpm exec expo prebuild --platform ios --clean --no-install
```

then install pods and build the `Release` configuration with `xcodebuild`, as
`scripts/mac-install.sh` does. Run prebuild again with `--clean` before going
back to a dev build, so the local-network keys come back.

Check the built app:

```sh
plutil -p <App>.app/Info.plist | grep -E 'ITSAppUsesNonExemptEncryption|NSAllowsLocalNetworking|NSLocalNetworkUsageDescription'
ls <App>.app/PrivacyInfo.xcprivacy
```

Only `ITSAppUsesNonExemptEncryption => false` should be printed, and the
privacy manifest should exist.

## Version and build number

- The marketing version (`CFBundleShortVersionString`) is `version` in
  `package.json`. Bump it there.
- The build number (`CFBundleVersion`) is `GHOST_BUILD_NUMBER`, a positive whole
  number, default `1`. App Store Connect rejects an upload whose build number is
  not higher than the last one for the same version, so pass a higher number for
  every upload (for example the CI run number). Anything that is not a positive
  whole number stops the config from loading.

## Export compliance: `ITSAppUsesNonExemptEncryption = false`

Ghost Wallet uses only standard cryptography, through the operating system and
the open-source Ghost core library:

- authentication: Face ID / passcode through the system, and keys kept in the
  system keychain and on the NTAG 424 card;
- signing transactions and deriving keys with standard, published algorithms.

It does not implement proprietary or non-standard encryption and does not
offer encryption of user data as a feature. Encryption used only for
authentication and digital signatures is exempt under the US Export
Administration Regulations (category 5, part 2, note 3 and the
authentication/signature exclusions), so the app is marked exempt and App Store
Connect does not ask for export documentation on each upload.

This was decided by the front desk. Revisit it, and change the flag in
`app.config.js`, if counsel says otherwise or if the app starts encrypting data
for confidentiality (for example encrypted backups or messaging).

## Privacy manifest

`NSPrivacyTracking` is `false`, there are no tracking domains and no collected
data types. The required-reason APIs declared are the ones React Native, Expo
modules and their pods use:

| API category                                 | Reasons                |
| -------------------------------------------- | ---------------------- |
| `NSPrivacyAccessedAPICategoryFileTimestamp`  | C617.1, 0A2A.1, 3B52.1 |
| `NSPrivacyAccessedAPICategorySystemBootTime` | 35F9.1                 |
| `NSPrivacyAccessedAPICategoryDiskSpace`      | E174.1, 85F4.1         |
| `NSPrivacyAccessedAPICategoryUserDefaults`   | CA92.1                 |

When a pod is added, check its own `PrivacyInfo.xcprivacy` and add any new
category or reason here and in `app.config.js`.

## Icon and splash

Both builds use the brand kit:

- icon: `brand/app-icon/ghost-app-icon-violet-1024.png`;
- splash: `brand/png/ghost-logo-on-violet-1024.png` on Ghost violet `#6B4CFF`.

Prebuild generates the app icon set from `icon`. The `splash` values are the
ones the `expo-splash-screen` config plugin reads; that package is not a
dependency of this project yet, so until it is added the native launch screen
is prebuild's default.
