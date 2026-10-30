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

## Uploading to TestFlight

`scripts/release-testflight.sh` makes a store build of the current commit on
the Mac Studio (Xcode, CocoaPods, Node 22 and rustup installed) and uploads it
to App Store Connect, from where it reaches TestFlight.

The Apple team, App ID, certificate, profile, App Store Connect app and API
key it relies on are recorded in [app-store-connect.md](app-store-connect.md).

Signing needs no Apple account signed in to Xcode. The export signs manually
with the Apple Distribution certificate for the team in the login keychain and
the installed App Store provisioning profile for the bundle id, named by
`GHOST_EXPORT_PROFILE` (default `Ghost Wallet App Store`).

1. Check out the commit to release, normally the tip of `main`. The script
   refuses to run with any uncommitted change or untracked file, so the build
   always matches a commit.
2. Try it without uploading:

   ```sh
   bash scripts/release-testflight.sh --dry-run
   ```

   The dry run does everything except the upload, needs no App Store Connect
   key and makes no call to Apple when it exports. It leaves a signed `GhostWallet.ipa` in
   `ios/build/release/export/` (git-ignored).
3. Upload, with the App Store Connect API key:

   ```sh
   GHOST_ASC_KEY_PATH=<path to the .p8 file> \
   GHOST_ASC_KEY_ID=<key id> \
   GHOST_ASC_ISSUER_ID=<issuer id> \
   bash scripts/release-testflight.sh
   ```

   - `GHOST_ASC_KEY_PATH`: the path of the API key's `.p8` file. Keep it outside
     the repository (for example in `~/.appstoreconnect/`); never commit it.
   - `GHOST_ASC_KEY_ID`: the key's id, shown next to it in App Store Connect
     (Users and Access, Integrations).
   - `GHOST_ASC_ISSUER_ID`: the issuer id shown on the same page.

   Without all three, or when the key file does not exist, the script refuses
   to run. It never prints their values.

What the script does, in order:

- checks the tree is clean, the build number and (unless `--dry-run`) the key
  variables, before it builds anything;
- prints the version and build number;
- `pnpm install --frozen-lockfile`, builds the Rust core and its bindings as
  `scripts/mac-install.sh` does;
- `expo prebuild --platform ios --clean` with `EXPO_PUBLIC_GHOST_BUILD=release`
  and `GHOST_BUILD_NUMBER` set, then `pod install`;
- `xcodebuild archive` of the `Release` configuration into
  `ios/build/release/GhostWallet.xcarchive`;
- `xcodebuild -exportArchive` with an export options plist it writes to a
  temporary file: method `app-store-connect`, manual signing with the
  `Apple Distribution` certificate and the profile named by
  `GHOST_EXPORT_PROFILE` for the bundle id, the team id and bundle id from
  `app.json`, and destination `upload` (or `export` for `--dry-run`). A real run passes the key with `-authenticationKeyPath`,
  `-authenticationKeyID` and `-authenticationKeyIssuerID`;
- prints the version and build number again, and the `.ipa` path on a dry run.

The build then shows in App Store Connect under TestFlight once Apple has
processed it. Run prebuild again with `--clean` before going back to a dev
build (the install script does).

## Building by hand

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
  not higher than the last one for the same version, so every upload needs a
  higher number. Anything that is not a positive whole number stops the config
  from loading.
- `scripts/release-testflight.sh` sets `GHOST_BUILD_NUMBER` to the number of
  commits on the current branch (`git rev-list --count HEAD`), which goes up
  with every commit on `main`; nothing is written to a file. It warns when run
  off `main`. To use another number, set `GHOST_BUILD_NUMBER` yourself; the
  script refuses one that is not a positive whole number.

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
