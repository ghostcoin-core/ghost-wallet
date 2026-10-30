# Apple accounts and signing

The Apple Developer and App Store Connect setup for release builds. The build
steps themselves are in [release.md](release.md).

Set up on 2026-10-29. Nothing here is secret; the private keys never leave the
Mac Studio.

| Item | Value |
| --- | --- |
| Team | Phantom Systems Inc, team ID `U388328MWX`, Apple Developer Program, enrolled as an organization (renews 2026-12-15) |
| App ID | explicit `com.ghostcoin.wallet` (portal name "XC com ghostcoin wallet"), with NFC Tag Reading |
| Distribution certificate | "Apple Distribution: Phantom Systems Inc (U388328MWX)", expires 2027-10-29; private key in the Mac Studio login keychain |
| App Store provisioning profile | "Ghost Wallet App Store", for `com.ghostcoin.wallet` with that certificate, expires 2027-10-29; installed in Xcode's provisioning profiles folder on the Mac Studio |
| App Store Connect app | "Ghost Wallet App" (the name "Ghost Wallet" was already taken), Apple ID `6828639686`, bundle ID `com.ghostcoin.wallet`, primary language English (U.S.), SKU `ghost-wallet-ios` |
| App Store Connect API key | team key "Ghost Wallet release", App Manager access, key ID `FNB4V6XS49` |

The API key's `.p8` file (`AuthKey_<key ID>.p8`) and a note file with its key
ID and issuer ID (`asc-api-key.env`) are in the private release-config folder
under `~/.config/` on the Mac Studio, both mode 600. Below, `$ASC_DIR` is that
folder. Apple lets the `.p8` be downloaded only once; if it is lost, revoke the
key in App Store Connect (Users and Access, Integrations) and make a new one.

Check the key works:

```sh
set -a; . "$ASC_DIR/asc-api-key.env"; set +a
API_PRIVATE_KEYS_DIR="$ASC_DIR" xcrun altool --list-apps --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
```

It should list "Ghost Wallet App" with bundle ID `com.ghostcoin.wallet`.

Over plain `ssh`, the login keychain is locked, so signing (archive, export)
must run in the logged-in GUI session, for example through `gui-run` on the
Mac Studio.

Renew the certificate and the profile before 2027-10-29, and accept any new
Apple Developer Program License Agreement when Apple posts one, or signing
and uploads stop working.
