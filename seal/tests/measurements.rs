//! The published measurements list: the fixture the app's parser reads
//! too, the rules for accepting a build, and every malformed list refused.

#[path = "fixtures/test_release_key.rs"]
mod release;

use ghost_seal::measurements::{
    BuildStatus, COMPILED_BUILDS, ListError, MeasurementList, MeasurementRefused, Pcrs, RELEASE_KEY_HEX,
    RELEASE_SIGNATURE_BYTES, ReleaseKey, TrustedList, parse_pcr, pcr_hex,
};
use release::{TestOnlyReleaseKey, with_signature};

const FIXTURE: &str = include_str!("fixtures/measurements.json");
const PUBLISHED: &str = include_str!("../../enclave/measurements.json");

fn pcr(byte: u8) -> [u8; 48] {
    [byte; 48]
}

fn pcrs(a: u8, b: u8, c: u8) -> Pcrs {
    Pcrs { pcr0: pcr(a), pcr1: pcr(b), pcr2: pcr(c) }
}

fn hex(byte: u8) -> String {
    pcr_hex(&pcr(byte))
}

/// One build entry as JSON.
fn entry(name: &str, released: &str, a: &str, b: &str, c: &str, status: &str) -> String {
    format!(
        r#"{{"name": "{name}", "released": "{released}", "pcr0": "{a}", "pcr1": "{b}", "pcr2": "{c}", "status": "{status}"}}"#
    )
}

fn list(entries: &[String]) -> String {
    format!(r#"{{"version": 1, "builds": [{}]}}"#, entries.join(", "))
}

fn good_entry() -> String {
    entry("seal-a", "2026-10-01", &hex(0xa1), &hex(0xb1), &hex(0xc1), "allowed")
}

fn refused(text: &str) -> bool {
    MeasurementList::parse(text).is_err()
}

#[test]
fn the_fixture_parses_to_its_three_builds() {
    let list = MeasurementList::parse(FIXTURE).expect("the fixture parses");
    let builds = list.builds();
    assert_eq!(builds.len(), 3);
    assert_eq!(builds[0].name, "seal-2026-09-01");
    assert_eq!(builds[0].status, BuildStatus::Revoked);
    assert_eq!(builds[0].pcrs, pcrs(0xa0, 0xb0, 0xc0));
    assert_eq!(builds[1].name, "seal-2026-10-01");
    assert_eq!(builds[1].released, "2026-10-01");
    assert_eq!(builds[1].status, BuildStatus::Allowed);
    assert_eq!(builds[1].pcrs, pcrs(0xa1, 0xb1, 0xc1));
    assert_eq!(builds[2].name, "seal-2026-11-01");
    assert_eq!(builds[2].pcrs, pcrs(0xa2, 0xb1, 0xc2));
    let allowed: Vec<&str> = list.allowed().map(|b| b.name.as_str()).collect();
    assert_eq!(allowed, ["seal-2026-10-01", "seal-2026-11-01"]);
}

#[test]
fn an_allowed_build_is_accepted_only_with_all_three_pcrs() {
    let list = MeasurementList::parse(FIXTURE).unwrap();
    assert_eq!(list.check(&pcrs(0xa1, 0xb1, 0xc1)).unwrap().name, "seal-2026-10-01");
    assert_eq!(list.check(&pcrs(0xa2, 0xb1, 0xc2)).unwrap().name, "seal-2026-11-01");
    // PCR0 of one build with another's PCR2, or a PCR1 or PCR2 that differs.
    assert_eq!(list.check(&pcrs(0xa1, 0xb1, 0xc2)), Err(MeasurementRefused::NotListed));
    assert_eq!(list.check(&pcrs(0xa1, 0xb2, 0xc1)), Err(MeasurementRefused::NotListed));
    assert_eq!(list.check(&pcrs(0xa1, 0xb1, 0xc3)), Err(MeasurementRefused::NotListed));
    assert_eq!(list.check(&pcrs(0xa3, 0xb1, 0xc1)), Err(MeasurementRefused::NotListed));
}

#[test]
fn a_revoked_build_is_never_accepted() {
    let list = MeasurementList::parse(FIXTURE).unwrap();
    assert_eq!(
        list.check(&pcrs(0xa0, 0xb0, 0xc0)),
        Err(MeasurementRefused::Revoked { name: "seal-2026-09-01".into() })
    );
}

#[test]
fn a_debug_mode_enclave_is_never_accepted() {
    let list = MeasurementList::parse(FIXTURE).unwrap();
    assert_eq!(list.check(&pcrs(0, 0, 0)), Err(MeasurementRefused::DebugMode));
    assert_eq!(list.check(&pcrs(0xa1, 0, 0xc1)), Err(MeasurementRefused::DebugMode));
    // And a list may not name one.
    assert!(refused(&list_with(|e| e.replace(&hex(0xb1), &hex(0)))));
}

fn list_with(change: impl Fn(String) -> String) -> String {
    list(&[change(good_entry())])
}

#[test]
fn the_published_list_holds_the_live_builds_and_refuses_any_other() {
    let published = MeasurementList::parse(PUBLISHED).expect("enclave/measurements.json parses");
    let live = [
        (
            "seal-2026-11-07c-us-east-1",
            "1912432154f1c0afeb0ab5f3cec6483ef9f8fc194207e572b0d4593110159c8e589ca1e73091538fad1ce427acfcc752",
            "144fbf212cf269355f5965e726c5c147adf9a5aee67c2ffcb6eb7e5aa51439444cbf2a53ae6a3aed928f9829152e04a7",
        ),
        (
            "seal-2026-11-07c-eu-central-1",
            "ebc96b54e23b88062170a7a6b028a969a1e28759e095d2b289b9c2ae816d68fcc24063f77aaffb994110eb88821ef67b",
            "6a04b33dfd0ddf1bc872f4449f034060aeb913fe4bd8741e507edec4c60403fe3ff1b6e9fed9c9a3a1c3e958eabff470",
        ),
        (
            "seal-2026-11-07c-ap-southeast-1",
            "8c4c1fc47d821753a1a5881b404842f3556ab5a5beb16ea47a02591f4e23d95521c97276d91dddf727962756c2ac5c00",
            "e5b838beabfd3127e5c567db0afa0460a3c7d890ffe822905a049391e7ef3fd98c9fa8fc3788e035cbe81688bb7bb8c8",
        ),
    ];
    let pcr1 = "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03";
    let builds = published.builds();
    assert_eq!(builds.len(), live.len());
    for (build, (name, pcr0, pcr2)) in builds.iter().zip(live) {
        let expected = Pcrs {
            pcr0: parse_pcr(pcr0).unwrap(),
            pcr1: parse_pcr(pcr1).unwrap(),
            pcr2: parse_pcr(pcr2).unwrap(),
        };
        assert_eq!(build.name, name);
        assert_eq!(build.released, "2026-11-07");
        assert_eq!(build.status, BuildStatus::Allowed);
        assert_eq!(build.pcrs, expected);
        assert_eq!(published.check(&expected).expect("a live build is accepted").name, name);
    }
    assert_eq!(published.check(&pcrs(0xa1, 0xb1, 0xc1)), Err(MeasurementRefused::NotListed));
}

#[test]
fn a_good_list_parses_and_its_pcrs_round_trip() {
    let parsed = MeasurementList::parse(&list(&[good_entry()])).unwrap();
    assert_eq!(parsed.builds()[0].pcrs, pcrs(0xa1, 0xb1, 0xc1));
    assert_eq!(parse_pcr(&hex(0x5e)), Some(pcr(0x5e)));
    assert_eq!(pcr_hex(&pcr(0x0f)), "0f".repeat(48));
}

#[test]
fn the_wrong_version_is_refused() {
    let text = list(&[good_entry()]).replace(r#""version": 1"#, r#""version": 2"#);
    assert!(matches!(MeasurementList::parse(&text), Err(ListError::Format(_))));
    assert!(refused(&list(&[good_entry()]).replace(r#""version": 1"#, r#""version": "1""#)));
    assert!(refused(&list(&[good_entry()]).replace(r#""version": 1"#, r#""version": 1.0"#)));
    assert!(refused(r#"{"builds": []}"#));
    assert!(refused(r#"{"version": 1}"#));
}

#[test]
fn unknown_and_missing_fields_are_refused() {
    assert!(refused(r#"{"version": 1, "builds": [], "extra": true}"#));
    assert!(refused(&list_with(|e| e.replace(r#""status""#, r#""note": "x", "status""#))));
    for field in ["name", "released", "pcr0", "pcr1", "pcr2", "status"] {
        let renamed = list_with(|e| e.replace(&format!(r#""{field}""#), r#""other""#));
        assert!(refused(&renamed), "a build without {field} is refused");
    }
}

#[test]
fn bad_pcrs_are_refused() {
    let upper = hex(0xab).to_uppercase();
    assert!(refused(&list_with(|e| e.replace(&hex(0xa1), &upper))));
    assert!(refused(&list_with(|e| e.replace(&hex(0xa1), &hex(0xa1)[2..]))));
    assert!(refused(&list_with(|e| e.replace(&hex(0xa1), &format!("{}aa", hex(0xa1))))));
    assert!(refused(&list_with(|e| e.replace(&hex(0xa1), &format!("{}zz", &hex(0xa1)[2..])))));
    assert!(refused(&list_with(|e| e.replace(&format!(r#""{}""#, hex(0xa1)), "1234"))));
}

#[test]
fn bad_names_dates_and_statuses_are_refused() {
    assert!(refused(&list_with(|e| e.replace("seal-a", ""))));
    assert!(refused(&list_with(|e| e.replace("seal-a", "seal a"))));
    assert!(refused(&list_with(|e| e.replace("seal-a", &"x".repeat(65)))));
    for date in ["2026-02-30", "2026-13-01", "2026-1-01", "26-10-01", "2026/10/01", "1999-10-01"] {
        assert!(refused(&list_with(|e| e.replace("2026-10-01", date))), "{date} is refused");
    }
    assert!(!refused(&list_with(|e| e.replace("2026-10-01", "2028-02-29"))));
    for status in ["Allowed", "deprecated", ""] {
        assert!(refused(&list_with(|e| e.replace(r#""allowed""#, &format!(r#""{status}""#)))));
    }
}

#[test]
fn a_build_listed_twice_is_refused() {
    let other = entry("seal-b", "2026-11-01", &hex(0xa2), &hex(0xb1), &hex(0xc2), "allowed");
    assert!(!refused(&list(&[good_entry(), other.clone()])), "two builds may share PCR1");
    let same_name = other.replace("seal-b", "seal-a");
    assert!(refused(&list(&[good_entry(), same_name])));
    let same_image = entry("seal-b", "2026-11-01", &hex(0xa1), &hex(0xb1), &hex(0xc1), "revoked");
    assert!(refused(&list(&[good_entry(), same_image])));
}

#[test]
fn json_that_is_not_strict_is_refused() {
    let good = list(&[good_entry()]);
    assert!(refused(&format!("{good} {{}}")));
    assert!(refused(&good.replace("]}", "],}")));
    assert!(refused(&good.replace(r#""version": 1,"#, r#""version": 1, "version": 1,"#)));
    assert!(refused(""));
    assert!(refused("[]"));
    assert!(refused(&format!("{}{}", "[".repeat(40), "]".repeat(40))));
    assert!(refused(&good.replace('"', "'")));
    // Whitespace and escapes that spell the same text are fine.
    let spaced = good.replace(", ", ",\n\t ").replace("seal-a", "seal\\u002da");
    assert_eq!(MeasurementList::parse(&spaced).unwrap(), MeasurementList::parse(&good).unwrap());
}

#[test]
fn the_digest_is_of_the_list_not_its_spacing() {
    let good = list(&[good_entry()]);
    let a = MeasurementList::parse(&good).unwrap();
    let b = MeasurementList::parse(&good.replace(", ", ",\n  ")).unwrap();
    assert_eq!(a.digest(), b.digest());
    let revoked = MeasurementList::parse(&good.replace(r#""allowed""#, r#""revoked""#)).unwrap();
    assert_ne!(a.digest(), revoked.digest());
    assert_ne!(a.digest(), MeasurementList::empty().digest());
}

// The release signature, and the only list an enclave enforces.

fn trusted_with_fixture() -> TrustedList {
    let release = TestOnlyReleaseKey::new();
    let mut trusted = TrustedList::compiled_in();
    trusted.install_signed(&release.sign(FIXTURE), &release.release_key()).expect("the signed fixture is taken");
    trusted
}

/// The fixture with one more allowed build, as a host would add its own.
fn fixture_with_extra_build() -> String {
    let extra = entry("host-build", "2026-11-02", &hex(0xd1), &hex(0xb1), &hex(0xd2), "allowed");
    FIXTURE.replacen("\"builds\": [", &format!("\"builds\": [{extra},"), 1)
}

#[test]
fn a_list_signed_by_the_release_key_is_taken_whatever_its_spacing() {
    let release = TestOnlyReleaseKey::new();
    let signed = release.sign(FIXTURE);
    let list = MeasurementList::parse_signed(&signed, &release.release_key()).unwrap();
    assert_eq!(list, MeasurementList::parse(FIXTURE).unwrap());
    // The signature covers the builds, not the JSON spacing.
    let respaced = signed.replace(", ", ",\n   ");
    assert_eq!(MeasurementList::parse_signed(&respaced, &release.release_key()).unwrap(), list);
    // The app's reader takes a signed file too.
    assert_eq!(MeasurementList::parse(&signed).unwrap(), list);
    assert_eq!(release.signature_hex(FIXTURE).len(), 2 * RELEASE_SIGNATURE_BYTES);
}

#[test]
fn a_list_with_a_missing_signature_is_refused() {
    let release = TestOnlyReleaseKey::new();
    let key = release.release_key();
    assert_eq!(MeasurementList::parse_signed(FIXTURE, &key), Err(ListError::Signature("the list is not signed")));
    // The published file has no signature until the release key signs it.
    assert!(matches!(MeasurementList::parse_signed(PUBLISHED, &key), Err(ListError::Signature(_))));
    let mut trusted = TrustedList::compiled_in();
    assert!(matches!(trusted.install_signed(FIXTURE, &key), Err(ListError::Signature(_))));
    assert!(!trusted.has_signed_list());
    assert_eq!(trusted.check(&pcrs(0xa1, 0xb1, 0xc1)), Err(MeasurementRefused::NotListed));
}

#[test]
fn a_list_with_a_bad_signature_is_refused() {
    let release = TestOnlyReleaseKey::new();
    let key = release.release_key();
    let good = release.signature_hex(FIXTURE);
    let bad = |text: &str| matches!(MeasurementList::parse_signed(text, &key), Err(ListError::Signature(_)));

    // A signature with one digit changed.
    let flipped = format!("{}{}", if good.starts_with('0') { '1' } else { '0' }, &good[1..]);
    assert!(bad(&with_signature(FIXTURE, &flipped)));
    // A signature by another key.
    assert!(bad(&TestOnlyReleaseKey::other().sign(FIXTURE)));
    // The release key's signature over another list: a build added, or a
    // revoked build made allowed after signing.
    assert!(bad(&with_signature(&fixture_with_extra_build(), &good)));
    let unrevoked = FIXTURE.replacen("\"revoked\"", "\"allowed\"", 1);
    assert!(bad(&with_signature(&unrevoked, &good)));
    // A signature that is not one: refused by any reader.
    for not_a_signature in [&good[2..], &good.to_uppercase(), "", "00"] {
        let text = with_signature(FIXTURE, not_a_signature);
        assert!(MeasurementList::parse_signed(&text, &key).is_err());
        assert!(MeasurementList::parse(&text).is_err());
    }
    assert!(MeasurementList::parse(&FIXTURE.replacen('{', "{\"signature\": 1, ", 1)).is_err());
}

#[test]
fn a_host_supplied_list_naming_an_extra_measurement_is_refused() {
    let release = TestOnlyReleaseKey::new();
    let host_list = fixture_with_extra_build();
    let host_build = pcrs(0xd1, 0xb1, 0xd2);
    for offered in [host_list.clone(), TestOnlyReleaseKey::other().sign(&host_list)] {
        // Neither an enclave with no list yet ...
        let mut fresh = TrustedList::compiled_in();
        assert!(matches!(fresh.install_signed(&offered, &release.release_key()), Err(ListError::Signature(_))));
        assert_eq!(fresh.check(&host_build), Err(MeasurementRefused::NotListed));
        // ... nor one holding the signed list takes it, and the held list stays.
        let mut trusted = trusted_with_fixture();
        assert!(matches!(trusted.install_signed(&offered, &release.release_key()), Err(ListError::Signature(_))));
        assert_eq!(trusted.check(&host_build), Err(MeasurementRefused::NotListed));
        assert_eq!(trusted.check(&pcrs(0xa1, 0xb1, 0xc1)).unwrap().name, "seal-2026-10-01");
    }
    // Signed by the release key, the same extra build is taken.
    let mut trusted = trusted_with_fixture();
    trusted.install_signed(&release.sign(&host_list), &release.release_key()).unwrap();
    assert_eq!(trusted.check(&host_build).unwrap().name, "host-build");
}

#[test]
fn a_signed_list_that_does_not_extend_the_held_one_is_refused() {
    let release = TestOnlyReleaseKey::new();
    let key = release.release_key();
    let older = [
        // A held build's PCRs changed.
        FIXTURE.replacen(&format!("\"pcr0\": \"{}\"", hex(0xa0)), &format!("\"pcr0\": \"{}\"", hex(0xa9)), 1),
        // A revoked build made allowed again.
        FIXTURE.replacen("\"revoked\"", "\"allowed\"", 1),
        // Every build dropped.
        r#"{"version": 1, "builds": []}"#.to_string(),
    ];
    for text in older {
        let mut trusted = trusted_with_fixture();
        assert!(matches!(trusted.install_signed(&release.sign(&text), &key), Err(ListError::Rollback(_))), "{text}");
        assert_eq!(
            trusted.check(&pcrs(0xa0, 0xb0, 0xc0)),
            Err(MeasurementRefused::Revoked { name: "seal-2026-09-01".into() })
        );
    }
    // A later list that adds a build and revokes another is taken.
    let later = fixture_with_extra_build().replacen("\"allowed\"", "\"revoked\"", 2);
    let mut trusted = trusted_with_fixture();
    trusted.install_signed(&release.sign(&later), &key).unwrap();
    assert!(matches!(trusted.check(&pcrs(0xa1, 0xb1, 0xc1)), Err(MeasurementRefused::Revoked { .. })));
}

#[test]
fn the_trusted_list_checks_like_the_published_one() {
    let trusted = trusted_with_fixture();
    assert_eq!(trusted.check(&pcrs(0xa1, 0xb1, 0xc1)).unwrap().name, "seal-2026-10-01");
    assert_eq!(trusted.check(&pcrs(0xa2, 0xb1, 0xc2)).unwrap().name, "seal-2026-11-01");
    assert_eq!(trusted.check(&pcrs(0xa1, 0xb1, 0xc2)), Err(MeasurementRefused::NotListed));
    assert_eq!(trusted.check(&pcrs(0xa0, 0xb0, 0xc0)), Err(MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }));
    assert_eq!(trusted.check(&pcrs(0, 0, 0)), Err(MeasurementRefused::DebugMode));
}

#[test]
fn the_image_trusts_only_what_it_compiles_in_until_a_release_key_is_made() {
    // The compiled-in builds parse, and today hold no build.
    assert!(MeasurementList::parse(COMPILED_BUILDS).unwrap().is_empty());
    assert_eq!(TrustedList::compiled_in().check(&pcrs(0xa1, 0xb1, 0xc1)), Err(MeasurementRefused::NotListed));
    // With no release key compiled in, no signed list is taken at all.
    if RELEASE_KEY_HEX.is_empty() {
        assert!(matches!(ReleaseKey::compiled_in(), Err(ListError::Signature(_))));
    } else {
        assert_eq!(RELEASE_KEY_HEX.len(), 2 * 1952);
        assert!(ReleaseKey::compiled_in().is_ok());
    }
}
