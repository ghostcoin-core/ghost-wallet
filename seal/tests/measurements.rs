//! The published measurements list: the fixture the app's parser reads
//! too, the rules for accepting a build, and every malformed list refused.

use ghost_seal::measurements::{BuildStatus, ListError, MeasurementList, MeasurementRefused, Pcrs, parse_pcr, pcr_hex};

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
fn the_published_list_holds_no_build_yet_and_refuses_every_seal() {
    let published = MeasurementList::parse(PUBLISHED).expect("enclave/measurements.json parses");
    assert!(published.is_empty());
    assert_eq!(published, MeasurementList::empty());
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
