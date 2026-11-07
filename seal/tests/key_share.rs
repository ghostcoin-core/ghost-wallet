//! The handover of M between enclaves, with simulated attestation
//! documents from a test authority: a good handover, and every way a
//! receiver, a giver, a document or a package can be wrong.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "fixtures/test_release_key.rs"]
mod release;

use std::fmt::{Debug, Display};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use authority::{Authority, AuthoritySource, NOW, allowed_new, allowed_old, pcrs, revoked, unlisted};
use ghost_seal::attestation::fake::{FakeSource, FakeVerifier};
use ghost_seal::attestation::{AttestationRejected, AttestationVerifier};
use ghost_seal::key_share::{
    self, CONTROL_GENESIS, CONTROL_JOIN, CONTROL_REGISTRY, CONTROL_SIGNED_LIST, ControlFrame, GiverContext, KEM_KEY_BYTES, NONCE_BYTES,
    Receiver, ShareRefused, read_frame, write_frame,
};
use ghost_seal::measurements::{ListError, MeasurementRefused, OWN_BUILD_NAME, TrustedList};
use release::TestOnlyReleaseKey;
use ghost_seal::phone_attestation::answer_key;
use ghost_seal::primitives::sha3_256;
use ghost_seal::proxy::relay;
use ghost_seal::{Clock, MasterKey, SealError, SealRandom};

const FIXTURE: &str = include_str!("fixtures/measurements.json");
/// The test master key's bytes (a fixed pattern: test only).
const TEST_M: [u8; 32] = [
    0x6d, 0x31, 0x9c, 0x02, 0xe7, 0x4b, 0x58, 0xa0, 0x13, 0xfe, 0x27, 0x84, 0xc9, 0x5a, 0x36, 0x0b, 0x91, 0x7d, 0xd2,
    0x48, 0x2f, 0xb6, 0x05, 0xec, 0x63, 0x1a, 0x8e, 0xf4, 0x57, 0xc0, 0x29, 0x9b,
];

fn master() -> MasterKey {
    let mut bytes = TEST_M;
    MasterKey::take(&mut bytes)
}

/// Deterministic test randomness: SHA3-256 of a label and a counter.
struct TestRandom {
    label: u64,
    counter: u64,
}

impl TestRandom {
    fn new(label: u64) -> TestRandom {
        TestRandom { label, counter: 0 }
    }
}

impl SealRandom for TestRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.counter += 1;
            let block = sha3_256(&[b"key share test random", &self.label.to_be_bytes(), &self.counter.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

/// The fixture, signed by the tests' stand-in for the release key, as an
/// enclave holding it would trust it.
fn trusted_fixture() -> TrustedList {
    trusted_list(FIXTURE)
}

fn trusted_list(text: &str) -> TrustedList {
    let release = TestOnlyReleaseKey::new();
    let mut trusted = TrustedList::compiled_in();
    trusted.install_signed(&release.sign(text), &release.release_key()).unwrap();
    trusted
}

struct World {
    authority: Rc<Authority>,
    list: TrustedList,
}

impl World {
    fn new() -> World {
        World { authority: Rc::new(Authority::new(0x21)), list: trusted_fixture() }
    }

    fn source(&self, measured: ghost_seal::measurements::Pcrs) -> AuthoritySource {
        AuthoritySource::new(self.authority.clone(), measured)
    }

    fn receiver(&self, measured: ghost_seal::measurements::Pcrs, label: u64) -> Receiver {
        Receiver::start(&mut self.source(measured), &mut TestRandom::new(label)).unwrap()
    }

    /// The giver (build `measured`) answering `request` under `list`.
    fn give_as(
        &self,
        measured: ghost_seal::measurements::Pcrs,
        list: &TrustedList,
        verifier: &dyn AttestationVerifier,
        request: &[u8],
        now: u64,
    ) -> Result<key_share::GivenPackage, ShareRefused> {
        key_share::package_for(
            &master(),
            request,
            GiverContext {
                verifier,
                list,
                source: &mut self.source(measured),
                random: &mut TestRandom::new(99),
                now_unix: now,
            },
        )
    }

    fn give(&self, request: &[u8]) -> Result<Vec<u8>, ShareRefused> {
        self.give_as(allowed_old(), &self.list, &self.authority.verifier(), request, NOW).map(|g| g.package)
    }

    fn accept(&self, receiver: Receiver, package: &[u8]) -> Result<MasterKey, ShareRefused> {
        receiver.accept(package, &self.authority.verifier(), &self.list, NOW).map(|(m, _)| m)
    }
}

/// Two master keys are the same M when they derive the same answer key.
fn same_m(a: &MasterKey, b: &MasterKey) -> bool {
    answer_key(a) == answer_key(b)
}

#[test]
fn a_good_handover_gives_the_new_build_the_same_m() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let given = world.give_as(allowed_old(), &world.list, &world.authority.verifier(), &receiver.request(), NOW).unwrap();
    assert_eq!(given.receiver.name, "seal-2026-11-01");
    let (received, giver) = receiver.accept(&given.package, &world.authority.verifier(), &world.list, NOW).unwrap();
    assert_eq!(giver.name, "seal-2026-10-01");
    assert!(same_m(&received, &master()));
    let mut other = [0x11; 32];
    assert!(!same_m(&received, &MasterKey::take(&mut other)));
}

#[test]
fn a_receiver_on_a_measurement_not_on_the_list_is_refused() {
    let world = World::new();
    let receiver = world.receiver(unlisted(), 1);
    assert_eq!(world.give(&receiver.request()).err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed)));
    // And with only what the image compiles in (no build today), nobody but
    // a copy of the giver's own build gets M.
    let receiver = world.receiver(allowed_new(), 1);
    let refused = world.give_as(
        allowed_old(),
        &TrustedList::compiled_in(),
        &world.authority.verifier(),
        &receiver.request(),
        NOW,
    );
    assert_eq!(refused.err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed)));
}

#[test]
fn a_revoked_build_is_never_given_m() {
    let world = World::new();
    let receiver = world.receiver(revoked(), 1);
    assert_eq!(
        world.give(&receiver.request()).err(),
        Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }))
    );
}

#[test]
fn a_receiver_whose_pcr1_or_pcr2_differs_from_the_list_is_refused() {
    let world = World::new();
    for measured in [pcrs(0xa2, 0xb2, 0xc2), pcrs(0xa2, 0xb1, 0xc1), pcrs(0xa2, 0xb1, 0xc3)] {
        let receiver = world.receiver(measured, 1);
        assert_eq!(
            world.give(&receiver.request()).err(),
            Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed))
        );
    }
    let debug = world.receiver(pcrs(0, 0, 0), 1);
    assert_eq!(world.give(&debug.request()).err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::DebugMode)));
}

#[test]
fn a_giver_not_on_the_list_is_refused_by_the_receiver() {
    let world = World::new();
    // A rogue giver that lists itself under its own key; the receiver holds
    // the list the release key signed.
    let rogue = FIXTURE.replace("\"builds\": [", &format!("\"builds\": [{},", rogue_entry()));
    let rogue_key = TestOnlyReleaseKey::other();
    let mut rogue_list = TrustedList::compiled_in();
    rogue_list.install_signed(&rogue_key.sign(&rogue), &rogue_key.release_key()).unwrap();
    let receiver = world.receiver(allowed_new(), 1);
    let given = world.give_as(unlisted(), &rogue_list, &world.authority.verifier(), &receiver.request(), NOW).unwrap();
    assert_eq!(
        world.accept(receiver, &given.package).err(),
        Some(ShareRefused::GiverNotAllowed(MeasurementRefused::NotListed))
    );
}

fn rogue_entry() -> String {
    format!(
        r#"{{"name": "rogue", "released": "2026-11-02", "pcr0": "{}", "pcr1": "{}", "pcr2": "{}", "status": "allowed"}}"#,
        "d1".repeat(48),
        "b1".repeat(48),
        "d2".repeat(48)
    )
}

#[test]
fn a_revoked_or_unlisted_giver_does_not_give() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let request = receiver.request();
    for (giver, why) in [
        (revoked(), MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }),
        (unlisted(), MeasurementRefused::NotListed),
    ] {
        let refused = world.give_as(giver, &world.list, &world.authority.verifier(), &request, NOW);
        assert_eq!(refused.err(), Some(ShareRefused::GiverNotAllowed(why)));
    }
}

/// The host's own build: a valid enclave, on no list the giver trusts.
fn host_entry() -> String {
    format!(
        r#"{{"name": "host-build", "released": "2026-11-02", "pcr0": "{}", "pcr1": "{}", "pcr2": "{}", "status": "allowed"}}"#,
        "d1".repeat(48),
        "b1".repeat(48),
        "d2".repeat(48)
    )
}

#[test]
fn a_host_supplied_list_naming_an_extra_measurement_is_refused() {
    let world = World::new();
    let host_list = FIXTURE.replace("\"builds\": [", &format!("\"builds\": [{},", host_entry()));
    let release = TestOnlyReleaseKey::new();
    // The giver is offered the host's list unsigned, and signed by a key that
    // is not the release key: both refused, and the held list is unchanged.
    let mut giver_list = world.list.clone();
    for offered in [host_list.clone(), TestOnlyReleaseKey::other().sign(&host_list)] {
        assert!(matches!(giver_list.install_signed(&offered, &release.release_key()), Err(ListError::Signature(_))));
    }
    // So the host's build, with a perfectly good document, gets no M.
    let receiver = world.receiver(unlisted(), 1);
    let refused = world.give_as(allowed_old(), &giver_list, &world.authority.verifier(), &receiver.request(), NOW);
    assert_eq!(refused.err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed)));
}

#[test]
fn a_handover_to_a_build_not_on_the_trusted_list_is_refused_even_with_a_valid_document() {
    let world = World::new();
    let receiver = world.receiver(unlisted(), 1);
    let request = receiver.request();
    // The receiver's document itself is good: right root, fresh, its key bound.
    let document = &request[4 + KEM_KEY_BYTES + 4..];
    let attested = world.authority.verifier().verify(document, NOW).expect("a valid document");
    assert_eq!(attested.pcrs, unlisted());
    // A giver trusting the signed list, or only itself, or both, refuses it.
    let mut own_only = TrustedList::compiled_in();
    own_only.trust_own_build(&mut world.source(allowed_old()), &world.authority.verifier(), NOW).unwrap();
    let mut both = world.list.clone();
    both.trust_own_build(&mut world.source(allowed_old()), &world.authority.verifier(), NOW).unwrap();
    for list in [&world.list, &own_only, &both, &TrustedList::compiled_in()] {
        let refused = world.give_as(allowed_old(), list, &world.authority.verifier(), &request, NOW);
        assert_eq!(refused.err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed)));
    }
}

#[test]
fn a_join_ignores_any_list_the_host_passes() {
    let host_list = FIXTURE.replace("\"builds\": [", &format!("\"builds\": [{},", host_entry()));
    let frame = [&[CONTROL_JOIN][..], host_list.as_bytes()].concat();
    // The join start has no field for a list: whatever follows is dropped.
    assert_eq!(ControlFrame::parse(&frame), Ok(ControlFrame::Join));
    assert_eq!(ControlFrame::parse(&[CONTROL_JOIN]), Ok(ControlFrame::Join));
    assert_eq!(ControlFrame::parse(&[CONTROL_JOIN, 0xff, 0xfe]), Ok(ControlFrame::Join));
    // A genesis start or a later list hands its text to the signature check.
    let genesis = [&[CONTROL_GENESIS][..], host_list.as_bytes()].concat();
    assert_eq!(ControlFrame::parse(&genesis), Ok(ControlFrame::Genesis { signed_list: Some(host_list.as_str()) }));
    assert_eq!(ControlFrame::parse(&[CONTROL_GENESIS]), Ok(ControlFrame::Genesis { signed_list: None }));
    let later = [&[CONTROL_SIGNED_LIST][..], host_list.as_bytes()].concat();
    assert_eq!(ControlFrame::parse(&later), Ok(ControlFrame::SignedList(host_list.as_str())));
    // Kind 4 carries the card registry's text.
    let registry = [&[CONTROL_REGISTRY][..], b"04518dfaa96180 2026-11-06 lot-1 0011223344556677\n"].concat();
    assert_eq!(
        ControlFrame::parse(&registry),
        Ok(ControlFrame::Registry("04518dfaa96180 2026-11-06 lot-1 0011223344556677\n"))
    );
    assert_eq!(ControlFrame::parse(&[CONTROL_REGISTRY]), Ok(ControlFrame::Registry("")));
    for bad in [&[][..], &[0][..], &[5][..], &[CONTROL_SIGNED_LIST, 0xff][..], &[CONTROL_REGISTRY, 0xff][..]] {
        assert!(ControlFrame::parse(bad).is_err());
    }

    // The joining enclave checks its giver against what it trusts itself:
    // a giver on the host's list only is refused.
    let world = World::new();
    let mut joiner = TrustedList::compiled_in();
    joiner.trust_own_build(&mut world.source(allowed_new()), &world.authority.verifier(), NOW).unwrap();
    let receiver = world.receiver(allowed_new(), 1);
    let host_trusted = trusted_list(&host_list);
    let given = world.give_as(unlisted(), &host_trusted, &world.authority.verifier(), &receiver.request(), NOW).unwrap();
    assert_eq!(
        receiver.accept(&given.package, &world.authority.verifier(), &joiner, NOW).err(),
        Some(ShareRefused::GiverNotAllowed(MeasurementRefused::NotListed))
    );
}

#[test]
fn a_copy_of_the_same_build_gets_m_with_no_list_at_all() {
    let world = World::new();
    let mut giver = TrustedList::compiled_in();
    giver.trust_own_build(&mut world.source(allowed_old()), &world.authority.verifier(), NOW).unwrap();
    let mut joiner = TrustedList::compiled_in();
    joiner.trust_own_build(&mut world.source(allowed_old()), &world.authority.verifier(), NOW).unwrap();
    let receiver = world.receiver(allowed_old(), 1);
    let given = world.give_as(allowed_old(), &giver, &world.authority.verifier(), &receiver.request(), NOW).unwrap();
    assert_eq!(given.receiver.name, OWN_BUILD_NAME);
    let (received, from) = receiver.accept(&given.package, &world.authority.verifier(), &joiner, NOW).unwrap();
    assert_eq!(from.name, OWN_BUILD_NAME);
    assert!(same_m(&received, &master()));
    // Another build is not a copy.
    let other = world.receiver(allowed_new(), 2);
    let refused = world.give_as(allowed_old(), &giver, &world.authority.verifier(), &other.request(), NOW);
    assert_eq!(refused.err(), Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::NotListed)));
}

#[test]
fn a_signed_list_that_revokes_the_givers_own_build_stops_it_giving() {
    let world = World::new();
    let mut giver = TrustedList::compiled_in();
    giver.trust_own_build(&mut world.source(revoked()), &world.authority.verifier(), NOW).unwrap();
    let receiver = world.receiver(revoked(), 1);
    assert!(world.give_as(revoked(), &giver, &world.authority.verifier(), &receiver.request(), NOW).is_ok());
    let release = TestOnlyReleaseKey::new();
    giver.install_signed(&release.sign(FIXTURE), &release.release_key()).unwrap();
    let receiver = world.receiver(revoked(), 2);
    let refused = world.give_as(revoked(), &giver, &world.authority.verifier(), &receiver.request(), NOW);
    assert_eq!(
        refused.err(),
        Some(ShareRefused::ReceiverNotAllowed(MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }))
    );
    // A debug-mode enclave never trusts its own build.
    let mut debug = TrustedList::compiled_in();
    assert!(debug.trust_own_build(&mut world.source(pcrs(0, 0, 0)), &world.authority.verifier(), NOW).is_err());
}

#[test]
fn a_tampered_receiver_document_is_refused() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let mut request = receiver.request();
    let last = request.len() - 1;
    request[last] ^= 0x01;
    assert_eq!(world.give(&request).err(), Some(ShareRefused::ReceiverDocument(AttestationRejected::BadSignature)));
}

#[test]
fn a_tampered_package_is_refused() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let package = world.give(&receiver.request()).unwrap();
    // The giver's document (just after the 8-byte head), the KEM ciphertext,
    // the ciphertext and the tag.
    let length = u32::from_be_bytes(package[4..8].try_into().unwrap()) as usize;
    let cases = [
        (8 + length - 1, "the giver document's signature"),
        (8 + length + 10, "the KEM ciphertext"),
        (package.len() - 40, "the ciphertext"),
        (package.len() - 1, "the tag"),
    ];
    for (at, what) in cases {
        let mut tampered = package.clone();
        tampered[at] ^= 0x01;
        let receiver = world.receiver(allowed_new(), 1);
        let refused = world.accept(receiver, &tampered).err().unwrap_or_else(|| panic!("{what} tampered is refused"));
        match what {
            "the giver document's signature" => {
                assert_eq!(refused, ShareRefused::GiverDocument(AttestationRejected::BadSignature))
            }
            // The giver's document binds the KEM ciphertext.
            "the KEM ciphertext" => assert!(matches!(refused, ShareRefused::Binding(_))),
            _ => assert_eq!(refused, ShareRefused::BadPackage),
        }
    }
    let receiver = world.receiver(allowed_new(), 1);
    assert!(matches!(world.accept(receiver, &package[..package.len() - 1]), Err(ShareRefused::Malformed(_))));
}

#[test]
fn the_wrong_root_is_refused_both_ways() {
    let world = World::new();
    let other = Authority::new(0x51);
    let receiver = world.receiver(allowed_new(), 1);
    let refused = world.give_as(allowed_old(), &world.list, &other.verifier(), &receiver.request(), NOW);
    assert_eq!(refused.err(), Some(ShareRefused::ReceiverDocument(AttestationRejected::WrongRoot)));
    let package = world.give(&receiver.request()).unwrap();
    assert_eq!(
        receiver.accept(&package, &other.verifier(), &world.list, NOW).err(),
        Some(ShareRefused::GiverDocument(AttestationRejected::WrongRoot))
    );
}

#[test]
fn an_expired_document_is_refused_both_ways() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let late = NOW + 3600;
    let refused = world.give_as(allowed_old(), &world.list, &world.authority.verifier(), &receiver.request(), late);
    assert_eq!(refused.err(), Some(ShareRefused::ReceiverDocument(AttestationRejected::Expired)));
    let package = world.give(&receiver.request()).unwrap();
    assert_eq!(
        receiver.accept(&package, &world.authority.verifier(), &world.list, late).err(),
        Some(ShareRefused::GiverDocument(AttestationRejected::Expired))
    );
}

#[test]
fn a_package_for_another_nonce_is_refused() {
    let world = World::new();
    let first = world.receiver(allowed_new(), 1);
    let package = world.give(&first.request()).unwrap();
    // Same build, its own fresh nonce and key.
    let second = world.receiver(allowed_new(), 2);
    assert_eq!(world.accept(second, &package).err(), Some(ShareRefused::Binding("the package is for another nonce")));
}

#[test]
fn a_package_for_another_receiver_is_refused() {
    let world = World::new();
    // Two receivers with the same randomness, so the same key and nonce, but
    // their own documents (another build): the package names the first.
    let first = world.receiver(allowed_new(), 1);
    let package = world.give(&first.request()).unwrap();
    let second = Receiver::start(&mut world.source(allowed_old()), &mut TestRandom::new(1)).unwrap();
    assert_eq!(&second.request()[..4 + KEM_KEY_BYTES], &first.request()[..4 + KEM_KEY_BYTES]);
    assert_eq!(world.accept(second, &package).err(), Some(ShareRefused::Binding("the package is for another receiver")));
    // The package still opens for the receiver it was made for, once.
    assert!(world.accept(first, &package).is_ok());
}

#[test]
fn a_request_whose_document_does_not_bind_its_key_is_refused() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let other = world.receiver(allowed_new(), 2);
    let mut request = receiver.request();
    request[4..4 + KEM_KEY_BYTES].copy_from_slice(&other.request()[4..4 + KEM_KEY_BYTES]);
    assert_eq!(
        world.give(&request).err(),
        Some(ShareRefused::Binding("the receiver's document does not bind its key"))
    );
}

#[test]
fn a_document_without_the_receivers_nonce_is_refused() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let request = receiver.request();
    // Re-sign the receiver's document with a 16-byte nonce.
    let kem_key = &request[4..4 + KEM_KEY_BYTES];
    let binding = sha3_256(&[key_share::REQUEST_LABEL, kem_key]);
    let document = world.authority.document(&allowed_new(), &binding, &[0x01; 16]);
    let mut short = request[..4 + KEM_KEY_BYTES].to_vec();
    short.extend_from_slice(&(document.len() as u32).to_be_bytes());
    short.extend_from_slice(&document);
    assert!(matches!(world.give(&short), Err(ShareRefused::Binding(_))));
    assert_eq!(NONCE_BYTES, 32);
}

#[test]
fn malformed_requests_are_refused() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let request = receiver.request();
    let wrong_magic = [&b"XXXX"[..], &request[4..]].concat();
    let bad: [&[u8]; 4] = [b"", b"GKQ1", &request[..request.len() - 1], &wrong_magic];
    for bad in bad {
        assert!(matches!(world.give(bad), Err(ShareRefused::Malformed(_))));
    }
    let mut long = request.clone();
    long.push(0);
    assert!(matches!(world.give(&long), Err(ShareRefused::Malformed(_))));
}

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

#[test]
fn the_protocol_runs_with_any_verifier_and_source() {
    let list = trusted_fixture();
    let verifier = FakeVerifier::new([3; 32]);
    let mut receiver_source = FakeSource::new([3; 32], allowed_new(), Box::new(FixedClock(NOW)));
    let receiver = Receiver::start(&mut receiver_source, &mut TestRandom::new(1)).unwrap();
    let mut giver_source = FakeSource::new([3; 32], allowed_old(), Box::new(FixedClock(NOW)));
    let given = key_share::package_for(
        &master(),
        &receiver.request(),
        GiverContext {
            verifier: &verifier,
            list: &list,
            source: &mut giver_source,
            random: &mut TestRandom::new(9),
            now_unix: NOW,
        },
    )
    .unwrap();
    let (received, _) = receiver.accept(&given.package, &verifier, &list, NOW).unwrap();
    assert!(same_m(&received, &master()));
}

/// Records every byte a relay carries, in both directions.
struct Tap<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: Read> Read for Tap<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl<S: Write> Write for Tap<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ghost_seal::proxy::ProxyStream for Tap<UnixStream> {
    fn duplicate(&self) -> std::io::Result<Self> {
        Ok(Tap { inner: self.inner.try_clone()?, seen: self.seen.clone() })
    }
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(read)?;
        self.inner.set_write_timeout(write)
    }
    fn close(&self) {
        let _ = self.inner.shutdown(std::net::Shutdown::Both);
    }
}

#[test]
fn the_proxys_view_of_a_handover_shows_no_m() {
    let world = World::new();
    let receiver = world.receiver(allowed_new(), 1);
    let request = receiver.request();

    // receiver <-> [proxy] <-> giver, with every byte the proxy reads recorded.
    let (receiver_end, proxy_client) = UnixStream::pair().unwrap();
    let (proxy_upstream, giver_end) = UnixStream::pair().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let client = Tap { inner: proxy_client, seen: seen.clone() };
    let upstream = Tap { inner: proxy_upstream, seen: seen.clone() };
    let proxy = thread::spawn(move || relay(client, upstream, Duration::from_secs(5)));

    let package = world.give(&{
        let mut receiver_end = &receiver_end;
        write_frame(&mut receiver_end, &request).unwrap();
        let mut giver_end = &giver_end;
        read_frame(&mut giver_end).unwrap()
    });
    let package = package.unwrap();
    let mut giver_end_writer = &giver_end;
    write_frame(&mut giver_end_writer, &package).unwrap();
    let mut receiver_reader = &receiver_end;
    let carried = read_frame(&mut receiver_reader).unwrap();
    drop(receiver_end);
    drop(giver_end);
    proxy.join().unwrap();

    assert_eq!(carried, package);
    let seen = seen.lock().unwrap().clone();
    assert!(seen.len() > request.len() + package.len());
    // Not M, not any 8-byte piece of it, not its hex.
    for window in TEST_M.windows(8) {
        assert!(!seen.windows(8).any(|w| w == window), "a piece of M crossed the proxy");
    }
    let m_hex: String = TEST_M.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!String::from_utf8_lossy(&seen).contains(&m_hex[..16]));
    // And the receiver opens it.
    assert!(same_m(&world.accept(receiver, &carried).unwrap(), &master()));
}

// Compile-time checks: these call sites resolve only when the type does NOT
// implement Debug (or Display); if it ever does, the call is ambiguous and
// this test file no longer builds.
trait NotDebug<A> {
    fn not_debug() {}
}
impl<T: ?Sized> NotDebug<()> for T {}
impl<T: ?Sized + Debug> NotDebug<u8> for T {}

trait NotDisplay<A> {
    fn not_display() {}
}
impl<T: ?Sized> NotDisplay<()> for T {}
impl<T: ?Sized + Display> NotDisplay<u8> for T {}

#[test]
fn nothing_prints_or_formats_m() {
    <MasterKey as NotDebug<_>>::not_debug();
    <MasterKey as NotDisplay<_>>::not_display();
    <Receiver as NotDebug<_>>::not_debug();
    <key_share::GivenPackage as NotDebug<_>>::not_debug();

    // Every refusal's text and debug form: no M.
    let world = World::new();
    let m_hex: String = TEST_M.iter().map(|b| format!("{b:02x}")).collect();
    let m_debug = format!("{TEST_M:?}");
    let receiver = world.receiver(unlisted(), 1);
    let mut errors = vec![world.give(&receiver.request()).err().unwrap(), world.give(b"junk").err().unwrap()];
    let good = world.receiver(allowed_new(), 1);
    let package = world.give(&good.request()).unwrap();
    let mut tampered = package.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    errors.push(world.accept(good, &tampered).err().unwrap());
    for error in errors {
        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(&m_hex[..16]) && !text.contains(&m_debug[..20]), "{text}");
        }
    }

    // No print, log or format call in the code that holds M.
    for (file, source) in [
        ("key_share.rs", include_str!("../src/key_share.rs")),
        ("secrets.rs", include_str!("../src/secrets.rs")),
    ] {
        for word in ["println!", "eprintln!", "print!(", "dbg!", "log::", "{:?}"] {
            assert!(!source.contains(word), "{file} has {word}");
        }
    }
    // The enclave program never names M in what it prints.
    for line in include_str!("../src/bin/seal_enclave.rs").lines() {
        if line.contains("status(") || line.contains("eprintln!") || line.contains("format!") {
            assert!(!line.contains("master"), "{line}");
        }
    }
}
