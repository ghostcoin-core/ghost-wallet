//! The enclave's card registry, loaded from the host (`LoadedRegistry`, the
//! control frame of kind 4): a good load, a line failing its check left
//! out, a torn last line left out, a load that drops a held card or changes
//! a held card's entry refused with nothing changed, later loads adding
//! cards, nothing loaded before the first frame, and with M held the routes
//! serve (and check the registry) only once it is loaded.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "support/enclave.rs"]
mod enclave;
#[path = "fixtures/test_release_key.rs"]
mod release;
mod support;

use std::sync::Arc;

use authority::allowed_old;
use ghost_seal::enclave_serve::{MemoryServiceLog, RegistrySource, ServiceEvent};
use ghost_seal::key_share::{CONTROL_REGISTRY, ControlFrame};
use ghost_seal::registry::{LoadReport, RegistryLoadRefused};
use ghost_seal::relay::to_hex;
use ghost_seal::relay_http::NOT_READY_MESSAGE;
use ghost_seal::{CardRegistry, CardUid, LoadedRegistry, RegistryEntry, SealError};
use serde_json::{Value, json};
use support::UID;

const SECOND: CardUid = CardUid([0x04, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
const THIRD: CardUid = CardUid([0x04, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35]);
const STRANGER: CardUid = CardUid([0x04, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45]);

fn line(uid: CardUid, batch: &str) -> String {
    RegistryEntry::new(uid, "2026-11-06", batch).unwrap().to_line()
}

fn held(registry: &LoadedRegistry) -> Vec<CardUid> {
    registry.entries().iter().map(RegistryEntry::uid).collect()
}

#[test]
fn a_good_load_holds_its_cards() {
    let registry = LoadedRegistry::new();
    assert!(!registry.loaded());
    assert!(!registry.view().contains(&UID));
    let text = format!("{}{}", line(UID, "lot-1"), line(SECOND, "lot-1"));
    assert_eq!(registry.load(&text), Ok(LoadReport { cards: 2, added: 2, ignored_lines: 0 }));
    assert!(registry.loaded());
    let view = registry.view();
    assert!(view.contains(&UID) && view.contains(&SECOND));
    assert!(!view.contains(&STRANGER));
    assert_eq!(view.lookup(&SECOND), Some(RegistryEntry::new(SECOND, "2026-11-06", "lot-1").unwrap()));
}

#[test]
fn a_line_failing_its_check_and_a_torn_last_line_are_left_out() {
    let registry = LoadedRegistry::new();
    let damaged = line(SECOND, "lot-1").replace("lot-1", "lot-9");
    let torn = line(THIRD, "lot-1");
    let text = format!("{}{damaged}{}", line(UID, "lot-1"), &torn[..torn.len() - 4]);
    assert_eq!(registry.load(&text), Ok(LoadReport { cards: 1, added: 1, ignored_lines: 2 }));
    assert_eq!(held(&registry), vec![UID]);
    // A torn line alone is no card, but it is a load.
    let alone = LoadedRegistry::new();
    assert_eq!(alone.load(&torn[..torn.len() - 1]), Ok(LoadReport { cards: 0, added: 0, ignored_lines: 1 }));
    assert!(alone.loaded());
    assert!(alone.entries().is_empty());
}

#[test]
fn a_load_that_drops_or_changes_a_held_card_is_refused_and_changes_nothing() {
    let registry = LoadedRegistry::new();
    registry.load(&format!("{}{}", line(UID, "lot-1"), line(SECOND, "lot-1"))).unwrap();
    let before = registry.entries();

    // SECOND left out (and THIRD offered): refused whole.
    let dropping = format!("{}{}", line(UID, "lot-1"), line(THIRD, "lot-2"));
    assert_eq!(registry.load(&dropping), Err(RegistryLoadRefused::DropsCard(SECOND)));
    assert_eq!(registry.entries(), before);
    assert!(!registry.view().contains(&THIRD));

    // SECOND's entry changed: refused whole.
    let changing = format!("{}{}{}", line(UID, "lot-1"), line(SECOND, "lot-7"), line(THIRD, "lot-2"));
    assert_eq!(registry.load(&changing), Err(RegistryLoadRefused::ChangesEntry(SECOND)));
    assert_eq!(registry.entries(), before);

    // A damaged copy of a held card's line is the card left out.
    let damaged = line(SECOND, "lot-1").replace("lot-1", "lot-3");
    let text = format!("{}{damaged}", line(UID, "lot-1"));
    assert_eq!(registry.load(&text), Err(RegistryLoadRefused::DropsCard(SECOND)));
    assert_eq!(registry.entries(), before);
    assert!(RegistryLoadRefused::DropsCard(SECOND).to_string().contains("leaves out"));
}

#[test]
fn later_loads_add_cards_and_reach_views_made_before() {
    let registry = LoadedRegistry::new();
    let first = line(UID, "lot-1");
    registry.load(&first).unwrap();
    let view = registry.view();
    assert!(!view.contains(&SECOND));
    let more = format!("{first}{}{}", line(SECOND, "lot-2"), line(THIRD, "lot-2"));
    assert_eq!(registry.load(&more), Ok(LoadReport { cards: 3, added: 2, ignored_lines: 0 }));
    assert!(view.contains(&SECOND) && view.contains(&THIRD));
    // The same text again changes nothing.
    assert_eq!(registry.load(&more), Ok(LoadReport { cards: 3, added: 0, ignored_lines: 0 }));
    // Nothing records through a Seal's view.
    let mut view = registry.view();
    assert!(matches!(view.record(&RegistryEntry::new(STRANGER, "2026-11-06", "x").unwrap()), Err(SealError::Registry(_))));
    assert!(!registry.view().contains(&STRANGER));
}

#[test]
fn the_control_frame_of_kind_4_carries_the_registry_text() {
    let text = format!("{}{}", line(UID, "lot-1"), line(SECOND, "lot-1"));
    let frame = [&[CONTROL_REGISTRY][..], text.as_bytes()].concat();
    let Ok(ControlFrame::Registry(carried)) = ControlFrame::parse(&frame) else { panic!("not a registry frame") };
    assert_eq!(carried, text);
    let registry = LoadedRegistry::new();
    assert_eq!(registry.load(carried).unwrap().cards, 2);
    assert!(ControlFrame::parse(&[CONTROL_REGISTRY, 0xc3, 0x28]).is_err(), "not UTF-8");
}

fn post(service: &ghost_seal::enclave_serve::EnclaveService, path: &str, body: &Value) -> (u16, Value) {
    let reply = service.routes().answer("POST", path, body.to_string().as_bytes());
    (reply.status, serde_json::from_str(&reply.body).expect("JSON"))
}

fn check_start(uid: &CardUid) -> Value {
    json!({ "uid": to_hex(&uid.0), "challenge": to_hex(&[9; 32]) })
}

#[test]
fn with_m_held_the_routes_serve_only_once_the_registry_is_loaded() {
    let registry = LoadedRegistry::new();
    let (deps, _fakes) = enclave::deps_with_loaded(&registry);
    assert!(!deps.ready(), "a registry not loaded yet is not ready");
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps.clone(), allowed_old(), log.clone());
    service.install_master(support::master());
    assert!(!service.serves_flows());
    assert!(!service.refresh_flows(), "nothing new yet");
    let (status, body) = post(&service, "/v1/check/start", &check_start(&UID));
    assert_eq!((status, body["message"].as_str()), (503, Some(NOT_READY_MESSAGE)));

    // A frame that does not read loads nothing; the first good load serves.
    assert!(ControlFrame::parse(&[CONTROL_REGISTRY, 0xff]).is_err());
    assert!(!registry.loaded());
    registry.load(&line(UID, "lot-1")).unwrap();
    assert!(deps.ready());
    assert!(service.refresh_flows());
    assert!(service.serves_flows());
    assert_eq!(
        *log.0.lock().unwrap(),
        vec![ServiceEvent::MasterInstalled { serves_flows: false }, ServiceEvent::FlowsServed]
    );
    // Again: already serving, nothing logged.
    assert!(service.refresh_flows());
    assert_eq!(log.0.lock().unwrap().len(), 2);

    // The registry is checked: a held card gets its first command, another
    // is refused before any.
    let (status, body) = post(&service, "/v1/check/start", &check_start(&UID));
    assert_eq!((status, body["status"].as_str()), (200, Some("apdu")), "{body}");
    let (status, body) = post(&service, "/v1/check/start", &check_start(&STRANGER));
    assert_eq!((status, body["reason"].as_str()), (422, Some("not-a-ghost-card")), "{body}");
    assert!(body.get("apdu").is_none());

    // A card added by a later load is served without a restart.
    registry.load(&format!("{}{}", line(UID, "lot-1"), line(STRANGER, "lot-2"))).unwrap();
    let (status, body) = post(&service, "/v1/check/start", &check_start(&STRANGER));
    assert_eq!((status, body["status"].as_str()), (200, Some("apdu")), "{body}");
}

#[test]
fn a_registry_loaded_before_m_serves_as_soon_as_m_arrives() {
    let registry = LoadedRegistry::new();
    registry.load(&line(UID, "lot-1")).unwrap();
    let (deps, _fakes) = enclave::deps_with_loaded(&registry);
    let service = enclave::service(deps, allowed_old(), Arc::new(MemoryServiceLog::default()));
    assert!(!service.refresh_flows(), "no M yet");
    service.install_master(support::master());
    assert!(service.serves_flows());
    // The trait as the service sees it.
    let source: &dyn RegistrySource = &registry;
    assert!(source.loaded());
    assert!(source.registry().contains(&UID));
}
