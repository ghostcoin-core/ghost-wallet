//! The host side of EV2 secure messaging against NXP's published vectors
//! (AN12196), the same vectors the app's command framing is tested with.

mod support;

use ghost_seal::SealError;
use ghost_seal::apdu::{access_rights, file_range_header, select_ndef_application, split_response, wrap_native};
use ghost_seal::primitives::{aes128_cbc_decrypt, pad, truncate_mac, unpad};
use ghost_seal::session::{
    AnswerMode, Session, authenticate_first_command, authenticate_second_command, session_keys, session_vector,
};
use support::{array, hex, unhex};

const RND_A: &str = "13C5DB8A5930439FC3DEF9A4C675360F";
const RND_B: &str = "B9E2FC789B64BF237CCCAA20EC7E6E48";
const ZERO_KEY: [u8; 16] = [0u8; 16];

#[test]
fn selects_the_ndef_application_by_name() {
    assert_eq!(hex(&select_ndef_application()), "00A4040007D276000085010100");
}

#[test]
fn wraps_native_commands() {
    assert_eq!(hex(&wrap_native(0x60, &[]).unwrap()), "9060000000");
    assert_eq!(hex(&wrap_native(0x71, &[0x00, 0x00]).unwrap()), "9071000002000000");
    assert_eq!(wrap_native(0x8d, &[0u8; 256]), Err(SealError::TooLong));
    let response = split_response(&unhex("0102039100")).unwrap();
    assert_eq!((response.data, response.sw1, response.sw2), (vec![1, 2, 3], 0x91, 0x00));
    assert!(split_response(&[0x91]).is_err());
}

#[test]
fn lays_out_file_headers_and_access_rights() {
    assert_eq!(hex(&file_range_header(0x02, 0x80, 0x0a).unwrap()), "028000000A0000");
    assert_eq!(hex(&file_range_header(0x03, 0x010203, 0x00ff00).unwrap()), "0303020100FF00");
    assert_eq!(hex(&access_rights(0xe, 0x0, 0xe, 0xe)), "E0EE");
    assert_eq!(hex(&access_rights(2, 0, 1, 2)), "2012");
}

#[test]
fn pads_and_truncates_as_the_note_does() {
    assert_eq!(hex(&pad(&unhex("0102030405060708090A"))), "0102030405060708090A800000000000");
    assert_eq!(pad(&[0u8; 16]).len(), 32);
    assert_eq!(hex(&unpad(&unhex("04958CAA5C5E80800000000000000000")).unwrap()), "04958CAA5C5E80");
    assert!(unpad(&[0u8; 16]).is_err());
    assert!(unpad(&unhex("0102030405060708090A0B0C0D0E0F10")).is_err());
    // AN12196 5.12: the CMAC's odd bytes.
    assert_eq!(hex(&truncate_mac(&array("426CD70CE153ED315E5B139CB97384AA"))), "6C0C53315B9C73AA");
}

#[test]
fn derives_the_session_keys_of_the_note() {
    let rnd_a: [u8; 16] = array(RND_A);
    let rnd_b: [u8; 16] = array(RND_B);
    assert_eq!(
        hex(&session_vector([0xa5, 0x5a], &rnd_a, &rnd_b)),
        "A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F"
    );
    let (enc, mac) = session_keys(&ZERO_KEY, &rnd_a, &rnd_b);
    assert_eq!(hex(&*enc), "1309C877509E5A215007FF0ED19CA564");
    assert_eq!(hex(&*mac), "4C6626F5E72EA694202139295C7A7FC7");
}

#[test]
fn authenticate_ev2_first_frames_and_the_write_that_follows() {
    // AN12196 5.6, key 0 all zeros.
    assert_eq!(hex(&authenticate_first_command(0)), "9071000002000000");
    let first = unhex(&format!("{}91AF", "A04C124213C186F22399D33AC2A30215"));
    // The chip's challenge decrypts to the note's RndB.
    let rnd_b = aes128_cbc_decrypt(&ZERO_KEY, &[0u8; 16], &first[..16]).unwrap();
    assert_eq!(hex(&rnd_b), RND_B);
    let (second, pending) = authenticate_second_command(0, &ZERO_KEY, &first, array(RND_A)).unwrap();
    assert_eq!(hex(&second), format!("90AF000020{}00", "35C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D"));
    let answer = unhex(&format!("{}9100", "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663"));
    let session = pending.finish(&answer).unwrap();
    assert_eq!(hex(&session.ti()), "9D00C4DF");
    assert_eq!(session.counter(), 0);

    // AN12196 5.8.2: the first WriteData of the NDEF file in that session.
    let ndef_padded = unhex(
        "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D3030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000",
    );
    let ndef = unpad(&ndef_padded).unwrap();
    let header = file_range_header(0x02, 0, ndef.len() as u32).unwrap();
    let write = hex(&session.full_command(0x8d, &header, Some(&ndef[..])).unwrap());
    assert_eq!(&write[0..8], "908D0000");
    assert_eq!(&write[10..24], hex(&header));
    assert_eq!(
        &write[24..24 + 2 * ndef_padded.len()],
        "421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768BFE596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D651A3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802AF745660F2B4"
    );
}

#[test]
fn refuses_a_card_that_does_not_prove_the_key() {
    let first = unhex(&format!("{}91AF", "A04C124213C186F22399D33AC2A30215"));
    let (_, pending) = authenticate_second_command(0, &ZERO_KEY, &first, array(RND_A)).unwrap();
    // The chip refused the key.
    assert!(matches!(pending.finish(&unhex("91AE")), Err(SealError::Chip { sw2: 0xae, .. })));
    // An answer that is not E(K, TI || RndA') is refused too.
    let (_, pending) = authenticate_second_command(0, &ZERO_KEY, &first, array(RND_A)).unwrap();
    let wrong = unhex(&format!("{}9100", "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120664"));
    assert!(matches!(pending.finish(&wrong), Err(SealError::Integrity(_))));
}

fn write_session() -> Session {
    Session::from_session_keys(
        array("7A93D6571E4B180FCA6AC90C9A7488D4"),
        array("FC4AF159B62E549B5812394CAB1918CC"),
        array("7614281A"),
        0,
    )
}

#[test]
fn frames_write_data_of_5_12() {
    let mut session = write_session();
    assert_eq!(hex(&session.iv_input(false)), "A55A7614281A00000000000000000000");
    let header = file_range_header(0x03, 0, 10).unwrap();
    assert_eq!(
        hex(&session.command_mac_input(0x8d, &header, &unhex("6B5E6804909962FC4E3FF5522CF0F843"))),
        "8D00007614281A030000000A00006B5E6804909962FC4E3FF5522CF0F843"
    );
    let apdu = session.full_command(0x8d, &header, Some(&unhex("0102030405060708090A")[..])).unwrap();
    assert_eq!(
        hex(&apdu),
        format!("908D00001F{}{}{}00", "030000000A0000", "6B5E6804909962FC4E3FF5522CF0F843", "6C0C53315B9C73AA")
    );
    // The chip's answer: its MAC over RC || CmdCtr + 1 || TI.
    let answer = session.read_answer(0x8d, &unhex("C26D236E4A7C046D9100"), AnswerMode::Mac).unwrap();
    assert!(answer.is_empty());
    assert_eq!(session.counter(), 1);
    assert_eq!(hex(&session.response_mac_input(0x00, &[])), "0001007614281A");
}

#[test]
fn refuses_an_answer_with_a_wrong_or_missing_mac() {
    let header = file_range_header(0x03, 0, 10).unwrap();
    let mut session = write_session();
    session.full_command(0x8d, &header, Some(&unhex("0102030405060708090A")[..])).unwrap();
    assert!(matches!(
        session.read_answer(0x8d, &unhex("C26D236E4A7C046E9100"), AnswerMode::Mac),
        Err(SealError::Integrity(_))
    ));
    assert!(!session.is_open());

    let mut session = write_session();
    assert!(matches!(session.read_answer(0x5f, &unhex("9100"), AnswerMode::Mac), Err(SealError::Integrity(_))));

    // A refused command closes the session, as the chip drops its authentication.
    let mut session = write_session();
    assert!(matches!(session.read_answer(0x5f, &unhex("919D"), AnswerMode::Mac), Err(SealError::Chip { .. })));
    assert!(session.full_command(0x5f, &[2], None).is_err());
}

#[test]
fn decrypts_an_answer_with_the_response_iv_of_5_20() {
    let mut session = Session::from_session_keys(
        array("2B4D963C014DC36F24F69A50A394F875"),
        array("379D32130CE61705DD5FD8C36B95D764"),
        array("DF055522"),
        0,
    );
    let apdu = session.full_command(0x51, &[], None).unwrap();
    assert_eq!(hex(&apdu), "90510000088E2C155ADDA99BE300");
    let answer = unhex(&format!("{}{}9100", "70756055688505B52A5E26E59E329CD6", "595F672298EA41B7"));
    let uid = session.read_answer(0x51, &answer, AnswerMode::Full).unwrap();
    assert_eq!(hex(&uid), "04958CAA5C5E80");
    assert_eq!(hex(&session.iv_input(true)), "5AA5DF05552201000000000000000000");
}

#[test]
fn change_key_of_the_session_key_takes_no_mac_back() {
    let session = write_session();
    let apdu = session.change_key_command(0, &[0u8; 16], &[0u8; 16], 0).unwrap();
    // NewKey || KeyVer, padded: two blocks, then the MAC.
    assert_eq!(&hex(&apdu)[..12], "90C400002900");
    let mut session = write_session();
    session.change_key_command(0, &[0u8; 16], &[0u8; 16], 0).unwrap();
    assert!(session.read_answer(0xc4, &unhex("9100"), AnswerMode::NoMac).unwrap().is_empty());
    assert!(!session.is_open());
    // Another key's cryptogram is (New XOR Old) || KeyVer || CRC32: still two blocks.
    let session = write_session();
    let apdu = session.change_key_command(2, &[1u8; 16], &[0u8; 16], 1).unwrap();
    assert_eq!(&hex(&apdu)[..12], "90C400002902");
}
