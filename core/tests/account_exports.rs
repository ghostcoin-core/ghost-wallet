//! The functions the app calls, end to end, against the app's own store (in
//! memory off iOS). They share one store for the process, so this file holds
//! one test that walks the whole flow in order.

use ghost_wallet_core::{
    AccountError, AccountLookup, AccountState, CHECKED_WORDS, RestoreError, RestoreLookup, account_zero_address,
    check_new_account_word, discard_new_account, has_account, import_account_words, is_account_word,
    new_account_words, save_new_account, saved_account_words, saved_account_zero_address,
};

const TIP_HASH: [u8; 32] = [7u8; 32];

/// A node where account 0 of the saved account holds 5 wei and every other
/// address nothing.
struct OneAccountNode {
    address: Vec<u8>,
}

impl AccountLookup for OneAccountNode {
    fn account_state(&self, address: Vec<u8>, _block_hash: Vec<u8>) -> Result<AccountState, RestoreError> {
        let balance = if address == self.address { vec![5] } else { vec![] };
        Ok(AccountState { balance, nonce: 0 })
    }
}

fn address_bytes(address: &str) -> Vec<u8> {
    (0..20).map(|i| u8::from_str_radix(&address[2 + 2 * i..4 + 2 * i], 16).unwrap()).collect()
}

#[test]
fn create_check_save_then_nothing_overwrites_it() {
    assert!(!has_account().unwrap());
    assert_eq!(saved_account_zero_address(), Err(AccountError::NoAccount));
    assert_eq!(saved_account_words(), Err(AccountError::NoAccount));
    let nothing = RestoreLookup::saved_account(Box::new(OneAccountNode { address: vec![] }), 1, TIP_HASH.to_vec());
    assert!(matches!(nothing, Err(RestoreError::SavedAccount { .. })));

    // Made, then discarded: nothing is held or saved.
    let discarded = new_account_words().unwrap();
    discard_new_account();
    assert_eq!(check_new_account_word(1, discarded[0].clone()), Err(AccountError::NoNewAccount));

    // Create, back up, check three words, save.
    let words = new_account_words().unwrap();
    assert_eq!(words.len(), 24);
    assert!(words.iter().all(|word| is_account_word(word.clone())));
    assert_eq!(save_new_account(), Err(AccountError::NotChecked { checked: 0, needed: CHECKED_WORDS }));
    let wrong = if words[2] == "zoo" { "abandon" } else { "zoo" };
    assert!(!check_new_account_word(3, wrong.to_owned()).unwrap());
    for position in [3u32, 11, 24] {
        let typed = format!(" {} ", words[position as usize - 1].to_uppercase());
        assert!(check_new_account_word(position, typed).unwrap());
    }
    save_new_account().unwrap();

    assert!(has_account().unwrap());
    let address = saved_account_zero_address().unwrap();
    assert_eq!(address, account_zero_address(words.join(" ")).unwrap());
    assert_eq!(saved_account_words().unwrap(), words);

    // Home's balance lookup opens the saved account, not the test words.
    let node = OneAccountNode { address: address_bytes(&address) };
    let lookup = RestoreLookup::saved_account(Box::new(node), 9, TIP_HASH.to_vec()).unwrap();
    assert_eq!(lookup.derive_account(0).address, address);
    let account = lookup.look_up_account(0).unwrap();
    assert_eq!(account.address, address);
    assert_eq!(account.balance, "5");
    assert!(matches!(
        RestoreLookup::saved_account(Box::new(OneAccountNode { address: vec![] }), 9, vec![0u8; 31]),
        Err(RestoreError::BadTip { .. })
    ));

    // The saved account stays: no new account, no import over it.
    assert_eq!(new_account_words(), Err(AccountError::AccountExists));
    assert_eq!(import_account_words(discarded.join(" ")), Err(AccountError::AccountExists));
    assert_eq!(saved_account_zero_address().unwrap(), address);
    assert!(!is_account_word("ghostly".to_owned()));
}
