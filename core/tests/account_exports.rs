//! The functions the app calls, end to end, against the app's own store (in
//! memory off iOS). They share one store for the process, so this file holds
//! one test that walks the whole flow in order.

use ghost_wallet_core::{
    AccountError, CHECKED_WORDS, account_zero_address, check_new_account_word, discard_new_account, has_account,
    import_account_words, is_account_word, new_account_words, save_new_account, saved_account_zero_address,
};

#[test]
fn create_check_save_then_nothing_overwrites_it() {
    assert!(!has_account().unwrap());
    assert_eq!(saved_account_zero_address(), Err(AccountError::NoAccount));

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

    // The saved account stays: no new account, no import over it.
    assert_eq!(new_account_words(), Err(AccountError::AccountExists));
    assert_eq!(import_account_words(discarded.join(" ")), Err(AccountError::AccountExists));
    assert_eq!(saved_account_zero_address().unwrap(), address);
    assert!(!is_account_word("ghostly".to_owned()));
}
