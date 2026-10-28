//! The saved account's seed in the iOS Keychain, this device only.
//!
//! One generic password item, service `com.ghostcoin.wallet`, account
//! `account-seed`, holding the seed's 32 bytes. It is
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never synchronised, so
//! it stays on this phone and leaves no backup that restores elsewhere. It is
//! only ever added, never updated: a saved account is not overwritten.
//!
//! The Security and CoreFoundation calls are made directly, so no crate is
//! added. The seed handed to `SecItemAdd` is wrapped without a copy; the copy
//! `SecItemCopyMatching` returns is read once and released.

use core::ffi::c_void;
use core::ptr;

use ghost_client::account::{SEED_BYTES, WalletSeed};

use crate::accounts::{AccountError, SeedStore, wipe};

const SERVICE: &str = "com.ghostcoin.wallet";
const ACCOUNT: &str = "account-seed";

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;

const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

#[repr(C)]
struct CallBacks {
    _private: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFAllocatorNull: CFTypeRef;
    static kCFBooleanTrue: CFTypeRef;
    static kCFBooleanFalse: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: CallBacks;
    static kCFTypeDictionaryValueCallBacks: CallBacks;

    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const CallBacks,
        value_callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFDataCreateWithBytesNoCopy(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        bytes_deallocator: CFTypeRef,
    ) -> CFTypeRef;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        count: CFIndex,
        encoding: u32,
        is_external_representation: u8,
    ) -> CFTypeRef;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CFTypeRef;
    static kSecClassGenericPassword: CFTypeRef;
    static kSecAttrService: CFTypeRef;
    static kSecAttrAccount: CFTypeRef;
    static kSecAttrAccessible: CFTypeRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef;
    static kSecAttrSynchronizable: CFTypeRef;
    static kSecValueData: CFTypeRef;
    static kSecReturnData: CFTypeRef;
    static kSecMatchLimit: CFTypeRef;
    static kSecMatchLimitOne: CFTypeRef;

    fn SecItemAdd(attributes: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
}

/// A CoreFoundation object this code owns, released when dropped.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from a CoreFoundation create or copy call.
            unsafe { CFRelease(self.0) };
        }
    }
}

fn string(text: &str) -> Owned {
    // SAFETY: the bytes are valid UTF-8 for `text.len()` bytes.
    Owned(unsafe {
        CFStringCreateWithBytes(ptr::null(), text.as_ptr(), text.len() as CFIndex, CF_STRING_ENCODING_UTF8, 0)
    })
}

/// The Keychain item's query, with `extra` keys and values added.
fn query(extra: &[(CFTypeRef, CFTypeRef)]) -> Owned {
    let service = string(SERVICE);
    let account = string(ACCOUNT);
    // SAFETY: the Security and CoreFoundation constants are valid for the
    // life of the process; the dictionary retains every key and value.
    unsafe {
        let mut keys = vec![kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrSynchronizable];
        let mut values = vec![kSecClassGenericPassword, service.0, account.0, kCFBooleanFalse];
        for (key, value) in extra {
            keys.push(*key);
            values.push(*value);
        }
        Owned(CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as CFIndex,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        ))
    }
}

/// The saved account in the Keychain.
#[derive(Default)]
pub struct KeychainStore;

impl SeedStore for KeychainStore {
    fn contains(&self) -> Result<bool, AccountError> {
        // SAFETY: the constants are valid; no result is asked for.
        let status = unsafe {
            let query = query(&[(kSecMatchLimit, kSecMatchLimitOne)]);
            SecItemCopyMatching(query.0, ptr::null_mut())
        };
        match status {
            ERR_SEC_SUCCESS => Ok(true),
            ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            status => Err(AccountError::Keychain { status }),
        }
    }

    fn load(&self) -> Result<Option<WalletSeed>, AccountError> {
        let mut result: CFTypeRef = ptr::null();
        // SAFETY: the constants are valid; `result` receives a CFData we own.
        let status = unsafe {
            let query = query(&[(kSecReturnData, kCFBooleanTrue), (kSecMatchLimit, kSecMatchLimitOne)]);
            SecItemCopyMatching(query.0, &mut result)
        };
        let data = Owned(result);
        match status {
            ERR_SEC_SUCCESS => {}
            ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            status => return Err(AccountError::Keychain { status }),
        }
        if data.0.is_null() {
            return Err(AccountError::BadSavedAccount);
        }
        // SAFETY: `data.0` is a CFData; its bytes are valid for its length.
        let mut bytes = [0u8; SEED_BYTES];
        unsafe {
            if CFDataGetLength(data.0) != SEED_BYTES as CFIndex {
                return Err(AccountError::BadSavedAccount);
            }
            ptr::copy_nonoverlapping(CFDataGetBytePtr(data.0), bytes.as_mut_ptr(), SEED_BYTES);
        }
        drop(data);
        let seed = WalletSeed::from_bytes(bytes);
        wipe(&mut bytes);
        Ok(Some(seed))
    }

    fn save(&self, seed: &WalletSeed) -> Result<(), AccountError> {
        let bytes = seed.as_bytes();
        // SAFETY: the CFData points at the seed's bytes without copying or
        // freeing them (`kCFAllocatorNull`), and is released before `seed`
        // can go; the constants are valid.
        let status = unsafe {
            let data =
                Owned(CFDataCreateWithBytesNoCopy(ptr::null(), bytes.as_ptr(), SEED_BYTES as CFIndex, kCFAllocatorNull));
            let attributes = query(&[
                (kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
                (kSecValueData, data.0),
            ]);
            SecItemAdd(attributes.0, ptr::null_mut())
        };
        match status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(AccountError::AccountExists),
            status => Err(AccountError::Keychain { status }),
        }
    }
}
