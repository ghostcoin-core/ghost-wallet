// The C bridge of core/src/card.rs. The Phantom Key crosses between the
// native core and the card module only here; the JavaScript bindings do not
// carry these functions.
#pragma once

#include <stddef.h>
#include <stdint.h>

/// Copies the words of the Phantom Key Vanish holds, once checked, into
/// `out`. Returns the byte count, -1 when no checked key is held, -2 when
/// `capacity` is too small, -3 for a null pointer.
intptr_t ghost_wallet_card_copy_new_key(uint8_t *out, uintptr_t capacity);

/// Holds the Phantom Key words a card handed over. Returns 0, -1 when they
/// are not a Phantom Key, -3 for a null pointer.
intptr_t ghost_wallet_card_hold_key(const uint8_t *words, uintptr_t length);

// The C bridge of core/src/seal_open.rs: a Sealed card's Open. The release
// package the Seal sends goes from the relay to the core here, and the Open's
// phone key seed between the core and the Keychain; JavaScript sees neither.

/// Holds the release package of an Open for the core's phone key. Returns 0,
/// -1 when no phone key is held, -2 for a package too long, -3 for a null
/// pointer.
intptr_t ghost_wallet_seal_open_take_release(const uint8_t *package, uintptr_t length);

/// Copies the core's Open phone key seed (64 bytes) into `out`. Returns 64,
/// -1 when none is held, -2 when `capacity` is under 64, -3 for a null pointer.
intptr_t ghost_wallet_seal_open_copy_seed(uint8_t *out, uintptr_t capacity);

/// Gives the core back an Open phone key seed kept in the Keychain. Returns 0,
/// -2 when `length` is not 64, -3 for a null pointer.
intptr_t ghost_wallet_seal_open_restore_seed(const uint8_t *seed, uintptr_t length);
