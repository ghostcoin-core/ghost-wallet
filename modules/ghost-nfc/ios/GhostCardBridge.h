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
