// The account the app shows: account 0 of the account saved on this phone,
// created or imported in onboarding. Never the public test words: if the
// saved account cannot be read, there is no address, and Home and Receive
// show none rather than one that is not this person's.
import { savedAccountZeroAddress } from 'ghost-core';

/** Its address, or null when no saved account can be read in this build. */
export function accountZeroAddress(): string | null {
  try {
    return savedAccountZeroAddress();
  } catch {
    return null;
  }
}
