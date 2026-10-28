// The account the app shows. Until words can be created or imported, it is
// account 0 of Ghost's public test words.
import { testWordsAccountZeroAddress } from 'ghost-core';

/** Its address, or null when this build has no native core. */
export function accountZeroAddress(): string | null {
  try {
    return testWordsAccountZeroAddress();
  } catch {
    return null;
  }
}
