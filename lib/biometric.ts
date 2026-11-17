// Which fingerprint or face check this phone has, so the app can name it:
// Touch ID on some iPhones, Face ID on others. Neither name is written into a
// label by hand.
import { requireOptionalNativeModule } from 'expo';
import { useEffect, useState } from 'react';

export type Biometric = {
  kind: 'touch' | 'face' | 'none';
  /** Set up on this phone, so the system prompt will ask for it. */
  enrolled: boolean;
};

type Native = {
  supportedAuthenticationTypesAsync(): Promise<number[]>;
  isEnrolledAsync(): Promise<boolean>;
};

// Expo local authentication's type numbers.
const FINGERPRINT = 1;
const FACE = 2;

const NONE: Biometric = { kind: 'none', enrolled: false };

export function biometricFrom(types: readonly number[], enrolled: boolean): Biometric {
  const kind = types.includes(FACE) ? 'face' : types.includes(FINGERPRINT) ? 'touch' : 'none';
  return { kind, enrolled: kind !== 'none' && enrolled };
}

/** The name of the phone's check, or null when it has none or it is not known yet. */
export function biometricName(biometric: Biometric | null): 'Touch ID' | 'Face ID' | null {
  if (biometric?.kind === 'touch') {
    return 'Touch ID';
  }
  return biometric?.kind === 'face' ? 'Face ID' : null;
}

/**
 * A button's words for an action the phone confirms first: "Send with Touch
 * ID", "Send with Face ID", or "Send with passcode" where neither is set up.
 * Until the phone has answered, the action alone.
 */
export function withBiometric(action: string, biometric: Biometric | null): string {
  if (biometric === null) {
    return action;
  }
  const name = biometric.enrolled ? biometricName(biometric) : null;
  return `${action} with ${name ?? 'passcode'}`;
}

export async function readBiometric(): Promise<Biometric> {
  let native: Native | null;
  try {
    native = requireOptionalNativeModule<Native>('ExpoLocalAuthentication');
  } catch {
    native = null;
  }
  if (!native) {
    return NONE;
  }
  try {
    return biometricFrom(await native.supportedAuthenticationTypesAsync(), await native.isEnrolledAsync());
  } catch {
    return NONE;
  }
}

// Asked once; a phone's hardware does not change while the app is open.
let known: Biometric | null = null;

/** The phone's check, or null until it has answered. */
export function useBiometric(): Biometric | null {
  const [biometric, setBiometric] = useState(known);

  useEffect(() => {
    if (known !== null) {
      return;
    }
    let current = true;
    void readBiometric().then((found) => {
      known = found;
      if (current) {
        setBiometric(found);
      }
    });
    return () => {
      current = false;
    };
  }, []);

  return biometric;
}

/** Forgets the answer, so a test can start from a phone that has not been asked. */
export function forgetBiometric(): void {
  known = null;
}
