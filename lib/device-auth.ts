// Touch ID or Face ID (or the passcode) before anything sensitive.
//
// It goes through Expo's local authentication native module when the build
// has it. A build without it can never authenticate, so whatever sits behind
// this stays shut: it fails closed.
import { requireOptionalNativeModule } from 'expo';

import { biometricName, type Biometric } from './biometric';

export type AuthResult = { ok: true } | { ok: false; reason: 'unavailable' | 'cancelled' | 'failed' };

type LocalAuthentication = {
  hasHardwareAsync(): Promise<boolean>;
  isEnrolledAsync(): Promise<boolean>;
  authenticateAsync(options: {
    promptMessage: string;
    cancelLabel?: string;
    disableDeviceFallback?: boolean;
  }): Promise<{ success: boolean; error?: string }>;
};

function localAuthentication(): LocalAuthentication | null {
  try {
    return requireOptionalNativeModule<LocalAuthentication>('ExpoLocalAuthentication');
  } catch {
    return null;
  }
}

/** Whether this phone and build can ask for Touch ID, Face ID or the passcode. */
export async function canAuthenticate(): Promise<boolean> {
  const native = localAuthentication();
  if (!native) {
    return false;
  }
  try {
    return (await native.hasHardwareAsync()) && (await native.isEnrolledAsync());
  } catch {
    return false;
  }
}

/** Asks for Touch ID or Face ID, falling back to the passcode. */
export async function authenticate(promptMessage: string): Promise<AuthResult> {
  const native = localAuthentication();
  if (!native) {
    return { ok: false, reason: 'unavailable' };
  }
  try {
    const result = await native.authenticateAsync({ promptMessage, cancelLabel: 'Cancel', disableDeviceFallback: false });
    if (result.success) {
      return { ok: true };
    }
    const cancelled = result.error === 'user_cancel' || result.error === 'system_cancel' || result.error === 'app_cancel';
    return { ok: false, reason: cancelled ? 'cancelled' : 'failed' };
  } catch {
    return { ok: false, reason: 'failed' };
  }
}

/**
 * What to tell someone when authentication did not go through. `biometric`
 * names the phone's own check; without it the words name neither.
 */
export function authFailureMessage(
  reason: Exclude<AuthResult, { ok: true }>['reason'],
  biometric: Biometric | null = null,
): string {
  const name = biometricName(biometric);
  switch (reason) {
    case 'unavailable':
      return `${name ?? 'Checking it is you'} is not available in this build.`;
    case 'cancelled':
      return 'Cancelled.';
    case 'failed':
      return name ? `${name} did not match. Try again.` : 'That did not match. Try again.';
  }
}
