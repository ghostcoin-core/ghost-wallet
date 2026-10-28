// Face ID (or the passcode) before anything sensitive.
//
// It goes through Expo's local authentication native module when the build
// has it. A build without it can never authenticate, so whatever sits behind
// this stays shut: it fails closed.
import { requireOptionalNativeModule } from 'expo';

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

/** Whether this phone and build can ask for Face ID or the passcode. */
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

/** Asks for Face ID, falling back to the passcode. */
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

/** What to tell someone when authentication did not go through. */
export function authFailureMessage(reason: Exclude<AuthResult, { ok: true }>['reason']): string {
  switch (reason) {
    case 'unavailable':
      return 'Face ID is not available in this build.';
    case 'cancelled':
      return 'Cancelled.';
    case 'failed':
      return 'Face ID did not match. Try again.';
  }
}
