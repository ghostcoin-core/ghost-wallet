// The app lock: Face ID, or the phone's passcode, through iOS's own prompt.
import * as LocalAuthentication from 'expo-local-authentication';

export type UnlockOutcome =
  | { unlocked: true }
  | { unlocked: false; message: string | null };

const PROMPT = 'Unlock Ghost Wallet';

/** What to tell the person after a prompt that did not unlock; null when they cancelled. */
export function unlockMessage(error: LocalAuthentication.LocalAuthenticationError | undefined): string | null {
  switch (error) {
    case 'user_cancel':
    case 'system_cancel':
    case 'app_cancel':
      return null;
    case 'lockout':
      return 'Face ID is locked after too many tries. Use your passcode.';
    case 'not_enrolled':
    case 'not_available':
      return 'Face ID is not set up on this phone. Use your passcode.';
    default:
      return 'Ghost Wallet is still locked. Try again.';
  }
}

/**
 * Shows the system prompt: Face ID where it is set up, with the passcode as
 * the fallback; the passcode alone where Face ID is not.
 */
export async function unlock(): Promise<UnlockOutcome> {
  let result: LocalAuthentication.LocalAuthenticationResult;
  try {
    result = await LocalAuthentication.authenticateAsync({
      promptMessage: PROMPT,
      fallbackLabel: 'Use passcode',
      cancelLabel: 'Cancel',
      disableDeviceFallback: false,
    });
  } catch {
    return { unlocked: false, message: 'Ghost Wallet is still locked. Try again.' };
  }
  if (result.success) {
    return { unlocked: true };
  }
  // A phone with no passcode has no lock for the app to ask for.
  if (result.error === 'passcode_not_set') {
    return { unlocked: true };
  }
  return { unlocked: false, message: unlockMessage(result.error) };
}
