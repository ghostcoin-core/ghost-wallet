import { unlock, unlockMessage } from '../../lib/app-lock';

const mockAuthenticate = jest.fn();
jest.mock('expo-local-authentication', () => ({
  authenticateAsync: (options: unknown) => mockAuthenticate(options),
}));

beforeEach(() => {
  mockAuthenticate.mockReset();
});

describe('unlock', () => {
  it('unlocks when Face ID or the passcode passes, with the passcode allowed as fallback', async () => {
    mockAuthenticate.mockResolvedValue({ success: true });

    await expect(unlock()).resolves.toEqual({ unlocked: true });
    expect(mockAuthenticate).toHaveBeenCalledWith(
      expect.objectContaining({ promptMessage: 'Unlock Ghost Wallet', disableDeviceFallback: false }),
    );
  });

  it('stays locked without a message when the person cancels', async () => {
    mockAuthenticate.mockResolvedValue({ success: false, error: 'user_cancel' });

    await expect(unlock()).resolves.toEqual({ unlocked: false, message: null });
  });

  it('stays locked and says why when the check fails', async () => {
    mockAuthenticate.mockResolvedValue({ success: false, error: 'authentication_failed' });

    await expect(unlock()).resolves.toEqual({ unlocked: false, message: 'Ghost Wallet is still locked. Try again.' });
  });

  it('stays locked when the prompt itself fails', async () => {
    mockAuthenticate.mockRejectedValue(new Error('no native module'));

    await expect(unlock()).resolves.toEqual({ unlocked: false, message: 'Ghost Wallet is still locked. Try again.' });
  });

  it('opens on a phone with no passcode, which has no lock to ask for', async () => {
    mockAuthenticate.mockResolvedValue({ success: false, error: 'passcode_not_set' });

    await expect(unlock()).resolves.toEqual({ unlocked: true });
  });
});

describe('unlockMessage', () => {
  it('points to the passcode when Face ID is locked out or not set up', () => {
    expect(unlockMessage('lockout')).toContain('Use your passcode');
    expect(unlockMessage('not_enrolled')).toContain('Use your passcode');
  });
});
