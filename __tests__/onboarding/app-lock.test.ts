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
  it('points to the passcode when the phone\'s check is locked out or not set up', () => {
    expect(unlockMessage('lockout')).toContain('Use your passcode');
    expect(unlockMessage('not_enrolled')).toContain('Use your passcode');
  });

  it('names the check the phone has, and neither when it is not known', () => {
    const touch = { kind: 'touch', enrolled: true } as const;
    const face = { kind: 'face', enrolled: true } as const;

    expect(unlockMessage('lockout', touch)).toBe('Touch ID is locked after too many tries. Use your passcode.');
    expect(unlockMessage('lockout', face)).toBe('Face ID is locked after too many tries. Use your passcode.');
    expect(unlockMessage('not_enrolled', { kind: 'touch', enrolled: false })).toBe(
      'Touch ID is not set up on this phone. Use your passcode.',
    );
    for (const error of ['lockout', 'not_enrolled'] as const) {
      expect(unlockMessage(error)).not.toMatch(/Touch ID|Face ID/);
      expect(unlockMessage(error, { kind: 'none', enrolled: false })).not.toMatch(/Touch ID|Face ID/);
    }
  });
});
