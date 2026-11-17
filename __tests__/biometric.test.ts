import { biometricFrom, biometricName, withBiometric } from '../lib/biometric';
import { authFailureMessage } from '../lib/device-auth';

const FINGERPRINT = 1;
const FACE = 2;

describe('which check the phone has', () => {
  it('reads Touch ID, Face ID or neither from what the phone supports', () => {
    expect(biometricFrom([FINGERPRINT], true)).toEqual({ kind: 'touch', enrolled: true });
    expect(biometricFrom([FACE], true)).toEqual({ kind: 'face', enrolled: true });
    expect(biometricFrom([], true)).toEqual({ kind: 'none', enrolled: false });
  });

  it('keeps the kind when it is not set up, so messages can still name it', () => {
    expect(biometricFrom([FINGERPRINT], false)).toEqual({ kind: 'touch', enrolled: false });
  });

  it('names it', () => {
    expect(biometricName({ kind: 'touch', enrolled: true })).toBe('Touch ID');
    expect(biometricName({ kind: 'face', enrolled: false })).toBe('Face ID');
    expect(biometricName({ kind: 'none', enrolled: false })).toBeNull();
    expect(biometricName(null)).toBeNull();
  });
});

describe('a button that the phone confirms first', () => {
  it('names the check that is set up', () => {
    expect(withBiometric('Send', { kind: 'touch', enrolled: true })).toBe('Send with Touch ID');
    expect(withBiometric('Unlock', { kind: 'face', enrolled: true })).toBe('Unlock with Face ID');
  });

  it('says passcode when the phone has no check, or it is not set up', () => {
    expect(withBiometric('Send', { kind: 'none', enrolled: false })).toBe('Send with passcode');
    expect(withBiometric('Send', { kind: 'touch', enrolled: false })).toBe('Send with passcode');
  });

  it('is the action alone until the phone has answered', () => {
    expect(withBiometric('Send', null)).toBe('Send');
  });
});

describe('when the check does not go through', () => {
  it('names the phone\'s own check', () => {
    expect(authFailureMessage('failed', { kind: 'touch', enrolled: true })).toBe('Touch ID did not match. Try again.');
    expect(authFailureMessage('failed', { kind: 'face', enrolled: true })).toBe('Face ID did not match. Try again.');
    expect(authFailureMessage('unavailable', { kind: 'touch', enrolled: true })).toBe(
      'Touch ID is not available in this build.',
    );
  });

  it('names neither when the phone has none or has not answered', () => {
    for (const reason of ['failed', 'unavailable', 'cancelled'] as const) {
      expect(authFailureMessage(reason)).not.toMatch(/Touch ID|Face ID/);
      expect(authFailureMessage(reason, { kind: 'none', enrolled: false })).not.toMatch(/Touch ID|Face ID/);
    }
  });
});
