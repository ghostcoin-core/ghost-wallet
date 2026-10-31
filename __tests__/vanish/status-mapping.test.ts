import {
  NOT_FOUND_MESSAGE,
  STEP_NAMES,
  arrivedText,
  isFinal,
  lookupMessage,
  progressRows,
  screenDone,
  statusDetail,
  statusLabel,
  statusOfRecovery,
  statusOfStep,
  stepName,
  type PaymentStatus,
} from '../../lib/vanish/status-mapping';

describe('the core steps', () => {
  it('are read by index (the generated enum) or by name', () => {
    expect(STEP_NAMES).toEqual(['Prepared', 'BackedUp', 'Signed', 'Sent', 'Included', 'Settled', 'Failed', 'Conflicted']);
    STEP_NAMES.forEach((name, index) => {
      expect(stepName(index)).toBe(name);
      expect(stepName(name.toLowerCase())).toBe(name);
    });
    expect(stepName('backed up')).toBe('BackedUp');
    expect(stepName(8)).toBeNull();
    expect(stepName(1.5)).toBeNull();
    expect(stepName('done')).toBeNull();
  });

  it('map to proving, sent, in a block, settled or failed', () => {
    const expected: Record<string, PaymentStatus> = {
      Prepared: 'proving',
      BackedUp: 'proving',
      Signed: 'proving',
      Sent: 'sent',
      Included: 'in-block',
      Settled: 'settled',
      Failed: 'failed',
      Conflicted: 'failed',
    };
    for (const [name, status] of Object.entries(expected)) {
      expect(statusOfStep(name)).toBe(status);
      expect(statusOfStep(STEP_NAMES.indexOf(name as never))).toBe(status);
    }
  });

  it('never shows a step it does not know as done', () => {
    expect(statusOfStep('Vanished')).toBe('failed');
    expect(statusOfStep(42)).toBe('failed');
  });
});

describe('what recover says to do', () => {
  it('shows a new proof when the fee window moved, and sending when it sends', () => {
    expect(statusOfRecovery('Rebuild', 'Sent')).toBe('proving');
    expect(statusOfRecovery('Sign', 'BackedUp')).toBe('proving');
    expect(statusOfRecovery('BackUp', 'Prepared')).toBe('proving');
    expect(statusOfRecovery('Send', 'Signed')).toBe('sent');
  });

  it('shows the saved step while waiting or done', () => {
    expect(statusOfRecovery('Wait', 'Sent')).toBe('sent');
    expect(statusOfRecovery('Wait', 'Included')).toBe('in-block');
    expect(statusOfRecovery('Done', 'Settled')).toBe('settled');
    expect(statusOfRecovery('Done', 'Conflicted')).toBe('failed');
  });

  it('stops asking the chain only once settled or failed', () => {
    expect(isFinal('settled')).toBe(true);
    expect(isFinal('failed')).toBe(true);
    expect(isFinal('in-block')).toBe(false);
    expect(isFinal('sent')).toBe(false);
    expect(isFinal('proving')).toBe(false);
  });
});

describe('what the screen shows', () => {
  it('labels each stage for Summon and Claim as proving, and for Vanish as signing', () => {
    expect(statusLabel('proving', 'summon')).toBe('Proving on this phone');
    expect(statusLabel('proving', 'claim')).toBe('Proving on this phone');
    expect(statusLabel('proving', 'vanish')).toBe('Signing');
    expect(statusLabel('sent', 'vanish')).toBe('Sent');
    expect(statusLabel('in-block', 'summon')).toBe('In a block');
    expect(statusLabel('settled', 'summon')).toBe('Settled');
    expect(statusLabel('failed', 'claim')).toBe('Failed');
  });

  it('marks the stages before the current one done', () => {
    expect(progressRows('in-block', 'summon').map((row) => [row.status, row.state])).toEqual([
      ['proving', 'done'],
      ['sent', 'done'],
      ['in-block', 'current'],
      ['settled', 'waiting'],
    ]);
    expect(progressRows('settled', 'vanish').every((row) => row.state === 'done')).toBe(true);
    expect(progressRows('proving', 'claim')[0].state).toBe('current');
  });

  it('shows a failure on its own', () => {
    expect(progressRows('failed', 'summon')).toEqual([{ status: 'failed', label: 'Failed', state: 'current' }]);
    expect(statusDetail('failed', 'summon', 'Conflicted')).toContain('Another payment');
    expect(statusDetail('failed', 'summon', 'Failed')).toContain('did not take it');
  });

  it('says it is safe to close once sent, and where the coins are once settled', () => {
    expect(statusDetail('sent', 'vanish')).toBe('Safe to close the app. It never pays twice.');
    expect(statusDetail('settled', 'vanish')).toBe('The coins are in the Phantom Key.');
    expect(statusDetail('settled', 'summon')).toBe('The coins are back in your account.');
  });

  it('counts settling from the first block, and lets the screen finish there', () => {
    expect(statusDetail('in-block', 'summon')).toBe('Settling: 1 of 3 confirmations');
    expect(statusDetail('in-block', 'vanish')).toBe('The coins are in the Phantom Key. Settling: 1 of 3 confirmations');
    expect(arrivedText('in-block', 'claim')).toBe('The coins are in your account.');
    expect(arrivedText('sent', 'summon')).toBeNull();
    expect(arrivedText('failed', 'summon')).toBeNull();
    expect((['proving', 'sent', 'in-block', 'settled', 'failed'] as const).map(screenDone)).toEqual([
      false,
      false,
      true,
      true,
      true,
    ]);
  });
});

describe('the coin lookup', () => {
  it('never says zero for a key this phone cannot find', () => {
    const message = lookupMessage('not-found');
    expect(message).toContain(NOT_FOUND_MESSAGE);
    expect(message).not.toMatch(/\b0\b|zero|empty/i);
    expect(NOT_FOUND_MESSAGE).toBe("Can't find this key's coins yet.");
    expect(lookupMessage('something else')).toBe(NOT_FOUND_MESSAGE);
  });

  it('says nothing for a found coin and names a spent one', () => {
    expect(lookupMessage('found')).toBeNull();
    expect(lookupMessage('spent')).toContain('summoned already');
  });
});
