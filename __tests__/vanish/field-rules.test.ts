import { fireEvent, render, screen } from '@testing-library/react-native';
import { createElement } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import ImportScreen from '../../app/import';
import { PHANTOM_KEY_IN_WALLET_FIELD, keyFieldRule, walletFieldRule, type CheckWords } from '../../lib/vanish/field-rules';
import { RECOVERY_WORDS_IN_KEY_FIELD, WRONG_FORMAT, type WordsCheck } from '../../lib/vanish/word-validation';
import { SessionProvider } from '../../lib/session';

// Plain words from the public word list stand in for a key and for recovery
// words; the stand-in core says which is which, as the Rust core does with
// Ghost's own parsers.
const KEY = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]).join(' ');
const RECOVERY = Array.from({ length: 24 }, (_, i) => ['zoo', 'zone', 'zero', 'youth'][i % 4]).join(' ');

function core(answers: Record<string, WordsCheck>): jest.MockedFunction<CheckWords> {
  return jest.fn((text: string) => answers[text] ?? { verdict: 'word-check', position: 0 });
}

const KNOWN = {
  [KEY]: { verdict: 'phantom-key', position: 0 },
  [RECOVERY]: { verdict: 'account-words', position: 0 },
} as const satisfies Record<string, WordsCheck>;

describe('the Phantom Key field', () => {
  it('takes a Phantom Key, however it was typed', () => {
    const check = core(KNOWN);
    expect(keyFieldRule(`  ${KEY.toUpperCase().replace(/ /g, '   ')} `, check)).toEqual({ accept: true, message: null });
    expect(check).toHaveBeenCalledWith(KEY);
  });

  it('refuses recovery words by name', () => {
    expect(keyFieldRule(RECOVERY, core(KNOWN))).toEqual({ accept: false, message: RECOVERY_WORDS_IN_KEY_FIELD });
  });

  it('does not ask the core until the text has a key length', () => {
    const check = core(KNOWN);
    expect(keyFieldRule(KEY.split(' ').slice(0, 20).join(' '), check)).toEqual({ accept: false, message: null });
    expect(check).not.toHaveBeenCalled();
  });

  it('refuses what can never be a key at once, without the core', () => {
    const check = core(KNOWN);
    expect(keyFieldRule(`${KEY} able`, check)).toEqual({ accept: false, message: WRONG_FORMAT });
    expect(keyFieldRule('abandon 1234', check)).toEqual({ accept: false, message: WRONG_FORMAT });
    expect(check).not.toHaveBeenCalled();
  });

  it('passes on the core reason for a mistyped key, naming no word', () => {
    const typo = KEY.replace(/^abandon/, 'abandom');
    const rule = keyFieldRule(typo, core({ [typo]: { verdict: 'unknown-word', position: 1 } }));
    expect(rule.accept).toBe(false);
    expect(rule.message).toBe("Word 1 isn't a Phantom Key word. Check it against the key you saved.");
    expect(rule.message).not.toContain('abandom');
  });

  it('accepts nothing when the core is missing', () => {
    const rule = keyFieldRule(KEY, () => {
      throw new Error('no native core');
    });
    expect(rule.accept).toBe(false);
    expect(rule.message).not.toBeNull();
  });
});

describe('the wallet field', () => {
  it('refuses a Phantom Key by name', () => {
    expect(walletFieldRule(KEY, core(KNOWN))).toEqual({ accept: false, message: PHANTOM_KEY_IN_WALLET_FIELD });
  });

  it('leaves recovery words and anything else to its own checks', () => {
    expect(walletFieldRule(RECOVERY, core(KNOWN))).toEqual({ accept: true, message: null });
    expect(walletFieldRule('abandon '.repeat(24).trim(), core({}))).toEqual({ accept: true, message: null });
  });
});

const mockImport = jest.fn();
const mockAnswers: Record<string, WordsCheck> = { ...KNOWN };
jest.mock(
  '../../modules/ghost-core/src/index',
  () => ({
    isAccountWord: () => true,
    hasAccount: () => false,
    importAccountWords: (words: string) => mockImport(words),
    checkKeyWords: (text: string) => mockAnswers[text] ?? { verdict: 'word-check', position: 0 },
  }),
  { virtual: true },
);
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

function renderImport() {
  const frame = { x: 0, y: 0, width: 393, height: 852 };
  return render(
    createElement(
      SafeAreaProvider,
      { initialMetrics: { frame, insets: { top: 47, left: 0, right: 0, bottom: 34 } } },
      createElement(SessionProvider, null, createElement(ImportScreen)),
    ),
  );
}

describe('the import screen', () => {
  beforeEach(() => mockImport.mockReset());

  it('refuses a Phantom Key typed as the 24 words and never saves it', () => {
    renderImport();
    fireEvent.changeText(screen.getByTestId('import-word-1'), KEY);
    fireEvent.press(screen.getByTestId('import-open'));
    expect(screen.getByTestId('import-error').props.children).toBe(PHANTOM_KEY_IN_WALLET_FIELD);
    expect(mockImport).not.toHaveBeenCalled();
  });

  it('still opens recovery words', () => {
    renderImport();
    fireEvent.changeText(screen.getByTestId('import-word-1'), RECOVERY);
    fireEvent.press(screen.getByTestId('import-open'));
    expect(mockImport).toHaveBeenCalledWith(RECOVERY);
    expect(screen.queryByTestId('import-error')).toBeNull();
  });
});
