// Ghost brand kit v1.0 (brand/README.txt): colors and type for the app.
import { Platform } from 'react-native';

export const colors = {
  paper: '#FFFFFF',
  mist: '#F5F5F8',
  line: '#E4E3EC',
  ink: '#0E0D1A',
  body: '#4A4860',
  quiet: '#6E6C82',
  violet: '#6B4CFF',
  violetTint: '#EEEAFF',
  /** Summon mint: only when coins come back, as a fill with ink text. */
  mint: '#4FF0C8',
  danger: '#B3261E',
} as const;

/** Amounts, addresses and words: anything people copy or check. */
export const monoFont = Platform.select({ ios: 'Menlo', default: 'monospace' });
