// Ghost brand kit v1.0 (brand/README.txt): light-first, ink text, Ghost violet
// only for main buttons and links.
export const colours = {
  paper: '#FFFFFF',
  mist: '#F5F5F8',
  line: '#E4E3EC',
  ink: '#0E0D1A',
  body: '#4A4860',
  quiet: '#6E6C82',
  violet: '#6B4CFF',
  violetTint: '#EEEAFF',
  danger: '#B3261E',
} as const;

// The names the fonts are loaded under in app/_layout.tsx.
export const fonts = {
  sans: 'InstrumentSans',
  mono: 'IBMPlexMono-Regular',
  monoMedium: 'IBMPlexMono-Medium',
} as const;

export const fontFiles = {
  [fonts.sans]: require('../brand/fonts/InstrumentSans.ttf'),
  [fonts.mono]: require('../brand/fonts/IBMPlexMono-Regular.ttf'),
  [fonts.monoMedium]: require('../brand/fonts/IBMPlexMono-Medium.ttf'),
};
