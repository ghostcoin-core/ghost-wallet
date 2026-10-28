// The mockups' stroke icons (docs/mockups), drawn with react-native-svg.
import Svg, { Circle, Path, Rect } from 'react-native-svg';

import { colors } from './theme';

export type IconName =
  | 'back'
  | 'settings'
  | 'send'
  | 'receive'
  | 'clock'
  | 'check'
  | 'cross'
  | 'warning'
  | 'copy'
  | 'share'
  | 'chevron'
  | 'account'
  | 'key'
  | 'lock'
  | 'globe'
  | 'node'
  | 'info'
  | 'dot';

function shapes(name: IconName) {
  switch (name) {
    case 'back':
      return <Path d="M15 18l-6-6 6-6" />;
    case 'settings':
      return (
        <>
          <Circle cx="12" cy="12" r="3" />
          <Path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" />
        </>
      );
    case 'send':
      return <Path d="M7 17L17 7M8 7h9v9" />;
    case 'receive':
      return <Path d="M17 7L7 17M16 17H7V8" />;
    case 'clock':
      return (
        <>
          <Circle cx="12" cy="12" r="9" />
          <Path d="M12 7v5l3 2" />
        </>
      );
    case 'check':
      return <Path d="M5 12.5l4.5 4.5L19 7.5" />;
    case 'cross':
      return (
        <>
          <Circle cx="12" cy="12" r="9" />
          <Path d="M15 9l-6 6M9 9l6 6" />
        </>
      );
    case 'warning':
      return (
        <>
          <Path d="M12 3.5l9 16H3z" />
          <Path d="M12 10v4M12 16.8v.01" />
        </>
      );
    case 'copy':
      return (
        <>
          <Rect x="9" y="9" width="11" height="11" rx="2" />
          <Path d="M5 15V5a1 1 0 0 1 1-1h9" />
        </>
      );
    case 'share':
      return <Path d="M12 3v12M7 8l5-5 5 5M5 13v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6" />;
    case 'chevron':
      return <Path d="M9 6l6 6-6 6" />;
    case 'account':
      return (
        <>
          <Circle cx="12" cy="8" r="4" />
          <Path d="M4 21a8 8 0 0 1 16 0" />
        </>
      );
    case 'key':
      return (
        <>
          <Circle cx="8" cy="15" r="4" />
          <Path d="M11 12l9-9M17 6l3 3" />
        </>
      );
    case 'lock':
      return (
        <>
          <Rect x="5" y="11" width="14" height="10" rx="2" />
          <Path d="M8 11V7a4 4 0 0 1 8 0v4" />
        </>
      );
    case 'globe':
      return (
        <>
          <Circle cx="12" cy="12" r="9" />
          <Path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
        </>
      );
    case 'node':
      return (
        <>
          <Rect x="3" y="4" width="18" height="7" rx="2" />
          <Rect x="3" y="13" width="18" height="7" rx="2" />
          <Path d="M7 7.5v.01M7 16.5v.01" />
        </>
      );
    case 'info':
      return (
        <>
          <Circle cx="12" cy="12" r="9" />
          <Path d="M12 11v5M12 8v.01" />
        </>
      );
    case 'dot':
      return <Circle cx="12" cy="12" r="5" />;
  }
}

export function Icon({ name, size = 20, color = colors.ink }: { name: IconName; size?: number; color?: string }) {
  return (
    <Svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {shapes(name)}
    </Svg>
  );
}
