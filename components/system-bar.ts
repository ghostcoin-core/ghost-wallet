// Whether the system's navigation bar is above this screen, and how tall it
// is. A screen under it must not add the top safe area again.
import { HeaderHeightContext } from 'expo-router/react-navigation';
import { useContext } from 'react';

/** The height of the system bar above this screen, or 0 when it has none. */
export function useSystemBarHeight(): number {
  return useContext(HeaderHeightContext) ?? 0;
}
