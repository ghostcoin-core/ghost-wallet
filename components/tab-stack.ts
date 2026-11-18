// A tab that holds the screens it opens. Switching to another tab closes
// whatever this one had open, back to its first screen, so a screen left by
// the tab bar is closed just as one left with Back is. Screens that show or
// hold something secret (recovery words, a typed key, a card's PIN) rely on
// being closed when they are left.
import { useNavigation } from 'expo-router';
import { StackActions } from 'expo-router/react-navigation';
import { useEffect } from 'react';

type TabRoute = { name: string; state?: { key?: string; index?: number } };

/** The pop that closes a tab's open screens, or null when it is on its first screen. */
export function closeOpenScreens(routes: readonly TabRoute[], tab: string) {
  const state = routes.find((route) => route.name === tab)?.state;
  if (!state?.key || (state.index ?? 0) === 0) {
    return null;
  }
  return { ...StackActions.popToTop(), target: state.key };
}

/** Call in a tab's layout, with the tab's own route name. */
export function useCloseOnLeavingTab(tab: string) {
  const navigation = useNavigation();

  useEffect(
    () =>
      navigation.addListener('blur', () => {
        const pop = closeOpenScreens(navigation.getState()?.routes ?? [], tab);
        if (pop) {
          navigation.dispatch(pop);
        }
      }),
    [navigation, tab],
  );
}
