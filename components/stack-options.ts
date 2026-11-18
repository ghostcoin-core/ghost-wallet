// The system navigation bar on screens opened inside a tab. iOS draws Back
// itself, so on the iPhone Duo it moves to the side rail when the phone is
// folded or held sideways. The bar carries no title: each screen shows its own.
import { colors } from './theme';

export const pushedScreenOptions = {
  headerShown: true,
  title: '',
  headerBackButtonDisplayMode: 'minimal',
  headerShadowVisible: false,
  headerTintColor: colors.ink,
  headerStyle: { backgroundColor: colors.paper },
} as const;

/** For screens drawn on the mist page colour. */
export const onMist = { headerStyle: { backgroundColor: colors.mist } } as const;

/** A tab's own first screen has no bar: there is nothing to go back to. */
export const tabRootOptions = { headerShown: false } as const;
