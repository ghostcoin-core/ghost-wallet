// A text box for one account word: no autocorrect, no capitals, no autofill,
// so the keyboard neither changes nor learns the word.
import { forwardRef } from 'react';
import { StyleSheet, TextInput, type TextInputProps } from 'react-native';

import { colours, fonts } from '../lib/theme';

type WordFieldProps = Omit<
  TextInputProps,
  'autoCapitalize' | 'autoComplete' | 'autoCorrect' | 'spellCheck' | 'textContentType'
> & { invalid?: boolean };

export const WordField = forwardRef<TextInput, WordFieldProps>(function WordField(
  { invalid, style, ...props },
  ref,
) {
  return (
    <TextInput
      ref={ref}
      autoCapitalize="none"
      autoComplete="off"
      autoCorrect={false}
      importantForAutofill="no"
      placeholderTextColor={colours.quiet}
      spellCheck={false}
      textContentType="none"
      {...props}
      style={[styles.field, invalid && styles.invalid, style]}
    />
  );
});

const styles = StyleSheet.create({
  field: {
    minHeight: 44,
    color: colours.ink,
    fontFamily: fonts.mono,
    fontSize: 14,
  },
  invalid: {
    color: colours.danger,
  },
});
