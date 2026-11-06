// What the Sealed card screen tests share (test only): the three devices
// every screen is laid out for, rendering on one, and a payment kit whose
// core is the fake world's.
import { render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { colors } from '../../components/theme';
import { buildNetwork } from '../../lib/network/build-network';
import type { CorePaymentIntent, CorePaymentRecord } from '../../modules/ghost-core';
import { world } from './fake-seal';

export const DEVICES = {
  iPhone: { width: 393, height: 852 },
  'iPhone Duo folded': { width: 466, height: 678 },
  'iPhone Duo open': { width: 626, height: 890 },
} as const;
export type Device = keyof typeof DEVICES;
export const DEVICE_NAMES = Object.keys(DEVICES) as Device[];

/** The window size the screens read; the tests' mock of useWindowDimensions returns it. */
export const windowSize = { width: 393, height: 852, scale: 3, fontScale: 1 };

function tree(device: Device, Screen: ComponentType) {
  const { width, height } = DEVICES[device];
  return (
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <Screen />
    </SafeAreaProvider>
  );
}

export function renderOn(device: Device, Screen: ComponentType) {
  const { width, height } = DEVICES[device];
  windowSize.width = width;
  windowSize.height = height;
  const view = render(tree(device, Screen));
  return { ...view, again: () => view.rerender(tree(device, Screen)) };
}

/** Whether the screen's two columns sit side by side (the open Duo only). */
export function sideBySide(testID: string): boolean {
  return StyleSheet.flatten(screen.getByTestId(testID).props.contentContainerStyle).flexDirection === 'row';
}

/** Whether a text is drawn in the danger red. */
export function isRed(testID: string): boolean {
  return StyleSheet.flatten(screen.getByTestId(testID).props.style).color === colors.danger;
}

export const ACCOUNT = '0x00000000000000000000000000000000000000aa';

/** A payment kit over the fake world's core, with payments kept in memory. */
export function fakeKit() {
  const records = new Map<string, CorePaymentRecord>();
  const started: { id: string; intent: CorePaymentIntent }[] = [];
  const sequenceOf = (record: CorePaymentRecord) => ({
    record: () => record,
    step: () => record.step,
    markBackedUp: () => {
      record.step = 1;
    },
    recover: () => ({ tag: 'Wait' }),
    addAttempt: () => new ArrayBuffer(0),
    markSent: () => new ArrayBuffer(0),
  });
  const PaymentSequence = {
    start: (_store: unknown, id: string, intent: CorePaymentIntent) => {
      const record: CorePaymentRecord = { id, intent, step: 0, attempts: [], version: 1, checksum: new ArrayBuffer(0) };
      records.set(id, record);
      started.push({ id, intent });
      return sequenceOf(record);
    },
    open: (_store: unknown, id: string) => {
      const record = records.get(id);
      if (!record) {
        throw new Error('no such payment');
      }
      return sequenceOf(record);
    },
  };
  const core = new Proxy(
    {},
    {
      get(_target, name: string) {
        if (name === 'PaymentSequence') {
          return PaymentSequence;
        }
        const fake = world.current.core as unknown as Record<string, unknown>;
        const value = fake[name];
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(fake) : value;
      },
    },
  );
  const store = {
    save: (record: CorePaymentRecord) => void records.set(record.id, record),
    load: (id: string) => records.get(id),
    list: () => [...records.keys()],
    remove: (id: string) => void records.delete(id),
    savePayload: () => {},
    loadPayload: () => undefined,
  };
  const node = { chainId: async () => buildNetwork.chainId, nonce: async () => 7n };
  return { kit: { core, store, node, nodeUrl: 'http://127.0.0.1:8547' }, started, records };
}
