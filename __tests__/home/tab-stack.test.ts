import { closeOpenScreens } from '../../components/tab-stack';

jest.mock('expo-router', () => ({ useNavigation: jest.fn() }));

describe('leaving a tab', () => {
  const routes = [
    { name: '(home)', state: { key: 'stack-home', index: 2 } },
    { name: '(cards)', state: { key: 'stack-cards', index: 0 } },
    { name: 'activity' },
    { name: '(settings)' },
  ];

  it('closes the screens the tab had open, back to its first screen', () => {
    expect(closeOpenScreens(routes, '(home)')).toMatchObject({ type: 'POP_TO_TOP', target: 'stack-home' });
  });

  it('does nothing for a tab already on its first screen', () => {
    expect(closeOpenScreens(routes, '(cards)')).toBeNull();
  });

  it('does nothing for a tab that has opened nothing yet, or holds no screens', () => {
    expect(closeOpenScreens(routes, '(settings)')).toBeNull();
    expect(closeOpenScreens(routes, 'activity')).toBeNull();
    expect(closeOpenScreens(routes, 'nowhere')).toBeNull();
  });
});
