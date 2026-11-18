// Summon from an older NTAG 424 card this iPhone wrote: the Summon steps, with
// the key read from the card.
import { SummonFlow } from '../(home)/summon';

export default function SummonOlderCardScreen() {
  return <SummonFlow olderCard />;
}
