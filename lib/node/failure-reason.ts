// Why a send, Vanish, Summon or Claim failed, in plain words from what the
// node or the native core said. Never only "Transaction failed": the person
// should know whether the node is out of reach, the account is short of test
// GHOST, or the node refused it for another reason it gave.

import type { NodeError } from './rpc';

const NOT_ENOUGH = 'Not enough test GHOST in this account for the amount and its fee. Tap Get test GHOST on Home.';

function rawMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return '';
}

function sentence(text: string): string {
  const trimmed = text.trim();
  const capital = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

/** The node the error came from, when it says (lib/node/rpc.ts `fromNode`). */
function failedNode(error: unknown): string | null {
  const url = error instanceof Error ? (error as NodeError).nodeUrl : undefined;
  return typeof url === 'string' && url !== '' ? url : null;
}

/**
 * The reason, as one or two sentences the screen can show as they are. The
 * node named is the one the error came from, which may be a backup node;
 * `settingsUrl` only when the error does not say.
 */
export function failureReason(error: unknown, settingsUrl: string): string {
  const message = rawMessage(error).trim();
  const lower = message.toLowerCase();
  const nodeUrl = failedNode(error) ?? settingsUrl;
  const node = `the test node at ${nodeUrl}`;

  if (
    /network request failed|failed to fetch|load failed|could not connect|connection refused|econnrefused|ehostunreach|enetunreach|timed out|offline|internet connection/.test(
      lower,
    )
  ) {
    return `Can't reach ${node}. Check that it is running and that this phone is on the same network.`;
  }
  if (lower.includes('did not answer in time')) {
    return sentence(`${node} did not answer in time. Check that it is running and try again`);
  }
  const http = /answered http (\d{3})/.exec(lower);
  if (http) {
    return sentence(`${node} answered with an error (HTTP ${http[1]})`);
  }
  if (lower.includes('not the ghost test network')) {
    return `The node at ${nodeUrl} is not the Ghost test network. Check the node in Settings.`;
  }
  // The node's words, or the core's error names (InsufficientFunds, …).
  if (/insufficient ?(funds|balance)|not enough|exceeds balance|balance too low/.test(lower)) {
    return NOT_ENOUGH;
  }
  if (lower.includes('nonce too low')) {
    return 'Another payment from this account went first. Try again.';
  }
  if (/underpriced|fee cap|less than block base fee|fee too low|max fee per gas/.test(lower)) {
    return 'The fee was too low for the test node. Try again.';
  }
  if (/gas limit|intrinsic gas/.test(lower)) {
    return 'The test node would not run it with this gas limit.';
  }
  if (lower.includes('sent a malformed') || lower.includes('left a call unanswered')) {
    return sentence(`${node} sent an answer this app cannot read`);
  }
  const refused = /the node refused a call: (.*)$/is.exec(message);
  if (refused) {
    const reason = refused[1].trim();
    return reason === '' || /^no reason given$/i.test(reason)
      ? sentence(`${node} refused it and gave no reason`)
      : sentence(`${node} refused it: ${reason}`);
  }
  if (message === '' || /^transaction failed\.?$/i.test(message)) {
    return sentence(`${node} did not take it and gave no reason`);
  }
  return sentence(message);
}
