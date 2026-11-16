// T8: compare the published-rule verdict to the container replay's for one
// packet, and RECORD the comparison — never assert it. A recorded disagreement
// is evidence for the ledger, not a test failure hidden by an assert.
//
// Usage: node compare.mjs --record <json> --container-verdict holds --browser-verdict holds
import { writeFileSync } from 'node:fs';
import { publishedVerdict } from './verifier.mjs';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const recordPath = arg('--record');
if (!recordPath) {
  console.error('no --record path');
  process.exit(2);
}
const container = arg('--container-verdict') || '';
const decisionJson = arg('--browser-decision');
const browser = decisionJson
  ? publishedVerdict(JSON.parse(decisionJson)).verdict
  : (arg('--browser-verdict') || publishedVerdict({}).verdict);

const record = {
  container_verdict: container,
  browser_verdict: browser,
  equal: container === browser,
  source: 'publishedVerdict (gate.py transcription)',
};
writeFileSync(recordPath, JSON.stringify(record, null, 2) + '\n', 'utf8');
console.log(`recorded ${record.equal ? 'equal' : 'DIFFERENT'}: container=${container} browser=${browser}`);
process.exit(0);
