// T8: a literal transcription of the frozen repository's published decision
// vocabulary (src/autorate/gate.py::Gate.decide, PRD F7 rule 2). The browser
// checker embeds this file verbatim and calls only `publishedVerdict`; it does
// not invent a second rule. Any change here must be reviewed against gate.py.
//
// The verdict is the CLI's exit vocabulary, never a boolean:
//   0 holds / 3 not-certifiable / 4 drift / 2 configuration-bug.
// `replay required` is the checker's own degradation state when the pinned
// wheel cannot be fetched — it is deliberately outside the CLI's four, so it
// can never be mistaken for a pass.

export function publishedVerdict(decision) {
  if (!decision || typeof decision !== 'object') {
    return { verdict: 'replay required', reason: 'no decision object was supplied' };
  }
  if (decision.fetch_ok === false) {
    return { verdict: 'replay required', reason: 'the pinned wheel could not be fetched or verified' };
  }
  if (decision.feasible !== true) {
    return { verdict: 'not-certifiable', reason: decision.reason || 'certificate refused' };
  }
  if (decision.drift === true) {
    return { verdict: 'drift', reason: 'the replay reported drift' };
  }
  if (decision.backend_mismatch === true) {
    return { verdict: 'not-certifiable', reason: 'subject_mismatch' };
  }
  return { verdict: 'holds', reason: 'the published decision rule holds' };
}

export default publishedVerdict;
