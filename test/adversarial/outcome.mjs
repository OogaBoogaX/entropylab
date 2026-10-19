// Whether a Jev adversarial run fails, from the harness's result rows.
//
// The harness's own checks are deterministic: a network attempt, an uncaught
// exception or rejection, a failed invariant or a dead page is something the
// app must never do, so each fails the run. Jev's "broken" fails it too. A
// "suspect", or no verdict at all (no API key, the API down), does not: a
// suspect is for a person to read in the table, and an outage is not the
// app's fault. Returns one line per reason, each naming its scenario; an
// empty list means the run passed.
export const runFailures = (rows) =>
  rows.flatMap((row) => {
    const reasons = [];
    if (row.net) reasons.push(`${row.net} network attempt(s)`);
    if (row.exceptions) reasons.push(`${row.exceptions} uncaught exception(s)`);
    if (row.rejections) reasons.push(`${row.rejections} unhandled rejection(s)`);
    for (const failure of row.failures ?? []) if (!/^network attempts:/.test(failure)) reasons.push(failure);
    if (row.alive === false) reasons.push("page not alive after the scenario");
    if (row.choice === "broken") reasons.push('Jev verdict "broken"');
    return reasons.map((reason) => `${row.name}: ${reason}`);
  });

// Whether Jev judged the run at all. A scenario without a verdict never fails
// on its own (above), but with an API key configured, a run in which no
// scenario got one is a judge outage or a refused key, not a judged run: on
// 2026-10-09 a rejected key passed silently every night. That fails the run.
// `keyConfigured` is false for local runs and forks without the secret.
const UNJUDGED = "(none)";
export const judgeFailures = (rows, keyConfigured) =>
  keyConfigured && rows.length && rows.every((row) => row.choice === UNJUDGED)
    ? [`Jev judged none of the ${rows.length} scenario(s): the judge was unreachable or refused the API key`]
    : [];

// The partial case only warns, naming the scenarios Jev did not judge: one
// failed request is an outage worth seeing, not a verdict on the app.
export const judgeWarnings = (rows, keyConfigured) => {
  if (!keyConfigured) return [];
  const missing = rows.filter((row) => row.choice === UNJUDGED);
  if (!missing.length || missing.length === rows.length) return [];
  return [`Jev gave no verdict for ${missing.length} of ${rows.length} scenario(s): ${missing.map((row) => row.name).join(", ")}`];
};
