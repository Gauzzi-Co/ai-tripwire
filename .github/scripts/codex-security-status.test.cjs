'use strict';

const { readFileSync, existsSync } = require('node:fs');
const { resolve } = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const workflow = readFileSync(resolve(__dirname, '../workflows/codex-security-status.yml'), 'utf8');
const section = workflow.split('          script: |\n');
assert.equal(section.length, 2, 'Test the one actual privileged script.');
const lines = [];
for (const line of section[1].split('\n')) {
  if (line && !line.startsWith('            ')) break;
  lines.push(line.slice(12));
}
const source = lines.join('\n');
assert.ok(source.length > 2000);
assert.ok(!source.includes('${{'), 'No event expression interpolation into code.');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const publish = new AsyncFunction('github', 'context', 'core', source);
const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);
const FULL = 'Gauzzi-Co/example';
const BOT = { id: 199175422, login: 'chatgpt-codex-connector[bot]' };
const HUMAN = { id: 1, login: 'collaborator' };
const HEADER = '<!-- codex-pull-request-review-summary -->';

function event({ sha = SHA, receiptSha = sha, any = true, unresolved = any,
  status = 'completed', receiptStatus = status, number = 5, receiptNumber = number,
  repository = FULL, sender = BOT, author = BOT, action = 'edited', omit = [] } = {}) {
  const security_review = { commit_sha: sha, has_any_findings: any,
    has_unresolved_findings: unresolved, status };
  for (const key of omit) delete security_review[key];
  const receipt = { headSha: receiptSha, repository, pullRequestNumber: receiptNumber, status: receiptStatus };
  return { action, issue: { number, pull_request: {} }, sender,
    comment: { id: 20, user: author, body: HEADER + '\n' +
      '<!-- codex-review-state:v1 ' + JSON.stringify({ security_review }) + ' -->\n' +
      '<!-- codex-security-review:v1 ' + JSON.stringify(receipt) + ' -->' } };
}
async function run({ payload = event(), eventName = 'issue_comment', prState = 'open',
  head = SHA, base = FULL, getError, writeError, writes = [] } = {}) {
  const calls = [];
  const info = [];
  const github = { rest: {
    pulls: { get: async args => {
      calls.push(args);
      if (getError) throw new Error('PR API unavailable');
      return { data: { state: prState, head: { sha: head }, base: { repo: { full_name: base } } } };
    } },
    repos: { createCommitStatus: async status => {
      if (writeError) throw new Error('Status write denied');
      writes.push(status);
    } },
    issues: { listComments: () => { throw new Error('Mutable comments must never be read'); } },
  }, paginate: () => { throw new Error('No mutable comment/status-history reads permitted'); } };
  await publish(github, { eventName, payload, repo: { owner: 'Gauzzi-Co', repo: 'example' } },
    { info: value => info.push(value) });
  return { writes, calls, info };
}

test('fresh authenticated positive finding creates an advisory red check on the exact SHA', async () => {
  const f = await run();
  assert.equal(f.writes.length, 1);
  assert.deepEqual(f.writes[0], { owner: 'Gauzzi-Co', repo: 'example', sha: SHA,
    state: 'failure', context: 'Codex Security Review',
    description: 'Codex reported security findings in PR #5. Review before merging.',
    target_url: 'https://github.com/Gauzzi-Co/example/pull/5#issuecomment-20' });
});
test('resolved discussions do not clear reported findings', async () => {
  for (const unresolved of [true, false, null]) {
    assert.equal((await run({ payload: event({ any: true, unresolved }) })).writes[0].state, 'failure');
  }
});
test('an explicit unresolved finding still signals red when the other flag is unknown', async () => {
  assert.equal((await run({ payload: event({ any: null, unresolved: true }) })).writes[0].state, 'failure');
});
test('real completed-null receipts are accepted without a parser error or a fabricated clean result', async () => {
  const f = await run({ payload: event({ any: null, unresolved: null }) });
  assert.deepEqual(f.writes, []);
  assert.deepEqual(f.calls, []);
});
test('omitted disposition flags are unknown, not clean', async () => {
  assert.deepEqual((await run({ payload: event({ omit: ['has_any_findings', 'has_unresolved_findings'] }) })).writes, []);
});
test('clean and partially unknown events never write a green status', async () => {
  for (const [any, unresolved] of [[false, false], [false, null], [null, false]]) {
    assert.deepEqual((await run({ payload: event({ any, unresolved }) })).writes, []);
  }
});
for (const status of ['queued', 'running', 'pending', 'in_progress', 'failed', 'cancelled']) {
  test(status + ' without a reported finding does not change the security signal', async () => {
    assert.deepEqual((await run({ payload: event({ status, any: null, unresolved: null }) })).writes, []);
  });
}
test('an authenticated positive finding is retained even if the wider review is still running', async () => {
  assert.equal((await run({ payload: event({ status: 'running' }) })).writes[0].state, 'failure');
});
test('only a real bot author AND sender can provide findings evidence', async () => {
  for (const author of [HUMAN, { id: 1, login: BOT.login }, { id: BOT.id, login: 'impostor' }]) {
    assert.deepEqual((await run({ payload: event({ author }) })).writes, []);
  }
  for (const sender of [HUMAN, { id: 1, login: BOT.login }, { id: BOT.id, login: 'impostor' }]) {
    assert.deepEqual((await run({ payload: event({ sender }) })).writes, []);
  }
});
test('human edits of a bot-authored receipt are not authenticated evidence', async () => {
  const writes = [];
  await run({ writes });
  await run({ writes, payload: event({ sender: HUMAN, any: false, unresolved: false }) });
  assert.deepEqual(writes.map(s => s.state), ['failure']);
});
test('mutable API comments and status history cannot influence the signal', async () => {
  // The mock throws if either endpoint is accessed; webhook evidence is used.
  assert.equal((await run()).writes[0].state, 'failure');
});
test('copied markers in human text or another comment type cannot impersonate a summary', async () => {
  const payload = event(); payload.comment.body = 'Quoted:\n' + payload.comment.body;
  assert.deepEqual((await run({ payload })).writes, []);
  const other = event(); other.comment.body = 'SECURITY: REVIEW_BLOCKING';
  assert.deepEqual((await run({ payload: other })).writes, []);
});
test('ordinary issues, deleted comments and non-comment events cannot invoke the writer', async () => {
  const ordinary = event(); delete ordinary.issue.pull_request;
  assert.deepEqual((await run({ payload: ordinary })).writes, []);
  assert.deepEqual((await run({ payload: event({ action: 'deleted' }) })).writes, []);
  for (const eventName of ['pull_request', 'pull_request_target', 'workflow_run', 'workflow_dispatch', 'repository_dispatch', 'workflow_call']) {
    assert.deepEqual((await run({ eventName })).writes, []);
  }
});
test('created and edited native events are both supported', async () => {
  for (const action of ['created', 'edited']) {
    assert.equal((await run({ payload: event({ action }) })).writes[0].state, 'failure');
  }
});
test('freshness is bound to the live open PR head, never a new commit', async () => {
  assert.deepEqual((await run({ payload: event({ sha: OLD }) })).writes, []);
  assert.deepEqual((await run({ head: OLD })).writes, []);
  assert.deepEqual((await run({ prState: 'closed' })).writes, []);
});
test('inconsistent SHA pairs cannot target another commit', async () => {
  for (const options of [{ sha: SHA, receiptSha: OLD }, { sha: OLD, receiptSha: SHA }]) {
    await assert.rejects(run({ payload: event(options) }), /does not match/);
  }
});
test('repository, PR, status and SHA bindings are mandatory for a finding', async () => {
  for (const options of [{ repository: 'other/repo' }, { receiptNumber: 6 },
    { receiptStatus: 'running' }, { sha: 'invalid' }, { number: -1 }, { status: '' }]) {
    await assert.rejects(run({ payload: event(options) }));
  }
  await assert.rejects(run({ base: 'other/repo' }));
});
test('string, numeric or other flag types cannot manufacture a positive signal', async () => {
  for (const any of ['true', 'false', 1, [], {}]) {
    await assert.rejects(run({ payload: event({ any, unresolved: null }) }), /disposition/);
  }
});
test('missing, duplicate, malformed and array receipt JSON fails without publishing', async () => {
  const duplicate = event(); duplicate.comment.body += '\n' + duplicate.comment.body.split('\n')[2];
  const array = event(); array.comment.body = HEADER + '\n<!-- codex-security-review:v1 [] -->';
  const malformed = event(); malformed.comment.body = HEADER + '\n<!-- codex-security-review:v1 {oops} -->';
  for (const payload of [duplicate, array, malformed]) await assert.rejects(run({ payload }));
});
test('CRLF receipts are accepted without interpreting their text as code', async () => {
  const payload = event(); payload.comment.body = payload.comment.body.replaceAll('\n', '\r\n');
  assert.equal((await run({ payload })).writes[0].state, 'failure');
});
test('unsafe comment identifiers cannot influence the target URL', async () => {
  const payload = event(); payload.comment.id = '20; echo pwn';
  await assert.rejects(run({ payload }));
});
test('GitHub API failures cannot create a clean or fabricated result', async () => {
  await assert.rejects(run({ getError: true }));
  await assert.rejects(run({ writeError: true }));
});
test('deleting a later receipt or replacing a queued refresh can never expose older green', async () => {
  const writes = [];
  await run({ writes });
  for (const payload of [event({ action: 'deleted' }), event({ any: false, unresolved: false }),
    event({ any: null, unresolved: null }), event({ sender: HUMAN, any: false, unresolved: false })]) {
    await run({ payload, writes });
  }
  assert.deepEqual(writes.map(s => s.state), ['failure']);
});
test('two PRs sharing a SHA cannot erase each other\'s security finding', async () => {
  const writes = [];
  await run({ writes, payload: event({ number: 5 }) });
  await run({ writes, payload: event({ number: 6, any: false, unresolved: false }) });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].sha, SHA);
  assert.equal(writes[0].state, 'failure');
});
test('out-of-order events and reruns are monotonic red-only writes', async () => {
  const events = [event(), event({ any: null, unresolved: null }), event({ any: false, unresolved: false })];
  for (const order of [events, events.toReversed(), [events[1], events[0], events[2]]]) {
    const writes = [];
    for (const payload of order) await run({ payload, writes });
    assert.deepEqual(writes.map(s => s.state), ['failure']);
  }
});
test('there is no introduced PR-revision workflow or selectable-ref writer trigger', () => {
  const triggers = workflow.split('\npermissions:\n')[0];
  assert.doesNotMatch(triggers, /^  (pull_request\w*|workflow_dispatch|workflow_call|workflow_run|push):/m);
  assert.match(triggers, /^  issue_comment:/m);
  assert.match(triggers, /^  repository_dispatch:\n    types: \[codex-security-self-test\]/m);
  assert.equal(existsSync(resolve(__dirname, '../workflows/codex-security-status-tests.yml')), false);
  assert.doesNotMatch(workflow, /github\.event\.pull_request\.head|inputs\.pr_number|head_ref/);
});
test('trusted tests checkout only default-branch snapshot and carry no write permission', () => {
  const tests = workflow.split('  self-test:\n')[1].split('  publish:\n')[0];
  assert.match(tests, /ref: \$\{\{ github.sha \}\}/);
  assert.match(tests, /persist-credentials: false/);
  assert.doesNotMatch(tests, /^\s+[\w-]+: write\s*$/m);
});
test('write job never checks out code, reads mutable comments, or grants unrelated access', () => {
  const publisher = workflow.split('  publish:\n')[1];
  assert.doesNotMatch(publisher, /actions\/checkout|download-artifact|require\(|import\(|eval\(/);
  assert.doesNotMatch(source, /listComments|listReviewComments|listCommitStatuses|paginate|state: 'success'|state: 'pending'/);
  assert.match(publisher, /github.event_name == 'issue_comment'/);
  assert.match(publisher, /needs: self-test/);
  assert.doesNotMatch(publisher, /^\s+(contents|issues|actions|id-token): write\s*$/m);
});
test('SHA pins and explicit permissions are retained without secrets or merge rules', () => {
  assert.doesNotMatch(workflow, /secrets\.|pull_request_target:|^concurrency:/m);
  assert.match(workflow, /^permissions:\n  contents: read/m);
  for (const line of workflow.split('\n').filter(l => /^\s*-?\s*uses:/.test(l))) {
    assert.match(line, /@[a-f0-9]{40}(?:\s|$)/);
  }
});
