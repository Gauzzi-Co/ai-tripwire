'use strict';

const { readFileSync, existsSync } = require('node:fs');
const { resolve } = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const repoWorkflow = resolve(__dirname, '../workflows/codex-security-status.yml');
const source = readFileSync(existsSync(repoWorkflow)
  ? repoWorkflow : resolve(__dirname, 'codex-security-status.yml'), 'utf8');
const scriptLines = [];
let inScript = false;
for (const line of source.split('\n')) {
  if (line === '          script: |') {
    assert.equal(inScript, false);
    inScript = true;
    continue;
  }
  if (inScript) {
    if (line.trim() === '') { scriptLines.push(''); continue; }
    if (!line.startsWith('            ')) break;
    scriptLines.push(line.slice(12));
  }
}
assert.ok(scriptLines.length > 50, 'Tests must execute the actual inline publisher.');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction('github', 'context', 'core', scriptLines.join('\n'));
const SHA = 'a'.repeat(40);
const OLD_SHA = 'b'.repeat(40);
const BOT = { id: 199175422, login: 'chatgpt-codex-connector[bot]' };
const REPOSITORY = 'Gauzzi-Co/example';

function summary({ sha = SHA, status = 'completed', findings = false,
  unresolved = findings, user = BOT, id = 10, updated = '2026-10-28T12:00:00Z',
  repository = REPOSITORY, number = 5, receiptStatus = status } = {}) {
  const state = { security_review: { commit_sha: sha, status,
    has_any_findings: findings, has_unresolved_findings: unresolved } };
  const receipt = { repository, pullRequestNumber: number, headSha: sha,
    status: receiptStatus };
  return { id, user, updated_at: updated,
    html_url: 'https://github.com/Gauzzi-Co/example/pull/5#issuecomment-' + id,
    body: '<!-- codex-pull-request-review-summary -->\n' +
      '<!-- codex-review-state:v1 ' + JSON.stringify(state) + ' -->\n' +
      '<!-- codex-security-review:v1 ' + JSON.stringify(receipt) + ' -->' };
}

async function run(comments = [], { payload = { pull_request: { number: 5 } },
  prState = 'open', sha = SHA, publishError, listError } = {}) {
  const writes = [];
  const core = { info() {}, warning() {} };
  const github = {
    rest: {
      pulls: { get: async () => ({ data: { state: prState, head: { sha },
        html_url: 'https://github.com/Gauzzi-Co/example/pull/5' } }) },
      issues: { listComments() {} },
      repos: { createCommitStatus: async value => {
        if (publishError) throw new Error(publishError);
        writes.push(value);
      } },
    },
    paginate: async () => { if (listError) throw new Error(listError); return comments; },
  };
  await execute(github, { repo: { owner: 'Gauzzi-Co', repo: 'example' }, payload }, core);
  return writes;
}

test('clean completed native review publishes green on the exact head', async () => {
  const [status] = await run([summary()]);
  assert.equal(status.state, 'success');
  assert.equal(status.sha, SHA);
  assert.equal(status.context, 'Codex Security Review');
});
test('findings publish red', async () => {
  assert.equal((await run([summary({ findings: true })]))[0].state, 'failure');
});
test('resolving a review thread alone cannot turn reported findings green', async () => {
  assert.equal((await run([summary({ findings: true, unresolved: false })]))[0].state, 'failure');
});
test('no review is pending, never green', async () => {
  assert.equal((await run())[0].state, 'pending');
});
test('a clean review of an earlier SHA cannot approve the current SHA', async () => {
  assert.equal((await run([summary({ sha: OLD_SHA })]))[0].state, 'pending');
});
test('human comments cannot forge a clean result', async () => {
  assert.equal((await run([summary({ user: { id: 1, login: BOT.login } })]))[0].state, 'pending');
  assert.equal((await run([summary({ user: { id: BOT.id, login: 'somebody-else' } })]))[0].state, 'pending');
});
test('a finding in free text or a quoted marker is not trusted', async () => {
  const comment = summary({ user: { id: 1, login: 'human' } });
  comment.body = 'SECURITY: REVIEW_BLOCKING\n' + comment.body;
  assert.equal((await run([comment]))[0].state, 'pending');
});
for (const status of ['running', 'queued', 'pending', 'in_progress']) {
  test(status + ' review stays pending', async () => {
    assert.equal((await run([summary({ status, findings: null, unresolved: null })]))[0].state, 'pending');
  });
}
for (const status of ['failed', 'cancelled', 'timed_out', 'unknown_future_status']) {
  test(status + ' review is an error, never green', async () => {
    assert.equal((await run([summary({ status })]))[0].state, 'error');
  });
}
test('completed review with missing flags fails closed', async () => {
  assert.equal((await run([summary({ findings: null, unresolved: null })]))[0].state, 'error');
});
test('inconsistent flags fail closed', async () => {
  assert.equal((await run([summary({ findings: false, unresolved: true })]))[0].state, 'error');
});
test('inconsistent status markers fail closed', async () => {
  assert.equal((await run([summary({ receiptStatus: 'running' })]))[0].state, 'error');
});
test('malformed or duplicated structured data fails closed', async () => {
  const malformed = summary();
  malformed.body = '<!-- codex-pull-request-review-summary -->\n<!-- codex-security-review:v1 {oops} -->';
  assert.equal((await run([malformed]))[0].state, 'error');
  const duplicate = summary();
  duplicate.body += '\n' + duplicate.body.split('\n')[2];
  assert.equal((await run([duplicate]))[0].state, 'error');
});
test('a receipt for another repository or PR fails closed', async () => {
  assert.equal((await run([summary({ repository: 'somebody/else' })]))[0].state, 'error');
  assert.equal((await run([summary({ number: 6 })]))[0].state, 'error');
});
test('the latest current-commit result supersedes an older clean result', async () => {
  const old = summary({ updated: '2026-10-28T11:00:00Z' });
  const recent = summary({ findings: true, updated: '2026-10-28T12:00:00Z' });
  assert.equal((await run([old, recent]))[0].state, 'failure');
});
test('an old-commit summary is skipped when a current result exists', async () => {
  const old = summary({ sha: OLD_SHA, updated: '2026-10-28T13:00:00Z' });
  assert.equal((await run([old, summary()]))[0].state, 'success');
});
test('issue-comment and manual refresh events resolve the intended PR', async () => {
  for (const payload of [{ issue: { number: 5 } }, { inputs: { pr_number: '5' } }]) {
    assert.equal((await run([summary()], { payload }))[0].state, 'success');
  }
});
test('invalid manual input is rejected without posting a status', async () => {
  for (const value of ['1; rm -rf /', '-1', '1.5', '', 'NaN']) {
    await assert.rejects(run([], { payload: { inputs: { pr_number: value } } }));
  }
});
test('closed PRs are not modified', async () => {
  assert.deepEqual(await run([summary()], { prState: 'closed' }), []);
});
test('GitHub failures propagate instead of fabricating a green result', async () => {
  await assert.rejects(run([summary()], { publishError: 'forbidden' }));
  await assert.rejects(run([summary()], { listError: 'unavailable' }));
});
test('workflow pins actions, limits permission, and never uses pull_request_target', () => {
  assert.ok(!source.includes('pull_request_target:'));
  const publishJob = source.split('  publish:\n')[1].split('  status-tests:\n')[0];
  assert.ok(!publishJob.includes('actions/checkout'));
  assert.ok(publishJob.includes('statuses: write'));
  assert.ok(!source.includes('secrets.'));
  for (const line of source.split('\n').filter(l => /^\s*-?\s*uses:/.test(l))) {
    assert.match(line, /@[a-f0-9]{40}(?:\s|$)/);
  }
});
