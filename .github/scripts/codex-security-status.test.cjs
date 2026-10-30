'use strict';

const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const writer = readFileSync(resolve(__dirname, '../workflows/codex-security-status.yml'), 'utf8');
const reader = readFileSync(resolve(__dirname, '../workflows/codex-security-status-tests.yml'), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
function scriptFor(step) {
  const block = writer.split('      - name: ' + step + '\n')[1];
  assert.ok(block, 'Missing actual workflow step: ' + step);
  const lines = block.split('          script: |\n')[1].split('\n');
  const source = [];
  for (const line of lines) {
    if (line && !line.startsWith('            ')) break;
    source.push(line.slice(12));
  }
  assert.ok(source.length > 30, 'Tests must execute the actual inline script.');
  assert.ok(!source.join('\n').includes('${{'), 'No expression interpolation in executable code.');
  return source.join('\n');
}
const resolveTarget = new AsyncFunction('github', 'context', 'core', scriptFor('Resolve refresh target'));
const publish = new AsyncFunction('github', 'context', 'core', 'process', scriptFor('Publish current-commit security result'));
const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);
const BOT = { id: 199175422, login: 'chatgpt-codex-connector[bot]' };
const FULL = 'Gauzzi-Co/example';
const MARKER = '<!-- codex-pull-request-review-summary -->';
const STATUS = 'Codex Security Review';
const DELETED = 'Security receipt removed; awaiting a new Codex review.';
const url = n => 'https://github.com/' + FULL + '/pull/' + n;

function pr(number = 5, overrides = {}) {
  return { number, state: 'open', head: { sha: SHA }, base: { repo: { full_name: FULL } }, ...overrides };
}
function summary({ number = 5, sha = SHA, receiptSha = sha, status = 'completed',
  receiptStatus = status, any = false, unresolved = any, user = BOT, id = 10,
  updated = '2026-10-30T12:00:00Z', repository = FULL, omit = [] } = {}) {
  const state = { security_review: { commit_sha: sha, status,
    has_any_findings: any, has_unresolved_findings: unresolved } };
  for (const key of omit) delete state.security_review[key];
  const receipt = { repository, pullRequestNumber: number, headSha: receiptSha, status: receiptStatus };
  return { id, user, updated_at: updated, html_url: url(number) + '#issuecomment-' + id,
    body: MARKER + '\n<!-- codex-review-state:v1 ' + JSON.stringify(state) + ' -->\n' +
      '<!-- codex-security-review:v1 ' + JSON.stringify(receipt) + ' -->' };
}
function finding({ sha = SHA, user = BOT, created = '2026-10-30T11:00:00Z' } = {}) {
  return { user, commit_id: sha, original_commit_id: sha, created_at: created,
    body: '<!-- codex-security-review-finding:v1 -->\nSecurity: missing authorization.' };
}
function fixture(options = {}) {
  const writes = [];
  const failures = [];
  const outputs = {};
  const calls = [];
  const primary = options.primary ?? pr();
  const extra = options.linked ?? [];
  const map = new Map([primary, ...extra].map(p => [p.number, p]));
  const comments = options.comments ?? { 5: [summary()] };
  const history = [...(options.history ?? [])];
  const core = { info() {}, warning() {}, setOutput(k, v) { outputs[k] = v; },
    setFailed(message) { failures.push(message); } };
  const rest = {
    pulls: {
      get: async args => {
        calls.push({ name: 'pulls.get', ...args });
        if (options.getError) throw new Error('PR API unavailable');
        const p = options.getPR ? options.getPR(args, calls) : map.get(args.pull_number);
        if (!p) throw new Error('PR not found');
        return { data: p };
      },
      listReviewComments() {},
    },
    issues: { listComments() {} },
    repos: {
      listPullRequestsAssociatedWithCommit() {},
      listCommitStatusesForRef() {},
      createCommitStatus: async status => {
        calls.push({ name: 'createCommitStatus' });
        if (options.writeError) throw new Error('Status write forbidden');
        writes.push(status);
        history.unshift(status);
      },
    },
    actions: { getWorkflowRun: async args => {
      calls.push({ name: 'getWorkflowRun', ...args });
      return { data: options.run ?? { id: 100, repository: { full_name: FULL }, status: 'completed',
        event: 'pull_request', name: 'Codex Security status tests',
        path: '.github/workflows/codex-security-status-tests.yml', display_title: '5',
        pull_requests: [{ number: 5 }] } };
    } },
  };
  const github = { rest, paginate: async (method, args) => {
    calls.push({ name: 'paginate', method, ...args });
    if (method === rest.repos.listPullRequestsAssociatedWithCommit) return extra;
    if (method === rest.repos.listCommitStatusesForRef) return [...history];
    if (method === rest.issues.listComments) {
      if (options.readError) throw new Error('Comments API unavailable');
      return comments[args.issue_number] ?? [];
    }
    if (method === rest.pulls.listReviewComments) return options.inline?.[args.pull_number] ?? [];
    throw new Error('Unexpected endpoint');
  } };
  const context = { repo: { owner: 'Gauzzi-Co', repo: 'example' },
    eventName: options.eventName ?? 'issue_comment',
    payload: options.payload ?? { action: 'edited', issue: { number: 5, pull_request: {} },
      comment: summary(), sender: BOT } };
  return { github, core, context, writes, outputs, failures, calls };
}
async function execute(options = {}) {
  const f = fixture(options);
  await publish(f.github, f.context, f.core, { env: {
    PR_NUMBER: options.numberText ?? '5', EXPECTED_SHA: options.expectedSha ?? SHA,
    DELETED_ID: options.deletedText ?? '',
  } });
  return { ...f, final: f.writes.at(-1) };
}

test('positive clean proof becomes green on the exact SHA after pending invalidation', async () => {
  const f = await execute();
  assert.equal(f.writes[0].state, 'pending');
  assert.equal(f.final.state, 'success');
  assert.equal(f.final.sha, SHA);
  assert.equal(f.final.context, STATUS);
  assert.equal(f.final.target_url, url(5) + '#issuecomment-10');
  assert.deepEqual(f.failures, []);
});
test('reported findings are red, including resolved discussion threads', async () => {
  for (const unresolved of [true, false, null]) {
    assert.equal((await execute({ comments: { 5: [summary({ any: true, unresolved })] } })).final.state, 'failure');
  }
});
test('actual completed-null native shape is unknown/yellow, not error or green', async () => {
  const f = await execute({ comments: { 5: [summary({ any: null, unresolved: null })] } });
  assert.equal(f.final.state, 'pending');
  assert.match(f.final.description, /disposition unavailable/);
  assert.deepEqual(f.failures, []);
});
test('omitted and partially-null flags also remain non-green', async () => {
  for (const options of [{ omit: ['has_any_findings', 'has_unresolved_findings'] },
    { omit: ['has_unresolved_findings'] }, { any: false, unresolved: null },
    { any: null, unresolved: false }]) {
    assert.equal((await execute({ comments: { 5: [summary(options)] } })).final.state, 'pending');
  }
});
test('a genuine current-SHA inline finding supplies positive evidence despite null flags', async () => {
  const f = await execute({ comments: { 5: [summary({ any: null, unresolved: null })] }, inline: { 5: [finding()] } });
  assert.equal(f.final.state, 'failure');
});
test('a new inline finding cannot be hidden by an earlier clean summary', async () => {
  assert.equal((await execute({ inline: { 5: [finding({ created: '2026-10-30T13:00:00Z' })] } })).final.state, 'failure');
});
test('a later explicit clean rerun can supersede an earlier same-SHA finding', async () => {
  assert.equal((await execute({ inline: { 5: [finding()] } })).final.state, 'success');
});
test('fake, ordinary, or old-SHA inline comments cannot create a security result', async () => {
  const cases = [finding({ user: { id: 1, login: BOT.login } }), finding({ sha: OLD }),
    { ...finding(), body: 'SECURITY: REVIEW_BLOCKING' }];
  for (const item of cases) {
    assert.equal((await execute({ comments: { 5: [summary({ any: null, unresolved: null })] }, inline: { 5: [item] } })).final.state, 'pending');
  }
});
test('finding without a summary is red, but no summary and no finding stays pending', async () => {
  assert.equal((await execute({ comments: {}, inline: { 5: [finding()] } })).final.state, 'failure');
  assert.equal((await execute({ comments: {} })).final.state, 'pending');
});
test('both bot ID and login plus the anchored marker are required', async () => {
  for (const user of [{ id: 1, login: BOT.login }, { id: BOT.id, login: 'human' }]) {
    assert.equal((await execute({ comments: { 5: [summary({ user })] } })).final.state, 'pending');
  }
  const quoted = summary(); quoted.body = 'Quoted:\n' + quoted.body;
  assert.equal((await execute({ comments: { 5: [quoted] } })).final.state, 'pending');
});
test('consistently stale SHA pairs do not approve the head', async () => {
  assert.equal((await execute({ comments: { 5: [summary({ sha: OLD })] } })).final.state, 'pending');
});
test('contradictory SHA fields invalidate the newest result instead of falling back to older green', async () => {
  const older = summary({ updated: '2026-10-30T10:00:00Z' });
  for (const pair of [{ sha: SHA, receiptSha: OLD }, { sha: OLD, receiptSha: SHA }]) {
    const bad = summary({ ...pair, id: 11 });
    assert.equal((await execute({ comments: { 5: [older, bad] } })).final.state, 'error');
  }
});
test('wrong repository, PR number, statuses, and findings types fail closed', async () => {
  for (const options of [{ repository: 'other/repo' }, { number: 6 }, { receiptStatus: 'running' },
    { any: 'false' }, { any: false, unresolved: true }]) {
    assert.equal((await execute({ comments: { 5: [summary(options)] } })).final.state, 'error');
  }
});
test('duplicate, malformed, and array JSON markers never approve', async () => {
  const duplicated = summary(); duplicated.body += '\n' + duplicated.body.split('\n')[2];
  const invalid = summary(); invalid.body = MARKER + '\n<!-- codex-security-review:v1 [] -->';
  const syntax = summary(); syntax.body = MARKER + '\n<!-- codex-security-review:v1 {oops} -->';
  for (const comment of [duplicated, invalid, syntax]) {
    assert.equal((await execute({ comments: { 5: [comment] } })).final.state, 'error');
  }
});
for (const status of ['running', 'queued', 'pending', 'in_progress']) {
  test(status + ' supersedes older completion with pending', async () => {
    const older = summary({ updated: '2026-10-30T10:00:00Z' });
    const newer = summary({ status, any: null, unresolved: null, id: 11 });
    assert.equal((await execute({ comments: { 5: [older, newer] } })).final.state, 'pending');
  });
}
for (const status of ['failed', 'cancelled', 'timed_out', 'future_unknown']) {
  test(status + ' is visibly erroneous, not clean', async () => {
    assert.equal((await execute({ comments: { 5: [summary({ status })] } })).final.state, 'error');
  });
}
test('a deleted newer receipt cannot expose an older green receipt', async () => {
  const history = [{ context: STATUS, target_url: url(5) + '#issuecomment-20', description: 'Previous result' }];
  const f = await execute({ history });
  assert.equal(f.final.state, 'pending');
  assert.equal(f.final.description, DELETED);
  assert.equal(f.final.target_url, url(5) + '#issuecomment-20');
});
test('deletion invalidation survives later refreshes and clears only for a fresh receipt', async () => {
  const history = [{ context: STATUS, target_url: url(5) + '#issuecomment-20', description: DELETED }];
  assert.equal((await execute({ history, comments: { 5: [summary({ id: 20 })] } })).final.state, 'pending');
  assert.equal((await execute({ history, comments: { 5: [summary({ id: 21 })] } })).final.state, 'success');
  const deletion = await execute({ deletedText: '20', comments: { 5: [summary({ id: 20 })] } });
  assert.equal(deletion.final.state, 'pending');
});
test('a clean PR cannot overwrite findings from another PR sharing the commit', async () => {
  const f = await execute({ linked: [pr(6)], comments: { 5: [summary()], 6: [summary({ number: 6, any: true })] } });
  assert.equal(f.final.state, 'failure');
  assert.equal(f.final.target_url, url(6) + '#issuecomment-10');
});
test('shared-commit uncertainty cannot be hidden by one clean PR', async () => {
  const f = await execute({ linked: [pr(6)], comments: { 5: [summary()] } });
  assert.equal(f.final.state, 'pending');
});
test('closed, other-repository, or other-SHA PRs do not participate', async () => {
  const linked = [pr(6, { state: 'closed' }), pr(7, { head: { sha: OLD } }),
    pr(8, { base: { repo: { full_name: 'other/repo' } } })];
  assert.equal((await execute({ linked })).final.state, 'success');
});
test('closed PR without a live same-SHA sibling is not modified', async () => {
  assert.deepEqual((await execute({ primary: pr(5, { state: 'closed' }) })).writes, []);
});
test('closing the triggering PR cannot suppress a live same-SHA sibling finding', async () => {
  const f = await execute({ primary: pr(5, { state: 'closed' }), linked: [pr(6)],
    comments: { 6: [summary({ number: 6, any: true })] } });
  assert.equal(f.final.state, 'failure');
});
test('head changes while waiting never publish a green on the new SHA', async () => {
  const f = await execute({ getPR: () => pr(5, { head: { sha: OLD } }) });
  assert.deepEqual(f.writes, []);
});
test('read failure replaces previous success with an error after pending invalidation', async () => {
  const f = await execute({ readError: true });
  assert.deepEqual(f.writes.map(s => s.state), ['pending', 'error']);
  assert.equal(f.failures.length, 1);
});
test('an API failure or write denial cannot synthesize a green status', async () => {
  const f = await execute({ getError: true });
  assert.equal(f.final.state, 'error');
  await assert.rejects(execute({ writeError: true }));
});
test('invalid target outputs are rejected before status publication', async () => {
  for (const numberText of ['05', '5e0', '0x5', '5.0', '-1', '', '5; echo pwn']) {
    await assert.rejects(execute({ numberText }));
  }
  await assert.rejects(execute({ expectedSha: 'not-a-sha' }));
});

test('trusted bot comment resolves only the live PR head', async () => {
  const f = fixture(); await resolveTarget(f.github, f.context, f.core);
  assert.deepEqual(f.outputs, { pr_number: '5', head_sha: SHA, deleted_id: '' });
});
test('human copies, human edits, and ordinary issues cannot request positive publication', async () => {
  for (const payload of [
    { issue: { number: 5, pull_request: {} }, comment: summary({ user: { id: 1, login: 'human' } }), sender: BOT },
    { issue: { number: 5, pull_request: {} }, comment: summary(), sender: { id: 1, login: 'human' } },
    { issue: { number: 5 }, comment: summary(), sender: BOT },
  ]) {
    const f = fixture({ payload }); await resolveTarget(f.github, f.context, f.core);
    assert.deepEqual(f.outputs, {});
  }
});
test('deleting a native bot summary is a safe invalidation, not approval', async () => {
  const payload = { action: 'deleted', issue: { number: 5, pull_request: {} },
    comment: summary({ id: 20 }), sender: { id: 1, login: 'human' } };
  const f = fixture({ payload }); await resolveTarget(f.github, f.context, f.core);
  assert.equal(f.outputs.deleted_id, '20');
});
test('workflow_run is verified via GitHub and its conclusion is never scan evidence', async () => {
  const payload = { workflow_run: { id: 100, conclusion: 'success', display_title: '999' } };
  const f = fixture({ eventName: 'workflow_run', payload });
  await resolveTarget(f.github, f.context, f.core);
  assert.equal(f.outputs.pr_number, '5');
  assert.equal(f.calls[0].name, 'getWorkflowRun');
});
test('manual refresh is read-only upstream and accepts only canonical PR numbers', async () => {
  const base = { repository: { full_name: FULL }, status: 'completed', event: 'workflow_dispatch',
    name: 'Codex Security status tests', path: '.github/workflows/codex-security-status-tests.yml',
    display_title: '5', pull_requests: [] };
  const payload = { workflow_run: { id: 100 } };
  const good = fixture({ eventName: 'workflow_run', payload, run: base });
  await resolveTarget(good.github, good.context, good.core);
  assert.equal(good.outputs.pr_number, '5');
  for (const display_title of ['05', '5e0', '0x5', '5.0', '5; echo pwn']) {
    const f = fixture({ eventName: 'workflow_run', payload, run: { ...base, display_title } });
    await assert.rejects(resolveTarget(f.github, f.context, f.core));
  }
});
test('wrong workflow origin, repository, path, event or PR binding is rejected', async () => {
  const base = { repository: { full_name: FULL }, status: 'completed', event: 'pull_request',
    name: 'Codex Security status tests', path: '.github/workflows/codex-security-status-tests.yml',
    display_title: '5', pull_requests: [{ number: 5 }] };
  for (const change of [{ repository: { full_name: 'other/repo' } }, { status: 'in_progress' },
    { name: 'evil' }, { path: '.github/workflows/evil.yml' }, { event: 'push' },
    { pull_requests: [{ number: 6 }] }]) {
    const f = fixture({ eventName: 'workflow_run', payload: { workflow_run: { id: 100 } }, run: { ...base, ...change } });
    await assert.rejects(resolveTarget(f.github, f.context, f.core));
  }
});
test('PR-revision and selectable-ref events cannot invoke the privileged resolver', async () => {
  for (const eventName of ['pull_request', 'pull_request_review', 'workflow_dispatch', 'workflow_call']) {
    const f = fixture({ eventName });
    await assert.rejects(resolveTarget(f.github, f.context, f.core), /Untrusted writer trigger/);
    assert.deepEqual(f.writes, []);
  }
});
test('closed or incorrectly bound targets cannot receive a writer output', async () => {
  const closed = fixture({ primary: pr(5, { state: 'closed' }) });
  await resolveTarget(closed.github, closed.context, closed.core);
  assert.deepEqual(closed.outputs, {});
  const wrong = fixture({ primary: pr(5, { base: { repo: { full_name: 'other/repo' } } }) });
  await assert.rejects(resolveTarget(wrong.github, wrong.context, wrong.core));
});
test('regression: writer has ONLY default-branch event types, no checkout or untrusted helpers', () => {
  const triggers = writer.split('\npermissions:\n')[0];
  assert.doesNotMatch(triggers, /^  (pull_request|pull_request_review|pull_request_review_comment|workflow_dispatch|workflow_call|repository_dispatch):/m);
  assert.match(triggers, /^  issue_comment:/m);
  assert.match(triggers, /^  workflow_run:/m);
  assert.doesNotMatch(writer, /actions\/checkout|download-artifact|upload-artifact|require\(|import\(|eval\(/);
  assert.doesNotMatch(writer, /^concurrency:/m, 'Unrelated events must not cancel publication.');
  assert.match(writer, /group: codex-security-status-.*needs.resolve.outputs.head_sha/);
  assert.match(writer, /cancel-in-progress: false/);
});
test('regression: all PR-revision jobs are read-only; dispatch never carries a write token', () => {
  assert.match(reader, /^  pull_request:/m);
  assert.match(reader, /^  workflow_dispatch:/m);
  assert.doesNotMatch(reader, /^\s+[\w-]+: write\s*$/m);
  assert.doesNotMatch(reader, /secrets\.|persist-credentials: true|cache:|upload-artifact/);
  const resolveJob = writer.split('  resolve:\n')[1].split('  publish:\n')[0];
  assert.doesNotMatch(resolveJob, /^\s+[\w-]+: write\s*$/m);
});
test('all actions are SHA-pinned, and no alternate privileged PR trigger exists', () => {
  for (const source of [reader, writer]) {
    assert.doesNotMatch(source, /pull_request_target:|secrets\./);
    for (const line of source.split('\n').filter(l => /^\s*-?\s*uses:/.test(l))) {
      assert.match(line, /@[a-f0-9]{40}(?:\s|$)/);
    }
  }
});
