'use strict';

// WorkBuddy's own auth file is the authority, and these tests pin down what
// happens when it stops being readable: the app sealing its credential fields is
// the state that motivated the fallback, and it must not be reported as a
// signed-out app. The fallback source is workbuddy-switch's accounts.json — a
// file the user's own tooling writes and Token Monitor only reads, never
// decrypts or rewrites.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  WORKBUDDY_AUTH_FILE_NAME,
  WORKBUDDY_SESSION_READ_REASONS,
  WORKBUDDY_SWITCH_ACCOUNTS_FILE,
  createWorkbuddyLocalAuth,
  readSwitchSessions,
  sessionFromSwitchAccount
} = require('../../src/electron/providers/workbuddy/localAuth');

const BILLING_URL = 'https://copilot.tencent.com/v2/billing/meter/get-user-resource';

function sessionDocument(overrides = {}) {
  const account = {
    uid: 'app-user',
    accountType: 'personal',
    type: 'personal',
    ...overrides.account
  };
  return {
    account,
    accounts: [account],
    allAccounts: [account],
    auth: {
      accessToken: 'app-access-token',
      domain: 'copilot.tencent.com',
      expiresAt: Date.now() + 60 * 60 * 1000,
      ...overrides.auth
    }
  };
}

function sealedSessionDocument() {
  const document = sessionDocument();
  document.auth.accessToken = { $wbEncrypted: 1, envelope: 'sealed' };
  return document;
}

function switchAccount(overrides = {}) {
  return {
    uid: 'switch-user-a',
    nickname: 'Account A',
    access_token: 'switch-token-a',
    expiresAt: Date.now() + 60 * 60 * 1000,
    ...overrides
  };
}

// Both sources live under one temp home, so a test never reads the machine's
// real ~/.wb-switch. The auth file sits at the path the platform resolver
// computes, because the fallback is only reachable when the resolver ran.
function createFixture() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'token-monitor-workbuddy-switch-'));
  const authDirectory = path.join(
    home,
    'Library',
    'Application Support',
    'CodeBuddyExtension',
    'Data',
    'Public',
    'auth'
  );
  fs.mkdirSync(authDirectory, { recursive: true });
  const authPath = path.join(authDirectory, WORKBUDDY_AUTH_FILE_NAME);
  const switchPath = path.join(home, WORKBUDDY_SWITCH_ACCOUNTS_FILE);
  fs.mkdirSync(path.dirname(switchPath), { recursive: true });
  return { home, authDirectory, authPath, switchPath };
}

function writeSwitch(fixture, accounts) {
  fs.writeFileSync(fixture.switchPath, JSON.stringify(accounts), 'utf8');
}

function createAuth(fixture, options = {}) {
  return createWorkbuddyLocalAuth({
    platform: 'darwin',
    homeDir: fixture.home,
    ...options
  });
}

function billingResponse(accountId) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      data: { Response: { Data: { Accounts: [{ AccountId: accountId }], TotalCount: 1 } } }
    })
  };
}

test('WorkBuddy reads its own auth file before the switch fallback', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sessionDocument()), 'utf8');
    writeSwitch(fixture, [switchAccount(), switchAccount({ uid: 'switch-user-b' })]);
    const requested = [];
    const auth = createAuth(fixture, {
      fetch: async (url, init) => {
        requested.push(init.headers['X-User-Id']);
        return billingResponse(init.headers['X-User-Id']);
      }
    });

    assert.equal(auth.getSessionInfo().userId, 'app-user');
    assert.equal(auth.sessions().length, 1);
    await auth.request(BILLING_URL, { method: 'POST' });
    assert.deepEqual(requested, ['app-user']);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy falls back to the switch accounts only when the app file is sealed', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    writeSwitch(fixture, [
      switchAccount(),
      switchAccount({ uid: 'switch-user-b', nickname: 'Account B', access_token: 'switch-token-b' })
    ]);
    const requested = [];
    const auth = createAuth(fixture, {
      fetch: async (url, init) => {
        requested.push(init.headers['X-User-Id']);
        return billingResponse(init.headers['X-User-Id']);
      }
    });

    assert.equal(auth.sessions().length, 2);
    const response = await auth.request(BILLING_URL, { method: 'POST' });
    assert.deepEqual([...requested].sort(), ['switch-user-a', 'switch-user-b']);
    // Both accounts came back in one document, which is what lets the limits
    // layer sum them instead of reporting whichever one answered first.
    const body = await response.json();
    assert.equal(body.data.Response.Data.Accounts.length, 2);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy falls back when the app file is absent, and a sealed file is not read as signed out', () => {
  const fixture = createFixture();
  try {
    writeSwitch(fixture, [switchAccount()]);

    // No app file at all: the fallback answers.
    const absent = createAuth(fixture);
    assert.equal(absent.getSessionInfo().authenticated, true);
    assert.equal(absent.getSessionInfo().userId, 'switch-user-a');

    // A sealed credential is still not a sign-out: the fallback answers, and the
    // reason that describes the app file never reaches the caller.
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    const sealed = createAuth(fixture);
    assert.equal(sealed.getSessionInfo().authenticated, true);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy reports the app file reason when neither source has a session', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    const auth = createAuth(fixture);
    assert.equal(auth.getSessionInfo().authenticated, false);
    assert.equal(auth.getSessionInfo().reason, WORKBUDDY_SESSION_READ_REASONS.encrypted);
    await assert.rejects(
      () => auth.request(BILLING_URL, { method: 'POST' }),
      (error) => error?.status === 'notConfigured'
    );
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy skips expired switch accounts instead of reporting their balance', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    writeSwitch(fixture, [
      switchAccount(),
      switchAccount({
        uid: 'switch-user-expired',
        nickname: 'Expired',
        expiresAt: Date.now() - 60 * 1000
      })
    ]);
    const requested = [];
    const auth = createAuth(fixture, {
      fetch: async (url, init) => {
        requested.push(init.headers['X-User-Id']);
        return billingResponse(init.headers['X-User-Id']);
      }
    });

    assert.deepEqual(auth.sessions().map((session) => session.userId), ['switch-user-a']);
    await auth.request(BILLING_URL, { method: 'POST' });
    assert.deepEqual(requested, ['switch-user-a']);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy keeps one row per switch account and drops duplicates', async () => {
  const fixture = createFixture();
  try {
    writeSwitch(fixture, [
      switchAccount(),
      // The same uid twice would double-count that account's credits.
      switchAccount({ nickname: 'Duplicate' }),
      switchAccount({ uid: 'switch-user-b', nickname: '', access_token: 'switch-token-b' })
    ]);
    const auth = createAuth(fixture);
    const sessions = auth.sessions();
    assert.deepEqual(sessions.map((session) => session.userId), ['switch-user-a', 'switch-user-b']);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy names a switch account by its nickname, or by its uid', () => {
  const now = Date.now();
  assert.equal(sessionFromSwitchAccount(switchAccount(), now).accountName, 'Account A');
  assert.equal(
    sessionFromSwitchAccount(switchAccount({ nickname: '  ' }), now).accountName,
    'switch-user-a'
  );
  // A partial entry is skipped: repairing it would publish a wrong balance.
  assert.equal(sessionFromSwitchAccount({ uid: 'no-token' }, now), null);
  assert.equal(sessionFromSwitchAccount({ access_token: 'no-uid' }, now), null);
});

test('WorkBuddy reads nothing from the switch file when it is not a usable document', () => {
  const now = Date.now();
  const fixture = createFixture();
  try {
    assert.deepEqual(readSwitchSessions(fixture.home, fs, now), []);

    fs.writeFileSync(fixture.switchPath, '{ not json', 'utf8');
    assert.deepEqual(readSwitchSessions(fixture.home, fs, now), []);

    fs.writeFileSync(fixture.switchPath, JSON.stringify({ accounts: [] }), 'utf8');
    assert.deepEqual(readSwitchSessions(fixture.home, fs, now), []);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy never opens the switch file for an injected fixture directory', () => {
  const fixture = createFixture();
  try {
    // A test that supplies its own auth directory supplies the whole
    // environment; reaching back to the real home would make the result depend
    // on the machine it runs on.
    writeSwitch(fixture, [switchAccount()]);
    const auth = createWorkbuddyLocalAuth({
      platform: 'darwin',
      authDirectory: fixture.authDirectory,
      fetch: async () => billingResponse('x')
    });
    assert.equal(auth.getSessionInfo().authenticated, false);
    assert.deepEqual(auth.sessions(), []);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('WorkBuddy asks each account only for itself when one is named', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    writeSwitch(fixture, [
      switchAccount(),
      switchAccount({ uid: 'switch-user-b', nickname: 'Account B', access_token: 'switch-token-b' })
    ]);
    const requested = [];
    const auth = createAuth(fixture, {
      fetch: async (url, init) => {
        requested.push(init.headers['X-User-Id']);
        return billingResponse(init.headers['X-User-Id']);
      }
    });

    const expected = auth.sessions().find((session) => session.userId === 'switch-user-b');
    await auth.request(BILLING_URL, { method: 'POST' }, expected);
    assert.deepEqual(requested, ['switch-user-b']);
    await assert.rejects(
      () => auth.request(BILLING_URL, { method: 'POST' }, { authenticated: true, userId: 'not-signed-in' }),
      (error) => error?.status === 'unauthorized'
    );
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('a switch nickname survives the trip to the limits row', async () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sealedSessionDocument()), 'utf8');
    writeSwitch(fixture, [
      switchAccount({ nickname: 'Account A' }),
      switchAccount({ uid: 'switch-user-b', nickname: 'Account B', access_token: 'switch-token-b' })
    ]);
    const auth = createAuth(fixture, {
      fetch: async (url, init) => billingResponse(init.headers['X-User-Id'])
    });

    // accountName is the row title and the only thing telling two personal
    // accounts apart, so it has to survive sessionInfo() rather than being
    // dropped there and falling back to a generic "Account N" on screen.
    const sessions = auth.sessions();
    assert.deepEqual(sessions.map((session) => session.accountName), ['Account A', 'Account B']);
    assert.deepEqual(sessions.map((session) => session.userId), ['switch-user-a', 'switch-user-b']);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});

test('an app-file session carries no account name of its own', () => {
  const fixture = createFixture();
  try {
    fs.writeFileSync(fixture.authPath, JSON.stringify(sessionDocument()), 'utf8');
    const auth = createAuth(fixture);
    const [session] = auth.sessions();

    // The app file describes one account, which the plan word already titles, so
    // there is no nickname to carry and an empty one must not be invented.
    assert.equal(session.userId, 'app-user');
    assert.equal(Object.hasOwn(session, 'accountName'), false);
  } finally {
    fs.rmSync(fixture.home, { recursive: true, force: true });
  }
});
