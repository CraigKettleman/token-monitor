'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readRegularFileNoFollow } = require('../../../shared/credentialStore');
const {
  WORKBUDDY_ENTERPRISE_PATH,
  WORKBUDDY_PERSONAL_PATH,
  WORKBUDDY_SESSION_REASON_ENCRYPTED
} = require('../../../shared/providers/workbuddy/limits');

const WORKBUDDY_AUTH_FILE_NAME = 'workbuddy-desktop.info';
// The international client writes its own file beside the domestic one. Both
// live in the same directory and hold the same document, so the region is not
// what separates them — the client is.
const WORKBUDDY_INTERNATIONAL_AUTH_FILE_NAME = 'workbuddy-desktop-ai.info';
const WORKBUDDY_LOGOUT_MARKER_SUFFIX = '.logged-out';
const WORKBUDDY_AUTH_FILE_MAX_BYTES = 1024 * 1024;
const WORKBUDDY_SESSION_EXPIRY_SKEW_MS = 30 * 1000;
// workbuddy-switch keeps every signed-in WorkBuddy account here, already
// decrypted. Token Monitor never writes to it and never opens the app's own
// envelope; this is a read of a file the user's own tooling produced.
const WORKBUDDY_SWITCH_ACCOUNTS_FILE = path.join('.wb-switch', 'accounts.json');
const WORKBUDDY_SWITCH_ACCOUNTS_MAX_BYTES = 4 * 1024 * 1024;
// Newer WorkBuddy builds seal individual credential fields with the key their
// own runtime holds, so `auth.accessToken` is a `{$wbEncrypted: 1, envelope: …}`
// shell rather than a string. Token Monitor cannot open that envelope, and the
// distinction matters: an unreadable credential is not the same state as a
// signed-out app, because signing in again cannot change it.
const WORKBUDDY_ENCRYPTED_FIELD_MARKER = '$wbEncrypted';
const WORKBUDDY_SESSION_READ_REASONS = Object.freeze({
  // No canonical file, or the app left its logout marker.
  absent: 'absent',
  // The platform has no supported local app session at all.
  unsupported: 'unsupported',
  // The canonical file exists but is not a readable session document.
  malformed: 'malformed',
  // Readable document without a usable access token or account id.
  incomplete: 'incomplete',
  // The app sealed its credential fields; Token Monitor cannot decrypt them.
  encrypted: WORKBUDDY_SESSION_REASON_ENCRYPTED,
  // A usable session that is past its expiry.
  expired: 'expired'
});
const WORKBUDDY_API_HOSTS = new Set([
  'copilot.tencent.com',
  // The international client bills through its own host. Both are reachable and
  // each refuses the other region's credential, so the allowlist states the two
  // hosts the transport may ever carry a token to rather than trusting the
  // endpoint the caller built.
  'www.codebuddy.ai'
]);
const WORKBUDDY_API_PATHS = new Set([
  WORKBUDDY_PERSONAL_PATH,
  WORKBUDDY_ENTERPRISE_PATH
]);
const WORKBUDDY_PROTECTED_HEADERS = new Set([
  'authorization',
  'cookie',
  'x-refresh-token',
  'x-user-id',
  'x-enterprise-id',
  'x-tenant-id',
  'x-domain',
  'x-department-info',
  'x-no-authorization',
  'x-no-user-id',
  'x-no-enterprise-id',
  'x-no-department-info'
]);

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function numberOrNull(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isAllowedWorkbuddyApiUrl(value, method = 'GET') {
  try {
    const url = new URL(String(value || ''));
    return String(method || '').toUpperCase() === 'POST'
      && url.protocol === 'https:'
      && WORKBUDDY_API_HOSTS.has(url.hostname.toLowerCase())
      && WORKBUDDY_API_PATHS.has(url.pathname)
      && !url.username
      && !url.password
      && !url.port
      && !url.search
      && !url.hash;
  } catch (_) {
    return false;
  }
}

function sanitizeRequestInit(init = {}) {
  const headers = {};
  for (const [key, value] of Object.entries(init.headers || {})) {
    if (WORKBUDDY_PROTECTED_HEADERS.has(String(key || '').toLowerCase())) continue;
    headers[key] = String(value);
  }
  const body = typeof init.body === 'string' ? init.body : undefined;
  return {
    method: String(init.method || 'GET').toUpperCase(),
    headers,
    // Authentication is injected only after the exact billing URL has been
    // allowlisted. Never let the transport carry it to a redirect target.
    redirect: 'error',
    ...(body === undefined ? {} : { body }),
    ...(init.signal ? { signal: init.signal } : {})
  };
}

function isSupportedWorkbuddyLocalAppPlatform(platform = process.platform) {
  return platform === 'darwin' || platform === 'win32';
}

function authDirectoriesForPlatform(platform = process.platform, homeDir = os.homedir(), env = process.env) {
  if (platform === 'darwin') {
    return [path.join(homeDir, 'Library', 'Application Support', 'CodeBuddyExtension', 'Data', 'Public', 'auth')];
  }
  if (platform === 'win32') {
    const localAppData = cleanText(env?.LOCALAPPDATA) || path.join(homeDir, 'AppData', 'Local');
    const roamingAppData = cleanText(env?.APPDATA) || path.join(homeDir, 'AppData', 'Roaming');
    return [...new Set([localAppData, roamingAppData])]
      .map((root) => path.join(root, 'CodeBuddyExtension', 'Data', 'Public', 'auth'));
  }
  return [];
}

function authDirectoryForPlatform(platform = process.platform, homeDir = os.homedir(), env = process.env) {
  return authDirectoriesForPlatform(platform, homeDir, env)[0] || null;
}

function authPathCandidates(authDirectory) {
  if (!authDirectory) return [];
  // The domestic file is tried first because it is the one this reader has
  // always taken: a machine running both clients keeps reporting what it
  // reported before, and one running only the international client now finds a
  // session where it previously found none.
  return [
    path.join(authDirectory, WORKBUDDY_AUTH_FILE_NAME),
    path.join(authDirectory, WORKBUDDY_INTERNATIONAL_AUTH_FILE_NAME)
  ];
}

// Which reader supplied a session. The two sources answer different questions,
// so one appearing mid-request must not read as the other one disappearing.
const WORKBUDDY_SESSION_SOURCES = Object.freeze({
  switch: 'switch',
  app: 'app'
});

function authError(status, message) {
  const error = new Error(message);
  error.status = status;
  error.code = status === 'unauthorized'
    ? 'WORKBUDDY_LOCAL_AUTH_REQUIRED'
    : 'WORKBUDDY_LOCAL_APP_UNAVAILABLE';
  return error;
}

// Kept separate from the user-facing status label: this message is what the
// collector logs, and it must say whether signing in again could help.
function sessionUnavailableMessage(reason) {
  if (reason === WORKBUDDY_SESSION_READ_REASONS.encrypted) {
    return 'WorkBuddy app credential is encrypted and cannot be read by Token Monitor';
  }
  if (reason === WORKBUDDY_SESSION_READ_REASONS.expired) {
    return 'WorkBuddy app session has expired';
  }
  return 'WorkBuddy app sign-in is required';
}

function isEncryptedCredentialField(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.hasOwn(value, WORKBUDDY_ENCRYPTED_FIELD_MARKER);
}

// Separates "the app is not signed in" from "Token Monitor cannot read what the
// app wrote". Only the read reason reaches the limits path; callers that just
// need a session keep using normalizeStoredSession().
function inspectStoredSession(value, now = Date.now()) {
  if (!value || typeof value !== 'object') {
    return { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.malformed };
  }
  const auth = value.auth && typeof value.auth === 'object' ? value.auth : {};
  const account = value.account && typeof value.account === 'object' ? value.account : {};
  // Only the access token gates the read: it is the one field the billing
  // request consumes, so a sealed refresh token must not mark an otherwise
  // usable session as unreadable.
  if (isEncryptedCredentialField(auth.accessToken)) {
    return { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.encrypted };
  }
  const accessToken = cleanText(auth.accessToken);
  const userId = cleanText(account.uid);
  if (!accessToken || !userId) {
    return { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.incomplete };
  }

  const expiresAt = numberOrNull(auth.expiresAt);
  const enterpriseId = cleanText(account.enterpriseId);
  const departmentInfo = cleanText(account.departmentFullName);
  return {
    session: {
      accessToken,
      userId,
      enterpriseId,
      departmentInfo,
      domain: cleanText(auth.domain),
      accountType: cleanText(account.accountType || account.type) || 'personal',
      expiresAt,
      expired: expiresAt !== null && expiresAt <= now + WORKBUDDY_SESSION_EXPIRY_SKEW_MS
    },
    reason: ''
  };
}

function normalizeStoredSession(value, now = Date.now()) {
  return inspectStoredSession(value, now).session;
}

// One workbuddy-switch entry -> the session shape the rest of this module
// already speaks. A partial entry is skipped rather than repaired, because a
// repaired account would silently under-report its own balance.
function sessionFromSwitchAccount(entry, now) {
  if (!entry || typeof entry !== 'object') return null;
  const accessToken = cleanText(entry.access_token);
  const userId = cleanText(entry.uid);
  if (!accessToken || !userId) return null;
  const expiresAt = numberOrNull(entry.expiresAt);
  return {
    accessToken,
    userId,
    enterpriseId: cleanText(entry.enterpriseId),
    departmentInfo: '',
    domain: cleanText(entry.domain),
    accountType: 'personal',
    // The nickname, falling back to the uid, so an unnamed account still has a
    // stable title of its own on the limits row.
    accountName: cleanText(entry.nickname) || userId,
    expiresAt,
    expired: expiresAt !== null && expiresAt <= now + WORKBUDDY_SESSION_EXPIRY_SKEW_MS
  };
}

// The accounts workbuddy-switch holds, which is the primary source. Absent,
// unreadable or malformed all mean the same thing here — no accounts from this
// source — because the caller falls through to the app file and a second reason
// would only change the message.
function readSwitchSessions(homeDir, fsApi, now) {
  let parsed;
  try {
    const raw = readRegularFileNoFollow(path.join(homeDir, WORKBUDDY_SWITCH_ACCOUNTS_FILE), {
      fs: fsApi,
      description: 'workbuddy-switch accounts file',
      encoding: 'utf8',
      maxBytes: WORKBUDDY_SWITCH_ACCOUNTS_MAX_BYTES
    });
    parsed = JSON.parse(raw);
  } catch (_) {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const seen = new Set();
  const sessions = [];
  for (const entry of parsed) {
    const session = sessionFromSwitchAccount(entry, now);
    // A uid appears once: the same account listed twice would double its
    // credits in the merged response.
    if (!session || seen.has(session.userId)) continue;
    seen.add(session.userId);
    sessions.push(session);
  }
  return sessions;
}

function readSessionFile(filePath, fsApi = fs, now = Date.now()) {
  const absent = { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.absent };
  if (!filePath) return absent;
  if (fsApi.existsSync(`${filePath}${WORKBUDDY_LOGOUT_MARKER_SUFFIX}`)) return absent;
  try {
    const raw = readRegularFileNoFollow(filePath, {
      fs: fsApi,
      description: 'WorkBuddy app authentication file',
      encoding: 'utf8',
      maxBytes: WORKBUDDY_AUTH_FILE_MAX_BYTES
    });
    return inspectStoredSession(JSON.parse(raw), now);
  } catch (_) {
    // The reader rejects missing, oversized, symlinked and unreadable paths
    // with one error shape. Only a path that is genuinely gone counts as
    // absent; anything else left a canonical file the app owns behind.
    return fsApi.existsSync(filePath)
      ? { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.malformed }
      : absent;
  }
}

function sessionInfo(session, reason = '') {
  if (!session) {
    return {
      authenticated: false,
      userId: '',
      enterpriseId: '',
      departmentInfo: '',
      domain: '',
      accountType: '',
      ...(reason ? { reason } : {})
    };
  }
  return {
    authenticated: true,
    userId: session.userId,
    enterpriseId: session.enterpriseId,
    departmentInfo: session.departmentInfo,
    domain: session.domain,
    accountType: session.accountType,
    // The title the limits row shows. Only a switch account carries one; the
    // app file describes a single account, whose row the plan word already
    // titles. Kept out of the object entirely when empty so a caller spreading
    // this into a request never sends an empty name as an identity.
    ...(session.accountName ? { accountName: session.accountName } : {})
  };
}

function matchesExpectedSession(expected, session) {
  if (!expected || typeof expected !== 'object') return true;
  const actual = sessionInfo(session);
  if (expected.authenticated !== true || actual.authenticated !== true) return false;
  return ['userId', 'enterpriseId', 'departmentInfo', 'domain', 'accountType']
    .every((field) => cleanText(expected[field]) === cleanText(actual[field]));
}

function createWorkbuddyLocalAuth(deps = {}) {
  const fsApi = deps.fs || fs;
  const platform = deps.platform || process.platform;
  const homeDir = deps.homeDir || os.homedir();
  const env = deps.env || process.env;
  const supported = isSupportedWorkbuddyLocalAppPlatform(platform);
  const authDirectories = supported
    ? deps.authDirectory
      ? [deps.authDirectory]
      : authDirectoriesForPlatform(platform, homeDir, env)
    : [];
  // An injected authDirectory means the caller supplied the whole environment,
  // so the switch source is off: reading the real home directory from a test
  // that asked for one fixture would make the result depend on the machine.
  const switchHomeDir = supported && !deps.authDirectory ? homeDir : null;
  const fetcher = typeof deps.fetch === 'function'
    ? deps.fetch
    : typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null;
  const now = typeof deps.now === 'function' ? deps.now : Date.now;

  function locateSession() {
    const checkedAt = now();
    if (!supported) {
      return { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.unsupported };
    }
    for (const authDirectory of authDirectories) {
      for (const filePath of authPathCandidates(authDirectory)) {
        const hasCanonicalState = fsApi.existsSync(filePath)
          || fsApi.existsSync(`${filePath}${WORKBUDDY_LOGOUT_MARKER_SUFFIX}`);
        if (!hasCanonicalState) continue;
        // Once the preferred location has a canonical file or logout marker,
        // do not revive a stale session from a legacy fallback directory.
        return readSessionFile(filePath, fsApi, checkedAt);
      }
    }
    return { session: null, reason: WORKBUDDY_SESSION_READ_REASONS.absent };
  }

  // Every account the billing request should cover, in the order the sources are
  // trusted. workbuddy-switch comes first: it is the user's own tool for holding
  // several accounts, and the app file can only ever describe the one account
  // that is currently active. The app file is the fallback, so an install
  // without workbuddy-switch reads exactly what it read before this existed.
  function resolveSessions() {
    const checkedAt = now();
    const switched = switchedSessions(checkedAt);
    if (switched.length > 0) return {
      sessions: switched,
      source: WORKBUDDY_SESSION_SOURCES.switch,
      reason: ''
    };
    const { session, reason } = locateSession();
    if (session && !session.expired) return {
      sessions: [session],
      source: WORKBUDDY_SESSION_SOURCES.app,
      reason: ''
    };
    // Nothing usable anywhere: report why the app file failed, which is the
    // reason that tells the user what to do about it.
    return {
      sessions: [],
      source: '',
      reason: session && session.expired ? WORKBUDDY_SESSION_READ_REASONS.expired : reason
    };
  }

  // The accounts the switch file holds, expired ones removed. Read on its own so
  // a request can re-read the source that supplied its credential without
  // consulting the other one.
  function switchedSessions(checkedAt) {
    return switchHomeDir
      ? readSwitchSessions(switchHomeDir, fsApi, checkedAt).filter((entry) => !entry.expired)
      : [];
  }

  // Re-reads one source. The app file is the mutable one — the app rewrites it
  // whenever the user switches account — so an expectation about it has to hold
  // against what it says now. Re-resolving both sources would instead let the
  // other one appear mid-request and read as the account being removed, which
  // rejects an answer that was correctly fetched under the credential that was
  // in force when the request started.
  function resolveSource(source) {
    if (source === WORKBUDDY_SESSION_SOURCES.switch) return switchedSessions(now());
    if (source !== WORKBUDDY_SESSION_SOURCES.app) return [];
    const { session } = locateSession();
    return session && !session.expired ? [session] : [];
  }

  function getSessionInfo() {
    const { sessions, reason } = resolveSessions();
    if (sessions.length === 0) return sessionInfo(null, reason);
    return sessionInfo(sessions[0]);
  }

  function headersFor(session, requestInit) {
    const headers = {
      ...requestInit.headers,
      Accept: requestInit.headers.Accept || 'application/json',
      'Content-Type': requestInit.headers['Content-Type'] || 'application/json',
      Authorization: `Bearer ${session.accessToken}`,
      'X-User-Id': session.userId
    };
    if (session.enterpriseId) {
      headers['X-Enterprise-Id'] = session.enterpriseId;
      headers['X-Tenant-Id'] = session.enterpriseId;
    }
    if (session.domain) headers['X-Domain'] = session.domain;
    if (session.departmentInfo) headers['X-Department-Info'] = session.departmentInfo;
    return headers;
  }

  // The billing response nests its rows at data.Response.Data.Accounts. Merging
  // there is what makes the downstream parser see every account: each row
  // already carries its own AccountId, so they stay distinguishable inside the
  // combined total.
  function mergeAccountRows(bodies) {
    if (bodies.length === 1) return bodies[0];
    const [first] = bodies;
    const rows = [];
    for (const body of bodies) {
      const accounts = body?.data?.Response?.Data?.Accounts;
      if (Array.isArray(accounts)) rows.push(...accounts);
    }
    if (rows.length === 0) return first;
    const merged = JSON.parse(JSON.stringify(first));
    merged.data.Response.Data.Accounts = rows;
    merged.data.Response.Data.TotalCount = rows.length;
    return merged;
  }

  async function requestAccount(url, requestInit, session) {
    const response = await fetcher(url, { ...requestInit, headers: headersFor(session, requestInit) });
    // A response without json() is handed back as-is and merged around, which is
    // what a caller that only looks at status expects to receive.
    if (typeof response?.json !== 'function') return { response, body: null };
    // The body is read once here and handed on as a plain document, so the
    // caller's own json() call keeps working on the merged result. A response
    // whose body cannot be parsed is passed on as if it had none.
    let body = null;
    try {
      body = await response.json();
    } catch (_) {
      // body stays null
    }
    return { response, body };
  }

  function mergedResponse(response, body) {
    if (body === null) return response;
    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      json: async () => body
    };
  }

  async function request(url, init = {}, expectedSession = null) {
    const requestInit = sanitizeRequestInit(init);
    if (!isAllowedWorkbuddyApiUrl(url, requestInit.method)) {
      throw authError('unavailable', 'WorkBuddy billing endpoint is not allowed');
    }
    const { sessions, source, reason } = resolveSessions();
    if (sessions.length === 0) {
      // An expired session is not a missing one: the app is signed in and the
      // user has to sign in again, which is a different instruction to the user
      // and a different status to the renderer.
      if (reason === WORKBUDDY_SESSION_READ_REASONS.expired) {
        throw authError('unauthorized', 'WorkBuddy app session has expired');
      }
      throw authError('notConfigured', sessionUnavailableMessage(reason));
    }
    if (!fetcher) throw authError('unavailable', 'WorkBuddy billing transport is unavailable');

    // A caller that names one account gets exactly that account back, so the
    // limits layer can publish one row per account. Without a name the request
    // fans out and merges, which is what a single row wants.
    const wanted = cleanText(expectedSession?.userId);
    const selected = wanted
      ? sessions.filter((session) => session.userId === wanted)
      : sessions;
    if (selected.length === 0) {
      throw authError('unauthorized', 'WorkBuddy app session changed during the billing request');
    }

    const results = await Promise.all(selected.map(async (session) => {
      try {
        return await requestAccount(url, requestInit, session);
      } catch (error) {
        // One rejected account must not blank the whole row: the accounts that
        // did answer still describe a real balance.
        return { error };
      }
    }));
    const fulfilled = results.filter((result) => !result.error);
    if (fulfilled.length === 0) throw results[0].error;

    if (expectedSession) {
      // Re-read from the source that answered rather than checked against the
      // account the request ran as: the file can be rewritten mid-request, and
      // the caller's expectation has to hold against what is on disk now, not
      // against what it matched at the start of the call.
      const latest = resolveSource(source);
      if (!latest.some((session) => matchesExpectedSession(expectedSession, session))) {
        throw authError('unauthorized', 'WorkBuddy app session changed during the billing request');
      }
    }
    const first = fulfilled[0];
    return mergedResponse(first.response, mergeAccountRows(fulfilled.map((result) => result.body)));
  }

  return {
    getSessionInfo,
    sessions: () => resolveSessions().sessions.map((session) => sessionInfo(session)),
    request,
    dispose() {}
  };
}

module.exports = {
  WORKBUDDY_AUTH_FILE_NAME,
  WORKBUDDY_INTERNATIONAL_AUTH_FILE_NAME,
  WORKBUDDY_AUTH_FILE_MAX_BYTES,
  WORKBUDDY_ENCRYPTED_FIELD_MARKER,
  WORKBUDDY_LOGOUT_MARKER_SUFFIX,
  WORKBUDDY_SESSION_EXPIRY_SKEW_MS,
  WORKBUDDY_SESSION_READ_REASONS,
  WORKBUDDY_SWITCH_ACCOUNTS_FILE,
  WORKBUDDY_SWITCH_ACCOUNTS_MAX_BYTES,
  authDirectoriesForPlatform,
  authDirectoryForPlatform,
  createWorkbuddyLocalAuth,
  inspectStoredSession,
  isAllowedWorkbuddyApiUrl,
  isSupportedWorkbuddyLocalAppPlatform,
  normalizeStoredSession,
  readSwitchSessions,
  sanitizeRequestInit,
  sessionFromSwitchAccount
};
