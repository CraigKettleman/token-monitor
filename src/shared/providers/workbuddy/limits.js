'use strict';

const { hashKey } = require('../../hashKey');
const { normalizeLimitProvider } = require('../../limits/core');
const { cleanSecret, numberOrNull } = require('../../limits/providerHelpers');
const { runWithProbeDeadline } = require('../../probeDeadline');

const WORKBUDDY_FETCH_TIMEOUT_MS = 12_000;
const WORKBUDDY_DEFAULT_ENDPOINT = 'https://copilot.tencent.com';
// WorkBuddy ships in two regions, and each signs its tokens in its own realm:
// a credential issued for one is rejected by the other's billing host. Both
// answer with the same document, so the region picks the host and nothing else.
const WORKBUDDY_INTERNATIONAL_ENDPOINT = 'https://www.codebuddy.ai';
const WORKBUDDY_PERSONAL_PATH = '/v2/billing/meter/get-user-resource';
const WORKBUDDY_ENTERPRISE_PATH = '/v2/billing/meter/get-enterprise-user-usage';
const WORKBUDDY_PRODUCT_CODE = 'p_tcaca';
const WORKBUDDY_PERSONAL_RANGE_MS = 101 * 365 * 24 * 60 * 60 * 1000;
// The Electron reader reports why the app-owned session is unusable. Only the
// encrypted case changes the limits outcome — signing in again cannot fix a
// credential the app sealed with a key Token Monitor does not hold — so it is
// the one reason both layers have to agree on.
const WORKBUDDY_SESSION_REASON_ENCRYPTED = 'encrypted';
const WORKBUDDY_SESSION_ENCRYPTED_ACTION = 'appSessionEncrypted';

// WorkBuddy is the only provider reading a credential this way: Trae needs the
// same precedence but its own stricter cleaner, so this stays local rather than
// becoming a shared helper with one caller.
function firstSetting(options, env, settingName, envNames) {
  const explicit = cleanSecret(options?.[settingName]);
  if (explicit) return explicit;
  for (const name of envNames) {
    const value = cleanSecret(env?.[name]);
    if (value) return value;
  }
  return '';
}

function workbuddyAccessToken(env = process.env, options = {}) {
  return firstSetting(options, env, 'workbuddyAccessToken', [
    'TOKEN_MONITOR_WORKBUDDY_ACCESS_TOKEN',
    'WORKBUDDY_ACCESS_TOKEN'
  ]).replace(/^authorization\s*:\s*/i, '').replace(/^bearer\s+/i, '').trim();
}

function workbuddyUserId(env = process.env, options = {}) {
  return firstSetting(options, env, 'workbuddyUserId', [
    'TOKEN_MONITOR_WORKBUDDY_USER_ID',
    'WORKBUDDY_USER_ID'
  ]);
}

function workbuddyEnterpriseId(env = process.env, options = {}) {
  return firstSetting(options, env, 'workbuddyEnterpriseId', [
    'TOKEN_MONITOR_WORKBUDDY_ENTERPRISE_ID',
    'WORKBUDDY_ENTERPRISE_ID'
  ]);
}

function workbuddyDomain(env = process.env, options = {}) {
  return firstSetting(options, env, 'workbuddyDomain', [
    'TOKEN_MONITOR_WORKBUDDY_DOMAIN',
    'WORKBUDDY_DOMAIN'
  ]);
}

function workbuddyDepartmentInfo(env = process.env, options = {}) {
  return firstSetting(options, env, 'workbuddyDepartmentInfo', [
    'TOKEN_MONITOR_WORKBUDDY_DEPARTMENT_INFO',
    'WORKBUDDY_DEPARTMENT_INFO'
  ]);
}

function workbuddyLocale(env = process.env, options = {}) {
  const value = firstSetting(options, env, 'workbuddyLocale', [
    'TOKEN_MONITOR_WORKBUDDY_LOCALE',
    'WORKBUDDY_LOCALE'
  ]).toLowerCase();
  if (value.startsWith('en')) return 'en';
  if (value.startsWith('zh')) return 'zh';
  return '';
}

// WorkBuddy's numeric timestamp strings are milliseconds, unlike the Unix
// seconds convention used by a few other providers.
function toIso(value) {
  if (value === null || value === undefined || value === '') return null;
  const date = typeof value === 'number' || /^\d+$/.test(String(value).trim())
    ? new Date(Number(value))
    : new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function formatWorkbuddyDateTime(value) {
  const date = new Date(value);
  const pad = (part) => String(part).padStart(2, '0');
  return [
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`,
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  ].join(' ');
}

function pickValue(source, keys) {
  if (!source || typeof source !== 'object') return null;
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null && source[key] !== '') return source[key];
  }
  return null;
}

function accountIdentity(source) {
  return String(pickValue(source, [
    'AccountId', 'accountId', 'UserId', 'userId', 'Uid', 'uid', 'TenantId', 'tenantId'
  ]) || '').trim();
}

function pickArray(source, paths) {
  for (const path of paths) {
    let value = source;
    for (const key of path) value = value?.[key];
    if (Array.isArray(value)) return value;
  }
  return null;
}

function parsePersonalAccounts(body) {
  const accounts = pickArray(body, [
    ['data', 'Response', 'Data', 'Accounts'],
    ['data', 'data', 'Response', 'Data', 'Accounts'],
    ['Response', 'Data', 'Accounts'],
    ['data', 'response', 'data', 'accounts'],
    ['response', 'data', 'accounts']
  ]);
  if (!accounts) throw new Error('WorkBuddy personal billing response has no Accounts array');
  return accounts;
}

function parsePersonalUsage(body) {
  const resources = parsePersonalAccounts(body);
  let used = 0;
  let limit = 0;
  let remaining = 0;
  let validResources = 0;
  let candidateResources = 0;
  const accountId = resources.map(accountIdentity).find(Boolean) || '';

  for (const resource of resources) {
    if (!resource || typeof resource !== 'object') {
      candidateResources += 1;
      continue;
    }
    const status = numberOrNull(pickValue(resource, ['Status', 'status']));
    // The official client requests Status 3 packages for its wider UI, but
    // those historical rows are not part of the currently spendable balance.
    if (status !== null && status !== 0) continue;
    candidateResources += 1;
    const total = numberOrNull(pickValue(resource, ['CycleCapacitySizePrecise', 'cycleCapacitySizePrecise']));
    const left = numberOrNull(pickValue(resource, ['CycleCapacityRemainPrecise', 'cycleCapacityRemainPrecise']));
    if (total === null || left === null || total < 0 || left < 0) continue;
    const safeTotal = total;
    const safeRemaining = Math.min(safeTotal, left);
    const reportedUsed = numberOrNull(pickValue(resource, ['CycleCapacityUsedPrecise', 'cycleCapacityUsedPrecise']));
    const safeUsed = reportedUsed === null
      ? Math.max(0, safeTotal - safeRemaining)
      : Math.min(safeTotal, Math.max(0, reportedUsed));
    limit += safeTotal;
    remaining += safeRemaining;
    used += safeUsed;
    validResources += 1;
  }

  // Returning a partial aggregate is worse than returning no snapshot: the
  // omitted active package would make a plausible-looking balance incorrect.
  // Explicitly inactive rows were excluded before candidateResources increased.
  if (candidateResources > validResources) {
    throw new Error('WorkBuddy personal billing response contains unusable active resource packages');
  }

  if (validResources === 0) {
    return { used: 0, limit: 0, remaining: 0, resetsAt: null, resourceCount: 0, accountId, window: null };
  }

  const usedPercent = limit > 0 ? (used / limit) * 100 : null;
  return {
    used,
    limit,
    remaining,
    resetsAt: null,
    resourceCount: validResources,
    accountId,
    window: {
      kind: 'billing',
      label: 'Credits',
      metric: 'credits',
      currency: 'CREDITS',
      used,
      limit,
      remaining,
      usedPercent,
      // Each WorkBuddy resource package has its own expiry. There is no
      // single reset timestamp for this aggregate window.
      resetsAt: null,
      showMeter: usedPercent !== null
    }
  };
}

function unwrapEnterpriseUsage(body) {
  const candidates = [
    body?.data?.data,
    body?.data,
    body?.Data,
    body
  ];
  return candidates.find((value) => value && typeof value === 'object' && !Array.isArray(value)) || null;
}

function parseEnterpriseUsage(body) {
  const usage = unwrapEnterpriseUsage(body);
  const rawLimit = pickValue(usage, ['limitNum', 'limit_num']);
  const limit = numberOrNull(rawLimit);
  if (limit === null) throw new Error('WorkBuddy enterprise billing response has no limitNum');
  if (limit < 0 && limit !== -1) {
    throw new Error('WorkBuddy enterprise billing response has an invalid limitNum');
  }
  const rawUsed = numberOrNull(pickValue(usage, [
    'credit', 'used', 'usedNum', 'used_num'
  ]));
  if (rawUsed === null) throw new Error('WorkBuddy enterprise billing response has no usage value');
  if (rawUsed < 0) {
    throw new Error('WorkBuddy enterprise billing response has an invalid usage value');
  }
  const used = rawUsed;
  const resetsAt = toIso(pickValue(usage, ['cycleResetTime', 'cycle_reset_time']));
  const accountId = accountIdentity(usage);

  if (limit === -1) {
    return {
      used,
      limit: null,
      remaining: null,
      resetsAt,
      accountId,
      window: {
        kind: 'billing',
        label: 'Credits',
        metric: 'credits',
        currency: 'CREDITS',
        used,
        detail: 'unlimited',
        resetsAt,
        showMeter: false
      }
    };
  }

  const safeLimit = Math.max(0, limit);
  const remaining = Math.max(0, safeLimit - used);
  return {
    used,
    limit: safeLimit,
    remaining,
    resetsAt,
    accountId,
    window: {
      kind: 'billing',
      label: 'Credits',
      metric: 'credits',
      currency: 'CREDITS',
      used,
      limit: safeLimit,
      remaining,
      usedPercent: safeLimit > 0 ? (used / safeLimit) * 100 : null,
      resetsAt,
      showMeter: safeLimit > 0
    }
  };
}

function httpError(status) {
  const error = new Error(`WorkBuddy billing request returned HTTP ${status}`);
  error.status = status === 401 || status === 403
    ? 'unauthorized'
    : status === 429
      ? 'sourceRateLimited'
      : status >= 500 || status === 408
        ? 'unavailable'
        : 'error';
  return error;
}

function applicationError(code) {
  const error = new Error(`WorkBuddy billing response returned application code ${code}`);
  error.status = code === 401 || code === 403
    ? 'unauthorized'
    : code === 429
      ? 'sourceRateLimited'
      : 'error';
  return error;
}

async function fetchJson(url, init, deps = {}) {
  const deadlineMs = Number(deps.workbuddyFetchTimeoutMs || deps.fetchTimeoutMs || WORKBUDDY_FETCH_TIMEOUT_MS);
  return runWithProbeDeadline(
    async ({ signal }) => {
      const response = await (deps.fetch || fetch)(url, { ...init, signal });
      const status = Number(response?.status || 0);
      let body = null;
      if (typeof response?.json === 'function') {
        try { body = await response.json(); } catch (_) { body = null; }
      }
      if (response?.ok === false || status >= 400) throw httpError(status);
      if (body && typeof body === 'object' && Object.hasOwn(body, 'code')) {
        const code = numberOrNull(body.code);
        if (code !== 0 && code !== 200) throw applicationError(code ?? 'invalid');
      }
      return body;
    },
    { signal: deps.signal, deadlineMs }
  );
}

function requestHeaders(token, userId, enterpriseId, locale, domain, departmentInfo) {
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json'
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (userId) headers['X-User-Id'] = userId;
  if (enterpriseId) {
    headers['X-Enterprise-Id'] = enterpriseId;
    headers['X-Tenant-Id'] = enterpriseId;
  }
  if (domain) headers['X-Domain'] = domain;
  if (departmentInfo) headers['X-Department-Info'] = departmentInfo;
  if (locale) headers['Accept-Language'] = locale;
  return headers;
}

function workbuddyStatus(error) {
  if (['notConfigured', 'unauthorized', 'sourceRateLimited', 'unavailable', 'error'].includes(error?.status)) return error.status;
  if (error?.status === 'timeout' || error?.name === 'AbortError') return 'unavailable';
  return 'unavailable';
}

// The account's own domain is the region signal, because it is the one field
// both readers carry in the clear: the switch file writes `www.workbuddy.cn`
// or `www.workbuddy.ai`, and the app file writes `auth.domain` unsealed even
// when the credential beside it is not. The TLD decides, since the product
// spells the same region as both `workbuddy.cn` and `codebuddy.cn`.
function workbuddyEndpoint(domain) {
  return /\.ai$/i.test(cleanSecret(domain))
    ? WORKBUDDY_INTERNATIONAL_ENDPOINT
    : WORKBUDDY_DEFAULT_ENDPOINT;
}

function workbuddyAccountKey(token, userId, enterpriseId, identity = '') {
  if (enterpriseId && userId) return hashKey('workbuddy', `enterprise:${enterpriseId}:${userId}`);
  if (userId) return hashKey('workbuddy', `user:${userId}`);
  if (identity) return hashKey('workbuddy', `account:${identity}`);
  return hashKey('workbuddy', token ? `token:${token}` : 'local-app');
}

async function fetchWorkbuddyLimits(options = {}, deps = {}) {
  const env = deps.env || process.env;
  const now = (deps.now || Date.now)();
  const updatedAt = new Date(now).toISOString();
  // Only the token lane reads these here; the desktop lane reads them per
  // account inside fetchWorkbuddyAccount, so they must not be resolved twice.
  const token = workbuddyAccessToken(env, options);
  const sessionReason = cleanSecret(options.workbuddyLocalSessionReason);
  const localAppUnsupported = !token && options.workbuddyDesktopSessionSupported === false;
  // The app owns the credential and sealed it: the generic not-configured row
  // would tell the user to sign in again, which cannot change this outcome.
  const localAppSessionEncrypted = !token
    && options.workbuddyDesktopSessionEnabled === true
    && sessionReason === WORKBUDDY_SESSION_REASON_ENCRYPTED;
  // The desktop widget reads the session owned by the installed WorkBuddy
  // app. If an advanced/headless token is present, keep the explicit token
  // path deterministic rather than mixing its metadata with the app session.
  const useLocalApp = !localAppUnsupported
    && !token
    && options.workbuddyDesktopSessionEnabled === true
    && typeof deps.workbuddyFetch === 'function';
  const source = {
    provider: 'workbuddy',
    source: useLocalApp || localAppUnsupported ? 'local' : 'api',
    sourceDetail: useLocalApp || localAppUnsupported ? 'app' : 'unknown',
    updatedAt,
    windows: []
  };

  if (localAppUnsupported) return normalizeLimitProvider({ ...source, status: 'unavailable' });
  // A sealed credential names its own outcome before any transport is built: no
  // request could succeed and the user has to be told why. This is also the
  // shape a host without an account enumerator keeps, so the encrypted row does
  // not change meaning depending on what the host wired up.
  if (localAppSessionEncrypted && !hasSessionEnumerator(deps)) {
    return normalizeLimitProvider({
      ...source,
      status: 'notConfigured',
      actionRequired: WORKBUDDY_SESSION_ENCRYPTED_ACTION
    });
  }
  // The desktop lane covers every signed-in account, so each one becomes its own
  // row. The token lane stays single: an explicit token names exactly one account.
  if (useLocalApp) {
    const accounts = workbuddyLocalAccounts(deps);
    // Nothing signed in: the sealed credential is the reason that changed, so it
    // is the one to report.
    if (accounts.length === 0) {
      return normalizeLimitProvider({
        ...source,
        status: 'notConfigured',
        ...(localAppSessionEncrypted ? { actionRequired: WORKBUDDY_SESSION_ENCRYPTED_ACTION } : {})
      });
    }
    // A single-row refresh names the account it wants; without this every
    // per-account refresh would re-query all of them.
    const scope = options.limitRefreshScope?.provider === 'workbuddy' ? options.limitRefreshScope : null;
    const selected = scope ? accounts.filter((account) => matchesLocalScope(account, scope)) : accounts;
    if (selected.length === 0) return normalizeLimitProvider({ ...source, status: 'notConfigured' });
    return Promise.all(selected.map((account) => fetchWorkbuddyAccount(account, source, options, deps, true)));
  }
  if (localAppSessionEncrypted) {
    return normalizeLimitProvider({
      ...source,
      status: 'notConfigured',
      actionRequired: WORKBUDDY_SESSION_ENCRYPTED_ACTION
    });
  }
  if (!token) return normalizeLimitProvider({ ...source, status: 'notConfigured' });
  return fetchWorkbuddyAccount(null, source, options, deps, false);
}

// The sessions the desktop transport can authenticate as. Absent an enumerator
// (a headless caller, or a host that never wired one) the row falls back to a
// single merged request, so the provider never disappears over a missing
// optional dep. An empty array is a real answer — nothing is signed in — and is
// kept distinct from that fallback.
// Whether the host can enumerate accounts at all. A host that cannot is running
// the pre-existing single-row lane, and its session reason still decides the row
// on its own.
function hasSessionEnumerator(deps = {}) {
  return typeof deps.workbuddySessions === 'function';
}

function workbuddyLocalAccounts(deps = {}) {
  if (!hasSessionEnumerator(deps)) return [null];
  try {
    const sessions = deps.workbuddySessions();
    return Array.isArray(sessions) ? sessions : [null];
  } catch (_) {
    return [null];
  }
}

// A refresh scope matches an account by name or by key. The name is what the
// row shows, and the key is what identifies it across platforms; either is
// enough to name one account, and one that matches neither is not refreshed
// rather than refreshed as somebody else.
function matchesLocalScope(account, scope) {
  if (!account) return true;
  const wantedName = cleanSecret(scope.accountName || scope.accountLabel);
  const wantedKey = cleanSecret(scope.accountKey);
  if (!wantedName && !wantedKey) return true;
  return Boolean((wantedName && account.accountName === wantedName)
    || (wantedKey && workbuddyAccountKey('', account.userId, account.enterpriseId, '') === wantedKey));
}

async function fetchWorkbuddyAccount(account, source, options = {}, deps = {}, desktopLane = false) {
  const env = deps.env || process.env;
  const now = (deps.now || Date.now)();
  const token = desktopLane ? '' : workbuddyAccessToken(env, options);
  const userId = account ? account.userId : workbuddyUserId(env, options);
  const enterpriseId = account ? account.enterpriseId : workbuddyEnterpriseId(env, options);
  const domain = account ? account.domain : workbuddyDomain(env, options);
  const departmentInfo = account ? account.departmentInfo : workbuddyDepartmentInfo(env, options);
  const accountType = account ? account.accountType : cleanSecret(options.workbuddyAccountType);

  const endpoint = workbuddyEndpoint(domain);
  // The desktop transport injects its own credentials per request, so the
  // headers it is handed must not repeat the token lane's copy.
  const headers = desktopLane
    ? requestHeaders('', '', '', workbuddyLocale(env, options), '', '')
    : requestHeaders(token, userId, enterpriseId, workbuddyLocale(env, options), domain, departmentInfo);
  // Naming the account is what selects it at the transport, so a fan-out cannot
  // read one account's balance under another account's label.
  const expectedSession = account
    ? {
        authenticated: true,
        userId: account.userId,
        enterpriseId: account.enterpriseId || '',
        departmentInfo: account.departmentInfo || '',
        domain: account.domain || '',
        accountType: account.accountType || ''
      }
    : desktopLane
      ? { authenticated: true, userId, enterpriseId, departmentInfo, domain, accountType }
      : null;
  const requestDeps = desktopLane
    ? {
        ...deps,
        fetch: (url, init) => deps.workbuddyFetch(url, init, expectedSession)
      }
    : deps;
  const accountKey = workbuddyAccountKey(token, userId, enterpriseId, '');
  try {
    const isEnterprise = Boolean(enterpriseId);
    const body = isEnterprise
      ? await fetchJson(`${endpoint}${WORKBUDDY_ENTERPRISE_PATH}`, {
        method: 'POST',
        redirect: 'error',
        headers,
        body: '{}'
      }, requestDeps)
      : await fetchJson(`${endpoint}${WORKBUDDY_PERSONAL_PATH}`, {
        method: 'POST',
        redirect: 'error',
        headers,
        body: JSON.stringify({
          PageNumber: 1,
          PageSize: 100,
          ProductCode: WORKBUDDY_PRODUCT_CODE,
          // Match the server-side package selection used by WorkBuddy's
          // desktop client. parsePersonalUsage still excludes Status 3 rows
          // from the current spendable aggregate.
          Status: [0, 3],
          PackageEndTimeRangeBegin: formatWorkbuddyDateTime(now),
          PackageEndTimeRangeEnd: formatWorkbuddyDateTime(now + WORKBUDDY_PERSONAL_RANGE_MS)
        })
      }, requestDeps);
    const usage = isEnterprise ? parseEnterpriseUsage(body) : parsePersonalUsage(body);
    const resolvedAccountKey = workbuddyAccountKey(token, userId, enterpriseId, usage.accountId);
    const balance = usage.window
      ? { amount: usage.remaining, currency: 'CREDITS' }
      : null;
    return normalizeLimitProvider({
      ...source,
      accountKey: resolvedAccountKey,
      // A desktop account is titled by its own nickname, falling back to the
      // plan. Two personal accounts are otherwise indistinguishable on screen,
      // and the plan word is the same for both.
      accountName: account?.accountName || '',
      accountLabel: isEnterprise ? 'Enterprise' : 'Personal',
      status: 'ok',
      windows: usage.window ? [usage.window] : [],
      ...(balance ? { balance } : {})
    });
  } catch (error) {
    return normalizeLimitProvider({
      ...source,
      accountKey,
      accountName: account?.accountName || '',
      status: workbuddyStatus(error)
    });
  }
}

module.exports = {
  WORKBUDDY_DEFAULT_ENDPOINT,
  WORKBUDDY_ENTERPRISE_PATH,
  WORKBUDDY_INTERNATIONAL_ENDPOINT,
  WORKBUDDY_FETCH_TIMEOUT_MS,
  WORKBUDDY_PERSONAL_PATH,
  WORKBUDDY_PRODUCT_CODE,
  WORKBUDDY_SESSION_ENCRYPTED_ACTION,
  WORKBUDDY_SESSION_REASON_ENCRYPTED,
  fetchWorkbuddyLimits,
  matchesLocalScope,
  parseEnterpriseUsage,
  parsePersonalAccounts,
  parsePersonalUsage,
  workbuddyAccessToken,
  workbuddyAccountKey,
  workbuddyEndpoint,
  workbuddyLocalAccounts,
  workbuddyDepartmentInfo,
  workbuddyDomain,
  workbuddyEnterpriseId,
  workbuddyLocale,
  workbuddyUserId
};
