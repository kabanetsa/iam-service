'use strict';

/**
 * Демо-клиент authorization server-а: проходит authorization_code + PKCE
 * целиком в браузере и показывает результат каждого шага.
 *
 * Страница рассчитана на локальную отладку против dev-стека, где Nginx отдаёт
 * и сам сервис, и эту статику с одного origin — поэтому CORS не нужен. В реальном
 * SPA на другом домене потребуется CORS на /oauth/token и /oauth/userinfo.
 */

const CONFIG = {
  // По умолчанию — тот же origin, что и у страницы (dev-стенд: http://localhost:8088).
  issuer: new URLSearchParams(window.location.search).get('issuer') || window.location.origin,
  clientId: new URLSearchParams(window.location.search).get('client_id') || 'erplite-demo-spa',
  redirectUri: window.location.origin + '/demo/callback',
  scope: 'openid profile email offline_access api.read',
  apiPath: '/api/ping',
};

const KEY = {
  verifier: 'iam_demo.verifier',
  state: 'iam_demo.state',
  tokens: 'iam_demo.tokens',
  previousRefresh: 'iam_demo.previous_refresh',
  previousAt: 'iam_demo.previous_at',
};

const el = (id) => document.getElementById(id);

// --- утилиты ---------------------------------------------------------------

function base64UrlEncode(bytes) {
  let binary = '';
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecodeToString(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
}

function randomUrlSafe(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('не JWT');
  return {
    header: JSON.parse(base64UrlDecodeToString(parts[0])),
    payload: JSON.parse(base64UrlDecodeToString(parts[1])),
  };
}

function humanTime(seconds) {
  const minutes = Math.round(seconds / 60);
  return `${seconds} с (≈ ${minutes} мин)`;
}

// --- журнал ----------------------------------------------------------------

function log(kind, message, detail) {
  const entry = document.createElement('div');
  entry.className = 'log-entry ' + kind;

  const meta = document.createElement('div');
  meta.className = 'meta';

  const time = document.createElement('span');
  time.textContent = new Date().toLocaleTimeString('ru-RU') + ' ';
  const status = document.createElement('span');
  status.className = 'status';
  status.textContent = kind.toUpperCase() + ' ';
  const text = document.createElement('span');
  text.textContent = message;

  meta.append(time, status, text);
  entry.append(meta);

  if (detail) {
    const pre = document.createElement('pre');
    pre.textContent = typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2);
    entry.append(pre);
  }

  const container = el('log');
  container.prepend(entry);
  while (container.childElementCount > 60) container.lastElementChild.remove();
}

function logTokens(label, tokens) {
  const detail = {};
  for (const [name, value] of Object.entries(tokens)) {
    detail[name] = name.endsWith('_token') ? summarizeToken(value) : value;
  }
  log('ok', label, detail);
}

function summarizeToken(token) {
  if (!token) return token;
  try {
    const { header, payload } = decodeJwt(token);
    return { header, payload, signature_bytes: token.split('.')[2].length };
  } catch (err) {
    return token.slice(0, 24) + '…';
  }
}

// --- состояние -------------------------------------------------------------

function saveTokens(tokens) {
  sessionStorage.setItem(KEY.tokens, JSON.stringify(tokens));
}

function loadTokens() {
  const raw = sessionStorage.getItem(KEY.tokens);
  return raw ? JSON.parse(raw) : null;
}

function clearState() {
  Object.values(KEY).forEach((key) => sessionStorage.removeItem(key));
}

// --- сетевые вызовы --------------------------------------------------------

async function postToken(body) {
  const response = await fetch(CONFIG.issuer + '/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });

  const raw = await response.text();
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    payload = { raw };
  }

  log(response.ok ? 'ok' : 'error',
      `POST /oauth/token (${body.grant_type}) → ${response.status}`, payload);

  if (!response.ok) {
    const error = new Error(payload.error_description || payload.error || `HTTP ${response.status}`);
    error.code = payload.error;
    throw error;
  }
  return payload;
}

async function authorizedFetch(path, options = {}) {
  const tokens = loadTokens();
  const headers = Object.assign({}, options.headers);
  if (tokens && tokens.access_token && !options.anonymous) {
    headers.Authorization = 'Bearer ' + tokens.access_token;
  }

  const response = await fetch(CONFIG.issuer + path, Object.assign({}, options, { headers }));
  const raw = await response.text();
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    payload = { raw };
  }

  const where = path === CONFIG.apiPath ? ' (через Nginx, после auth_request)' : '';
  log(response.ok ? 'ok' : 'error', `${options.method || 'GET'} ${path} → ${response.status}${where}`, payload);
  return { response, payload };
}

// --- шаги потока -----------------------------------------------------------

async function startLogin() {
  if (!window.crypto || !window.crypto.subtle) {
    log('error', 'crypto.subtle недоступен: откройте страницу через http://localhost:8088/demo/');
    return;
  }

  const verifier = randomUrlSafe(48); // 64 символа base64url
  const challenge = await pkceChallenge(verifier);
  const state = randomUrlSafe(16);

  sessionStorage.setItem(KEY.verifier, verifier);
  sessionStorage.setItem(KEY.state, state);

  const url = new URL('/oauth/authorize', CONFIG.issuer);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CONFIG.clientId);
  url.searchParams.set('redirect_uri', CONFIG.redirectUri);
  url.searchParams.set('scope', CONFIG.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  log('info', 'Шаг 1: переход на /oauth/authorize', {
    url: url.toString(),
    code_verifier: verifier,
    code_challenge: challenge,
    note: 'verifier остаётся в браузере и уйдёт только на /oauth/token',
  });

  window.location.assign(url.toString());
}

async function handleCallback(params) {
  const error = params.get('error');
  if (error) {
    log('error', 'Authorization server вернул ошибку: ' + error, {
      error,
      error_description: params.get('error_description'),
      state: params.get('state'),
    });
    return;
  }

  const code = params.get('code');
  const state = params.get('state');
  const expectedState = sessionStorage.getItem(KEY.state);
  const verifier = sessionStorage.getItem(KEY.verifier);

  log('info', 'Шаг 2: получен код авторизации', {
    code: code ? code.slice(0, 12) + '…' : null,
    state,
    state_matches: state === expectedState,
  });

  if (!code) {
    log('error', 'В redirect_uri нет параметра code');
    return;
  }
  if (state !== expectedState) {
    log('error', 'state не совпал с сохранённым — запрос мог быть подменён');
    return;
  }
  if (!verifier) {
    log('error', 'нет code_verifier: возможно, страница открыта в новой вкладке');
    return;
  }

  const tokens = await postToken({
    grant_type: 'authorization_code',
    code,
    redirect_uri: CONFIG.redirectUri,
    client_id: CONFIG.clientId,
    code_verifier: verifier,
  });

  // Одноразовые значения больше не нужны.
  sessionStorage.removeItem(KEY.verifier);
  sessionStorage.removeItem(KEY.state);

  saveTokens(tokens);
  logTokens('Шаг 3: токены получены', tokens);
  renderTokens(tokens);
  window.history.replaceState({}, '', '/demo/');
}

async function refresh() {
  const tokens = loadTokens();
  if (!tokens || !tokens.refresh_token) {
    log('error', 'Нет refresh-токена: он выдаётся только со scope offline_access');
    return;
  }

  const used = tokens.refresh_token;
  const fresh = await postToken({
    grant_type: 'refresh_token',
    refresh_token: used,
    client_id: CONFIG.clientId,
  });

  sessionStorage.setItem(KEY.previousRefresh, used);
  sessionStorage.setItem(KEY.previousAt, String(Date.now()));
  saveTokens(fresh);
  log('info', 'Предыдущий refresh-токен сохранён для проверки reuse-detection', {
    previous_refresh: used.slice(0, 12) + '…',
    rotated: fresh.refresh_token !== used,
  });
  renderTokens(fresh);
}

async function replayPrevious() {
  const previous = sessionStorage.getItem(KEY.previousRefresh);
  if (!previous) {
    log('error', 'Сначала нажмите «Обновить»: нужен уже использованный refresh-токен');
    return;
  }
  const ageMs = Date.now() - Number(sessionStorage.getItem(KEY.previousAt) || 0);
  log('info', `Отправляем использованный refresh-токен (прошло ${(ageMs / 1000).toFixed(1)} с)`, {
    hint: ageMs < 10000
      ? 'внутри 10-секундного окна ответ будет той же парой'
      : 'вне окна: ожидаем invalid_grant и отзыв всей цепочки',
  });

  try {
    const tokens = await postToken({
      grant_type: 'refresh_token',
      refresh_token: previous,
      client_id: CONFIG.clientId,
    });
    log('ok', 'Сервис вернул ту же пару (идемпотентный ретрай), сессия жива', {
      same_access_token: tokens.access_token === (loadTokens() || {}).access_token,
    });
    saveTokens(tokens);
    renderTokens(tokens);
  } catch (err) {
    log('error', 'Ожидаемо: ' + err.message + '. Все токены этой сессии отозваны', {
      next: 'нажмите «GET /api/ping через Nginx» — токен больше не пройдёт /verify',
    });
  }
}

async function fetchUserInfo() {
  const { payload } = await authorizedFetch('/oauth/userinfo');
  if (payload && payload.sub) {
    el('api-output').textContent = JSON.stringify(payload, null, 2);
    el('api-output').classList.remove('empty');
  }
}

async function fetchProtectedApi() {
  const { payload } = await authorizedFetch(CONFIG.apiPath);
  el('api-output').textContent = JSON.stringify(payload, null, 2);
  el('api-output').classList.remove('empty');

  if (payload && payload.headers) {
    log('info', 'Заголовки, которые добавил Nginx после /verify', {
      'x-user-id': payload.headers['x-user-id'],
      'x-client-id': payload.headers['x-client-id'],
      'x-session-id': payload.headers['x-session-id'],
      'x-scopes': payload.headers['x-scopes'],
      'x-user-roles': payload.headers['x-user-roles'],
      authorization: payload.headers.authorization || '(удалён прокси)',
    });
  }
}

async function logout() {
  const { response } = await authorizedFetch('/oauth/logout', { method: 'POST' });
  if (response.ok) {
    log('info', 'Сессия завершена: access-токен больше не проходит /verify. ' +
      'Refresh-токен остался в браузере, но обменять его не получится.');
  }
}

// --- отрисовка -------------------------------------------------------------

function configRow(term, value) {
  const dt = document.createElement('dt');
  dt.textContent = term;
  const dd = document.createElement('dd');
  dd.textContent = value;
  return [dt, dd];
}

function renderConfig() {
  const list = el('config');
  list.replaceChildren();
  const rows = [
    ['issuer', CONFIG.issuer],
    ['client_id', CONFIG.clientId],
    ['redirect_uri', CONFIG.redirectUri],
    ['scope', CONFIG.scope],
    ['PKCE', 'S256 (code_challenge_method)'],
  ];
  rows.forEach(([term, value]) => configRow(term, value).forEach((node) => list.append(node)));
}

function tokenCard(title, value, extraNote) {
  const card = document.createElement('div');
  card.className = 'token';

  const heading = document.createElement('h3');
  heading.textContent = title;
  card.append(heading);

  if (extraNote) {
    const note = document.createElement('div');
    note.className = 'muted';
    note.textContent = extraNote;
    card.append(note);
  }

  const body = document.createElement('div');
  body.className = 'value';
  body.textContent = value;
  card.append(body);

  const copy = document.createElement('button');
  copy.className = 'copy';
  copy.type = 'button';
  copy.textContent = 'копировать';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = 'скопировано';
      setTimeout(() => { copy.textContent = 'копировать'; }, 1500);
    } catch (err) {
      copy.textContent = 'не удалось';
    }
  });
  heading.append(copy);

  return card;
}

function claimsCard(title, token) {
  const card = document.createElement('div');
  card.className = 'token';

  const heading = document.createElement('h3');
  heading.textContent = title;
  card.append(heading);

  const body = document.createElement('pre');
  try {
    const { header, payload } = decodeJwt(token);
    body.textContent = JSON.stringify({ header, payload }, null, 2);
  } catch (err) {
    body.textContent = '(не удалось разобрать токен: ' + err.message + ')';
  }
  card.append(body);
  return card;
}

function renderTokens(tokens) {
  const container = el('tokens');
  container.replaceChildren();
  container.classList.remove('empty');

  if (!tokens || !tokens.access_token) {
    container.classList.add('empty');
    container.textContent = 'Токенов пока нет — нажмите «Войти через IAM».';
    updateButtons(null);
    return;
  }

  container.append(claimsCard('access_token · claims', tokens.access_token));
  container.append(tokenCard('access_token', tokens.access_token,
    'Отправляется в заголовке Authorization: Bearer …'));

  if (tokens.id_token) {
    container.append(claimsCard('id_token · claims (aud = client_id)', tokens.id_token));
  }
  if (tokens.refresh_token) {
    container.append(tokenCard('refresh_token', tokens.refresh_token,
      'Одноразовый: обмен возвращает новую пару'));
  }
  if (typeof tokens.expires_in === 'number') {
    container.append(tokenCard('expires_in', humanTime(tokens.expires_in)));
  }
  if (tokens.scope) {
    container.append(tokenCard('scope', tokens.scope));
  }

  updateButtons(tokens);
}

function updateButtons(tokens) {
  const hasTokens = Boolean(tokens && tokens.access_token);
  el('btn-refresh').disabled = !(tokens && tokens.refresh_token);
  el('btn-replay').disabled = !sessionStorage.getItem(KEY.previousRefresh);
  el('btn-userinfo').disabled = !hasTokens;
  el('btn-api').disabled = !hasTokens;
  el('btn-logout').disabled = !hasTokens;
}

// --- старт -----------------------------------------------------------------

function bind() {
  el('btn-login').addEventListener('click', startLogin);
  el('btn-refresh').addEventListener('click', () => refresh().catch((err) => log('error', err.message)));
  el('btn-replay').addEventListener('click', () => replayPrevious().catch((err) => log('error', err.message)));
  el('btn-userinfo').addEventListener('click', () => fetchUserInfo().catch((err) => log('error', err.message)));
  el('btn-api').addEventListener('click', () => fetchProtectedApi().catch((err) => log('error', err.message)));
  el('btn-logout').addEventListener('click', () => logout().catch((err) => log('error', err.message)));
  el('btn-reset').addEventListener('click', () => {
    clearState();
    el('tokens').classList.add('empty');
    el('tokens').textContent = 'Состояние сброшено.';
    el('api-output').textContent = 'Состояние сброшено.';
    el('api-output').classList.add('empty');
    updateButtons(null);
    log('info', 'sessionStorage очищен: verifier, state, токены');
  });
  el('btn-clear-log').addEventListener('click', () => { el('log').replaceChildren(); });
}

async function main() {
  renderConfig();
  bind();

  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    el('secure-context').classList.remove('hidden');
  }

  const params = new URLSearchParams(window.location.search);
  if (window.location.pathname.endsWith('/demo/callback')) {
    await handleCallback(params);
    log('info', 'Готово. Дальше можно обновлять токен, запрашивать userinfo и защищённый API');
    return;
  }

  log('info', 'Демо-клиент готов', { issuer: CONFIG.issuer, client_id: CONFIG.clientId });
  renderTokens(loadTokens());
}

main().catch((err) => log('error', 'Сбой демо-клиента: ' + err.message));
