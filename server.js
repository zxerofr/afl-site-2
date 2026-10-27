'use strict';
/*
 * AFL — Official Items & Ticket Requests
 * Zero-dependency Node.js server (Node >= 22.13): http + node:sqlite + fetch.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cfg = require('./lib/config');
const { db, now } = require('./lib/db');
const auth = require('./lib/auth');
const {
  HttpError, Router, SECURITY_HEADERS, clientIp, readBody, send, sendJson, redirect, rateLimit, serveFile, safeJoin,
} = require('./lib/http');
const SEED = require('./lib/seed');

const PUBLIC_DIR = path.join(__dirname, 'public');
const STAFF_UI_DIR = path.join(__dirname, 'staff-ui');
fs.mkdirSync(cfg.uploadDir, { recursive: true });

/* ------------------------------------------------------------------ helpers */
const AVAILABILITY = ['available', 'limited', 'unavailable', 'tbc'];
const STATUSES = ['pending', 'accepted', 'in_progress', 'completed', 'denied', 'cancelled'];
const OPEN_STATUSES = ['pending', 'accepted', 'in_progress'];
const NEXT = {
  pending: ['accepted', 'denied', 'cancelled'],
  accepted: ['in_progress', 'completed', 'denied', 'cancelled'],
  in_progress: ['completed', 'denied', 'cancelled'],
  denied: ['pending'],
  completed: [],
  cancelled: [],
};
const MAX_OPEN_TICKETS = 5;
const ref = (id) => 'AFL-' + String(id).padStart(4, '0');

function text(v, { name = 'Value', min = 0, max = 500, required = false } = {}) {
  if (v === undefined || v === null || v === '') {
    if (required || min > 0) throw new HttpError(400, `${name} is required.`);
    return '';
  }
  if (typeof v !== 'string') throw new HttpError(400, `${name} must be text.`);
  const s = v.replace(/\r\n/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
  if (s.length < min) throw new HttpError(400, `${name} must be at least ${min} characters.`);
  if (s.length > max) throw new HttpError(400, `${name} must be at most ${max} characters.`);
  return s;
}
function intIn(v, { name, min, max }) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${name} must be a whole number between ${min} and ${max}.`);
  return n;
}
const likeEsc = (s) => '%' + s.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
async function jsonBody(ctx, limit = 64 * 1024) {
  const ct = String(ctx.req.headers['content-type'] || '');
  if (!ct.startsWith('application/json')) throw new HttpError(415, 'Expected application/json.');
  const buf = await readBody(ctx.req, limit);
  try { const o = JSON.parse(buf.toString('utf8') || '{}'); if (o && typeof o === 'object' && !Array.isArray(o)) return o; } catch { /* fallthrough */ }
  throw new HttpError(400, 'Invalid JSON body.');
}
function audit(ctx, action, targetType, targetId, detail) {
  db.run('INSERT INTO audit_log (actor_id,actor_name,action,target_type,target_id,detail,ip,created_at) VALUES (?,?,?,?,?,?,?,?)',
    ctx.user?.id || null, ctx.user ? auth.displayName(ctx.user) : null, action, targetType || null,
    targetId === undefined || targetId === null ? null : String(targetId), detail ? JSON.stringify(detail).slice(0, 2000) : null, ctx.ip, now());
}
function notify(userId, { type, title, body = '', ticketId = null }) {
  db.run('INSERT INTO notifications (user_id,type,title,body,ticket_id,read,created_at) VALUES (?,?,?,?,?,0,?)', userId, type, title, body.slice(0, 600), ticketId, now());
}

/* ----------------------------------------------------------------- formatters */
const fmtItem = (r) => ({
  id: r.id, name: r.name, description: r.description, category: r.category, collection: r.collection,
  availability: r.availability, image: r.image, sortOrder: r.sort_order, placeholder: !!r.placeholder, archived: !!r.archived,
});
const fmtUser = (r) => ({
  id: r.user_id, username: r.username, name: r.global_name || r.username,
  avatarUrl: auth.avatarUrl({ id: r.user_id, avatar: r.avatar }),
});
const TICKET_SQL = `SELECT t.*, i.name AS item_name, i.image AS item_image, i.category AS item_category,
  u.username, u.global_name, u.avatar
  FROM tickets t JOIN items i ON i.id = t.item_id JOIN users u ON u.id = t.user_id`;
const fmtTicket = (r) => ({
  id: r.id, ref: ref(r.id), status: r.status, quantity: r.quantity, details: r.details, contactNote: r.contact_note,
  denialReason: r.denial_reason, staffNote: r.staff_note, handledBy: r.handled_by_name,
  createdAt: r.created_at, updatedAt: r.updated_at,
  item: { id: r.item_id, name: r.item_name, image: r.item_image, category: r.item_category },
  user: fmtUser(r),
});
const fmtEvent = (e) => ({ id: e.id, kind: e.kind, from: e.from_status, to: e.to_status, message: e.message, actor: e.actor_name, createdAt: e.created_at });
const ticketEvents = (id) => db.all('SELECT * FROM ticket_events WHERE ticket_id = ? ORDER BY id', id).map(fmtEvent);

/* ----------------------------------------------------------------- middleware */
const requireUser = (ctx) => { if (!ctx.user) throw new HttpError(401, 'Please sign in with Discord first.'); };
const requireStaff = (ctx) => { requireUser(ctx); if (ctx.role !== 'staff' && ctx.role !== 'owner') throw new HttpError(403, 'Staff access required.'); };
const requireOwner = (ctx) => { requireUser(ctx); if (ctx.role !== 'owner') throw new HttpError(403, 'Owner access required.'); };
const writeLimit = rateLimit('write', 60, 60_000, (c) => c.user?.id || c.ip);
const authLimit = rateLimit('auth', 30, 10 * 60_000);

/* --------------------------------------------------------------------- routes */
const router = new Router();

/* ---- Discord OAuth2 ---- */
router.get('/auth/discord/login', authLimit, (ctx) => {
  if (!cfg.discord.clientId || !cfg.discord.clientSecret) return redirect(ctx.res, '/?auth=not_configured');
  const next = ctx.query.next === '/staff' ? '/staff' : '/';
  const state = auth.randomToken(24);
  const params = new URLSearchParams({
    client_id: cfg.discord.clientId, redirect_uri: `${cfg.baseUrl}/auth/discord/callback`,
    response_type: 'code', scope: 'identify', state, prompt: 'none',
  });
  redirect(ctx.res, `https://discord.com/oauth2/authorize?${params}`, {
    'Set-Cookie': auth.cookie(auth.OAUTH_COOKIE, `${state}|${next}`, { maxAge: 600 }),
  });
});

router.get('/auth/discord/callback', authLimit, async (ctx) => {
  const clear = auth.cookie(auth.OAUTH_COOKIE, '', { maxAge: 0 });
  const stored = auth.parseCookies(ctx.req.headers.cookie)[auth.OAUTH_COOKIE] || '';
  const [state, next = '/'] = stored.split('|');
  const fail = (code) => redirect(ctx.res, `/?auth=${code}`, { 'Set-Cookie': clear });
  if (ctx.query.error) return fail('denied');
  if (!state || !ctx.query.state || !auth.safeEqual(state, ctx.query.state) || !ctx.query.code) return fail('state');
  try {
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: cfg.discord.clientId, client_secret: cfg.discord.clientSecret, grant_type: 'authorization_code',
        code: String(ctx.query.code), redirect_uri: `${cfg.baseUrl}/auth/discord/callback`,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) { console.error('Discord token exchange failed', tokenRes.status); return fail('token'); }
    const tok = await tokenRes.json();
    const meRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${tok.access_token}` }, signal: AbortSignal.timeout(10_000),
    });
    if (!meRes.ok) return fail('profile');
    const me = await meRes.json();
    if (!me.id || !cfg.idRe.test(String(me.id))) return fail('profile');

    const t = now();
    db.run(`INSERT INTO users (id,username,global_name,avatar,created_at,last_login) VALUES (?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET username=excluded.username, global_name=excluded.global_name, avatar=excluded.avatar, last_login=excluded.last_login`,
      String(me.id), String(me.username || 'unknown').slice(0, 64), me.global_name ? String(me.global_name).slice(0, 64) : null, me.avatar || null, t, t);

    auth.destroySession(ctx.req); // never reuse an existing session id on login
    const s = auth.createSession(String(me.id), ctx.ip, ctx.req.headers['user-agent']);
    ctx.user = { id: String(me.id), username: me.username, globalName: me.global_name };
    audit(ctx, 'auth.login', 'user', me.id, { role: auth.roleOf(String(me.id)) });
    const dest = next === '/staff' && auth.roleOf(String(me.id)) !== 'user' ? '/staff' : '/';
    redirect(ctx.res, dest, { 'Set-Cookie': [auth.cookie(auth.SID_COOKIE, s.token, { maxAge: s.maxAge }), clear] });
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    fail('error');
  }
});

router.post('/auth/logout', (ctx) => {
  auth.destroySession(ctx.req);
  ctx.res.setHeader('Set-Cookie', auth.cookie(auth.SID_COOKIE, '', { maxAge: 0 }));
  return { ok: true };
});

/* ---- session / profile ---- */
router.get('/api/me', (ctx) => {
  const base = { discordConfigured: !!(cfg.discord.clientId && cfg.discord.clientSecret) };
  if (!ctx.user) return { user: null, ...base };
  const unread = db.get('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0', ctx.user.id).n;
  return {
    user: { id: ctx.user.id, username: ctx.user.username, name: auth.displayName(ctx.user), avatarUrl: auth.avatarUrl(ctx.user) },
    role: ctx.role, csrf: ctx.session.csrf, unread, ...base,
  };
});

/* ---- catalogue (public read) ---- */
router.get('/api/items', (ctx) => {
  const { q, category, collection, availability, sort } = ctx.query;
  const where = ['archived = 0'];
  const args = [];
  if (q) { const s = text(String(q), { max: 80 }); where.push(`(name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' OR collection LIKE ? ESCAPE '\\')`); const l = likeEsc(s); args.push(l, l, l, l); }
  if (category) { where.push('category = ?'); args.push(String(category)); }
  if (collection) { where.push('collection = ?'); args.push(String(collection)); }
  if (availability && AVAILABILITY.includes(availability)) { where.push('availability = ?'); args.push(availability); }
  const order = { name: 'name COLLATE NOCASE ASC', newest: 'created_at DESC', category: 'category COLLATE NOCASE, name COLLATE NOCASE' }[sort] || 'sort_order ASC, id ASC';
  const items = db.all(`SELECT * FROM items WHERE ${where.join(' AND ')} ORDER BY ${order}`, ...args).map(fmtItem);
  const categories = db.all('SELECT DISTINCT category AS v FROM items WHERE archived = 0 ORDER BY category COLLATE NOCASE').map((r) => r.v);
  const collections = db.all(`SELECT DISTINCT collection AS v FROM items WHERE archived = 0 AND collection != '' ORDER BY collection COLLATE NOCASE`).map((r) => r.v);
  return { items, categories, collections };
});
router.get('/api/items/:id', (ctx) => {
  const r = db.get('SELECT * FROM items WHERE id = ? AND archived = 0', Number(ctx.params.id));
  if (!r) throw new HttpError(404, 'Item not found.');
  return { item: fmtItem(r) };
});

/* ---- user tickets ---- */
router.post('/api/tickets', requireUser, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const itemId = intIn(b.itemId, { name: 'Item', min: 1, max: 2 ** 31 });
  const quantity = intIn(b.quantity ?? 1, { name: 'Quantity', min: 1, max: 10 });
  const details = text(b.details, { name: 'Details', min: 10, max: 1500, required: true });
  const contactNote = text(b.contactNote, { name: 'Contact note', max: 200 });
  const item = db.get('SELECT * FROM items WHERE id = ? AND archived = 0', itemId);
  if (!item) throw new HttpError(404, 'That item does not exist.');
  if (item.availability === 'unavailable') throw new HttpError(409, 'That item is currently unavailable.');

  const result = db.tx(() => {
    const open = db.get(`SELECT COUNT(*) AS n FROM tickets WHERE user_id = ? AND status IN ('pending','accepted','in_progress')`, ctx.user.id).n;
    if (open >= MAX_OPEN_TICKETS) throw new HttpError(409, `You already have ${MAX_OPEN_TICKETS} open tickets. Wait for some to be resolved or cancel one.`);
    const dup = db.get(`SELECT id FROM tickets WHERE user_id = ? AND item_id = ? AND status = 'pending'`, ctx.user.id, itemId);
    if (dup) throw new HttpError(409, `You already have a pending request for this item (${ref(dup.id)}).`);
    const t = now();
    const r = db.run('INSERT INTO tickets (user_id,item_id,quantity,details,contact_note,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)',
      ctx.user.id, itemId, quantity, details, contactNote, 'pending', t, t);
    const id = Number(r.lastInsertRowid);
    db.run('INSERT INTO ticket_events (ticket_id,actor_id,actor_name,kind,to_status,message,created_at) VALUES (?,?,?,?,?,?,?)',
      id, ctx.user.id, auth.displayName(ctx.user), 'created', 'pending', null, t);
    notify(ctx.user.id, { type: 'ticket', title: `Ticket ${ref(id)} submitted`, body: `We received your request for ${item.name}. Staff will review it soon.`, ticketId: id });
    return id;
  });
  sendWebhook(result, item, quantity, ctx.user);
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, result)) };
});

router.get('/api/tickets', requireUser, (ctx) => {
  const rows = db.all(`${TICKET_SQL} WHERE t.user_id = ? ORDER BY t.created_at DESC LIMIT 200`, ctx.user.id);
  return { tickets: rows.map(fmtTicket) };
});
router.get('/api/tickets/:id', requireUser, (ctx) => {
  const r = db.get(`${TICKET_SQL} WHERE t.id = ? AND t.user_id = ?`, Number(ctx.params.id), ctx.user.id);
  if (!r) throw new HttpError(404, 'Ticket not found.');
  return { ticket: fmtTicket(r), events: ticketEvents(r.id) };
});
router.post('/api/tickets/:id/cancel', requireUser, writeLimit, (ctx) => {
  const r = db.get(`${TICKET_SQL} WHERE t.id = ? AND t.user_id = ?`, Number(ctx.params.id), ctx.user.id);
  if (!r) throw new HttpError(404, 'Ticket not found.');
  applyStatus(r, 'cancelled', ctx, { message: 'Cancelled by requester.', notifyUser: false, byRequester: true });
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, r.id)) };
});

/* ---- notifications ---- */
router.get('/api/notifications', requireUser, (ctx) => {
  const rows = db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100', ctx.user.id);
  const unread = db.get('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0', ctx.user.id).n;
  return {
    unread,
    notifications: rows.map((n) => ({ id: n.id, type: n.type, title: n.title, body: n.body, ticketId: n.ticket_id, read: !!n.read, createdAt: n.created_at })),
  };
});
router.post('/api/notifications/read', requireUser, async (ctx) => {
  const b = await jsonBody(ctx);
  if (Array.isArray(b.ids) && b.ids.length) {
    for (const id of b.ids.slice(0, 100)) db.run('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', Number(id) || 0, ctx.user.id);
  } else {
    db.run('UPDATE notifications SET read = 1 WHERE user_id = ?', ctx.user.id);
  }
  return { ok: true };
});

/* ---- shared ticket state machine ---- */
function applyStatus(row, to, ctx, { message = '', reason = '', notifyUser = true, force = false, byRequester = false } = {}) {
  const from = row.status;
  if (!STATUSES.includes(to)) throw new HttpError(400, 'Unknown status.');
  const isUserCancel = byRequester && ctx.user.id === row.user_id && to === 'cancelled';
  if (isUserCancel && !OPEN_STATUSES.includes(from)) throw new HttpError(409, 'Only open tickets can be cancelled.');
  if (!isUserCancel) {
    if (ctx.role !== 'staff' && ctx.role !== 'owner') throw new HttpError(403, 'Staff access required.');
    if (row.user_id === ctx.user.id && ctx.role !== 'owner') throw new HttpError(403, 'You cannot act on your own ticket.');
  }
  const allowed = NEXT[from] || [];
  if (!(allowed.includes(to) || (force && ctx.role === 'owner' && to !== from))) {
    throw new HttpError(409, `A ${from.replace('_', ' ')} ticket cannot be changed to ${to.replace('_', ' ')}.`);
  }
  if (to === 'denied' && !reason) throw new HttpError(400, 'A reason is required when denying a ticket.');

  const actorName = auth.displayName(ctx.user);
  const t = now();
  const changed = db.tx(() => {
    const r = db.run(
      `UPDATE tickets SET status = ?, denial_reason = ?, staff_note = COALESCE(?, staff_note), handled_by = ?, handled_by_name = ?, updated_at = ?
       WHERE id = ? AND status = ?`,
      to, to === 'denied' ? reason : (to === 'pending' ? null : row.denial_reason), message || null,
      isUserCancel ? row.handled_by : ctx.user.id, isUserCancel ? row.handled_by_name : actorName, t, row.id, from);
    if (!r.changes) return false; // someone else changed it first
    const kind = { accepted: 'accepted', denied: 'denied', cancelled: 'cancelled', pending: 'reopened' }[to] || 'status';
    db.run('INSERT INTO ticket_events (ticket_id,actor_id,actor_name,kind,from_status,to_status,message,created_at) VALUES (?,?,?,?,?,?,?,?)',
      row.id, ctx.user.id, actorName, kind, from, to, (to === 'denied' ? reason : message) || null, t);
    if (notifyUser) {
      const n = {
        accepted: { title: `Ticket ${ref(row.id)} accepted`, body: `Good news — your request for ${row.item_name} was accepted.${message ? ' Note: ' + message : ''}` },
        denied: { title: `Ticket ${ref(row.id)} denied`, body: `Your request for ${row.item_name} was denied. Reason: ${reason}` },
        in_progress: { title: `Ticket ${ref(row.id)} is in progress`, body: `Staff are working on your request for ${row.item_name}.${message ? ' Note: ' + message : ''}` },
        completed: { title: `Ticket ${ref(row.id)} completed`, body: `Your request for ${row.item_name} is complete.${message ? ' Note: ' + message : ''}` },
        pending: { title: `Ticket ${ref(row.id)} reopened`, body: `Your request for ${row.item_name} was reopened and is back in the queue.${message ? ' Note: ' + message : ''}` },
        cancelled: { title: `Ticket ${ref(row.id)} cancelled`, body: `Your request for ${row.item_name} was cancelled by staff.${message ? ' Note: ' + message : ''}` },
      }[to];
      notify(row.user_id, { type: 'ticket', ticketId: row.id, ...n });
    }
    return true;
  });
  if (!changed) throw new HttpError(409, 'This ticket was just updated by someone else. Refresh and try again.');
  audit(ctx, `ticket.${to}`, 'ticket', row.id, { from, to, reason: reason || undefined, message: message || undefined, forced: force || undefined });
}

/* ---- staff portal API ---- */
router.get('/api/staff/stats', requireStaff, () => {
  const rows = db.all('SELECT status, COUNT(*) AS n FROM tickets GROUP BY status');
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const r of rows) counts[r.status] = r.n;
  return { counts, open: OPEN_STATUSES.reduce((a, s) => a + counts[s], 0) };
});

function listTickets(ctx) {
  const { status, q } = ctx.query;
  const where = [];
  const args = [];
  if (status === 'open') where.push(`t.status IN ('pending','accepted','in_progress')`);
  else if (STATUSES.includes(status)) { where.push('t.status = ?'); args.push(status); }
  if (q) {
    const s = text(String(q), { max: 80 });
    const refMatch = s.match(/^(?:afl-?)?0*(\d+)$/i);
    const l = likeEsc(s);
    where.push(`(u.username LIKE ? ESCAPE '\\' OR u.global_name LIKE ? ESCAPE '\\' OR i.name LIKE ? ESCAPE '\\' OR u.id = ?${refMatch ? ' OR t.id = ?' : ''})`);
    args.push(l, l, l, s);
    if (refMatch) args.push(Number(refMatch[1]));
  }
  const W = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const page = Math.max(1, parseInt(ctx.query.page, 10) || 1);
  const size = 25;
  const total = db.get(`SELECT COUNT(*) AS n FROM tickets t JOIN items i ON i.id = t.item_id JOIN users u ON u.id = t.user_id ${W}`, ...args).n;
  const rows = db.all(`${TICKET_SQL} ${W} ORDER BY CASE t.status WHEN 'pending' THEN 0 ELSE 1 END, t.created_at ${status === 'pending' || status === 'open' ? 'ASC' : 'DESC'} LIMIT ? OFFSET ?`, ...args, size, (page - 1) * size);
  return { tickets: rows.map(fmtTicket), total, page, pages: Math.max(1, Math.ceil(total / size)) };
}
router.get('/api/staff/tickets', requireStaff, listTickets);

router.get('/api/staff/tickets/:id', requireStaff, (ctx) => {
  const r = db.get(`${TICKET_SQL} WHERE t.id = ?`, Number(ctx.params.id));
  if (!r) throw new HttpError(404, 'Ticket not found.');
  const history = db.all(`SELECT id, status, item_id, created_at FROM tickets WHERE user_id = ? AND id != ? ORDER BY id DESC LIMIT 5`, r.user_id, r.id)
    .map((h) => ({ id: h.id, ref: ref(h.id), status: h.status, createdAt: h.created_at }));
  return { ticket: fmtTicket(r), events: ticketEvents(r.id), requesterHistory: history, canAct: r.user_id !== ctx.user.id || ctx.role === 'owner' };
});

function loadForAction(ctx) {
  const r = db.get(`${TICKET_SQL} WHERE t.id = ?`, Number(ctx.params.id));
  if (!r) throw new HttpError(404, 'Ticket not found.');
  return r;
}
router.post('/api/staff/tickets/:id/accept', requireStaff, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const r = loadForAction(ctx);
  applyStatus(r, 'accepted', ctx, { message: text(b.note, { name: 'Note', max: 500 }) });
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, r.id)), events: ticketEvents(r.id) };
});
router.post('/api/staff/tickets/:id/deny', requireStaff, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const r = loadForAction(ctx);
  applyStatus(r, 'denied', ctx, { reason: text(b.reason, { name: 'Denial reason', min: 3, max: 500, required: true }) });
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, r.id)), events: ticketEvents(r.id) };
});
router.post('/api/staff/tickets/:id/status', requireStaff, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const r = loadForAction(ctx);
  const to = String(b.status || '');
  applyStatus(r, to, ctx, {
    message: text(b.note, { name: 'Note', max: 500 }),
    reason: to === 'denied' ? text(b.reason, { name: 'Denial reason', min: 3, max: 500, required: true }) : '',
    force: b.force === true,
  });
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, r.id)), events: ticketEvents(r.id) };
});
router.post('/api/staff/tickets/:id/note', requireStaff, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const r = loadForAction(ctx);
  if (r.user_id === ctx.user.id && ctx.role !== 'owner') throw new HttpError(403, 'You cannot act on your own ticket.');
  const message = text(b.note, { name: 'Update', min: 1, max: 500, required: true });
  const t = now();
  db.tx(() => {
    db.run('UPDATE tickets SET staff_note = ?, updated_at = ? WHERE id = ?', message, t, r.id);
    db.run('INSERT INTO ticket_events (ticket_id,actor_id,actor_name,kind,from_status,to_status,message,created_at) VALUES (?,?,?,?,?,?,?,?)',
      r.id, ctx.user.id, auth.displayName(ctx.user), 'note', r.status, r.status, message, t);
    notify(r.user_id, { type: 'ticket', ticketId: r.id, title: `Update on ticket ${ref(r.id)}`, body: message });
  });
  audit(ctx, 'ticket.note', 'ticket', r.id, { message });
  return { ticket: fmtTicket(db.get(`${TICKET_SQL} WHERE t.id = ?`, r.id)), events: ticketEvents(r.id) };
});

/* ---- owner controls ---- */
router.get('/api/owner/staff', requireOwner, () => {
  const rows = db.all(`SELECT s.*, u.username, u.global_name, u.avatar, u.last_login FROM staff s LEFT JOIN users u ON u.id = s.discord_id ORDER BY s.created_at`);
  const owner = cfg.ownerId ? db.get('SELECT * FROM users WHERE id = ?', cfg.ownerId) : null;
  return {
    owner: { discordId: cfg.ownerId, name: owner ? (owner.global_name || owner.username) : null },
    staff: rows.map((r) => ({
      discordId: r.discord_id, label: r.label, source: r.source, addedBy: r.added_by, createdAt: r.created_at,
      name: r.global_name || r.username || null, avatarUrl: r.username ? auth.avatarUrl({ id: r.discord_id, avatar: r.avatar }) : null, lastLogin: r.last_login || null,
    })),
  };
});
router.post('/api/owner/staff', requireOwner, writeLimit, async (ctx) => {
  const b = await jsonBody(ctx);
  const id = String(b.discordId || '').trim();
  if (!cfg.idRe.test(id)) throw new HttpError(400, 'Enter a valid Discord user ID (17–20 digits). Enable Developer Mode in Discord, then right-click a user → Copy User ID.');
  if (id === cfg.ownerId) throw new HttpError(409, 'That user is the owner and already has full access.');
  const label = text(b.label, { name: 'Label', max: 60 });
  const r = db.run('INSERT OR IGNORE INTO staff (discord_id,label,source,added_by,created_at) VALUES (?,?,?,?,?)', id, label, 'owner', ctx.user.id, now());
  if (!r.changes) throw new HttpError(409, 'That user is already staff.');
  audit(ctx, 'staff.add', 'staff', id, { label });
  return { ok: true };
});
router.delete('/api/owner/staff/:id', requireOwner, writeLimit, (ctx) => {
  const id = ctx.params.id;
  const row = db.get('SELECT * FROM staff WHERE discord_id = ?', id);
  if (!row) throw new HttpError(404, 'Staff member not found.');
  if (row.source === 'env') throw new HttpError(409, 'This ID is set in STAFF_DISCORD_IDS. Remove it from your environment and restart the server.');
  db.run('DELETE FROM staff WHERE discord_id = ?', id);
  audit(ctx, 'staff.remove', 'staff', id, { label: row.label });
  return { ok: true };
});

function readItemBody(b) {
  const image = String(b.image || '').trim();
  if (image && !/^\/(img\/items|uploads)\/[A-Za-z0-9._-]{1,120}$/.test(image)) throw new HttpError(400, 'Image must be an uploaded file or a file in /img/items/.');
  const availability = String(b.availability || 'tbc');
  if (!AVAILABILITY.includes(availability)) throw new HttpError(400, 'Invalid availability.');
  return {
    name: text(b.name, { name: 'Name', min: 1, max: 80, required: true }),
    description: text(b.description, { name: 'Description', max: 1000 }),
    category: text(b.category, { name: 'Category', min: 1, max: 40, required: true }),
    collection: text(b.collection, { name: 'Collection', max: 40 }),
    availability, image,
    sortOrder: intIn(b.sortOrder ?? 0, { name: 'Sort order', min: -9999, max: 9999 }),
    placeholder: b.placeholder ? 1 : 0,
    archived: b.archived ? 1 : 0,
  };
}
router.get('/api/owner/items', requireOwner, () => ({ items: db.all('SELECT * FROM items ORDER BY archived, sort_order, id').map(fmtItem) }));
router.post('/api/owner/items', requireOwner, writeLimit, async (ctx) => {
  const v = readItemBody(await jsonBody(ctx));
  const t = now();
  const r = db.run('INSERT INTO items (name,description,category,collection,availability,image,sort_order,placeholder,archived,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    v.name, v.description, v.category, v.collection, v.availability, v.image, v.sortOrder, v.placeholder, v.archived, t, t);
  audit(ctx, 'item.create', 'item', r.lastInsertRowid, { name: v.name });
  return { item: fmtItem(db.get('SELECT * FROM items WHERE id = ?', Number(r.lastInsertRowid))) };
});
router.put('/api/owner/items/:id', requireOwner, writeLimit, async (ctx) => {
  const id = Number(ctx.params.id);
  if (!db.get('SELECT 1 AS x FROM items WHERE id = ?', id)) throw new HttpError(404, 'Item not found.');
  const v = readItemBody(await jsonBody(ctx));
  db.run('UPDATE items SET name=?,description=?,category=?,collection=?,availability=?,image=?,sort_order=?,placeholder=?,archived=?,updated_at=? WHERE id=?',
    v.name, v.description, v.category, v.collection, v.availability, v.image, v.sortOrder, v.placeholder, v.archived, now(), id);
  audit(ctx, 'item.update', 'item', id, { name: v.name, availability: v.availability, archived: !!v.archived });
  return { item: fmtItem(db.get('SELECT * FROM items WHERE id = ?', id)) };
});
router.delete('/api/owner/items/:id', requireOwner, writeLimit, (ctx) => {
  const id = Number(ctx.params.id);
  const it = db.get('SELECT * FROM items WHERE id = ?', id);
  if (!it) throw new HttpError(404, 'Item not found.');
  const used = db.get('SELECT COUNT(*) AS n FROM tickets WHERE item_id = ?', id).n;
  if (used) {
    db.run('UPDATE items SET archived = 1, updated_at = ? WHERE id = ?', now(), id);
    audit(ctx, 'item.archive', 'item', id, { name: it.name, tickets: used });
    return { ok: true, archived: true, message: `Item has ${used} ticket(s), so it was archived instead of deleted.` };
  }
  db.run('DELETE FROM items WHERE id = ?', id);
  audit(ctx, 'item.delete', 'item', id, { name: it.name });
  return { ok: true, deleted: true };
});

router.post('/api/owner/upload', requireOwner, writeLimit, async (ctx) => {
  const buf = await readBody(ctx.req, 4 * 1024 * 1024);
  let ext = null;
  if (buf.length > 12 && buf[0] === 0x89 && buf.toString('latin1', 1, 4) === 'PNG') ext = 'png';
  else if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) ext = 'jpg';
  else if (buf.length > 12 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') ext = 'webp';
  if (!ext) throw new HttpError(415, 'Only PNG, JPEG or WebP images up to 4 MB are accepted.');
  const name = `${crypto.randomBytes(16).toString('hex')}.${ext}`;
  fs.writeFileSync(path.join(cfg.uploadDir, name), buf, { mode: 0o644 });
  audit(ctx, 'item.upload', 'upload', name, { bytes: buf.length });
  return { path: `/uploads/${name}` };
});

router.get('/api/owner/tickets', requireOwner, listTickets);
router.delete('/api/owner/tickets/:id', requireOwner, writeLimit, (ctx) => {
  const id = Number(ctx.params.id);
  const r = db.get(`${TICKET_SQL} WHERE t.id = ?`, id);
  if (!r) throw new HttpError(404, 'Ticket not found.');
  db.tx(() => {
    db.run('UPDATE notifications SET ticket_id = NULL WHERE ticket_id = ?', id);
    db.run('DELETE FROM tickets WHERE id = ?', id);
  });
  audit(ctx, 'ticket.delete', 'ticket', id, { ref: ref(id), item: r.item_name, user: r.user_id, status: r.status });
  return { ok: true };
});
router.get('/api/owner/audit', requireOwner, (ctx) => {
  const page = Math.max(1, parseInt(ctx.query.page, 10) || 1);
  const size = 50;
  const total = db.get('SELECT COUNT(*) AS n FROM audit_log').n;
  const rows = db.all('SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?', size, (page - 1) * size);
  return {
    total, page, pages: Math.max(1, Math.ceil(total / size)),
    entries: rows.map((e) => ({ id: e.id, actorId: e.actor_id, actor: e.actor_name, action: e.action, targetType: e.target_type, targetId: e.target_id, detail: e.detail, ip: e.ip, createdAt: e.created_at })),
  };
});

/* ---- optional Discord webhook for new tickets ---- */
function sendWebhook(id, item, qty, user) {
  if (!/^https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\//.test(cfg.webhook)) return;
  fetch(cfg.webhook, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(8000),
    body: JSON.stringify({
      allowed_mentions: { parse: [] },
      embeds: [{ title: `New ticket ${ref(id)}`, description: `**${item.name}** × ${qty}\nRequested by ${auth.displayName(user).replace(/[*_`~|>@#]/g, '')}`, color: 0x22c1ee, url: `${cfg.baseUrl}/staff` }],
    }),
  }).catch(() => { /* webhook is best-effort */ });
}

/* ------------------------------------------------------------------- seeding */
function seedCatalogue() {
  if (!cfg.seedCatalogue) return;
  if (db.get('SELECT COUNT(*) AS n FROM items').n > 0) return;
  const t = now();
  let order = 0;
  for (const s of SEED) {
    const file = path.join(PUBLIC_DIR, 'img', 'items', s.file);
    if (!fs.existsSync(file)) continue;
    db.run('INSERT INTO items (name,description,category,collection,availability,image,sort_order,placeholder,archived,created_at,updated_at) VALUES (?,?,?,?,?,?,?,1,0,?,?)',
      s.name, s.description, s.category, s.collection, 'tbc', `/img/items/${s.file}`, order += 10, t, t);
  }
  console.log(`Seeded ${order / 10} catalogue items from supplied images (placeholders — review them in the staff portal).`);
}
seedCatalogue();

/* --------------------------------------------------------------- HTTP server */
const ORIGIN = new URL(cfg.baseUrl).origin;
const LONG = 'public, max-age=86400';
const REVALIDATE = 'no-cache';

function notFound(res) {
  send(res, 404, '<!doctype html><meta charset="utf-8"><title>Not found</title><body style="font-family:system-ui;background:#05090d;color:#9fb4c0;display:grid;place-items:center;height:100vh;margin:0"><p>404 — Not found</p>',
    { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
}

async function handle(req, res) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  if (!['GET', 'HEAD', 'POST', 'PUT', 'DELETE'].includes(req.method)) return send(res, 405, 'Method Not Allowed');
  let url;
  try { url = new URL(req.url, ORIGIN); } catch { return send(res, 400, 'Bad request'); }
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { return send(res, 400, 'Bad request'); }
  if (p.includes('\0')) return send(res, 400, 'Bad request');
  const ip = clientIp(req);

  /* API + auth */
  if (p.startsWith('/api/') || p.startsWith('/auth/')) {
    try {
      const m = router.match(req.method === 'HEAD' ? 'GET' : req.method, p);
      if (!m.route) throw new HttpError(m.pathMatched ? 405 : 404, m.pathMatched ? 'Method not allowed.' : 'Not found.');
      const ctx = { req, res, url, ip, params: m.params, query: Object.fromEntries(url.searchParams), session: null, user: null, role: 'user' };
      const s = auth.loadSession(req);
      if (s) { ctx.session = s; ctx.user = s.user; ctx.role = auth.roleOf(s.user.id); }
      rateLimit('global', 600, 60_000)(ctx);

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const origin = req.headers.origin;
        if (origin && origin !== ORIGIN) throw new HttpError(403, 'Cross-origin request blocked.');
        const isLogout = p === '/auth/logout';
        if (!ctx.session) { if (isLogout) return sendJson(res, 200, { ok: true }); throw new HttpError(401, 'Please sign in with Discord first.'); }
        if (!auth.safeEqual(req.headers['x-csrf-token'] || '', ctx.session.csrf)) throw new HttpError(403, 'Invalid or missing CSRF token. Reload the page and try again.');
      }
      for (const fn of m.route.fns) {
        const out = await fn(ctx);
        if (res.headersSent) return;
        if (out !== undefined) return sendJson(res, 200, out);
      }
      if (!res.headersSent) sendJson(res, 204, {});
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
      console.error(`[${new Date().toISOString()}] ${req.method} ${p}:`, err);
      sendJson(res, 500, { error: 'Something went wrong on our side. Please try again.' });
    }
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method Not Allowed');

  /* Staff portal — never served (or even acknowledged) to non-staff */
  if (p === '/staff' || p === '/staff/' || p.startsWith('/staff-ui/')) {
    const s = auth.loadSession(req);
    if (!s) {
      if (p.startsWith('/staff-ui/')) return notFound(res);
      return redirect(res, '/auth/discord/login?next=/staff');
    }
    if (auth.roleOf(s.user.id) === 'user') return notFound(res);
    const file = p.startsWith('/staff-ui/') ? safeJoin(STAFF_UI_DIR, p.slice('/staff-ui/'.length)) : path.join(STAFF_UI_DIR, 'index.html');
    if (file && serveFile(req, res, file, { 'Cache-Control': 'no-store' })) return;
    return notFound(res);
  }

  /* Logo: serve an owner-supplied logo.png/webp/jpg if present, otherwise the bundled logo.svg */
  if (p === '/brand/logo') {
    for (const f of ['logo.png', 'logo.webp', 'logo.jpg', 'logo.svg']) {
      if (serveFile(req, res, path.join(PUBLIC_DIR, 'img', f), { 'Cache-Control': 'public, max-age=300' })) return;
    }
    return notFound(res);
  }

  /* Uploaded catalogue images */
  if (p.startsWith('/uploads/')) {
    const name = p.slice(9);
    if (/^[a-f0-9]{32}\.(png|jpg|webp)$/.test(name) && serveFile(req, res, path.join(cfg.uploadDir, name), { 'Cache-Control': LONG })) return;
    return notFound(res);
  }

  /* Public static files */
  let rel = p === '/' ? '/index.html' : p;
  let file = safeJoin(PUBLIC_DIR, rel);
  if (file) {
    const ext = path.extname(file).toLowerCase();
    const cache = ['.webp', '.png', '.jpg', '.jpeg', '.svg', '.ico'].includes(ext) ? LONG : REVALIDATE;
    if (serveFile(req, res, file, { 'Cache-Control': cache })) return;
  }
  notFound(res);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('Unhandled error:', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'Something went wrong on our side.' });
  });
});
server.requestTimeout = 30_000;
server.headersTimeout = 15_000;

if (require.main === module) {
  server.listen(cfg.port, () => {
    console.log(`AFL is running at ${cfg.baseUrl} (port ${cfg.port})`);
    for (const p of cfg.problems) console.warn('⚠ ' + p);
  });
}
module.exports = { server };
