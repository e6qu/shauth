// SPDX-License-Identifier: AGPL-3.0-or-later
import { escapeHTML as e, icon, button, badge, notice, metric, appCard } from '../components.js';
import { initialState, validateState, storageKey, currentUserId, currentSessionId } from './state.js';

const main = document.querySelector('#main-content');
const dialog = document.querySelector('#demo-dialog');
const form = document.querySelector('#dialog-form');
const routes = [['apps', 'Apps', 'apps'], ['users', 'Users', 'users'], ['invitations', 'Invitations', 'mail'], ['sessions', 'Sessions', 'timer'], ['audit', 'Audit record', 'record']];
let state, storageError, message = '', dialogCallback, returnFocus;
let userQuery = '', userRole = 'all', sessionFilter = 'active';
try { const saved = localStorage.getItem(storageKey); state = saved ? validateState(JSON.parse(saved)) : initialState(); } catch (error) { storageError = error; }
const currentSession = () => state.sessions.find(session => session.id === currentSessionId);
const user = id => state.users.find(person => person.id === id);
const date = value => new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const attr = (action, id = '') => `data-action="${action}"${id ? ` data-id="${e(id)}"` : ''}`;
const field = (id, label, input, hint = '') => `<div class="field"><label for="${id}">${label}</label>${input}${hint ? `<span class="field-help">${hint}</span>` : ''}</div>`;
const roles = selected => ['developer', 'admin'].map(role => `<option value="${role}"${role === selected ? ' selected' : ''}>${role === 'admin' ? 'Administrator' : 'Developer'}</option>`).join('');
function record(action, detail) { state.audit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), actor: 'Morgan Lee', action, detail }); }
function save(text) {
  localStorage.setItem(storageKey, JSON.stringify(state));
  message = text;
  render();
}
function notification() { return message ? `<div class="status-banner status-banner-info demo-notification" role="status"><span>${e(message)}</span><button type="button" data-action="dismiss" aria-label="Dismiss notification">×</button></div>` : ''; }
function heading(title, description, action = '') { return `<section class="demo-heading"><p class="eyebrow">${title === 'Apps' ? 'Connected services' : 'Administration'}</p><div class="demo-heading-row"><h1>${title}</h1>${action}</div><p class="lede">${description}</p></section>`; }
function empty(title, text) { return `<div class="demo-empty"><h2>${title}</h2><p>${text}</p></div>`; }
function renderApps() {
  const session = currentSession();
  return heading('Apps', 'Open a sample application to explore single sign-on. Sign out from any sample app to end this browser’s shared session.') +
    `<section class="demo-summary" aria-label="Demo summary">${metric('Connected applications', state.apps.length)}${metric('Apps open in this session', session.apps.length)}${metric('Enabled demo users', state.users.filter(u => u.enabled).length)}</section>` +
    `<section class="demo-apps" aria-label="Available applications">${state.apps.map(app => appCard(app, { active: session.apps.includes(app.id) })).join('')}</section>` +
    `<aside class="demo-story"><strong>Try a shared session</strong><p>Open Atlas Docs, then Orbit Board. Both use the same demo identity. Sign out from either app, then try opening the other again.</p></aside>`;
}
function usersTable() {
  const found = state.users.filter(u => `${u.name} ${u.username} ${u.email}`.toLowerCase().includes(userQuery.toLowerCase()) && (userRole === 'all' || u.role === userRole));
  if (!found.length) return empty('No users match', 'Change the search or role filter to see more users.');
  return `<div class="table-wrap"><table><caption>Demo users · ${found.length} shown</caption><thead><tr><th scope="col">Account</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead><tbody>${found.map(u => `<tr><td data-label="Account"><span class="demo-cell-name">${e(u.name)}</span><span class="demo-cell-detail">${e(u.email)} · ${e(u.source)}</span></td><td data-label="Role">${u.id === currentUserId ? 'Administrator (you)' : `<select data-role-user="${e(u.id)}" aria-label="Role for ${e(u.name)}">${roles(u.role)}</select>`}</td><td data-label="Status">${badge(u.enabled ? 'Enabled' : 'Disabled', u.enabled ? 'success' : 'neutral')}</td><td data-label="Actions">${u.id === currentUserId ? '<span class="muted">Current administrator</span>' : button({ label: `${u.enabled ? 'Disable' : 'Enable'} ${u.name}`, variant: u.enabled ? 'danger' : 'secondary', attrs: attr('toggle-user', u.id) })}</td></tr>`).join('')}</tbody></table></div>`;
}
function renderUsers() {
  return heading('Users', 'Manage the people in this synthetic directory. Disabling an account also ends its active demo sessions.', button({ label: 'Add demo user', iconName: 'users', attrs: attr('add-user') })) +
    `<div class="demo-tools">${field('user-search', 'Find a user', `<input id="user-search" type="search" value="${e(userQuery)}" placeholder="Name or email">`)}<div class="field field-small"><label for="user-role">Role</label><select id="user-role"><option value="all">All roles</option>${roles(userRole)}</select></div></div><section id="users-results" aria-label="User directory">${usersTable()}</section>`;
}
function renderInvitations() {
  return heading('Invitations', 'Create and revoke sample invitations. This demo never sends email.', button({ label: 'Create invitation', iconName: 'mail', attrs: attr('invite') })) +
    (state.invitations.length ? `<div class="table-wrap"><table><caption>Demo invitations</caption><thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead><tbody>${state.invitations.map(invite => `<tr><td data-label="Email">${e(invite.email)}</td><td data-label="Role">${e(invite.role)}</td><td data-label="Status">${badge(invite.status, invite.status === 'pending' ? 'warning' : 'neutral')}</td><td data-label="Created">${e(date(invite.createdAt))}</td><td data-label="Actions">${invite.status === 'pending' ? button({ label: 'Revoke invitation', variant: 'danger', attrs: `${attr('revoke-invite', invite.id)} aria-label="Revoke invitation for ${e(invite.email)}"` }) : '<span class="muted">Revoked</span>'}</td></tr>`).join('')}</tbody></table></div>` : empty('No invitations', 'Create an invitation to explore the workflow.'));
}
function renderSessions() {
  const sessions = state.sessions.filter(session => sessionFilter === 'all' || session.active);
  return heading('Signed-in sessions', 'Inspect browser sessions and end access across their connected sample apps.') +
    `<div class="demo-tools"><div class="field field-small"><label for="session-state">Show</label><select id="session-state"><option value="active"${sessionFilter === 'active' ? ' selected' : ''}>Active sessions</option><option value="all"${sessionFilter === 'all' ? ' selected' : ''}>Every session</option></select></div></div>` +
    (sessions.length ? `<div class="table-wrap"><table><caption>Demo browser sessions</caption><thead><tr><th scope="col">Account</th><th scope="col">Browser</th><th scope="col">Started</th><th scope="col">State</th><th scope="col">Actions</th></tr></thead><tbody>${sessions.map(session => `<tr><td data-label="Account">${e(user(session.userId)?.name || 'Deleted demo user')}</td><td data-label="Browser">${e(session.browser)}<span class="demo-cell-detail">${session.apps.length} connected apps</span></td><td data-label="Started">${e(date(session.startedAt))}</td><td data-label="State">${badge(session.active ? 'Active' : 'Ended', session.active ? 'success' : 'neutral')}</td><td data-label="Actions">${session.active ? button({ label: 'End session', variant: 'danger', attrs: `${attr('revoke-session', session.id)} aria-label="End session for ${e(user(session.userId)?.name)} in ${e(session.browser)}"` }) : '<span class="muted">Session ended</span>'}</td></tr>`).join('')}</tbody></table></div>` : empty('No active sessions', 'Switch to every session to inspect ended sessions.'));
}
function renderAudit() {
  return heading('Audit record', 'A local record of the actions you take in this demo. Resetting the demo clears these events.') +
    `<ol class="demo-audit">${state.audit.map(event => `<li><time datetime="${e(event.at)}">${e(date(event.at))}</time><div><strong>${e(event.action)}</strong><p>${e(event.detail)}</p><span class="demo-event-label">${e(event.actor)} · synthetic demo</span></div></li>`).join('')}</ol>`;
}
function renderApp(id) {
  const app = state.apps.find(app => app.id === id);
  if (!app) return heading('Application not found', 'Choose one of the sample applications from the catalog.') + '<a class="button" href="#/apps">Back to apps</a>';
  if (!currentSession().apps.includes(id)) return heading(app.name, app.description) + button({ label: `Open ${app.name}`, attrs: attr('open-app', id) });
  return heading(app.name, 'Example relying party · this screen belongs to the synthetic demo.') + `<section class="card"><p class="eyebrow">Shared identity</p><h2>Signed in as Morgan Lee</h2><p class="lede">This application is using the same demo browser session as Shauth.</p><div class="demo-session-apps">${state.apps.filter(app => currentSession().apps.includes(app.id)).map(app => badge(app.name, 'success')).join('')}</div><p><strong>${currentSession().apps.length}</strong> sample ${currentSession().apps.length === 1 ? 'application shares' : 'applications share'} this session.</p><div class="actions"><a class="button button-secondary" href="#/apps">Open another app</a>${button({ label: 'Sign out of all apps', variant: 'danger', iconName: 'signout', attrs: attr('logout', id) })}</div></section><aside class="demo-story"><strong>What would happen in a real deployment?</strong><p>The application uses an OIDC authorization-code flow. Shauth and Ory Hydra validate the session and issue tokens for that application. This static demo illustrates the session relationship; it does not issue tokens.</p><p><a href="../docs/architecture.html">Read the authentication architecture</a></p></aside>`;
}
function signedOut() {
  return `<section class="card demo-signedout"><p class="eyebrow">Demo session ended</p><h1>You are signed out</h1><p class="lede">This browser’s Shauth demo session and all its connected sample application sessions have ended.</p><p>Other demo users’ sessions are unchanged. Starting a new session keeps your directory edits and audit history.</p><p class="actions">${button({ label: 'Start a new demo session', iconName: 'key', attrs: attr('sign-in') })}<a href="../">Back to the presentation</a></p></section>`;
}
function render() {
  const route = location.hash.replace(/^#\/?/, '') || 'apps';
  const section = route.startsWith('app/') ? 'apps' : route;
  document.querySelector('#demo-nav').innerHTML = routes.map(([id, label, glyph]) => `<a href="#/${id}"${section === id ? ' aria-current="page"' : ''}>${icon(glyph)}${label}</a>`).join('');
  if (storageError) { main.innerHTML = `<section class="card"><h1>Reset saved demo data</h1>${notice(storageError.message, 'danger')}<p>${button({ label: 'Reset demo data', attrs: attr('reset') })}</p></section>`; return; }
  const views = { apps: renderApps, users: renderUsers, invitations: renderInvitations, sessions: renderSessions, audit: renderAudit };
  main.innerHTML = notification() + (!currentSession().active ? signedOut() : route.startsWith('app/') ? renderApp(route.slice(4)) : (views[route] || renderApps)());
  document.title = `${!currentSession().active ? 'Signed out' : routes.find(([id]) => id === section)?.[1] || 'Apps'} · Shauth demo`;
}
function showDialog(title, body, label, callback, destructive = false) {
  returnFocus = document.activeElement;
  document.querySelector('#dialog-content').innerHTML = `<h2 id="dialog-title">${e(title)}</h2>${body}`;
  document.querySelector('#dialog-submit').textContent = label;
  document.querySelector('#dialog-submit').className = `button${destructive ? ' button-danger' : ''}`;
  document.querySelector('#dialog-error').textContent = '';
  dialogCallback = callback;
  dialog.showModal();
}
function confirm(title, description, label, callback) { showDialog(title, `<p>${description}</p>`, label, callback, true); }
function endSession(session) { session.active = false; session.apps = []; }
function action(name, id) {
  if (name === 'cancel-dialog') { dialog.close(); return; }
  if (name === 'dismiss') { message = ''; render(); return; }
  if (name === 'reset') { confirm('Reset the demo?', 'This removes your local demo edits and restores the original synthetic users, invitations, and sessions.', 'Reset demo', () => { state = initialState(); storageError = null; userQuery = ''; userRole = 'all'; sessionFilter = 'active'; location.hash = '/apps'; save('Demo reset. The original sample data is restored.'); }); return; }
  if (!state) return;
  if (name === 'sign-in') { currentSession().active = true; currentSession().startedAt = new Date().toISOString(); record('Demo session started', 'A new synthetic browser session.'); location.hash = '/apps'; save('A new demo session has started.'); return; }
  if (!currentSession().active) return;
  if (name === 'open-app') {
    const app = state.apps.find(app => app.id === id); if (!app) return;
    if (!currentSession().apps.includes(id)) { currentSession().apps.push(id); record('Application opened', `${app.name} joined this browser’s shared demo session.`); }
    location.hash = `/app/${id}`; save(`${app.name} is open with your shared demo identity.`);
  } else if (name === 'logout') {
    const app = state.apps.find(app => app.id === id);
    confirm('Sign out of all sample apps?', `End this browser’s shared demo session from ${e(app?.name || 'this app')}? Every sample app connected to this session will be signed out.`, 'Sign out of all apps', () => { endSession(currentSession()); record('Global logout', `Initiated by ${app?.name}; all apps in this demo browser were signed out.`); save('Global demo logout completed.'); });
  } else if (name === 'add-user') {
    showDialog('Add a demo user', `<div class="stack">${field('new-name', 'Name', '<input id="new-name" name="name" required maxlength="80" autocomplete="off">')}${field('new-username', 'Username', '<input id="new-username" name="username" required pattern="[a-zA-Z0-9._-]+" maxlength="40" autocomplete="off">')}${field('new-email', 'Email', '<input id="new-email" name="email" type="email" required maxlength="160" placeholder="person@example.test" autocomplete="off">', 'Use sample details. Nothing leaves this browser.')}${field('new-role', 'Role', `<select id="new-role" name="role">${roles('developer')}</select>`)}</div>`, 'Add user', data => {
      const username = data.get('username').trim(), email = data.get('email').trim().toLowerCase();
      if (state.users.some(user => user.username.toLowerCase() === username.toLowerCase() || user.email.toLowerCase() === email)) throw new Error('A demo user with that username or email already exists.');
      const name = data.get('name').trim(); if (!name) throw new Error('Enter a name.');
      state.users.push({ id: crypto.randomUUID(), name, username, email, role: data.get('role'), enabled: true, source: 'Local' }); record('User added', `${name} · ${data.get('role')}`); userQuery = ''; userRole = 'all'; save(`${name} was added to the demo directory.`);
    });
  } else if (name === 'toggle-user') {
    const person = user(id); if (!person || id === currentUserId) return;
    confirm(`${person.enabled ? 'Disable' : 'Enable'} ${person.name}?`, person.enabled ? 'Their active demo sessions will end and the account will be marked disabled.' : 'The account can have new demo sessions. Previously ended sessions stay ended.', person.enabled ? 'Disable user' : 'Enable user', () => { person.enabled = !person.enabled; if (!person.enabled) state.sessions.filter(session => session.userId === id).forEach(endSession); record(person.enabled ? 'User enabled' : 'User disabled', person.name); save(`${person.name} is now ${person.enabled ? 'enabled' : 'disabled'}.`); });
  } else if (name === 'invite') {
    showDialog('Create a demo invitation', `<div class="stack">${field('invite-email', 'Email', '<input id="invite-email" name="email" type="email" required maxlength="160" placeholder="person@example.test" autocomplete="off">')}${field('invite-role', 'Role', `<select id="invite-role" name="role">${roles('developer')}</select>`)}<p class="muted">This adds a synthetic invitation. No email is sent.</p></div>`, 'Create invitation', data => { const email = data.get('email').trim().toLowerCase(); if (state.invitations.some(i => i.email === email && i.status === 'pending')) throw new Error('A pending demo invitation already exists for this address.'); state.invitations.unshift({ id: crypto.randomUUID(), email, role: data.get('role'), status: 'pending', createdAt: new Date().toISOString() }); record('Invitation created', `${email} · ${data.get('role')}`); save('Demo invitation created. No email was sent.'); });
  } else if (name === 'revoke-invite') {
    const invitation = state.invitations.find(i => i.id === id); if (!invitation || invitation.status !== 'pending') return;
    confirm('Revoke this invitation?', `Revoke the demo invitation for ${e(invitation.email)}?`, 'Revoke invitation', () => { invitation.status = 'revoked'; record('Invitation revoked', invitation.email); save('Demo invitation revoked.'); });
  } else if (name === 'revoke-session') {
    const session = state.sessions.find(s => s.id === id); if (!session?.active) return;
    confirm('End this browser session?', `End ${e(user(session.userId).name)}’s session in ${e(session.browser)} and all its connected sample app sessions?`, 'End session', () => { endSession(session); record('Session ended', `${user(session.userId).name} · ${session.browser}`); save('Demo session and its connected app sessions ended.'); });
  }
}
document.addEventListener('click', event => {
  const control = event.target.closest('[data-action]');
  if (!control) return;
  try { action(control.dataset.action, control.dataset.id); } catch (error) { message = error.message; render(); }
});
document.addEventListener('input', event => {
  if (event.target.id === 'user-search') { userQuery = event.target.value; document.querySelector('#users-results').innerHTML = usersTable(); }
});
document.addEventListener('change', event => {
  if (event.target.id === 'user-role') { userRole = event.target.value; document.querySelector('#users-results').innerHTML = usersTable(); }
  if (event.target.id === 'session-state') { sessionFilter = event.target.value; render(); }
  if (event.target.dataset.roleUser) { const person = user(event.target.dataset.roleUser); if (!person || person.id === currentUserId || !['admin', 'developer'].includes(event.target.value)) return; person.role = event.target.value; record('Role changed', `${person.name} · ${person.role}`); save(`${person.name} is now ${person.role === 'admin' ? 'an administrator' : 'a developer'}.`); }
});
form.addEventListener('submit', event => {
  event.preventDefault();
  try { dialogCallback(new FormData(form)); dialog.close(); } catch (error) { document.querySelector('#dialog-error').textContent = error.message; }
});
dialog.addEventListener('close', () => { if (returnFocus?.isConnected) returnFocus.focus(); else main.focus(); });
window.addEventListener('hashchange', () => { render(); main.focus(); });
render();
