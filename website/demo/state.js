// SPDX-License-Identifier: AGPL-3.0-or-later
// This state is exclusively for the user-requested synthetic browser demo.
export const storageKey = 'shauth-public-demo-v1';
export const currentUserId = 'morgan';
export const currentSessionId = 'this-browser';
export function initialState() {
  const now = Date.now();
  const at = minutes => new Date(now - minutes * 60000).toISOString();
  return {
    version: 1,
    users: [
      { id: 'morgan', name: 'Morgan Lee', username: 'morgan', email: 'morgan@example.test', role: 'admin', enabled: true, source: 'Local' },
      { id: 'sam', name: 'Sam Rivera', username: 'sam', email: 'sam@example.test', role: 'developer', enabled: true, source: 'GitHub' },
      { id: 'alex', name: 'Alex Chen', username: 'alex', email: 'alex@example.test', role: 'developer', enabled: true, source: 'Local' },
      { id: 'riley', name: 'Riley Park', username: 'riley', email: 'riley@example.test', role: 'developer', enabled: false, source: 'Local' },
    ],
    apps: [
      { id: 'atlas', name: 'Atlas Docs', description: 'A sample team knowledge base. Explore how a shared session follows you into an application.', category: 'Knowledge' },
      { id: 'orbit', name: 'Orbit Board', description: 'A sample planning workspace. Open it after Atlas to see single sign-on across applications.', category: 'Planning' },
      { id: 'fieldnotes', name: 'Field Notes', description: 'A sample writing app. Sign out here to end the shared session in every connected sample app.', category: 'Writing' },
    ],
    sessions: [
      { id: currentSessionId, userId: 'morgan', browser: 'This demo browser', startedAt: at(6), active: true, apps: [] },
      { id: 'sam-browser', userId: 'sam', browser: 'Firefox · Linux', startedAt: at(42), active: true, apps: ['atlas', 'orbit'] },
      { id: 'alex-browser', userId: 'alex', browser: 'Safari · macOS', startedAt: at(125), active: true, apps: ['fieldnotes'] },
      { id: 'morgan-previous', userId: 'morgan', browser: 'Chrome · macOS', startedAt: at(1440), active: false, apps: [] },
    ],
    invitations: [{ id: 'invite-jules', email: 'jules@example.test', role: 'developer', status: 'pending', createdAt: at(30) }],
    audit: [
      { id: 'initial-login', at: at(6), actor: 'Morgan Lee', action: 'Demo session started', detail: 'Synthetic administrator session in this browser.' },
      { id: 'initial-invite', at: at(30), actor: 'Morgan Lee', action: 'Invitation created', detail: 'jules@example.test · developer · synthetic example' },
    ],
  };
}
export function validateState(value) {
  if (!value || value.version !== 1 || !['users', 'apps', 'sessions', 'invitations', 'audit'].every(key => Array.isArray(value[key])) || !value.users.some(user => user.id === currentUserId) || !value.sessions.some(session => session.id === currentSessionId)) throw new Error('Saved demo data is incompatible. Reset the demo to restore the sample data.');
  return value;
}
