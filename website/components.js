// SPDX-License-Identifier: AGPL-3.0-or-later
// Shared by the browser-local demonstration and its component stories.
import { icons } from './assets/icons.js';

export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

export function icon(name) {
  if (!Object.hasOwn(icons, name)) throw new Error(`Unknown Shauth icon: ${name}`);
  return icons[name];
}

export function button({ label, variant = 'primary', iconName = '', attrs = '' }) {
  const variants = { primary: '', secondary: ' button-secondary', danger: ' button-danger' };
  if (!Object.hasOwn(variants, variant)) throw new Error(`Unknown button variant: ${variant}`);
  return `<button type="button" class="button${variants[variant]}"${attrs ? ` ${attrs}` : ''}>${iconName ? icon(iconName) : ''}${escapeHTML(label)}</button>`;
}

export function badge(label, tone = 'neutral') {
  const tones = { neutral: ' status-neutral', success: '', warning: ' status-warn', danger: ' status-bad' };
  if (!Object.hasOwn(tones, tone)) throw new Error(`Unknown badge tone: ${tone}`);
  return `<span class="status${tones[tone]}">${escapeHTML(label)}</span>`;
}

export function notice(message, tone = 'info') {
  const tones = { info: 'status-banner status-banner-info', success: 'status-banner', danger: 'notice' };
  if (!Object.hasOwn(tones, tone)) throw new Error(`Unknown notice tone: ${tone}`);
  return `<p class="${tones[tone]}" role="${tone === 'danger' ? 'alert' : 'status'}">${escapeHTML(message)}</p>`;
}

export function metric(label, value) {
  return `<article class="metric"><strong>${escapeHTML(value)}</strong><p>${escapeHTML(label)}</p></article>`;
}

export function appCard(app, { active = false } = {}) {
  return `<article class="card"><p class="eyebrow">${escapeHTML(app.id)}</p><h2>${escapeHTML(app.name)}</h2><p class="lede">${escapeHTML(app.description)}</p><p>${badge(active ? 'Demo session active' : 'Ready to explore', active ? 'success' : 'neutral')}</p><div class="actions">${button({ label: `Open ${app.name}`, iconName: 'external', attrs: `data-action="open-app" data-id="${escapeHTML(app.id)}"` })}</div></article>`;
}
