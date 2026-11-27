// SPDX-License-Identifier: AGPL-3.0-or-later
import { icons } from '../assets/icons.js';
import { escapeHTML, icon } from '../components.js';

export default { title: 'Foundations/Design system' };

export const Colors = {
  render: () => `<h1>Color tokens</h1><p class="component-description">The same CSS custom properties used by Shauth’s server-rendered interface. Change the theme in the toolbar to inspect both palettes.</p><div class="component-token-grid">${['bg', 'surface', 'surface-strong', 'text', 'muted', 'border', 'brand', 'brand-soft', 'accent', 'accent-soft', 'success', 'success-soft', 'warning', 'warning-soft', 'danger', 'danger-soft', 'focus'].map(name => `<figure class="component-token"><div class="component-token-swatch" style="background:var(--${name})"></div><figcaption>--${name}</figcaption></figure>`).join('')}</div>`,
};

export const Typography = {
  render: () => `<section class="component-stack"><p class="eyebrow">Typography</p><h1>Identity, clearly presented.</h1><p class="lede">The application uses system fonts, an explicit hierarchy, and readable body text.</p><h2>Manage people and access</h2><p>A single browser session connects registered applications. Administrators can inspect and revoke it.</p><h3>Session details</h3><p class="muted">Supporting text explains the action or state without competing with the main task.</p><p><a href="../docs/" target="_top">Read the documentation</a></p><p><code>/.well-known/openid-configuration</code></p></section>`,
};

export const Icons = {
  render: () => `<h1>Interface icons</h1><p class="component-description">These SVGs come directly from Shauth’s Go templates. Icons accompany text; their SVG markup is hidden from assistive technology.</p><div class="component-icon-grid">${Object.keys(icons).map(name => `<div class="component-icon">${icon(name)}<code>${escapeHTML(name)}</code></div>`).join('')}</div>`,
};
