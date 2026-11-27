// SPDX-License-Identifier: AGPL-3.0-or-later
import { button } from '../components.js';

export default { title: 'Components/Form fields' };

export const Invitation = {
  render: () => {
    const root = document.createElement('section');
    root.innerHTML = `<h1>Invitation fields</h1><p class="component-description">A browser-only form example. Submitting updates the text below; no email is sent.</p><form class="stack component-form"><div class="field"><label for="story-email">Email address</label><input id="story-email" name="email" type="email" required aria-describedby="story-email-help"><span class="field-help" id="story-email-help">Use a synthetic address, such as alex@example.test.</span></div><div class="field"><label for="story-role">Role</label><select id="story-role" name="role"><option value="developer">Developer</option><option value="admin">Administrator</option></select></div><button class="button" type="submit">Preview invitation</button></form><output class="component-output" aria-live="polite">No invitation previewed.</output>`;
    root.querySelector('form').addEventListener('submit', event => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      root.querySelector('output').textContent = `Demo invitation: ${data.get('email')} as ${data.get('role')}. No email was sent.`;
    });
    return root;
  },
};

export const ValidationError = {
  render: () => `<section class="component-form stack"><h1>Field validation</h1><div class="field"><label for="story-name">Display name</label><input id="story-name" name="name" aria-invalid="true" aria-describedby="story-name-error" required><span class="field-error" id="story-name-error">Enter a display name.</span></div>${button({ label: 'Save changes', attrs: 'disabled' })}</section>`,
};
