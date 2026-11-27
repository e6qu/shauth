// SPDX-License-Identifier: AGPL-3.0-or-later
import { appCard } from '../components.js';

export default {
  title: 'Components/Application card',
  args: { name: 'Team notes', description: 'A shared notebook for the demonstration workspace.', active: false },
  argTypes: { name: { control: 'text' }, description: { control: 'text' }, active: { control: 'boolean' } },
  render: ({ name, description, active }) => {
    const root = document.createElement('section');
    root.className = 'component-form';
    root.innerHTML = `${appCard({ id: 'team-notes', name, description }, { active })}<output class="component-output" aria-live="polite">Use the button to inspect its local action.</output>`;
    root.querySelector('[data-action="open-app"]').addEventListener('click', () => { root.querySelector('output').textContent = `Open application action selected for ${name}. This component story does not open a live application.`; });
    return root;
  },
};

export const Ready = {};
export const ActiveSession = { args: { active: true } };
