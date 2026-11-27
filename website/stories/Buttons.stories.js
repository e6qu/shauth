// SPDX-License-Identifier: AGPL-3.0-or-later
import { button } from '../components.js';

export default {
  title: 'Components/Button',
  args: { label: 'Add user', variant: 'primary', iconName: 'users', disabled: false },
  argTypes: {
    label: { control: 'text' },
    variant: { control: 'select', options: ['primary', 'secondary', 'danger'] },
    iconName: { control: 'select', options: ['', 'users', 'refresh', 'signout', 'mail', 'key', 'trash'] },
    disabled: { control: 'boolean' },
  },
  render: args => {
    const root = document.createElement('section');
    root.innerHTML = `${button({ ...args, attrs: args.disabled ? 'disabled' : '' })}<output class="component-output" aria-live="polite">Button activated 0 times.</output>`;
    let count = 0;
    root.querySelector('button').addEventListener('click', () => { count += 1; root.querySelector('output').textContent = `Button activated ${count} ${count === 1 ? 'time' : 'times'}.`; });
    return root;
  },
};

export const Primary = {};
export const Secondary = { args: { label: 'Refresh view', variant: 'secondary', iconName: 'refresh' } };
export const Destructive = { args: { label: 'End session', variant: 'danger', iconName: 'signout' } };
export const Disabled = { args: { label: 'Saving', disabled: true, iconName: '' } };
