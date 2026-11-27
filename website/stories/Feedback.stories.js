// SPDX-License-Identifier: AGPL-3.0-or-later
import { badge, notice, metric } from '../components.js';

export default { title: 'Components/Feedback' };

export const Statuses = {
  render: () => `<h1>Status labels</h1><p class="component-description">Text carries the meaning alongside color. These are examples of the states shown in the synthetic demo.</p><div class="actions">${badge('Active', 'success')}${badge('Ended', 'neutral')}${badge('Pending', 'warning')}${badge('Disabled', 'danger')}</div>`,
};

export const Notices = {
  render: () => `<h1>Notices</h1><div class="component-stack">${notice('This demonstration uses synthetic data stored in your browser.', 'info')}${notice('Your demo changes were saved in this browser.', 'success')}${notice('Enter an email address to continue.', 'danger')}</div>`,
};

export const Metrics = {
  render: () => {
    const sessions = [{ active: true }, { active: true }, { active: false }];
    return `<h1>Summary metrics</h1><p class="component-description">Counts are derived from the synthetic example records, just as the demo derives them from its current state.</p><section class="metric-row">${metric('Example sessions', sessions.length)}${metric('Active sessions', sessions.filter(session => session.active).length)}${metric('Ended sessions', sessions.filter(session => !session.active).length)}</section>`;
  },
};
